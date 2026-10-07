// Settlin — INDEPENDENT validator-attestor service (C-01).
//
// Run by each INDEPENDENT validator operator, on their OWN host, with their OWN signing key and their
// OWN RPC endpoints. The Settlin relayer never holds this key and cannot sign on this validator's
// behalf — it can only ASK, over HTTP, and this service decides for itself.
//
// This package is intentionally standalone and public: an independent operator needs NO access to the
// private bridge repo to run it. It contains no secrets and no bridge internals — just the attestation
// logic and an independent on-chain delivery check.
//
// POST /attest flow:
//   1. (optional) bearer-token auth — a coarse anti-spam gate, NOT the security boundary.
//   2. INDEPENDENT delivery verification on this validator's own nodes (verify-delivery.mjs): the
//      destination payout must be visible, to the right recipient, for >= the amount, at the required
//      finality, and the bound hashes must match the raw facts. Fail-closed otherwise.
//   3. Read the AUTHORITATIVE digest from the on-chain DeliveryAttestor (so it can never drift from the
//      deployed scoping), then sign it with this validator's own key.
//   4. Return { validator, signature }.
//
// Security model: compromising the relayer yields no validator signatures (it holds none); compromising
// one of these services yields exactly one signature, below the m-of-n threshold. No single credential
// can forge a quorum. The signing key here can ONLY attest delivery — it custodies nothing.
//
// Start:  node service.mjs
//   env:  VALIDATOR_KEY=0x…                  this validator's OWN signing key
//         DELIVERY_ATTESTOR_ADDRESS=0x…      the attestor to read digests from
//         ATTESTOR_RPC=https://… (or EVM_RPC) RPC for the attestor's chain (Ethereum)
//         SOLANA_RPC=https://…               this validator's OWN Solana node (for SOL payouts)
//         EVM_RPC_<CHAIN>=https://…          per-dest-chain EVM RPC (e.g. EVM_RPC_ARBITRUM)
//         PORT=8800  HOST=0.0.0.0
//         VALIDATOR_AUTH_TOKEN=…             optional bearer the relayer must present

import http from "node:http";
import { ethers } from "ethers";
import { makeOnchainVerifier, makeExpectationReader, checkSourceExpectation } from "./verify-delivery.mjs";

// Only what this service reads from the DeliveryAttestor: the authoritative digest (v2 + legacy v1).
const DELIVERY_ATTESTOR_ABI = [
  "function attestationDigest(bytes32 intentId, bytes32 destTxHash, bytes32 recipient, uint256 amount, bytes32 asset, uint8 finality) view returns (bytes32)",
  "function attestationDigest(bytes32 intentId, bytes32 destTxHash) view returns (bytes32)",
];

// Local key signer (this validator's own key). An operator who keeps its key in a KMS / its own Turnkey
// sub-org can replace this with a signer of the same shape: { address, signDigest(digest32) -> 0x sig }.
export function localSignerFromKey(pk) {
  const w = new ethers.Wallet(pk);
  return {
    address: ethers.getAddress(w.address),
    async signDigest(digest32) {
      return w.signingKey.sign(digest32).serialized; // canonical low-s, v in {27,28}
    },
  };
}

function readBody(req, maxBytes = 64 * 1024) {
  return new Promise((resolve, reject) => {
    let n = 0; const chunks = [];
    req.on("data", (c) => { n += c.length; if (n > maxBytes) { reject(new Error("body too large")); req.destroy(); } else chunks.push(c); });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

/**
 * Build the request handler + counters. Pure (no listen) so it can be driven directly in tests.
 * @param {object} opts
 * @param {{address:string, signDigest:(d:string)=>Promise<string>}} opts.signer
 * @param {string} opts.attestorAddress
 * @param {import('ethers').Provider} opts.attestorProvider
 * @param {(claim:object)=>Promise<{ok:boolean,reason?:string}>} opts.verifyDelivery
 * @param {(intentId:string)=>Promise<object|null>} [opts.readExpectation] C-01 (v8): source pool's
 *   expected-delivery commitment reader; a claim that does not satisfy it is refused before signing.
 * @param {string} [opts.authToken]
 */
export function createValidatorService(opts) {
  const { signer, attestorAddress, attestorProvider, verifyDelivery, readExpectation, authToken } = opts;
  if (!signer?.address || typeof signer.signDigest !== "function") throw new Error("createValidatorService needs a signer {address, signDigest}");
  if (!attestorAddress) throw new Error("createValidatorService needs attestorAddress");
  if (!attestorProvider) throw new Error("createValidatorService needs attestorProvider");
  if (typeof verifyDelivery !== "function") throw new Error("createValidatorService needs verifyDelivery");

  const attestor = new ethers.Contract(attestorAddress, DELIVERY_ATTESTOR_ABI, attestorProvider);
  const stats = { attested: 0, declined: 0, errors: 0, address: signer.address };

  function json(res, code, obj) {
    const body = JSON.stringify(obj);
    res.writeHead(code, { "content-type": "application/json", "content-length": Buffer.byteLength(body) });
    res.end(body);
  }
  function authed(req) {
    if (!authToken) return true;
    return (req.headers["authorization"] || "") === `Bearer ${authToken}`;
  }

  async function handler(req, res) {
    try {
      const url = (req.url || "").split("?")[0];
      if (req.method === "GET" && url === "/identity") return json(res, 200, { address: signer.address });
      if (req.method === "GET" && (url === "/health" || url === "/")) return json(res, 200, { status: "ok", ...stats });
      if (req.method !== "POST" || url !== "/attest") return json(res, 404, { error: "not found" });
      if (!authed(req)) { stats.declined++; return json(res, 401, { error: "unauthorized" }); }

      let claim;
      try { claim = JSON.parse(await readBody(req)); } catch { return json(res, 400, { error: "bad json" }); }
      if (!claim?.intentId || !claim?.destTxHash) return json(res, 400, { error: "missing intentId/destTxHash" });

      const verdict = await verifyDelivery(claim);
      if (!verdict?.ok) { stats.declined++; return json(res, 409, { error: `delivery not verified: ${verdict?.reason || "unknown"}` }); }

      // C-01 (v8): the payout is real — but is it the payout the SOURCE intent requires? Read the pool's
      // expected-delivery commitment (set when the SP1 proof verified) and refuse anything else, so a
      // relayer cannot steer this validator into attesting a real-but-wrong payout.
      if (readExpectation) {
        let x;
        try { x = await readExpectation(claim.intentId, claim.destTxHash); }
        catch (e) { stats.errors++; return json(res, 502, { error: `source expectation read failed: ${e.message}` }); }
        const why = checkSourceExpectation(claim, x); // v9 C-01: + chain binding + on-chain receipt use
        if (why) { stats.declined++; return json(res, 409, { error: `delivery does not match the source commitment: ${why}` }); }
      }

      let digest;
      try {
        digest = claim.legacy
          ? await attestor["attestationDigest(bytes32,bytes32)"](claim.intentId, claim.destTxHash)
          : await attestor["attestationDigest(bytes32,bytes32,bytes32,uint256,bytes32,uint8)"](
              claim.intentId, claim.destTxHash, claim.recipient, BigInt(claim.amount), claim.asset, Number(claim.finality));
      } catch (e) { stats.errors++; return json(res, 502, { error: `attestor digest read failed: ${e.message}` }); }

      const signature = await signer.signDigest(digest);
      if (ethers.getAddress(ethers.recoverAddress(digest, signature)) !== signer.address) {
        stats.errors++; return json(res, 500, { error: "self-recovery mismatch" });
      }
      stats.attested++;
      return json(res, 200, { validator: signer.address, signature });
    } catch (e) {
      stats.errors++;
      try { return json(res, 500, { error: e.message || "internal error" }); } catch { /* sent */ }
    }
  }

  return { handler, stats, address: signer.address };
}

export function startValidatorService(opts, port = 0, host = "127.0.0.1") {
  const svc = createValidatorService(opts);
  const server = http.createServer((req, res) => { svc.handler(req, res); });
  return new Promise((resolve) => {
    server.listen(port, host, () => {
      const a = server.address();
      resolve({ server, address: svc.address, stats: svc.stats, port: a.port, url: `http://${host}:${a.port}` });
    });
  });
}

async function main() {
  const env = process.env;
  const pk = env.VALIDATOR_KEY;
  if (!pk) throw new Error("VALIDATOR_KEY is required (this validator's own signing key)");
  const signer = localSignerFromKey(pk);

  const attestorAddress = env.DELIVERY_ATTESTOR_ADDRESS;
  if (!attestorAddress) throw new Error("DELIVERY_ATTESTOR_ADDRESS is required");
  const attestorRpc = env.ATTESTOR_RPC || env.EVM_RPC;
  if (!attestorRpc) throw new Error("ATTESTOR_RPC (or EVM_RPC) is required");
  const attestorProvider = new ethers.JsonRpcProvider(attestorRpc);

  const evmRpc = {};
  for (const [k, v] of Object.entries(env)) {
    const m = /^EVM_RPC_([A-Z0-9]+)$/.exec(k);
    if (m && v) evmRpc[m[1].toLowerCase()] = v;
  }
  if (env.EVM_RPC && !evmRpc.ethereum) evmRpc.ethereum = env.EVM_RPC;
  // Fail fast if this validator can't load its Solana client. Otherwise every Solana payout is
  // silently declined ("@solana/web3.js not available") and the quorum can never form. Seen in prod:
  // Node < 22.12 can't require() the ESM-only deps of @solana/web3.js >= 1.98 (ERR_REQUIRE_ESM).
  if (env.SOLANA_RPC) {
    try { await import("@solana/web3.js"); }
    catch (e) { throw new Error(`SOLANA_RPC is set but @solana/web3.js failed to load (${e.code || e.message}) — use Node >= 22.12`); }
  }
  const verifyDelivery = makeOnchainVerifier({ evmRpc, solanaRpc: env.SOLANA_RPC });

  // M-06: a validator signing service must NOT be open to the public — /attest is a high-value signing
  // endpoint (DoS + signature-harvesting surface). Require a bearer token unless explicitly opted into
  // open mode for local dev.
  if (!env.VALIDATOR_AUTH_TOKEN && env.VALIDATOR_ALLOW_OPEN !== "true") {
    throw new Error("M-06: VALIDATOR_AUTH_TOKEN is required (or set VALIDATOR_ALLOW_OPEN=true for local dev only). /attest must not be publicly open.");
  }
  // C-01 (v8): bind every signature to the source pool's expected-delivery commitment (pool address is
  // read from the attestor). Compatible with a pre-v8 pool (no commitment API → check skipped).
  const readExpectation = makeExpectationReader({ attestorAddress, provider: attestorProvider });
  const port = Number(env.PORT || 8800);
  const { url, address } = await startValidatorService(
    { signer, attestorAddress, attestorProvider, verifyDelivery, readExpectation, authToken: env.VALIDATOR_AUTH_TOKEN },
    port,
    env.HOST || "0.0.0.0",
  );
  console.log(`✅ settlin-validator listening on ${url}`);
  console.log(`   validator address: ${address}`);
  console.log(`   attestor:          ${attestorAddress}`);
  console.log(`   verifiable chains: ${[...Object.keys(evmRpc), env.SOLANA_RPC ? "solana" : null].filter(Boolean).join(", ") || "(none configured!)"}`);
  console.log(`   auth:              ${env.VALIDATOR_AUTH_TOKEN ? "bearer token required" : "OPEN (set VALIDATOR_AUTH_TOKEN)"}`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => { console.error("settlin-validator fatal:", e.message || e); process.exit(1); });
}
