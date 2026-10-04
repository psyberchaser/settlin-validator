// C-01 — INDEPENDENT delivery verification, run inside each validator-attestor-service.
//
// A validator must only sign that a destination payout happened if IT can see that payout on ITS OWN
// node. This module turns the relayer's claim into a yes/no decision using the validator's own RPC
// endpoints — never trusting the relayer. It does two things, both fail-closed:
//
//   1. Bind-check: recompute the hashed digest fields from the RAW claim and require they equal the
//      bound bytes32 the relayer is asking signatures over. This guarantees the signature the
//      validator produces actually commits to the facts it verified (not some other digest).
//        recipient(bytes32) == keccak256(utf8(raw.recipient))
//        asset(bytes32)     == keccak256(utf8(raw.assetSymbol))
//        amount(uint256)    == round(raw.amount * raw.amountScale)
//
//   2. On-chain check: look up raw.destTx on raw.destChain and confirm it delivered >= raw.amount of
//      the native asset to raw.recipient at the required finality.
//
// Covers the live corridors (native SOL payouts, native EVM payouts). Anything it cannot positively
// verify — unknown chain, missing tx, wrong recipient, short amount, insufficient finality, SPL/ERC-20
// token payouts (not yet implemented) — returns { ok:false }, so the validator declines to sign.

import { ethers } from "ethers";

// H-06: a validator must NEVER attest more than it observed. The delivered amount must be at least the
// FULL claimed amount (100%) — there is no tolerance in the evidence layer. Any product-level slippage
// belongs in the intent / minDestAmount and the on-chain digest, not in a hidden validator fudge factor.
const AMOUNT_FLOOR_BPS = 10000n; // 100% — delivered must be >= the exact signed amount

// M-03: integer-precise scaling. NEVER multiply a float by the scale (Number loses precision above 2^53
// and rounds high-decimal values). Treat the scale as a decimal exponent and parse fixed-point, so the
// relayer's committed amount and the validator's recomputation agree exactly, bit-for-bit.
function scaleToInt(amount, scale) {
  const decimals = Math.round(Math.log10(Number(scale)));
  // toFixed(decimals) pins to the smallest unit; parseUnits yields the exact integer with no float mul.
  return ethers.parseUnits(Number(amount).toFixed(decimals), decimals);
}

// ── C-01 (v8): source-side expected-delivery commitment ─────────────────────────────────────────
// bindCheck + the on-chain check prove the claim describes a REAL payout — but the relayer chooses
// which payout to describe. A compromised relayer could pay attacker X and ask honest validators to
// attest that real-but-wrong payout under a legitimate intentId. So, before signing, a validator also
// reads the SOURCE pool's expected-delivery commitment (written when the SP1 proof verified) and
// refuses any claim that does not satisfy it. The pool enforces the same predicate on-chain
// (SettlementProofLib.requireDelivered); this makes honest validators refuse up front as well.
export const POOL_EXPECTATION_ABI = [
  "function deliveryExpectation(bytes32) view returns (bytes32 recipientHash, uint256 destAmount, uint64 destChainId, uint8 finality, bool set)",
  "function expectedDeliveryAsset(uint256) view returns (bytes32)",
];

/**
 * Pure decision: does the claim satisfy the source pool's expected-delivery commitment?
 * @param {object} claim { recipient, amount, asset, finality } (the bound digest fields)
 * @param {object|null} x  { set, recipientHash, destAmount, finality, asset } — null = the pool
 *   predates v8 (no commitment API), so there is nothing to check (pre-upgrade compatibility).
 * @returns {string|null} a refusal reason, or null when the claim matches.
 */
export function checkSourceExpectation(claim, x) {
  if (!x) return null;
  if (!x.set) return "no expected-delivery commitment on the source pool (proof not committed)";
  try {
    if (ethers.hexlify(claim.recipient) !== ethers.hexlify(x.recipientHash)) return "recipient differs from the source intent's committed recipient";
    if (BigInt(claim.amount) < BigInt(x.destAmount)) return "amount below the source proof's committed destination amount";
    if (Number(claim.finality) < Number(x.finality)) return "finality below the source commitment";
    if (x.asset && x.asset !== ethers.ZeroHash && ethers.hexlify(claim.asset) !== ethers.hexlify(x.asset)) return "asset differs from the corridor's expected asset";
  } catch (e) {
    return `source-expectation check error: ${e.message}`;
  }
  return null;
}

// A pre-v8 pool has no deliveryExpectation(): the call reverts with no data (or returns undecodable
// empty data). Anything else — RPC/network failures, real reverts — must propagate (fail closed).
function isMissingFunction(e) {
  return e?.code === "BAD_DATA" || (e?.code === "CALL_EXCEPTION" && (!e.data || e.data === "0x"));
}

/**
 * On-chain reader for the source commitment. The pool address is read from the attestor itself
 * (attestor.pool()), so validators need no extra configuration.
 * @returns {(intentId:string)=>Promise<object|null>} null when the pool predates v8.
 */
export function makeExpectationReader({ attestorAddress, provider }) {
  const att = new ethers.Contract(attestorAddress, ["function pool() view returns (address)"], provider);
  let poolP;
  return async (intentId) => {
    poolP ??= att.pool()
      .then((a) => new ethers.Contract(a, POOL_EXPECTATION_ABI, provider))
      .catch((e) => { poolP = undefined; throw e; }); // don't cache a transient failure
    const pool = await poolP;
    let r;
    try { r = await pool.deliveryExpectation(intentId); }
    catch (e) { if (isMissingFunction(e)) return null; throw e; }
    const asset = r.set ? await pool.expectedDeliveryAsset(r.destChainId) : ethers.ZeroHash;
    return { set: r.set, recipientHash: r.recipientHash, destAmount: r.destAmount, destChainId: r.destChainId, finality: r.finality, asset };
  };
}

function bindCheck(claim) {
  const raw = claim.raw;
  if (!raw) return "no raw delivery facts in claim (cannot verify independently)";
  try {
    const rHash = ethers.keccak256(ethers.toUtf8Bytes(String(raw.recipient)));
    if (ethers.hexlify(claim.recipient) !== ethers.hexlify(rHash)) return "recipient hash mismatch";
    const aHash = ethers.keccak256(ethers.toUtf8Bytes(String(raw.assetSymbol)));
    if (ethers.hexlify(claim.asset) !== ethers.hexlify(aHash)) return "asset hash mismatch";
    const boundAmount = scaleToInt(raw.amount, raw.amountScale || 1e9);
    if (BigInt(claim.amount) !== boundAmount) return "amount commitment mismatch";
  } catch (e) {
    return `bind-check error: ${e.message}`;
  }
  return null; // ok
}

// ── Solana native payout ──────────────────────────────────────────────────────
async function verifySolana(raw, connMod, rpcUrl, requireFinalized) {
  let Connection, PublicKey, LAMPORTS_PER_SOL;
  try {
    ({ Connection, PublicKey, LAMPORTS_PER_SOL } = connMod || (await import("@solana/web3.js")));
  } catch {
    return { ok: false, reason: "@solana/web3.js not available on this validator" };
  }
  const conn = new Connection(rpcUrl, requireFinalized ? "finalized" : "confirmed");
  let tx;
  try {
    tx = await conn.getTransaction(raw.destTx, { commitment: requireFinalized ? "finalized" : "confirmed", maxSupportedTransactionVersion: 0 });
  } catch (e) {
    return { ok: false, reason: `solana getTransaction failed: ${e.message}` };
  }
  if (!tx) return { ok: false, reason: "solana tx not found at required commitment (not finalized yet?)" };
  if (tx.meta?.err) return { ok: false, reason: `solana tx failed on-chain: ${JSON.stringify(tx.meta.err)}` };

  // Find the recipient's balance delta from pre/post balances.
  let recipientKey;
  try { recipientKey = new PublicKey(String(raw.recipient)); } catch { return { ok: false, reason: "bad solana recipient pubkey" }; }
  const keys = tx.transaction.message.getAccountKeys ? tx.transaction.message.getAccountKeys().staticAccountKeys : tx.transaction.message.accountKeys;
  const idx = keys.findIndex((k) => k.equals(recipientKey));
  if (idx < 0) return { ok: false, reason: "recipient not an account in the tx" };
  const pre = BigInt(tx.meta.preBalances[idx]);
  const post = BigInt(tx.meta.postBalances[idx]);
  const deliveredLamports = post - pre;
  if (deliveredLamports <= 0n) return { ok: false, reason: "recipient balance did not increase" };

  const expectedLamports = scaleToInt(raw.amount, LAMPORTS_PER_SOL); // M-03: integer-precise
  const floor = (expectedLamports * AMOUNT_FLOOR_BPS) / 10000n;      // H-06: == expected (100%)
  if (deliveredLamports < floor) {
    return { ok: false, reason: `delivered ${deliveredLamports} lamports < required ${floor} (expected ${expectedLamports})` };
  }
  return { ok: true, detail: { deliveredLamports: deliveredLamports.toString(), expectedLamports: expectedLamports.toString() } };
}

// ── EVM native payout ───────────────────────────────────────────────────────────
async function verifyEvm(raw, provider, requireFinalized) {
  let rcpt, txn;
  try {
    [rcpt, txn] = await Promise.all([provider.getTransactionReceipt(raw.destTx), provider.getTransaction(raw.destTx)]);
  } catch (e) {
    return { ok: false, reason: `evm lookup failed: ${e.message}` };
  }
  if (!rcpt || !txn) return { ok: false, reason: "evm tx not found" };
  if (rcpt.status !== 1) return { ok: false, reason: "evm tx reverted" };

  let recipient;
  try { recipient = ethers.getAddress(String(raw.recipient)); } catch { return { ok: false, reason: "bad evm recipient address" }; }
  if (!txn.to || ethers.getAddress(txn.to) !== recipient) return { ok: false, reason: "evm tx recipient mismatch (native transfer expected)" };

  const expectedWei = ethers.parseEther(String(raw.amount));
  const floor = (expectedWei * AMOUNT_FLOOR_BPS) / 10000n;
  if (txn.value < floor) return { ok: false, reason: `evm value ${txn.value} < floor ${floor} (expected ${expectedWei})` };

  // Finality: require the tx block to be at/under the chain's finalized tag when finality==2.
  if (requireFinalized) {
    try {
      const fin = await provider.getBlock("finalized");
      if (!fin || rcpt.blockNumber == null || fin.number < rcpt.blockNumber) {
        return { ok: false, reason: "evm tx not yet finalized" };
      }
    } catch {
      // Chain/RPC without the finalized tag: fall back to a deep confirmation count.
      try {
        const latest = await provider.getBlockNumber();
        if (latest - rcpt.blockNumber + 1 < 64) return { ok: false, reason: "evm tx lacks deep confirmations (no finalized tag)" };
      } catch (e) { return { ok: false, reason: `evm finality check failed: ${e.message}` }; }
    }
  }
  return { ok: true, detail: { value: txn.value.toString(), expectedWei: expectedWei.toString() } };
}

/**
 * Build an independent verifier bound to this validator's own RPC endpoints.
 * @param {object} cfg
 * @param {Record<string,string>} [cfg.evmRpc]  map chain name -> EVM RPC URL (e.g. {ethereum, arbitrum})
 * @param {string} [cfg.solanaRpc]              Solana RPC URL
 * @param {object} [cfg.solanaModule]           injected @solana/web3.js (tests); else imported lazily
 * @returns {(claim:object)=>Promise<{ok:boolean, reason?:string, detail?:object}>}
 */
export function makeOnchainVerifier(cfg = {}) {
  const evmProviders = {};
  for (const [name, url] of Object.entries(cfg.evmRpc || {})) {
    if (url) evmProviders[name] = new ethers.JsonRpcProvider(url);
  }
  return async function verifyDelivery(claim) {
    const bindErr = bindCheck(claim);
    if (bindErr) return { ok: false, reason: bindErr };
    const raw = claim.raw;
    const requireFinalized = Number(claim.finality) >= 2;
    const chain = String(raw.destChain || "").toLowerCase();

    if (chain === "solana") {
      if (!cfg.solanaRpc) return { ok: false, reason: "validator has no Solana RPC configured" };
      return verifySolana(raw, cfg.solanaModule, cfg.solanaRpc, requireFinalized);
    }
    if (evmProviders[chain]) {
      return verifyEvm(raw, evmProviders[chain], requireFinalized);
    }
    if (chain === "bitcoin") return { ok: false, reason: "BTC payout verification not implemented — validator declines" };
    return { ok: false, reason: `validator cannot verify destination chain '${raw.destChain}'` };
  };
}
