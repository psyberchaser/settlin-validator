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
//        asset(bytes32)     == the native asset of raw.destChain, as its v9 M-01 canonical id
//                              keccak256(abi.encode(keccak256("settlin.asset.v1"), chainId, 0)) — or, until the
//                              pool's registry is cut over, the legacy keccak256(utf8(raw.assetSymbol))
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

// M-02 (v8): the relayer now ships the settlement-authoritative amount as an exact smallest-unit integer
// string (raw.amountUnits) — the same value it paid and proved. Use it verbatim; only claims from a relayer
// that predates it fall back to the decimal parse.
function unitsOf(raw, scale) {
  if (raw.amountUnits != null) return BigInt(raw.amountUnits);
  return scaleToInt(raw.amount, scale);
}

// ── C-01 (v8): source-side expected-delivery commitment ─────────────────────────────────────────
// bindCheck + the on-chain check prove the claim describes a REAL payout — but the relayer chooses
// which payout to describe. A compromised relayer could pay attacker X and ask honest validators to
// attest that real-but-wrong payout under a legitimate intentId. So, before signing, a validator also
// reads the SOURCE pool's expected-delivery commitment (written when the SP1 proof verified) and
// refuses any claim that does not satisfy it. The pool enforces the same predicate on-chain
// (SettlementProofLib.requireDelivered); this makes honest validators refuse up front as well.
// ── v9 C-01: observation identity ─────────────────────────────────────────────────────────────────
// What a validator signs must be exactly what it fetched. Destination chains this validator can verify,
// their source-side chain id (as stored in the intent's destChainId) and the ONLY asset a native
// balance delta can prove (a native transfer can't attest a token, so a relabelled asset is refused).
export const DEST_CHAINS = {
  solana: { chainId: 1399811149n, native: "SOL" },
  ethereum: { chainId: 1n, native: "ETH" },
  arbitrum: { chainId: 42161n, native: "ETH" },
  polygon: { chainId: 137n, native: "MATIC" },
  avalanche: { chainId: 43114n, native: "AVAX" },
};

// v9 M-01: canonical asset ids — chain + contract/mint identity, never a symbol (mirrors SettlementProofLib).
export const ASSET_DOMAIN = ethers.id("settlin.asset.v1");
export function canonicalAssetId(chainId, identity = ethers.ZeroHash) {
  return ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["bytes32", "uint256", "bytes32"], [ASSET_DOMAIN, BigInt(chainId), identity]));
}
/** The asset ids a native payout on `destChain` may be attested as: canonical (v9 M-01) or the legacy symbol hash. */
export function nativeAssetIds(destChain) {
  const dc = DEST_CHAINS[String(destChain || "").toLowerCase()];
  if (!dc) return [];
  return [canonicalAssetId(dc.chainId), ethers.keccak256(ethers.toUtf8Bytes(dc.native))].map((h) => h.toLowerCase());
}

/** Canonical receipt id the relayer binds as destTxHash (mirrors multi-chain-relayer.mjs exactly). */
export function destTxHashFor(destTx) {
  const t = String(destTx || "");
  return t.startsWith("0x") ? t.slice(0, 66).padEnd(66, "0").toLowerCase() : ethers.keccak256(ethers.toUtf8Bytes(t));
}

// Explicit intent linkage: every attested payout names the ONE intent it settles — a Solana SPL Memo v2
// instruction (or EVM calldata) equal to the lowercase intentId. A payment can then only be evidence
// for that intent: older payments, third-party transfers and duplicate payouts (no / other memo) are
// refused, independent of timing. The attestor's single-use receipts back this up on-chain.
export const MEMO_PROGRAM_IDS = new Set(["MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr", "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo"]);

export const POOL_EXPECTATION_ABI = [
  "function deliveryExpectation(bytes32) view returns (bytes32 recipientHash, uint256 destAmount, uint64 destChainId, uint8 finality, bool set)",
  "function expectedDeliveryAsset(uint256) view returns (bytes32)",
  "function intentDestAsset(bytes32) view returns (bytes32)", // v9 M-01 (absent on older pools)
  "function committedToSettle(bytes32) view returns (bool)",
  "function intents(bytes32) view returns (bytes32 id, address sender, address token, uint256 amount, uint256 destChainId, bytes destAddress, bytes destToken, uint256 minDestAmount, uint256 deadline, bool executed, bool refunded)",
  "function REQUIRED_FINALITY() view returns (uint8)",
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
    // v9 C-01: the observed destination chain must be the intent's committed destination chain.
    const dc = DEST_CHAINS[String(claim.raw?.destChain || "").toLowerCase()];
    if (!dc) return `unknown destination chain '${claim.raw?.destChain}'`;
    if (dc.chainId !== BigInt(x.destChainId)) return "destination chain differs from the source intent's committed chain";
    // v9 C-01: a receipt already consumed by another intent can never be attested again.
    if (x.receiptUsedBy && x.receiptUsedBy !== ethers.ZeroHash && x.receiptUsedBy.toLowerCase() !== String(claim.intentId).toLowerCase())
      return "destination receipt already backs another intent";
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
  const att = new ethers.Contract(attestorAddress, ["function pool() view returns (address)", "function receiptUsedBy(bytes32) view returns (bytes32)"], provider);
  let poolP;
  return async (intentId, destTxHash) => {
    poolP ??= att.pool()
      .then((a) => new ethers.Contract(a, POOL_EXPECTATION_ABI, provider))
      .catch((e) => { poolP = undefined; throw e; }); // don't cache a transient failure
    const pool = await poolP;
    let r;
    try { r = await pool.deliveryExpectation(intentId); }
    catch (e) { if (isMissingFunction(e)) return null; throw e; }
    let x = { set: r.set, recipientHash: r.recipientHash, destAmount: r.destAmount, destChainId: r.destChainId, finality: r.finality };
    if (!r.set && (await pool.committedToSettle(intentId))) {
      // Mirror SettlementProofLib._expected: an intent committed by a pre-v8 pool has no stored
      // commitment — derive it from the intent's own immutable fields (never the SP1 verifier record).
      const it = await pool.intents(intentId);
      x = { set: true, recipientHash: ethers.keccak256(it.destAddress), destAmount: it.minDestAmount, destChainId: it.destChainId, finality: await pool.REQUIRED_FINALITY() };
    }
    // v9 M-01: mirror SettlementProofLib._intentAsset — the asset recorded for the intent at funding, else the
    // corridor's registered asset. A pool that predates M-01 has no intentDestAsset() → registry only.
    x.asset = ethers.ZeroHash;
    if (x.set) {
      try { x.asset = await pool.intentDestAsset(intentId); } catch (e) { if (!isMissingFunction(e)) throw e; }
      if (x.asset === ethers.ZeroHash) x.asset = await pool.expectedDeliveryAsset(x.destChainId);
    }
    if (destTxHash) {
      // v9 C-01: on-chain receipt consumption (an attestor that predates single-use receipts → skip).
      try { x.receiptUsedBy = await att.receiptUsedBy(destTxHash); }
      catch (e) { if (!isMissingFunction(e)) throw e; }
    }
    return x;
  };
}

export function bindCheck(claim) {
  const raw = claim.raw;
  if (!raw) return "no raw delivery facts in claim (cannot verify independently)";
  try {
    const rHash = ethers.keccak256(ethers.toUtf8Bytes(String(raw.recipient)));
    if (ethers.hexlify(claim.recipient) !== ethers.hexlify(rHash)) return "recipient hash mismatch";
    // v9 M-01: the signed asset must be the destination chain's NATIVE asset — its canonical id, or the legacy
    // symbol hash while the pool registry still holds it (checkSourceExpectation then pins it to the pool's value).
    if (!nativeAssetIds(raw.destChain).includes(ethers.hexlify(claim.asset).toLowerCase())) return "asset is not the destination chain's native asset id";
    const boundAmount = unitsOf(raw, raw.amountScale || 1e9); // M-02: exact units when present
    if (BigInt(claim.amount) !== boundAmount) return "amount commitment mismatch";
    // v9 C-01: the receipt id being signed must be the very transaction this validator fetches.
    if (!claim.destTxHash || destTxHashFor(raw.destTx) !== String(claim.destTxHash).toLowerCase()) return "signed destTxHash does not match raw.destTx";
    // v9 C-01: a native balance delta proves only the chain's native asset — refuse a relabelled asset.
    const dc = DEST_CHAINS[String(raw.destChain || "").toLowerCase()];
    if (dc && String(raw.assetSymbol) !== dc.native) return `asset '${raw.assetSymbol}' is not ${raw.destChain}'s native asset (${dc.native})`;
  } catch (e) {
    return `bind-check error: ${e.message}`;
  }
  return null; // ok
}

// ── Solana native payout ──────────────────────────────────────────────────────
async function verifySolana(raw, connMod, rpcUrl, requireFinalized, intentId) {
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
  // Full ordered key list (static + address-lookup-table loaded), matching pre/postBalances indexes.
  // getAccountKeys() with no lookups THROWS for a v0 tx that uses lookup tables, so pass them in.
  let keys;
  try {
    const m = tx.transaction.message;
    keys = m.getAccountKeys ? m.getAccountKeys({ accountKeysFromLookups: tx.meta?.loadedAddresses }).keySegments().flat() : m.accountKeys;
  } catch { keys = tx.transaction.message.staticAccountKeys || tx.transaction.message.accountKeys || []; }
  const idx = keys.findIndex((k) => k.equals(recipientKey));
  if (idx < 0) return { ok: false, reason: "recipient not an account in the tx" };
  // v9 C-01: explicit intent linkage — exactly one memo instruction, equal to this intent's id.
  const msg = tx.transaction.message;
  const ixs = msg.compiledInstructions || msg.instructions || [];
  const memos = ixs.filter((ix) => MEMO_PROGRAM_IDS.has(String(keys[ix.programIdIndex]?.toBase58?.() ?? keys[ix.programIdIndex])));
  if (memos.length !== 1) return { ok: false, reason: `payout must carry exactly one intent memo (found ${memos.length})` };
  const memo = Buffer.from(memos[0].data).toString("utf8").trim().toLowerCase();
  if (memo !== String(intentId || "").toLowerCase()) return { ok: false, reason: "payout memo names a different intent" };
  const pre = BigInt(tx.meta.preBalances[idx]);
  const post = BigInt(tx.meta.postBalances[idx]);
  const deliveredLamports = post - pre;
  if (deliveredLamports <= 0n) return { ok: false, reason: "recipient balance did not increase" };

  const expectedLamports = unitsOf(raw, LAMPORTS_PER_SOL); // M-02/M-03: exact units when present
  const floor = (expectedLamports * AMOUNT_FLOOR_BPS) / 10000n;      // H-06: == expected (100%)
  if (deliveredLamports < floor) {
    return { ok: false, reason: `delivered ${deliveredLamports} lamports < required ${floor} (expected ${expectedLamports})` };
  }
  return { ok: true, detail: { deliveredLamports: deliveredLamports.toString(), expectedLamports: expectedLamports.toString() } };
}

// ── EVM native payout ───────────────────────────────────────────────────────────
async function verifyEvm(raw, provider, requireFinalized, intentId) {
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

  // v9 C-01: explicit intent linkage — the native transfer's calldata is exactly this intent's id.
  if (String(txn.data || "0x").toLowerCase() !== String(intentId || "").toLowerCase()) return { ok: false, reason: "payout calldata does not name this intent" };
  const expectedWei = raw.amountUnits != null ? BigInt(raw.amountUnits) : ethers.parseEther(String(raw.amount)); // M-02
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
      return verifySolana(raw, cfg.solanaModule, cfg.solanaRpc, requireFinalized, claim.intentId);
    }
    if (evmProviders[chain]) {
      return verifyEvm(raw, evmProviders[chain], requireFinalized, claim.intentId);
    }
    if (chain === "bitcoin") return { ok: false, reason: "BTC payout verification not implemented — validator declines" };
    return { ok: false, reason: `validator cannot verify destination chain '${raw.destChain}'` };
  };
}

// ── v12 H-03: SOURCE-side observation for the Solana → EVM corridor ───────────────────────────────────
// The sol-tx-verify SP1 proof shows a correctly SIGNED Solana transfer message; it cannot show the transaction was
// included, succeeded and finalized. Each validator observes the deposit on ITS OWN Solana RPC at FINALIZED commitment
// and signs SP1SolInboundGate.sourceDigest(...) only for exactly the transfer the gate will authorize. The gate requires
// a quorum of these signatures, so no single relayer / RPC view can authorize a payout for a deposit that never landed.
export const SOL_SOURCE_TYPEHASH = ethers.id("SETTLIN_SOL_SOURCE_V1");
const SYSTEM_PROGRAM = "11111111111111111111111111111111";

/** Mirrors SP1SolInboundGate.sourceDigest exactly. */
export function solSourceDigest({ chainId, gate, nullifier, sender, recipient, lamports, destChainId, destAddrHash }) {
  return ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
    ["bytes32", "uint256", "address", "bytes32", "bytes32", "bytes32", "uint256", "uint256", "bytes32"],
    [SOL_SOURCE_TYPEHASH, BigInt(chainId), gate, nullifier, sender, recipient, BigInt(lamports), BigInt(destChainId), destAddrHash]));
}
/** keccak256(sigHi || sigLo) of a base58 Solana signature — the gate's nullifier. */
export function solNullifier(sigB58) {
  return ethers.keccak256(ethers.toBeHex(ethers.decodeBase58(String(sigB58)), 64));
}

/**
 * @param {object} cfg { solanaRpc, solanaModule?, depositAccount? (base58; when set, the only accepted recipient) }
 * @returns {(req:object)=>Promise<{ok:boolean, reason?:string, facts?:object}>}
 *   req: { solSignature, sender, depositAccount, lamports, destChainId, destAddress }
 */
export function makeSolSourceVerifier(cfg = {}) {
  return async function verifySolSource(req) {
    if (!cfg.solanaRpc) return { ok: false, reason: "validator has no Solana RPC configured" };
    let Connection, PublicKey;
    try { ({ Connection, PublicKey } = cfg.solanaModule || (await import("@solana/web3.js"))); }
    catch { return { ok: false, reason: "@solana/web3.js not available on this validator" }; }
    const deposit = String(req.depositAccount || "");
    if (cfg.depositAccount && deposit !== cfg.depositAccount) return { ok: false, reason: "recipient is not this validator's configured Settlin deposit account" };
    let lamports, destChainId;
    try { lamports = BigInt(req.lamports); destChainId = BigInt(req.destChainId); } catch { return { ok: false, reason: "bad lamports / destChainId" }; }
    if (lamports <= 0n) return { ok: false, reason: "zero lamports" };
    const destAddress = String(req.destAddress || "");
    if (!destAddress || destAddress.includes("|")) return { ok: false, reason: "bad destination address" };

    const conn = new Connection(cfg.solanaRpc, "finalized");
    let tx;
    try { tx = await conn.getTransaction(String(req.solSignature), { commitment: "finalized", maxSupportedTransactionVersion: 0 }); }
    catch (e) { return { ok: false, reason: `solana getTransaction failed: ${e.message}` }; }
    if (!tx) return { ok: false, reason: "deposit not found at FINALIZED commitment (not finalized, or never landed)" };
    if (tx.meta?.err) return { ok: false, reason: `deposit failed on-chain: ${JSON.stringify(tx.meta.err)}` };

    let keys;
    try {
      const m = tx.transaction.message;
      keys = m.getAccountKeys ? m.getAccountKeys({ accountKeysFromLookups: tx.meta?.loadedAddresses }).keySegments().flat() : m.accountKeys;
    } catch { keys = tx.transaction.message.staticAccountKeys || tx.transaction.message.accountKeys || []; }
    const b58 = (k) => String(k?.toBase58?.() ?? k);
    const msg = tx.transaction.message;
    const nSigners = Number(msg.header?.numRequiredSignatures ?? 1);
    const senderIdx = keys.findIndex((k) => b58(k) === String(req.sender));
    if (senderIdx < 0 || senderIdx >= nSigners) return { ok: false, reason: "the funding account did not sign the deposit" };

    const ixs = msg.compiledInstructions || msg.instructions || [];
    const accts = (ix) => ix.accountKeyIndexes || ix.accounts || [];
    const data = (ix) => (typeof ix.data === "string" ? Buffer.from(ethers.getBytes(ethers.toBeHex(ethers.decodeBase58(ix.data)))) : Buffer.from(ix.data));
    // Exactly one System transfer (the circuit reads the transfer instruction; more than one would be ambiguous).
    const transfers = ixs.filter((ix) => b58(keys[ix.programIdIndex]) === SYSTEM_PROGRAM && data(ix).length >= 12 && data(ix).readUInt32LE(0) === 2);
    if (transfers.length !== 1) return { ok: false, reason: `deposit must contain exactly one SOL transfer (found ${transfers.length})` };
    const t = transfers[0], td = data(t);
    const from = b58(keys[accts(t)[0]]), to = b58(keys[accts(t)[1]]), amt = td.readBigUInt64LE(4);
    if (from !== String(req.sender)) return { ok: false, reason: "transfer is not from the funding account" };
    if (to !== deposit) return { ok: false, reason: "transfer is not into the Settlin deposit account" };
    if (amt !== lamports) return { ok: false, reason: `transfer moved ${amt} lamports, not ${lamports}` };
    // Exactly one memo, exactly GHOST|<destChainId>|<destAddress> (token memos are refused — v11 C-01).
    const memos = ixs.filter((ix) => MEMO_PROGRAM_IDS.has(b58(keys[ix.programIdIndex])));
    if (memos.length !== 1) return { ok: false, reason: `deposit must carry exactly one memo (found ${memos.length})` };
    if (data(memos[0]).toString("utf8") !== `GHOST|${destChainId}|${destAddress}`) return { ok: false, reason: "memo does not match the claimed destination" };
    // The deposit account's balance really rose by at least the transfer.
    const di = keys.findIndex((k) => b58(k) === deposit);
    if (di < 0 || BigInt(tx.meta.postBalances[di]) - BigInt(tx.meta.preBalances[di]) < lamports) return { ok: false, reason: "deposit account balance did not increase by the transfer" };

    let senderHex, depositHex;
    try { senderHex = ethers.hexlify(new PublicKey(String(req.sender)).toBytes()); depositHex = ethers.hexlify(new PublicKey(deposit).toBytes()); }
    catch { return { ok: false, reason: "bad Solana pubkey" }; }
    return { ok: true, facts: {
      nullifier: solNullifier(req.solSignature), sender: senderHex, recipient: depositHex, lamports,
      destChainId, destAddrHash: ethers.keccak256(ethers.toUtf8Bytes(destAddress)),
    } };
  };
}
