# settlin-validator

An **independent delivery-attestation validator** for the Settlin bridge (audit finding **C-01**).

Each validator in the bridge's m-of-n delivery quorum runs one of these, **on its own host, with its own
signing key and its own RPC endpoints**. The Settlin relayer holds no validator key and cannot sign on a
validator's behalf — it can only ask, over HTTP, and each validator decides for itself after checking the
payout on its own node.

> Compromising the relayer yields **zero** validator signatures. Compromising one validator yields exactly
> **one** — below the threshold. No single party can forge a quorum.

This package is standalone and public **on purpose**: an independent operator needs no access to the
private bridge repo, and anyone can audit exactly what a validator runs. It contains no secrets.

## What it does

`POST /attest` (bearer-token gated) runs, on your own machine:

1. **Bind-check** — recompute the hashed digest fields from the raw delivery facts and require they match
   what the signature will commit to (`recipient = keccak256(raw.recipient)`, etc.).
2. **On-chain check** — look up the destination tx on **your own** RPC and confirm it delivered `>=` the
   amount to the recipient at the required finality (native SOL and native EVM payouts supported).
3. **Sign** — read the authoritative digest from the on-chain `DeliveryAttestor` and sign it with your own
   key. Return `{ validator, signature }`.

Anything it cannot positively verify is declined (`409`). It custodies nothing and governs nothing.

Endpoints: `GET /identity` → `{address}`, `GET /health` → counters, `POST /attest`.

## Run it

```bash
cp .env.example .env     # fill in VALIDATOR_KEY (generate below), your RPCs, a random auth token
npm install
npm start
```

Generate your signing key **on this host** (never share it):

```bash
node -e "const w=require('ethers').Wallet.createRandom(); console.log('VALIDATOR_KEY='+w.privateKey); console.log('ADDRESS='+w.address)"
```

Send the Settlin relayer operator only your **service URL + auth token + validator address** — never the key.
They register your address on-chain (`DeliveryAttestor.setValidator`) and add your URL to the relayer's
`VALIDATOR_ENDPOINTS`.

### Deploy on Render

New Web Service → this repo → it picks up `render.yaml`. Set the `sync:false` secrets (`VALIDATOR_KEY`,
`ATTESTOR_RPC`, `SOLANA_RPC`, `VALIDATOR_AUTH_TOKEN`) in the dashboard. Use your **own** RPC providers.

## Env

| var | required | notes |
|---|---|---|
| `VALIDATOR_KEY` | yes | your own signing key; stays only here |
| `DELIVERY_ATTESTOR_ADDRESS` | yes | `0x3Fb200cFbD2965B72A6210783B0d66051A222CfD` (mainnet) |
| `ATTESTOR_RPC` | yes | your Ethereum RPC (reads the attestor digest) |
| `SOLANA_RPC` | for SOL payouts | your Solana RPC |
| `EVM_RPC_<CHAIN>` | for EVM payouts | e.g. `EVM_RPC_ARBITRUM` |
| `VALIDATOR_AUTH_TOKEN` | recommended | bearer the relayer presents |
| `PORT` / `HOST` | no | default `8800` / `0.0.0.0` |
