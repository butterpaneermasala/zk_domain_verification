# Email domain verification (headers + optional on-chain)

This fork adds a privacy-first flow to prove you control an email at a given domain using only delivered headers and a tiny commitment (H = sha256(padded secret)). You can optionally mint a non-transferable on-chain badge once verified.

What’s included:

- Smart contract: `packages/foundry/contracts/DomainBadge.sol` (ERC-1155 SBT)
- API routes (Next.js):
  - POST `/api/session` → start session, get nonce
  - POST `/api/verify-dkim-headers` → verify delivered headers via DKIM, exact domain match, nonce-in-Subject
  - POST `/api/prove-secret` → compute H from your secret (toggle ZK enforcement later)
  - POST `/api/issue-mint-auth` → issuer-signed EIP-712 auth for on-chain mint
- Frontend page: `/headers-verify-mint` runs the whole flow; mint is optional.

Environment:

- `ISSUER_PK` (Next.js server): EOA private key to sign mint authorizations
- `CHAIN_ID` (default 31337) and `BADGE_CONTRACT` (optional): to bind EIP-712 domain
- `ENFORCE_ZK` (default `false`): set `true` only after wiring SNARK artifacts

Quickstart:

```bash
# 1) Install deps
cd emailverify
yarn install

# 2) Start chain (Foundry)
yarn chain

# 3) Deploy DomainBadge (uses broadcaster as issuer/owner by default)
yarn foundry:deploy --script DeployDomainBadge

# 4) Start frontend (set ISSUER_PK in packages/nextjs/.env.local)
yarn start

# 5) Open http://localhost:3000/headers-verify-mint
```

Notes:

- On-chain mint is optional. You can use the issuer-signed authorization off-chain if preferred.
- ZK step is modeled as a commitment H today; SNARK verification can be enabled via `ENFORCE_ZK=true` after generating artifacts.

ZK enforcement (optional):

1) See `packages/zk/README.md` for generating ptau, compiling the circuit, creating the zkey, and copying the verification key.
2) After running those steps, set `ENFORCE_ZK=true` in `packages/nextjs/.env.local` and restart the Next.js server.
3) The UI will accept a proof generated with `snarkjs.groth16.fullProve` using the circuit at `packages/zk/build/commit64_sha256_js/commit64_sha256.wasm` and `packages/zk/build/commit64_final.zkey`.
