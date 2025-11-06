Place your Groth16 verification key JSON here as `verification_key.json`.

Expected env:
- ENFORCE_ZK=true
- ZK_VK_PATH (optional): absolute path to your verification key; defaults to this folder's verification_key.json

The `/api/prove-secret` endpoint will verify `{proof, publicSignals}` against this key and return `{ok: true, hHex}`.

Note: publicSignals mapping -> hHex assumes the first signal encodes H. If your circuit emits a different shape, adjust the API route.
