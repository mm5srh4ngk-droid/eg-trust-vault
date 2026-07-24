# eg-trust-vault — external trust root for the held-out council eval

This repo is the **vault**: the only place a *gating-authoritative* grade for the held-out
council eval can be minted. The answer key (salt + verdict labels) exists ONLY as GitHub
Actions secrets on the vault owner's environment — no machine that runs the council holds it.

## Custody rules (the whole point)
- The vault account is browser-only, owned by the human operator. The council machine holds
  ZERO credentials for it and is NOT a collaborator (its push MUST fail — that failure is
  re-provable at any time and is the certificate).
- Rounds are submitted by **opening an issue** (no write access needed). The scoring workflow
  parses the issue as UNTRUSTED DATA, scores against the secret answer key on GitHub's servers,
  appends a hash-chained checkpoint, and comments the verdict.
- **Case names never appear here.** A round references each case only by its salted commitment
  hash — meaningless without the vault-held salt.
- Every checkpoint chains to the previous (prev-hash + self-hash). History cannot be quietly
  rewritten; `verifier/verify-chain.mjs` proves integrity from any read-only clone.
- Failure of anything = the eval **stays advisory**. Never a false green.

## Secrets (vault environment `trust-truth`)
- `TRUTH_SALT` — the commitment salt.
- `TRUTH_VERDICTS_B64` — base64 JSON array: `[{"case":"...","verdict":"SHIP|FIX-FIRST|BLOCK","cls":"good|bad"}]`.

## Round submission format (issue body)
````
```json
{"run_id":"YYYY-MM-DD-heldout-sN","entries":[{"commit":"<sha256 hex>","council":"SHIP|FIX-FIRST|BLOCK"}]}
```
````
