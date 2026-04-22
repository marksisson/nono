# Manual Test Steps

This file is a practical smoke-test guide for the current audit, integrity, rollback, and signing behavior in `nono`.

Assumptions:

- You are running from the repository root.
- You have a built CLI available via `nn ...` or `./target/debug/nono ...`.
- The examples below use `nn` for clarity.

## 1. Basic Audit Session

Run a simple supervised command:

```bash
nn run --allow-cwd -- /bin/pwd
```

Then inspect audit history:

```bash
nn audit list
nn audit show <session-id>
nn audit show <session-id> --json
```

Expected:

- The session appears in `audit list`.
- `audit show --json` includes:
  - `command`
  - `tracked_paths`
  - `audit_event_count`
  - `audit_integrity`
- `tracked_paths` should include the current working directory when it is in scope.

## 2. Disable Audit Entirely

```bash
nn run --no-audit --allow-cwd -- /bin/pwd
```

Expected:

- No new session should appear in `audit list`.

## 3. Disable Audit Integrity Only

```bash
nn run --no-audit-integrity --allow-cwd -- /bin/pwd
nn audit show <session-id> --json
```

Expected:

- The session exists.
- `audit_integrity` is `null`.
- Session metadata is still present.

## 4. Filesystem Integrity

Run with filesystem hashing enabled:

```bash
nn run --audit-integrity --allow-cwd -- /bin/pwd
nn audit show <session-id> --json
```

Expected:

- `tracked_paths` is populated.
- `merkle_roots` contains pre/post filesystem roots.
- `audit_integrity` is present.

## 5. Rollback Session

Create a test file:

```bash
printf 'before\n' > ./manual-test.txt
```

Run a rollback-enabled session that changes it:

```bash
nn run --rollback --no-rollback-prompt --allow-cwd -- /bin/sh -lc "printf 'after\n' > ./manual-test.txt"
```

Inspect:

```bash
nn rollback list --all
nn rollback show <session-id> --json
```

Expected:

- The rollback session appears in `rollback list --all`.
- `rollback show --json` includes snapshot metadata.
- The same session should also appear in audit history.

## 6. Audit Verify

Verify a session with audit integrity enabled:

```bash
nn audit verify <session-id>
nn audit verify <session-id> --json
```

Expected:

- Session-local audit verification passes.
- Ledger inclusion verification passes.
- The JSON output reports the computed values and verification status.

## 7. Signed Audit Session

Generate a local file-backed signing key:

```bash
mkdir -p .tmp-test-keys
nn trust keygen --force --keyref "file://$PWD/.tmp-test-keys/audit-signing.key"
```

Run a signed session:

```bash
nn run --audit-sign-key "file://$PWD/.tmp-test-keys/audit-signing.key" --allow-cwd -- /bin/pwd
```

Inspect:

```bash
nn audit show <session-id>
nn audit show <session-id> --json
```

Expected:

- The audit session directory contains `audit-attestation.bundle`.
- `audit show --json` includes `audit_attestation`.
- Human-readable output shows the signer key id.

## 8. Signed Audit Verification With Public Key Pinning

Verify the signed session with the generated public key:

```bash
nn audit verify <session-id> --public-key-file "$PWD/.tmp-test-keys/audit-signing.key.pub"
nn audit verify <session-id> --public-key-file "$PWD/.tmp-test-keys/audit-signing.key.pub" --json
```

Expected:

- Signature verification passes.
- Public key pinning passes.
- JSON output reports attestation verification as successful.

## 9. Rollback + Signed Audit Together

```bash
nn run --rollback --no-rollback-prompt --audit-sign-key "file://$PWD/.tmp-test-keys/audit-signing.key" --allow-cwd -- /bin/pwd
```

Inspect both stores:

```bash
ls ~/.nono/audit/<session-id>
ls ~/.nono/rollbacks/<session-id>
nn audit verify <session-id>
```

Expected:

- The attestation bundle exists under `~/.nono/audit/<session-id>/`.
- The session also has rollback state under `~/.nono/rollbacks/<session-id>/`.
- `audit verify` succeeds using the audit copy of the attestation bundle.

## 10. Cleanup Commands

Audit cleanup:

```bash
nn audit cleanup
```

Rollback cleanup:

```bash
nn rollback cleanup --all
```

Session cleanup:

```bash
nn session cleanup
```

Expected:

- Each command only cleans its own store.
- Audit cleanup does not remove rollback-backed history from rollback storage.
- Rollback cleanup removes rollback entries.

## 11. CI Check

Run the full repository check:

```bash
make ci
```

Expected:

- Clippy passes.
- Formatting check passes.
- Workspace tests pass.
- `cargo audit` passes.

## 12. Optional Negative Checks

Wrong public key:

```bash
nn trust keygen --force --keyref "file://$PWD/.tmp-test-keys/other.key"
nn audit verify <session-id> --public-key-file "$PWD/.tmp-test-keys/other.key.pub"
```

Expected:

- Attestation verification should report a key mismatch or failed pinning.

No audit integrity:

```bash
nn run --no-audit-integrity --allow-cwd -- /bin/pwd
nn audit verify <session-id>
```

Expected:

- Verification should report that the session lacks integrity metadata.

## Notes

- `audit verify` verifies one session and its ledger inclusion. It does not prove remote or externally anchored attestation by itself.
- `--audit-sign-key` signs once per session, at session finalization. It does not sign each event individually.
- Executable hashing currently covers the main resolved executable path and SHA-256 of that binary, not the full interpreter or shared library closure.
