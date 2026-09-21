# Restored action journal reconciliation

Keep the authoritative service and the isolated recovery service stopped during this operation. Preserve both databases. The source must be the operator-verified newest journal from the same installation; this utility cannot prove that an arbitrary file is the latest backup.

Run from the ToolGate environment:

```sh
python -m toolgate.core.recovery_journal --source /recovery/current.db --target /recovery/restored.db
```

The source is opened read-only. The target receives a persistent recovery hold before journal validation. Reconciliation requires coverage of every restored action identity, compatible timestamps, valid fingerprints, parent coverage, and matching previously completed receipts. Conflicts roll back receipt changes and retain the hold. Completed authoritative receipts and post-backup actions are stored in an overlay; immutable original execution records remain intact. Interrupted actions remain outcome-unknown. Repeated reconciliation is idempotent.

Journal reads and cached replays consult the overlay. New dispatches are blocked and service startup refuses a held database before migration, credential generation, or bootstrap. No action is executed by reconciliation. Output contains action identifiers and counts, never arguments or response bodies.

This is evidence reconciliation, not recovery promotion. It does not reconcile spending, external state, credentials, or other services. Do not remove the hold to start production. Those checks and coordinated recovery promotion are still required. Do not run against a live service: this offline utility does not acquire a service process lease.
