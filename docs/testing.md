# Testing ToolGate

The deterministic suite, the mutation check that proves the tests catch broken behaviour, and the live boundary verifier.

## Verification

Install the pinned API requirements and pytest, then run the behavioral suite:

```powershell
python -m pytest toolgate/tests --ignore=toolgate/tests/test_module_contract.py -q
```

Prove the A2/B5 tests detect broken behavior in disposable source copies:

```powershell
python toolgate/scripts/mutation_check.py
```

Run one file:

```powershell
python -m unittest toolgate.tests.test_approval_boundary -v
```

The suite is not all in-memory: the approval binding is driven over the ASGI app against a real SQLite database -- including a twelve-thread race that must produce exactly one success -- and `/health` is checked against an upstream that is genuinely stopped mid-test.

With both Docker stacks running, execute the live boundary verifier. It reads vault values through the vault rather than parsing `.env`, so it has to run where the vault key is — inside the API container:

```powershell
Set-Location toolgate
docker compose exec api python toolgate/scripts/verify_v2.py
```

The live verifier creates temporary namespaced capabilities and keys, tests executors, workflows, scope isolation, exact approvals, callback replay resistance, redaction, and lockdown, then removes its temporary objects.
