# Working in toolgate

Part of the Conker workspace; read the workspace `AGENTS.md` (two levels up from `gates/toolgate`) first. It holds the shared rules for every model.

`toolgate` is the only action path: approvals, spending, tools. It is a headless gate with its own repo, CI and release tags.

## Rules
- Branch per unit of work; never commit to `main`, never force-push. Merge when CI is green.
- Keep to the files the task allows. No scope creep.
- Security-critical code (approvals, spending, auth, vault, forgetting, access policy, backup) is written by Claude, with a real test.
- The repo is public: no keys, passwords, hostnames or Tailscale addresses.
- Never edit `CHANGELOG.md` in a feature PR unless the task says so.

## Checks (run before a PR; CI runs the same)
- Tests: `python -m pytest toolgate/tests/ --ignore=toolgate/tests/test_module_contract.py -q`
- Other checks: `python toolgate/scripts/check_file_sizes.py; python toolgate/scripts/check_package_boundaries.py; python toolgate/scripts/check_types.py; python toolgate/scripts/export_openapi.py --check; python toolgate/scripts/mutation_check.py`
- Lint and format: `ruff check .` and `ruff format --check .`; hooks in `.pre-commit-config.yaml`.

## Limits
- Every source file stays under 600 lines (`file-size-allowlist.txt` may only shrink).
- `package-boundaries.txt` lists the allowed cross-package edges; the list only shrinks.
- `type-baseline.txt` (where present) may only shrink; coverage floors only rise.

## Docs
`docs/`. Decisions and status live in the workspace `context/master-plan.md`.
