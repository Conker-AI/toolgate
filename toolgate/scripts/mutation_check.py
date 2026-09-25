"""Prove boundary tests detect broken authority, archival and approval integrity, in disposable copies.

Run from the repository root: python toolgate/scripts/mutation_check.py
No live source, database, vault, or gate configuration is modified.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MCP = "toolgate/tests/test_mcp_adapter.py::"
ARCHIVE = "toolgate/tests/test_execution_boundary.py::"
INTEGRITY = "toolgate/tests/test_approval_integrity.py::"

# A mutant counts as caught only when its named behavioral test fails, never
# when collection fails or the subprocess cannot start.
MUTANTS = [
    (
        "catalogue scope bypass",
        "toolgate/api/server.py",
        'if tool.get("status") == "active" and control_plane.is_scoped(agent, tool["id"])]',
        'if tool.get("status") == "active"]',
        MCP + "test_scoped_catalogue_and_direct_call_cannot_escape",
    ),
    (
        "invocation scope bypass",
        "toolgate/api/server.py",
        'if tool.get("status") != "active" or not control_plane.is_scoped(agent, tool_id):',
        'if tool.get("status") != "active":',
        MCP + "test_scoped_catalogue_and_direct_call_cannot_escape",
    ),
    (
        "request identity bypass",
        "toolgate/api/server.py",
        'if not request or request.get("payload", {}).get("created_by_agent_key") != agent["id"]:',
        "if not request:",
        MCP + "test_approvals_keep_identity_arguments_and_single_consumption",
    ),
    (
        "partial archive commit",
        "toolgate/core/legacy_archive.py",
        "        for row in retired:\n",
        "        for row in retired:\n            conn.commit()\n",
        ARCHIVE + "test_archive_failure_rolls_back_every_retained_record",
    ),
    (
        "lossy archive",
        "toolgate/core/legacy_archive.py",
        "original = json.dumps(row, ensure_ascii=False, sort_keys=True)",
        'original = json.dumps({**row, "body": "{}"}, ensure_ascii=False, sort_keys=True)',
        ARCHIVE + "test_archive_export_is_lossless_idempotent_and_owner_only",
    ),
    (
        "AI route restored",
        "toolgate/api/server.py",
        '@app.get("/v2/archives/ai")',
        '@app.post("/v2/ai/conversation")\n@app.get("/v2/archives/ai")',
        ARCHIVE + "test_startup_retires_ai_routes_and_preserves_other_tools",
    ),
    (
        "credential redirect enabled",
        "toolgate/mcp/toolgate_mcp.py",
        "follow_redirects=False",
        "follow_redirects=True",
        MCP + "test_transport_never_follows_redirects_or_retries[302]",
    ),
    (
        "forged verification accepted through generic requests",
        "toolgate/core/control_plane.py",
        "if kind not in INFORMATIONAL_REQUEST_KINDS:",
        'if kind not in INFORMATIONAL_REQUEST_KINDS and kind != "verification":',
        INTEGRITY + "test_execution_key_cannot_forge_approval_text_or_binding",
    ),
    (
        "stale decision overwrites consumption",
        "toolgate/core/control_plane.py",
        """    with _conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM v2_objects WHERE kind='request' AND id=?", (request_id,)).fetchone()
        if not row:
            return None
        record = _row(row)
        if record.get("status") != "pending":""",
        """    record = get("request", request_id)
    if not record:
        return None
    with _conn() as conn:
        if record.get("status") != "pending":""",
        INTEGRITY + "test_late_decision_cannot_restore_a_consumed_token",
    ),
    (
        "bootstrap resurrects revoked authority",
        "toolgate/core/control_plane.py",
        "            return public_agent_key(existing)",
        """            conn.execute("UPDATE v2_agent_keys SET scopes=?,status='active' WHERE id=?",
                         (json.dumps(normalized_scopes), existing["id"]))
            return public_agent_key(conn.execute("SELECT * FROM v2_agent_keys WHERE id=?", (existing["id"],)).fetchone())""",
        INTEGRITY + "test_restart_never_widens_or_revives_bootstrap_key",
    ),
]

MUTANTS.extend([('dispatch without a committed record',
  'toolgate/core/execution_journal.py',
  ('# The context manager commits before the caller can enter its executor.\n'
  '        return _row(row), True'),
  ('# The context manager commits before the caller can enter its executor.\n'
  '        conn.rollback()\n'
  '        return _row(row), True'),
  'toolgate/tests/test_execution_journal.py::test_dispatch_is_durable_before_external_effect_and_replay_is_cached'),
 ('arguments excluded from action identity',
  'toolgate/core/execution_journal.py',
  '[subject_type, subject_id, args, actor_id, job_id, parent_action_id]',
  '[subject_type, subject_id, {}, actor_id, job_id, parent_action_id]',
  'toolgate/tests/test_execution_journal.py::test_reusing_identity_with_different_arguments_fails'),
 ('actor excluded from action identity',
  'toolgate/core/execution_journal.py',
  '[subject_type, subject_id, args, actor_id, job_id, parent_action_id]',
  '[subject_type, subject_id, args, "shared", job_id, parent_action_id]',
  'toolgate/tests/test_execution_journal.py::test_identity_includes_actor_and_parent_job'),
 ('restart misreports uncertain dispatch',
  'toolgate/core/execution_journal.py',
  '" WHERE status=\'dispatching\'", (time.time(),)).rowcount',
  '" WHERE status=\'never\'", (time.time(),)).rowcount',
  'toolgate/tests/test_execution_journal.py::test_interruption_after_external_effect_is_unknown_and_never_retried'),
 ('lost cached receipt',
  'toolgate/core/execution_journal.py',
  'if record["response"] is not None:',
  'if False:',
  'toolgate/tests/test_execution_journal.py::test_dispatch_is_durable_before_external_effect_and_replay_is_cached'),
 ('approval committed before budget reservation',
  'toolgate/core/execution_journal.py',
  '        if reserve:\n            reserve(conn)',
  '        if reserve:\n            conn.commit()\n            reserve(conn)',
  'toolgate/tests/test_spending.py::test_budget_denial_rolls_back_approval_and_dispatch_together'),
 ('workflow retries uncertain dispatch',
  'toolgate/api/server.py',
  'if result.get("code") in {"OUTCOME_UNKNOWN", "IN_PROGRESS"}:',
  'if False:',
  'toolgate/tests/test_execution_journal.py::test_workflow_retry_block_never_repeats_uncertain_child'),
 ('action status disclosed to another agent',
  'toolgate/api/server.py',
  'if not record or record["actor_id"] != agent["id"]:',
  'if not record:',
  'toolgate/tests/test_execution_journal.py::test_status_is_visible_only_to_owner_or_originating_agent'),
 ('paid reservation omitted before dispatch',
  'toolgate/core/spending.py',
  '    reserved = amount(price, price["max_input_tokens"], price["max_output_tokens"])',
  '    return\n    reserved = amount(price, price["max_input_tokens"], price["max_output_tokens"])',
  'toolgate/tests/test_spending.py::test_reservation_precedes_network_reconciles_and_replay_does_not_charge'),
 ('workflow child job ceiling bypass',
  'toolgate/core/spending.py',
  'or job_used + reserved > job["cap"]:',
  ':',
  'toolgate/tests/test_spending.py::test_workflow_children_share_job_ceiling_and_cannot_resume_partial_run'),
 ('cumulative ceiling bypass',
  'toolgate/core/spending.py',
  'used + reserved > policy["cumulative_cap"] or ',
  '',
  'toolgate/tests/test_spending.py::test_concurrent_jobs_cannot_overbook_cumulative_cap'),
 ('refund missing billing telemetry',
  'toolgate/core/spending.py',
  '# Missing billing telemetry is never interpreted as a free request.\n        return',
  ('# Missing billing telemetry is never interpreted as a free request.\n'
  '        conn.execute("UPDATE v2_spend_reservations SET accounted=0 WHERE action_id=?", '
  '(action_id,))\n'
  '        return'),
  'toolgate/tests/test_spending.py::test_uncertain_billing_keeps_reservation_across_restart[missing_usage]'),
 ('known actual usage ignored',
  'toolgate/core/spending.py',
  '(actual, action_id))',
  '(row["reserved"], action_id))',
  'toolgate/tests/test_spending.py::test_reservation_precedes_network_reconciles_and_replay_does_not_charge'),
 ('pricing expiry ignored at quotation',
  'toolgate/core/spending.py',
  'if not price or price["valid_until"] <= time.time():',
  'if not price:',
  'toolgate/tests/test_spending.py::test_quote_requires_enabled_policy_and_current_known_price[expired]'),
 ('paid policy ignored at quotation',
  'toolgate/core/spending.py',
  'if not policy or not policy["enabled"]:\n            raise BudgetDenied("Paid routes',
  'if not policy:\n            raise BudgetDenied("Paid routes',
  'toolgate/tests/test_spending.py::test_quote_requires_enabled_policy_and_current_known_price[disabled]'),
 ('unknown HTTP billing allowed',
  'toolgate/api/server.py',
  'if kind == "http_json" and execution.get("billing") != {"mode": "free"}:',
  'if False:',
  'toolgate/tests/test_spending.py::test_unaccounted_paid_routes_never_reach_network[http_json]'),
 ('delegated billing allowed',
  'toolgate/api/server.py',
  'if kind == "memorygate" and execution.get("operation") != "context":',
  'if False:',
  'toolgate/tests/test_spending.py::test_unaccounted_paid_routes_never_reach_network[memorygate]'),
 ('paid Tavily fallback reenabled',
  'toolgate/executors/research.py',
  ('    raise ResearchError("Tavily is disabled until it has a bounded spending adapter; use '
  'SearXNG")'),
  '    return _tavily_unmetered(query, source, limit, recency_days, timeout)',
  'toolgate/tests/test_spending.py::test_unaccounted_paid_routes_never_reach_network[tavily]'),
 ('thinking enabled on bounded paid request',
  'toolgate/api/server.py',
  '"thinkingConfig": {"thinkingBudget": 0}',
  '"thinkingConfig": {"thinkingBudget": 512}',
  'toolgate/tests/test_spending.py::test_reservation_precedes_network_reconciles_and_replay_does_not_charge'),
 ('provider bound violation does not freeze paid dispatch',
  'toolgate/core/spending.py',
  '        conn.execute("UPDATE v2_spend_policy SET enabled=0 WHERE id=1")\n        actual = max(actual, row["reserved"])',
  '        actual = max(actual, row["reserved"])',
  'toolgate/tests/test_spending.py::test_provider_bound_violation_disables_further_paid_dispatch'),
 ('approval committed before journal insert',
  'toolgate/core/execution_journal.py',
  '        if authorize:\n            authorize(conn)',
  '        if authorize:\n            authorize(conn)\n            conn.commit()',
  'toolgate/tests/test_execution_journal.py::test_failed_journal_commit_cannot_dispatch_or_consume_approval'),
 ('job actor binding removed',
  'toolgate/core/spending.py',
  'if not job or job["actor_id"] != actor_id:',
  'if not job:',
  'toolgate/tests/test_spending.py::test_job_cannot_be_reused_by_another_agent_or_root[impostor-root]'),
 ('job root binding removed',
  'toolgate/core/spending.py',
  'if root != job["root_action_id"]:',
  'if False:',
  'toolgate/tests/test_spending.py::test_job_cannot_be_reused_by_another_agent_or_root[agent-another]'),
 ('execution record deletion allowed',
  'toolgate/core/execution_journal.py',
  'CREATE TRIGGER IF NOT EXISTS v2_actions_no_delete BEFORE DELETE ON v2_actions',
  'CREATE TRIGGER IF NOT EXISTS v2_actions_no_delete BEFORE DELETE ON v2_actions WHEN 0',
  'toolgate/tests/test_execution_journal.py::test_completed_receipt_cannot_be_replaced_or_deleted'),
 ('reservation deletion allowed',
  'toolgate/core/spending.py',
  ('CREATE TRIGGER IF NOT EXISTS v2_spend_reservations_no_delete BEFORE DELETE ON '
  'v2_spend_reservations'),
  ('CREATE TRIGGER IF NOT EXISTS v2_spend_reservations_no_delete BEFORE DELETE ON '
  'v2_spend_reservations WHEN 0'),
  'toolgate/tests/test_spending.py::test_reservations_and_job_identity_cannot_be_erased'),
 ('budget policy accessible to execution key',
  'toolgate/api/server.py',
  'def spending_policy(payload: SpendPolicy, _tier: str = Depends(require_admin)):',
  'def spending_policy(payload: SpendPolicy, _tier: dict = Depends(require_agent)):',
  'toolgate/tests/test_spending.py::test_owner_only_can_set_caps_prices_and_mint_jobs'),
 ('budget jobs accessible to execution key',
  'toolgate/api/server.py',
  'def spending_job(payload: SpendJob, _tier: str = Depends(require_admin)):',
  'def spending_job(payload: SpendJob, _tier: dict = Depends(require_agent)):',
  'toolgate/tests/test_spending.py::test_owner_only_can_set_caps_prices_and_mint_jobs'),
 ('child spending job omitted',
  'toolgate/api/server.py',
  'job_id=state.get("job_id"), parent_action_id=parent_id)',
  'job_id=None, parent_action_id=parent_id)',
  'toolgate/tests/test_spending.py::test_workflow_children_share_job_ceiling_and_cannot_resume_partial_run'),
 ('stale quote accepted after owner price refresh',
  'toolgate/core/spending.py',
  'if not current_price or any(price[key] != current_price[key] for key in current_price.keys()):',
  'if False:',
  'toolgate/tests/test_spending.py::test_price_change_before_reservation_cannot_use_old_rates')])


MUTANTS.extend([
    ("automation child binding omitted", "toolgate/core/control_plane.py",
     'if binding.get("child_tools") != current:', 'if False:',
     "toolgate/tests/test_automation_approval.py::test_changed_child_invalidates_approval_without_consumption"),
    ("automation child snapshot discarded", "toolgate/api/server.py",
     '"tool_snapshot": tool_snapshot,', '',
     "toolgate/tests/test_automation_approval.py::test_edit_after_consumption_cannot_replace_pinned_child"),
])


MUTANTS.extend([
    ("worker-can-release-spending", "toolgate/api/server.py",
     'def release_reservation(action_id: str, payload: ReservationRelease, _tier: str = Depends(require_admin)):',
     'def release_reservation(action_id: str, payload: ReservationRelease, _tier: dict = Depends(require_agent)):',
     "toolgate/tests/test_reservation_release.py::test_owner_release_frees_local_hold_without_allowing_redispatch"),
    ("release-ignores-live-dispatch", "toolgate/core/spending.py",
     'or action["status"] != "outcome_unknown"', '',
     "toolgate/tests/test_reservation_release.py::test_release_requires_owner_evidence_and_inactive_dispatch"),
    ("released-hold-still-consumes-budget", "toolgate/core/spending.py",
     'THEN 0 ELSE r.reserved END', 'THEN r.reserved ELSE r.reserved END',
     "toolgate/tests/test_reservation_release.py::test_owner_release_frees_local_hold_without_allowing_redispatch"),
    ("late-reply-does-not-dispute-release", "toolgate/core/spending.py",
     'if conn.execute("SELECT 1 FROM v2_spend_releases WHERE action_id=?", (action_id,)).fetchone():',
     'if False:', "toolgate/tests/test_reservation_release.py::test_late_reply_disputes_release_and_restores_budget_hold"),
])


def run_tests(root: Path, tests: list[str], name: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONPATH": str(root), "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            *tests,
            "-q",
            "--tb=short",
            "-p",
            "no:cacheprovider",
            f"--basetemp={root / name}",
        ],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="toolgate-mutations-") as directory:
        root = Path(directory)
        for source in (ROOT / "toolgate").rglob("*.py"):
            destination = root / source.relative_to(ROOT)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
        baseline = run_tests(root, sorted({m[4] for m in MUTANTS}), "baseline")
        if baseline.returncode:
            print(baseline.stdout + baseline.stderr)
            print("Baseline failed; fix the behavior before testing mutations.")
            return 1
        print("Baseline passed", flush=True)
        for index, (label, file, before, after, test) in enumerate(MUTANTS):
            path = root / file
            original = path.read_text(encoding="utf-8")
            if original.count(before) != 1:
                raise RuntimeError(
                    f"Mutation anchor changed: {label}. Update the drill before relying on it."
                )
            path.write_text(original.replace(before, after), encoding="utf-8")
            try:
                result = run_tests(root, [test], f"mutant-{index}")
            finally:
                path.write_text(original, encoding="utf-8")
            if result.returncode != 1 or f"FAILED {test}" not in result.stdout:
                print(result.stdout + result.stderr)
                print(f"NOT CAUGHT: {label}")
                return 1
            print(f"Caught: {label}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
