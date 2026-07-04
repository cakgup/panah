from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


class JobStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS jobs (
                  id TEXT PRIMARY KEY,
                  scope_type TEXT NOT NULL,
                  scope_label TEXT NOT NULL,
                  target TEXT NOT NULL,
                  note TEXT NOT NULL,
                  status TEXT NOT NULL,
                  progress INTEGER NOT NULL DEFAULT 0,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  module_ids TEXT NOT NULL,
                  logs TEXT NOT NULL,
                  severity_summary TEXT NOT NULL DEFAULT '{}',
                  evidence TEXT NOT NULL DEFAULT '[]',
                  module_runs TEXT NOT NULL DEFAULT '[]',
                  runtime_meta TEXT NOT NULL DEFAULT '{}'
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS assessments (
                  id TEXT PRIMARY KEY,
                  target TEXT NOT NULL,
                  target_kind TEXT NOT NULL,
                  assessment_type TEXT NOT NULL,
                  risk_mode TEXT NOT NULL,
                  operator_name TEXT NOT NULL,
                  ticket_ref TEXT NOT NULL,
                  note TEXT NOT NULL,
                  status TEXT NOT NULL,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  metadata TEXT NOT NULL DEFAULT '{}'
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS approvals (
                  id TEXT PRIMARY KEY,
                  assessment_id TEXT NOT NULL,
                  module_id TEXT NOT NULL,
                  approved_by TEXT NOT NULL,
                  ticket_ref TEXT NOT NULL,
                  reason TEXT NOT NULL,
                  created_at TEXT NOT NULL,
                  expires_at TEXT NOT NULL DEFAULT '',
                  metadata TEXT NOT NULL DEFAULT '{}'
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS findings (
                  id TEXT PRIMARY KEY,
                  assessment_id TEXT NOT NULL,
                  source_key TEXT NOT NULL,
                  target TEXT NOT NULL,
                  title TEXT NOT NULL,
                  severity TEXT NOT NULL,
                  status TEXT NOT NULL,
                  module_id TEXT NOT NULL,
                  module_title TEXT NOT NULL,
                  phase_label TEXT NOT NULL,
                  description TEXT NOT NULL DEFAULT '[]',
                  impact TEXT NOT NULL DEFAULT '[]',
                  recommendations TEXT NOT NULL DEFAULT '[]',
                  evidence_lines TEXT NOT NULL DEFAULT '[]',
                  artifacts TEXT NOT NULL DEFAULT '{}',
                  job_refs TEXT NOT NULL DEFAULT '[]',
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  metadata TEXT NOT NULL DEFAULT '{}',
                  UNIQUE (assessment_id, source_key)
                )
                """
            )

            existing_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(jobs)").fetchall()
            }

            migrations = {
                "progress": "ALTER TABLE jobs ADD COLUMN progress INTEGER NOT NULL DEFAULT 0",
                "severity_summary": "ALTER TABLE jobs ADD COLUMN severity_summary TEXT NOT NULL DEFAULT '{}'",
                "evidence": "ALTER TABLE jobs ADD COLUMN evidence TEXT NOT NULL DEFAULT '[]'",
                "module_runs": "ALTER TABLE jobs ADD COLUMN module_runs TEXT NOT NULL DEFAULT '[]'",
                "runtime_meta": "ALTER TABLE jobs ADD COLUMN runtime_meta TEXT NOT NULL DEFAULT '{}'",
            }

            for column, statement in migrations.items():
                if column not in existing_columns:
                    connection.execute(statement)

            connection.commit()

    def create_job(self, payload: dict[str, Any]) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO jobs (
                  id, scope_type, scope_label, target, note, status, progress,
                  created_at, updated_at, module_ids, logs, severity_summary, evidence, module_runs, runtime_meta
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["id"],
                    payload["scope_type"],
                    payload["scope_label"],
                    payload["target"],
                    payload["note"],
                    payload["status"],
                    payload["progress"],
                    payload["created_at"],
                    payload["updated_at"],
                    json.dumps(payload["module_ids"]),
                    json.dumps(payload["logs"]),
                    json.dumps(payload["severity_summary"]),
                    json.dumps(payload["evidence"]),
                    json.dumps(payload["module_runs"]),
                    json.dumps(payload.get("runtime_meta", {})),
                ),
            )
            connection.commit()

    def list_jobs(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM jobs
                ORDER BY created_at DESC
                """
            ).fetchall()
        return [self._deserialize_job(row) for row in rows]

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM jobs WHERE id = ?",
                (job_id,),
            ).fetchone()
        return self._deserialize_job(row) if row else None

    def update_job(
        self,
        job_id: str,
        *,
        status: str | None = None,
        progress: int | None = None,
        logs: list[dict[str, Any]] | None = None,
        severity_summary: dict[str, int] | None = None,
        evidence: list[dict[str, Any]] | None = None,
        module_runs: list[dict[str, Any]] | None = None,
        runtime_meta: dict[str, Any] | None = None,
        updated_at: str,
    ) -> None:
        current = self.get_job(job_id)
        if not current:
            return

        next_status = status or current["status"]
        next_progress = current["progress"] if progress is None else progress
        next_logs = logs if logs is not None else current["logs"]
        next_severity = severity_summary if severity_summary is not None else current["severity_summary"]
        next_evidence = evidence if evidence is not None else current["evidence"]
        next_module_runs = module_runs if module_runs is not None else current["module_runs"]
        next_runtime_meta = runtime_meta if runtime_meta is not None else current.get("runtime_meta", {})

        with self._connect() as connection:
            connection.execute(
                """
                UPDATE jobs
                SET status = ?, progress = ?, updated_at = ?, logs = ?, severity_summary = ?, evidence = ?, module_runs = ?, runtime_meta = ?
                WHERE id = ?
                """,
                (
                    next_status,
                    next_progress,
                    updated_at,
                    json.dumps(next_logs),
                    json.dumps(next_severity),
                    json.dumps(next_evidence),
                    json.dumps(next_module_runs),
                    json.dumps(next_runtime_meta),
                    job_id,
                ),
            )
            connection.commit()

    def delete_job(self, job_id: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute("DELETE FROM jobs WHERE id = ?", (job_id,))
            connection.commit()
        return int(cursor.rowcount or 0) > 0

    def delete_all_jobs(self) -> int:
        with self._connect() as connection:
            cursor = connection.execute("DELETE FROM jobs")
            connection.commit()
        return int(cursor.rowcount or 0)

    def create_assessment(self, payload: dict[str, Any]) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO assessments (
                  id, target, target_kind, assessment_type, risk_mode, operator_name,
                  ticket_ref, note, status, created_at, updated_at, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["id"],
                    payload["target"],
                    payload["target_kind"],
                    payload["assessment_type"],
                    payload["risk_mode"],
                    payload["operator_name"],
                    payload["ticket_ref"],
                    payload["note"],
                    payload["status"],
                    payload["created_at"],
                    payload["updated_at"],
                    json.dumps(payload.get("metadata", {})),
                ),
            )
            connection.commit()

    def list_assessments(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM assessments ORDER BY created_at DESC"
            ).fetchall()
        return [self._deserialize_assessment(row) for row in rows]

    def get_assessment(self, assessment_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM assessments WHERE id = ?",
                (assessment_id,),
            ).fetchone()
        return self._deserialize_assessment(row) if row else None

    def update_assessment(self, assessment_id: str, *, status: str | None = None, metadata: dict[str, Any] | None = None, updated_at: str) -> None:
        current = self.get_assessment(assessment_id)
        if not current:
            return
        next_status = status or current["status"]
        next_metadata = metadata if metadata is not None else current.get("metadata", {})
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE assessments
                SET status = ?, updated_at = ?, metadata = ?
                WHERE id = ?
                """,
                (next_status, updated_at, json.dumps(next_metadata), assessment_id),
            )
            connection.commit()

    def create_approval(self, payload: dict[str, Any]) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO approvals (
                  id, assessment_id, module_id, approved_by, ticket_ref, reason, created_at, expires_at, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["id"],
                    payload["assessment_id"],
                    payload["module_id"],
                    payload["approved_by"],
                    payload["ticket_ref"],
                    payload["reason"],
                    payload["created_at"],
                    payload.get("expires_at", ""),
                    json.dumps(payload.get("metadata", {})),
                ),
            )
            connection.commit()

    def list_approvals(self, assessment_id: str | None = None) -> list[dict[str, Any]]:
        with self._connect() as connection:
            if assessment_id:
                rows = connection.execute(
                    "SELECT * FROM approvals WHERE assessment_id = ? ORDER BY created_at DESC",
                    (assessment_id,),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM approvals ORDER BY created_at DESC"
                ).fetchall()
        return [self._deserialize_approval(row) for row in rows]

    def get_approval(self, assessment_id: str, module_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM approvals
                WHERE assessment_id = ? AND module_id = ?
                ORDER BY created_at DESC LIMIT 1
                """,
                (assessment_id, module_id),
            ).fetchone()
        return self._deserialize_approval(row) if row else None

    def replace_assessment_findings(self, assessment_id: str, findings: list[dict[str, Any]]) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM findings WHERE assessment_id = ?", (assessment_id,))
            for finding in findings:
                connection.execute(
                    """
                    INSERT INTO findings (
                      id, assessment_id, source_key, target, title, severity, status,
                      module_id, module_title, phase_label, description, impact, recommendations,
                      evidence_lines, artifacts, job_refs, created_at, updated_at, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        finding["id"],
                        assessment_id,
                        finding["source_key"],
                        finding.get("target", ""),
                        finding["title"],
                        finding.get("severity", "INFO"),
                        finding.get("status", "open"),
                        finding.get("module_id", ""),
                        finding.get("module_title", ""),
                        finding.get("phase_label", ""),
                        json.dumps(finding.get("description", [])),
                        json.dumps(finding.get("impact", [])),
                        json.dumps(finding.get("recommendations", [])),
                        json.dumps(finding.get("evidence_lines", [])),
                        json.dumps(finding.get("artifacts", {})),
                        json.dumps(finding.get("job_refs", [])),
                        finding.get("created_at", ""),
                        finding.get("updated_at", ""),
                        json.dumps(finding.get("metadata", {})),
                    ),
                )
            connection.commit()

    def list_findings(self, assessment_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM findings WHERE assessment_id = ? ORDER BY updated_at DESC, severity DESC, title ASC",
                (assessment_id,),
            ).fetchall()
        return [self._deserialize_finding(row) for row in rows]

    def update_finding(self, assessment_id: str, finding_id: str, *, status: str | None = None, metadata: dict[str, Any] | None = None, updated_at: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM findings WHERE assessment_id = ? AND id = ?",
                (assessment_id, finding_id),
            ).fetchone()
            if not row:
                return None
            current = self._deserialize_finding(row)
            next_status = status or current.get("status", "open")
            next_metadata = metadata if metadata is not None else current.get("metadata", {})
            connection.execute(
                "UPDATE findings SET status = ?, metadata = ?, updated_at = ? WHERE assessment_id = ? AND id = ?",
                (next_status, json.dumps(next_metadata), updated_at, assessment_id, finding_id),
            )
            connection.commit()
        return self.get_finding(assessment_id, finding_id)

    def get_finding(self, assessment_id: str, finding_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM findings WHERE assessment_id = ? AND id = ?",
                (assessment_id, finding_id),
            ).fetchone()
        return self._deserialize_finding(row) if row else None

    def _deserialize_job(self, row: sqlite3.Row) -> dict[str, Any]:
        logs = self._normalize_logs(json.loads(row["logs"]))
        severity_summary = self._ensure_dict(json.loads(row["severity_summary"]))
        evidence = self._ensure_list(json.loads(row["evidence"]))
        module_runs = self._ensure_list(json.loads(row["module_runs"]))
        runtime_meta = self._ensure_dict_generic(json.loads(row["runtime_meta"])) if "runtime_meta" in row.keys() else {}

        return {
            "id": row["id"],
            "scope_type": row["scope_type"],
            "scope_label": row["scope_label"],
            "target": row["target"],
            "note": row["note"],
            "status": row["status"],
            "progress": int(row["progress"] or 0),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "module_ids": self._ensure_list(json.loads(row["module_ids"])),
            "logs": logs,
            "severity_summary": severity_summary,
            "evidence": evidence,
            "module_runs": module_runs,
            "runtime_meta": runtime_meta,
        }

    def _deserialize_assessment(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "target": row["target"],
            "target_kind": row["target_kind"],
            "assessment_type": row["assessment_type"],
            "risk_mode": row["risk_mode"],
            "operator_name": row["operator_name"],
            "ticket_ref": row["ticket_ref"],
            "note": row["note"],
            "status": row["status"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "metadata": self._ensure_dict_generic(json.loads(row["metadata"])),
        }

    def _deserialize_approval(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "assessment_id": row["assessment_id"],
            "module_id": row["module_id"],
            "approved_by": row["approved_by"],
            "ticket_ref": row["ticket_ref"],
            "reason": row["reason"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "metadata": self._ensure_dict_generic(json.loads(row["metadata"])),
        }

    def _deserialize_finding(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "assessment_id": row["assessment_id"],
            "source_key": row["source_key"],
            "target": row["target"],
            "title": row["title"],
            "severity": row["severity"],
            "status": row["status"],
            "module_id": row["module_id"],
            "module_title": row["module_title"],
            "phase_label": row["phase_label"],
            "description": self._ensure_list(json.loads(row["description"])),
            "impact": self._ensure_list(json.loads(row["impact"])),
            "recommendations": self._ensure_list(json.loads(row["recommendations"])),
            "evidence_lines": self._ensure_list(json.loads(row["evidence_lines"])),
            "artifacts": self._ensure_dict_generic(json.loads(row["artifacts"])),
            "job_refs": self._ensure_list(json.loads(row["job_refs"])),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "metadata": self._ensure_dict_generic(json.loads(row["metadata"])),
        }

    def _normalize_logs(self, logs: Any) -> list[dict[str, Any]]:
        if not isinstance(logs, list):
            return []

        normalized: list[dict[str, Any]] = []
        for entry in logs:
            if isinstance(entry, dict):
                normalized.append(
                    {
                        "timestamp": str(entry.get("timestamp") or ""),
                        "severity": str(entry.get("severity") or "info"),
                        "message": str(entry.get("message") or ""),
                    }
                )
            else:
                normalized.append(
                    {
                        "timestamp": "",
                        "severity": "info",
                        "message": str(entry),
                    }
                )
        return normalized

    def _ensure_dict(self, value: Any) -> dict[str, int]:
        if not isinstance(value, dict):
            return {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        base = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for key in base:
            try:
                base[key] = int(value.get(key, 0))
            except (TypeError, ValueError):
                base[key] = 0
        return base

    def _ensure_list(self, value: Any) -> list[Any]:
        return value if isinstance(value, list) else []

    def _ensure_dict_generic(self, value: Any) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}
