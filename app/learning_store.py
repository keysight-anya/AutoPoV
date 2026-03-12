"""
AutoPoV Learning Store
Persists scan outcomes to support model routing and self-improvement.
"""

import os
import sqlite3
from typing import Optional, Any, List
from datetime import datetime

from app.config import settings


class LearningStore:
    """SQLite-backed learning store for model performance and outcomes."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or settings.LEARNING_DB_PATH
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _init_db(self):
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS investigations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT,
                    cwe TEXT,
                    filepath TEXT,
                    language TEXT,
                    source TEXT,
                    verdict TEXT,
                    confidence REAL,
                    model TEXT,
                    cost_usd REAL,
                    timestamp TEXT
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS pov_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT,
                    cwe TEXT,
                    model TEXT,
                    cost_usd REAL,
                    success INTEGER,
                    validation_method TEXT,
                    timestamp TEXT
                )
                """
            )
            conn.commit()

    def record_investigation(
        self,
        scan_id: str,
        cwe: str,
        filepath: str,
        language: str,
        source: str,
        verdict: str,
        confidence: float,
        model: str,
        cost_usd: float
    ):
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO investigations
                (scan_id, cwe, filepath, language, source, verdict, confidence, model, cost_usd, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    cwe,
                    filepath,
                    language,
                    source,
                    verdict,
                    confidence,
                    model,
                    cost_usd,
                    datetime.utcnow().isoformat()
                )
            )
            conn.commit()

    def record_pov(
        self,
        scan_id: str,
        cwe: str,
        model: str,
        cost_usd: float,
        success: bool,
        validation_method: str
    ):
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO pov_runs
                (scan_id, cwe, model, cost_usd, success, validation_method, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    cwe,
                    model,
                    cost_usd,
                    1 if success else 0,
                    validation_method,
                    datetime.utcnow().isoformat()
                )
            )
            conn.commit()


    def get_summary(self) -> dict:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*), SUM(cost_usd) FROM investigations")
            inv_count, inv_cost = cur.fetchone()
            cur.execute("SELECT COUNT(*), SUM(cost_usd), SUM(success) FROM pov_runs")
            pov_count, pov_cost, pov_success = cur.fetchone()

            return {
                "investigations_total": inv_count or 0,
                "investigations_cost_usd": float(inv_cost or 0.0),
                "pov_total": pov_count or 0,
                "pov_cost_usd": float(pov_cost or 0.0),
                "pov_success_total": pov_success or 0
            }

    def get_model_stats(self) -> dict:
        """Aggregate model performance for investigate and PoV stages."""
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT model,
                       COUNT(*) AS total,
                       SUM(CASE WHEN verdict='REAL' THEN 1 ELSE 0 END) AS confirmed,
                       AVG(confidence) AS avg_confidence,
                       SUM(cost_usd) AS cost
                FROM investigations
                GROUP BY model
            """)
            investigate = [
                {
                    "model": row[0],
                    "total": row[1] or 0,
                    "confirmed": row[2] or 0,
                    "avg_confidence": float(row[3] or 0.0),
                    "cost_usd": float(row[4] or 0.0),
                    "confirm_rate": (row[2] or 0) / (row[1] or 1)
                }
                for row in cur.fetchall()
            ]

            cur.execute("""
                SELECT model,
                       COUNT(*) AS total,
                       SUM(success) AS confirmed,
                       SUM(cost_usd) AS cost
                FROM pov_runs
                GROUP BY model
            """)
            pov = [
                {
                    "model": row[0],
                    "total": row[1] or 0,
                    "confirmed": row[2] or 0,
                    "cost_usd": float(row[3] or 0.0),
                    "success_rate": (row[2] or 0) / (row[1] or 1)
                }
                for row in cur.fetchall()
            ]

        return {"investigate": investigate, "pov": pov}

    def get_model_recommendation(
        self,
        stage: str,
        cwe: Optional[str] = None,
        language: Optional[str] = None
    ) -> Optional[str]:
        """
        Recommend a model based on historical performance.
        Uses a simple confirmed-per-cost score.
        """
        if stage not in ["investigate", "pov"]:
            return None

        with self._connect() as conn:
            cur = conn.cursor()

            if stage == "investigate":
                query = """
                    SELECT model,
                           SUM(CASE WHEN verdict='REAL' THEN 1 ELSE 0 END) AS confirmed,
                           SUM(cost_usd) AS cost
                    FROM investigations
                    WHERE 1=1
                """
                params: List[Any] = []
                if cwe:
                    query += " AND cwe=?"
                    params.append(cwe)
                if language:
                    query += " AND language=?"
                    params.append(language)
                query += " GROUP BY model"
            else:
                query = """
                    SELECT model,
                           SUM(success) AS confirmed,
                           SUM(cost_usd) AS cost
                    FROM pov_runs
                    WHERE 1=1
                """
                params = []
                if cwe:
                    query += " AND cwe=?"
                    params.append(cwe)
                query += " GROUP BY model"

            cur.execute(query, params)
            rows = cur.fetchall()

        best_model = None
        best_score = 0.0
        for model, confirmed, cost in rows:
            if confirmed is None:
                continue
            cost = cost or 0.0
            score = confirmed / (cost + 0.01)
            if score > best_score:
                best_score = score
                best_model = model

        return best_model


learning_store = LearningStore()


def get_learning_store() -> LearningStore:
    return learning_store
