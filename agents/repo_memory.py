"""
Repo Memory Module
==================
Persistent cross-scan memory for repository-specific intelligence.

Stores what worked and what didn't for each repo so subsequent scans
can reuse successful strategies and avoid known dead-ends.

Uses SQLite for zero-dependency persistence. Can be upgraded to mem0
when the dependency is available.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Default DB location — inside data/ alongside learning.db
_DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'data', 'repo_memory.db',
)


class RepoMemory:
    """Persistent repo-specific memory store."""

    def __init__(self, db_path: str = ''):
        self._db_path = db_path or _DEFAULT_DB_PATH
        self._conn: Optional[sqlite3.Connection] = None
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        try:
            os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
            conn = sqlite3.connect(self._db_path, timeout=10)
            conn.execute('''CREATE TABLE IF NOT EXISTS repo_memories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo_name TEXT NOT NULL,
                memory_type TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                confidence REAL DEFAULT 1.0,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                scan_id TEXT DEFAULT '',
                UNIQUE(repo_name, memory_type, key)
            )''')
            conn.execute('''CREATE INDEX IF NOT EXISTS idx_repo_memories_repo
                ON repo_memories(repo_name)''')
            conn.execute('''CREATE TABLE IF NOT EXISTS strategy_outcomes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo_name TEXT NOT NULL,
                finding_cwe TEXT DEFAULT '',
                strategy_name TEXT NOT NULL,
                outcome TEXT NOT NULL,
                details TEXT DEFAULT '',
                scan_id TEXT DEFAULT '',
                created_at REAL NOT NULL
            )''')
            conn.execute('''CREATE INDEX IF NOT EXISTS idx_strategy_repo
                ON strategy_outcomes(repo_name)''')
            conn.commit()
            conn.close()
        except Exception as e:
            logger.warning('RepoMemory schema init failed: %s', e)

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self._db_path, timeout=10)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def store(self, repo_name: str, memory_type: str, key: str, value: Any,
              confidence: float = 1.0, scan_id: str = '') -> None:
        """Store or update a memory for a repo.

        memory_type examples: 'binary_protocol', 'format_hint', 'bootstrap_cmd',
        'successful_strategy', 'failed_strategy', 'input_format', 'rejection_pattern'
        """
        try:
            conn = self._get_conn()
            now = time.time()
            val_str = json.dumps(value, default=str) if not isinstance(value, str) else value
            conn.execute('''INSERT INTO repo_memories (repo_name, memory_type, key, value, confidence, created_at, updated_at, scan_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(repo_name, memory_type, key) DO UPDATE SET
                    value = excluded.value,
                    confidence = excluded.confidence,
                    updated_at = excluded.updated_at,
                    scan_id = excluded.scan_id
            ''', (repo_name, memory_type, key, val_str, confidence, now, now, scan_id))
            conn.commit()
        except Exception as e:
            logger.warning('RepoMemory.store failed: %s', e)

    def recall(self, repo_name: str, memory_type: str = '', limit: int = 50) -> List[Dict[str, Any]]:
        """Recall memories for a repo, optionally filtered by type."""
        try:
            conn = self._get_conn()
            if memory_type:
                rows = conn.execute(
                    'SELECT * FROM repo_memories WHERE repo_name = ? AND memory_type = ? ORDER BY updated_at DESC LIMIT ?',
                    (repo_name, memory_type, limit)
                ).fetchall()
            else:
                rows = conn.execute(
                    'SELECT * FROM repo_memories WHERE repo_name = ? ORDER BY updated_at DESC LIMIT ?',
                    (repo_name, limit)
                ).fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.warning('RepoMemory.recall failed: %s', e)
            return []

    def record_strategy_outcome(self, repo_name: str, strategy_name: str,
                                 outcome: str, finding_cwe: str = '',
                                 details: str = '', scan_id: str = '') -> None:
        """Record whether a strategy succeeded or failed for future rotation prioritization."""
        try:
            conn = self._get_conn()
            conn.execute('''INSERT INTO strategy_outcomes
                (repo_name, finding_cwe, strategy_name, outcome, details, scan_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (repo_name, finding_cwe, strategy_name, outcome, details, scan_id, time.time()))
            conn.commit()
        except Exception as e:
            logger.warning('RepoMemory.record_strategy_outcome failed: %s', e)

    def get_strategy_history(self, repo_name: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Get strategy outcome history for a repo to inform strategy rotation."""
        try:
            conn = self._get_conn()
            rows = conn.execute(
                '''SELECT strategy_name, outcome, finding_cwe, details, created_at
                   FROM strategy_outcomes WHERE repo_name = ? ORDER BY created_at DESC LIMIT ?''',
                (repo_name, limit)
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.warning('RepoMemory.get_strategy_history failed: %s', e)
            return []

    def get_winning_strategies(self, repo_name: str) -> List[str]:
        """Get strategies that succeeded for this repo, ordered by frequency."""
        try:
            conn = self._get_conn()
            rows = conn.execute(
                '''SELECT strategy_name, COUNT(*) as cnt
                   FROM strategy_outcomes
                   WHERE repo_name = ? AND outcome = 'success'
                   GROUP BY strategy_name ORDER BY cnt DESC''',
                (repo_name,)
            ).fetchall()
            return [r['strategy_name'] for r in rows]
        except Exception as e:
            logger.warning('RepoMemory.get_winning_strategies failed: %s', e)
            return []

    def store_repo_profile(self, repo_name: str, profile: Dict[str, Any],
                           scan_id: str = '') -> None:
        """Persist a full RepoProfile for future scans."""
        for key, value in profile.items():
            if value:  # Only store non-empty values
                self.store(repo_name, 'repo_profile', key, value, scan_id=scan_id)

    def recall_repo_profile(self, repo_name: str) -> Dict[str, Any]:
        """Recall a previously stored RepoProfile."""
        memories = self.recall(repo_name, memory_type='repo_profile')
        profile = {}
        for m in memories:
            try:
                profile[m['key']] = json.loads(m['value'])
            except (json.JSONDecodeError, KeyError):
                profile[m.get('key', '')] = m.get('value', '')
        return profile

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None


# Module-level singleton
_instance: Optional[RepoMemory] = None


def get_repo_memory() -> RepoMemory:
    """Get or create the singleton RepoMemory instance."""
    global _instance
    if _instance is None:
        _instance = RepoMemory()
    return _instance
