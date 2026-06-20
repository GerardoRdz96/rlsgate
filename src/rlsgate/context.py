"""The shared, read-only context every rule receives.

Built once per scan: discover files, split every migration into statements, and
construct the SQL model. Rules never re-read the filesystem or re-parse SQL.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

from .discover import Project, discover
from .gitinfo import env_status
from .model import SqlModel, build_model
from .sql import Statement, split_statements


@dataclass
class ScanContext:
    project: Project
    statements: List[Statement]
    model: SqlModel
    # rel-path -> 'tracked' | 'ignored' | 'untracked' | 'no-git' for env files
    env_status: Dict[str, str] = field(default_factory=dict)

    @property
    def root(self) -> Path:
        return self.project.root


def build_context(path) -> ScanContext:
    project = discover(path)
    statements: List[Statement] = []
    for rel, text in project.sql_files:
        for st in split_statements(text):
            st.file = rel
            statements.append(st)
    model = build_model(statements)
    status = env_status(project.root, [rel for rel, _ in project.env_files])
    return ScanContext(project=project, statements=statements, model=model, env_status=status)
