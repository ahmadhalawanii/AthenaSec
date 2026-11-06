"""Copy an AthenaSec SQLite database into PostgreSQL, then prove nothing was lost.

Usage (from the backend folder, or inside the container from /app):

    python -m app.services.storage.sqlite_to_postgres --sqlite data/athenasec.db --dry-run
    python -m app.services.storage.sqlite_to_postgres --sqlite data/athenasec.db
    python -m app.services.storage.sqlite_to_postgres --sqlite data/athenasec.db --verify-only

The PostgreSQL address comes from --database-url or ATHENASEC_DATABASE_URL.

Safety rules:
- The SQLite file is opened read-only; it is never changed.
- The PostgreSQL schema must already be at the newest Alembic revision
  (`alembic upgrade head`). This tool never creates or alters tables.
- Every table being copied must be empty in PostgreSQL. Nothing is merged or
  overwritten; a non-empty target stops the run before anything is written.
- Everything happens in one transaction. Row counts, every row's values and the
  operator audit hash chain are checked before COMMIT; any difference rolls the
  whole copy back, so PostgreSQL is left exactly as it was.

Type conversion: SQLite keeps timestamps as ISO text and booleans as 0/1, the
PostgreSQL schema uses timestamptz and boolean. Text without a time zone is read
as UTC, which is what AthenaSec writes. Every other column is copied as is.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psycopg

# Tables that exist only in PostgreSQL (accounts and sign-in). SQLite mode never
# had them, so they are not expected in the SQLite file.
SKIP_SQLITE_TABLES = {"sqlite_sequence"}


class MigrationError(RuntimeError):
    pass


@dataclass
class TableReport:
    name: str
    sqlite_rows: int
    postgres_rows: int = 0
    rows_verified: int = 0


@dataclass
class Report:
    sqlite_path: str
    sqlite_sha256: str
    alembic_revision: str | None = None
    tables: list[TableReport] = field(default_factory=list)
    audit_chain_sqlite: dict | None = None
    audit_chain_postgres: dict | None = None
    committed: bool = False
    mode: str = "migrate"

    def as_dict(self) -> dict:
        return {
            "mode": self.mode,
            "sqlite_path": self.sqlite_path,
            "sqlite_sha256": self.sqlite_sha256,
            "alembic_revision": self.alembic_revision,
            "committed": self.committed,
            "total_rows": sum(t.sqlite_rows for t in self.tables),
            "tables": {t.name: {"sqlite": t.sqlite_rows, "postgres": t.postgres_rows,
                                "rows_verified": t.rows_verified} for t in self.tables},
            "audit_chain_sqlite": self.audit_chain_sqlite,
            "audit_chain_postgres": self.audit_chain_postgres,
        }


# ----- helpers --------------------------------------------------------------------


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def open_sqlite_read_only(path: Path) -> sqlite3.Connection:
    if not path.is_file():
        raise MigrationError(f"SQLite file not found: {path}")
    return sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)


def _parse_timestamp(value: Any, where: str) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        moment = value
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            moment = datetime.fromisoformat(text.replace(" ", "T", 1) if "T" not in text else text)
        except ValueError as error:
            raise MigrationError(f"{where}: cannot read timestamp {value!r}") from error
    elif isinstance(value, (int, float)):
        moment = datetime.fromtimestamp(value, tz=timezone.utc)
    else:
        raise MigrationError(f"{where}: unexpected timestamp value {value!r}")
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment


def _parse_boolean(value: Any, where: str) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.strip().lower() in {"0", "1", "true", "false", "t", "f"}:
        return value.strip().lower() in {"1", "true", "t"}
    raise MigrationError(f"{where}: cannot read boolean {value!r}")


def convert(value: Any, pg_type: str, where: str) -> Any:
    if pg_type.startswith("timestamp"):
        return _parse_timestamp(value, where)
    if pg_type == "boolean":
        return _parse_boolean(value, where)
    if pg_type in {"json", "jsonb"} and value is not None and not isinstance(value, str):
        return json.dumps(value)
    return value


def comparable(value: Any, pg_type: str) -> Any:
    """Normalise a PostgreSQL value so it compares with the converted SQLite value."""
    if value is None:
        return None
    if pg_type.startswith("timestamp") and isinstance(value, datetime):
        return value.astimezone(timezone.utc)
    if pg_type in {"json", "jsonb"}:
        return json.loads(value) if isinstance(value, str) else value
    if pg_type in {"numeric", "double precision", "real"}:
        return float(value)
    if isinstance(value, memoryview):
        return bytes(value)
    return value


def comparable_source(value: Any, pg_type: str) -> Any:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc)
    if pg_type in {"json", "jsonb"}:
        return json.loads(value) if isinstance(value, str) else value
    if pg_type in {"numeric", "double precision", "real"}:
        return float(value)
    return value


# ----- schema inspection ----------------------------------------------------------------


def sqlite_tables(lite: sqlite3.Connection) -> dict[str, list[str]]:
    names = [row[0] for row in lite.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")]
    return {
        name: [row[1] for row in lite.execute(f'PRAGMA table_info("{name}")')]
        for name in names if name not in SKIP_SQLITE_TABLES
    }


def postgres_columns(pg: psycopg.Connection) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for table, column, data_type in pg.execute(
        "SELECT table_name, column_name, data_type FROM information_schema.columns "
        "WHERE table_schema = 'public' ORDER BY table_name, ordinal_position"
    ):
        result.setdefault(table, {})[column] = data_type
    return result


def postgres_primary_keys(pg: psycopg.Connection) -> dict[str, list[str]]:
    keys: dict[str, list[str]] = {}
    for table, column in pg.execute(
        """
        SELECT tc.table_name, kcu.column_name
        FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage kcu
          ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema
        WHERE tc.table_schema = 'public' AND tc.constraint_type = 'PRIMARY KEY'
        ORDER BY tc.table_name, kcu.ordinal_position
        """
    ):
        keys.setdefault(table, []).append(column)
    return keys


def foreign_key_order(pg: psycopg.Connection, tables: list[str]) -> list[str]:
    """Parents before children, so non-deferrable foreign keys hold while inserting."""
    depends: dict[str, set[str]] = {name: set() for name in tables}
    for child, parent in pg.execute(
        "SELECT conrelid::regclass::text, confrelid::regclass::text "
        "FROM pg_constraint WHERE contype = 'f'"
    ):
        child, parent = child.strip('"'), parent.strip('"')
        if child in depends and parent in depends and child != parent:
            depends[child].add(parent)

    ordered: list[str] = []
    remaining = dict(depends)
    while remaining:
        ready = sorted(name for name, parents in remaining.items() if not parents - set(ordered))
        if not ready:
            raise MigrationError(f"Foreign keys form a cycle between: {sorted(remaining)}")
        for name in ready:
            ordered.append(name)
            del remaining[name]
    return ordered


def foreign_keys(pg: psycopg.Connection) -> list[tuple[str, list[str], str, list[str]]]:
    """(child table, child columns, parent table, parent columns) for every foreign key."""
    rows = pg.execute(
        """
        SELECT c.conrelid::regclass::text, c.confrelid::regclass::text,
               ARRAY(SELECT a.attname FROM unnest(c.conkey) WITH ORDINALITY k(n, i)
                     JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.n
                     ORDER BY k.i)::text[],
               ARRAY(SELECT a.attname FROM unnest(c.confkey) WITH ORDINALITY k(n, i)
                     JOIN pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = k.n
                     ORDER BY k.i)::text[]
        FROM pg_constraint c WHERE c.contype = 'f'
        """
    ).fetchall()
    return [(child.strip('"'), list(cc), parent.strip('"'), list(pc))
            for child, parent, cc, pc in rows]


def find_orphans(lite: sqlite3.Connection, lite_tables, fks) -> list[str]:
    """Rows PostgreSQL would reject: SQLite never enforced these foreign keys."""
    problems = []
    for child, child_cols, parent, parent_cols in fks:
        if child not in lite_tables:
            continue
        not_null = " AND ".join(f'c."{col}" IS NOT NULL' for col in child_cols)
        if parent in lite_tables:
            join = " AND ".join(f'p."{pc}" = c."{cc}"' for cc, pc in zip(child_cols, parent_cols))
            query = (f'SELECT {", ".join(f"c.{chr(34)}{col}{chr(34)}" for col in child_cols)} '
                     f'FROM "{child}" c WHERE {not_null} AND NOT EXISTS '
                     f'(SELECT 1 FROM "{parent}" p WHERE {join})')
        else:
            query = (f'SELECT {", ".join(f"c.{chr(34)}{col}{chr(34)}" for col in child_cols)} '
                     f'FROM "{child}" c WHERE {not_null}')
        missing = lite.execute(query).fetchall()
        if missing:
            sample = ", ".join(str(row[0] if len(row) == 1 else row) for row in missing[:5])
            problems.append(f"{child}.{'/'.join(child_cols)} -> {parent}: {len(missing)} row(s) "
                            f"point to a missing {parent} row (e.g. {sample})")
    return problems


def alembic_state(pg: psycopg.Connection) -> tuple[str | None, str | None]:
    """(revision in the database, newest revision shipped with this code)."""
    try:
        current = pg.execute("SELECT version_num FROM alembic_version").fetchone()
    except psycopg.errors.UndefinedTable:
        pg.rollback()
        current = None
    head = None
    try:
        from alembic.config import Config
        from alembic.script import ScriptDirectory

        ini = Path(__file__).resolve().parents[3] / "alembic.ini"
        if ini.is_file():
            config = Config(str(ini))
            config.set_main_option("script_location", str(ini.parent / "migrations"))
            head = ScriptDirectory.from_config(config).get_current_head()
    except Exception:  # pragma: no cover - alembic missing is reported as unknown head
        head = None
    return (current[0] if current else None), head


# ----- audit chain -------------------------------------------------------------------------


def audit_chain(rows) -> dict:
    from app.services.audit.operator_audit_store import _event_from_row, verify_chain

    result = verify_chain(_event_from_row(row) for row in rows)
    return {"valid": result.valid, "checked": result.checked,
            "first_broken_seq": result.first_broken_seq, "head_hash": result.head_hash}


def sqlite_audit_chain(lite: sqlite3.Connection) -> dict | None:
    from app.services.audit.operator_audit_store import _COLUMNS

    exists = lite.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='operator_audit_events'").fetchone()
    if not exists:
        return None
    return audit_chain(lite.execute(
        f"SELECT {_COLUMNS} FROM operator_audit_events ORDER BY seq ASC").fetchall())


def postgres_audit_chain(pg: psycopg.Connection) -> dict:
    from app.services.audit.operator_audit_store import _COLUMNS

    return audit_chain(pg.execute(
        f"SELECT {_COLUMNS} FROM operator_audit_events ORDER BY seq ASC").fetchall())


# ----- the copy ----------------------------------------------------------------------------------


def _quoted(names) -> str:
    return ", ".join(f'"{name}"' for name in names)


def check_schema(lite_tables, pg_columns) -> None:
    problems = []
    for table, columns in lite_tables.items():
        if table not in pg_columns:
            problems.append(f"table {table} is missing in PostgreSQL")
            continue
        missing = [c for c in columns if c not in pg_columns[table]]
        if missing:
            problems.append(f"{table}: columns missing in PostgreSQL: {missing}")
    if problems:
        raise MigrationError(
            "PostgreSQL schema does not match the SQLite file. Run `alembic upgrade head` "
            "with this code version first.\n  - " + "\n  - ".join(problems))


def source_rows(lite, table, columns, types, order_by):
    order = _quoted(order_by) if order_by else "rowid"
    rows = []
    for index, raw in enumerate(lite.execute(
            f'SELECT {_quoted(columns)} FROM "{table}" ORDER BY {order}')):
        rows.append(tuple(
            convert(value, types[column], f"{table} row {index + 1} column {column}")
            for column, value in zip(columns, raw)))
    return rows


def verify_table(pg, table, columns, types, keys, expected) -> int:
    order = _quoted(keys) if keys else _quoted(columns)
    actual = pg.execute(f'SELECT {_quoted(columns)} FROM "{table}" ORDER BY {order}').fetchall()
    if len(actual) != len(expected):
        raise MigrationError(f"{table}: {len(expected)} rows in SQLite, {len(actual)} in PostgreSQL")

    def normalise(rows, fn):
        return [tuple(fn(value, types[column]) for column, value in zip(columns, row)) for row in rows]

    left = normalise(expected, comparable_source)
    right = normalise(actual, comparable)
    if not keys:
        left = sorted(left, key=repr)
        right = sorted(right, key=repr)
    else:
        positions = [columns.index(k) for k in keys]
        left = sorted(left, key=lambda row: tuple(repr(row[p]) for p in positions))
        right = sorted(right, key=lambda row: tuple(repr(row[p]) for p in positions))
    for index, (a, b) in enumerate(zip(left, right)):
        if a != b:
            differing = [c for c, x, y in zip(columns, a, b) if x != y]
            raise MigrationError(f"{table}: row {index + 1} differs after copy in {differing}")
    return len(actual)


def reset_sequences(pg) -> None:
    for table, column, sequence in pg.execute(
        """
        SELECT c.table_name, c.column_name, pg_get_serial_sequence(c.table_name, c.column_name)
        FROM information_schema.columns c
        WHERE c.table_schema = 'public'
          AND pg_get_serial_sequence(c.table_name, c.column_name) IS NOT NULL
        """
    ).fetchall():
        pg.execute(
            f'SELECT setval(%s, COALESCE((SELECT MAX("{column}") FROM "{table}"), 0) + 1, false)',
            (sequence,))


def run(sqlite_path: Path, database_url: str, *, dry_run: bool = False,
        verify_only: bool = False, log=print) -> Report:
    report = Report(sqlite_path=str(sqlite_path), sqlite_sha256=sha256_file(sqlite_path),
                    mode="verify-only" if verify_only else ("dry-run" if dry_run else "migrate"))
    lite = open_sqlite_read_only(sqlite_path)
    integrity = lite.execute("PRAGMA integrity_check").fetchone()[0]
    if integrity != "ok":
        raise MigrationError(f"SQLite integrity_check failed: {integrity}")

    with psycopg.connect(database_url) as pg:
        current, head = alembic_state(pg)
        report.alembic_revision = current
        if current is None:
            raise MigrationError("PostgreSQL has no Alembic revision. Run `alembic upgrade head` first.")
        if head and current != head:
            raise MigrationError(
                f"PostgreSQL is at revision {current}, this code expects {head}. "
                "Run `alembic upgrade head` first.")

        lite_tables = sqlite_tables(lite)
        pg_columns = postgres_columns(pg)
        check_schema(lite_tables, pg_columns)
        keys = postgres_primary_keys(pg)
        order = foreign_key_order(pg, list(lite_tables))
        orphans = find_orphans(lite, lite_tables, foreign_keys(pg))
        if orphans:
            raise MigrationError(
                "Some SQLite rows refer to rows that do not exist (SQLite never checked this, "
                "PostgreSQL does). Nothing was copied. Decide with the team how to fix them, "
                "on a copy of the database, then run again:\n  - " + "\n  - ".join(orphans))

        report.audit_chain_sqlite = sqlite_audit_chain(lite)
        if report.audit_chain_sqlite and not report.audit_chain_sqlite["valid"]:
            raise MigrationError(
                "The SQLite operator audit chain is already broken at seq "
                f"{report.audit_chain_sqlite['first_broken_seq']}; refusing to copy it.")

        non_empty = []
        for table in order:
            count = lite.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
            report.tables.append(TableReport(name=table, sqlite_rows=count))
            if not verify_only:
                existing = pg.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
                if existing:
                    non_empty.append(f"{table} ({existing} rows)")
        if non_empty:
            raise MigrationError(
                "These PostgreSQL tables already hold data, so nothing was copied "
                "(this tool never merges): " + ", ".join(non_empty))

        log(f"SQLite file  {sqlite_path}  sha256 {report.sqlite_sha256}")
        log(f"PostgreSQL   revision {current}")

        try:
            for entry in report.tables:
                table = entry.name
                columns = lite_tables[table]
                types = pg_columns[table]
                rows = source_rows(lite, table, columns, types, keys.get(table))
                if not verify_only and rows:
                    placeholders = ", ".join(["%s"] * len(columns))
                    try:
                        with pg.cursor() as cursor:
                            cursor.executemany(
                                f'INSERT INTO "{table}" ({_quoted(columns)}) '
                                f'VALUES ({placeholders})', rows)
                    except psycopg.Error as error:
                        raise MigrationError(f"{table}: PostgreSQL refused a row: {error}") from error
                entry.postgres_rows = pg.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
                entry.rows_verified = verify_table(pg, table, columns, types, keys.get(table), rows)
                log(f"  {table:34} {entry.sqlite_rows:>7} rows  ok")

            if not verify_only:
                reset_sequences(pg)

            if "operator_audit_events" in lite_tables:
                report.audit_chain_postgres = postgres_audit_chain(pg)
                chain_pg, chain_lite = report.audit_chain_postgres, report.audit_chain_sqlite
                if (not chain_pg["valid"] or chain_pg["checked"] != chain_lite["checked"]
                        or chain_pg["head_hash"] != chain_lite["head_hash"]):
                    raise MigrationError(
                        f"Operator audit chain differs after copy: SQLite {chain_lite}, "
                        f"PostgreSQL {chain_pg}")
                log(f"  audit chain: {chain_pg['checked']} events, head {chain_pg['head_hash']}")

            if dry_run or verify_only:
                pg.rollback()
            else:
                pg.commit()
                report.committed = True
        except Exception:
            pg.rollback()
            raise
        finally:
            lite.close()

    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--sqlite", required=True, type=Path, help="Path to the SQLite database")
    parser.add_argument("--database-url", default=os.getenv("ATHENASEC_DATABASE_URL"),
                        help="PostgreSQL URL (default: ATHENASEC_DATABASE_URL)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--dry-run", action="store_true",
                       help="Copy and verify inside a transaction, then roll back")
    group.add_argument("--verify-only", action="store_true",
                       help="Compare an already migrated PostgreSQL database with the SQLite file")
    parser.add_argument("--report", type=Path, help="Write the JSON report to this file")
    args = parser.parse_args(argv)

    if not args.database_url:
        parser.error("Set ATHENASEC_DATABASE_URL or pass --database-url")

    try:
        report = run(args.sqlite, args.database_url, dry_run=args.dry_run,
                     verify_only=args.verify_only)
    except (MigrationError, psycopg.Error) as error:
        print(f"\nSTOPPED, nothing was changed in PostgreSQL:\n{error}", file=sys.stderr)
        return 1

    summary = report.as_dict()
    if args.report:
        args.report.write_text(json.dumps(summary, indent=2) + "\n")
    total = summary["total_rows"]
    if report.committed:
        print(f"\nDONE: {total} rows copied and verified. The SQLite file was not modified.")
    elif args.verify_only:
        print(f"\nVERIFIED: PostgreSQL matches the SQLite file ({total} rows).")
    else:
        print(f"\nDRY RUN OK: {total} rows would be copied; nothing was written.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
