# src/tic/cli/commands/cache_cmd.py
"""`tic cache` — purge expired entries and show stats."""

from __future__ import annotations

import sqlite3

import typer

from tic.cli._wiring import build_cache
from tic.domain.errors import TICError
from tic.infra.config import load_settings
from tic.infra.exit_codes import ExitCode
from tic.infra.logging import configure_logging, get_logger

app = typer.Typer(add_completion=False, help="Enrichment cache management.", no_args_is_help=True)
_log = get_logger(__name__)


@app.command("purge")
def purge(yes: bool = typer.Option(False, "--yes")) -> None:
    """Purge expired cache entries."""
    try:
        settings = load_settings()
        configure_logging(level=settings.log_level, fmt=settings.log_format)
        if not yes:
            try:
                if not typer.confirm("Purge expired cache entries?", default=False):
                    typer.echo("Aborted.", err=True)
                    raise typer.Exit(code=int(ExitCode.SUCCESS))
            except typer.Abort:
                typer.echo("Aborted.", err=True)
                raise typer.Exit(code=int(ExitCode.SUCCESS))
        cache = build_cache(settings)
        removed = cache.purge_expired()  # type: ignore[attr-defined]
        typer.echo(f"Purged {removed} expired entries.")
        raise typer.Exit(code=int(ExitCode.SUCCESS))
    except typer.Exit:
        raise
    except TICError as e:
        typer.echo(e.user_message, err=True)
        raise typer.Exit(code=e.exit_code) from e
    except Exception as e:  # noqa: BLE001
        typer.echo("An unexpected error occurred.", err=True)
        raise typer.Exit(code=int(ExitCode.INTERNAL_ERROR)) from e


@app.command("stats")
def stats() -> None:
    """Print cache statistics."""
    try:
        settings = load_settings()
        configure_logging(level=settings.log_level, fmt=settings.log_format)
        db_path = settings.paths.cache_dir / "tic-cache.sqlite"
        typer.echo(f"Cache file: {db_path}")
        if not db_path.exists():
            typer.echo("Total entries: 0")
            raise typer.Exit(code=int(ExitCode.SUCCESS))
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            total = int(conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0])
            typer.echo(f"Total entries: {total}")
            by_ns = {
                row[0]: int(row[1])
                for row in conn.execute(
                    "SELECT namespace, COUNT(*) FROM entries GROUP BY namespace ORDER BY namespace"
                )
            }
            if by_ns:
                typer.echo("By namespace:")
                for ns, cnt in by_ns.items():
                    typer.echo(f"  {ns}: {cnt}")
        finally:
            conn.close()
        raise typer.Exit(code=int(ExitCode.SUCCESS))
    except typer.Exit:
        raise
    except TICError as e:
        typer.echo(e.user_message, err=True)
        raise typer.Exit(code=e.exit_code) from e
    except Exception as e:  # noqa: BLE001
        typer.echo("An unexpected error occurred.", err=True)
        raise typer.Exit(code=int(ExitCode.INTERNAL_ERROR)) from e
