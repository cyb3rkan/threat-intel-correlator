# src/tic/cli/commands/audit_cmd.py
"""`tic audit` — verify and tail the tamper-evident audit log."""
from __future__ import annotations
import json, sys
import typer
from tic.adapters.audit.hash_chain import HashChainAuditLogger
from tic.domain.errors import TICError
from tic.infra.config import load_settings
from tic.infra.exit_codes import ExitCode
from tic.infra.logging import configure_logging, get_logger
from tic.security.ansi_strip import strip_terminal_controls

app = typer.Typer(add_completion=False, help="Audit-log integrity and inspection.", no_args_is_help=True)
_log = get_logger(__name__)


@app.command("verify")
def verify() -> None:
    """Verify hash-chain integrity of the audit log."""
    try:
        settings = load_settings()
        configure_logging(level=settings.log_level, fmt=settings.log_format)
        ok = HashChainAuditLogger(settings.paths.audit_log_path).verify_chain()
        if ok:
            typer.echo("Audit log integrity: OK")
            raise typer.Exit(code=int(ExitCode.SUCCESS))
        typer.echo("Audit log integrity: BROKEN", err=True)
        raise typer.Exit(code=int(ExitCode.FINDINGS_ABOVE_THRESHOLD))
    except typer.Exit:
        raise
    except TICError as e:
        typer.echo(e.user_message, err=True)
        raise typer.Exit(code=e.exit_code) from e
    except Exception as e:  # noqa: BLE001
        typer.echo("An unexpected error occurred.", err=True)
        raise typer.Exit(code=int(ExitCode.INTERNAL_ERROR)) from e


@app.command("tail")
def tail(n: int = typer.Option(20, "-n", "--lines", min=1, max=10000)) -> None:
    """Print the most recent N audit records."""
    try:
        settings = load_settings()
        configure_logging(level=settings.log_level, fmt=settings.log_format)
        path = settings.paths.audit_log_path
        if not path.exists() or path.stat().st_size == 0:
            return
        with path.open("r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        for raw in lines[-n:]:
            stripped = raw.rstrip("\n")
            if not stripped:
                continue
            try:
                obj     = json.loads(stripped)
                cleaned = strip_terminal_controls(json.dumps(obj))
            except json.JSONDecodeError:
                cleaned = strip_terminal_controls(stripped)
            sys.stdout.write(cleaned + "\n")
    except typer.Exit:
        raise
    except TICError as e:
        typer.echo(e.user_message, err=True)
        raise typer.Exit(code=e.exit_code) from e
    except Exception as e:  # noqa: BLE001
        typer.echo("An unexpected error occurred.", err=True)
        raise typer.Exit(code=int(ExitCode.INTERNAL_ERROR)) from e
