"""`tic config` — show config and manage keyring secrets.

Fix #12: endpoints/allowed_hosts masked by default; --verbose shows full values.
"""

from __future__ import annotations

import sys

import keyring
import typer
from keyring.errors import KeyringError

from tic.domain.errors import ConfigError, TICError
from tic.infra.config import load_settings
from tic.infra.exit_codes import ExitCode
from tic.infra.logging import configure_logging, get_logger

app = typer.Typer(
    add_completion=False,
    help="Inspect and manage configuration and credentials.",
    no_args_is_help=True,
)
_log = get_logger(__name__)


def _mask(value: str, verbose: bool) -> str:
    if verbose or not value:
        return value
    if len(value) <= 8:
        return value[:2] + "***"
    return value[:4] + "***" + value[-4:]


@app.command("show")
def show(
    verbose: bool = typer.Option(False, "--verbose", help="Show full endpoint/host values."),
) -> None:
    """Print resolved config. Secrets are never printed."""
    try:
        settings = load_settings()
        configure_logging(level=settings.log_level, fmt=settings.log_format)
        typer.echo("Paths:")
        typer.echo(f"  working_dir:    {settings.paths.working_dir}")
        typer.echo(f"  cache_dir:      {settings.paths.cache_dir}")
        typer.echo(f"  audit_log_path: {settings.paths.audit_log_path}")
        typer.echo("\nProviders:")
        if not settings.providers:
            typer.echo("  (none configured)")
        for name, cfg in settings.providers.items():
            typer.echo(
                f"  {name}:  enabled={cfg.enabled}  keyring={cfg.keyring_service}/{cfg.keyring_user}"
            )
            if cfg.endpoint:
                typer.echo(f"    endpoint: {_mask(cfg.endpoint, verbose)}")
            if cfg.allowed_hosts:
                hosts = [_mask(h, verbose) for h in cfg.allowed_hosts]
                typer.echo(f"    allowed_hosts: {', '.join(hosts)}")
        typer.echo("\nAI:")
        typer.echo(f"  enabled: {settings.ai.enabled}  model: {settings.ai.model or '(unset)'}")
        if settings.ai.endpoint_allowlist:
            typer.echo(
                f"  endpoints: {[_mask(e, verbose) for e in settings.ai.endpoint_allowlist]}"
            )
        typer.echo("\nNote: secret values are stored in the OS keyring and never printed.")
        if not verbose:
            typer.echo("Tip: use --verbose to see full endpoint/host values.")
        raise typer.Exit(code=int(ExitCode.SUCCESS))
    except typer.Exit:
        raise
    except TICError as e:
        typer.echo(e.user_message, err=True)
        raise typer.Exit(code=e.exit_code) from e
    except Exception as e:  # noqa: BLE001
        typer.echo("An unexpected error occurred.", err=True)
        raise typer.Exit(code=int(ExitCode.INTERNAL_ERROR)) from e


def _read_secret() -> str:
    if sys.stdin.isatty():
        return typer.prompt("Secret", hide_input=True, confirmation_prompt=False)
    typer.echo("Warning: reading secret from stdin pipe (not hidden).", err=True)
    return sys.stdin.readline().rstrip("\n\r")


def _resolve_target(provider: str) -> tuple[str, str]:
    settings = load_settings()
    if provider == "ai":
        return settings.ai.keyring_service, settings.ai.keyring_user
    if provider == "redaction-hmac":
        return settings.redaction_hmac_keyring_service, settings.redaction_hmac_keyring_user
    if provider in settings.providers:
        cfg = settings.providers[provider]
        return cfg.keyring_service, cfg.keyring_user
    raise ConfigError(
        f"unknown provider: {provider}", user_message=f"Unknown provider '{provider}'."
    )


@app.command("set-key")
def set_key(provider: str = typer.Argument(...)) -> None:
    """Store a secret in the OS keyring (interactive or stdin pipe)."""
    try:
        settings = load_settings()
        configure_logging(level=settings.log_level, fmt=settings.log_format)
        service, user = _resolve_target(provider)
        secret = _read_secret()
        if not secret:
            typer.echo("Empty secret rejected.", err=True)
            raise typer.Exit(code=int(ExitCode.INPUT_ERROR))
        try:
            keyring.set_password(service, user, secret)
        except KeyringError as e:
            typer.echo("Failed to store secret in keyring.", err=True)
            raise typer.Exit(code=int(ExitCode.AUTH_ERROR)) from e
        typer.echo(f"Stored secret: service='{service}', user='{user}'.")
        raise typer.Exit(code=int(ExitCode.SUCCESS))
    except typer.Exit:
        raise
    except TICError as e:
        typer.echo(e.user_message, err=True)
        raise typer.Exit(code=e.exit_code) from e
    except Exception as e:  # noqa: BLE001
        typer.echo("An unexpected error occurred.", err=True)
        raise typer.Exit(code=int(ExitCode.INTERNAL_ERROR)) from e


@app.command("delete-key")
def delete_key(
    provider: str = typer.Argument(...), yes: bool = typer.Option(False, "--yes")
) -> None:
    """Delete a secret from the OS keyring."""
    try:
        settings = load_settings()
        configure_logging(level=settings.log_level, fmt=settings.log_format)
        service, user = _resolve_target(provider)
        if not yes:
            try:
                if not typer.confirm(
                    f"Delete keyring entry service='{service}' user='{user}'?", default=False
                ):
                    typer.echo("Aborted.", err=True)
                    raise typer.Exit(code=int(ExitCode.SUCCESS))
            except typer.Abort:
                typer.echo("Aborted.", err=True)
                raise typer.Exit(code=int(ExitCode.SUCCESS))
        try:
            keyring.delete_password(service, user)
        except KeyringError as e:
            typer.echo("Could not delete (may not exist).", err=True)
            raise typer.Exit(code=int(ExitCode.AUTH_ERROR)) from e
        typer.echo(f"Deleted: service='{service}', user='{user}'.")
        raise typer.Exit(code=int(ExitCode.SUCCESS))
    except typer.Exit:
        raise
    except TICError as e:
        typer.echo(e.user_message, err=True)
        raise typer.Exit(code=e.exit_code) from e
    except Exception as e:  # noqa: BLE001
        typer.echo("An unexpected error occurred.", err=True)
        raise typer.Exit(code=int(ExitCode.INTERNAL_ERROR)) from e