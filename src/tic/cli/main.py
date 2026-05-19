# src/tic/cli/main.py
"""TIC CLI entry point — wires subcommand groups."""
from __future__ import annotations
import typer
from tic.cli.commands import audit_cmd, cache_cmd, config_cmd, sweep

app = typer.Typer(
    add_completion=False,
    help="Threat Intel Correlator — defensive IOC correlation CLI.",
    no_args_is_help=True,
)
app.add_typer(sweep.app,      name="sweep")
app.add_typer(audit_cmd.app,  name="audit")
app.add_typer(cache_cmd.app,  name="cache")
app.add_typer(config_cmd.app, name="config")

if __name__ == "__main__":
    app()
