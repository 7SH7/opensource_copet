"""Allow `python -m forensicagent` to run the Typer app directly."""

from forensicagent.cli.main import app

if __name__ == "__main__":
    app()
