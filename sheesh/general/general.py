import typer
from rich import print

from sheesh.app import app
from sheesh.general.text_utils import generate_random_password, slug_from_text


@app.command("version")
def get_version() -> None:
    """
    Get the currently installed version of sheesh
    """
    print("[green]sheesh version [bold]0.0.2[/bold] (Feral Pigeon) [italic]released 10 Feb 2024[/italic][/green]")


@app.command()
def slugify(text: str) -> None:
    """
    Create a slug from a string.
    """
    print(slug_from_text(text))


@app.command()
def password(length: int = 12, special_chars: bool = False) -> None:
    """
    Generate a random password
    """
    if length < 4:
        print("[red]Password length should be at least  characters long[/red]")
        typer.Exit()
    else:
        print(f"[green]{generate_random_password(length, special_chars)}[/green]")
