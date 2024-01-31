import typer
from rich import print

from swoosh.app import app
from swoosh.general.text_utils import generate_random_password, slug_from_text


@app.command()
def slugify(text: str) -> None:
    """
    Create a slug from a string.
    """
    print(slug_from_text(text))


@app.command()
def password(length: int = 12, special_chars: bool = True) -> None:
    """
    Generate a random password
    """
    if length < 4:
        print("[red]Password length should be at least  characters long[/red]")
        typer.Exit()
    else:
        print(f"[green]{generate_random_password(length, special_chars)}[/green]")
