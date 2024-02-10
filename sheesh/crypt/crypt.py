import typer
from rich import print
from rich.console import Console
from rich.table import Table

from sheesh.app import app
from sheesh.crypt.crypto_utils import (
    analyze_password,
    bcrypt_compare,
    bcrypt_encrypt,
    decrypt_text,
    encrypt_text,
    generate_bip39_passphrase,
    generate_hmac,
    generate_random_string,
    generate_rsa_keypair,
    get_hashes,
    get_ulid,
    get_uuid,
)

console = Console()


@app.command("hash")
def hash_text(text: str, encoding: str = "hexadecimal") -> None:
    """
    Hash text using several hashing algorithms. Supported encodings: hexadecimal, base64, base64url, binary
    """
    supported_encodings = ["hexadecimal", "base64", "base64url", "binary"]
    if encoding not in supported_encodings:
        print("[red]supported encodings are hexadecimal, base64, base64url and binary[/red]")
        typer.Exit()
    else:
        table = Table("Algorithm", "Hash")
        for item in get_hashes(text, encoding):
            table.add_row(item[0], item[1])
        console.print(table)


@app.command()
def uuid(version: int = 4, count: int = 1) -> None:
    """
    Generate a uuid. Defaults to version 4 when uuid version is not specified.
    """
    for v in get_uuid(version, count):
        print(f"[green]{v}[/green]")


@app.command()
def ulid(count: int = 1) -> None:
    """
    Generate a ULID (Universally Unique Lexicographically Sortable Identifier).
    """
    for v in get_ulid(count):
        print(f"[green]{v}[/green]")


@app.command("token")
def generate_token(length: int = 10) -> None:
    """
    Generate a random string of characters
    """
    print(f"[green]{generate_random_string(length)}[/green]")


@app.command("bcrypt")
def bcrypt_hash(
    input_password: str,
    salt: int = 10,
    compare: bool = typer.Option(False, help="Compare a hash to a string"),
    hash: str = typer.Option(
        "",
        help="Hashed password. Required only with --compare. Should be passed in single quotes eg."
        "--hash='$2b$10$IK2OnY4ohbdDpmthwyec/uPhGVbPcaR0MkKE0o4DLK4fsLV8BygoK'",
    ),
) -> None:
    """
    Hash a password or compare password to a hash using bcrypt (the password hashing function based on Blowfish cipher)
    """
    if not compare:
        print(f"[green]{bcrypt_encrypt(input_password, salt)}[/green]")
    else:
        try:
            result = (
                "[green]:red_heart-emoji:  It's a match[/green]"
                if bcrypt_compare(input_password, hash)
                else "[red]:frowning-emoji: not matched[/red]"
            )
            print(result)
        except ValueError:
            print(
                "[red][bold]:warning: An error has occurred.[/bold] \nPlease make sure password hash is in single "
                "quotes to avoid variable substitution in the terminal[/red]"
            )


@app.command("encrypt")
def encrypt(text: str, key: str = "secret key from space", algorithm: str = "AES") -> None:
    """
    Encrypt text with a key. Default key is "secret key from space". Supported algorithms are: AES, TripleDES
    """
    supported_algorithms = ["aes", "tripledes"]
    error_message = (
        "[red][bold]:warning: Unsupported Algorithm [/bold] \nHere is the list of supported algorithms:"
        " \nAES \nTripleDES[/red]"
    )
    if algorithm.lower() not in supported_algorithms:
        print(error_message)
    else:
        print(f"[green]{encrypt_text(text, key, algorithm)}[/green]")


@app.command("decrypt")
def decrypt(encrypted_text: str, key: str = "secret key from space", algorithm: str = "AES") -> None:
    """
    Encrypt text with a key. Default key is "secret key from space". Supported algorithms are: AES, TripleDES
    """
    supported_algorithms = ["aes", "tripledes"]
    error_message = (
        "[red][bold]:warning: Unsupported Algorithm [/bold] \nHere is the list of supported algorithms"
        " \nAES \nTripleDES[/red]"
    )
    if algorithm.lower() not in supported_algorithms:
        print(error_message)
    else:
        print(f"[green]{decrypt_text(encrypted_text, key, algorithm)}[/green]")


@app.command("bip39")
def bip39(language: str = "english") -> None:
    """
    Generate a BIP39 passphrase. Default language is english. Other supported languages are: french,
    simplified_chinese, traditional_chinese,czech, italian, japanese, korean, portuguese, spanish
    """

    supported_languages = [
        "english",
        "french",
        "simplified_chinese",
        "traditional_chinese",
        "czech",
        "italian",
        "japanese",
        "korean",
        "portuguese",
        "spanish",
    ]
    error_message = (
        "[red][bold]:warning: Unsupported language [/bold] \nHere is a list of all supported languages \n"
        "english \nfrench \nsimplified_chinese \ntraditional_chinese \nczech \nitalian \njapanese "
        "\nkorean \nportuguese \nspanish[/red]"
    )

    if language.lower() not in supported_languages:
        print(error_message)
    else:
        print(f"[green]{generate_bip39_passphrase(language)}[/green]")


@app.command("hmac")
def hmac(data: str, key: str = "love heals the world", encoding: str = "hexadecimal") -> None:
    """
    Computes a hash-based message authentication code (HMAC). Supported encodings are: hexadecimal, base64 and base64url
    """
    supported_encodings = ["hexadecimal", "base64", "base64url", "binary"]
    if encoding not in supported_encodings:
        print("[red]supported encodings are hexadecimal, base64 and base64url[/red]")
        typer.Exit()
    else:
        table = Table("Algorithm", "HMAC")
        for item in generate_hmac(data, key, encoding):
            table.add_row(item[0], item[1])
        console.print(table)


@app.command("rsa")
def rsa_key_pair(bits: int = 2048) -> None:
    """
    Generate generate RSA key pair
    """
    public_key, private_key = generate_rsa_keypair(bits)
    print(f"[green]{public_key} \n[/green] [red]\n{private_key}[/red]")


@app.command("analyze-password")
def password_analysis(password: str) -> None:
    """
    Analyze password and print details about the input password
    """
    password_details = analyze_password(password)
    table = Table(title="Password analysis results")
    table.add_column("Item", style="green")
    table.add_column("Value", style="green")
    for key, value in password_details.items():
        key = key.title().replace("_", " ").upper()
        table.add_row(key, str(value))

    console.print(table)
