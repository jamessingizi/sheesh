from typer.testing import CliRunner

from swoosh.crypt.crypt import app

runner = CliRunner()


def test_hash_text() -> None:
    result = runner.invoke(app, ["hash", "swoosh"])
    assert result.exit_code == 0


def test_hash_text_binary() -> None:
    result = runner.invoke(app, ["hash", "swoosh", "--encoding", "binary"])
    assert result.exit_code == 0


def test_hash_text_base64() -> None:
    result = runner.invoke(app, ["hash", "swoosh", "--encoding", "base64"])
    assert result.exit_code == 0


def test_hash_text_base64url() -> None:
    result = runner.invoke(app, ["hash", "swoosh", "--encoding", "base64url"])
    assert result.exit_code == 0


def test_hash_text_unsupported_encoding():
    result = runner.invoke(app, ["hash", "swoosh", "--encoding=unsupported"])
    assert result.exit_code == 0
    assert result.stdout == "supported encodings are hexadecimal, base64, base64url and binary\n"


def test_uuid():
    result = runner.invoke(app, ["uuid"])
    assert result.exit_code == 0


def test_ulid():
    result = runner.invoke(app, ["ulid"])
    assert result.exit_code == 0


def test_generate_token():
    result = runner.invoke(app, ["token", "--length", "10"])
    assert result.exit_code == 0
    assert len(result.stdout) == 11


def test_generate_bcrypt():
    result = runner.invoke(app, ["bcrypt", "password"])
    assert result.exit_code == 0


def test_compare_bcrypt():
    result = runner.invoke(
        app,
        [
            "bcrypt",
            "--compare",
            "--hash",
            "$2b$10$IK2OnY4ohbdDpmthwyec/uPhGVbPcaR0MkKE0o4DLK4fsLV8BygoK",
            "password",
        ],
    )
    assert result.exit_code == 0
    assert "It's a match" in result.stdout


def test_compare_bcrypt_double_quotes():
    # entering the command as
    # swoosh --compare --hash "$2b$10$IK2OnY4ohbdDpmthwyec/uPhGVbPcaR0MkKE0o4DLK4fsLV8BygoK" "password"
    # result in the hash being converted to b/uPhGVbPcaR0MkKE0o4DLK4fsLV8BygoK because of variable substitution
    result = runner.invoke(
        app,
        [
            "bcrypt",
            "--compare",
            "--hash",
            "b/uPhGVbPcaR0MkKE0o4DLK4fsLV8BygoK",
            "password",
        ],
    )
    assert result.exit_code == 0
    assert "An error has occurred" in result.stdout


def test_compare_bcrypt_fails_with_wrong_password():
    result = runner.invoke(
        app,
        [
            "bcrypt",
            "--compare",
            "--hash",
            "$2b$10$IK2OnY4ohbdDpmthwyec/uPhGVbPcaR0MkKE0o4DLK4fsLV8BygoK",
            "wrongpas",
        ],
    )
    assert result.exit_code == 0
    assert "not matched" in result.stdout


def test_encrypt_text_triple_des():
    result = runner.invoke(
        app,
        ["encrypt", "plain text", "--key", "secret key", "--algorithm", "tripledes"],
    )
    assert result.exit_code == 0


def test_encrypt_text_aes():
    result = runner.invoke(app, ["encrypt", "plain text", "--key", "secret key", "--algorithm", "AES"])
    assert result.exit_code == 0


def test_decrypt_text_aes():
    result = runner.invoke(
        app,
        [
            "decrypt",
            "MlZ0O57D7q+nuF1tlfufi2rDA1kBjqDl1XcNH4tZdJQ=",
            "--key",
            "top secret",
            "--algorithm",
            "AES",
        ],
    )
    assert result.exit_code == 0
    assert "swoosh" in result.stdout


def test_decrypt_text_tripledes():
    result = runner.invoke(
        app,
        [
            "decrypt",
            "HlotlwnZwjpuE5t5vSzS9w==",
            "--key",
            "top secret",
            "--algorithm",
            "TripleDES",
        ],
    )
    assert result.exit_code == 0
    assert "swoosh" in result.stdout


def test_decrypt_text_unsupported_algorithm():
    result = runner.invoke(
        app,
        [
            "decrypt",
            "cipher text",
            "--key",
            "top secret",
            "--algorithm",
            "unknown algorithm",
        ],
    )
    assert result.exit_code == 0
    assert "Unsupported Algorithm" in result.stdout


def test_encrypt_text_unsupported_algorithm():
    result = runner.invoke(
        app,
        [
            "encrypt",
            "plain text",
            "--key",
            "top secret",
            "--algorithm",
            "unknown algorithm",
        ],
    )
    assert result.exit_code == 0
    assert "Unsupported Algorithm" in result.stdout


def test_bip39():
    result = runner.invoke(app, ["bip39"])
    assert result.exit_code == 0


def test_bip39_unsupported_language():
    result = runner.invoke(app, ["bip39", "--language", "shona"])
    assert result.exit_code == 0
    assert "Unsupported language" in result.stdout


def test_hmac():
    result = runner.invoke(app, ["hmac", "Hello, world!"])
    assert result.exit_code == 0


def test_hmac_bad_encoding():
    result = runner.invoke(app, ["hmac", "Hello, world!", "--encoding", "bad_encoding"])
    assert result.exit_code == 0


def test_rsa():
    result = runner.invoke(app, ["rsa"])
    assert result.exit_code == 0


def test_password_analysis():
    result = runner.invoke(app, ["analyze-password", "Top-secret!"])
    assert result.exit_code == 0
