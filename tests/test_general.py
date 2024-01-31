from typer.testing import CliRunner

from swoosh.general.general import app

runner = CliRunner()


def test_slug():
    result = runner.invoke(app, ["slugify", "this is swoosh"])
    assert result.exit_code == 0
    assert result.stdout == "this-is-swoosh\n"


def test_password():
    result = runner.invoke(app, ["password"])
    assert result.exit_code == 0
    # 12 chars from the password and new line char
    assert len(result.stdout) == 13


def test_password_shorter_than_four_chars():
    result = runner.invoke(app, ["password", "--length=3"])
    assert result.exit_code == 0
    assert result.stdout == "Password length should be at least  characters long\n"


def test_password_longer_than_four_chars_less_than_eight_chars():
    result = runner.invoke(app, ["password", "--length=7"])
    assert result.exit_code == 0
    # 7 chars from the password and new line char
    assert len(result.stdout) == 8


def test_password_shorter_than_twelve_chars():
    result = runner.invoke(app, ["password", "--length=10"])
    assert result.exit_code == 0
    # 10 chars from the password and new line char
    assert len(result.stdout) == 11
