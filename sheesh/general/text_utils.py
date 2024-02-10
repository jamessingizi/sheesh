import random
import re
import string


def slug_from_text(text: str) -> str:
    """
    Returns a slugified version of the given text.
    """
    text = text.lower()
    text = text.replace(" ", "-")
    text = "".join(char for char in text if char.isalnum() or char == "-")
    text = re.sub(r"-+", "-", text)  # Remove consecutive dashes.
    text = text.strip("-")  # Remove leading and trailing dashes.

    return text


def generate_random_password(length: int = 12, include_special_chars: bool = True) -> str:
    # Define character sets for different password strength levels
    lower_case = string.ascii_lowercase
    upper_case = string.ascii_uppercase
    digits = string.digits
    special_chars = string.punctuation if include_special_chars else ""

    # Combine character sets based on strength
    if length < 8:
        charset = lower_case + upper_case + digits
    elif length < 12:
        charset = lower_case + upper_case + digits + special_chars
    else:
        charset = lower_case + upper_case + digits + special_chars

    # Generate the password
    password = "".join(random.choice(charset) for _ in range(length))

    return password
