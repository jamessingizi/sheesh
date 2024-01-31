import base64
import binascii
import hashlib
import hmac
import math
import random
import string
import uuid
from base64 import b64decode, b64encode
from typing import Generator, List, Tuple

import bcrypt
import mnemonic
import ulid
from Crypto.Cipher import AES, DES3
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def get_uuid(version: int, count: int) -> Generator[str, None, None]:
    if version == 1:
        for _ in range(count):
            yield str(uuid.uuid1())
    elif version == 3:
        for _ in range(count):
            yield str(uuid.uuid3(uuid.NAMESPACE_DNS, "python.org"))
    elif version == 4:
        for _ in range(count):
            yield str(uuid.uuid4())
    elif version == 5:
        for _ in range(count):
            yield str(uuid.uuid5(uuid.NAMESPACE_DNS, "python.org"))
    else:
        for _ in range(count):
            yield str(uuid.uuid4())


def get_ulid(count: int) -> Generator[str, None, None]:
    for _ in range(count):
        yield str(ulid.new())


def get_hashes(text: str, encoding: str) -> list:
    if encoding == "binary":
        return get_bin_hash(text)
    elif encoding == "base64":
        get_base64_hash(text)
    elif encoding == "base64url":
        get_base64_url_hash(text)

    return get_hex_hash(text)


def get_hex_hash(text: str) -> List[Tuple[str, str]]:
    return [
        ("MD5", hashlib.md5(text.encode()).hexdigest()),
        ("SHA1", hashlib.sha1(text.encode()).hexdigest()),
        ("SHA256", hashlib.sha256(text.encode()).hexdigest()),
        ("SHA224", hashlib.sha224(text.encode()).hexdigest()),
        ("SHA512", hashlib.sha512(text.encode()).hexdigest()),
        ("SHA384", hashlib.sha384(text.encode()).hexdigest()),
        ("SHA3_512", hashlib.sha3_512(text.encode()).hexdigest()),
    ]


def get_base64_hash(text: str) -> List[Tuple[str, str]]:
    return [
        ("MD5", base64.b64encode(hashlib.md5(text.encode()).digest()).decode()),
        ("SHA1", base64.b64encode(hashlib.sha1(text.encode()).digest()).decode()),
        ("SHA256", base64.b64encode(hashlib.sha256(text.encode()).digest()).decode()),
        ("SHA224", base64.b64encode(hashlib.sha224(text.encode()).digest()).decode()),
        ("SHA512", base64.b64encode(hashlib.sha512(text.encode()).digest()).decode()),
        ("SHA384", base64.b64encode(hashlib.sha384(text.encode()).digest()).decode()),
        (
            "SHA3_512",
            base64.b64encode(hashlib.sha3_512(text.encode()).digest()).decode(),
        ),
    ]


def get_base64_url_hash(text: str) -> List[Tuple[str, str]]:
    return [
        ("MD5", base64.urlsafe_b64encode(hashlib.md5(text.encode()).digest()).decode()),
        (
            "SHA1",
            base64.urlsafe_b64encode(hashlib.sha1(text.encode()).digest()).decode(),
        ),
        (
            "SHA256",
            base64.urlsafe_b64encode(hashlib.sha256(text.encode()).digest()).decode(),
        ),
        (
            "SHA224",
            base64.urlsafe_b64encode(hashlib.sha224(text.encode()).digest()).decode(),
        ),
        (
            "SHA512",
            base64.urlsafe_b64encode(hashlib.sha512(text.encode()).digest()).decode(),
        ),
        (
            "SHA384",
            base64.urlsafe_b64encode(hashlib.sha384(text.encode()).digest()).decode(),
        ),
        (
            "SHA3_512",
            base64.urlsafe_b64encode(hashlib.sha3_512(text.encode()).digest()).decode(),
        ),
    ]


def get_bin_hash(text: str) -> List[Tuple[str, str]]:
    return [
        (
            "MD5",
            bin(int(binascii.hexlify(hashlib.md5(text.encode()).digest()), 16))[2:],
        ),
        (
            "SHA1",
            bin(int(binascii.hexlify(hashlib.sha1(text.encode()).digest()), 16))[2:],
        ),
        (
            "SHA256",
            bin(int(binascii.hexlify(hashlib.sha256(text.encode()).digest()), 16))[2:],
        ),
        (
            "SHA224",
            bin(int(binascii.hexlify(hashlib.sha224(text.encode()).digest()), 16))[2:],
        ),
        (
            "SHA512",
            bin(int(binascii.hexlify(hashlib.sha512(text.encode()).digest()), 16))[2:],
        ),
        (
            "SHA384",
            bin(int(binascii.hexlify(hashlib.sha384(text.encode()).digest()), 16))[2:],
        ),
        (
            "SHA3_512",
            bin(int(binascii.hexlify(hashlib.sha3_512(text.encode()).digest()), 16))[2:],
        ),
    ]


def generate_random_string(length: int) -> str:
    # Get all alphanumeric characters
    alphanumeric_chars = string.ascii_letters + string.digits

    # Generate a random string of the specified length
    random_string = "".join(random.choice(alphanumeric_chars) for _ in range(length))

    return random_string


def bcrypt_encrypt(input_password: str, salt_rounds: int) -> str:
    """
    Encrypts a string using bcrypt.
    """
    salt = bcrypt.gensalt(salt_rounds)
    hashed = bcrypt.hashpw(input_password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def bcrypt_compare(input_password: str, password_hash: str) -> bool:
    """
    Compare password against hash
    """

    input_password_bytes = input_password.encode("utf-8")
    hashed_bytes = password_hash.encode("utf-8")

    return bcrypt.checkpw(input_password_bytes, hashed_bytes)


def encrypt_text(text: str, key: str, algorithm: str) -> str:
    algorithms = [
        "aes",
        "tripledes",
    ]
    if algorithm.lower() not in algorithms:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    if algorithm.lower() == "aes":
        return encrypt_text_aes(text, key)
    else:
        return encrypt_text_3des(text, key)


def decrypt_text(text: str, key: str, algorithm: str) -> str:
    algorithms = ["aes", "tripledes"]
    if algorithm.lower() not in algorithms:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    if algorithm.lower() == "aes":
        return decrypt_text_aes(text, key)
    else:
        return decrypt_text_3des(text, key)


def encrypt_text_aes(text: str, key: str) -> str:
    # Ensure the key is 32 bytes (256 bits) for AES-256
    enc_key: bytes = key.ljust(32, "\0")[:32].encode()
    iv = get_random_bytes(16)
    cipher = AES.new(enc_key, AES.MODE_CFB, iv=iv)
    padded_data = pad(text.encode("utf-8"), AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    encrypted_data = b64encode(iv + ciphertext).decode("utf-8")

    return encrypted_data


def decrypt_text_aes(encrypted_data: str, key: str) -> str:
    # Ensure the key is 32 bytes (256 bits) for AES-256
    enc_key: bytes = key.ljust(32, "\0")[:32].encode()

    encrypted_data_bytes: bytes = b64decode(encrypted_data)
    iv = encrypted_data_bytes[:16]
    ciphertext = encrypted_data_bytes[16:]
    cipher = AES.new(enc_key, AES.MODE_CFB, iv=iv)
    padded_data = cipher.decrypt(ciphertext)
    text = unpad(padded_data, AES.block_size).decode("utf-8")

    return text


def encrypt_text_3des(text: str, key: str) -> str:
    # Ensure the key is 24 bytes for 3DES
    key_bytes: bytes = key.encode()
    key_bytes = hashlib.sha256(key_bytes).digest()[:24]
    iv = get_random_bytes(8)  # 3DES uses an 8-byte IV
    cipher = DES3.new(key_bytes, DES3.MODE_CFB, iv=iv)
    padded_data = pad(text.encode("utf-8"), DES3.block_size)
    ciphertext = cipher.encrypt(padded_data)
    encrypted_data = b64encode(iv + ciphertext).decode("utf-8")

    return encrypted_data


def decrypt_text_3des(encrypted_data: str, key: str) -> str:
    # Ensure the key is 24 bytes for 3DES
    key_bytes: bytes = key.encode()
    key_bytes = hashlib.sha256(key_bytes).digest()[:24]
    encrypted_data_bytes: bytes = b64decode(encrypted_data)
    iv = encrypted_data_bytes[:8]  # The IV is the first 8 bytes of the encrypted data
    ciphertext = encrypted_data_bytes[8:]
    cipher = DES3.new(key_bytes, DES3.MODE_CFB, iv=iv)
    padded_data = cipher.decrypt(ciphertext)
    text = unpad(padded_data, DES3.block_size).decode("utf-8")

    return text


def generate_bip39_passphrase(language: str) -> str:
    language_map = {
        "english": "english",
        "french": "french",
        "chinese": "chinese_simplified",
        "traditional_chinese": "chinese_traditional",
        "czech": "czech",
        "italian": "italian",
        "japanese": "japanese",
        "korean": "korean",
        "portuguese": "portuguese",
        "spanish": "spanish",
    }

    mnemonic_language = language_map.get(language)
    if not mnemonic_language:
        raise ValueError("Invalid language. Choose from supported languages.")

    return mnemonic.Mnemonic(mnemonic_language).generate()


def generate_hmac(data: str, key: str, encoding: str = "hexadecimal") -> list:
    supported_algorithms = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha224": hashlib.sha224,
        "sha256": hashlib.sha256,
        "sha384": hashlib.sha384,
        "sha512": hashlib.sha512,
        "sha3_512": hashlib.sha3_512,
    }

    hmac_results = []
    for algorithm, hasher in supported_algorithms.items():
        hmac_hash = hmac.new(key.encode(), data.encode(), hasher).digest()  # type: ignore

        if encoding == "base64":
            hmac_hash = base64.b64encode(hmac_hash).decode()
        elif encoding == "base64url":
            hmac_hash = base64.urlsafe_b64encode(hmac_hash).decode()
        elif encoding == "hexadecimal":
            hmac_hash = hmac_hash.hex()
        elif encoding == "binary":
            hmac_hash = "".join(format(byte, "08b") for byte in hmac_hash)

        hmac_results.append((algorithm, hmac_hash))

    return hmac_results


def generate_rsa_keypair(bits: int) -> Tuple[str, str]:
    key = RSA.generate(bits)
    private_key = key.export_key().decode()
    public_key = key.publickey().export_key().decode()
    return public_key, private_key


def calculate_charset_size(s: str) -> int:
    charset_size = 0
    if any(c.islower() for c in s):
        charset_size += 26

    if any(c.isupper() for c in s):
        charset_size += 26

    if any(c.isdigit() for c in s):
        charset_size += 10

    special_chars = "!@#$%^&*()-_+=[]{}|;:',.<>?/"
    if any(c in special_chars for c in s):
        charset_size += 28
    return charset_size


def analyze_password(password: str) -> dict:
    password_length = len(password)
    char_set_size = calculate_charset_size(password)

    entropy = password_length * math.log2(char_set_size)
    # Assuming 1000 attempts per second
    attempts_per_second = 1_000_000_000
    brute_force_time = char_set_size**password_length / attempts_per_second
    strength_score = min(100, int((entropy / 128) * 100))

    return {
        "password": password,
        "length": password_length,
        "character_set_size": char_set_size,
        "entropy": "{:,.2f}".format(entropy),
        "brute_force_time": convert_seconds(brute_force_time),
        "strength_score": f"{strength_score:,.0f}/100",
    }


def convert_seconds(seconds: int) -> str:
    if seconds <= 1:
        return "immediately"
    elif seconds < 60:
        return f"{seconds:,.0f} seconds"
    elif seconds < 3600:
        minutes = seconds // 60
        remaining_seconds = seconds % 60
        return f"{minutes:,.0f} minutes, {remaining_seconds:,.0f} seconds"
    elif seconds < 86400:
        hours = seconds // 3600
        remaining_seconds = seconds % 3600
        minutes = remaining_seconds // 60
        remaining_seconds %= 60
        return f"{hours:,.0f} hours, {minutes:,.0f} minutes"
    elif seconds < 31536000:
        days = seconds // 86400
        remaining_seconds = seconds % 86400
        hours = remaining_seconds // 3600
        return f"{days:,.0f} days, {hours:,.0f} hours"
    elif seconds < 3153600000:
        years = seconds // 31536000
        remaining_seconds = seconds % 31536000
        days = remaining_seconds // 86400
        return f"{years:,.0f} years, {days:,.0f} days"
    elif seconds < 315360000000:
        centuries = seconds // 3153600000
        remaining_seconds = seconds % 3153600000
        years = remaining_seconds // 31536000
        return f"{centuries:,.0f} centuries, {years:,.0f} years"
    else:
        millennia = seconds // 31536000000
        remaining_seconds = seconds % 31536000000
        centuries = remaining_seconds // 3153600000
        return f"{millennia:,.0f} millennia, {centuries:,.0f} centuries"
