import uuid

import pytest
import ulid

from sheesh.crypt.crypto_utils import (
    calculate_charset_size,
    convert_seconds,
    decrypt_text,
    encrypt_text,
    generate_bip39_passphrase,
    generate_hmac,
    generate_rsa_keypair,
    get_ulid,
    get_uuid,
)


def test_version_1():
    uuid_list = list(get_uuid(1, 3))
    assert len(uuid_list) == 3
    for uuid_str in uuid_list:
        assert uuid.UUID(uuid_str).version == 1


def test_version_3():
    uuid_list = list(get_uuid(3, 2))
    assert len(uuid_list) == 2
    for uuid_str in uuid_list:
        assert uuid.UUID(uuid_str).version == 3


def test_version_4():
    uuid_list = list(get_uuid(4, 4))
    assert len(uuid_list) == 4
    for uuid_str in uuid_list:
        assert uuid.UUID(uuid_str).version == 4


def test_version_5():
    uuid_list = list(get_uuid(5, 1))
    assert len(uuid_list) == 1
    for uuid_str in uuid_list:
        assert uuid.UUID(uuid_str).version == 5


def test_invalid_version():
    uuid_list = list(get_uuid(10, 2))
    assert len(uuid_list) == 2
    for uuid_str in uuid_list:
        assert uuid.UUID(uuid_str).version == 4


def test_ulid():
    ulid_list = list(get_ulid(6))
    assert len(ulid_list) == 6
    for ulid_str in ulid_list:
        try:
            ulid.from_str(ulid_str)
        except ValueError:
            pytest.fail(f"Invalid ULID string: {ulid_str}")


@pytest.mark.parametrize("algorithm", ["AES", "TripleDES"])
def test_encrypt_decrypt(algorithm):
    text = "Hello, world!"
    key = "my_secret_key"
    encrypted_text = encrypt_text(text, key, algorithm)
    decrypted_text = decrypt_text(encrypted_text, key, algorithm)
    assert text == decrypted_text
    with pytest.raises(ValueError):
        encrypt_text(text, key, "Unknown algorithm")
        decrypt_text(text, key, "Unknown algorithm")


# test cases for test_generate_bip39_passphrase. run the same test with different params
test_cases = [
    ("english", 12),
    ("french", 12),
    ("chinese", 12),
    ("traditional_chinese", 12),
    ("czech", 12),
    ("italian", 12),
    ("japanese", 12),
    ("korean", 12),
    ("portuguese", 12),
    ("spanish", 12),
]


@pytest.mark.parametrize("language, word_count", test_cases)
def test_generate_bip39_passphrase(language, word_count):
    with pytest.raises(ValueError):
        generate_bip39_passphrase("bad_lang")
    passphrase = generate_bip39_passphrase(language)
    words = passphrase.split()
    assert len(words) == word_count


@pytest.mark.parametrize(
    "data, key, encoding, expected_results",
    [
        (
            "Hello, world!",
            "secretkey",
            "base64",
            [
                ("md5", "NibFJx9vacTAZkWot9tQkg=="),
                ("sha1", "++c3TXW/WDz1vS2TglXOU4WKhNE="),
                ("sha224", "8yrWb7Tc9vqwP1Lw43Tb8UgDmRlvoOz3XV4FCw=="),
                ("sha256", "mgNm56UI1U3OD22M2IEiZdq0smYFZgNhvw4NLkgf9Gg="),
                (
                    "sha384",
                    "TCw95icrMFr69q3gJnHC1/NMXbLh48RopJcO1Ad8HswJzoC82bqtYJt3xBz34U+A",
                ),
                (
                    "sha512",
                    "PzPPMWPtjw2ZFSfi3pBAuQA9tlYc+i//wyaw+cwiU9ilEn9KkWu8d3DizJ+eB6Js9lPU005lLkj7o4QoYTzqKQ==",
                ),
                (
                    "sha3_512",
                    "5iCSchdA+TXm0QuDCJhNyQ7gV5vPz6rYu11Vjxj65+T90gtocRLCjimsaZfTbZM5wHhidlyIMWGQB0QX3XCxXA==",
                ),
            ],
        ),
        (
            "Hello, world!",
            "secretkey",
            "hexadecimal",
            [
                ("md5", "3626c5271f6f69c4c06645a8b7db5092"),
                ("sha1", "fbe7374d75bf583cf5bd2d938255ce53858a84d1"),
                ("sha224", "f32ad66fb4dcf6fab03f52f0e374dbf1480399196fa0ecf75d5e050b"),
                (
                    "sha256",
                    "9a0366e7a508d54dce0f6d8cd8812265dab4b26605660361bf0e0d2e481ff468",
                ),
                (
                    "sha384",
                    "4c2c3de6272b305afaf6ade02671c2d7f34c5db2e1e3c468a4970ed4077c1ecc09ce80bcd9baad609b77c41cf7e14f80",
                ),
                (
                    "sha512",
                    "3f33cf3163ed8f0d991527e2de9040b9003db6561cfa2fffc326b0f9cc2253d8a5127f4a916bbc7770e2cc9f9e07a26cf65"
                    "3d4d34e652e48fba38428613cea29",
                ),
                (
                    "sha3_512",
                    "e62092721740f935e6d10b8308984dc90ee0579bcfcfaad8bb5d558f18fae7e4fdd20b687112c28e29ac6997d36d9339c"
                    "07862765c88316190074417dd70b15c",
                ),
            ],
        ),
        (
            "Hello, world!",
            "secretkey",
            "binary",
            [
                (
                    "md5",
                    "00110110001001101100010100100111000111110110111101101001110001001100000001100110010001011",
                ),
                (
                    "sha1",
                    "1111101111100111001101110100110101110101101111110101100000111100111101011011110100101101100100111000"
                    "00100101010111001110010100111",
                ),
                (
                    "sha224",
                    "1111001100101010110101100110111110110100110111001111011011111010101100000011111101010010111100001"
                    "1100011011101001101101111110001",
                ),
                (
                    "sha256",
                    "10011010000000110110011011100111101001010000100011010101010011011100111000001111011011011000110011"
                    "0110001000000100100010011001011",
                ),
                (
                    "sha384",
                    "01001100001011000011110111100110001001110010101100110000010110101111101011110110101011011110000000"
                    "10011001110001110000101101011111",
                ),
                (
                    "sha512",
                    "001111110011001111001111001100010110001111101101100011110000110110011001000101010010011111100010110"
                    "11110100100000100000010111001000",
                ),
                (
                    "sha3_512",
                    "1110011000100000100100100111001000010111010000001111100100110101111001101101000100001011100000110"
                    "00010001001100001001101110010010000111",
                ),
            ],
        ),
        (
            "Hello, world!",
            "secretkey",
            "base64url",
            [
                ("md5", "NibFJx9vacTAZkWot9tQkg=="),
                ("sha1", "--c3TXW_WDz1vS2TglXOU4WKhNE="),
                ("sha224", "8yrWb7Tc9vqwP1Lw43Tb8UgDmRlvoOz3XV4FCw=="),
                ("sha256", "mgNm56UI1U3OD22M2IEiZdq0smYFZgNhvw4NLkgf9Gg="),
                (
                    "sha384",
                    "TCw95icrMFr69q3gJnHC1_NMXbLh48RopJcO1Ad8HswJzoC82bqtYJt3xBz34U-A",
                ),
                (
                    "sha512",
                    "PzPPMWPtjw2ZFSfi3pBAuQA9tlYc-i__wyaw-cwiU9ilEn9KkWu8d3DizJ-eB6Js9lPU005lLkj7o4QoYTzqKQ==",
                ),
                (
                    "sha3_512",
                    "5iCSchdA-TXm0QuDCJhNyQ7gV5vPz6rYu11Vjxj65-T90gtocRLCjimsaZfTbZM5wHhidlyIMWGQB0QX3XCxXA==",
                ),
            ],
        ),
    ],
)
def test_generate_hmac(data, key, encoding, expected_results) -> None:
    result = generate_hmac(data, key, encoding)
    for (algorithm, hmac_value), (expected_algorithm, expected_hmac_value) in zip(result, expected_results):
        assert algorithm == expected_algorithm
        assert expected_hmac_value in hmac_value


def test_generate_rsa_keypair() -> None:
    public_key, private_key = generate_rsa_keypair(2048)
    assert isinstance(public_key, str)
    assert isinstance(private_key, str)

    assert public_key.strip() != ""
    assert private_key.strip() != ""

    assert public_key.startswith("-----BEGIN PUBLIC KEY-----")
    assert public_key.endswith("-----END PUBLIC KEY-----")

    assert private_key.startswith("-----BEGIN RSA PRIVATE KEY-----")
    assert private_key.endswith("-----END RSA PRIVATE KEY-----")


@pytest.mark.parametrize(
    "password,expected_results",
    [("Top_secret!", 80), ("topsecret", 26), ("123456789", 10)],
)
def test_calculate_charset_size(password, expected_results) -> None:
    assert calculate_charset_size(password) == expected_results


@pytest.mark.parametrize(
    "seconds,expected_results",
    [
        (1, "immediately"),
        (30, "30 seconds"),
        (65, "1 minutes, 5 seconds"),
        (3600, "1 hours, 0 minutes"),
        (86400, "1 days, 0 hours"),
        (31536000, "1 years, 0 days"),
        (3153600000, "1 centuries, 0 years"),
        (315400000000, "10 millennia, 0 centuries"),
    ],
)
def test_convert_seconds(seconds, expected_results) -> None:
    assert convert_seconds(seconds) == expected_results
