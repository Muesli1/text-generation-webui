import base64
import binascii
import codecs
import json
import struct
import time
from os import getenv
from typing import Dict, Optional, Tuple

import nacl.utils
from nacl.bindings.crypto_pwhash import crypto_pwhash_alg, crypto_pwhash_ALG_ARGON2ID13
from nacl.exceptions import CryptoError
from nacl.hash import blake2b, BLAKE2B_SALTBYTES
from nacl.public import PrivateKey, Box
from nacl.secret import SecretBox


def _to_hex(data: bytes) -> str:
    return data.hex()


def _from_hex(hex: str) -> bytes:
    return codecs.decode(hex, "hex")


def _internal_encrypt(text: str) -> Tuple[str, str]:
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)

    box = nacl.secret.SecretBox(_INTERNAL_KEY)
    encrypt = box.encrypt(text.encode("UTF-8"), nonce)

    return _to_hex(encrypt.ciphertext), _to_hex(nonce)


def _internal_decrypt(text: Optional[str]):
    if text is None:
        raise Exception("Missing master password!")

    box = nacl.secret.SecretBox(_INTERNAL_KEY)
    return box.decrypt(_from_hex(text)).decode("UTF-8")


def salted_random(length: int, salt: str) -> bytes:
    return crypto_pwhash_alg(length, MASTER_PASSWORD.encode("UTF-8"), _from_hex(salt),
                             100, 500_000, crypto_pwhash_ALG_ARGON2ID13)


def decrypt_server_side(message: str, nonce: str) -> str | None:
    box = Box(server_key, client_key.public_key)
    decrypted = box.decrypt(base64.standard_b64decode(message.encode("us_ascii")),
                            base64.standard_b64decode(nonce.encode("us_ascii")))

    if len(decrypted) < 40:
        # Not enough bytes for timestamp + api key
        return None

    message_bytes = decrypted[:len(decrypted) - 40]
    time_bytes = decrypted[len(decrypted) - 40:len(decrypted) - 32]
    server_api_key_bytes = decrypted[len(decrypted) - 32:]

    if server_api_key != server_api_key_bytes:
        # Invalid authentication
        return None

    time_difference = abs(struct.unpack("<q", time_bytes)[0] - current_utc_epoch_seconds())

    if time_difference >= 20:
        # Out of time
        return None

    return message_bytes.decode("UTF-8")


def encrypt_server_side(message_dict: dict) -> dict:
    message = json.dumps(message_dict)

    box = Box(server_key, client_key.public_key)
    nonce = nacl.utils.random(Box.NONCE_SIZE)

    message_bytes = message.encode("UTF_8")
    time_bytes = struct.pack("<q", current_utc_epoch_seconds())
    assert len(time_bytes) == 8
    assert len(client_api_key) == 32

    total_bytes = message_bytes + time_bytes + client_api_key
    encrypted = box.encrypt(total_bytes, nonce).ciphertext

    # nacl.utils.encoding.Base64Encoder.encode()
    return {"message": base64.standard_b64encode(encrypted).decode("us_ascii"),
            "nonce": base64.standard_b64encode(nonce).decode("us_ascii")}


def current_utc_epoch_seconds() -> int:
    return int(time.time())


# nacl.utils.random(SecretBox.KEY_SIZE)
_INTERNAL_KEY = _from_hex(getenv("IK", "153adf99f78b726b0b50aa5a95c5d6f3d8599c03469c7ceae9f387e412e57af1"))
MASTER_PASSWORD = _internal_decrypt(getenv("MP",
                                           "a64162236ff12fa99b4a7004eb4458c86a1da4b89f1b26e5cd7eb62f15085856916a44841c7b8559a95cde451b937380e07cb8"))

client_key = PrivateKey.from_seed(salted_random(32, "5C412E8967E06D22C40843080A637514"))
server_key = PrivateKey.from_seed(salted_random(32, "3A938D3B6267890B5180BFDB52CE78E2"))
client_api_key = salted_random(32, "954E28509A2BC81BCD63577DB6C21DB1")
server_api_key = salted_random(32, "98EDBB1742F5DE31BEA04A85DD587567")

def decrypt_message(message) -> Optional[dict]:
    try:
        message = json.loads(message)

        ciphertext = message["message"]
        nonce = message["nonce"]

        decrypted = decrypt_server_side(ciphertext, nonce)
        return json.loads(decrypted) if decrypted is not None else None
    except UnicodeDecodeError as e:
        return None
    except json.decoder.JSONDecodeError as e:
        return None
    except binascii.Error as e:
        return None
    except KeyError as e:
        return None
    except CryptoError as e:
        return None
