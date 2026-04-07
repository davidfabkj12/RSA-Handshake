from __future__ import annotations

import os
import base64
from typing import Dict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CryptoService:
    """
    Gère le chiffrement et le déchiffrement AES-GCM des messages applicatifs.
    Le format de sortie contient :
    - iv
    - ciphertext
    - tag
    """

    def __init__(self, nonce_size: int = 12) -> None:
        self.nonce_size = nonce_size

    def encrypt_message(self, plaintext: str, aes_key: bytes) -> Dict[str, str]:
        self._validate_aes_key(aes_key)

        if plaintext is None:
            raise ValueError("Le plaintext ne peut pas être None.")

        plaintext_bytes = plaintext.encode("utf-8")
        aesgcm = AESGCM(aes_key)

        iv = os.urandom(self.nonce_size)
        encrypted_data = aesgcm.encrypt(iv, plaintext_bytes, associated_data=None)

        ciphertext = encrypted_data[:-16]
        tag = encrypted_data[-16:]

        return {
            "iv": base64.b64encode(iv).decode("utf-8"),
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
            "tag": base64.b64encode(tag).decode("utf-8"),
        }

    def decrypt_message(self, iv: str, ciphertext: str, tag: str, aes_key: bytes) -> str:
        self._validate_aes_key(aes_key)

        try:
            iv_bytes = base64.b64decode(iv)
            ciphertext_bytes = base64.b64decode(ciphertext)
            tag_bytes = base64.b64decode(tag)
        except Exception as exc:
            raise ValueError("Le payload chiffré contient un champ base64 invalide.") from exc

        encrypted_data = ciphertext_bytes + tag_bytes
        aesgcm = AESGCM(aes_key)

        try:
            plaintext_bytes = aesgcm.decrypt(iv_bytes, encrypted_data, associated_data=None)
        except Exception as exc:
            raise ValueError("Échec du déchiffrement AES ou tag d'authentification invalide.") from exc

        return plaintext_bytes.decode("utf-8")

    def _validate_aes_key(self, aes_key: bytes) -> None:
        if not aes_key:
            raise ValueError("La clé AES ne peut pas être vide.")

        if len(aes_key) != 32:
            raise ValueError("La clé AES doit contenir 32 octets pour AES-256.")