from __future__ import annotations

import base64
import os
from typing import Dict

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_aes_key() -> bytes:
    """
    Génère une clé AES-256 aléatoire (32 octets).
    """
    return os.urandom(32)


def encrypt_aes_key_with_rsa(public_key_pem: str, aes_key: bytes) -> str:
    """
    Chiffre la clé AES avec la clé publique RSA du serveur
    puis retourne le résultat encodé en base64.

    :param public_key_pem: clé publique RSA au format PEM
    :param aes_key: clé AES brute (32 octets)
    :return: clé AES chiffrée et encodée en base64
    """
    if not public_key_pem:
        raise ValueError("La clé publique PEM ne peut pas être vide.")

    if not aes_key or len(aes_key) != 32:
        raise ValueError("La clé AES doit contenir 32 octets pour AES-256.")

    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))

    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return base64.b64encode(encrypted_key).decode("utf-8")


def encrypt_message_with_aes(message: str, aes_key: bytes) -> Dict[str, str]:
    """
    Chiffre un message texte avec AES-GCM.

    :param message: message en clair
    :param aes_key: clé AES de session
    :return: dictionnaire contenant iv, ciphertext et tag en base64
    """
    _validate_aes_key(aes_key)

    if message is None:
        raise ValueError("Le message ne peut pas être None.")

    aesgcm = AESGCM(aes_key)
    iv = os.urandom(12)

    encrypted_data = aesgcm.encrypt(
        iv,
        message.encode("utf-8"),
        associated_data=None,
    )

    ciphertext = encrypted_data[:-16]
    tag = encrypted_data[-16:]

    return {
        "iv": base64.b64encode(iv).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "tag": base64.b64encode(tag).decode("utf-8"),
    }


def decrypt_response_with_aes(payload: Dict[str, str], aes_key: bytes) -> str:
    """
    Déchiffre une réponse chiffrée AES-GCM provenant du serveur.

    :param payload: dictionnaire contenant iv, ciphertext, tag
    :param aes_key: clé AES de session
    :return: message déchiffré
    """
    _validate_aes_key(aes_key)

    if not isinstance(payload, dict):
        raise ValueError("Le payload de réponse doit être un dictionnaire.")

    iv = payload.get("iv")
    ciphertext = payload.get("ciphertext")
    tag = payload.get("tag")

    if not iv or not ciphertext or not tag:
        raise ValueError("Le payload doit contenir iv, ciphertext et tag.")

    try:
        iv_bytes = base64.b64decode(iv)
        ciphertext_bytes = base64.b64decode(ciphertext)
        tag_bytes = base64.b64decode(tag)
    except Exception as exc:
        raise ValueError("La réponse chiffrée contient un champ base64 invalide.") from exc

    encrypted_data = ciphertext_bytes + tag_bytes
    aesgcm = AESGCM(aes_key)

    try:
        plaintext_bytes = aesgcm.decrypt(
            iv_bytes,
            encrypted_data,
            associated_data=None,
        )
    except Exception as exc:
        raise ValueError("Échec du déchiffrement AES de la réponse du serveur.") from exc

    return plaintext_bytes.decode("utf-8")


def _validate_aes_key(aes_key: bytes) -> None:
    """
    Vérifie la conformité d'une clé AES-256.
    """
    if not aes_key:
        raise ValueError("La clé AES ne peut pas être vide.")

    if len(aes_key) != 32:
        raise ValueError("La clé AES doit contenir 32 octets pour AES-256.")