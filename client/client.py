from __future__ import annotations

import time
import os
import sys
import uuid
import logging
from typing import Optional

import requests

from client_crypto import (
    decrypt_response_with_aes,
    encrypt_aes_key_with_rsa,
    encrypt_message_with_aes,
    generate_aes_key,
)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)

logger = logging.getLogger(__name__)


class SecureClientDemo:
    """
    Client de démonstration pour :
    - récupérer la clé publique du serveur
    - établir un handshake RSA/AES
    - envoyer un message chiffré
    - déchiffrer la réponse du serveur
    """

    def __init__(self, server_base_url: str) -> None:
        self.server_base_url = server_base_url.rstrip("/")
        self.client_id = str(uuid.uuid4())
        self.aes_key: Optional[bytes] = None
        self.session_id: Optional[str] = None
        self.public_key_pem: Optional[str] = None

    import time

    def fetch_public_key(self) -> str:
        """
        Récupère la clé publique du serveur avec quelques tentatives.
        """
        url = f"{self.server_base_url}/public-key"
        last_exception = None

        for attempt in range(1, 11):
            try:
                response = requests.get(url, timeout=10)
                response.raise_for_status()

                data = response.json()
                public_key = data.get("public_key")

                if not public_key:
                    raise ValueError("La réponse /public-key ne contient pas de clé publique.")

                self.public_key_pem = public_key
                logger.info("Clé publique récupérée avec succès.")
                return public_key

            except Exception as exc:
                last_exception = exc
                logger.info("Serveur non prêt, tentative %s/10...", attempt)
                time.sleep(2)

        raise RuntimeError("Impossible de récupérer la clé publique du serveur.") from last_exception

    def perform_handshake(self) -> str:
        """
        Établit une session sécurisée avec le serveur.
        """
        if not self.public_key_pem:
            raise ValueError("La clé publique doit être récupérée avant le handshake.")

        self.aes_key = generate_aes_key()
        encrypted_session_key = encrypt_aes_key_with_rsa(self.public_key_pem, self.aes_key)

        url = f"{self.server_base_url}/handshake"
        payload = {
            "client_id": self.client_id,
            "encrypted_session_key": encrypted_session_key,
        }

        response = requests.post(url, json=payload, timeout=10)
        response.raise_for_status()

        data = response.json()
        session_id = data.get("session_id")

        if not session_id:
            raise ValueError("La réponse /handshake ne contient pas de session_id.")

        self.session_id = session_id
        logger.info("Handshake réussi. session_id=%s", self.session_id)
        return session_id

    def send_encrypted_message(self, message: str) -> str:
        """
        Chiffre le message avec AES, l'envoie au serveur, puis déchiffre la réponse.
        """
        if not self.aes_key:
            raise ValueError("Aucune clé AES disponible. Effectuez d'abord le handshake.")

        if not self.session_id:
            raise ValueError("Aucune session active. Effectuez d'abord le handshake.")

        encrypted_payload = encrypt_message_with_aes(message, self.aes_key)

        url = f"{self.server_base_url}/message"
        headers = {
            "X-Session-ID": self.session_id,
        }

        response = requests.post(url, json=encrypted_payload, headers=headers, timeout=10)
        response.raise_for_status()

        response_payload = response.json()
        decrypted_response = decrypt_response_with_aes(response_payload, self.aes_key)

        logger.info("Réponse du serveur déchiffrée avec succès.")
        return decrypted_response

    def run_demo(self) -> None:
        """
        Lance le scénario complet de démonstration.
        """
        print("=== Client de démonstration RSA/AES ===")
        print(f"Client ID : {self.client_id}")

        self.fetch_public_key()
        self.perform_handshake()

        print("Session sécurisée établie.")
        print("Saisissez un message à envoyer au serveur.")
        print("Tapez 'exit' pour quitter.\n")

        while True:
            user_message = input("Message > ").strip()

            if user_message.lower() in {"exit", "quit"}:
                print("Arrêt du client.")
                break

            if not user_message:
                print("Veuillez saisir un message non vide.")
                continue

            try:
                response_text = self.send_encrypted_message(user_message)
                print(f"Réponse déchiffrée du serveur : {response_text}\n")
            except requests.HTTPError as exc:
                error_text = exc.response.text if exc.response is not None else str(exc)
                print(f"Erreur HTTP : {error_text}\n")
            except Exception as exc:
                print(f"Erreur : {exc}\n")


def main() -> None:
    """
    Point d'entrée principal du client.
    """
    
    server_base_url = os.getenv("SERVER_BASE_URL", "http://rsa-server:8000").strip()

    try:
        client = SecureClientDemo(server_base_url=server_base_url)
        client.run_demo()
    except KeyboardInterrupt:
        print("\nInterruption utilisateur.")
    except Exception as exc:
        logger.exception("Échec du client de démonstration : %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()