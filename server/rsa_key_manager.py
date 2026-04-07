from __future__ import annotations

import base64
import logging
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


logger = logging.getLogger(__name__)


class RSAKeyManager:
    """
    Gère le cycle de vie des clés RSA du serveur :
    - chargement depuis le disque si elles existent
    - génération si elles n'existent pas
    - sauvegarde dans le répertoire de persistance
    - exposition de la clé publique au format PEM
    - déchiffrement de la clé de session AES transmise par le client
    """

    def __init__(
        self,
        key_dir: str = "keys",
        private_key_filename: str = "private_key.pem",
        public_key_filename: str = "public_key.pem",
        key_size: int = 2048,
    ) -> None:
        self.key_dir = Path(key_dir)
        self.private_key_path = self.key_dir / private_key_filename
        self.public_key_path = self.key_dir / public_key_filename
        self.key_size = key_size

        self._private_key: Optional[rsa.RSAPrivateKey] = None
        self._public_key: Optional[rsa.RSAPublicKey] = None

    def load_or_generate_keys(self) -> None:
        """
        Charge les clés si elles existent déjà.
        Sinon, génère une nouvelle paire RSA et la sauvegarde.
        """
        self.key_dir.mkdir(parents=True, exist_ok=True)

        if self.private_key_path.exists() and self.public_key_path.exists():
            logger.info("Clés RSA trouvées. Chargement depuis le disque.")
            self.load_keys()
            return

        logger.info("Aucune paire RSA existante trouvée. Génération de nouvelles clés.")
        self.generate_keys()
        self.save_keys()

    def load_keys(self) -> None:
        """
        Charge la clé privée et la clé publique depuis les fichiers PEM.
        """
        if not self.private_key_path.exists():
            raise FileNotFoundError(f"Clé privée introuvable: {self.private_key_path}")

        if not self.public_key_path.exists():
            raise FileNotFoundError(f"Clé publique introuvable: {self.public_key_path}")

        with self.private_key_path.open("rb") as private_file:
            private_key_data = private_file.read()

        with self.public_key_path.open("rb") as public_file:
            public_key_data = public_file.read()

        self._private_key = serialization.load_pem_private_key(
            private_key_data,
            password=None,
        )

        self._public_key = serialization.load_pem_public_key(public_key_data)

        logger.info("Clés RSA chargées avec succès.")

    def generate_keys(self) -> None:
        """
        Génère une nouvelle paire de clés RSA.
        """
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
        )
        self._public_key = self._private_key.public_key()

        logger.info("Nouvelle paire de clés RSA %s bits générée.", self.key_size)

    def save_keys(self) -> None:
        """
        Sauvegarde les clés au format PEM.
        """
        if self._private_key is None or self._public_key is None:
            raise ValueError("Impossible de sauvegarder des clés non initialisées.")

        private_pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        public_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        with self.private_key_path.open("wb") as private_file:
            private_file.write(private_pem)

        with self.public_key_path.open("wb") as public_file:
            public_file.write(public_pem)

        logger.info("Clés RSA sauvegardées dans %s", self.key_dir)

    def get_public_key_pem(self) -> str:
        """
        Retourne la clé publique PEM sous forme de chaîne texte.
        """
        if self._public_key is None:
            raise ValueError("Clé publique non chargée ou non générée.")

        public_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return public_pem.decode("utf-8")

    def decrypt_session_key(self, encrypted_key_b64: str) -> bytes:
        """
        Déchiffre la clé AES chiffrée par le client avec la clé publique RSA.
        L'entrée attendue est encodée en base64.

        :param encrypted_key_b64: clé AES chiffrée, encodée en base64
        :return: clé AES déchiffrée sous forme d'octets
        """
        if self._private_key is None:
            raise ValueError("Clé privée non chargée ou non générée.")

        try:
            encrypted_key = base64.b64decode(encrypted_key_b64)
        except Exception as exc:
            raise ValueError("Le champ encrypted_session_key n'est pas un base64 valide.") from exc

        try:
            decrypted_key = self._private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception as exc:
            raise ValueError("Échec du déchiffrement RSA de la clé de session.") from exc

        return decrypted_key

    @property
    def key_metadata(self) -> dict:
        """
        Retourne des métadonnées utiles pour l'endpoint /public-key.
        """
        return {
            "algorithm": "RSA",
            "key_size": self.key_size,
            "public_key": self.get_public_key_pem(),
        }