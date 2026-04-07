from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional


logger = logging.getLogger(__name__)


@dataclass
class SessionData:
    """
    Représente une session sécurisée active.
    """
    client_id: str
    session_id: str
    aes_key: bytes
    expires_at: datetime


class SessionManager:
    """
    Gère les sessions actives en mémoire.
    Chaque session contient :
    - l'identifiant du client
    - l'identifiant de session
    - la clé AES de session
    - la date d'expiration
    """

    def __init__(self, session_ttl_seconds: int = 3600) -> None:
        self.session_ttl_seconds = session_ttl_seconds
        self.sessions: Dict[str, SessionData] = {}

    def create_session(self, client_id: str, aes_key: bytes) -> SessionData:
        """
        Crée une nouvelle session pour un client et la stocke en mémoire.
        """
        if not client_id:
            raise ValueError("client_id ne peut pas être vide.")

        if not aes_key:
            raise ValueError("La clé AES ne peut pas être vide.")

        self.remove_expired_sessions()

        session_id = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=self.session_ttl_seconds)

        session = SessionData(
            client_id=client_id,
            session_id=session_id,
            aes_key=aes_key,
            expires_at=expires_at,
        )

        self.sessions[session_id] = session

        logger.info(
            "Nouvelle session créée pour client_id=%s, session_id=%s, expiration=%s",
            client_id,
            session_id,
            expires_at.isoformat(),
        )

        return session

    def get_session(self, session_id: str) -> Optional[SessionData]:
        """
        Retourne la session correspondant au session_id, si elle existe
        et n'est pas expirée.
        """
        if not session_id:
            return None

        session = self.sessions.get(session_id)
        if session is None:
            return None

        if self._is_expired(session):
            logger.warning("Session expirée détectée: session_id=%s", session_id)
            self.sessions.pop(session_id, None)
            return None

        return session

    def is_valid(self, session_id: str) -> bool:
        """
        Vérifie si une session existe encore et n'est pas expirée.
        """
        return self.get_session(session_id) is not None

    def remove_expired_sessions(self) -> None:
        """
        Supprime toutes les sessions expirées.
        """
        now = datetime.now(timezone.utc)
        expired_session_ids = [
            session_id
            for session_id, session in self.sessions.items()
            if session.expires_at <= now
        ]

        for session_id in expired_session_ids:
            self.sessions.pop(session_id, None)

        if expired_session_ids:
            logger.info(
                "Sessions expirées supprimées: %s",
                ", ".join(expired_session_ids),
            )

    def get_aes_key(self, session_id: str) -> Optional[bytes]:
        """
        Retourne la clé AES associée à une session valide.
        """
        session = self.get_session(session_id)
        if session is None:
            return None
        return session.aes_key

    def delete_session(self, session_id: str) -> bool:
        """
        Supprime explicitement une session.
        Retourne True si elle existait, sinon False.
        """
        if session_id in self.sessions:
            self.sessions.pop(session_id, None)
            logger.info("Session supprimée: session_id=%s", session_id)
            return True
        return False

    def _is_expired(self, session: SessionData) -> bool:
        """
        Indique si une session est expirée.
        """
        return session.expires_at <= datetime.now(timezone.utc)