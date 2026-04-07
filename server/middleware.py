from __future__ import annotations

import json
import logging
from typing import Iterable, Optional, Set

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from crypto_service import CryptoService
from session_manager import SessionManager


logger = logging.getLogger(__name__)


class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Middleware de sécurité pour les routes protégées.

    Responsabilités :
    - vérifier la présence de X-Session-ID
    - valider l'existence et l'expiration de la session
    - lire le corps JSON chiffré
    - déchiffrer le message avec la clé AES de la session
    - placer le contenu déchiffré dans request.state
    - rejeter et journaliser toute requête invalide
    """

    def __init__(
        self,
        app,
        session_manager: SessionManager,
        crypto_service: CryptoService,
        protected_paths: Optional[Iterable[str]] = None,
    ) -> None:
        super().__init__(app)
        self.session_manager = session_manager
        self.crypto_service = crypto_service
        self.protected_paths: Set[str] = set(protected_paths or ["/message"])

    async def dispatch(self, request: Request, call_next):
        """
        Intercepte les requêtes destinées aux routes protégées.
        """
        if request.url.path not in self.protected_paths:
            return await call_next(request)

        session_id = request.headers.get("X-Session-ID")
        if not session_id:
            logger.warning("Accès rejeté : en-tête X-Session-ID absent.")
            return self._reject_unauthorized("En-tête X-Session-ID manquant.")

        session = self.session_manager.get_session(session_id)
        if session is None:
            logger.warning(
                "Accès rejeté : session absente, invalide ou expirée. session_id=%s",
                session_id,
            )
            return self._reject_unauthorized("Session invalide ou expirée.")

        try:
            request_body = await request.body()
            if not request_body:
                logger.warning("Accès rejeté : corps de requête vide.")
                return self._reject_bad_request("Corps de requête vide.")

            try:
                payload = json.loads(request_body.decode("utf-8"))
            except Exception:
                logger.warning("Accès rejeté : corps JSON invalide.")
                return self._reject_bad_request("Le corps de la requête doit être un JSON valide.")

            iv = payload.get("iv")
            ciphertext = payload.get("ciphertext")
            tag = payload.get("tag")

            if not iv or not ciphertext or not tag:
                logger.warning(
                    "Accès rejeté : payload chiffré incomplet pour session_id=%s",
                    session_id,
                )
                return self._reject_bad_request(
                    "Le payload doit contenir iv, ciphertext et tag."
                )

            decrypted_message = self.crypto_service.decrypt_message(
                iv=iv,
                ciphertext=ciphertext,
                tag=tag,
                aes_key=session.aes_key,
            )

            # On expose au handler le contexte déjà authentifié et déchiffré.
            request.state.session = session
            request.state.session_id = session.session_id
            request.state.client_id = session.client_id
            request.state.decrypted_message = decrypted_message

        except ValueError as exc:
            logger.warning(
                "Accès rejeté : échec du déchiffrement/authentification. session_id=%s erreur=%s",
                session_id,
                exc,
            )
            return self._reject_bad_request(str(exc))
        except Exception as exc:
            logger.exception(
                "Erreur inattendue dans le middleware de sécurité pour session_id=%s : %s",
                session_id,
                exc,
            )
            return JSONResponse(
                status_code=500,
                content={"detail": "Erreur interne du middleware de sécurité."},
            )

        return await call_next(request)

    @staticmethod
    def _reject_unauthorized(detail: str) -> JSONResponse:
        return JSONResponse(
            status_code=401,
            content={"detail": detail},
        )

    @staticmethod
    def _reject_bad_request(detail: str) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            content={"detail": detail},
        )