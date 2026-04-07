from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi import Request
from middleware import SecurityMiddleware

from crypto_service import CryptoService
from models import (
    EncryptedMessageRequest,
    EncryptedMessageResponse,
    HandshakeRequest,
    HandshakeResponse,
    PublicKeyResponse,
)


from rsa_key_manager import RSAKeyManager
from session_manager import SessionManager


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)

logger = logging.getLogger(__name__)

# Services globaux
rsa_key_manager = RSAKeyManager(key_dir="keys")
session_manager = SessionManager(session_ttl_seconds=3600)
crypto_service = CryptoService()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Initialise les ressources critiques au démarrage de l'application.
    """
    logger.info("Initialisation du serveur sécurisé RSA/AES.")
    rsa_key_manager.load_or_generate_keys()
    logger.info("Serveur prêt.")
    yield
    logger.info("Arrêt du serveur sécurisé.")


app = FastAPI(
    title="RSA Secure API",
    description="API sécurisée avec handshake RSA et canal AES de session",
    version="1.0.0",
    lifespan=lifespan,
)
app.add_middleware(
    SecurityMiddleware,
    session_manager=session_manager,
    crypto_service=crypto_service,
    protected_paths={"/message"},
)

@app.get("/health")
def health_check() -> dict:
    """
    Endpoint technique simple pour vérifier que l'API répond.
    """
    return {"status": "ok"}


@app.get("/public-key", response_model=PublicKeyResponse)
def get_public_key() -> PublicKeyResponse:
    """
    Retourne la clé publique du serveur au format PEM.
    """
    try:
        return PublicKeyResponse(**rsa_key_manager.key_metadata)
    except Exception as exc:
        logger.exception("Erreur lors de la récupération de la clé publique.")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/handshake", response_model=HandshakeResponse)
def handshake(payload: HandshakeRequest) -> HandshakeResponse:
    """
    Reçoit la clé AES de session chiffrée par RSA, la déchiffre,
    crée une session et retourne un identifiant de session.
    """
    try:
        aes_key = rsa_key_manager.decrypt_session_key(payload.encrypted_session_key)

        session = session_manager.create_session(
            client_id=payload.client_id,
            aes_key=aes_key,
        )

        return HandshakeResponse(
            status="success",
            session_id=session.session_id,
            expires_in=session_manager.session_ttl_seconds,
        )

    except ValueError as exc:
        logger.warning("Handshake invalide pour client_id=%s : %s", payload.client_id, exc)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Erreur inattendue pendant le handshake.")
        raise HTTPException(status_code=500, detail="Erreur interne du serveur.") from exc

@app.post("/message", response_model=EncryptedMessageResponse)
def post_message(request: Request) -> EncryptedMessageResponse:
    """
    Route protégée par le middleware.
    """
    try:
        session = request.state.session
        decrypted_message = request.state.decrypted_message

        logger.info(
            "Message déchiffré reçu de client_id=%s, session_id=%s : %s",
            session.client_id,
            session.session_id,
            decrypted_message,
        )

        response_message = f"Message reçu avec succès: {decrypted_message}"

        encrypted_response = crypto_service.encrypt_message(
            plaintext=response_message,
            aes_key=session.aes_key,
        )

        return EncryptedMessageResponse(**encrypted_response)

    except Exception as exc:
        logger.exception("Erreur interne lors du traitement de /message.")
        raise HTTPException(status_code=500, detail="Erreur interne du serveur.") from exc
    
    
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """
    Gestionnaire global de secours pour éviter les erreurs non contrôlées.
    """
    logger.exception("Exception non gérée: %s", exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "Erreur interne non gérée."},
    )