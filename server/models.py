from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class PublicKeyResponse(BaseModel):
    """
    Réponse de l'endpoint GET /public-key
    """
    algorithm: str = Field(..., example="RSA")
    key_size: int = Field(..., example=2048)
    public_key: str


class HandshakeRequest(BaseModel):
    """
    Requête reçue par POST /handshake
    """
    client_id: str = Field(..., min_length=1, example="550e8400-e29b-41d4-a716-446655440000")
    encrypted_session_key: str = Field(..., min_length=1)


class HandshakeResponse(BaseModel):
    """
    Réponse renvoyée après un handshake réussi
    """
    status: str = Field(..., example="success")
    session_id: str
    expires_in: int = Field(..., example=3600)


class EncryptedMessageRequest(BaseModel):
    """
    Corps d'une requête POST /message
    """
    iv: str = Field(..., min_length=1)
    ciphertext: str = Field(..., min_length=1)
    tag: str = Field(..., min_length=1)


class EncryptedMessageResponse(BaseModel):
    """
    Réponse chiffrée renvoyée par le serveur
    """
    iv: str = Field(..., min_length=1)
    ciphertext: str = Field(..., min_length=1)
    tag: str = Field(..., min_length=1)


class ErrorResponse(BaseModel):
    """
    Réponse d'erreur standard
    """
    detail: str


class SessionModel(BaseModel):
    """
    Modèle de session utile pour représentation ou debug contrôlé.
    Il ne doit pas être exposé publiquement avec la clé AES.
    """
    client_id: str
    session_id: str
    expires_at: datetime


class DecryptedMessageContext(BaseModel):
    """
    Représente un message déchiffré prêt à être traité applicativement.
    Peut être utile si on veut structurer le passage entre middleware et logique métier.
    """
    message: str


class AuthenticatedRequestContext(BaseModel):
    """
    Contexte minimal d'une requête authentifiée.
    """
    client_id: str
    session_id: str