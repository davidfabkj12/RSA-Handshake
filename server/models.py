class HandshakeRequest:
    client_id: str
    encrypted_session_key: str

class HandshakeResponse:
    status: str
    sesson_id: str
    expires_in: int

class EncryptedMessageRequest:
    iv: str
    ciphertext: str
    tag: str

class SessionData:
    client_id: str
    aes_key: bytes
    expires_at: float
    session_id: str