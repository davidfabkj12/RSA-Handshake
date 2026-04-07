def generate_rsa_keys() -> bytes:
    pass

def encrypt_aes_key_with_rsa(public_key_pem: bytes, aes_key: bytes) -> str:
    pass

def decrypt_aes_key_with_rsa(message: str, aes_key: bytes) -> dict:
    pass

def decrypt_response_with_aes(payload: dict, aes_key: bytes) -> str:
    pass