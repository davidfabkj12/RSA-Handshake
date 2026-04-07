class CryptoService:
    def __init__(self):
        pass

    def encrypt_message(self, plaintext: str, aes_key: bytes) -> dict:
        pass

    def decrypt_message(self, iv: str, ciphertext: str, tag: str, aes_key: bytes) -> str:
        pass