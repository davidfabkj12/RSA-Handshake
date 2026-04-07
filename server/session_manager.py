class SessionManager:
    def __init__(self):
       pass

    def create_session(self, client_id: str, aes_key: bytes) -> str:
        pass

    def get_session(self, session_id: str):
        pass

    def is_valid(self, session_id: str) -> bool:
        pass

    def remove_expired_sessions(self):
        pass