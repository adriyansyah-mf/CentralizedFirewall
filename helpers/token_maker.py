from typing import Dict, Any
from jose import JWTError, jwt
from fastapi import HTTPException


class TokenMaker:
    def create_token(self, key: str, name: str) -> str:
        """
        membuat token baru
        """
        val: Dict[str, Any] = {"uuid": name}

        return jwt.encode(val, key, algorithm="HS256")

    def verify_token(self, token: str, key: str) -> dict:
        """
        memverify token
        """
        try:
            return jwt.decode(token, key, algorithms=["HS256"])
        except JWTError as e:
            raise HTTPException(401, {"msg": str(e)}) from e

    def return_token(self, key: str, name: str) -> dict:
        """
        return token
        """
        return {
            "access_token": self.create_token(key, name),
            "type": "bearer",
        }
