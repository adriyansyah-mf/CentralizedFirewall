from typing import AsyncIterator, Tuple

from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy.ext.asyncio import AsyncConnection

from api.config import cfg
from core.db import engine
from exceptions import AdminNotFoundError
from facades.admin import Admin
from helpers.token_maker import TokenMaker

admin_login_schema = OAuth2PasswordBearer(
    tokenUrl="/admin/login", scheme_name="Admin", auto_error=True
)
async def get_connection() -> AsyncConnection:
    """
    method untuk get connection ke database
    """
    async with engine.begin() as conn:
        yield conn


async def get_name(token: str = Depends(admin_login_schema)) -> str:
    """
    get name from token
    """
    try:
        new_token = TokenMaker().verify_token(token, cfg.password.token_key)
        return new_token["uuid"]
    except JWTError as e:
        raise HTTPException(401, {"msg": str(e)}) from e

async def get_id(
    conn: AsyncConnection = Depends(get_connection), uuid_: str = Depends(get_name)
) -> AsyncIterator[Tuple[int, AsyncConnection]]:
    """
    get id by token
    """
    a = Admin(conn)
    try:
        row = await a.read_by_name(uuid_)
    except AdminNotFoundError as e:
        raise HTTPException(401, {"msg": "silahkan login"}) from e

    yield row.id, conn
