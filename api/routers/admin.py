from typing import Tuple, Optional

from fastapi import APIRouter, WebSocket
from fastapi import HTTPException, Depends
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection
from api.config import cfg
from api.depends.admin import get_id
from core.db import engine
from exceptions import AdminPasswordError, AdminIsNotLoginError, GroupNotFoundError
from facades.admin import Admin
from helpers.authentication import BasicSalt, PasswordHasher
from schemas.admin import AdminLoginSchema, UpdateAdminSchema

router = APIRouter(prefix='/admin', tags=["Admin"])

@router.post("/login")
async def login(data: OAuth2PasswordRequestForm = Depends()):
    """
    Route For Admin Login
    :param data:
    :return:
    """
    salt = BasicSalt(cfg.password.salt)
    hash_ = PasswordHasher(salt)
    async with engine.begin() as conn:
        try:
            return await Admin(
                conn
            ).login(
                AdminLoginSchema(
                    name=data.username,
                    password=data.password
                ), hash_
            )
        except AdminPasswordError:
            raise HTTPException(401, detail="Login Failed")

@router.post("/create-apikey")
async def generate_apikey(admin_conn: Tuple[int, AsyncConnection] = Depends(get_id)):
    """
    Handles the creation of an API key through an HTTP POST endpoint. The function
    essentially generates a new API key for authorized users who meet the required
    dependency checks. This API key could then be used for authorization of
    future operations.

    :param admin_conn: A tuple containing an integer ID and an
        AsyncConnection object, used to validate and retrieve the
        necessary administrative connection information.
    :return: The newly generated API key or an appropriate response
        based on the execution process.
    """
    admin_id, conn = admin_conn
    try:
        return await Admin(conn).generate_apikey(admin_id)
    except AdminIsNotLoginError:
        raise HTTPException(401, detail="Admin is not login")

@router.get("/get-apikey")
async def get_apikey(admin_conn: Tuple[int, AsyncConnection] = Depends(get_id)):
    admin_id, conn = admin_conn
    try:
        return await Admin(conn).get_apikey(admin_id)
    except AdminIsNotLoginError:
        raise HTTPException(401, detail="Admin is not login")


@router.post("/add-group")
async def add_group(name: str, admin_conn: Tuple[int, AsyncConnection] = Depends(get_id)):
    admin_id, conn = admin_conn
    try:
        return await Admin(conn).add_group(name)
    except AdminIsNotLoginError:
        raise HTTPException(401, detail="Admin is not login")
    except IntegrityError:
        raise HTTPException(409, detail="Group already exists")

@router.post("/add-host")
async def add_host(
    apikey: str,
    ip_address: str,
    hostname: str,
    group: str,
    os: str,
    version_agent: str,
):
    async with engine.connect() as conn:
        try:
            return await Admin(conn).add_host(apikey, ip_address, hostname, group,os, version_agent)
        except AdminIsNotLoginError:
            raise HTTPException(401, detail="Admin is not login")
        except GroupNotFoundError:
            raise HTTPException(404, detail="Group not found")
        except IntegrityError:
            raise HTTPException(409, detail="Host already exists")

@router.get("/report")
async def report(admin_conn: Tuple[int, AsyncConnection] = Depends(get_id)):
    admin_id, conn = admin_conn
    try:
        return await Admin(conn).report()
    except AdminIsNotLoginError:
        raise HTTPException(401, detail="Admin is not login")

@router.get("/list-hosts")
async def list_hosts(admin_conn: Tuple[int, AsyncConnection] = Depends(get_id)):
    admin_id, conn = admin_conn
    try:
        return await Admin(conn).listing_host()
    except AdminIsNotLoginError:
        raise HTTPException(401, detail="Admin is not login")


@router.get("/enrich/{ip_address}")
async def enrich(ip_address: str, admin_conn: Tuple[int, AsyncConnection] = Depends(get_id)):
    admin_id, conn = admin_conn
    try:
        return Admin(conn).enrich(ip_address)
    except AdminIsNotLoginError:
        raise HTTPException(401, detail="Admin is not login")
    except Exception as e:
        raise HTTPException(500, detail=str(e))

@router.get("/list-mal-ip")
async def list_mal_ip(hostname: Optional[str] = None, is_blocked: Optional[bool] = None, admin_conn: Tuple[int, AsyncConnection] = Depends(get_id), page: Optional[int] = 1, per_page: Optional[int] = 5):
    admin_id, conn = admin_conn
    try:
        return await Admin(conn).list_mal_ip(hostname, is_blocked, page, per_page)
    except AdminIsNotLoginError:
        raise HTTPException(401, detail="Admin is not login")
    except Exception as e:
        raise HTTPException(500, detail=str(e))

@router.get("/list-ioc")
async def list_ioc(ip:Optional[str] = None, page: Optional[int] = 1, per_page: Optional[int] = 5, hostname: Optional[str] = None, is_blocked: Optional[bool] = None, admin_conn: Tuple[int, AsyncConnection] = Depends(get_id)):
    admin_id, conn = admin_conn
    try:
        return await Admin(conn).list_ioc(page, per_page, hostname, is_blocked, ip)
    except AdminIsNotLoginError:
        raise HTTPException(401, detail="Admin is not login")
    except Exception as e:
        raise HTTPException(500, detail=str(e))

@router.post("/block-ip")
async def block_ip(ip: str, hostname: str, admin_conn: Tuple[int, AsyncConnection] = Depends(get_id)):
    admin_id, conn = admin_conn
    try:
        return await Admin(conn).block_ip(ip, hostname)
    except AdminIsNotLoginError:
        raise HTTPException(401, detail="Admin is not login")
    except Exception as e:
        raise HTTPException(500, detail=str(e))

@router.patch("/me/update")
async def update_me(data: UpdateAdminSchema, admin_conn: Tuple[int, AsyncConnection] = Depends(get_id)):
    admin_id, conn = admin_conn
    try:
        return await Admin(conn).update_me(admin_id, data)
    except AdminIsNotLoginError:
        raise HTTPException(401, detail="Admin is not login")
    except Exception as e:
        raise HTTPException(500, detail=str(e))

@router.get("/me")
async def get_admin(admin_conn: Tuple[int, AsyncConnection] = Depends(get_id)):
    admin_id, conn = admin_conn
    try:
        return await Admin(conn).get_admin(admin_id)
    except AdminIsNotLoginError:
        raise HTTPException(401, detail="Admin is not login")
    except Exception as e:
        raise HTTPException(500, detail=str(e))

@router.get("/log-activity")
async def log_activity(page: Optional[int] = 1, per_page: Optional[int] = 5, admin_conn: Tuple[int, AsyncConnection] = Depends(get_id)):
    admin_id, conn = admin_conn
    try:
        return await Admin(conn).list_log(page, per_page)
    except AdminIsNotLoginError:
        raise HTTPException(401, detail="Admin is not login")
    except Exception as e:
        raise HTTPException(500, detail=str(e))


@router.get("/check-reputation/{ip_address}")
def check_reputation(ip_address: str, admin_conn: Tuple[int, AsyncConnection] = Depends(get_id)):
    admin_id, conn = admin_conn
    try:
        return Admin(conn).check_reputation(ip_address)
    except AdminIsNotLoginError:
        raise HTTPException(401, detail="Admin is not login")
    except Exception as e:
        raise HTTPException(500, detail=str(e))





