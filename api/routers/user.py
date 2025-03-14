

from fastapi import APIRouter, HTTPException

from core.db import engine
from facades.admin import Admin



router = APIRouter(prefix='/general', tags=["General"])

@router.post("/add-ip")
async def add_ip(
    ip: str,
    hostname: str,
    apikey: str,
):
    """
    Add malicious IP to the firewall
    :param ip:
    :param hostname:
    :param apikey:
    :param admin_conn:
    :return:
    """
    async with engine.begin() as conn:

        return await Admin(conn).add_ioc(ip, hostname, apikey)


@router.get("/list-ips")
async def list_ips(
    hostname: str,
    apikey: str,
):
    """
    List all malicious IP addresses
    :param hostname:
    :param is_blocked:
    :param admin_conn:
    :return:
    """
    is_blocked = False
    async with engine.begin() as conn:

        return await Admin(conn).list_mal_ip_general(hostname, is_blocked, apikey)

@router.patch("/update-status")
async def update_status(
    ip: str,
    status: bool,
    apikey: str,
):
    """
    Update status of IP address
    :param ip:
    :param status:
    :param apikey:
    :param admin_conn:
    :return:
    """
    async with engine.begin() as conn:
        return await Admin(conn).update_statis(ip, status, apikey)

