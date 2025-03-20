from datetime import datetime
from typing import Optional, List

import attrs
import pycti
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncConnection
import requests
from api.config import cfg
from exceptions import AdminIsNotLoginError
from models.admin import AdminModel
from models.blocked import BlockedModel

from models.ioc import IocModel
from models.log import LogsModel
from schemas.admin import ListMalIpResponseSchema, ListingIocResponseSchema, GeneralPaginationResponseSchema


@attrs.define
class EnrichService:
    """
    Enrich data with opencti data
    """
    opencti =  pycti.OpenCTIApiClient(cfg.opencti.url, cfg.opencti.token)


    def _abuse_ip(self, ip_address: str):
        url = "https://api.abuseipdb.com/api/v2/check"

        headers = {
            "Key": cfg.abuseip.token,
            "Accept": "application/json"
        }

    def enrich(self, ip_address: str):
        """
        Enrich data with opencti data
        :param data:
        :return:
        """
        data = self.opencti.stix_cyber_observable.list(search=ip_address)

        return data[0]['objectLabel'] if data else None

    async def add_iochost(self,conn: AsyncConnection, ip_address: str, hostname: str, apikey: str, comment: Optional[str] = None) -> int:
        """
        Add malicious ip to list watch by admin
        :param conn:
        :param ip_address:
        :param hostname:
        :param apikey:
        :return:
        """

        query = select(
            func.count(AdminModel.c.id)
        ).select_from(
            AdminModel
        ).where(
            AdminModel.c.api_key == apikey
        )

        result = (await conn.execute(query)).scalar()
        if result == 0:
            return False

        query = IocModel.insert().values(
            ip_address=ip_address,
            hostname=hostname,
            is_process=False,
            comment=comment if comment else None
        )

        query_log = LogsModel.insert().values(
            activity=f"Add ioc {ip_address} to watch list",
        )
        await conn.execute(query_log)

        return (await conn.execute(query)).inserted_primary_key[0]

    async def list_iochost(self,page: Optional[int] = 1, per_page: Optional[int] = 5, hostname: Optional[str] = None, is_process: Optional[bool] = None, conn: AsyncConnection = None, ip: Optional[str] = None) -> List[ListingIocResponseSchema]:
        """
        List all iocs ip
        :param hostname:
        :return:
        """
        query = select(
            IocModel.c.id,
            IocModel.c.ip_address,
            IocModel.c.hostname,
            IocModel.c.is_process,
            IocModel.c.comment
        ).select_from(
            IocModel
        )

        #pagination
        query = query.limit(per_page).offset((page - 1) * per_page)

        if hostname:
            query = query.where(
                IocModel.c.hostname == hostname
            )

        if is_process is not None:
            query = query.where(
                IocModel.c.is_process == is_process
            )
        if ip is not None:
            query = query.where(
                IocModel.c.ip_address == ip
            )

        query = query.order_by(IocModel.c.id.desc())
        data = (await conn.execute(query)).fetchall()

        _query_total = select(
            func.count(IocModel.c.id)
        ).select_from(
            IocModel
        )

        total = (await conn.execute(_query_total)).scalar()
        all = []
        for row in data:
            all.append(
                ListingIocResponseSchema(
                    id=row.id,
                    ip_address=row.ip_address,
                    hostname=row.hostname,
                    is_process=row.is_process,
                    comment=row.comment,
                    pagination=GeneralPaginationResponseSchema(
                        total=total,
                        page=page,
                        per_page=per_page
                    )

                )
            )
        return all


    async def add_mal_ip(self,conn: AsyncConnection, ip: str, hostname: str, apikey: str) -> int:
        """
        Add malicious ip to firewall
        :param ip:
        :param hostname:
        :return:
        """

        query = select(
            func.count(AdminModel.c.id)
        ).select_from(
            AdminModel
        ).where(
            AdminModel.c.api_key == apikey
        )

        result = (await conn.execute(query)).scalar()
        if result == 0:
            return False

        query = BlockedModel.insert().values(
            mal_ip=ip,
            hostname=hostname,
        )

        query_log = LogsModel.insert().values(
            activity=f"Add malicious ip {ip} to firewall",
        )

        await conn.execute(query_log)

        return (await conn.execute(query)).inserted_primary_key[0]

    async def list_mal_ip(self, hostname: Optional[str] = None, is_blocked: Optional[bool] = None, conn: AsyncConnection = None) -> List[ListMalIpResponseSchema]:
        """
        List all malicious ip
        :param hostname:
        :return:
        """
        query = select(
            BlockedModel.c.id,
            BlockedModel.c.mal_ip,
            BlockedModel.c.hostname,
            BlockedModel.c.executed_time
        ).select_from(
            BlockedModel
        )

        if hostname:
            query = query.where(
                BlockedModel.c.hostname == hostname
            )

        if is_blocked is not None:
            query = query.where(
                BlockedModel.c.is_blocked == is_blocked
            )

        data = (await conn.execute(query)).fetchall()
        all = []
        for row in data:
            all.append(
                ListMalIpResponseSchema(
                    id=row.id,
                    ip_address=row.mal_ip,
                    hostname=row.hostname,
                    executed_time=row.executed_time,
                )
            )
        return all

    async def list_mal_ip_general(self,apikey: str, hostname: Optional[str] = None, is_blocked: Optional[bool] = None,
                          conn: AsyncConnection = None) -> List[ListMalIpResponseSchema]:
        """
        List all malicious ip
        :param hostname:
        :return:
        """
        query_check = select(
            func.count(AdminModel.c.id)
        ).select_from(
            AdminModel
        ).where(
            AdminModel.c.api_key == apikey
        )
        result = (await conn.execute(query_check)).scalar()
        if result == 0:
            raise AdminIsNotLoginError

        query = select(
            BlockedModel.c.id,
            BlockedModel.c.mal_ip,
            BlockedModel.c.hostname,
            BlockedModel.c.executed_time
        ).select_from(
            BlockedModel
        )

        if hostname:
            query = query.where(
                BlockedModel.c.hostname == hostname
            )

        if is_blocked is not None:
            query = query.where(
                BlockedModel.c.is_blocked == is_blocked
            )
        data = (await conn.execute(query)).fetchall()

        all = []
        for row in data:
            all.append(
                ListMalIpResponseSchema(
                    id=row.id,
                    ip_address=row.mal_ip,
                    hostname=row.hostname,
                    executed_time=row.executed_time if row.executed_time else None,
                )
            )
        return all

    async def block_ip(self, ip: str, hostname: str, conn: AsyncConnection) -> int:
        """
        Block ip
        :param ip:
        :param hostname:
        :param conn:
        :return:
        """
        query = select(
            BlockedModel.c.id
        ).select_from(
            IocModel
        ).where(
            BlockedModel.c.mal_ip == ip
        )

        result = (await conn.execute(query)).fetchone()
        if result:
            return False

        query = IocModel.update().values(
            is_process=True
        ).where(
            IocModel.c.ip_address == ip
        )

        await conn.execute(query)

        query = BlockedModel.insert().values(
            mal_ip=ip,
            hostname=hostname,
        )

        query_log = LogsModel.insert().values(
            activity=f"Block malicious ip {ip}",
        )

        await conn.execute(query_log)

        return (await conn.execute(query)).inserted_primary_key[0]


    async def update_status(self, ip: str, status: bool,apikey: str, conn: AsyncConnection) -> int:
        """
        Update status of ip
        :param ip:
        :param status:
        :param conn:
        :return:
        """

        query = select(
            func.count(AdminModel.c.id)
        ).select_from(
            AdminModel
        ).where(
            AdminModel.c.api_key == apikey
        )

        result = (await conn.execute(query)).scalar()
        if result == 0:
            raise AdminIsNotLoginError

        time = int(datetime.now().timestamp())

        query = BlockedModel.update().where(
            BlockedModel.c.mal_ip == ip
        ).values(
            is_blocked=status,
            executed_time=time
        )


        query_log = LogsModel.insert().values(
            activity=f"Update status of malicious ip {ip} to {status}",
        )

        await conn.execute(query_log)


        await conn.execute(query)
        return True







