from datetime import datetime
from typing import Optional, List

import attrs
import pycti
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncConnection

from api.config import cfg
from exceptions import AdminIsNotLoginError
from models.admin import AdminModel
from models.blocked import BlockedModel
from models.hosts import HostModel
from models.ioc import IocModel
from schemas.admin import ListMalIpResponseSchema, ListingIocResponseSchema


@attrs.define
class EnrichService:
    """
    Enrich data with opencti data
    """
    opencti =  pycti.OpenCTIApiClient(cfg.opencti.url, cfg.opencti.token)


    def enrich(self, ip_address: str):
        """
        Enrich data with opencti data
        :param data:
        :return:
        """
        data = self.opencti.stix_cyber_observable.list(search=ip_address)
        return data[0]['objectLabel']

    async def add_iochost(self,conn: AsyncConnection, ip_address: str, hostname: str, apikey: str) -> int:
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
        )

        return (await conn.execute(query)).inserted_primary_key[0]

    async def list_iochost(self, hostname: Optional[str] = None, is_process: Optional[bool] = None, conn: AsyncConnection = None) -> List[ListingIocResponseSchema]:
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

        if hostname:
            query = query.where(
                IocModel.c.hostname == hostname
            )

        if is_process is not None:
            query = query.where(
                IocModel.c.is_process == is_process
            )
        data = (await conn.execute(query)).fetchall()
        all = []
        for row in data:
            all.append(
                ListingIocResponseSchema(
                    id=row.id,
                    ip_address=row.ip_address,
                    hostname=row.hostname,
                    is_process=row.is_process,
                    comment=row.comment
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
                    hostname=row.hostname
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
                    hostname=row.hostname
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

        query = BlockedModel.insert().values(
            mal_ip=ip,
            hostname=hostname,
        )

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



        await conn.execute(query)
        return True







