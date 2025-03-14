import secrets
from typing import List

import attrs
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncConnection
from exceptions import AdminPasswordError, GroupNotFoundError
from helpers.authentication import PasswordHasher
from models.admin import AdminModel
from models.hosts import HostModel
from models.groups import GroupModel
from schemas.admin import ApikeyResponseSchema, ListingHostsResponseSchema


@attrs.define
class AdminRead:
    """
    Class For Admin
    """
    conn: AsyncConnection

    async def login(self, data: dict, hasher: PasswordHasher) -> str:
        """
        Method for login
        :param data:
        :param hasher:
        :return:
        """
        username = data['name']
        password = data['password']
        query = (
            select(
                AdminModel.c.password,
                AdminModel.c.name,
                AdminModel.c.uuid
            ).select_from(
                AdminModel
            )
        ).where(
            AdminModel.c.name == username
        )

        result = (await self.conn.execute(query)).first()

        if not hasher.verify(password, result.password):
            raise AdminPasswordError


        return str(result.uuid)

    async def generate_apikey(self, admin_id: int) -> str:
        """
        Generates a new API key asynchronously.

        This method generates a new API key securely, ensuring that the resulting
        key conforms to the required format and length. An API key is typically
        used to authenticate requests and grant access to specific operations
        or resources in your system. The key generation process is implemented
        asynchronously to allow for non-blocking operations in the application.

        :raises RuntimeError: If the key generation fails due to an internal
            error or other unexpected issues.

        :return: A newly generated API key which is a string.
        :rtype: str
        """
        try:
            apikey = secrets.token_urlsafe(32)
            query = AdminModel.update().where(AdminModel.c.id == admin_id).values(api_key=apikey)

            await self.conn.execute(query)
            return apikey
        except Exception as e:
            raise RuntimeError(f"Failed to generate API key: {e}")

    async def get_apikey(self, admin_id: int) -> ApikeyResponseSchema:
        """
        Retrieve the API key associated with the specified admin ID. This method is
        designed to fetch the API key asynchronously and is expected to only be used
        for valid administrative identifiers.

        :param admin_id: The unique identifier of the administrator for whom the
            API key is being requested.
        :return: A string representation of the API key associated with the specified
            admin ID.
        """
        query = select(
            AdminModel.c.api_key
        ).select_from(
            AdminModel
        ).where(
            AdminModel.c.id == admin_id
        )
        data = await self.conn.execute(query)

        return ApikeyResponseSchema(
            apikey=data.first().api_key
        )

    async def _validate_apikey(self, apikey: str) -> bool:
        """
        Validates the provided API key asynchronously to ensure it is legitimate and can
        be used for authorized operations. This internal method performs validation logic
        and returns a boolean indicating the API key's validity.

        :param apikey: The API key to be validated.
        :type apikey: str
        :return: A boolean value where True signifies a valid API key and False indicates
            an invalid API key.
        :rtype: bool
        """

        query = select(
            func.count(AdminModel.c.id)
        ).select_from(
            AdminModel
        ).where(
            AdminModel.c.api_key == apikey
        )

        result = (await self.conn.execute(query)).scalar()
        if result == 0:
            return False
        return True

    async def read_by_name(self, name: str):
        """
        Method for read by name
        :param name:
        :return:
        """
        query = (
            select(
                AdminModel.c.id
            ).select_from(AdminModel)
        ).where(
            AdminModel.c.uuid == name
        )

        return (await self.conn.execute(query)).first()

    async def add_group(self, name: str) -> int:
        """
        Adds a new group to the system.

        The method is responsible for handling the creation of a new group with the
        provided name. It operates asynchronously and ensures that the group is
        properly added. The group name must be a valid string.

        :param name: The name of the group to be added.
        :type name: str
        :return: A confirmation or result of the operation upon successful
            addition of the group.
        """

        query = GroupModel.insert().values(
            groups=name
        )


        return (await self.conn.execute(query)).inserted_primary_key[0]

    async def listing_host(self) -> List[ListingHostsResponseSchema]:
        """
        Listing all host
        :return:
        """
        query = (
            select(
                HostModel.c.id,
                HostModel.c.ip_address,
                HostModel.c.hostname,
                HostModel.c.os,
                HostModel.c.version_agent,
                GroupModel.c.groups
            ).select_from(
                HostModel.join(GroupModel)
            )
        )

        return [ListingHostsResponseSchema(
            id=host.id,
            ip=host.ip_address,
            name=host.hostname,
            group_id=host.groups,
            group_name=host.groups,
            os=host.os,
            version_agent=host.version_agent
        ) for host in await self.conn.execute(query)]

    async def add_host(self, apikey: str, ip_address: str, hostname: str, group:str,os: str, version_agent: str ) -> bool:
        """
        Adds a host to the system asynchronously using the provided API key.

        This method sends a request to the system to add a host associated with
        the specified API key. The result indicates whether the process was
        successful or not.

        :param apikey: The API key used to authenticate and identify the host
            to be added.
        :return: A boolean value indicating whether the host was successfully
            added or not.
        """
        query = select(
            func.count(AdminModel.c.id)
        ).select_from(
            AdminModel
        ).where(
            AdminModel.c.api_key == apikey
        )

        result = (await self.conn.execute(query)).scalar()
        if result == 0:
            return False

        _query_get_id_group = select(
            GroupModel.c.id
        ).select_from(
            GroupModel
        ).where(
            GroupModel.c.groups == group
        )

        group_id = (await self.conn.execute(_query_get_id_group)).first()

        if not group_id:
            raise GroupNotFoundError

        query = HostModel.insert().values(
            ip_address=ip_address,
            hostname=hostname,
            groups=group_id.id,
            os=os,
            version_agent=version_agent
        )
        _id = (await self.conn.execute(query)).inserted_primary_key[0]
        await self.conn.commit()
        return _id

    async def check_cred(self, apikey: str, hostname: str) -> bool:
        """
        Check credential
        :param apikey:
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

        result = (await self.conn.execute(query)).scalar()
        if result == 0:
            return False

        query = select(
            func.count(HostModel.c.id)
        ).select_from(
            HostModel
        ).where(
            HostModel.c.hostname == hostname
        )

        result = (await self.conn.execute(query)).scalar()
        if result == 0:
            return False

        return True



