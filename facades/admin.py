from typing import Optional

import attrs
from sqlalchemy.ext.asyncio import AsyncConnection

from api.config import cfg
from services.admin import AdminRead
from exceptions import AdminPasswordError
from helpers.authentication import PasswordHasher
from helpers.token_maker import TokenMaker
from schemas.admin import AdminLoginSchema
from services.enrich import EnrichService
from fastapi import WebSocket
@attrs.define
class Admin:
    """
    Class for facades admin login
    """
    conn: AsyncConnection

    async def login(self, data: AdminLoginSchema, hasher: PasswordHasher):
        """
        Method for login
        :param data:
        :param hasher:
        :return:
        """
        data = data.__dict__
        try:
            check_login = await AdminRead(self.conn).login(data, hasher)
            token = TokenMaker()

            return token.return_token(
                cfg.password.token_key, check_login
            )
        except AdminPasswordError as e:
            raise AdminPasswordError

    async def generate_apikey(self, admin_id: int) -> str:
        """
        Asynchronously generates a unique API key associated with a given admin ID. The API key can be used for
        authentication and authorization purposes within the application. The process ensures the generated key
        is unique and can be traced back to the specified admin account.

        :param admin_id: The unique identifier of the admin for whom the API key is generated.
        :type admin_id: int

        :return: A newly generated string representing the unique API key.
        :rtype: str
        """

        return await AdminRead(self.conn).generate_apikey(admin_id)

    async def read_by_name(self, name: str):
        """
        Asynchronously retrieves an item by its name.

        This function is used to fetch a specific item from a data source using its name
        as a unique identifier. It returns the item if found, or an appropriate result
        if the item does not exist. This operation follows asynchronous patterns ensuring
        non-blocking behavior in runtime environments that support async programming.

        :param name: The unique identifier of the target item to be retrieved.
        :type name: str
        :return: The item corresponding to the provided name, or appropriate data if not
                 found.
        :rtype: Any
        """

        return await AdminRead(self.conn).read_by_name(name)

    async def add_group(self, name: str) -> int:
        """
        Adds a new group to the system.

        This method takes the name of the group to be added, stores it in the system,
        and returns the unique identifier (ID) corresponding to the newly created
        group. It is expected to be asynchronous and should work with an event loop.

        :param name: The name of the group to be added to the system.
        :type name: str
        :return: The unique identifier (ID) of the newly created group.
        :rtype: int
        """

        return await AdminRead(self.conn).add_group(name)

    async def add_host(self, apikey: str, ip_address: str, hostname: str, group:str,os: str, version_agent: str ) -> bool:
        """
        Adds a new host to the system with the provided details.

        This function asynchronously adds host information such as IP address,
        hostname, group, operating system, and agent version to the underlying
        system using the specified API key for authentication. The function
        ensures that the operation is completed before returning the result.

        :param apikey: API key used for authentication.
        :param ip_address: The IP address of the host to be added.
        :param hostname: The hostname of the host to be added.
        :param group: The name of the group to which the host belongs.
        :param os: The operating system running on the host.
        :param version_agent: The version of the agent running on the host.
        :return: A boolean indicating whether the host addition was successful.
        """

        return await AdminRead(self.conn).add_host(apikey, ip_address, hostname, group,os, version_agent)

    async def listing_host(self):
        """
        Lists all hosts in the system.

        This asynchronous function retrieves a list of all hosts stored in the system.
        The list includes details such as IP address, hostname, group, operating system,
        and agent version for each host. The function ensures that the data is fetched
        correctly and returned in the expected format.

        :return: A list of host details including IP address, hostname, group, operating
            system, and agent version.
        """
        return await AdminRead(self.conn).listing_host()
    async def get_apikey(self, admin_id: int) -> str:
        """
        Retrieves an API key associated with the given admin ID.

        This asynchronous function fetches an API key that corresponds to the specified
        admin ID. The admin ID must be valid to ensure an appropriate API key is
        returned.

        :param admin_id: Integer representing the administrator's unique ID.
        :return: A string containing the API key associated with the provided admin ID.
        """
        return await AdminRead(self.conn).get_apikey(admin_id)

    def enrich(self, ip_address: str):
        """
        Enrich data with opencti data
        :param data:
        :return:
        """
        return EnrichService().enrich(ip_address)

    async def add_mal_ip(self, ip: str, hostname: str, apikey: str) -> int:
        """
        Add malicious ip to firewall
        :param ip:
        :param hostname:
        :return:
        """
        return await EnrichService().add_mal_ip(self.conn, ip, hostname, apikey)

    async def add_ioc(self, ip: str, hostname: str, apikey: str) -> int:
        """
        Add malicious ip to firewall
        :param ip:
        :param hostname:
        :return:
        """
        return await EnrichService().add_iochost(self.conn, ip, hostname, apikey)

    async def list_mal_ip(self, hostname: str, is_blocked: bool):
        """
        List all malicious ip
        :param hostname:
        :return:
        """
        return await EnrichService().list_mal_ip(hostname, is_blocked, self.conn)

    async def list_mal_ip_general(self, hostname: str, is_blocked: bool, apikey: str):
        """
        List all malicious ip
        :param hostname:
        :return:
        """
        return await EnrichService().list_mal_ip_general(apikey, hostname, is_blocked, self.conn)

    async def list_ioc(self, hostname: Optional[str] = None, is_blocked: Optional[bool] = False):
        """
        List all iocs ip
        :param hostname:
        :return:
        """
        return await EnrichService().list_iochost(hostname, is_blocked, self.conn)

    async def block_ip(self, ip: str, hostname: str) -> int:
        """
        Block malicious ip
        :param ip:
        :param hostname:
        :return:
        """
        return await EnrichService().block_ip(ip, hostname, self.conn)

    async def update_statis(self, ip: str, status: bool, apikey: str) -> int:
        """
        Update status of ip
        :param ip:
        :param status:
        :return:
        """
        return await EnrichService().update_status(ip, status,apikey, self.conn)