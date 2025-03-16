from typing import Optional
import attrs
from pydantic import BaseModel, Field
from enum import Enum

from sqlalchemy import BigInteger


class AdminLoginSchema(BaseModel):
    """
    Class For Schema Admin Login
    """
    name: str = Field(...)
    password: str = Field(...)

class AdminRoleEnum(str, Enum):
    """
    Enum for Admin
    """
    SUPERADMIN = 'superadmin'
    ADMIN = 'admin'

@attrs.define(slots=False)
class ApikeyResponseSchema:
    apikey: str = attrs.field()

@attrs.define(slots=False)
class ListingHostsResponseSchema:
    """
    Class For Listing Hosts Response Schema
    """
    id: int = attrs.field()
    name: str = attrs.field()
    ip: str = attrs.field()
    version_agent: int = attrs.field()
    os: str = attrs.field()
    group_id: int = attrs.field()
    group_name: str = attrs.field()

@attrs.define(slots=False)
class ListMalIpResponseSchema:
    """
    Class For Add Host Schema
    """
    id: int = attrs.field()
    ip_address: str = attrs.field()
    hostname: str = attrs.field()
    executed_time: BigInteger = attrs.field()


@attrs.define(slots=False)
class ListingIocResponseSchema:
    """
    Class For Add Host Schema
    """
    id: int = attrs.field()
    ip_address: str = attrs.field()
    hostname: str = attrs.field()
    is_process: bool = attrs.field()
    comment: str = attrs.field()

@attrs.define(slots=False)
class ReportResponseSchema:
    """
    Class For Report Response Schema
    """
    connected_agents: int = attrs.field()
    blocked_ips: int = attrs.field()
    active_alerts: int = attrs.field()


class UpdateAdminSchema(BaseModel):
    """
    Class For Schema Admin Login
    """
    name: Optional[str] = Field(None)
    password: Optional[str] = Field(None)

@attrs.define(slots=False)
class ReadAdminSchema:
    """
    Class For Schema Admin Login
    """
    id: int = attrs.field()
    name: str = attrs.field()
    apikey: str = attrs.field()

@attrs.define(slots=False)
class LogResponseSchema:
    """
    Class For Schema Admin Login
    """
    id: int = attrs.field()
    activity: str = attrs.field()


