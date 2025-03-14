from sqlalchemy import Table, Column, BigInteger, Unicode, DateTime, ForeignKey, Text, Boolean, UUID, String

from core.db import meta

HostModel = Table(
    'hosts', meta,
    Column('id', BigInteger, primary_key=True, autoincrement=True),
    Column('ip_address', Unicode(100), nullable=False, unique=True),
    Column('hostname', Unicode(100), nullable=False, unique=True),
    Column('groups', ForeignKey('groups.id'), nullable=False),
    Column('os', Unicode(250), primary_key=True),
    Column('version_agent', Unicode(250), nullable=True),
)
