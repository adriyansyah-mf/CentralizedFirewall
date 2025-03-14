from sqlalchemy import MetaData
from sqlalchemy.ext.asyncio import create_async_engine
from api.config import cfg

meta = MetaData()
engine = create_async_engine(cfg.db, pool_pre_ping=True)