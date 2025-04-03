import asyncio
from core.db import meta, engine
from models.admin import AdminModel
from models.groups import GroupModel
from models.ioc import IocModel
from models.hosts import HostModel
from models.blocked import BlockedModel
from models.log import LogsModel

async def main():
    async with engine.begin() as conn:

        await conn.run_sync(meta.drop_all)
        await conn.run_sync(meta.create_all, tables=[
            AdminModel,
            GroupModel,
            IocModel,
            HostModel,
            BlockedModel,
            LogsModel
        ] )

    await engine.dispose()

if __name__ == '__main__':
    asyncio.run(main())
