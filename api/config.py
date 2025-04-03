import os
import environ as environ
import dotenv

dotenv.load_dotenv(os.environ.get("ENV_PATH", None))

@environ.config()
class Jwt:
    secret: str = environ.var()

@environ.config()
class Password:
    salt: str = environ.var()
    token_key: str = environ.var()

@environ.config()
class Opencti:
    url: str = environ.var()
    token: str = environ.var()

@environ.config(prefix="")
class Config:
    """
    class config
    """
    db: str = environ.var()
    jwt: Jwt = environ.group(Jwt)
    password: Password = environ.group(Password)
    opencti: Opencti = environ.group(Opencti)
    abuseipdb_api_key: str = environ.var()

cfg: Config = environ.to_config(Config)
