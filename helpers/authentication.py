import attrs

from abc import ABCMeta
from abc import abstractmethod

from passlib.context import CryptContext






class SaltAbc(metaclass=ABCMeta):
    """
    Abstract buat salt
    """

    def __init__(self, salt: str):
        self.salt = salt

    @abstractmethod
    def __call__(self, password: str) -> str:
        """
        Method utama untuk memberikan salt ke password

        :param password: password untuk di berikan salt
        """


class BasicSalt(SaltAbc):
    """
    memberikan salt pada password
    """

    def __call__(self, password: str) -> str:
        """
        Method utama untuk memberikan salt ke password

        :param password: password untuk di berikan salt
        """
        return f"{self.salt}/{password}\\{self.salt}"


@attrs.define(slots=False)
class PasswordHasher:
    """
    helper untuk hash password
    """
    salt_method: SaltAbc
    context: CryptContext = attrs.Factory(lambda: CryptContext(schemes=["bcrypt"], deprecated="auto"))

    def hash(self, password: str) -> str:
        """
        Hash Password dengan salt

        :param password: password untuk di hash
        """
        salted = self.salt_method(password)

        return self.context.hash(salted)

    def verify(self, plain_password: str, hashed_password: str) -> bool:
        """
        Check apakah password benar atau tidak

        Note: method sama dengan ``CryptContext.verify``, method ini untuk memberikan penjelasan tambahan

        :param plain_password: password yang tidak di hash
        :param hashed_password: password yang di hash
        :return: ``True`` kalau benar, ``False`` kalau tidak
        """
        salted = self.salt_method(plain_password)

        return self.context.verify(salted, hashed_password)
