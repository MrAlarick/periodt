import abc


class Authenticator(abc.ABC):
    @abc.abstractmethod
    def verify(self, username: bytes, *args, **kwargs) -> bytes:
        """SMTP VRFY command"""