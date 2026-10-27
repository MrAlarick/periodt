import abc


class Sender(abc.ABC):
    @abc.abstractmethod
    def put(self, data: bytes, reverse_path: bytes, forward_path: list, *args, **kwargs) -> bytes:
        """SMTP"""


class ChunkingSender(Sender):
    @abc.abstractmethod
    def chunking_put(self, data: bytes, reverse_path: bytes, forward_path: list, *args, **kwargs) -> tuple(bool, bytes):
        """SMTP"""

    @abc.abstractmethod
    def check_size(self, size: int) -> bool:
        """SIZE check resources"""
        return True

    def check_rcpt_size(self, rcpt: bytes, size: int) -> bool:
        """"""
        return True

    def check_rcpt_curr_size(self, rcpt: bytes, size: int) -> bool:
        """"""
        return True