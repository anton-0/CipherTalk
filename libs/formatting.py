import json
from enum import Enum
from typing import Dict
from cryptography.hazmat.primitives import padding


class CipherMode(Enum):
    ECB = "ECB"
    CBC = "CBC"


class MessageType(Enum):
    MESSAGE = 1
    LEAVING = 2
    SYN = 4
    SYN_ACK = 5
    FILE_TRANSFER = 6
    FILE_RECEIVED = 7
    FILE_SENT = 8
    INFO = 9


HEADER_LENGTH = 128

def add_padding(data: bytes, block_size: int):
    """
    The function to add padding to data given as parameter.
    The size of data is expended by null bytes, so it is divisible by the block_size.

    :param data: bytes
    :param block_size: int
    :return: bytes
    """

    padder = padding.PKCS7(block_size).padder()
    padded_data = padder.update(data)
    return padded_data + padder.finalize()


def remove_padding(data: bytes, block_size: int):
    """
    The function to remove earlier added padding.
    Removes null bytes added by padder.

    :param data: bytes
    :param block_size: int
    :return: bytes
    """

    unpadder = padding.PKCS7(block_size).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def read_header(string: str) -> Dict[str, int | str | MessageType | CipherMode]:
    """
    Function reads header, parsing some fields into Enums.

    Returns a header which is a json dict or None in special cases.
    :param string:
    :return: dict[str, int | str | MessageType | CipherMode] | None
    """

    if not string:
        return None
    header = json.loads(string)
    header['type'] = MessageType(header['type'])
    if 'mode' in header:
        header['mode'] = CipherMode(header['mode'])
    return header


def format_header(header: Dict[str, int | str | MessageType | CipherMode], info='') -> str:
    """
    Function formats header to serializable format.
    Also adds padding to fixed size length.

    Returns serialized json header.
    :param header: dict[str, int | str | MessageType | CipherMode]
    :param info: str
    :return: str
    """
    if 'mode' in header:
        header['mode'] = header['mode'].value
    header['type'] = header['type'].value
    header['info'] = info
    l = len(json.dumps(header))
    if l > HEADER_LENGTH:
        raise Exception(f"Header too long, expected max {HEADER_LENGTH}, got {l}")
    elif l < HEADER_LENGTH:
        header['padding'] = '0'*(HEADER_LENGTH-l-len(', "padding": ')-2)

    return json.dumps(header)

