import os
from enum import Enum
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class CipherMode(Enum):
    ECB = "ECB"
    CBC = "CBC"


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


def ecb_encrypt(data: bytes, key_size: int = 128):
    """
    The function to encrypt data with AES algorithm and ECB mode.
    The padding is added to data before encryption.
    Key size must be one of (128, 192, 256).
    Key is generated using system's RNG.

    :param data: bytes
    :param key_size: int = 128
    :return: {'ciphertext': encrypted data, 'key': key used in encryption, 'additional': None}
    """
    key = os.urandom(key_size // 8)
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    data = add_padding(data, algorithms.AES.block_size)

    ct = encryptor.update(data) + encryptor.finalize()

    return {'ciphertext': ct, 'key': key, 'additional': None}


def ecb_decrypt(ct: bytes, key: bytes):
    """
    The function to decrypt data, encrypted with AES algorithm and ECB mode.
    The padding is removed from data after decryption.

    :param ct: bytes
    :param key: bytes
    :return: decrypted data: bytes
    """
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ct) + decryptor.finalize()
    try:
        data = remove_padding(padded_data, algorithms.AES.block_size)
    except ValueError:
        data = padded_data
    return data


def cbc_encrypt(data, key_size=128):
    """
    The function to encrypt data with AES algorithm and CBC mode.
    The padding is added to data before encryption.
    Key size must be one of (128, 192, 256).
    Key and initialization vector is generated using system's RNG.

    :param data: bytes
    :param key_size: int = 128
    :return: {'ciphertext': encrypted data, 'key': key used in encryption, 'additional': initialization vector}
    """
    key = os.urandom(key_size // 8)
    iv = os.urandom(algorithms.AES.block_size // 8)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    data = add_padding(data, algorithms.AES.block_size)

    ct = encryptor.update(data) + encryptor.finalize()

    return {'ciphertext': ct, 'key': key, 'additional': iv}


def cbc_decrypt(ct, iv, key):
    """
    The function to decrypt data, encrypted with AES algorithm and CBC mode.
    The padding is removed from data after decryption.
    The initialization vector generated before encryption must be provided as parameter.

    :param ct: bytes
    :param iv: bytes
    :param key: bytes
    :return: decrypted data: bytes
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ct) + decryptor.finalize()
    try:
        data = remove_padding(padded_data, algorithms.AES.block_size)
    except ValueError:
        data = padded_data
    return data


def add_header(file_localization: str, algorithm: str, mode: str, additional: bytes = None, shape: (int, int) = None):
    """
    The function adds all the information provided as parameters to the metadata of the file specified as a path.

    :param shape: if file is image, width and height
    :param file_localization: str
    :param algorithm: str
    :param mode: str
    :param additional: bytes
    :return: None
    """
    os.setxattr(file_localization, 'user.alg', bytes(algorithm.encode('ascii')))
    os.setxattr(file_localization, 'user.mode', bytes(mode.encode('ascii')))
    if mode == 'CBC':
        os.setxattr(file_localization, 'user.add', additional)
    if shape is not None:
        os.setxattr(file_localization, 'user.width', shape[0].to_bytes(4, 'big'))
        os.setxattr(file_localization, 'user.height', shape[1].to_bytes(4, 'big'))


def read_header(file_localization: str):
    """
    The function reads all the information needed to decryption, such as algorithm, mode and additional data
    e.g. initialization vector, nonce, and returns it as dictionary.

    :param file_localization: str
    :return: {'algorithm': algorithm,
              'mode': mode,
              'additional': additional data,
              'shape': shape if encrypted file is image}
    """
    algo = os.getxattr(file_localization, 'user.alg').decode('ascii')
    mode = os.getxattr(file_localization, 'user.mode').decode('ascii')
    additional = None
    shape = None
    if mode == 'CBC':
        additional = os.getxattr(file_localization, 'user.add')
    if 'user.width' in os.listxattr(file_localization):
        width = int.from_bytes(os.getxattr(file_localization, 'user.width'), 'big')
        height = int.from_bytes(os.getxattr(file_localization, 'user.height'), 'big')
        shape = (width, height)

    return {'algorithm': algo, 'mode': mode, 'additional': additional, 'shape': shape}


def encrypt(algorithm: str, mode: str, key_len: int, data):
    """
    The function to encrypt data with given algorithm and mode.
    Raises ValueError if algorithm or mode is unknown.

    :raises ValueError:
    :param algorithm: str
    :param mode: str
    :param key_len: int
    :param data: bytes
    :return: None
    """
    if algorithm == 'AES':
        if mode == 'ECB':
            return ecb_encrypt(data, key_len)
        elif mode == 'CBC':
            return cbc_encrypt(data, key_len)
        else:
            raise ValueError(f"Unknown mode: {mode}")
    else:
        raise ValueError(f"Unknown algorithm: {algorithm}")


def decrypt(algorithm: str, mode: str, key: bytes, ct, additional=None):
    """
    The function to decrypt data with given algorithm, mode and key.
    Raises ValueError if algorithm or mode is unknown.

    :raises ValueError:
    :param algorithm: str
    :param mode: str
    :param key: bytes
    :param additional: bytes
    :param ct: bytes
    :return: Optional[bytes]
    """
    if algorithm == 'AES':
        if mode == 'ECB':
            return ecb_decrypt(ct, key)
        elif mode == 'CBC':
            if additional is None:
                raise ValueError('CBC mode requires providing an initialization vector')
            return cbc_decrypt(ct, additional, key)
        else:
            print('Cannot resolve mode:', mode)
            return None
    else:
        print('Cannot resolve algorithm:', algorithm)
        return None
