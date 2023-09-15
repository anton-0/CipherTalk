import os
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from formatting import add_padding, remove_padding


def encrypt_key(encrypting_key: serialization.base.PublicKeyTypes, key_to_encrypt: bytes) -> bytes:
    """
    Function encrypts key using another key.
    :param encrypting_key: serialization.base.PublicKeyTypes
    :param key_to_encrypt: bytes
    :return: bytes
    """
    return encrypting_key.encrypt(
        key_to_encrypt,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decrypt_key(decrypting_key: serialization.base.PrivateKeyTypes, key_to_decrypt: bytes) -> bytes:
    """
    Function decrypts key using another key.
    :param decrypting_key: serialization.base.PrivateKeyTypes
    :param key_to_decrypt: bytes
    :return: bytes
    """
    return decrypting_key.decrypt(
        key_to_decrypt,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decrypt_private_key(encrypted_private_key: bytes, local_key: bytes, iv: bytes) -> serialization.base.PrivateKeyTypes:
    """
    Function decrypts provided private key using local key, AES algorithm in CBC mode.
    :param encrypted_private_key: bytes
    :param local_key: bytes
    :param iv: bytes
    :return: serialization.base.PrivateKeyTypes
    """
    cipher = Cipher(algorithms.AES(local_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    private_key_bytes_padded = decryptor.update(encrypted_private_key) + decryptor.finalize()
    private_key = remove_padding(private_key_bytes_padded, algorithms.AES.block_size)
    return serialization.load_pem_private_key(private_key, None)


def encrypt_private_key(local_key: bytes, private_key: bytes) -> Tuple[bytes, bytes]:
    """
    Function encrypts provided key using local key.
    For encryption algorithm AES in CBC mode is used.

    :param local_key: Key used for encryption.
    :param private_key: Key that is being encrypted.
    :return: Encrypted private key and initialization vector used in CBC mode.
    """

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(local_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    private_key_padded = add_padding(private_key, algorithms.AES.block_size)
    encrypted_private_key = encryptor.update(private_key_padded) + encryptor.finalize()

    return encrypted_private_key, iv


def ecb_encrypt(data: bytes, key: bytes) -> dict[str, bytes]:
    """
    Function encrypts data using AES algorithm and ECB mode.
    Padding is added to data before encryption.

    :param data: bytes
    :param key: int = 128
    :return: {'ciphertext': encrypted data}
    """

    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    data = add_padding(data, algorithms.AES.block_size)

    ct = encryptor.update(data) + encryptor.finalize()

    return {'ciphertext': ct}


def ecb_decrypt(ct: bytes, key: bytes) -> bytes:
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


def cbc_encrypt(data: bytes, key: bytes) -> dict[str, bytes]:
    """
    Function encrypts data using AES algorithm and CBC mode.
    Padding is added to data before encryption.
    Initialization vector is generated using system's RNG.

    :param data: bytes
    :param key: bytes
    :return: {'ciphertext': encrypted data, 'iv': initialization vector}
    """

    iv = os.urandom(algorithms.AES.block_size // 8)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    data = add_padding(data, algorithms.AES.block_size)

    ct = encryptor.update(data) + encryptor.finalize()

    return {'ciphertext': ct, 'iv': iv}


def cbc_decrypt(ct, iv, key) -> bytes:
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


def encrypt(algorithm: str, mode: str, key: bytes, data) -> dict[str, bytes]:
    """
    The function to encrypt data with given algorithm and mode.
    Raises ValueError if algorithm or mode is unknown.

    :raises ValueError:
    :param algorithm: str
    :param mode: str
    :param key: bytes
    :param data: bytes
    :return: dict[str, bytes]
    """

    if algorithm == 'AES':
        if mode == 'ECB':
            return ecb_encrypt(data, key)
        elif mode == 'CBC':
            return cbc_encrypt(data, key)
        else:
            raise ValueError(f"Unknown mode: {mode}")
    else:
        raise ValueError(f"Unknown algorithm: {algorithm}")


def decrypt(algorithm: str, mode: str, key: bytes, ct, additional=None) -> bytes | None:
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
