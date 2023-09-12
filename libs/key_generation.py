import os
import pickle
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes

from libs.encryption_decryption import encrypt_private_key

def generate_session_key(key_size: int) -> bytes:
    return os.getrandom(key_size // 8)


def save_keys(private_key: bytes, public_key: bytes, local_key: bytes, iv: bytes) -> None:

    # save local key
    local_dir = '../keys/.local'
    if not os.path.exists(local_dir):
        os.mkdir(local_dir)
    with open(local_dir + '/local_key.p', 'wb') as f:
        pickle.dump({'key':local_key, 'iv':iv}, f)

    # save rsa key pair
    private_dir = '../keys/.private'
    if not os.path.exists(private_dir):
        os.mkdir(private_dir)
    with open(private_dir + "/rsa_private.pem", "wb") as f:
        f.write(private_key)

    public_dir = '../keys/.pub'
    if not os.path.exists(public_dir):
        os.mkdir(public_dir)
    with open(public_dir + "/rsa_public.pub", "wb") as f:
        f.write(public_key)


def generate_local_key(password: str) -> bytes:
    """
    Function generates local key (SHA function)
    :param password: Passphrase from which hash is going to be generated.
    :return: Hash
    """

    digest = hashes.Hash(hashes.SHA256())
    digest.update(password.encode())
    local_key = digest.finalize()

    return local_key


def generate_rsa_key_pair(private_key_size: int) -> Tuple[bytes, bytes]:
    """
    Function generates RSA key pair.
    :param private_key_size: Must be one of values 1024, 2048, 4096.
    :return: private and public keys
    """

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=private_key_size
    )

    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem_private_key, pem_public_key


def generate_and_save_all_keys(password: str) -> None:
    """
    Function generate RSA key par and local key.
    Local key is used to encrypt private key with AES algorithm in CBC mode.
    All keys are saved into different directories.
    :param password: Password used to encrypt private key.
    :return: None
    """

    private_key, public_key = generate_rsa_key_pair(2048)
    local_key = generate_local_key(password)
    encrypted_private_key, iv, = encrypt_private_key(local_key, private_key)
    save_keys(encrypted_private_key, public_key, local_key, iv)


if __name__ == '__main__':
    # generate_and_save_all_keys('strongpass')
    pass

