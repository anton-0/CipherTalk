import os
import pickle
import argparse
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes

from libs.encryption_decryption import encrypt_private_key


def generate_session_key(key_size: int) -> bytes:
    return os.getrandom(key_size // 8)


def save_keys(private_key: bytes, public_key: bytes, local_key: bytes, iv: bytes, output_dir: str) -> Tuple:
    """
    Function simply saves keys in output_dir. Keys are also separated into hidden directories:
        .local      .private       .pub
    :return: Output dir.
    """

    if not output_dir.endswith('/'):
        output_dir += '/'

    # save local key
    local_dir = output_dir + '.local'
    if not os.path.exists(local_dir):
        os.makedirs(local_dir, exist_ok=True)
    with open(local_dir + '/local_key.p', 'wb') as f:
        pickle.dump({'key':local_key, 'iv':iv}, f)

    # save rsa key pair
    private_dir = output_dir + '.private'
    if not os.path.exists(private_dir):
        os.makedirs(private_dir, exist_ok=True)
    with open(private_dir + "/rsa_private.pem", "wb") as f:
        f.write(private_key)

    public_dir = output_dir + '.pub'
    if not os.path.exists(public_dir):
        os.makedirs(public_dir, exist_ok=True)
    with open(public_dir + "/rsa_public.pub", "wb") as f:
        f.write(public_key)

    return private_dir, public_dir, local_dir

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


def generate_and_save_all_keys(password: str, output_dir: str) -> Tuple:
    """
    Function generate RSA key par and local key.
    Local key is used to encrypt private key with AES algorithm in CBC mode.
    All keys are saved into different directories.
    :param password: Password used to encrypt private key.
    :param output_dir: Directory to store keys.
    :return: None
    """

    private_key, public_key = generate_rsa_key_pair(2048)
    local_key = generate_local_key(password)
    encrypted_private_key, iv, = encrypt_private_key(local_key, private_key)
    dirs = save_keys(encrypted_private_key, public_key, local_key, iv, output_dir)
    return dirs


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('password', type=str, help='Password to encode local key with.')
    parser.add_argument('output_dir', type=str, help='Directory in which you want to save the keys.')
    arguments = parser.parse_args()
    return arguments.password, arguments.output_dir


if __name__ == '__main__':
    dirs = generate_and_save_all_keys(*get_arguments())
    print('Keys generated and saved in:')
    for directory in dirs:
        print(directory, end='  ')
    print()

