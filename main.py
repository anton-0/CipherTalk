import os
import time
import json
import tqdm
import socket
import argparse
from enum import Enum
from typing import Dict
from threading import Thread

from libs.encryption_decryption import CipherMode, encrypt, decrypt

class MessageType(Enum):
    MESSAGE = 1
    LEAVING = 2
    LEAVING_TOO = 3
    FILE_TRANSFER = 4


status = {
    "waiting": True,
    "listening": True,
    "quitRequest": False
}


params = {
    "key": b'T\x04\xc3\x1c\xe6\xfc_\xc9\xbeg\x88L\xd4\x05\xf9S',
    "mode": CipherMode.ECB
}


HEADER_LENGTH = 128
BUFFER_SIZE = 4096


def read_header(string: str) -> Dict[str, int | str | MessageType | CipherMode]:
    """
    Function reads header, parsing some fields into Enums.

    Returns a header which is a json dict.
    :param string:
    :return: dict[str, int | str | MessageType | CipherMode]
    """

    header = json.loads(string)
    header['type'] = MessageType(header['type'])
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

    header['mode'] = header['mode'].value
    header['type'] = header['type'].value
    header['info'] = info
    l = len(json.dumps(header))
    if l > HEADER_LENGTH:
        raise Exception(f"Header too long, expected max {HEADER_LENGTH}, got {l}")
    elif l < HEADER_LENGTH:
        header['padding'] = '0'*(HEADER_LENGTH-l-len(', "padding": ')-2)

    return json.dumps(header)


def switch_encryption_mode() -> None:
    """
    Function switches between encryption modes.
    :return: None
    """

    params['mode'] = CipherMode.ECB if params['mode'] == CipherMode.CBC else CipherMode.CBC


def listen(s: socket.socket):
    """
    Thread function that reads data coming to provided network socket.
    :param s: socket
    :return: None
    """

    while status['listening']:
        header = read_header(s.recv(HEADER_LENGTH).decode())

        if header['type'] == MessageType.LEAVING:
            print("Other user just left, press ENTER to quit")
            status['quitRequest'] = True
            status['listening'] = False

        elif header['type'] == MessageType.LEAVING_TOO:
            status['listening'] = False

        elif header['type'] == MessageType.MESSAGE:
            iv = None
            if header['mode'] == CipherMode.CBC:
                iv = s.recv(16)
            message = decrypt('AES', header['mode'].value, params['key'], s.recv(header['content_length']), iv).decode()
            print(f"> {message}")

        elif header['type'] == MessageType.FILE_TRANSFER:
            iv = None
            if header['mode'] == CipherMode.CBC:
                iv = s.recv(16)

            iterations = header['content_length'] // BUFFER_SIZE
            if header['content_length'] % BUFFER_SIZE:
                iterations += 1

            bar = tqdm.tqdm(range(header['content_length']), f"Receiving {header['filename']}", unit="B", unit_scale=True, unit_divisor=1024)
            fpath = 'data/receiver/' + os.path.basename(header['filename'])
            with open(fpath, 'wb') as file:
                for _ in range(iterations):
                    bytes_read = s.recv(BUFFER_SIZE)
                    decrypted_bytes = decrypt('AES', header['mode'].value, params['key'], bytes_read, iv)
                    file.write(decrypted_bytes)
                    bar.update(len(bytes_read))
                bar.disable = True

            bar.update(len(bytes_read))
            print("File received!")

        else:
            print(f"Unknown message type: {header['type']}")


def encrypt_and_send(s: socket, data: bytes, header: dict[str, int | CipherMode | MessageType]) -> None:
    """
    Function encrypts data, adds necessary fields to the header,
    encrypts data and sends it with optional info about used cryptography.

    :param s: socket
    :param data: bytes
    :param header: dict[str, int | CipherMode | MessageType]
    :return: None
    """

    encrypted_data = encrypt('AES', params['mode'].value, params['key'], data)
    header['content_length'] = len(encrypted_data['ciphertext'])
    formatted_header = format_header(header)

    s.send(formatted_header.encode())
    if 'iv' in encrypted_data:
        s.send(encrypted_data['iv'])
    s.send(encrypted_data['ciphertext'])


def wait_for_input(s: socket.socket):
    """
    Thread function that waits for user input and sends data through provided network socket.

    :param s: socket
    :return: None
    """

    while status['waiting']:
        message = input()

        header = {
            'mode': params['mode']
        }
        if message == "/q":
            print("Leaving...")
            header['type'] = MessageType.LEAVING
            s.send(format_header(header).encode())
            status['waiting'] = False

        elif status['quitRequest']:
            print("Quitting...")
            header['type'] = MessageType.LEAVING_TOO
            status['waiting'] = False
            s.send(format_header(header).encode())

        elif message == "/f":
            fpath = '/home/anton/studia/CipherTalk/data/sender/pytorch_model.bin'
            if os.path.isfile(fpath):
                header['type'] = MessageType.FILE_TRANSFER
                header['filename'] = os.path.basename(fpath)
#
                with open(fpath, 'rb') as file:
                    file_bytes = file.read()
                encrypted_file = encrypt('AES', params['mode'].value, params['key'], file_bytes)
                header['content_length'] = len(encrypted_file['ciphertext'])

                s.send(format_header(header).encode())
                if 'iv' in encrypted_file:
                    s.send(encrypted_file['iv'])

                iterations = header['content_length'] // BUFFER_SIZE
                if header['content_length'] % BUFFER_SIZE:
                    iterations += 1

                bar = tqdm.tqdm(range(header['content_length'] + 1), f"Sending {header['filename']}",
                                     unit="B", unit_scale=True, unit_divisor=1024)

                for i in range(iterations):
                    data = encrypted_file['ciphertext'][BUFFER_SIZE*i:BUFFER_SIZE*i+BUFFER_SIZE]
                    s.send(data)
                    bar.update(len(data))
                bar.disable = True

                print("File sent!")
                continue

        elif message == "/m":
            switch_encryption_mode()

        else:
            header['type'] = MessageType.MESSAGE
            encrypt_and_send(s, message.encode(), header)


def main():
    host = socket.gethostname()
    port = 4002
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        s.bind((host, port))
        s.listen(1)
        print("Waiting for other user to connect...")
        client, _ = s.accept()
        print("Other user connected!")
    except OSError:
        s.connect((host, port))
        client = s
        print("Connected to other user!")

    listening_thread = Thread(target=listen, args=(client,))
    waiting_input_thread = Thread(target=wait_for_input, args=(client,))

    listening_thread.start()
    waiting_input_thread.start()

    listening_thread.join()
    waiting_input_thread.join()

    s.shutdown(socket.SHUT_RDWR)
    s.close()


if __name__ == "__main__":
    main()
