import os
import sys
import time
import socket
import traceback
from cryptography.hazmat.primitives import serialization, hashes
from typing import Tuple
from libs.key_generation import generate_session_key
from libs.encryption_decryption import encrypt, decrypt, decrypt_private_key, encrypt_key, decrypt_key
from libs.formatting import read_header, format_header, HEADER_LENGTH, MessageType, CipherMode
from libs.utils import calculate_needed_iterations

from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

status = {
    "waiting": True,
    "listening": True,
    "connected": False,
    "logged_in": False
}

params = {
    "mode": CipherMode.ECB
}

BUFFER_SIZE = 4096


class WorkerSignals(QObject):
    """
    The goal of this class is to enable value return,
    during as well as at the end of a run.
    """
    finished = pyqtSignal()
    error = pyqtSignal(tuple)
    result = pyqtSignal(object)
    progress = pyqtSignal(tuple)


class Worker(QRunnable):
    """
    Thread class.
    Instances of this class are used to deliver jobs that would freeze the main window.
    """
    def __init__(self, fn, *args, **kwargs):
        super(Worker, self).__init__()

        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()

        self.kwargs['progress_callback'] = self.signals.progress

    @pyqtSlot()
    def run(self):
        try:
            result = self.fn(*self.args, **self.kwargs)
        except:
            traceback.print_exc()
            exctype, value = sys.exc_info()[:2]
            self.signals.error.emit((exctype, value, traceback.format_exc()))
        else:
            self.signals.result.emit(result)  # Return the result of the processing
        finally:
            self.signals.finished.emit()  # Done


def switch_encryption_mode() -> None:
    """
    Function switches between encryption modes.
    :return: None
    """

    params['mode'] = CipherMode.ECB if params['mode'] == CipherMode.CBC else CipherMode.CBC


def encrypt_and_send(s: socket, data: bytes, header: dict[str, int | CipherMode | MessageType]) -> None:
    """
    Function encrypts data, adds necessary fields to the header,
    encrypts data and sends it with optional info about used cryptography.

    :param s: Socket used for communication.
    :param data: Data to encrypt and send.
    :param header: Header with additional information about the data.
    :return: None
    """

    encrypted_data = encrypt('AES', params['mode'].value, params['session_key'], data)
    header['content_length'] = len(encrypted_data['ciphertext'])
    formatted_header = format_header(header)

    s.send(formatted_header.encode())
    if 'iv' in encrypted_data:
        s.send(encrypted_data['iv'])
    s.send(encrypted_data['ciphertext'])


def handle_incoming_traffic(s: socket.socket, progress_callback: pyqtBoundSignal) -> None:
    """
    Thread function that reads data coming through provided network socket.
    :param progress_callback: Object through which information to main thread will be sent.
    :param s: Socket used for communication.
    :return: None
    """

    print("Listening...")
    while status['listening']:
        header = read_header(s.recv(HEADER_LENGTH).decode())
        if not header:
            print("Header is None is handle_incoming_traffic(), exiting worker")
            return None

        elif header['type'] == MessageType.LEAVING:
            print("Other user just left")
            status['listening'] = False
            progress_callback.emit((MessageType.LEAVING, header['username']))

        elif header['type'] == MessageType.MESSAGE:
            iv = None
            if header['mode'] == CipherMode.CBC:
                iv = s.recv(16)
            message = decrypt('AES', header['mode'].value, params['session_key'], s.recv(header['content_length']), iv).decode()
            progress_callback.emit((MessageType.MESSAGE, message, header['username']))

        elif header['type'] == MessageType.FILE_TRANSFER:
            iv = None
            if header['mode'] == CipherMode.CBC:
                iv = s.recv(16)

            iterations = calculate_needed_iterations(header, BUFFER_SIZE)

            fpath = 'data/receiver/' + os.path.basename(header['filename'])
            with open(fpath, 'wb') as file:
                for _ in range(iterations):
                    bytes_read = s.recv(BUFFER_SIZE)
                    decrypted_bytes = decrypt('AES', header['mode'].value, params['session_key'], bytes_read, iv)
                    file.write(decrypted_bytes)
                    progress_callback.emit((MessageType.FILE_TRANSFER, header['content_length'], len(bytes_read)))

            progress_callback.emit((MessageType.FILE_RECEIVED, fpath))


def try_connect(host: str, port: int, my_username: str, progress_callback: pyqtBoundSignal) -> Tuple:
    """
    Worker function that tries to connect to the given address and port.

    :param host: Destination address.
    :param port: Destination port.
    :param my_username: Username set in main thread.
    :param progress_callback: _
    :return: None
    """

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    if status['connected']:
        print("Seems like you're already connected!")
        return None, None
    else:
        try:
            client.connect((host, port))

            # send SYN
            header = {'type': MessageType.SYN, 'username': my_username}
            client.send(format_header(header).encode())
            client.send(params['public_key'])
            print("SYN sent")

            # wait for SYN_ACK
            header = read_header(client.recv(HEADER_LENGTH).decode())
            if header['type'] == MessageType.SYN_ACK:
                print("SYN_ACK received")

                # read and decrypt session key
                encrypted_session_key = client.recv(BUFFER_SIZE)
                params['session_key'] = decrypt_key(params['private_key'], encrypted_session_key)
                print("Decrypted and saved session key")
                status['connected'] = True

                return client, header['username']

        except ConnectionRefusedError:
            print('User is currently offline, try again later')
            return None, None


def send_file(s: socket.socket, fpath: str, fsize: int, progress_callback: pyqtBoundSignal) -> None:
    """
    Worker function to send files. Files are being encrypted and divided into chunks of size
    BUFFER_SIZE, which by default equals 4096 bytes.

    :param s: Socket to send file through.
    :param fpath: File to path to send.
    :param fsize: Size of the file.
    :param progress_callback: Object through the progress of sending will be sent to the main thread.
    :return: None
    """
    header = {
        'mode': params['mode'],
        'type': MessageType.FILE_TRANSFER,
        'filename': os.path.basename(fpath)
    }

    with open(fpath, 'rb') as file:
        file_bytes = file.read()
    encrypted_file = encrypt('AES', params['mode'].value, params['session_key'], file_bytes)
    header['content_length'] = len(encrypted_file['ciphertext'])
    fraction = fsize/header['content_length']

    s.send(format_header(header).encode())
    if 'iv' in encrypted_file:
        s.send(encrypted_file['iv'])

    iterations = calculate_needed_iterations(header, BUFFER_SIZE)

    for i in range(iterations):
        data = encrypted_file['ciphertext'][BUFFER_SIZE * i:BUFFER_SIZE * i + BUFFER_SIZE]
        s.send(data)
        progress_callback.emit((MessageType.FILE_TRANSFER, len(data)*fraction))

    progress_callback.emit((MessageType.FILE_SENT,))


def listen(s: socket.socket, progress_callback: pyqtBoundSignal) -> Tuple:
    """
    Function that listens if other users want to connect.
    If so, the network socket is returned with the username of client.

    :param s: Socket to listen through.
    :param progress_callback: _
    :return: Netowrk socket, username of client.
    """

    s.listen(1)
    try:
        client, _ = s.accept()
        if not status['connected']:
            header = read_header(client.recv(HEADER_LENGTH).decode())
            if header['type'] == MessageType.SYN:
                print(f"DEBUG:: listen(): {header['username']}")
                return client, header['username']
    except OSError:
        # Main thread quits.
        print("Stopping listening worker")
        return None, None


def handshake(client: socket.socket, client_username: str, my_username: str, progress_callback: pyqtBoundSignal):
    """
    Function handles communication establishment. Protocol:
    Generate session key. Encrypt it using client's public key.
    Send encrypted session key.

    Returns network socket for communication, as well as client's username.
    :param client: Network socket to communicate through.
    :param client_username:
    :param my_username:
    :param progress_callback: _
    :return: socket.socket, str
    """

    # generate session key
    params['session_key'] = generate_session_key(128)

    # encrypt session key
    client_pub_key = client.recv(BUFFER_SIZE)
    client_pub_key = serialization.load_pem_public_key(client_pub_key)
    encrypted_session_key = encrypt_key(client_pub_key, params['session_key'])

    # send encrypted session key
    header = {'type': MessageType.SYN_ACK, 'username': my_username}
    client.send(format_header(header).encode())
    client.send(encrypted_session_key)

    status['connected'] = True
    return client, client_username


def worker_sleep(sec: float, progress_callback: pyqtBoundSignal):
    """
    Function puts worker to sleep for given amount of time.
    :param sec: Seconds to sleep.
    :param progress_callback: _
    :return:
    """
    time.sleep(sec)
    return True
