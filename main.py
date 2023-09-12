import os
import tqdm
import socket
import pickle
import argparse

from threading import Thread
from cryptography.hazmat.primitives import serialization, hashes

from libs.key_generation import generate_session_key
from libs.encryption_decryption import encrypt, decrypt, decrypt_private_key, encrypt_key, decrypt_key
from libs.formatting import read_header, format_header, HEADER_LENGTH, MessageType, CipherMode
from libs.utils import calculate_needed_iterations


status = {
    "waiting": True,
    "listening": True,
    "quitRequest": False,
    "connected": False
}


params = {
    "mode": CipherMode.ECB
}

BUFFER_SIZE = 4096


def switch_encryption_mode() -> None:
    """
    Function switches between encryption modes.
    :return: None
    """

    params['mode'] = CipherMode.ECB if params['mode'] == CipherMode.CBC else CipherMode.CBC


def listen(s: socket.socket) -> None:
    """
    Thread function that reads data coming to provided network socket.
    :param s: socket
    :return: None
    """

    print("Listening...")
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
            message = decrypt('AES', header['mode'].value, params['session_key'], s.recv(header['content_length']), iv).decode()
            print(f"> {message}")

        elif header['type'] == MessageType.FILE_TRANSFER:
            iv = None
            if header['mode'] == CipherMode.CBC:
                iv = s.recv(16)

            iterations = calculate_needed_iterations(header, BUFFER_SIZE)

            bar = tqdm.tqdm(range(header['content_length']), f"Receiving {header['filename']}", unit="B", unit_scale=True, unit_divisor=1024)
            fpath = 'data/receiver/' + os.path.basename(header['filename'])
            with open(fpath, 'wb') as file:
                for _ in range(iterations):
                    bytes_read = s.recv(BUFFER_SIZE)
                    decrypted_bytes = decrypt('AES', header['mode'].value, params['session_key'], bytes_read, iv)
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

    encrypted_data = encrypt('AES', params['mode'].value, params['session_key'], data)
    header['content_length'] = len(encrypted_data['ciphertext'])
    formatted_header = format_header(header)

    s.send(formatted_header.encode())
    if 'iv' in encrypted_data:
        s.send(encrypted_data['iv'])
    s.send(encrypted_data['ciphertext'])


def wait_for_input(s: socket.socket) -> None:
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

                with open(fpath, 'rb') as file:
                    file_bytes = file.read()
                encrypted_file = encrypt('AES', params['mode'].value, params['session_key'], file_bytes)
                header['content_length'] = len(encrypted_file['ciphertext'])

                s.send(format_header(header).encode())
                if 'iv' in encrypted_file:
                    s.send(encrypted_file['iv'])

                iterations = calculate_needed_iterations(header, BUFFER_SIZE)

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

        # normal message was provided, just check if not empty
        elif len(message):
            header['type'] = MessageType.MESSAGE
            encrypt_and_send(s, message.encode(), header)


def input_thread_func(s: socket.socket):
    s.listen(1)
    try:
        client, _ = s.accept()
    except OSError:
        print("Stopping listening thread")
        return

    if not status['connected']:
        header = read_header(client.recv(HEADER_LENGTH).decode())
        if header['type'] == MessageType.SYN:
            print("SYN Message received, generating, encrypting and sending session key")
            # generate session key
            params['session_key'] = generate_session_key(128)

            # encrypt session key
            client_pub_key = client.recv(BUFFER_SIZE)
            client_pub_key = serialization.load_pem_public_key(client_pub_key)
            encrypted_session_key = encrypt_key(client_pub_key, params['session_key'])

            # send encrypted session key
            header = {'type': MessageType.SYN_ACK}
            client.send(format_header(header).encode())
            client.send(encrypted_session_key)

            status['connected'] = True

            output_thread = Thread(target=wait_for_input, args=(client,))
            output_thread.start()
            listen(client)
            output_thread.join()

    client.shutdown(socket.SHUT_RDWR)
    client.close()


def output_thread_func(host: str, port: int):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"Available commands: /q - quit, /c - connect to other user")

    while not status['connected']:
        cmd = input()
        if cmd == '/q':
            print("Quitting...")
            break
        elif cmd == '/c':
            if status['connected']:
                print("Seems like you're already connected!")
                break
            try:
                client.connect((host, port))

                # send SYN
                header = {'type': MessageType.SYN}
                client.send(format_header(header).encode())
                client.send(params['public_key'])

                # wait for SYN_ACK
                header = read_header(client.recv(HEADER_LENGTH).decode())
                if header['type'] == MessageType.SYN_ACK:
                    print("SYN_ACK Message received")

                    # read and decrypt session key
                    encrypted_session_key = client.recv(BUFFER_SIZE)
                    params['session_key'] = decrypt_key(params['private_key'], encrypted_session_key)
                    print("Decrypted and saved session key")
                    status['connected'] = True

                    input_thread = Thread(target=listen, args=(client,))
                    input_thread.start()
                    wait_for_input(client)
                    input_thread.join()

            except ConnectionRefusedError:
                print('User is currently offline, try again later using /c command')

    client.close()


def main(name, host_port, dest_port):
    print(f"Hello user {name}!")

    # load keys
    with open('keys/.private/rsa_private.pem', 'rb') as f:
        encrypted_private_key = f.read()

    with open('keys/.local/local_key.p', 'rb') as f:
        local_key = pickle.load(f)

    with open('keys/.pub/rsa_public.pub', 'rb') as f:
        params['public_key'] = f.read()

    # authentication & authorization
    while True:
        password = input("Provide your password: ")
        digest = hashes.Hash(hashes.SHA256())
        digest.update(password.encode())
        provided_local_key = digest.finalize()

        if provided_local_key == local_key['key']:
            params['private_key'] = decrypt_private_key(encrypted_private_key, local_key['key'], local_key['iv'])
            print("Private key decrypted")
            break
        else:
            print("Wrong pass!")

    # open sockets and start threads for communication
    host = socket.gethostname()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, host_port))

    listening_thread = Thread(target=input_thread_func, args=(s,))
    output_thread = Thread(target=output_thread_func, args=(host, dest_port))

    listening_thread.start()
    output_thread.start()

    output_thread.join()
    s.shutdown(socket.SHUT_RDWR)
    s.close()
    listening_thread.join()


def get_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument('name', type=str, help='Username.')
    parser.add_argument('host_port', type=int, help='Port which will be exposed for incoming traffic.')
    parser.add_argument('dest_port', type=int, help='Port of destination address.')
    arguments = parser.parse_args()
    return arguments.name, arguments.host_port, arguments.dest_port


if __name__ == "__main__":
    main(*get_arguments())
