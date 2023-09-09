import os
import time
import json
import tqdm
import socket
import argparse
from enum import Enum
from typing import Dict
from threading import Thread


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

HEADER_LENGTH = 128
BUFFER_SIZE = 4096


def read_header(string: str):
    header = json.loads(string)
    header['type'] = MessageType(header['type'])
    return header


def format_header(header: Dict[str, int | str | MessageType]) -> str:
    header['type'] = header['type'].value
    l = len(json.dumps(header))
    if l > HEADER_LENGTH:
        raise Exception(f"Header too long, expected max {HEADER_LENGTH}, got {l}")
    elif l < HEADER_LENGTH:
        # add padding
        header['padding'] = '0'*(HEADER_LENGTH-l-len(', "padding": ')-2)

    return json.dumps(header)


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("port")
    parser.parse_args()
    return parser.port


def progress_bar(file, filesize: int, filename: str):
    bar = tqdm.tqdm(range(filesize), f"Sending {filename}", unit="B", unit_scale=True, unit_divisor=1024)
    while bar.n < filesize:
        # time.sleep(0.1)  # don't know if it's needed, we'll see when we set up machines
        bar.update(file.tell())


def listen(s: socket.socket):
    while status['listening']:
        header = read_header(s.recv(HEADER_LENGTH).decode())

        if header['type'] == MessageType.LEAVING:
            print("Other user just left, press ENTER to quit")
            status['quitRequest'] = True
            status['listening'] = False
        elif header['type'] == MessageType.LEAVING_TOO:
            status['listening'] = False
        elif header['type'] == MessageType.MESSAGE:
            message = s.recv(header['content_length']).decode()
            print(f"> {message}")
        elif header['type'] == MessageType.FILE_TRANSFER:
            fpath = 'data/receiver/' + os.path.basename(header['filename'])
            iterations = header['content_length'] // BUFFER_SIZE
            if header['content_length'] % BUFFER_SIZE:
                iterations += 1
            print(f"Receiving file {header['filename']} of size {header['content_length']}, needed iterations: {iterations}")
            with open(fpath, 'wb') as file:
                for _ in range(iterations):
                    bytes_read = s.recv(BUFFER_SIZE)
                    file.write(bytes_read)
            print("File received!")
        else:
            print(f"Unknown message type: {header['type']}")


def wait_for_input(s: socket.socket):
    while status['waiting']:
        message = input()

        header = {
            'content_length': len(message.encode())
        }
        if message == "/q":
            print("Leaving...")
            header['type'] = MessageType.LEAVING
            status['waiting'] = False
        elif status['quitRequest']:
            print("Leaving...")
            header['type'] = MessageType.LEAVING_TOO
            status['waiting'] = False
        elif message == "/f":
            # print("Provide path to file you wanna send: ", end="")
            # fpath = input()
            fpath = '/home/anton/studia/CipherTalk/data/sender/pytorch_model.bin'
            if os.path.isfile(fpath):
                header['type'] = MessageType.FILE_TRANSFER
                header['content_length'] = os.path.getsize(fpath)
                header['filename'] = os.path.basename(fpath)
                formatted_header = format_header(header)
                s.send(formatted_header.encode())
                print(f"Sending file {fpath} of size {header['content_length']}")
                with open(fpath, 'rb') as file:
                    progress_bar_thread = Thread(target=progress_bar, args=(file, header['content_length'], header['filename']))
                    progress_bar_thread.start()
                    s.sendfile(file)
                    progress_bar_thread.join()
                print("File sent!")
                continue
        else:
            header['type'] = MessageType.MESSAGE

        formatted_header = format_header(header)
        data = formatted_header + message
        s.send(data.encode())


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
    main()  # *get_arguments()
