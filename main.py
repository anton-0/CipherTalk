import sys
import argparse

from libs.app import UiMainWindow, QApplication

def main(username, host_port, dest_address, dest_port):
    app = QApplication(sys.argv)
    window = UiMainWindow(username, host_port, dest_address, dest_port)
    window.show()
    sys.exit(app.exec_())


def get_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument('name', type=str, help='Username.')
    parser.add_argument('host_port', type=int, help='Port which will be exposed for incoming traffic.')
    parser.add_argument('dest_address', type=str, help='Destination address.')
    parser.add_argument('dest_port', type=int, help='Port of destination address.')
    arguments = parser.parse_args()
    return arguments.name, arguments.host_port, arguments.dest_address, arguments.dest_port


if __name__ == "__main__":
    main(*get_arguments())
