import sys
import argparse

from libs.app import UiMainWindow, QApplication

def main(username, host, dest):
    app = QApplication(sys.argv)
    window = UiMainWindow(username, host, dest)
    window.setWindowTitle("CipherTalk")
    window.show()
    sys.exit(app.exec_())


def get_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument('name', type=str, help='Username.')
    parser.add_argument('host', type=str, help='IP addres and port through which you want to communicate. Splitted by a semicolon.')
    parser.add_argument('dest', type=str, help='Destination IP addres and port. Splitted by a semicolon.')
    arguments = parser.parse_args()

    return arguments.name, arguments.host, arguments.dest


if __name__ == "__main__":
    main(*get_arguments())
