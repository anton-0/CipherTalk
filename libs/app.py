import pickle

from libs.workers import *
from uis.dialogs import ConnectionDialog

class UiMainWindow(QMainWindow):
    def __init__(self, username: str, host_port: int, dest_address: str, dest_port: int):
        super().__init__()
        self.setObjectName("self")
        self.resize(650, 580)

        self.centralwidget = QWidget(self)
        self.centralwidget.setObjectName("centralwidget")

        self.background = QLabel(self.centralwidget)
        self.background.setGeometry(QRect(-10, 0, 861, 661))
        self.background.setStyleSheet("background-color: rgb(192, 191, 188);")
        self.background.setText("")
        self.background.setObjectName("background")

        self.input_field = QTextEdit(self.centralwidget)
        self.input_field.setEnabled(True)
        self.input_field.setGeometry(QRect(100, 450, 310, 41))
        self.input_field.setStyleSheet("")
        self.input_field.setObjectName("input_field")

        self.send_button = QPushButton(
            self.centralwidget,
            clicked=lambda: self.on_send_clicked(
                self.input_field.toPlainText()
            )
        )
        self.send_button.setEnabled(False)
        self.send_button.setGeometry(QRect(415, 450, 80, 41))
        self.send_button.setObjectName("send_button")

        self.file_button = QPushButton(
            self.centralwidget,
            clicked=lambda: self.on_file_clicked()
        )
        self.file_button.setEnabled(False)
        self.file_button.setGeometry(QRect(500, 450, 80, 41))
        self.file_button.setText("File")
        self.file_button.setObjectName("file_button")

        self.progress_bar = QProgressBar(self.centralwidget)
        self.progress_bar.setGeometry(QRect(20, 510, 250, 20))
        self.progress_bar.setMinimum(0)

        self.output_field = QTextEdit(self.centralwidget)
        self.output_field.setEnabled(True)
        self.output_field.setGeometry(QRect(100, 90, 395, 350))
        self.output_field.setObjectName("output_field")

        self.password_field = QLineEdit(self.centralwidget)
        self.password_field.setGeometry(QRect(380, 20, 160, 38))
        self.password_field.setAlignment(Qt.AlignRight)
        self.password_field.setEchoMode(QLineEdit.Password)
        self.password_field.setObjectName("password_field")

        self.password_button = QPushButton(
            self.centralwidget,
            clicked=lambda: self.on_login_clicked(
                self.password_field.text()
            )
        )
        self.password_button.setGeometry(QRect(550, 20, 70, 38))
        self.password_button.setObjectName("password_button")

        self.mode_button = QPushButton(
            self.centralwidget,
            clicked=lambda: self.on_mode_clicked()
        )
        self.mode_button.setGeometry(QRect(500, 500, 80, 41))
        self.mode_button.setObjectName("mode_button")

        self.mode_label = QLabel(self.centralwidget)
        self.mode_label.setGeometry(QRect(325, 500, 170, 41))
        self.mode_label.setStyleSheet("background-color: rgb(246, 245, 244);")
        self.mode_label.setAlignment(Qt.AlignCenter)
        self.mode_label.setObjectName("mode_label")

        self.setCentralWidget(self.centralwidget)
        self.statusbar = QStatusBar(self)
        self.statusbar.setObjectName("statusbar")
        self.setStatusBar(self.statusbar)

        self.logged_status_label = QLabel(self.statusbar)
        self.logged_status_label.setGeometry(QRect(310, 0, 120, 20))
        self.logged_status_label.setText("Unsigned")
        self.logged_status_label.setObjectName("logges_status_label")

        self.connection_status_label = QLabel(self.statusbar)
        self.connection_status_label.setGeometry(QRect(430, 0, 150, 20))
        self.connection_status_label.setText("Offline")
        self.connection_status_label.setObjectName("connection_status_label")
        
        self.connect_button = QPushButton(
            self.centralwidget,
            clicked=lambda:self.on_connect_clicked(dest_address, dest_port)
        )
        self.connect_button.setGeometry(QRect(20, 20, 100, 40))
        self.connect_button.setObjectName("connect_button")
        self.connect_button.setEnabled(False)

        self.retranslate_ui()

        load_keys()

        self.fpath = None
        self.username = username
        self.threadpool = QThreadPool()
        self.host_port = host_port
        self.socket = None
        self.client = None
        self.dialog = None

    def on_file_clicked(self):
        """
        Functino handles File button clicks.
        Lets user choose a file to send.
        :return:
        """
        self.fpath = QFileDialog.getOpenFileName(self,'Select file')[0]
        self.input_field.setText(
            f"{os.path.basename(self.fpath)} - {os.path.getsize(self.fpath)}"
        )

    def on_mode_clicked(self):
        """
        Function handles Switch Mode button clicks.
        :return:
        """
        switch_encryption_mode()
        label = self.mode_label.text()[:-3] + params['mode'].value
        self.mode_label.setText(label)

    def setup_socket(self, host_port: int):
        """
        Functions sets up socket, user is technically online after listening worker starts.
        :param host_port: Port to listen on.
        :return:
        """
        host = socket.gethostname()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((host, host_port))
        worker_listening = Worker(listen, self.socket)
        worker_listening.signals.result.connect(self.user_wants_to_connect)
        self.threadpool.start(worker_listening)

    def user_wants_to_connect(self, args):
        """
        Function handles return value of worker that listened on socket, waiting for users to connect.
        :param args: (socket | None, username: str | None)
        :return:
        """
        client = args[0]
        client_username = args[1]
        if client is not None:

            self.dialog = ConnectionDialog()
            self.dialog.button_box.clicked.connect(self.connect_dialog)
            self.dialog.exec_()

            if status['connection_accepted']:
                worker_handshake = Worker(handshake, client, client_username, self.username)
                worker_handshake.signals.result.connect(self.start_communication)
                self.threadpool.start(worker_handshake)

    def connect_dialog(self, i: QPushButton):
        """
        Handles output of the dialog window.
        :param i: Button pushed.
        :return:
        """
        status['connection_accepted'] = True if i.text().endswith('Yes') else False
        self.dialog.close()

    def closeEvent(self, event):
        """
        Function handles quitting procedure.
        Information about leaving is sent.
        Sockets are being closed.
        :param event:
        :return:
        """
        if self.client:
            print('CLOSING CLIENT')
            header = {
                'type': MessageType.LEAVING,
                'username': self.username
            }
            formatted_header = format_header(header)
            self.client.send(formatted_header.encode())
            self.client.close()

        if self.socket:
            print('CLOSING SOCKET')
            self.socket.shutdown(socket.SHUT_RDWR)
            self.socket.close()

    def on_connect_clicked(self, dest_address: str, dest_port: int):
        """
        Function handles Connect button clicks.
        Start worker trying to connect to given address.
        :param dest_address: Destination addres
        :param dest_port: Destination port
        :return:
        """
        host = socket.gethostname()
        worker_connecting = Worker(try_connect, host, dest_port, self.username)
        worker_connecting.signals.result.connect(self.start_communication)

        self.threadpool.start(worker_connecting)

    def start_communication(self, args):
        """
        Function starts worker listening on just connected socket.
        Also enables necessary buttons and updates status.
        :param args: (socket, username: str)
        :return:
        """
        if args:
            client = args[0]
            username = args[1]
            if client:
                self.client = client
                worker_incoming_traffic = Worker(handle_incoming_traffic, client)
                worker_incoming_traffic.signals.progress.connect(self.incoming_traffic_progress)
                self.threadpool.start(worker_incoming_traffic)
                self.send_button.setEnabled(True)
                self.file_button.setEnabled(True)
                self.connection_status_label.setText(f"Connected to {username}")

    def incoming_traffic_progress(self, args):
        """
        Function handles messages|files incomming from worker thread listening on connected socket.
        :param args: (MessageType, message: str | filename: str, username: str)
        :return:
        """
        if args[0] == MessageType.MESSAGE:
            self.update_chat_field((MessageType.MESSAGE, args[1], args[2]))

        elif args[0] == MessageType.LEAVING:
            self.user_left()

        elif args[0] == MessageType.FILE_TRANSFER:
            if self.progress_bar.value() <= 0:
                self.progress_bar.setMaximum(args[1])
            self.update_progress_bar(args[2])

        elif args[0] == MessageType.FILE_RECEIVED:
            fname = os.path.basename(args[1])
            print(f"Received {fname}\nSaved in {args[1]}")
            self.statusbar.showMessage(f"Received a file {fname}", 3000)
            self.progress_bar.setValue(self.progress_bar.maximum())
            self.progress_bar.setStyleSheet("selection-background-color: rgb(6, 191, 15);")
            worker_sleeper = Worker(worker_sleep, 3.0)
            worker_sleeper.signals.result.connect(self.reset_bar)
            self.threadpool.start(worker_sleeper)

    def user_left(self):
        """
        Function handles situation when user to whom self was connected, left.
        Updating status of buttons, labels, params.
        Closing network sockets.
        :return:
        """
        self.send_button.setEnabled(False)
        self.file_button.setEnabled(False)
        self.connection_status_label.setText("Online")
        self.client.close()
        self.client = None
        status['connected'] = False

        if self.socket is None:
            self.setup_socket(self.host_port)

    def reset_bar(self):
        """
        Function resets progress bar to inital state.
        :return:
        """
        self.progress_bar.setValue(0)
        self.progress_bar.setStyleSheet("")

    def on_login_clicked(self, password: str):
        """
        Function handles log in/out button clicks.
        It also delivers procedure of logging in, that means:
        Comparing hash of provided password to the local key.
        If they are the same, user is loggin in and private key may be encrypted.
        :param password: Password provided by the user.
        :return:
        """
        if not status['logged_in']:
            # authentication & authorization
            digest = hashes.Hash(hashes.SHA256())
            digest.update(password.encode())
            provided_local_key = digest.finalize()

            if provided_local_key == params['local_key']['key']:
                params['private_key'] = decrypt_private_key(
                    params['encrypted_private_key'],
                    params['local_key']['key'],
                    params['local_key']['iv']
                )
                self.logged_status_label.setText(f"Logged in as {self.username}")
                self.setup_socket(self.host_port)
                self.connect_button.setEnabled(True)
                self.connection_status_label.setText("Online")
                self.password_field.clear()
                self.password_button.setText("Sign out")
                status['logged_in'] = True
        else:
            self.sign_out()

    def sign_out(self):
        """
        Function delivers singing out procedure, that means:
        Updating buttons status and status labels.
        Sending information about the leaving to connected client.
        Closing network sockets.
        :return:
        """
        self.password_button.setText("Sign in")
        self.logged_status_label.setText("Unsigned")
        self.connection_status_label.setText("Offline")
        self.connect_button.setEnabled(False)
        self.send_button.setEnabled(False)
        self.file_button.setEnabled(False)
        self.connect_button.setEnabled(False)

        header = {
            'type': MessageType.LEAVING,
            'username': self.username
        }
        formatted_header = format_header(header)
        self.client.send(formatted_header.encode())
        status['connected'] = False
        status['logged_in'] = False

        if self.socket:
            self.socket.shutdown(socket.SHUT_RDWR)
            self.socket.close()

        try:
            self.client.close()
            self.client = None
        except Exception as e:
            print(e)

    def on_send_clicked(self, message: str):
        """
        Function handles Send button presses.
        Either sends a file or a message.
        :param message: Message to be sent.
        :return:
        """
        if self.fpath:
            fsize = os.path.getsize(self.fpath)
            self.progress_bar.setMaximum(fsize)
            worker_file_sending = Worker(send_file, self.client, self.fpath, fsize)
            worker_file_sending.signals.progress.connect(self.file_sending)
            self.threadpool.start(worker_file_sending)
            self.fpath = None
            self.input_field.clear()

        elif message:
            header = {
                'mode': params['mode'],
                'username': self.username,
                'type': MessageType.MESSAGE
            }
            encrypt_and_send(self.client, message.encode(), header)
            self.update_chat_field((MessageType.MESSAGE, message, self.username))
            self.input_field.clear()

    def file_sending(self, args):
        """
        Function handles progress emitted by a worker during file sending.
        :param args: (MessageType, int | None)
        :return:
        """
        if args[0] == MessageType.FILE_TRANSFER:
            self.update_progress_bar(args[1])

        elif args[0] == MessageType.FILE_SENT:
            self.statusbar.showMessage(f"File sent!", 3000)
            self.progress_bar.setValue(self.progress_bar.maximum())
            self.progress_bar.setStyleSheet("selection-background-color: rgb(6, 191, 15);")
            worker_sleeper = Worker(worker_sleep, 3.0)
            worker_sleeper.signals.result.connect(self.reset_bar)
            self.threadpool.start(worker_sleeper)

    def update_progress_bar(self, value):
        """
        Function updates progress bar by given value.
        :param value: float | int
        :return:
        """
        self.progress_bar.setValue(int(self.progress_bar.value() + value))

    def update_chat_field(self, args: Tuple):
        """
        Function updates output text area.
        :param args: (MessageType, str, str)
        :return:
        """
        text = args[1]
        username = args[2]
        if args[0] == MessageType.FILE_SENT:
            text = f"{username} sent a file '{text}'"
        elif args[0] == MessageType.MESSAGE:
            text = username + ': ' + text
            if len(self.output_field.toPlainText()):
                text = '\n' + text
        self.output_field.insertPlainText(text)

    def retranslate_ui(self):
        _translate = QCoreApplication.translate
        self.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.input_field.setHtml(_translate("MainWindow",
                                            "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
                                            "<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
                                            "p, li { white-space: pre-wrap; }\n"
                                            "</style></head><body style=\" font-family:\'Ubuntu\'; font-size:11pt; font-weight:400; font-style:normal;\">\n"
                                            "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"></p></body></html>"))
        self.input_field.setPlaceholderText(_translate("MainWindow", "message"))
        self.send_button.setText(_translate("MainWindow", "Send"))
        self.password_field.setPlaceholderText(_translate("MainWindow", "password"))
        self.password_button.setText(_translate("MainWindow", "Sign in"))
        self.mode_button.setText(_translate("MainWindow", "Switch"))
        self.mode_label.setText(_translate("MainWindow", "encryption mode:    ECB"))
        self.connect_button.setText(_translate("MainWindow", "Connect"))


def load_keys():

    # load keys
    with open('keys/.private/rsa_private.pem', 'rb') as f:
        params['encrypted_private_key'] = f.read()

    with open('keys/.local/local_key.p', 'rb') as f:
        params['local_key'] = pickle.load(f)

    with open('keys/.pub/rsa_public.pub', 'rb') as f:
        params['public_key'] = f.read()