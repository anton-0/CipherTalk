from libs.workers import *

class ConnectionDialog(QDialog):

    def __init__(self):
        super().__init__()
        self.setObjectName("ConnectionDialog")
        self.resize(353, 173)
        self.setStyleSheet("background-color: rgb(222, 221, 218);")

        self.button_box = QDialogButtonBox(self)
        self.button_box.setGeometry(QRect(90, 120, 166, 25))
        self.button_box.setStandardButtons(QDialogButtonBox.No|QDialogButtonBox.Yes)
        self.button_box.setObjectName("button_box")

        self.info_label = QLabel(self)
        self.info_label.setGeometry(QRect(50, 30, 251, 61))
        self.info_label.setStyleSheet("background-color: rgb(245, 236, 226);")
        self.info_label.setAlignment(Qt.AlignCenter)
        self.info_label.setWordWrap(True)
        self.info_label.setObjectName("info_label")
        self.label = QLabel(self)
        self.label.setEnabled(True)
        self.label.setGeometry(QRect(-30, -20, 391, 201))
        self.label.setStyleSheet("background-color: rgb(255, 239, 185);")
        self.label.setText("")
        self.label.setObjectName("label")
        self.label.raise_()
        self.button_box.raise_()
        self.info_label.raise_()

        self.retranslateUi()

    def retranslateUi(self):
        _translate = QCoreApplication.translate
        self.setWindowTitle(_translate("ConnectionDialog", "Dialog"))
        self.info_label.setText(_translate("ConnectionDialog", "User X wants to connect"))
