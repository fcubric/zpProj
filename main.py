import sys

from PyQt5.QtCore import QModelIndex, Qt
from PyQt5.QtGui import QStandardItem, QStandardItemModel
from PyQt5.QtWidgets import *
from api import *
from PyQt5 import uic

class PGP_GUI(QMainWindow):
    def __init__(self):
        super(PGP_GUI,self).__init__()
        uic.loadUi("GUI.ui",self)
        self.show()

        self.gen_button.clicked.connect(self.generate_new_keypair_wrapper)

        self.import_priv.clicked.connect(lambda: self.import_key_wrapper(True))
        self.import_pub.clicked.connect(lambda: self.import_key_wrapper(False))
        self.export_priv.clicked.connect(lambda: self.export_key_wrapper(True))
        self.export_pub.clicked.connect(lambda: self.export_key_wrapper(False))

        self.pk_button.clicked.connect(self.show_ring_wrapper)
        self.del_button.clicked.connect(self.delete_wrapper)

        self.send_button.clicked.connect(self.send_wrapper)
        self.dec_button.clicked.connect(self.receive_wrapper)

        self.model1 = QStandardItemModel()
        self.model1.setColumnCount(3)
        headerNames = ["Last Name","First Name","Description"]
        self.model1.setHorizontalHeaderLabels(headerNames)
        self.public_keys.setModel(self.model1)

        self.model2 = QStandardItemModel()
        self.model2.setColumnCount(3)
        self.model2.setHorizontalHeaderLabels(headerNames)
        self.public_keys.setModel(self.model2)

        stylesheet = "::section{Background-color:rgb(0,0,0); color: rgb(0, 255, 93)}"
        self.public_keys.horizontalHeader().setStyleSheet(stylesheet)
        self.private_keys.horizontalHeader().setStyleSheet(stylesheet)
        self.public_keys.verticalHeader().setStyleSheet(stylesheet)
        self.private_keys.verticalHeader().setStyleSheet(stylesheet)

        self.check_enc.stateChanged.connect(self.toggle_enc)
        self.check_sign.stateChanged.connect(self.toggle_sign)

    def generate_new_keypair_wrapper(self):
        name=str(self.gen_name.text())
        email=str(self.gen_email.text())
        password=str(self.gen_pw.text())
        key_size=int(self.gen_key_size_radio.checkedButton().text())
        alg=str(self.gen_key_alg_radio.checkedButton().text())

        if name=='' or key_size=='' or password=='' or alg=='' or email=='':
            self.gen_err.setText("You have to input all parameters")
            return

        msg=generate_new_keypair(name,password,email,key_size,alg[:3])
        self.gen_err.setText(msg)

    def import_key_wrapper(self,req):
        filename = str(self.import_filename.text())
        path = str(self.import_path.text())
        password = str(self.import_pw.text())
        if req and password=='':
            self.import_err.setText("Password is required for private import")
            return
        if filename=='' or path=='':
            self.import_err.setText("You have to input file name and path")
            return
        msg = import_key(filename,path,password,req)
        self.import_err.setText(msg)

    def export_key_wrapper(self,req):
        filename = str(self.export_filename.text())
        path = str(self.export_path.text())
        password = str(self.export_pw.text())
        if req and password=='':
            self.export_err.setText("Password is required for private export")
            return
        if filename=='' or path=='':
            self.export_err.setText("You have to input file name and path")
            return
        msg = export_key(filename,path,password,req)
        self.export_err.setText(msg)

    def send_wrapper(self):
        filename = str(self.send_filename.text())
        path = str(self.send_path.text())
        if filename=='' or path=='':
            self.send_err.setText("You must enter file name and path")
            return
        enc={}
        sign={}
        compress=self.check_compress.isChecked()
        radix=self.check_radix.isChecked()
        if self.check_enc.isChecked():
            alg=str(self.send_enc_radio.checkedButton().text())
            key = str(self.send_public_key.text())
            if key=='' or alg=='':
                self.send_err.setText("You must enter all encription parameters")
                return
            enc={
                "alg":alg,
                "key":key
            }
        if self.check_sign.isChecked():
            alg=str(self.send_sign_radio.checkedButton().text())
            key = str(self.send_private_key.text())
            if key=='' or alg=='':
                self.send_err.setText("You must enter all signature parameters")
                return
            sign={
                "alg":alg,
                "key":key
            }
        msg=send_message(filename,path,enc,sign,compress,radix)
        self.send_err.setText(msg)

    def receive_wrapper(self):
        filename_from = str(self.dec_file1.text())
        path_from = str(self.dec_path1.text())
        filename_to = str(self.dec_file2.text())
        path_to = str(self.dec_path2.text())
        if path_to=='' or filename_to=='' or path_from=='' or filename_from=='':
            self.dec_err.setText("You have to input all parameters")
            return
        auth=["",""]
        msg=receive_message(filename_from,path_from,filename_to,path_to,auth)
        self.dec_err.setText(msg)
        self.dec_auth.setText(auth[0])
        self.dec_verify.setText(auth[1])

    def show_ring_wrapper(self):
        password=str(self.pk_pw.text())
        if password=='':
            self.keys_err.setText("You have to input password")
            return
        msg=show_ring(password)
        self.keys_err.setText(msg)

    def delete_wrapper(self):
        rows1=self.private_keys.selectionModel()
        role=Qt.DisplayRole
        if rows1:
            model=self.private_keys.model()
            i=0
            for kp in rows1.selectedRows():
                i+=1
                # exact values will be changed later
                # if i%10==3: delete_keypair(model.data(kp));

        rows2=self.public_keys.selectionModel()
        if rows2:
            model=self.public_keys.model()
            i=0
            for kp in rows2.selectedIndexes():
                i+=1
                # exact values will be changed later
                # if i%10==3: delete_keypair(model.data(kp));

    def toggle_enc(self):
        if self.enc_alg1.isEnabled():
            self.enc_alg1.setEnabled(False)
            self.enc_alg2.setEnabled(False)
            self.send_public_key.setEnabled(False)
        else:
            self.enc_alg1.setEnabled(True)
            self.enc_alg2.setEnabled(True)
            self.send_public_key.setEnabled(True)

    def toggle_sign(self):
        if self.sign_alg1.isEnabled():
            self.sign_alg1.setEnabled(False)
            self.sign_alg2.setEnabled(False)
            self.send_private_key.setEnabled(False)
        else:
            self.sign_alg1.setEnabled(True)
            self.sign_alg2.setEnabled(True)
            self.send_private_key.setEnabled(True)

    def public_key_table(self,contents):
        for obj in contents:
            row = []
            for field in obj:
                item = QStandardItem(field)
                item.setEditable(False)
                row.append(item)
            self.model1.appendRow(row)
        self.public_keys.setModel(self.model1)


def main():
    app=QApplication([])
    window = PGP_GUI()
    app.exec_()

if __name__=="__main__":
    main()