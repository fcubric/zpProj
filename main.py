import sys

import PyQt5
from PyQt5.QtCore import QModelIndex, Qt
from PyQt5.QtGui import QStandardItem, QStandardItemModel
from PyQt5.QtWidgets import *
from api import *
from PyQt5 import uic
import models
from models import Users_Set, user_logged


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
        self.model1.setColumnCount(6)
        headerNames1 = ["Key id","Algorithm","User","Public key","Private key (enc)","Timestamp"]
        self.model1.setHorizontalHeaderLabels(headerNames1)
        self.public_keys.setModel(self.model1)

        self.model2 = QStandardItemModel()
        self.model1.setColumnCount(5)
        headerNames2 = ["Key id","Algorithm","User","Public key","Timestamp"]
        self.model2.setHorizontalHeaderLabels(headerNames2)
        self.public_keys.setModel(self.model2)

        stylesheet = "::section{Background-color:rgb(0,0,0); color: rgb(0, 255, 93)}"
        self.public_keys.horizontalHeader().setStyleSheet(stylesheet)
        self.private_keys.horizontalHeader().setStyleSheet(stylesheet)
        self.public_keys.verticalHeader().setStyleSheet(stylesheet)
        self.private_keys.verticalHeader().setStyleSheet(stylesheet)

        self.check_enc.stateChanged.connect(self.toggle_enc)
        self.check_sign.stateChanged.connect(self.toggle_sign)

        self.login_button.clicked.connect(self.login)
        self.logout_button.clicked.connect(self.logout)
        self.reg_button.clicked.connect(self.register)

    def generate_new_keypair_wrapper(self):
        if models.user_logged==None:
            self.gen_err.setText("You have to log in")
            return

        name=models.user_logged.name
        password=models.user_logged.password
        email=models.user_logged.email

        key_size=int(self.gen_key_size_radio.checkedButton().text())
        alg=str(self.gen_key_alg_radio.checkedButton().text())

        if name=='' or key_size=='' or password=='' or alg=='' or email=='':
            self.gen_err.setText("You have to input all parameters")
            return

        msg=generate_new_keypair(name,password,email,key_size,alg[:3])
        self.gen_err.setText(msg)
        self.hide_keys()
        self.show_keys()

    def import_key_wrapper(self,req):

        if models.user_logged == None:
            self.import_err.setText("You have to log in")
            return

        filename = str(self.import_filename.text())
        path = str(self.import_path.text())
        password = str(self.import_pw.text())
        if req and password=='':
            self.import_err.setText("Password is required for private import")
            return
        if filename=='':
            self.import_err.setText("You have to input file name")
            return
        try:
            msg = import_key(filename,path,password,req)
            self.import_err.setText(msg)

            self.hide_keys()
            self.show_keys()
        except FileNotFoundError:
            self.import_err.setText("File not found")


    def export_key_wrapper(self,req):

        if models.user_logged == None:
            self.export_err.setText("You have to log in")
            return

        filename = str(self.export_filename.text())
        path = str(self.export_path.text())
        password = str(self.export_pw.text())
        keyid=str(self.export_id.text())
        if req and password=='':
            self.export_err.setText("Password is required for private export")
            return
        if filename=='' or keyid=='':
            self.export_err.setText("You have to input file name and key id")
            return
        try:
            if (req and self.check_pw(password,int(keyid))) or not req:
                msg = export_key(filename,path,keyid,req)
                self.export_err.setText(msg)
            elif req:
                self.export_err.setText("Wrong password")
        except Exception as e:
            self.export_err.setText("The key id doesnt exist")

    def send_wrapper(self):

        if models.user_logged == None:
            self.send_err.setText("You have to log in")
            return

        filename = str(self.send_filename.text())
        path = str(self.send_path.text())
        message=str(self.message.toPlainText())
        if filename=='' or message=='':
            self.send_err.setText("You must enter file name and message")
            return
        enc=None
        sign=None
        compress=self.check_compress.isChecked()
        radix=self.check_radix.isChecked()
        if self.check_enc.isChecked():
            alg=str(self.send_enc_radio.checkedButton().text())
            key = str(self.send_public_key.text())
            if key=='' or alg=='':
                self.send_err.setText("You must enter all encription parameters")
                return
            try:
                enc={
                    "alg":alg,
                    "key":models.user_logged.other_keys[int(key)]
                }
            except Exception as e:
                self.send_err.setText(str(e))
                return
        if self.check_sign.isChecked():
            alg=str(self.send_sign_radio.checkedButton().text())
            key = str(self.send_private_key.text())
            if key=='' or alg=='':
                self.send_err.setText("You must enter all signature parameters")
                return
            try:
                sign={
                    "alg":alg,
                    "key":models.user_logged.my_keys[int(key)]
                }
            except Exception as e:
                self.send_err.setText(str(e))
                return
        try:
            msg=send_message(filename,path,enc,sign,compress,radix,message)
            self.send_err.setText(msg)
        except Exception as e:
            self.send_err.setText(str(e))


    def receive_wrapper(self):
        if models.user_logged == None:
            self.dec_err.setText("You have to log in")
            return

        filename_from = str(self.dec_file1.text())
        path_from = str(self.dec_path1.text())
        filename_to = str(self.dec_file2.text())
        path_to = str(self.dec_path2.text())
        if  filename_to=='' or filename_from=='':
            self.dec_err.setText("You have to input both file names")
            return
        auth=["",""]
        try:
            msg=receive_message(filename_from,path_from,filename_to,path_to,auth)
            self.dec_err.setText(msg)
            self.dec_auth.setText(auth[0])
            self.dec_verify.setText(auth[1])
        except Exception as e:
            self.dec_err.setText(str(e))

    def show_ring_wrapper(self):
        if models.user_logged == None:
            self.keys_err.setText("You have to log in")
            return

        password=str(self.pk_pw.text())
        if password=='':
            self.keys_err.setText("You have to input password")
            return
        rows = self.private_keys.selectionModel().selectedRows()
        keyid=0
        if rows:
            model = self.private_keys.model()
            for kp in rows:
                keyid=model.data(kp)
                break
        else:
            self.keys_err.setText("You have to select row with the key you want to see")
            return

        if self.check_pw(password,int(keyid)):
            self.hide_keys()
            self.show_keys(int(keyid))
            self.keys_err.setText("Success")
        else:
            self.keys_err.setText("Wrong password")
        self.keys_err_2.setText("")

    def delete_wrapper(self):
        if models.user_logged == None:
            self.keys_err_2.setText("You have to log in")
            return

        rows1=self.private_keys.selectionModel()
        if rows1:
            model=self.private_keys.model()
            for kp in rows1.selectedRows():
                password=str(self.pk_pw.text())
                if password!="" and self.check_pw(password,int(kp.data())):
                    delete_keypair(int(kp.data()),0)
                elif password=="":
                    self.keys_err_2.setText("You have to input password")
                    return
                else:
                    self.keys_err_2.setText("Wrong password")
                    return


        rows2=self.public_keys.selectionModel()
        if rows2:
            model=self.public_keys.model()
            for kp in rows2.selectedRows():
                delete_keypair(int(kp.data()),1)

        self.hide_keys()
        self.show_keys()
        self.keys_err_2.setText("Success")
        self.keys_err.setText("")

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

    def login(self):
        if models.user_logged!=None:
            self.log_err.setText("You have to log out first")
            return
        email = str(self.log_email.text())
        password = str(self.log_pw.text())
        if email=="" or password=="":
            self.log_err.setText("You have to input email and password")
            return
        msg=Users_Set.login(email,password)
        self.log_err.setText(msg)
        if models.user_logged!=None:
            self.show_keys()

    def logout(self):
        if models.user_logged==None:
            self.log_err.setText("You are not logged in")
            return
        msg=Users_Set.logout()
        self.log_err.setText(msg)
        if models.user_logged==None:
            self.hide_keys()

    def register(self):
        if models.user_logged!=None:
            self.reg_err.setText("You have to log out first")
            return
        name = str(self.reg_name.text())
        email = str(self.reg_email.text())
        password = str(self.reg_pw.text())

        if email=="" or password=="" or name=="":
            self.reg_err.setText("You have to input name, email and password")
            return

        msg=Users_Set.register(name,email,password)
        self.reg_err.setText(msg)
        if models.user_logged!=None:
            self.show_keys()

    def check_pw(self,password, k):
        return sha1(password.encode()).digest()==models.user_logged.my_keys[k].password

    def show_keys(self,showkey=0):
        for id in models.user_logged.my_keys.keys():
            row = []

            keyid=models.user_logged.my_keys[id].keyId
            priv_key = self.actual_priv(models.user_logged.my_keys[id])
            pub_key=self.actual_pub(models.user_logged.my_keys[id])
            show= keyid==showkey

            self.add_field_to_row(row,keyid,show)
            self.add_field_to_row(row,models.user_logged.my_keys[id].algorithm,show)
            self.add_field_to_row(row,models.user_logged.my_keys[id].user_id,show)
            self.add_field_to_row(row,pub_key,show)
            self.add_field_to_row(row,priv_key,show)
            self.add_field_to_row(row,models.user_logged.my_keys[id].timestamp,show)
            self.model1.appendRow(row)
        self.private_keys.setModel(self.model1)

        for id in models.user_logged.other_keys.keys():
            row = []

            pub_key=self.actual_pub(models.user_logged.other_keys[id])

            self.add_field_to_row(row,models.user_logged.other_keys[id].keyId)
            self.add_field_to_row(row,models.user_logged.other_keys[id].algorithm)
            self.add_field_to_row(row,models.user_logged.other_keys[id].user_id)
            self.add_field_to_row(row,pub_key)
            self.add_field_to_row(row,models.user_logged.other_keys[id].timestamp)
            self.model2.appendRow(row)
        self.public_keys.setModel(self.model2)

    def actual_pub(self,key):
        if key.algorithm == "ELG":
            pub_key = "p= " + str(key.public_key.p) + ",\n" + \
                      "g= " + str(key.public_key.g) + ",\n" + \
                      "y= " + str(key.public_key.y)
        elif key.algorithm == "RSA":
            pub_key = "n= " + str(key.public_key.public_numbers().n) + ",\n" + \
                      "e= " + str(key.public_key.public_numbers().e)
        else:
            pub_key = "y= " + str(key.public_key.public_numbers().y)
        return pub_key
    def actual_priv(self,key):
        priv_key=str(key.private_key)
        if key.algorithm == "ELG":
            priv_key = priv_key[92:-25]
        else:
            priv_key = priv_key[41:-40]
        return priv_key

    def hide_keys(self):
        self.model1 = QStandardItemModel()
        self.model1.setColumnCount(6)
        headerNames1 = ["Key id","Algorithm", "User", "Public key", "Private key (enc)", "Timestamp"]
        self.model1.setHorizontalHeaderLabels(headerNames1)
        self.public_keys.setModel(self.model1)

        self.model2 = QStandardItemModel()
        self.model1.setColumnCount(5)
        headerNames2 = ["Key id", "Algorithm", "User", "Public key", "Timestamp"]
        self.model2.setHorizontalHeaderLabels(headerNames2)
        self.public_keys.setModel(self.model2)

    def add_field_to_row(self,row, field,show=True):
        item = QStandardItem(str(field))
        item.setEditable(False)
        item.setEnabled(show)
        row.append(item)

def main():

    app=QApplication([])
    window = PGP_GUI()
    app.exec_()

if __name__=="__main__":
    main()