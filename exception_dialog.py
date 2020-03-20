# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'exception_dialog.ui'
#
# Created by: PyQt5 UI code generator 5.14.1
#
# WARNING! All changes made in this file will be lost!


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_ExceptionDialog(object):
    def setupUi(self, ExceptionDialog, error_msg):
        ExceptionDialog.setObjectName("ExceptionDialog")
        ExceptionDialog.resize(446, 283)
        self.gridLayout = QtWidgets.QGridLayout(ExceptionDialog)
        self.gridLayout.setObjectName("gridLayout")
        spacerItem = QtWidgets.QSpacerItem(
            10, 20, QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout.addItem(spacerItem, 3, 2, 1, 1)
        spacerItem1 = QtWidgets.QSpacerItem(
            20, 5, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Fixed)
        self.gridLayout.addItem(spacerItem1, 2, 1, 1, 1)
        self.exceptionTextBrowser = QtWidgets.QTextBrowser(ExceptionDialog)
        self.exceptionTextBrowser.setObjectName("exceptionTextBrowser")
        self.exceptionTextBrowser.setText(error_msg)

        self.gridLayout.addWidget(self.exceptionTextBrowser, 3, 1, 1, 1)
        self.exceptionDescription = QtWidgets.QLabel(ExceptionDialog)
        font = QtGui.QFont()
        font.setFamily("Ubuntu")
        font.setPointSize(12)
        font.setStrikeOut(False)
        self.exceptionDescription.setFont(font)
        self.exceptionDescription.setObjectName("exceptionDescription")
        self.gridLayout.addWidget(self.exceptionDescription, 1, 1, 1, 1)
        spacerItem2 = QtWidgets.QSpacerItem(
            10, 20, QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout.addItem(spacerItem2, 3, 0, 1, 1)
        spacerItem3 = QtWidgets.QSpacerItem(
            20, 15, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Fixed)
        self.gridLayout.addItem(spacerItem3, 0, 1, 1, 1)
        spacerItem4 = QtWidgets.QSpacerItem(
            20, 5, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Fixed)
        self.gridLayout.addItem(spacerItem4, 4, 1, 1, 1)
        self.exceptionOkButton = QtWidgets.QPushButton(ExceptionDialog)
        self.exceptionOkButton.setObjectName("exceptionOkButton")
        self.gridLayout.addWidget(
            self.exceptionOkButton, 5, 1, 1, 1, QtCore.Qt.AlignRight)

        self.exceptionOkButton.clicked.connect(ExceptionDialog.accept)

        self.retranslateUi(ExceptionDialog)
        QtCore.QMetaObject.connectSlotsByName(ExceptionDialog)

    def retranslateUi(self, ExceptionDialog):
        _translate = QtCore.QCoreApplication.translate
        ExceptionDialog.setWindowTitle(_translate(
            "ExceptionDialog", "Exception dialog"))
        self.exceptionDescription.setText(_translate(
            "ExceptionDialog", "Exception description:"))
        self.exceptionOkButton.setText(_translate("ExceptionDialog", "Ok"))
