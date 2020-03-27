# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'display_window.ui'
#
# Created by: PyQt5 UI code generator 5.14.1
#
# WARNING! All changes made in this file will be lost!


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(795, 765)
        Form.setMinimumSize(QtCore.QSize(690, 305))
        self.gridLayout = QtWidgets.QGridLayout(Form)
        self.gridLayout.setSizeConstraint(
            QtWidgets.QLayout.SetDefaultConstraint)

        self.gridLayout.setObjectName("gridLayout")
        spacerItem = QtWidgets.QSpacerItem(
            20, 10, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Fixed)
        self.gridLayout.addItem(spacerItem, 0, 1, 1, 1)
        spacerItem1 = QtWidgets.QSpacerItem(
            10, 20, QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout.addItem(spacerItem1, 1, 0, 1, 1)
        spacerItem2 = QtWidgets.QSpacerItem(
            10, 20, QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout.addItem(spacerItem2, 1, 3, 1, 1)
        self.verticalLayout = QtWidgets.QVBoxLayout()
        self.verticalLayout.setSizeConstraint(
            QtWidgets.QLayout.SetDefaultConstraint)
        self.verticalLayout.setContentsMargins(0, -1, -1, -1)
        self.verticalLayout.setSpacing(6)
        self.verticalLayout.setObjectName("verticalLayout")
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setContentsMargins(-1, -1, -1, 0)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.frame = QtWidgets.QFrame(Form)
        self.frame.setMinimumSize(QtCore.QSize(0, 75))
        self.frame.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame.setLineWidth(0)
        self.frame.setObjectName("frame")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout(self.frame)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.score_label = QtWidgets.QLabel(self.frame)
        self.score_label.setMaximumSize(QtCore.QSize(180, 16777215))
        font = QtGui.QFont()
        font.setFamily("Ubuntu Mono")
        font.setPointSize(30)
        self.score_label.setFont(font)
        self.score_label.setObjectName("score_label")
        self.horizontalLayout_2.addWidget(self.score_label)
        self.num_score_label = QtWidgets.QLabel(self.frame)
        font = QtGui.QFont()
        font.setPointSize(27)
        self.num_score_label.setFont(font)
        self.num_score_label.setAlignment(QtCore.Qt.AlignCenter)
        self.num_score_label.setObjectName("num_score_label")
        self.horizontalLayout_2.addWidget(self.num_score_label)
        self.horizontalLayout.addWidget(self.frame)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.score_treeView = QtWidgets.QTreeView(Form)
        sizePolicy = QtWidgets.QSizePolicy(
            QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(
            self.score_treeView.sizePolicy().hasHeightForWidth())
        self.score_treeView.setSizePolicy(sizePolicy)
        self.score_treeView.setMinimumSize(QtCore.QSize(0, 165))
        self.score_treeView.setMaximumSize(QtCore.QSize(300, 16777215))
        self.score_treeView.setObjectName("score_treeView")
        self.verticalLayout.addWidget(self.score_treeView)
        self.connection_details = QtWidgets.QTableWidget(Form)
        self.connection_details.setEnabled(True)
        sizePolicy = QtWidgets.QSizePolicy(
            QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(
            self.connection_details.sizePolicy().hasHeightForWidth())
        self.connection_details.setSizePolicy(sizePolicy)
        self.connection_details.setMinimumSize(QtCore.QSize(0, 0))
        self.connection_details.setMaximumSize(QtCore.QSize(300, 338))
        self.connection_details.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.connection_details.setSizeAdjustPolicy(
            QtWidgets.QAbstractScrollArea.AdjustToContents)
        self.connection_details.setAutoScroll(True)
        self.connection_details.setEditTriggers(
            QtWidgets.QAbstractItemView.NoEditTriggers)
        self.connection_details.setAlternatingRowColors(True)
        self.connection_details.setSelectionMode(
            QtWidgets.QAbstractItemView.SingleSelection)
        self.connection_details.setIconSize(QtCore.QSize(0, 0))
        self.connection_details.setShowGrid(True)
        self.connection_details.setGridStyle(QtCore.Qt.SolidLine)
        self.connection_details.setCornerButtonEnabled(False)
        self.connection_details.setObjectName("connection_details")
        self.connection_details.setColumnCount(1)
        self.connection_details.setRowCount(9)
        item = QtWidgets.QTableWidgetItem()
        self.connection_details.setVerticalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.connection_details.setVerticalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.connection_details.setVerticalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.connection_details.setVerticalHeaderItem(3, item)
        item = QtWidgets.QTableWidgetItem()
        self.connection_details.setVerticalHeaderItem(4, item)
        item = QtWidgets.QTableWidgetItem()
        self.connection_details.setVerticalHeaderItem(5, item)
        item = QtWidgets.QTableWidgetItem()
        self.connection_details.setVerticalHeaderItem(6, item)
        item = QtWidgets.QTableWidgetItem()
        self.connection_details.setVerticalHeaderItem(7, item)
        item = QtWidgets.QTableWidgetItem()
        self.connection_details.setVerticalHeaderItem(8, item)
        item = QtWidgets.QTableWidgetItem()
        self.connection_details.setHorizontalHeaderItem(0, item)
        self.connection_details.horizontalHeader().setCascadingSectionResizes(False)
        self.connection_details.horizontalHeader().setStretchLastSection(True)
        self.connection_details.verticalHeader().setDefaultSectionSize(35)
        self.connection_details.verticalHeader().setMinimumSectionSize(35)
        self.connection_details.verticalHeader().setStretchLastSection(False)
        self.verticalLayout.addWidget(self.connection_details)
        self.gridLayout.addLayout(self.verticalLayout, 1, 2, 1, 1)
        spacerItem3 = QtWidgets.QSpacerItem(
            20, 10, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Fixed)
        self.gridLayout.addItem(spacerItem3, 2, 1, 1, 1)
        self.verticalLayout_2 = QtWidgets.QVBoxLayout()
        self.verticalLayout_2.setSizeConstraint(
            QtWidgets.QLayout.SetDefaultConstraint)
        self.verticalLayout_2.setContentsMargins(-1, -1, 0, -1)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.cert_chain_treeView = QtWidgets.QTreeView(Form)
        sizePolicy = QtWidgets.QSizePolicy(
            QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(
            self.cert_chain_treeView.sizePolicy().hasHeightForWidth())
        self.cert_chain_treeView.setSizePolicy(sizePolicy)
        self.cert_chain_treeView.setMinimumSize(QtCore.QSize(0, 0))
        self.cert_chain_treeView.setAutoScroll(True)
        self.cert_chain_treeView.setObjectName("cert_chain_treeView")
        self.verticalLayout_2.addWidget(self.cert_chain_treeView)
        self.gridLayout.addLayout(self.verticalLayout_2, 1, 1, 1, 1)

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Certificate Visualization"))
        self.score_label.setText(_translate("Form", "Score:"))
        self.num_score_label.setText(_translate("Form", "None"))
        item = self.connection_details.verticalHeaderItem(0)
        item.setText(_translate("Form", "IP"))
        item.setToolTip(_translate("Form", "IP Address"))
        item = self.connection_details.verticalHeaderItem(1)
        item.setText(_translate("Form", "SN"))
        item.setToolTip(_translate("Form", "Server Name"))
        item = self.connection_details.verticalHeaderItem(2)
        item.setText(_translate("Form", "TLS Versions"))
        item.setToolTip(_translate(
            "Form", "Transport Layer Security Versions supported by server"))
        item = self.connection_details.verticalHeaderItem(3)
        item.setText(_translate("Form", "Protocol"))
        item.setToolTip(_translate(
            "Form", "Protocol used for securing certificate transfer"))
        item = self.connection_details.verticalHeaderItem(4)
        item.setText(_translate("Form", "Cipher suite"))
        item.setToolTip(_translate(
            "Form", "Cipher suite used for securing certificate transfer"))
        item = self.connection_details.verticalHeaderItem(5)
        item.setText(_translate("Form", "HSTS"))
        item.setToolTip(_translate("Form", "HTTP Strict Transport Security"))
        item = self.connection_details.verticalHeaderItem(6)
        item.setText(_translate("Form", "OCSP-Stapling"))
        item.setToolTip(_translate("Form", "OCSP Staple Support"))
        item = self.connection_details.verticalHeaderItem(7)
        item.setText(_translate("Form", "DNS CAA"))
        item.setToolTip(_translate(
            "Form", "DNS Certificate Autorithy Authorization"))
        item = self.connection_details.verticalHeaderItem(8)
        item.setText(_translate("Form", "Certificates"))
        item.setToolTip(_translate(
            "Form", "Certificates served by the server"))
        item = self.connection_details.horizontalHeaderItem(0)
        item.setText(_translate("Form", "Details"))
        __sortingEnabled = self.connection_details.isSortingEnabled()
        self.connection_details.setSortingEnabled(False)
        self.connection_details.setSortingEnabled(__sortingEnabled)
