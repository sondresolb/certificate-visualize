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
        Form.resize(1127, 703)
        self.gridLayout = QtWidgets.QGridLayout(Form)
        self.gridLayout.setContentsMargins(15, 15, 15, 15)
        self.gridLayout.setObjectName("gridLayout")
        self.splitter_2 = QtWidgets.QSplitter(Form)
        sizePolicy = QtWidgets.QSizePolicy(
            QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(
            self.splitter_2.sizePolicy().hasHeightForWidth())
        self.splitter_2.setSizePolicy(sizePolicy)
        self.splitter_2.setMinimumSize(QtCore.QSize(0, 0))
        self.splitter_2.setBaseSize(QtCore.QSize(0, 0))
        self.splitter_2.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.splitter_2.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.splitter_2.setFrameShadow(QtWidgets.QFrame.Plain)
        self.splitter_2.setOrientation(QtCore.Qt.Horizontal)
        self.splitter_2.setOpaqueResize(True)
        self.splitter_2.setHandleWidth(5)
        self.splitter_2.setObjectName("splitter_2")
        self.data_view = QtWidgets.QTreeView(self.splitter_2)
        sizePolicy = QtWidgets.QSizePolicy(
            QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(20)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(
            self.data_view.sizePolicy().hasHeightForWidth())
        self.data_view.setSizePolicy(sizePolicy)
        self.data_view.setMinimumSize(QtCore.QSize(0, 0))
        self.data_view.setSizeAdjustPolicy(
            QtWidgets.QAbstractScrollArea.AdjustToContents)
        self.data_view.setEditTriggers(
            QtWidgets.QAbstractItemView.NoEditTriggers)
        self.data_view.setAlternatingRowColors(True)
        self.data_view.setIndentation(30)
        self.data_view.setAnimated(True)
        self.data_view.setObjectName("data_view")
        self.data_view.header().setCascadingSectionResizes(True)
        self.data_view.header().setDefaultSectionSize(350)
        self.layoutWidget = QtWidgets.QWidget(self.splitter_2)
        self.layoutWidget.setObjectName("layoutWidget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.layoutWidget)
        self.verticalLayout.setSizeConstraint(
            QtWidgets.QLayout.SetDefaultConstraint)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout.setObjectName("verticalLayout")
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setContentsMargins(2, -1, -1, 0)
        self.horizontalLayout.setSpacing(5)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.score_name = QtWidgets.QLabel(self.layoutWidget)
        font = QtGui.QFont()
        font.setFamily("Tlwg Typo")
        font.setPointSize(28)
        self.score_name.setFont(font)
        self.score_name.setAlignment(
            QtCore.Qt.AlignBottom | QtCore.Qt.AlignRight | QtCore.Qt.AlignTrailing)
        self.score_name.setObjectName("score_name")
        self.horizontalLayout.addWidget(self.score_name)
        spacerItem = QtWidgets.QSpacerItem(
            2, 20, QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.score = QtWidgets.QLabel(self.layoutWidget)
        font = QtGui.QFont()
        font.setFamily("Tlwg Typo")
        font.setPointSize(28)
        font.setBold(False)
        font.setItalic(False)
        font.setUnderline(False)
        font.setWeight(50)
        font.setStrikeOut(False)
        font.setKerning(True)
        self.score.setFont(font)
        self.score.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.score.setFrameShadow(QtWidgets.QFrame.Plain)
        self.score.setTextFormat(QtCore.Qt.AutoText)
        self.score.setScaledContents(False)
        self.score.setAlignment(QtCore.Qt.AlignBottom |
                                QtCore.Qt.AlignRight | QtCore.Qt.AlignTrailing)
        self.score.setObjectName("score")
        self.horizontalLayout.addWidget(self.score)
        spacerItem1 = QtWidgets.QSpacerItem(
            0, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem1)
        self.status_light = QtWidgets.QLabel(self.layoutWidget)
        sizePolicy = QtWidgets.QSizePolicy(
            QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(
            self.status_light.sizePolicy().hasHeightForWidth())
        self.status_light.setSizePolicy(sizePolicy)
        self.status_light.setMaximumSize(QtCore.QSize(60, 60))
        self.status_light.setText("")
        self.status_light.setPixmap(QtGui.QPixmap(
            "qt_files/color_lights/idle_light.svg"))
        self.status_light.setScaledContents(True)
        self.status_light.setAlignment(QtCore.Qt.AlignCenter)
        self.status_light.setIndent(-1)
        self.status_light.setObjectName("status_light")
        self.horizontalLayout.addWidget(self.status_light)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.splitter = QtWidgets.QSplitter(self.layoutWidget)
        self.splitter.setOrientation(QtCore.Qt.Vertical)
        self.splitter.setHandleWidth(0)
        self.splitter.setObjectName("splitter")
        self.metric_tree = QtWidgets.QTreeView(self.splitter)
        self.metric_tree.setEditTriggers(
            QtWidgets.QAbstractItemView.NoEditTriggers)
        self.metric_tree.setAlternatingRowColors(True)
        self.metric_tree.setIndentation(20)
        self.metric_tree.setAnimated(True)
        self.metric_tree.setObjectName("metric_tree")
        self.metric_tree.header().setDefaultSectionSize(200)
        self.connection_details = QtWidgets.QTableWidget(self.splitter)
        sizePolicy = QtWidgets.QSizePolicy(
            QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(
            self.connection_details.sizePolicy().hasHeightForWidth())
        self.connection_details.setSizePolicy(sizePolicy)
        self.connection_details.setMaximumSize(QtCore.QSize(16777215, 293))
        self.connection_details.setSizeAdjustPolicy(
            QtWidgets.QAbstractScrollArea.AdjustToContents)
        self.connection_details.setEditTriggers(
            QtWidgets.QAbstractItemView.NoEditTriggers)
        self.connection_details.setAlternatingRowColors(True)
        self.connection_details.setSelectionMode(
            QtWidgets.QAbstractItemView.SingleSelection)
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
        item = QtWidgets.QTableWidgetItem()
        self.connection_details.setItem(0, 0, item)
        self.connection_details.horizontalHeader().setStretchLastSection(True)
        self.connection_details.verticalHeader().setStretchLastSection(False)
        self.verticalLayout.addWidget(self.splitter)
        self.gridLayout.addWidget(self.splitter_2, 0, 0, 1, 1)

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Certificate Display"))
        self.score_name.setText(_translate("Form", "Score:"))
        self.score.setText(_translate("Form", "0/100"))
        item = self.connection_details.verticalHeaderItem(0)
        item.setText(_translate("Form", "IP"))
        item.setToolTip(_translate("Form", "Server IP address"))
        item = self.connection_details.verticalHeaderItem(1)
        item.setText(_translate("Form", "SN"))
        item.setToolTip(_translate("Form", "Server Name"))
        item = self.connection_details.verticalHeaderItem(2)
        item.setText(_translate("Form", "TLS Versions"))
        item.setToolTip(_translate("Form", "Transport Layer Security\n"
                                   " versions supported by server"))
        item = self.connection_details.verticalHeaderItem(3)
        item.setText(_translate("Form", "Protocol"))
        item.setToolTip(_translate("Form", "Protocol used for secure\n"
                                   " transmission of certificate data"))
        item = self.connection_details.verticalHeaderItem(4)
        item.setText(_translate("Form", "Cipher Suite"))
        item.setToolTip(_translate("Form", "Cipher Suite used for\n"
                                   " securing connection"))
        item = self.connection_details.verticalHeaderItem(5)
        item.setText(_translate("Form", "HSTS"))
        item.setToolTip(_translate(
            "Form", "HTTP Strict Transport Security support"))
        item = self.connection_details.verticalHeaderItem(6)
        item.setText(_translate("Form", "OCSP-Stapling"))
        item.setToolTip(_translate("Form", "Online Certificate Status\n"
                                   " Protocol stapling support"))
        item = self.connection_details.verticalHeaderItem(7)
        item.setText(_translate("Form", "DNS CAA"))
        item.setToolTip(_translate("Form", "Domain Name System Certificate\n"
                                   " Authority Authorization support"))
        item = self.connection_details.verticalHeaderItem(8)
        item.setText(_translate("Form", "Certificates"))
        item.setToolTip(_translate(
            "Form", "Number of certificates provided by server"))
        item = self.connection_details.horizontalHeaderItem(0)
        item.setText(_translate("Form", "Details"))
        __sortingEnabled = self.connection_details.isSortingEnabled()
        self.connection_details.setSortingEnabled(False)
        self.connection_details.setSortingEnabled(__sortingEnabled)


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    Form = QtWidgets.QWidget()
    ui = Ui_Form()
    ui.setupUi(Form)
    Form.show()
    sys.exit(app.exec_())
