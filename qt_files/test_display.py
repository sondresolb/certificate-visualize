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
        Form.resize(1050, 867)
        self.horizontalLayout = QtWidgets.QHBoxLayout(Form)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.treeView = QtWidgets.QTreeView(Form)
        self.treeView.setObjectName("treeView")
        self.horizontalLayout.addWidget(self.treeView)
        self.verticalLayout = QtWidgets.QVBoxLayout()
        self.verticalLayout.setSizeConstraint(
            QtWidgets.QLayout.SetDefaultConstraint)
        self.verticalLayout.setContentsMargins(0, -1, -1, -1)
        self.verticalLayout.setSpacing(6)
        self.verticalLayout.setObjectName("verticalLayout")
        self.tableWidget_2 = QtWidgets.QTableWidget(Form)
        self.tableWidget_2.setObjectName("tableWidget_2")
        self.tableWidget_2.setColumnCount(1)
        self.tableWidget_2.setRowCount(2)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget_2.setVerticalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget_2.setVerticalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget_2.setHorizontalHeaderItem(0, item)
        self.tableWidget_2.horizontalHeader().setStretchLastSection(True)
        self.verticalLayout.addWidget(self.tableWidget_2)
        self.tableWidget = QtWidgets.QTableWidget(Form)
        self.tableWidget.setEnabled(True)
        self.tableWidget.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.tableWidget.setEditTriggers(
            QtWidgets.QAbstractItemView.NoEditTriggers)
        self.tableWidget.setAlternatingRowColors(True)
        self.tableWidget.setSelectionMode(
            QtWidgets.QAbstractItemView.SingleSelection)
        self.tableWidget.setIconSize(QtCore.QSize(0, 0))
        self.tableWidget.setShowGrid(True)
        self.tableWidget.setGridStyle(QtCore.Qt.SolidLine)
        self.tableWidget.setCornerButtonEnabled(False)
        self.tableWidget.setObjectName("tableWidget")
        self.tableWidget.setColumnCount(1)
        self.tableWidget.setRowCount(9)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setVerticalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setVerticalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setVerticalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setVerticalHeaderItem(3, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setVerticalHeaderItem(4, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setVerticalHeaderItem(5, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setVerticalHeaderItem(6, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setVerticalHeaderItem(7, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setVerticalHeaderItem(8, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setItem(0, 0, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setItem(1, 0, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setItem(2, 0, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setItem(3, 0, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setItem(4, 0, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setItem(5, 0, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setItem(6, 0, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setItem(7, 0, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setItem(8, 0, item)
        self.tableWidget.horizontalHeader().setCascadingSectionResizes(False)
        self.tableWidget.horizontalHeader().setStretchLastSection(True)
        self.tableWidget.verticalHeader().setDefaultSectionSize(35)
        self.tableWidget.verticalHeader().setMinimumSectionSize(35)
        self.tableWidget.verticalHeader().setStretchLastSection(False)
        self.verticalLayout.addWidget(self.tableWidget)
        self.horizontalLayout.addLayout(self.verticalLayout)

        data = {'ip': '129.240.118.130', 'server_name': 'uio.no', 'tls_v': [
            'TLS1.0', 'TLS1.1', 'TLS1.3'], 'protocol': 'TLSv1.2',
            'cipher': 'ECDHE-RSA-AES128-GCM-SHA256', 'hsts': True,
            'stapling': False, 'caa': True, 'certificates': 5}
        self.fill_connection_details(data)

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Form"))
        item = self.tableWidget_2.verticalHeaderItem(0)
        item.setText(_translate("Form", "DN"))
        item = self.tableWidget_2.verticalHeaderItem(1)
        item.setText(_translate("Form", "Public key"))
        item = self.tableWidget_2.horizontalHeaderItem(0)
        item.setText(_translate("Form", "End certificate"))
        item = self.tableWidget.verticalHeaderItem(0)
        item.setText(_translate("Form", "IP"))
        item.setToolTip(_translate("Form", "IP Address"))
        item = self.tableWidget.verticalHeaderItem(1)
        item.setText(_translate("Form", "SN"))
        item.setToolTip(_translate("Form", "Server Name"))
        item = self.tableWidget.verticalHeaderItem(2)
        item.setText(_translate("Form", "TLS Versions"))
        item.setToolTip(_translate(
            "Form", "Transport Layer Security Versions supported by server"))
        item = self.tableWidget.verticalHeaderItem(3)
        item.setText(_translate("Form", "Protocol"))
        item.setToolTip(_translate(
            "Form", "Protocol used for securing certificate transfer"))
        item = self.tableWidget.verticalHeaderItem(4)
        item.setText(_translate("Form", "Cipher suite"))
        item.setToolTip(_translate(
            "Form", "Cipher suite used for securing certificate transfer"))
        item = self.tableWidget.verticalHeaderItem(5)
        item.setText(_translate("Form", "HSTS"))
        item.setToolTip(_translate("Form", "HTTP Strict Transport Security"))
        item = self.tableWidget.verticalHeaderItem(6)
        item.setText(_translate("Form", "OCSP-Stapling"))
        item.setToolTip(_translate("Form", "OCSP Staple Support"))
        item = self.tableWidget.verticalHeaderItem(7)
        item.setText(_translate("Form", "DNS CAA"))
        item.setToolTip(_translate(
            "Form", "DNS Certificate Autorithy Authorization"))
        item = self.tableWidget.verticalHeaderItem(8)
        item.setText(_translate("Form", "Certificates"))
        item.setToolTip(_translate(
            "Form", "Certificates served by the server"))
        item = self.tableWidget.horizontalHeaderItem(0)
        item.setText(_translate("Form", "Connection & Domain details"))
        __sortingEnabled = self.tableWidget.isSortingEnabled()
        self.tableWidget.setSortingEnabled(False)
        self.tableWidget.setSortingEnabled(__sortingEnabled)

    def fill_connection_details(self, data):
        _translate = QtCore.QCoreApplication.translate

        for index, key in enumerate(data):
            item = self.tableWidget.item(index, 0)
            if type(data[key]) is list:
                data[key] = ", ".join(data[key])
            item.setText(_translate("Form", str(data[key])))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    Form = QtWidgets.QWidget()
    ui = Ui_Form()
    ui.setupUi(Form)
    Form.show()
    sys.exit(app.exec_())
