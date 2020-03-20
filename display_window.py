# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'display_window.ui'
#
# Created by: PyQt5 UI code generator 5.14.1
#
# WARNING! All changes made in this file will be lost!


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainDisplay(object):
    def setupUi(self, DisplayWindow):
        DisplayWindow.setObjectName("DisplayWindow")
        DisplayWindow.resize(856, 797)
        self.centralwidget = QtWidgets.QWidget(DisplayWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.gridLayout = QtWidgets.QGridLayout(self.centralwidget)
        self.gridLayout.setObjectName("gridLayout")
        spacerItem = QtWidgets.QSpacerItem(
            100, 20, QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout.addItem(spacerItem, 0, 1, 1, 1)
        self.tree_view = QtWidgets.QTreeView(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(
            QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(
            self.tree_view.sizePolicy().hasHeightForWidth())
        self.tree_view.setSizePolicy(sizePolicy)
        self.tree_view.setMaximumSize(QtCore.QSize(16777215, 700))
        self.tree_view.setAlternatingRowColors(True)
        self.tree_view.setAnimated(True)
        self.tree_view.setObjectName("tree_view")
        self.gridLayout.addWidget(self.tree_view, 0, 0, 2, 1)
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setObjectName("label")
        self.gridLayout.addWidget(self.label, 0, 3, 1, 1)
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setObjectName("label_2")
        self.gridLayout.addWidget(self.label_2, 1, 3, 1, 1)
        DisplayWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(DisplayWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 856, 22))
        self.menubar.setObjectName("menubar")
        DisplayWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(DisplayWindow)
        self.statusbar.setObjectName("statusbar")
        DisplayWindow.setStatusBar(self.statusbar)

        self.retranslateUi(DisplayWindow)
        QtCore.QMetaObject.connectSlotsByName(DisplayWindow)

    def retranslateUi(self, DisplayWindow):
        _translate = QtCore.QCoreApplication.translate
        DisplayWindow.setWindowTitle(
            _translate("DisplayWindow", "DisplayWindow"))
        self.label.setText(_translate("DisplayWindow", "hey hey"))
        self.label_2.setText(_translate("DisplayWindow", "this is great"))
