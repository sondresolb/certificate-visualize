import run_visualize
import data_translation as dt
import visualize_exceptions as c_ex
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import QObject, pyqtSignal
from display_window import Ui_Form
from exception_dialog import Ui_ExceptionDialog


class Ui_MainWindow(QObject):
    progress_signal = pyqtSignal(int, str)

    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(868, 466)
        MainWindow.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.centralwidget)
        self.verticalLayout.setObjectName("verticalLayout")
        spacerItem = QtWidgets.QSpacerItem(
            20, 41, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Fixed)
        self.verticalLayout.addItem(spacerItem)
        self.header_text_label = QtWidgets.QLabel(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(
            QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Maximum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(
            self.header_text_label.sizePolicy().hasHeightForWidth())
        self.header_text_label.setSizePolicy(sizePolicy)
        self.header_text_label.setMaximumSize(QtCore.QSize(16777, 32))
        font = QtGui.QFont()
        font.setFamily("Ubuntu Light")
        font.setPointSize(18)
        font.setBold(True)
        font.setUnderline(False)
        font.setWeight(75)
        font.setStrikeOut(False)
        font.setKerning(True)
        self.header_text_label.setFont(font)
        self.header_text_label.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.header_text_label.setTextFormat(QtCore.Qt.AutoText)
        self.header_text_label.setScaledContents(False)
        self.header_text_label.setAlignment(QtCore.Qt.AlignCenter)
        self.header_text_label.setWordWrap(False)
        self.header_text_label.setObjectName("header_text_label")
        self.verticalLayout.addWidget(self.header_text_label)
        spacerItem1 = QtWidgets.QSpacerItem(
            20, 10, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Fixed)
        self.verticalLayout.addItem(spacerItem1)
        self.sub_header_label = QtWidgets.QLabel(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(
            QtWidgets.QSizePolicy.Maximum, QtWidgets.QSizePolicy.Maximum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(
            self.sub_header_label.sizePolicy().hasHeightForWidth())
        self.sub_header_label.setSizePolicy(sizePolicy)
        self.sub_header_label.setMaximumSize(QtCore.QSize(16777, 45))
        font = QtGui.QFont()
        font.setItalic(True)
        self.sub_header_label.setFont(font)
        self.sub_header_label.setAlignment(QtCore.Qt.AlignCenter)
        self.sub_header_label.setWordWrap(True)
        self.sub_header_label.setObjectName("sub_header_label")
        self.verticalLayout.addWidget(self.sub_header_label)
        spacerItem2 = QtWidgets.QSpacerItem(
            20, 70, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Fixed)
        self.verticalLayout.addItem(spacerItem2)
        self.horizontalLayout_input_lineEdit = QtWidgets.QHBoxLayout()
        self.horizontalLayout_input_lineEdit.setSizeConstraint(
            QtWidgets.QLayout.SetMaximumSize)
        self.horizontalLayout_input_lineEdit.setContentsMargins(-1, 0, -1, -1)
        self.horizontalLayout_input_lineEdit.setObjectName(
            "horizontalLayout_input_lineEdit")
        spacerItem3 = QtWidgets.QSpacerItem(
            100, 20, QtWidgets.QSizePolicy.Maximum, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_input_lineEdit.addItem(spacerItem3)
        self.url_input_lineEdit = QtWidgets.QLineEdit(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(
            QtWidgets.QSizePolicy.Maximum, QtWidgets.QSizePolicy.Maximum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(
            self.url_input_lineEdit.sizePolicy().hasHeightForWidth())
        self.url_input_lineEdit.setSizePolicy(sizePolicy)
        self.url_input_lineEdit.setMinimumSize(QtCore.QSize(200, 58))
        self.url_input_lineEdit.setMaximumSize(QtCore.QSize(167773, 58))
        self.url_input_lineEdit.setBaseSize(QtCore.QSize(700, 58))
        font = QtGui.QFont()
        font.setFamily("Ubuntu Light")
        font.setPointSize(14)
        self.url_input_lineEdit.setFont(font)
        self.url_input_lineEdit.setFocusPolicy(QtCore.Qt.ClickFocus)
        self.url_input_lineEdit.setAlignment(QtCore.Qt.AlignCenter)
        self.url_input_lineEdit.setDragEnabled(False)
        self.url_input_lineEdit.setObjectName("url_input_lineEdit")
        self.horizontalLayout_input_lineEdit.addWidget(self.url_input_lineEdit)
        spacerItem4 = QtWidgets.QSpacerItem(
            100, 20, QtWidgets.QSizePolicy.Maximum, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_input_lineEdit.addItem(spacerItem4)
        self.verticalLayout.addLayout(self.horizontalLayout_input_lineEdit)
        spacerItem5 = QtWidgets.QSpacerItem(
            20, 25, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Fixed)
        self.verticalLayout.addItem(spacerItem5)
        self.horizontalLayout_progressBar = QtWidgets.QHBoxLayout()
        self.horizontalLayout_progressBar.setSizeConstraint(
            QtWidgets.QLayout.SetFixedSize)
        self.horizontalLayout_progressBar.setContentsMargins(-1, 10, -1, 10)
        self.horizontalLayout_progressBar.setSpacing(0)
        self.horizontalLayout_progressBar.setObjectName(
            "horizontalLayout_progressBar")
        self.progressBar = QtWidgets.QProgressBar(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(
            QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(
            self.progressBar.sizePolicy().hasHeightForWidth())
        self.progressBar.setSizePolicy(sizePolicy)
        self.progressBar.setMinimumSize(QtCore.QSize(50, 35))
        self.progressBar.setMaximumSize(QtCore.QSize(400, 35))
        self.progressBar.setProperty("value", 0)
        self.progressBar.setAlignment(
            QtCore.Qt.AlignLeading | QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        self.progressBar.setTextVisible(True)
        self.progressBar.setOrientation(QtCore.Qt.Horizontal)
        self.progressBar.setObjectName("progressBar")
        self.horizontalLayout_progressBar.addWidget(self.progressBar)
        self.verticalLayout.addLayout(self.horizontalLayout_progressBar)
        self.progress_label = QtWidgets.QLabel(self.centralwidget)
        self.progress_label.setAlignment(QtCore.Qt.AlignCenter)
        self.progress_label.setObjectName("progress_label")
        self.verticalLayout.addWidget(self.progress_label)
        self.progress_label.hide()
        spacerItem6 = QtWidgets.QSpacerItem(
            20, 20, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.verticalLayout.addItem(spacerItem6)
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 868, 22))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)

        # Initilize signaling
        self.progress_signal.connect(self.handle_progress_signal)

        self.url_input_lineEdit.returnPressed.connect(
            self.run_cert_visualization)

        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate(
            "MainWindow", "Certificate Security Visualization"))
        self.header_text_label.setText(_translate(
            "MainWindow", "Certificate Security Visualization"))
        self.sub_header_label.setText(_translate(
            "MainWindow", "Developed by\nSondre Solbakken"))
        self.url_input_lineEdit.setPlaceholderText(
            _translate("MainWindow", "www.example.com"))
        self.progress_label.setText(_translate(
            "MainWindow", "None"))

    def handle_progress_signal(self, percent, action_string):
        self.progress_label.setText(action_string)
        self.progressBar.setValue(percent)

    def run_cert_visualization(self):
        self.url_input_lineEdit.setEnabled(False)
        self.progress_label.show()
        domain_url = self.url_input_lineEdit.text()
        domain = domain_url.replace("http://", "")

        try:

            res = run_visualize.certificate_scan(domain, self.progress_signal)

        except Exception as e:
            # Open popup window with failure
            # TODO: Write better exception format with type of ex
            error_msg = f"Type: {type(e)}\n\n{str(e)}"
            self.ExceptionDialog = QtWidgets.QDialog()
            self.ex_ui = Ui_ExceptionDialog()
            self.ex_ui.setupUi(self.ExceptionDialog, error_msg)
            self.ExceptionDialog.show()

            self.clean_main_window()
            self.url_input_lineEdit.setEnabled(True)
            return

        # Initilize display window (taking output from last run)
        self.Form = QtWidgets.QWidget()
        self.ui = Ui_Form()
        self.ui.setupUi(self.Form)

        # Do data translation for all windows in display
        # Connection details window
        connection_details = dt.translate_connection_details(res)
        # TODO: Fill connection details from here by calling it in dt
        # dt.fill_connection_details(self.ui.connection_details, connection_details)
        self.ui.fill_connection_details(connection_details)

        # Main information window (Certificate path)
        validation_res, cert_path = res["validation_path"]
        if validation_res:
            certificate_path = dt.translate_certificate_path(cert_path)
        else:
            # Call seperate function for displaying validation failure
            # with the error message. Done in display window
            pass

        # Open display window
        self.Form.show()

        self.clean_main_window()
        self.url_input_lineEdit.setEnabled(True)

    def clean_main_window(self):
        self.progress_label.hide()
        self.url_input_lineEdit.clear()
        self.progressBar.setValue(0)


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
