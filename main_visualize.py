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
        MainWindow.resize(815, 405)
        MainWindow.setFocusPolicy(QtCore.Qt.StrongFocus)

        MainWindow.setMinimumSize(QtCore.QSize(405, 410))

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
        dt.fill_connection_details(
            self.ui.connection_details, connection_details)

        data_model = dt.create_data_model(self.ui, self.Form)
        data_root = data_model.invisibleRootItem()

        metric_model = dt.create_metric_model(self.ui, self.Form)
        metric_root = metric_model.invisibleRootItem()

        # Main information window (Certificate path)
        validation_res = res["validation_path"]
        if validation_res[0]:
            cert_path = validation_res[1]
            translated_path = dt.translate_certificate_path(cert_path)
            dt.fill_data_model(data_root, translated_path)

        else:
            # Call seperate function for displaying validation failure
            # with the error message. Parse and display only end-cert
            # and issuer. Error should go in metric window
            _, cert_path, _ = validation_res
            translated_path = dt.translate_failed_path(cert_path)
            dt.fill_data_model(data_root, translated_path)

            # Displaying validation error dialog to warn user
            # self.ExceptionDialog = QtWidgets.QDialog()
            # self.ex_ui = Ui_ExceptionDialog()
            # self.ex_ui.setupUi(self.ExceptionDialog, path_error)
            # self.ExceptionDialog.show()

        # Main information window (CRL)
        crl_support, crl_revoked, crl_data = res["crl"]
        translated_crl = dt.translate_crl(crl_support, crl_data)
        dt.fill_data_model(data_root, translated_crl)

        # Main information window (OCSP) ocsp data can be error string
        ocsp_support, ocsp_revoked, ocsp_data = res["ocsp"]
        translated_ocsp = dt.translate_ocsp(ocsp_support, ocsp_data)
        dt.fill_data_model(data_root, translated_ocsp)

        # Main information window (CT)
        ct_support, ct_data = res["ct"]
        translated_ct = dt.translate_certificate_transparency(
            ct_support, ct_data)
        dt.fill_data_model(data_root, translated_ct)

        # Expand first level of CT row(3)
        if ct_support:
            ct_item = data_model.item(3, 0)
            ct_index = data_model.indexFromItem(ct_item)
            self.ui.data_view.expandRecursively(ct_index, 1)
            self.ui.data_view.collapse(ct_index)

        # Main information window (CAA)
        caa_support, caa_data = res["caa"]
        translated_caa = dt.translate_caa(caa_support, caa_data)
        dt.fill_data_model(data_root, translated_caa)

        # Main information window (Proto_Cipher)
        pc_support, pc_data = res["proto_cipher"]
        translated_pc = dt.translate_proto_cipher(pc_support, pc_data)
        dt.fill_data_model(data_root, translated_pc)

        # Expand End-user Certificate and first intermediate in data_view
        if validation_res[0]:
            val_path_item = data_model.item(0, 0)
            val_path_index = data_model.indexFromItem(val_path_item)
            end_cert_index = data_model.indexFromItem(
                val_path_item.child(0, 0))
            interm_index = data_model.indexFromItem(
                val_path_item.child(1, 0).child(0, 0))
            self.ui.data_view.expand(val_path_index)
            self.ui.data_view.expand(end_cert_index)
            self.ui.data_view.expand(interm_index)

        # Translation of metrics window
        # Scan date
        scan_date = res["connection"]["date"]
        dt.fill_data_model(metric_root, {"Scan date": scan_date})

        # Certificate revoked
        translated_revoked = dt.translate_revoked(
            res["cert_revoked"], crl_support, ocsp_support)
        dt.fill_data_model(metric_root, translated_revoked)

        # Path validation
        translated_validation_res = dt.translate_validation_res(validation_res)
        dt.fill_data_model(metric_root, translated_validation_res)

        # Total keyusage
        try:
            translated_keyusage = dt.translate_all_keyusages(
                res["total_keyusage"])
            dt.fill_data_model(metric_root, translated_keyusage)
        except Exception:
            # Did not find a total key usage entry
            pass

        # Evaluation results
        evaluation_tree, evaluation_score = res["evaluation_result"]
        translated_evaluation = dt.translate_evaluation(evaluation_tree)
        dt.fill_data_model(metric_root, translated_evaluation)

        # Set light and score
        dt.set_evaluation_result(evaluation_score, self.ui)

        # resize data_views second column to fit data
        self.ui.data_view.resizeColumnToContents(1)
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
