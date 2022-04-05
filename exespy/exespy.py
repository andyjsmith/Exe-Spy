import os
import sys

import PySide6.QtGui as QtGui
import PySide6.QtWidgets as QtWidgets
import PySide6.QtCore as QtCore

import pefile

from . import pe_file
from . import tab_view
from . import license_dialog
from . import helpers


# Set the app ID on windows (helps with making sure icon is used)
try:
    import ctypes
    appid = f"ajsmith.{helpers.APP_NAME_SHORT}.desktop.v1"
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(appid)
except (AttributeError, OSError):
    pass


class ExeSpy(QtWidgets.QMainWindow):
    """Main window"""

    def __init__(self):
        """Initialize the application"""
        super().__init__()

        self.app = QtWidgets.QApplication.instance()
        self.settings = QtCore.QSettings()

        self.initial_style = self.app.style().name()

        use_native_style = self.settings.value(
            "view/native_style", False, bool)

        if not use_native_style:
            self.app.setStyle("fusion")

        # Set up main window
        self.resize(1200, 700)
        self.setWindowTitle(helpers.APP_NAME)

        # Restore window geometry from settings
        self.restoreGeometry(self.settings.value(
            "view/geometry", QtCore.QByteArray()))

        self.tabview = tab_view.TabView(self)

        # Set up file menu
        file_menu = QtWidgets.QMenu("&File", self)
        open_action = QtGui.QAction("Open PE", self)
        open_action.setShortcut(QtGui.QKeySequence.Open)
        open_action.triggered.connect(self.show_open_file)
        file_menu.addAction(open_action)
        file_menu.addSeparator()
        quit_action = QtGui.QAction("Quit", self)
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)
        self.menuBar().addMenu(file_menu)

        # Set up view menu
        view_menu = QtWidgets.QMenu("&View", self)
        self.native_style_action = QtGui.QAction("Use native style", self)
        self.native_style_action.setCheckable(True)
        self.native_style_action.setChecked(use_native_style)
        self.native_style_action.toggled.connect(self.toggle_style)
        view_menu.addAction(self.native_style_action)
        self.menuBar().addMenu(view_menu)

        # Set up help menu
        help_menu = QtWidgets.QMenu("&Help", self)
        about_action = QtGui.QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        licenses_action = QtGui.QAction("Third-Party Licenses", self)
        licenses_action.triggered.connect(self.show_licenses)
        help_menu.addAction(licenses_action)
        self.menuBar().addMenu(help_menu)

        self.menuBar().setContextMenuPolicy(QtCore.Qt.PreventContextMenu)

        self.statusBar()

        # Set up main layout
        main_widget = QtWidgets.QWidget(self)
        main_layout = QtWidgets.QVBoxLayout(main_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_widget.setLayout(main_layout)

        self.statusBar().setStyleSheet(
            "QStatusBar QLabel { border-color: lightgray; border-style: solid; border-width: 0 1px 0 0; }")

        # Create a container for the tab view
        tab_container = QtWidgets.QWidget()
        tab_container_layout = QtWidgets.QVBoxLayout(tab_container)
        tab_container_layout.setContentsMargins(0, 0, 0, 0)
        tab_container.setLayout(tab_container_layout)
        tab_container_layout.addWidget(self.tabview)
        self.tabview.setSizePolicy(
            QtWidgets.QSizePolicy.MinimumExpanding, QtWidgets.QSizePolicy.MinimumExpanding)

        self.setCentralWidget(main_widget)

        main_layout.addWidget(tab_container)

        self.progress_bar = QtWidgets.QProgressBar(self.statusBar())
        self.progress_bar.setMaximumWidth(100)
        self.progress_bar.hide()
        self.statusBar().addPermanentWidget(self.progress_bar)

    def show_about(self):
        """Show the about dialog"""
        QtWidgets.QMessageBox().about(
            self, f"About {helpers.APP_NAME}", helpers.ABOUT_TEXT)

    def show_licenses(self):
        """Show the third-party license dialog"""
        license = license_dialog.LicenseDialog(self)
        license.exec()

    def show_open_file(self):
        """Show the open file dialog"""
        file_selection = QtWidgets.QFileDialog.getOpenFileName(
            self, "Open PE File")

        self.statusBar().showMessage("Loading...")
        self.statusBar().repaint()

        if isinstance(file_selection, tuple) and len(file_selection) > 0 and len(file_selection[0]) > 0:
            self.load_pe(file_selection[0])

        self.statusBar().clearMessage()

    def toggle_style(self):
        """Toggle the application style between native and fusion"""
        if self.native_style_action.isChecked():
            self.app.setStyle(self.initial_style)
            self.settings.setValue("view/native_style", True)
        else:
            self.app.setStyle("fusion")
            self.settings.setValue("view/native_style", False)

    def closeEvent(self, event):
        """Save the current geometry of the application"""
        self.settings.setValue("view/geometry", self.saveGeometry())
        event.accept()

    def load_pe(self, path: str):
        """Load a PE file and begin parsing"""
        try:
            self.pe = pe_file.PEFile(path)
        except pefile.PEFormatError:
            helpers.show_message_box(
                "Not a valid PE file", alert_type=helpers.MessageBoxTypes.CRITICAL)
        except FileNotFoundError:
            helpers.show_message_box(
                "File not found", alert_type=helpers.MessageBoxTypes.CRITICAL)
        else:
            self.tabview.load(self.pe)


def main():
    """Main entry point"""
    app = QtWidgets.QApplication(sys.argv)
    # app.setAttribute(QtCore.Qt.AA_EnableHighDpiScaling)

    app.setOrganizationName(helpers.ORGANIZATION_NAME)
    app.setOrganizationDomain(helpers.ORGANIZATION_DOMAIN)
    app.setApplicationName(helpers.APP_NAME)

    exe_spy = ExeSpy()

    app.setWindowIcon(QtGui.QIcon(helpers.resource_path("img/icon.ico")))

    exe_spy.show()

    # Close the splash screen
    try:
        import pyi_splash  # type: ignore
        pyi_splash.close()
    except ImportError:
        pass

    # Process command-line file(s)
    if len(sys.argv) > 1:
        for filename in sys.argv[1:]:
            exe_spy.load_pe(filename)

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
