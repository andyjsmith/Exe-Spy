import time
import logging

import PySide6.QtCore as QtCore
import PySide6.QtWidgets as QtWidgets
import PySide6.QtGui as QtGui

import icoextract

from .. import helpers
from .. import pe_file
from .components import table


class ChecksumWorker(QtCore.QObject):
    """Calculate the checksum of the PE file asynchronously since it is slow"""

    finished = QtCore.Signal()

    def __init__(self, pe: pe_file.PEFile):
        super().__init__()
        self.pe = pe

    def run(self):
        start = time.time()
        self.pe.calculate_checksum()
        logging.getLogger("exespy").debug(
            f" (ASYNC) took {time.time() - start:.4f} seconds"
        )
        self.finished.emit()


class GeneralView(QtWidgets.QScrollArea):
    NAME = "General"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Set up scroll area
        self.setWidgetResizable(True)
        self.scroll_area = QtWidgets.QWidget(self)
        self.setWidget(self.scroll_area)
        self.scroll_area.setLayout(QtWidgets.QFormLayout())

        # File Information group
        ########################
        self.file_group = QtWidgets.QGroupBox("File Information")
        self.file_group.setLayout(QtWidgets.QFormLayout())
        self.scroll_area.layout().addWidget(self.file_group)

        # Name
        self.file_name = QtWidgets.QLabel()
        font = self.file_name.font()
        font.setPointSize(font.pointSize() + 2)
        self.file_name.setFont(font)
        self.file_name.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        self.file_group.layout().addWidget(self.file_name)

        self.icon = QtWidgets.QLabel()
        self.file_group.layout().addWidget(self.icon)

        # File information group
        self.file_group = table.TableGroup("File Information")
        self.scroll_area.layout().addWidget(self.file_group)

        # Image information group
        self.image_group = table.TableGroup("Image Information")
        self.scroll_area.layout().addWidget(self.image_group)

    def load(self, pe_obj: pe_file.PEFile):
        self.pe_obj = pe_obj

        self.thread = QtCore.QThread()
        self.worker = ChecksumWorker(pe_obj)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()
        self.thread.finished.connect(self.show_checksum_result)

        self.file_name.setText(pe_obj.name)

        try:
            icon = icoextract.IconExtractor(pe_obj.path).get_icon()
            icon.seek(0)
            icon_bytes = icon.read()

            pixmap = QtGui.QPixmap()
            pixmap.loadFromData(icon_bytes)
            pixmap = pixmap.scaled(
                48, 48, QtCore.Qt.KeepAspectRatio, QtCore.Qt.SmoothTransformation
            )
            self.icon.setPixmap(pixmap)
        except icoextract.IconExtractorError:
            pass

        # File Metadata
        c_time = helpers.format_time(pe_obj.stat.st_ctime)
        m_time = helpers.format_time(pe_obj.stat.st_mtime)
        a_time = helpers.format_time(pe_obj.stat.st_atime)
        self.file_group.view.setModel(
            table.TableModel(
                [
                    ("Path", pe_obj.path),
                    ("Created", c_time),
                    ("Modified", m_time),
                    ("Accessed", a_time),
                ]
            )
        )

        # Image Information
        self.model = [
            (
                "Size",
                f"{self.sizeof_fmt(pe_obj.stat.st_size)} ({pe_obj.stat.st_size:,} bytes)",
            ),
            (
                "Timestamp",
                helpers.format_time(pe_obj.pe.FILE_HEADER.TimeDateStamp),
            ),
            ("Type", pe_obj.type()),
            ("Architecture", pe_obj.architecture()),
            ("Subsystem", pe_obj.subsystem()),
            ("Image Base", hex(pe_obj.pe.OPTIONAL_HEADER.ImageBase)),
            ("Entrypoint", hex(pe_obj.pe.OPTIONAL_HEADER.AddressOfEntryPoint)),
            ("Signature", pe_obj.verify_signature()),
        ]
        self.image_group.view.setModel(
            table.TableModel(self.model + [("Checksum", "loading...")])
        )

    def show_checksum_result(self):
        """Add the checksum verification result to the table."""
        self.image_group.view.setModel(
            table.TableModel(self.model + [("Checksum", self.pe_obj.verify_checksum())])
        )
        QtCore.QCoreApplication.processEvents()

    def sizeof_fmt(self, num, suffix="B"):
        for unit in ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"]:
            if abs(num) < 1024.0:
                return f"{num:3.1f}{unit}{suffix}"
            num /= 1024.0
        return f"{num:.1f}Yi{suffix}"
