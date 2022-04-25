import PySide6.QtCore as QtCore
import PySide6.QtWidgets as QtWidgets
import PySide6.QtGui as QtGui

import humanize
import icoextract

from . import view
from .. import helpers
from .. import pe_file
from .components import table


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
        self.image_group.view.setModel(
            table.TableModel(
                [
                    (
                        "Size",
                        f"{humanize.naturalsize(pe_obj.stat.st_size, binary=True)} ({humanize.intcomma(pe_obj.stat.st_size)} bytes)",
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
                    ("Checksum", pe_obj.verify_checksum()),
                ]
            )
        )
