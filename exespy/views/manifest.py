import PySide6.QtWidgets as QtWidgets
import PySide6.QtGui as QtGui
import PySide6.QtCore as QtCore
import magic

from .. import pe_file
from .components import textedit


class ManifestView(QtWidgets.QWidget):
    NAME = "Manifest"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.setLayout(QtWidgets.QVBoxLayout())

        self.manifest_edit = textedit.MonoTextEdit()

        self.layout().addWidget(self.manifest_edit)

    def load(self, pe_obj: pe_file.PEFile):
        # Manifest

        manifest_rsrc = None
        for resource in pe_obj.resources:
            if resource.rtype == "RT_MANIFEST":
                manifest_rsrc = resource
                break

        if manifest_rsrc is None:
            self.manifest_edit.setPlainText("No manifest found.")
            return

        self.manifest_edit.setPlainText(
            manifest_rsrc.data.decode("utf-8", errors="ignore")
        )
