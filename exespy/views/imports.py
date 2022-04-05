import PySide6.QtWidgets as QtWidgets

from .. import pe_file


class ImportsView(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def load(self, pe_obj: pe_file.PEFile):
        ...
