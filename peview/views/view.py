import PySide6.QtWidgets as QtWidgets

from .. import pe_file


class View(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def load(self, pe_file: pe_file.PEFile):
        ...
