import PySide6.QtWidgets as QtWidgets
import PySide6.QtGui as QtGui
import PySide6.QtCore as QtCore

from .. import helpers
from .. import pe_file
from .components import table


class StringsView(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Set up scroll area
        self.setLayout(QtWidgets.QVBoxLayout())

        self.controls_widget = QtWidgets.QWidget()
        self.controls_widget.setLayout(QtWidgets.QHBoxLayout())
        self.controls_widget.layout().setContentsMargins(0, 0, 0, 0)
        self.controls_widget.setSizePolicy(
            QtWidgets.QSizePolicy.MinimumExpanding, QtWidgets.QSizePolicy.Maximum)

        self.search_box = QtWidgets.QLineEdit()
        self.search_box.setPlaceholderText("Search")
        self.search_box.textChanged.connect(self.handle_search_change)
        self.controls_widget.layout().addWidget(self.search_box)

        self.case_sensitive = QtWidgets.QCheckBox("Case Sensitive")
        self.case_sensitive.stateChanged.connect(
            self.handle_case_sensitive_change)
        self.controls_widget.layout().addWidget(self.case_sensitive)

        self.search_minimum_label = QtWidgets.QLabel("Minimum Length:")
        self.controls_widget.layout().addWidget(self.search_minimum_label)

        self.search_minimum = QtWidgets.QSpinBox()
        self.search_minimum.setMinimum(1)
        self.search_minimum.setMaximum(100000000)
        self.search_minimum.setValue(4)
        self.search_minimum.valueChanged.connect(self.handle_minimum_change)
        self.controls_widget.layout().addWidget(self.search_minimum)

        self.layout().addWidget(self.controls_widget)

        self.table = table.Table(
            fit_columns=True, fit_to_contents=False, headers=["String", "Offset"])
        self.table.setSortingEnabled(True)
        self.layout().addWidget(self.table)

    def load(self, pe_obj: pe_file.PEFile):
        self.pe = pe_obj
        self.table.set_contents(pe_obj.strings(
            min_length=self.search_minimum.value()), hex_columns=[1])

    def handle_search_change(self):
        search_text = self.search_box.text()
        for row in range(self.table.rowCount()):
            if self.case_sensitive.isChecked():
                self.table.setRowHidden(
                    row, search_text not in self.table.item(row, 0).text())
            else:
                self.table.setRowHidden(
                    row, search_text.lower() not in self.table.item(row, 0).text().lower())

        if len([x for x in range(self.table.rowCount()) if not self.table.isRowHidden(x)]) == 0:
            palette = QtGui.QPalette()
            palette.setColor(QtGui.QPalette.Base, QtGui.QColor(255, 150, 150))
            self.search_box.setPalette(palette)
        else:
            palette = QtGui.QPalette()
            self.search_box.setPalette(palette)

    def handle_case_sensitive_change(self):
        self.handle_search_change()

    def handle_minimum_change(self):
        self.load(self.pe)
        self.handle_search_change()
