import PySide6.QtWidgets as QtWidgets
import PySide6.QtGui as QtGui
import PySide6.QtCore as QtCore

from .. import helpers
from .. import pe_file
from .. import state
from .components import table


class StringsView(QtWidgets.QWidget):
    NAME = "Strings"
    LOAD_ASYNC = True
    SHOW_PROGRESS = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.loaded = False

        self.setLayout(QtWidgets.QVBoxLayout())

        # Set up top control bar
        self.controls_widget = QtWidgets.QWidget()
        self.controls_widget.setLayout(QtWidgets.QHBoxLayout())
        self.controls_widget.layout().setContentsMargins(0, 0, 0, 0)
        self.controls_widget.setSizePolicy(
            QtWidgets.QSizePolicy.MinimumExpanding, QtWidgets.QSizePolicy.Maximum
        )

        self.search_box = QtWidgets.QLineEdit()
        self.search_box.setPlaceholderText("Search")
        self.search_box.textChanged.connect(self.handle_search_change)
        self.controls_widget.layout().addWidget(self.search_box)

        self.case_sensitive = QtWidgets.QCheckBox("Case Sensitive")
        self.case_sensitive.stateChanged.connect(self.handle_case_sensitive_change)
        self.controls_widget.layout().addWidget(self.case_sensitive)

        self.search_minimum_label = QtWidgets.QLabel("Minimum Length:")
        self.controls_widget.layout().addWidget(self.search_minimum_label)

        self.search_minimum = QtWidgets.QSpinBox()
        self.search_minimum.setMinimum(1)
        self.search_minimum.setMaximum(100000000)
        self.search_minimum.setValue(8)
        self.search_minimum.valueChanged.connect(self.handle_minimum_change)
        self.controls_widget.layout().addWidget(self.search_minimum)

        self.layout().addWidget(self.controls_widget)

        # Set up strings table
        self.table_view = table.TableView(
            fit_columns=False,
            fit_to_contents=False,
            headers=["String", "Offset"],
            first_column_scale=1.2,
        )
        self.table_view.setSortingEnabled(True)

        self.layout().addWidget(self.table_view)

    def load_async(self, pe_obj: pe_file.PEFile):
        self.pe = pe_obj
        self.table_model = table.TableModel(
            pe_obj.strings(min_length=self.search_minimum.value()),
            headers=["String", "Offset"],
            hex_columns=[1],
        )

        self.table_proxy = QtCore.QSortFilterProxyModel()
        self.table_proxy.setSourceModel(self.table_model)
        self.table_proxy.setSortRole(QtCore.Qt.UserRole)
        self.table_proxy.setFilterKeyColumn(0)
        self.table_proxy.setSortCaseSensitivity(QtCore.Qt.CaseInsensitive)

    def load_finalize(self):
        self.table_view.setModel(self.table_proxy)
        self.table_view.fit_contents()
        self.handle_case_sensitive_change()

    def enable_tab(self):
        state.tabview.set_loading(self.NAME, False)

    def load(self, pe_obj: pe_file.PEFile):
        self.load_async(pe_obj)
        self.load_finalize()

    def handle_search_change(self):
        search_text = self.search_box.text()

        self.table_proxy.setFilterFixedString(search_text)
        self.table_view.resizeRowsToContents()

        if self.table_proxy.rowCount() == 0:
            palette = QtGui.QPalette()
            palette.setColor(QtGui.QPalette.Base, QtGui.QColor(255, 150, 150))
            self.search_box.setPalette(palette)
        else:
            palette = QtGui.QPalette()
            self.search_box.setPalette(palette)

    def handle_case_sensitive_change(self):
        if self.case_sensitive.isChecked():
            self.table_proxy.setFilterCaseSensitivity(QtCore.Qt.CaseSensitive)
        else:
            self.table_proxy.setFilterCaseSensitivity(QtCore.Qt.CaseInsensitive)
        self.handle_search_change()

    def handle_minimum_change(self):
        progress = helpers.progress_dialog(f"Loading {self.NAME}...", "Loading", self)
        self.load(self.pe)
        self.handle_search_change()
        progress.close()
