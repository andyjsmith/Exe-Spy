import PySide6.QtCore as QtCore
import PySide6.QtWidgets as QtWidgets
from matplotlib.pyplot import table


class NumericItem(QtWidgets.QTableWidgetItem):
    # https://stackoverflow.com/questions/48496311/how-to-customize-sorting-behaviour-in-qtablewidget
    def __lt__(self, other):
        return (self.data(QtCore.Qt.UserRole) <
                other.data(QtCore.Qt.UserRole))


class TableGroup(QtWidgets.QGroupBox):
    """QGroupBox with a Table inside"""

    def __init__(self, title, *args, **kwargs):
        super().__init__(title)

        self.table = Table(*args, **kwargs)
        """KVTable inside the group, use to set contents"""

        self.setLayout(QtWidgets.QFormLayout())
        self.layout().setContentsMargins(0, 0, 0, 0)
        self.layout().setSpacing(0)
        self.layout().addWidget(self.table)


class Table(QtWidgets.QTableWidget):
    """Table extended from QTableWidget"""

    def __init__(self, *args, fit_columns=False, headers=None, fit_to_contents=True, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.fit_columns = fit_columns
        self.fit_to_contents = fit_to_contents
        self.setColumnCount(3)
        self.setRowCount(0)
        self.headers = headers

        if self.headers is None:
            self.horizontalHeader().hide()
        else:
            self.setHorizontalHeaderLabels(self.headers)

        self.horizontalHeader().setStretchLastSection(True)
        self.verticalHeader().hide()
        self.setSizePolicy(
            QtWidgets.QSizePolicy.MinimumExpanding, QtWidgets.QSizePolicy.Minimum)
        self.setFrameStyle(QtWidgets.QFrame.NoFrame)
        self.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)

        self.fit_contents()

    def fit_contents(self) -> None:
        """Resize the table to fit its contents"""

        if self.fit_columns:
            for col in range(self.horizontalHeader().count()):
                self.horizontalHeader().setSectionResizeMode(
                    col, QtWidgets.QHeaderView.ResizeToContents)
        else:
            self.setColumnWidth(0, self.width() / 3)

        self.resizeRowsToContents()

        if self.fit_to_contents:
            table_height = 0
            if self.rowCount() != 0:
                for i in range(self.rowCount()):
                    table_height += self.rowHeight(i)

            table_height += self.horizontalHeader().height()

            self.setMinimumHeight(table_height)
            self.setMaximumHeight(table_height)

    def set_contents(self, contents: "list[tuple]", hex_columns=[]) -> None:
        """
        Set the contents of the table

        :param contents: list of tuples that contain the items in a row
        :param numeric_columns: list of column numbers that should be sorted numerically
        """
        self.clear()
        self.setRowCount(len(contents))

        if self.headers is None:
            self.horizontalHeader().hide()
        else:
            self.setHorizontalHeaderLabels(self.headers)

        if len(contents) == 0:
            return

        self.setColumnCount(len(contents[0]))

        for row, cols in enumerate(contents):
            for col, field in enumerate(cols):
                if col in hex_columns:
                    item = NumericItem(hex(field))
                    item.setData(QtCore.Qt.UserRole, field)
                else:
                    item = QtWidgets.QTableWidgetItem(field)
                item.setFlags(item.flags() & ~
                              QtCore.Qt.ItemFlag.ItemIsEditable)
                self.setItem(row, col, item)

        self.fit_contents()
