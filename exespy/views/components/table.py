import PySide6.QtCore as QtCore
import PySide6.QtWidgets as QtWidgets


class TableGroup(QtWidgets.QGroupBox):
    """QGroupBox with a Table inside"""

    def __init__(
        self,
        title,
        *args,
        fit_columns=False,
        headers=None,
        fit_to_contents=True,
        **kwargs
    ):
        super().__init__(title, *args, **kwargs)

        self.view = TableView(
            fit_columns=fit_columns, headers=headers, fit_to_contents=fit_to_contents
        )

        self.setLayout(QtWidgets.QFormLayout())
        self.layout().setContentsMargins(0, 0, 0, 0)
        self.layout().setSpacing(0)
        self.layout().addWidget(self.view)


class TableModel(QtCore.QAbstractTableModel):
    """Custom QAbstractTableModel for modeling a table"""

    def __init__(self, data, *args, headers=None, hex_columns=[], **kwargs) -> None:
        super(TableModel, self).__init__(*args, **kwargs)
        self._data = data

        self.headers = headers
        self.hex_columns = hex_columns

        if self.headers is None:
            self.headers = []

    def set_data(self, data):
        self._data = data

    def headerData(self, section, orientation, role=QtCore.Qt.DisplayRole):
        if role == QtCore.Qt.DisplayRole and orientation == QtCore.Qt.Horizontal:
            return self.headers[section]
        return QtCore.QAbstractTableModel.headerData(self, section, orientation, role)

    def data(self, index, role):
        if role == QtCore.Qt.DisplayRole:
            # See below for the nested-list data structure.
            # .row() indexes into the outer list,
            # .column() indexes into the sub-list
            if index.column() in self.hex_columns:
                return hex(self._data[index.row()][index.column()])
            else:
                return self._data[index.row()][index.column()]
        elif role == QtCore.Qt.UserRole:
            return self._data[index.row()][index.column()]

    def rowCount(self, index):
        # The length of the outer list.
        return len(self._data)

    def columnCount(self, index):
        # The following takes the first sub-list, and returns
        # the length (only works if all rows are an equal length)
        if len(self._data) > 0:
            return len(self._data[0])
        return 0


class TableView(QtWidgets.QTableView):
    """Custom QTableView for displaying a table"""

    def __init__(
        self,
        *args,
        fit_columns=False,
        headers=None,
        fit_to_contents=True,
        first_column_scale=3,
        **kwargs
    ) -> None:
        super().__init__(*args, **kwargs)

        self.headers = headers
        self.fit_columns = fit_columns
        self.fit_to_contents = fit_to_contents
        self.first_column_scale = first_column_scale

        self.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)

        if self.headers is None:
            self.horizontalHeader().hide()

        self.horizontalHeader().setStretchLastSection(True)
        self.verticalHeader().hide()

        self.setSizePolicy(
            QtWidgets.QSizePolicy.MinimumExpanding, QtWidgets.QSizePolicy.Minimum
        )
        self.setFrameStyle(QtWidgets.QFrame.NoFrame)
        self.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)

        self.fit_contents()

    def fit_contents(self) -> None:
        """Resize the table to fit its contents"""

        if self.fit_columns:
            for col in range(self.horizontalHeader().count()):
                self.horizontalHeader().setSectionResizeMode(
                    col, QtWidgets.QHeaderView.ResizeToContents
                )
        else:
            self.setColumnWidth(0, self.width() / self.first_column_scale)

        self.resizeRowsToContents()

        if self.fit_to_contents and self.model():
            table_height = 0
            if self.model().rowCount(None) != 0:
                for i in range(self.model().rowCount(None)):
                    table_height += self.rowHeight(i)

            table_height += self.horizontalHeader().height()

            self.setMinimumHeight(table_height)
            self.setMaximumHeight(table_height)

    def setModel(self, *args, **kwargs):
        super().setModel(*args, **kwargs)
        if self.fit_to_contents:
            self.fit_contents()
