import PySide6.QtWidgets as QtWidgets

from .. import pe_file
from .components import table


class ExportsView(QtWidgets.QWidget):
    NAME = "Exports"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.setLayout(QtWidgets.QVBoxLayout())

        # Exports
        self.exports_table = table.TableView(
            fit_columns=True,
            fit_to_contents=False,
            headers=["Name", "Ordinal", "Address"],
        )
        self.layout().addWidget(self.exports_table)

    def load(self, pe_obj: pe_file.PEFile):
        # Exports
        exports_list = []

        if hasattr(pe_obj.pe, "DIRECTORY_ENTRY_EXPORT"):
            for symbol in pe_obj.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if symbol.name:
                    name = symbol.name.decode("utf-8").strip("\x00")
                else:
                    name = f"[Ordinal {symbol.ordinal}]"

                exports_list.append((name, symbol.ordinal, hex(symbol.address)))

        self.exports_table.setModel(
            table.TableModel(exports_list, headers=["Name", "Ordinal", "Address"])
        )
