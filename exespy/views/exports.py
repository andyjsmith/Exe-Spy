import PySide6.QtWidgets as QtWidgets

from .. import pe_file
from .components import table


class ExportsView(QtWidgets.QScrollArea):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Set up scroll area
        self.setWidgetResizable(True)
        self.scroll_area = QtWidgets.QWidget(self)
        self.setWidget(self.scroll_area)
        self.scroll_area.setLayout(QtWidgets.QFormLayout())

        # Exports
        self.exports_group = table.TableGroup(
            "Exports", fit_columns=True, headers=["Name", "Ordinal", "Address"]
        )
        self.scroll_area.layout().addWidget(self.exports_group)

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

        self.exports_group.view.setModel(
            table.TableModel(exports_list, headers=["Name", "Ordinal", "Address"])
        )
