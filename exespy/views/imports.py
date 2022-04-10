import PySide6.QtWidgets as QtWidgets

from .. import pe_file
from .components import table


class ImportsView(QtWidgets.QScrollArea):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Set up scroll area
        self.setWidgetResizable(True)
        self.scroll_area = QtWidgets.QWidget(self)
        self.setWidget(self.scroll_area)
        self.scroll_area.setLayout(QtWidgets.QFormLayout())

        # Libraries
        self.imports_group = table.TableGroup(
            "Imports", fit_columns=True, headers=["Name", "Library", "Address"])
        self.scroll_area.layout().addWidget(self.imports_group)

    def load(self, pe_obj: pe_file.PEFile):
        # Libraries
        imports_list = []
        for import_obj in pe_obj.pe.DIRECTORY_ENTRY_IMPORT:
            for import_func in import_obj.imports:
                if import_func.name:
                    imports_list.append((
                        import_func.name.decode("utf-8").strip('\x00'),
                        import_obj.dll.decode("utf-8").strip('\x00'),
                        hex(import_func.address)
                    ))
                else:
                    imports_list.append((
                        f"[Ordinal {import_func.ordinal}]",
                        import_obj.dll.decode("utf-8").strip('\x00'),
                        hex(import_func.address)
                    ))

        self.imports_group.view.setModel(table.TableModel(
            imports_list, headers=["Name", "Library", "Address"]))
