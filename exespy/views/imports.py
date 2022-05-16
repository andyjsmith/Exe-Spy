import PySide6.QtWidgets as QtWidgets

from .. import pe_file
from .components import table


class ImportsView(QtWidgets.QWidget):
    NAME = "Imports"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.setLayout(QtWidgets.QVBoxLayout())

        # Imports
        self.imports_table = table.TableView(
            fit_columns=True,
            fit_to_contents=False,
            headers=["Name", "Library", "Address"],
        )
        self.layout().addWidget(self.imports_table)

    def load(self, pe_obj: pe_file.PEFile):
        # Imports
        imports_list = []

        if hasattr(pe_obj.pe, "DIRECTORY_ENTRY_IMPORT"):
            for import_obj in pe_obj.pe.DIRECTORY_ENTRY_IMPORT:
                for import_func in import_obj.imports:
                    if import_func.name:
                        name = import_func.name.decode("utf-8").strip("\x00")
                    else:
                        name = f"[Ordinal {import_func.ordinal}]"

                    imports_list.append(
                        (
                            name,
                            import_obj.dll.decode("utf-8").strip("\x00"),
                            hex(import_func.address),
                        )
                    )

        # TODO: Add support for delay imports DIRECTORY_ENTRY_DELAY_IMPORT

        self.imports_table.setModel(
            table.TableModel(imports_list, headers=["Name", "Library", "Address"])
        )
