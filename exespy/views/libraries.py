import PySide6.QtWidgets as QtWidgets

from .. import pe_file
from .components import table


class LibrariesView(QtWidgets.QWidget):
    NAME = "Libraries"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.setLayout(QtWidgets.QVBoxLayout())

        # Libraries
        self.libraries_table = table.TableView(
            fit_columns=True, fit_to_contents=False, headers=["Name", "Imports"]
        )
        self.layout().addWidget(self.libraries_table)

    def load(self, pe_obj: pe_file.PEFile):
        # Libraries
        libraries_list = []
        if hasattr(pe_obj.pe, "DIRECTORY_ENTRY_IMPORT"):
            for import_obj in pe_obj.pe.DIRECTORY_ENTRY_IMPORT:
                libraries_list.append(
                    (
                        import_obj.dll.decode("utf-8").strip("\x00"),
                        len(import_obj.imports),
                    )
                )

        self.libraries_table.setModel(
            table.TableModel(libraries_list, headers=["Name", "Imports"])
        )
