import PySide6.QtWidgets as QtWidgets

from .. import pe_file
from .components import table


class LibrariesView(QtWidgets.QScrollArea):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Set up scroll area
        self.setWidgetResizable(True)
        self.scroll_area = QtWidgets.QWidget(self)
        self.setWidget(self.scroll_area)
        self.scroll_area.setLayout(QtWidgets.QFormLayout())

        # Libraries
        self.libraries_group = table.TableGroup(
            "Libraries", fit_columns=True, headers=["Name", "Imports"]
        )
        self.scroll_area.layout().addWidget(self.libraries_group)

    def load(self, pe_obj: pe_file.PEFile):
        # Libraries
        libraries_list = []
        for import_obj in pe_obj.pe.DIRECTORY_ENTRY_IMPORT:
            libraries_list.append(
                (
                    import_obj.dll.decode("utf-8").strip("\x00"),
                    len(import_obj.imports),
                )
            )

        self.libraries_group.view.setModel(
            table.TableModel(libraries_list, headers=["Name", "Imports"])
        )
