import PySide6.QtWidgets as QtWidgets

from .. import pe_file
from .components import table


class SectionsView(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.setLayout(QtWidgets.QVBoxLayout())

        # Sections
        self.sections_table = table.TableView(
            fit_columns=True,
            fit_to_contents=False,
            headers=[
                "Name",
                "VirtualSize",
                "VirtualAddress",
                "SizeOfRawData",
                "PointerToRawData",
                "Characteristics",
            ],
        )

        self.layout().addWidget(self.sections_table)

    def load(self, pe_obj: pe_file.PEFile):

        # Sections
        sections_list = []
        for i, section in enumerate(pe_obj.pe.sections):
            sections_list.append(
                (
                    section.Name.decode("utf-8").strip("\x00"),
                    section.Misc_VirtualSize,
                    hex(section.VirtualAddress),
                    section.SizeOfRawData,
                    hex(section.PointerToRawData),
                    f"{hex(section.Characteristics)} ({pe_obj.section_characteristics_str(i)})",
                )
            )

        self.sections_table.setModel(
            table.TableModel(
                sections_list,
                headers=[
                    "Name",
                    "VirtualSize",
                    "VirtualAddress",
                    "SizeOfRawData",
                    "PointerToRawData",
                    "Characteristics",
                ],
            )
        )

        self.sections_table.resizeColumnsToContents()
