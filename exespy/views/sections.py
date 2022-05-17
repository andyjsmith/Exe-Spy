import PySide6.QtWidgets as QtWidgets

from .. import pe_file
from .components import table


class SectionsView(QtWidgets.QWidget):
    NAME = "Sections"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.setLayout(QtWidgets.QVBoxLayout())

        self.headers = [
            "Name",
            "VirtualSize",
            "VirtualAddress",
            "SizeOfRawData",
            "PointerToRawData",
            "PointerToRelocations",
            "PointerToLinenumbers",
            "NumberOfRelocations",
            "NumberOfLinenumbers",
            "Characteristics",
        ]

        # Sections
        self.sections_table = table.TableView(
            fit_columns=True,
            fit_to_contents=False,
            expand_last_column=True,
            headers=self.headers,
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
                    hex(section.PointerToRelocations),
                    hex(section.PointerToLinenumbers),
                    section.NumberOfRelocations,
                    section.NumberOfLinenumbers,
                    f"{hex(section.Characteristics)} ({pe_obj.section_characteristics_str(i)})",
                )
            )

        self.sections_table.setModel(
            table.TableModel(
                sections_list,
                headers=self.headers,
            )
        )

        self.sections_table.resizeColumnsToContents()
