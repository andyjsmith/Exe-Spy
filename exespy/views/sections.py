import PySide6.QtWidgets as QtWidgets

from .. import pe_file
from .components import table


class SectionsView(QtWidgets.QScrollArea):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Set up scroll area
        self.setWidgetResizable(True)
        self.scroll_area = QtWidgets.QWidget(self)
        self.setWidget(self.scroll_area)
        self.scroll_area.setLayout(QtWidgets.QFormLayout())

        # Sections
        self.sections_group = table.TableGroup(
            "Sections",
            fit_columns=True,
            headers=[
                "Name",
                "VirtualSize",
                "VirtualAddress",
                "SizeOfRawData",
                "PointerToRawData",
                "Characteristics",
            ],
        )
        self.scroll_area.layout().addWidget(self.sections_group)

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

        self.sections_group.view.setModel(
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
