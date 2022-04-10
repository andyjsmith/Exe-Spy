from dataclasses import dataclass

import PySide6.QtWidgets as QtWidgets
import magic

from .. import pe_file
from .components import table


class ResourcesView(QtWidgets.QScrollArea):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Set up scroll area
        self.setWidgetResizable(True)
        self.scroll_area = QtWidgets.QWidget(self)
        self.setWidget(self.scroll_area)
        self.scroll_area.setLayout(QtWidgets.QFormLayout())

        # Resources
        self.HEADERS = ["Type", "ID", "Language", "Sublanguage", "Magic"]
        self.resources_group = table.TableGroup(
            "Resources",
            fit_columns=True,
            headers=self.HEADERS,
        )
        self.scroll_area.layout().addWidget(self.resources_group)

    def load(self, pe_obj: pe_file.PEFile):
        # Resources
        resources_list = []

        for resource_obj in pe_obj.resources:
            resources_list.append(
                (
                    resource_obj.rtype,
                    resource_obj.id,
                    resource_obj.lang.replace("LANG_", ""),
                    resource_obj.sublang.replace("SUBLANG_", ""),
                    magic.from_buffer(resource_obj.data),
                )
            )

        self.resources_group.view.setModel(
            table.TableModel(resources_list, headers=self.HEADERS)
        )
