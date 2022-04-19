import PySide6.QtWidgets as QtWidgets
import PySide6.QtGui as QtGui
import PySide6.QtCore as QtCore
import magic

from .. import pe_file
from .components import table


class ResourcesView(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.pe_obj = None

        self.setLayout(QtWidgets.QVBoxLayout())

        # Resources
        self.HEADERS = [
            "Type",
            "ID",
            "Size",
            "Offset",
            "Language",
            "Sublanguage",
            "Magic",
        ]
        self.resources_group = table.TableView(
            fit_to_contents=False,
            headers=self.HEADERS,
        )

        self.resources_group.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.resources_group.customContextMenuRequested.connect(self.show_context_menu)

        self.layout().addWidget(self.resources_group)

    def load(self, pe_obj: pe_file.PEFile):
        # Resources
        resources_list = []

        self.pe_obj = pe_obj

        for resource_obj in pe_obj.resources:
            resources_list.append(
                (
                    resource_obj.rtype,
                    resource_obj.id,
                    resource_obj.size,
                    resource_obj.offset,
                    resource_obj.lang.replace("LANG_", ""),
                    resource_obj.sublang.replace("SUBLANG_", ""),
                    magic.from_buffer(resource_obj.data),
                )
            )

        self.resources_group.setModel(
            table.TableModel(resources_list, headers=self.HEADERS)
        )

    def show_context_menu(self, pos):
        """Show the context menu with a save button"""
        menu = QtWidgets.QMenu(self)
        save_action = QtGui.QAction("Save", self)
        row = self.resources_group.rowAt(pos.y())
        save_action.triggered.connect(lambda: self.save_selected_resource(row))
        menu.addAction(save_action)
        menu.popup(self.resources_group.viewport().mapToGlobal(pos))

    def save_selected_resource(self, index):
        """Save the resource at an index to a file"""
        filename, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save Resource")
        if filename:
            with open(filename, "wb") as f:
                f.write(self.pe_obj.resources[index].data)
