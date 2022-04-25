import PySide6.QtWidgets as QtWidgets
import PySide6.QtGui as QtGui
import PySide6.QtCore as QtCore

import yara

from .. import pe_file
from .components import table


class PackersView(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.pe_obj = None

        self.setLayout(QtWidgets.QVBoxLayout())

        # Packers
        self.HEADERS = [
            "Match",
            "Source",
        ]
        self.packers_table = table.TableView(
            fit_to_contents=False,
            fit_columns=True,
            headers=self.HEADERS,
        )

        self.layout().addWidget(self.packers_table)

    def load(self, pe_obj: pe_file.PEFile):
        # Packers
        matches_list = []

        # rules = yara.compile(
        #     filepaths={
        #         "Yara's Packers List": "yara/packer.yara",
        #         "PEID Rules": "yara/peid.yara",
        #         "GoDaddy's Packer List": "yara/godaddy.yara",
        #     }
        # )
        #
        # rules.save("exespy/yara/compiled.yara.bin")

        rules = yara.load("exespy/yara/compiled.yara.bin")

        matches = rules.match(pe_obj.path)

        for match in matches:
            if "description" in match.meta:
                name = match.meta["description"]
            else:
                name = match.rule

            matches_list.append((name, match.namespace))

        self.packers_table.setModel(
            table.TableModel(matches_list, headers=self.HEADERS)
        )

        self.packers_table.fit_contents()
