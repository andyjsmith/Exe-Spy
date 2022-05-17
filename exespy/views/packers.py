import PySide6.QtWidgets as QtWidgets

import yara

from .. import pe_file
from .. import state
from .. import helpers
from .components import table


class PackersView(QtWidgets.QWidget):
    NAME = "Packers"
    LOAD_ASYNC = True
    SHOW_PROGRESS = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.loaded = False

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

    def load_async(self, pe_obj: pe_file.PEFile):
        # Packers
        self.matches_list = []

        rules = yara.compile(
            filepaths={
                "Yara's Packers List": helpers.resource_path("yara/packer.yara"),
                "PEID Rules": helpers.resource_path("yara/peid.yara"),
                "GoDaddy's Packer List": helpers.resource_path("yara/godaddy.yara"),
            }
        )

        # rules.save("exespy/yara/compiled.yara.bin")
        # rules = yara.load(helpers.resource_path("yara/compiled.yara.bin"))

        matches = rules.match(data=pe_obj.data)

        for match in matches:
            if "description" in match.meta:
                name = match.meta["description"]
            else:
                name = match.rule

            self.matches_list.append((name, match.namespace))

    def load_finalize(self):
        self.packers_table.setModel(
            table.TableModel(self.matches_list, headers=self.HEADERS)
        )

        self.packers_table.fit_contents()

    def enable_tab(self):
        state.tabview.set_loading(self.NAME, False)

    def load(self, pe_obj: pe_file.PEFile):
        self.load_async(pe_obj)
        self.load_finalize()
