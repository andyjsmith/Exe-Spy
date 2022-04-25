import PySide6.QtWidgets as QtWidgets
import PySide6.QtCore as QtCore
import PySide6.QtGui as QtGui

import vt

from .. import helpers
from .. import pe_file
from .components import table


class VirusTotalView(QtWidgets.QScrollArea):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Set up scroll area
        self.setWidgetResizable(True)
        self.scroll_area = QtWidgets.QWidget(self)
        self.setWidget(self.scroll_area)
        self.scroll_area.setLayout(QtWidgets.QFormLayout())

        self.scan_btn = QtWidgets.QPushButton("Get Hash Results")
        self.scan_btn.clicked.connect(self.get_vt)
        self.scroll_area.layout().addWidget(self.scan_btn)

        self.result_label = QtWidgets.QLabel("No results")
        result_label_font = self.result_label.font()
        result_label_font.setPointSize(result_label_font.pointSize() + 4)
        self.result_label.setFont(result_label_font)
        self.scroll_area.layout().addWidget(self.result_label)
        self.result_label.setHidden(True)

        # Information
        self.info_group = table.TableGroup(
            "Information", fit_columns=True, headers=["Name", "Value"]
        )
        self.scroll_area.layout().addWidget(self.info_group)

        # Stats
        self.stats_group = table.TableGroup(
            "Scan Stats", fit_columns=True, headers=["Name", "Count"]
        )
        self.scroll_area.layout().addWidget(self.stats_group)

        # Results
        self.results_group = table.TableGroup(
            "Scan Results", fit_columns=True, headers=["Name", "Category", "Result"]
        )
        self.scroll_area.layout().addWidget(self.results_group)

        self.info_group.setFocus()

    def load(self, pe_obj: pe_file.PEFile):
        self.pe_obj = pe_obj

    def get_vt(self):

        apikey = QtCore.QSettings().value("virustotal/api_key", "")

        if apikey == "":
            helpers.show_message_box(
                "VirusTotal API key is not set. Set it in the options menu.",
                helpers.MessageBoxTypes.CRITICAL,
                "API Key Not Set",
            )
            return

        self.client = vt.Client(apikey)

        self.vt_results = None

        try:
            self.vt_results = self.client.get_object(f"/files/{self.pe_obj.sha256}")
            found = True
        except vt.error.APIError as err:
            found = False
            if err.code == "NotFoundError":
                self.vt_results = None
            else:
                helpers.show_message_box(
                    err.message, helpers.MessageBoxTypes.CRITICAL, err.code
                )
                return

        self.scan_btn.setHidden(True)

        if not found:
            response = QtWidgets.QMessageBox.question(
                self,
                "Upload to VirusTotal",
                "The file hash was not previously found on VirusTotal. Would you like to open VirusTotal so you can upload the file?",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
            )
            if response == QtWidgets.QMessageBox.Yes:
                QtGui.QDesktopServices.openUrl(
                    "https://www.virustotal.com/gui/home/upload"
                )

        if not self.vt_results:
            return

        # Information
        self.info_group.view.setModel(
            table.TableModel(
                [
                    (
                        "Creation Time",
                        helpers.format_time(self.vt_results.get("creation_date")),
                    ),
                    (
                        "First Seen In The Wild",
                        helpers.format_time(self.vt_results.get("first_seen_itw_date")),
                    ),
                    (
                        "First Submission",
                        helpers.format_time(
                            self.vt_results.get("first_submission_date")
                        ),
                    ),
                    (
                        "Last Submission",
                        helpers.format_time(
                            self.vt_results.get("last_submission_date")
                        ),
                    ),
                    (
                        "Last Analysis",
                        helpers.format_time(self.vt_results.get("last_analysis_date")),
                    ),
                    ("Reputation", str(self.vt_results.get("reputation"))),
                    ("Vhash", self.vt_results.get("vhash")),
                    ("Meaningful Name", self.vt_results.get("meaningful_name")),
                    ("Times Submitted", str(self.vt_results.get("times_submitted"))),
                    ("Unique Sources", str(self.vt_results.get("unique_sources"))),
                ],
                headers=["Name", "Value"],
            )
        )

        # Scan stats
        if self.vt_results.get("last_analysis_stats"):
            num_malicious = self.vt_results.get("last_analysis_stats")["malicious"]
            self.result_label.setText(f"{num_malicious} malicious results")
            if num_malicious > 0:
                self.result_label.setStyleSheet("color: red")
            else:
                self.result_label.setStyleSheet("color: green")
            self.result_label.setHidden(False)

            self.stats_group.view.setModel(
                table.TableModel(
                    [
                        (
                            "Malicious",
                            str(
                                self.vt_results.get("last_analysis_stats")["malicious"]
                            ),
                        ),
                        (
                            "Suspicious",
                            str(
                                self.vt_results.get("last_analysis_stats")["suspicious"]
                            ),
                        ),
                        (
                            "Undetected",
                            str(
                                self.vt_results.get("last_analysis_stats")["undetected"]
                            ),
                        ),
                        (
                            "Harmless",
                            str(self.vt_results.get("last_analysis_stats")["harmless"]),
                        ),
                        (
                            "Failure",
                            str(self.vt_results.get("last_analysis_stats")["failure"]),
                        ),
                        (
                            "Timeout",
                            str(self.vt_results.get("last_analysis_stats")["timeout"]),
                        ),
                    ],
                    headers=["Name", "Count"],
                )
            )

        # Scan results
        if self.vt_results.get("last_analysis_results"):
            scan_results = []
            for result in self.vt_results.get("last_analysis_results").values():
                scan_results.append(
                    (
                        result["engine_name"],
                        result["category"],
                        result["result"] if result["result"] else "",
                    )
                )

            self.results_group.view.setModel(
                table.TableModel(
                    scan_results,
                    headers=["Name", "Category", "Result"],
                )
            )
