import os
import sys
import datetime
from dateutil import tz

import PySide6.QtWidgets as QtWidgets
import PySide6.QtCore as QtCore


APP_NAME = "Exe Spy"
APP_NAME_SHORT = "exespy"
VERSION = (1, 0, 0)
ORGANIZATION_NAME = "Andy Smith"
ORGANIZATION_DOMAIN = "ajsmith.us"
ABOUT_TEXT = f"""\
{APP_NAME}
{".".join(str(i) for i in VERSION)}
Copyright (C) 2022 Andy Smith

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""


def resource_path(relative_path: str) -> str:
    """Get absolute path to resource, works for dev and for PyInstaller"""
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.dirname(os.path.realpath(__file__))

    return os.path.join(base_path, relative_path)


class MessageBoxTypes:
    INFORMATION = (QtWidgets.QMessageBox.Information, "Information")
    WARNING = (QtWidgets.QMessageBox.Warning, "Warning")
    CRITICAL = (QtWidgets.QMessageBox.Critical, "Error")
    QUESTION = (QtWidgets.QMessageBox.Question, "Question")


def show_message_box(
    text: str,
    alert_type: MessageBoxTypes = MessageBoxTypes.INFORMATION,
    title: str = None,
) -> int:
    """Show a message box with the given text and alert type"""
    msgbox = QtWidgets.QMessageBox()
    if title is None:
        msgbox.setWindowTitle(alert_type[1])
    else:
        msgbox.setWindowTitle(title)
    msgbox.setText(text)
    msgbox.setIcon(alert_type[0])
    return msgbox.exec()


def progress_dialog(
    text: str, title: str = None, parent: QtWidgets.QWidget = None
) -> QtWidgets.QProgressDialog:
    progress = QtWidgets.QProgressDialog(text, title, 0, 0, parent)
    progress.setCancelButton(None)
    progress.show()
    QtCore.QCoreApplication.processEvents()
    return progress


def format_time(time: "int|float|datetime.datetime") -> str:
    if time is None:
        return ""

    # Convert int/float to datetime
    if not isinstance(time, datetime.datetime):
        time = datetime.datetime.utcfromtimestamp(time)

    # TODO: Add option to change time format to local time
    # Format in local time
    # time_tz = time_unaware.replace(tzinfo=tz.tzutc()).astimezone(tz.tzlocal())

    # Format in UTC
    time_tz = time.replace(tzinfo=tz.tzutc())
    return time_tz.strftime("%Y-%m-%d %H:%M:%S %Z")
