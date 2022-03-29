import enum
from typing import Dict
import PySide6.QtCore as QtCore
import PySide6.QtWidgets as QtWidgets
import PySide6.QtGui as QtGui

from . import pe_file
from .views import view

from .views import general, headers, strings, hashes


class TabBar(QtWidgets.QTabBar):
    """Custom tab bar for horizontal text in a west/east tab position"""
    # https://stackoverflow.com/questions/51230544/pyqt5-how-to-set-tabwidget-west-but-keep-the-text-horizontal

    def tabSizeHint(self, index):
        s = QtWidgets.QTabBar.tabSizeHint(self, index)
        s.transpose()
        return s

    def paintEvent(self, _):
        painter = QtWidgets.QStylePainter(self)
        opt = QtWidgets.QStyleOptionTab()

        for i in range(self.count()):
            self.initStyleOption(opt, i)
            painter.drawControl(QtWidgets.QStyle.CE_TabBarTabShape, opt)
            painter.save()

            s = opt.rect.size()
            s.transpose()
            r = QtCore.QRect(QtCore.QPoint(), s)
            r.moveCenter(opt.rect.center())
            opt.rect = r

            c = self.tabRect(i).center()
            painter.translate(c)
            painter.rotate(90)
            painter.translate(-c)
            painter.drawControl(QtWidgets.QStyle.CE_TabBarTabLabel, opt)
            painter.restore()


class Tabs(enum.Enum):
    GENERAL = enum.auto()
    HEADERS = enum.auto()
    SECTIONS = enum.auto()
    LIBRARIES = enum.auto()
    IMPORTS = enum.auto()
    EXPORTS = enum.auto()
    RESOURCES = enum.auto()
    STRINGS = enum.auto()
    HEXVIEW = enum.auto()
    HASHES = enum.auto()
    VIRUSTOTAL = enum.auto()


class TabView(QtWidgets.QTabWidget):
    """Tab view that acts as the main view controller"""

    def __init__(self, parent: QtWidgets.QMainWindow, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)

        self.setTabBar(TabBar(self))
        self.setTabPosition(self.TabPosition.West)

        self.tabs: Dict[Tabs, view.View] = {}

        self.tabs[Tabs.GENERAL] = general.GeneralView()
        self.addTab(self.tabs[Tabs.GENERAL], "General")
        self.tabBar().setTabTextColor(self.indexOf(
            self.tabs[Tabs.GENERAL]), QtGui.QColor(255, 0, 0))

        self.tabs[Tabs.HEADERS] = headers.HeadersView()
        self.addTab(self.tabs[Tabs.HEADERS], "Headers")

        self.tabs[Tabs.SECTIONS] = QtWidgets.QWidget()
        self.addTab(self.tabs[Tabs.SECTIONS], "Sections")
        self.tabBar().setTabTextColor(self.indexOf(
            self.tabs[Tabs.SECTIONS]), QtGui.QColor(150, 150, 150))
        self.tabBar().setTabEnabled(self.indexOf(
            self.tabs[Tabs.SECTIONS]), False)

        self.tabs[Tabs.LIBRARIES] = QtWidgets.QWidget()
        self.addTab(self.tabs[Tabs.LIBRARIES], "Libraries")

        self.tabs[Tabs.IMPORTS] = QtWidgets.QWidget()
        self.addTab(self.tabs[Tabs.IMPORTS], "Imports")

        self.tabs[Tabs.EXPORTS] = QtWidgets.QWidget()
        self.addTab(self.tabs[Tabs.EXPORTS], "Exports")

        self.tabs[Tabs.RESOURCES] = QtWidgets.QWidget()
        self.addTab(self.tabs[Tabs.RESOURCES], "Resources")

        self.tabs[Tabs.STRINGS] = strings.StringsView()
        self.addTab(self.tabs[Tabs.STRINGS], "Strings")

        self.tabs[Tabs.HEXVIEW] = QtWidgets.QWidget()
        self.addTab(self.tabs[Tabs.HEXVIEW], "Hex View")

        self.tabs[Tabs.HASHES] = hashes.HashesView()
        self.addTab(self.tabs[Tabs.HASHES], "Hashes")

        self.tabs[Tabs.VIRUSTOTAL] = QtWidgets.QWidget()
        self.addTab(self.tabs[Tabs.VIRUSTOTAL], "VirusTotal")

    def load(self, pe: pe_file.PEFile):
        # Loop through all tabs and call their update function
        for tab in self.tabs.values():
            if hasattr(tab, "load"):
                tab.load(pe)
