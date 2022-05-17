import time
import logging
from typing import Dict

import PySide6.QtCore as QtCore
import PySide6.QtWidgets as QtWidgets
import PySide6.QtGui as QtGui

from . import helpers
from . import pe_file
from .views import (
    view,
    general,
    headers,
    strings,
    hashes,
    sections,
    libraries,
    imports,
    exports,
    resources,
    hexview,
    virustotal,
    disassembly,
    entropy,
    manifest,
    packers,
)


class LoadWorker(QtCore.QObject):
    finished = QtCore.Signal()

    def __init__(self, tab: QtWidgets.QWidget, pe: pe_file.PEFile):
        super().__init__()
        self.tab = tab
        self.pe = pe

    def run(self):
        load_start = time.time()
        self.tab.load_async(self.pe)
        load_end = time.time()
        logging.getLogger("exespy").debug(
            f"{self.tab.NAME} (ASYNC) took {load_end - load_start:.4f} seconds"
        )
        self.finished.emit()


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


class TabView(QtWidgets.QTabWidget):
    """Tab view that acts as the main view controller"""

    def __init__(self, parent: QtWidgets.QMainWindow, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)

        self.setTabBar(TabBar(self))
        self.setTabPosition(self.TabPosition.West)

        self.tabs: Dict[str, view.View] = {}

        self.currentChanged.connect(self.on_tab_change)

        self.add_tab(general.GeneralView())
        self.add_tab(headers.HeadersView())
        self.add_tab(sections.SectionsView())
        self.add_tab(libraries.LibrariesView())
        self.add_tab(imports.ImportsView())
        self.add_tab(exports.ExportsView())
        self.add_tab(resources.ResourcesView())
        self.add_tab(manifest.ManifestView())
        self.add_tab(strings.StringsView())
        self.add_tab(hexview.HexView())
        self.add_tab(hashes.HashesView())
        self.add_tab(disassembly.DisassemblyView())
        self.add_tab(packers.PackersView())
        self.add_tab(entropy.EntropyView())
        self.add_tab(virustotal.VirusTotalView())

        self.ORIGINAL_TAB_TEXT_COLOR = self.tabBar().tabTextColor(0)

        # Disable all tabs except general
        for tab_name, tab in self.tabs.items():
            if tab_name != general.GeneralView.NAME:
                self.set_disabled(tab_name, True)

    def load(self, pe: pe_file.PEFile):
        """Loop through all tabs and call their update function"""
        self.window().progress_bar.setMaximum(len(self.tabs))

        # Set loading state of tabs
        for tab_name, tab in self.tabs.items():
            if hasattr(tab, "LOAD_ASYNC") and tab.LOAD_ASYNC:
                self.set_loading(tab_name, True)

        # Load tabs (sync and async)
        total_load_start = time.time()
        i = 0
        for tab_name, tab in self.tabs.items():
            load_start = time.time()
            if hasattr(tab, "load"):
                if hasattr(tab, "LOAD_ASYNC") and tab.LOAD_ASYNC:
                    # Asynchronous load
                    tab.load_thread = QtCore.QThread()
                    tab.load_worker = LoadWorker(tab, pe)
                    tab.load_worker.moveToThread(tab.load_thread)
                    tab.load_thread.started.connect(tab.load_worker.run)
                    tab.load_worker.finished.connect(tab.load_thread.quit)
                    tab.load_worker.finished.connect(tab.load_worker.deleteLater)
                    tab.load_thread.finished.connect(tab.load_thread.deleteLater)
                    self.set_loading(tab_name, True)
                    tab.load_thread.start()
                    tab.load_thread.finished.connect(tab.enable_tab)
                else:
                    # Synchronous load
                    tab.load(pe)
                    self.set_disabled(tab_name, False)

            logging.getLogger("exespy").debug(
                f"{tab_name} took {time.time() - load_start:.4f} seconds"
            )

            i += 1
            self.window().progress_bar.setValue(i)
            self.window().statusBar().repaint()
            QtCore.QCoreApplication.processEvents()

        logging.getLogger("exespy").debug(
            f"Total synchronous load took {time.time() - total_load_start:.4f} seconds"
        )

        self.window().progress_bar.hide()
        self.window().statusBar().clearMessage()

    def add_tab(self, view: QtWidgets.QWidget):
        """Add a tab to the view"""
        self.tabs[view.NAME] = view
        self.addTab(self.tabs[view.NAME], view.NAME)

    def set_loading(self, tab: str, loading: bool):
        """Set the loading state of a tab"""
        if loading:
            self.set_disabled(tab, True)
            self.tabBar().setTabText(self.indexOf(self.tabs[tab]), f"{tab}...")
        else:
            self.set_disabled(tab, False)
            self.tabBar().setTabText(self.indexOf(self.tabs[tab]), tab)

    def set_disabled(self, tab: str, disabled: bool):
        """Set the disabled state of a tab"""
        if disabled:
            self.tabBar().setTabTextColor(
                self.indexOf(self.tabs[tab]), QtGui.QColor(150, 150, 150)
            )
            self.tabBar().setTabEnabled(self.indexOf(self.tabs[tab]), False)
        else:
            self.tabBar().setTabTextColor(
                self.indexOf(self.tabs[tab]), self.ORIGINAL_TAB_TEXT_COLOR
            )
            self.tabBar().setTabEnabled(self.indexOf(self.tabs[tab]), True)

    def on_tab_change(self, index: int):
        """Called when a tab is changed"""
        tab = self.tabs[self.tabText(index)]
        if hasattr(tab, "load_finalize") and tab.loaded == False:
            if tab.SHOW_PROGRESS:
                progress = helpers.progress_dialog(
                    f"Loading {tab.NAME}...", "Loading", self
                )

            tab.load_finalize()

            if tab.SHOW_PROGRESS:
                progress.close()
                tab.loaded = True
