import math
import io
from collections import Counter

import PySide6.QtWidgets as QtWidgets
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg
from matplotlib.figure import Figure

from exespy import helpers

from .. import pe_file
from .. import state


class EntropyView(QtWidgets.QWidget):
    NAME = "Entropy"
    LOAD_ASYNC = True
    SHOW_PROGRESS = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.loaded = False

        self.pe_obj: pe_file.PEFile = None
        self.heatmap_canvas = None
        self.line_plot_canvas = None

        self.setLayout(QtWidgets.QVBoxLayout())

        # Controls
        self.controls_widget = QtWidgets.QWidget()
        self.controls_widget.setLayout(QtWidgets.QHBoxLayout())
        self.controls_widget.layout().setContentsMargins(0, 0, 0, 0)
        self.controls_widget.setSizePolicy(
            QtWidgets.QSizePolicy.MinimumExpanding, QtWidgets.QSizePolicy.Maximum
        )

        self.block_size_label = QtWidgets.QLabel("Block Size:")
        self.controls_widget.layout().addWidget(self.block_size_label)

        self.block_size_box = QtWidgets.QComboBox()
        self.block_size_box.addItems(
            ["8", "16", "32", "64", "128", "256", "512", "1024", "2048", "4096"]
        )

        self.block_size = 128
        self.block_size_box.setCurrentText(str(self.block_size))

        self.block_size_box.currentTextChanged.connect(self.handle_block_size_changed)
        self.controls_widget.layout().addWidget(self.block_size_box)

        self.controls_widget.layout().addStretch()

        # Entropy info button
        info_button = QtWidgets.QPushButton()
        info_button.setIcon(
            self.style().standardIcon(QtWidgets.QStyle.SP_MessageBoxInformation)
        )
        info_button.clicked.connect(self.handle_info_clicked)
        self.controls_widget.layout().addWidget(info_button)

        self.layout().addWidget(self.controls_widget)

        # Tabs
        tabs = QtWidgets.QTabWidget()

        self.line_plot_tab = QtWidgets.QWidget()
        self.line_plot_tab.setLayout(QtWidgets.QVBoxLayout())
        self.heatmap_tab = QtWidgets.QWidget()
        self.heatmap_tab.setLayout(QtWidgets.QVBoxLayout())

        tabs.addTab(self.line_plot_tab, "Line Plot")
        tabs.addTab(self.heatmap_tab, "Heatmap")

        self.layout().addWidget(tabs)

    def load_async(self, pe_obj: pe_file.PEFile):
        self.pe_obj = pe_obj

        if pe_obj is None:
            return

        self.entropy = []
        self.addresses = []

        # Remove the old canvases if we're reloading
        if self.heatmap_canvas is not None:
            self.heatmap_tab.layout().removeWidget(self.heatmap_canvas)
        if self.line_plot_canvas is not None:
            self.line_plot_tab.layout().removeWidget(self.line_plot_canvas)

        # Calculate entropy from file
        with io.BytesIO(pe_obj.data) as f:
            data = f.read(self.block_size)
            while data:
                self.entropy.append(self.calc_entropy(data))
                self.addresses.append(f.tell())
                data = f.read(self.block_size)

        # Calculate 2D matrix from entropy for heatmap
        size = math.floor(math.sqrt(len(self.entropy)))
        cur = 0
        self.items = [[] for _ in range(size)]
        for i in range(size):
            for j in range(size):
                if cur >= len(self.entropy):
                    break

                self.items[i].append(self.entropy[cur])
                cur += 1
            if cur >= len(self.entropy):
                break

    def load_finalize(self):
        # Line plot
        line_plot_figure = Figure()
        self.line_plot_canvas = FigureCanvasQTAgg(line_plot_figure)
        self.line_plot_canvas.axes = line_plot_figure.add_subplot(111)
        self.line_plot_canvas.axes.set_title("Entropy")
        self.line_plot_canvas.axes.set_xlabel("Address")
        self.line_plot_canvas.axes.set_ylabel("Shannon Entropy")
        self.line_plot_canvas.axes.set_ylim((0, 8))
        self.line_plot_canvas.axes.set_xlim((0, self.addresses[-1]))
        self.line_plot_canvas.axes.plot(self.addresses, self.entropy, "#223EAA")
        line_plot_figure.tight_layout()
        self.line_plot_canvas.axes.autoscale_view()
        self.line_plot_tab.layout().addWidget(self.line_plot_canvas)

        # Heatmap plot
        # https://stackoverflow.com/questions/33282368/plotting-a-2d-heatmap-with-matplotlib
        heatmap_figure = Figure()
        self.heatmap_canvas = FigureCanvasQTAgg(heatmap_figure)
        self.heatmap_canvas.axes = heatmap_figure.add_subplot(111)
        self.heatmap_canvas.axes.set_title("Entropy")
        self.heatmap_canvas.axes.get_xaxis().set_ticks([])
        self.heatmap_canvas.axes.get_yaxis().set_ticks([0])
        heatmap_subplot = self.heatmap_canvas.axes.imshow(
            self.items, cmap="hot", interpolation="nearest", vmin=0, vmax=8
        )
        heatmap_figure.colorbar(heatmap_subplot)
        heatmap_figure.tight_layout()
        self.heatmap_canvas.axes.autoscale_view()
        self.heatmap_tab.layout().addWidget(self.heatmap_canvas)

    def enable_tab(self):
        state.tabview.set_loading(self.NAME, False)

    def load(self, pe_obj: pe_file.PEFile):
        progress = helpers.progress_dialog("Loading Entropy...", "Loading", self)
        self.load_async(pe_obj)
        self.load_finalize()
        progress.close()

    def calc_entropy(self, data, unit="shannon"):
        """
        Calculate entropy for a given iterable.
        https://stackoverflow.com/questions/15450192/fastest-way-to-compute-entropy-in-python/37890790#37890790
        """
        base = {"shannon": 2.0, "natural": math.exp(1), "hartley": 10.0}

        if len(data) <= 1:
            return 0

        counts = Counter()

        for d in data:
            counts[d] += 1

        ent = 0

        probs = [float(c) / len(data) for c in counts.values()]
        for p in probs:
            if p > 0.0:
                ent -= p * math.log(p, base[unit])

        return ent

    def handle_block_size_changed(self):
        """Reload the entropy data with the new block size."""
        self.block_size = int(self.block_size_box.currentText())
        self.load(self.pe_obj)

    def handle_info_clicked(self):
        """Show the entropy info dialog."""
        text = """Entropy is a measure of the randomness in the loaded PE file.

Shannon entropy is scaled between 0 and 8 bits per byte.
- 0 means the data is uniform
- 8 means the data is completely random

Entropy can indicate what kind of data is in the file.
- Higher entropy values may indicate encrypted or compressed data sections
- Plaintext generally has 3.5 to 5 bits of entropy per byte

The block size indicates how many bytes to read at a time and calculate entropy for. Each block's entropy is calculated and then plotted in the charts.
"""
        helpers.show_message_box(text, title="Information About Entropy")
