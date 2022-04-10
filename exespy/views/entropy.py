import math
from collections import Counter

import PySide6.QtWidgets as QtWidgets
from matplotlib import pyplot as plt
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg
from matplotlib.figure import Figure

from .. import pe_file


class EntropyView(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.pe_obj: pe_file.PEFile = None

        self.setLayout(QtWidgets.QVBoxLayout())

    def load(self, pe_obj: pe_file.PEFile):
        self.pe_obj = pe_obj

        if pe_obj is None:
            return

        BLOCK_SIZE = 64

        entropy = []
        addresses = []

        with open(r"C:\Users\Andy\Downloads\notepad.exe", "rb") as f:
            data = f.read(BLOCK_SIZE)
            while data:
                entropy.append(self.calc_entropy(data))
                addresses.append(f.tell())
                data = f.read(BLOCK_SIZE)

        # figure = Figure()
        # canvas = FigureCanvasQTAgg(figure)
        # canvas.axes = figure.add_subplot()
        # canvas.axes.set_title("Entropy")
        # canvas.axes.set_xlabel("Address")
        # canvas.axes.set_ylabel("Shannon Entropy")
        # canvas.axes.set_ylim((0, 8))
        # canvas.axes.set_xlim((0, addresses[-1]))
        # canvas.axes.autoscale_view()
        # figure.subplots_adjust(left=0.05, right=0.95, top=0.95, bottom=0.05)
        # canvas.axes.plot(addresses, entropy)

        size = math.floor(math.sqrt(len(entropy)))
        cur = 0
        items = [[] for _ in range(size)]
        for i in range(size):
            for j in range(size):
                if cur >= len(entropy):
                    break
                # figure.axes[i][j].plot(addresses, entropy[cur:cur + size])
                items[i].append(entropy[cur])
                cur += 1
            if cur >= len(entropy):
                break

        figure = Figure()
        plt.imshow(items, cmap="hot", interpolation="nearest")
        # plt.show()
        canvas = FigureCanvasQTAgg(figure)
        canvas.axes = figure.add_subplot()
        canvas.axes.set_title("Entropy")
        canvas.axes.set_xlabel("Address")
        canvas.axes.set_ylabel("Shannon Entropy")
        canvas.axes.set_ylim((0, 8))
        canvas.axes.set_xlim((0, addresses[-1]))
        canvas.axes.autoscale_view()
        figure.subplots_adjust(left=0.05, right=0.95, top=0.95, bottom=0.05)
        canvas.axes.plot(addresses, entropy)

        self.layout().addWidget(canvas)

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
