import PySide6.QtWidgets as QtWidgets
import PySide6.QtCore as QtCore
import PySide6.QtGui as QtGui

from .. import pe_file

from .components import textedit


class HexView(QtWidgets.QWidget):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.setLayout(QtWidgets.QHBoxLayout())

        self.address_panel = textedit.MonoTextEdit()
        self.hex_panel = textedit.MonoTextEdit()
        self.text_panel = textedit.MonoTextEdit()
        self.layout().addWidget(self.address_panel)
        self.layout().addWidget(self.hex_panel)
        self.layout().addWidget(self.text_panel)

        test_contents = "\n".join(str(i) for i in range(0, 1000))
        self.address_panel.setPlainText(test_contents)
        self.hex_panel.setPlainText(test_contents)
        self.text_panel.setPlainText(test_contents)

        # Cross-connect all the valueChanged signals to the setValue slots so
        # that the panels scroll together
        self.address_panel.verticalScrollBar().valueChanged.connect(
            self.hex_panel.verticalScrollBar().setValue)
        self.address_panel.verticalScrollBar().valueChanged.connect(
            self.text_panel.verticalScrollBar().setValue)
        self.hex_panel.verticalScrollBar().valueChanged.connect(
            self.address_panel.verticalScrollBar().setValue)
        self.hex_panel.verticalScrollBar().valueChanged.connect(
            self.text_panel.verticalScrollBar().setValue)
        self.text_panel.verticalScrollBar().valueChanged.connect(
            self.address_panel.verticalScrollBar().setValue)
        self.text_panel.verticalScrollBar().valueChanged.connect(
            self.hex_panel.verticalScrollBar().setValue)

        # Hide the address and hex panel scrollbars, only show the text panel
        self.address_panel.setVerticalScrollBarPolicy(
            QtCore.Qt.ScrollBarAlwaysOff)
        self.hex_panel.setVerticalScrollBarPolicy(
            QtCore.Qt.ScrollBarAlwaysOff)

        # Set the size of the panels to the smallest possible
        self.address_panel.setSizePolicy(
            QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Expanding)
        self.hex_panel.setSizePolicy(
            QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Expanding)
        self.text_panel.setSizePolicy(
            QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)

    def load(self, pe_obj: pe_file.PEFile):
        self.pe_obj = pe_obj

        if pe_obj is None:
            return

        BYTES_PER_LINE = 16

        # Set the length of the address in the address panel
        # Minumum length is 4 bytes, but will increase for larger files
        NUM_ADDRESS_CHARS = max(8, len("{:X}".format(pe_obj.stat.st_size)))

        address_values = []
        hex_values = []
        text_values = []

        with open(pe_obj.path, "rb") as f:
            data = f.read(BYTES_PER_LINE)
            while data:
                address_values.append(
                    "{0:0{1}X}".format(f.tell()-BYTES_PER_LINE, NUM_ADDRESS_CHARS))
                hex_values.append(" ".join(["{:02x}".format(x) for x in data]))
                text_values.append(self.bytes_to_str(data))

                data = f.read(BYTES_PER_LINE)

        self.address_panel.setPlainText("\n".join(address_values))
        self.hex_panel.setPlainText("\n".join(hex_values))
        self.text_panel.setPlainText("\n".join(text_values))

        # Set width of address and hex panels to match their text
        font = self.address_panel.font()
        fontMetrics = QtGui.QFontMetrics(font)
        textSize = fontMetrics.size(0, self.address_panel.toPlainText())
        w = textSize.width() + 10
        self.address_panel.setMinimumWidth(w)
        self.address_panel.setMaximumWidth(w)
        font = self.hex_panel.font()
        fontMetrics = QtGui.QFontMetrics(font)
        textSize = fontMetrics.size(0, self.hex_panel.toPlainText())
        w = textSize.width() + 10
        self.hex_panel.setMinimumWidth(w)
        self.hex_panel.setMaximumWidth(w)

    def bytes_to_str(self, data: bytes) -> str:
        """Convert a byte array to a string with printable characters"""

        ascii_string = ""
        for c in data:
            if 33 <= c <= 126:
                ascii_string += chr(c)
            else:
                ascii_string += "."

        return ascii_string
