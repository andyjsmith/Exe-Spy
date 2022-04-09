import math
import PySide6.QtWidgets as QtWidgets
import PySide6.QtCore as QtCore
import PySide6.QtGui as QtGui

from .. import pe_file

from .components import textedit


class HexView(QtWidgets.QWidget):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.setLayout(QtWidgets.QGridLayout())

        self.address_panel = textedit.MonoTextEdit()
        self.hex_panel = textedit.MonoTextEdit()
        self.text_panel = textedit.MonoTextEdit()
        self.layout().addWidget(self.address_panel, 1, 0, 1, 1)
        self.layout().addWidget(self.hex_panel, 1, 1, 1, 1)
        self.layout().addWidget(self.text_panel, 1, 2, 1, 1)

        address_label = QtWidgets.QLabel("Offset")
        address_label.setFont(self.address_panel.font())
        self.layout().addWidget(address_label, 0, 0, 1, 1)

        hex_label = QtWidgets.QLabel(
            "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F")
        hex_label.setFont(self.hex_panel.font())
        hex_label.setAlignment(QtCore.Qt.AlignCenter)
        self.layout().addWidget(hex_label, 0, 1, 1, 1)

        text_label = QtWidgets.QLabel("Decoded Text")
        text_label.setFont(self.text_panel.font())
        self.layout().addWidget(text_label, 0, 2, 1, 1)

        self.hex_panel.selectionChanged.connect(self.hex_selection_changed)
        self.text_panel.selectionChanged.connect(self.text_selection_changed)

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

        # Make the panels inactive highlight color match the active color
        palette_match_active_highlight = self.hex_panel.palette()
        palette_match_active_highlight.setColor(QtGui.QPalette.Inactive, QtGui.QPalette.Highlight, palette_match_active_highlight.color(
            QtGui.QPalette.Active, QtGui.QPalette.Highlight))
        palette_match_active_highlight.setColor(QtGui.QPalette.Inactive, QtGui.QPalette.HighlightedText, palette_match_active_highlight.color(
            QtGui.QPalette.Active, QtGui.QPalette.HighlightedText))
        self.hex_panel.setPalette(palette_match_active_highlight)
        self.text_panel.setPalette(palette_match_active_highlight)

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

    def hex_selection_changed(self):
        """Select only by whole bytes in the hex panel"""
        old_state = self.hex_panel.blockSignals(True)

        text = self.hex_panel.toPlainText()

        cursor = self.hex_panel.textCursor()

        # Get selection start and end
        start = cursor.selectionStart()
        end = cursor.selectionEnd()

        # Check if the selection is going forwards or backwards
        selecting_forward = cursor.anchor() == start

        # Format selection around whole bytes, rather than individual chars
        # Adjust the selection start
        try:
            if text[start] == " ":
                start += 1
            elif text[start+1] == " ":
                start -= 1
            # Adjust the selection end
            if text[end-1] == " ":
                end -= 1
            elif end == 1 or text[end-2] == " ":
                end += 1
        except IndexError:
            # Ignore any IndexErrors from selecting at the start/end
            pass

        # Set the modified selection
        if selecting_forward:
            # Selection is in the forward direction
            cursor.setPosition(start)
            cursor.setPosition(end, QtGui.QTextCursor.KeepAnchor)
        else:
            # Selection is in the backward direction
            cursor.setPosition(end)
            cursor.setPosition(start, QtGui.QTextCursor.KeepAnchor)

        self.hex_panel.setTextCursor(cursor)

        self.hex_panel.blockSignals(old_state)

        # Now, set the text selection to match the hex selection
        # ------------------------------------------------------
        old_state = self.text_panel.blockSignals(True)

        hex_cursor = self.hex_panel.textCursor()
        text_cursor = self.text_panel.textCursor()

        # Calculate corresponding positions using blocks
        hex_starting_position_in_block = hex_cursor.selectionStart() - self.hex_panel.document().findBlock(
            hex_cursor.selectionStart()).position()
        hex_starting_block = self.hex_panel.document().findBlock(
            hex_cursor.selectionStart()).blockNumber()

        hex_ending_position_in_block = hex_cursor.selectionEnd() - self.hex_panel.document().findBlock(
            hex_cursor.selectionEnd()).position()
        hex_ending_block = self.hex_panel.document().findBlock(
            hex_cursor.selectionEnd()).blockNumber()

        text_starting_block_pos = self.text_panel.document(
        ).findBlockByNumber(hex_starting_block).position()
        text_cursor.setPosition(
            text_starting_block_pos + math.floor(hex_starting_position_in_block/3))

        text_ending_block_pos = self.text_panel.document(
        ).findBlockByNumber(hex_ending_block).position()
        text_cursor.setPosition(text_ending_block_pos + math.ceil(hex_ending_position_in_block/3),
                                QtGui.QTextCursor.KeepAnchor)

        self.text_panel.setTextCursor(text_cursor)

        self.text_panel.blockSignals(old_state)

    def text_selection_changed(self):
        """Match selection from text panel to hex panel"""
        old_state = self.hex_panel.blockSignals(True)

        hex_cursor = self.hex_panel.textCursor()
        text_cursor = self.text_panel.textCursor()

        # Calculate corresponding positions using blocks
        text_starting_position_in_block = text_cursor.selectionStart() - self.text_panel.document().findBlock(
            text_cursor.selectionStart()).position()
        text_starting_block = self.text_panel.document().findBlock(
            text_cursor.selectionStart()).blockNumber()

        text_ending_position_in_block = text_cursor.selectionEnd() - self.text_panel.document().findBlock(
            text_cursor.selectionEnd()).position()
        text_ending_block = self.text_panel.document().findBlock(
            text_cursor.selectionEnd()).blockNumber()

        hex_starting_block_pos = self.hex_panel.document(
        ).findBlockByNumber(text_starting_block).position()
        hex_cursor.setPosition(
            hex_starting_block_pos + 3*text_starting_position_in_block)

        hex_ending_block_pos = self.hex_panel.document(
        ).findBlockByNumber(text_ending_block).position()
        hex_cursor.setPosition(hex_ending_block_pos + 3*text_ending_position_in_block - 1,
                               QtGui.QTextCursor.KeepAnchor)

        self.hex_panel.setTextCursor(hex_cursor)

        self.hex_panel.blockSignals(old_state)
