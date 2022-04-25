import PySide6.QtWidgets as QtWidgets
import PySide6.QtGui as QtGui
import PySide6.QtCore as QtCore

import iced_x86

from .. import state
from .. import pe_file
from .. import helpers
from .components import textedit


class DisassemblyView(QtWidgets.QWidget):
    NAME = "Disassembly"
    LOAD_ASYNC = True
    SHOW_PROGRESS = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.loaded = False

        self.pe_obj: pe_file.PEFile = None
        self.assembly: "list[str]" = None
        self.addresses: "list[int]" = None

        self.setLayout(QtWidgets.QVBoxLayout())

        # Set up top control bar
        self.controls_widget = QtWidgets.QWidget()
        self.controls_widget.setLayout(QtWidgets.QHBoxLayout())
        self.controls_widget.layout().setContentsMargins(0, 0, 0, 0)
        self.controls_widget.setSizePolicy(
            QtWidgets.QSizePolicy.MinimumExpanding, QtWidgets.QSizePolicy.Maximum
        )

        self.entrypoint_btn = QtWidgets.QPushButton("Go to Entrypoint")
        self.entrypoint_btn.clicked.connect(self.handle_entrypoint_btn_clicked)
        self.entrypoint_btn.setSizePolicy(
            QtWidgets.QSizePolicy.Maximum, QtWidgets.QSizePolicy.Maximum
        )
        self.controls_widget.layout().addWidget(self.entrypoint_btn)
        self.controls_widget.layout().addStretch()

        self.address_box = QtWidgets.QLineEdit()
        self.address_box.setPlaceholderText("Go to address")
        self.address_box.returnPressed.connect(self.handle_address_box_search)
        self.controls_widget.layout().addWidget(self.address_box)

        self.controls_widget.layout().addStretch()

        self.formatter_syntax_label = QtWidgets.QLabel("Assembly syntax:")
        self.controls_widget.layout().addWidget(self.formatter_syntax_label)

        self.formatter_syntax_box = QtWidgets.QComboBox()
        self.formatter_syntax_box.addItems(
            ["Intel", "GNU Assembler (AT&T)", "masm", "nasm"]
        )
        self.formatter_syntax_box.currentTextChanged.connect(
            self.handle_formatter_changed
        )
        self.controls_widget.layout().addWidget(self.formatter_syntax_box)

        self.layout().addWidget(self.controls_widget)

        # Set up disassembly text edit
        self.text_edit = textedit.MonoTextEdit()
        self.layout().addWidget(self.text_edit)

    def load_async(self, pe_obj: pe_file.PEFile):
        self.pe_obj = pe_obj

        if pe_obj is None:
            return

        if self.formatter_syntax_box.currentText() == "Intel":
            syntax = iced_x86.FormatterSyntax.INTEL
        elif self.formatter_syntax_box.currentText() == "GNU Assembler (AT&T)":
            syntax = iced_x86.FormatterSyntax.GAS
        elif self.formatter_syntax_box.currentText() == "masm":
            syntax = iced_x86.FormatterSyntax.MASM
        elif self.formatter_syntax_box.currentText() == "nasm":
            syntax = iced_x86.FormatterSyntax.NASM
        else:
            syntax = iced_x86.FormatterSyntax.INTEL

        self.assembly, self.addresses = self.get_disassembly(
            pe_obj.pe.get_memory_mapped_image(),
            image_base=pe_obj.pe.OPTIONAL_HEADER.ImageBase,
            is_64bit=pe_obj.is_64bit(),
            syntax=syntax,
        )

        self.assembly_text = "\n".join(self.assembly)

    def load_finalize(self):
        self.text_edit.setPlainText(self.assembly_text)

    def enable_tab(self):
        state.tabview.set_loading(self.NAME, False)

    def load(self, pe_obj: pe_file.PEFile):
        self.load_async(pe_obj)
        self.load_finalize()

    def get_disassembly(
        self,
        code: bytes,
        image_base=0,
        is_64bit=False,
        syntax=iced_x86.FormatterSyntax.GAS,
    ) -> "tuple[list[str], list[int]]":
        """
        Get the disassembly of the given x86 code.
        :param code: The code to disassemble.
        :param image_base: The image base to use when disassembling.
        :param is_64bit: Whether the code is 64-bit or not.
        :param syntax: The assembly syntax to use.
        :return: A tuple of two lists containing the disassembly and the addresses of the instructions.
        """
        decoder = iced_x86.Decoder(64 if is_64bit else 32, code)
        formatter = iced_x86.Formatter(syntax)
        formatter.first_operand_char_index = 10

        assembly: "list[str]" = []
        addresses: "list[int]" = []

        for instr in decoder:
            disasm = formatter.format(instr)

            start_index = instr.ip
            bytes_str = code[start_index : start_index + instr.len].hex().upper()

            if is_64bit:
                assembly.append(f"{instr.ip+image_base:016X} {bytes_str:20} {disasm}")
            else:
                assembly.append(f"{instr.ip+image_base:08X} {bytes_str:20} {disasm}")

            addresses.append(instr.ip + image_base)

        return assembly, addresses

    def handle_formatter_changed(self):
        """Reload the tab to re-parse the disassembly with the new formatter syntax"""
        self.text_edit.setPlainText("")
        self.load(self.pe_obj)

    def handle_entrypoint_btn_clicked(self):
        """Jump to the entrypoint of the loaded PE file."""
        if self.addresses is None or len(self.addresses) == 0:
            return

        self.scroll_to_address(self.pe_obj.entrypoint())

    def handle_address_box_search(self):
        """Jump to the address in the address box."""
        if self.addresses is None or len(self.addresses) == 0:
            return

        try:
            address = int(self.address_box.text(), 16)
        except ValueError:
            helpers.show_message_box(
                "The address you entered was invalid.",
                alert_type=helpers.MessageBoxTypes.CRITICAL,
                title="Invalid Address",
            )
            return

        self.scroll_to_address(address)

    def scroll_to_address(self, target_address: int):
        """
        Scroll to the given address in the disassembly view, or the closest address.
        :param target_address: The address to scroll to, can be an address with or without the image base.
        """
        if self.addresses is None or len(self.addresses) == 0:
            return

        # Find assembly line with entrypoint address
        # Need to find the address CLOSEST to the entrypoint address, since the exact address
        # may not be in the disassembly, only an address near it.
        closest_line = 0
        closest_distance = 0xFFFFFFFFFFFFFFFF
        closest_line_base = 0
        closest_distance_base = 0xFFFFFFFFFFFFFFFF
        for i, address in enumerate(self.addresses):
            # Calculate distance without image base
            distance = abs(address - target_address)
            if distance <= closest_distance:
                closest_distance = distance
                closest_line = i

            # Calculate distance with image base
            distance_base = abs(address - (target_address + self.pe_obj.image_base()))
            if distance_base <= closest_distance_base:
                closest_distance_base = distance_base
                closest_line_base = i

        # Use whichever is closer, the one with the image base or the one without it
        if closest_distance < closest_distance_base:
            entrypoint_line = closest_line
        else:
            entrypoint_line = closest_line_base

        # Scroll to and highlight the line
        cursor = self.text_edit.textCursor()
        cursor.setPosition(
            self.text_edit.document().findBlockByLineNumber(entrypoint_line).position()
        )
        cursor.select(QtGui.QTextCursor.LineUnderCursor)
        self.text_edit.setTextCursor(cursor)
        self.text_edit.setFocus()
