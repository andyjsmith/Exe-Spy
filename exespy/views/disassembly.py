import PySide6.QtWidgets as QtWidgets
import PySide6.QtGui as QtGui
import PySide6.QtCore as QtCore

import iced_x86

from .. import pe_file


class DisassemblyView(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.pe_obj: pe_file.PEFile = None
        self.assembly: "list[str]" = None
        self.addresses: "list[int]" = None

        self.setLayout(QtWidgets.QVBoxLayout())

        # Set up top control bar
        self.controls_widget = QtWidgets.QWidget()
        self.controls_widget.setLayout(QtWidgets.QHBoxLayout())
        self.controls_widget.layout().setContentsMargins(0, 0, 0, 0)
        self.controls_widget.setSizePolicy(
            QtWidgets.QSizePolicy.MinimumExpanding, QtWidgets.QSizePolicy.Maximum)

        self.entrypoint_btn = QtWidgets.QPushButton("Go to Entrypoint")
        self.entrypoint_btn.clicked.connect(self.handle_entrypoint_btn_clicked)
        self.entrypoint_btn.setSizePolicy(
            QtWidgets.QSizePolicy.Maximum, QtWidgets.QSizePolicy.Maximum)
        self.controls_widget.layout().addWidget(self.entrypoint_btn)

        self.controls_widget.layout().addStretch()

        self.formatter_syntax_label = QtWidgets.QLabel("Assembly syntax:")
        self.controls_widget.layout().addWidget(self.formatter_syntax_label)

        self.formatter_syntax_box = QtWidgets.QComboBox()
        self.formatter_syntax_box.addItems(
            ["Intel", "GNU Assembler (AT&T)", "masm", "nasm"])
        self.formatter_syntax_box.currentTextChanged.connect(
            self.handle_formatter_changed)
        self.controls_widget.layout().addWidget(self.formatter_syntax_box)

        self.layout().addWidget(self.controls_widget)

        # Set up disassembly text edit
        self.text_edit = QtWidgets.QPlainTextEdit()
        self.text_edit.setReadOnly(True)
        # The following possibly improve the plaintextedit's performance
        self.text_edit.setUndoRedoEnabled(False)
        self.text_edit.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap)
        self.text_edit.setWordWrapMode(QtGui.QTextOption.NoWrap)

        mono_font = QtGui.QFont(["Monospace", "Consolas", "Courier New"])
        mono_font.setStyleHint(QtGui.QFont.TypeWriter)
        self.text_edit.setFont(mono_font)
        self.layout().addWidget(self.text_edit)

    def load(self, pe_obj: pe_file.PEFile):
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

        self.assembly, self.addresses = self.get_disassembly(pe_obj.pe.get_memory_mapped_image(
        ), image_base=pe_obj.pe.OPTIONAL_HEADER.ImageBase, is_64bit=pe_obj.is_64bit(), syntax=syntax)

        self.text_edit.setPlainText("\n".join(self.assembly))

    def get_disassembly(self, code: bytes, image_base=0, is_64bit=False, syntax=iced_x86.FormatterSyntax.GAS) -> "tuple[list[str], list[int]]":
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
            bytes_str = code[start_index:start_index +
                             instr.len].hex().upper()

            if is_64bit:
                assembly.append(
                    f"{instr.ip+image_base:016X} {bytes_str:20} {disasm}")
            else:
                assembly.append(
                    f"{instr.ip+image_base:08X} {bytes_str:20} {disasm}")

            addresses.append(instr.ip+image_base)

        return assembly, addresses

    def handle_formatter_changed(self):
        """Reload the tab to re-parse the disassembly with the new formatter syntax"""
        self.text_edit.setPlainText("")
        self.load(self.pe_obj)

    def handle_entrypoint_btn_clicked(self):
        """Jump to the entrypoint of the loaded PE file."""
        if self.addresses is None or len(self.addresses) == 0:
            return

        # Find assembly line with entrypoint address
        # Need to find the address CLOSEST to the entrypoint address, since the exact address
        # may not be in the disassembly, only an address near it.
        entrypoint_line = min(range(len(self.addresses)), key=lambda i: abs(
            self.addresses[i]-(self.pe_obj.entrypoint()+self.pe_obj.image_base())))

        # Scroll to and highlight the line
        cursor = self.text_edit.textCursor()
        cursor.setPosition(self.text_edit.document(
        ).findBlockByLineNumber(entrypoint_line).position())
        cursor.select(QtGui.QTextCursor.LineUnderCursor)
        self.text_edit.setTextCursor(cursor)
        self.text_edit.setFocus()
