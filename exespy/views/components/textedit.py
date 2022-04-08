import PySide6.QtWidgets as QtWidgets
import PySide6.QtGui as QtGui


class MonoTextEdit(QtWidgets.QPlainTextEdit):
    """Monospaced, read-only plain text edit."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.setReadOnly(True)
        self.setUndoRedoEnabled(False)
        self.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap)
        self.setWordWrapMode(QtGui.QTextOption.NoWrap)

        monospaced_font = QtGui.QFont(["Monospace", "Consolas", "Courier New"])
        monospaced_font.setStyleHint(QtGui.QFont.TypeWriter)
        self.document().setDefaultFont(monospaced_font)
        self.setFont(monospaced_font)
