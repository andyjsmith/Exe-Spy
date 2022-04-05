import PySide6.QtWidgets as QtWidgets

from .. import helpers
from .. import pe_file
from .components import table


class HeadersView(QtWidgets.QScrollArea):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Set up scroll area
        self.setWidgetResizable(True)
        self.scroll_area = QtWidgets.QWidget(self)
        self.setWidget(self.scroll_area)
        self.scroll_area.setLayout(QtWidgets.QFormLayout())

        # DOS Header
        self.dos_header_group = table.TableGroup(
            "DOS Header", fit_columns=True, headers=["Name", "Description", "Value"])
        self.scroll_area.layout().addWidget(self.dos_header_group)

        # COFF File Header
        self.file_header_group = table.TableGroup(
            "File Header", fit_columns=True, headers=["Name", "Value"])
        self.scroll_area.layout().addWidget(self.file_header_group)

        # Optional Header
        self.optional_header_group = table.TableGroup(
            "Optional Header", fit_columns=True, headers=["Name", "Value"])
        self.scroll_area.layout().addWidget(self.optional_header_group)
        self.dos_header_group.setFocus()

    def load(self, pe_obj: pe_file.PEFile):

        # DOS Header
        self.dos_header_group.view.setModel(table.TableModel([
            ("e_magic", "Magic number", hex(pe_obj.pe.DOS_HEADER.e_magic)),
            ("e_cblp", "Bytes on last page of file",
             hex(pe_obj.pe.DOS_HEADER.e_cblp)),
            ("e_cp", "Pages in file", hex(pe_obj.pe.DOS_HEADER.e_cp)),
            ("e_crlc", "Relocations", hex(pe_obj.pe.DOS_HEADER.e_crlc)),
            ("e_cparhdr", "Size of header in paragraphs",
             hex(pe_obj.pe.DOS_HEADER.e_cparhdr)),
            ("e_minalloc", "Minimum extra paragraphs needed", hex(
                pe_obj.pe.DOS_HEADER.e_minalloc)),
            ("e_maxalloc", "Maximum extra paragraphs needed", hex(
                pe_obj.pe.DOS_HEADER.e_maxalloc)),
            ("e_ss", "Initial (relative) SS value", hex(pe_obj.pe.DOS_HEADER.e_ss)),
            ("e_sp", "Initial SP value", hex(pe_obj.pe.DOS_HEADER.e_sp)),
            ("e_csum", "Checksum", hex(pe_obj.pe.DOS_HEADER.e_csum)),
            ("e_ip", "Initial IP value", hex(pe_obj.pe.DOS_HEADER.e_ip)),
            ("e_cs", "Initial (relative) CS value", hex(pe_obj.pe.DOS_HEADER.e_cs)),
            ("e_lfarlc", "File address of relocation table",
             hex(pe_obj.pe.DOS_HEADER.e_lfarlc)),
            ("e_ovno", "Overlay number", hex(pe_obj.pe.DOS_HEADER.e_ovno)),
            ("e_res", "Reserved words", hex(int.from_bytes(
                pe_obj.pe.DOS_HEADER.e_res, "big"))),
            ("e_oemid", "OEM identifier (for e_oeminfo)",
             hex(pe_obj.pe.DOS_HEADER.e_oemid)),
            ("e_oeminfo", "OEM information; e_oemid specific",
             hex(pe_obj.pe.DOS_HEADER.e_oeminfo)),
            ("e_res2", "Reserved words", hex(int.from_bytes(
                pe_obj.pe.DOS_HEADER.e_res2, "big"))),
            ("e_lfanew", "File address of new exe header",
             hex(pe_obj.pe.DOS_HEADER.e_lfanew))
        ], headers=["Name", "Description", "Value"]))

        # COFF File Header
        self.file_header_group.view.setModel(table.TableModel([
            ("Machine",
             f"{hex(pe_obj.pe.FILE_HEADER.Machine)} ({pe_obj.architecture()})"),
            ("NumberOfSections", str(pe_obj.pe.FILE_HEADER.NumberOfSections)),
            ("TimeDateStamp",
             f"{hex(pe_obj.pe.FILE_HEADER.TimeDateStamp)} ({helpers.format_time(pe_obj.pe.FILE_HEADER.TimeDateStamp)})"),
            ("PointerToSymbolTable", hex(pe_obj.pe.FILE_HEADER.PointerToSymbolTable)),
            ("NumberOfSymbols", str(pe_obj.pe.FILE_HEADER.NumberOfSymbols)),
            ("SizeOfOptionalHeader", hex(pe_obj.pe.FILE_HEADER.SizeOfOptionalHeader)),
            ("Characteristics",
             f"{hex(pe_obj.pe.FILE_HEADER.Characteristics)} ({pe_obj.characteristics_str()})"),
        ], headers=["Name", "Value"]))

        # Optional Header
        base_of_data = []
        try:
            base_of_data.append(("BaseOfData", hex(
                pe_obj.pe.OPTIONAL_HEADER.BaseOfData)))
        except AttributeError:
            pass

        self.optional_header_group.view.setModel(table.TableModel([
            ("Magic",
             f"{hex(pe_obj.pe.OPTIONAL_HEADER.Magic)} ({pe_obj.pe_format()})"),
            ("MajorLinkerVersion", str(pe_obj.pe.OPTIONAL_HEADER.MajorLinkerVersion)),
            ("MinorLinkerVersion", str(pe_obj.pe.OPTIONAL_HEADER.MinorLinkerVersion)),
            ("SizeOfCode", hex(pe_obj.pe.OPTIONAL_HEADER.SizeOfCode)),
            ("SizeOfInitializedData", hex(
                pe_obj.pe.OPTIONAL_HEADER.SizeOfInitializedData)),
            ("SizeOfUninitializedData", hex(
                pe_obj.pe.OPTIONAL_HEADER.SizeOfUninitializedData)),
            ("AddressOfEntryPoint", hex(pe_obj.pe.OPTIONAL_HEADER.AddressOfEntryPoint)),
            ("BaseOfCode", hex(pe_obj.pe.OPTIONAL_HEADER.BaseOfCode)),
        ] + base_of_data + [
            ("ImageBase", hex(pe_obj.pe.OPTIONAL_HEADER.ImageBase)),
            ("SectionAlignment", hex(pe_obj.pe.OPTIONAL_HEADER.SectionAlignment)),
            ("FileAlignment", hex(pe_obj.pe.OPTIONAL_HEADER.FileAlignment)),
            ("MajorOperatingSystemVersion", str(
                pe_obj.pe.OPTIONAL_HEADER.MajorOperatingSystemVersion)),
            ("MinorOperatingSystemVersion", str(
                pe_obj.pe.OPTIONAL_HEADER.MinorOperatingSystemVersion)),
            ("MajorImageVersion", str(pe_obj.pe.OPTIONAL_HEADER.MajorImageVersion)),
            ("MinorImageVersion", str(pe_obj.pe.OPTIONAL_HEADER.MinorImageVersion)),
            ("MajorSubsystemVersion", str(
                pe_obj.pe.OPTIONAL_HEADER.MajorSubsystemVersion)),
            ("MinorSubsystemVersion", str(
                pe_obj.pe.OPTIONAL_HEADER.MinorSubsystemVersion)),
            ("Win32VersionValue (reserved)", hex(
                pe_obj.pe.OPTIONAL_HEADER.Reserved1)),
            ("SizeOfImage", hex(pe_obj.pe.OPTIONAL_HEADER.SizeOfImage)),
            ("SizeOfHeaders", hex(pe_obj.pe.OPTIONAL_HEADER.SizeOfHeaders)),
            ("CheckSum",
             f"{hex(pe_obj.pe.OPTIONAL_HEADER.CheckSum)} ({pe_obj.verify_checksum()})"),
            ("Subsystem",
             f"{hex(pe_obj.pe.OPTIONAL_HEADER.Subsystem)} ({pe_obj.subsystem()})"),
            ("DllCharacteristics",
             f"{hex(pe_obj.pe.OPTIONAL_HEADER.DllCharacteristics)}, ({pe_obj.dll_characteristics_str()})"),
            ("SizeOfStackReserve", hex(pe_obj.pe.OPTIONAL_HEADER.SizeOfStackReserve)),
            ("SizeOfStackCommit", hex(pe_obj.pe.OPTIONAL_HEADER.SizeOfStackCommit)),
            ("SizeOfHeapReserve", hex(pe_obj.pe.OPTIONAL_HEADER.SizeOfHeapReserve)),
            ("SizeOfHeapCommit", hex(pe_obj.pe.OPTIONAL_HEADER.SizeOfHeapCommit)),
            ("LoaderFlags", hex(pe_obj.pe.OPTIONAL_HEADER.LoaderFlags)),
            ("NumberOfRvaAndSizes", str(pe_obj.pe.OPTIONAL_HEADER.NumberOfRvaAndSizes)),
        ], headers=["Name", "Value"]))
