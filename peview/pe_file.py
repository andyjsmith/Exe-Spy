import os

import pefile
import lief


class PEFile:
    def __init__(self, path: str):
        self.path = path
        self.name = os.path.basename(path)
        self.stat = os.stat(path)
        self.pe = pefile.PE(path)
        self.lief_obj = lief.parse(path)
        # TODO: this is a very slow operation, any way to speed up checksum generation?
        self.calculated_checksum = self.pe.generate_checksum()

    def type(self) -> str:
        if self.pe.is_dll():
            return "DLL"
        elif self.pe.is_driver():
            return "Driver"
        elif self.pe.is_exe():
            return "Executable"
        else:
            return "Unknown"

    def architecture(self) -> str:
        return pefile.MACHINE_TYPE[self.pe.FILE_HEADER.Machine].replace("IMAGE_FILE_MACHINE_", "")

    def subsystem(self) -> str:
        return pefile.SUBSYSTEM_TYPE[self.pe.OPTIONAL_HEADER.Subsystem].replace("IMAGE_SUBSYSTEM_", "")

    def verify_signature(self) -> str:
        sig = self.lief_obj.verify_signature()
        if sig == lief.PE.Signature.VERIFICATION_FLAGS.OK:
            return "Verified"
        elif sig == lief.PE.Signature.VERIFICATION_FLAGS.NO_SIGNATURE:
            return "Not signed"
        return "Invalid"

    def verify_checksum(self) -> str:
        if self.pe.OPTIONAL_HEADER.CheckSum == self.calculated_checksum:
            return "Valid"
        else:
            return f"Invalid, should be {hex(self.calculated_checksum)}"

    def characteristics(self) -> "list[str]":
        names = []
        for name, val in pefile.image_characteristics:
            if self.pe.FILE_HEADER.Characteristics & val:
                names.append(name)
        return names

    def characteristics_str(self) -> str:
        return ", ".join([c.replace("IMAGE_FILE_", "") for c in self.characteristics()])

    def dll_characteristics(self) -> "list[str]":
        names = []
        for name, val in pefile.dll_characteristics:
            if self.pe.OPTIONAL_HEADER.DllCharacteristics & val:
                names.append(name)
        return names

    def dll_characteristics_str(self) -> str:
        return ", ".join([c.replace("IMAGE_DLLCHARACTERISTICS_", "").replace("IMAGE_LIBRARY_", "") for c in self.dll_characteristics()])

    def pe_format(self) -> str:
        if self.pe.OPTIONAL_HEADER.Magic == pefile.OPTIONAL_HEADER_MAGIC_PE:
            return("PE")
        elif self.pe.OPTIONAL_HEADER.Magic == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS:
            return("PE+")
        return "unknown"

    def section_characteristics(self, section_num) -> "list[str]":
        names = []
        for name, val in pefile.section_characteristics:
            if self.pe.sections[section_num].Characteristics & val:
                names.append(name)
        return names

    def section_characteristics_str(self, section_num) -> str:
        return ", ".join([c.replace("IMAGE_SCN_", "") for c in self.section_characteristics(section_num)])

    # TODO: this is slow, maybe do in another thread?
    def strings(self, min_length=10) -> "list[str]":
        strings = []
        with open(self.path, "rb") as f:
            current_string = b""
            byte = f.read(1)

            while byte:
                if b" " <= byte <= b"~":
                    current_string += byte
                else:
                    if len(current_string) >= min_length:
                        strings.append((current_string.decode(
                            "ascii"), f.tell() - len(current_string) - 1))
                    current_string = b""
                byte = f.read(1)

            if len(current_string) >= min_length:
                strings.append((current_string.decode("ascii"),
                                f.tell() - len(current_string)))

        return strings
