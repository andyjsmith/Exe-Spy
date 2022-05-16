from dataclasses import dataclass
import hashlib
import os
import time
import logging
import io

import pefile
import lief


@dataclass
class Resource:
    rtype: str
    id: str
    lang: str
    sublang: str
    size: int
    offset: int
    data: bytes


class PEFile:
    """Base class for representing a PE file"""

    def __init__(self, path: str):
        """
        Initialize the PEFile object
        :param path: Path to the PE file
        """
        init_start = time.time()

        self.path = path
        self.name = os.path.basename(path)
        self.stat = os.stat(path)

        # Read the PE into memory so it can be reused
        with open(path, "rb") as f:
            self.data = f.read()

        self.pe = pefile.PE(data=self.data)
        self.lief_obj = lief.parse(raw=self.data, name=self.name)

        # TODO: this is a very slow operation, any way to speed up checksum generation?
        checksum_start = time.time()
        self.calculated_checksum = self.pe.generate_checksum()
        logging.getLogger("exespy").debug(
            f"Generated checksum in {time.time() - checksum_start:.4f} seconds"
        )

        self.sha256 = self.calculate_sha256()

        self.resources = self.get_resources()

        logging.getLogger("exespy").debug(
            f"PEFile init finished in {time.time() - init_start:.4f} seconds"
        )

    def type(self) -> str:
        """Return the type of the PE file (PE/DLL/etc)"""
        if self.pe.is_dll():
            return "DLL"
        elif self.pe.is_driver():
            return "Driver"
        elif self.pe.is_exe():
            return "Executable"
        else:
            return "Unknown"

    def architecture(self) -> str:
        """Return the architecture of the PE file"""
        return pefile.MACHINE_TYPE[self.pe.FILE_HEADER.Machine].replace(
            "IMAGE_FILE_MACHINE_", ""
        )

    def is_x86(self) -> bool:
        """Return whether the PE file uses the x86 instruction set"""
        return self.architecture() == "I386" or self.architecture() == "AMD64"

    def is_32bit(self) -> bool:
        """Return whether the PE file is 32-bit"""
        return self.architecture() == "I386"

    def is_64bit(self) -> bool:
        """Return whether the PE file is 64-bit"""
        return self.architecture() == "AMD64"

    def subsystem(self) -> str:
        """Return the subsystem of the PE file"""
        return pefile.SUBSYSTEM_TYPE[self.pe.OPTIONAL_HEADER.Subsystem].replace(
            "IMAGE_SUBSYSTEM_", ""
        )

    def entrypoint(self) -> int:
        """Return the entrypoint of the PE file"""
        try:
            return self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        except AttributeError:
            return 0

    def image_base(self) -> int:
        """Return the imagebase of the PE file"""
        try:
            return self.pe.OPTIONAL_HEADER.ImageBase
        except AttributeError:
            return 0

    def verify_signature(self) -> str:
        """Verify the PE file's signature"""
        sig = self.lief_obj.verify_signature()
        if sig == lief.PE.Signature.VERIFICATION_FLAGS.OK:
            return "Verified"
        elif sig == lief.PE.Signature.VERIFICATION_FLAGS.NO_SIGNATURE:
            return "Not signed"
        return "Invalid"

    def verify_checksum(self) -> str:
        """Verify the PE file's checksum"""
        if self.pe.OPTIONAL_HEADER.CheckSum == self.calculated_checksum:
            return "Valid"
        else:
            return f"Invalid, should be {hex(self.calculated_checksum)}"

    def characteristics(self) -> "list[str]":
        """Return a list of characteristics for the PE file"""
        names = []
        for name, val in pefile.image_characteristics:
            if self.pe.FILE_HEADER.Characteristics & val:
                names.append(name)
        return names

    def characteristics_str(self) -> str:
        """Convert the characteristics to a readable string"""
        return ", ".join([c.replace("IMAGE_FILE_", "") for c in self.characteristics()])

    def dll_characteristics(self) -> "list[str]":
        """Return a list of DLL characteristics for the PE file"""
        names = []
        for name, val in pefile.dll_characteristics:
            if self.pe.OPTIONAL_HEADER.DllCharacteristics & val:
                names.append(name)
        return names

    def dll_characteristics_str(self) -> str:
        """Convert the DLL characteristics to a readable string"""
        return ", ".join(
            [
                c.replace("IMAGE_DLLCHARACTERISTICS_", "").replace("IMAGE_LIBRARY_", "")
                for c in self.dll_characteristics()
            ]
        )

    def pe_format(self) -> str:
        """Return the PE format of the PE file (PE32 or PE32+)"""
        if self.pe.OPTIONAL_HEADER.Magic == pefile.OPTIONAL_HEADER_MAGIC_PE:
            return "PE32"
        elif self.pe.OPTIONAL_HEADER.Magic == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS:
            return "PE32+"
        return "unknown"

    def section_characteristics(self, section_num) -> "list[str]":
        """Return a list of characteristics for the section"""
        names = []
        for name, val in pefile.section_characteristics:
            if self.pe.sections[section_num].Characteristics & val:
                names.append(name)
        return names

    def section_characteristics_str(self, section_num) -> str:
        """Convert the section characteristics to a readable string"""
        return ", ".join(
            [
                c.replace("IMAGE_SCN_", "")
                for c in self.section_characteristics(section_num)
            ]
        )

    def get_resources(self) -> "list[Resource]":
        """Return a list of resources for the PE file"""
        resources: "list[Resource]" = []

        # Parse PE resources
        if hasattr(self.pe, "DIRECTORY_ENTRY_RESOURCE"):
            for type_item in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if type_item.name is not None:
                    resource_type = str(type_item.name)
                else:
                    resource_type = pefile.RESOURCE_TYPE[type_item.id]

                if hasattr(type_item, "directory") and hasattr(
                    type_item.directory, "entries"
                ):
                    for id_item in type_item.directory.entries:
                        if id_item.name is not None:
                            resource_id = str(id_item.name)
                        else:
                            resource_id = id_item.id

                        if hasattr(id_item, "directory") and hasattr(
                            id_item.directory, "entries"
                        ):
                            for language_item in id_item.directory.entries:
                                lang = pefile.LANG[language_item.data.lang]
                                sublang = pefile.get_sublang_name_for_lang(
                                    language_item.data.lang, language_item.data.sublang
                                )

                                resource_obj = Resource(
                                    resource_type,
                                    resource_id,
                                    lang,
                                    sublang,
                                    language_item.data.struct.Size,
                                    language_item.data.struct.OffsetToData,
                                    bytes(
                                        self.pe.get_data(
                                            language_item.data.struct.OffsetToData,
                                            language_item.data.struct.Size,
                                        )
                                    ),
                                )

                                resources.append(resource_obj)

        return resources

    def strings(self, min_length=10) -> "list[str]":
        """Return a list of strings from the PE file"""
        strings = []
        with io.BytesIO(self.data) as f:
            current_string = b""
            byte = f.read(1)

            while byte:
                if b" " <= byte <= b"~":
                    current_string += byte
                else:
                    if len(current_string) >= min_length:
                        strings.append(
                            (
                                current_string.decode("ascii"),
                                f.tell() - len(current_string) - 1,
                            )
                        )
                    current_string = b""
                byte = f.read(1)

            if len(current_string) >= min_length:
                strings.append(
                    (current_string.decode("ascii"), f.tell() - len(current_string))
                )

        return strings

    def calculate_sha256(self) -> str:
        """Generate a SHA256 hash of the PE file"""
        sha256 = hashlib.sha256()
        # Calculate the hashes while only looping through the file once
        with io.BytesIO(self.data) as f:
            # Read the file in chunks of 4096 bytes
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256.update(byte_block)
        return sha256.hexdigest()
