import hashlib
import zlib

import PySide6.QtWidgets as QtWidgets

from .. import helpers
from .. import pe_file
from .components import table


class HashesView(QtWidgets.QScrollArea):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Set up scroll area
        self.setWidgetResizable(True)
        self.scroll_area = QtWidgets.QWidget(self)
        self.setWidget(self.scroll_area)
        self.scroll_area.setLayout(QtWidgets.QFormLayout())

        # File Hashes
        self.file_hashes_group = table.TableGroup(
            "File Hashes", fit_columns=True, headers=["Type", "Hash"])
        self.scroll_area.layout().addWidget(self.file_hashes_group)

        self.file_hashes_group.setFocus()

    def load(self, pe_obj: pe_file.PEFile):
        hashes = self.calculate_hashes(pe_obj.path)

        # File Hashes
        # TODO: CRC
        self.file_hashes_group.view.setModel(
            table.TableModel(hashes, headers=["Type", "Hash"]))

    def calculate_hashes(self, filename) -> "list[tuple]":
        """Calculate file hashes as a list of tuples."""
        hash_crc32 = crc32()
        hash_md5 = hashlib.md5()
        hash_sha1 = hashlib.sha1()
        hash_sha224 = hashlib.sha224()
        hash_sha256 = hashlib.sha256()
        hash_sha384 = hashlib.sha384()
        hash_sha512 = hashlib.sha512()
        hash_sha3_224 = hashlib.sha3_224()
        hash_sha3_256 = hashlib.sha3_256()
        hash_sha3_384 = hashlib.sha3_384()
        hash_sha3_512 = hashlib.sha3_512()
        hash_blake2s = hashlib.blake2s()
        hash_blake2b = hashlib.blake2b()

        # Calculate the hashes while only looping through the file once
        with open(filename, "rb") as f:
            # Read the file in chunks of 4096 bytes
            for byte_block in iter(lambda: f.read(4096), b""):
                hash_crc32.update(byte_block)
                hash_md5.update(byte_block)
                hash_sha1.update(byte_block)
                hash_sha224.update(byte_block)
                hash_sha256.update(byte_block)
                hash_sha384.update(byte_block)
                hash_sha512.update(byte_block)
                hash_sha3_224.update(byte_block)
                hash_sha3_256.update(byte_block)
                hash_sha3_384.update(byte_block)
                hash_sha3_512.update(byte_block)
                hash_blake2s.update(byte_block)
                hash_blake2b.update(byte_block)

        # Hashes are done
        return [
            ("CRC32", hash_crc32.hexdigest()),
            ("MD5", hash_md5.hexdigest()),
            ("SHA1", hash_sha1.hexdigest()),
            ("SHA224", hash_sha224.hexdigest()),
            ("SHA256", hash_sha256.hexdigest()),
            ("SHA384", hash_sha384.hexdigest()),
            ("SHA512", hash_sha512.hexdigest()),
            ("SHA3-224", hash_sha3_224.hexdigest()),
            ("SHA3-256", hash_sha3_256.hexdigest()),
            ("SHA3-384", hash_sha3_384.hexdigest()),
            ("SHA3-512", hash_sha3_512.hexdigest()),
            ("BLAKE2s", hash_blake2s.hexdigest()),
            ("BLAKE2b", hash_blake2b.hexdigest())
        ]


class crc32(object):
    # https://stackoverflow.com/questions/1742866/compute-crc-of-file-in-python
    name = 'crc32'
    digest_size = 4
    block_size = 1

    def __init__(self, arg=b''):
        self.__digest = 0
        self.update(arg)

    def copy(self):
        copy = super(self.__class__, self).__new__(self.__class__)
        copy.__digest = self.__digest
        return copy

    def digest(self):
        return self.__digest

    def hexdigest(self):
        return '{:08x}'.format(self.__digest)

    def update(self, arg):
        self.__digest = zlib.crc32(arg, self.__digest) & 0xffffffff