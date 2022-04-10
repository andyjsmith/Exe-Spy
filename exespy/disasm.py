import pefile
from iced_x86 import *

pe = pefile.PE("C:\\Users\\Andy\\Downloads\\notepad.exe")
EXAMPLE_CODE = pe.get_memory_mapped_image(ImageBase=pe.OPTIONAL_HEADER.ImageBase)
EXAMPLE_CODE_BITNESS = 64

# Create the decoder and initialize RIP
decoder = Decoder(EXAMPLE_CODE_BITNESS, EXAMPLE_CODE)

# Formatters: MASM, NASM, GAS (AT&T) and INTEL (XED).
# There's also `FastFormatter` which is ~1.25x faster. Use it if formatting
# speed is more important than being able to re-assemble formatted
# instructions.
#    formatter = FastFormatter()
formatter = Formatter(FormatterSyntax.NASM)

# Change some options, there are many more
formatter.digit_separator = "`"
formatter.first_operand_char_index = 10

# You can also call decoder.can_decode + decoder.decode()/decode_out(instr)
# but the iterator is faster
with open("disasm.txt", "w") as f:
    for instr in decoder:
        disasm = formatter.format(instr)
        # You can also get only the mnemonic string, or only one or more of the operands:
        #   mnemonic_str = formatter.format_mnemonic(instr, FormatMnemonicOptions.NO_PREFIXES)
        #   op0_str = formatter.format_operand(instr, 0)
        #   operands_str = formatter.format_all_operands(instr)

        start_index = instr.ip
        bytes_str = EXAMPLE_CODE[start_index : start_index + instr.len].hex().upper()
        # Eg. "00007FFAC46ACDB2 488DAC2400FFFFFF     lea       rbp,[rsp-100h]"
        f.write(
            f"{instr.ip+pe.OPTIONAL_HEADER.ImageBase:016X} {bytes_str:20} {disasm}\n"
        )
