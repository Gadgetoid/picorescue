"""Vendored Binary Info (bi_decl) parser, adapted from py_decl.

Originally from https://github.com/gadgetoid/py_decl (MIT). Trimmed to the
parser itself; the CLI/argparse harness is removed. Used here to locate
``BlockDevice`` declarations (LittleFS / FAT partitions) inside a Pico binary.
"""
import io
import struct
import sys

UF2_MAGIC_START0 = 0x0A324655  # "UF2\n"
UF2_MAGIC_START1 = 0x9E5D5157
UF2_MAGIC_END = 0x0AB16F30

FAMILY_ID_RP2040 = 0xE48BFF56
FAMILY_ID_PAD = 0xE48BFF57
FAMILY_ID_RP2350 = 0xE48BFF59

FLASH_START_ADDR = 0x10000000

BLOCK_SIZE = 512
DATA_SIZE = 256
HEADER_SIZE = 32
FOOTER_SIZE = 4

BI_MAGIC = b"\xf2\xeb\x88\x71"
BI_END = b"\x90\xa3\x1a\xe7"

GPIO_FUNCS = {
    0: "XIP", 1: "SPI", 2: "UART", 3: "I2C", 4: "PWM", 5: "SIO",
    6: "PIO0", 7: "PIO1", 8: "GPCK", 9: "USB", 0xF: "NULL",
}

TYPE_RAW_DATA = 1
TYPE_SIZED_DATA = 2
TYPE_LIST_ZERO_TERMINATED = 3
TYPE_BSON = 4
TYPE_ID_AND_INT = 5
TYPE_ID_AND_STRING = 6
TYPE_BLOCK_DEVICE = 7
TYPE_PINS_WITH_FUNC = 8
TYPE_PINS_WITH_NAME = 9
TYPE_NAMED_GROUP = 10

ID_PROGRAM_NAME = 0x02031C86
ID_PROGRAM_VERSION_STRING = 0x11A9BC3A
ID_PROGRAM_BUILD_DATE_STRING = 0x9DA22254
ID_BINARY_END = 0x68F465DE
ID_PROGRAM_URL = 0x1856239A
ID_PROGRAM_DESCRIPTION = 0xB6A07C19
ID_PROGRAM_FEATURE = 0xA1F4B453
ID_PROGRAM_BUILD_ATTRIBUTE = 0x4275F0D3
ID_SDK_VERSION = 0x5360B3AB
ID_PICO_BOARD = 0xB63CFFBB
ID_BOOT2_NAME = 0x7F8882E1
ID_FILESYSTEM = 0x1009BE7E

IDS = {
    ID_PROGRAM_NAME: "Program Name",
    ID_PROGRAM_VERSION_STRING: "Program Version",
    ID_PROGRAM_BUILD_DATE_STRING: "Build Date",
    ID_BINARY_END: "Binary End Address",
    ID_PROGRAM_URL: "Program URL",
    ID_PROGRAM_DESCRIPTION: "Program Description",
    ID_PROGRAM_FEATURE: "Program Feature",
    ID_PROGRAM_BUILD_ATTRIBUTE: "Program Build Attribute",
    ID_SDK_VERSION: "SDK Version",
    ID_PICO_BOARD: "Pico Board",
    ID_BOOT2_NAME: "Boot Stage 2 Name",
}

TYPES = {
    TYPE_RAW_DATA: "Raw Data",
    TYPE_SIZED_DATA: "Sized Data",
    TYPE_LIST_ZERO_TERMINATED: "Zero Terminated List",
    TYPE_BSON: "BSON",
    TYPE_ID_AND_INT: "ID & Int",
    TYPE_ID_AND_STRING: "ID & Str",
    TYPE_BLOCK_DEVICE: "Block Device",
    TYPE_PINS_WITH_FUNC: "Pins With Func",
    TYPE_PINS_WITH_NAME: "Pins With Name",
    TYPE_NAMED_GROUP: "Named Group",
}

# Block device permission / partition-table flags.
BLOCK_DEV_FLAG_READ = 1 << 0
BLOCK_DEV_FLAG_WRITE = 1 << 1
BLOCK_DEV_FLAG_REFORMAT = 1 << 2

ALWAYS_A_LIST = ("NamedGroup", "BlockDevice", "ProgramFeature")


class UF2Reader(io.BytesIO):
    """Flatten the first RP2040/RP2350 family section of a UF2 into a BytesIO.

    NOTE: this concatenates block data and is only suitable for the contiguous
    firmware region (which is what bi_decl parsing needs). For correctly
    *addressed* flash images use :func:`picorescue.dump.load_image`.
    """

    def __init__(self, filepath):
        bin_data = b""
        for section in self.uf2_to_bin(filepath):
            _, _, family_id, _, _, block_data = section
            if family_id in (FAMILY_ID_RP2040, FAMILY_ID_RP2350):
                bin_data = block_data
                break
        io.BytesIO.__init__(self, bin_data)

    def uf2_to_bin(self, filepath):
        with open(filepath, "rb") as file:
            section_index = 0
            while data := file.read(BLOCK_SIZE):
                _, _, _, addr, _, block_no, num_blocks, family_id = struct.unpack(
                    b"<IIIIIIII", data[0:HEADER_SIZE]
                )
                if block_no == 0:
                    file.seek(file.tell() - BLOCK_SIZE)
                    yield (
                        section_index, addr, family_id, _, num_blocks,
                        b"".join(self.uf2_section_data(file)),
                    )
                    section_index += 1

    def uf2_section_data(self, file):
        count = 0
        while data := file.read(BLOCK_SIZE):
            _, _, _, addr, _, block_no, num_blocks, family_id = struct.unpack(
                b"<IIIIIIII", data[0:HEADER_SIZE]
            )
            if block_no == 0 and count > 0:
                file.seek(file.tell() - BLOCK_SIZE)
                break
            yield data[HEADER_SIZE:HEADER_SIZE + DATA_SIZE]
            count += 1


class PyDecl:
    def __init__(self, file, debug=False):
        self.entry_parsers = {
            TYPE_ID_AND_INT: self._parse_type_id_and_int,
            TYPE_ID_AND_STRING: self._parse_type_id_and_str,
            TYPE_BLOCK_DEVICE: self._parse_block_device,
            TYPE_NAMED_GROUP: self._parse_named_group,
            TYPE_PINS_WITH_FUNC: self._parse_pins_with_func,
            TYPE_PINS_WITH_NAME: self._parse_pins_with_name,
        }
        self.file = file
        self.debug = debug

    def parse(self):
        self.file.seek(0)
        if self.read_until(BI_MAGIC) is None:
            return None
        data = self.read_until(BI_END)
        if len(data) != 12:
            return None
        entries_start, entries_end, _ = struct.unpack("III", data)
        entries_start = self.addr_to_bin_offset(entries_start)
        entries_end = self.addr_to_bin_offset(entries_end)
        entries_bytes_len = entries_end - entries_start
        entries_len = entries_bytes_len // 4

        self.file.seek(entries_start)
        data = self.file.read(entries_bytes_len)
        if len(data) != entries_bytes_len:
            return None
        entries = struct.unpack("I" * entries_len, data)

        parsed = {}
        for entry in entries:
            self.file.seek(self.addr_to_bin_offset(entry))
            if (parsed_entry := self.parse_entry()) is not None:
                k, v = parsed_entry
                if k in parsed:
                    if k == "Pins":
                        parsed[k].update(v)
                        continue
                    if isinstance(parsed[k], list):
                        parsed[k] += [v]
                    else:
                        parsed[k] = [parsed[k], v]
                else:
                    parsed[k] = [v] if k in ALWAYS_A_LIST else v

        if "NamedGroup" in parsed:
            for group in parsed["NamedGroup"]:
                if group["id"] in parsed:
                    group["data"] = parsed[group["id"]]
                    del parsed[group["id"]]
        return parsed

    def addr_to_bin_offset(self, addr):
        return addr - FLASH_START_ADDR

    def data_type_to_str(self, data_type):
        return TYPES.get(data_type, "Unknown")

    def data_id_to_str(self, data_id):
        return IDS.get(data_id, "Unknown")

    def is_valid_data_id(self, data_id):
        return data_id in IDS

    def data_id_to_typename(self, data_id):
        return self.data_id_to_str(data_id).replace(" ", "")

    def _read_until(self, delimiter=b"\x00"):
        while (chunk := self.file.read(len(delimiter))) != delimiter:
            if len(chunk) == 0:
                raise EOFError
            yield chunk

    def read_until(self, delimiter=b"\x00"):
        try:
            return b"".join(self._read_until(delimiter))
        except EOFError:
            return None

    def lookup_string(self, address):
        self.file.seek(self.addr_to_bin_offset(address))
        return self.read_until(delimiter=b"\x00").decode("utf-8", "replace")

    def _parse_type_id_and_int(self, tag):
        data_id, data_value = struct.unpack("<II", self.file.read(8))
        if self.is_valid_data_id(data_id):
            return self.data_id_to_typename(data_id), data_value
        return data_id, data_value

    def _parse_type_id_and_str(self, tag):
        data_id, str_addr = struct.unpack("<II", self.file.read(8))
        data_value = self.lookup_string(str_addr)
        if self.is_valid_data_id(data_id):
            return self.data_id_to_typename(data_id), data_value
        return data_id, data_value

    def _parse_block_device(self, tag):
        name_addr, start_addr, size, _more_info_addr, flags = struct.unpack(
            "<IIIIH", self.file.read(18)
        )
        name = self.lookup_string(name_addr)
        return "BlockDevice", {
            "name": name, "address": start_addr, "size": size, "flags": flags,
        }

    def _parse_named_group(self, tag):
        parent_id, flags, group_tag, group_id, label_addr = struct.unpack(
            "<IHHII", self.file.read(16)
        )
        label = self.lookup_string(label_addr)
        return "NamedGroup", {
            "label": label, "parent": parent_id, "flags": flags,
            "tag": group_tag, "id": group_id,
        }

    def _parse_pins_with_func(self, tag):
        pin_encoding = struct.unpack("<I", self.file.read(4))[0]
        encoding_type = pin_encoding & 0b111
        func = (pin_encoding & 0b1111000) >> 3
        func_name = GPIO_FUNCS.get(func)
        pin_encoding >>= 7
        pins = []
        if encoding_type == 0b001:
            for _ in range(5):
                pins.append(pin_encoding & 0b11111)
                pin_encoding >>= 5
        elif encoding_type == 0b010:
            pin_end = pin_encoding & 0b11111
            pin_start = (pin_encoding >> 5) & 0b11111
            pins = list(range(pin_start, pin_end + 1))
        return "Pins", {pin: {"function": func_name} for pin in pins}

    def _parse_pins_with_name(self, tag):
        pin_mask, name_addr = struct.unpack("<II", self.file.read(8))
        name = self.lookup_string(name_addr)
        pin_no = bin(pin_mask)[::-1].index("1")
        return "Pins", {pin_no: {"name": name}}

    def parse_entry(self, include_tags=("RP", "MP")):
        data_type, tag = struct.unpack("<H2s", self.file.read(4))
        if tag.decode("utf-8", "replace") in include_tags:
            try:
                return self.entry_parsers[data_type](tag)
            except KeyError:
                if self.debug:
                    sys.stderr.write(
                        f"ERROR: No parser for: {self.data_type_to_str(data_type)}\n"
                    )
        return None
