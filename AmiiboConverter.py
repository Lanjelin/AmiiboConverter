#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Takes a .bin, .nfc, an amiibo-id or a .txt with a list of them, as imput
Option to randomize UID
Option to make duplicates
Outputs as .bin or .nfc

Requires decryption keys in same directory for anything but pure bin-nfc conversion

Inspiration:
    https://github.com/Lucaslhm/AmiiboFlipperConverter
    https://gbatemp.net/threads/release-amiibo-bin-serial-changer.464702/

Resources:
    https://www.3dbrew.org/wiki/Amiibo
    https://wiki.gbatemp.net/wiki/Amiibo
    https://www.amiiboapi.com/
    https://hax0kartik.github.io/amiibo-generator/
    https://github.com/socram8888/amiitool
    https://github.com/tobywf/pyamiibo
    https://github.com/turbospok/Flipper-NTAG215-password-converter
"""
import argparse
import logging
import os
import pathlib
import random
import re

from amiibo import AmiiboDump, AmiiboMasterKey, crypto


class AmiiboConverter:
    """
    Takes a .bin, .nfc, or a raw amiibo-id as imput
    Option to randomize UID
    Outputs a .bin or .nfc file

    Requires decryption keys in same directory for anything but pure bin-nfc conversion
    """

    def __init__(self):
        self.mode = []
        self.byte_data = b""
        self.extra_data = b""
        self.parsed_input = []
        self.output_folder = ""
        self.randomize_uid = False
        self.master_keys = self._check_for_keys()

    def _check_for_keys(self) -> bool or str:
        """
        Checks if decryption keys are present.

        :return: False if keys are missing, keys if present
        """
        if os.path.exists("key_retail.bin"):
            with open("key_retail.bin", "rb") as fp_m:
                logging.info("Loaded decryption keys.")
                return AmiiboMasterKey.from_combined_bin(fp_m.read())
        if os.path.exists("unfixed-info.bin"):
            if os.path.exists("locked-secret.bin"):
                with open("unfixed-info.bin", "rb") as fp_d, open(
                        "locked-secret.bin", "rb"
                ) as fp_t:
                    logging.info("Loaded decryption keys.")
                    return AmiiboMasterKey.from_separate_bin(fp_d.read(), fp_t.read())
        logging.info("Didn't detect decryption keys.")
        return False

    def set_mode(self, command: str) -> bool:
        """
        Set the function to run, what to convert from and to

        :param command: The function to run
        :return: True / False depending on supported input
        """
        read, save = command.split("2")
        if read.strip() not in ["id", "bin", "nfc"]:
            return False
        if save not in ["bin", "nfc"]:
            return False
        self.mode = [read, save]
        return True

    def read_file(self, input_path: str) -> bool:
        """
        Read a .bin or .nfc and return the encrypted byte values

        Ensures the returned data is exacly 540 bytes
        Appends zero-values if smaller, truncate if larger

        :param input_path: Path of file to read
        :return: True False
        """
        self.byte_data = b""
        self.extra_data = b""
        input_extension = os.path.splitext(input_path)[1]
        if input_extension == ".nfc":
            with open(input_path, "rt", encoding="utf-8") as fn_r:
                contents = fn_r.readlines()
            hexvalues = ""
            for line in contents:
                if re.search("Page ?[0-9]{1,3}", line):
                    hexvalues += line.split(":")[1].strip().replace(" ", "")
            data = bytes.fromhex(hexvalues)
        elif input_extension == ".bin":
            with open(input_path, "rb") as fb_r:
                data = fb_r.read()
        else:
            data = self._build_from_amiiboid(input_path.strip())
        if not data:
            pass
            # return False
        while len(data) < 540:
            data += bytes(1)
        self.byte_data = data[:540]
        if len(data) > 540:
            self.extra_data = data[540:]
        return True

    def _assemble_nfc(self) -> str:
        """
        Create the string values that a .nfc should contain

        :return: Flipper Compatible string
        """
        pages, page_count = self._make_pages()

        nfc_content = (
            f"Filetype: Flipper NFC device\n"
            f"Version: 2\n"
            f"# Nfc device type can be UID, Mifare Ultralight, Mifare Classic, Bank card\n"
            f"Device type: NTAG215\n"
            f"# UID, ATQA and SAK are common for all formats\n"
            f"UID: {self._get_uid()}\n"
            f"ATQA: 44 00\n"
            f"SAK: 00\n"
            f"# Mifare Ultralight specific data\n"
            f"Signature: {('00 ' * 32).strip()}\n"
            f"Mifare version: 00 04 04 02 01 00 11 03\n"
            f"Counter 0: 0\n"
            f"Tearing 0: 00\n"
            f"Counter 1: 0\n"
            f"Tearing 1: 00\n"
            f"Counter 2: 0\n"
            f"Tearing 2: 00\n"
            f"Pages total: {page_count}\n"
            f"{pages}"
        )

        return nfc_content

    def _calculate_password(self) -> str:
        """
        Calculate the password for Page 133

        :return: Password string
        """
        uid = bytes.fromhex(self._get_uid())

        pwd = []
        pwd_str = ""
        if len(uid) == 7:
            pwd.append(uid[1] ^ uid[3] ^ 0xAA)
            pwd.append(uid[2] ^ uid[4] ^ 0x55)
            pwd.append(uid[3] ^ uid[5] ^ 0xAA)
            pwd.append(uid[4] ^ uid[6] ^ 0x55)
            pwd_str = ' '.join('{:02X}'.format(byte) for byte in pwd)

        return pwd_str

    def _get_uid(self) -> str:
        """
        Get the UID of the byte data, .nfc files needs this

        :return: The UID
        """
        uid = []
        for i in range(3):
            byte = self.byte_data[i: i + 1].hex()
            uid.append(byte)
        for i in range(4, 8):
            byte = self.byte_data[i: i + 1].hex()
            uid.append(byte)

        return " ".join(uid).upper()

    def _make_pages(self) -> [str, int]:
        """
        Convert from bytes into the NTAG Page-based format

        :param data: Encrypted byte values of the Amiibo
        :return: Tuple with string of pages, integer with total pages
        """
        pages = []
        page_count = 0
        page = []
        for i in range(len(self.byte_data)):
            byte = self.byte_data[i: i + 1].hex()
            page.append(byte)
            if len(page) == 4:
                pages.append(f"Page {page_count}: {' '.join(page).upper()}")
                page = []
                page_count += 1

        pages[133] = f"Page 133: {self._calculate_password()}"
        pages[134] = "Page 134: 80 80 00 00"
        return "\n".join(pages), page_count

    def _randomize_uid(self) -> bool:
        """
        Changes the UID in the byte values

        :return: Bool on success
        """
        if not self.master_keys:
            logging.warning("Missing decryption keys!")
            return False
        new_uid = bytes([4] + [random.randint(0, 255) for _ in range(6)])
        dump = AmiiboDump(self.master_keys, self.byte_data)
        dump.unlock()
        dump.uid_bin = new_uid
        dump.lock()
        self.byte_data = dump.data
        return True

    def _build_fresh(self, amiiboid: bytearray) -> bytes:
        """
        Generates a new Amiibo out of (almost) thin air!
        Requires decryption keys available in the same folder as the script

        :param amiiboid: bytearray containing the ID of the Amiibo to make
        :return: A fresh set of byte values of the Amiibo you want
        """
        if not self.master_keys:
            logging.warning("Missing decryption keys!")
            return False
        dump = AmiiboDump(self.master_keys, bytes(540))
        dump.is_locked = False
        dump.uid_bin = bytes([4] + [random.randint(0, 255) for _ in range(6)])
        dump.data[0x009:0x011] = bytearray.fromhex("480fe0f110ffeea5")
        dump.data[0x054:0x05C] = amiiboid
        dump.data[0x208:] = bytearray.fromhex(
            "01000fbf000000045f0000004edbf12880800000"
        )
        dump.lock()
        return dump.data

    def _get_amiiboid(self) -> str:
        """
        Reads the amiibo ID from the data, if able

        :return: String containing id
        """
        dump = self._decrypt(self.byte_data)
        return str(dump[0x054:0x05C].hex())

    def _load_hax0kartik(self) -> bool:
        """
        Reads Amiiboid ID from a .bin loaded from hax0kartik, and Generates a valid Amiibo
        Requires decryption keys available in the same folder as the script

        :return: Bool on success
        """
        if not self.master_keys:
            logging.warning("Missing decryption keys!")
            return False
        dump = AmiiboDump(self.master_keys, self.byte_data)
        self.byte_data = self._build_fresh(dump.data[0x1DC:0x1E4])
        return True

    def _build_from_amiiboid(self, amiiboid: str) -> bytes:
        """
        Prepares the data and runs self._build_fresh
        Generates a new Amiibo out of (almost) thin air!
        Requires decryption keys available in the same folder as the script

        :param amiiboid: string with the ID of the Amiibo you want
        :return: A fresh set of byte values of the Amiibo you want
        """
        if not self.master_keys:
            logging.warning("Missing decryption keys!")
            return False
        if len(amiiboid) < 16:
            logging.warning("Wrong length of input")
            return False
        if "0x" in amiiboid:
            amiiboid = amiiboid.replace("0x", "")
        amiiboid = bytearray.fromhex(amiiboid)
        return self._build_fresh(amiiboid)

    def _encrypt(self, data: bytes) -> bytes:
        """
        Returns encrypted bytes of the input

        :param data: Decrypted byte values
        :return: Encrypted byte values
        """
        if not self.master_keys:
            logging.warning("Missing decryption keys!")
            return False
        dump = AmiiboDump(self.master_keys, data)
        dump.is_locked = False
        dump.lock()
        return dump.data

    def _decrypt(self, data: bytes) -> bytes:
        """
        Returns decrypted bytes of the input

        :param data: Encrypted byte values
        :return: Decrypted byte values
        """
        if not self.master_keys:
            logging.warning("Missing decryption keys!")
            return False
        dump = AmiiboDump(self.master_keys, data)
        dump.unlock()
        return dump.data

    def write_files(self, multi_input: list or None = None, multi: int or None = 0) -> [int, list]:
        """
        Loops through and writes all the data based on what format specified.
        Handles duplicating of files.

        :param multi_input: Input when running recursively
        :param multi: Number of duplicates to make from each input
        :return: Number of files created, list of errors
        """
        if multi_input:
            to_write = multi_input
        else:
            to_write = self.parsed_input
        failed = []
        counter = 0
        for file in to_write:
            logging.debug(f"Parsing {file[0]}")
            if multi > 1:
                multiply = []
                for i in range(0, multi):
                    multiply.append([file[0], file[1] + "_" + str(i + 1).zfill(2)])
                result = self.write_files(multi_input=multiply)
                counter += result[0]
                for fail in result[1]:
                    if fail not in failed:
                        failed.append(fail)
            else:
                try:
                    self.read_file(file[0])
                except TypeError:
                    failed.append("Missing decryption keys!")
                    break
                if self.randomize_uid:
                    try:
                        self._randomize_uid()
                    except crypto.AmiiboHMACTagError:
                        failed.append(f"Failed to randomize UID of {file[0]}!")
                        continue
                if self.mode[1] == "bin":
                    self._write_bin(file)
                if self.mode[1] == "nfc":
                    self._write_nfc(file)
                counter += 1
        return [counter, failed]

    def _write_bin(self, parsed_data: list, truncate=False):
        """
        Writes the byte values to .bin, creates folders if they don't exist

        :param parsed_data: List with source and name
        :param truncate: Whether to strip the extra bytes not used by NTAG215
        """
        if truncate:
            data = self.byte_data
        else:
            data = self.byte_data + self.extra_data
        filename = self._get_save_path(parsed_data)
        with open(filename + ".bin", "wb") as fb_w:
            fb_w.write(data)
        logging.info(f"Wrote to {filename}.bin")

    def _write_nfc(self, parsed_data: list):
        """
        Writes Flipper compatible string to .nfc, creates folders if they don't exist

        :param parsed_data: List with source and name
        :param truncate: Whether to strip the extra bytes not used by NTAG215
        """
        nfc_content = self._assemble_nfc()
        filename = self._get_save_path(parsed_data)
        with open(filename + ".nfc", "wt", encoding="utf-8") as ft_w:
            ft_w.write(nfc_content)
        logging.info(f"Wrote to {filename}.nfc")

    def set_input(self, source: str):
        """
        Recursively scans files and folders, and append source and names to
        self.parsed_input. If mode is set to read from id, it looks for
        a .txt-file, if not found it checks and parses the string as an Amiibo-id

        :param source: Source of the data
        """
        if self.mode[0] == "id":
            if os.path.isfile(source):
                if os.path.splitext(source)[1] == ".txt":
                    with open(source, "rt", encoding="utf-8") as rt_r:
                        lines = rt_r.readlines()
                    for line in lines:
                        if not line.strip():
                            continue
                        try:
                            name, amiibo_id = line.split(":")
                        except ValueError:
                            name, amiibo_id = line, line
                        self.parsed_input.append([amiibo_id.strip(), name.strip()])
            else:
                if len(source) >= 16:
                    try:
                        name, amiibo_id = source.split(":")
                    except ValueError:
                        name, amiibo_id = source, source
                    self.parsed_input.append([amiibo_id.strip(), name.strip()])
        else:
            if os.path.isfile(source):
                if self.mode[0] in os.path.splitext(source)[1]:
                    name = pathlib.Path(source).stem
                    self.parsed_input.append([source, name])
            else:
                for path in os.listdir(source):
                    new_path = os.path.join(source, path)
                    if os.path.isfile(new_path):
                        if self.mode[0] in os.path.splitext(new_path)[1]:
                            name = pathlib.Path(new_path).stem
                            self.parsed_input.append([new_path, name])
                    else:
                        self.set_input(new_path)

    def set_output(self, output_path: str):
        """
        Sets the root folder or file to store the data

        :param output_folder: Root folder to store the files
        """
        # if os.path.splitext(output_path)[1] in [".nfc", ".bin"]:
        if os.path.splitext(output_path)[1] not in [".nfc", ".bin"]:
            # self.name = os.path.splitext(output_path)[0]
        # else:
            self.output_folder = output_path

    def _get_save_path(self, parsed_data: list) -> str:
        """
        Finds the full path of the file to write

        Figures out where to store the new files based on values parsed to set_output
        and names of files / amiiboid.

        :param parsed_data: Parsed input values
        :return: Full path to store output
        """
        if self.mode[0] == "id":
            filename = os.path.join(self.output_folder, parsed_data[1])
            if self.output_folder:
                os.makedirs(self.output_folder, exist_ok=True)
            return filename
        path = os.path.split(parsed_data[0])[0]
        if self.output_folder:
            save_path = (
                pathlib.PurePosixPath(self.output_folder)
                .joinpath(pathlib.Path(*pathlib.Path(path).parts[1:]))
                .as_posix()
            )
            os.makedirs(save_path, exist_ok=True)
            filename = os.path.join(path, parsed_data[1])
        else:
            save_path = path
        return os.path.join(save_path, parsed_data[1])  # , filename, extension


def confirm_prompt(question: str) -> bool:
    """Ask user to confirm"""
    reply = None
    while reply not in ("y", "n"):
        reply = input(f"{question} (y/n): ").lower()
    return reply == "y"


def get_args():
    """Define and get arguments"""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-m",
        "--mode",
        required=True,
        help="Mode to run; bin2bin, bin2nfc, id2bin, id2nfc, nfc2bin, or nfc2nfc.",
    )
    parser.add_argument(
        "-i",
        "--input",
        nargs="*",
        required=True,
        help="Single file or directory tree to convert.",
    )
    parser.add_argument(
        "-o",
        "--output",
        required=False,
        type=pathlib.Path,
        help="Directory or file to save to. Will be created if it doesn't exist. If not specified,"
             " the output will be stored in the same location as the original file.",
    )
    parser.add_argument(
        "-r",
        "--random-uid",
        required=False,
        action="store_true",
        default=False,
        help="Set to randomize UID of the output.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Show extra info: pass -v to see what's going on, pass -vv to get debug info.",
    )
    parser.add_argument(
        "-d",
        "--duplicate-files",
        required=False,
        default=0,
        type=int,
        help="Do you want duplicates?",
    )
    args = parser.parse_args()
    return args


def validate_arguments(args) -> bool:
    """
    Validate arguments
    :return: True if everything checks out
    """
    if ((args.mode in ["bin2bin", "nfc2nfc"]) and not args.output) or (
            (args.mode in ["bin2bin", "nfc2nfc"]) and (str(args.output) in args.input)
    ):
        if not confirm_prompt(
                f"This will overwrite existing files in {args.output}, do you wish to continue?"
        ):
            return False
    if args.output:
        if (len(args.input) > 1) and (os.path.splitext(args.output)[1] in [".nfc", ".bin"]):
            logging.basicConfig(level=logging.ERROR)
            logging.error(f"Unable to write multiple inputs to a single file!")
            return False
    modes = ["bin2bin", "bin2nfc", "id2bin", "id2nfc", "nfc2bin", "nfc2nfc"]
    if args.mode not in modes:
        logging.basicConfig(level=logging.ERROR)
        logging.error(f"{args.mode} is not a valid mode. Supported: {', '.join(modes)}")
        return False
    return True


def main():
    """Parse arguments and run script."""
    args = get_args()
    if not validate_arguments(args):
        return False
    if args.verbose >= 2:
        logging.basicConfig(level=logging.DEBUG)
    elif args.verbose >= 1:
        logging.basicConfig(level=logging.INFO)
    tool = AmiiboConverter()
    tool.set_mode(args.mode)
    for argument in args.input:
        tool.set_input(argument)
    if not tool.parsed_input:
        logging.basicConfig(level=logging.ERROR)
        logging.error(
            f"Mode {args.mode} on input {', '.join(args.input)} returned no valid data."
        )
        return False
    logging.debug(f"Parsed input {tool.parsed_input}")
    if args.output:
        tool.set_output(args.output)
        logging.debug(f"Saving to {args.output}")
    if args.random_uid:
        tool.randomize_uid = True
    if args.duplicate_files:
        tool.randomize_uid = True
        result = tool.write_files(multi=args.duplicate_files)
    else:
        result = tool.write_files()
    if result[1]:
        for error in result[1]:
            logging.warning(error)
    logging.info(f"Saved {result[0]} files.")
    return True


if __name__ == "__main__":
    if main():
        print(f"{'#' * 12} Done! {'#' * 12}")
    else:
        print(f"{'#' * 12} Aborted! {'#' * 12}")
