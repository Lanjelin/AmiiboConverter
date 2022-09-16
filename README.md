# AmiiboConverter

Convert, duplicate, randomize. A tool for amiibo.

## What can it do?

Reads .bin or .nfc-files, amiibo ID directly, or as a list from a .txt-file, and outputs it as a .bin or .nfc-file.

Does recursive scan of folders, where it outputs the new files in the same directory, or a new with the same folder structure.

Option to randomize UID, and make multiple outputs of the same source-file (for games like BOTW).

## How to do it?

Run the script from the terminal, passing the following arguments:  
`-m` required: mode to run, bin2bin, bin2nfc, id2bin, id2nfc, nfc2bin, or nfc2nfc. multiple files or strings can be parse at the same time, separated by space.  
`-i` required: path, file or string to parse as input.  
`-o` optional: path or file to write the output.  
`-r` optional: randomize UID of the output.  
`-d` optional: number of copies to write (`-r` is automatic set when running this).  
`-v` optional: display more info when running, `-vv` for even more info.  
`-h` display the help text.

**examples:**  
`python AmiiboConverter.py -m bin2nfc -i bin -o nfc` will convert all .bin-files found in the folder ./bin, convert them to .nfc, and store them in a folder called ./nfc  
`python AmiiboConverter.py -m id2bin -i id.txt -d 3` will take all the amiibo ID found in id.txt, and make 3 new .bin-files (with random UID) per ID found.

When inputing amiibo ID, filename can be set by adding name and a semicolon before the ID. Like `Luigi:0x00010000...` or `Daisy:00130000037a..`, same goes for .txt-files, where one ID per line applies as well. If no name is added, the ID will be used as filename.

## What does it require?

Python 3.8 or newer

You need the libraries in `requirements.txt`, install them using something like `python -m pip install -r requirements.txt`

For anything but pure bin-to-nfc / nfc-to-bin conversion, you need the correct decryption keys in the same folder as the script, these are files commonly called `unfixed-info.bin` and `locked-secret.bin`. A merged version of these files called `key_retail.bin` can also be used. These files are not provided.

## A small warning at the end!

Keep a backup of your source files, whether it be .bin or .nfc. This tool can overwrite your files. Generated files with a random UID are working at the moment, but they may not work in the future.

## Disclaimer

AmiiboConverter is intended for educational and archival purposes only, please only use this tool on amiibo™ you already own.
AmiiboConverter is not affiliated, associated, authorized, endorsed by, or in any way officially connected with Nintendo. No amiibo™ or digital representations of amiibo™ are included in this project.

## License

AmiiboConverter is released under the GNU General Public License v3.0 License. See the LICENSE file for further details.
