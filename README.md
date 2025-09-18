# EasyCrypt
EasyCrypt is a Python-based file encryption and decryption tool supporting both GUI (Zenity) and terminal modes. It uses strong cryptography (Fernet/AES) and offers secure file deletion options. Designed for use as a Nautilus script or directly from the command line.


## Features

- Encrypt and decrypt files using password-based Fernet encryption.
- Optional Zenity GUI dialogs for password entry and notifications.
- Secure deletion of original files using shred, dd, or rm.
- Configurable number of overwrite passes for file deletion.
- Auto-detection of encryption/decryption mode.
- Configurable via command-line arguments or JSON config file.
- Suitable for integration as a Nautilus script or terminal use.

## Usage
For easier usage place in a folder called "bin" in your home directory, and then put this in your .bashrc:
alias easycrypt=".~/bin/easycrypt.py"
### Command-Line

"""
sh
python3 easycrypt.py [OPTIONS] INPUT [INPUT ...] [-o OUTPUT | --output OUTPUT]
"""

#### Arguments

- INPUT  
  One or more input files, or - to read from stdin.

- -o, --output OUTPUT
  Optional. Output file or - for stdout; defaults to auto-naming.

#### Options

- --encrypt | --decrypt
  Force encryption or decryption mode (auto-detected by default).

- -p, --password PASSWORD  
  Specify password directly (not recommended for security).

- -c, --config FILE  
  Specify a custom configuration file (JSON).

- --use-zenity  
  Enable Zenity dialogs; use GUI input/output.

- --delete-method METHOD  
  Select overwrite method before deletion: 'shred', 'dd', or 'rm'.

- --shred-passes N  
  Number of times to overwrite file with random data.

- --auto-delete  
  Automatically delete original files after encryption/decryption.

- --help  
  Show help message and exit.

### Example Command-Line Usage

"""
sh
python3 easycrypt.py file1.txt file2.txt
# Uses Zenity dialogs for input/output by default.

python3 easycrypt.py --no-zenity -p mysecret file.txt
# Uses password from command line, disables Zenity dialogs.

python3 easycrypt.py --delete-method dd --shred-passes 3 file.txt
# Overwrites file 3 times with random data using dd before deletion.
"""

### Example Nautilus Script Usage

Place easycrypt.py in ~/.local/share/nautilus/scripts/.  
Select files in Nautilus, right-click, and choose Scripts > easycrypt.py.

## Configuration File

You can use a JSON config file to set defaults for all options.

### Example: GUI/Nautilus Config (gui-config.json)

"""
json
{
    "input_files": [],
    "output_file": [],
    "mode": "",
    "use_zenity": true,
    "delete_method": "shred",
    "shred_passes": 10,
    "auto_overwrite_encrypted": true,
    "auto_delete_originals": true
}
"""

### Example: Terminal Config (terminal-config.json)

"""
json
{
    "input_files": ["file1.txt", "file2.txt"],
    "output_file": "",
    "mode": "encrypt",
    "use_zenity": false,
    "delete_method": "dd",
    "shred_passes": 5,
    "auto_overwrite_encrypted": false,
    "auto_delete_originals": false,
    "password": "yourpassword"
}
"""

## Configuration Options

| Option                   | Type      | Description                                                                                  |
|--------------------------|-----------|----------------------------------------------------------------------------------------------|
| input_files              | list      | List of input files to process                                                               |
| output_file              | string    | Output file name (optional)                                                                  |
| mode                     | string    | "encrypt" or "decrypt" (auto-detected if empty)                                         |
| use_zenity               | bool      | Use Zenity GUI dialogs (true) or terminal (false)                                       |
| delete_method            | string    | File deletion method: "shred", "dd", or "rm"                                          |
| shred_passes             | int       | Number of overwrite passes for deletion                                                      |
| auto_overwrite_encrypted | bool      | Automatically overwrite existing encrypted files                                             |
| auto_delete_originals    | bool      | Automatically delete original files after encryption/decryption                              |
| password                 | string    | Password for encryption/decryption (optional, not recommended to store in config)            |
| config_file              | string    | Path to config file (optional)                                                               |

## Notes

- Passwords passed via command line or stored in config files may be visible in your shell history or process list. 
    Use Zenity dialogs or terminal input (do not pass --password argument and no password configuration option) for better security.
- Encryption or decryption mode is auto-detected; override with --encrypt or --decrypt if needed.
- When used as a Nautilus script, select files and choose 'Scripts > easycrypt.py'.

## Secure Deletion Methods

- **shred**: Overwrites file with random data multiple times and deletes it.
- **dd**: Overwrites file with random data using dd and deletes it.
- **rm**: Deletes file without overwriting (not secure).

## License

MIT License

## Author

EasyCrypt

