# EasyCrypt

EasyCrypt is a Python-based tool for secure file encryption and decryption, supporting both Zenity GUI dialogs and terminal interaction. It is designed for easy integration as a Nautilus script or direct command-line use, with flexible configuration via command-line arguments or a JSON config file.

---

## Description

Encrypt or decrypt files securely, with optional Zenity GUI or terminal interaction.  
By default, EasyCrypt uses Zenity dialogs for password entry and notifications, making it ideal for integration as a Nautilus script (place in `~/.local/share/nautilus/scripts` together with your config.json file (use_zenity=True)).
There is also a separate nautilus extension script that adds an item to the nautilus context menu. For this to work you make the file executable and add it to you PATH environment variable (or just put it into /usr/bin if you have root access).
Installing without root access from any folder:
```
git clone https://github.com/ernos/easycrypt.git
mkdir ~/bin
ln -s $PWD/easycrypt/easycrypt ~/bin/easycrypt
ln -s $PWD/easycrypt/easycrypt-config.json ~/bin/easycrypt-config.json
#For installing nautilus extension:
#if your $PATH env does not have your /home/x/bin you need to run these two commands as well:
echo 'PATH="$HOME/bin:$PATH"' >> .bashrc
source .bashrc
```
You can also use the script directly from the terminal or in automation contexts, with options to disable Zenity and control input/output methods.  
EasyCrypt reads the default configuration file `config.json` in the same directory as the script. Command-line arguments override configuration file settings.

---

## Usage

```sh
python3 easycrypt.py INPUTS [INPUTS ...] [-o OUTPUT | --output OUTPUT] [OPTIONS]
```

### Required Arguments

- **INPUTS**  
  One or more input files, or `-` to read from stdin.

### Optional Arguments

- -o, --output OUTPUT       Output file or `-` for stdout; defaults to auto-naming.
- --encrypt | --decrypt     Force encryption or decryption mode (usually auto-detected).

- **-p, --password PASSWORD**  
  Specify password directly (not recommended for security).

- **-c, --config FILE**  
  Specify a custom configuration file.

- **-z, --use-zenity**  
  Enable interactive Zenity dialogs in your X window manager. If not specified, uses terminal for stdin/stdout.

- **-m, --delete-method METHOD**  
  Select overwrite method before deletion: `'shred'`, `'dd'`, or `'rm'`.

- **-n, --shred-passes N**  
  Number of times to overwrite file with random data.

- **-d, --auto-delete**  
  Automatically delete original file after encryption/decryption.

- **-v, --version**  
  Show program's version number and exit.

- **-h, --help**  
  Show this help message and exit.

---

## Examples

```sh
python3 easycrypt.py file1.txt file2.txt
# Uses Zenity dialogs for input/output by default.

python3 easycrypt.py --no-zenity -p mysecret file.txt
# Uses password from command line, disables Zenity dialogs.

python3 easycrypt.py --delete-method dd --shred-passes 3 file.txt
# Overwrites file 3 times with random data using dd before deletion.

python3 easycrypt.py --help
# Show help message.
```

---

## Notes

- Passwords passed via command line may be visible in your shell history and process list.
- Encryption or decryption mode is auto-detected; override with `--encrypt` or `--decrypt` if needed.
- When used as a Nautilus script, select files and choose 'Scripts > easycrypt.py'.

---

## Credits

©️ Copyright 2025 Maximilian Cornett  
📨 max.cornett@gmail.com 📨

---
