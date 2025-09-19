#!/usr/bin/python3
from asyncio import sleep
from fileinput import filename
from math import e
from re import I
import sys
import subprocess
import os
import hashlib
import base64
import argparse
import json
import configparser
import notify2
import shutil

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

ERROR = 1
WARNING = 2
PASSWORD = 3
DOUBLEPASSWORD = 4
QUESTION = 5
ENTRY = 6
INFO = 7
INFON = 8
INFOZ = 9
DEBUG = 10
DEBUGVERBOSE = 11

# useful emojies: 🔑 ⚠️ ✅ ⛔ ℹ️❓🗃️🔤
__version__ = "1.4"
LoggingLevel = DEBUGVERBOSE
global config
strConfigFile = "easycryptconfig.json"


def zenity_info(msg):
    subprocess.run(
        ["zenity", "--info", "--title=ℹ️EasyCrypt informationℹ️", f"--text={msg}"]
    )
def zenity_error(msg):
    subprocess.run(
        ["zenity", "--error", "--title=⛔EasyCrypt error⛔", f"--text={msg}"]
    )
def zenity_warning(msg):
    subprocess.run(
        ["zenity", "--warning", "--title=⚠️EasyCrypt warning⚠️", f"--text={msg}"]
    )
def zenity_password(msg):
    outl(f"{msg}")

    result = subprocess.run(
        [
            "zenity",
            "--password",
            f"--title=🔑{msg}🔑 "
        ],
        stdout=subprocess.PIPE,
    )
    return result.stdout.decode().strip()
def zenity_question(msg):
    outl(f"{msg}")
    result = subprocess.run(
        ["zenity", "--question", "--title=❓EasyCrypt Question❓", f"--text={msg}"]
    )
    return result.returncode == 0  # 0=yes
def zenity_entry(msg, default=""):
    outl(f"{msg}")
    result = subprocess.run(
        [
            "zenity",
            "--entry",
            "--title=🔤EasyCrypt Entry🔤",
            f"--text={msg}",
            f"--entry-text={default}"
        ],
        stdout=subprocess.PIPE,
    )
    return result.stdout.decode().strip()
def zenity_select_files(start_dir="."):
    result = subprocess.run(
        [
            "zenity",
            "--file-selection",
            "--multiple",
            "--separator=|",
            "--title=🗃️Select files for EasyCrypt🗃️",
            f"--filename={os.path.abspath(start_dir)}/"
        ],
        stdout=subprocess.PIPE,
    )
    # Zenity returns selected files separated by '|'
    files = result.stdout.decode().strip()
    return files.split('|') if files else []
def outl(str, type=DEBUG):
    global config
    global msgtype

    if config["use_zenity"] == True:
        msgtype = "zenity"
    else:
        msgtype = "terminal"

    if LoggingLevel >= type:

        if type >= ERROR and type <= LoggingLevel:

            if type == INFO:
                if msgtype == "zenity":
                    return zenity_info(f"{str}")
                else:
                    print(f"ℹ️Info(Verbose): {str}ℹ️")
                    return
            if type == INFON:
                # print(f"INFO: {str}")
                notmsg = notify2.init("EasyCrypt")
                msg = notify2.Notification(f"EasyCrypt", f"️ℹ️Info ️{str}ℹ️")
                msg.show()
                print(f"ℹ️Info(Notification): {str}ℹ️")
                return
            if type == INFOZ:
                if msgtype == "zenity":
                    zenity_info(f"{str}")
                else:
                    print(f"ℹ️Info: {str}ℹ️")
                return
            if type == DEBUGVERBOSE:
                print(f"INFO: {str}")
                return
            if type == DEBUG:
                print(f"DEBUG: {str}")
                return
            if type == ERROR:
                if msgtype == "zenity":
                    return zenity_error(f"{str}")
                else:
                    print(f"⛔Error: {str}⛔")
            if type == WARNING:
                if msgtype == "zenity":
                    return zenity_warning(f"{str}")
                else:
                    print(f"⚠️Warning: {str}⚠️")
            if type == PASSWORD:
                if msgtype == "zenity":
                    return zenity_password(f"{str}")
                else:
                    return input(f"{str}")
                return password
            if type == DOUBLEPASSWORD:
                while 1:
                    if msgtype == "zenity":
                        tmppass = zenity_password(f"{str}")
                        tmppass2 = zenity_password(f"Enter password again")
                        if tmppass == tmppass2:
                            print(f"✅ Passwords matched continuing...")
                            return tmppass
                        else:
                            zenity_error(f"Passwords do not match! Try again.")
                    else:
                        tmppass = input(f"{str}")
                        tmppass2 = input(f"{str}")
                        if tmppass == tmppass2:
                            return tmppass
                        else:
                            print(f"⛔ Passwords do not match! Try again.⛔", ERROR)
                print(
                    f"⛔Error! User cancelled password entry and password entry recheck. (Two times to minimize encryption mistakes).\n Quitting...⛔",
                    ERROR,
                )
                sleep(5)
                exit
            if type == QUESTION:
                if msgtype == "zenity":
                    return zenity_question(f"{str}")
                else:
                    return input(f"{str}")
            if type == ENTRY:
                if msgtype == "zenity":
                    return zenity_entry(f"{str}")
                else:
                    return input(f"{str}")

        return True
    else:
        return False
def load_config(config_path=strConfigFile):
    if config_path and os.path.exists(config_path):
        with open(config_path, "r") as f:
            return json.load(f)
    return {}
def is_file_encrypted(file_path: str, filemode: bool = True) -> bool:
    """
    Checks if a file is encrypted using the custom Fernet format:
    - First 16 bytes: salt (random)
    - Next bytes: Fernet token (starts with b'gAAAAA')
    - Minimum file size: 32 bytes
    Returns True if file matches expected encrypted format, False otherwise.
    """
    try:
        with open(file_path, "rb") as f:
            salt = f.read(16)
            header = f.read(8)
            # Fernet tokens start with b'gAAAAAB'
        retu = header.startswith(b"gAAAAAB")
        if retu:
            return True
    except Exception:
        outl("❌ Could not check if file is encrypted, No such file", ERROR)
        return False
def decrypt_file(encrypted_path: str, password: str, output_path: str = None):
    global msgtype
    with open(encrypted_path, "rb") as f:
        salt = f.read(16)
        encrypted_data = f.read()

    key = generate_key(password, salt)
    cipher = Fernet(key)

    try:
        decrypted_data = cipher.decrypt(encrypted_data)
    except Exception:
        outl("❌ Decryption failed. Wrong password or corrupted file.", ERROR)
        return

    if output_path.endswith(".enc"):
        # If output_path is given, use it. Otherwise, remove .enc suffix if present.
        output_path = encrypted_path[:-4]

    # Overwrite protection
    if os.path.exists(output_path):
        if not outl(
            f"Decrypted file '{output_path}' already exists. Overwrite?", QUESTION
        ):
            new_name = outl(
                f"Enter new name for decrypted output file:{output_path}", ENTRY
            )
            if new_name and new_name != output_path:
                output_path = new_name
            else:
                outl("❌ No new name given. Aborted.", ERROR)
                return

    with open(output_path, "wb") as f:
        f.write(decrypted_data)

    decrypted_checksum = hashlib.sha256(decrypted_data).hexdigest()
    output_checksum = file_checksum(output_path)
    if decrypted_checksum == output_checksum:
        return (True,
            f"""✅ Checksum verified: decryption integrity OK.✅
            Decrypted file saved as: {os.path.basename(output_path)}""",)
    else:
        outl("❌ Checksum mismatch after decryption! File may be corrupted.", ERROR)
def encrypt_file(origfile: str, password: str, output_path=None) -> {str, str, str}:
    global config
    global msgtype
    origfilesalt = os.urandom(16)
    origfiledata: str = None
    key = generate_key(password, origfilesalt)
    cipher = Fernet(key)
    encrypted_data = None
    origsha256 = None
    with open(origfile, "rb") as f:
        file_data = f.read()

    origsha256 = hashlib.sha256(file_data).hexdigest()
    origfiledata = cipher.encrypt(file_data)

    
    outl(f"Original file{origfile} \tsha256:{origsha256}", DEBUG)

    # Overwrite protection
    dooverwrite = False
    newfilename = origfile + ".enc"
    if os.path.exists(newfilename):
        if config["auto_overwrite"] == False:
            if config["use_zenity"] == True:
                subprocess.run(["shred", "-u", "-n", str(config["shred_passes"]), origfile])
                dooverwrite = True
                newfilename = outl(f"Enter new name for encrypted output file: {newfilename}", ENTRY)

            elif msgtype == "terminal":
                if outl(f"Encrypted file '{newfilename}' already exists. Overwrite?",QUESTION):
                    dooverwrite = True
                    newfilename = outl("Enter name of the new encrypted file:", QUESTION)
                else:
                    outl("Not overwriting and no value inputted, aborting.", WARNING)
        else:
            outl("Config auto_overwrite is true and overwriting original file.",DEBUG)

    try:
        with open(newfilename, "wb") as f:
            f.write(origfilesalt + origfiledata)

        return True, "✅ Encrypted file saved as: " + os.path.basename(newfilename)
    except Exception as e:
        newfilename = None
        outl(f"ERROR: Exception coult not save to new encrypted file: {newfilename} Exception message: {e}",ERROR)

    # Verify by decrypting and checking checksum
    with open(newfilename, "rb") as f:
        salt2 = f.read(16)
        encrypted_data2 = f.read()

    key2 = generate_key(password, salt2)
    cipher2 = Fernet(key2)
    try:
        decrypted_data = cipher2.decrypt(encrypted_data2)
        decrypted_checksum = hashlib.sha256(decrypted_data).hexdigest()
        if decrypted_checksum == origsha256:
            return (
                True,
                "✅ Checksum verified (after encryption and decryption again): encryption integrity OK.",
            )
        else:
            outl("❌ Checksum mismatch after encryption! File may be corrupted.", ERROR)
    except Exception as e:
        outl(f"❌ Could not verify encryption integrity: {e}", ERROR)

    return False, ""
def shred_delete(path):
    if os.path.isfile(path):
        subprocess.run(["shred", "-u", "-n", "3", path])
    elif os.path.isdir(path):
        for root, dirs, files in os.walk(path):
            for f in files:
                subprocess.run(["shred", "-u", "-n", "3", os.path.join(root, f)])
        os.rmdir(path)
def file_checksum(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()
def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))
def file_delete_original(origfile: str) -> bool:
    global config
    """_summary_
    Do whatever checks and things we need to do after encryption/decryption to the original file.
    Checks if user wants to delete it, how he likes to name his files and what programs and methods
    when deleting.
    """
    numpasses = config["shred_passes"]
    wipemethod = config["delete_method"]
    autodelete = config["delete_original"]

    if config['verbose_logging']:
        outl(f"Filename:{origfile} is being deleted with {wipemethod} and {numpasses} passes",DEBUGVERBOSE)
    if autodelete == False:
        outl("Autodelete is turned off", DEBUG)
        return False, ""
    if wipemethod != "shred" and wipemethod != "rm" and wipemethod != "dd":
        outl(f"Unknown wipe method: {wipemethod}", ERROR)
        return False, ""
    if wipemethod == "shred":
        subprocess.run(["shred", "-u", "-n", str(config["shred_passes"]), origfile])
        return True,f"\nOriginal file {os.path.basename(origfile)} has been shredded with {numpasses} passes."

    elif wipemethod == "dd":
        if filewipedata(origfile, numpasses):
            return True, f"{origfile} has been deleted with method dd"
    else:
        try:
            os.remove(origfile)
            return True, f"Original file '{origfile}' deleted with rm as per config."

        except Exception as e:
            outl(f"Could not delete original file: {e}", ERROR)

    return False, ""
def process_file(filepath, password, mode, output, delete_method, shred_passes, filemode=True):
    global config
    origfilename: str = ""
    oldsha256: str = ""
    origfilesalt: bytes = None
    newfilename: str = ""
    boolcrypt = False
    strcrypt = ""
    origfileencrypted = is_file_encrypted(filepath)

    if filepath == "-":
        if config["use_zenity"] == True:
            strdata = zenity_entry("Write the data you want encrypted/decrypted")
            outputfile = zenity_entry("Enter output file name:")
        else:
            strdata = input("Write the data you want encrypted/decrypted: ")
            outputfile = input("Enter output file name:")

        if mode == "encrypt":
            encrypt_string(strdata, password, outputfile)
        elif mode == "decrypt":
            decrypt_string(strdata, password, outputfile)
    else:
        if is_file_encrypted(filepath):
            mode = "decrypt"
        else:
            mode = "encrypt"

        if mode == "encrypt":
            boolcrypt, strcrypt = encrypt_file(filepath, password, output)
        elif mode == "decrypt":
            boolcrypt, strcrypt = decrypt_file(filepath, password, output)

        booldelete, strdelete = file_delete_original(filepath)
    printstr = ""
    if boolcrypt:
        printstr = strcrypt
    if booldelete:
        printstr = printstr + strdelete
    if boolcrypt or booldelete:
        return printstr
def filewipedata(path, passes):
    """Overwrites data in file {path} {passes} times. and deletes it."""
    filesize = os.path.getsize(path)
    for _ in range(passes):
        with open(path, "wb") as f:
            f.write(os.urandom(filesize))
            f.delete()
def merge_args_with_config(args, config):

    # If an argparse value is not None, use it. Otherwise fall back to config.
    merged = {
        "input_files": args.inputs if args.inputs else config.get("input_files", [""]),
        "output_file": (
            args.output if args.output is not None else config.get("output_file")
        ),
        "mode": (
            "encrypt"
            if args.encrypt
            else "decrypt" if args.decrypt else config.get("mode")
        ),
        "password": (
            args.password if args.password is not None else config.get("")
        ),
        "use_zenity": (
            args.use_zenity
            if args.use_zenity is not False
            else config.get("use_zenity")
        ),
        "delete_method": (
            args.delete_method
            if args.delete_method is not None
            else config.get("delete_method")
        ),
        "shred_passes": (
            args.shred_passes
            if args.shred_passes is not None
            else config.get("shred_passes", 6)
        ),
        "config_file": (
            args.config if args.config is not None else config.get(strConfigFile)
        ),
        "auto_overwrite": (config.get("auto_overwrite")),
        "delete_original": (config.get("delete_original")),
        "verbose_logging": (config.get("verbose_logging")),
    }
    return merged

def selectfilesindir(path, default="*"):
    global config
    retfiles = []
    if config['use_zenity']:
        return zenity_select_files(path)
    else:
        all_files = [
            f
            for f in os.listdir(path)
            if os.path.isfile(os.path.join(path, f))
        ]
        files_abs_path = [
            os.path.abspath(os.path.join(path, f))
            for f in os.listdir(path)
            if os.path.isfile(os.path.join(path, f))
        ]
        files = "*. All files in current folder\n"
        for i, filename in enumerate(all_files):
            files += f"{i+1}.{filename}\n"

        selection = outl(
            f"""No input file specified, choose one. Enter full path to file or any file in folder (or corresponding number):
                {path}\n{files}""",
            ENTRY,
        )

        # Try single number selection
        try:
            selectnum = int(selection) - 1
            if 0 <= selectnum < len(files_abs_path):
                outl(f"Selected file is: {all_files[selectnum]} (num:{selectnum+1})", DEBUG)
                return [files_abs_path[selectnum]]
        except ValueError:
            pass

        # If '*' return all files
        if selection.strip() == '*':
            return files_abs_path

        # Check for comma/space separated numbers
        def parse_indices(s):
            # Accepts numbers separated by commas and/or spaces
            parts = [p for p in s.replace(',', ' ').split() if p]
            indices = []
            for part in parts:
                if part.isdigit():
                    idx = int(part) - 1
                    if 0 <= idx < len(files_abs_path):
                        indices.append(idx)
            return indices

        indices = parse_indices(selection)
        if indices:
            selected_files = [files_abs_path[i] for i in indices]
            outl(f"Selected files: {selected_files}", DEBUG)
            return selected_files

        # If user entered a path, check if it's a file
        if os.path.isfile(selection.strip()):
            return [os.path.abspath(selection.strip())]

        outl(f"{selection} is not a valid selection!", ERROR)
        return []
def passwordcheck(mode):
    global config
    """Only ask for password once"""
    # Password
    if config["password"]:
        password = config["password"]
    else:
        if mode == "encrypt":
            password = outl(f"Encryption password",DOUBLEPASSWORD)
        else:
            password = outl(f"Decryption password", PASSWORD)

    return password

def main():
    # Load config file if specified
    parser = argparse.ArgumentParser(
        description="""
        Encrypt or decrypt files securely, with optional Zenity GUI or terminal interaction.
        By default, the script uses Zenity dialogs for password entry and notifications, making it ideal for integration as a Nautilus script (place in ~/.local/share/nautilus/scripts).

        You can also use the script directly from the terminal or in other automation contexts, with options to disable Zenity and control input/output methods.
        It will read the default configuration file config.json in the same directory as this file.
        Arguments below will override configuration file settings.

        Usage:
            python3 crypt.py INPUTS [INPUTS ...] [-o OUTPUT | --output OUTPUT] [OPTIONS]

        Required arguments:
        [INPUTS]                            One or more input files, or '-' to read from stdin.
        [OPTIONS] (Optional arguments):
        -h, --help                          show this help message and exit
        -o OUTPUT, --output OUTPUT          Output file, or '-' for stdout. Defaults to auto-naming.
        --encrypt                           Force encryption mode. 
                                                (Optional, will detect if file is encrypted or not even if file type is incorrect.)
        --decrypt                           Force decryption mode. 
                                                (Optional, will detect if file is encrypted or not even if file type is incorrect.)
        -p PASSWORD, --password PASSWORD    Password for encryption/decryption.
        -c CONFIG, --config CONFIG          Path to custom configuration file.
        -z, --use-zenity                    Disable Zenity dialogs; use terminal input/output.
        -m {shred,dd,rm}, 
            --delete-method {shred,dd,rm}   Overwrite method before deletion.
        -n SHRED_PASSES, 
            --shred-passes SHRED_PASSES     Number of times to overwrite old files with random data. If you decrypt a file, this setting will write /dev/urandom over the original unencrypted file and then automatically remove it if argument --auto-delete or configuration variable delete_original in config.json is set to true.
        -d, --auto-delete                   Chooses if original file should be automatically deleted or not after encryption/decryption
        -v, --version                       Show program's version number and exit.

        Examples:
        easycrypt file1.txt file2.txt
            # Uses Zenity dialogs for input/output by default.

        easycrypt --no-zenity -p mysecret file.txt
            # Uses password from command line, disables Zenity dialogs.

        easycrypt --delete-method dd --shred-passes 3 file.txt
            # Overwrites file 3 times with random data using dd before deletion.

        easycrypt --help
        
        Notes:
        - Passwords passed via command line may be visible in your shell history and process list.
        - Encryption or decryption mode is auto-detected; override with --encrypt or --decrypt if needed.
        - When used as a Nautilus script, select files and choose 'Scripts > crypt.py'.

        Credits:
        ©️ Copyright 2025 Maximilian Cornett ©️
        📨 max.cornett@gmail.com 📨
        """,formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("inputs", nargs="*", 
                        help="Input file(s), or '-' to read from stdin.")
    parser.add_argument("-o","--output",
        help="Output file, or '-' for stdout. Defaults to auto-naming.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--encrypt", action="store_true", 
        help="Force encryption mode. (Optional, will detect if file is encrypted or not even if file type is incorrect.)")
    group.add_argument("--decrypt", action="store_true", 
        help="Force decryption mode. (Optional, will detect if file is encrypted or not even if file type is incorrect.)")
    parser.add_argument("-p", "--password", 
        help="Password for encryption/decryption.")
    parser.add_argument("-c","--config",default=strConfigFile,
        help="Path to custom configuration file.")
    parser.add_argument("-z", "--use-zenity",action="store_true",
        help="Disable Zenity dialogs; use terminal input/output.")
    parser.add_argument("-m", "--delete-method",choices=["shred", "dd", "rm"],default="shred",
        help="Overwrite method before deletion.")
    parser.add_argument("-n", "--shred-passes",type=int,default=5,
        help="Number of times to overwrite old files with random data. If you decrypt a file, this setting will write /dev/urandom over the original unencrypted file and then automatically remove it if argument --auto-delete or configuration variable delete_original in config.json is set to true.")
    parser.add_argument("-d", "--auto-delete",action="store_true",default=False,
        help="Chooses if original file should be automatically deleted or not after encryption/decryption")
    parser.add_argument("--verbose",action="store_true",
        help="Verbose logging")
    parser.add_argument("-v", "--version",action="version",
        version=f"""EasyCrypt v{__version__}
        Copyright ©️ 2025 Maximilian Cornett Email: 📧 max.cornett@gmail.com""",
        help="Show program's version number and exit.")
    args = parser.parse_args()

    if args.config:
        configfile = load_config(args.config)


    # Merge args and config, command-line args take precedence
    global config
    global msgtype
    config = merge_args_with_config(args, configfile)

    if config["use_zenity"]:
        msgtype = "zenity"
    elif config["use_zenity"] == False:
        msgtype = "terminal"
    else:
        msgtype = "none"
    print("Final merged configuration:")
    for k, v in config.items():
        outl(f"{k}: {v}")
    # Ensure shred_passes is always an integer
    shred_passes = config["shred_passes"]
    if isinstance(shred_passes, dict):
        shred_passes = shred_passes.get("Value", 1)



    numfiles = len(config["input_files"])
    if numfiles == 0:        
        """
        If no input files are specified, get files from current working directory, print then to user and ask him which one he wants to choose.
        """
        config["input_files"].append(os.getcwd())
        numfiles=1
    
    if numfiles > 0:
        if os.path.isdir(config["input_files"][0]) and numfiles == 1:
            """
            If only one 'file' is input and it is a directory, open select files dialog box
            """
            currentworkingdirectory = config["input_files"][0]
            if config['verbose_logging']:
                outl(f"{currentworkingdirectory}", INFO)
            selection = selectfilesindir(currentworkingdirectory)          
            for curpath in selection:
                if os.path.isfile(curpath):
                    print(f"Appending file:{curpath}")
                    config["input_files"].append(curpath)
                else:
                    print(f"Error not a file:{curpath}")  
        else:
            if config['verbose_logging']:
                outl(f"Loaded {numfiles} input files, starting with: {config['input_files'][0]}",INFO)

        

            
    # Loop over input files or input string(s)
    curcount = 0
    password = ""
    filemode = True  # set to false when we send a string to process_file function instead of file.
    
    numfiles = len(config['input_files'])
    
    if numfiles > 0:
        printstr = ""
        for curfilein in config["input_files"]:
            
            outl(f"working on file: {curfilein}")
            if (not os.path.isfile(curfilein) and curfilein == "-") or len(curfilein) < 1:
                outl(f"File not found: {curfilein}. Assuming STDIN", ERROR)
                filemode = False
                tmpdata = outl(
                    "We will take a string input from you now. Go ahead...", QUESTION
                )
                if not config['use_zenity']:
                    tmpdata = input("We will take a string input from you now. Go ahead...")
                    curfilein = tmpdata
                    filemode = False
                mode = config["mode"] if config["mode"] else "encrypt"
                if password == "":
                    password = passwordcheck(mode)
            elif os.path.isfile(curfilein):

                filemode = True
                if is_file_encrypted(curfilein):
                    mode = "decrypt"
                else:
                    mode = "encrypt"
                if password == "":
                    password = passwordcheck(mode)
                printstr = printstr + "\n\n" + process_file(
                    curfilein,
                    password,
                    mode,
                    curfilein,
                    config["delete_method"],
                    shred_passes,
                    filemode,
                )
        outl(f"{printstr}", INFO)

    else:
        outl(f"No files selected! Nothing to do.", ERROR)

if __name__ == "__main__":

    # with open("output.txt", "w") as f:
    #    f.write(sys.argv[0])
    main()
