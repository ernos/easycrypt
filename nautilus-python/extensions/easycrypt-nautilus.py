#!/usr/bin/env python3

import subprocess
from gi.repository import Nautilus, GObject

class EasyCryptMenuProvider(GObject.GObject, Nautilus.MenuProvider):
    def __init__(self):
        pass
    def get_file_items(self, files):
        # Only show for files
        if len(files) >= 1 and not files[0].is_directory():

            item = Nautilus.MenuItem(
                name="EasyCryptExtension::encrypt_selected_files",
                label="EasyCrypt selected files",
                tip="Encrypt or decrypt selected files with EasyCrypt.",
            )
            item.connect("activate", self.open_files_with_easycrypt, files)
            return [item]
        # Only show for a single folder
        elif len(files) == 1 and files[0].is_directory():
            folder_path = files[0].get_location().get_path()
            item = Nautilus.MenuItem(
                name="EasyCryptExtension::encrypt_folder_files",
                label="Encrypt/Decrypt files in this folder",
                tip="Open a file dialog and select files to encrypt/decrypt with EasyCrypt.",
            )
            item.connect("activate", self.open_with_easycrypt, files[0])
            return [item]
        else:
            return []

    def get_background_items(self, current_folder):
        folder_path = current_folder.get_location().get_path()
        item = Nautilus.MenuItem(
            name="EasyCryptExtension::encrypt_background",
            label="Encrypt files here",
            tip="Open a file dialog and select files to encrypt with EasyCrypt",
        )
        item.connect("activate", self.open_with_easycrypt, current_folder)
        return [item]

    def open_files_with_easycrypt(self, menu, files):
        filepaths = [file.get_location().get_path() for file in files]
        # Call easycrypt with all selected files
        subprocess.Popen(["easycrypt", "--use-zenity"] + filepaths)

    def open_with_easycrypt(self, menu, folder):
        folder_path = folder.get_location().get_path()
        # Call easycrypt with the folder path
        subprocess.Popen(["easycrypt", "--use-zenity", folder_path])