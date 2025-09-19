#!/bin/bash
BIN="$HOME/bin"
EXTDIR="$HOME/.local/share/nautilus-python/extensions"
EASYCRYPTFOLDER="$PWD"
BINFOLDER="~/bin"
EASYCRYPT="easycrypt.py"
NAUTEXTENS="easycrypt-nautilus.py"
EASYCRYPTCONFIG="easycryptconfig.json"


# Create ~/bin if it doesn't exist
if [[ ! -d "$BIN" ]]; then
    echo "Creating directory $BIN"
    mkdir -p "$BIN"
fi

echo "Installing EasyCrypt..."
echo "Creating symlinks for local bin folder"

# Symlink main script and config to ~/bin
ln -sf "${EASYCRYPTFOLDER}/${EASYCRYPT}" "${BINFOLDER}/${EASYCRYPT}"
ln -sf "${EASYCRYPTFOLDER}/${EASYCRYPTCONFIG}" "${BINFOLDER}/${EASYCRYPTCONFIG}"

# Create Nautilus extension directory if it doesn't exist
if [[ ! -d "$EXTDIR" ]]; then
    echo "Creating directory $EXTDIR"
    mkdir -p "$EXTDIR"

fi
echo "Creating symlink for nautilus context menu extension"
# Symlink Nautilus extension script
ln -sf "${EASYCRYPTFOLDER}/nautilus-python/extensions/${NAUTEXTENS}" "${EXTDIR}/${NAUTEXTENS}"
