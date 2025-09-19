#!/bin/bash
BIN="$HOME/bin"
EXTDIR="$HOME/.local/share/nautilus-python/extensions"
EASYCRYPTFOLDER="$PWD"
BINFOLDER="$HOME/bin"
EASYCRYPT="easycrypt.py"
NAUTEXTENS="easycrypt-nautilus.py"
EASYCRYPTCONFIG="easycryptconfig.json"
echo "${PWD}/${EASYCRYPT}" 
echo "${BINFOLDER}/${EASYCRYPT}"
echo "${PWD}/${EASYCRYPTCONFIG}" 
echo "${BINFOLDER}/${EASYCRYPTCONFIG}"
# Create ~/bin if it doesn't exist
if [[ ! -d "$BIN" ]]; then
    echo "Creating directory $BIN"
    mkdir -p "$BIN"
fi

echo "Installing EasyCrypt..."
echo "Creating symlinks for local bin folder"

# Symlink main script and config to ~/bin
ln -s "${PWD}/${EASYCRYPT}" "${BINFOLDER}/easycrypt"
ln -s "${PWD}/${EASYCRYPTCONFIG}" "${BINFOLDER}/${EASYCRYPTCONFIG}"

# Create Nautilus extension directory if it doesn't exist
if [[ ! -d "$EXTDIR" ]]; then
    echo "Creating directory $EXTDIR"
    mkdir -p "$EXTDIR"

fi
echo "Creating symlink for nautilus context menu extension"
# Symlink Nautilus extension script
ln -s "${EASYCRYPTFOLDER}/nautilus-python/extensions/${NAUTEXTENS}" "${EXTDIR}/${NAUTEXTENS}"
