#!/bin/bash
mkdir ~/bin
git clone https://github.com/ernos/easycrypt.git
ln -s $PWD/easycrypt/easycrypt.py ~/bin/easycrypt
ln -s $PWD/easycrypt/easycryptconfig.json ~/easycryptconfig.json