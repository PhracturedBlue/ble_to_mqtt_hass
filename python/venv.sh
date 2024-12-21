#!/bin/sh
# On CoreElec, python is compiled with --disable-pyc-build which breaks 'wheel'.
# See: https://bugs.python.org/issue42446
# The fix is to patch wheel after install
# 1st argument is the directory for the venv

if [ "x$1" == "x" ]; then
    VENV=.venv
else
    VENV=$1
fi
python3 -m venv $VENV
$VENV/bin/python3 -m ensurepip --upgrade
sed -i -e 's/if pycompile:/if False and pycompile:/' $VENV/lib/python3.*/site-packages/pip/_internal/operations/install/wheel.py
$VENV/bin/python -m pip install --force-reinstall pip
sed -i -e 's/if pycompile:/if False and pycompile:/' $VENV/lib/python3.*/site-packages/pip/_internal/operations/install/wheel.py

