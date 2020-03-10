#! /bin/sh

SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "$SCRIPT")
NEWDIR="$SCRIPTPATH/deps"

mkdir "$NEWDIR"
cd "$NEWDIR"

echo "Getting povsim . . ."
git clone https://github.com/mechaphish/povsim.git
pip install -e povsim

echo "Getting compilerex . . ."
git clone https://github.com/mechaphish/compilerex.git
pip install -e compilerex

echo "Getting fidget . . ."
git clone https://github.com/angr/fidget.git
pip install -e fidget

echo "Getting tracer . . ."
git clone https://github.com/angr/tracer
pip install -e tracer

echo "Done!"
