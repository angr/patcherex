#!/bin/bash

if [ -L $0 ] ; then
    DIR=$(dirname $(readlink -f $0)) ;
else
    DIR=$(dirname $0) ;
fi ;

if [ "$#" -lt 1 ]; then
    echo "clang as an assembler"
    echo "usage $0 <clang commands>";
    exit 1
fi

export CC=$DIR/../bin/clang
export LD=$DIR/../bin/ld
export CXX=$DIR/../bin/clang++
export OBJCOPY=$DIR/../bin/objcopy

export PATH="$DIR/../bin:$PATH"

function assemble() {
    #LDFLAGS="-nostdlib -static -Wl,-m$output_type $LDFLAGS"
    $CC "$@" ;
}

assemble "$@"
