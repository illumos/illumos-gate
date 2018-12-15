#!/bin/bash

# This is a generic script to parse --info output.  For the kernel, don't use
# this script, use build_kernel_data.sh instead.

NR_CPU=$(cat /proc/cpuinfo | grep ^processor | wc -l)
SCRIPT_DIR=$(dirname $0)
DATA_DIR=smatch_data
PROJECT=smatch_generic
TARGET=""

function usage {
    echo
    echo "Usage:  $0"
    echo "Updates the smatch_data/ directory and builds the smatch database"
    echo " -p <project> (default = $PROJECT)"
    echo
    exit 1
}

while true ; do
    if [[ "$1" == "--target" ]] ; then
        shift
        TARGET="$1"
        shift
    elif [ "$1" == "-p" ] || [ "$1" == "--project" ] ; then
        shift
        PROJECT="$1"
        shift
    elif [ "$1" == "--help" ] || [ "$1" = "-h" ] ; then
        usage
    else
        break
    fi
done

if [ -e $SCRIPT_DIR/../smatch ] ; then
    BIN_DIR=$SCRIPT_DIR/../
else
    echo "This script should be located in the smatch_scripts/ subdirectory of the smatch source."
    exit 1
fi

# If someone is building the database for the first time then make sure all the
# required packages are installed
if [ ! -e smatch_db.sqlite ] ; then
    [ -e smatch_warns.txt ] || touch smatch_warns.txt
    if ! $SCRIPT_DIR/../smatch_data/db/create_db.sh -p=$PROJECT smatch_warns.txt ; then
        echo "Hm... Not working.  Make sure you have all the sqlite3 packages"
        echo "And the sqlite3 libraries for Perl and Python"
        exit 1
    fi
fi

make -j${NR_CPU} CHECK="$BIN_DIR/smatch --call-tree --info --param-mapper --spammy --file-output" $TARGET

find -name \*.c.smatch -exec cat \{\} \; -exec rm \{\} \; > smatch_warns.txt

for i in $SCRIPT_DIR/gen_* ; do
        $i smatch_warns.txt -p=${PROJECT}
done

mkdir -p $DATA_DIR
mv $PROJECT.* $DATA_DIR

$SCRIPT_DIR/../smatch_data/db/create_db.sh -p=$PROJECT smatch_warns.txt

