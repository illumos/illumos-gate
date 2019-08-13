#!/bin/bash

PROJECT=kernel

function usage {
    echo
    echo "Usage:  $0"
    echo "Updates the smatch_data/ directory and builds the smatch database"
    echo
    exit 1
}

if [ "$1" = "-h" ] || [ "$1" = "--help" ] ; then
	usage;
fi

SCRIPT_DIR=$(dirname $0)
if [ -e $SCRIPT_DIR/../smatch -a -d kernel -a -d fs ] ; then
    CMD=$SCRIPT_DIR/../smatch
    DATA_DIR=$SCRIPT_DIR/../smatch_data
else
    echo "This script should be located in the smatch_scripts/ subdirectory of the smatch source."
    echo "It should be run from the root of a kernel source tree."
    exit 1
fi

# If someone is building the database for the first time then make sure all the
# required packages are installed
if [ ! -e smatch_db.sqlite ] ; then
    [ -e smatch_warns.txt ] || touch smatch_warns.txt
    if ! $DATA_DIR/db/create_db.sh -p=kernel smatch_warns.txt ; then
        echo "Hm... Not working.  Make sure you have all the sqlite3 packages"
        echo "And the sqlite3 libraries for Perl and Python"
        exit 1
    fi
fi

BUILD_STATUS=0
$SCRIPT_DIR/test_kernel.sh --call-tree --info --param-mapper --spammy --data=$DATA_DIR || BUILD_STATUS=$?

for i in $SCRIPT_DIR/gen_* ; do
	$i smatch_warns.txt -p=kernel
done

mv ${PROJECT}.* $DATA_DIR

$DATA_DIR/db/create_db.sh -p=kernel smatch_warns.txt

exit $BUILD_STATUS
