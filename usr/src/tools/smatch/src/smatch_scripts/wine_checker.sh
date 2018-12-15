#!/bin/bash

function usage {
    echo "Usage:  $0 [--sparse][--valgrind][--debug] path/to/file.c"
    exit 1
}

SCRIPT_DIR=$(dirname $0)
if [ -e $SCRIPT_DIR/../smatch ] ; then
    CMD=$SCRIPT_DIR/../smatch
elif which smatch | grep smatch > /dev/null ; then
    CMD=smatch
else
    echo "Smatch binary not found."
    exit 1
fi
    
POST=""
WINE_ARGS="-p=wine --full-path -D__i386__"

while true ; do
    if [[ "$1" == "--sparse" ]] ; then
	CMD="sparse"
	shift
    elif [[ "$1" == "--valgrind" ]] ; then
	PRE="valgrind"
	shift
    elif [[ "$1" == "" ]] ; then
	break
    else
	if [[ "$1" == "--help" ]] ; then
		$CMD --help
		exit 1
	fi
	if echo $1 | grep -q ^- ; then
		POST="$POST $1"
	else
		break
	fi
	shift
    fi
done

cname=$1
cname=$(echo ${cname/.o/.c})
if [[ "$cname" == "" ]] ; then
    usege
fi
if ! test -e $cname ; then
    usege
fi

oname=$(echo ${cname/.c/.o})
if ! echo $oname | grep .o$ > /dev/null ; then
    usege
fi
rm -f $oname

cur=$(pwd)
file_dir=$(dirname $oname)
o_short_name=$(basename $oname)
cd $file_dir
make CC="$PRE $CMD $POST $WINE_ARGS" $o_short_name
make $o_short_name
cd $cur
