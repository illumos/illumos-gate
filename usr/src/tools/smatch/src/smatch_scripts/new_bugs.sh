#!/bin/bash

new=$1
old=$2

if [ "$old" = "" ] ; then
    echo "usage:  $0 <new file> <old file>"
    exit 1
fi

#
# If the $old and $new are very similar then we can 
# filter out a lot of bug just by doing a diff.
#
# But the line numbers change quite frequently so
# really we only want to see if the line numbers
# have changed inside the function.
# The 42 in this message:
# file.c +123 some_func(42) warn: blah blah blah
#

IFS="
"
for err in $(diff -u $old $new | cut -b 2- | egrep '(warn|error|warning):') ; do

    # we are only interested in the last chunk.
    # "some_func(42) warn: blah blah blah"
    last=$(echo $err | cut -d ' ' -f 2-)

    # There are some error message which include a second
    # line number so we crudely chop that off.
    last=$(echo $last | sed -e 's/line .*//')

    if ! grep -Fq "$last" $old ; then
	echo $err
    fi
done
