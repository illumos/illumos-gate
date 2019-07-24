#!/bin/bash

if echo $1 | grep -q '^-p' ; then
    PROJ=$(echo $1 | cut -d = -f 2)
    shift
fi

bin_dir=$(dirname $0)
db_file=$1
if [ "$db_file" == "" ] ; then
    echo "usage: $0 -p=<project> <db_file>"
    exit
fi

test -e  ${bin_dir}/${PROJ}.return_fixes && \
cat ${bin_dir}/${PROJ}.return_fixes | \
while read func old new ; do
    echo "update return_states set return = '$new' where function = '$func' and return = '$old';" | sqlite3 $db_file
done

