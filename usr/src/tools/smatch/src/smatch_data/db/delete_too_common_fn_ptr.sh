#!/bin/bash

db_file=$1

IFS="|"
echo "select count(function), function from function_ptr group by function;" | \
    sqlite3 $db_file  | sort -n | tail -n 100 | \

while read cnt func ; do
    if [ $cnt -lt 200 ] ; then
        continue
    fi
    echo "delete from function_ptr where function = '$func';" | sqlite3 $db_file
done
