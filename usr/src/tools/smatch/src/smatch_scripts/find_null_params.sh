#!/bin/bash

file=$1

if [[ "$file" = "" ]] ; then
    echo "Usage:  $0 <file with smatch messages>"
    exit 1
fi

grep " unchecked " $file | cut -d ' ' -f 5- | sort -u > unchecked
grep " undefined " $file | cut -d ' ' -f 5- | sort -u > null_calls.txt
cat null_calls.txt unchecked | sort | uniq -d > null_params.txt
IFS="
"
for i in $(cat null_params.txt) ; do
	grep "$i" $file | grep -w undefined 
done


