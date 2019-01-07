#!/bin/bash

context=6
while true ; do
    if [ "$1" = "-C" ] ; then
	shift
	context=$1
	shift
	continue
    fi
    break
done


file=$1
[ "$file" = "" ] && [ -e err-list ] && file=err-list
if [[ "$file" = "" ]] ; then
    echo "Usage:  $0 [-C <lines>] [-b] [-k] <file with smatch messages>"
    echo "  -C <lines>:  Print <lines> of context"
    exit 1
fi

cat $file | while read line ; do
    code_file=$(echo "$line" | cut -d ':' -f 1)
    lineno=$(echo "$line" | cut -d ' ' -f 1 | cut -d ':' -f 2)
    echo "========================================================="
    echo "$line"
    echo "---"
    tail -n +$(($lineno - ($context - 1))) $code_file | head -n $(($context - 1))
    echo "---------------------------------------------------------"
    tail -n +${lineno} $code_file | head -n $context
done

