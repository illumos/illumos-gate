#!/bin/bash

context=1
if [ "$1" = "-C" ] ; then
    shift
    context=$1
    shift
fi

file=$1
if [[ "$file" = "" ]] ; then
    echo "Usage:  $0 [-C <lines of context>] <file with smatch messages>"
    exit 1
fi

grep 'if();' $file | cut -d ' ' -f1 | while read loc; do
    code_file=$(echo $loc | cut -d ':' -f 1)
    line=$(echo $loc | cut -d ':' -f 2)
    echo "========================================================="
    echo $code_file $line
    tail -n +$(($line - ($context - 1))) $code_file | head -n $(($context - 1))
    if [[ $context -gt 1 ]] ; then
	echo "---------------------------------------------------------"
    fi
    tail -n +${line} $code_file | head -n $context
done

