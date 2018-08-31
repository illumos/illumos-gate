#!/bin/bash

if [[ -z "$AWK" ]]; then
    printf '$AWK must be set\n' >&2
    exit 1
fi

$AWK 'BEGIN {
	if (ARGV[1]) print 1
	ARGV[1] = ""
	if (ARGV[2]) print 2
	ARGV[2] = ""
	if ("0") print "zero"
	if ("") print "null"
	if (0) print 0
}
{
	if ($0) print $0
	if ($1) print $1
}' 0 1 compare.in
