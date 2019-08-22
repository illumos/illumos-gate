#!/bin/bash

if [[ -z "$AWK" || -z "$WORKDIR" ]]; then
    printf '$AWK and $WORKDIR must be set\n' >&2
    exit 1
fi

TEMP1=$WORKDIR/test.temp.1
TEMP2=$WORKDIR/test.temp.2
TEMP3=$WORKDIR/test.temp.3

# This is a demo of different ways of printing with gawk.  Try it
# with and without -c (compatibility) flag, redirecting output
# from gawk to a file or not.  Some results can be quite unexpected. 
$AWK 'BEGIN {
	print "Goes to a file out1" > "'$TEMP1'"
	print "Normal print statement"
	print "This printed on stdout" > "/dev/stdout"
	print "You blew it!" > "/dev/stderr"
}' > $TEMP2 2> $TEMP3

diff out1.ok $TEMP1 \
    && diff out2.ok $TEMP2 \
    && diff out3.ok $TEMP3 \
    && rm -f $TEMP1 $TEMP2 $TEMP3
