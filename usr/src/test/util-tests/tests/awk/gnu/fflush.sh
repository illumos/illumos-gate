#! /bin/sh

if [ -z "$AWK" ]; then
    printf '$AWK must be set\n' >&2
    exit 1
fi

$AWK 'BEGIN{print "1st";fflush("/dev/stdout");print "2nd"|"cat"}'

$AWK 'BEGIN{print "1st";fflush("/dev/stdout");print "2nd"|"cat"}'|cat

# gawk and nawk differ here: nawk will close stdout, and future writes (by nawk
# or by the cat child) will fail. gawk's child will print "2nd" here, and also
# allow other print statements to succeed.
$AWK 'BEGIN{print "1st";fflush("/dev/stdout");close("/dev/stdout");print "2nd"|"cat"}'|cat

$AWK 'BEGIN{print "1st";fflush("/dev/stdout");print "2nd"|"cat";close("cat")}'|cat

$AWK 'BEGIN{print "1st";fflush("/dev/stdout");print "2nd"|"cat";close("cat")}'|cat

$AWK 'BEGIN{print "1st";fflush("/dev/stdout");print "2nd"|"cat";close("cat")}'|cat

$AWK 'BEGIN{print "1st";fflush("/dev/stdout");print "2nd"|"sort"}'|cat

$AWK 'BEGIN{print "1st";fflush("/dev/stdout");print "2nd"|"sort";close("sort")}'|cat
