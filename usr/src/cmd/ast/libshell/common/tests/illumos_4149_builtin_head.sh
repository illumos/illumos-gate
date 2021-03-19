#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
#

#
# Test whether the builtin head command properly handles files which do
# not have a trailing newline.
#

# test setup
function err_exit
{
	print -u2 -n "\t"
	print -u2 -r ${Command}[$1]: "${@:2}"
	(( Errors++ ))
}
alias err_exit='err_exit $LINENO'

set -o nounset
Command=${0##*/}
integer Errors=0

builtin head tail

t1=`mktemp`
t2=`mktemp`
t3=`mktemp`
if [[ ! -f "$t1" || ! -f "$t2" || ! -f "$t3" ]]; then
	# Don't use the global err _ exit function as the test harness uses
	# calls to that to compute the number of tests present in this file.
	echo "Could not create temporary files"
	rm -f "$t1" "$t2" "$t3"
	exit 1
fi

for f in test{0..4%02d}; do
	echo $f
done | tee $t1 > $t2
printf "nonewline" >> $t2
printf "nonewline" >> $t3

# Standard file, five lines, with trailing newline

[[ $(head -1 $t1) == 'test00' ]] || \
    err_exit "Shell head -1 standard file"

[[ $(head -2 $t1) == $'test00\ntest01' ]] || \
    err_exit "Shell head -2 standard file"

[[ $(head -s 2 -n2 $t1) == $'test02\ntest03' ]] || \
    err_exit "Shell head -s 2 -n 2 standard file"

[[ $(head -5 $t1) == $'test00\ntest01\ntest02\ntest03\ntest04' ]] || \
    err_exit "Shell head -5 standard file"

[[ $(head -10 $t1) == $'test00\ntest01\ntest02\ntest03\ntest04' ]] || \
    err_exit "Shell head -10 standard file"

[[ $(tail -1 $t1) == 'test04' ]] || \
    err_exit "Shell tail -1 standard file"

[[ $(tail -2 $t1) == $'test03\ntest04' ]] || \
    err_exit "Shell tail -2 standard file"

[[ $(tail -10 $t1) == $'test00\ntest01\ntest02\ntest03\ntest04' ]] || \
    err_exit "Shell tail -10 standard file"

# File with a single line, no trailing newline

[[ $(head -1 $t3) == 'nonewline' ]] || \
    err_exit "Shell head -1 one-line file"

[[ $(head -2 $t3) == 'nonewline' ]] || \
    err_exit "Shell head -2 one-line file"

[[ $(tail -1 $t3) == 'nonewline' ]] || \
    err_exit "Shell tail -1 one-line file"

[[ $(tail -2 $t3) == 'nonewline' ]] || \
    err_exit "Shell tail -2 one-line file"

# File with six lines, no trailing newline

[[ $(head -1 $t2) == "test00" ]] || \
    err_exit "Shell head -1 six-line file"

[[ $(head -2 $t2) == $'test00\ntest01' ]] || \
    err_exit "Shell head -2 six-line file"

[[ $(head -s 2 -n2 $t2) == $'test02\ntest03' ]] || \
    err_exit "Shell head -s 2 -n 2 six-line file"

[[ $(head -5 $t2) == $'test00\ntest01\ntest02\ntest03\ntest04' ]] || \
    err_exit "Shell head -5 six-line file"

[[ $(head -6 $t2) == $'test00\ntest01\ntest02\ntest03\ntest04\nnonewline' ]] \
    || err_exit "Shell head -6 six-line file"

[[ $(head -10 $t2) == $'test00\ntest01\ntest02\ntest03\ntest04\nnonewline' ]] \
    || err_exit "Shell head -10 six-line file"

[[ $(tail -1 $t2) == 'nonewline' ]] || \
    err_exit "Shell tail -1 six-line file"

[[ $(tail -2 $t2) == $'test04\nnonewline' ]] || \
    err_exit "Shell tail -2 six-line file"

[[ $(tail -10 $t2) == $'test00\ntest01\ntest02\ntest03\ntest04\nnonewline' ]] \
     || err_exit "Shell tail -10 six-line file"

rm -f "$t1" "$t2" "$t3"

# tests done
exit $Errors
