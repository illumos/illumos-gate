#!/bin/bash
#
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy is of the CDDL is also available via the Internet
# at http://www.illumos.org/license/CDDL.
#

#
# Copyright 2010 Chris Love.  All rights reserved.
#


# 
# Test cases for 'tail', some based on CoreUtils test cases (validated
# with legacy Solaris 'tail' and/or xpg4 'tail')
#
PROG=/usr/bin/tail

case $1 in 
    -x)
    	PROG=/usr/xpg4/bin/tail
	;;
    -o)
    	PROG=$2
	;;
    -?)
    	echo "Usage: tailtests.sh [-x][-o <override tail executable>]"
	exit 1
	;;
esac

echo "Using $PROG"

o=`echo -e "bcd"`
a=`echo -e "abcd" | $PROG +2c`
[[ "$a" != "$o" ]] && echo "Fail test 1 - $a"

o=`echo -e ""`
a=`echo "abcd" | $PROG +8c`
[[ "$a" != "$o" ]] && echo "Fail test 2 - $a"

o=`echo -e "abcd"`
a=`echo "abcd" | $PROG -9c`
[[ "$a" != "$o" ]] && echo "Fail test 3 - $a"

o=`echo -e "x"`
a=`echo -e "x" | $PROG -1l`
[[ "$a" != "x" ]] && echo "Fail test 4 - $a"

o=`echo -e "\n"`
a=`echo -e "x\ny\n" | $PROG -1l`
[[ "$a" != "$o" ]] && echo "Fail test 5 - $a"

o=`echo -e "y\n"`
a=`echo -e "x\ny\n" | $PROG -2l`
[[ "$a" != "$o" ]] && echo "Fail test 6 - $a"

o=`echo -e "y"`
a=`echo -e "x\ny" | $PROG -1l`
[[ "$a" != "$o" ]] && echo "Fail test 7 - $a"

o=`echo -e "x\ny\n"`
a=`echo -e "x\ny\n" | $PROG +1l`
[[ "$a" != "$o" ]] && echo "Fail test 8 - $a"

o=`echo -e "y\n"`
a=`echo -e "x\ny\n" | $PROG +2l`
[[ "$a" != "$o" ]] && echo "Fail test 9 - $a"

o=`echo -e "x"`
a=`echo -e "x" | $PROG -1`
[[ "$a" != "$o" ]] && echo "Fail test 10 - $a"

o=`echo -e "\n"`
a=`echo -e "x\ny\n" | $PROG -1`
[[ "$a" != "$o" ]] && echo "Fail test 11 - $a"

o=`echo -e "y\n"`
a=`echo -e "x\ny\n" | $PROG -2`
[[ "$a" != "$o" ]] && echo "Fail test 12 - $a"

o=`echo -e "y"`
a=`echo -e "x\ny" | $PROG -1`
[[ "$a" != "$o" ]] && echo "Fail test 13 - $a"

o=`echo -e "x\ny\n"`
a=`echo -e "x\ny\n" | $PROG +1`
[[ "$a" != "$o" ]] && echo "Fail test 14 - $a"

o=`echo -e "y\n"`
a=`echo -e "x\ny\n" | $PROG +2`
[[ "$a" != "$o" ]] && echo "Fail test 15 - $a"

# For compatibility with Legacy Solaris tail this should also work as '+c'
o=`echo -e "yyz"`
a=`echo -e "xyyyyyyyyyyz" | $PROG +10c`
[[ "$a" != "$o" ]] && echo "Fail test 16 - $a"

o=`echo -e "yyz"`
a=`echo -e "xyyyyyyyyyyz" | $PROG +c`
[[ "$a" != "$o" ]] && echo "Fail test 16a - $a"


# For compatibility with Legacy Solaris tail this should also work as '+l'
o=`echo -e "y\ny\nz"`
a=`echo -e "x\ny\ny\ny\ny\ny\ny\ny\ny\ny\ny\nz" | $PROG +10l`
[[ "$a" != "$o" ]] && echo "Fail test 17 - $a"

o=`echo -e "y\ny\nz"`
a=`echo -e "x\ny\ny\ny\ny\ny\ny\ny\ny\ny\ny\nz" | $PROG +l`
[[ "$a" != "$o" ]] && echo "Fail test 17a - $a"


# For compatibility with Legacy Solaris tail this should also work as '-l'
o=`echo -e "y\ny\ny\ny\ny\ny\ny\ny\ny\nz"`
a=`echo -e "x\ny\ny\ny\ny\ny\ny\ny\ny\ny\ny\nz" | $PROG -10l`
[[ "$a" != "$o" ]] && echo "Fail test 18 - $a"

o=`echo -e "y\ny\ny\ny\ny\ny\ny\ny\ny\nz"`
a=`echo -e "x\ny\ny\ny\ny\ny\ny\ny\ny\ny\ny\nz" | $PROG -l`
[[ "$a" != "$o" ]] && echo "Fail test 18a - $a"

o=`echo -e "c\nb\na"`
a=`echo -e "a\nb\nc" | $PROG -r`
[[ "$a" != "$o" ]] && echo "Fail test 19 - $a"


echo "Completed"

exit 0

# Template for additional test cases
#o=`echo -e ""`
#a=`echo -e "" | $PROG `
#[[ "$a" != "$o" ]] && echo "Fail test  - $a"
