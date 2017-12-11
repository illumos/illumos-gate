#! /usr/bin/ksh
#
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
# Copyright 2017 Nexenta Systems, Inc. All rights reserved.
#

XGREP=${XGREP:=/usr/xpg4/bin/grep}
FILEDIR=$MY_TESTS/tests/files

fail() {
	echo $1
	exit -1
}

FLAGLIST="
-n
-c
-q
-v
-nv
-vc
-A 5
-nA 5
-cA 5
-qA 5
-vA 5
-nvA 5
-vcA 5
-B 5
-nB 5
-cB 5
-qB 5
-vB 5
-nvB 5
-vcB 5
-C 5
-nC 5
-cC 5
-qC 5
-vC 5
-nvC 5
-vcC 5
-B 5 -A 2
-nB 5 -A 2
-cB 5 -A 2
-qB 5 -A 2
-vB 5 -A 2
-nvB 5 -A 2
-vcB 5 -A 2
-B 5 -A 2 -C 5
-nB 5 -A 2 -C 5
-cB 5 -A 2 -C 5
-qB 5 -A 2 -C 5
-vB 5 -A 2 -C 5
-nvB 5 -A 2 -C 5
-vcB 5 -A 2 -C 5
-5
-n -5
-c -5
-q -5
-v -5
-nv -5
-vc -5
-50000
-n -50000
-c -50000
-q -50000
-v -50000
-nv -50000
-vc -50000
-C 5 -B 4 -A 2
-nC 5 -B 4 -A 2
-cC 5 -B 4 -A 2
-qC 5 -B 4 -A 2
-vC 5 -B 4 -A 2
-nvC 5 -B 4 -A 2
-vcC 5 -B 4 -A 2"

echo "$FLAGLIST" > /tmp/flags

cd $FILEDIR

i=0
while read flags; do
	print -n "test $i: grep $flags: "
	$XGREP $flags a test0 test1 test2 \
	    test3 test4 test5 test6 \
	    test7 > out
	err="$?"
	if [[ $err -ne 0 ]]; then
		fail "failed on exit: $err"
	elif [ -n "$(diff out gout$i)" ]; then
		print "$(diff out gout$i)"
		fail "output is different"
	fi
	echo "passed"
	((i++))
done < /tmp/flags

FLAGS2="-nE"

echo "$FLAGS2" > /tmp/flags

while read flags; do
	print -n "test $i: grep $flags: "
	$XGREP $flags ".*" testnl > out
	err="$?"
	if [[ $err -ne 0 ]]; then
		fail "failed on exit: $err"
	elif [ -n "$(diff out gout$i)" ]; then
		print "$(diff out gout$i)"
		fail "output is different"
	fi
	echo "passed"
	((i++))
done < /tmp/flags

FLAGS3="-B 1
-vA 1
-vB 1"

echo "$FLAGS3" > /tmp/flags

while read flags; do
	print -n "test $i: grep $flags: "
	$XGREP $flags a testnl > out
	err="$?"
	if [[ $err -ne 0 ]]; then
		fail "failed on exit: $err"
	elif [ -n "$(diff out gout$i)" ]; then
		print "$(diff out gout$i)"
		fail "output is different"
	fi
	echo "passed"
	((i++))
done < /tmp/flags
