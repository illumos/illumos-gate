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
# Copyright 2019 Alexander Pyhalov
#

CHOWN=${CHOWN:=/usr/bin/chown}
FILEDIR=/opt/util-tests/tests/files

fail() {
	echo $1
	exit -1
}

create_test_hier() {
	mkdir -p $1/src $1/dst
	touch $1/target
	touch $1/file
	touch $1/dst/file1
	touch $1/src/file2
	ln -s ../target $1/src/tlink
	ln -s ../dst $1/src/dstlink
	ln -s target $1/tlink
}

SUCCESSFLAGS="
-f
-h
-fhR
-R
-RH
-RP
-RL
-Rh
-RHL
-RPH
-RLP"

FAILFLAGS="-RPh
-RLh
-RHh
-P
-H
-L"

NEWOWNER=daemon

# We set PATH to /bin to try get ksh chown builtin
# and to ensure that /usr/bin/chown is used instead.
export PATH=/bin

# We want unified output from tools
export LC_ALL=en_US.UTF-8

i=0
echo "$SUCCESSFLAGS" | while read flags; do
	print -n "test $i: chown $flags: "
	TD=$(mktemp -d  -t)
	if [ -d "$TD" ]; then
		create_test_hier $TD
		chown $flags $NEWOWNER $TD/src   || fail "chown $flags $NEWOWNER $TD/src failed on exit"
		chown $flags $NEWOWNER $TD/tlink || fail "chown $flags $NEWOWNER $TD/tlink failed on exit"
		chown $flags $NEWOWNER $TD/file  || fail "chown $flags $NEWOWNER $TD/file failed on exit"
		(cd $TD ; find . -ls |\
			awk ' { print $3 " " $5 " " $11 }'|\
			sort -k 3 > /tmp/out.$$)
		if [ -n "$(diff /tmp/out.$$ $FILEDIR/cout$i)" ]; then
			print "$(diff -u /tmp/out.$$ $FILEDIR/cout$i)"
			fail "result is different"
		fi
		echo "passed"
		rm -fr $TD /tmp/out.$$
	else
		fail "couldn't create $TD"
	fi
	((i++))
done

echo "$FAILFLAGS" | while read flags; do
	print -n "test $i: chown $flags: "
	TD=$(mktemp -d  -t)
	if [ -d "$TD" ]; then
		create_test_hier $TD
		chown $flags $NEWOWNER $TD/file && fail "chown $flags $NEWOWNER $TD/file should have failed"
		echo "passed"
		rm -fr $TD
	else
		fail "couldn't create $TD"
	fi
	((i++))
done
