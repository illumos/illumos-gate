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
# Copyright 2020 Peter Tribble.
# Copyright 2020 Oxide Computer Company
#

XGREP=${XGREP:=/usr/bin/grep}
FILEDIR=$MY_TESTS/tests/files/grep
OUTFILE=/tmp/grep_test.out.$$
FLAGSFILE=/tmp/grep_flags.$$

#
# Set the tests to a known multi-byte locale to start with.
#
export LC_ALL=C.UTF-8

fail() {
	echo $1
	exit -1
}

test_fail() {
	echo "$*"
	((failures++))
}

#
# Run through a set of tests once for each value in $FLAGSFILE. Arguments are:
# - expected exit status
# - the file pass this is
# - the remaining arguments to grep
#
run_tests() {
	i=0
	exp=$1
	shift
	pass=$1
	shift

	echo "$FLAGS" > $FLAGSFILE
	while read flags; do
		difffile="gout.$pass.$i"
		print -n "test $total: grep $flags: "
		((total++))
		((i++))
		$XGREP $flags "$@" > $OUTFILE
		err=$?
		if [[ $err -ne $exp ]]; then
			test_fail "failed on exit: $err"
			continue
		fi

		if [[ $exp -eq 0 ]]; then
			if [[ ! -f "$difffile" ]]; then
				test_fail "missing output file $difffile"
				continue
			fi

			if [[ -n "$(diff $OUTFILE $difffile)" ]]; then
				print "$(diff $OUTFILE $difffile)"
				test_fail "output is different from $difffile"
				continue
			fi
		fi
		echo "passed"
	done < $FLAGSFILE
}

run_tests_stdin() {
	i=0
	exp=$1
	pass=$2
	pattern=$3
	file=$4

	echo "$FLAGS" > $FLAGSFILE
	while read flags; do
		difffile="gout.$pass.$i"
		print -n "test $total: grep (stdin) $flags: "
		((total++))
		((i++))
		$XGREP $flags $pattern < $file > $OUTFILE
		err=$?
		if [[ $err -ne $exp ]]; then
			test_fail "failed on exit: $err"
			continue
		fi

		if [[ $exp -eq 0 ]]; then
			if [[ ! -f "$difffile" ]]; then
				test_fail "missing output file $difffile"
				continue
			fi

			if [[ -n "$(diff $OUTFILE $difffile)" ]]; then
				print "$(diff $OUTFILE $difffile)"
				test_fail "output is different"
				continue
			fi
		fi
		echo "passed"
	done < $FLAGSFILE
}
total=0
failures=0

FLAGS="
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
-vcC 5 -B 4 -A 2
-b
-bh
-bn
-bnh
-ib
-ibnH
-b -C 1
-bn -C 1
-o
-no
-cno
-bo
-bno
-cbno
-ho
-xo
-o -C 3"

cd $FILEDIR || fail "failed to cd to $FILEDIR"

#
# Test Pass 1: General flags with a basic pattern, checked against all
# three primary forms of grep: grep, egrep, and fgrep. We do this in two
# different passes. In one we're in a default multi-byte locale and in
# the other we're in a single-byte locale. This ensures that we get
# basic coverage of the use_bmg path in grep.
#
run_tests 0 t1 a test0 test1 test2 test3 test4 test5 test6 test7
run_tests 0 t1 -E a test0 test1 test2 test3 test4 test5 test6 test7
run_tests 0 t1 -F a test0 test1 test2 test3 test4 test5 test6 test7
export LC_ALL=C
run_tests 0 t1 a test0 test1 test2 test3 test4 test5 test6 test7
run_tests 0 t1 -E a test0 test1 test2 test3 test4 test5 test6 test7
run_tests 0 t1 -F a test0 test1 test2 test3 test4 test5 test6 test7
export LC_ALL=C.UTF-8

FLAGS="-nE"
run_tests 0 t2 ".*" testnl

FLAGS="-B 1
-vA 1
-vB 1"
run_tests 0 t3 a testnl

FLAGS="-h
-H"
run_tests 0 t4 a test0

# need a directory with predictable contents
rm -fr /tmp/test0
mkdir /tmp/test0
cp test0 /tmp/test0

FLAGS="-r
-hr"
run_tests 0 t5 a /tmp/test0
rm -rf /tmp/test0

#
# Test Group 6: Test -l and -L which are supposed to match the file or
# not. We break this into cases that should always pass and those that
# should fail. The first group should always pass.
#
FLAGS="-l
-L
-il
-vl
-vil
-hl
-hL
-Hl
-HL
-cl
-cL
-nl
-nL
-l -A5 -B5
-L -C5
-nHvl
-l -L -l
-L -l
-l -L
-L -l -L"
run_tests 0 t6 foo test.lL.0 test.lL.1

#
# Test Group 7: -l and -L variants that should cause us to not match or
# fail for another reason.
#
FLAGS="-vL
-viL
-nHvL"
run_tests 1 t7 foo test.lL.0 test.lL.1

#
# Test Group 8, 9: Here we are testing the ability for --label to
# properly replace the name of a file from standard in, but not
# replacing that of a file that's normally specified. Set 8 verifies the
# former while set 9 verifies the latter.
#
FLAGS="-H
-H --label=zelda
--label=zelda
-h --label=zelda
-n --label=zelda
-H -n --label=zelda"
run_tests_stdin 0 t8 a test0
run_tests 0 t9 a test0

#
# Test group 10, using multiple regexps.
#
FLAGS="-o
-E -o
-o -n
-E -o -n
-o -n -b
-E -o -n -b
-E -o -n -H
-E -o -n -H -b"
run_tests 0 t10 -e '[fF]oo' -e 's[df]+;' test.o.0

#
# Test group 11, using multibyte files.
#
OLDLOC=$LC_ALL
export LC_ALL=C.UTF-8
FLAGS="
-o
-n
-n -o
-H -n -o
-l
-c"
run_tests 0 t11 -e ï -e à test.mb.0
export LC_ALL=$OLDLOC

#
# Clean up temporary files.
#
rm -f $FLAGSFILE $OUTFILE

if [[ "$failures" -ne 0 ]]; then
	printf "%u tests failed\n" "$failures" 2>&1
	exit -1
fi
exit 0
