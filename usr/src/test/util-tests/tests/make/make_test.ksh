#!/usr/bin/ksh
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
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
#

: "${MAKE:=/usr/bin/make}"
: "${FILEDIR:=/opt/util-tests/tests/files}"

[[ -d "$FILEDIR" ]] || fail "no files directory $FILEDIR"

typeset -i fail=0

function fail {
	echo "FAIL $@"
	((fail++))
}

function pass {
	echo "PASS $@"
}

function check_results {
	typeset expected="$1"
	typeset actual="$2"
	typeset name="$3"

	if ! cmp -s $expected $actual; then
		fail "$name"
		diff -u "$expected" "$actual" | sed 's/^/    /'
	else
		pass "$name"
	fi
}

test_make_C() {
	TD=$(mktemp -d -t)

	if [[ ! -d "$TD" ]]; then
		fail "couldn't create test directory $TD"
		return
	fi

	# Create output files corresponding to running make in each directory
	# and to running make with a -C argument pointing to the directory.
	# The results should be identical.
	for s in "" a b c; do
		# Baseline - running 'make' in the directory
		( cd "$FILEDIR/make_a/$s"; $MAKE ) > $TD/M_a_$s.out 2>&1

		# Running 'make -C' from a directory with no make* files
		( cd "$TD"; $MAKE -C "$FILEDIR/make_a/$s" ) \
		    > $TD/Ce_a_$s.out 2>&1
		check_results $TD/{M,Ce}_a_$s.out \
		    "make -C a/$s from empty directory"

		# Running 'make -C' from a directory WITH make* files
		( cd "$FILEDIR/make_a"; $MAKE -C "$FILEDIR/make_a/$s" ) \
		    > $TD/C_a_$s.out 2>&1
		check_results $TD/{M,C}_a_$s.out \
		    "make -C a/$s from non-empty directory"

		# Using MAKEFLAGS from a directory with no make* files
		( cd "$TD"; MAKEFLAGS="-C $FILEDIR/make_a/$s" $MAKE) \
		    > $TD/Fe_a_$s.out 2>&1
		check_results $TD/{M,Fe}_a_$s.out \
		    "makeflags -C a/$s from empty directory"

		# Using MAKEFLAGS from a directory WITH make* files
		( cd "$FILEDIR/make_a"; \
		    MAKEFLAGS="-C $FILEDIR/make_a/$s" $MAKE) \
		    > $TD/F_a_$s.out 2>&1
		check_results $TD/{M,F}_a_$s.out \
		    "makeflags -C a/$s from non-empty directory"
	done

	rm -rf "$TD"
}

test_make_C_multiple() {
	TD=$(mktemp -d -t)

	if [[ ! -d "$TD" ]]; then
		fail "couldn't create test directory $TD"
		return
	fi

	# Expected output
	( cd "$FILEDIR/make_a/b"; $MAKE ) > $TD/expect 2>&1

	# Running 'make -C' from a directory with no make* files
	( cd "$TD"; $MAKE -C $FILEDIR/make_a/a -C $FILEDIR/make_a/b ) \
	    > $TD/empty 2>&1
	check_results $TD/{expect,empty} "make -C -C from empty directory"

	# Running 'make -C' from a directory WITH make* files
	( cd "$FILEDIR/make_a"; \
	    $MAKE -C $FILEDIR/make_a/a -C $FILEDIR/make_a/b ) \
	    > $TD/with 2>&1
	check_results $TD/{expect,with} "make -C -C from non-empty directory"

	# Using MAKEFLAGS from a directory with no make* files
	( cd "$TD";
	    MAKEFLAGS="-C $FILEDIR/make_a/a -C $FILEDIR/make_a/b" $MAKE ) \
	    > $TD/emptyflags 2>&1
	check_results $TD/{expect,emptyflags} \
	    "makeflags -C -C from empty directory"

	# Using MAKEFLAGS from a directory WITH make* files
	( cd "$FILEDIR/make_a";
	    MAKEFLAGS="-C $FILEDIR/make_a/a -C $FILEDIR/make_a/b" $MAKE ) \
	    > $TD/withflags 2>&1
	check_results $TD/{expect,withflags} \
	    "makeflags -C -C from non-empty directory"

	( cd "$FILEDIR/make_l"; $MAKE -C ../make_a/a -C ../b ) \
	    > $TD/relative 2>&1
	check_results $TD/{expect,relative} \
	    "make -C -C relative from empty directory"

	rm -rf "$TD"
}

test_make_C_invalid() {
	outf=$(mktemp)

	tst="make -C error"
	$MAKE -C > $outf 2>&1 && fail "$tst" || pass "$tst"
	egrep -s 'Missing argument' $outf && pass "$tst (output)" \
	    || fail "$tst (output)"

	tst="MAKEFLAGS=-C error"
	MAKEFLAGS="-C" $MAKE > $outf 2>&1 && fail "$tst" || pass "$tst"
	egrep -s 'Missing argument' $outf && pass "$tst (output)" \
	    || fail "$tst (output)"

	tst="make -C <noexist>"
	$MAKE -C /no/such/directory > $outf 2>&1 && fail "$tst" || pass "$tst"
	egrep -s 'No such file or directory' $outf && pass "$tst (output)" \
	    || fail "$tst (output)"

	tst="MAKEFLAGS=-C <noexist>"
	MAKEFLAGS="-C /no/such/directory" $MAKE > $outf 2>&1 && fail "$tst" \
	    || pass "$tst"
	egrep -s 'No such file or directory' $outf  && pass "$tst (output)" \
	    || fail "$tst (output)"

	rm -f $outf
}

test_make_C
test_make_C_multiple
test_make_C_invalid

[[ $fail -gt 0 ]] && exit -1

exit 0

