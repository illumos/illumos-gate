#!/bin/bash
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
# Copyright 2012 (c), Joyent, Inc.
#

#
# mdb test driver
#
unalias -a
shopt -s xpg_echo
#set -o xtrace

mt_arg0=$(basename $0)
mt_ksh="/usr/bin/ksh"
mt_mdb="/usr/bin/mdb"
mt_outdir=
mt_keep=
mt_all=
mt_tests=
mt_tnum=0
mt_tfail=0
mt_tsuc=0

function usage
{
	local msg="$*"
	[[ -z "$msg" ]] || echo "$msg" 2>&1
	cat <<USAGE >&2
Usage: $mt_arg0  [ -o dir ] [ -k ] [ -m executable ] [ -a | test ... ]

	-o dir		Sets 'dir' as the output directory
	-a		Runs all tests, ignores tests passed in
	-k		Keep output from all tests, not just failures
	-m 		mdb binary to test
USAGE
	exit 2
}

function fatal
{
	local msg="$*"
	[[ -z "$msg" ]] && msg="failed"
	echo "$mt_arg0: $msg" >&2
	exit 1
}

function setup_outdir
{
	mt_outdir="$mt_outdir/$mt_arg0.$$"
	mkdir -p $mt_outdir || fatal "failed to make output dir $mt_outdir"
}

function run_single
{
	local name=$1
	local expect base ext exe command odir res reason input

	[[ -z "$name" ]] && fail "missing test to run"
	base=${name##*/}
	ext=${base##*.}
	expect=${base%%.*}
	odir="$mt_outdir/current"
	[[ -z "$ext" ]] && fatal "found test without ext: $name"
	[[ -z "$expect" ]] && fatal "found test without prefix: $name"

	case "$ext" in
	"ksh")
		command="$mt_ksh $name"
		;;
	"mdb")
		command="$mt_mdb"
		input="$name"
		;;
	"out")
		#
		# This is the file format for checking output against.
		#
		return 0
		;;
	*)
		echo "skipping test $name (unknown extensino)"
		return 0
		;;
	esac

	echo "Executing test $name ... \c"
	mkdir -p "$odir" >/dev/null || fatal "can't make output directory"
	if [[ -z "$input" ]]; then
		MDB=$mt_mdb $command > "$odir/stdout" 2>"$odir/stderr"
		res=$?
	else
		MDB=$mt_mdb $command < $input > "$odir/stdout" 2>"$odir/stderr"
		res=$?
	fi

	if [[ -f "$name.out" ]] && ! diff "$name.out" "$odir/stdout" >/dev/null; then
		cp $name.out $odir/$base.out
		reason="stdout mismatch"
	elif [[ "$expect" == "tst" && $res -ne 0 ]]; then
		reason="test exited $res, not zero"
	elif [[ "$expect" == "err" && $res -eq 0 ]]; then
		reason="test exited $res, not non-zero"
	fi

	if [[ -n "$reason" ]]; then
		echo "$reason"
		((mt_tfail++))
		mv "$odir" "$mt_outdir/failure.$mt_tfail" || fatal \
		    "failed to move test output directory"
		cp "$name" "$mt_outdir/failure.$mt_tfail/test" || fatal \
		    "failed to copy test into output directory"
	else
		echo "passed"
		((mt_tsuc++))
		mv "$odir" "$mt_outdir/success.$mt_tsuc" || fatal \
		    "failed to move test directory"	
	fi

	((mt_tnum++))
}

function run_all
{
	local tests t
	
	tests=$(find . -type f -name '[tst,err]*.*.[ksh,mdb]*')
	for t in $tests; do
		run_single $t
	done
}

function welcome
{
	cat <<WELCOME
Starting tests...
mtest target: $mt_mdb
output directory: $mt_outdir
WELCOME
}

function cleanup
{
	[[ -n "$mt_keep" ]] && return
	rm -rf "$mt_outdir"/success.* || fatal \
	     "failed to remove successful test cases"
	if [[ $mt_tfail -eq 0 ]]; then
		rmdir "$mt_outdir" || fatal \
		    "failed to remove test output directory"
	fi
}

function goodbye
{
	cat <<EOF

-------------
Results
-------------

Tests passed: $mt_tsuc
Tests failed: $mt_tfail
Tests ran:    $mt_tnum

EOF
	if [[ $mt_tfail  -eq 0 ]]; then
		echo "Congrats, mdb isn't completely broken, the tests pass".
	else
		echo "Some tests failed, you have some work to do."
	fi
}

while getopts ":ahko:m:" c $@; do
	case "$c" in
	a)
		mt_all="y"
		;;
	k)
		mt_keep="y"
		;;
	m)
		mt_mdb="$OPTARG"
		;;
	o)
		mt_outdir="$OPTARG"
		;;
	h)
		usage
		;;
	:)
		usage "option requires an argument -- $OPTARG"
		;;
	*)
		usage "invalid option -- $OPTARG"
		;;
	esac
done

shift $((OPTIND-1))

[[ -z "$mt_all" && $# == 0 ]] && usage "no tests to run"

[[ -x "$mt_mdb" ]] || fatal "unable to execute mdb binary: $mt_mdb"

[[ -z "$mt_outdir" ]] && mt_outdir=/var/tmp

setup_outdir
welcome

if [[ ! -z "$mt_all" ]]; then
	run_all
else
	for t in $@; do
		[[ -f $t ]] || fatal "cannot find test $t"
		run_single $t		
	done
fi

goodbye
cleanup

#
# Exit 1 if we have tests that return non-zero
#
[[ $mt_tfai -eq 0 ]]
