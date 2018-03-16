#!/bin/ksh
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
# Copyright 2018 Joyent, Inc.
#

#
# bhyve test suite driver
#
unalias -a

bt_arg0=$(basename $0)
bt_root="$(cd $(dirname $0)/..; pwd -P)"
bt_ksh="/usr/bin/ksh"
bt_outdir=
bt_keep=
bt_all=
bt_tnum=0
bt_tfail=0
bt_tsuc=0

function usage
{
	typeset msg="$*"
	[[ -z "$msg" ]] || echo "$msg" 2>&1
	cat <<USAGE >&2
Usage: $bt_arg0  [ -o dir ] [ -k ] [ -a | test ... ]

	-o dir		Sets 'dir' as the output directory
	-a		Runs all tests, ignores tests passed in
	-k		Keep output from all tests, not just failures
	-m		mdb binary to test
USAGE
	exit 2
}

function fatal
{
	typeset msg="$*"
	[[ -z "$msg" ]] && msg="failed"
	echo "$bt_arg0: $msg" >&2
	exit 1
}

function setup_outdir
{
	bt_outdir="$bt_outdir/$bt_arg0.$$"
	mkdir -p $bt_outdir || fatal "failed to make output dir $bt_outdir"
}

function run_single
{
	typeset name=$1
	typeset expect base ext exe command odir res reason
	typeset iserr

	[[ -z "$name" ]] && fail "missing test to run"
	base=${name##*/}
	ext=${base##*.}
	expect=${base%%.*}
	odir="$bt_outdir/current"
	[[ -z "$ext" ]] && fatal "found test without ext: $name"
	[[ -z "$expect" ]] && fatal "found test without prefix: $name"

	if [[ "$expect" == "err" || "$expect" == "ecreate" ]]; then
		iserr="yup"
	else
		iserr=""
	fi

	case "$ext" in
	"ksh")
		command="$bt_ksh ./$base"
		;;
	"exe")
		command="./$base"
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
	cd $(dirname $name) || fatal "failed to enter test directory"
	$command > "$odir/stdout" 2>"$odir/stderr"
	res=$?
	cd - > /dev/null || fatal "failed to leave test directory"

	if [[ -f "$name.out" ]] && \
	    ! diff "$name.out" "$odir/stdout" >/dev/null; then
		cp $name.out $odir/$base.out
		reason="stdout mismatch"
	elif [[ -n "$iserr" && $res -eq 0 ]]; then
		reason="test exited $res, not non-zero"
	elif [[ -z "$iserr" && $res -ne 0 ]]; then
		reason="test exited $res, not zero"
	fi

	if [[ -n "$reason" ]]; then
		echo "$reason"
		((bt_tfail++))
		mv "$odir" "$bt_outdir/failure.$bt_tfail" || fatal \
		    "failed to move test output directory"
		cp "$name" "$bt_outdir/failure.$bt_tfail/$(basename $name)" || \
		    fatal "failed to copy test into output directory"
	else
		echo "passed"
		((bt_tsuc++))
		mv "$odir" "$bt_outdir/success.$bt_tsuc" || fatal \
		    "failed to move test directory"
	fi

	((bt_tnum++))
}

function run_all
{
	typeset tests t dir

	tests=$(ls -1 $bt_root/tst/*/*.@(ksh|exe))
	for t in $tests; do
		run_single $t
	done
}

function welcome
{
	cat <<WELCOME
Starting tests...
output directory: $bt_outdir
WELCOME
}

function cleanup
{
	[[ -n "$bt_keep" ]] && return
	rm -rf "$bt_outdir"/success.* || fatal \
	     "failed to remove successful test cases"
	if [[ $bt_tfail -eq 0 ]]; then
		rmdir "$bt_outdir" || fatal \
		    "failed to remove test output directory"
	fi
}

function goodbye
{
	cat <<EOF

-------------
Results
-------------

Tests passed: $bt_tsuc
Tests failed: $bt_tfail
Tests ran:    $bt_tnum

EOF
	if [[ $bt_tfail  -eq 0 ]]; then
		echo "Congrats, some tiny parts of bhyve aren't completely" \
		    "broken, the tests pass".
	else
		echo "Some tests failed, you have some work to do."
	fi
}

while getopts ":ahko:m:" c $@; do
	case "$c" in
	a)
		bt_all="y"
		;;
	k)
		bt_keep="y"
		;;
	o)
		bt_outdir="$OPTARG"
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

[[ -z "$bt_all" && $# == 0 ]] && usage "no tests to run"

[[ -z "$bt_outdir" ]] && bt_outdir="$PWD"

setup_outdir
welcome

if [[ ! -z "$bt_all" ]]; then
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
[[ $bt_tfai -eq 0 ]]
