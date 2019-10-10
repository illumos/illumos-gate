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
# Copyright 2019 Joyent, Inc.
#

#
# vnd test suite driver
#
unalias -a

vt_arg0=$(basename $0)
vt_root="$(dirname $0)/.."
vt_ksh="/usr/bin/ksh"
vt_outdir=
vt_keep=
vt_all=
vt_tests=
vt_stub=
vt_vnics="vndtest1 vndtest2 vndtest3 vndtest4 vndtest5"
vt_tnum=0
vt_tfail=0
vt_tsuc=0

function usage
{
	typeset msg="$*"
	[[ -z "$msg" ]] || echo "$msg" 2>&1
	cat <<USAGE >&2
Usage: $vt_arg0  [ -o dir ] [ -k ] [ -a | test ... ]

	-o dir		Sets 'dir' as the output directory
	-a		Runs all tests, ignores tests passed in
	-k		Keep output from all tests, not just failures
	-m 		mdb binary to test
USAGE
	exit 2
}

function fatal
{
	typeset msg="$*"
	[[ -z "$msg" ]] && msg="failed"
	echo "$vt_arg0: $msg" >&2
	exit 1
}

function setup_outdir
{
	vt_outdir="$vt_outdir/$vt_arg0.$$"
	mkdir -p $vt_outdir || fatal "failed to make output dir $vt_outdir"
}

function setup_etherstub
{
	vt_ether="vndstub$$"

	dladm create-etherstub -t $vt_ether || \
	    fatal "failed to create etherstub"
}

function cleanup_vnd
{
	typeset over=$1
	typeset vnddevs vn

	vnddevs=$(vndadm list -p -d: -o datalink,name)
	[[ $? -eq 0 ]] || fatal "failed to list vnics"
	for v in $vnddevs; do
		vn=$(echo $v | awk 'BEGIN{ FS=":"}
		    { if ($1 == targ) { print $2 } }' targ=$over)
		[[ -z "$vn" ]] && continue
		vndadm destroy $vn || fatal "failed to destroy $vn"
	done
}

function create_vnics
{
	for n in $vt_vnics; do
		dladm create-vnic -t -l $vt_ether $n || fatal \
		    "failed to create vnic $n over $vt_ether"
	done
}

function cleanup_vnics
{
	typeset nics vn
	
	nics=$(dladm show-vnic -p -o over,link)
	[[ $? -eq 0 ]] || fatal "failed to list vnics"
	for n in $nics; do 
		vn=$(echo $n | awk 'BEGIN{ FS=":"}
		    { if ($1 == targ) { print $2 } }' targ=$vt_ether )
		[[ -z "$vn" ]] && continue
		cleanup_vnd $vn
		#
		# There may or may not be an IP device on our nics...
		#
		ifconfig $vn down unplumb 2>/dev/null || /bin/true
		dladm delete-vnic $vn || fatal "failed to delete vnic $n"
	done

}

function cleanup_etherstub
{
	cleanup_vnics
	dladm delete-etherstub -t $vt_ether || \
	    fatal "failed to delete etherstub"
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
	odir="$vt_outdir/current"
	[[ -z "$ext" ]] && fatal "found test without ext: $name"
	[[ -z "$expect" ]] && fatal "found test without prefix: $name"

	[[ "$expect" == "create" || "$expect" == "ecreate" ]] && create_vnics
	if [[ "$expect" == "err" || "$expect" == "ecreate" ]]; then
		iserr="yup"
	else
		iserr=""
	fi

	case "$ext" in
	"ksh")
		command="$vt_ksh ./$base"
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
	$command $vt_vnics > "$odir/stdout" 2>"$odir/stderr"
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
		((vt_tfail++))
		mv "$odir" "$vt_outdir/failure.$vt_tfail" || fatal \
		    "failed to move test output directory"
		cp "$name" "$vt_outdir/failure.$vt_tfail/$(basename $name)" || \
		    fatal "failed to copy test into output directory"
	else
		echo "passed"
		((vt_tsuc++))
		mv "$odir" "$vt_outdir/success.$vt_tsuc" || fatal \
		    "failed to move test directory"	
	fi

	[[ "$expect" == "create" || "$expect" == "ecreate" ]] && cleanup_vnics

	((vt_tnum++))
}

function run_all
{
	typeset tests t dir

	tests=$(ls -1 $vt_root/*/*/@(ecreate|create|tst|err).*.@(ksh|exe))
	for t in $tests; do
		run_single $t
	done
}

function welcome
{
	cat <<WELCOME
Starting tests...
output directory: $vt_outdir
WELCOME
}

function cleanup
{
	[[ -n "$vt_keep" ]] && return
	rm -rf "$vt_outdir"/success.* || fatal \
	     "failed to remove successful test cases"
	if [[ $vt_tfail -eq 0 ]]; then
		rmdir "$vt_outdir" || fatal \
		    "failed to remove test output directory"
	fi
}

function goodbye
{
	cat <<EOF

-------------
Results
-------------

Tests passed: $vt_tsuc
Tests failed: $vt_tfail
Tests ran:    $vt_tnum

EOF
	if [[ $vt_tfail  -eq 0 ]]; then
		echo "Congrats, vnd isn't completely broken, the tests pass".
	else
		echo "Some tests failed, you have some work to do."
	fi
}

while getopts ":ahko:m:" c $@; do
	case "$c" in
	a)
		vt_all="y"
		;;
	k)
		vt_keep="y"
		;;
	o)
		vt_outdir="$OPTARG"
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

[[ $(zonename) != "global" ]] && fatal "vndtest only runs in the global zone"

[[ -z "$vt_all" && $# == 0 ]] && usage "no tests to run"

[[ -z "$vt_outdir" ]] && vt_outdir="$PWD"

setup_outdir
setup_etherstub
welcome

if [[ ! -z "$vt_all" ]]; then
	run_all
else
	for t in $@; do
		[[ -f $t ]] || fatal "cannot find test $t"
		run_single $t		
	done
fi

cleanup_etherstub
goodbye
cleanup

#
# Exit 1 if we have tests that return non-zero
#
[[ $vt_tfai -eq 0 ]]
