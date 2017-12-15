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
# Copyright (c) 2017, Joyent, Inc.
#

#
# Run all of the various libsff tests.
#

unalias -a
sff_arg0=$(basename $0)
sff_origwd=
sff_root=
sff_tests="8472 br compliance conn enc ident lengths opts strings wave"
sff_tests="$sff_tests 8636_diag 8636_extspec 8636_tech 8636_temp einval efault"
sff_outfile="/tmp/$sff_arg0.out.$$"

fatal()
{
	typeset msg="$*"
	[[ -z "$msg" ]] && msg="failed"
	echo "TEST FAILED: $sff_arg0: $msg" >&2
	rm -f $sff_outfile
	exit 1
}

sff_origwd=$PWD
cd $(dirname $0) || fatal "failed to cd to test root"
sff_root=$PWD
cd $dt_origwd || fatal "failed to return to original dir"

for t in $sff_tests; do
	difffile=
	testfile=$sff_root/libsff_$t

	if ! $testfile > $sff_outfile; then
		fatal "failed to run $testfile"
	fi

	if [[ -f $testfile.out ]]; then
		if ! diff $testfile.out $sff_outfile >/dev/null; then
			fatal "$t results differ from expected values"
		fi
	fi
	printf "TEST PASSED: libsff_%s\n" $t
done

rm -f $sff_outfile || fatal "failed to remove output file"
exit 0
