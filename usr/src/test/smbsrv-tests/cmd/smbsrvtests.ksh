#!/usr/bin/ksh

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
# Copyright 2021 Tintri by DDN, Inc.  All rights reserved.
#

# Run all the smbsrv-tests

export PATH="/usr/bin"
export SMBSRV_TESTS="/opt/smbsrv-tests"

export CFGFILE=$SMBSRV_TESTS/include/default.cfg
export OUTDIR=/var/tmp/test_results/smbsrv-tests

function fail
{
	echo $1
	exit ${2:-1}
}

while getopts c:o:t: c; do
	case $c in
	'c')
		CFGFILE=$OPTARG
		[[ -f $CFGFILE ]] || fail "Cannot read file: $CFGFILE"
		;;
	'o')
		OUTDIR=$OPTARG
		;;
	't')
		export TIMEOUT=$OPTARG
		;;
	esac
done
shift $((OPTIND - 1))

set -x

$SMBSRV_TESTS/tests/smbtorture/runst-smb2
$SMBSRV_TESTS/tests/smbtorture/runst-rpc
