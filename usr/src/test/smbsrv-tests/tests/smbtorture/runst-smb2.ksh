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
# Copyright 2021 Tintri by DDN, Inc. All rights reserved.
#

export SMBSRV_TESTS="/opt/smbsrv-tests"
export SMBTOR="/usr/bin/smbtorture"

runsmbtor=$SMBSRV_TESTS/bin/run_smbtorture
excl_file=$SMBSRV_TESTS/include/smbtor-excl-smb2.txt

cfgfile=${CFGFILE:-$SMBSRV_TESTS/include/default.cfg}
outdir=${OUTDIR:-/var/tmp/test_results/smbsrv-tests}

function fail
{
	echo $1
	exit ${2:-1}
}

while getopts c:o:t: c; do
	case $c in
	'c')
		cfgfile=$OPTARG
		[[ -f $cfgfile ]] || fail "Cannot read file: $cfgfile"
		;;
	'o')
		outdir=$OPTARG
		;;
	't')
		timeout="-t $OPTARG"
		;;
	esac
done
shift $((OPTIND - 1))

. $cfgfile

export PATH="$(dirname $SMBTOR):$PATH"

mkdir -p $outdir
cd $outdir || fail "Could not cd to $outdir"

tstamp=$(date +'%Y%m%dT%H%M%S')
logfile=$outdir/smbtor-smb2-${tstamp}.log
outfile=$outdir/smbtor-smb2-${tstamp}.summary

if [[ -z "$timeout" && -n "$TIMEOUT" ]]; then
	timeout="-t $TIMEOUT"
fi

# Non-option args taken as list of match patterns
if [ -z "$1" ] ; then
    match="-m smb2"
fi
for m
do
    match="$match -m $m"
done

# Make sure we can connect, otherwise we'll report every test as failing.
$SMBTOR -U "$SMBT_USER%${SMBT_PASS}" //$SMBT_HOST/$SMBT_SHARE smb2.dir.find \
 > /dev/null 2>&1 || \
    fail "Cannot connect to //$SMBT_HOST/$SMBT_SHARE"

echo "Running smbtorture/smb2 tests with //$SMBT_HOST/$SMBT_SHARE"
$runsmbtor $match -e $excl_file -o $logfile $timeout \
    "$SMBT_HOST" "$SMBT_SHARE" "$SMBT_USER" "${SMBT_PASS}" |
     tee $outfile

exit 0
