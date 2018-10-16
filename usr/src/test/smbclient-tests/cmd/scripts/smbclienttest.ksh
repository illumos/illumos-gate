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
# Copyright (c) 2012 by Delphix. All rights reserved.
#

#
# Define necessary environments and config variables here
# prior to invoking the test runner
#

export STF_SUITE="/opt/smbclient-tests"
export STF_TOOLS="/opt/test-runner/stf"
runner="/opt/test-runner/bin/run"

runfile=$STF_SUITE/runfiles/default.run

PATH=/usr/bin:/usr/sbin:/sbin:$STF_SUITE/bin:$PATH
export PATH

while getopts 'c:fqs:' c; do
	case $c in
	'c')
		runfile=$OPTARG
		;;
	'f')
		export STC_QUICK=1
		;;
	'q')
		quiet='-q'
		;;
	's')
		export SRV=$OPTARG
		;;
	esac
done
shift $((OPTIND - 1))

. $STF_SUITE/include/default_cfg.ksh

[[ -n "$SRV" ]] || { echo "$0 -s SERVER required"; exit 1; }

# Allow relative runfiles for convenience.
if [[ ! -r "$runfile" && -r "$STF_SUITE/runfiles/$runfile" ]]
then
    runfile="$STF_SUITE/runfiles/$runfile"
fi
[[ -r $runfile ]] || { echo "$0 Cannot read file: $runfile"; exit 1; }

$runner $quiet -c $runfile

exit $?
