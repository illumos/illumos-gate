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
# Copyright 2022 Oxide Computer Company
#

TEST_DIR="/opt/bhyve-tests"
RUNNER="/opt/test-runner/bin/run"

while getopts c: c; do
	case $c in
	'c')
		RUN_FILE=$OPTARG
		if [[ ! -f $RUN_FILE ]]; then
			echo "Cannot read file: $RUN_FILE"
			exit 1
		fi
		;;
	esac
done
shift $((OPTIND - 1))

if [[ -z $RUN_FILE ]]; then
	RUN_FILE="$TEST_DIR/runfiles/default.run"
fi

exec $RUNNER -c $RUN_FILE
