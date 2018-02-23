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
# Copyright (c) 2017 by Delphix. All rights reserved.
#

source ${JENKINS_DIRECTORY}/sh/library/common.sh

check_env ENABLE_WATCHPOINTS RUN_TIME

if [[ "$ENABLE_WATCHPOINTS" == "yes" ]]; then
	export ZFS_DEBUG="watch"
else
	export ZFS_DEBUG=""
fi

log_must mkdir /var/tmp/test_results
log_must cd /var/tmp/test_results

log zloop -t $RUN_TIME -c . -f .
result=$?

if [[ $result -ne 0 ]]; then
	if [[ -r ztest.cores ]]; then
		log_must cat ztest.cores
	fi

	if [[ -r core ]]; then
		log_must echo '::status' | log_must mdb core
		log_must echo '::stack' | log_must mdb core
	fi
fi

log_must tail -n 30 ztest.out

exit $result
