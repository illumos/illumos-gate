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
# Copyright (c) 2018 by Delphix. All rights reserved.
#

source ${JENKINS_DIRECTORY}/sh/library/common.sh

check_env OPENZFS_DIRECTORY ILLUMOS_REMOTE ILLUMOS_BRANCH

log_must cd "$OPENZFS_DIRECTORY"
log_must git fetch "$ILLUMOS_REMOTE" >&2
log_must git cherry HEAD "$ILLUMOS_REMOTE/$ILLUMOS_BRANCH" \
	| log_must grep '^+' \
	| log_must cut -c '3-'
