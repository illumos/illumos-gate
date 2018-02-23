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

check_env OPENZFS_DIRECTORY

#
# The illumos build cannot be run as the root user. The Jenkins
# infrastructure built around running the build should ensure the build
# is not attempted as root. In case that fails for whatever reason, it's
# best to fail early and with a good error message, than failing later
# with an obscure build error.
#
[ $EUID -ne 0 ] || die "nits attempted as root user; this is not supported."

OPENZFS_DIRECTORY=$(log_must readlink -f "$OPENZFS_DIRECTORY")
log_must test -d "$OPENZFS_DIRECTORY"
log_must cd "$OPENZFS_DIRECTORY"

#
# The assumption is this script will run after a full nightly build of
# illumos, and the environment file will already exist as a byproduct of
# the build. If this is not the case, it's best to explicitly fail here.
#
log_must test -f "illumos.sh"

log_must ln -sf usr/src/tools/scripts/bldenv.sh .

BASE=${BASE_COMMIT:-'HEAD^'}
log_must env -i ksh93 bldenv.sh -d "illumos.sh" -c "git nits -b '$BASE'" 2>&1
