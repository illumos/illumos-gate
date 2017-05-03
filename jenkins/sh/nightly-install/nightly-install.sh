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

check_env OPENZFS_DIRECTORY INSTALL_DEBUG

OPENZFS_DIRECTORY=$(log_must readlink -f "$OPENZFS_DIRECTORY")
log_must test -d "$OPENZFS_DIRECTORY"
log_must cd "$OPENZFS_DIRECTORY"

ONU="${OPENZFS_DIRECTORY}/usr/src/tools/scripts/onu"
REPO="${OPENZFS_DIRECTORY}/packages/i386/nightly"
[[ "$INSTALL_DEBUG" == "yes" ]] || REPO="${REPO}-nd"

export BE_PRINT_ERR=true
log_must sudo "${ONU}" -t "openzfs-nightly" -d "${REPO}"
