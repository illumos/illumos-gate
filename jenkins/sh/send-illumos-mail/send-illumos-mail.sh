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
source ${JENKINS_DIRECTORY}/sh/library/vault.sh
source ${JENKINS_DIRECTORY}/sh/library/githubapi.sh

check_env REPOSITORY

DIR=$(dirname ${BASH_SOURCE[0]})
NAME=$(basename -s ".sh" ${BASH_SOURCE[0]})

githubapi_setup_environment

#
# To avoid the password being present in the Jenkins job console page,
# we pass the SMTP password to the ruby script via the processes stdin.
#
echo $(vault_read_smtp_password) | log_must ruby "${DIR}/${NAME}.rb" \
	--netrc-file netrc-file \
	--repository "$REPOSITORY" \
	--smtp-user "$(vault_read_smtp_user)" \
	--smtp-password "-"
