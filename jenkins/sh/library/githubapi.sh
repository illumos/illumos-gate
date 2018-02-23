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

function githubapi_setup_environment() {
	#
	# We need to be careful not to expose the token such that it will
	# end up in the console logs of the jenkins job that will execute
	# this script.
	#
	log_must cat >netrc-file <<EOF
machine api.github.com
  login $(vault_read_github_user)
  password $(vault_read_github_token)
EOF

	#
	# The ruby netrc module will throw an error if the netrc file's
	# permissions are not 600.
	#
	log_must chmod 600 netrc-file
}
