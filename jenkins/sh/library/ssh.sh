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
# Copyright (c) 2017, 2018 by Delphix. All rights reserved.
#

source ${JENKINS_DIRECTORY}/sh/library/common.sh

function ssh_log_must() {
	check_env HOST

	log_must ssh \
		-o UserKnownHostsFile=/dev/null \
		-o StrictHostKeyChecking=no \
		"root@$HOST" "$@"
}

function ssh_wait_for() {
	local INVENTORY="$1"
	local PLAYBOOK="$2"

	check_env HOST INVENTORY PLAYBOOK

	#
	# The tabs below aren't a mistake, that's a requirement of using a
	# heredoc with indentation.
	#

	log_must cat >"$INVENTORY" <<-EOF
	$HOST ansible_ssh_user=root ansible_ssh_pass=root
	EOF

	log_must cat >"$PLAYBOOK" <<-EOF
	---
	- hosts: localhost
	  gather_facts: no
	  tasks:
	    - wait_for:
	        host: $HOST
	        port: 22
	        state: started
	        timeout: 1800
	EOF

	log_must ansible-playbook -vvvv -i "$INVENTORY" "$PLAYBOOK" >&2
}

function ssh_fetch_remote_directory() {
	local REMOTE_DIRECTORY="$1"

	check_env HOST REMOTE_DIRECTORY

	#
	# We inject the pv(1) (pipe viewer) utility in between the stream so
	# we can output statistics about the speed of the transfer.
	#
	# pv(1) will print carriage returns instead of newline characters
	# each time it updates the statistics it's showing, so that it can
	# continually update the output inline (instead of printing a new
	# line for each update) when it is run interactively from the
	# command line.
	#
	# Unfortunately, Jenkins does not handle carriage returns the same
	# way it does new lines, and the "console" page for a job will only
	# be updated when a newline is printed. Thus, as pv(1) prints its
	# updates, these will not get propagated to the job's "console" page
	# until the transfer completes and a new line is printed. This
	# essentially defeats the purpose of using pv(1) at all, since the
	# point is to periodically display output as feedback to let the user
	# know the transfer is progressing.
	#
	# To work around this limitation, we pipe the output from pv(1) into
	# tr(1) and replace any carriage returns with newlines; this will
	# achieve the desired behavior with each update from pv(1) being
	# immediately displayed on a new line in the Jenkins job's "console"
	# page.
	#
	# Additionally, we need to use stdbuf(1) to prevent bash from
	# buffering the output of pv(1). If we did not use stdbuf(1), the
	# output emitted by pv(1) wouldn't get immediately printed to the
	# Jenkins job's "console" page; instead, multiple lines would get
	# batched and all printed to the "console" page at the same time.
	# Again, this would defeat the purpose of using pv(1) at all, since
	# we really want to have each line that is emitted, shown on the
	# job's "console" page immeidately.
	#
	# Lastly, we want to stream the contents of the compressed tarball
	# (which reflects the contents of the remote directory) to stdout,
	# so we must perform a complicated dance of Bash redirection to
	# ensure *only* the contents of the tarball will be redirected to
	# stdout, and *everything else* (i.e. the progress reporting emitted
	# by pv(1)) is contained in stderr. Ultimately, this complexity
	# stems from the fact that we have to pipe the output of pv(1)
	# through stdbuf(1) and tr(1) (as described above).
	#
	{ ssh_log_must "gtar -C '$REMOTE_DIRECTORY' -cf - . | xz -9e --stdout -" \
		| pv -fi 15 2>&1 1>&3 | stdbuf -oL -eL tr '\r' '\n' >&2; } 3>&1
}

function ssh_fetch_remote_file() {
	local REMOTE_FILE="$1"

	check_env HOST REMOTE_FILE

	#
	# See the comment in "ssh_fetch_remote_directory" above for an
	# explanation of the complexity here.
	#
	{ ssh_log_must "cat $REMOTE_FILE" \
		| pv -fi 15 2>&1 1>&3 | stdbuf -oL -eL tr '\r' '\n' >&2; } 3>&1
}
