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

function __echo_jenkins_helper_script() {
	local build_mail

	build_mail=$1

	cat <<EOF
#!/bin/bash
#
# Files created by nightly.sh
#
build_time_file="\$TMPDIR/build_time"
build_env_file="\$TMPDIR/build_environ"
mail_msg_file="\$TMPDIR/mail_msg"

cat \$build_time \$build_environ_file \$mail_msg_file >"$build_mail"
EOF
	return 0
}

#
# Runs the nightly script using the given environment file. The path to the
# nightly script to run must be specified along with the directory in which
# the build will take place. At the end of the build a file called
# "build.mail" will be placed in the build_dir that is suitable for mailing
# to anyone interested in the results of the build. The exit return status
# of this function is the same as the exit status of the nightly script.
#
function nightly_run() {
	local nightly=$1
	local build_dir=$2
	local envfile=$3

	local build_pid=$$

	#
	# We do not want to let the nightly script send mail, but we do want
	# to mimic the mail_msg sent by the nightly script. Rather than try
	# to find the mail_msg file in the log directory once the build is
	# finished we use the POST_BUILD hook in the nighly script to assemble
	# our own copy of the mail message in the build directory.
	#
	local jenkins_helper="$build_dir/jenkins_helper.sh"
	log_must __echo_jenkins_helper_script \
		"$build_dir/mail_msg" >"$jenkins_helper"
	log_must chmod +x "$jenkins_helper"

	#
	# The LOCKNAME defined in the environment file should normally not
	# be changed, but we set it to a predicatble value because it is
	# actually a symlink to a file whose name ends with the PID of
	# the build process, which we use to identify the build's temp
	# directory later on.
	#
	local lockname="jenkins-$build_pid-nightly.lock"

	log_must nightly_env_set_var "LOCKNAME" "$lockname"
	log_must nightly_env_set_var "POST_NIGHTLY" "$jenkins_helper"

	log env -i time "$nightly" "$envfile" &
	local nightly_pid=$!

	sleep 10
	local nightly_tmpdir=/tmp/nightly.tmpdir.$(readlink -f "/tmp/$lockname" \
		| sed -E 's@.*\.([0-9]+)@\1@') || die "could not look up tmpdir"
	tail -f $nightly_tmpdir/mail_msg &
	local tail_pid=$!

	wait $nightly_pid
	local result=$?
	kill $tail_pid

	return $result
}

#
# Checks the section of the mail_msg file in the given build directory
# (assumes mail_msg was created by the "nightly_run" function). If the
# section between the given lines is empty, this returns 0, otherwise
# it returns non-zero. If the start line does not exist always returns 0.
#
function mail_msg_is_clean() {
	local build_dir="$1"
	local start="==== $(echo "$2" | sed "s@/@\\\\/@") ===="
	local end="==== $(echo "$3" | sed "s@/@\\\\/@") ===="

	if [[ ! -z "$(sed -n "/^$start\$/,/^$end\$/p" $build_dir/mail_msg \
		| sed -e "/^$start\$/d" -e "/^$end\$/d" -e "/^$/d")" ]]; then
		return 1
	fi

	return 0
}
