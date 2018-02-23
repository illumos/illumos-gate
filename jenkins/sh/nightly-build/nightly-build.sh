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
source ${JENKINS_DIRECTORY}/sh/library/nightly.sh

check_env OPENZFS_DIRECTORY BUILD_NONDEBUG BUILD_DEBUG RUN_LINT

#
# Updates the nightly environment file. If there's a default value
# provided for the variable we're attempting to set, this value is
# overridden in-place. We need to modify the value of the variable,
# without changing it's location in the file so we don't invalidate
# any later references of the variable. If there isn't an existing
# default value, then the export declaration for the variable is
# simply appended to the end of environment file using the provided
# value.
#
function nightly_env_set_var() {
	#
	# The environment file is hard-coded. Since we don't use
	# anything other than this value, using a hard-coded value here
	# makes it easier on consumers since each call do this function
	# doesn't have to pass in the filename.
	#
	local file="illumos.sh"
	local variable=$1
	local value=$2

	#
	# Check and ensure the file we need is actually present.
	#
	[ -f "$file" ] || die "illumos nightly environment file '$file' not found."

	#
	# Here is how we determine if there's a default value for the
	# variable that we need to update in-place, or if we can append
	# the new value to the end of the file.
	#
	# Also note, when adding quotes around the value provided, we
	# need to be careful to not use single quotes. The contents of
	# the provided value may reference another shell variable, so we
	# need to make sure variable expansion will occur (it wouldn't
	# if we surrounding the value with single quotes).
	#
	#
	if /usr/bin/grep "^export $variable" "$file" >/dev/null; then
		#
		# If an existing value was found, we assign the new
		# value without modifying the variables location in the
		# file.
		#
		/usr/bin/sed -ie "s|^export $variable.*|export $variable=\"$value\"|" "$file"
		return $?
	elif /usr/bin/grep "^$variable" "$file" >/dev/null; then
		#
		# It's also possible that the variable exists in the
		# file, but does not contain the "export" keyword, so we
		# have to explicity check for that case too; this can be
		# found in the OmniOS specific illumos.sh file that we
		# copy out of "/opt/onbld/env".
		#
		/usr/bin/sed -ie "s|^$variable.*|$variable=\"$value\"|" "$file"
		return $?
	else
		#
		# If a default value wasn't found, we don't need to
		# worry about any references to this variable in the
		# file, so we can simply append the value to the end of
		# the file.
		#
		echo "export $variable=\"$value\"" >>"$file"
		return $?
	fi
}

#
# The illumos build cannot be run as the root user. The Jenkins
# infrastructure built around running the build should ensure the build
# is not attempted as root. In case that fails for whatever reason, it's
# best to fail early and with a good error message, than failing later
# with an obscure build error.
#
[ $EUID -ne 0 ] || die "build attempted as root user; this is not supported."

OPENZFS_DIRECTORY=$(log_must readlink -f "$OPENZFS_DIRECTORY")
log_must test -d "$OPENZFS_DIRECTORY"
log_must cd "$OPENZFS_DIRECTORY"

NIGHTLY_OPTIONS="-nCprt"
if [[ "$BUILD_NONDEBUG" == "no" ]]; then
	NIGHTLY_OPTIONS+=F
else
	[[ "$BUILD_NONDEBUG" == "yes" ]] \
		|| die "Invalid value for BUILD_NONDEBUG: $BUILD_NONDEBUG'"
fi

if [[ "$BUILD_DEBUG" == "yes" ]]; then
	NIGHTLY_OPTIONS+=D
else
	[[ "$BUILD_DEBUG" == "no" ]] \
		|| die "Invalid value for BUILD_DEBUG: '$BUILD_DEBUG'"
fi

if [[ "$RUN_LINT" == "yes" ]]; then
	NIGHTLY_OPTIONS+=l
else
	[[ "$RUN_LINT" == "no" ]] \
		|| die "Invalid value for RUN_LINT: '$RUN_LINT'"
fi

log_must wget --quiet \
	https://download.joyent.com/pub/build/illumos/on-closed-bins.i386.tar.bz2 \
	https://download.joyent.com/pub/build/illumos/on-closed-bins-nd.i386.tar.bz2

log_must tar xjpf on-closed-bins.i386.tar.bz2
log_must tar xjpf on-closed-bins-nd.i386.tar.bz2

if [[ -f /opt/onbld/env/omnios-illumos-gate ]]; then
	#
	# We're building on an OmniOS based system, so use the provided
	# illumos.sh environment file.
	#
	log_must cp /opt/onbld/env/omnios-illumos-gate illumos.sh
else
	#
	# If this isn't an OmniOS system, the assumption is this is an
	# OpenIndiana based system. In which case, use the illumos.sh
	# environment file from the respository, and provided some
	# OpenIndiana specific customizations.
	#
	log_must cp usr/src/tools/env/illumos.sh illumos.sh

	PKGVERS_BRANCH=$(log_must pkg info -r pkg://openindiana.org/SUNWcs \
		| log_must awk '$1 == "Branch:" {print $2}')

	log_must nightly_env_set_var "PKGVERS_BRANCH" "'$PKGVERS_BRANCH'"
	log_must nightly_env_set_var "ONNV_BUILDNUM" "'$PKGVERS_BRANCH'"
	log_must nightly_env_set_var "PERL_VERSION" "5.22"
	log_must nightly_env_set_var "PERL_PKGVERS" "-522"
	log_must nightly_env_set_var "BLD_JAVA_8" ""
fi

log_must nightly_env_set_var "NIGHTLY_OPTIONS" "$NIGHTLY_OPTIONS"
log_must nightly_env_set_var "GATE" "openzfs-nightly"
log_must nightly_env_set_var "CODEMGR_WS" "$OPENZFS_DIRECTORY"
log_must nightly_env_set_var "ON_CLOSED_BINS" "$OPENZFS_DIRECTORY/closed"
log_must nightly_env_set_var "ENABLE_IPP_PRINTING" "#"
log_must nightly_env_set_var "ENABLE_SMB_PRINTING" "#"

#
# While VERSION is already set this way when using the illumos.sh file
# contained in the OpenZFS repository, that's not the case when building
# on OmniOS and we start with the illumos.sh file copied out of the
# "/opt/onbld/env" directory. Thus, to ensure the VERSION is set
# consistently whether building on OmniOS or OpenIndiana (or any other
# platform that would use the in-tree illumos.sh file), we explicitly
# set the value of VERSION here.
#
log_must nightly_env_set_var "VERSION" \
	"$(log_must git describe --long --all HEAD | log_must cut -d/ -f2-)"

log_must cp usr/src/tools/scripts/nightly.sh .
log_must chmod +x nightly.sh
log_must nightly_run ./nightly.sh "$OPENZFS_DIRECTORY" "illumos.sh"

log_must mail_msg_is_clean "$OPENZFS_DIRECTORY" "Build errors" "Build warnings"
log_must mail_msg_is_clean "$OPENZFS_DIRECTORY" "Build warnings" "Elapsed build time"
log_must mail_msg_is_clean "$OPENZFS_DIRECTORY" "Build errors (non-DEBUG)" "Build warnings (non-DEBUG)"
log_must mail_msg_is_clean "$OPENZFS_DIRECTORY" "Build warnings (non-DEBUG)" "Elapsed build time (non-DEBUG)"
log_must mail_msg_is_clean "$OPENZFS_DIRECTORY" "Build errors (DEBUG)" "Build warnings (DEBUG)"
log_must mail_msg_is_clean "$OPENZFS_DIRECTORY" "Build warnings (DEBUG)" "Elapsed build time (DEBUG)"
log_must mail_msg_is_clean "$OPENZFS_DIRECTORY" "lint warnings src" "lint noise differences src"
log_must mail_msg_is_clean "$OPENZFS_DIRECTORY" "cstyle/hdrchk errors" "Find core files"
log_must mail_msg_is_clean "$OPENZFS_DIRECTORY" "Validating manifests against proto area" "Check ELF runtime attributes"
