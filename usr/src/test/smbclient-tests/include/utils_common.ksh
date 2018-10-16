#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
#

#
# NAME
#	print_test_case
#
# DESCRIPTION
#	Print the test case name to the results formated to fit with
#	60 characters.
#
# RETURN
#	no return
#
print_test_case() {
	cti_report "======================================================="
	cti_report "Test case $*"
	cti_report "======================================================="
}


#
# NAME
#	do_nothing
#
# DESCRIPTION
#	Didn't do anything on the system
#
# RETURN
#	no return
#
do_nothing() {
	cti_report "do nothing"
}

#
# NAME
#	no_tested
#
# DESCRIPTION
#	Determine if need to trun the test case
#
# RETURN
#	0 - the test case will run
#       1 - the test case will not run
#
no_tested() {
	cti_result NOTINUSE
}

#
# NAME
#	server_name
#
# DESCRIPTION
#	Function used to sync with client and server
#
# RETURN
#	0 - sync successfully
#       1 - sync failed
#
server_name() {
	if [[ -z $SRV ]]; then
		cti_report "SRV not set"
		cti_result UNRESOLVED
		return 1
	fi
	server=$SRV
	echo $server
	return 0
}

#
# NAME
#	file_size
#
# DESCRIPTION
#	Print the file size
#
# RETURN
#	no return
#
file_size() {
	typeset file=$1
	typeset -a arr
	set -A arr x$(ls -l $file 2>/dev/null || echo 0 0 0 0 0);
	echo "${arr[4]}"
}
