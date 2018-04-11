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
#       parse_status_output
#
# DESCRIPTION
#       Parse the output of the smbutil status, and print the
#	workgroup and the server
#
# RETURN
#       no return
#

parse_status_output() {
	typeset w_tag a_tag Workgroup Server
	w_tag=0
	s_tag=0
	while getopts w:s: opt
	do
	        case $opt in
		w)
			w_tag=1
	                output="$OPTARG";;
		s)
			s_tag=1
	                output="$OPTARG";;
	        esac
	done
	if [[ w_tag == 1 ]]; then
		Workgroup=$(cat $output|grep Workgroup \
			|awk -F: '{print $2}')
		echo $Workgroup
	else
		Server=$(cat $output|grep Server \
			|awk -F: '{print $2}')
		echo $Server
	fi
}

#
# NAME
#       parse_view_output
#
# DESCRIPTION
#       Parse the output of the smbutil view, and print the shares
#
# RETURN
#       0 - success
#
parse_view_output() {
	typeset share str
	share=$1
	stdout=$2
	str=$(cat $stdout |grep -v -- "---"|grep $share)
	name=$(echo $str |awk '{print $1}')
	type=$(echo $str |awk '{print $2}')
	if [[ "$name" != "$share" ]]; then
		cti_fail "FAIL: share name should be $share"
		return 1
	fi
	if [[ "$type" != "disk" ]]; then
		cti_fail "FAIL: share type is $type, should be disk"
		return 1
	fi
	return 0
}
