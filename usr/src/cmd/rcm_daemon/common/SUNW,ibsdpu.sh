#!/sbin/sh
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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# RCM script to inform the need to run 'sdpadm disable' before removing the
# last IB HCA, when SDP is enabled in the system.
#

rcm_script_version=1
rcm_script_func_info="SDP (un)configuration rcm script"
rcm_cmd_timeout=10
rcm_resource_name=/devices/ib/sdpib@0:sdpib

do_scriptinfo()
{
	printf "rcm_script_version=%d\n" $rcm_script_version;
	printf "rcm_script_func_info=$rcm_script_func_info\n";
	printf "rcm_cmd_timeout=%d\n" $rcm_cmd_timeout;
	exit 0;
}

do_register()
{
	printf "rcm_resource_name=%s\n" $rcm_resource_name;
	exit 0;
}

do_resourceinfo()
{
	if [ x"$1" = x"/devices/ib/sdpib@0:sdpib" ]
	then
		printf "rcm_resource_usage_info=SDP IB device 0\n";
		exit 0;
	else
		printf "rcm_failure_reason=Unknown SDP device\n";
		exit 3;
	fi
}

do_queryremove()
{
	status=`sdpadm status`
	ret=$?

	if [ $ret -eq 0 ] && [ "$status" != "SDP is Disabled" ]
	then
		printf "rcm_log_warn=SDP is enabled. Please run 'sdpadm disable' command "
		printf "before un-configuring IB HCA/SDP\n";
		printf "rcm_failure_reason=SDP is enabled on this system\n";
		exit 3;
	elif [ $ret -ne 0 ]
	then
		printf "rcm_log_warn='sdpadm status' command failed. Could not find the "
		printf "status of SDP\n";
		printf "rcm_failure_reason='sdpadm status' command failed.\n";
		exit 1;
	fi
	exit 0;
}

do_preremove()
{
	exit 0;
}

do_undoremove()
{
	exit 0;
}

do_postremove()
{
	exit 0;
}

case "$1" in 
	scriptinfo) do_scriptinfo;;
	register) do_register;;
	resourceinfo) do_resourceinfo $2;;
	queryremove) do_queryremove $2;;
	preremove) do_preremove $2;;
	undoremove) do_undoremove $2;;
	postremove) do_postremove $2;;
	*) echo Unknown option $1;;
esac
