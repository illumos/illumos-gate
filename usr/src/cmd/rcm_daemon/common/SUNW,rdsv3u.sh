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
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
#

#
# RCM script to inform if RDSv3 is currently used
#
rcm_script_version=1
rcm_script_func_info="RDSv3 (un)configuration rcm script"
rcm_cmd_timeout=10
rcm_resource_name=/devices/ib/rdsv3@0:rdsv3

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
	if [ x"$1" = x"/devices/ib/rdsv3@0:rdsv3" ]
	then
		printf "rcm_resource_usage_info=RDSv3 IB device 0\n";
		exit 0;
	else
		printf "rcm_failure_reason=Unknown RDSv3 device\n";
		exit 3;
	fi
}

do_queryremove()
{
	output=`/usr/sbin/fuser $rcm_resource_name 2>&1`
	ret=$?

	sockrds=`echo "$output" | grep 'sockrds'`

        if [ $ret -eq 0 ] && [ ! -z "$sockrds" ]
        then
                printf "rcm_log_warn=RDSv3 is being used currently. "
                printf "Please stop processes currently running on it "
		printf "before un-configuring IB HCA/RDSv3.\n";
                printf "rcm_failure_reason=RDSv3 is being used on this system\n";
                exit 3;
        elif [ $ret -ne 0 ]
        then
                printf "rcm_log_warn='fuser $rcm_resource_name' command failed."
                printf "rcm_failure_reason='fuser $rcm_resource_name' command "
		printf "failed.\n";
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
