#!/usr/bin/ksh -p
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
# Copyright 2011 Joyent, Inc.  All rights reserved.
# Use is subject to license terms.
#

unset LD_LIBRARY_PATH
PATH=/usr/bin:/usr/sbin
export PATH

myzone=`zonename`

if [[ $myzone != "global" ]]; then
	echo "zonemon can only be run in the global zone"
	exit 1
fi

show_kernel()
{
    echo "Kernel state:"
    echo "::zone" | mdb -k | nawk '{
	print $0
	if ($3 == "shutting_down" || $3 == "down")
		hung[$1]=$2
    } END {
	for (i in hung) {
		printf("Zone %d shutting down - references\n", hung[i]);
		cmd = "echo \"" i "::zone -rv\" | mdb -k"
		system(cmd);
	}
        for (i in hung) {
		printf("Zone %d shutting down - zsd\n", hung[i]);
		cmd = "echo \"" i "::walk zsd | ::print struct zsd_entry\"" \
		    "| mdb -k"
		system(cmd);
	}

	for (i in hung) {
		printf("Zone %d shutting down - processes\n", hung[i]);
		cmd = "echo \"::ps -z\" | mdb -k | nawk -v zid=" hung[i] \
		    " \047{if ($6 == zid) print $0}\047"
		system(cmd);
	}
    }'
}

show_zone_up_down()
{
	/usr/sbin/dtrace -n '
	#pragma D option quiet

	inline string ZONENAME = "'$ZONENAME'";

	dtrace:::BEGIN
	{
		zname = ZONENAME;
	}

	/*
	 * arg1 is zone_status_t
	 *	ZONE_IS_UNINITIALIZED = 0
	 *	ZONE_IS_INITIALIZED
	 *	ZONE_IS_READY
	 *	ZONE_IS_BOOTING
	 *	ZONE_IS_RUNNING
	 *	ZONE_IS_SHUTTING_DOWN
	 *	ZONE_IS_EMPTY
	 *	ZONE_IS_DOWN
	 *	ZONE_IS_DYING
	 *	ZONE_IS_DEAD
	 */
	fbt::zone_status_set:entry
	/stringof(((zone_t *)arg0)->zone_name) == zname &&
	    (arg1 == 4 || arg1 == 5)/
	{
		printf("%13s %3d %s\n",
		    (arg1 == 4 ? "running" : "shutting_down"), arg1,
		    stringof(((zone_t *)arg0)->zone_name));
	}
	'
	exit 0
}

show_all_zone_up_down()
{
	/usr/sbin/dtrace -n '
	#pragma D option quiet

	/*
	 * arg1 is zone_status_t
	 *	ZONE_IS_UNINITIALIZED = 0
	 *	ZONE_IS_INITIALIZED
	 *	ZONE_IS_READY
	 *	ZONE_IS_BOOTING
	 *	ZONE_IS_RUNNING
	 *	ZONE_IS_SHUTTING_DOWN
	 *	ZONE_IS_EMPTY
	 *	ZONE_IS_DOWN
	 *	ZONE_IS_DYING
	 *	ZONE_IS_DEAD
	 */
	fbt::zone_status_set:entry
	/arg1 == 4 || arg1 == 5/
	{
		printf("%13s %3d %s\n",
		    (arg1 == 4 ? "running" : "shutting_down"), arg1,
		    stringof(((zone_t *)arg0)->zone_name));
	}
	'
	exit 0
}

show_zone_trans()
{
	echo "State Transitions:"

	/usr/sbin/dtrace -n '
	#pragma D option quiet

	fbt::zone_create:entry
	{
		this->zonename = stringof(copyinstr(arg0));
		printf("%Y %15s   - %s\n", walltimestamp, probefunc,
		    this->zonename);
	}

	fbt::zone_create:return
	/errno != 0/
	{
		printf("%Y %15s    - %s failed, errno %d\n", walltimestamp,
		    probefunc, this->zonename, errno);
		this->zonename=0;
	}

	fbt::zone_create:return
	/errno == 0/
	{
		printf("%Y %15s %3d %s\n", walltimestamp, probefunc, arg1,
		     this->zonename);
		this->zonename=0;
	}

	fbt::zsched:entry
	{
		printf("%Y %15s %3d\n", walltimestamp, probefunc,
		    ((struct zsched_arg *)args[0])->zone->zone_id);
	}

	fbt::zone_start_init:entry
	{
       	 printf("%Y %15s %3d\n", walltimestamp, probefunc,
	    curpsinfo->pr_zoneid);
	}

	fbt::zone_boot:entry
	{
		this->zoneid=args[0];
	}

	fbt::zone_boot:return
	/errno != 0/
	{
		printf("%Y %15s %3d failed, errno %d\n", walltimestamp,
		    probefunc, this->zoneid, errno);
		this->zoneid=0;
	}

	fbt::zone_boot:return
	/errno == 0/
	{
		printf("%Y %15s %3d\n", walltimestamp, probefunc, this->zoneid);
		this->zoneid=0;
	}

	fbt::zone_empty:entry
	{
		this->zoneid=((zone_t *)args[0])->zone_id;
		printf("%Y %15s %3d start\n", walltimestamp, probefunc,
		    this->zoneid);
	}

	fbt::zone_empty:return
	{
		printf("%Y %15s %3d return\n", walltimestamp, probefunc,
		    this->zoneid);
		this->zoneid=0;
	}

	fbt::zone_shutdown:entry,
	fbt::zone_destroy:entry
	{
		printf("%Y %15s %3d\n", walltimestamp, probefunc, args[0]);
		this->zoneid=args[0];
	}

	fbt::zone_shutdown:return,
	fbt::zone_destroy:return
	/errno != 0/
	{
		printf("%Y %15s %3d failed, errno %d\n", walltimestamp,
		    probefunc, this->zoneid, errno);
		this->zoneid=0;
	}

	fbt::zone_shutdown:return,
	fbt::zone_destroy:return
	/errno == 0/
	{
		this->zoneid=0;
	}
	'

	exit 0
}

do_kern=0
do_mon=0
do_up_down=0
do_all_up_down=0

while getopts "kwz:Z" opt
do
	case "$opt" in
		k)	do_kern=1;;
		w)	do_mon=1;;
		z)	do_up_down=1
			ZONENAME=$OPTARG
			;;
		Z)	do_all_up_down=1;;
		*)	printf "zonemon [-k] [-w | -z zonename | -Z]\n"
			exit 1;;
	esac
done
shift OPTIND-1

(( $do_kern == 1 )) && show_kernel
(( $do_up_down == 1 )) && show_zone_up_down
(( $do_all_up_down == 1 )) && show_all_zone_up_down
(( $do_mon == 1 )) && show_zone_trans
