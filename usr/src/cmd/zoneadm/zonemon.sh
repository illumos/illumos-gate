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

echo "Current status:"
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
		printf("Zone %d shutting down - processes\n", hung[i]);
		cmd = "echo \"::ps -z\" | mdb -k | nawk -v zid=" hung[i] \
		    " \047{if ($6 == zid) print $0}\047"
		system(cmd);
	}
}'

echo
echo "Watching:"

/usr/sbin/dtrace -n '
#pragma D option quiet

fbt::zone_create:entry
{
	this->zonename = stringof(copyinstr(arg0));
	printf("%Y %15s   - %s\n", walltimestamp, probefunc, this->zonename);
}

fbt::zone_create:return
/errno != 0/
{
	printf("%Y %15s    - %s failed, errno %d\n", walltimestamp, probefunc,
	     this->zonename, errno);
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
        printf("%Y %15s %3d\n", walltimestamp, probefunc, curpsinfo->pr_zoneid);
}

fbt::zone_boot:entry
{
	this->zoneid=args[0];
}

fbt::zone_boot:return
/errno != 0/
{
        printf("%Y %15s %3d failed, errno %d\n", walltimestamp, probefunc,
	    this->zoneid, errno);
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
        printf("%Y %15s %3d return\n", walltimestamp, probefunc, this->zoneid);
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
	printf("%Y %15s %3d failed, errno %d\n", walltimestamp, probefunc,
	     this->zoneid, errno);
	this->zoneid=0;
}

fbt::zone_shutdown:return,
fbt::zone_destroy:return
/errno == 0/
{
	this->zoneid=0;
}
'
