#!/usr/sbin/dtrace -s

/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Quantize the time spent in each NFSv3 andf NFSv4 operation,
 * optionally for a specified client, share and zone.
 *
 * Usage: nfs-time.d [<client ip>|all [<share path>|all] [<zone id>]]]
 *
 * example: nfs_time.d 192.168.123.1 /mypool/fs1  0
 *
 * It is valid to specify <client ip> or <share path> as "all"
 * to quantize data for all clients and/or all shares.
 * Omitting <zone id> will quantize data for all zones.
 */

#pragma D option flowindent
#pragma D option defaultargs

dtrace:::BEGIN
{
	all_clients = (($$1 == NULL) || ($$1 == "all")) ? 1 : 0;
	all_shares = (($$2 == NULL) || ($$2 == "all")) ? 1 : 0;
	all_zones = ($$3 == NULL) ? 1 : 0;

	client = $$1;
	share = $$2;
	zoneid = $3;

	printf("%Y - client=%s share=%s zone=%s)\n", walltimestamp,
	    (all_clients) ? "all" : client,
	    (all_shares) ? "all" : share,
	    (all_zones) ? "all" : $$3);
}

nfsv3:::op-*-start,
nfsv4:::op-*-start
{
	self->ts[probefunc] = timestamp;
}

nfsv3:::op-*-done,
nfsv4:::op-*-done
/ ((all_clients) || (args[0]->ci_remote == client)) &&
   ((all_shares) || (args[1]->noi_shrpath == share)) &&
   ((all_zones) || (args[1]->noi_zoneid == zoneid)) /
{
	elapsed = (timestamp - self->ts[probefunc]);
	@q[probefunc]=quantize(elapsed);
}

tick-5s
{
	printa(@q);
	/*
	 * uncomment "clear" to quantize per 5s interval
	 * rather than cumulative for duration of script.
	 * clear(@q);
	 */
}

dtrace:::END
{
}
