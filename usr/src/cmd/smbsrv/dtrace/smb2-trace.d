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
 * Example using the "smb2" dtrace provider.
 * Traces all SMB commands.
 *
 * All these probes provide:
 *	args[0]  conninfo_t
 *	args[1]  smb2opinfo_t
 * Some also provide one of: (not used here)
 *	args[2]  smb_open_args_t
 *	args[2]  smb_rw_args_t
 *
 * Usage: smb2-trace.d [<client ip>|all [<share path>|all] [<zone id>]]]
 *
 * example: smb2_trace.d 192.168.012.001 mypool_fs1  0
 *
 * It is valid to specify <client ip> or <share path> as "all" to
 * print data for all clients and/or all shares.
 * Omitting <zone id> will print data for all zones.
 */

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

smb2:::op-*-start
/ ((all_clients == 1) || (args[0]->ci_remote == client)) &&
   ((all_shares == 1) || (args[1]->soi_share == share)) &&
   ((all_zones == 1) || (args[1]->soi_zoneid == zoneid)) /
{
	printf("clnt=%s mid=0x%x uid=0x%x tid=0x%x\n",
	       args[0]->ci_remote,
	       args[1]->soi_mid,
	       args[1]->soi_uid,
	       args[1]->soi_tid);
}

smb2:::op-*-done
/ ((all_clients == 1) || (args[0]->ci_remote == client)) &&
   ((all_shares == 1) || (args[1]->soi_share == share)) &&
   ((all_zones == 1) || (args[1]->soi_zoneid == zoneid)) /
{
	printf("clnt=%s mid=0x%x status=0x%x\n",
	       args[0]->ci_remote,
	       args[1]->soi_mid,
	       args[1]->soi_status);
}

dtrace:::END
{
}
