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
 * Print input and output values for each NFSv3 andf NFSv4 operation,
 * optionally for a specified client, share and zone.
 *
 * Usage: nfs-trace.d [<client ip>|all [<share path>|all] [<zone id>]]]
 *
 * example: nfs_trace.d 192.168.123.1 /mypool/fs1  0
 *
 * It is valid to specify <client ip> or <share path> as "all"
 * to quantize data for all clients and/or all shares.
 * Omitting <zone id> will quantize data for all zones.
 */

/*
 * Unfortunately, trying to write this script using wildcards, for example:
 *	nfsv3:::op-*-start {}
 *	nfsv3:::op-*-done {}
 * prints the operation-specific args[2] structure as the incorrect type.
 * Until this is resolved it is necessary to explicitly list each operation.
 *
 * See nfs-time.d for an example of using the wildcard format when there are
 * no operation-specific args (args[2]) being traced.
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

nfsv3:::op-getattr-start,
nfsv3:::op-setattr-start,
nfsv3:::op-lookup-start,
nfsv3:::op-access-start,
nfsv3:::op-commit-start,
nfsv3:::op-create-start,
nfsv3:::op-fsinfo-start,
nfsv3:::op-fsstat-start,
nfsv3:::op-link-start,
nfsv3:::op-mkdir-start,
nfsv3:::op-mknod-start,
nfsv3:::op-pathconf-start,
nfsv3:::op-read-start,
nfsv3:::op-readdir-start,
nfsv3:::op-readdirplus-start,
nfsv3:::op-readlink-start,
nfsv3:::op-remove-start,
nfsv3:::op-rename-start,
nfsv3:::op-rmdir-start,
nfsv3:::op-symlink-start,
nfsv3:::op-write-start
/ ((all_clients) || (args[0]->ci_remote == client)) &&
   ((all_shares) || (args[1]->noi_shrpath == share)) &&
   ((all_zones) || (args[1]->noi_zoneid == zoneid)) /
{
	printf("\n");
	print(*args[0]);
	printf("\n");
	print(*args[1]);
	printf("\n");
	print(*args[2]);
	printf("\n");
}

nfsv3:::op-getattr-done,
nfsv3:::op-setattr-done,
nfsv3:::op-lookup-done,
nfsv3:::op-access-done,
nfsv3:::op-commit-done,
nfsv3:::op-create-done,
nfsv3:::op-fsinfo-done,
nfsv3:::op-fsstat-done,
nfsv3:::op-link-done,
nfsv3:::op-mkdir-done,
nfsv3:::op-mknod-done,
nfsv3:::op-pathconf-done,
nfsv3:::op-read-done,
nfsv3:::op-readdir-done,
nfsv3:::op-readdirplus-done,
nfsv3:::op-readlink-done,
nfsv3:::op-remove-done,
nfsv3:::op-rename-done,
nfsv3:::op-rmdir-done,
nfsv3:::op-symlink-done,
nfsv3:::op-write-done
/ ((all_clients) || (args[0]->ci_remote == client)) &&
   ((all_shares) || (args[1]->noi_shrpath == share)) &&
   ((all_zones) || (args[1]->noi_zoneid == zoneid)) /
{
	/*
	printf("\n");
	print(*args[0]);
	printf("\n");
	print(*args[1]);
	*/
	printf("\n");
	print(*args[2]);
	printf("\n");
}

nfsv4:::op-access-start,
nfsv4:::op-close-start,
nfsv4:::op-commit-start,
nfsv4:::op-create-start,
nfsv4:::op-delegpurge-start,
nfsv4:::op-delegreturn-start,
nfsv4:::op-getattr-start,
nfsv4:::op-link-start,
nfsv4:::op-lock-start,
nfsv4:::op-lockt-start,
nfsv4:::op-locku-start,
nfsv4:::op-lookup-start,
nfsv4:::op-nverify-start,
nfsv4:::op-open-start,
nfsv4:::op-open-confirm-start,
nfsv4:::op-open-downgrade-start,
nfsv4:::op-openattr-start,
nfsv4:::op-putfh-start,
nfsv4:::op-read-start,
nfsv4:::op-readdir-start,
nfsv4:::op-release-lockowner-start,
nfsv4:::op-remove-start,
nfsv4:::op-rename-start,
nfsv4:::op-renew-start,
nfsv4:::op-secinfo-start,
nfsv4:::op-setattr-start,
nfsv4:::op-setclientid-start,
nfsv4:::op-setclientid-confirm-start,
nfsv4:::op-verify-start,
nfsv4:::op-write-start
/ ((all_clients) || (args[0]->ci_remote == client)) &&
   ((all_shares) || (args[1]->noi_shrpath == share)) &&
   ((all_zones) || (args[1]->noi_zoneid == zoneid)) /
{
	printf("\n");
	print(*args[0]);
	printf("\n");
	print(*args[1]);
	printf("\n");
	print(*args[2]);
	printf("\n");
}

/* These operations do not have args[2] */
nfsv4:::op-getfh-start,
nfsv4:::op-lookupp-start,
nfsv4:::op-putpubfh-start,
nfsv4:::op-putrootfh-start,
nfsv4:::op-readlink-start,
nfsv4:::op-restorefh-start,
nfsv4:::op-savefh-start
/ ((all_clients) || (args[0]->ci_remote == client)) &&
   ((all_shares) || (args[1]->noi_shrpath == share)) &&
   ((all_zones) || (args[1]->noi_zoneid == zoneid)) /
{
	printf("\n");
	print(*args[0]);
	printf("\n");
	print(*args[1]);
	printf("\n");
}


nfsv4:::op-access-done,
nfsv4:::op-close-done,
nfsv4:::op-commit-done,
nfsv4:::op-create-done,
nfsv4:::op-delegpurge-done,
nfsv4:::op-delegreturn-done,
nfsv4:::op-getattr-done,
nfsv4:::op-getfh-done,
nfsv4:::op-link-done,
nfsv4:::op-lock-done,
nfsv4:::op-lockt-done,
nfsv4:::op-locku-done,
nfsv4:::op-lookup-done,
nfsv4:::op-lookupp-done,
nfsv4:::op-nverify-done,
nfsv4:::op-open-done,
nfsv4:::op-open-confirm-done,
nfsv4:::op-open-downgrade-done,
nfsv4:::op-openattr-done,
nfsv4:::op-putfh-done,
nfsv4:::op-putpubfh-done,
nfsv4:::op-putrootfh-done,
nfsv4:::op-read-done,
nfsv4:::op-readdir-done,
nfsv4:::op-readlink-done,
nfsv4:::op-release-lockowner-done,
nfsv4:::op-remove-done,
nfsv4:::op-rename-done,
nfsv4:::op-renew-done,
nfsv4:::op-restorefh-done,
nfsv4:::op-savefh-done,
nfsv4:::op-secinfo-done,
nfsv4:::op-setattr-done,
nfsv4:::op-setclientid-done,
nfsv4:::op-setclientid-confirm-done,
nfsv4:::op-verify-done,
nfsv4:::op-write-done
/ ((all_clients) || (args[0]->ci_remote == client)) &&
   ((all_shares) || (args[1]->noi_shrpath == share)) &&
   ((all_zones) || (args[1]->noi_zoneid == zoneid)) /
{
	/*
	printf("\n");
	print(*args[0]);
	printf("\n");
	print(*args[1]);
	*/
	printf("\n");
	print(*args[2]);
	printf("\n");
}

dtrace:::END
{
}
