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
 * Copyright (c) 2013, 2015 by Delphix. All rights reserved.
 */

/*
 * time: Seconds since the epoch
 * @ops: The number of reads and writes per interval
 * @bytes: Bytes read and written per interval
 * @latencies: Mean read and write latency per interval in ns
 *   These aggregations are indexed with read/write for back end
 *   statistics and zfs_read/zfs_write for ZPL level statistics.
 */

#pragma D option aggsortkey
#pragma D option quiet

BEGIN
{
	@ops["read"] = count();
	@ops["write"] = count();
	@ops["zfs_read"] = count();
	@ops["zfs_write"] = count();
	@latencies["read"] = avg(0);
	@latencies["write"] = avg(0);
	@latencies["zfs_read"] = avg(0);
	@latencies["zfs_write"] = avg(0);
	@bytes["read"] = sum(0);
	@bytes["write"] = sum(0);
	@bytes["zfs_read"] = sum(0);
	@bytes["zfs_write"] = sum(0);
	clear(@ops);
	clear(@latencies);
	clear(@bytes);
}

fbt:zfs:zfs_read:entry,
fbt:zfs:zfs_write:entry
{
	this->zp = (znode_t *)args[0]->v_data;
	this->poolname = stringof(this->zp->z_zfsvfs->z_os->os_spa->spa_name);
}

fbt:zfs:zfs_read:entry,
fbt:zfs:zfs_write:entry
/ this->poolname == $$1 /
{
	self->ts = timestamp;
	@ops[probefunc] = count();
	@bytes[probefunc] = sum(args[1]->uio_resid);
}

fbt:zfs:zfs_read:return,
fbt:zfs:zfs_write:return
/ self->ts != 0 /
{
	@latencies[probefunc] = avg(timestamp - self->ts);
	self->ts = 0;
}

io:::start
/ strstr($$2, args[1]->dev_statname) != NULL /
{
	start[args[0]->b_edev, args[0]->b_blkno] = timestamp;
}

io:::done
/ start[args[0]->b_edev, args[0]->b_blkno] /
{
	this->elapsed = timestamp - start[args[0]->b_edev, args[0]->b_blkno];
	this->name = args[0]->b_flags & B_READ ? "read" : "write";
	@ops[this->name] = count();
	@bytes[this->name] = sum(args[0]->b_bcount);
	@latencies[this->name] = avg(this->elapsed);
	start[args[0]->b_edev, args[0]->b_blkno] = 0;
}

tick-$3s
{
	printf("%u\n", `time);
	printa("ops_%-21s%@u\n", @ops);
	printa("bytes_%-21s%@u\n", @bytes);
	printa("latencies_%-21s%@u\n", @latencies);

	clear(@ops);
	clear(@bytes);
	clear(@latencies);
}

ERROR
{
	trace(arg1);
	trace(arg2);
	trace(arg3);
	trace(arg4);
	trace(arg5);
}
