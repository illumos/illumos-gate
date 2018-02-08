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
 * Copyright (c) 2013, 2016 by Delphix. All rights reserved.
 */

/*
 * This measures the IO operations as seen by the ZPL layer (e.g.
 * zfs_read and zfs_write), as well as the underlying block layer (e.g.
 * the "io" dtrace provider).
 *
 * time: The number of seconds elapsed since the epoch
 * @ops: collects the count of each metric (e.g. count of zfs_read calls)
 * @latencies: collects the latency information of each metric
 * @histograms: collects histograms of the latency for each metric
 * @bytes: collects the throughput information for each metric
 */

#include <sys/file.h>
#include <sys/fs/zfs.h>

#pragma D option aggsortkey
#pragma D option quiet

BEGIN
{
	@ops["read"] = count();
	@ops["write"] = count();
	@ops["zfs_read"] = count();
	@ops["zfs_write"] = count();
	@ops["zfs_write_sync"] = count();
	@ops["zfs_write_async"] = count();
	@latencies["read"] = avg(0);
	@latencies["write"] = avg(0);
	@latencies["zfs_read"] = avg(0);
	@latencies["zfs_write"] = avg(0);
	@latencies["zfs_write_sync"] = avg(0);
	@latencies["zfs_write_async"] = avg(0);
	@histograms["read"] = quantize(0);
	@histograms["write"] = quantize(0);
	@histograms["zfs_read"] = quantize(0);
	@histograms["zfs_write"] = quantize(0);
	@histograms["zfs_write_sync"] = quantize(0);
	@histograms["zfs_write_async"] = quantize(0);
	@bytes["read"] = sum(0);
	@bytes["write"] = sum(0);
	@bytes["zfs_read"] = sum(0);
	@bytes["zfs_write"] = sum(0);
	@bytes["zfs_write_sync"] = sum(0);
	@bytes["zfs_write_async"] = sum(0);
	clear(@ops);
	clear(@latencies);
	clear(@histograms);
	clear(@bytes);
}

fbt:zfs:zfs_read:entry,
fbt:zfs:zfs_write:entry
{
	this->zp = (znode_t *)args[0]->v_data;
	self->os = this->zp->z_zfsvfs->z_os;
	self->poolname = stringof(self->os->os_spa->spa_name);
}

fbt:zfs:zfs_read:entry,
fbt:zfs:zfs_write:entry
/ self->poolname == $$1 /
{
	self->zfs_rw = timestamp;
	self->bytes = args[1]->uio_resid;
}

fbt:zfs:zfs_write:entry
/ self->zfs_rw != 0 /
{
	self->flag = self->os->os_sync == ZFS_SYNC_ALWAYS ? "sync" :
	    (args[2] & (FSYNC | FDSYNC)) ? "sync" : "async";
}

fbt:zfs:zfs_write:return
/ self->zfs_rw != 0 /
{
	if (self->flag == "sync") {
		this->name = "zfs_write_sync"
	} else {
		this->name = "zfs_write_async"
	}

	@ops[this->name] = count();
	@bytes[this->name] = sum(self->bytes);
	this->elapsed = timestamp - self->zfs_rw;
	@latencies[this->name] = avg(this->elapsed);
	@histograms[this->name] = quantize(this->elapsed);
}

fbt:zfs:zfs_read:return,
fbt:zfs:zfs_write:return
/ self->zfs_rw != 0 /
{
	@ops[probefunc] = count();
	@bytes[probefunc] = sum(self->bytes);
	this->elapsed = timestamp - self->zfs_rw;
	@latencies[probefunc] = avg(this->elapsed);
	@histograms[probefunc] = quantize(this->elapsed);
	self->zfs_rw = 0;
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
	@histograms[this->name] = quantize(this->elapsed);
	start[args[0]->b_edev, args[0]->b_blkno] = 0;
}

tick-$3s
{
	printf("%u\n", `time);
	printa("ops_%-21s%@u\n", @ops);
	printa("bytes_%-21s%@u\n", @bytes);
	printa("latencies_%-21s%@u\n", @latencies);
	printa("histograms_%-21s%@u\n", @histograms);

	clear(@ops);
	clear(@bytes);
	clear(@latencies);
	clear(@histograms);
}

ERROR
{
	trace(arg1);
	trace(arg2);
	trace(arg3);
	trace(arg4);
	trace(arg5);
}
