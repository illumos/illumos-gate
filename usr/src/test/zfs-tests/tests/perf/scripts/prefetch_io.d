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
 * Copyright (c) 2015, 2016 by Delphix. All rights reserved.
 */

/*
 * prefetch_ios: Number of IOs the prefetcher issued
 * @c["prefetched_demand_reads"]: Number of demand reads already prefetched
 * @c["sync_wait_for_async"]: Number of times sync IO waited for prefetch IO
 * @s["demand"]: Number of non-prefetch read IOs
 * @s["logical"]: Logical (uncompressed) bytes read per interval
 * @s["physical"]: Physical (compressed) bytes read per interval
 */

#pragma D option aggsortkey
#pragma D option quiet

#define	SPA_MINBLOCKSHIFT	9
#define	ARC_FLAGS_PREFETCH	(1 << 3)
#define	HDR_GET_LSIZE(hdr)	((hdr)->b_lsize << SPA_MINBLOCKSHIFT)
#define	HDR_GET_PSIZE(hdr)	((hdr)->b_psize << SPA_MINBLOCKSHIFT)

BEGIN
{
	prefetch_ios = `arc_stats.arcstat_prefetch_data_misses.value.ui64;
	prefetch_ios += `arc_stats.arcstat_prefetch_metadata_misses.value.ui64;
	@s["demand"] = sum(0);
	@s["logical"] = sum(0);
	@s["physical"] = sum(0);
	@c["prefetched_demand_reads"] = count();
	@c["sync_wait_for_async"] = count();
	clear(@s);
	clear(@c);
}

arc_read:arc-demand-hit-predictive-prefetch
{
	@c["prefetched_demand_reads"] = count();
}

arc_read:arc-sync-wait-for-async
{
	@c["sync_wait_for_async"] = count();
}

arc_read_done:entry
/ args[0]->io_spa->spa_name == $$1 /
{
	this->zio = args[0];
	this->hdr = (arc_buf_hdr_t *)this->zio->io_private;
	@s["demand"] = sum(this->hdr->b_flags & ARC_FLAGS_PREFETCH ? 0 : 1);
	@s["logical"] = sum(HDR_GET_LSIZE(this->hdr));
	@s["physical"] = sum(HDR_GET_PSIZE(this->hdr));
}

tick-$2s
{
	this->new_prefetch_ios =
	    `arc_stats.arcstat_prefetch_data_misses.value.ui64 +
	    `arc_stats.arcstat_prefetch_metadata_misses.value.ui64;
	printf("%u\n%-24s\t%u\n", `time, "prefetch_ios",
	    this->new_prefetch_ios - prefetch_ios);
	printa("%-24s\t%@u\n", @s);
	printa("%-24s\t%@u\n", @c);
	prefetch_ios = this->new_prefetch_ios;
	clear(@s);
	clear(@c);
}

ERROR
{
	trace(arg1);
	trace(arg2);
	trace(arg3);
	trace(arg4);
	trace(arg5);
}
