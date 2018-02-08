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
 * Copyright (c) 2016, 2018 by Delphix. All rights reserved.
 */

/*
 * This measures metrics that relate to the performance of the ZIL.
 *
 * The "zil_commit" and "zil_commit_writer" fuctions are instrumented.
 * For each function, the number of times each function is called is
 * tracked, as well as the average latency for function, and a histogram
 * of the latencies for each function.
 */

#pragma D option aggsortkey
#pragma D option quiet

BEGIN
{
	@c["zil_commit"] = count();
	@a["zil_commit"] = avg(0);
	@h["zil_commit"] = quantize(0);

	@c["zil_commit_writer"] = count();
	@a["zil_commit_writer"] = avg(0);
	@h["zil_commit_writer"] = quantize(0);

	clear(@c);
	clear(@a);
	clear(@h);
}

fbt:zfs:zil_commit:entry
/ args[0]->zl_spa->spa_name == $$1 /
{
	self->zc_elapsed = timestamp;
}

fbt:zfs:zil_commit:return
/ self->zc_elapsed /
{
	@c[probefunc] = count();
	@a[probefunc] = avg(timestamp - self->zc_elapsed);
	@h[probefunc] = quantize(timestamp - self->zc_elapsed);
	self->zc_elapsed = 0;
}

fbt:zfs:zil_commit_writer:entry
/ self->zc_elapsed && args[0]->zl_spa->spa_name == $$1 /
{
	self->zcw_elapsed = timestamp;
}

fbt:zfs:zil_commit_writer:return
/ self->zcw_elapsed /
{
	@c[probefunc] = count();
	@a[probefunc] = avg(timestamp - self->zcw_elapsed);
	@h[probefunc] = quantize(timestamp - self->zcw_elapsed);
	self->zcw_elapsed = 0;
}

tick-$2s
{
	printf("%u\n", `time);
	printa("counts_%-21s %@u\n", @c);
	printa("avgs_%-21s %@u\n", @a);
	printa("histograms_%-21s %@u\n", @h);

	clear(@c);
	clear(@a);
	clear(@h);
}

ERROR
{
	trace(arg1);
	trace(arg2);
	trace(arg3);
	trace(arg4);
	trace(arg5);
}
