/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright (c) 2006 Oracle.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */
#include <sys/rds.h>

#include <sys/ib/clients/rdsv3/rdsv3.h>

RDSV3_DEFINE_PER_CPU(struct rdsv3_statistics, rdsv3_stats);

static char *rdsv3_stat_names[] = {
	"conn_reset",
	"recv_drop_bad_checksum",
	"recv_drop_old_seq",
	"recv_drop_no_sock",
	"recv_drop_dead_sock",
	"recv_deliver_raced",
	"recv_delivered",
	"recv_queued",
	"recv_immediate_retry",
	"recv_delayed_retry",
	"recv_ack_required",
	"recv_rdma_bytes",
	"recv_ping",
	"send_queue_empty",
	"send_queue_full",
	"send_sem_contention",
	"send_sem_queue_raced",
	"send_immediate_retry",
	"send_delayed_retry",
	"send_drop_acked",
	"send_ack_required",
	"send_queued",
	"send_rdma",
	"send_rdma_bytes",
	"send_pong",
	"page_remainder_hit",
	"page_remainder_miss",
	"copy_to_user",
	"copy_from_user",
	"cong_update_queued",
	"cong_update_received",
	"cong_send_error",
	"cong_send_blocked",
};

void
rdsv3_stats_info_copy(struct rdsv3_info_iterator *iter,
    uint64_t *values, char **names, size_t nr)
{
	struct rdsv3_info_counter ctr;
	size_t i;

	for (i = 0; i < nr; i++) {
		ASSERT(!(strlen(names[i]) >= sizeof (ctr.name)));
		(void) strncpy((char *)ctr.name, names[i],
		    sizeof (ctr.name) - 1);
		ctr.value = values[i];

		rdsv3_info_copy(iter, &ctr, sizeof (ctr));
	}
}

/*
 * This gives global counters across all the transports.  The strings
 * are copied in so that the tool doesn't need knowledge of the specific
 * stats that we're exporting.  Some are pretty implementation dependent
 * and may change over time.  That doesn't stop them from being useful.
 *
 * This is the only function in the chain that knows about the byte granular
 * length in userspace.  It converts it to number of stat entries that the
 * rest of the functions operate in.
 */
/* ARGSUSED */
static void
rdsv3_stats_info(struct rsock *sock, unsigned int len,
    struct rdsv3_info_iterator *iter,
    struct rdsv3_info_lengths *lens)
{
	struct rdsv3_statistics stats = {0, };
	uint64_t *src;
	uint64_t *sum;
	size_t i;
	int cpu;
	unsigned int avail;

	avail = len / sizeof (struct rdsv3_info_counter);

	if (avail < ARRAY_SIZE(rdsv3_stat_names)) {
		avail = 0;
		goto trans;
	}

	for (cpu = 0; cpu < NR_CPUS; cpu++) {
		src = (uint64_t *)&(rdsv3_per_cpu(rdsv3_stats, cpu));
		sum = (uint64_t *)&stats;
		for (i = 0; i < sizeof (stats) / sizeof (uint64_t); i++)
			*(sum++) += *(src++);
	}

	rdsv3_stats_info_copy(iter, (uint64_t *)&stats, rdsv3_stat_names,
	    ARRAY_SIZE(rdsv3_stat_names));
	avail -= ARRAY_SIZE(rdsv3_stat_names);

trans:
	lens->each = sizeof (struct rdsv3_info_counter);
	lens->nr = rdsv3_trans_stats_info_copy(iter, avail) +
	    ARRAY_SIZE(rdsv3_stat_names);
}

void
rdsv3_stats_exit(void)
{
	rdsv3_info_deregister_func(RDSV3_INFO_COUNTERS, rdsv3_stats_info);
}

int
rdsv3_stats_init(void)
{
	rdsv3_info_register_func(RDSV3_INFO_COUNTERS, rdsv3_stats_info);
	return (0);
}
