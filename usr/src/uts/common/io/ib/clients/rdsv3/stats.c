/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This file contains code imported from the OFED rds source file stats.c
 * Oracle elects to have and use the contents of stats.c under and governed
 * by the OpenIB.org BSD license (see below for full license text). However,
 * the following notice accompanied the original version of this file:
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

struct rdsv3_statistics *rdsv3_stats = NULL;
uint_t	nr_cpus;

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
	struct rds_info_counter ctr;
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
	struct rdsv3_statistics stats;
	uint64_t *src;
	uint64_t *sum;
	size_t i;
	int cpu;
	unsigned int avail;

	avail = len / sizeof (struct rds_info_counter);

	if (avail < ARRAY_SIZE(rdsv3_stat_names)) {
		avail = 0;
		goto trans;
	}

	bzero(&stats, sizeof (struct rdsv3_statistics));

	for (cpu = 0; cpu < nr_cpus; cpu++) {
		src = (uint64_t *)&(rdsv3_per_cpu(rdsv3_stats, cpu));
		sum = (uint64_t *)&stats;
		for (i = 0;
		    i < sizeof (struct rdsv3_statistics) / sizeof (uint64_t);
		    i++)
			*(sum++) += *(src++);
	}

	rdsv3_stats_info_copy(iter, (uint64_t *)&stats, rdsv3_stat_names,
	    ARRAY_SIZE(rdsv3_stat_names));
	avail -= ARRAY_SIZE(rdsv3_stat_names);

trans:
	lens->each = sizeof (struct rds_info_counter);
	lens->nr = rdsv3_trans_stats_info_copy(iter, avail) +
	    ARRAY_SIZE(rdsv3_stat_names);
}

void
rdsv3_stats_exit(void)
{
	rdsv3_info_deregister_func(RDS_INFO_COUNTERS, rdsv3_stats_info);

	ASSERT(rdsv3_stats);
	kmem_free(rdsv3_stats,
	    nr_cpus * sizeof (struct rdsv3_statistics));
	rdsv3_stats = NULL;
}

int
rdsv3_stats_init(void)
{
	/*
	 * Note the max number of cpus that this system can have at most.
	 */
	nr_cpus = max_ncpus;
	ASSERT(rdsv3_stats == NULL);
	rdsv3_stats = kmem_zalloc(nr_cpus *
	    sizeof (struct rdsv3_statistics), KM_SLEEP);

	rdsv3_info_register_func(RDS_INFO_COUNTERS, rdsv3_stats_info);
	return (0);
}
