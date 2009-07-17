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
 * Copyright (c) 2008-2009, Intel Corporation.
 * All Rights Reserved.
 */

#include <unistd.h>
#include <stdio.h>
#include <dtrace.h>
#include <string.h>
#include <stdlib.h>
#include <memory.h>
#include <limits.h>

#include "latencytop.h"

static dtrace_hdl_t *g_dtp = NULL;	/* The dtrace handle */
static pid_t pid_self = -1;		/* PID of our own process */

/*
 * Checks if the process is latencytop itself or sched (if we are not tracing
 * sched), we should ignore them.
 */
#define	SHOULD_IGNORE(pid)		\
	((!g_config.trace_sched && 0 == (pid)) || pid_self == (pid))

/*
 * Get an integer value from dtrace record.
 */
static uint64_t
rec_get_value(void *a, size_t b)
{
	uint64_t ret = 0;

	switch (b) {
	case sizeof (uint64_t):
		ret = *((uint64_t *)(a));
		break;
	case sizeof (uint32_t):
		ret = *((uint32_t *)(a));
		break;
	case sizeof (uint16_t):
		ret = *((uint16_t *)(a));
		break;
	case sizeof (uint8_t):
		ret = *((uint8_t *)(a));
		break;
	default:
		break;
	}

	return (ret);
}

/*
 * Callback to process each aggregation in the snapshot.
 * This one processes lt_call_*, which contains on/off cpu activites.
 */
static int
aggwalk_call(const dtrace_aggdata_t *data, lt_stat_type_t stat_type)
{
	const int REC_PID = 1;
	const int REC_TID = 2;
	const int REC_STACK = 3;
	const int REC_AGG = 4;
	const int NREC = 5;

	dtrace_aggdesc_t *aggdesc = data->dtada_desc;
	dtrace_syminfo_t dts;
	GElf_Sym sym;
	caddr_t addr;
	pid_t pid;
	id_t tid;
	unsigned int stack_depth;
	unsigned int pc_size;
	uint64_t pc;
	uint64_t agg_value;
	char *ptr = NULL;
	char *buffer = NULL;
	int ptrsize;
	unsigned int buffersize;

	if (aggdesc->dtagd_nrecs < NREC) {
		/* Not enough records */
		goto err;
	}

	if (aggdesc->dtagd_rec[REC_PID].dtrd_action != DTRACEACT_DIFEXPR) {
		/* Record is not PID, this is an error. */
		goto err;
	}
	pid = rec_get_value(
	    data->dtada_data + aggdesc->dtagd_rec[REC_PID].dtrd_offset,
	    aggdesc->dtagd_rec[REC_PID].dtrd_size);
	if (SHOULD_IGNORE(pid)) {
		goto done;
	}

	if (aggdesc->dtagd_rec[REC_TID].dtrd_action != DTRACEACT_DIFEXPR) {
		/* Record is not TID, this is an error. */
		goto err;
	}
	tid = rec_get_value(
	    data->dtada_data + aggdesc->dtagd_rec[REC_TID].dtrd_offset,
	    aggdesc->dtagd_rec[REC_TID].dtrd_size);

	if (aggdesc->dtagd_rec[REC_STACK].dtrd_action != DTRACEACT_STACK) {
		/* Record is not stack(), this is an error. */
		goto err;
	}

	/* Parse stack array from dtagd_rec */
	stack_depth = aggdesc->dtagd_rec[REC_STACK].dtrd_arg;
	pc_size = aggdesc->dtagd_rec[REC_STACK].dtrd_size / stack_depth;
	addr = data->dtada_data + aggdesc->dtagd_rec[REC_STACK].dtrd_offset;
	buffersize = (stack_depth * (2 * PATH_MAX + 2) + 1) * sizeof (char);
	buffer = (char *)lt_malloc(buffersize);
	ptr = buffer;
	ptrsize = buffersize;

	/* Print the stack */
	while (stack_depth > 0) {
		pc = rec_get_value(addr, pc_size);
		if (pc == 0) {
			break;
		}
		addr += pc_size;
		if (dtrace_lookup_by_addr(g_dtp, pc, &sym, &dts) == 0) {
			int len;
			len = snprintf(ptr, ptrsize,
			    "%s`%s ", dts.dts_object, dts.dts_name);
			ptrsize -= len;
			if (ptrsize <= 0) {
				/*
				 * Snprintf returns "desired" length, so
				 * reaching here means our buffer is full.
				 * Move ptr to last byte in the buffer and
				 * break early.
				 */
				ptr = &buffer[buffersize-1];
				break;
			} else	{
				ptr += len;
			}
		}
	}

	if (ptr != buffer) {
		/*
		 * We have printed something,
		 * so it is safe to remove last ' '.
		 */
		*(ptr-1) = 0;
	}

	/* Parsing aggregation data */
	if (!DTRACEACT_ISAGG(aggdesc->dtagd_rec[REC_AGG].dtrd_action)) {
		/* Record is not aggregation, this is an error. */
		goto err;
	}
	agg_value = rec_get_value(
	    data->dtada_data + aggdesc->dtagd_rec[REC_AGG].dtrd_offset,
	    aggdesc->dtagd_rec[REC_AGG].dtrd_size);

	lt_stat_update(pid, tid, buffer, stat_type, agg_value);

done:
	if (buffer != NULL) {
		free(buffer);
	}
	return (0);

err:
	if (buffer != NULL) {
		free(buffer);
	}
	return (-1);
}

/*
 * Callback to process each aggregation in the snapshot.
 * This one processes lt_named_*, which contains data such as lock spinning.
 */
static int
aggwalk_named(const dtrace_aggdata_t *data, lt_stat_type_t stat_type)
{
	const int REC_PID = 1;
	const int REC_TID = 2;
	const int REC_TYPE = 3;
	const int REC_AGG = 4;
	const int NREC = 5;

	dtrace_aggdesc_t *aggdesc = data->dtada_desc;
	pid_t pid;
	id_t tid;
	uint64_t agg_value;
	int cause_id;
	char *type = NULL;

	if (aggdesc->dtagd_nrecs < NREC) {
		/* Not enough records */
		return (-1);
	}

	if (aggdesc->dtagd_rec[REC_PID].dtrd_action != DTRACEACT_DIFEXPR) {
		/* Record is not PID, this is an error. */
		return (-1);
	}
	pid = rec_get_value(
	    data->dtada_data + aggdesc->dtagd_rec[REC_PID].dtrd_offset,
	    aggdesc->dtagd_rec[REC_PID].dtrd_size);
	if (SHOULD_IGNORE(pid)) {
		return (0);
	}
	if (aggdesc->dtagd_rec[REC_TID].dtrd_action != DTRACEACT_DIFEXPR) {
		/* Record is not TID, this is an error. */
		return (-1);
	}
	tid = rec_get_value(
	    data->dtada_data + aggdesc->dtagd_rec[REC_TID].dtrd_offset,
	    aggdesc->dtagd_rec[REC_TID].dtrd_size);

	if (aggdesc->dtagd_rec[REC_TYPE].dtrd_action != DTRACEACT_DIFEXPR) {
		/* Record is not type, this is an error. */
		return (-1);
	}
	type = (char *)data->dtada_data
	    + aggdesc->dtagd_rec[REC_TYPE].dtrd_offset;
	cause_id = lt_table_lookup_named_cause(type, 1);

	/* Parsing aggregation data */
	if (!DTRACEACT_ISAGG(aggdesc->dtagd_rec[REC_AGG].dtrd_action)) {
		/* Record is not aggregation, this is an error. */
		return (-1);
	}
	agg_value = rec_get_value(
	    data->dtada_data + aggdesc->dtagd_rec[REC_AGG].dtrd_offset,
	    aggdesc->dtagd_rec[REC_AGG].dtrd_size);

	lt_stat_update_cause(pid, tid, cause_id, stat_type, agg_value);

	return (0);

}

/*
 * Callback to process each aggregation in the snapshot.
 * This one processes lt_sync_*, which traces synchronization objects.
 */
static int
aggwalk_sync(const dtrace_aggdata_t *data, lt_stat_type_t stat_type)
{
	const int REC_PID = 1;
	const int REC_TID = 2;
	const int REC_STYPE = 3;
	const int REC_WCHAN = 4;
	const int REC_AGG = 5;
	const int NREC = 6;

	dtrace_aggdesc_t *aggdesc = data->dtada_desc;
	pid_t pid;
	id_t tid;
	uint64_t agg_value;
	int stype;
	unsigned long long wchan;

	if (aggdesc->dtagd_nrecs < NREC) {
		/* Not enough records */
		return (-1);
	}

	if (aggdesc->dtagd_rec[REC_PID].dtrd_action != DTRACEACT_DIFEXPR) {
		/* Record is not PID, this is an error. */
		return (-1);
	}
	pid = rec_get_value(
	    data->dtada_data + aggdesc->dtagd_rec[REC_PID].dtrd_offset,
	    aggdesc->dtagd_rec[REC_PID].dtrd_size);
	if (SHOULD_IGNORE(pid)) {
		return (0);
	}

	if (aggdesc->dtagd_rec[REC_TID].dtrd_action != DTRACEACT_DIFEXPR) {
		/* Record is not TID, this is an error. */
		return (-1);
	}
	tid = rec_get_value(
	    data->dtada_data + aggdesc->dtagd_rec[REC_TID].dtrd_offset,
	    aggdesc->dtagd_rec[REC_TID].dtrd_size);

	if (aggdesc->dtagd_rec[REC_STYPE].dtrd_action != DTRACEACT_DIFEXPR) {
		/* Record is not stype, this is an error. */
		return (-1);
	}
	stype = rec_get_value(
	    data->dtada_data + aggdesc->dtagd_rec[REC_STYPE].dtrd_offset,
	    aggdesc->dtagd_rec[REC_STYPE].dtrd_size);

	if (aggdesc->dtagd_rec[REC_WCHAN].dtrd_action != DTRACEACT_DIFEXPR) {
		/* Record is not wchan, this is an error. */
		return (-1);
	}
	wchan = rec_get_value(
	    data->dtada_data + aggdesc->dtagd_rec[REC_WCHAN].dtrd_offset,
	    aggdesc->dtagd_rec[REC_WCHAN].dtrd_size);

	/* Parsing aggregation data */
	if (!DTRACEACT_ISAGG(aggdesc->dtagd_rec[REC_AGG].dtrd_action)) {
		/* Record is not aggregation, this is an error. */
		return (-1);
	}
	agg_value = rec_get_value(
	    data->dtada_data + aggdesc->dtagd_rec[REC_AGG].dtrd_offset,
	    aggdesc->dtagd_rec[REC_AGG].dtrd_size);

	lt_stat_update_sobj(pid, tid, stype, wchan, stat_type, agg_value);

	return (0);
}

/*
 * Callback to process each aggregation in the snapshot.
 * This one dispatches to different aggwalk_*().
 */
/* ARGSUSED */
static int
aggwalk(const dtrace_aggdata_t *data, void *arg)
{
	char *tmp;
	char buffer[32];
	lt_stat_type_t stat_type = LT_STAT_COUNT;
	int (*func)(const dtrace_aggdata_t *, lt_stat_type_t);

	(void) strncpy(buffer, data->dtada_desc->dtagd_name, sizeof (buffer));
	buffer[sizeof (buffer) - 1] = 0;

	tmp = strtok(buffer, "_");
	if (strcmp(tmp, "lt") != 0) {
		goto done;
	}

	tmp = strtok(NULL, "_");
	if (strcmp(tmp, "call") == 0) {
		func = aggwalk_call;
	} else if (strcmp(tmp, "named") == 0) {
		func = aggwalk_named;
	} else if (strcmp(tmp, "sync") == 0) {
		func = aggwalk_sync;
	} else {
		goto done;
	}

	tmp = strtok(NULL, "_");
	if (strcmp(tmp, "count") == 0) {
		stat_type = LT_STAT_COUNT;
	} else if (strcmp(tmp, "sum") == 0) {
		stat_type = LT_STAT_SUM;
	} else if (strcmp(tmp, "max") == 0) {
		stat_type = LT_STAT_MAX;
	} else {
		goto done;
	}

	(void) func(data, stat_type);

done:
	/* We have our data, remove it from DTrace. */
	return (DTRACE_AGGWALK_REMOVE);
}

/*
 * Callback to handle DTrace drop data events.
 */
/*ARGSUSED*/
static int
drop_handler(const dtrace_dropdata_t *data, void *user)
{
	lt_display_error("Drop: %s\n", data->dtdda_msg);
	/*
	 * Pretend nothing happened. So our program can continue.
	 */
	return (DTRACE_HANDLE_OK);
}

/*
 * DTrace initialization. The D script is running when this function returns.
 */
int
lt_dtrace_init(void)
{
	dtrace_prog_t *prog;
	dtrace_proginfo_t info;
	int err;
	FILE *fp_script = NULL;

	pid_self = getpid();
	/* Open dtrace, set up handler */
	g_dtp = dtrace_open(DTRACE_VERSION, 0, &err);
	if (g_dtp == NULL) {
		lt_display_error("Cannot open dtrace library: %s\n",
		    dtrace_errmsg(NULL, err));
		return (-1);
	}

	if (dtrace_handle_drop(g_dtp, &drop_handler, NULL) == -1) {
		lt_display_error("Cannot install DTrace handle: %s\n",
		    dtrace_errmsg(NULL, err));
		return (-1);
	}

	/* Load D script, set up macro and compile */
#ifdef EMBED_CONFIGS
	/* Create a temp file because libdtrace use cpp(1) on files only. */
	fp_script = tmpfile();
	if (fp_script == NULL) {
		lt_display_error("Cannot create tmp file\n");
		return (-1);
	}
	(void) fwrite(latencytop_d, latencytop_d_len, 1, fp_script);
	(void) fseek(fp_script, 0, SEEK_SET);
#else
	fp_script = fopen(DEFAULT_D_SCRIPT_NAME, "r");
	if (fp_script == NULL) {
		lt_display_error("Cannot open script file %s\n",
		    DEFAULT_D_SCRIPT_NAME);
		return (-1);
	}
#endif	/* EMBED_CONFIGS */

	if (g_config.enable_filter) {
		(void) dtrace_setopt(g_dtp, "define", "ENABLE_FILTER");
	}
	if (g_config.trace_syncobj) {
		(void) dtrace_setopt(g_dtp, "define", "ENABLE_SYNCOBJ");
	}
	if (g_config.trace_sched) {
		(void) dtrace_setopt(g_dtp, "define", "ENABLE_SCHED");
	}
	if (g_config.low_overhead_mode) {
		(void) dtrace_setopt(g_dtp, "define", "ENABLE_LOW_OVERHEAD");
	}

	prog = dtrace_program_fcompile(g_dtp, fp_script,
	    DTRACE_C_CPP, 0, NULL);
	(void) fclose(fp_script);
	if (prog == NULL) {
		lt_display_error("Failed to compile D script.\n");
		return (dtrace_errno(g_dtp));
	}

	/* Execute the D script */
	if (dtrace_program_exec(g_dtp, prog, &info) == -1) {
		lt_display_error("Failed to enable probes.\n");
		return (dtrace_errno(g_dtp));
	}
	if (dtrace_go(g_dtp) != 0) {
		lt_display_error("Failed to run D script.\n");
		return (dtrace_errno(g_dtp));
	}
	return (0);
}

/*
 * Worker function to move aggregator data to user space.
 * Needs to be called periodically to prevent running out of kernel memory.
 */
int
lt_dtrace_work(int force)
{
	static uint64_t last_snap = 0;
	uint64_t now = lt_millisecond();

	if (!force && now - last_snap < g_config.snap_interval) {
		return (last_snap + g_config.snap_interval - now);
	}

	if (dtrace_status(g_dtp) == -1) {
		lt_display_error("Failed when getting status: %s\n",
		    dtrace_errmsg(g_dtp, dtrace_errno(g_dtp)));
		return (-1);
	}

	if (dtrace_aggregate_snap(g_dtp) != 0) {
		lt_display_error("Failed to snap aggregate: %s\n",
		    dtrace_errmsg(g_dtp, dtrace_errno(g_dtp)));
		return (-1);
	}

	last_snap = now;
	return (0);
}

/*
 * Walk through aggregator and collect data to LatencyTOP.
 * Different from lt_dtrace_work, this one moves data from libdtrace
 * to latencytop.
 * This needs to be called immediately before update UI.
 */
int
lt_dtrace_collect(void)
{
	if (lt_dtrace_work(1) != 0) {
		return (-1);
	}

	if (dtrace_aggregate_walk(g_dtp, aggwalk, NULL) != 0) {
		lt_display_error("Failed to sort aggregate: %s\n",
		    dtrace_errmsg(g_dtp, dtrace_errno(g_dtp)));
		return (-1);
	}

	/*
	 * Probably no need to clear again, because we removed everything.
	 * Paranoid.
	 */
	dtrace_aggregate_clear(g_dtp);

	return (0);
}

/*
 * Clean up and close DTrace.
 */
void
lt_dtrace_deinit(void)
{
	(void) dtrace_stop(g_dtp);
	dtrace_close(g_dtp);
}
