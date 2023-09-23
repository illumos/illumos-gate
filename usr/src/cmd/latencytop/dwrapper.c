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

static dtrace_hdl_t *g_dtp = NULL;	/* dtrace handle */
static pid_t pid_self = -1;		/* PID of our own process */

/*
 * Ignore sched if sched is not tracked.
 * Also ignore ourselves (i.e., latencytop).
 */
#define	SHOULD_IGNORE(pid)		\
	((!g_config.lt_cfg_trace_sched && 0 == (pid)) || pid_self == (pid))

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
 * Callback to process aggregation lt_call_* (related to on/off cpu
 * activities) in the snapshot.
 */
static int
aggwalk_call(const dtrace_aggdata_t *data, lt_stat_type_t stat_type)
{
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
	char *tag = NULL;
	unsigned int priority;
	enum { REC_PID = 1, REC_TID, REC_STACK, REC_TAG, REC_PRIO, REC_AGG,
	    NREC };

	/* Check action type */
	if ((aggdesc->dtagd_nrecs < NREC) ||
	    (aggdesc->dtagd_rec[REC_PID].dtrd_action != DTRACEACT_DIFEXPR) ||
	    (aggdesc->dtagd_rec[REC_TID].dtrd_action != DTRACEACT_DIFEXPR) ||
	    (aggdesc->dtagd_rec[REC_TAG].dtrd_action != DTRACEACT_DIFEXPR) ||
	    (aggdesc->dtagd_rec[REC_PRIO].dtrd_action != DTRACEACT_DIFEXPR) ||
	    (!DTRACEACT_ISAGG(aggdesc->dtagd_rec[REC_AGG].dtrd_action)) ||
	    (aggdesc->dtagd_rec[REC_STACK].dtrd_action != DTRACEACT_STACK)) {

		return (-1);
	}

	pid = rec_get_value(
	    data->dtada_data + aggdesc->dtagd_rec[REC_PID].dtrd_offset,
	    aggdesc->dtagd_rec[REC_PID].dtrd_size);

	if (SHOULD_IGNORE(pid)) {
		return (0);
	}

	tid = rec_get_value(
	    data->dtada_data + aggdesc->dtagd_rec[REC_TID].dtrd_offset,
	    aggdesc->dtagd_rec[REC_TID].dtrd_size);

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
				 * snprintf returns "desired" length, so
				 * reaching here means our buffer is full.
				 * Move ptr to the last byte of the buffer and
				 * break.
				 */
				ptr = &buffer[buffersize-1];
				break;
			} else {
				ptr += len;
			}
		}
	}

	if (ptr != buffer) {
		/*
		 * We have printed something, so it is safe to remove
		 * the last ' '.
		 */
		*(ptr-1) = '\0';
	}

	tag = (char *)data->dtada_data +
	    aggdesc->dtagd_rec[REC_TAG].dtrd_offset;

	priority = rec_get_value(
	    data->dtada_data + aggdesc->dtagd_rec[REC_PRIO].dtrd_offset,
	    aggdesc->dtagd_rec[REC_PRIO].dtrd_size);

	agg_value = rec_get_value(
	    data->dtada_data + aggdesc->dtagd_rec[REC_AGG].dtrd_offset,
	    aggdesc->dtagd_rec[REC_AGG].dtrd_size);

	lt_stat_update(pid, tid, buffer, tag, priority, stat_type, agg_value);

	if (buffer != NULL)  {
		free(buffer);
	}

	return (0);
}

/*
 * Callback to process aggregation lt_named_* (related to lock spinning etc.),
 * in the snapshot.
 */
static int
aggwalk_named(const dtrace_aggdata_t *data, lt_stat_type_t stat_type)
{
	dtrace_aggdesc_t *aggdesc = data->dtada_desc;
	pid_t pid;
	id_t tid;
	uint64_t agg_value;
	int cause_id;
	char *type = NULL;
	enum { REC_PID = 1, REC_TID, REC_TYPE, REC_AGG, NREC };

	/* Check action type */
	if ((aggdesc->dtagd_nrecs < NREC) ||
	    (aggdesc->dtagd_rec[REC_PID].dtrd_action != DTRACEACT_DIFEXPR) ||
	    (aggdesc->dtagd_rec[REC_TID].dtrd_action != DTRACEACT_DIFEXPR) ||
	    (aggdesc->dtagd_rec[REC_TYPE].dtrd_action != DTRACEACT_DIFEXPR) ||
	    (!DTRACEACT_ISAGG(aggdesc->dtagd_rec[REC_AGG].dtrd_action))) {

		return (-1);
	}

	pid = rec_get_value(
	    data->dtada_data + aggdesc->dtagd_rec[REC_PID].dtrd_offset,
	    aggdesc->dtagd_rec[REC_PID].dtrd_size);

	if (SHOULD_IGNORE(pid)) {
		return (0);
	}

	tid = rec_get_value(
	    data->dtada_data + aggdesc->dtagd_rec[REC_TID].dtrd_offset,
	    aggdesc->dtagd_rec[REC_TID].dtrd_size);

	type = (char *)data->dtada_data
	    + aggdesc->dtagd_rec[REC_TYPE].dtrd_offset;
	cause_id = lt_table_cause_from_name(type, 1, CAUSE_FLAG_SPECIAL);

	agg_value = rec_get_value(
	    data->dtada_data + aggdesc->dtagd_rec[REC_AGG].dtrd_offset,
	    aggdesc->dtagd_rec[REC_AGG].dtrd_size);

	lt_stat_update_cause(pid, tid, cause_id, stat_type, agg_value);

	return (0);

}

/*
 * Callback to process aggregation lt_sync_* (related to synchronization
 * objects), in the snapshot.
 */
static int
aggwalk_sync(const dtrace_aggdata_t *data, lt_stat_type_t stat_type)
{
	dtrace_aggdesc_t *aggdesc = data->dtada_desc;
	pid_t pid;
	id_t tid;
	uint64_t agg_value;
	int stype;
	unsigned long long wchan;
	enum { REC_PID = 1, REC_TID, REC_STYPE, REC_WCHAN, REC_AGG, NREC };

	/* Check action type */
	if ((aggdesc->dtagd_nrecs < NREC) ||
	    (aggdesc->dtagd_rec[REC_PID].dtrd_action != DTRACEACT_DIFEXPR) ||
	    (aggdesc->dtagd_rec[REC_TID].dtrd_action != DTRACEACT_DIFEXPR) ||
	    (aggdesc->dtagd_rec[REC_STYPE].dtrd_action != DTRACEACT_DIFEXPR) ||
	    (aggdesc->dtagd_rec[REC_WCHAN].dtrd_action != DTRACEACT_DIFEXPR) ||
	    (!DTRACEACT_ISAGG(aggdesc->dtagd_rec[REC_AGG].dtrd_action))) {

		return (-1);
	}

	pid = rec_get_value(
	    data->dtada_data + aggdesc->dtagd_rec[REC_PID].dtrd_offset,
	    aggdesc->dtagd_rec[REC_PID].dtrd_size);

	if (SHOULD_IGNORE(pid)) {
		return (0);
	}

	tid = rec_get_value(
	    data->dtada_data + aggdesc->dtagd_rec[REC_TID].dtrd_offset,
	    aggdesc->dtagd_rec[REC_TID].dtrd_size);

	stype = rec_get_value(
	    data->dtada_data + aggdesc->dtagd_rec[REC_STYPE].dtrd_offset,
	    aggdesc->dtagd_rec[REC_STYPE].dtrd_size);

	wchan = rec_get_value(
	    data->dtada_data + aggdesc->dtagd_rec[REC_WCHAN].dtrd_offset,
	    aggdesc->dtagd_rec[REC_WCHAN].dtrd_size);

	agg_value = rec_get_value(
	    data->dtada_data + aggdesc->dtagd_rec[REC_AGG].dtrd_offset,
	    aggdesc->dtagd_rec[REC_AGG].dtrd_size);

	lt_stat_update_sobj(pid, tid, stype, wchan, stat_type, agg_value);

	return (0);
}

/*
 * Callback to process various aggregations in the snapshot. Called by
 * different aggwalk_* functions.
 */
/* ARGSUSED */
static int
aggwalk(const dtrace_aggdata_t *data, void *arg)
{
	char *tmp;
	char buffer[32];
	lt_stat_type_t stat_type;
	int (*func)(const dtrace_aggdata_t *, lt_stat_type_t);

	(void) strncpy(buffer, data->dtada_desc->dtagd_name, sizeof (buffer));
	buffer[sizeof (buffer) - 1] = '\0';
	tmp = strtok(buffer, "_");

	if (tmp == NULL || strcmp(tmp, "lt") != 0) {
		goto done;
	}

	tmp = strtok(NULL, "_");

	if (tmp == NULL) {
		goto done;
	} else if (strcmp(tmp, "call") == 0) {
		func = aggwalk_call;
	} else if (strcmp(tmp, "named") == 0) {
		func = aggwalk_named;
	} else if (strcmp(tmp, "sync") == 0) {
		func = aggwalk_sync;
	} else {
		goto done;
	}

	tmp = strtok(NULL, "_");

	if (tmp == NULL) {
		goto done;
	} else if (strcmp(tmp, "count") == 0) {
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
	/* We have our data, so remove it from DTrace now */
	return (DTRACE_AGGWALK_REMOVE);
}

/*
 * Callback to handle event caused by DTrace dropping data.
 */
/*ARGSUSED*/
static int
drop_handler(const dtrace_dropdata_t *data, void *user)
{
	lt_display_error("Drop: %s\n", data->dtdda_msg);
	lt_drop_detected = B_TRUE;

	/* Pretend nothing happened, so just continue */
	return (DTRACE_HANDLE_OK);
}

#ifndef EMBED_CONFIGS
/*
 * Copy the content from a "real" file into a temp file.
 */
static int
copy_tmp_file(const char *src, FILE *dst)
{
	FILE *tmp = NULL;
	char buffer[256];
	int bytes;

	if ((tmp = fopen(src, "r")) == NULL) {
		return (-1);
	}

	while ((bytes = fread(buffer, 1, sizeof (buffer), tmp)) > 0) {
		if (fwrite(buffer, bytes, 1, dst) != 1) {
			return (-1);
		}
	}

	(void) fclose(tmp);

	return (0);
}
#endif

/*
 * DTrace initialization. D script starts running when this function returns.
 */
int
lt_dtrace_init(void)
{
	dtrace_prog_t *prog;
	dtrace_proginfo_t info;
	int err;
	FILE *fp_script = NULL;
	char tmp[64];

	pid_self = getpid();

	if ((g_dtp = dtrace_open(DTRACE_VERSION, 0, &err)) == NULL) {
		lt_display_error("Cannot open dtrace library: %s\n",
		    dtrace_errmsg(NULL, err));
		return (-1);
	}

	if (dtrace_handle_drop(g_dtp, &drop_handler, NULL) == -1) {
		lt_display_error("Cannot install DTrace handle: %s\n",
		    dtrace_errmsg(NULL, err));
		return (-1);
	}

	if (g_config.lt_cfg_enable_filter) {
		if ((err = dtrace_setopt(g_dtp, "define",
		    "ENABLE_FILTER")) != 0) {
			lt_display_error(
			    "Failed to set option ENABLE_FILTER.\n");
			return (err);
		}
	}

	if (g_config.lt_cfg_trace_syncobj) {
		if ((err = dtrace_setopt(g_dtp, "define",
		    "ENABLE_SYNCOBJ")) != 0) {
			lt_display_error(
			    "Failed to set option ENABLE_SYNCOBJ.\n");
			return (err);
		}
	}

	if (g_config.lt_cfg_trace_sched) {
		if ((err = dtrace_setopt(g_dtp, "define",
		    "ENABLE_SCHED")) != 0) {
			lt_display_error(
			    "Failed to set option ENABLE_SCHED.\n");
			return (err);
		}
	}

	if (g_config.lt_cfg_trace_pid != 0) {
		(void) snprintf(tmp, sizeof (tmp), "TRACE_PID=%u",
		    g_config.lt_cfg_trace_pid);
		if ((err = dtrace_setopt(g_dtp, "define", tmp)) != 0) {
			lt_display_error(
			    "Failed to set option TRACE_PID.\n");
			return (err);
		}
	}

	if (g_config.lt_cfg_trace_pgid != 0) {
		(void) snprintf(tmp, sizeof (tmp), "TRACE_PGID=%u",
		    g_config.lt_cfg_trace_pgid);
		if ((err = dtrace_setopt(g_dtp, "define", tmp)) != 0) {
			lt_display_error(
			    "Failed to set option TRACE_PGID.\n");
			return (err);
		}
	}

	if (g_config.lt_cfg_low_overhead_mode) {
		if ((err = dtrace_setopt(g_dtp, "define",
		    "ENABLE_LOW_OVERHEAD")) != 0) {
			lt_display_error(
			    "Failed to set option ENABLE_LOW_OVERHEAD.\n");
			return (err);
		}
	}

	/* Create a temp file; libdtrace needs it for cpp(1) */
	if ((fp_script = tmpfile()) == NULL) {
		lt_display_error("Cannot create tmp file\n");
		return (-1);
	}

	/* Copy the main D script into the temp file */
#ifdef EMBED_CONFIGS
	if (fwrite(&latencytop_d_start,
	    (size_t)(&latencytop_d_end - &latencytop_d_start), 1, fp_script)
	    != 1) {
		lt_display_error("Could not copy D script, fwrite() failed\n");
		(void) fclose(fp_script);
		return (-1);
	}
#else
	if (copy_tmp_file(DEFAULT_D_SCRIPT_NAME, fp_script) != 0) {
		lt_display_error("Cannot open script file %s\n",
		    DEFAULT_D_SCRIPT_NAME);
		(void) fclose(fp_script);
		return (-1);
	}
#endif	/* EMBED_CONFIGS */

	if (lt_table_append_trans(fp_script) != 0) {
		(void) fclose(fp_script);
		return (-1);
	}

	(void) fseek(fp_script, 0, SEEK_SET);

	if ((prog = dtrace_program_fcompile(g_dtp, fp_script,
	    DTRACE_C_CPP, 0, NULL)) == NULL) {
		lt_display_error("Failed to compile D script.\n");
		(void) fclose(fp_script);
		return (dtrace_errno(g_dtp));
	}

	(void) fclose(fp_script);

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
 * Worker function to move aggregate data to user space. Called periodically
 * to prevent the kernel from running out of memory.
 */
int
lt_dtrace_work(int force)
{
	static uint64_t last_snap = 0;
	uint64_t now = lt_millisecond();

	if (!force && now - last_snap < g_config.lt_cfg_snap_interval) {
		return (last_snap + g_config.lt_cfg_snap_interval - now);
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
 * Walk through dtrace aggregator and collect data for latencytop to display.
 * Called immediately before UI update.
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
	 * Probably we don't need to clear again, because we have removed
	 * everything. Paranoid ?
	 */
	dtrace_aggregate_clear(g_dtp);

	return (0);
}

/*
 * dtrace clean up.
 */
int
lt_dtrace_deinit(void)
{
	int ret = 0;

	if (dtrace_stop(g_dtp) != 0) {
		lt_display_error("dtrace_stop failed: %s\n",
		    dtrace_errmsg(g_dtp, dtrace_errno(g_dtp)));
		ret = -1;
	}

	dtrace_close(g_dtp);

	return (ret);
}
