/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ctf.h>

#include <configd.h>

mdb_ctf_id_t request_enum;
mdb_ctf_id_t response_enum;
mdb_ctf_id_t ptr_type_enum;
mdb_ctf_id_t thread_state_enum;

hrtime_t max_time_seen;

static void
enum_lookup(char *out, size_t size, mdb_ctf_id_t id, int val,
    const char *prefix, const char *prefix2)
{
	const char *cp;
	size_t len = strlen(prefix);
	size_t len2 = strlen(prefix2);

	if ((cp = mdb_ctf_enum_name(id, val)) != NULL) {
		if (strncmp(cp, prefix, len) == 0)
			cp += len;
		if (strncmp(cp, prefix2, len2) == 0)
			cp += len2;
		(void) strlcpy(out, cp, size);
	} else {
		mdb_snprintf(out, size, "? (%d)", val);
	}
}

static void
make_lower(char *out, size_t sz)
{
	while (*out != 0 && sz > 0) {
		if (*out >= 'A' && *out <= 'Z')
			*out += 'a' - 'A';
		out++;
		sz--;
	}
}

/*ARGSUSED*/
static int
configd_status(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int num_servers;
	int num_started;

	if (argc != 0)
		return (DCMD_USAGE);

	if (mdb_readvar(&num_servers, "num_servers") == -1) {
		mdb_warn("unable to read num_servers");
		return (DCMD_ERR);
	}
	if (mdb_readvar(&num_started, "num_started") == -1) {
		mdb_warn("unable to read num_started");
		return (DCMD_ERR);
	}
	mdb_printf(
	    "\nserver threads:\t%d running, %d starting\n\n", num_servers,
	    num_started - num_servers);

	if (mdb_walk_dcmd("configd_threads", "configd_thread", argc,
	    argv) == -1) {
		mdb_warn("can't walk 'configd_threads'");
		return (DCMD_ERR);
	}
	return (DCMD_OK);
}

/*ARGSUSED*/
static int
configd_thread(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	thread_info_t t;
	char state[20];
	char oldstate[20];

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("configd_threads", "configd_thread", argc,
		    argv) == -1) {
			mdb_warn("can't walk 'configd_threads'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (argc != 0)
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%-?s %5s %-12s %-12s %-?s %-?s %-?s%</u>\n",
		    "ADDR", "TID", "STATE", "PREV_STATE", "CLIENT", "CLIENTRQ",
		    "MAINREQ");
	}

	if (mdb_vread(&t, sizeof (t), addr) == -1) {
		mdb_warn("failed to read thread_info_t at %p", addr);
		return (DCMD_ERR);
	}

	enum_lookup(state, sizeof (state), thread_state_enum,
	    t.ti_state, "TI_", "");
	make_lower(state, sizeof (state));

	enum_lookup(oldstate, sizeof (oldstate), thread_state_enum,
	    t.ti_prev_state, "TI_", "");
	make_lower(oldstate, sizeof (oldstate));

	mdb_printf("%0?p %5d %-12s %-12s %?p %?p %?p\n",
	    (void *)addr, t.ti_thread, state, oldstate,
	    t.ti_active_client, t.ti_client_request, t.ti_main_door_request);

	return (DCMD_OK);
}

static int
walk_thread_info_init(mdb_walk_state_t *wsp)
{
	if (mdb_readvar(&wsp->walk_addr, "thread_list") == -1) {
		mdb_warn("unable to read thread_list");
		return (WALK_ERR);
	}

	if (mdb_layered_walk("uu_list_node", wsp) == -1) {
		mdb_warn("couldn't walk 'uu_list_node'");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

static int
walk_thread_info_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;
	thread_info_t ti;

	if (mdb_vread(&ti, sizeof (ti), addr) == -1) {
		mdb_warn("unable to read thread_info_t at %p", addr);
		return (WALK_ERR);
	}

	return (wsp->walk_callback(addr, &ti, wsp->walk_cbdata));
}

static int
request_log(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	request_log_entry_t cur;
	hrtime_t dur;
	hrtime_t dursec;
	hrtime_t durnsec;
	char durstr[20];
	char stampstr[20];
	char requstr[30];
	char respstr[30];
	char typestr[30];
	uintptr_t node = 0;
	uintptr_t client = 0;
	uint64_t clientid = 0;

	int idx;
	int opt_v = FALSE;			/* verbose */

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("configd_log", "configd_log", argc,
		    argv) == -1) {
			mdb_warn("can't walk 'configd_log'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_getopts(argc, argv,
	    'c', MDB_OPT_UINTPTR, &client,
	    'i', MDB_OPT_UINT64, &clientid,
	    'n', MDB_OPT_UINTPTR, &node,
	    'v', MDB_OPT_SETBITS, TRUE, &opt_v, NULL) != argc)
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%-?s %-4s %-14s %9s %-22s %-17s\n%</u>",
		    "ADDR", "THRD", "START", "DURATION", "REQUEST",
		    "RESPONSE");
	}

	if (mdb_vread(&cur, sizeof (cur), addr) == -1) {
		mdb_warn("couldn't read log entry at %p", addr);
		return (DCMD_ERR);
	}

	/*
	 * apply filters, if any.
	 */
	if (clientid != 0 && clientid != cur.rl_clientid)
		return (DCMD_OK);

	if (client != 0 && client != (uintptr_t)cur.rl_client)
		return (DCMD_OK);

	if (node != 0) {
		for (idx = 0; idx < MIN(MAX_PTRS, cur.rl_num_ptrs); idx++) {
			if ((uintptr_t)cur.rl_ptrs[idx].rlp_data == node) {
				node = 0;		/* found it */
				break;
			}
		}
		if (node != 0)
			return (DCMD_OK);
	}

	enum_lookup(requstr, sizeof (requstr), request_enum, cur.rl_request,
	    "REP_PROTOCOL_", "");

	if (cur.rl_end != 0) {
		enum_lookup(respstr, sizeof (respstr), response_enum,
		    cur.rl_response, "REP_PROTOCOL_", "FAIL_");

		dur = cur.rl_end - cur.rl_start;
		dursec = dur / NANOSEC;
		durnsec = dur % NANOSEC;

		if (dursec <= 9)
			mdb_snprintf(durstr, sizeof (durstr),
			    "%lld.%06lld",
			    dursec, durnsec / (NANOSEC / MICROSEC));
		else if (dursec <= 9999)
			mdb_snprintf(durstr, sizeof (durstr),
			    "%lld.%03lld",
			    dursec, NSEC2MSEC(durnsec));
		else
			mdb_snprintf(durstr, sizeof (durstr),
			    "%lld", dursec);
	} else {
		(void) strcpy(durstr, "-");
		(void) strcpy(respstr, "-");
	}

	if (max_time_seen != 0 && max_time_seen >= cur.rl_start) {
		dur = max_time_seen - cur.rl_start;
		dursec = dur / NANOSEC;
		durnsec = dur % NANOSEC;

		if (dursec <= 99ULL)
			mdb_snprintf(stampstr, sizeof (stampstr),
			    "-%lld.%09lld", dursec, durnsec);
		else if (dursec <= 99999ULL)
			mdb_snprintf(stampstr, sizeof (stampstr),
			    "-%lld.%06lld",
			    dursec, durnsec / (NANOSEC / MICROSEC));
		else if (dursec <= 99999999ULL)
			mdb_snprintf(stampstr, sizeof (stampstr),
			    "-%lld.%03lld",
			    dursec, NSEC2MSEC(durnsec));
		else
			mdb_snprintf(stampstr, sizeof (stampstr),
			    "-%lld", dursec);
	} else {
		(void) strcpy(stampstr, "-");
	}

	mdb_printf("%0?x %4d T%13s %9s %-22s %-17s\n",
	    addr, cur.rl_tid, stampstr, durstr, requstr, respstr);

	if (opt_v) {
		mdb_printf("\tclient: %?p (%d)\tptrs: %d\tstamp: %llx\n",
		    cur.rl_client, cur.rl_clientid, cur.rl_num_ptrs,
		    cur.rl_start);
		for (idx = 0; idx < MIN(MAX_PTRS, cur.rl_num_ptrs); idx++) {
			enum_lookup(typestr, sizeof (typestr), ptr_type_enum,
			    cur.rl_ptrs[idx].rlp_type, "RC_PTR_TYPE_", "");
			mdb_printf("\t\t%-7s %5d %?p %?p\n", typestr,
			    cur.rl_ptrs[idx].rlp_id, cur.rl_ptrs[idx].rlp_ptr,
			    cur.rl_ptrs[idx].rlp_data);
		}
		mdb_printf("\n");
	}
	return (DCMD_OK);
}

struct request_log_walk {
	size_t		rlw_max;
	size_t		rlw_count;
	size_t		rlw_cur;
	struct request_entry {
		hrtime_t  timestamp;
		uintptr_t addr;
	}		*rlw_list;
};

/*
 * we want newer items at the top
 */
static int
request_entry_compare(const void *l, const void *r)
{
	const struct request_entry *lp = l;
	const struct request_entry *rp = r;

	if (rp->timestamp == lp->timestamp)
		return (0);

	/*
	 * 0 timestamps go first.
	 */
	if (rp->timestamp == 0)
		return (1);
	if (lp->timestamp == 0)
		return (-1);

	if (lp->timestamp < rp->timestamp)
		return (1);
	return (-1);
}

/*ARGSUSED*/
static int
request_log_count_thread(uintptr_t addr, thread_info_t *tip, uint_t *arg)
{
	(*arg)++;

	return (WALK_NEXT);
}

static int
request_log_add_thread(uintptr_t addr, thread_info_t *tip,
    struct request_entry **arg)
{
	if (max_time_seen < tip->ti_log.rl_start)
		max_time_seen = tip->ti_log.rl_start;

	if (max_time_seen < tip->ti_log.rl_end)
		max_time_seen = tip->ti_log.rl_end;

	if (tip->ti_log.rl_start != 0) {
		if (tip->ti_log.rl_end)
			(*arg)->timestamp = tip->ti_log.rl_start;
		else
			(*arg)->timestamp = 0;		/* sort to the top */

		(*arg)->addr = addr + offsetof(thread_info_t, ti_log);
		++*arg;
	}
	return (WALK_NEXT);
}

static int
request_log_walk_init(mdb_walk_state_t *wsp)
{
	struct request_log_walk *rlw;
	struct request_entry *list, *listp;

	uint_t log_size;
	uint_t size;
	uint_t idx;
	uint_t pos;
	request_log_entry_t *base;
	request_log_entry_t cur;

	if (mdb_readvar(&base, "request_log") == -1) {
		mdb_warn("couldn't read 'request_log'");
		return (WALK_ERR);
	}
	if (mdb_readvar(&log_size, "request_log_size") == -1) {
		mdb_warn("couldn't read 'request_log_size'");
		return (WALK_ERR);
	}
	size = log_size;

	if (mdb_walk("configd_threads", (mdb_walk_cb_t)request_log_count_thread,
	    &size) == -1) {
		mdb_warn("couldn't walk 'configd_threads'");
		return (WALK_ERR);
	}

	list = mdb_zalloc(sizeof (*list) * size, UM_SLEEP);
	listp = list;

	if (mdb_walk("configd_threads", (mdb_walk_cb_t)request_log_add_thread,
	    &listp) == -1) {
		mdb_warn("couldn't walk 'configd_threads'");
		mdb_free(list, sizeof (*list) * size);
		return (WALK_ERR);
	}

	pos = listp - list;
	for (idx = 0; idx < log_size; idx++) {
		uintptr_t addr = (uintptr_t)&base[idx];
		if (mdb_vread(&cur, sizeof (cur), addr) == -1) {
			mdb_warn("couldn't read log entry at %p", addr);
			mdb_free(list, sizeof (*list) * size);
			return (WALK_ERR);
		}

		if (max_time_seen < cur.rl_start)
			max_time_seen = cur.rl_start;

		if (max_time_seen < cur.rl_end)
			max_time_seen = cur.rl_end;

		if (cur.rl_start != 0) {
			list[pos].timestamp = cur.rl_start;
			list[pos].addr = addr;
			pos++;
		}
	}
	qsort(list, pos, sizeof (*list), &request_entry_compare);

	rlw = mdb_zalloc(sizeof (*rlw), UM_SLEEP);
	rlw->rlw_max = size;
	rlw->rlw_count = pos;
	rlw->rlw_cur = 0;
	rlw->rlw_list = list;

	wsp->walk_data = rlw;

	return (WALK_NEXT);
}

static int
request_log_walk_step(mdb_walk_state_t *wsp)
{
	struct request_log_walk *rlw = wsp->walk_data;
	uintptr_t addr;
	request_log_entry_t cur;

	if (rlw->rlw_cur >= rlw->rlw_count)
		return (WALK_DONE);

	addr = rlw->rlw_list[rlw->rlw_cur++].addr;

	if (mdb_vread(&cur, sizeof (cur), addr) == -1) {
		mdb_warn("couldn't read log entry at %p", addr);
		return (WALK_ERR);
	}
	return (wsp->walk_callback(addr, &cur, wsp->walk_cbdata));
}

static void
request_log_walk_fini(mdb_walk_state_t *wsp)
{
	struct request_log_walk *rlw = wsp->walk_data;

	mdb_free(rlw->rlw_list, sizeof (*rlw->rlw_list) * rlw->rlw_max);
	mdb_free(rlw, sizeof (*rlw));
}

static const mdb_dcmd_t dcmds[] = {
	{ "configd_status", NULL, "svc.configd status summary",
	    configd_status },
	{ "configd_thread", "?", "Print a thread_info_t tabularly",
	    configd_thread },
	{ "configd_log", "?[-v] [-c clientptr] [-i clientid]",
	    "Print the request log, or a single entry", request_log },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "configd_threads", "walks the thread_info_ts for all "
	    "threads", walk_thread_info_init, walk_thread_info_step },
	{ "configd_log", "walks the request_log_entry_ts",
	    request_log_walk_init, request_log_walk_step,
	    request_log_walk_fini},
	{ NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, walkers
};

const mdb_modinfo_t *
_mdb_init(void)
{
	if (mdb_ctf_lookup_by_name("enum rep_protocol_requestid",
	    &request_enum) == -1) {
		mdb_warn("enum rep_protocol_requestid not found");
	}
	if (mdb_ctf_lookup_by_name("enum rep_protocol_responseid",
	    &response_enum) == -1) {
		mdb_warn("enum rep_protocol_responseid not found");
	}
	if (mdb_ctf_lookup_by_name("enum rc_ptr_type",
	    &ptr_type_enum) == -1) {
		mdb_warn("enum rc_ptr_type not found");
	}
	if (mdb_ctf_lookup_by_name("enum thread_state",
	    &thread_state_enum) == -1) {
		mdb_warn("enum thread_state not found");
	}
	return (&modinfo);
}
