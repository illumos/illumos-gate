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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/mdb_modapi.h>
#include <limits.h>

#include <fmd_trace.h>
#include <fmd_module.h>
#include <fmd_thread.h>
#include <fmd_ustat.h>
#include <fmd_event.h>
#include <fmd_case.h>
#include <fmd_buf.h>
#include <fmd_asru.h>
#include <fmd_ckpt.h>
#include <fmd_timerq.h>
#include <fmd_xprt.h>

#include <fmd.h>

typedef struct trwalk_state {
	struct trwalk_state *trw_next;
	fmd_tracebuf_t trw_data;
	pthread_t trw_tid;
	uintptr_t trw_base;
	const fmd_tracerec_t *trw_stop;
	fmd_tracerec_t *trw_xrec;
} trwalk_state_t;

typedef struct hashwalk_data {
	uintptr_t *hw_hash;
	uint_t hw_hashlen;
	uint_t hw_hashidx;
	const char *hw_name;
	void *hw_data;
	size_t hw_size;
	size_t hw_next;
} hashwalk_data_t;

static int fmd_stat(uintptr_t, uint_t, int, const mdb_arg_t *);
static int fmd_ustat(uintptr_t, uint_t, int, const mdb_arg_t *);

static int
trwalk_init(mdb_walk_state_t *wsp)
{
	uintptr_t addr;
	fmd_thread_t thr;
	fmd_t F;

	if (wsp->walk_addr != 0) {
		mdb_warn("fmd_trace only supports global walks\n");
		return (WALK_ERR);
	}

	if (mdb_readvar(&F, "fmd") != sizeof (F)) {
		mdb_warn("failed to read fmd meta-data");
		return (WALK_ERR);
	}

	for (addr = (uintptr_t)F.d_thr_list.l_next; addr != 0;
	    addr = (uintptr_t)thr.thr_list.l_next) {

		size_t len, ptr_off, end_off;
		fmd_tracerec_t *buf;
		trwalk_state_t *t;

		if (mdb_vread(&thr, sizeof (thr), addr) != sizeof (thr)) {
			mdb_warn("failed to read thread at %p "
			    "(some trace data will be unavailable)", addr);
			break;
		}

		t = mdb_zalloc(sizeof (trwalk_state_t), UM_SLEEP);
		t->trw_next = wsp->walk_data;
		wsp->walk_data = t;

		(void) mdb_vread(&t->trw_data,
		    sizeof (t->trw_data), (uintptr_t)thr.thr_trdata);

		if (t->trw_data.tb_recs == 0)
			continue; /* no trace buffer allocated for thread */

		len = t->trw_data.tb_recs * t->trw_data.tb_size;
		buf = mdb_alloc(len, UM_SLEEP);

		t->trw_tid = thr.thr_tid;
		t->trw_base = (uintptr_t)t->trw_data.tb_buf;

		if (mdb_vread(buf, len, t->trw_base) == -1) {
			mdb_warn("failed to read buffer for t%u", t->trw_tid);
			bzero(buf, len);
		}

		end_off = (uintptr_t)t->trw_data.tb_end - t->trw_base;
		ptr_off = (uintptr_t)t->trw_data.tb_ptr - t->trw_base;

		t->trw_data.tb_buf = buf;
		t->trw_data.tb_end = (void *)((uintptr_t)buf + end_off);
		t->trw_data.tb_ptr = (void *)((uintptr_t)buf + ptr_off);

		if (t->trw_data.tb_ptr < t->trw_data.tb_buf ||
		    t->trw_data.tb_ptr > t->trw_data.tb_end) {
			mdb_warn("trace record ptr for t%u is corrupt "
			    "(some data may be unavailable)\n", t->trw_tid);
			t->trw_data.tb_ptr = t->trw_data.tb_buf;
		}

		t->trw_stop = t->trw_data.tb_ptr;
		t->trw_xrec = mdb_alloc(
		    t->trw_data.tb_size + sizeof (uintptr_t), UM_SLEEP);
	}

	return (WALK_NEXT);
}

static fmd_tracerec_t *
trwalk_nextrec(trwalk_state_t *t)
{
	if (t->trw_stop == NULL)
		return (t->trw_data.tb_ptr);

	if (t->trw_data.tb_ptr == t->trw_data.tb_buf)
		t->trw_data.tb_ptr = t->trw_data.tb_end;
	else
		t->trw_data.tb_ptr = (fmd_tracerec_t *)
		    ((uintptr_t)t->trw_data.tb_ptr - t->trw_data.tb_size);

	if (t->trw_data.tb_ptr == t->trw_stop)
		t->trw_stop = NULL; /* mark buffer as empty */

	return (t->trw_data.tb_ptr);
}

static int
trwalk_step(mdb_walk_state_t *wsp)
{
	trwalk_state_t *t, *oldest_t;
	hrtime_t oldest_time = 0;
	fmd_tracerec_t *trp;
	int status;

	for (t = wsp->walk_data; t != NULL; t = t->trw_next) {
		for (trp = t->trw_data.tb_ptr; t->trw_stop != NULL &&
		    trp->tr_time == 0; trp = trwalk_nextrec(t))
			continue;

		if (t->trw_stop == NULL)
			continue; /* buffer has been emptied */

		if (trp->tr_time > oldest_time) {
			oldest_time = trp->tr_time;
			oldest_t = t;
		}
	}

	if (oldest_time == 0)
		return (WALK_DONE);

	t = oldest_t;
	trp = t->trw_data.tb_ptr;

	bcopy(trp, t->trw_xrec, t->trw_data.tb_size);
	t->trw_xrec->tr_depth = MIN(trp->tr_depth, t->trw_data.tb_frames);
	t->trw_xrec->tr_stack[t->trw_xrec->tr_depth] = t->trw_tid;

	status = wsp->walk_callback((uintptr_t)trp - (uintptr_t)
	    t->trw_data.tb_buf + t->trw_base, t->trw_xrec, wsp->walk_cbdata);

	(void) trwalk_nextrec(t);
	return (status);
}

static void
trwalk_fini(mdb_walk_state_t *wsp)
{
	trwalk_state_t *t, *u;

	for (t = wsp->walk_data; t != NULL; t = u) {
		u = t->trw_next;
		mdb_free(t->trw_data.tb_buf,
		    t->trw_data.tb_recs * t->trw_data.tb_size);
		mdb_free(t->trw_xrec, t->trw_data.tb_size + sizeof (uintptr_t));
		mdb_free(t, sizeof (trwalk_state_t));
	}
}

/*ARGSUSED*/
static int
trprint_msg(uintptr_t addr, const void *arg, void *arg1)
{
	const fmd_tracerec_t *trp = arg;
	uintptr_t tid = (uintptr_t)arg1;

	if (tid == 0)
		mdb_printf("%3lu ", trp->tr_stack[trp->tr_depth]);
	else if (trp->tr_stack[trp->tr_depth] != tid)
		return (WALK_NEXT);

	mdb_printf("%016llx %04x %-5u %s\n",
	    trp->tr_time, 1 << trp->tr_tag, trp->tr_errno, trp->tr_msg);

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
trprint_cpp(uintptr_t addr, const void *arg, void *arg1)
{
	const fmd_tracerec_t *trp = arg;
	uintptr_t tid = (uintptr_t)arg1;
	char file[64];

	if (tid == 0)
		mdb_printf("%3lu ", trp->tr_stack[trp->tr_depth]);
	else if (trp->tr_stack[trp->tr_depth] != tid)
		return (WALK_NEXT);

	if (mdb_readstr(file, sizeof (file), (uintptr_t)trp->tr_file) <= 0)
		(void) strcpy(file, "???");

	mdb_printf("%016llx %04x %s: %u\n",
	    trp->tr_time, 1 << trp->tr_tag, file, trp->tr_line);

	return (WALK_NEXT);
}

static void
trprint_stack(const fmd_tracerec_t *trp)
{
	uint8_t i;

	for (i = 0; i < trp->tr_depth; i++)
		mdb_printf("\t%a\n", trp->tr_stack[i]);

	if (trp->tr_depth != 0)
		mdb_printf("\n");
}

static int
trprint_msg_stack(uintptr_t addr, const void *arg, void *arg1)
{
	const fmd_tracerec_t *trp = arg;
	int status = trprint_msg(addr, trp, arg1);
	trprint_stack(trp);
	return (status);
}

static int
trprint_cpp_stack(uintptr_t addr, const void *arg, void *arg1)
{
	const fmd_tracerec_t *trp = arg;
	int status = trprint_cpp(addr, trp, arg1);
	trprint_stack(trp);
	return (status);
}

static int
fmd_trace(uintptr_t tid, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int (*func)(uintptr_t, const void *, void *);
	uint_t opt_c = FALSE, opt_s = FALSE;

	if (mdb_getopts(argc, argv,
	    'c', MDB_OPT_SETBITS, TRUE, &opt_c,
	    's', MDB_OPT_SETBITS, TRUE, &opt_s, NULL) != argc)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_printf("TID ");
		tid = 0;
	}

	if (opt_c) {
		mdb_printf("%-16s %-4s FILE:LINE\n", "TIME", "TAG");
		func = opt_s ? trprint_cpp_stack : trprint_cpp;
	} else {
		mdb_printf("%-16s %-4s %-5s MSG\n", "TIME", "TAG", "ERRNO");
		func = opt_s ? trprint_msg_stack : trprint_msg;
	}

	if (mdb_walk("fmd_trace", func, (void *)tid) == -1) {
		mdb_warn("failed to walk fmd_trace");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

static int
hash_walk_init(mdb_walk_state_t *wsp, uintptr_t addr, uint_t hashlen,
    const char *name, size_t size, size_t next)
{
	hashwalk_data_t *hwp;
	size_t len = sizeof (uintptr_t) * hashlen;

	if (len == 0) {
		mdb_warn("failed to walk hash: invalid hash length\n");
		return (WALK_ERR);
	}

	hwp = mdb_alloc(sizeof (hashwalk_data_t), UM_SLEEP);
	hwp->hw_hash = mdb_zalloc(len, UM_SLEEP);
	(void) mdb_vread(hwp->hw_hash, len, addr);
	hwp->hw_hashlen = hashlen;
	hwp->hw_hashidx = 0;
	hwp->hw_name = name;
	hwp->hw_data = mdb_zalloc(size, UM_SLEEP);
	hwp->hw_size = size;
	hwp->hw_next = next;

	wsp->walk_addr = hwp->hw_hash[0];
	wsp->walk_data = hwp;

	return (WALK_NEXT);
}

static int
hash_walk_step(mdb_walk_state_t *wsp)
{
	hashwalk_data_t *hwp = wsp->walk_data;
	int rv;

	while (wsp->walk_addr == 0) {
		if (++hwp->hw_hashidx < hwp->hw_hashlen)
			wsp->walk_addr = hwp->hw_hash[hwp->hw_hashidx];
		else
			return (WALK_DONE);
	}

	if (mdb_vread(hwp->hw_data, hwp->hw_size, wsp->walk_addr) == -1) {
		mdb_warn("failed to read %s at %p",
		    hwp->hw_name, wsp->walk_addr);
		return (WALK_ERR);
	}

	rv = wsp->walk_callback(wsp->walk_addr, hwp->hw_data, wsp->walk_cbdata);
	wsp->walk_addr = *(uintptr_t *)((uintptr_t)hwp->hw_data + hwp->hw_next);
	return (rv);
}

static void
hash_walk_fini(mdb_walk_state_t *wsp)
{
	hashwalk_data_t *hwp = wsp->walk_data;

	mdb_free(hwp->hw_hash, sizeof (uintptr_t) * hwp->hw_hashlen);
	mdb_free(hwp->hw_data, hwp->hw_size);
	mdb_free(hwp, sizeof (hashwalk_data_t));
}

static int
ustat_walk_init(mdb_walk_state_t *wsp)
{
	fmd_ustat_t us;

	if (mdb_vread(&us, sizeof (us), wsp->walk_addr) != sizeof (us)) {
		mdb_warn("failed to read fmd_ustat_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	return (hash_walk_init(wsp,
	    (uintptr_t)us.us_hash, us.us_hashlen, NULL, 0, 0));
}

static int
ustat_walk_step(mdb_walk_state_t *wsp)
{
	hashwalk_data_t *hwp = wsp->walk_data;
	fmd_ustat_elem_t ue;
	fmd_stat_t s;

	while (wsp->walk_addr == 0) {
		if (++hwp->hw_hashidx < hwp->hw_hashlen)
			wsp->walk_addr = hwp->hw_hash[hwp->hw_hashidx];
		else
			return (WALK_DONE);
	}

	if (mdb_vread(&ue, sizeof (ue), wsp->walk_addr) != sizeof (ue) ||
	    mdb_vread(&s, sizeof (s), (uintptr_t)ue.use_stat) != sizeof (s)) {
		mdb_warn("failed to read stat element at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)ue.use_next;

	return (wsp->walk_callback(
	    (uintptr_t)ue.use_stat, &s, wsp->walk_cbdata));
}

struct fmd_cmd_data {
	int argc;
	const mdb_arg_t *argv;
};

/* ARGSUSED */
static int
module_ustat(uintptr_t addr, const void *data, void *wsp)
{
	fmd_module_t *modp = (fmd_module_t *)data;
	char name[PATH_MAX];
	const struct fmd_cmd_data *udp = wsp;

	if (mdb_readstr(name, sizeof (name), (uintptr_t)modp->mod_name) <= 0)
		(void) mdb_snprintf(name, sizeof (name), "<%p>",
		    modp->mod_name);
	mdb_printf("%s\n", name);
	(void) fmd_ustat((uintptr_t)modp->mod_ustat,
	    DCMD_ADDRSPEC | DCMD_LOOPFIRST, udp->argc, udp->argv);
	return (WALK_NEXT);
}

static int
fmd_ustat(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (!(flags & DCMD_ADDRSPEC)) {
		struct fmd_cmd_data ud;

		ud.argc = argc;
		ud.argv = argv;
		if (mdb_walk("fmd_module", module_ustat, &ud) == -1) {
			mdb_warn("failed to walk 'fmd_module'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_pwalk_dcmd("fmd_ustat", "fmd_stat", argc, argv, addr) != 0) {
		mdb_warn("failed to walk fmd_ustat at %p", addr);
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/* ARGSUSED */
static int
module_stat(uintptr_t addr, const void *data, void *wsp)
{
	fmd_module_t *modp = (fmd_module_t *)data;
	char name[PATH_MAX];
	const struct fmd_cmd_data *udp = wsp;
	fmd_modstat_t *mod_stats;

	if (mdb_readstr(name, sizeof (name), (uintptr_t)modp->mod_name) <= 0) {
		(void) mdb_snprintf(name, sizeof (name), "<%p>",
		    modp->mod_name);
	}
	mdb_printf("%s\n", name);
	mod_stats = modp->mod_stats;
	(void) fmd_stat((uintptr_t)&mod_stats->ms_loadtime,
	    DCMD_ADDRSPEC | DCMD_LOOPFIRST, udp->argc, udp->argv);
	(void) fmd_stat((uintptr_t)&mod_stats->ms_snaptime,
	    DCMD_ADDRSPEC | DCMD_LOOP, udp->argc, udp->argv);
	(void) fmd_stat((uintptr_t)&mod_stats->ms_accepted,
	    DCMD_ADDRSPEC | DCMD_LOOP, udp->argc, udp->argv);
	(void) fmd_stat((uintptr_t)&mod_stats->ms_debugdrop,
	    DCMD_ADDRSPEC | DCMD_LOOP, udp->argc, udp->argv);
	(void) fmd_stat((uintptr_t)&mod_stats->ms_memtotal,
	    DCMD_ADDRSPEC | DCMD_LOOP, udp->argc, udp->argv);
	(void) fmd_stat((uintptr_t)&mod_stats->ms_memlimit,
	    DCMD_ADDRSPEC | DCMD_LOOP, udp->argc, udp->argv);
	(void) fmd_stat((uintptr_t)&mod_stats->ms_buftotal,
	    DCMD_ADDRSPEC | DCMD_LOOP, udp->argc, udp->argv);
	(void) fmd_stat((uintptr_t)&mod_stats->ms_buflimit,
	    DCMD_ADDRSPEC | DCMD_LOOP, udp->argc, udp->argv);
	(void) fmd_stat((uintptr_t)&mod_stats->ms_thrtotal,
	    DCMD_ADDRSPEC | DCMD_LOOP, udp->argc, udp->argv);
	(void) fmd_stat((uintptr_t)&mod_stats->ms_thrlimit,
	    DCMD_ADDRSPEC | DCMD_LOOP, udp->argc, udp->argv);
	(void) fmd_stat((uintptr_t)&mod_stats->ms_doorthrtotal,
	    DCMD_ADDRSPEC | DCMD_LOOP, udp->argc, udp->argv);
	(void) fmd_stat((uintptr_t)&mod_stats->ms_doorthrlimit,
	    DCMD_ADDRSPEC | DCMD_LOOP, udp->argc, udp->argv);
	(void) fmd_stat((uintptr_t)&mod_stats->ms_caseopen,
	    DCMD_ADDRSPEC | DCMD_LOOP, udp->argc, udp->argv);
	(void) fmd_stat((uintptr_t)&mod_stats->ms_casesolved,
	    DCMD_ADDRSPEC | DCMD_LOOP, udp->argc, udp->argv);
	(void) fmd_stat((uintptr_t)&mod_stats->ms_caseclosed,
	    DCMD_ADDRSPEC | DCMD_LOOP, udp->argc, udp->argv);
	(void) fmd_stat((uintptr_t)&mod_stats->ms_ckpt_save,
	    DCMD_ADDRSPEC | DCMD_LOOP, udp->argc, udp->argv);
	(void) fmd_stat((uintptr_t)&mod_stats->ms_ckpt_restore,
	    DCMD_ADDRSPEC | DCMD_LOOP, udp->argc, udp->argv);
	(void) fmd_stat((uintptr_t)&mod_stats->ms_ckpt_zeroed,
	    DCMD_ADDRSPEC | DCMD_LOOP, udp->argc, udp->argv);
	(void) fmd_stat((uintptr_t)&mod_stats->ms_ckpt_cnt,
	    DCMD_ADDRSPEC | DCMD_LOOP, udp->argc, udp->argv);
	(void) fmd_stat((uintptr_t)&mod_stats->ms_ckpt_time,
	    DCMD_ADDRSPEC | DCMD_LOOP, udp->argc, udp->argv);
	(void) fmd_stat((uintptr_t)&mod_stats->ms_xprtopen,
	    DCMD_ADDRSPEC | DCMD_LOOP, udp->argc, udp->argv);
	(void) fmd_stat((uintptr_t)&mod_stats->ms_xprtlimit,
	    DCMD_ADDRSPEC | DCMD_LOOP, udp->argc, udp->argv);
	(void) fmd_stat((uintptr_t)&mod_stats->ms_xprtqlimit,
	    DCMD_ADDRSPEC | DCMD_LOOP, udp->argc, udp->argv);
	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
fmd_stat(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char buf[512];
	fmd_stat_t s;

	if (argc != 0)
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%<u>%-11s %-4s %-32s %s%</u>\n",
		    "ADDR", "TYPE", "NAME", "VALUE");

	if (!(flags & DCMD_ADDRSPEC)) {
		struct fmd_cmd_data ud;

		ud.argc = argc;
		ud.argv = argv;

		if (mdb_walk("fmd_module", module_stat, &ud) == -1) {
			mdb_warn("failed to walk 'fmd_module'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_vread(&s, sizeof (s), addr) != sizeof (s)) {
		mdb_warn("failed to read statistic at %p", addr);
		return (DCMD_ERR);
	}

	switch (s.fmds_type) {
	case FMD_TYPE_BOOL:
		mdb_printf("%-11p %-4s %-32s %s\n", addr, "bool",
		    s.fmds_name, s.fmds_value.bool ? "true" : "false");
		break;
	case FMD_TYPE_INT32:
		mdb_printf("%-11p %-4s %-32s %d\n", addr, "i32",
		    s.fmds_name, s.fmds_value.i32);
		break;
	case FMD_TYPE_UINT32:
		mdb_printf("%-11p %-4s %-32s %u\n", addr, "ui32",
		    s.fmds_name, s.fmds_value.i32);
		break;
	case FMD_TYPE_INT64:
		mdb_printf("%-11p %-4s %-32s %lld\n", addr, "i64",
		    s.fmds_name, s.fmds_value.i64);
		break;
	case FMD_TYPE_UINT64:
		mdb_printf("%-11p %-4s %-32s %llu\n", addr, "ui64",
		    s.fmds_name, s.fmds_value.ui64);
		break;
	case FMD_TYPE_STRING:
		if (mdb_readstr(buf, sizeof (buf),
		    (uintptr_t)s.fmds_value.str) < 0) {
			(void) mdb_snprintf(buf, sizeof (buf), "<%p>",
			    s.fmds_value.str);
		}
		mdb_printf("%-11p %-4s %-32s %s\n", addr, "str",
		    s.fmds_name, buf);
		break;
	case FMD_TYPE_TIME:
		mdb_printf("%-11p %-4s %-32s %llu\n", addr, "time",
		    s.fmds_name, s.fmds_value.ui64);
		break;
	case FMD_TYPE_SIZE:
		mdb_printf("%-11p %-4s %-32s %llu\n", addr, "size",
		    s.fmds_name, s.fmds_value.ui64);
		break;
	default:
		mdb_printf("%-11p %-4u %-32s ???\n", addr,
		    s.fmds_type, s.fmds_name);
		break;
	}

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
fmd_event(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char type[16], name[16];
	fmd_event_impl_t ev;

	if (argc != 0)
		return (DCMD_USAGE);

	if (mdb_vread(&ev, sizeof (ev), addr) != sizeof (ev)) {
		mdb_warn("failed to read fmd_event at %p", addr);
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%-11s %-4s %-5s %-3s %-?s%</u>\n",
		    "ADDR", "TYPE", "STATE", "REF", "NVPAIR");
	}

	switch (ev.ev_type) {
	case FMD_EVT_PROTOCOL:
		(void) strcpy(type, "PROT");
		break;
	case FMD_EVT_GC:
		(void) strcpy(type, "GC");
		break;
	case FMD_EVT_CLOSE:
		(void) strcpy(type, "CLSE");
		break;
	case FMD_EVT_TIMEOUT:
		(void) strcpy(type, "TIME");
		break;
	case FMD_EVT_STATS:
		(void) strcpy(type, "STAT");
		break;
	case FMD_EVT_PUBLISH:
		(void) strcpy(type, "PUBL");
		break;
	case FMD_EVT_TOPO:
		(void) strcpy(type, "TOPO");
		break;
	default:
		(void) mdb_snprintf(type, sizeof (type), "%u", ev.ev_type);
	}

	switch (ev.ev_state) {
	case FMD_EVS_RECEIVED:
		(void) strcpy(name, "RECVD");
		break;
	case FMD_EVS_ACCEPTED:
		(void) strcpy(name, "ACCPT");
		break;
	case FMD_EVS_DISCARDED:
		(void) strcpy(name, "DSCRD");
		break;
	case FMD_EVS_DIAGNOSED:
		(void) strcpy(name, "DIAGN");
		break;
	default:
		(void) mdb_snprintf(name, sizeof (name), "%u", ev.ev_state);
	}

	mdb_printf("%-11p %-4s %-5s %-3u %p\n",
	    addr, type, name, ev.ev_refs, ev.ev_nvl);

	return (DCMD_OK);
}

static int
thread_walk_init(mdb_walk_state_t *wsp)
{
	fmd_t F;

	if (mdb_readvar(&F, "fmd") != sizeof (F)) {
		mdb_warn("failed to read fmd meta-data");
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)F.d_thr_list.l_next;
	return (WALK_NEXT);
}

static int
thread_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;
	fmd_thread_t t;

	if (addr == 0)
		return (WALK_DONE);

	if (mdb_vread(&t, sizeof (t), addr) != sizeof (t)) {
		mdb_warn("failed to read fmd_thread at %p", addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)t.thr_list.l_next;
	return (wsp->walk_callback(addr, &t, wsp->walk_cbdata));
}

static int
fmd_thread(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	fmd_thread_t thr;

	if (!(flags & DCMD_ADDRSPEC))
		return (mdb_walk_dcmd("fmd_thread", "fmd_thread", argc, argv));

	if (argc != 0)
		return (DCMD_USAGE);

	if (mdb_vread(&thr, sizeof (thr), addr) != sizeof (thr)) {
		mdb_warn("failed to read fmd_thread at %p", addr);
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%-11s %-11s %-8s %-16s%</u>\n",
		    "ADDR", "MOD", "TID", "FUNC");
	}

	mdb_printf("%-11p %-11p %-8u %a\n",
	    addr, thr.thr_mod, thr.thr_tid, thr.thr_func);

	return (DCMD_OK);
}

static int
mod_walk_init(mdb_walk_state_t *wsp)
{
	fmd_t F;

	if (mdb_readvar(&F, "fmd") != sizeof (F)) {
		mdb_warn("failed to read fmd meta-data");
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)F.d_mod_list.l_next;
	return (WALK_NEXT);
}

static int
mod_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;
	fmd_module_t m;

	if (addr == 0)
		return (WALK_DONE);

	if (mdb_vread(&m, sizeof (m), addr) != sizeof (m)) {
		mdb_warn("failed to read fmd_module at %p", addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)m.mod_list.l_next;
	return (wsp->walk_callback(addr, &m, wsp->walk_cbdata));
}

static int
fmd_module(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	fmd_module_t mod;
	char name[PATH_MAX];

	if (!(flags & DCMD_ADDRSPEC))
		return (mdb_walk_dcmd("fmd_module", "fmd_module", argc, argv));

	if (argc != 0)
		return (DCMD_USAGE);

	if (mdb_vread(&mod, sizeof (mod), addr) != sizeof (mod)) {
		mdb_warn("failed to read fmd_module at %p", addr);
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%-11s %-16s %-11s %-4s %-?s %-16s%</u>\n",
		    "ADDR", "OPS", "DATA", "FLAG", "USTAT", "NAME");
	}

	if (mdb_readstr(name, sizeof (name), (uintptr_t)mod.mod_name) <= 0)
		(void) mdb_snprintf(name, sizeof (name), "<%p>", mod.mod_name);

	mdb_printf("%-11p %-16a %-11p 0x%02x %-?p %s\n", addr,
	    mod.mod_ops, mod.mod_data, mod.mod_flags, mod.mod_ustat, name);

	return (DCMD_OK);
}

static int
case_walk_init(mdb_walk_state_t *wsp)
{
	fmd_module_t mod;
	fmd_case_hash_t ch;
	fmd_t F;

	if (wsp->walk_addr != 0) {
		if (mdb_vread(&mod, sizeof (mod), wsp->walk_addr) == -1) {
			mdb_warn("failed to read module at %p", wsp->walk_addr);
			return (WALK_ERR);
		}

		wsp->walk_addr = (uintptr_t)mod.mod_cases.l_next;
		return (WALK_NEXT);
	}

	if (mdb_readvar(&F, "fmd") != sizeof (F) ||
	    mdb_vread(&ch, sizeof (ch), (uintptr_t)F.d_cases) != sizeof (ch)) {
		mdb_warn("failed to read fmd meta-data");
		return (WALK_ERR);
	}

	return (hash_walk_init(wsp, (uintptr_t)ch.ch_hash, ch.ch_hashlen,
	    "fmd_case", sizeof (fmd_case_impl_t),
	    OFFSETOF(fmd_case_impl_t, ci_next)));
}

static int
case_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;
	fmd_case_impl_t ci;

	if (wsp->walk_data != NULL)
		return (hash_walk_step(wsp));

	if (addr == 0)
		return (WALK_DONE);

	if (mdb_vread(&ci, sizeof (ci), addr) != sizeof (ci)) {
		mdb_warn("failed to read fmd_case at %p", addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)ci.ci_list.l_next;
	return (wsp->walk_callback(addr, &ci, wsp->walk_cbdata));
}

static void
case_walk_fini(mdb_walk_state_t *wsp)
{
	if (wsp->walk_data != NULL)
		hash_walk_fini(wsp);
}

static int
fmd_case(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char uuid[48], name[16];
	fmd_case_impl_t ci;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("fmd_case", "fmd_case", argc, argv) != 0) {
			mdb_warn("failed to walk fmd_case hash");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_vread(&ci, sizeof (ci), addr) != sizeof (ci)) {
		mdb_warn("failed to read fmd_case at %p", addr);
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%-11s %-5s %-3s %-?s %-36s%</u>\n",
		    "ADDR", "STATE", "REF", "DATA", "UUID");
	}

	if (mdb_readstr(uuid, sizeof (uuid), (uintptr_t)ci.ci_uuid) <= 0)
		(void) mdb_snprintf(uuid, sizeof (uuid), "<%p>", ci.ci_uuid);

	switch (ci.ci_state) {
	case FMD_CASE_UNSOLVED:
		(void) strcpy(name, "UNSLV");
		break;
	case FMD_CASE_SOLVED:
		(void) strcpy(name, "SOLVE");
		break;
	case FMD_CASE_CLOSE_WAIT:
		(void) strcpy(name, "CWAIT");
		break;
	case FMD_CASE_CLOSED:
		(void) strcpy(name, "CLOSE");
		break;
	case FMD_CASE_REPAIRED:
		(void) strcpy(name, "RPAIR");
		break;
	case FMD_CASE_RESOLVED:
		(void) strcpy(name, "RSLVD");
		break;
	default:
		(void) mdb_snprintf(name, sizeof (name), "%u", ci.ci_state);
	}

	mdb_printf("%-11p %-5s %-3u %-?p %s\n",
	    addr, name, ci.ci_refs, ci.ci_data, uuid);

	return (DCMD_OK);
}

static int
buf_walk_init(mdb_walk_state_t *wsp)
{
	fmd_buf_hash_t bh;

	if (mdb_vread(&bh, sizeof (bh), wsp->walk_addr) != sizeof (bh)) {
		mdb_warn("failed to read fmd_buf_hash_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	return (hash_walk_init(wsp, (uintptr_t)bh.bh_hash, bh.bh_hashlen,
	    "fmd_buf", sizeof (fmd_buf_t), OFFSETOF(fmd_buf_t, buf_next)));
}

/*ARGSUSED*/
static int
fmd_buf(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char name[PATH_MAX];
	fmd_buf_t b;

	if (argc != 0 || !(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&b, sizeof (b), addr) != sizeof (b)) {
		mdb_warn("failed to read fmd_buf at %p", addr);
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%-11s %-32s %-5s %-?s %s%</u>\n",
		    "ADDR", "NAME", "FLAGS", "DATA", "SIZE");
	}

	if (mdb_readstr(name, sizeof (name), (uintptr_t)b.buf_name) <= 0)
		(void) mdb_snprintf(name, sizeof (name), "<%p>", b.buf_name);

	mdb_printf("%-11p %-32s %-#5x %-?p %lu\n",
	    addr, name, b.buf_flags, b.buf_data, b.buf_size);

	return (DCMD_OK);
}

static int
serd_walk_init(mdb_walk_state_t *wsp)
{
	fmd_serd_hash_t sh;

	if (mdb_vread(&sh, sizeof (sh), wsp->walk_addr) != sizeof (sh)) {
		mdb_warn("failed to read fmd_serd_hash at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	return (hash_walk_init(wsp, (uintptr_t)sh.sh_hash, sh.sh_hashlen,
	    "fmd_serd_eng", sizeof (fmd_serd_eng_t),
	    OFFSETOF(fmd_serd_eng_t, sg_next)));
}

/* ARGSUSED */
static int
module_serd(uintptr_t addr, const void *data, void *wsp)
{
	fmd_module_t *modp = (fmd_module_t *)data;

	if (modp->mod_serds.sh_count != 0) {
		modp = (fmd_module_t *)addr;
		(void) mdb_pwalk_dcmd("fmd_serd", "fmd_serd", 0, 0,
		    (uintptr_t)&modp->mod_serds);
	}
	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
fmd_serd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char name[PATH_MAX];
	fmd_serd_eng_t sg;

	if (argc != 0)
		return (DCMD_USAGE);
	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk("fmd_module", module_serd, 0) == -1) {
			mdb_warn("failed to walk 'fmd_module'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_vread(&sg, sizeof (sg), addr) != sizeof (sg)) {
		mdb_warn("failed to read fmd_serd_eng at %p", addr);
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%-11s %-32s %-3s F >%-2s %-16s%</u>\n",
		    "ADDR", "NAME", "CNT", "N", "T");
	}

	if (mdb_readstr(name, sizeof (name), (uintptr_t)sg.sg_name) <= 0)
		(void) mdb_snprintf(name, sizeof (name), "<%p>", sg.sg_name);

	mdb_printf("%-11p %-32s %-3u %c >%-2u %lluns\n",
	    addr, name, sg.sg_count, (sg.sg_flags & FMD_SERD_FIRED) ? 'F' : ' ',
	    sg.sg_n, (u_longlong_t)sg.sg_t);

	return (DCMD_OK);
}

static int
asru_walk_init(mdb_walk_state_t *wsp)
{
	fmd_asru_hash_t ah;
	fmd_t F;

	if (wsp->walk_addr == 0 && mdb_readvar(&F, "fmd") != sizeof (F)) {
		mdb_warn("failed to read fmd meta-data");
		return (WALK_ERR);
	}

	if (wsp->walk_addr == 0)
		wsp->walk_addr = (uintptr_t)F.d_asrus;

	if (mdb_vread(&ah, sizeof (ah), wsp->walk_addr) != sizeof (ah)) {
		mdb_warn("failed to read asru_hash at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	return (hash_walk_init(wsp, (uintptr_t)ah.ah_hash, ah.ah_hashlen,
	    "fmd_asru", sizeof (fmd_asru_t), OFFSETOF(fmd_asru_t, asru_next)));
}

static int
fmd_asru(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char uuid[48], name[PATH_MAX];
	fmd_asru_t a;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("fmd_asru", "fmd_asru", argc, argv) != 0) {
			mdb_warn("failed to walk fmd_asru hash");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_vread(&a, sizeof (a), addr) != sizeof (a)) {
		mdb_warn("failed to read fmd_asru at %p", addr);
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%<u>%-8s %-36s %s%</u>\n", "ADDR", "UUID", "NAME");

	if (mdb_readstr(uuid, sizeof (uuid), (uintptr_t)a.asru_uuid) <= 0)
		(void) mdb_snprintf(uuid, sizeof (uuid), "<%p>", a.asru_uuid);
	if (mdb_readstr(name, sizeof (name), (uintptr_t)a.asru_name) <= 0)
		(void) mdb_snprintf(name, sizeof (name), "<%p>", a.asru_name);

	mdb_printf("%-8p %-36s %s\n", addr, uuid, name);
	return (DCMD_OK);
}

static int
al_walk_init(mdb_walk_state_t *wsp)
{
	fmd_asru_hash_t ah;
	fmd_t F;

	if (wsp->walk_addr == 0 && mdb_readvar(&F, "fmd") != sizeof (F)) {
		mdb_warn("failed to read fmd meta-data");
		return (WALK_ERR);
	}

	if (wsp->walk_addr == 0)
		wsp->walk_addr = (uintptr_t)F.d_asrus;

	if (mdb_vread(&ah, sizeof (ah), wsp->walk_addr) != sizeof (ah)) {
		mdb_warn("failed to read asru_hash at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	return (hash_walk_init(wsp, (uintptr_t)ah.ah_rsrc_hash, ah.ah_hashlen,
	    "fmd_asru_link", sizeof (fmd_asru_link_t), OFFSETOF(fmd_asru_link_t,
	    al_rsrc_next)));
}

static int
fmd_asru_link(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char uuid[48], name[PATH_MAX];
	fmd_asru_link_t a;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("fmd_asru_link", "fmd_asru_link", argc,
		    argv) != 0) {
			mdb_warn("failed to walk fmd_asru_link hash");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_vread(&a, sizeof (a), addr) != sizeof (a)) {
		mdb_warn("failed to read fmd_asru_link at %p", addr);
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%<u>%-8s %-36s %s%</u>\n", "ADDR", "UUID", "NAME");

	if (mdb_readstr(uuid, sizeof (uuid), (uintptr_t)a.al_uuid) <= 0)
		(void) mdb_snprintf(uuid, sizeof (uuid), "<%p>", a.al_uuid);
	if (mdb_readstr(name, sizeof (name), (uintptr_t)a.al_rsrc_name) <= 0)
		(void) mdb_snprintf(name, sizeof (name), "<%p>",
		    a.al_rsrc_name);

	mdb_printf("%-8p %-36s %s\n", addr, uuid, name);
	return (DCMD_OK);
}

/*ARGSUSED*/
static int
fcf_hdr(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	fcf_hdr_t h;

	if (argc != 0)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC))
		addr = 0; /* assume base of file in file target */

	if (mdb_vread(&h, sizeof (h), addr) != sizeof (h)) {
		mdb_warn("failed to read header at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("fcfh_ident.id_magic = 0x%x, %c, %c, %c\n",
	    h.fcfh_ident[FCF_ID_MAG0], h.fcfh_ident[FCF_ID_MAG1],
	    h.fcfh_ident[FCF_ID_MAG2], h.fcfh_ident[FCF_ID_MAG3]);

	switch (h.fcfh_ident[FCF_ID_MODEL]) {
	case FCF_MODEL_ILP32:
		mdb_printf("fcfh_ident.id_model = ILP32\n");
		break;
	case FCF_MODEL_LP64:
		mdb_printf("fcfh_ident.id_model = LP64\n");
		break;
	default:
		mdb_printf("fcfh_ident.id_model = 0x%x\n",
		    h.fcfh_ident[FCF_ID_MODEL]);
	}

	switch (h.fcfh_ident[FCF_ID_ENCODING]) {
	case FCF_ENCODE_LSB:
		mdb_printf("fcfh_ident.id_encoding = LSB\n");
		break;
	case FCF_ENCODE_MSB:
		mdb_printf("fcfh_ident.id_encoding = MSB\n");
		break;
	default:
		mdb_printf("fcfh_ident.id_encoding = 0x%x\n",
		    h.fcfh_ident[FCF_ID_ENCODING]);
	}

	mdb_printf("fcfh_ident.id_version = %u\n",
	    h.fcfh_ident[FCF_ID_VERSION]);

	mdb_printf("fcfh_flags = 0x%x\n", h.fcfh_flags);
	mdb_printf("fcfh_hdrsize = %u\n", h.fcfh_hdrsize);
	mdb_printf("fcfh_secsize = %u\n", h.fcfh_secsize);
	mdb_printf("fcfh_secnum = %u\n", h.fcfh_secnum);
	mdb_printf("fcfh_secoff = %llu\n", h.fcfh_secoff);
	mdb_printf("fcfh_filesz = %llu\n", h.fcfh_filesz);
	mdb_printf("fcfh_cgen = %llu\n", h.fcfh_cgen);

	return (DCMD_OK);
}

static int fcf_sec(uintptr_t, uint_t, int, const mdb_arg_t *);
/*ARGSUSED*/
static int
fcf_sec_one(uintptr_t addr, void *ignored, uint_t *secp)
{

	mdb_printf("%3d ", (*secp)++);
	(void) fcf_sec(addr, DCMD_ADDRSPEC | DCMD_LOOP, 0, NULL);
	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
fcf_sec(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	static const char *const types[] = {
		"none",		/* FCF_SECT_NONE */
		"strtab",	/* FCF_SECT_STRTAB */
		"module",	/* FCF_SECT_MODULE */
		"case",		/* FCF_SECT_CASE */
		"bufs",		/* FCF_SECT_BUFS */
		"buffer",	/* FCF_SECT_BUFFER */
		"serd",		/* FCF_SECT_SERD */
		"events",	/* FCF_SECT_EVENTS */
		"nvlists",	/* FCF_SECT_NVLISTS */
	};

	uint_t sec = 0;
	fcf_sec_t s;

	if (!(flags & DCMD_ADDRSPEC))
		mdb_printf("%<u>%-3s ", "NDX");

	if (!(flags & DCMD_ADDRSPEC) || DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%?s %-10s %-5s %-5s %-5s %-6s %-5s%</u>\n",
		    "ADDR", "TYPE", "ALIGN", "FLAGS", "ENTSZ", "OFF", "SIZE");
	}

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk("fcf_sec", (mdb_walk_cb_t)fcf_sec_one, &sec) < 0) {
			mdb_warn("failed to walk fcf_sec");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (argc != 0)
		return (DCMD_USAGE);

	if (mdb_vread(&s, sizeof (s), addr) != sizeof (s)) {
		mdb_warn("failed to read section header at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%?p ", addr);

	if (s.fcfs_type < sizeof (types) / sizeof (types[0]))
		mdb_printf("%-10s ", types[s.fcfs_type]);
	else
		mdb_printf("%-10u ", s.fcfs_type);

	mdb_printf("%-5u %-#5x %-#5x %-6llx %-#5llx\n", s.fcfs_align,
	    s.fcfs_flags, s.fcfs_entsize, s.fcfs_offset, s.fcfs_size);

	return (DCMD_OK);
}

static int
fcf_sec_walk_init(mdb_walk_state_t *wsp)
{
	fcf_hdr_t h, *hp;
	size_t size;

	if (mdb_vread(&h, sizeof (h), wsp->walk_addr) != sizeof (h)) {
		mdb_warn("failed to read FCF header at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	size = sizeof (fcf_hdr_t) + sizeof (fcf_sec_t) * h.fcfh_secnum;
	hp = mdb_alloc(size, UM_SLEEP);

	if (mdb_vread(hp, size, wsp->walk_addr) != size) {
		mdb_warn("failed to read FCF sections at %p", wsp->walk_addr);
		mdb_free(hp, size);
		return (WALK_ERR);
	}

	wsp->walk_data = hp;
	wsp->walk_arg = 0;

	return (WALK_NEXT);
}

static int
fcf_sec_walk_step(mdb_walk_state_t *wsp)
{
	uint_t i = (uint_t)wsp->walk_arg;
	size_t off = sizeof (fcf_hdr_t) + sizeof (fcf_sec_t) * i;
	fcf_hdr_t *hp = wsp->walk_data;
	fcf_sec_t *sp = (fcf_sec_t *)((uintptr_t)hp + off);

	if (i >= hp->fcfh_secnum)
		return (WALK_DONE);

	wsp->walk_arg = (void *)(i + 1);
	return (wsp->walk_callback(wsp->walk_addr + off, sp, wsp->walk_cbdata));
}

static void
fcf_sec_walk_fini(mdb_walk_state_t *wsp)
{
	fcf_hdr_t *hp = wsp->walk_data;
	mdb_free(hp, sizeof (fcf_hdr_t) + sizeof (fcf_sec_t) * hp->fcfh_secnum);
}

/*ARGSUSED*/
static int
fcf_case(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	fcf_case_t fcfc;

	if (argc != 0)
		return (DCMD_USAGE);

	if (mdb_vread(&fcfc, sizeof (fcfc), addr) != sizeof (fcfc)) {
		mdb_warn("failed to read case at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("fcfc_uuid = 0x%x\n", fcfc.fcfc_uuid);
	mdb_printf("fcfc_state = %u\n", fcfc.fcfc_state);
	mdb_printf("fcfc_bufs = %u\n", fcfc.fcfc_bufs);
	mdb_printf("fcfc_events = %u\n", fcfc.fcfc_events);
	mdb_printf("fcfc_suspects = %u\n", fcfc.fcfc_suspects);

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
fcf_event(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	fcf_event_t fcfe;

	if (argc != 0)
		return (DCMD_USAGE);

	if (mdb_vread(&fcfe, sizeof (fcfe), addr) != sizeof (fcfe)) {
		mdb_warn("failed to read event at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("fcfe_todsec = %llu (%Y)\n",
	    fcfe.fcfe_todsec, (time_t)fcfe.fcfe_todsec);
	mdb_printf("fcfe_todnsec = %llu\n", fcfe.fcfe_todnsec);
	mdb_printf("fcfe_major = %u\n", fcfe.fcfe_major);
	mdb_printf("fcfe_minor = %u\n", fcfe.fcfe_minor);
	mdb_printf("fcfe_inode = %llu\n", fcfe.fcfe_inode);
	mdb_printf("fcfe_offset = %llu\n", fcfe.fcfe_offset);

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
fcf_serd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	fcf_serd_t fcfd;

	if (argc != 0)
		return (DCMD_USAGE);

	if (mdb_vread(&fcfd, sizeof (fcfd), addr) != sizeof (fcfd)) {
		mdb_warn("failed to read serd at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("fcfd_name = 0x%x\n", fcfd.fcfd_name);
	mdb_printf("fcfd_events = %u\n", fcfd.fcfd_events);
	mdb_printf("fcfd_n = >%u\n", fcfd.fcfd_n);
	mdb_printf("fcfd_t = %lluns\n", fcfd.fcfd_t);

	return (DCMD_OK);
}

static int
tmq_walk_init(mdb_walk_state_t *wsp)
{
	fmd_timerq_t tmq;
	fmd_t F;

	if (wsp->walk_addr == 0 && mdb_readvar(&F, "fmd") != sizeof (F)) {
		mdb_warn("failed to read fmd meta-data");
		return (WALK_ERR);
	}

	if (wsp->walk_addr == 0)
		wsp->walk_addr = (uintptr_t)F.d_timers;

	if (mdb_vread(&tmq, sizeof (tmq), wsp->walk_addr) != sizeof (tmq)) {
		mdb_warn("failed to read timerq at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)tmq.tmq_list.l_next;
	return (WALK_NEXT);
}

static int
tmq_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;
	fmd_timer_t tmr;

	if (addr == 0)
		return (WALK_DONE);

	if (mdb_vread(&tmr, sizeof (tmr), addr) != sizeof (tmr)) {
		mdb_warn("failed to read fmd_timer at %p", addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)tmr.tmr_list.l_next;
	return (wsp->walk_callback(addr, &tmr, wsp->walk_cbdata));
}

static int
fmd_timer(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char name[32], func[MDB_SYM_NAMLEN];
	fmd_timer_t t;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("fmd_timerq", "fmd_timer", argc, argv) != 0) {
			mdb_warn("failed to walk fmd_timerq");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_vread(&t, sizeof (t), addr) != sizeof (t)) {
		mdb_warn("failed to read fmd_timer at %p", addr);
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%-8s %-20s %-4s %-18s %-8s %s%</u>\n",
		    "ADDR", "MODULE", "ID", "HRTIME", "ARG", "FUNC");
	}

	if (mdb_readstr(name, sizeof (name), (uintptr_t)
	    t.tmr_ids + OFFSETOF(fmd_idspace_t, ids_name)) <= 0)
		(void) mdb_snprintf(name, sizeof (name), "<%p>", t.tmr_ids);

	if (mdb_lookup_by_addr((uintptr_t)t.tmr_func, MDB_SYM_FUZZY,
	    func, sizeof (func), NULL) != 0)
		(void) mdb_snprintf(func, sizeof (func), "<%p>", t.tmr_func);

	mdb_printf("%-8p %-20s %4d 0x%-16llx %-8p %s\n",
	    addr, name, t.tmr_id, t.tmr_hrt, t.tmr_arg, func);
	return (DCMD_OK);
}

static int
xprt_walk_init(mdb_walk_state_t *wsp)
{
	fmd_module_t m;

	if (wsp->walk_addr == 0) {
		mdb_warn("transport walker requires fmd_module_t address\n");
		return (WALK_ERR);
	}

	if (mdb_vread(&m, sizeof (m), wsp->walk_addr) != sizeof (m)) {
		mdb_warn("failed to read module at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)m.mod_transports.l_next;
	return (WALK_NEXT);
}

static int
xprt_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;
	fmd_xprt_impl_t xi;

	if (addr == 0)
		return (WALK_DONE);

	if (mdb_vread(&xi, sizeof (xi), addr) != sizeof (xi)) {
		mdb_warn("failed to read fmd_xprt at %p", addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)xi.xi_list.l_next;
	return (wsp->walk_callback(addr, &xi, wsp->walk_cbdata));
}

static int
xpc_walk_init(mdb_walk_state_t *wsp)
{
	fmd_xprt_class_hash_t xch;

	if (mdb_vread(&xch, sizeof (xch), wsp->walk_addr) != sizeof (xch)) {
		mdb_warn("failed to read fmd_xprt_class_hash at %p",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	return (hash_walk_init(wsp, (uintptr_t)xch.xch_hash, xch.xch_hashlen,
	    "fmd_xprt_class", sizeof (fmd_xprt_class_t),
	    OFFSETOF(fmd_xprt_class_t, xc_next)));
}

/*ARGSUSED*/
static int
fmd_xprt_class(uintptr_t addr, const void *data, void *arg)
{
	const fmd_xprt_class_t *xcp = data;
	char name[1024];

	if (mdb_readstr(name, sizeof (name), (uintptr_t)xcp->xc_class) <= 0)
		(void) mdb_snprintf(name, sizeof (name), "<%p>", xcp->xc_class);

	mdb_printf("%-8p %-4u %s\n", addr, xcp->xc_refs, name);
	return (WALK_NEXT);
}

static int
fmd_xprt(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t opt_s = FALSE, opt_l = FALSE, opt_r = FALSE, opt_u = FALSE;
	fmd_xprt_impl_t xi;

	if (mdb_getopts(argc, argv,
	    'l', MDB_OPT_SETBITS, TRUE, &opt_l,
	    'r', MDB_OPT_SETBITS, TRUE, &opt_r,
	    's', MDB_OPT_SETBITS, TRUE, &opt_s,
	    'u', MDB_OPT_SETBITS, TRUE, &opt_u, NULL) != argc)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("fmd_xprt", "fmd_xprt", argc, argv) != 0) {
			mdb_warn("failed to walk fmd_xprt");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_vread(&xi, sizeof (xi), addr) != sizeof (xi)) {
		mdb_warn("failed to read fmd_xprt at %p", addr);
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%-8s %-4s %-4s %-5s %s%</u>\n",
		    "ADDR", "ID", "VERS", "FLAGS", "STATE");
	}

	mdb_printf("%-8p %-4d %-4u %-5x %a\n",
	    addr, xi.xi_id, xi.xi_version, xi.xi_flags, xi.xi_state);

	if (opt_l | opt_s) {
		(void) mdb_inc_indent(4);
		mdb_printf("Local subscriptions requested by peer:\n");
		mdb_printf("%<u>%-8s %-4s %s%</u>\n", "ADDR", "REFS", "CLASS");
		(void) mdb_pwalk("fmd_xprt_class", fmd_xprt_class, &xi,
		    addr + OFFSETOF(fmd_xprt_impl_t, xi_lsub));
		(void) mdb_dec_indent(4);
	}

	if (opt_r | opt_s) {
		(void) mdb_inc_indent(4);
		mdb_printf("Remote subscriptions requested of peer:\n");
		mdb_printf("%<u>%-8s %-4s %s%</u>\n", "ADDR", "REFS", "CLASS");
		(void) mdb_pwalk("fmd_xprt_class", fmd_xprt_class, &xi,
		    addr + OFFSETOF(fmd_xprt_impl_t, xi_rsub));
		(void) mdb_dec_indent(4);
	}

	if (opt_u | opt_s) {
		(void) mdb_inc_indent(4);
		mdb_printf("Pending unsubscription acknowledgements:\n");
		mdb_printf("%<u>%-8s %-4s %s%</u>\n", "ADDR", "REFS", "CLASS");
		(void) mdb_pwalk("fmd_xprt_class", fmd_xprt_class, &xi,
		    addr + OFFSETOF(fmd_xprt_impl_t, xi_usub));
		(void) mdb_dec_indent(4);
	}

	return (DCMD_OK);
}

static int
tsnap_walk_init(mdb_walk_state_t *wsp)
{
	fmd_t F;

	if (mdb_readvar(&F, "fmd") != sizeof (F)) {
		mdb_warn("failed to read fmd meta-data");
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)F.d_topo_list.l_next;
	return (WALK_NEXT);
}

static int
tsnap_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;
	fmd_topo_t ftp;

	if (addr == 0)
		return (WALK_DONE);

	if (mdb_vread(&ftp, sizeof (ftp), addr) != sizeof (ftp)) {
		mdb_warn("failed to read fmd_topo_t at %p", addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)ftp.ft_list.l_next;
	return (wsp->walk_callback(addr, &ftp, wsp->walk_cbdata));
}

static int
mq_walk_init(mdb_walk_state_t *wsp)
{
	fmd_module_t m;
	struct fmd_eventq eq;

	if (wsp->walk_addr == 0) {
		mdb_warn("NULL fmd_module_t passed in");
		return (WALK_ERR);
	}

	if (mdb_vread(&m, sizeof (m), wsp->walk_addr) != sizeof (m)) {
		mdb_warn("failed to read fmd_module_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}
	if (mdb_vread(&eq, sizeof (eq), (uintptr_t)m.mod_queue)
	    != sizeof (eq)) {
		mdb_warn("failed to read fmd_eventq at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)eq.eq_list.l_next;

	return (WALK_NEXT);
}

static int
mq_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;
	fmd_eventqelem_t eqe;

	if (addr == 0)
		return (WALK_DONE);

	if (mdb_vread(&eqe, sizeof (eqe), addr) != sizeof (eqe)) {
		mdb_warn("failed to read fmd_eventqelem_t at %p", addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)eqe.eqe_list.l_next;
	return (wsp->walk_callback(addr, &eqe, wsp->walk_cbdata));
}

static const mdb_dcmd_t dcmds[] = {
	{ "fcf_case", "?", "print a FCF case", fcf_case },
	{ "fcf_event", "?", "print a FCF event", fcf_event },
	{ "fcf_hdr", "?", "print a FCF header", fcf_hdr },
	{ "fcf_sec", ":", "print a FCF section header", fcf_sec },
	{ "fcf_serd", "?", "print a FCF serd engine", fcf_serd },
	{ "fmd_trace", "?[-cs]", "display thread trace buffer(s)", fmd_trace },
	{ "fmd_ustat", "[:]", "display statistics collection", fmd_ustat },
	{ "fmd_stat", "[:]", "display statistic structure", fmd_stat },
	{ "fmd_event", NULL, "display event structure", fmd_event },
	{ "fmd_thread", "?", "display thread or list of threads", fmd_thread },
	{ "fmd_module", "?", "display module or list of modules", fmd_module },
	{ "fmd_case", ":", "display case file structure", fmd_case },
	{ "fmd_buf", ":", "display buffer structure", fmd_buf },
	{ "fmd_serd", "[:]", "display serd engine structure", fmd_serd },
	{ "fmd_asru", "?", "display asru resource structure", fmd_asru },
	{ "fmd_asru_link", "?", "display resource structure", fmd_asru_link },
	{ "fmd_timer", "?", "display pending timer(s)", fmd_timer },
	{ "fmd_xprt", "?[-lrsu]", "display event transport(s)", fmd_xprt },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "fcf_sec", "walk FCF section header table given header address",
		fcf_sec_walk_init, fcf_sec_walk_step, fcf_sec_walk_fini },
	{ "fmd_trace", "walk per-thread trace buffers",
		trwalk_init, trwalk_step, trwalk_fini },
	{ "fmd_ustat", "walk per-collection statistics",
		ustat_walk_init, ustat_walk_step, hash_walk_fini },
	{ "fmd_thread", "walk list of all fmd_thread_t's",
		thread_walk_init, thread_walk_step, NULL },
	{ "fmd_module", "walk list of all fmd_module_t's",
		mod_walk_init, mod_walk_step, NULL },
	{ "fmd_case", "walk per-module case objects",
		case_walk_init, case_walk_step, case_walk_fini },
	{ "fmd_buf", "walk per-buf_hash buffers",
		buf_walk_init, hash_walk_step, hash_walk_fini },
	{ "fmd_serd", "walk per-serd_hash engines",
		serd_walk_init, hash_walk_step, hash_walk_fini },
	{ "fmd_asru", "walk asru resource hash",
		asru_walk_init, hash_walk_step, hash_walk_fini },
	{ "fmd_asru_link", "walk resource hash",
		al_walk_init, hash_walk_step, hash_walk_fini },
	{ "fmd_timerq", "walk timer queue",
		tmq_walk_init, tmq_walk_step, NULL },
	{ "fmd_xprt", "walk per-module list of transports",
		xprt_walk_init, xprt_walk_step, NULL },
	{ "fmd_xprt_class", "walk hash table of subscription classes",
		xpc_walk_init, hash_walk_step, hash_walk_fini },
	{ "fmd_topo", "walk fmd's list of topo snapshots",
		tsnap_walk_init, tsnap_walk_step, NULL },
	{ "fmd_mod_queue", "walk per-module event queue",
		mq_walk_init, mq_walk_step, NULL },
	{ NULL, NULL, NULL, NULL, NULL }
};

static const mdb_modinfo_t modinfo = { MDB_API_VERSION, dcmds, walkers };

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
