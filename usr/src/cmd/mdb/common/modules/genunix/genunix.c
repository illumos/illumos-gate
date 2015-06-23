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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2013 Joyent, Inc. All rights reserved.
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

#include <mdb/mdb_param.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>
#include <mdb/mdb_ctf.h>

#include <sys/types.h>
#include <sys/thread.h>
#include <sys/session.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/var.h>
#include <sys/t_lock.h>
#include <sys/callo.h>
#include <sys/priocntl.h>
#include <sys/class.h>
#include <sys/regset.h>
#include <sys/stack.h>
#include <sys/cpuvar.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/flock_impl.h>
#include <sys/kmem_impl.h>
#include <sys/vmem_impl.h>
#include <sys/kstat.h>
#include <sys/dditypes.h>
#include <sys/ddi_impldefs.h>
#include <sys/sysmacros.h>
#include <sys/sysconf.h>
#include <sys/task.h>
#include <sys/project.h>
#include <sys/errorq_impl.h>
#include <sys/cred_impl.h>
#include <sys/zone.h>
#include <sys/panic.h>
#include <regex.h>
#include <sys/port_impl.h>

#include "avl.h"
#include "bio.h"
#include "bitset.h"
#include "combined.h"
#include "contract.h"
#include "cpupart_mdb.h"
#include "cred.h"
#include "ctxop.h"
#include "cyclic.h"
#include "damap.h"
#include "ddi_periodic.h"
#include "devinfo.h"
#include "findstack.h"
#include "fm.h"
#include "gcore.h"
#include "group.h"
#include "irm.h"
#include "kgrep.h"
#include "kmem.h"
#include "ldi.h"
#include "leaky.h"
#include "lgrp.h"
#include "list.h"
#include "log.h"
#include "mdi.h"
#include "memory.h"
#include "mmd.h"
#include "modhash.h"
#include "ndievents.h"
#include "net.h"
#include "netstack.h"
#include "nvpair.h"
#include "pg.h"
#include "rctl.h"
#include "sobj.h"
#include "streams.h"
#include "sysevent.h"
#include "taskq.h"
#include "thread.h"
#include "tsd.h"
#include "tsol.h"
#include "typegraph.h"
#include "vfs.h"
#include "zone.h"
#include "hotplug.h"

/*
 * Surely this is defined somewhere...
 */
#define	NINTR		16

#define	KILOS		10
#define	MEGS		20
#define	GIGS		30

#ifndef STACK_BIAS
#define	STACK_BIAS	0
#endif

static char
pstat2ch(uchar_t state)
{
	switch (state) {
		case SSLEEP: return ('S');
		case SRUN: return ('R');
		case SZOMB: return ('Z');
		case SIDL: return ('I');
		case SONPROC: return ('O');
		case SSTOP: return ('T');
		case SWAIT: return ('W');
		default: return ('?');
	}
}

#define	PS_PRTTHREADS	0x1
#define	PS_PRTLWPS	0x2
#define	PS_PSARGS	0x4
#define	PS_TASKS	0x8
#define	PS_PROJECTS	0x10
#define	PS_ZONES	0x20

static int
ps_threadprint(uintptr_t addr, const void *data, void *private)
{
	const kthread_t *t = (const kthread_t *)data;
	uint_t prt_flags = *((uint_t *)private);

	static const mdb_bitmask_t t_state_bits[] = {
		{ "TS_FREE",	UINT_MAX,	TS_FREE		},
		{ "TS_SLEEP",	TS_SLEEP,	TS_SLEEP	},
		{ "TS_RUN",	TS_RUN,		TS_RUN		},
		{ "TS_ONPROC",	TS_ONPROC,	TS_ONPROC	},
		{ "TS_ZOMB",	TS_ZOMB,	TS_ZOMB		},
		{ "TS_STOPPED",	TS_STOPPED,	TS_STOPPED	},
		{ "TS_WAIT",	TS_WAIT,	TS_WAIT		},
		{ NULL,		0,		0		}
	};

	if (prt_flags & PS_PRTTHREADS)
		mdb_printf("\tT  %?a <%b>\n", addr, t->t_state, t_state_bits);

	if (prt_flags & PS_PRTLWPS)
		mdb_printf("\tL  %?a ID: %u\n", t->t_lwp, t->t_tid);

	return (WALK_NEXT);
}

int
ps(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t prt_flags = 0;
	proc_t pr;
	struct pid pid, pgid, sid;
	sess_t session;
	cred_t cred;
	task_t tk;
	kproject_t pj;
	zone_t zn;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("proc", "ps", argc, argv) == -1) {
			mdb_warn("can't walk 'proc'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_getopts(argc, argv,
	    'f', MDB_OPT_SETBITS, PS_PSARGS, &prt_flags,
	    'l', MDB_OPT_SETBITS, PS_PRTLWPS, &prt_flags,
	    'T', MDB_OPT_SETBITS, PS_TASKS, &prt_flags,
	    'P', MDB_OPT_SETBITS, PS_PROJECTS, &prt_flags,
	    'z', MDB_OPT_SETBITS, PS_ZONES, &prt_flags,
	    't', MDB_OPT_SETBITS, PS_PRTTHREADS, &prt_flags, NULL) != argc)
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%1s %6s %6s %6s %6s ",
		    "S", "PID", "PPID", "PGID", "SID");
		if (prt_flags & PS_TASKS)
			mdb_printf("%5s ", "TASK");
		if (prt_flags & PS_PROJECTS)
			mdb_printf("%5s ", "PROJ");
		if (prt_flags & PS_ZONES)
			mdb_printf("%5s ", "ZONE");
		mdb_printf("%6s %10s %?s %s%</u>\n",
		    "UID", "FLAGS", "ADDR", "NAME");
	}

	mdb_vread(&pr, sizeof (pr), addr);
	mdb_vread(&pid, sizeof (pid), (uintptr_t)pr.p_pidp);
	mdb_vread(&pgid, sizeof (pgid), (uintptr_t)pr.p_pgidp);
	mdb_vread(&cred, sizeof (cred), (uintptr_t)pr.p_cred);
	mdb_vread(&session, sizeof (session), (uintptr_t)pr.p_sessp);
	mdb_vread(&sid, sizeof (sid), (uintptr_t)session.s_sidp);
	if (prt_flags & (PS_TASKS | PS_PROJECTS))
		mdb_vread(&tk, sizeof (tk), (uintptr_t)pr.p_task);
	if (prt_flags & PS_PROJECTS)
		mdb_vread(&pj, sizeof (pj), (uintptr_t)tk.tk_proj);
	if (prt_flags & PS_ZONES)
		mdb_vread(&zn, sizeof (zone_t), (uintptr_t)pr.p_zone);

	mdb_printf("%c %6d %6d %6d %6d ",
	    pstat2ch(pr.p_stat), pid.pid_id, pr.p_ppid, pgid.pid_id,
	    sid.pid_id);
	if (prt_flags & PS_TASKS)
		mdb_printf("%5d ", tk.tk_tkid);
	if (prt_flags & PS_PROJECTS)
		mdb_printf("%5d ", pj.kpj_id);
	if (prt_flags & PS_ZONES)
		mdb_printf("%5d ", zn.zone_id);
	mdb_printf("%6d 0x%08x %0?p %s\n",
	    cred.cr_uid, pr.p_flag, addr,
	    (prt_flags & PS_PSARGS) ? pr.p_user.u_psargs : pr.p_user.u_comm);

	if (prt_flags & ~PS_PSARGS)
		(void) mdb_pwalk("thread", ps_threadprint, &prt_flags, addr);

	return (DCMD_OK);
}

#define	PG_NEWEST	0x0001
#define	PG_OLDEST	0x0002
#define	PG_PIPE_OUT	0x0004
#define	PG_EXACT_MATCH	0x0008

typedef struct pgrep_data {
	uint_t pg_flags;
	uint_t pg_psflags;
	uintptr_t pg_xaddr;
	hrtime_t pg_xstart;
	const char *pg_pat;
#ifndef _KMDB
	regex_t pg_reg;
#endif
} pgrep_data_t;

/*ARGSUSED*/
static int
pgrep_cb(uintptr_t addr, const void *pdata, void *data)
{
	const proc_t *prp = pdata;
	pgrep_data_t *pgp = data;
#ifndef _KMDB
	regmatch_t pmatch;
#endif

	/*
	 * kmdb doesn't have access to the reg* functions, so we fall back
	 * to strstr/strcmp.
	 */
#ifdef _KMDB
	if ((pgp->pg_flags & PG_EXACT_MATCH) ?
	    (strcmp(prp->p_user.u_comm, pgp->pg_pat) != 0) :
	    (strstr(prp->p_user.u_comm, pgp->pg_pat) == NULL))
		return (WALK_NEXT);
#else
	if (regexec(&pgp->pg_reg, prp->p_user.u_comm, 1, &pmatch, 0) != 0)
		return (WALK_NEXT);

	if ((pgp->pg_flags & PG_EXACT_MATCH) &&
	    (pmatch.rm_so != 0 || prp->p_user.u_comm[pmatch.rm_eo] != '\0'))
		return (WALK_NEXT);
#endif

	if (pgp->pg_flags & (PG_NEWEST | PG_OLDEST)) {
		hrtime_t start;

		start = (hrtime_t)prp->p_user.u_start.tv_sec * NANOSEC +
		    prp->p_user.u_start.tv_nsec;

		if (pgp->pg_flags & PG_NEWEST) {
			if (pgp->pg_xaddr == NULL || start > pgp->pg_xstart) {
				pgp->pg_xaddr = addr;
				pgp->pg_xstart = start;
			}
		} else {
			if (pgp->pg_xaddr == NULL || start < pgp->pg_xstart) {
				pgp->pg_xaddr = addr;
				pgp->pg_xstart = start;
			}
		}

	} else if (pgp->pg_flags & PG_PIPE_OUT) {
		mdb_printf("%p\n", addr);

	} else {
		if (mdb_call_dcmd("ps", addr, pgp->pg_psflags, 0, NULL) != 0) {
			mdb_warn("can't invoke 'ps'");
			return (WALK_DONE);
		}
		pgp->pg_psflags &= ~DCMD_LOOPFIRST;
	}

	return (WALK_NEXT);
}

/*ARGSUSED*/
int
pgrep(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	pgrep_data_t pg;
	int i;
#ifndef _KMDB
	int err;
#endif

	if (flags & DCMD_ADDRSPEC)
		return (DCMD_USAGE);

	pg.pg_flags = 0;
	pg.pg_xaddr = 0;

	i = mdb_getopts(argc, argv,
	    'n', MDB_OPT_SETBITS, PG_NEWEST, &pg.pg_flags,
	    'o', MDB_OPT_SETBITS, PG_OLDEST, &pg.pg_flags,
	    'x', MDB_OPT_SETBITS, PG_EXACT_MATCH, &pg.pg_flags,
	    NULL);

	argc -= i;
	argv += i;

	if (argc != 1)
		return (DCMD_USAGE);

	/*
	 * -n and -o are mutually exclusive.
	 */
	if ((pg.pg_flags & PG_NEWEST) && (pg.pg_flags & PG_OLDEST))
		return (DCMD_USAGE);

	if (argv->a_type != MDB_TYPE_STRING)
		return (DCMD_USAGE);

	if (flags & DCMD_PIPE_OUT)
		pg.pg_flags |= PG_PIPE_OUT;

	pg.pg_pat = argv->a_un.a_str;
	if (DCMD_HDRSPEC(flags))
		pg.pg_psflags = DCMD_ADDRSPEC | DCMD_LOOP | DCMD_LOOPFIRST;
	else
		pg.pg_psflags = DCMD_ADDRSPEC | DCMD_LOOP;

#ifndef _KMDB
	if ((err = regcomp(&pg.pg_reg, pg.pg_pat, REG_EXTENDED)) != 0) {
		size_t nbytes;
		char *buf;

		nbytes = regerror(err, &pg.pg_reg, NULL, 0);
		buf = mdb_alloc(nbytes + 1, UM_SLEEP | UM_GC);
		(void) regerror(err, &pg.pg_reg, buf, nbytes);
		mdb_warn("%s\n", buf);

		return (DCMD_ERR);
	}
#endif

	if (mdb_walk("proc", pgrep_cb, &pg) != 0) {
		mdb_warn("can't walk 'proc'");
		return (DCMD_ERR);
	}

	if (pg.pg_xaddr != 0 && (pg.pg_flags & (PG_NEWEST | PG_OLDEST))) {
		if (pg.pg_flags & PG_PIPE_OUT) {
			mdb_printf("%p\n", pg.pg_xaddr);
		} else {
			if (mdb_call_dcmd("ps", pg.pg_xaddr, pg.pg_psflags,
			    0, NULL) != 0) {
				mdb_warn("can't invoke 'ps'");
				return (DCMD_ERR);
			}
		}
	}

	return (DCMD_OK);
}

int
task(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	task_t tk;
	kproject_t pj;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("task_cache", "task", argc, argv) == -1) {
			mdb_warn("can't walk task_cache");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}
	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%?s %6s %6s %6s %6s %10s%</u>\n",
		    "ADDR", "TASKID", "PROJID", "ZONEID", "REFCNT", "FLAGS");
	}
	if (mdb_vread(&tk, sizeof (task_t), addr) == -1) {
		mdb_warn("can't read task_t structure at %p", addr);
		return (DCMD_ERR);
	}
	if (mdb_vread(&pj, sizeof (kproject_t), (uintptr_t)tk.tk_proj) == -1) {
		mdb_warn("can't read project_t structure at %p", addr);
		return (DCMD_ERR);
	}
	mdb_printf("%0?p %6d %6d %6d %6u 0x%08x\n",
	    addr, tk.tk_tkid, pj.kpj_id, pj.kpj_zoneid, tk.tk_hold_count,
	    tk.tk_flags);
	return (DCMD_OK);
}

int
project(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	kproject_t pj;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("projects", "project", argc, argv) == -1) {
			mdb_warn("can't walk projects");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}
	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%?s %6s %6s %6s%</u>\n",
		    "ADDR", "PROJID", "ZONEID", "REFCNT");
	}
	if (mdb_vread(&pj, sizeof (kproject_t), addr) == -1) {
		mdb_warn("can't read kproject_t structure at %p", addr);
		return (DCMD_ERR);
	}
	mdb_printf("%0?p %6d %6d %6u\n", addr, pj.kpj_id, pj.kpj_zoneid,
	    pj.kpj_count);
	return (DCMD_OK);
}

/* walk callouts themselves, either by list or id hash. */
int
callout_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		mdb_warn("callout doesn't support global walk");
		return (WALK_ERR);
	}
	wsp->walk_data = mdb_alloc(sizeof (callout_t), UM_SLEEP);
	return (WALK_NEXT);
}

#define	CALLOUT_WALK_BYLIST	0
#define	CALLOUT_WALK_BYID	1

/* the walker arg switches between walking by list (0) and walking by id (1). */
int
callout_walk_step(mdb_walk_state_t *wsp)
{
	int retval;

	if (wsp->walk_addr == NULL) {
		return (WALK_DONE);
	}
	if (mdb_vread(wsp->walk_data, sizeof (callout_t),
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read callout at %p", wsp->walk_addr);
		return (WALK_DONE);
	}
	retval = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	if ((ulong_t)wsp->walk_arg == CALLOUT_WALK_BYID) {
		wsp->walk_addr =
		    (uintptr_t)(((callout_t *)wsp->walk_data)->c_idnext);
	} else {
		wsp->walk_addr =
		    (uintptr_t)(((callout_t *)wsp->walk_data)->c_clnext);
	}

	return (retval);
}

void
callout_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (callout_t));
}

/*
 * walker for callout lists. This is different from hashes and callouts.
 * Thankfully, it's also simpler.
 */
int
callout_list_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		mdb_warn("callout list doesn't support global walk");
		return (WALK_ERR);
	}
	wsp->walk_data = mdb_alloc(sizeof (callout_list_t), UM_SLEEP);
	return (WALK_NEXT);
}

int
callout_list_walk_step(mdb_walk_state_t *wsp)
{
	int retval;

	if (wsp->walk_addr == NULL) {
		return (WALK_DONE);
	}
	if (mdb_vread(wsp->walk_data, sizeof (callout_list_t),
	    wsp->walk_addr) != sizeof (callout_list_t)) {
		mdb_warn("failed to read callout_list at %p", wsp->walk_addr);
		return (WALK_ERR);
	}
	retval = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)
	    (((callout_list_t *)wsp->walk_data)->cl_next);

	return (retval);
}

void
callout_list_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (callout_list_t));
}

/* routines/structs to walk callout table(s) */
typedef struct cot_data {
	callout_table_t *ct0;
	callout_table_t ct;
	callout_hash_t cot_idhash[CALLOUT_BUCKETS];
	callout_hash_t cot_clhash[CALLOUT_BUCKETS];
	kstat_named_t ct_kstat_data[CALLOUT_NUM_STATS];
	int cotndx;
	int cotsize;
} cot_data_t;

int
callout_table_walk_init(mdb_walk_state_t *wsp)
{
	int max_ncpus;
	cot_data_t *cot_walk_data;

	cot_walk_data = mdb_alloc(sizeof (cot_data_t), UM_SLEEP);

	if (wsp->walk_addr == NULL) {
		if (mdb_readvar(&cot_walk_data->ct0, "callout_table") == -1) {
			mdb_warn("failed to read 'callout_table'");
			return (WALK_ERR);
		}
		if (mdb_readvar(&max_ncpus, "max_ncpus") == -1) {
			mdb_warn("failed to get callout_table array size");
			return (WALK_ERR);
		}
		cot_walk_data->cotsize = CALLOUT_NTYPES * max_ncpus;
		wsp->walk_addr = (uintptr_t)cot_walk_data->ct0;
	} else {
		/* not a global walk */
		cot_walk_data->cotsize = 1;
	}

	cot_walk_data->cotndx = 0;
	wsp->walk_data = cot_walk_data;

	return (WALK_NEXT);
}

int
callout_table_walk_step(mdb_walk_state_t *wsp)
{
	int retval;
	cot_data_t *cotwd = (cot_data_t *)wsp->walk_data;
	size_t size;

	if (cotwd->cotndx >= cotwd->cotsize) {
		return (WALK_DONE);
	}
	if (mdb_vread(&(cotwd->ct), sizeof (callout_table_t),
	    wsp->walk_addr) != sizeof (callout_table_t)) {
		mdb_warn("failed to read callout_table at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	size = sizeof (callout_hash_t) * CALLOUT_BUCKETS;
	if (cotwd->ct.ct_idhash != NULL) {
		if (mdb_vread(cotwd->cot_idhash, size,
		    (uintptr_t)(cotwd->ct.ct_idhash)) != size) {
			mdb_warn("failed to read id_hash at %p",
			    cotwd->ct.ct_idhash);
			return (WALK_ERR);
		}
	}
	if (cotwd->ct.ct_clhash != NULL) {
		if (mdb_vread(&(cotwd->cot_clhash), size,
		    (uintptr_t)cotwd->ct.ct_clhash) == -1) {
			mdb_warn("failed to read cl_hash at %p",
			    cotwd->ct.ct_clhash);
			return (WALK_ERR);
		}
	}
	size = sizeof (kstat_named_t) * CALLOUT_NUM_STATS;
	if (cotwd->ct.ct_kstat_data != NULL) {
		if (mdb_vread(&(cotwd->ct_kstat_data), size,
		    (uintptr_t)cotwd->ct.ct_kstat_data) == -1) {
			mdb_warn("failed to read kstats at %p",
			    cotwd->ct.ct_kstat_data);
			return (WALK_ERR);
		}
	}
	retval = wsp->walk_callback(wsp->walk_addr, (void *)cotwd,
	    wsp->walk_cbdata);

	cotwd->cotndx++;
	if (cotwd->cotndx >= cotwd->cotsize) {
		return (WALK_DONE);
	}
	wsp->walk_addr = (uintptr_t)((char *)wsp->walk_addr +
	    sizeof (callout_table_t));

	return (retval);
}

void
callout_table_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (cot_data_t));
}

static const char *co_typenames[] = { "R", "N" };

#define	CO_PLAIN_ID(xid)	((xid) & CALLOUT_ID_MASK)

#define	TABLE_TO_SEQID(x)	((x) >> CALLOUT_TYPE_BITS)

/* callout flags, in no particular order */
#define	COF_REAL	0x00000001
#define	COF_NORM	0x00000002
#define	COF_LONG	0x00000004
#define	COF_SHORT	0x00000008
#define	COF_EMPTY	0x00000010
#define	COF_TIME	0x00000020
#define	COF_BEFORE	0x00000040
#define	COF_AFTER	0x00000080
#define	COF_SEQID	0x00000100
#define	COF_FUNC	0x00000200
#define	COF_ADDR	0x00000400
#define	COF_EXEC	0x00000800
#define	COF_HIRES	0x00001000
#define	COF_ABS		0x00002000
#define	COF_TABLE	0x00004000
#define	COF_BYIDH	0x00008000
#define	COF_FREE	0x00010000
#define	COF_LIST	0x00020000
#define	COF_EXPREL	0x00040000
#define	COF_HDR		0x00080000
#define	COF_VERBOSE	0x00100000
#define	COF_LONGLIST	0x00200000
#define	COF_THDR	0x00400000
#define	COF_LHDR	0x00800000
#define	COF_CHDR	0x01000000
#define	COF_PARAM	0x02000000
#define	COF_DECODE	0x04000000
#define	COF_HEAP	0x08000000
#define	COF_QUEUE	0x10000000

/* show real and normal, short and long, expired and unexpired. */
#define	COF_DEFAULT	(COF_REAL | COF_NORM | COF_LONG | COF_SHORT)

#define	COF_LIST_FLAGS	\
	(CALLOUT_LIST_FLAG_HRESTIME | CALLOUT_LIST_FLAG_ABSOLUTE)

/* private callout data for callback functions */
typedef struct callout_data {
	uint_t flags;		/* COF_* */
	cpu_t *cpu;		/* cpu pointer if given */
	int seqid;		/* cpu seqid, or -1 */
	hrtime_t time;		/* expiration time value */
	hrtime_t atime;		/* expiration before value */
	hrtime_t btime;		/* expiration after value */
	uintptr_t funcaddr;	/* function address or NULL */
	uintptr_t param;	/* parameter to function or NULL */
	hrtime_t now;		/* current system time */
	int nsec_per_tick;	/* for conversions */
	ulong_t ctbits;		/* for decoding xid */
	callout_table_t *co_table;	/* top of callout table array */
	int ndx;		/* table index. */
	int bucket;		/* which list/id bucket are we in */
	hrtime_t exp;		/* expire time */
	int list_flags;		/* copy of cl_flags */
} callout_data_t;

/* this callback does the actual callback itself (finally). */
/*ARGSUSED*/
static int
callouts_cb(uintptr_t addr, const void *data, void *priv)
{
	callout_data_t *coargs = (callout_data_t *)priv;
	callout_t *co = (callout_t *)data;
	int tableid, list_flags;
	callout_id_t coid;

	if ((coargs == NULL) || (co == NULL)) {
		return (WALK_ERR);
	}

	if ((coargs->flags & COF_FREE) && !(co->c_xid & CALLOUT_ID_FREE)) {
		/*
		 * The callout must have been reallocated. No point in
		 * walking any more.
		 */
		return (WALK_DONE);
	}
	if (!(coargs->flags & COF_FREE) && (co->c_xid & CALLOUT_ID_FREE)) {
		/*
		 * The callout must have been freed. No point in
		 * walking any more.
		 */
		return (WALK_DONE);
	}
	if ((coargs->flags & COF_FUNC) &&
	    (coargs->funcaddr != (uintptr_t)co->c_func)) {
		return (WALK_NEXT);
	}
	if ((coargs->flags & COF_PARAM) &&
	    (coargs->param != (uintptr_t)co->c_arg)) {
		return (WALK_NEXT);
	}
	if (!(coargs->flags & COF_LONG) && (co->c_xid & CALLOUT_LONGTERM)) {
		return (WALK_NEXT);
	}
	if (!(coargs->flags & COF_SHORT) && !(co->c_xid & CALLOUT_LONGTERM)) {
		return (WALK_NEXT);
	}
	if ((coargs->flags & COF_EXEC) && !(co->c_xid & CALLOUT_EXECUTING)) {
		return (WALK_NEXT);
	}
	/* it is possible we don't have the exp time or flags */
	if (coargs->flags & COF_BYIDH) {
		if (!(coargs->flags & COF_FREE)) {
			/* we have to fetch the expire time ourselves. */
			if (mdb_vread(&coargs->exp, sizeof (hrtime_t),
			    (uintptr_t)co->c_list + offsetof(callout_list_t,
			    cl_expiration)) == -1) {
				mdb_warn("failed to read expiration "
				    "time from %p", co->c_list);
				coargs->exp = 0;
			}
			/* and flags. */
			if (mdb_vread(&coargs->list_flags, sizeof (int),
			    (uintptr_t)co->c_list + offsetof(callout_list_t,
			    cl_flags)) == -1) {
				mdb_warn("failed to read list flags"
				    "from %p", co->c_list);
				coargs->list_flags = 0;
			}
		} else {
			/* free callouts can't use list pointer. */
			coargs->exp = 0;
			coargs->list_flags = 0;
		}
		if (coargs->exp != 0) {
			if ((coargs->flags & COF_TIME) &&
			    (coargs->exp != coargs->time)) {
				return (WALK_NEXT);
			}
			if ((coargs->flags & COF_BEFORE) &&
			    (coargs->exp > coargs->btime)) {
				return (WALK_NEXT);
			}
			if ((coargs->flags & COF_AFTER) &&
			    (coargs->exp < coargs->atime)) {
				return (WALK_NEXT);
			}
		}
		/* tricky part, since both HIRES and ABS can be set */
		list_flags = coargs->list_flags;
		if ((coargs->flags & COF_HIRES) && (coargs->flags & COF_ABS)) {
			/* both flags are set, only skip "regular" ones */
			if (! (list_flags & COF_LIST_FLAGS)) {
				return (WALK_NEXT);
			}
		} else {
			/* individual flags, or no flags */
			if ((coargs->flags & COF_HIRES) &&
			    !(list_flags & CALLOUT_LIST_FLAG_HRESTIME)) {
				return (WALK_NEXT);
			}
			if ((coargs->flags & COF_ABS) &&
			    !(list_flags & CALLOUT_LIST_FLAG_ABSOLUTE)) {
				return (WALK_NEXT);
			}
		}
		/*
		 * We do the checks for COF_HEAP and COF_QUEUE here only if we
		 * are traversing BYIDH. If the traversal is by callout list,
		 * we do this check in callout_list_cb() to be more
		 * efficient.
		 */
		if ((coargs->flags & COF_HEAP) &&
		    !(list_flags & CALLOUT_LIST_FLAG_HEAPED)) {
			return (WALK_NEXT);
		}

		if ((coargs->flags & COF_QUEUE) &&
		    !(list_flags & CALLOUT_LIST_FLAG_QUEUED)) {
			return (WALK_NEXT);
		}
	}

#define	callout_table_mask	((1 << coargs->ctbits) - 1)
	tableid = CALLOUT_ID_TO_TABLE(co->c_xid);
#undef	callout_table_mask
	coid = CO_PLAIN_ID(co->c_xid);

	if ((coargs->flags & COF_CHDR) && !(coargs->flags & COF_ADDR)) {
		/*
		 * We need to print the headers. If walking by id, then
		 * the list header isn't printed, so we must include
		 * that info here.
		 */
		if (!(coargs->flags & COF_VERBOSE)) {
			mdb_printf("%<u>%3s %-1s %-14s %</u>",
			    "SEQ", "T", "EXP");
		} else if (coargs->flags & COF_BYIDH) {
			mdb_printf("%<u>%-14s %</u>", "EXP");
		}
		mdb_printf("%<u>%-4s %-?s %-20s%</u>",
		    "XHAL", "XID", "FUNC(ARG)");
		if (coargs->flags & COF_LONGLIST) {
			mdb_printf("%<u> %-?s %-?s %-?s %-?s%</u>",
			    "PREVID", "NEXTID", "PREVL", "NEXTL");
			mdb_printf("%<u> %-?s %-4s %-?s%</u>",
			    "DONE", "UTOS", "THREAD");
		}
		mdb_printf("\n");
		coargs->flags &= ~COF_CHDR;
		coargs->flags |= (COF_THDR | COF_LHDR);
	}

	if (!(coargs->flags & COF_ADDR)) {
		if (!(coargs->flags & COF_VERBOSE)) {
			mdb_printf("%-3d %1s %-14llx ",
			    TABLE_TO_SEQID(tableid),
			    co_typenames[tableid & CALLOUT_TYPE_MASK],
			    (coargs->flags & COF_EXPREL) ?
			    coargs->exp - coargs->now : coargs->exp);
		} else if (coargs->flags & COF_BYIDH) {
			mdb_printf("%-14x ",
			    (coargs->flags & COF_EXPREL) ?
			    coargs->exp - coargs->now : coargs->exp);
		}
		list_flags = coargs->list_flags;
		mdb_printf("%1s%1s%1s%1s %-?llx %a(%p)",
		    (co->c_xid & CALLOUT_EXECUTING) ? "X" : " ",
		    (list_flags & CALLOUT_LIST_FLAG_HRESTIME) ? "H" : " ",
		    (list_flags & CALLOUT_LIST_FLAG_ABSOLUTE) ? "A" : " ",
		    (co->c_xid & CALLOUT_LONGTERM) ? "L" : " ",
		    (long long)coid, co->c_func, co->c_arg);
		if (coargs->flags & COF_LONGLIST) {
			mdb_printf(" %-?p %-?p %-?p %-?p",
			    co->c_idprev, co->c_idnext, co->c_clprev,
			    co->c_clnext);
			mdb_printf(" %-?p %-4d %-0?p",
			    co->c_done, co->c_waiting, co->c_executor);
		}
	} else {
		/* address only */
		mdb_printf("%-0p", addr);
	}
	mdb_printf("\n");
	return (WALK_NEXT);
}

/* this callback is for callout list handling. idhash is done by callout_t_cb */
/*ARGSUSED*/
static int
callout_list_cb(uintptr_t addr, const void *data, void *priv)
{
	callout_data_t *coargs = (callout_data_t *)priv;
	callout_list_t *cl = (callout_list_t *)data;
	callout_t *coptr;
	int list_flags;

	if ((coargs == NULL) || (cl == NULL)) {
		return (WALK_ERR);
	}

	coargs->exp = cl->cl_expiration;
	coargs->list_flags = cl->cl_flags;
	if ((coargs->flags & COF_FREE) &&
	    !(cl->cl_flags & CALLOUT_LIST_FLAG_FREE)) {
		/*
		 * The callout list must have been reallocated. No point in
		 * walking any more.
		 */
		return (WALK_DONE);
	}
	if (!(coargs->flags & COF_FREE) &&
	    (cl->cl_flags & CALLOUT_LIST_FLAG_FREE)) {
		/*
		 * The callout list must have been freed. No point in
		 * walking any more.
		 */
		return (WALK_DONE);
	}
	if ((coargs->flags & COF_TIME) &&
	    (cl->cl_expiration != coargs->time)) {
		return (WALK_NEXT);
	}
	if ((coargs->flags & COF_BEFORE) &&
	    (cl->cl_expiration > coargs->btime)) {
		return (WALK_NEXT);
	}
	if ((coargs->flags & COF_AFTER) &&
	    (cl->cl_expiration < coargs->atime)) {
		return (WALK_NEXT);
	}
	if (!(coargs->flags & COF_EMPTY) &&
	    (cl->cl_callouts.ch_head == NULL)) {
		return (WALK_NEXT);
	}
	/* FOUR cases, each different, !A!B, !AB, A!B, AB */
	if ((coargs->flags & COF_HIRES) && (coargs->flags & COF_ABS)) {
		/* both flags are set, only skip "regular" ones */
		if (! (cl->cl_flags & COF_LIST_FLAGS)) {
			return (WALK_NEXT);
		}
	} else {
		if ((coargs->flags & COF_HIRES) &&
		    !(cl->cl_flags & CALLOUT_LIST_FLAG_HRESTIME)) {
			return (WALK_NEXT);
		}
		if ((coargs->flags & COF_ABS) &&
		    !(cl->cl_flags & CALLOUT_LIST_FLAG_ABSOLUTE)) {
			return (WALK_NEXT);
		}
	}

	if ((coargs->flags & COF_HEAP) &&
	    !(coargs->list_flags & CALLOUT_LIST_FLAG_HEAPED)) {
		return (WALK_NEXT);
	}

	if ((coargs->flags & COF_QUEUE) &&
	    !(coargs->list_flags & CALLOUT_LIST_FLAG_QUEUED)) {
		return (WALK_NEXT);
	}

	if ((coargs->flags & COF_LHDR) && !(coargs->flags & COF_ADDR) &&
	    (coargs->flags & (COF_LIST | COF_VERBOSE))) {
		if (!(coargs->flags & COF_VERBOSE)) {
			/* don't be redundant again */
			mdb_printf("%<u>SEQ T %</u>");
		}
		mdb_printf("%<u>EXP            HA BUCKET "
		    "CALLOUTS         %</u>");

		if (coargs->flags & COF_LONGLIST) {
			mdb_printf("%<u> %-?s %-?s%</u>",
			    "PREV", "NEXT");
		}
		mdb_printf("\n");
		coargs->flags &= ~COF_LHDR;
		coargs->flags |= (COF_THDR | COF_CHDR);
	}
	if (coargs->flags & (COF_LIST | COF_VERBOSE)) {
		if (!(coargs->flags & COF_ADDR)) {
			if (!(coargs->flags & COF_VERBOSE)) {
				mdb_printf("%3d %1s ",
				    TABLE_TO_SEQID(coargs->ndx),
				    co_typenames[coargs->ndx &
				    CALLOUT_TYPE_MASK]);
			}

			list_flags = coargs->list_flags;
			mdb_printf("%-14llx %1s%1s %-6d %-0?p ",
			    (coargs->flags & COF_EXPREL) ?
			    coargs->exp - coargs->now : coargs->exp,
			    (list_flags & CALLOUT_LIST_FLAG_HRESTIME) ?
			    "H" : " ",
			    (list_flags & CALLOUT_LIST_FLAG_ABSOLUTE) ?
			    "A" : " ",
			    coargs->bucket, cl->cl_callouts.ch_head);

			if (coargs->flags & COF_LONGLIST) {
				mdb_printf(" %-?p %-?p",
				    cl->cl_prev, cl->cl_next);
			}
		} else {
			/* address only */
			mdb_printf("%-0p", addr);
		}
		mdb_printf("\n");
		if (coargs->flags & COF_LIST) {
			return (WALK_NEXT);
		}
	}
	/* yet another layer as we walk the actual callouts via list. */
	if (cl->cl_callouts.ch_head == NULL) {
		return (WALK_NEXT);
	}
	/* free list structures do not have valid callouts off of them. */
	if (coargs->flags & COF_FREE) {
		return (WALK_NEXT);
	}
	coptr = (callout_t *)cl->cl_callouts.ch_head;

	if (coargs->flags & COF_VERBOSE) {
		mdb_inc_indent(4);
	}
	/*
	 * walk callouts using yet another callback routine.
	 * we use callouts_bytime because id hash is handled via
	 * the callout_t_cb callback.
	 */
	if (mdb_pwalk("callouts_bytime", callouts_cb, coargs,
	    (uintptr_t)coptr) == -1) {
		mdb_warn("cannot walk callouts at %p", coptr);
		return (WALK_ERR);
	}
	if (coargs->flags & COF_VERBOSE) {
		mdb_dec_indent(4);
	}

	return (WALK_NEXT);
}

/* this callback handles the details of callout table walking. */
static int
callout_t_cb(uintptr_t addr, const void *data, void *priv)
{
	callout_data_t *coargs = (callout_data_t *)priv;
	cot_data_t *cotwd = (cot_data_t *)data;
	callout_table_t *ct = &(cotwd->ct);
	int index, seqid, cotype;
	int i;
	callout_list_t *clptr;
	callout_t *coptr;

	if ((coargs == NULL) || (ct == NULL) || (coargs->co_table == NULL)) {
		return (WALK_ERR);
	}

	index =  ((char *)addr - (char *)coargs->co_table) /
	    sizeof (callout_table_t);
	cotype = index & CALLOUT_TYPE_MASK;
	seqid = TABLE_TO_SEQID(index);

	if ((coargs->flags & COF_SEQID) && (coargs->seqid != seqid)) {
		return (WALK_NEXT);
	}

	if (!(coargs->flags & COF_REAL) && (cotype == CALLOUT_REALTIME)) {
		return (WALK_NEXT);
	}

	if (!(coargs->flags & COF_NORM) && (cotype == CALLOUT_NORMAL)) {
		return (WALK_NEXT);
	}

	if (!(coargs->flags & COF_EMPTY) && (
	    (ct->ct_heap == NULL) || (ct->ct_cyclic == NULL))) {
		return (WALK_NEXT);
	}

	if ((coargs->flags & COF_THDR) && !(coargs->flags & COF_ADDR) &&
	    (coargs->flags & (COF_TABLE | COF_VERBOSE))) {
		/* print table hdr */
		mdb_printf("%<u>%-3s %-1s %-?s %-?s %-?s %-?s%</u>",
		    "SEQ", "T", "FREE", "LFREE", "CYCLIC", "HEAP");
		coargs->flags &= ~COF_THDR;
		coargs->flags |= (COF_LHDR | COF_CHDR);
		if (coargs->flags & COF_LONGLIST) {
			/* more info! */
			mdb_printf("%<u> %-T%-7s %-7s %-?s %-?s %-?s"
			    " %-?s %-?s %-?s%</u>",
			    "HEAPNUM", "HEAPMAX", "TASKQ", "EXPQ", "QUE",
			    "PEND", "FREE", "LOCK");
		}
		mdb_printf("\n");
	}
	if (coargs->flags & (COF_TABLE | COF_VERBOSE)) {
		if (!(coargs->flags & COF_ADDR)) {
			mdb_printf("%-3d %-1s %-0?p %-0?p %-0?p %-?p",
			    seqid, co_typenames[cotype],
			    ct->ct_free, ct->ct_lfree, ct->ct_cyclic,
			    ct->ct_heap);
			if (coargs->flags & COF_LONGLIST)  {
				/* more info! */
				mdb_printf(" %-7d %-7d %-?p %-?p %-?p"
				    " %-?lld %-?lld %-?p",
				    ct->ct_heap_num,  ct->ct_heap_max,
				    ct->ct_taskq, ct->ct_expired.ch_head,
				    ct->ct_queue.ch_head,
				    cotwd->ct_timeouts_pending,
				    cotwd->ct_allocations -
				    cotwd->ct_timeouts_pending,
				    ct->ct_mutex);
			}
		} else {
			/* address only */
			mdb_printf("%-0?p", addr);
		}
		mdb_printf("\n");
		if (coargs->flags & COF_TABLE) {
			return (WALK_NEXT);
		}
	}

	coargs->ndx = index;
	if (coargs->flags & COF_VERBOSE) {
		mdb_inc_indent(4);
	}
	/* keep digging. */
	if (!(coargs->flags & COF_BYIDH)) {
		/* walk the list hash table */
		if (coargs->flags & COF_FREE) {
			clptr = ct->ct_lfree;
			coargs->bucket = 0;
			if (clptr == NULL) {
				return (WALK_NEXT);
			}
			if (mdb_pwalk("callout_list", callout_list_cb, coargs,
			    (uintptr_t)clptr) == -1) {
				mdb_warn("cannot walk callout free list at %p",
				    clptr);
				return (WALK_ERR);
			}
		} else {
			/* first print the expired list. */
			clptr = (callout_list_t *)ct->ct_expired.ch_head;
			if (clptr != NULL) {
				coargs->bucket = -1;
				if (mdb_pwalk("callout_list", callout_list_cb,
				    coargs, (uintptr_t)clptr) == -1) {
					mdb_warn("cannot walk callout_list"
					    " at %p", clptr);
					return (WALK_ERR);
				}
			}
			/* then, print the callout queue */
			clptr = (callout_list_t *)ct->ct_queue.ch_head;
			if (clptr != NULL) {
				coargs->bucket = -1;
				if (mdb_pwalk("callout_list", callout_list_cb,
				    coargs, (uintptr_t)clptr) == -1) {
					mdb_warn("cannot walk callout_list"
					    " at %p", clptr);
					return (WALK_ERR);
				}
			}
			for (i = 0; i < CALLOUT_BUCKETS; i++) {
				if (ct->ct_clhash == NULL) {
					/* nothing to do */
					break;
				}
				if (cotwd->cot_clhash[i].ch_head == NULL) {
					continue;
				}
				clptr = (callout_list_t *)
				    cotwd->cot_clhash[i].ch_head;
				coargs->bucket = i;
				/* walk list with callback routine. */
				if (mdb_pwalk("callout_list", callout_list_cb,
				    coargs, (uintptr_t)clptr) == -1) {
					mdb_warn("cannot walk callout_list"
					    " at %p", clptr);
					return (WALK_ERR);
				}
			}
		}
	} else {
		/* walk the id hash table. */
		if (coargs->flags & COF_FREE) {
			coptr = ct->ct_free;
			coargs->bucket = 0;
			if (coptr == NULL) {
				return (WALK_NEXT);
			}
			if (mdb_pwalk("callouts_byid", callouts_cb, coargs,
			    (uintptr_t)coptr) == -1) {
				mdb_warn("cannot walk callout id free list"
				    " at %p", coptr);
				return (WALK_ERR);
			}
		} else {
			for (i = 0; i < CALLOUT_BUCKETS; i++) {
				if (ct->ct_idhash == NULL) {
					break;
				}
				coptr = (callout_t *)
				    cotwd->cot_idhash[i].ch_head;
				if (coptr == NULL) {
					continue;
				}
				coargs->bucket = i;

				/*
				 * walk callouts directly by id. For id
				 * chain, the callout list is just a header,
				 * so there's no need to walk it.
				 */
				if (mdb_pwalk("callouts_byid", callouts_cb,
				    coargs, (uintptr_t)coptr) == -1) {
					mdb_warn("cannot walk callouts at %p",
					    coptr);
					return (WALK_ERR);
				}
			}
		}
	}
	if (coargs->flags & COF_VERBOSE) {
		mdb_dec_indent(4);
	}
	return (WALK_NEXT);
}

/*
 * initialize some common info for both callout dcmds.
 */
int
callout_common_init(callout_data_t *coargs)
{
	/* we need a couple of things */
	if (mdb_readvar(&(coargs->co_table), "callout_table") == -1) {
		mdb_warn("failed to read 'callout_table'");
		return (DCMD_ERR);
	}
	/* need to get now in nsecs. Approximate with hrtime vars */
	if (mdb_readsym(&(coargs->now), sizeof (hrtime_t), "hrtime_last") !=
	    sizeof (hrtime_t)) {
		if (mdb_readsym(&(coargs->now), sizeof (hrtime_t),
		    "hrtime_base") != sizeof (hrtime_t)) {
			mdb_warn("Could not determine current system time");
			return (DCMD_ERR);
		}
	}

	if (mdb_readvar(&(coargs->ctbits), "callout_table_bits") == -1) {
		mdb_warn("failed to read 'callout_table_bits'");
		return (DCMD_ERR);
	}
	if (mdb_readvar(&(coargs->nsec_per_tick), "nsec_per_tick") == -1) {
		mdb_warn("failed to read 'nsec_per_tick'");
		return (DCMD_ERR);
	}
	return (DCMD_OK);
}

/*
 * dcmd to print callouts.  Optional addr limits to specific table.
 * Parses lots of options that get passed to callbacks for walkers.
 * Has it's own help function.
 */
/*ARGSUSED*/
int
callout(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	callout_data_t coargs;
	/* getopts doesn't help much with stuff like this */
	boolean_t Sflag, Cflag, tflag, aflag, bflag, dflag, kflag;
	char *funcname = NULL;
	char *paramstr = NULL;
	uintptr_t Stmp, Ctmp;	/* for getopt. */
	int retval;

	coargs.flags = COF_DEFAULT;
	Sflag = Cflag = tflag = bflag = aflag = dflag = kflag = FALSE;
	coargs.seqid = -1;

	if (mdb_getopts(argc, argv,
	    'r', MDB_OPT_CLRBITS, COF_NORM, &coargs.flags,
	    'n', MDB_OPT_CLRBITS, COF_REAL, &coargs.flags,
	    'l', MDB_OPT_CLRBITS, COF_SHORT, &coargs.flags,
	    's', MDB_OPT_CLRBITS, COF_LONG, &coargs.flags,
	    'x', MDB_OPT_SETBITS, COF_EXEC, &coargs.flags,
	    'h', MDB_OPT_SETBITS, COF_HIRES, &coargs.flags,
	    'B', MDB_OPT_SETBITS, COF_ABS, &coargs.flags,
	    'E', MDB_OPT_SETBITS, COF_EMPTY, &coargs.flags,
	    'd', MDB_OPT_SETBITS, 1, &dflag,
	    'C', MDB_OPT_UINTPTR_SET, &Cflag, &Ctmp,
	    'S', MDB_OPT_UINTPTR_SET, &Sflag, &Stmp,
	    't', MDB_OPT_UINTPTR_SET, &tflag, (uintptr_t *)&coargs.time,
	    'a', MDB_OPT_UINTPTR_SET, &aflag, (uintptr_t *)&coargs.atime,
	    'b', MDB_OPT_UINTPTR_SET, &bflag, (uintptr_t *)&coargs.btime,
	    'k', MDB_OPT_SETBITS, 1, &kflag,
	    'f', MDB_OPT_STR, &funcname,
	    'p', MDB_OPT_STR, &paramstr,
	    'T', MDB_OPT_SETBITS, COF_TABLE, &coargs.flags,
	    'D', MDB_OPT_SETBITS, COF_EXPREL, &coargs.flags,
	    'L', MDB_OPT_SETBITS, COF_LIST, &coargs.flags,
	    'V', MDB_OPT_SETBITS, COF_VERBOSE, &coargs.flags,
	    'v', MDB_OPT_SETBITS, COF_LONGLIST, &coargs.flags,
	    'i', MDB_OPT_SETBITS, COF_BYIDH, &coargs.flags,
	    'F', MDB_OPT_SETBITS, COF_FREE, &coargs.flags,
	    'H', MDB_OPT_SETBITS, COF_HEAP, &coargs.flags,
	    'Q', MDB_OPT_SETBITS, COF_QUEUE, &coargs.flags,
	    'A', MDB_OPT_SETBITS, COF_ADDR, &coargs.flags,
	    NULL) != argc) {
		return (DCMD_USAGE);
	}

	/* initialize from kernel variables */
	if ((retval = callout_common_init(&coargs)) != DCMD_OK) {
		return (retval);
	}

	/* do some option post-processing */
	if (kflag) {
		coargs.time *= coargs.nsec_per_tick;
		coargs.atime *= coargs.nsec_per_tick;
		coargs.btime *= coargs.nsec_per_tick;
	}

	if (dflag) {
		coargs.time += coargs.now;
		coargs.atime += coargs.now;
		coargs.btime += coargs.now;
	}
	if (Sflag) {
		if (flags & DCMD_ADDRSPEC) {
			mdb_printf("-S option conflicts with explicit"
			    " address\n");
			return (DCMD_USAGE);
		}
		coargs.flags |= COF_SEQID;
		coargs.seqid = (int)Stmp;
	}
	if (Cflag) {
		if (flags & DCMD_ADDRSPEC) {
			mdb_printf("-C option conflicts with explicit"
			    " address\n");
			return (DCMD_USAGE);
		}
		if (coargs.flags & COF_SEQID) {
			mdb_printf("-C and -S are mutually exclusive\n");
			return (DCMD_USAGE);
		}
		coargs.cpu = (cpu_t *)Ctmp;
		if (mdb_vread(&coargs.seqid, sizeof (processorid_t),
		    (uintptr_t)&(coargs.cpu->cpu_seqid)) == -1) {
			mdb_warn("failed to read cpu_t at %p", Ctmp);
			return (DCMD_ERR);
		}
		coargs.flags |= COF_SEQID;
	}
	/* avoid null outputs. */
	if (!(coargs.flags & (COF_REAL | COF_NORM))) {
		coargs.flags |= COF_REAL | COF_NORM;
	}
	if (!(coargs.flags & (COF_LONG | COF_SHORT))) {
		coargs.flags |= COF_LONG | COF_SHORT;
	}
	if (tflag) {
		if (aflag || bflag) {
			mdb_printf("-t and -a|b are mutually exclusive\n");
			return (DCMD_USAGE);
		}
		coargs.flags |= COF_TIME;
	}
	if (aflag) {
		coargs.flags |= COF_AFTER;
	}
	if (bflag) {
		coargs.flags |= COF_BEFORE;
	}
	if ((aflag && bflag) && (coargs.btime <= coargs.atime)) {
		mdb_printf("value for -a must be earlier than the value"
		    " for -b.\n");
		return (DCMD_USAGE);
	}

	if ((coargs.flags & COF_HEAP) && (coargs.flags & COF_QUEUE)) {
		mdb_printf("-H and -Q are mutually exclusive\n");
		return (DCMD_USAGE);
	}

	if (funcname != NULL) {
		GElf_Sym sym;

		if (mdb_lookup_by_name(funcname, &sym) != 0) {
			coargs.funcaddr = mdb_strtoull(funcname);
		} else {
			coargs.funcaddr = sym.st_value;
		}
		coargs.flags |= COF_FUNC;
	}

	if (paramstr != NULL) {
		GElf_Sym sym;

		if (mdb_lookup_by_name(paramstr, &sym) != 0) {
			coargs.param = mdb_strtoull(paramstr);
		} else {
			coargs.param = sym.st_value;
		}
		coargs.flags |= COF_PARAM;
	}

	if (!(flags & DCMD_ADDRSPEC)) {
		/* don't pass "dot" if no addr. */
		addr = NULL;
	}
	if (addr != NULL) {
		/*
		 * a callout table was specified. Ignore -r|n option
		 * to avoid null output.
		 */
		coargs.flags |= (COF_REAL | COF_NORM);
	}

	if (DCMD_HDRSPEC(flags) || (coargs.flags & COF_VERBOSE)) {
		coargs.flags |= COF_THDR | COF_LHDR | COF_CHDR;
	}
	if (coargs.flags & COF_FREE) {
		coargs.flags |= COF_EMPTY;
		/* -F = free callouts, -FL = free lists */
		if (!(coargs.flags & COF_LIST)) {
			coargs.flags |= COF_BYIDH;
		}
	}

	/* walk table, using specialized callback routine. */
	if (mdb_pwalk("callout_table", callout_t_cb, &coargs, addr) == -1) {
		mdb_warn("cannot walk callout_table");
		return (DCMD_ERR);
	}
	return (DCMD_OK);
}


/*
 * Given an extended callout id, dump its information.
 */
/*ARGSUSED*/
int
calloutid(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	callout_data_t coargs;
	callout_table_t *ctptr;
	callout_table_t ct;
	callout_id_t coid;
	callout_t *coptr;
	int tableid;
	callout_id_t xid;
	ulong_t idhash;
	int i, retval;
	const mdb_arg_t *arg;
	size_t size;
	callout_hash_t cot_idhash[CALLOUT_BUCKETS];

	coargs.flags = COF_DEFAULT | COF_BYIDH;
	i = mdb_getopts(argc, argv,
	    'd', MDB_OPT_SETBITS, COF_DECODE, &coargs.flags,
	    'v', MDB_OPT_SETBITS, COF_LONGLIST, &coargs.flags,
	    NULL);
	argc -= i;
	argv += i;

	if (argc != 1) {
		return (DCMD_USAGE);
	}
	arg = &argv[0];

	if (arg->a_type == MDB_TYPE_IMMEDIATE) {
		xid = arg->a_un.a_val;
	} else {
		xid = (callout_id_t)mdb_strtoull(arg->a_un.a_str);
	}

	if (DCMD_HDRSPEC(flags)) {
		coargs.flags |= COF_CHDR;
	}


	/* initialize from kernel variables */
	if ((retval = callout_common_init(&coargs)) != DCMD_OK) {
		return (retval);
	}

	/* we must massage the environment so that the macros will play nice */
#define	callout_table_mask	((1 << coargs.ctbits) - 1)
#define	callout_table_bits	coargs.ctbits
#define	nsec_per_tick		coargs.nsec_per_tick
	tableid = CALLOUT_ID_TO_TABLE(xid);
	idhash = CALLOUT_IDHASH(xid);
#undef	callouts_table_bits
#undef	callout_table_mask
#undef	nsec_per_tick
	coid = CO_PLAIN_ID(xid);

	if (flags & DCMD_ADDRSPEC) {
		mdb_printf("calloutid does not accept explicit address.\n");
		return (DCMD_USAGE);
	}

	if (coargs.flags & COF_DECODE) {
		if (DCMD_HDRSPEC(flags)) {
			mdb_printf("%<u>%3s %1s %2s %-?s %-6s %</u>\n",
			    "SEQ", "T", "XL", "XID", "IDHASH");
		}
		mdb_printf("%-3d %1s %1s%1s %-?llx %-6d\n",
		    TABLE_TO_SEQID(tableid),
		    co_typenames[tableid & CALLOUT_TYPE_MASK],
		    (xid & CALLOUT_EXECUTING) ? "X" : " ",
		    (xid & CALLOUT_LONGTERM) ? "L" : " ",
		    (long long)coid, idhash);
		return (DCMD_OK);
	}

	/* get our table. Note this relies on the types being correct */
	ctptr = coargs.co_table + tableid;
	if (mdb_vread(&ct, sizeof (callout_table_t), (uintptr_t)ctptr) == -1) {
		mdb_warn("failed to read callout_table at %p", ctptr);
		return (DCMD_ERR);
	}
	size = sizeof (callout_hash_t) * CALLOUT_BUCKETS;
	if (ct.ct_idhash != NULL) {
		if (mdb_vread(&(cot_idhash), size,
		    (uintptr_t)ct.ct_idhash) == -1) {
			mdb_warn("failed to read id_hash at %p",
			    ct.ct_idhash);
			return (WALK_ERR);
		}
	}

	/* callout at beginning of hash chain */
	if (ct.ct_idhash == NULL) {
		mdb_printf("id hash chain for this xid is empty\n");
		return (DCMD_ERR);
	}
	coptr = (callout_t *)cot_idhash[idhash].ch_head;
	if (coptr == NULL) {
		mdb_printf("id hash chain for this xid is empty\n");
		return (DCMD_ERR);
	}

	coargs.ndx = tableid;
	coargs.bucket = idhash;

	/* use the walker, luke */
	if (mdb_pwalk("callouts_byid", callouts_cb, &coargs,
	    (uintptr_t)coptr) == -1) {
		mdb_warn("cannot walk callouts at %p", coptr);
		return (WALK_ERR);
	}

	return (DCMD_OK);
}

void
callout_help(void)
{
	mdb_printf("callout: display callouts.\n"
	    "Given a callout table address, display callouts from table.\n"
	    "Without an address, display callouts from all tables.\n"
	    "options:\n"
	    " -r|n : limit display to (r)ealtime or (n)ormal type callouts\n"
	    " -s|l : limit display to (s)hort-term ids or (l)ong-term ids\n"
	    " -x : limit display to callouts which are executing\n"
	    " -h : limit display to callouts based on hrestime\n"
	    " -B : limit display to callouts based on absolute time\n"
	    " -t|a|b nsec: limit display to callouts that expire a(t) time,"
	    " (a)fter time,\n     or (b)efore time. Use -a and -b together "
	    " to specify a range.\n     For \"now\", use -d[t|a|b] 0.\n"
	    " -d : interpret time option to -t|a|b as delta from current time\n"
	    " -k : use ticks instead of nanoseconds as arguments to"
	    " -t|a|b. Note that\n     ticks are less accurate and may not"
	    " match other tick times (ie: lbolt).\n"
	    " -D : display exiration time as delta from current time\n"
	    " -S seqid : limit display to callouts for this cpu sequence id\n"
	    " -C addr :  limit display to callouts for this cpu pointer\n"
	    " -f name|addr : limit display to callouts with this function\n"
	    " -p name|addr : limit display to callouts functions with this"
	    " parameter\n"
	    " -T : display the callout table itself, instead of callouts\n"
	    " -L : display callout lists instead of callouts\n"
	    " -E : with -T or L, display empty data structures.\n"
	    " -i : traverse callouts by id hash instead of list hash\n"
	    " -F : walk free callout list (free list with -i) instead\n"
	    " -v : display more info for each item\n"
	    " -V : show details of each level of info as it is traversed\n"
	    " -H : limit display to callouts in the callout heap\n"
	    " -Q : limit display to callouts in the callout queue\n"
	    " -A : show only addresses. Useful for pipelines.\n");
}

void
calloutid_help(void)
{
	mdb_printf("calloutid: display callout by id.\n"
	    "Given an extended callout id, display the callout infomation.\n"
	    "options:\n"
	    " -d : do not dereference callout, just decode the id.\n"
	    " -v : verbose display more info about the callout\n");
}

/*ARGSUSED*/
int
class(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	long num_classes, i;
	sclass_t *class_tbl;
	GElf_Sym g_sclass;
	char class_name[PC_CLNMSZ];
	size_t tbl_size;

	if (mdb_lookup_by_name("sclass", &g_sclass) == -1) {
		mdb_warn("failed to find symbol sclass\n");
		return (DCMD_ERR);
	}

	tbl_size = (size_t)g_sclass.st_size;
	num_classes = tbl_size / (sizeof (sclass_t));
	class_tbl = mdb_alloc(tbl_size, UM_SLEEP | UM_GC);

	if (mdb_readsym(class_tbl, tbl_size, "sclass") == -1) {
		mdb_warn("failed to read sclass");
		return (DCMD_ERR);
	}

	mdb_printf("%<u>%4s %-10s %-24s %-24s%</u>\n", "SLOT", "NAME",
	    "INIT FCN", "CLASS FCN");

	for (i = 0; i < num_classes; i++) {
		if (mdb_vread(class_name, sizeof (class_name),
		    (uintptr_t)class_tbl[i].cl_name) == -1)
			(void) strcpy(class_name, "???");

		mdb_printf("%4ld %-10s %-24a %-24a\n", i, class_name,
		    class_tbl[i].cl_init, class_tbl[i].cl_funcs);
	}

	return (DCMD_OK);
}

#define	FSNAMELEN	32	/* Max len of FS name we read from vnodeops */

int
vnode2path(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uintptr_t rootdir;
	vnode_t vn;
	char buf[MAXPATHLEN];

	uint_t opt_F = FALSE;

	if (mdb_getopts(argc, argv,
	    'F', MDB_OPT_SETBITS, TRUE, &opt_F, NULL) != argc)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_warn("expected explicit vnode_t address before ::\n");
		return (DCMD_USAGE);
	}

	if (mdb_readvar(&rootdir, "rootdir") == -1) {
		mdb_warn("failed to read rootdir");
		return (DCMD_ERR);
	}

	if (mdb_vnode2path(addr, buf, sizeof (buf)) == -1)
		return (DCMD_ERR);

	if (*buf == '\0') {
		mdb_printf("??\n");
		return (DCMD_OK);
	}

	mdb_printf("%s", buf);
	if (opt_F && buf[strlen(buf)-1] != '/' &&
	    mdb_vread(&vn, sizeof (vn), addr) == sizeof (vn))
		mdb_printf("%c", mdb_vtype2chr(vn.v_type, 0));
	mdb_printf("\n");

	return (DCMD_OK);
}

int
ld_walk_init(mdb_walk_state_t *wsp)
{
	wsp->walk_data = (void *)wsp->walk_addr;
	return (WALK_NEXT);
}

int
ld_walk_step(mdb_walk_state_t *wsp)
{
	int status;
	lock_descriptor_t ld;

	if (mdb_vread(&ld, sizeof (lock_descriptor_t), wsp->walk_addr) == -1) {
		mdb_warn("couldn't read lock_descriptor_t at %p\n",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, &ld, wsp->walk_cbdata);
	if (status == WALK_ERR)
		return (WALK_ERR);

	wsp->walk_addr = (uintptr_t)ld.l_next;
	if (wsp->walk_addr == (uintptr_t)wsp->walk_data)
		return (WALK_DONE);

	return (status);
}

int
lg_walk_init(mdb_walk_state_t *wsp)
{
	GElf_Sym sym;

	if (mdb_lookup_by_name("lock_graph", &sym) == -1) {
		mdb_warn("failed to find symbol 'lock_graph'\n");
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)sym.st_value;
	wsp->walk_data = (void *)(uintptr_t)(sym.st_value + sym.st_size);

	return (WALK_NEXT);
}

typedef struct lg_walk_data {
	uintptr_t startaddr;
	mdb_walk_cb_t callback;
	void *data;
} lg_walk_data_t;

/*
 * We can't use ::walk lock_descriptor directly, because the head of each graph
 * is really a dummy lock.  Rather than trying to dynamically determine if this
 * is a dummy node or not, we just filter out the initial element of the
 * list.
 */
static int
lg_walk_cb(uintptr_t addr, const void *data, void *priv)
{
	lg_walk_data_t *lw = priv;

	if (addr != lw->startaddr)
		return (lw->callback(addr, data, lw->data));

	return (WALK_NEXT);
}

int
lg_walk_step(mdb_walk_state_t *wsp)
{
	graph_t *graph;
	lg_walk_data_t lw;

	if (wsp->walk_addr >= (uintptr_t)wsp->walk_data)
		return (WALK_DONE);

	if (mdb_vread(&graph, sizeof (graph), wsp->walk_addr) == -1) {
		mdb_warn("failed to read graph_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	wsp->walk_addr += sizeof (graph);

	if (graph == NULL)
		return (WALK_NEXT);

	lw.callback = wsp->walk_callback;
	lw.data = wsp->walk_cbdata;

	lw.startaddr = (uintptr_t)&(graph->active_locks);
	if (mdb_pwalk("lock_descriptor", lg_walk_cb, &lw, lw.startaddr)) {
		mdb_warn("couldn't walk lock_descriptor at %p\n", lw.startaddr);
		return (WALK_ERR);
	}

	lw.startaddr = (uintptr_t)&(graph->sleeping_locks);
	if (mdb_pwalk("lock_descriptor", lg_walk_cb, &lw, lw.startaddr)) {
		mdb_warn("couldn't walk lock_descriptor at %p\n", lw.startaddr);
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

/*
 * The space available for the path corresponding to the locked vnode depends
 * on whether we are printing 32- or 64-bit addresses.
 */
#ifdef _LP64
#define	LM_VNPATHLEN	20
#else
#define	LM_VNPATHLEN	30
#endif

/*ARGSUSED*/
static int
lminfo_cb(uintptr_t addr, const void *data, void *priv)
{
	const lock_descriptor_t *ld = data;
	char buf[LM_VNPATHLEN];
	proc_t p;

	mdb_printf("%-?p %2s %04x %6d %-16s %-?p ",
	    addr, ld->l_type == F_RDLCK ? "RD" :
	    ld->l_type == F_WRLCK ? "WR" : "??",
	    ld->l_state, ld->l_flock.l_pid,
	    ld->l_flock.l_pid == 0 ? "<kernel>" :
	    mdb_pid2proc(ld->l_flock.l_pid, &p) == NULL ?
	    "<defunct>" : p.p_user.u_comm,
	    ld->l_vnode);

	mdb_vnode2path((uintptr_t)ld->l_vnode, buf,
	    sizeof (buf));
	mdb_printf("%s\n", buf);

	return (WALK_NEXT);
}

/*ARGSUSED*/
int
lminfo(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (DCMD_HDRSPEC(flags))
		mdb_printf("%<u>%-?s %2s %4s %6s %-16s %-?s %s%</u>\n",
		    "ADDR", "TP", "FLAG", "PID", "COMM", "VNODE", "PATH");

	return (mdb_pwalk("lock_graph", lminfo_cb, NULL, NULL));
}

/*ARGSUSED*/
int
whereopen_fwalk(uintptr_t addr, struct file *f, uintptr_t *target)
{
	if ((uintptr_t)f->f_vnode == *target) {
		mdb_printf("file %p\n", addr);
		*target = NULL;
	}

	return (WALK_NEXT);
}

/*ARGSUSED*/
int
whereopen_pwalk(uintptr_t addr, void *ignored, uintptr_t *target)
{
	uintptr_t t = *target;

	if (mdb_pwalk("file", (mdb_walk_cb_t)whereopen_fwalk, &t, addr) == -1) {
		mdb_warn("couldn't file walk proc %p", addr);
		return (WALK_ERR);
	}

	if (t == NULL)
		mdb_printf("%p\n", addr);

	return (WALK_NEXT);
}

/*ARGSUSED*/
int
whereopen(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uintptr_t target = addr;

	if (!(flags & DCMD_ADDRSPEC) || addr == NULL)
		return (DCMD_USAGE);

	if (mdb_walk("proc", (mdb_walk_cb_t)whereopen_pwalk, &target) == -1) {
		mdb_warn("can't proc walk");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

typedef struct datafmt {
	char	*hdr1;
	char	*hdr2;
	char	*dashes;
	char	*fmt;
} datafmt_t;

static datafmt_t kmemfmt[] = {
	{ "cache                    ", "name                     ",
	"-------------------------", "%-25s "				},
	{ "   buf",	"  size",	"------",	"%6u "		},
	{ "   buf",	"in use",	"------",	"%6u "		},
	{ "   buf",	" total",	"------",	"%6u "		},
	{ "   memory",	"   in use",	"----------",	"%10lu%c "	},
	{ "    alloc",	"  succeed",	"---------",	"%9u "		},
	{ "alloc",	" fail",	"-----",	"%5u "		},
	{ NULL,		NULL,		NULL,		NULL		}
};

static datafmt_t vmemfmt[] = {
	{ "vmem                     ", "name                     ",
	"-------------------------", "%-*s "				},
	{ "   memory",	"   in use",	"----------",	"%9llu%c "	},
	{ "    memory",	"     total",	"-----------",	"%10llu%c "	},
	{ "   memory",	"   import",	"----------",	"%9llu%c "	},
	{ "    alloc",	"  succeed",	"---------",	"%9llu "	},
	{ "alloc",	" fail",	"-----",	"%5llu "	},
	{ NULL,		NULL,		NULL,		NULL		}
};

/*ARGSUSED*/
static int
kmastat_cpu_avail(uintptr_t addr, const kmem_cpu_cache_t *ccp, int *avail)
{
	short rounds, prounds;

	if (KMEM_DUMPCC(ccp)) {
		rounds = ccp->cc_dump_rounds;
		prounds = ccp->cc_dump_prounds;
	} else {
		rounds = ccp->cc_rounds;
		prounds = ccp->cc_prounds;
	}
	if (rounds > 0)
		*avail += rounds;
	if (prounds > 0)
		*avail += prounds;

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
kmastat_cpu_alloc(uintptr_t addr, const kmem_cpu_cache_t *ccp, int *alloc)
{
	*alloc += ccp->cc_alloc;

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
kmastat_slab_avail(uintptr_t addr, const kmem_slab_t *sp, int *avail)
{
	*avail += sp->slab_chunks - sp->slab_refcnt;

	return (WALK_NEXT);
}

typedef struct kmastat_vmem {
	uintptr_t kv_addr;
	struct kmastat_vmem *kv_next;
	size_t kv_meminuse;
	int kv_alloc;
	int kv_fail;
} kmastat_vmem_t;

typedef struct kmastat_args {
	kmastat_vmem_t **ka_kvpp;
	uint_t ka_shift;
} kmastat_args_t;

static int
kmastat_cache(uintptr_t addr, const kmem_cache_t *cp, kmastat_args_t *kap)
{
	kmastat_vmem_t **kvpp = kap->ka_kvpp;
	kmastat_vmem_t *kv;
	datafmt_t *dfp = kmemfmt;
	int magsize;

	int avail, alloc, total;
	size_t meminuse = (cp->cache_slab_create - cp->cache_slab_destroy) *
	    cp->cache_slabsize;

	mdb_walk_cb_t cpu_avail = (mdb_walk_cb_t)kmastat_cpu_avail;
	mdb_walk_cb_t cpu_alloc = (mdb_walk_cb_t)kmastat_cpu_alloc;
	mdb_walk_cb_t slab_avail = (mdb_walk_cb_t)kmastat_slab_avail;

	magsize = kmem_get_magsize(cp);

	alloc = cp->cache_slab_alloc + cp->cache_full.ml_alloc;
	avail = cp->cache_full.ml_total * magsize;
	total = cp->cache_buftotal;

	(void) mdb_pwalk("kmem_cpu_cache", cpu_alloc, &alloc, addr);
	(void) mdb_pwalk("kmem_cpu_cache", cpu_avail, &avail, addr);
	(void) mdb_pwalk("kmem_slab_partial", slab_avail, &avail, addr);

	for (kv = *kvpp; kv != NULL; kv = kv->kv_next) {
		if (kv->kv_addr == (uintptr_t)cp->cache_arena)
			goto out;
	}

	kv = mdb_zalloc(sizeof (kmastat_vmem_t), UM_SLEEP | UM_GC);
	kv->kv_next = *kvpp;
	kv->kv_addr = (uintptr_t)cp->cache_arena;
	*kvpp = kv;
out:
	kv->kv_meminuse += meminuse;
	kv->kv_alloc += alloc;
	kv->kv_fail += cp->cache_alloc_fail;

	mdb_printf((dfp++)->fmt, cp->cache_name);
	mdb_printf((dfp++)->fmt, cp->cache_bufsize);
	mdb_printf((dfp++)->fmt, total - avail);
	mdb_printf((dfp++)->fmt, total);
	mdb_printf((dfp++)->fmt, meminuse >> kap->ka_shift,
	    kap->ka_shift == GIGS ? 'G' : kap->ka_shift == MEGS ? 'M' :
	    kap->ka_shift == KILOS ? 'K' : 'B');
	mdb_printf((dfp++)->fmt, alloc);
	mdb_printf((dfp++)->fmt, cp->cache_alloc_fail);
	mdb_printf("\n");

	return (WALK_NEXT);
}

static int
kmastat_vmem_totals(uintptr_t addr, const vmem_t *v, kmastat_args_t *kap)
{
	kmastat_vmem_t *kv = *kap->ka_kvpp;
	size_t len;

	while (kv != NULL && kv->kv_addr != addr)
		kv = kv->kv_next;

	if (kv == NULL || kv->kv_alloc == 0)
		return (WALK_NEXT);

	len = MIN(17, strlen(v->vm_name));

	mdb_printf("Total [%s]%*s %6s %6s %6s %10lu%c %9u %5u\n", v->vm_name,
	    17 - len, "", "", "", "",
	    kv->kv_meminuse >> kap->ka_shift,
	    kap->ka_shift == GIGS ? 'G' : kap->ka_shift == MEGS ? 'M' :
	    kap->ka_shift == KILOS ? 'K' : 'B', kv->kv_alloc, kv->kv_fail);

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
kmastat_vmem(uintptr_t addr, const vmem_t *v, const uint_t *shiftp)
{
	datafmt_t *dfp = vmemfmt;
	const vmem_kstat_t *vkp = &v->vm_kstat;
	uintptr_t paddr;
	vmem_t parent;
	int ident = 0;

	for (paddr = (uintptr_t)v->vm_source; paddr != NULL; ident += 4) {
		if (mdb_vread(&parent, sizeof (parent), paddr) == -1) {
			mdb_warn("couldn't trace %p's ancestry", addr);
			ident = 0;
			break;
		}
		paddr = (uintptr_t)parent.vm_source;
	}

	mdb_printf("%*s", ident, "");
	mdb_printf((dfp++)->fmt, 25 - ident, v->vm_name);
	mdb_printf((dfp++)->fmt, vkp->vk_mem_inuse.value.ui64 >> *shiftp,
	    *shiftp == GIGS ? 'G' : *shiftp == MEGS ? 'M' :
	    *shiftp == KILOS ? 'K' : 'B');
	mdb_printf((dfp++)->fmt, vkp->vk_mem_total.value.ui64 >> *shiftp,
	    *shiftp == GIGS ? 'G' : *shiftp == MEGS ? 'M' :
	    *shiftp == KILOS ? 'K' : 'B');
	mdb_printf((dfp++)->fmt, vkp->vk_mem_import.value.ui64 >> *shiftp,
	    *shiftp == GIGS ? 'G' : *shiftp == MEGS ? 'M' :
	    *shiftp == KILOS ? 'K' : 'B');
	mdb_printf((dfp++)->fmt, vkp->vk_alloc.value.ui64);
	mdb_printf((dfp++)->fmt, vkp->vk_fail.value.ui64);

	mdb_printf("\n");

	return (WALK_NEXT);
}

/*ARGSUSED*/
int
kmastat(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	kmastat_vmem_t *kv = NULL;
	datafmt_t *dfp;
	kmastat_args_t ka;

	ka.ka_shift = 0;
	if (mdb_getopts(argc, argv,
	    'k', MDB_OPT_SETBITS, KILOS, &ka.ka_shift,
	    'm', MDB_OPT_SETBITS, MEGS, &ka.ka_shift,
	    'g', MDB_OPT_SETBITS, GIGS, &ka.ka_shift, NULL) != argc)
		return (DCMD_USAGE);

	for (dfp = kmemfmt; dfp->hdr1 != NULL; dfp++)
		mdb_printf("%s ", dfp->hdr1);
	mdb_printf("\n");

	for (dfp = kmemfmt; dfp->hdr1 != NULL; dfp++)
		mdb_printf("%s ", dfp->hdr2);
	mdb_printf("\n");

	for (dfp = kmemfmt; dfp->hdr1 != NULL; dfp++)
		mdb_printf("%s ", dfp->dashes);
	mdb_printf("\n");

	ka.ka_kvpp = &kv;
	if (mdb_walk("kmem_cache", (mdb_walk_cb_t)kmastat_cache, &ka) == -1) {
		mdb_warn("can't walk 'kmem_cache'");
		return (DCMD_ERR);
	}

	for (dfp = kmemfmt; dfp->hdr1 != NULL; dfp++)
		mdb_printf("%s ", dfp->dashes);
	mdb_printf("\n");

	if (mdb_walk("vmem", (mdb_walk_cb_t)kmastat_vmem_totals, &ka) == -1) {
		mdb_warn("can't walk 'vmem'");
		return (DCMD_ERR);
	}

	for (dfp = kmemfmt; dfp->hdr1 != NULL; dfp++)
		mdb_printf("%s ", dfp->dashes);
	mdb_printf("\n");

	mdb_printf("\n");

	for (dfp = vmemfmt; dfp->hdr1 != NULL; dfp++)
		mdb_printf("%s ", dfp->hdr1);
	mdb_printf("\n");

	for (dfp = vmemfmt; dfp->hdr1 != NULL; dfp++)
		mdb_printf("%s ", dfp->hdr2);
	mdb_printf("\n");

	for (dfp = vmemfmt; dfp->hdr1 != NULL; dfp++)
		mdb_printf("%s ", dfp->dashes);
	mdb_printf("\n");

	if (mdb_walk("vmem", (mdb_walk_cb_t)kmastat_vmem, &ka.ka_shift) == -1) {
		mdb_warn("can't walk 'vmem'");
		return (DCMD_ERR);
	}

	for (dfp = vmemfmt; dfp->hdr1 != NULL; dfp++)
		mdb_printf("%s ", dfp->dashes);
	mdb_printf("\n");
	return (DCMD_OK);
}

/*
 * Our ::kgrep callback scans the entire kernel VA space (kas).  kas is made
 * up of a set of 'struct seg's.  We could just scan each seg en masse, but
 * unfortunately, a few of the segs are both large and sparse, so we could
 * spend quite a bit of time scanning VAs which have no backing pages.
 *
 * So for the few very sparse segs, we skip the segment itself, and scan
 * the allocated vmem_segs in the vmem arena which manages that part of kas.
 * Currently, we do this for:
 *
 *	SEG		VMEM ARENA
 *	kvseg		heap_arena
 *	kvseg32		heap32_arena
 *	kvseg_core	heap_core_arena
 *
 * In addition, we skip the segkpm segment in its entirety, since it is very
 * sparse, and contains no new kernel data.
 */
typedef struct kgrep_walk_data {
	kgrep_cb_func *kg_cb;
	void *kg_cbdata;
	uintptr_t kg_kvseg;
	uintptr_t kg_kvseg32;
	uintptr_t kg_kvseg_core;
	uintptr_t kg_segkpm;
	uintptr_t kg_heap_lp_base;
	uintptr_t kg_heap_lp_end;
} kgrep_walk_data_t;

static int
kgrep_walk_seg(uintptr_t addr, const struct seg *seg, kgrep_walk_data_t *kg)
{
	uintptr_t base = (uintptr_t)seg->s_base;

	if (addr == kg->kg_kvseg || addr == kg->kg_kvseg32 ||
	    addr == kg->kg_kvseg_core)
		return (WALK_NEXT);

	if ((uintptr_t)seg->s_ops == kg->kg_segkpm)
		return (WALK_NEXT);

	return (kg->kg_cb(base, base + seg->s_size, kg->kg_cbdata));
}

/*ARGSUSED*/
static int
kgrep_walk_vseg(uintptr_t addr, const vmem_seg_t *seg, kgrep_walk_data_t *kg)
{
	/*
	 * skip large page heap address range - it is scanned by walking
	 * allocated vmem_segs in the heap_lp_arena
	 */
	if (seg->vs_start == kg->kg_heap_lp_base &&
	    seg->vs_end == kg->kg_heap_lp_end)
		return (WALK_NEXT);

	return (kg->kg_cb(seg->vs_start, seg->vs_end, kg->kg_cbdata));
}

/*ARGSUSED*/
static int
kgrep_xwalk_vseg(uintptr_t addr, const vmem_seg_t *seg, kgrep_walk_data_t *kg)
{
	return (kg->kg_cb(seg->vs_start, seg->vs_end, kg->kg_cbdata));
}

static int
kgrep_walk_vmem(uintptr_t addr, const vmem_t *vmem, kgrep_walk_data_t *kg)
{
	mdb_walk_cb_t walk_vseg = (mdb_walk_cb_t)kgrep_walk_vseg;

	if (strcmp(vmem->vm_name, "heap") != 0 &&
	    strcmp(vmem->vm_name, "heap32") != 0 &&
	    strcmp(vmem->vm_name, "heap_core") != 0 &&
	    strcmp(vmem->vm_name, "heap_lp") != 0)
		return (WALK_NEXT);

	if (strcmp(vmem->vm_name, "heap_lp") == 0)
		walk_vseg = (mdb_walk_cb_t)kgrep_xwalk_vseg;

	if (mdb_pwalk("vmem_alloc", walk_vseg, kg, addr) == -1) {
		mdb_warn("couldn't walk vmem_alloc for vmem %p", addr);
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

int
kgrep_subr(kgrep_cb_func *cb, void *cbdata)
{
	GElf_Sym kas, kvseg, kvseg32, kvseg_core, segkpm;
	kgrep_walk_data_t kg;

	if (mdb_get_state() == MDB_STATE_RUNNING) {
		mdb_warn("kgrep can only be run on a system "
		    "dump or under kmdb; see dumpadm(1M)\n");
		return (DCMD_ERR);
	}

	if (mdb_lookup_by_name("kas", &kas) == -1) {
		mdb_warn("failed to locate 'kas' symbol\n");
		return (DCMD_ERR);
	}

	if (mdb_lookup_by_name("kvseg", &kvseg) == -1) {
		mdb_warn("failed to locate 'kvseg' symbol\n");
		return (DCMD_ERR);
	}

	if (mdb_lookup_by_name("kvseg32", &kvseg32) == -1) {
		mdb_warn("failed to locate 'kvseg32' symbol\n");
		return (DCMD_ERR);
	}

	if (mdb_lookup_by_name("kvseg_core", &kvseg_core) == -1) {
		mdb_warn("failed to locate 'kvseg_core' symbol\n");
		return (DCMD_ERR);
	}

	if (mdb_lookup_by_name("segkpm_ops", &segkpm) == -1) {
		mdb_warn("failed to locate 'segkpm_ops' symbol\n");
		return (DCMD_ERR);
	}

	if (mdb_readvar(&kg.kg_heap_lp_base, "heap_lp_base") == -1) {
		mdb_warn("failed to read 'heap_lp_base'\n");
		return (DCMD_ERR);
	}

	if (mdb_readvar(&kg.kg_heap_lp_end, "heap_lp_end") == -1) {
		mdb_warn("failed to read 'heap_lp_end'\n");
		return (DCMD_ERR);
	}

	kg.kg_cb = cb;
	kg.kg_cbdata = cbdata;
	kg.kg_kvseg = (uintptr_t)kvseg.st_value;
	kg.kg_kvseg32 = (uintptr_t)kvseg32.st_value;
	kg.kg_kvseg_core = (uintptr_t)kvseg_core.st_value;
	kg.kg_segkpm = (uintptr_t)segkpm.st_value;

	if (mdb_pwalk("seg", (mdb_walk_cb_t)kgrep_walk_seg,
	    &kg, kas.st_value) == -1) {
		mdb_warn("failed to walk kas segments");
		return (DCMD_ERR);
	}

	if (mdb_walk("vmem", (mdb_walk_cb_t)kgrep_walk_vmem, &kg) == -1) {
		mdb_warn("failed to walk heap/heap32 vmem arenas");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

size_t
kgrep_subr_pagesize(void)
{
	return (PAGESIZE);
}

typedef struct file_walk_data {
	struct uf_entry *fw_flist;
	int fw_flistsz;
	int fw_ndx;
	int fw_nofiles;
} file_walk_data_t;

int
file_walk_init(mdb_walk_state_t *wsp)
{
	file_walk_data_t *fw;
	proc_t p;

	if (wsp->walk_addr == NULL) {
		mdb_warn("file walk doesn't support global walks\n");
		return (WALK_ERR);
	}

	fw = mdb_alloc(sizeof (file_walk_data_t), UM_SLEEP);

	if (mdb_vread(&p, sizeof (p), wsp->walk_addr) == -1) {
		mdb_free(fw, sizeof (file_walk_data_t));
		mdb_warn("failed to read proc structure at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	if (p.p_user.u_finfo.fi_nfiles == 0) {
		mdb_free(fw, sizeof (file_walk_data_t));
		return (WALK_DONE);
	}

	fw->fw_nofiles = p.p_user.u_finfo.fi_nfiles;
	fw->fw_flistsz = sizeof (struct uf_entry) * fw->fw_nofiles;
	fw->fw_flist = mdb_alloc(fw->fw_flistsz, UM_SLEEP);

	if (mdb_vread(fw->fw_flist, fw->fw_flistsz,
	    (uintptr_t)p.p_user.u_finfo.fi_list) == -1) {
		mdb_warn("failed to read file array at %p",
		    p.p_user.u_finfo.fi_list);
		mdb_free(fw->fw_flist, fw->fw_flistsz);
		mdb_free(fw, sizeof (file_walk_data_t));
		return (WALK_ERR);
	}

	fw->fw_ndx = 0;
	wsp->walk_data = fw;

	return (WALK_NEXT);
}

int
file_walk_step(mdb_walk_state_t *wsp)
{
	file_walk_data_t *fw = (file_walk_data_t *)wsp->walk_data;
	struct file file;
	uintptr_t fp;

again:
	if (fw->fw_ndx == fw->fw_nofiles)
		return (WALK_DONE);

	if ((fp = (uintptr_t)fw->fw_flist[fw->fw_ndx++].uf_file) == NULL)
		goto again;

	(void) mdb_vread(&file, sizeof (file), (uintptr_t)fp);
	return (wsp->walk_callback(fp, &file, wsp->walk_cbdata));
}

int
allfile_walk_step(mdb_walk_state_t *wsp)
{
	file_walk_data_t *fw = (file_walk_data_t *)wsp->walk_data;
	struct file file;
	uintptr_t fp;

	if (fw->fw_ndx == fw->fw_nofiles)
		return (WALK_DONE);

	if ((fp = (uintptr_t)fw->fw_flist[fw->fw_ndx++].uf_file) != NULL)
		(void) mdb_vread(&file, sizeof (file), (uintptr_t)fp);
	else
		bzero(&file, sizeof (file));

	return (wsp->walk_callback(fp, &file, wsp->walk_cbdata));
}

void
file_walk_fini(mdb_walk_state_t *wsp)
{
	file_walk_data_t *fw = (file_walk_data_t *)wsp->walk_data;

	mdb_free(fw->fw_flist, fw->fw_flistsz);
	mdb_free(fw, sizeof (file_walk_data_t));
}

int
port_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		mdb_warn("port walk doesn't support global walks\n");
		return (WALK_ERR);
	}

	if (mdb_layered_walk("file", wsp) == -1) {
		mdb_warn("couldn't walk 'file'");
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

int
port_walk_step(mdb_walk_state_t *wsp)
{
	struct vnode	vn;
	uintptr_t	vp;
	uintptr_t	pp;
	struct port	port;

	vp = (uintptr_t)((struct file *)wsp->walk_layer)->f_vnode;
	if (mdb_vread(&vn, sizeof (vn), vp) == -1) {
		mdb_warn("failed to read vnode_t at %p", vp);
		return (WALK_ERR);
	}
	if (vn.v_type != VPORT)
		return (WALK_NEXT);

	pp = (uintptr_t)vn.v_data;
	if (mdb_vread(&port, sizeof (port), pp) == -1) {
		mdb_warn("failed to read port_t at %p", pp);
		return (WALK_ERR);
	}
	return (wsp->walk_callback(pp, &port, wsp->walk_cbdata));
}

typedef struct portev_walk_data {
	list_node_t	*pev_node;
	list_node_t	*pev_last;
	size_t		pev_offset;
} portev_walk_data_t;

int
portev_walk_init(mdb_walk_state_t *wsp)
{
	portev_walk_data_t *pevd;
	struct port	port;
	struct vnode	vn;
	struct list	*list;
	uintptr_t	vp;

	if (wsp->walk_addr == NULL) {
		mdb_warn("portev walk doesn't support global walks\n");
		return (WALK_ERR);
	}

	pevd = mdb_alloc(sizeof (portev_walk_data_t), UM_SLEEP);

	if (mdb_vread(&port, sizeof (port), wsp->walk_addr) == -1) {
		mdb_free(pevd, sizeof (portev_walk_data_t));
		mdb_warn("failed to read port structure at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	vp = (uintptr_t)port.port_vnode;
	if (mdb_vread(&vn, sizeof (vn), vp) == -1) {
		mdb_free(pevd, sizeof (portev_walk_data_t));
		mdb_warn("failed to read vnode_t at %p", vp);
		return (WALK_ERR);
	}

	if (vn.v_type != VPORT) {
		mdb_free(pevd, sizeof (portev_walk_data_t));
		mdb_warn("input address (%p) does not point to an event port",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	if (port.port_queue.portq_nent == 0) {
		mdb_free(pevd, sizeof (portev_walk_data_t));
		return (WALK_DONE);
	}
	list = &port.port_queue.portq_list;
	pevd->pev_offset = list->list_offset;
	pevd->pev_last = list->list_head.list_prev;
	pevd->pev_node = list->list_head.list_next;
	wsp->walk_data = pevd;
	return (WALK_NEXT);
}

int
portev_walk_step(mdb_walk_state_t *wsp)
{
	portev_walk_data_t	*pevd;
	struct port_kevent	ev;
	uintptr_t		evp;

	pevd = (portev_walk_data_t *)wsp->walk_data;

	if (pevd->pev_last == NULL)
		return (WALK_DONE);
	if (pevd->pev_node == pevd->pev_last)
		pevd->pev_last = NULL;		/* last round */

	evp = ((uintptr_t)(((char *)pevd->pev_node) - pevd->pev_offset));
	if (mdb_vread(&ev, sizeof (ev), evp) == -1) {
		mdb_warn("failed to read port_kevent at %p", evp);
		return (WALK_DONE);
	}
	pevd->pev_node = ev.portkev_node.list_next;
	return (wsp->walk_callback(evp, &ev, wsp->walk_cbdata));
}

void
portev_walk_fini(mdb_walk_state_t *wsp)
{
	portev_walk_data_t *pevd = (portev_walk_data_t *)wsp->walk_data;

	if (pevd != NULL)
		mdb_free(pevd, sizeof (portev_walk_data_t));
}

typedef struct proc_walk_data {
	uintptr_t *pw_stack;
	int pw_depth;
	int pw_max;
} proc_walk_data_t;

int
proc_walk_init(mdb_walk_state_t *wsp)
{
	GElf_Sym sym;
	proc_walk_data_t *pw;

	if (wsp->walk_addr == NULL) {
		if (mdb_lookup_by_name("p0", &sym) == -1) {
			mdb_warn("failed to read 'practive'");
			return (WALK_ERR);
		}
		wsp->walk_addr = (uintptr_t)sym.st_value;
	}

	pw = mdb_zalloc(sizeof (proc_walk_data_t), UM_SLEEP);

	if (mdb_readvar(&pw->pw_max, "nproc") == -1) {
		mdb_warn("failed to read 'nproc'");
		mdb_free(pw, sizeof (pw));
		return (WALK_ERR);
	}

	pw->pw_stack = mdb_alloc(pw->pw_max * sizeof (uintptr_t), UM_SLEEP);
	wsp->walk_data = pw;

	return (WALK_NEXT);
}

int
proc_walk_step(mdb_walk_state_t *wsp)
{
	proc_walk_data_t *pw = wsp->walk_data;
	uintptr_t addr = wsp->walk_addr;
	uintptr_t cld, sib;

	int status;
	proc_t pr;

	if (mdb_vread(&pr, sizeof (proc_t), addr) == -1) {
		mdb_warn("failed to read proc at %p", addr);
		return (WALK_DONE);
	}

	cld = (uintptr_t)pr.p_child;
	sib = (uintptr_t)pr.p_sibling;

	if (pw->pw_depth > 0 && addr == pw->pw_stack[pw->pw_depth - 1]) {
		pw->pw_depth--;
		goto sib;
	}

	status = wsp->walk_callback(addr, &pr, wsp->walk_cbdata);

	if (status != WALK_NEXT)
		return (status);

	if ((wsp->walk_addr = cld) != NULL) {
		if (mdb_vread(&pr, sizeof (proc_t), cld) == -1) {
			mdb_warn("proc %p has invalid p_child %p; skipping\n",
			    addr, cld);
			goto sib;
		}

		pw->pw_stack[pw->pw_depth++] = addr;

		if (pw->pw_depth == pw->pw_max) {
			mdb_warn("depth %d exceeds max depth; try again\n",
			    pw->pw_depth);
			return (WALK_DONE);
		}
		return (WALK_NEXT);
	}

sib:
	/*
	 * We know that p0 has no siblings, and if another starting proc
	 * was given, we don't want to walk its siblings anyway.
	 */
	if (pw->pw_depth == 0)
		return (WALK_DONE);

	if (sib != NULL && mdb_vread(&pr, sizeof (proc_t), sib) == -1) {
		mdb_warn("proc %p has invalid p_sibling %p; skipping\n",
		    addr, sib);
		sib = NULL;
	}

	if ((wsp->walk_addr = sib) == NULL) {
		if (pw->pw_depth > 0) {
			wsp->walk_addr = pw->pw_stack[pw->pw_depth - 1];
			return (WALK_NEXT);
		}
		return (WALK_DONE);
	}

	return (WALK_NEXT);
}

void
proc_walk_fini(mdb_walk_state_t *wsp)
{
	proc_walk_data_t *pw = wsp->walk_data;

	mdb_free(pw->pw_stack, pw->pw_max * sizeof (uintptr_t));
	mdb_free(pw, sizeof (proc_walk_data_t));
}

int
task_walk_init(mdb_walk_state_t *wsp)
{
	task_t task;

	if (mdb_vread(&task, sizeof (task_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read task at %p", wsp->walk_addr);
		return (WALK_ERR);
	}
	wsp->walk_addr = (uintptr_t)task.tk_memb_list;
	wsp->walk_data = task.tk_memb_list;
	return (WALK_NEXT);
}

int
task_walk_step(mdb_walk_state_t *wsp)
{
	proc_t proc;
	int status;

	if (mdb_vread(&proc, sizeof (proc_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read proc at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, NULL, wsp->walk_cbdata);

	if (proc.p_tasknext == wsp->walk_data)
		return (WALK_DONE);

	wsp->walk_addr = (uintptr_t)proc.p_tasknext;
	return (status);
}

int
project_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		if (mdb_readvar(&wsp->walk_addr, "proj0p") == -1) {
			mdb_warn("failed to read 'proj0p'");
			return (WALK_ERR);
		}
	}
	wsp->walk_data = (void *)wsp->walk_addr;
	return (WALK_NEXT);
}

int
project_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;
	kproject_t pj;
	int status;

	if (mdb_vread(&pj, sizeof (kproject_t), addr) == -1) {
		mdb_warn("failed to read project at %p", addr);
		return (WALK_DONE);
	}
	status = wsp->walk_callback(addr, &pj, wsp->walk_cbdata);
	if (status != WALK_NEXT)
		return (status);
	wsp->walk_addr = (uintptr_t)pj.kpj_next;
	if ((void *)wsp->walk_addr == wsp->walk_data)
		return (WALK_DONE);
	return (WALK_NEXT);
}

static int
generic_walk_step(mdb_walk_state_t *wsp)
{
	return (wsp->walk_callback(wsp->walk_addr, wsp->walk_layer,
	    wsp->walk_cbdata));
}

static int
cpu_walk_cmp(const void *l, const void *r)
{
	uintptr_t lhs = *((uintptr_t *)l);
	uintptr_t rhs = *((uintptr_t *)r);
	cpu_t lcpu, rcpu;

	(void) mdb_vread(&lcpu, sizeof (lcpu), lhs);
	(void) mdb_vread(&rcpu, sizeof (rcpu), rhs);

	if (lcpu.cpu_id < rcpu.cpu_id)
		return (-1);

	if (lcpu.cpu_id > rcpu.cpu_id)
		return (1);

	return (0);
}

typedef struct cpu_walk {
	uintptr_t *cw_array;
	int cw_ndx;
} cpu_walk_t;

int
cpu_walk_init(mdb_walk_state_t *wsp)
{
	cpu_walk_t *cw;
	int max_ncpus, i = 0;
	uintptr_t current, first;
	cpu_t cpu, panic_cpu;
	uintptr_t panicstr, addr;
	GElf_Sym sym;

	cw = mdb_zalloc(sizeof (cpu_walk_t), UM_SLEEP | UM_GC);

	if (mdb_readvar(&max_ncpus, "max_ncpus") == -1) {
		mdb_warn("failed to read 'max_ncpus'");
		return (WALK_ERR);
	}

	if (mdb_readvar(&panicstr, "panicstr") == -1) {
		mdb_warn("failed to read 'panicstr'");
		return (WALK_ERR);
	}

	if (panicstr != NULL) {
		if (mdb_lookup_by_name("panic_cpu", &sym) == -1) {
			mdb_warn("failed to find 'panic_cpu'");
			return (WALK_ERR);
		}

		addr = (uintptr_t)sym.st_value;

		if (mdb_vread(&panic_cpu, sizeof (cpu_t), addr) == -1) {
			mdb_warn("failed to read 'panic_cpu'");
			return (WALK_ERR);
		}
	}

	/*
	 * Unfortunately, there is no platform-independent way to walk
	 * CPUs in ID order.  We therefore loop through in cpu_next order,
	 * building an array of CPU pointers which will subsequently be
	 * sorted.
	 */
	cw->cw_array =
	    mdb_zalloc((max_ncpus + 1) * sizeof (uintptr_t), UM_SLEEP | UM_GC);

	if (mdb_readvar(&first, "cpu_list") == -1) {
		mdb_warn("failed to read 'cpu_list'");
		return (WALK_ERR);
	}

	current = first;
	do {
		if (mdb_vread(&cpu, sizeof (cpu), current) == -1) {
			mdb_warn("failed to read cpu at %p", current);
			return (WALK_ERR);
		}

		if (panicstr != NULL && panic_cpu.cpu_id == cpu.cpu_id) {
			cw->cw_array[i++] = addr;
		} else {
			cw->cw_array[i++] = current;
		}
	} while ((current = (uintptr_t)cpu.cpu_next) != first);

	qsort(cw->cw_array, i, sizeof (uintptr_t), cpu_walk_cmp);
	wsp->walk_data = cw;

	return (WALK_NEXT);
}

int
cpu_walk_step(mdb_walk_state_t *wsp)
{
	cpu_walk_t *cw = wsp->walk_data;
	cpu_t cpu;
	uintptr_t addr = cw->cw_array[cw->cw_ndx++];

	if (addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(&cpu, sizeof (cpu), addr) == -1) {
		mdb_warn("failed to read cpu at %p", addr);
		return (WALK_DONE);
	}

	return (wsp->walk_callback(addr, &cpu, wsp->walk_cbdata));
}

typedef struct cpuinfo_data {
	intptr_t cid_cpu;
	uintptr_t **cid_ithr;
	char	cid_print_head;
	char	cid_print_thr;
	char	cid_print_ithr;
	char	cid_print_flags;
} cpuinfo_data_t;

int
cpuinfo_walk_ithread(uintptr_t addr, const kthread_t *thr, cpuinfo_data_t *cid)
{
	cpu_t c;
	int id;
	uint8_t pil;

	if (!(thr->t_flag & T_INTR_THREAD) || thr->t_state == TS_FREE)
		return (WALK_NEXT);

	if (thr->t_bound_cpu == NULL) {
		mdb_warn("thr %p is intr thread w/out a CPU\n", addr);
		return (WALK_NEXT);
	}

	(void) mdb_vread(&c, sizeof (c), (uintptr_t)thr->t_bound_cpu);

	if ((id = c.cpu_id) >= NCPU) {
		mdb_warn("CPU %p has id (%d) greater than NCPU (%d)\n",
		    thr->t_bound_cpu, id, NCPU);
		return (WALK_NEXT);
	}

	if ((pil = thr->t_pil) >= NINTR) {
		mdb_warn("thread %p has pil (%d) greater than %d\n",
		    addr, pil, NINTR);
		return (WALK_NEXT);
	}

	if (cid->cid_ithr[id][pil] != NULL) {
		mdb_warn("CPU %d has multiple threads at pil %d (at least "
		    "%p and %p)\n", id, pil, addr, cid->cid_ithr[id][pil]);
		return (WALK_NEXT);
	}

	cid->cid_ithr[id][pil] = addr;

	return (WALK_NEXT);
}

#define	CPUINFO_IDWIDTH		3
#define	CPUINFO_FLAGWIDTH	9

#ifdef _LP64
#if defined(__amd64)
#define	CPUINFO_TWIDTH		16
#define	CPUINFO_CPUWIDTH	16
#else
#define	CPUINFO_CPUWIDTH	11
#define	CPUINFO_TWIDTH		11
#endif
#else
#define	CPUINFO_CPUWIDTH	8
#define	CPUINFO_TWIDTH		8
#endif

#define	CPUINFO_THRDELT		(CPUINFO_IDWIDTH + CPUINFO_CPUWIDTH + 9)
#define	CPUINFO_FLAGDELT	(CPUINFO_IDWIDTH + CPUINFO_CPUWIDTH + 4)
#define	CPUINFO_ITHRDELT	4

#define	CPUINFO_INDENT	mdb_printf("%*s", CPUINFO_THRDELT, \
    flagline < nflaglines ? flagbuf[flagline++] : "")

int
cpuinfo_walk_cpu(uintptr_t addr, const cpu_t *cpu, cpuinfo_data_t *cid)
{
	kthread_t t;
	disp_t disp;
	proc_t p;
	uintptr_t pinned;
	char **flagbuf;
	int nflaglines = 0, flagline = 0, bspl, rval = WALK_NEXT;

	const char *flags[] = {
	    "RUNNING", "READY", "QUIESCED", "EXISTS",
	    "ENABLE", "OFFLINE", "POWEROFF", "FROZEN",
	    "SPARE", "FAULTED", NULL
	};

	if (cid->cid_cpu != -1) {
		if (addr != cid->cid_cpu && cpu->cpu_id != cid->cid_cpu)
			return (WALK_NEXT);

		/*
		 * Set cid_cpu to -1 to indicate that we found a matching CPU.
		 */
		cid->cid_cpu = -1;
		rval = WALK_DONE;
	}

	if (cid->cid_print_head) {
		mdb_printf("%3s %-*s %3s %4s %4s %3s %4s %5s %-6s %-*s %s\n",
		    "ID", CPUINFO_CPUWIDTH, "ADDR", "FLG", "NRUN", "BSPL",
		    "PRI", "RNRN", "KRNRN", "SWITCH", CPUINFO_TWIDTH, "THREAD",
		    "PROC");
		cid->cid_print_head = FALSE;
	}

	bspl = cpu->cpu_base_spl;

	if (mdb_vread(&disp, sizeof (disp_t), (uintptr_t)cpu->cpu_disp) == -1) {
		mdb_warn("failed to read disp_t at %p", cpu->cpu_disp);
		return (WALK_ERR);
	}

	mdb_printf("%3d %0*p %3x %4d %4d ",
	    cpu->cpu_id, CPUINFO_CPUWIDTH, addr, cpu->cpu_flags,
	    disp.disp_nrunnable, bspl);

	if (mdb_vread(&t, sizeof (t), (uintptr_t)cpu->cpu_thread) != -1) {
		mdb_printf("%3d ", t.t_pri);
	} else {
		mdb_printf("%3s ", "-");
	}

	mdb_printf("%4s %5s ", cpu->cpu_runrun ? "yes" : "no",
	    cpu->cpu_kprunrun ? "yes" : "no");

	if (cpu->cpu_last_swtch) {
		mdb_printf("t-%-4d ",
		    (clock_t)mdb_get_lbolt() - cpu->cpu_last_swtch);
	} else {
		mdb_printf("%-6s ", "-");
	}

	mdb_printf("%0*p", CPUINFO_TWIDTH, cpu->cpu_thread);

	if (cpu->cpu_thread == cpu->cpu_idle_thread)
		mdb_printf(" (idle)\n");
	else if (cpu->cpu_thread == NULL)
		mdb_printf(" -\n");
	else {
		if (mdb_vread(&p, sizeof (p), (uintptr_t)t.t_procp) != -1) {
			mdb_printf(" %s\n", p.p_user.u_comm);
		} else {
			mdb_printf(" ?\n");
		}
	}

	flagbuf = mdb_zalloc(sizeof (flags), UM_SLEEP | UM_GC);

	if (cid->cid_print_flags) {
		int first = 1, i, j, k;
		char *s;

		cid->cid_print_head = TRUE;

		for (i = 1, j = 0; flags[j] != NULL; i <<= 1, j++) {
			if (!(cpu->cpu_flags & i))
				continue;

			if (first) {
				s = mdb_alloc(CPUINFO_THRDELT + 1,
				    UM_GC | UM_SLEEP);

				(void) mdb_snprintf(s, CPUINFO_THRDELT + 1,
				    "%*s|%*s", CPUINFO_FLAGDELT, "",
				    CPUINFO_THRDELT - 1 - CPUINFO_FLAGDELT, "");
				flagbuf[nflaglines++] = s;
			}

			s = mdb_alloc(CPUINFO_THRDELT + 1, UM_GC | UM_SLEEP);
			(void) mdb_snprintf(s, CPUINFO_THRDELT + 1, "%*s%*s %s",
			    CPUINFO_IDWIDTH + CPUINFO_CPUWIDTH -
			    CPUINFO_FLAGWIDTH, "", CPUINFO_FLAGWIDTH, flags[j],
			    first ? "<--+" : "");

			for (k = strlen(s); k < CPUINFO_THRDELT; k++)
				s[k] = ' ';
			s[k] = '\0';

			flagbuf[nflaglines++] = s;
			first = 0;
		}
	}

	if (cid->cid_print_ithr) {
		int i, found_one = FALSE;
		int print_thr = disp.disp_nrunnable && cid->cid_print_thr;

		for (i = NINTR - 1; i >= 0; i--) {
			uintptr_t iaddr = cid->cid_ithr[cpu->cpu_id][i];

			if (iaddr == NULL)
				continue;

			if (!found_one) {
				found_one = TRUE;

				CPUINFO_INDENT;
				mdb_printf("%c%*s|\n", print_thr ? '|' : ' ',
				    CPUINFO_ITHRDELT, "");

				CPUINFO_INDENT;
				mdb_printf("%c%*s+--> %3s %s\n",
				    print_thr ? '|' : ' ', CPUINFO_ITHRDELT,
				    "", "PIL", "THREAD");
			}

			if (mdb_vread(&t, sizeof (t), iaddr) == -1) {
				mdb_warn("failed to read kthread_t at %p",
				    iaddr);
				return (WALK_ERR);
			}

			CPUINFO_INDENT;
			mdb_printf("%c%*s     %3d %0*p\n",
			    print_thr ? '|' : ' ', CPUINFO_ITHRDELT, "",
			    t.t_pil, CPUINFO_TWIDTH, iaddr);

			pinned = (uintptr_t)t.t_intr;
		}

		if (found_one && pinned != NULL) {
			cid->cid_print_head = TRUE;
			(void) strcpy(p.p_user.u_comm, "?");

			if (mdb_vread(&t, sizeof (t),
			    (uintptr_t)pinned) == -1) {
				mdb_warn("failed to read kthread_t at %p",
				    pinned);
				return (WALK_ERR);
			}
			if (mdb_vread(&p, sizeof (p),
			    (uintptr_t)t.t_procp) == -1) {
				mdb_warn("failed to read proc_t at %p",
				    t.t_procp);
				return (WALK_ERR);
			}

			CPUINFO_INDENT;
			mdb_printf("%c%*s     %3s %0*p %s\n",
			    print_thr ? '|' : ' ', CPUINFO_ITHRDELT, "", "-",
			    CPUINFO_TWIDTH, pinned,
			    pinned == (uintptr_t)cpu->cpu_idle_thread ?
			    "(idle)" : p.p_user.u_comm);
		}
	}

	if (disp.disp_nrunnable && cid->cid_print_thr) {
		dispq_t *dq;

		int i, npri = disp.disp_npri;

		dq = mdb_alloc(sizeof (dispq_t) * npri, UM_SLEEP | UM_GC);

		if (mdb_vread(dq, sizeof (dispq_t) * npri,
		    (uintptr_t)disp.disp_q) == -1) {
			mdb_warn("failed to read dispq_t at %p", disp.disp_q);
			return (WALK_ERR);
		}

		CPUINFO_INDENT;
		mdb_printf("|\n");

		CPUINFO_INDENT;
		mdb_printf("+-->  %3s %-*s %s\n", "PRI",
		    CPUINFO_TWIDTH, "THREAD", "PROC");

		for (i = npri - 1; i >= 0; i--) {
			uintptr_t taddr = (uintptr_t)dq[i].dq_first;

			while (taddr != NULL) {
				if (mdb_vread(&t, sizeof (t), taddr) == -1) {
					mdb_warn("failed to read kthread_t "
					    "at %p", taddr);
					return (WALK_ERR);
				}
				if (mdb_vread(&p, sizeof (p),
				    (uintptr_t)t.t_procp) == -1) {
					mdb_warn("failed to read proc_t at %p",
					    t.t_procp);
					return (WALK_ERR);
				}

				CPUINFO_INDENT;
				mdb_printf("      %3d %0*p %s\n", t.t_pri,
				    CPUINFO_TWIDTH, taddr, p.p_user.u_comm);

				taddr = (uintptr_t)t.t_link;
			}
		}
		cid->cid_print_head = TRUE;
	}

	while (flagline < nflaglines)
		mdb_printf("%s\n", flagbuf[flagline++]);

	if (cid->cid_print_head)
		mdb_printf("\n");

	return (rval);
}

int
cpuinfo(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t verbose = FALSE;
	cpuinfo_data_t cid;

	cid.cid_print_ithr = FALSE;
	cid.cid_print_thr = FALSE;
	cid.cid_print_flags = FALSE;
	cid.cid_print_head = DCMD_HDRSPEC(flags) ? TRUE : FALSE;
	cid.cid_cpu = -1;

	if (flags & DCMD_ADDRSPEC)
		cid.cid_cpu = addr;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose, NULL) != argc)
		return (DCMD_USAGE);

	if (verbose) {
		cid.cid_print_ithr = TRUE;
		cid.cid_print_thr = TRUE;
		cid.cid_print_flags = TRUE;
		cid.cid_print_head = TRUE;
	}

	if (cid.cid_print_ithr) {
		int i;

		cid.cid_ithr = mdb_alloc(sizeof (uintptr_t **)
		    * NCPU, UM_SLEEP | UM_GC);

		for (i = 0; i < NCPU; i++)
			cid.cid_ithr[i] = mdb_zalloc(sizeof (uintptr_t *) *
			    NINTR, UM_SLEEP | UM_GC);

		if (mdb_walk("thread", (mdb_walk_cb_t)cpuinfo_walk_ithread,
		    &cid) == -1) {
			mdb_warn("couldn't walk thread");
			return (DCMD_ERR);
		}
	}

	if (mdb_walk("cpu", (mdb_walk_cb_t)cpuinfo_walk_cpu, &cid) == -1) {
		mdb_warn("can't walk cpus");
		return (DCMD_ERR);
	}

	if (cid.cid_cpu != -1) {
		/*
		 * We didn't find this CPU when we walked through the CPUs
		 * (i.e. the address specified doesn't show up in the "cpu"
		 * walk).  However, the specified address may still correspond
		 * to a valid cpu_t (for example, if the specified address is
		 * the actual panicking cpu_t and not the cached panic_cpu).
		 * Point is:  even if we didn't find it, we still want to try
		 * to print the specified address as a cpu_t.
		 */
		cpu_t cpu;

		if (mdb_vread(&cpu, sizeof (cpu), cid.cid_cpu) == -1) {
			mdb_warn("%p is neither a valid CPU ID nor a "
			    "valid cpu_t address\n", cid.cid_cpu);
			return (DCMD_ERR);
		}

		(void) cpuinfo_walk_cpu(cid.cid_cpu, &cpu, &cid);
	}

	return (DCMD_OK);
}

/*ARGSUSED*/
int
flipone(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int i;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	for (i = 0; i < sizeof (addr) * NBBY; i++)
		mdb_printf("%p\n", addr ^ (1UL << i));

	return (DCMD_OK);
}

int
as2proc_walk(uintptr_t addr, const proc_t *p, struct as **asp)
{
	if (p->p_as == *asp)
		mdb_printf("%p\n", addr);
	return (WALK_NEXT);
}

/*ARGSUSED*/
int
as2proc(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (!(flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	if (mdb_walk("proc", (mdb_walk_cb_t)as2proc_walk, &addr) == -1) {
		mdb_warn("failed to walk proc");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*ARGSUSED*/
int
ptree_walk(uintptr_t addr, const proc_t *p, void *ignored)
{
	proc_t parent;
	int ident = 0;
	uintptr_t paddr;

	for (paddr = (uintptr_t)p->p_parent; paddr != NULL; ident += 5) {
		mdb_vread(&parent, sizeof (parent), paddr);
		paddr = (uintptr_t)parent.p_parent;
	}

	mdb_inc_indent(ident);
	mdb_printf("%0?p  %s\n", addr, p->p_user.u_comm);
	mdb_dec_indent(ident);

	return (WALK_NEXT);
}

void
ptree_ancestors(uintptr_t addr, uintptr_t start)
{
	proc_t p;

	if (mdb_vread(&p, sizeof (p), addr) == -1) {
		mdb_warn("couldn't read ancestor at %p", addr);
		return;
	}

	if (p.p_parent != NULL)
		ptree_ancestors((uintptr_t)p.p_parent, start);

	if (addr != start)
		(void) ptree_walk(addr, &p, NULL);
}

/*ARGSUSED*/
int
ptree(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (!(flags & DCMD_ADDRSPEC))
		addr = NULL;
	else
		ptree_ancestors(addr, addr);

	if (mdb_pwalk("proc", (mdb_walk_cb_t)ptree_walk, NULL, addr) == -1) {
		mdb_warn("couldn't walk 'proc'");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
fd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int fdnum;
	const mdb_arg_t *argp = &argv[0];
	proc_t p;
	uf_entry_t uf;

	if ((flags & DCMD_ADDRSPEC) == 0) {
		mdb_warn("fd doesn't give global information\n");
		return (DCMD_ERR);
	}
	if (argc != 1)
		return (DCMD_USAGE);

	if (argp->a_type == MDB_TYPE_IMMEDIATE)
		fdnum = argp->a_un.a_val;
	else
		fdnum = mdb_strtoull(argp->a_un.a_str);

	if (mdb_vread(&p, sizeof (struct proc), addr) == -1) {
		mdb_warn("couldn't read proc_t at %p", addr);
		return (DCMD_ERR);
	}
	if (fdnum > p.p_user.u_finfo.fi_nfiles) {
		mdb_warn("process %p only has %d files open.\n",
		    addr, p.p_user.u_finfo.fi_nfiles);
		return (DCMD_ERR);
	}
	if (mdb_vread(&uf, sizeof (uf_entry_t),
	    (uintptr_t)&p.p_user.u_finfo.fi_list[fdnum]) == -1) {
		mdb_warn("couldn't read uf_entry_t at %p",
		    &p.p_user.u_finfo.fi_list[fdnum]);
		return (DCMD_ERR);
	}

	mdb_printf("%p\n", uf.uf_file);
	return (DCMD_OK);
}

/*ARGSUSED*/
static int
pid2proc(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	pid_t pid = (pid_t)addr;

	if (argc != 0)
		return (DCMD_USAGE);

	if ((addr = mdb_pid2proc(pid, NULL)) == NULL) {
		mdb_warn("PID 0t%d not found\n", pid);
		return (DCMD_ERR);
	}

	mdb_printf("%p\n", addr);
	return (DCMD_OK);
}

static char *sysfile_cmd[] = {
	"exclude:",
	"include:",
	"forceload:",
	"rootdev:",
	"rootfs:",
	"swapdev:",
	"swapfs:",
	"moddir:",
	"set",
	"unknown",
};

static char *sysfile_ops[] = { "", "=", "&", "|" };

/*ARGSUSED*/
static int
sysfile_vmem_seg(uintptr_t addr, const vmem_seg_t *vsp, void **target)
{
	if (vsp->vs_type == VMEM_ALLOC && (void *)vsp->vs_start == *target) {
		*target = NULL;
		return (WALK_DONE);
	}
	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
sysfile(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct sysparam *sysp, sys;
	char var[256];
	char modname[256];
	char val[256];
	char strval[256];
	vmem_t *mod_sysfile_arena;
	void *straddr;

	if (mdb_readvar(&sysp, "sysparam_hd") == -1) {
		mdb_warn("failed to read sysparam_hd");
		return (DCMD_ERR);
	}

	if (mdb_readvar(&mod_sysfile_arena, "mod_sysfile_arena") == -1) {
		mdb_warn("failed to read mod_sysfile_arena");
		return (DCMD_ERR);
	}

	while (sysp != NULL) {
		var[0] = '\0';
		val[0] = '\0';
		modname[0] = '\0';
		if (mdb_vread(&sys, sizeof (sys), (uintptr_t)sysp) == -1) {
			mdb_warn("couldn't read sysparam %p", sysp);
			return (DCMD_ERR);
		}
		if (sys.sys_modnam != NULL &&
		    mdb_readstr(modname, 256,
		    (uintptr_t)sys.sys_modnam) == -1) {
			mdb_warn("couldn't read modname in %p", sysp);
			return (DCMD_ERR);
		}
		if (sys.sys_ptr != NULL &&
		    mdb_readstr(var, 256, (uintptr_t)sys.sys_ptr) == -1) {
			mdb_warn("couldn't read ptr in %p", sysp);
			return (DCMD_ERR);
		}
		if (sys.sys_op != SETOP_NONE) {
			/*
			 * Is this an int or a string?  We determine this
			 * by checking whether straddr is contained in
			 * mod_sysfile_arena.  If so, the walker will set
			 * straddr to NULL.
			 */
			straddr = (void *)(uintptr_t)sys.sys_info;
			if (sys.sys_op == SETOP_ASSIGN &&
			    sys.sys_info != 0 &&
			    mdb_pwalk("vmem_seg",
			    (mdb_walk_cb_t)sysfile_vmem_seg, &straddr,
			    (uintptr_t)mod_sysfile_arena) == 0 &&
			    straddr == NULL &&
			    mdb_readstr(strval, 256,
			    (uintptr_t)sys.sys_info) != -1) {
				(void) mdb_snprintf(val, sizeof (val), "\"%s\"",
				    strval);
			} else {
				(void) mdb_snprintf(val, sizeof (val),
				    "0x%llx [0t%llu]", sys.sys_info,
				    sys.sys_info);
			}
		}
		mdb_printf("%s %s%s%s%s%s\n", sysfile_cmd[sys.sys_type],
		    modname, modname[0] == '\0' ? "" : ":",
		    var, sysfile_ops[sys.sys_op], val);

		sysp = sys.sys_next;
	}

	return (DCMD_OK);
}

int
didmatch(uintptr_t addr, const kthread_t *thr, kt_did_t *didp)
{

	if (*didp == thr->t_did) {
		mdb_printf("%p\n", addr);
		return (WALK_DONE);
	} else
		return (WALK_NEXT);
}

/*ARGSUSED*/
int
did2thread(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	const mdb_arg_t *argp = &argv[0];
	kt_did_t	did;

	if (argc != 1)
		return (DCMD_USAGE);

	did = (kt_did_t)mdb_strtoull(argp->a_un.a_str);

	if (mdb_walk("thread", (mdb_walk_cb_t)didmatch, (void *)&did) == -1) {
		mdb_warn("failed to walk thread");
		return (DCMD_ERR);

	}
	return (DCMD_OK);

}

static int
errorq_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL &&
	    mdb_readvar(&wsp->walk_addr, "errorq_list") == -1) {
		mdb_warn("failed to read errorq_list");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

static int
errorq_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;
	errorq_t eq;

	if (addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(&eq, sizeof (eq), addr) == -1) {
		mdb_warn("failed to read errorq at %p", addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)eq.eq_next;
	return (wsp->walk_callback(addr, &eq, wsp->walk_cbdata));
}

typedef struct eqd_walk_data {
	uintptr_t *eqd_stack;
	void *eqd_buf;
	ulong_t eqd_qpos;
	ulong_t eqd_qlen;
	size_t eqd_size;
} eqd_walk_data_t;

/*
 * In order to walk the list of pending error queue elements, we push the
 * addresses of the corresponding data buffers in to the eqd_stack array.
 * The error lists are in reverse chronological order when iterating using
 * eqe_prev, so we then pop things off the top in eqd_walk_step so that the
 * walker client gets addresses in order from oldest error to newest error.
 */
static void
eqd_push_list(eqd_walk_data_t *eqdp, uintptr_t addr)
{
	errorq_elem_t eqe;

	while (addr != NULL) {
		if (mdb_vread(&eqe, sizeof (eqe), addr) != sizeof (eqe)) {
			mdb_warn("failed to read errorq element at %p", addr);
			break;
		}

		if (eqdp->eqd_qpos == eqdp->eqd_qlen) {
			mdb_warn("errorq is overfull -- more than %lu "
			    "elems found\n", eqdp->eqd_qlen);
			break;
		}

		eqdp->eqd_stack[eqdp->eqd_qpos++] = (uintptr_t)eqe.eqe_data;
		addr = (uintptr_t)eqe.eqe_prev;
	}
}

static int
eqd_walk_init(mdb_walk_state_t *wsp)
{
	eqd_walk_data_t *eqdp;
	errorq_elem_t eqe, *addr;
	errorq_t eq;
	ulong_t i;

	if (mdb_vread(&eq, sizeof (eq), wsp->walk_addr) == -1) {
		mdb_warn("failed to read errorq at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	if (eq.eq_ptail != NULL &&
	    mdb_vread(&eqe, sizeof (eqe), (uintptr_t)eq.eq_ptail) == -1) {
		mdb_warn("failed to read errorq element at %p", eq.eq_ptail);
		return (WALK_ERR);
	}

	eqdp = mdb_alloc(sizeof (eqd_walk_data_t), UM_SLEEP);
	wsp->walk_data = eqdp;

	eqdp->eqd_stack = mdb_zalloc(sizeof (uintptr_t) * eq.eq_qlen, UM_SLEEP);
	eqdp->eqd_buf = mdb_alloc(eq.eq_size, UM_SLEEP);
	eqdp->eqd_qlen = eq.eq_qlen;
	eqdp->eqd_qpos = 0;
	eqdp->eqd_size = eq.eq_size;

	/*
	 * The newest elements in the queue are on the pending list, so we
	 * push those on to our stack first.
	 */
	eqd_push_list(eqdp, (uintptr_t)eq.eq_pend);

	/*
	 * If eq_ptail is set, it may point to a subset of the errors on the
	 * pending list in the event a atomic_cas_ptr() failed; if ptail's
	 * data is already in our stack, NULL out eq_ptail and ignore it.
	 */
	if (eq.eq_ptail != NULL) {
		for (i = 0; i < eqdp->eqd_qpos; i++) {
			if (eqdp->eqd_stack[i] == (uintptr_t)eqe.eqe_data) {
				eq.eq_ptail = NULL;
				break;
			}
		}
	}

	/*
	 * If eq_phead is set, it has the processing list in order from oldest
	 * to newest.  Use this to recompute eq_ptail as best we can and then
	 * we nicely fall into eqd_push_list() of eq_ptail below.
	 */
	for (addr = eq.eq_phead; addr != NULL && mdb_vread(&eqe, sizeof (eqe),
	    (uintptr_t)addr) == sizeof (eqe); addr = eqe.eqe_next)
		eq.eq_ptail = addr;

	/*
	 * The oldest elements in the queue are on the processing list, subject
	 * to machinations in the if-clauses above.  Push any such elements.
	 */
	eqd_push_list(eqdp, (uintptr_t)eq.eq_ptail);
	return (WALK_NEXT);
}

static int
eqd_walk_step(mdb_walk_state_t *wsp)
{
	eqd_walk_data_t *eqdp = wsp->walk_data;
	uintptr_t addr;

	if (eqdp->eqd_qpos == 0)
		return (WALK_DONE);

	addr = eqdp->eqd_stack[--eqdp->eqd_qpos];

	if (mdb_vread(eqdp->eqd_buf, eqdp->eqd_size, addr) != eqdp->eqd_size) {
		mdb_warn("failed to read errorq data at %p", addr);
		return (WALK_ERR);
	}

	return (wsp->walk_callback(addr, eqdp->eqd_buf, wsp->walk_cbdata));
}

static void
eqd_walk_fini(mdb_walk_state_t *wsp)
{
	eqd_walk_data_t *eqdp = wsp->walk_data;

	mdb_free(eqdp->eqd_stack, sizeof (uintptr_t) * eqdp->eqd_qlen);
	mdb_free(eqdp->eqd_buf, eqdp->eqd_size);
	mdb_free(eqdp, sizeof (eqd_walk_data_t));
}

#define	EQKSVAL(eqv, what) (eqv.eq_kstat.what.value.ui64)

static int
errorq(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int i;
	errorq_t eq;
	uint_t opt_v = FALSE;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("errorq", "errorq", argc, argv) == -1) {
			mdb_warn("can't walk 'errorq'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	i = mdb_getopts(argc, argv, 'v', MDB_OPT_SETBITS, TRUE, &opt_v, NULL);
	argc -= i;
	argv += i;

	if (argc != 0)
		return (DCMD_USAGE);

	if (opt_v || DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%-11s %-16s %1s %1s %1s ",
		    "ADDR", "NAME", "S", "V", "N");
		if (!opt_v) {
			mdb_printf("%7s %7s %7s%</u>\n",
			    "ACCEPT", "DROP", "LOG");
		} else {
			mdb_printf("%5s %6s %6s %3s %16s%</u>\n",
			    "KSTAT", "QLEN", "SIZE", "IPL", "FUNC");
		}
	}

	if (mdb_vread(&eq, sizeof (eq), addr) != sizeof (eq)) {
		mdb_warn("failed to read errorq at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%-11p %-16s %c %c %c ", addr, eq.eq_name,
	    (eq.eq_flags & ERRORQ_ACTIVE) ? '+' : '-',
	    (eq.eq_flags & ERRORQ_VITAL) ? '!' : ' ',
	    (eq.eq_flags & ERRORQ_NVLIST) ? '*' : ' ');

	if (!opt_v) {
		mdb_printf("%7llu %7llu %7llu\n",
		    EQKSVAL(eq, eqk_dispatched) + EQKSVAL(eq, eqk_committed),
		    EQKSVAL(eq, eqk_dropped) + EQKSVAL(eq, eqk_reserve_fail) +
		    EQKSVAL(eq, eqk_commit_fail), EQKSVAL(eq, eqk_logged));
	} else {
		mdb_printf("%5s %6lu %6lu %3u %a\n",
		    "  |  ", eq.eq_qlen, eq.eq_size, eq.eq_ipl, eq.eq_func);
		mdb_printf("%38s\n%41s"
		    "%12s %llu\n"
		    "%53s %llu\n"
		    "%53s %llu\n"
		    "%53s %llu\n"
		    "%53s %llu\n"
		    "%53s %llu\n"
		    "%53s %llu\n"
		    "%53s %llu\n\n",
		    "|", "+-> ",
		    "DISPATCHED",	EQKSVAL(eq, eqk_dispatched),
		    "DROPPED",		EQKSVAL(eq, eqk_dropped),
		    "LOGGED",		EQKSVAL(eq, eqk_logged),
		    "RESERVED",		EQKSVAL(eq, eqk_reserved),
		    "RESERVE FAIL",	EQKSVAL(eq, eqk_reserve_fail),
		    "COMMITTED",	EQKSVAL(eq, eqk_committed),
		    "COMMIT FAIL",	EQKSVAL(eq, eqk_commit_fail),
		    "CANCELLED",	EQKSVAL(eq, eqk_cancelled));
	}

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
panicinfo(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	cpu_t panic_cpu;
	kthread_t *panic_thread;
	void *buf;
	panic_data_t *pd;
	int i, n;

	if (!mdb_prop_postmortem) {
		mdb_warn("panicinfo can only be run on a system "
		    "dump; see dumpadm(1M)\n");
		return (DCMD_ERR);
	}

	if (flags & DCMD_ADDRSPEC || argc != 0)
		return (DCMD_USAGE);

	if (mdb_readsym(&panic_cpu, sizeof (cpu_t), "panic_cpu") == -1)
		mdb_warn("failed to read 'panic_cpu'");
	else
		mdb_printf("%16s %?d\n", "cpu", panic_cpu.cpu_id);

	if (mdb_readvar(&panic_thread, "panic_thread") == -1)
		mdb_warn("failed to read 'panic_thread'");
	else
		mdb_printf("%16s %?p\n", "thread", panic_thread);

	buf = mdb_alloc(PANICBUFSIZE, UM_SLEEP);
	pd = (panic_data_t *)buf;

	if (mdb_readsym(buf, PANICBUFSIZE, "panicbuf") == -1 ||
	    pd->pd_version != PANICBUFVERS) {
		mdb_warn("failed to read 'panicbuf'");
		mdb_free(buf, PANICBUFSIZE);
		return (DCMD_ERR);
	}

	mdb_printf("%16s %s\n", "message",  (char *)buf + pd->pd_msgoff);

	n = (pd->pd_msgoff - (sizeof (panic_data_t) -
	    sizeof (panic_nv_t))) / sizeof (panic_nv_t);

	for (i = 0; i < n; i++)
		mdb_printf("%16s %?llx\n",
		    pd->pd_nvdata[i].pnv_name, pd->pd_nvdata[i].pnv_value);

	mdb_free(buf, PANICBUFSIZE);
	return (DCMD_OK);
}

/*
 * ::time dcmd, which will print a hires timestamp of when we entered the
 * debugger, or the lbolt value if used with the -l option.
 *
 */
/*ARGSUSED*/
static int
time(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t opt_dec = FALSE;
	uint_t opt_lbolt = FALSE;
	uint_t opt_hex = FALSE;
	const char *fmt;
	hrtime_t result;

	if (mdb_getopts(argc, argv,
	    'd', MDB_OPT_SETBITS, TRUE, &opt_dec,
	    'l', MDB_OPT_SETBITS, TRUE, &opt_lbolt,
	    'x', MDB_OPT_SETBITS, TRUE, &opt_hex,
	    NULL) != argc)
		return (DCMD_USAGE);

	if (opt_dec && opt_hex)
		return (DCMD_USAGE);

	result = opt_lbolt ? mdb_get_lbolt() : mdb_gethrtime();
	fmt =
	    opt_hex ? "0x%llx\n" :
	    opt_dec ? "0t%lld\n" : "%#llr\n";

	mdb_printf(fmt, result);
	return (DCMD_OK);
}

void
time_help(void)
{
	mdb_printf("Prints the system time in nanoseconds.\n\n"
	    "::time will return the timestamp at which we dropped into, \n"
	    "if called from, kmdb(1); the core dump's high resolution \n"
	    "time if inspecting one; or the running hires time if we're \n"
	    "looking at a live system.\n\n"
	    "Switches:\n"
	    "  -d   report times in decimal\n"
	    "  -l   prints the number of clock ticks since system boot\n"
	    "  -x   report times in hexadecimal\n");
}

static const mdb_dcmd_t dcmds[] = {

	/* from genunix.c */
	{ "as2proc", ":", "convert as to proc_t address", as2proc },
	{ "binding_hash_entry", ":", "print driver names hash table entry",
		binding_hash_entry },
	{ "callout", "?[-r|n] [-s|l] [-xhB] [-t | -ab nsec [-dkD]]"
	    " [-C addr | -S seqid] [-f name|addr] [-p name| addr] [-T|L [-E]]"
	    " [-FivVA]",
	    "display callouts", callout, callout_help },
	{ "calloutid", "[-d|v] xid", "print callout by extended id",
	    calloutid, calloutid_help },
	{ "class", NULL, "print process scheduler classes", class },
	{ "cpuinfo", "?[-v]", "print CPUs and runnable threads", cpuinfo },
	{ "did2thread", "? kt_did", "find kernel thread for this id",
		did2thread },
	{ "errorq", "?[-v]", "display kernel error queues", errorq },
	{ "fd", ":[fd num]", "get a file pointer from an fd", fd },
	{ "flipone", ":", "the vik_rev_level 2 special", flipone },
	{ "lminfo", NULL, "print lock manager information", lminfo },
	{ "ndi_event_hdl", "?", "print ndi_event_hdl", ndi_event_hdl },
	{ "panicinfo", NULL, "print panic information", panicinfo },
	{ "pid2proc", "?", "convert PID to proc_t address", pid2proc },
	{ "project", NULL, "display kernel project(s)", project },
	{ "ps", "[-fltzTP]", "list processes (and associated thr,lwp)", ps },
	{ "pgrep", "[-x] [-n | -o] pattern",
		"pattern match against all processes", pgrep },
	{ "ptree", NULL, "print process tree", ptree },
	{ "sysevent", "?[-sv]", "print sysevent pending or sent queue",
		sysevent},
	{ "sysevent_channel", "?", "print sysevent channel database",
		sysevent_channel},
	{ "sysevent_class_list", ":", "print sysevent class list",
		sysevent_class_list},
	{ "sysevent_subclass_list", ":",
		"print sysevent subclass list", sysevent_subclass_list},
	{ "system", NULL, "print contents of /etc/system file", sysfile },
	{ "task", NULL, "display kernel task(s)", task },
	{ "time", "[-dlx]", "display system time", time, time_help },
	{ "vnode2path", ":[-F]", "vnode address to pathname", vnode2path },
	{ "whereopen", ":", "given a vnode, dumps procs which have it open",
	    whereopen },

	/* from bio.c */
	{ "bufpagefind", ":addr", "find page_t on buf_t list", bufpagefind },

	/* from bitset.c */
	{ "bitset", ":", "display a bitset", bitset, bitset_help },

	/* from contract.c */
	{ "contract", "?", "display a contract", cmd_contract },
	{ "ctevent", ":", "display a contract event", cmd_ctevent },
	{ "ctid", ":", "convert id to a contract pointer", cmd_ctid },

	/* from cpupart.c */
	{ "cpupart", "?[-v]", "print cpu partition info", cpupart },

	/* from cred.c */
	{ "cred", ":[-v]", "display a credential", cmd_cred },
	{ "credgrp", ":[-v]", "display cred_t groups", cmd_credgrp },
	{ "credsid", ":[-v]", "display a credsid_t", cmd_credsid },
	{ "ksidlist", ":[-v]", "display a ksidlist_t", cmd_ksidlist },

	/* from cyclic.c */
	{ "cyccover", NULL, "dump cyclic coverage information", cyccover },
	{ "cycid", "?", "dump a cyclic id", cycid },
	{ "cycinfo", "?", "dump cyc_cpu info", cycinfo },
	{ "cyclic", ":", "developer information", cyclic },
	{ "cyctrace", "?", "dump cyclic trace buffer", cyctrace },

	/* from damap.c */
	{ "damap", ":", "display a damap_t", damap, damap_help },

	/* from ddi_periodic.c */
	{ "ddi_periodic", "?[-v]", "dump ddi_periodic_impl_t info", dprinfo },

	/* from devinfo.c */
	{ "devbindings", "?[-qs] [device-name | major-num]",
	    "print devinfo nodes bound to device-name or major-num",
	    devbindings, devinfo_help },
	{ "devinfo", ":[-qs]", "detailed devinfo of one node", devinfo,
	    devinfo_help },
	{ "devinfo_audit", ":[-v]", "devinfo configuration audit record",
	    devinfo_audit },
	{ "devinfo_audit_log", "?[-v]", "system wide devinfo configuration log",
	    devinfo_audit_log },
	{ "devinfo_audit_node", ":[-v]", "devinfo node configuration history",
	    devinfo_audit_node },
	{ "devinfo2driver", ":", "find driver name for this devinfo node",
	    devinfo2driver },
	{ "devnames", "?[-vm] [num]", "print devnames array", devnames },
	{ "dev2major", "?<dev_t>", "convert dev_t to a major number",
	    dev2major },
	{ "dev2minor", "?<dev_t>", "convert dev_t to a minor number",
	    dev2minor },
	{ "devt", "?<dev_t>", "display a dev_t's major and minor numbers",
	    devt },
	{ "major2name", "?<major-num>", "convert major number to dev name",
	    major2name },
	{ "minornodes", ":", "given a devinfo node, print its minor nodes",
	    minornodes },
	{ "modctl2devinfo", ":", "given a modctl, list its devinfos",
	    modctl2devinfo },
	{ "name2major", "<dev-name>", "convert dev name to major number",
	    name2major },
	{ "prtconf", "?[-vpc]", "print devinfo tree", prtconf, prtconf_help },
	{ "softstate", ":<instance>", "retrieve soft-state pointer",
	    softstate },
	{ "devinfo_fm", ":", "devinfo fault managment configuration",
	    devinfo_fm },
	{ "devinfo_fmce", ":", "devinfo fault managment cache entry",
	    devinfo_fmce},

	/* from findstack.c */
	{ "findstack", ":[-v]", "find kernel thread stack", findstack },
	{ "findstack_debug", NULL, "toggle findstack debugging",
		findstack_debug },
	{ "stacks", "?[-afiv] [-c func] [-C func] [-m module] [-M module] "
		"[-s sobj | -S sobj] [-t tstate | -T tstate]",
		"print unique kernel thread stacks",
		stacks, stacks_help },

	/* from fm.c */
	{ "ereport", "[-v]", "print ereports logged in dump",
	    ereport },

	/* from group.c */
	{ "group", "?[-q]", "display a group", group},

	/* from hotplug.c */
	{ "hotplug", "?[-p]", "display a registered hotplug attachment",
	    hotplug, hotplug_help },

	/* from irm.c */
	{ "irmpools", NULL, "display interrupt pools", irmpools_dcmd },
	{ "irmreqs", NULL, "display interrupt requests in an interrupt pool",
	    irmreqs_dcmd },
	{ "irmreq", NULL, "display an interrupt request", irmreq_dcmd },

	/* from kgrep.c + genunix.c */
	{ "kgrep", KGREP_USAGE, "search kernel as for a pointer", kgrep,
		kgrep_help },

	/* from kmem.c */
	{ "allocdby", ":", "given a thread, print its allocated buffers",
		allocdby },
	{ "bufctl", ":[-vh] [-a addr] [-c caller] [-e earliest] [-l latest] "
		"[-t thd]", "print or filter a bufctl", bufctl, bufctl_help },
	{ "freedby", ":", "given a thread, print its freed buffers", freedby },
	{ "kmalog", "?[ fail | slab ]",
	    "display kmem transaction log and stack traces", kmalog },
	{ "kmastat", "[-kmg]", "kernel memory allocator stats",
	    kmastat },
	{ "kmausers", "?[-ef] [cache ...]", "current medium and large users "
		"of the kmem allocator", kmausers, kmausers_help },
	{ "kmem_cache", "?[-n name]",
		"print kernel memory caches", kmem_cache, kmem_cache_help},
	{ "kmem_slabs", "?[-v] [-n cache] [-N cache] [-b maxbins] "
		"[-B minbinsize]", "display slab usage per kmem cache",
		kmem_slabs, kmem_slabs_help },
	{ "kmem_debug", NULL, "toggle kmem dcmd/walk debugging", kmem_debug },
	{ "kmem_log", "?[-b]", "dump kmem transaction log", kmem_log },
	{ "kmem_verify", "?", "check integrity of kmem-managed memory",
		kmem_verify },
	{ "vmem", "?", "print a vmem_t", vmem },
	{ "vmem_seg", ":[-sv] [-c caller] [-e earliest] [-l latest] "
		"[-m minsize] [-M maxsize] [-t thread] [-T type]",
		"print or filter a vmem_seg", vmem_seg, vmem_seg_help },
	{ "whatthread", ":[-v]", "print threads whose stack contains the "
		"given address", whatthread },

	/* from ldi.c */
	{ "ldi_handle", "?[-i]", "display a layered driver handle",
	    ldi_handle, ldi_handle_help },
	{ "ldi_ident", NULL, "display a layered driver identifier",
	    ldi_ident, ldi_ident_help },

	/* from leaky.c + leaky_subr.c */
	{ "findleaks", FINDLEAKS_USAGE,
	    "search for potential kernel memory leaks", findleaks,
	    findleaks_help },

	/* from lgrp.c */
	{ "lgrp", "?[-q] [-p | -Pih]", "display an lgrp", lgrp},
	{ "lgrp_set", "", "display bitmask of lgroups as a list", lgrp_set},

	/* from log.c */
	{ "msgbuf", "?[-v]", "print most recent console messages", msgbuf },

	/* from mdi.c */
	{ "mdipi", NULL, "given a path, dump mdi_pathinfo "
		"and detailed pi_prop list", mdipi },
	{ "mdiprops", NULL, "given a pi_prop, dump the pi_prop list",
		mdiprops },
	{ "mdiphci", NULL, "given a phci, dump mdi_phci and "
		"list all paths", mdiphci },
	{ "mdivhci", NULL, "given a vhci, dump mdi_vhci and list "
		"all phcis", mdivhci },
	{ "mdiclient_paths", NULL, "given a path, walk mdi_pathinfo "
		"client links", mdiclient_paths },
	{ "mdiphci_paths", NULL, "given a path, walk through mdi_pathinfo "
		"phci links", mdiphci_paths },
	{ "mdiphcis", NULL, "given a phci, walk through mdi_phci ph_next links",
		mdiphcis },

	/* from memory.c */
	{ "addr2smap", ":[offset]", "translate address to smap", addr2smap },
	{ "memlist", "?[-iav]", "display a struct memlist", memlist },
	{ "memstat", NULL, "display memory usage summary", memstat },
	{ "page", "?", "display a summarized page_t", page },
	{ "pagelookup", "?[-v vp] [-o offset]",
		"find the page_t with the name {vp, offset}",
		pagelookup, pagelookup_help },
	{ "page_num2pp", ":", "find the page_t for a given page frame number",
		page_num2pp },
	{ "pmap", ":[-q]", "print process memory map", pmap },
	{ "seg", ":", "print address space segment", seg },
	{ "swapinfo", "?", "display a struct swapinfo", swapinfof },
	{ "vnode2smap", ":[offset]", "translate vnode to smap", vnode2smap },

	/* from mmd.c */
	{ "multidata", ":[-sv]", "display a summarized multidata_t",
		multidata },
	{ "pattbl", ":", "display a summarized multidata attribute table",
		pattbl },
	{ "pattr2multidata", ":", "print multidata pointer from pattr_t",
		pattr2multidata },
	{ "pdesc2slab", ":", "print pdesc slab pointer from pdesc_t",
		pdesc2slab },
	{ "pdesc_verify", ":", "verify integrity of a pdesc_t", pdesc_verify },
	{ "slab2multidata", ":", "print multidata pointer from pdesc_slab_t",
		slab2multidata },

	/* from modhash.c */
	{ "modhash", "?[-ceht] [-k key] [-v val] [-i index]",
		"display information about one or all mod_hash structures",
		modhash, modhash_help },
	{ "modent", ":[-k | -v | -t type]",
		"display information about a mod_hash_entry", modent,
		modent_help },

	/* from net.c */
	{ "dladm", "?<sub-command> [flags]", "show data link information",
		dladm, dladm_help },
	{ "mi", ":[-p] [-d | -m]", "filter and display MI object or payload",
		mi },
	{ "netstat", "[-arv] [-f inet | inet6 | unix] [-P tcp | udp | icmp]",
		"show network statistics", netstat },
	{ "sonode", "?[-f inet | inet6 | unix | #] "
		"[-t stream | dgram | raw | #] [-p #]",
		"filter and display sonode", sonode },

	/* from netstack.c */
	{ "netstack", "", "show stack instances", netstack },
	{ "netstackid2netstack", ":",
		"translate a netstack id to its netstack_t",
		netstackid2netstack },

	/* from nvpair.c */
	{ NVPAIR_DCMD_NAME, NVPAIR_DCMD_USAGE, NVPAIR_DCMD_DESCR,
		nvpair_print },
	{ NVLIST_DCMD_NAME, NVLIST_DCMD_USAGE, NVLIST_DCMD_DESCR,
		print_nvlist },

	/* from pg.c */
	{ "pg", "?[-q]", "display a pg", pg},

	/* from rctl.c */
	{ "rctl_dict", "?", "print systemwide default rctl definitions",
		rctl_dict },
	{ "rctl_list", ":[handle]", "print rctls for the given proc",
		rctl_list },
	{ "rctl", ":[handle]", "print a rctl_t, only if it matches the handle",
		rctl },
	{ "rctl_validate", ":[-v] [-n #]", "test resource control value "
		"sequence", rctl_validate },

	/* from sobj.c */
	{ "rwlock", ":", "dump out a readers/writer lock", rwlock },
	{ "mutex", ":[-f]", "dump out an adaptive or spin mutex", mutex,
		mutex_help },
	{ "sobj2ts", ":", "perform turnstile lookup on synch object", sobj2ts },
	{ "wchaninfo", "?[-v]", "dump condition variable", wchaninfo },
	{ "turnstile", "?", "display a turnstile", turnstile },

	/* from stream.c */
	{ "mblk", ":[-q|v] [-f|F flag] [-t|T type] [-l|L|B len] [-d dbaddr]",
		"print an mblk", mblk_prt, mblk_help },
	{ "mblk_verify", "?", "verify integrity of an mblk", mblk_verify },
	{ "mblk2dblk", ":", "convert mblk_t address to dblk_t address",
		mblk2dblk },
	{ "q2otherq", ":", "print peer queue for a given queue", q2otherq },
	{ "q2rdq", ":", "print read queue for a given queue", q2rdq },
	{ "q2syncq", ":", "print syncq for a given queue", q2syncq },
	{ "q2stream", ":", "print stream pointer for a given queue", q2stream },
	{ "q2wrq", ":", "print write queue for a given queue", q2wrq },
	{ "queue", ":[-q|v] [-m mod] [-f flag] [-F flag] [-s syncq_addr]",
		"filter and display STREAM queue", queue, queue_help },
	{ "stdata", ":[-q|v] [-f flag] [-F flag]",
		"filter and display STREAM head", stdata, stdata_help },
	{ "str2mate", ":", "print mate of this stream", str2mate },
	{ "str2wrq", ":", "print write queue of this stream", str2wrq },
	{ "stream", ":", "display STREAM", stream },
	{ "strftevent", ":", "print STREAMS flow trace event", strftevent },
	{ "syncq", ":[-q|v] [-f flag] [-F flag] [-t type] [-T type]",
		"filter and display STREAM sync queue", syncq, syncq_help },
	{ "syncq2q", ":", "print queue for a given syncq", syncq2q },

	/* from taskq.c */
	{ "taskq", ":[-atT] [-m min_maxq] [-n name]",
	    "display a taskq", taskq, taskq_help },
	{ "taskq_entry", ":", "display a taskq_ent_t", taskq_ent },

	/* from thread.c */
	{ "thread", "?[-bdfimps]", "display a summarized kthread_t", thread,
		thread_help },
	{ "threadlist", "?[-t] [-v [count]]",
		"display threads and associated C stack traces", threadlist,
		threadlist_help },
	{ "stackinfo", "?[-h|-a]", "display kthread_t stack usage", stackinfo,
		stackinfo_help },

	/* from tsd.c */
	{ "tsd", ":-k key", "print tsd[key-1] for this thread", ttotsd },
	{ "tsdtot", ":", "find thread with this tsd", tsdtot },

	/*
	 * typegraph does not work under kmdb, as it requires too much memory
	 * for its internal data structures.
	 */
#ifndef _KMDB
	/* from typegraph.c */
	{ "findlocks", ":", "find locks held by specified thread", findlocks },
	{ "findfalse", "?[-v]", "find potentially falsely shared structures",
		findfalse },
	{ "typegraph", NULL, "build type graph", typegraph },
	{ "istype", ":type", "manually set object type", istype },
	{ "notype", ":", "manually clear object type", notype },
	{ "whattype", ":", "determine object type", whattype },
#endif

	/* from vfs.c */
	{ "fsinfo", "?[-v]", "print mounted filesystems", fsinfo },
	{ "pfiles", ":[-fp]", "print process file information", pfiles,
		pfiles_help },

	/* from zone.c */
	{ "zid2zone", ":", "find the zone_t with the given zone id",
		zid2zone },
	{ "zone", "?[-r [-v]]", "display kernel zone(s)", zoneprt },
	{ "zsd", ":[-v] [zsd_key]", "display zone-specific-data entries for "
	    "selected zones", zsd },

#ifndef _KMDB
	{ "gcore", NULL, "generate a user core for the given process",
	    gcore_dcmd },
#endif

	{ NULL }
};

static const mdb_walker_t walkers[] = {

	/* from genunix.c */
	{ "callouts_bytime", "walk callouts by list chain (expiration time)",
		callout_walk_init, callout_walk_step, callout_walk_fini,
		(void *)CALLOUT_WALK_BYLIST },
	{ "callouts_byid", "walk callouts by id hash chain",
		callout_walk_init, callout_walk_step, callout_walk_fini,
		(void *)CALLOUT_WALK_BYID },
	{ "callout_list", "walk a callout list", callout_list_walk_init,
		callout_list_walk_step, callout_list_walk_fini },
	{ "callout_table", "walk callout table array", callout_table_walk_init,
		callout_table_walk_step, callout_table_walk_fini },
	{ "cpu", "walk cpu structures", cpu_walk_init, cpu_walk_step },
	{ "ereportq_dump", "walk list of ereports in dump error queue",
		ereportq_dump_walk_init, ereportq_dump_walk_step, NULL },
	{ "ereportq_pend", "walk list of ereports in pending error queue",
		ereportq_pend_walk_init, ereportq_pend_walk_step, NULL },
	{ "errorq", "walk list of system error queues",
		errorq_walk_init, errorq_walk_step, NULL },
	{ "errorq_data", "walk pending error queue data buffers",
		eqd_walk_init, eqd_walk_step, eqd_walk_fini },
	{ "allfile", "given a proc pointer, list all file pointers",
		file_walk_init, allfile_walk_step, file_walk_fini },
	{ "file", "given a proc pointer, list of open file pointers",
		file_walk_init, file_walk_step, file_walk_fini },
	{ "lock_descriptor", "walk lock_descriptor_t structures",
		ld_walk_init, ld_walk_step, NULL },
	{ "lock_graph", "walk lock graph",
		lg_walk_init, lg_walk_step, NULL },
	{ "port", "given a proc pointer, list of created event ports",
		port_walk_init, port_walk_step, NULL },
	{ "portev", "given a port pointer, list of events in the queue",
		portev_walk_init, portev_walk_step, portev_walk_fini },
	{ "proc", "list of active proc_t structures",
		proc_walk_init, proc_walk_step, proc_walk_fini },
	{ "projects", "walk a list of kernel projects",
		project_walk_init, project_walk_step, NULL },
	{ "sysevent_pend", "walk sysevent pending queue",
		sysevent_pend_walk_init, sysevent_walk_step,
		sysevent_walk_fini},
	{ "sysevent_sent", "walk sysevent sent queue", sysevent_sent_walk_init,
		sysevent_walk_step, sysevent_walk_fini},
	{ "sysevent_channel", "walk sysevent channel subscriptions",
		sysevent_channel_walk_init, sysevent_channel_walk_step,
		sysevent_channel_walk_fini},
	{ "sysevent_class_list", "walk sysevent subscription's class list",
		sysevent_class_list_walk_init, sysevent_class_list_walk_step,
		sysevent_class_list_walk_fini},
	{ "sysevent_subclass_list",
		"walk sysevent subscription's subclass list",
		sysevent_subclass_list_walk_init,
		sysevent_subclass_list_walk_step,
		sysevent_subclass_list_walk_fini},
	{ "task", "given a task pointer, walk its processes",
		task_walk_init, task_walk_step, NULL },

	/* from avl.c */
	{ AVL_WALK_NAME, AVL_WALK_DESC,
		avl_walk_init, avl_walk_step, avl_walk_fini },

	/* from bio.c */
	{ "buf", "walk the bio buf hash",
		buf_walk_init, buf_walk_step, buf_walk_fini },

	/* from contract.c */
	{ "contract", "walk all contracts, or those of the specified type",
		ct_walk_init, generic_walk_step, NULL },
	{ "ct_event", "walk events on a contract event queue",
		ct_event_walk_init, generic_walk_step, NULL },
	{ "ct_listener", "walk contract event queue listeners",
		ct_listener_walk_init, generic_walk_step, NULL },

	/* from cpupart.c */
	{ "cpupart_cpulist", "given an cpupart_t, walk cpus in partition",
		cpupart_cpulist_walk_init, cpupart_cpulist_walk_step,
		NULL },
	{ "cpupart_walk", "walk the set of cpu partitions",
		cpupart_walk_init, cpupart_walk_step, NULL },

	/* from ctxop.c */
	{ "ctxop", "walk list of context ops on a thread",
		ctxop_walk_init, ctxop_walk_step, ctxop_walk_fini },

	/* from cyclic.c */
	{ "cyccpu", "walk per-CPU cyc_cpu structures",
		cyccpu_walk_init, cyccpu_walk_step, NULL },
	{ "cycomni", "for an omnipresent cyclic, walk cyc_omni_cpu list",
		cycomni_walk_init, cycomni_walk_step, NULL },
	{ "cyctrace", "walk cyclic trace buffer",
		cyctrace_walk_init, cyctrace_walk_step, cyctrace_walk_fini },

	/* from devinfo.c */
	{ "binding_hash", "walk all entries in binding hash table",
		binding_hash_walk_init, binding_hash_walk_step, NULL },
	{ "devinfo", "walk devinfo tree or subtree",
		devinfo_walk_init, devinfo_walk_step, devinfo_walk_fini },
	{ "devinfo_audit_log", "walk devinfo audit system-wide log",
		devinfo_audit_log_walk_init, devinfo_audit_log_walk_step,
		devinfo_audit_log_walk_fini},
	{ "devinfo_audit_node", "walk per-devinfo audit history",
		devinfo_audit_node_walk_init, devinfo_audit_node_walk_step,
		devinfo_audit_node_walk_fini},
	{ "devinfo_children", "walk children of devinfo node",
		devinfo_children_walk_init, devinfo_children_walk_step,
		devinfo_children_walk_fini },
	{ "devinfo_parents", "walk ancestors of devinfo node",
		devinfo_parents_walk_init, devinfo_parents_walk_step,
		devinfo_parents_walk_fini },
	{ "devinfo_siblings", "walk siblings of devinfo node",
		devinfo_siblings_walk_init, devinfo_siblings_walk_step, NULL },
	{ "devi_next", "walk devinfo list",
		NULL, devi_next_walk_step, NULL },
	{ "devnames", "walk devnames array",
		devnames_walk_init, devnames_walk_step, devnames_walk_fini },
	{ "minornode", "given a devinfo node, walk minor nodes",
		minornode_walk_init, minornode_walk_step, NULL },
	{ "softstate",
		"given an i_ddi_soft_state*, list all in-use driver stateps",
		soft_state_walk_init, soft_state_walk_step,
		NULL, NULL },
	{ "softstate_all",
		"given an i_ddi_soft_state*, list all driver stateps",
		soft_state_walk_init, soft_state_all_walk_step,
		NULL, NULL },
	{ "devinfo_fmc",
		"walk a fault management handle cache active list",
		devinfo_fmc_walk_init, devinfo_fmc_walk_step, NULL },

	/* from group.c */
	{ "group", "walk all elements of a group",
		group_walk_init, group_walk_step, NULL },

	/* from irm.c */
	{ "irmpools", "walk global list of interrupt pools",
	    irmpools_walk_init, list_walk_step, list_walk_fini },
	{ "irmreqs", "walk list of interrupt requests in an interrupt pool",
	    irmreqs_walk_init, list_walk_step, list_walk_fini },

	/* from kmem.c */
	{ "allocdby", "given a thread, walk its allocated bufctls",
		allocdby_walk_init, allocdby_walk_step, allocdby_walk_fini },
	{ "bufctl", "walk a kmem cache's bufctls",
		bufctl_walk_init, kmem_walk_step, kmem_walk_fini },
	{ "bufctl_history", "walk the available history of a bufctl",
		bufctl_history_walk_init, bufctl_history_walk_step,
		bufctl_history_walk_fini },
	{ "freedby", "given a thread, walk its freed bufctls",
		freedby_walk_init, allocdby_walk_step, allocdby_walk_fini },
	{ "freectl", "walk a kmem cache's free bufctls",
		freectl_walk_init, kmem_walk_step, kmem_walk_fini },
	{ "freectl_constructed", "walk a kmem cache's constructed free bufctls",
		freectl_constructed_walk_init, kmem_walk_step, kmem_walk_fini },
	{ "freemem", "walk a kmem cache's free memory",
		freemem_walk_init, kmem_walk_step, kmem_walk_fini },
	{ "freemem_constructed", "walk a kmem cache's constructed free memory",
		freemem_constructed_walk_init, kmem_walk_step, kmem_walk_fini },
	{ "kmem", "walk a kmem cache",
		kmem_walk_init, kmem_walk_step, kmem_walk_fini },
	{ "kmem_cpu_cache", "given a kmem cache, walk its per-CPU caches",
		kmem_cpu_cache_walk_init, kmem_cpu_cache_walk_step, NULL },
	{ "kmem_hash", "given a kmem cache, walk its allocated hash table",
		kmem_hash_walk_init, kmem_hash_walk_step, kmem_hash_walk_fini },
	{ "kmem_log", "walk the kmem transaction log",
		kmem_log_walk_init, kmem_log_walk_step, kmem_log_walk_fini },
	{ "kmem_slab", "given a kmem cache, walk its slabs",
		kmem_slab_walk_init, combined_walk_step, combined_walk_fini },
	{ "kmem_slab_partial",
	    "given a kmem cache, walk its partially allocated slabs (min 1)",
		kmem_slab_walk_partial_init, combined_walk_step,
		combined_walk_fini },
	{ "vmem", "walk vmem structures in pre-fix, depth-first order",
		vmem_walk_init, vmem_walk_step, vmem_walk_fini },
	{ "vmem_alloc", "given a vmem_t, walk its allocated vmem_segs",
		vmem_alloc_walk_init, vmem_seg_walk_step, vmem_seg_walk_fini },
	{ "vmem_free", "given a vmem_t, walk its free vmem_segs",
		vmem_free_walk_init, vmem_seg_walk_step, vmem_seg_walk_fini },
	{ "vmem_postfix", "walk vmem structures in post-fix, depth-first order",
		vmem_walk_init, vmem_postfix_walk_step, vmem_walk_fini },
	{ "vmem_seg", "given a vmem_t, walk all of its vmem_segs",
		vmem_seg_walk_init, vmem_seg_walk_step, vmem_seg_walk_fini },
	{ "vmem_span", "given a vmem_t, walk its spanning vmem_segs",
		vmem_span_walk_init, vmem_seg_walk_step, vmem_seg_walk_fini },

	/* from ldi.c */
	{ "ldi_handle", "walk the layered driver handle hash",
		ldi_handle_walk_init, ldi_handle_walk_step, NULL },
	{ "ldi_ident", "walk the layered driver identifier hash",
		ldi_ident_walk_init, ldi_ident_walk_step, NULL },

	/* from leaky.c + leaky_subr.c */
	{ "leak", "given a leaked bufctl or vmem_seg, find leaks w/ same "
	    "stack trace",
		leaky_walk_init, leaky_walk_step, leaky_walk_fini },
	{ "leakbuf", "given a leaked bufctl or vmem_seg, walk buffers for "
	    "leaks w/ same stack trace",
		leaky_walk_init, leaky_buf_walk_step, leaky_walk_fini },

	/* from lgrp.c */
	{ "lgrp_cpulist", "walk CPUs in a given lgroup",
		lgrp_cpulist_walk_init, lgrp_cpulist_walk_step, NULL },
	{ "lgrptbl", "walk lgroup table",
		lgrp_walk_init, lgrp_walk_step, NULL },
	{ "lgrp_parents", "walk up lgroup lineage from given lgroup",
		lgrp_parents_walk_init, lgrp_parents_walk_step, NULL },
	{ "lgrp_rsrc_mem", "walk lgroup memory resources of given lgroup",
		lgrp_rsrc_mem_walk_init, lgrp_set_walk_step, NULL },
	{ "lgrp_rsrc_cpu", "walk lgroup CPU resources of given lgroup",
		lgrp_rsrc_cpu_walk_init, lgrp_set_walk_step, NULL },

	/* from list.c */
	{ LIST_WALK_NAME, LIST_WALK_DESC,
		list_walk_init, list_walk_step, list_walk_fini },

	/* from mdi.c */
	{ "mdipi_client_list", "Walker for mdi_pathinfo pi_client_link",
		mdi_pi_client_link_walk_init,
		mdi_pi_client_link_walk_step,
		mdi_pi_client_link_walk_fini },
	{ "mdipi_phci_list", "Walker for mdi_pathinfo pi_phci_link",
		mdi_pi_phci_link_walk_init,
		mdi_pi_phci_link_walk_step,
		mdi_pi_phci_link_walk_fini },
	{ "mdiphci_list", "Walker for mdi_phci ph_next link",
		mdi_phci_ph_next_walk_init,
		mdi_phci_ph_next_walk_step,
		mdi_phci_ph_next_walk_fini },

	/* from memory.c */
	{ "allpages", "walk all pages, including free pages",
		allpages_walk_init, allpages_walk_step, allpages_walk_fini },
	{ "anon", "given an amp, list allocated anon structures",
		anon_walk_init, anon_walk_step, anon_walk_fini,
		ANON_WALK_ALLOC },
	{ "anon_all", "given an amp, list contents of all anon slots",
		anon_walk_init, anon_walk_step, anon_walk_fini,
		ANON_WALK_ALL },
	{ "memlist", "walk specified memlist",
		NULL, memlist_walk_step, NULL },
	{ "page", "walk all pages, or those from the specified vnode",
		page_walk_init, page_walk_step, page_walk_fini },
	{ "seg", "given an as, list of segments",
		seg_walk_init, avl_walk_step, avl_walk_fini },
	{ "segvn_anon",
		"given a struct segvn_data, list allocated anon structures",
		segvn_anon_walk_init, anon_walk_step, anon_walk_fini,
		ANON_WALK_ALLOC },
	{ "segvn_anon_all",
		"given a struct segvn_data, list contents of all anon slots",
		segvn_anon_walk_init, anon_walk_step, anon_walk_fini,
		ANON_WALK_ALL },
	{ "segvn_pages",
		"given a struct segvn_data, list resident pages in "
		"offset order",
		segvn_pages_walk_init, segvn_pages_walk_step,
		segvn_pages_walk_fini, SEGVN_PAGES_RESIDENT },
	{ "segvn_pages_all",
		"for each offset in a struct segvn_data, give page_t pointer "
		"(if resident), or NULL.",
		segvn_pages_walk_init, segvn_pages_walk_step,
		segvn_pages_walk_fini, SEGVN_PAGES_ALL },
	{ "swapinfo", "walk swapinfo structures",
		swap_walk_init, swap_walk_step, NULL },

	/* from mmd.c */
	{ "pattr", "walk pattr_t structures", pattr_walk_init,
		mmdq_walk_step, mmdq_walk_fini },
	{ "pdesc", "walk pdesc_t structures",
		pdesc_walk_init, mmdq_walk_step, mmdq_walk_fini },
	{ "pdesc_slab", "walk pdesc_slab_t structures",
		pdesc_slab_walk_init, mmdq_walk_step, mmdq_walk_fini },

	/* from modhash.c */
	{ "modhash", "walk list of mod_hash structures", modhash_walk_init,
		modhash_walk_step, NULL },
	{ "modent", "walk list of entries in a given mod_hash",
		modent_walk_init, modent_walk_step, modent_walk_fini },
	{ "modchain", "walk list of entries in a given mod_hash_entry",
		NULL, modchain_walk_step, NULL },

	/* from net.c */
	{ "icmp", "walk ICMP control structures using MI for all stacks",
		mi_payload_walk_init, mi_payload_walk_step, NULL,
		&mi_icmp_arg },
	{ "mi", "given a MI_O, walk the MI",
		mi_walk_init, mi_walk_step, mi_walk_fini, NULL },
	{ "sonode", "given a sonode, walk its children",
		sonode_walk_init, sonode_walk_step, sonode_walk_fini, NULL },
	{ "icmp_stacks", "walk all the icmp_stack_t",
		icmp_stacks_walk_init, icmp_stacks_walk_step, NULL },
	{ "tcp_stacks", "walk all the tcp_stack_t",
		tcp_stacks_walk_init, tcp_stacks_walk_step, NULL },
	{ "udp_stacks", "walk all the udp_stack_t",
		udp_stacks_walk_init, udp_stacks_walk_step, NULL },

	/* from netstack.c */
	{ "netstack", "walk a list of kernel netstacks",
		netstack_walk_init, netstack_walk_step, NULL },

	/* from nvpair.c */
	{ NVPAIR_WALKER_NAME, NVPAIR_WALKER_DESCR,
		nvpair_walk_init, nvpair_walk_step, NULL },

	/* from rctl.c */
	{ "rctl_dict_list", "walk all rctl_dict_entry_t's from rctl_lists",
		rctl_dict_walk_init, rctl_dict_walk_step, NULL },
	{ "rctl_set", "given a rctl_set, walk all rctls", rctl_set_walk_init,
		rctl_set_walk_step, NULL },
	{ "rctl_val", "given a rctl_t, walk all rctl_val entries associated",
		rctl_val_walk_init, rctl_val_walk_step },

	/* from sobj.c */
	{ "blocked", "walk threads blocked on a given sobj",
		blocked_walk_init, blocked_walk_step, NULL },
	{ "wchan", "given a wchan, list of blocked threads",
		wchan_walk_init, wchan_walk_step, wchan_walk_fini },

	/* from stream.c */
	{ "b_cont", "walk mblk_t list using b_cont",
		mblk_walk_init, b_cont_step, mblk_walk_fini },
	{ "b_next", "walk mblk_t list using b_next",
		mblk_walk_init, b_next_step, mblk_walk_fini },
	{ "qlink", "walk queue_t list using q_link",
		queue_walk_init, queue_link_step, queue_walk_fini },
	{ "qnext", "walk queue_t list using q_next",
		queue_walk_init, queue_next_step, queue_walk_fini },
	{ "strftblk", "given a dblk_t, walk STREAMS flow trace event list",
		strftblk_walk_init, strftblk_step, strftblk_walk_fini },
	{ "readq", "walk read queue side of stdata",
		str_walk_init, strr_walk_step, str_walk_fini },
	{ "writeq", "walk write queue side of stdata",
		str_walk_init, strw_walk_step, str_walk_fini },

	/* from taskq.c */
	{ "taskq_thread", "given a taskq_t, list all of its threads",
		taskq_thread_walk_init,
		taskq_thread_walk_step,
		taskq_thread_walk_fini },
	{ "taskq_entry", "given a taskq_t*, list all taskq_ent_t in the list",
		taskq_ent_walk_init, taskq_ent_walk_step, NULL },

	/* from thread.c */
	{ "deathrow", "walk threads on both lwp_ and thread_deathrow",
		deathrow_walk_init, deathrow_walk_step, NULL },
	{ "cpu_dispq", "given a cpu_t, walk threads in dispatcher queues",
		cpu_dispq_walk_init, dispq_walk_step, dispq_walk_fini },
	{ "cpupart_dispq",
		"given a cpupart_t, walk threads in dispatcher queues",
		cpupart_dispq_walk_init, dispq_walk_step, dispq_walk_fini },
	{ "lwp_deathrow", "walk lwp_deathrow",
		lwp_deathrow_walk_init, deathrow_walk_step, NULL },
	{ "thread", "global or per-process kthread_t structures",
		thread_walk_init, thread_walk_step, thread_walk_fini },
	{ "thread_deathrow", "walk threads on thread_deathrow",
		thread_deathrow_walk_init, deathrow_walk_step, NULL },

	/* from tsd.c */
	{ "tsd", "walk list of thread-specific data",
		tsd_walk_init, tsd_walk_step, tsd_walk_fini },

	/* from tsol.c */
	{ "tnrh", "walk remote host cache structures",
	    tnrh_walk_init, tnrh_walk_step, tnrh_walk_fini },
	{ "tnrhtp", "walk remote host template structures",
	    tnrhtp_walk_init, tnrhtp_walk_step, tnrhtp_walk_fini },

	/*
	 * typegraph does not work under kmdb, as it requires too much memory
	 * for its internal data structures.
	 */
#ifndef _KMDB
	/* from typegraph.c */
	{ "typeconflict", "walk buffers with conflicting type inferences",
		typegraph_walk_init, typeconflict_walk_step },
	{ "typeunknown", "walk buffers with unknown types",
		typegraph_walk_init, typeunknown_walk_step },
#endif

	/* from vfs.c */
	{ "vfs", "walk file system list",
		vfs_walk_init, vfs_walk_step },

	/* from zone.c */
	{ "zone", "walk a list of kernel zones",
		zone_walk_init, zone_walk_step, NULL },
	{ "zsd", "walk list of zsd entries for a zone",
		zsd_walk_init, zsd_walk_step, NULL },

	{ NULL }
};

static const mdb_modinfo_t modinfo = { MDB_API_VERSION, dcmds, walkers };

/*ARGSUSED*/
static void
genunix_statechange_cb(void *ignored)
{
	/*
	 * Force ::findleaks and ::stacks to let go any cached state.
	 */
	leaky_cleanup(1);
	stacks_cleanup(1);

	kmem_statechange();	/* notify kmem */
}

const mdb_modinfo_t *
_mdb_init(void)
{
	kmem_init();

	(void) mdb_callback_add(MDB_CALLBACK_STCHG,
	    genunix_statechange_cb, NULL);

#ifndef _KMDB
	gcore_init();
#endif

	return (&modinfo);
}

void
_mdb_fini(void)
{
	leaky_cleanup(1);
	stacks_cleanup(1);
}
