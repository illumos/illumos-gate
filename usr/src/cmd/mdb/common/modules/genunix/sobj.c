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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <mdb/mdb_modapi.h>
#include <sys/types.h>
#include <sys/mutex.h>
#include <sys/thread.h>
#include <sys/condvar.h>
#include <sys/sleepq.h>
#include <sys/sobject.h>
#include <sys/rwlock_impl.h>
#include <sys/turnstile.h>
#include <sys/proc.h>
#include <sys/mutex_impl.h>

#include <stdio.h>

struct sobj_type_info {
	int		sobj_type;
	const char	*sobj_name;
	const char	*sobj_ops_name;
} sobj_types[] = {
	{ SOBJ_MUTEX,	"mutex",	"mutex_sobj_ops" },
	{ SOBJ_RWLOCK,	"rwlock",	"rw_sobj_ops" },
	{ SOBJ_CV,	"cv",		"cv_sobj_ops" },
	{ SOBJ_SEMA,	"sema",		"sema_sobj_ops" },
	{ SOBJ_USER,	"user",		"lwp_sobj_ops" },
	{ SOBJ_USER_PI,	"user_pi",	"lwp_sobj_pi_ops" },
	{ SOBJ_SHUTTLE,	"shuttle",	"shuttle_sobj_ops" }
};
#define	NUM_SOBJ_TYPES (sizeof (sobj_types) / sizeof (*sobj_types))

void
sobj_type_to_text(int type, char *out, size_t sz)
{
	int idx;
	if (type == SOBJ_NONE) {
		mdb_snprintf(out, sz, "<none>");
		return;
	}

	for (idx = 0; idx < NUM_SOBJ_TYPES; idx++) {
		struct sobj_type_info *info = &sobj_types[idx];
		if (info->sobj_type == type) {
			mdb_snprintf(out, sz, "%s",
			    sobj_types[idx].sobj_name);
			return;
		}
	}
	mdb_snprintf(out, sz, "<unk:%02x>", type);
}

void
sobj_ops_to_text(uintptr_t addr, char *out, size_t sz)
{
	sobj_ops_t ops;

	if (addr == 0) {
		mdb_snprintf(out, sz, "<none>");
		return;
	}
	if (mdb_vread(&ops, sizeof (ops), addr) == -1) {
		mdb_snprintf(out, sz, "??", ops.sobj_type);
		return;
	}

	sobj_type_to_text(ops.sobj_type, out, sz);
}

int
sobj_text_to_ops(const char *name, uintptr_t *sobj_ops_out)
{
	int idx;
	GElf_Sym sym;

	for (idx = 0; idx < NUM_SOBJ_TYPES; idx++) {
		struct sobj_type_info *info = &sobj_types[idx];
		if (strcasecmp(info->sobj_name, name) == 0) {
			if (mdb_lookup_by_name(info->sobj_ops_name,
			    &sym) == -1) {
				mdb_warn("unable to find symbol \"%s\"",
				    info->sobj_ops_name);
				return (-1);
			}
			*sobj_ops_out = (uintptr_t)sym.st_value;
			return (0);
		}
	}

	mdb_warn("sobj type \"%s\" unknown\n", name);
	return (-1);
}

void
sobj_type_walk(void (*cbfunc)(int, const char *, const char *, void *),
    void *cbarg)
{
	int idx;

	for (idx = 0; idx < NUM_SOBJ_TYPES; idx++) {
		struct sobj_type_info *info = &sobj_types[idx];
		cbfunc(info->sobj_type, info->sobj_name, info->sobj_ops_name,
		    cbarg);
	}
}

typedef struct wchan_walk_data {
	caddr_t *ww_seen;
	int ww_seen_size;
	int ww_seen_ndx;
	uintptr_t ww_thr;
	sleepq_head_t ww_sleepq[NSLEEPQ];
	int ww_sleepq_ndx;
	uintptr_t ww_compare;
} wchan_walk_data_t;

int
wchan_walk_init(mdb_walk_state_t *wsp)
{
	wchan_walk_data_t *ww =
	    mdb_zalloc(sizeof (wchan_walk_data_t), UM_SLEEP);

	if (mdb_readvar(&ww->ww_sleepq[0], "sleepq_head") == -1) {
		mdb_warn("failed to read sleepq");
		mdb_free(ww, sizeof (wchan_walk_data_t));
		return (WALK_ERR);
	}

	if ((ww->ww_compare = wsp->walk_addr) == 0) {
		if (mdb_readvar(&ww->ww_seen_size, "nthread") == -1) {
			mdb_warn("failed to read nthread");
			mdb_free(ww, sizeof (wchan_walk_data_t));
			return (WALK_ERR);
		}

		ww->ww_seen = mdb_alloc(ww->ww_seen_size *
		    sizeof (caddr_t), UM_SLEEP);
	} else {
		ww->ww_sleepq_ndx = SQHASHINDEX(wsp->walk_addr);
	}

	wsp->walk_data = ww;
	return (WALK_NEXT);
}

int
wchan_walk_step(mdb_walk_state_t *wsp)
{
	wchan_walk_data_t *ww = wsp->walk_data;
	sleepq_head_t *sq;
	kthread_t thr;
	uintptr_t t;
	int i;

again:
	/*
	 * Get the address of the first thread on the next sleepq in the
	 * sleepq hash.  If ww_compare is set, ww_sleepq_ndx is already
	 * set to the appropriate sleepq index for the desired cv.
	 */
	for (t = ww->ww_thr; t == 0; ) {
		if (ww->ww_sleepq_ndx == NSLEEPQ)
			return (WALK_DONE);

		sq = &ww->ww_sleepq[ww->ww_sleepq_ndx++];
		t = (uintptr_t)sq->sq_queue.sq_first;

		/*
		 * If we were looking for a specific cv and we're at the end
		 * of its sleepq, we're done walking.
		 */
		if (t == 0 && ww->ww_compare != 0)
			return (WALK_DONE);
	}

	/*
	 * Read in the thread.  If it's t_wchan pointer is NULL, the thread has
	 * woken up since we took a snapshot of the sleepq (i.e. we are probably
	 * being applied to a live system); we can't believe the t_link pointer
	 * anymore either, so just skip to the next sleepq index.
	 */
	if (mdb_vread(&thr, sizeof (thr), t) != sizeof (thr)) {
		mdb_warn("failed to read thread at %p", t);
		return (WALK_ERR);
	}

	if (thr.t_wchan == NULL) {
		ww->ww_thr = 0;
		goto again;
	}

	/*
	 * Set ww_thr to the address of the next thread in the sleepq list.
	 */
	ww->ww_thr = (uintptr_t)thr.t_link;

	/*
	 * If we're walking a specific cv, invoke the callback if we've
	 * found a match, or loop back to the top and read the next thread.
	 */
	if (ww->ww_compare != 0) {
		if (ww->ww_compare == (uintptr_t)thr.t_wchan)
			return (wsp->walk_callback(t, &thr, wsp->walk_cbdata));

		if (ww->ww_thr == 0)
			return (WALK_DONE);

		goto again;
	}

	/*
	 * If we're walking all cvs, seen if we've already encountered this one
	 * on the current sleepq.  If we have, skip to the next thread.
	 */
	for (i = 0; i < ww->ww_seen_ndx; i++) {
		if (ww->ww_seen[i] == thr.t_wchan)
			goto again;
	}

	/*
	 * If we're not at the end of a sleepq, save t_wchan; otherwise reset
	 * the seen index so our array is empty at the start of the next sleepq.
	 * If we hit seen_size this is a live kernel and nthread is now larger,
	 * cope by replacing the final element in our memory.
	 */
	if (ww->ww_thr != 0) {
		if (ww->ww_seen_ndx < ww->ww_seen_size)
			ww->ww_seen[ww->ww_seen_ndx++] = thr.t_wchan;
		else
			ww->ww_seen[ww->ww_seen_size - 1] = thr.t_wchan;
	} else
		ww->ww_seen_ndx = 0;

	return (wsp->walk_callback((uintptr_t)thr.t_wchan,
	    NULL, wsp->walk_cbdata));
}

void
wchan_walk_fini(mdb_walk_state_t *wsp)
{
	wchan_walk_data_t *ww = wsp->walk_data;

	mdb_free(ww->ww_seen, ww->ww_seen_size * sizeof (uintptr_t));
	mdb_free(ww, sizeof (wchan_walk_data_t));
}

struct wcdata {
	sobj_ops_t sobj;
	int nwaiters;
};

/*ARGSUSED*/
static int
wchaninfo_twalk(uintptr_t addr, const kthread_t *t, struct wcdata *wc)
{
	if (wc->sobj.sobj_type == SOBJ_NONE) {
		(void) mdb_vread(&wc->sobj, sizeof (sobj_ops_t),
		    (uintptr_t)t->t_sobj_ops);
	}

	wc->nwaiters++;
	return (WALK_NEXT);
}

static int
wchaninfo_vtwalk(uintptr_t addr, const kthread_t *t, int *first)
{
	proc_t p;

	(void) mdb_vread(&p, sizeof (p), (uintptr_t)t->t_procp);

	if (*first) {
		*first = 0;
		mdb_printf(":  %0?p %s\n", addr, p.p_user.u_comm);
	} else {
		mdb_printf("%*s%0?p %s\n", (int)(sizeof (uintptr_t) * 2 + 17),
		    "", addr, p.p_user.u_comm);
	}

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
wchaninfo_walk(uintptr_t addr, void *ignored, uint_t *verbose)
{
	struct wcdata wc;
	int first = 1;

	bzero(&wc, sizeof (wc));
	wc.sobj.sobj_type = SOBJ_NONE;

	if (mdb_pwalk("wchan", (mdb_walk_cb_t)wchaninfo_twalk, &wc, addr) < 0) {
		mdb_warn("failed to walk wchan %p", addr);
		return (WALK_NEXT);
	}

	mdb_printf("%0?p %4s %8d%s", addr,
	    wc.sobj.sobj_type == SOBJ_CV ? "cond" :
	    wc.sobj.sobj_type == SOBJ_SEMA ? "sema" : "??",
	    wc.nwaiters, (*verbose) ? "" : "\n");

	if (*verbose != 0 && wc.nwaiters != 0 && mdb_pwalk("wchan",
	    (mdb_walk_cb_t)wchaninfo_vtwalk, &first, addr) == -1) {
		mdb_warn("failed to walk waiters for wchan %p", addr);
		mdb_printf("\n");
	}

	return (WALK_NEXT);
}

int
wchaninfo(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t v = FALSE;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &v, NULL) != argc)
		return (DCMD_USAGE);

	if (v == TRUE) {
		mdb_printf("%-?s %-4s %8s   %-?s %s\n",
		    "ADDR", "TYPE", "NWAITERS", "THREAD", "PROC");
	} else
		mdb_printf("%-?s %-4s %8s\n", "ADDR", "TYPE", "NWAITERS");

	if (flags & DCMD_ADDRSPEC) {
		if (wchaninfo_walk(addr, NULL, &v) == WALK_ERR)
			return (DCMD_ERR);
	} else if (mdb_walk("wchan", (mdb_walk_cb_t)wchaninfo_walk, &v) == -1) {
		mdb_warn("failed to walk wchans");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

int
blocked_walk_init(mdb_walk_state_t *wsp)
{
	if ((wsp->walk_data = (void *)wsp->walk_addr) == NULL) {
		mdb_warn("must specify a sobj * for blocked walk");
		return (WALK_ERR);
	}

	wsp->walk_addr = 0;

	if (mdb_layered_walk("thread", wsp) == -1) {
		mdb_warn("couldn't walk 'thread'");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

int
blocked_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr = (uintptr_t)((const kthread_t *)wsp->walk_layer)->t_ts;
	uintptr_t taddr = wsp->walk_addr;
	turnstile_t ts;

	if (mdb_vread(&ts, sizeof (ts), addr) == -1) {
		mdb_warn("couldn't read %p's turnstile at %p", taddr, addr);
		return (WALK_ERR);
	}

	if (ts.ts_waiters == 0 || ts.ts_sobj != wsp->walk_data)
		return (WALK_NEXT);

	return (wsp->walk_callback(taddr, wsp->walk_layer, wsp->walk_cbdata));
}

typedef struct rwlock_block {
	struct rwlock_block *rw_next;
	int rw_qnum;
	uintptr_t rw_thread;
} rwlock_block_t;

static int
rwlock_walk(uintptr_t taddr, const kthread_t *t, rwlock_block_t **rwp)
{
	turnstile_t ts;
	uintptr_t addr = (uintptr_t)t->t_ts;
	rwlock_block_t *rw;
	int state, i;

	if (mdb_vread(&ts, sizeof (ts), addr) == -1) {
		mdb_warn("couldn't read %p's turnstile at %p", taddr, addr);
		return (WALK_ERR);
	}

	for (i = 0; i < TS_NUM_Q; i++) {
		if ((uintptr_t)t->t_sleepq ==
		    (uintptr_t)&ts.ts_sleepq[i] - (uintptr_t)&ts + addr)
			break;
	}

	if (i == TS_NUM_Q) {
		if ((state = mdb_get_state()) == MDB_STATE_DEAD ||
		    state == MDB_STATE_STOPPED) {
			/*
			 * This shouldn't happen post-mortem or under kmdb;
			 * the blocked walk returned a thread which wasn't
			 * actually blocked on its turnstile.  This may happen
			 * in-situ if the thread wakes up during the ::rwlock.
			 */
			mdb_warn("thread %p isn't blocked on ts %p\n",
			    taddr, addr);
			return (WALK_ERR);
		}

		return (WALK_NEXT);
	}

	rw = mdb_alloc(sizeof (rwlock_block_t), UM_SLEEP | UM_GC);

	rw->rw_next = *rwp;
	rw->rw_qnum = i;
	rw->rw_thread = taddr;
	*rwp = rw;

	return (WALK_NEXT);
}

/*
 * > rwd_rwlock::rwlock
 *             ADDR      OWNER/COUNT FLAGS          WAITERS
 *         7835dee8        READERS=1  B011      30004393d20 (W)
 *                                     ||
 *                 WRITE_WANTED -------+|
 *                  HAS_WAITERS --------+
 *
 * |--ADDR_WIDTH--| |--OWNR_WIDTH--|
 * |--LBL_OFFSET--||-LBL_WIDTH|
 * |--------------LONG-------------|
 * |------------WAITER_OFFSET------------|
 */

#ifdef _LP64
#define	RW_ADDR_WIDTH	16
#define	RW_OWNR_WIDTH	16
#else
#define	RW_ADDR_WIDTH	8
#define	RW_OWNR_WIDTH	11
#endif

#define	RW_LONG (RW_ADDR_WIDTH + 1 + RW_OWNR_WIDTH)
#define	RW_LBL_WIDTH 12
#define	RW_LBL_OFFSET (RW_ADDR_WIDTH + RW_OWNR_WIDTH - 3 - RW_LBL_WIDTH)
#define	RW_WAITER_OFFSET (RW_LONG + 6)

/* Access rwlock bits */
#define	RW_BIT(n, offon) (wwwh & (1 << (n)) ? offon[1] : offon[0])
#define	RW_BIT_SET(n) (wwwh & (1 << (n)))

/* Print a waiter (if any) and a newline */
#define	RW_NEWLINE \
	if (rw != NULL) { \
		int q = rw->rw_qnum; \
		mdb_printf(" %?p (%s)", rw->rw_thread, \
		    q == TS_READER_Q ? "R" : q == TS_WRITER_Q ? "W" : "?"); \
		rw = rw->rw_next; \
	} \
	mdb_printf("\n");

/*ARGSUSED*/
int
rwlock(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	rwlock_impl_t lock;
	rwlock_block_t *rw = NULL;
	uintptr_t wwwh;

	if (!(flags & DCMD_ADDRSPEC) || addr == 0 || argc != 0)
		return (DCMD_USAGE);

	if (mdb_vread(&lock, sizeof (lock), addr) == -1) {
		mdb_warn("failed to read rwlock at 0x%p", addr);
		return (DCMD_ERR);
	}

	if (mdb_pwalk("blocked", (mdb_walk_cb_t)rwlock_walk, &rw, addr) == -1) {
		mdb_warn("couldn't walk 'blocked' for sobj %p", addr);
		return (WALK_ERR);
	}

	mdb_printf("%?s %*s %5s %?s\n", "ADDR",
	    RW_OWNR_WIDTH, "OWNER/COUNT", "FLAGS", "WAITERS");

	mdb_printf("%?p ", addr);

	if (((wwwh = lock.rw_wwwh) & RW_DOUBLE_LOCK) == RW_DOUBLE_LOCK)
		mdb_printf("%*s", RW_OWNR_WIDTH, "1");
	else if ((wwwh = lock.rw_wwwh) & RW_WRITE_LOCKED)
		mdb_printf("%*p", RW_OWNR_WIDTH, wwwh & RW_OWNER);
	else {
		uintptr_t count = (wwwh & RW_HOLD_COUNT) >> RW_HOLD_COUNT_SHIFT;
		char c[20];

		mdb_snprintf(c, 20, "READERS=%ld", count);
		mdb_printf("%*s", RW_OWNR_WIDTH, count ? c : "-");
	}

	mdb_printf("  B%c%c%c",
	    RW_BIT(2, "01"), RW_BIT(1, "01"), RW_BIT(0, "01"));
	RW_NEWLINE;

	mdb_printf("%*s%c   %c%c%c", RW_LONG - 1, "",
	    " |"[(wwwh & RW_DOUBLE_LOCK) == RW_DOUBLE_LOCK],
	    RW_BIT(2, " |"), RW_BIT(1, " |"), RW_BIT(0, " |"));
	RW_NEWLINE;

	if ((wwwh & RW_DOUBLE_LOCK) == RW_DOUBLE_LOCK) {
		mdb_printf("%*s%*s --+---+", RW_LBL_OFFSET, "", RW_LBL_WIDTH,
		    "DESTROYED");
		goto no_zero;
	}

	if (!RW_BIT_SET(2))
		goto no_two;

	mdb_printf("%*s%*s ------+%c%c", RW_LBL_OFFSET, "", RW_LBL_WIDTH,
	    "WRITE_LOCKED", RW_BIT(1, " |"), RW_BIT(0, " |"));
	RW_NEWLINE;

no_two:
	if (!RW_BIT_SET(1))
		goto no_one;

	mdb_printf("%*s%*s -------+%c", RW_LBL_OFFSET, "", RW_LBL_WIDTH,
	    "WRITE_WANTED", RW_BIT(0, " |"));
	RW_NEWLINE;

no_one:
	if (!RW_BIT_SET(0))
		goto no_zero;

	mdb_printf("%*s%*s --------+", RW_LBL_OFFSET, "", RW_LBL_WIDTH,
	    "HAS_WAITERS");
	RW_NEWLINE;

no_zero:
	while (rw != NULL) {
		mdb_printf("%*s", RW_WAITER_OFFSET, "");
		RW_NEWLINE;
	}

	return (DCMD_OK);
}

int
mutex(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mutex_impl_t	lock;
	uint_t		force = FALSE;

	if (!(flags & DCMD_ADDRSPEC)) {
		return (DCMD_USAGE);
	}

	if (mdb_getopts(argc, argv,
	    'f', MDB_OPT_SETBITS, TRUE, &force, NULL) != argc) {
		return (DCMD_USAGE);
	}

	if (mdb_vread(&lock, sizeof (lock), addr) == -1) {
		mdb_warn("failed to read mutex at 0x%0?p", addr);
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%?s %5s %?s %6s %6s %7s%</u>\n",
		    "ADDR", "TYPE", "HELD", "MINSPL", "OLDSPL", "WAITERS");
	}

	if (MUTEX_TYPE_SPIN(&lock)) {
		struct spin_mutex *sp = &lock.m_spin;

		if (!force && (sp->m_filler != 0 ||
		    sp->m_minspl > PIL_MAX || sp->m_oldspl > PIL_MAX ||
		    (sp->m_spinlock != 0 && sp->m_spinlock != 0xff))) {
			mdb_warn("%a: invalid spin lock "
			    "(-f to dump anyway)\n", addr);
			return (DCMD_ERR);
		}

		if (sp->m_spinlock == 0xff) {
			mdb_printf("%0?p %5s %?s %6d %6d %7s\n",
			    addr, "spin", "yes", sp->m_minspl, sp->m_oldspl,
			    "-");
		} else {
			mdb_printf("%0?p %5s %?s %6d %6s %7s\n",
			    addr, "spin", "no", sp->m_minspl, "-", "-");
		}

	} else {
		kthread_t *owner = MUTEX_OWNER(&lock);
		char *waiters = MUTEX_HAS_WAITERS(&lock) ? "yes" : "no";

		if (!force && (!MUTEX_TYPE_ADAPTIVE(&lock) ||
		    (owner == NULL && MUTEX_HAS_WAITERS(&lock)))) {
			mdb_warn("%a: invalid adaptive mutex "
			    "(-f to dump anyway)\n", addr);
			return (DCMD_ERR);
		}

		if (owner != NULL) {
			mdb_printf("%0?p %5s %?p %6s %6s %7s\n",
			    addr, "adapt", owner, "-", "-", waiters);
		} else {
			mdb_printf("%0?p %5s %?s %6s %6s %7s\n",
			    addr, "adapt", "no", "-", "-", waiters);
		}
	}
	return (DCMD_OK);
}

void
mutex_help(void)
{
	mdb_printf("Options:\n"
	    "   -f    force printing even if the data seems to be"
	    " inconsistent\n");
}

int
turnstile(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	turnstile_t	t;

	if (argc != 0)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("turnstile_cache", "turnstile", argc, argv)
		    == -1) {
			mdb_warn("can't walk turnstiles");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%<u>%?s %?s %5s %4s %?s %?s%</u>\n",
		    "ADDR", "SOBJ", "WTRS", "EPRI", "ITOR", "PRIOINV");

	if (mdb_vread(&t, sizeof (turnstile_t), addr) == -1) {
		mdb_warn("can't read turnstile_t at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%0?p %?p %5d %4d %?p %?p\n",
	    addr, t.ts_sobj, t.ts_waiters, t.ts_epri,
	    t.ts_inheritor, t.ts_prioinv);

	return (DCMD_OK);
}

/*
 * Macros and structure definition copied from turnstile.c.
 * This is unfortunate, but half the macros we need aren't usable from
 * within mdb anyway.
 */
#define	TURNSTILE_HASH_SIZE	128		/* must be power of 2 */
#define	TURNSTILE_HASH_MASK	(TURNSTILE_HASH_SIZE - 1)
#define	TURNSTILE_SOBJ_HASH(sobj)	\
	((((int)sobj >> 2) + ((int)sobj >> 9)) & TURNSTILE_HASH_MASK)

typedef struct turnstile_chain {
	turnstile_t	*tc_first;	/* first turnstile on hash chain */
	disp_lock_t	tc_lock;	/* lock for this hash chain */
} turnstile_chain_t;

/*
 * Given the address of a blocked-upon synchronization object, return
 * the address of its turnstile.
 */

/*ARGSUSED*/
int
sobj2ts(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	GElf_Sym	sym;
	int		isupi;
	int		ttoff;
	uintptr_t	ttable;
	turnstile_t	ts, *tsp;
	turnstile_chain_t tc;

	if (!(flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	if (mdb_lookup_by_name("upimutextab", &sym) == -1) {
		mdb_warn("unable to reference upimutextab\n");
		return (DCMD_ERR);
	}
	isupi = addr - (uintptr_t)sym.st_value < sym.st_size;
	ttoff = (isupi ? 0 : TURNSTILE_HASH_SIZE) + TURNSTILE_SOBJ_HASH(addr);

	if (mdb_lookup_by_name("turnstile_table", &sym) == -1) {
		mdb_warn("unable to reference turnstile_table");
		return (DCMD_ERR);
	}
	ttable = (uintptr_t)sym.st_value + sizeof (turnstile_chain_t) * ttoff;

	if (mdb_vread(&tc, sizeof (turnstile_chain_t), ttable) == -1) {
		mdb_warn("unable to read turnstile_chain_t at %#lx", ttable);
		return (DCMD_ERR);
	}

	for (tsp = tc.tc_first; tsp != NULL; tsp = ts.ts_next) {
		if (mdb_vread(&ts, sizeof (turnstile_t),
		    (uintptr_t)tsp) == -1)  {
			mdb_warn("unable to read turnstile_t at %#p", tsp);
			return (DCMD_ERR);
		}
		if ((uintptr_t)ts.ts_sobj == addr) {
			mdb_printf("%p\n", tsp);
			break;
		}
	}

	return (DCMD_OK);
}
