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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2014, Joyent, Inc. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <thr_uberdata.h>
#include <thread_db.h>
#include <libc_int.h>

/*
 * Private structures.
 */

typedef union {
	mutex_t		lock;
	rwlock_t	rwlock;
	sema_t		semaphore;
	cond_t		condition;
} td_so_un_t;

struct td_thragent {
	rwlock_t	rwlock;
	struct ps_prochandle *ph_p;
	int		initialized;
	int		sync_tracking;
	int		model;
	int		primary_map;
	psaddr_t	bootstrap_addr;
	psaddr_t	uberdata_addr;
	psaddr_t	tdb_eventmask_addr;
	psaddr_t	tdb_register_sync_addr;
	psaddr_t	tdb_events[TD_MAX_EVENT_NUM - TD_MIN_EVENT_NUM + 1];
	psaddr_t	hash_table_addr;
	int		hash_size;
	lwpid_t		single_lwpid;
	psaddr_t	single_ulwp_addr;
};

/*
 * This is the name of the variable in libc that contains
 * the uberdata address that we will need.
 */
#define	TD_BOOTSTRAP_NAME	"_tdb_bootstrap"
/*
 * This is the actual name of uberdata, used in the event
 * that tdb_bootstrap has not yet been initialized.
 */
#define	TD_UBERDATA_NAME	"_uberdata"
/*
 * The library name should end with ".so.1", but older versions of
 * dbx expect the unadorned name and malfunction if ".1" is specified.
 * Unfortunately, if ".1" is not specified, mdb malfunctions when it
 * is applied to another instance of itself (due to the presence of
 * /usr/lib/mdb/proc/libc.so).  So we try it both ways.
 */
#define	TD_LIBRARY_NAME		"libc.so"
#define	TD_LIBRARY_NAME_1	"libc.so.1"

td_err_e __td_thr_get_info(td_thrhandle_t *th_p, td_thrinfo_t *ti_p);

td_err_e __td_ta_thr_iter(td_thragent_t *ta_p, td_thr_iter_f *cb,
	void *cbdata_p, td_thr_state_e state, int ti_pri,
	sigset_t *ti_sigmask_p, unsigned ti_user_flags);

/*
 * Initialize threads debugging interface.
 */
#pragma weak td_init = __td_init
td_err_e
__td_init()
{
	return (TD_OK);
}

/*
 * This function does nothing, and never did.
 * But the symbol is in the ABI, so we can't delete it.
 */
#pragma weak td_log = __td_log
void
__td_log()
{
}

/*
 * Short-cut to read just the hash table size from the process,
 * to avoid repeatedly reading the full uberdata structure when
 * dealing with a single-threaded process.
 */
static uint_t
td_read_hash_size(td_thragent_t *ta_p)
{
	psaddr_t addr;
	uint_t hash_size;

	switch (ta_p->initialized) {
	default:	/* uninitialized */
		return (0);
	case 1:		/* partially initialized */
		break;
	case 2:		/* fully initialized */
		return (ta_p->hash_size);
	}

	if (ta_p->model == PR_MODEL_NATIVE) {
		addr = ta_p->uberdata_addr + offsetof(uberdata_t, hash_size);
	} else {
#if defined(_LP64) && defined(_SYSCALL32)
		addr = ta_p->uberdata_addr + offsetof(uberdata32_t, hash_size);
#else
		addr = 0;
#endif
	}
	if (ps_pdread(ta_p->ph_p, addr, &hash_size, sizeof (hash_size))
	    != PS_OK)
		return (0);
	return (hash_size);
}

static td_err_e
td_read_uberdata(td_thragent_t *ta_p)
{
	struct ps_prochandle *ph_p = ta_p->ph_p;
	int i;

	if (ta_p->model == PR_MODEL_NATIVE) {
		uberdata_t uberdata;

		if (ps_pdread(ph_p, ta_p->uberdata_addr,
		    &uberdata, sizeof (uberdata)) != PS_OK)
			return (TD_DBERR);
		ta_p->primary_map = uberdata.primary_map;
		ta_p->tdb_eventmask_addr = ta_p->uberdata_addr +
		    offsetof(uberdata_t, tdb.tdb_ev_global_mask);
		ta_p->tdb_register_sync_addr = ta_p->uberdata_addr +
		    offsetof(uberdata_t, uberflags.uf_tdb_register_sync);
		ta_p->hash_table_addr = (psaddr_t)uberdata.thr_hash_table;
		ta_p->hash_size = uberdata.hash_size;
		if (ps_pdread(ph_p, (psaddr_t)uberdata.tdb.tdb_events,
		    ta_p->tdb_events, sizeof (ta_p->tdb_events)) != PS_OK)
			return (TD_DBERR);
	} else {
#if defined(_LP64) && defined(_SYSCALL32)
		uberdata32_t uberdata;
		caddr32_t tdb_events[TD_MAX_EVENT_NUM - TD_MIN_EVENT_NUM + 1];

		if (ps_pdread(ph_p, ta_p->uberdata_addr,
		    &uberdata, sizeof (uberdata)) != PS_OK)
			return (TD_DBERR);
		ta_p->primary_map = uberdata.primary_map;
		ta_p->tdb_eventmask_addr = ta_p->uberdata_addr +
		    offsetof(uberdata32_t, tdb.tdb_ev_global_mask);
		ta_p->tdb_register_sync_addr = ta_p->uberdata_addr +
		    offsetof(uberdata32_t, uberflags.uf_tdb_register_sync);
		ta_p->hash_table_addr = (psaddr_t)uberdata.thr_hash_table;
		ta_p->hash_size = uberdata.hash_size;
		if (ps_pdread(ph_p, (psaddr_t)uberdata.tdb.tdb_events,
		    tdb_events, sizeof (tdb_events)) != PS_OK)
			return (TD_DBERR);
		for (i = 0; i < TD_MAX_EVENT_NUM - TD_MIN_EVENT_NUM + 1; i++)
			ta_p->tdb_events[i] = tdb_events[i];
#else
		return (TD_DBERR);
#endif
	}

	/*
	 * Unfortunately, we are (implicitly) assuming that our uberdata
	 * definition precisely matches that of our target.  If this is not
	 * true (that is, if we're examining a core file from a foreign
	 * system that has a different definition of uberdata), the failure
	 * modes can be frustratingly non-explicit.  In an effort to catch
	 * this upon initialization (when the debugger may still be able to
	 * opt for another thread model or may be able to fail explicitly), we
	 * check that each of our tdb_events points to valid memory (these are
	 * putatively text upon which a breakpoint can be issued), with the
	 * hope that this is enough of a self-consistency check to lead to
	 * explicit failure on a mismatch.
	 */
	for (i = 0; i < TD_MAX_EVENT_NUM - TD_MIN_EVENT_NUM + 1; i++) {
		uint8_t check;

		if (ps_pdread(ph_p, (psaddr_t)ta_p->tdb_events[i],
		    &check, sizeof (check)) != PS_OK) {
			return (TD_DBERR);
		}
	}

	if (ta_p->hash_size != 1) {	/* multi-threaded */
		ta_p->initialized = 2;
		ta_p->single_lwpid = 0;
		ta_p->single_ulwp_addr = NULL;
	} else {			/* single-threaded */
		ta_p->initialized = 1;
		/*
		 * Get the address and lwpid of the single thread/LWP.
		 * It may not be ulwp_one if this is a child of fork1().
		 */
		if (ta_p->model == PR_MODEL_NATIVE) {
			thr_hash_table_t head;
			lwpid_t lwpid = 0;

			if (ps_pdread(ph_p, ta_p->hash_table_addr,
			    &head, sizeof (head)) != PS_OK)
				return (TD_DBERR);
			if ((psaddr_t)head.hash_bucket == NULL)
				ta_p->initialized = 0;
			else if (ps_pdread(ph_p, (psaddr_t)head.hash_bucket +
			    offsetof(ulwp_t, ul_lwpid),
			    &lwpid, sizeof (lwpid)) != PS_OK)
				return (TD_DBERR);
			ta_p->single_lwpid = lwpid;
			ta_p->single_ulwp_addr = (psaddr_t)head.hash_bucket;
		} else {
#if defined(_LP64) && defined(_SYSCALL32)
			thr_hash_table32_t head;
			lwpid_t lwpid = 0;

			if (ps_pdread(ph_p, ta_p->hash_table_addr,
			    &head, sizeof (head)) != PS_OK)
				return (TD_DBERR);
			if ((psaddr_t)head.hash_bucket == NULL)
				ta_p->initialized = 0;
			else if (ps_pdread(ph_p, (psaddr_t)head.hash_bucket +
			    offsetof(ulwp32_t, ul_lwpid),
			    &lwpid, sizeof (lwpid)) != PS_OK)
				return (TD_DBERR);
			ta_p->single_lwpid = lwpid;
			ta_p->single_ulwp_addr = (psaddr_t)head.hash_bucket;
#else
			return (TD_DBERR);
#endif
		}
	}
	if (!ta_p->primary_map)
		ta_p->initialized = 0;
	return (TD_OK);
}

static td_err_e
td_read_bootstrap_data(td_thragent_t *ta_p)
{
	struct ps_prochandle *ph_p = ta_p->ph_p;
	psaddr_t bootstrap_addr;
	psaddr_t uberdata_addr;
	ps_err_e db_return;
	td_err_e return_val;
	int do_1;

	switch (ta_p->initialized) {
	case 2:			/* fully initialized */
		return (TD_OK);
	case 1:			/* partially initialized */
		if (td_read_hash_size(ta_p) == 1)
			return (TD_OK);
		return (td_read_uberdata(ta_p));
	}

	/*
	 * Uninitialized -- do the startup work.
	 * We set ta_p->initialized to -1 to cut off recursive calls
	 * into libc_db by code in the provider of ps_pglobal_lookup().
	 */
	do_1 = 0;
	ta_p->initialized = -1;
	db_return = ps_pglobal_lookup(ph_p, TD_LIBRARY_NAME,
	    TD_BOOTSTRAP_NAME, &bootstrap_addr);
	if (db_return == PS_NOSYM) {
		do_1 = 1;
		db_return = ps_pglobal_lookup(ph_p, TD_LIBRARY_NAME_1,
		    TD_BOOTSTRAP_NAME, &bootstrap_addr);
	}
	if (db_return == PS_NOSYM)	/* libc is not linked yet */
		return (TD_NOLIBTHREAD);
	if (db_return != PS_OK)
		return (TD_ERR);
	db_return = ps_pglobal_lookup(ph_p,
	    do_1? TD_LIBRARY_NAME_1 : TD_LIBRARY_NAME,
	    TD_UBERDATA_NAME, &uberdata_addr);
	if (db_return == PS_NOSYM)	/* libc is not linked yet */
		return (TD_NOLIBTHREAD);
	if (db_return != PS_OK)
		return (TD_ERR);

	/*
	 * Read the uberdata address into the thread agent structure.
	 */
	if (ta_p->model == PR_MODEL_NATIVE) {
		psaddr_t psaddr;
		if (ps_pdread(ph_p, bootstrap_addr,
		    &psaddr, sizeof (psaddr)) != PS_OK)
			return (TD_DBERR);
		if ((ta_p->bootstrap_addr = psaddr) == NULL)
			psaddr = uberdata_addr;
		else if (ps_pdread(ph_p, psaddr,
		    &psaddr, sizeof (psaddr)) != PS_OK)
			return (TD_DBERR);
		if (psaddr == NULL) {
			/* primary linkmap in the tgt is not initialized */
			ta_p->bootstrap_addr = NULL;
			psaddr = uberdata_addr;
		}
		ta_p->uberdata_addr = psaddr;
	} else {
#if defined(_LP64) && defined(_SYSCALL32)
		caddr32_t psaddr;
		if (ps_pdread(ph_p, bootstrap_addr,
		    &psaddr, sizeof (psaddr)) != PS_OK)
			return (TD_DBERR);
		if ((ta_p->bootstrap_addr = (psaddr_t)psaddr) == NULL)
			psaddr = (caddr32_t)uberdata_addr;
		else if (ps_pdread(ph_p, (psaddr_t)psaddr,
		    &psaddr, sizeof (psaddr)) != PS_OK)
			return (TD_DBERR);
		if (psaddr == NULL) {
			/* primary linkmap in the tgt is not initialized */
			ta_p->bootstrap_addr = NULL;
			psaddr = (caddr32_t)uberdata_addr;
		}
		ta_p->uberdata_addr = (psaddr_t)psaddr;
#else
		return (TD_DBERR);
#endif	/* _SYSCALL32 */
	}

	if ((return_val = td_read_uberdata(ta_p)) != TD_OK)
		return (return_val);
	if (ta_p->bootstrap_addr == NULL)
		ta_p->initialized = 0;
	return (TD_OK);
}

#pragma weak ps_kill
#pragma weak ps_lrolltoaddr

/*
 * Allocate a new agent process handle ("thread agent").
 */
#pragma weak td_ta_new = __td_ta_new
td_err_e
__td_ta_new(struct ps_prochandle *ph_p, td_thragent_t **ta_pp)
{
	td_thragent_t *ta_p;
	int model;
	td_err_e return_val = TD_OK;

	if (ph_p == NULL)
		return (TD_BADPH);
	if (ta_pp == NULL)
		return (TD_ERR);
	*ta_pp = NULL;
	if (ps_pstop(ph_p) != PS_OK)
		return (TD_DBERR);
	/*
	 * ps_pdmodel might not be defined if this is an older client.
	 * Make it a weak symbol and test if it exists before calling.
	 */
#pragma weak ps_pdmodel
	if (ps_pdmodel == NULL) {
		model = PR_MODEL_NATIVE;
	} else if (ps_pdmodel(ph_p, &model) != PS_OK) {
		(void) ps_pcontinue(ph_p);
		return (TD_ERR);
	}
	if ((ta_p = malloc(sizeof (*ta_p))) == NULL) {
		(void) ps_pcontinue(ph_p);
		return (TD_MALLOC);
	}

	/*
	 * Initialize the agent process handle.
	 * Pick up the symbol value we need from the target process.
	 */
	(void) memset(ta_p, 0, sizeof (*ta_p));
	ta_p->ph_p = ph_p;
	(void) rwlock_init(&ta_p->rwlock, USYNC_THREAD, NULL);
	ta_p->model = model;
	return_val = td_read_bootstrap_data(ta_p);

	/*
	 * Because the old libthread_db enabled lock tracking by default,
	 * we must also do it.  However, we do it only if the application
	 * provides the ps_kill() and ps_lrolltoaddr() interfaces.
	 * (dbx provides the ps_kill() and ps_lrolltoaddr() interfaces.)
	 */
	if (return_val == TD_OK && ps_kill != NULL && ps_lrolltoaddr != NULL) {
		register_sync_t oldenable;
		register_sync_t enable = REGISTER_SYNC_ENABLE;
		psaddr_t psaddr = ta_p->tdb_register_sync_addr;

		if (ps_pdread(ph_p, psaddr,
		    &oldenable, sizeof (oldenable)) != PS_OK)
			return_val = TD_DBERR;
		else if (oldenable != REGISTER_SYNC_OFF ||
		    ps_pdwrite(ph_p, psaddr,
		    &enable, sizeof (enable)) != PS_OK) {
			/*
			 * Lock tracking was already enabled or we
			 * failed to enable it, probably because we
			 * are examining a core file.  In either case
			 * set the sync_tracking flag non-zero to
			 * indicate that we should not attempt to
			 * disable lock tracking when we delete the
			 * agent process handle in td_ta_delete().
			 */
			ta_p->sync_tracking = 1;
		}
	}

	if (return_val == TD_OK)
		*ta_pp = ta_p;
	else
		free(ta_p);

	(void) ps_pcontinue(ph_p);
	return (return_val);
}

/*
 * Utility function to grab the readers lock and return the prochandle,
 * given an agent process handle.  Performs standard error checking.
 * Returns non-NULL with the lock held, or NULL with the lock not held.
 */
static struct ps_prochandle *
ph_lock_ta(td_thragent_t *ta_p, td_err_e *err)
{
	struct ps_prochandle *ph_p = NULL;
	td_err_e error;

	if (ta_p == NULL || ta_p->initialized == -1) {
		*err = TD_BADTA;
	} else if (rw_rdlock(&ta_p->rwlock) != 0) {	/* can't happen? */
		*err = TD_BADTA;
	} else if ((ph_p = ta_p->ph_p) == NULL) {
		(void) rw_unlock(&ta_p->rwlock);
		*err = TD_BADPH;
	} else if (ta_p->initialized != 2 &&
	    (error = td_read_bootstrap_data(ta_p)) != TD_OK) {
		(void) rw_unlock(&ta_p->rwlock);
		ph_p = NULL;
		*err = error;
	} else {
		*err = TD_OK;
	}

	return (ph_p);
}

/*
 * Utility function to grab the readers lock and return the prochandle,
 * given an agent thread handle.  Performs standard error checking.
 * Returns non-NULL with the lock held, or NULL with the lock not held.
 */
static struct ps_prochandle *
ph_lock_th(const td_thrhandle_t *th_p, td_err_e *err)
{
	if (th_p == NULL || th_p->th_unique == NULL) {
		*err = TD_BADTH;
		return (NULL);
	}
	return (ph_lock_ta(th_p->th_ta_p, err));
}

/*
 * Utility function to grab the readers lock and return the prochandle,
 * given a synchronization object handle.  Performs standard error checking.
 * Returns non-NULL with the lock held, or NULL with the lock not held.
 */
static struct ps_prochandle *
ph_lock_sh(const td_synchandle_t *sh_p, td_err_e *err)
{
	if (sh_p == NULL || sh_p->sh_unique == NULL) {
		*err = TD_BADSH;
		return (NULL);
	}
	return (ph_lock_ta(sh_p->sh_ta_p, err));
}

/*
 * Unlock the agent process handle obtained from ph_lock_*().
 */
static void
ph_unlock(td_thragent_t *ta_p)
{
	(void) rw_unlock(&ta_p->rwlock);
}

/*
 * De-allocate an agent process handle,
 * releasing all related resources.
 *
 * XXX -- This is hopelessly broken ---
 * Storage for thread agent is not deallocated.  The prochandle
 * in the thread agent is set to NULL so that future uses of
 * the thread agent can be detected and an error value returned.
 * All functions in the external user interface that make
 * use of the thread agent are expected
 * to check for a NULL prochandle in the thread agent.
 * All such functions are also expected to obtain a
 * reader lock on the thread agent while it is using it.
 */
#pragma weak td_ta_delete = __td_ta_delete
td_err_e
__td_ta_delete(td_thragent_t *ta_p)
{
	struct ps_prochandle *ph_p;

	/*
	 * This is the only place we grab the writer lock.
	 * We are going to NULL out the prochandle.
	 */
	if (ta_p == NULL || rw_wrlock(&ta_p->rwlock) != 0)
		return (TD_BADTA);
	if ((ph_p = ta_p->ph_p) == NULL) {
		(void) rw_unlock(&ta_p->rwlock);
		return (TD_BADPH);
	}
	/*
	 * If synch. tracking was disabled when td_ta_new() was called and
	 * if td_ta_sync_tracking_enable() was never called, then disable
	 * synch. tracking (it was enabled by default in td_ta_new()).
	 */
	if (ta_p->sync_tracking == 0 &&
	    ps_kill != NULL && ps_lrolltoaddr != NULL) {
		register_sync_t enable = REGISTER_SYNC_DISABLE;

		(void) ps_pdwrite(ph_p, ta_p->tdb_register_sync_addr,
		    &enable, sizeof (enable));
	}
	ta_p->ph_p = NULL;
	(void) rw_unlock(&ta_p->rwlock);
	return (TD_OK);
}

/*
 * Map an agent process handle to a client prochandle.
 * Currently unused by dbx.
 */
#pragma weak td_ta_get_ph = __td_ta_get_ph
td_err_e
__td_ta_get_ph(td_thragent_t *ta_p, struct ps_prochandle **ph_pp)
{
	td_err_e return_val;

	if (ph_pp != NULL)	/* protect stupid callers */
		*ph_pp = NULL;
	if (ph_pp == NULL)
		return (TD_ERR);
	if ((*ph_pp = ph_lock_ta(ta_p, &return_val)) == NULL)
		return (return_val);
	ph_unlock(ta_p);
	return (TD_OK);
}

/*
 * Set the process's suggested concurrency level.
 * This is a no-op in a one-level model.
 * Currently unused by dbx.
 */
#pragma weak td_ta_setconcurrency = __td_ta_setconcurrency
/* ARGSUSED1 */
td_err_e
__td_ta_setconcurrency(const td_thragent_t *ta_p, int level)
{
	if (ta_p == NULL)
		return (TD_BADTA);
	if (ta_p->ph_p == NULL)
		return (TD_BADPH);
	return (TD_OK);
}

/*
 * Get the number of threads in the process.
 */
#pragma weak td_ta_get_nthreads = __td_ta_get_nthreads
td_err_e
__td_ta_get_nthreads(td_thragent_t *ta_p, int *nthread_p)
{
	struct ps_prochandle *ph_p;
	td_err_e return_val;
	int nthreads;
	int nzombies;
	psaddr_t nthreads_addr;
	psaddr_t nzombies_addr;

	if (ta_p->model == PR_MODEL_NATIVE) {
		nthreads_addr = ta_p->uberdata_addr +
		    offsetof(uberdata_t, nthreads);
		nzombies_addr = ta_p->uberdata_addr +
		    offsetof(uberdata_t, nzombies);
	} else {
#if defined(_LP64) && defined(_SYSCALL32)
		nthreads_addr = ta_p->uberdata_addr +
		    offsetof(uberdata32_t, nthreads);
		nzombies_addr = ta_p->uberdata_addr +
		    offsetof(uberdata32_t, nzombies);
#else
		nthreads_addr = 0;
		nzombies_addr = 0;
#endif	/* _SYSCALL32 */
	}

	if (nthread_p == NULL)
		return (TD_ERR);
	if ((ph_p = ph_lock_ta(ta_p, &return_val)) == NULL)
		return (return_val);
	if (ps_pdread(ph_p, nthreads_addr, &nthreads, sizeof (int)) != PS_OK)
		return_val = TD_DBERR;
	if (ps_pdread(ph_p, nzombies_addr, &nzombies, sizeof (int)) != PS_OK)
		return_val = TD_DBERR;
	ph_unlock(ta_p);
	if (return_val == TD_OK)
		*nthread_p = nthreads + nzombies;
	return (return_val);
}

typedef struct {
	thread_t	tid;
	int		found;
	td_thrhandle_t	th;
} td_mapper_param_t;

/*
 * Check the value in data against the thread id.
 * If it matches, return 1 to terminate iterations.
 * This function is used by td_ta_map_id2thr() to map a tid to a thread handle.
 */
static int
td_mapper_id2thr(td_thrhandle_t *th_p, td_mapper_param_t *data)
{
	td_thrinfo_t ti;

	if (__td_thr_get_info(th_p, &ti) == TD_OK &&
	    data->tid == ti.ti_tid) {
		data->found = 1;
		data->th = *th_p;
		return (1);
	}
	return (0);
}

/*
 * Given a thread identifier, return the corresponding thread handle.
 */
#pragma weak td_ta_map_id2thr = __td_ta_map_id2thr
td_err_e
__td_ta_map_id2thr(td_thragent_t *ta_p, thread_t tid,
	td_thrhandle_t *th_p)
{
	td_err_e		return_val;
	td_mapper_param_t	data;

	if (th_p != NULL &&	/* optimize for a single thread */
	    ta_p != NULL &&
	    ta_p->initialized == 1 &&
	    (td_read_hash_size(ta_p) == 1 ||
	    td_read_uberdata(ta_p) == TD_OK) &&
	    ta_p->initialized == 1 &&
	    ta_p->single_lwpid == tid) {
		th_p->th_ta_p = ta_p;
		if ((th_p->th_unique = ta_p->single_ulwp_addr) == 0)
			return (TD_NOTHR);
		return (TD_OK);
	}

	/*
	 * LOCKING EXCEPTION - Locking is not required here because
	 * the locking and checking will be done in __td_ta_thr_iter.
	 */

	if (ta_p == NULL)
		return (TD_BADTA);
	if (th_p == NULL)
		return (TD_BADTH);
	if (tid == 0)
		return (TD_NOTHR);

	data.tid = tid;
	data.found = 0;
	return_val = __td_ta_thr_iter(ta_p,
	    (td_thr_iter_f *)td_mapper_id2thr, (void *)&data,
	    TD_THR_ANY_STATE, TD_THR_LOWEST_PRIORITY,
	    TD_SIGNO_MASK, TD_THR_ANY_USER_FLAGS);
	if (return_val == TD_OK) {
		if (data.found == 0)
			return_val = TD_NOTHR;
		else
			*th_p = data.th;
	}

	return (return_val);
}

/*
 * Map the address of a synchronization object to a sync. object handle.
 */
#pragma weak td_ta_map_addr2sync = __td_ta_map_addr2sync
td_err_e
__td_ta_map_addr2sync(td_thragent_t *ta_p, psaddr_t addr, td_synchandle_t *sh_p)
{
	struct ps_prochandle *ph_p;
	td_err_e return_val;
	uint16_t sync_magic;

	if (sh_p == NULL)
		return (TD_BADSH);
	if (addr == NULL)
		return (TD_ERR);
	if ((ph_p = ph_lock_ta(ta_p, &return_val)) == NULL)
		return (return_val);
	/*
	 * Check the magic number of the sync. object to make sure it's valid.
	 * The magic number is at the same offset for all sync. objects.
	 */
	if (ps_pdread(ph_p, (psaddr_t)&((mutex_t *)addr)->mutex_magic,
	    &sync_magic, sizeof (sync_magic)) != PS_OK) {
		ph_unlock(ta_p);
		return (TD_BADSH);
	}
	ph_unlock(ta_p);
	if (sync_magic != MUTEX_MAGIC && sync_magic != COND_MAGIC &&
	    sync_magic != SEMA_MAGIC && sync_magic != RWL_MAGIC)
		return (TD_BADSH);
	/*
	 * Just fill in the appropriate fields of the sync. handle.
	 */
	sh_p->sh_ta_p = (td_thragent_t *)ta_p;
	sh_p->sh_unique = addr;
	return (TD_OK);
}

/*
 * Iterate over the set of global TSD keys.
 * The call back function is called with three arguments,
 * a key, a pointer to the destructor function, and the cbdata pointer.
 * Currently unused by dbx.
 */
#pragma weak td_ta_tsd_iter = __td_ta_tsd_iter
td_err_e
__td_ta_tsd_iter(td_thragent_t *ta_p, td_key_iter_f *cb, void *cbdata_p)
{
	struct ps_prochandle *ph_p;
	td_err_e	return_val;
	int		key;
	int		numkeys;
	psaddr_t	dest_addr;
	psaddr_t	*destructors = NULL;
	PFrV		destructor;

	if (cb == NULL)
		return (TD_ERR);
	if ((ph_p = ph_lock_ta(ta_p, &return_val)) == NULL)
		return (return_val);
	if (ps_pstop(ph_p) != PS_OK) {
		ph_unlock(ta_p);
		return (TD_DBERR);
	}

	if (ta_p->model == PR_MODEL_NATIVE) {
		tsd_metadata_t tsdm;

		if (ps_pdread(ph_p,
		    ta_p->uberdata_addr + offsetof(uberdata_t, tsd_metadata),
		    &tsdm, sizeof (tsdm)) != PS_OK)
			return_val = TD_DBERR;
		else {
			numkeys = tsdm.tsdm_nused;
			dest_addr = (psaddr_t)tsdm.tsdm_destro;
			if (numkeys > 0)
				destructors =
				    malloc(numkeys * sizeof (psaddr_t));
		}
	} else {
#if defined(_LP64) && defined(_SYSCALL32)
		tsd_metadata32_t tsdm;

		if (ps_pdread(ph_p,
		    ta_p->uberdata_addr + offsetof(uberdata32_t, tsd_metadata),
		    &tsdm, sizeof (tsdm)) != PS_OK)
			return_val = TD_DBERR;
		else {
			numkeys = tsdm.tsdm_nused;
			dest_addr = (psaddr_t)tsdm.tsdm_destro;
			if (numkeys > 0)
				destructors =
				    malloc(numkeys * sizeof (caddr32_t));
		}
#else
		return_val = TD_DBERR;
#endif	/* _SYSCALL32 */
	}

	if (return_val != TD_OK || numkeys <= 0) {
		(void) ps_pcontinue(ph_p);
		ph_unlock(ta_p);
		return (return_val);
	}

	if (destructors == NULL)
		return_val = TD_MALLOC;
	else if (ta_p->model == PR_MODEL_NATIVE) {
		if (ps_pdread(ph_p, dest_addr,
		    destructors, numkeys * sizeof (psaddr_t)) != PS_OK)
			return_val = TD_DBERR;
		else {
			for (key = 1; key < numkeys; key++) {
				destructor = (PFrV)destructors[key];
				if (destructor != TSD_UNALLOCATED &&
				    (*cb)(key, destructor, cbdata_p))
					break;
			}
		}
#if defined(_LP64) && defined(_SYSCALL32)
	} else {
		caddr32_t *destructors32 = (caddr32_t *)destructors;
		caddr32_t destruct32;

		if (ps_pdread(ph_p, dest_addr,
		    destructors32, numkeys * sizeof (caddr32_t)) != PS_OK)
			return_val = TD_DBERR;
		else {
			for (key = 1; key < numkeys; key++) {
				destruct32 = destructors32[key];
				if ((destruct32 !=
				    (caddr32_t)(uintptr_t)TSD_UNALLOCATED) &&
				    (*cb)(key, (PFrV)(uintptr_t)destruct32,
				    cbdata_p))
					break;
			}
		}
#endif	/* _SYSCALL32 */
	}

	if (destructors)
		free(destructors);
	(void) ps_pcontinue(ph_p);
	ph_unlock(ta_p);
	return (return_val);
}

int
sigequalset(const sigset_t *s1, const sigset_t *s2)
{
	return (
	    s1->__sigbits[0] == s2->__sigbits[0] &&
	    s1->__sigbits[1] == s2->__sigbits[1] &&
	    s1->__sigbits[2] == s2->__sigbits[2] &&
	    s1->__sigbits[3] == s2->__sigbits[3]);
}

/*
 * Description:
 *   Iterate over all threads. For each thread call
 * the function pointed to by "cb" with a pointer
 * to a thread handle, and a pointer to data which
 * can be NULL. Only call td_thr_iter_f() on threads
 * which match the properties of state, ti_pri,
 * ti_sigmask_p, and ti_user_flags.  If cb returns
 * a non-zero value, terminate iterations.
 *
 * Input:
 *   *ta_p - thread agent
 *   *cb - call back function defined by user.
 * td_thr_iter_f() takes a thread handle and
 * cbdata_p as a parameter.
 *   cbdata_p - parameter for td_thr_iter_f().
 *
 *   state - state of threads of interest.  A value of
 * TD_THR_ANY_STATE from enum td_thr_state_e
 * does not restrict iterations by state.
 *   ti_pri - lower bound of priorities of threads of
 * interest.  A value of TD_THR_LOWEST_PRIORITY
 * defined in thread_db.h does not restrict
 * iterations by priority.  A thread with priority
 * less than ti_pri will NOT be passed to the callback
 * function.
 *   ti_sigmask_p - signal mask of threads of interest.
 * A value of TD_SIGNO_MASK defined in thread_db.h
 * does not restrict iterations by signal mask.
 *   ti_user_flags - user flags of threads of interest.  A
 * value of TD_THR_ANY_USER_FLAGS defined in thread_db.h
 * does not restrict iterations by user flags.
 */
#pragma weak td_ta_thr_iter = __td_ta_thr_iter
td_err_e
__td_ta_thr_iter(td_thragent_t *ta_p, td_thr_iter_f *cb,
	void *cbdata_p, td_thr_state_e state, int ti_pri,
	sigset_t *ti_sigmask_p, unsigned ti_user_flags)
{
	struct ps_prochandle *ph_p;
	psaddr_t	first_lwp_addr;
	psaddr_t	first_zombie_addr;
	psaddr_t	curr_lwp_addr;
	psaddr_t	next_lwp_addr;
	td_thrhandle_t	th;
	ps_err_e	db_return;
	ps_err_e	db_return2;
	td_err_e	return_val;

	if (cb == NULL)
		return (TD_ERR);
	/*
	 * If state is not within bound, short circuit.
	 */
	if (state < TD_THR_ANY_STATE || state > TD_THR_STOPPED_ASLEEP)
		return (TD_OK);

	if ((ph_p = ph_lock_ta(ta_p, &return_val)) == NULL)
		return (return_val);
	if (ps_pstop(ph_p) != PS_OK) {
		ph_unlock(ta_p);
		return (TD_DBERR);
	}

	/*
	 * For each ulwp_t in the circular linked lists pointed
	 * to by "all_lwps" and "all_zombies":
	 * (1) Filter each thread.
	 * (2) Create the thread_object for each thread that passes.
	 * (3) Call the call back function on each thread.
	 */

	if (ta_p->model == PR_MODEL_NATIVE) {
		db_return = ps_pdread(ph_p,
		    ta_p->uberdata_addr + offsetof(uberdata_t, all_lwps),
		    &first_lwp_addr, sizeof (first_lwp_addr));
		db_return2 = ps_pdread(ph_p,
		    ta_p->uberdata_addr + offsetof(uberdata_t, all_zombies),
		    &first_zombie_addr, sizeof (first_zombie_addr));
	} else {
#if defined(_LP64) && defined(_SYSCALL32)
		caddr32_t addr32;

		db_return = ps_pdread(ph_p,
		    ta_p->uberdata_addr + offsetof(uberdata32_t, all_lwps),
		    &addr32, sizeof (addr32));
		first_lwp_addr = addr32;
		db_return2 = ps_pdread(ph_p,
		    ta_p->uberdata_addr + offsetof(uberdata32_t, all_zombies),
		    &addr32, sizeof (addr32));
		first_zombie_addr = addr32;
#else	/* _SYSCALL32 */
		db_return = PS_ERR;
		db_return2 = PS_ERR;
#endif	/* _SYSCALL32 */
	}
	if (db_return == PS_OK)
		db_return = db_return2;

	/*
	 * If first_lwp_addr and first_zombie_addr are both NULL,
	 * libc must not yet be initialized or all threads have
	 * exited.  Return TD_NOTHR and all will be well.
	 */
	if (db_return == PS_OK &&
	    first_lwp_addr == NULL && first_zombie_addr == NULL) {
		(void) ps_pcontinue(ph_p);
		ph_unlock(ta_p);
		return (TD_NOTHR);
	}
	if (db_return != PS_OK) {
		(void) ps_pcontinue(ph_p);
		ph_unlock(ta_p);
		return (TD_DBERR);
	}

	/*
	 * Run down the lists of all living and dead lwps.
	 */
	if (first_lwp_addr == NULL)
		first_lwp_addr = first_zombie_addr;
	curr_lwp_addr = first_lwp_addr;
	for (;;) {
		td_thr_state_e ts_state;
		int userpri;
		unsigned userflags;
		sigset_t mask;

		/*
		 * Read the ulwp struct.
		 */
		if (ta_p->model == PR_MODEL_NATIVE) {
			ulwp_t ulwp;

			if (ps_pdread(ph_p, curr_lwp_addr,
			    &ulwp, sizeof (ulwp)) != PS_OK &&
			    ((void) memset(&ulwp, 0, sizeof (ulwp)),
			    ps_pdread(ph_p, curr_lwp_addr,
			    &ulwp, REPLACEMENT_SIZE)) != PS_OK) {
				return_val = TD_DBERR;
				break;
			}
			next_lwp_addr = (psaddr_t)ulwp.ul_forw;

			ts_state = ulwp.ul_dead? TD_THR_ZOMBIE :
			    ulwp.ul_stop? TD_THR_STOPPED :
			    ulwp.ul_wchan? TD_THR_SLEEP :
			    TD_THR_ACTIVE;
			userpri = ulwp.ul_pri;
			userflags = ulwp.ul_usropts;
			if (ulwp.ul_dead)
				(void) sigemptyset(&mask);
			else
				mask = *(sigset_t *)&ulwp.ul_sigmask;
		} else {
#if defined(_LP64) && defined(_SYSCALL32)
			ulwp32_t ulwp;

			if (ps_pdread(ph_p, curr_lwp_addr,
			    &ulwp, sizeof (ulwp)) != PS_OK &&
			    ((void) memset(&ulwp, 0, sizeof (ulwp)),
			    ps_pdread(ph_p, curr_lwp_addr,
			    &ulwp, REPLACEMENT_SIZE32)) != PS_OK) {
				return_val = TD_DBERR;
				break;
			}
			next_lwp_addr = (psaddr_t)ulwp.ul_forw;

			ts_state = ulwp.ul_dead? TD_THR_ZOMBIE :
			    ulwp.ul_stop? TD_THR_STOPPED :
			    ulwp.ul_wchan? TD_THR_SLEEP :
			    TD_THR_ACTIVE;
			userpri = ulwp.ul_pri;
			userflags = ulwp.ul_usropts;
			if (ulwp.ul_dead)
				(void) sigemptyset(&mask);
			else
				mask = *(sigset_t *)&ulwp.ul_sigmask;
#else	/* _SYSCALL32 */
			return_val = TD_ERR;
			break;
#endif	/* _SYSCALL32 */
		}

		/*
		 * Filter on state, priority, sigmask, and user flags.
		 */

		if ((state != ts_state) &&
		    (state != TD_THR_ANY_STATE))
			goto advance;

		if (ti_pri > userpri)
			goto advance;

		if (ti_sigmask_p != TD_SIGNO_MASK &&
		    !sigequalset(ti_sigmask_p, &mask))
			goto advance;

		if (ti_user_flags != userflags &&
		    ti_user_flags != (unsigned)TD_THR_ANY_USER_FLAGS)
			goto advance;

		/*
		 * Call back - break if the return
		 * from the call back is non-zero.
		 */
		th.th_ta_p = (td_thragent_t *)ta_p;
		th.th_unique = curr_lwp_addr;
		if ((*cb)(&th, cbdata_p))
			break;

advance:
		if ((curr_lwp_addr = next_lwp_addr) == first_lwp_addr) {
			/*
			 * Switch to the zombie list, unless it is NULL
			 * or we have already been doing the zombie list,
			 * in which case terminate the loop.
			 */
			if (first_zombie_addr == NULL ||
			    first_lwp_addr == first_zombie_addr)
				break;
			curr_lwp_addr = first_lwp_addr = first_zombie_addr;
		}
	}

	(void) ps_pcontinue(ph_p);
	ph_unlock(ta_p);
	return (return_val);
}

/*
 * Enable or disable process synchronization object tracking.
 * Currently unused by dbx.
 */
#pragma weak td_ta_sync_tracking_enable = __td_ta_sync_tracking_enable
td_err_e
__td_ta_sync_tracking_enable(td_thragent_t *ta_p, int onoff)
{
	struct ps_prochandle *ph_p;
	td_err_e return_val;
	register_sync_t enable;

	if ((ph_p = ph_lock_ta(ta_p, &return_val)) == NULL)
		return (return_val);
	/*
	 * Values of tdb_register_sync in the victim process:
	 *	REGISTER_SYNC_ENABLE	enables registration of synch objects
	 *	REGISTER_SYNC_DISABLE	disables registration of synch objects
	 * These cause the table to be cleared and tdb_register_sync set to:
	 *	REGISTER_SYNC_ON	registration in effect
	 *	REGISTER_SYNC_OFF	registration not in effect
	 */
	enable = onoff? REGISTER_SYNC_ENABLE : REGISTER_SYNC_DISABLE;
	if (ps_pdwrite(ph_p, ta_p->tdb_register_sync_addr,
	    &enable, sizeof (enable)) != PS_OK)
		return_val = TD_DBERR;
	/*
	 * Remember that this interface was called (see td_ta_delete()).
	 */
	ta_p->sync_tracking = 1;
	ph_unlock(ta_p);
	return (return_val);
}

/*
 * Iterate over all known synchronization variables.
 * It is very possible that the list generated is incomplete,
 * because the iterator can only find synchronization variables
 * that have been registered by the process since synchronization
 * object registration was enabled.
 * The call back function cb is called for each synchronization
 * variable with two arguments: a pointer to the synchronization
 * handle and the passed-in argument cbdata.
 * If cb returns a non-zero value, iterations are terminated.
 */
#pragma weak td_ta_sync_iter = __td_ta_sync_iter
td_err_e
__td_ta_sync_iter(td_thragent_t *ta_p, td_sync_iter_f *cb, void *cbdata)
{
	struct ps_prochandle *ph_p;
	td_err_e	return_val;
	int		i;
	register_sync_t	enable;
	psaddr_t	next_desc;
	tdb_sync_stats_t sync_stats;
	td_synchandle_t	synchandle;
	psaddr_t	psaddr;
	void		*vaddr;
	uint64_t	*sync_addr_hash = NULL;

	if (cb == NULL)
		return (TD_ERR);
	if ((ph_p = ph_lock_ta(ta_p, &return_val)) == NULL)
		return (return_val);
	if (ps_pstop(ph_p) != PS_OK) {
		ph_unlock(ta_p);
		return (TD_DBERR);
	}
	if (ps_pdread(ph_p, ta_p->tdb_register_sync_addr,
	    &enable, sizeof (enable)) != PS_OK) {
		return_val = TD_DBERR;
		goto out;
	}
	if (enable != REGISTER_SYNC_ON)
		goto out;

	/*
	 * First read the hash table.
	 * The hash table is large; allocate with mmap().
	 */
	if ((vaddr = mmap(NULL, TDB_HASH_SIZE * sizeof (uint64_t),
	    PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, (off_t)0))
	    == MAP_FAILED) {
		return_val = TD_MALLOC;
		goto out;
	}
	sync_addr_hash = vaddr;

	if (ta_p->model == PR_MODEL_NATIVE) {
		if (ps_pdread(ph_p, ta_p->uberdata_addr +
		    offsetof(uberdata_t, tdb.tdb_sync_addr_hash),
		    &psaddr, sizeof (&psaddr)) != PS_OK) {
			return_val = TD_DBERR;
			goto out;
		}
	} else {
#ifdef  _SYSCALL32
		caddr32_t addr;

		if (ps_pdread(ph_p, ta_p->uberdata_addr +
		    offsetof(uberdata32_t, tdb.tdb_sync_addr_hash),
		    &addr, sizeof (addr)) != PS_OK) {
			return_val = TD_DBERR;
			goto out;
		}
		psaddr = addr;
#else
		return_val = TD_ERR;
		goto out;
#endif /* _SYSCALL32 */
	}

	if (psaddr == NULL)
		goto out;
	if (ps_pdread(ph_p, psaddr, sync_addr_hash,
	    TDB_HASH_SIZE * sizeof (uint64_t)) != PS_OK) {
		return_val = TD_DBERR;
		goto out;
	}

	/*
	 * Now scan the hash table.
	 */
	for (i = 0; i < TDB_HASH_SIZE; i++) {
		for (next_desc = (psaddr_t)sync_addr_hash[i];
		    next_desc != NULL;
		    next_desc = (psaddr_t)sync_stats.next) {
			if (ps_pdread(ph_p, next_desc,
			    &sync_stats, sizeof (sync_stats)) != PS_OK) {
				return_val = TD_DBERR;
				goto out;
			}
			if (sync_stats.un.type == TDB_NONE) {
				/* not registered since registration enabled */
				continue;
			}
			synchandle.sh_ta_p = ta_p;
			synchandle.sh_unique = (psaddr_t)sync_stats.sync_addr;
			if ((*cb)(&synchandle, cbdata) != 0)
				goto out;
		}
	}

out:
	if (sync_addr_hash != NULL)
		(void) munmap((void *)sync_addr_hash,
		    TDB_HASH_SIZE * sizeof (uint64_t));
	(void) ps_pcontinue(ph_p);
	ph_unlock(ta_p);
	return (return_val);
}

/*
 * Enable process statistics collection.
 */
#pragma weak td_ta_enable_stats = __td_ta_enable_stats
/* ARGSUSED */
td_err_e
__td_ta_enable_stats(const td_thragent_t *ta_p, int onoff)
{
	return (TD_NOCAPAB);
}

/*
 * Reset process statistics.
 */
#pragma weak td_ta_reset_stats = __td_ta_reset_stats
/* ARGSUSED */
td_err_e
__td_ta_reset_stats(const td_thragent_t *ta_p)
{
	return (TD_NOCAPAB);
}

/*
 * Read process statistics.
 */
#pragma weak td_ta_get_stats = __td_ta_get_stats
/* ARGSUSED */
td_err_e
__td_ta_get_stats(const td_thragent_t *ta_p, td_ta_stats_t *tstats)
{
	return (TD_NOCAPAB);
}

/*
 * Transfer information from lwp struct to thread information struct.
 * XXX -- lots of this needs cleaning up.
 */
static void
td_thr2to(td_thragent_t *ta_p, psaddr_t ts_addr,
	ulwp_t *ulwp, td_thrinfo_t *ti_p)
{
	lwpid_t lwpid;

	if ((lwpid = ulwp->ul_lwpid) == 0)
		lwpid = 1;
	(void) memset(ti_p, 0, sizeof (*ti_p));
	ti_p->ti_ta_p = ta_p;
	ti_p->ti_user_flags = ulwp->ul_usropts;
	ti_p->ti_tid = lwpid;
	ti_p->ti_exitval = ulwp->ul_rval;
	ti_p->ti_startfunc = (psaddr_t)ulwp->ul_startpc;
	if (!ulwp->ul_dead) {
		/*
		 * The bloody fools got this backwards!
		 */
		ti_p->ti_stkbase = (psaddr_t)ulwp->ul_stktop;
		ti_p->ti_stksize = ulwp->ul_stksiz;
	}
	ti_p->ti_ro_area = ts_addr;
	ti_p->ti_ro_size = ulwp->ul_replace?
	    REPLACEMENT_SIZE : sizeof (ulwp_t);
	ti_p->ti_state = ulwp->ul_dead? TD_THR_ZOMBIE :
	    ulwp->ul_stop? TD_THR_STOPPED :
	    ulwp->ul_wchan? TD_THR_SLEEP :
	    TD_THR_ACTIVE;
	ti_p->ti_db_suspended = 0;
	ti_p->ti_type = TD_THR_USER;
	ti_p->ti_sp = ulwp->ul_sp;
	ti_p->ti_flags = 0;
	ti_p->ti_pri = ulwp->ul_pri;
	ti_p->ti_lid = lwpid;
	if (!ulwp->ul_dead)
		ti_p->ti_sigmask = ulwp->ul_sigmask;
	ti_p->ti_traceme = 0;
	ti_p->ti_preemptflag = 0;
	ti_p->ti_pirecflag = 0;
	(void) sigemptyset(&ti_p->ti_pending);
	ti_p->ti_events = ulwp->ul_td_evbuf.eventmask;
}

#if defined(_LP64) && defined(_SYSCALL32)
static void
td_thr2to32(td_thragent_t *ta_p, psaddr_t ts_addr,
	ulwp32_t *ulwp, td_thrinfo_t *ti_p)
{
	lwpid_t lwpid;

	if ((lwpid = ulwp->ul_lwpid) == 0)
		lwpid = 1;
	(void) memset(ti_p, 0, sizeof (*ti_p));
	ti_p->ti_ta_p = ta_p;
	ti_p->ti_user_flags = ulwp->ul_usropts;
	ti_p->ti_tid = lwpid;
	ti_p->ti_exitval = (void *)(uintptr_t)ulwp->ul_rval;
	ti_p->ti_startfunc = (psaddr_t)ulwp->ul_startpc;
	if (!ulwp->ul_dead) {
		/*
		 * The bloody fools got this backwards!
		 */
		ti_p->ti_stkbase = (psaddr_t)ulwp->ul_stktop;
		ti_p->ti_stksize = ulwp->ul_stksiz;
	}
	ti_p->ti_ro_area = ts_addr;
	ti_p->ti_ro_size = ulwp->ul_replace?
	    REPLACEMENT_SIZE32 : sizeof (ulwp32_t);
	ti_p->ti_state = ulwp->ul_dead? TD_THR_ZOMBIE :
	    ulwp->ul_stop? TD_THR_STOPPED :
	    ulwp->ul_wchan? TD_THR_SLEEP :
	    TD_THR_ACTIVE;
	ti_p->ti_db_suspended = 0;
	ti_p->ti_type = TD_THR_USER;
	ti_p->ti_sp = (uint32_t)ulwp->ul_sp;
	ti_p->ti_flags = 0;
	ti_p->ti_pri = ulwp->ul_pri;
	ti_p->ti_lid = lwpid;
	if (!ulwp->ul_dead)
		ti_p->ti_sigmask = *(sigset_t *)&ulwp->ul_sigmask;
	ti_p->ti_traceme = 0;
	ti_p->ti_preemptflag = 0;
	ti_p->ti_pirecflag = 0;
	(void) sigemptyset(&ti_p->ti_pending);
	ti_p->ti_events = ulwp->ul_td_evbuf.eventmask;
}
#endif	/* _SYSCALL32 */

/*
 * Get thread information.
 */
#pragma weak td_thr_get_info = __td_thr_get_info
td_err_e
__td_thr_get_info(td_thrhandle_t *th_p, td_thrinfo_t *ti_p)
{
	struct ps_prochandle *ph_p;
	td_thragent_t	*ta_p;
	td_err_e	return_val;
	psaddr_t	psaddr;

	if (ti_p == NULL)
		return (TD_ERR);
	(void) memset(ti_p, NULL, sizeof (*ti_p));

	if ((ph_p = ph_lock_th(th_p, &return_val)) == NULL)
		return (return_val);
	ta_p = th_p->th_ta_p;
	if (ps_pstop(ph_p) != PS_OK) {
		ph_unlock(ta_p);
		return (TD_DBERR);
	}

	/*
	 * Read the ulwp struct from the process.
	 * Transfer the ulwp struct to the thread information struct.
	 */
	psaddr = th_p->th_unique;
	if (ta_p->model == PR_MODEL_NATIVE) {
		ulwp_t ulwp;

		if (ps_pdread(ph_p, psaddr, &ulwp, sizeof (ulwp)) != PS_OK &&
		    ((void) memset(&ulwp, 0, sizeof (ulwp)),
		    ps_pdread(ph_p, psaddr, &ulwp, REPLACEMENT_SIZE)) != PS_OK)
			return_val = TD_DBERR;
		else
			td_thr2to(ta_p, psaddr, &ulwp, ti_p);
	} else {
#if defined(_LP64) && defined(_SYSCALL32)
		ulwp32_t ulwp;

		if (ps_pdread(ph_p, psaddr, &ulwp, sizeof (ulwp)) != PS_OK &&
		    ((void) memset(&ulwp, 0, sizeof (ulwp)),
		    ps_pdread(ph_p, psaddr, &ulwp, REPLACEMENT_SIZE32)) !=
		    PS_OK)
			return_val = TD_DBERR;
		else
			td_thr2to32(ta_p, psaddr, &ulwp, ti_p);
#else
		return_val = TD_ERR;
#endif	/* _SYSCALL32 */
	}

	(void) ps_pcontinue(ph_p);
	ph_unlock(ta_p);
	return (return_val);
}

/*
 * Given a process and an event number, return information about
 * an address in the process or at which a breakpoint can be set
 * to monitor the event.
 */
#pragma weak td_ta_event_addr = __td_ta_event_addr
td_err_e
__td_ta_event_addr(td_thragent_t *ta_p, td_event_e event, td_notify_t *notify_p)
{
	if (ta_p == NULL)
		return (TD_BADTA);
	if (event < TD_MIN_EVENT_NUM || event > TD_MAX_EVENT_NUM)
		return (TD_NOEVENT);
	if (notify_p == NULL)
		return (TD_ERR);

	notify_p->type = NOTIFY_BPT;
	notify_p->u.bptaddr = ta_p->tdb_events[event - TD_MIN_EVENT_NUM];

	return (TD_OK);
}

/*
 * Add the events in eventset 2 to eventset 1.
 */
static void
eventsetaddset(td_thr_events_t *event1_p, td_thr_events_t *event2_p)
{
	int	i;

	for (i = 0; i < TD_EVENTSIZE; i++)
		event1_p->event_bits[i] |= event2_p->event_bits[i];
}

/*
 * Delete the events in eventset 2 from eventset 1.
 */
static void
eventsetdelset(td_thr_events_t *event1_p, td_thr_events_t *event2_p)
{
	int	i;

	for (i = 0; i < TD_EVENTSIZE; i++)
		event1_p->event_bits[i] &= ~event2_p->event_bits[i];
}

/*
 * Either add or delete the given event set from a thread's event mask.
 */
static td_err_e
mod_eventset(td_thrhandle_t *th_p, td_thr_events_t *events, int onoff)
{
	struct ps_prochandle *ph_p;
	td_err_e	return_val = TD_OK;
	char		enable;
	td_thr_events_t	evset;
	psaddr_t	psaddr_evset;
	psaddr_t	psaddr_enab;

	if ((ph_p = ph_lock_th(th_p, &return_val)) == NULL)
		return (return_val);
	if (th_p->th_ta_p->model == PR_MODEL_NATIVE) {
		ulwp_t *ulwp = (ulwp_t *)th_p->th_unique;
		psaddr_evset = (psaddr_t)&ulwp->ul_td_evbuf.eventmask;
		psaddr_enab = (psaddr_t)&ulwp->ul_td_events_enable;
	} else {
#if defined(_LP64) && defined(_SYSCALL32)
		ulwp32_t *ulwp = (ulwp32_t *)th_p->th_unique;
		psaddr_evset = (psaddr_t)&ulwp->ul_td_evbuf.eventmask;
		psaddr_enab = (psaddr_t)&ulwp->ul_td_events_enable;
#else
		ph_unlock(th_p->th_ta_p);
		return (TD_ERR);
#endif	/* _SYSCALL32 */
	}
	if (ps_pstop(ph_p) != PS_OK) {
		ph_unlock(th_p->th_ta_p);
		return (TD_DBERR);
	}

	if (ps_pdread(ph_p, psaddr_evset, &evset, sizeof (evset)) != PS_OK)
		return_val = TD_DBERR;
	else {
		if (onoff)
			eventsetaddset(&evset, events);
		else
			eventsetdelset(&evset, events);
		if (ps_pdwrite(ph_p, psaddr_evset, &evset, sizeof (evset))
		    != PS_OK)
			return_val = TD_DBERR;
		else {
			enable = 0;
			if (td_eventismember(&evset, TD_EVENTS_ENABLE))
				enable = 1;
			if (ps_pdwrite(ph_p, psaddr_enab,
			    &enable, sizeof (enable)) != PS_OK)
				return_val = TD_DBERR;
		}
	}

	(void) ps_pcontinue(ph_p);
	ph_unlock(th_p->th_ta_p);
	return (return_val);
}

/*
 * Enable or disable tracing for a given thread.  Tracing
 * is filtered based on the event mask of each thread.  Tracing
 * can be turned on/off for the thread without changing thread
 * event mask.
 * Currently unused by dbx.
 */
#pragma weak td_thr_event_enable = __td_thr_event_enable
td_err_e
__td_thr_event_enable(td_thrhandle_t *th_p, int onoff)
{
	td_thr_events_t	evset;

	td_event_emptyset(&evset);
	td_event_addset(&evset, TD_EVENTS_ENABLE);
	return (mod_eventset(th_p, &evset, onoff));
}

/*
 * Set event mask to enable event. event is turned on in
 * event mask for thread.  If a thread encounters an event
 * for which its event mask is on, notification will be sent
 * to the debugger.
 * Addresses for each event are provided to the
 * debugger.  It is assumed that a breakpoint of some type will
 * be placed at that address.  If the event mask for the thread
 * is on, the instruction at the address will be executed.
 * Otherwise, the instruction will be skipped.
 */
#pragma weak td_thr_set_event = __td_thr_set_event
td_err_e
__td_thr_set_event(td_thrhandle_t *th_p, td_thr_events_t *events)
{
	return (mod_eventset(th_p, events, 1));
}

/*
 * Enable or disable a set of events in the process-global event mask,
 * depending on the value of onoff.
 */
static td_err_e
td_ta_mod_event(td_thragent_t *ta_p, td_thr_events_t *events, int onoff)
{
	struct ps_prochandle *ph_p;
	td_thr_events_t targ_eventset;
	td_err_e	return_val;

	if ((ph_p = ph_lock_ta(ta_p, &return_val)) == NULL)
		return (return_val);
	if (ps_pstop(ph_p) != PS_OK) {
		ph_unlock(ta_p);
		return (TD_DBERR);
	}
	if (ps_pdread(ph_p, ta_p->tdb_eventmask_addr,
	    &targ_eventset, sizeof (targ_eventset)) != PS_OK)
		return_val = TD_DBERR;
	else {
		if (onoff)
			eventsetaddset(&targ_eventset, events);
		else
			eventsetdelset(&targ_eventset, events);
		if (ps_pdwrite(ph_p, ta_p->tdb_eventmask_addr,
		    &targ_eventset, sizeof (targ_eventset)) != PS_OK)
			return_val = TD_DBERR;
	}
	(void) ps_pcontinue(ph_p);
	ph_unlock(ta_p);
	return (return_val);
}

/*
 * Enable a set of events in the process-global event mask.
 */
#pragma weak td_ta_set_event = __td_ta_set_event
td_err_e
__td_ta_set_event(td_thragent_t *ta_p, td_thr_events_t *events)
{
	return (td_ta_mod_event(ta_p, events, 1));
}

/*
 * Set event mask to disable the given event set; these events are cleared
 * from the event mask of the thread.  Events that occur for a thread
 * with the event masked off will not cause notification to be
 * sent to the debugger (see td_thr_set_event for fuller description).
 */
#pragma weak td_thr_clear_event = __td_thr_clear_event
td_err_e
__td_thr_clear_event(td_thrhandle_t *th_p, td_thr_events_t *events)
{
	return (mod_eventset(th_p, events, 0));
}

/*
 * Disable a set of events in the process-global event mask.
 */
#pragma weak td_ta_clear_event = __td_ta_clear_event
td_err_e
__td_ta_clear_event(td_thragent_t *ta_p, td_thr_events_t *events)
{
	return (td_ta_mod_event(ta_p, events, 0));
}

/*
 * This function returns the most recent event message, if any,
 * associated with a thread.  Given a thread handle, return the message
 * corresponding to the event encountered by the thread.  Only one
 * message per thread is saved.  Messages from earlier events are lost
 * when later events occur.
 */
#pragma weak td_thr_event_getmsg = __td_thr_event_getmsg
td_err_e
__td_thr_event_getmsg(td_thrhandle_t *th_p, td_event_msg_t *msg)
{
	struct ps_prochandle *ph_p;
	td_err_e	return_val = TD_OK;
	psaddr_t	psaddr;

	if ((ph_p = ph_lock_th(th_p, &return_val)) == NULL)
		return (return_val);
	if (ps_pstop(ph_p) != PS_OK) {
		ph_unlock(th_p->th_ta_p);
		return (TD_BADTA);
	}
	if (th_p->th_ta_p->model == PR_MODEL_NATIVE) {
		ulwp_t *ulwp = (ulwp_t *)th_p->th_unique;
		td_evbuf_t evbuf;

		psaddr = (psaddr_t)&ulwp->ul_td_evbuf;
		if (ps_pdread(ph_p, psaddr, &evbuf, sizeof (evbuf)) != PS_OK) {
			return_val = TD_DBERR;
		} else if (evbuf.eventnum == TD_EVENT_NONE) {
			return_val = TD_NOEVENT;
		} else {
			msg->event = evbuf.eventnum;
			msg->th_p = (td_thrhandle_t *)th_p;
			msg->msg.data = (uintptr_t)evbuf.eventdata;
			/* "Consume" the message */
			evbuf.eventnum = TD_EVENT_NONE;
			evbuf.eventdata = NULL;
			if (ps_pdwrite(ph_p, psaddr, &evbuf, sizeof (evbuf))
			    != PS_OK)
				return_val = TD_DBERR;
		}
	} else {
#if defined(_LP64) && defined(_SYSCALL32)
		ulwp32_t *ulwp = (ulwp32_t *)th_p->th_unique;
		td_evbuf32_t evbuf;

		psaddr = (psaddr_t)&ulwp->ul_td_evbuf;
		if (ps_pdread(ph_p, psaddr, &evbuf, sizeof (evbuf)) != PS_OK) {
			return_val = TD_DBERR;
		} else if (evbuf.eventnum == TD_EVENT_NONE) {
			return_val = TD_NOEVENT;
		} else {
			msg->event = evbuf.eventnum;
			msg->th_p = (td_thrhandle_t *)th_p;
			msg->msg.data = (uintptr_t)evbuf.eventdata;
			/* "Consume" the message */
			evbuf.eventnum = TD_EVENT_NONE;
			evbuf.eventdata = NULL;
			if (ps_pdwrite(ph_p, psaddr, &evbuf, sizeof (evbuf))
			    != PS_OK)
				return_val = TD_DBERR;
		}
#else
		return_val = TD_ERR;
#endif	/* _SYSCALL32 */
	}

	(void) ps_pcontinue(ph_p);
	ph_unlock(th_p->th_ta_p);
	return (return_val);
}

/*
 * The callback function td_ta_event_getmsg uses when looking for
 * a thread with an event.  A thin wrapper around td_thr_event_getmsg.
 */
static int
event_msg_cb(const td_thrhandle_t *th_p, void *arg)
{
	static td_thrhandle_t th;
	td_event_msg_t *msg = arg;

	if (__td_thr_event_getmsg((td_thrhandle_t *)th_p, msg) == TD_OK) {
		/*
		 * Got an event, stop iterating.
		 *
		 * Because of past mistakes in interface definition,
		 * we are forced to pass back a static local variable
		 * for the thread handle because th_p is a pointer
		 * to a local variable in __td_ta_thr_iter().
		 * Grr...
		 */
		th = *th_p;
		msg->th_p = &th;
		return (1);
	}
	return (0);
}

/*
 * This function is just like td_thr_event_getmsg, except that it is
 * passed a process handle rather than a thread handle, and returns
 * an event message for some thread in the process that has an event
 * message pending.  If no thread has an event message pending, this
 * routine returns TD_NOEVENT.  Thus, all pending event messages may
 * be collected from a process by repeatedly calling this routine
 * until it returns TD_NOEVENT.
 */
#pragma weak td_ta_event_getmsg = __td_ta_event_getmsg
td_err_e
__td_ta_event_getmsg(td_thragent_t *ta_p, td_event_msg_t *msg)
{
	td_err_e return_val;

	if (ta_p == NULL)
		return (TD_BADTA);
	if (ta_p->ph_p == NULL)
		return (TD_BADPH);
	if (msg == NULL)
		return (TD_ERR);
	msg->event = TD_EVENT_NONE;
	if ((return_val = __td_ta_thr_iter(ta_p, event_msg_cb, msg,
	    TD_THR_ANY_STATE, TD_THR_LOWEST_PRIORITY, TD_SIGNO_MASK,
	    TD_THR_ANY_USER_FLAGS)) != TD_OK)
		return (return_val);
	if (msg->event == TD_EVENT_NONE)
		return (TD_NOEVENT);
	return (TD_OK);
}

static lwpid_t
thr_to_lwpid(const td_thrhandle_t *th_p)
{
	struct ps_prochandle *ph_p = th_p->th_ta_p->ph_p;
	lwpid_t lwpid;

	/*
	 * The caller holds the prochandle lock
	 * and has already verfied everything.
	 */
	if (th_p->th_ta_p->model == PR_MODEL_NATIVE) {
		ulwp_t *ulwp = (ulwp_t *)th_p->th_unique;

		if (ps_pdread(ph_p, (psaddr_t)&ulwp->ul_lwpid,
		    &lwpid, sizeof (lwpid)) != PS_OK)
			lwpid = 0;
		else if (lwpid == 0)
			lwpid = 1;
	} else {
#if defined(_LP64) && defined(_SYSCALL32)
		ulwp32_t *ulwp = (ulwp32_t *)th_p->th_unique;

		if (ps_pdread(ph_p, (psaddr_t)&ulwp->ul_lwpid,
		    &lwpid, sizeof (lwpid)) != PS_OK)
			lwpid = 0;
		else if (lwpid == 0)
			lwpid = 1;
#else
		lwpid = 0;
#endif	/* _SYSCALL32 */
	}

	return (lwpid);
}

/*
 * Suspend a thread.
 * XXX: What does this mean in a one-level model?
 */
#pragma weak td_thr_dbsuspend = __td_thr_dbsuspend
td_err_e
__td_thr_dbsuspend(const td_thrhandle_t *th_p)
{
	struct ps_prochandle *ph_p;
	td_err_e return_val;

	if ((ph_p = ph_lock_th(th_p, &return_val)) == NULL)
		return (return_val);
	if (ps_lstop(ph_p, thr_to_lwpid(th_p)) != PS_OK)
		return_val = TD_DBERR;
	ph_unlock(th_p->th_ta_p);
	return (return_val);
}

/*
 * Resume a suspended thread.
 * XXX: What does this mean in a one-level model?
 */
#pragma weak td_thr_dbresume = __td_thr_dbresume
td_err_e
__td_thr_dbresume(const td_thrhandle_t *th_p)
{
	struct ps_prochandle *ph_p;
	td_err_e return_val;

	if ((ph_p = ph_lock_th(th_p, &return_val)) == NULL)
		return (return_val);
	if (ps_lcontinue(ph_p, thr_to_lwpid(th_p)) != PS_OK)
		return_val = TD_DBERR;
	ph_unlock(th_p->th_ta_p);
	return (return_val);
}

/*
 * Set a thread's signal mask.
 * Currently unused by dbx.
 */
#pragma weak td_thr_sigsetmask = __td_thr_sigsetmask
/* ARGSUSED */
td_err_e
__td_thr_sigsetmask(const td_thrhandle_t *th_p, const sigset_t ti_sigmask)
{
	return (TD_NOCAPAB);
}

/*
 * Set a thread's "signals-pending" set.
 * Currently unused by dbx.
 */
#pragma weak td_thr_setsigpending = __td_thr_setsigpending
/* ARGSUSED */
td_err_e
__td_thr_setsigpending(const td_thrhandle_t *th_p,
	uchar_t ti_pending_flag, const sigset_t ti_pending)
{
	return (TD_NOCAPAB);
}

/*
 * Get a thread's general register set.
 */
#pragma weak td_thr_getgregs = __td_thr_getgregs
td_err_e
__td_thr_getgregs(td_thrhandle_t *th_p, prgregset_t regset)
{
	struct ps_prochandle *ph_p;
	td_err_e return_val;

	if ((ph_p = ph_lock_th(th_p, &return_val)) == NULL)
		return (return_val);
	if (ps_pstop(ph_p) != PS_OK) {
		ph_unlock(th_p->th_ta_p);
		return (TD_DBERR);
	}

	if (ps_lgetregs(ph_p, thr_to_lwpid(th_p), regset) != PS_OK)
		return_val = TD_DBERR;

	(void) ps_pcontinue(ph_p);
	ph_unlock(th_p->th_ta_p);
	return (return_val);
}

/*
 * Set a thread's general register set.
 */
#pragma weak td_thr_setgregs = __td_thr_setgregs
td_err_e
__td_thr_setgregs(td_thrhandle_t *th_p, const prgregset_t regset)
{
	struct ps_prochandle *ph_p;
	td_err_e return_val;

	if ((ph_p = ph_lock_th(th_p, &return_val)) == NULL)
		return (return_val);
	if (ps_pstop(ph_p) != PS_OK) {
		ph_unlock(th_p->th_ta_p);
		return (TD_DBERR);
	}

	if (ps_lsetregs(ph_p, thr_to_lwpid(th_p), regset) != PS_OK)
		return_val = TD_DBERR;

	(void) ps_pcontinue(ph_p);
	ph_unlock(th_p->th_ta_p);
	return (return_val);
}

/*
 * Get a thread's floating-point register set.
 */
#pragma weak td_thr_getfpregs = __td_thr_getfpregs
td_err_e
__td_thr_getfpregs(td_thrhandle_t *th_p, prfpregset_t *fpregset)
{
	struct ps_prochandle *ph_p;
	td_err_e return_val;

	if ((ph_p = ph_lock_th(th_p, &return_val)) == NULL)
		return (return_val);
	if (ps_pstop(ph_p) != PS_OK) {
		ph_unlock(th_p->th_ta_p);
		return (TD_DBERR);
	}

	if (ps_lgetfpregs(ph_p, thr_to_lwpid(th_p), fpregset) != PS_OK)
		return_val = TD_DBERR;

	(void) ps_pcontinue(ph_p);
	ph_unlock(th_p->th_ta_p);
	return (return_val);
}

/*
 * Set a thread's floating-point register set.
 */
#pragma weak td_thr_setfpregs = __td_thr_setfpregs
td_err_e
__td_thr_setfpregs(td_thrhandle_t *th_p, const prfpregset_t *fpregset)
{
	struct ps_prochandle *ph_p;
	td_err_e return_val;

	if ((ph_p = ph_lock_th(th_p, &return_val)) == NULL)
		return (return_val);
	if (ps_pstop(ph_p) != PS_OK) {
		ph_unlock(th_p->th_ta_p);
		return (TD_DBERR);
	}

	if (ps_lsetfpregs(ph_p, thr_to_lwpid(th_p), fpregset) != PS_OK)
		return_val = TD_DBERR;

	(void) ps_pcontinue(ph_p);
	ph_unlock(th_p->th_ta_p);
	return (return_val);
}

/*
 * Get the size of the extra state register set for this architecture.
 * Currently unused by dbx.
 */
#pragma weak td_thr_getxregsize = __td_thr_getxregsize
/* ARGSUSED */
td_err_e
__td_thr_getxregsize(td_thrhandle_t *th_p, int *xregsize)
{
#if defined(__sparc)
	struct ps_prochandle *ph_p;
	td_err_e return_val;

	if ((ph_p = ph_lock_th(th_p, &return_val)) == NULL)
		return (return_val);
	if (ps_pstop(ph_p) != PS_OK) {
		ph_unlock(th_p->th_ta_p);
		return (TD_DBERR);
	}

	if (ps_lgetxregsize(ph_p, thr_to_lwpid(th_p), xregsize) != PS_OK)
		return_val = TD_DBERR;

	(void) ps_pcontinue(ph_p);
	ph_unlock(th_p->th_ta_p);
	return (return_val);
#else	/* __sparc */
	return (TD_NOXREGS);
#endif	/* __sparc */
}

/*
 * Get a thread's extra state register set.
 */
#pragma weak td_thr_getxregs = __td_thr_getxregs
/* ARGSUSED */
td_err_e
__td_thr_getxregs(td_thrhandle_t *th_p, void *xregset)
{
#if defined(__sparc)
	struct ps_prochandle *ph_p;
	td_err_e return_val;

	if ((ph_p = ph_lock_th(th_p, &return_val)) == NULL)
		return (return_val);
	if (ps_pstop(ph_p) != PS_OK) {
		ph_unlock(th_p->th_ta_p);
		return (TD_DBERR);
	}

	if (ps_lgetxregs(ph_p, thr_to_lwpid(th_p), (caddr_t)xregset) != PS_OK)
		return_val = TD_DBERR;

	(void) ps_pcontinue(ph_p);
	ph_unlock(th_p->th_ta_p);
	return (return_val);
#else	/* __sparc */
	return (TD_NOXREGS);
#endif	/* __sparc */
}

/*
 * Set a thread's extra state register set.
 */
#pragma weak td_thr_setxregs = __td_thr_setxregs
/* ARGSUSED */
td_err_e
__td_thr_setxregs(td_thrhandle_t *th_p, const void *xregset)
{
#if defined(__sparc)
	struct ps_prochandle *ph_p;
	td_err_e return_val;

	if ((ph_p = ph_lock_th(th_p, &return_val)) == NULL)
		return (return_val);
	if (ps_pstop(ph_p) != PS_OK) {
		ph_unlock(th_p->th_ta_p);
		return (TD_DBERR);
	}

	if (ps_lsetxregs(ph_p, thr_to_lwpid(th_p), (caddr_t)xregset) != PS_OK)
		return_val = TD_DBERR;

	(void) ps_pcontinue(ph_p);
	ph_unlock(th_p->th_ta_p);
	return (return_val);
#else	/* __sparc */
	return (TD_NOXREGS);
#endif	/* __sparc */
}

struct searcher {
	psaddr_t	addr;
	int		status;
};

/*
 * Check the struct thread address in *th_p again first
 * value in "data".  If value in data is found, set second value
 * in "data" to 1 and return 1 to terminate iterations.
 * This function is used by td_thr_validate() to verify that
 * a thread handle is valid.
 */
static int
td_searcher(const td_thrhandle_t *th_p, void *data)
{
	struct searcher *searcher_data = (struct searcher *)data;

	if (searcher_data->addr == th_p->th_unique) {
		searcher_data->status = 1;
		return (1);
	}
	return (0);
}

/*
 * Validate the thread handle.  Check that
 * a thread exists in the thread agent/process that
 * corresponds to thread with handle *th_p.
 * Currently unused by dbx.
 */
#pragma weak td_thr_validate = __td_thr_validate
td_err_e
__td_thr_validate(const td_thrhandle_t *th_p)
{
	td_err_e return_val;
	struct searcher searcher_data = {0, 0};

	if (th_p == NULL)
		return (TD_BADTH);
	if (th_p->th_unique == NULL || th_p->th_ta_p == NULL)
		return (TD_BADTH);

	/*
	 * LOCKING EXCEPTION - Locking is not required
	 * here because no use of the thread agent is made (other
	 * than the sanity check) and checking of the thread
	 * agent will be done in __td_ta_thr_iter.
	 */

	searcher_data.addr = th_p->th_unique;
	return_val = __td_ta_thr_iter(th_p->th_ta_p,
	    td_searcher, &searcher_data,
	    TD_THR_ANY_STATE, TD_THR_LOWEST_PRIORITY,
	    TD_SIGNO_MASK, TD_THR_ANY_USER_FLAGS);

	if (return_val == TD_OK && searcher_data.status == 0)
		return_val = TD_NOTHR;

	return (return_val);
}

/*
 * Get a thread's private binding to a given thread specific
 * data(TSD) key(see thr_getspecific(3T).  If the thread doesn't
 * have a binding for a particular key, then NULL is returned.
 */
#pragma weak td_thr_tsd = __td_thr_tsd
td_err_e
__td_thr_tsd(td_thrhandle_t *th_p, thread_key_t key, void **data_pp)
{
	struct ps_prochandle *ph_p;
	td_thragent_t	*ta_p;
	td_err_e	return_val;
	int		maxkey;
	int		nkey;
	psaddr_t	tsd_paddr;

	if (data_pp == NULL)
		return (TD_ERR);
	*data_pp = NULL;
	if ((ph_p = ph_lock_th(th_p, &return_val)) == NULL)
		return (return_val);
	ta_p = th_p->th_ta_p;
	if (ps_pstop(ph_p) != PS_OK) {
		ph_unlock(ta_p);
		return (TD_DBERR);
	}

	if (ta_p->model == PR_MODEL_NATIVE) {
		ulwp_t *ulwp = (ulwp_t *)th_p->th_unique;
		tsd_metadata_t tsdm;
		tsd_t stsd;

		if (ps_pdread(ph_p,
		    ta_p->uberdata_addr + offsetof(uberdata_t, tsd_metadata),
		    &tsdm, sizeof (tsdm)) != PS_OK)
			return_val = TD_DBERR;
		else if (ps_pdread(ph_p, (psaddr_t)&ulwp->ul_stsd,
		    &tsd_paddr, sizeof (tsd_paddr)) != PS_OK)
			return_val = TD_DBERR;
		else if (tsd_paddr != NULL &&
		    ps_pdread(ph_p, tsd_paddr, &stsd, sizeof (stsd)) != PS_OK)
			return_val = TD_DBERR;
		else {
			maxkey = tsdm.tsdm_nused;
			nkey = tsd_paddr == NULL ? TSD_NFAST : stsd.tsd_nalloc;

			if (key < TSD_NFAST)
				tsd_paddr = (psaddr_t)&ulwp->ul_ftsd[0];
		}
	} else {
#if defined(_LP64) && defined(_SYSCALL32)
		ulwp32_t *ulwp = (ulwp32_t *)th_p->th_unique;
		tsd_metadata32_t tsdm;
		tsd32_t stsd;
		caddr32_t addr;

		if (ps_pdread(ph_p,
		    ta_p->uberdata_addr + offsetof(uberdata32_t, tsd_metadata),
		    &tsdm, sizeof (tsdm)) != PS_OK)
			return_val = TD_DBERR;
		else if (ps_pdread(ph_p, (psaddr_t)&ulwp->ul_stsd,
		    &addr, sizeof (addr)) != PS_OK)
			return_val = TD_DBERR;
		else if (addr != NULL &&
		    ps_pdread(ph_p, addr, &stsd, sizeof (stsd)) != PS_OK)
			return_val = TD_DBERR;
		else {
			maxkey = tsdm.tsdm_nused;
			nkey = addr == NULL ? TSD_NFAST : stsd.tsd_nalloc;

			if (key < TSD_NFAST) {
				tsd_paddr = (psaddr_t)&ulwp->ul_ftsd[0];
			} else {
				tsd_paddr = addr;
			}
		}
#else
		return_val = TD_ERR;
#endif	/* _SYSCALL32 */
	}

	if (return_val == TD_OK && (key < 1 || key >= maxkey))
		return_val = TD_NOTSD;
	if (return_val != TD_OK || key >= nkey) {
		/* NULL has already been stored in data_pp */
		(void) ps_pcontinue(ph_p);
		ph_unlock(ta_p);
		return (return_val);
	}

	/*
	 * Read the value from the thread's tsd array.
	 */
	if (ta_p->model == PR_MODEL_NATIVE) {
		void *value;

		if (ps_pdread(ph_p, tsd_paddr + key * sizeof (void *),
		    &value, sizeof (value)) != PS_OK)
			return_val = TD_DBERR;
		else
			*data_pp = value;
#if defined(_LP64) && defined(_SYSCALL32)
	} else {
		caddr32_t value32;

		if (ps_pdread(ph_p, tsd_paddr + key * sizeof (caddr32_t),
		    &value32, sizeof (value32)) != PS_OK)
			return_val = TD_DBERR;
		else
			*data_pp = (void *)(uintptr_t)value32;
#endif	/* _SYSCALL32 */
	}

	(void) ps_pcontinue(ph_p);
	ph_unlock(ta_p);
	return (return_val);
}

/*
 * Get the base address of a thread's thread local storage (TLS) block
 * for the module (executable or shared object) identified by 'moduleid'.
 */
#pragma weak td_thr_tlsbase = __td_thr_tlsbase
td_err_e
__td_thr_tlsbase(td_thrhandle_t *th_p, ulong_t moduleid, psaddr_t *base)
{
	struct ps_prochandle *ph_p;
	td_thragent_t	*ta_p;
	td_err_e	return_val;

	if (base == NULL)
		return (TD_ERR);
	*base = NULL;
	if ((ph_p = ph_lock_th(th_p, &return_val)) == NULL)
		return (return_val);
	ta_p = th_p->th_ta_p;
	if (ps_pstop(ph_p) != PS_OK) {
		ph_unlock(ta_p);
		return (TD_DBERR);
	}

	if (ta_p->model == PR_MODEL_NATIVE) {
		ulwp_t *ulwp = (ulwp_t *)th_p->th_unique;
		tls_metadata_t tls_metadata;
		TLS_modinfo tlsmod;
		tls_t tls;

		if (ps_pdread(ph_p,
		    ta_p->uberdata_addr + offsetof(uberdata_t, tls_metadata),
		    &tls_metadata, sizeof (tls_metadata)) != PS_OK)
			return_val = TD_DBERR;
		else if (moduleid >= tls_metadata.tls_modinfo.tls_size)
			return_val = TD_NOTLS;
		else if (ps_pdread(ph_p,
		    (psaddr_t)((TLS_modinfo *)
		    tls_metadata.tls_modinfo.tls_data + moduleid),
		    &tlsmod, sizeof (tlsmod)) != PS_OK)
			return_val = TD_DBERR;
		else if (tlsmod.tm_memsz == 0)
			return_val = TD_NOTLS;
		else if (tlsmod.tm_flags & TM_FLG_STATICTLS)
			*base = (psaddr_t)ulwp - tlsmod.tm_stattlsoffset;
		else if (ps_pdread(ph_p, (psaddr_t)&ulwp->ul_tls,
		    &tls, sizeof (tls)) != PS_OK)
			return_val = TD_DBERR;
		else if (moduleid >= tls.tls_size)
			return_val = TD_TLSDEFER;
		else if (ps_pdread(ph_p,
		    (psaddr_t)((tls_t *)tls.tls_data + moduleid),
		    &tls, sizeof (tls)) != PS_OK)
			return_val = TD_DBERR;
		else if (tls.tls_size == 0)
			return_val = TD_TLSDEFER;
		else
			*base = (psaddr_t)tls.tls_data;
	} else {
#if defined(_LP64) && defined(_SYSCALL32)
		ulwp32_t *ulwp = (ulwp32_t *)th_p->th_unique;
		tls_metadata32_t tls_metadata;
		TLS_modinfo32 tlsmod;
		tls32_t tls;

		if (ps_pdread(ph_p,
		    ta_p->uberdata_addr + offsetof(uberdata32_t, tls_metadata),
		    &tls_metadata, sizeof (tls_metadata)) != PS_OK)
			return_val = TD_DBERR;
		else if (moduleid >= tls_metadata.tls_modinfo.tls_size)
			return_val = TD_NOTLS;
		else if (ps_pdread(ph_p,
		    (psaddr_t)((TLS_modinfo32 *)
		    (uintptr_t)tls_metadata.tls_modinfo.tls_data + moduleid),
		    &tlsmod, sizeof (tlsmod)) != PS_OK)
			return_val = TD_DBERR;
		else if (tlsmod.tm_memsz == 0)
			return_val = TD_NOTLS;
		else if (tlsmod.tm_flags & TM_FLG_STATICTLS)
			*base = (psaddr_t)ulwp - tlsmod.tm_stattlsoffset;
		else if (ps_pdread(ph_p, (psaddr_t)&ulwp->ul_tls,
		    &tls, sizeof (tls)) != PS_OK)
			return_val = TD_DBERR;
		else if (moduleid >= tls.tls_size)
			return_val = TD_TLSDEFER;
		else if (ps_pdread(ph_p,
		    (psaddr_t)((tls32_t *)(uintptr_t)tls.tls_data + moduleid),
		    &tls, sizeof (tls)) != PS_OK)
			return_val = TD_DBERR;
		else if (tls.tls_size == 0)
			return_val = TD_TLSDEFER;
		else
			*base = (psaddr_t)tls.tls_data;
#else
		return_val = TD_ERR;
#endif	/* _SYSCALL32 */
	}

	(void) ps_pcontinue(ph_p);
	ph_unlock(ta_p);
	return (return_val);
}

/*
 * Change a thread's priority to the value specified by ti_pri.
 * Currently unused by dbx.
 */
#pragma weak td_thr_setprio = __td_thr_setprio
/* ARGSUSED */
td_err_e
__td_thr_setprio(td_thrhandle_t *th_p, int ti_pri)
{
	return (TD_NOCAPAB);
}

/*
 * This structure links td_thr_lockowner and the lowner_cb callback function.
 */
typedef struct {
	td_sync_iter_f	*owner_cb;
	void		*owner_cb_arg;
	td_thrhandle_t	*th_p;
} lowner_cb_ctl_t;

static int
lowner_cb(const td_synchandle_t *sh_p, void *arg)
{
	lowner_cb_ctl_t *ocb = arg;
	int trunc = 0;
	union {
		rwlock_t rwl;
		mutex_t mx;
	} rw_m;

	if (ps_pdread(sh_p->sh_ta_p->ph_p, sh_p->sh_unique,
	    &rw_m, sizeof (rw_m)) != PS_OK) {
		trunc = 1;
		if (ps_pdread(sh_p->sh_ta_p->ph_p, sh_p->sh_unique,
		    &rw_m.mx, sizeof (rw_m.mx)) != PS_OK)
			return (0);
	}
	if (rw_m.mx.mutex_magic == MUTEX_MAGIC &&
	    rw_m.mx.mutex_owner == ocb->th_p->th_unique)
		return ((ocb->owner_cb)(sh_p, ocb->owner_cb_arg));
	if (!trunc && rw_m.rwl.magic == RWL_MAGIC) {
		mutex_t *rwlock = &rw_m.rwl.mutex;
		if (rwlock->mutex_owner == ocb->th_p->th_unique)
			return ((ocb->owner_cb)(sh_p, ocb->owner_cb_arg));
	}
	return (0);
}

/*
 * Iterate over the set of locks owned by a specified thread.
 * If cb returns a non-zero value, terminate iterations.
 */
#pragma weak td_thr_lockowner = __td_thr_lockowner
td_err_e
__td_thr_lockowner(const td_thrhandle_t *th_p, td_sync_iter_f *cb,
	void *cb_data)
{
	td_thragent_t	*ta_p;
	td_err_e	return_val;
	lowner_cb_ctl_t	lcb;

	/*
	 * Just sanity checks.
	 */
	if (ph_lock_th((td_thrhandle_t *)th_p, &return_val) == NULL)
		return (return_val);
	ta_p = th_p->th_ta_p;
	ph_unlock(ta_p);

	lcb.owner_cb = cb;
	lcb.owner_cb_arg = cb_data;
	lcb.th_p = (td_thrhandle_t *)th_p;
	return (__td_ta_sync_iter(ta_p, lowner_cb, &lcb));
}

/*
 * If a thread is asleep on a synchronization variable,
 * then get the synchronization handle.
 */
#pragma weak td_thr_sleepinfo = __td_thr_sleepinfo
td_err_e
__td_thr_sleepinfo(const td_thrhandle_t *th_p, td_synchandle_t *sh_p)
{
	struct ps_prochandle *ph_p;
	td_err_e	return_val = TD_OK;
	uintptr_t	wchan;

	if (sh_p == NULL)
		return (TD_ERR);
	if ((ph_p = ph_lock_th((td_thrhandle_t *)th_p, &return_val)) == NULL)
		return (return_val);

	/*
	 * No need to stop the process for a simple read.
	 */
	if (th_p->th_ta_p->model == PR_MODEL_NATIVE) {
		ulwp_t *ulwp = (ulwp_t *)th_p->th_unique;

		if (ps_pdread(ph_p, (psaddr_t)&ulwp->ul_wchan,
		    &wchan, sizeof (wchan)) != PS_OK)
			return_val = TD_DBERR;
	} else {
#if defined(_LP64) && defined(_SYSCALL32)
		ulwp32_t *ulwp = (ulwp32_t *)th_p->th_unique;
		caddr32_t wchan32;

		if (ps_pdread(ph_p, (psaddr_t)&ulwp->ul_wchan,
		    &wchan32, sizeof (wchan32)) != PS_OK)
			return_val = TD_DBERR;
		wchan = wchan32;
#else
		return_val = TD_ERR;
#endif	/* _SYSCALL32 */
	}

	if (return_val != TD_OK || wchan == NULL) {
		sh_p->sh_ta_p = NULL;
		sh_p->sh_unique = NULL;
		if (return_val == TD_OK)
			return_val = TD_ERR;
	} else {
		sh_p->sh_ta_p = th_p->th_ta_p;
		sh_p->sh_unique = (psaddr_t)wchan;
	}

	ph_unlock(th_p->th_ta_p);
	return (return_val);
}

/*
 * Which thread is running on an lwp?
 */
#pragma weak td_ta_map_lwp2thr = __td_ta_map_lwp2thr
td_err_e
__td_ta_map_lwp2thr(td_thragent_t *ta_p, lwpid_t lwpid,
	td_thrhandle_t *th_p)
{
	return (__td_ta_map_id2thr(ta_p, lwpid, th_p));
}

/*
 * Common code for td_sync_get_info() and td_sync_get_stats()
 */
static td_err_e
sync_get_info_common(const td_synchandle_t *sh_p, struct ps_prochandle *ph_p,
	td_syncinfo_t *si_p)
{
	int trunc = 0;
	td_so_un_t generic_so;

	/*
	 * Determine the sync. object type; a little type fudgery here.
	 * First attempt to read the whole union.  If that fails, attempt
	 * to read just the condvar.  A condvar is the smallest sync. object.
	 */
	if (ps_pdread(ph_p, sh_p->sh_unique,
	    &generic_so, sizeof (generic_so)) != PS_OK) {
		trunc = 1;
		if (ps_pdread(ph_p, sh_p->sh_unique, &generic_so.condition,
		    sizeof (generic_so.condition)) != PS_OK)
			return (TD_DBERR);
	}

	switch (generic_so.condition.cond_magic) {
	case MUTEX_MAGIC:
		if (trunc && ps_pdread(ph_p, sh_p->sh_unique,
		    &generic_so.lock, sizeof (generic_so.lock)) != PS_OK)
			return (TD_DBERR);
		si_p->si_type = TD_SYNC_MUTEX;
		si_p->si_shared_type =
		    (generic_so.lock.mutex_type & USYNC_PROCESS);
		(void) memcpy(si_p->si_flags, &generic_so.lock.mutex_flag,
		    sizeof (generic_so.lock.mutex_flag));
		si_p->si_state.mutex_locked =
		    (generic_so.lock.mutex_lockw != 0);
		si_p->si_size = sizeof (generic_so.lock);
		si_p->si_has_waiters = generic_so.lock.mutex_waiters;
		si_p->si_rcount = generic_so.lock.mutex_rcount;
		si_p->si_prioceiling = generic_so.lock.mutex_ceiling;
		if (si_p->si_state.mutex_locked) {
			if (si_p->si_shared_type & USYNC_PROCESS)
				si_p->si_ownerpid =
				    generic_so.lock.mutex_ownerpid;
			si_p->si_owner.th_ta_p = sh_p->sh_ta_p;
			si_p->si_owner.th_unique = generic_so.lock.mutex_owner;
		}
		break;
	case COND_MAGIC:
		si_p->si_type = TD_SYNC_COND;
		si_p->si_shared_type =
		    (generic_so.condition.cond_type & USYNC_PROCESS);
		(void) memcpy(si_p->si_flags, generic_so.condition.flags.flag,
		    sizeof (generic_so.condition.flags.flag));
		si_p->si_size = sizeof (generic_so.condition);
		si_p->si_has_waiters =
		    (generic_so.condition.cond_waiters_user |
		    generic_so.condition.cond_waiters_kernel)? 1 : 0;
		break;
	case SEMA_MAGIC:
		if (trunc && ps_pdread(ph_p, sh_p->sh_unique,
		    &generic_so.semaphore, sizeof (generic_so.semaphore))
		    != PS_OK)
			return (TD_DBERR);
		si_p->si_type = TD_SYNC_SEMA;
		si_p->si_shared_type =
		    (generic_so.semaphore.type & USYNC_PROCESS);
		si_p->si_state.sem_count = generic_so.semaphore.count;
		si_p->si_size = sizeof (generic_so.semaphore);
		si_p->si_has_waiters =
		    ((lwp_sema_t *)&generic_so.semaphore)->flags[7];
		/* this is useless but the old interface provided it */
		si_p->si_data = (psaddr_t)generic_so.semaphore.count;
		break;
	case RWL_MAGIC:
	{
		uint32_t rwstate;

		if (trunc && ps_pdread(ph_p, sh_p->sh_unique,
		    &generic_so.rwlock, sizeof (generic_so.rwlock)) != PS_OK)
			return (TD_DBERR);
		si_p->si_type = TD_SYNC_RWLOCK;
		si_p->si_shared_type =
		    (generic_so.rwlock.rwlock_type & USYNC_PROCESS);
		si_p->si_size = sizeof (generic_so.rwlock);

		rwstate = (uint32_t)generic_so.rwlock.rwlock_readers;
		if (rwstate & URW_WRITE_LOCKED) {
			si_p->si_state.nreaders = -1;
			si_p->si_is_wlock = 1;
			si_p->si_owner.th_ta_p = sh_p->sh_ta_p;
			si_p->si_owner.th_unique =
			    generic_so.rwlock.rwlock_owner;
			if (si_p->si_shared_type & USYNC_PROCESS)
				si_p->si_ownerpid =
				    generic_so.rwlock.rwlock_ownerpid;
		} else {
			si_p->si_state.nreaders = (rwstate & URW_READERS_MASK);
		}
		si_p->si_has_waiters = ((rwstate & URW_HAS_WAITERS) != 0);

		/* this is useless but the old interface provided it */
		si_p->si_data = (psaddr_t)generic_so.rwlock.readers;
		break;
	}
	default:
		return (TD_BADSH);
	}

	si_p->si_ta_p = sh_p->sh_ta_p;
	si_p->si_sv_addr = sh_p->sh_unique;
	return (TD_OK);
}

/*
 * Given a synchronization handle, fill in the
 * information for the synchronization variable into *si_p.
 */
#pragma weak td_sync_get_info = __td_sync_get_info
td_err_e
__td_sync_get_info(const td_synchandle_t *sh_p, td_syncinfo_t *si_p)
{
	struct ps_prochandle *ph_p;
	td_err_e return_val;

	if (si_p == NULL)
		return (TD_ERR);
	(void) memset(si_p, 0, sizeof (*si_p));
	if ((ph_p = ph_lock_sh(sh_p, &return_val)) == NULL)
		return (return_val);
	if (ps_pstop(ph_p) != PS_OK) {
		ph_unlock(sh_p->sh_ta_p);
		return (TD_DBERR);
	}

	return_val = sync_get_info_common(sh_p, ph_p, si_p);

	(void) ps_pcontinue(ph_p);
	ph_unlock(sh_p->sh_ta_p);
	return (return_val);
}

static uint_t
tdb_addr_hash64(uint64_t addr)
{
	uint64_t value60 = (addr >> 4);
	uint32_t value30 = (value60 >> 30) ^ (value60 & 0x3fffffff);
	return ((value30 >> 15) ^ (value30 & 0x7fff));
}

static uint_t
tdb_addr_hash32(uint64_t addr)
{
	uint32_t value30 = (addr >> 2);		/* 30 bits */
	return ((value30 >> 15) ^ (value30 & 0x7fff));
}

static td_err_e
read_sync_stats(td_thragent_t *ta_p, psaddr_t hash_table,
	psaddr_t sync_obj_addr, tdb_sync_stats_t *sync_stats)
{
	psaddr_t next_desc;
	uint64_t first;
	uint_t ix;

	/*
	 * Compute the hash table index from the synch object's address.
	 */
	if (ta_p->model == PR_MODEL_LP64)
		ix = tdb_addr_hash64(sync_obj_addr);
	else
		ix = tdb_addr_hash32(sync_obj_addr);

	/*
	 * Get the address of the first element in the linked list.
	 */
	if (ps_pdread(ta_p->ph_p, hash_table + ix * sizeof (uint64_t),
	    &first, sizeof (first)) != PS_OK)
		return (TD_DBERR);

	/*
	 * Search the linked list for an entry for the synch object..
	 */
	for (next_desc = (psaddr_t)first; next_desc != NULL;
	    next_desc = (psaddr_t)sync_stats->next) {
		if (ps_pdread(ta_p->ph_p, next_desc,
		    sync_stats, sizeof (*sync_stats)) != PS_OK)
			return (TD_DBERR);
		if (sync_stats->sync_addr == sync_obj_addr)
			return (TD_OK);
	}

	(void) memset(sync_stats, 0, sizeof (*sync_stats));
	return (TD_OK);
}

/*
 * Given a synchronization handle, fill in the
 * statistics for the synchronization variable into *ss_p.
 */
#pragma weak td_sync_get_stats = __td_sync_get_stats
td_err_e
__td_sync_get_stats(const td_synchandle_t *sh_p, td_syncstats_t *ss_p)
{
	struct ps_prochandle *ph_p;
	td_thragent_t *ta_p;
	td_err_e return_val;
	register_sync_t enable;
	psaddr_t hashaddr;
	tdb_sync_stats_t sync_stats;
	size_t ix;

	if (ss_p == NULL)
		return (TD_ERR);
	(void) memset(ss_p, 0, sizeof (*ss_p));
	if ((ph_p = ph_lock_sh(sh_p, &return_val)) == NULL)
		return (return_val);
	ta_p = sh_p->sh_ta_p;
	if (ps_pstop(ph_p) != PS_OK) {
		ph_unlock(ta_p);
		return (TD_DBERR);
	}

	if ((return_val = sync_get_info_common(sh_p, ph_p, &ss_p->ss_info))
	    != TD_OK) {
		if (return_val != TD_BADSH)
			goto out;
		/* we can correct TD_BADSH */
		(void) memset(&ss_p->ss_info, 0, sizeof (ss_p->ss_info));
		ss_p->ss_info.si_ta_p = sh_p->sh_ta_p;
		ss_p->ss_info.si_sv_addr = sh_p->sh_unique;
		/* we correct si_type and si_size below */
		return_val = TD_OK;
	}
	if (ps_pdread(ph_p, ta_p->tdb_register_sync_addr,
	    &enable, sizeof (enable)) != PS_OK) {
		return_val = TD_DBERR;
		goto out;
	}
	if (enable != REGISTER_SYNC_ON)
		goto out;

	/*
	 * Get the address of the hash table in the target process.
	 */
	if (ta_p->model == PR_MODEL_NATIVE) {
		if (ps_pdread(ph_p, ta_p->uberdata_addr +
		    offsetof(uberdata_t, tdb.tdb_sync_addr_hash),
		    &hashaddr, sizeof (&hashaddr)) != PS_OK) {
			return_val = TD_DBERR;
			goto out;
		}
	} else {
#if defined(_LP64) && defined(_SYSCALL32)
		caddr32_t addr;

		if (ps_pdread(ph_p, ta_p->uberdata_addr +
		    offsetof(uberdata32_t, tdb.tdb_sync_addr_hash),
		    &addr, sizeof (addr)) != PS_OK) {
			return_val = TD_DBERR;
			goto out;
		}
		hashaddr = addr;
#else
		return_val = TD_ERR;
		goto out;
#endif	/* _SYSCALL32 */
	}

	if (hashaddr == 0)
		return_val = TD_BADSH;
	else
		return_val = read_sync_stats(ta_p, hashaddr,
		    sh_p->sh_unique, &sync_stats);
	if (return_val != TD_OK)
		goto out;

	/*
	 * We have the hash table entry.  Transfer the data to
	 * the td_syncstats_t structure provided by the caller.
	 */
	switch (sync_stats.un.type) {
	case TDB_MUTEX:
	{
		td_mutex_stats_t *msp = &ss_p->ss_un.mutex;

		ss_p->ss_info.si_type = TD_SYNC_MUTEX;
		ss_p->ss_info.si_size = sizeof (mutex_t);
		msp->mutex_lock =
		    sync_stats.un.mutex.mutex_lock;
		msp->mutex_sleep =
		    sync_stats.un.mutex.mutex_sleep;
		msp->mutex_sleep_time =
		    sync_stats.un.mutex.mutex_sleep_time;
		msp->mutex_hold_time =
		    sync_stats.un.mutex.mutex_hold_time;
		msp->mutex_try =
		    sync_stats.un.mutex.mutex_try;
		msp->mutex_try_fail =
		    sync_stats.un.mutex.mutex_try_fail;
		if (sync_stats.sync_addr >= ta_p->hash_table_addr &&
		    (ix = sync_stats.sync_addr - ta_p->hash_table_addr)
		    < ta_p->hash_size * sizeof (thr_hash_table_t))
			msp->mutex_internal =
			    ix / sizeof (thr_hash_table_t) + 1;
		break;
	}
	case TDB_COND:
	{
		td_cond_stats_t *csp = &ss_p->ss_un.cond;

		ss_p->ss_info.si_type = TD_SYNC_COND;
		ss_p->ss_info.si_size = sizeof (cond_t);
		csp->cond_wait =
		    sync_stats.un.cond.cond_wait;
		csp->cond_timedwait =
		    sync_stats.un.cond.cond_timedwait;
		csp->cond_wait_sleep_time =
		    sync_stats.un.cond.cond_wait_sleep_time;
		csp->cond_timedwait_sleep_time =
		    sync_stats.un.cond.cond_timedwait_sleep_time;
		csp->cond_timedwait_timeout =
		    sync_stats.un.cond.cond_timedwait_timeout;
		csp->cond_signal =
		    sync_stats.un.cond.cond_signal;
		csp->cond_broadcast =
		    sync_stats.un.cond.cond_broadcast;
		if (sync_stats.sync_addr >= ta_p->hash_table_addr &&
		    (ix = sync_stats.sync_addr - ta_p->hash_table_addr)
		    < ta_p->hash_size * sizeof (thr_hash_table_t))
			csp->cond_internal =
			    ix / sizeof (thr_hash_table_t) + 1;
		break;
	}
	case TDB_RWLOCK:
	{
		td_rwlock_stats_t *rwsp = &ss_p->ss_un.rwlock;

		ss_p->ss_info.si_type = TD_SYNC_RWLOCK;
		ss_p->ss_info.si_size = sizeof (rwlock_t);
		rwsp->rw_rdlock =
		    sync_stats.un.rwlock.rw_rdlock;
		rwsp->rw_rdlock_try =
		    sync_stats.un.rwlock.rw_rdlock_try;
		rwsp->rw_rdlock_try_fail =
		    sync_stats.un.rwlock.rw_rdlock_try_fail;
		rwsp->rw_wrlock =
		    sync_stats.un.rwlock.rw_wrlock;
		rwsp->rw_wrlock_hold_time =
		    sync_stats.un.rwlock.rw_wrlock_hold_time;
		rwsp->rw_wrlock_try =
		    sync_stats.un.rwlock.rw_wrlock_try;
		rwsp->rw_wrlock_try_fail =
		    sync_stats.un.rwlock.rw_wrlock_try_fail;
		break;
	}
	case TDB_SEMA:
	{
		td_sema_stats_t *ssp = &ss_p->ss_un.sema;

		ss_p->ss_info.si_type = TD_SYNC_SEMA;
		ss_p->ss_info.si_size = sizeof (sema_t);
		ssp->sema_wait =
		    sync_stats.un.sema.sema_wait;
		ssp->sema_wait_sleep =
		    sync_stats.un.sema.sema_wait_sleep;
		ssp->sema_wait_sleep_time =
		    sync_stats.un.sema.sema_wait_sleep_time;
		ssp->sema_trywait =
		    sync_stats.un.sema.sema_trywait;
		ssp->sema_trywait_fail =
		    sync_stats.un.sema.sema_trywait_fail;
		ssp->sema_post =
		    sync_stats.un.sema.sema_post;
		ssp->sema_max_count =
		    sync_stats.un.sema.sema_max_count;
		ssp->sema_min_count =
		    sync_stats.un.sema.sema_min_count;
		break;
	}
	default:
		return_val = TD_BADSH;
		break;
	}

out:
	(void) ps_pcontinue(ph_p);
	ph_unlock(ta_p);
	return (return_val);
}

/*
 * Change the state of a synchronization variable.
 *	1) mutex lock state set to value
 *	2) semaphore's count set to value
 *	3) writer's lock set by value < 0
 *	4) reader's lock number of readers set to value >= 0
 * Currently unused by dbx.
 */
#pragma weak td_sync_setstate = __td_sync_setstate
td_err_e
__td_sync_setstate(const td_synchandle_t *sh_p, long lvalue)
{
	struct ps_prochandle *ph_p;
	int		trunc = 0;
	td_err_e	return_val;
	td_so_un_t	generic_so;
	uint32_t	*rwstate;
	int		value = (int)lvalue;

	if ((ph_p = ph_lock_sh(sh_p, &return_val)) == NULL)
		return (return_val);
	if (ps_pstop(ph_p) != PS_OK) {
		ph_unlock(sh_p->sh_ta_p);
		return (TD_DBERR);
	}

	/*
	 * Read the synch. variable information.
	 * First attempt to read the whole union and if that fails
	 * fall back to reading only the smallest member, the condvar.
	 */
	if (ps_pdread(ph_p, sh_p->sh_unique, &generic_so,
	    sizeof (generic_so)) != PS_OK) {
		trunc = 1;
		if (ps_pdread(ph_p, sh_p->sh_unique, &generic_so.condition,
		    sizeof (generic_so.condition)) != PS_OK) {
			(void) ps_pcontinue(ph_p);
			ph_unlock(sh_p->sh_ta_p);
			return (TD_DBERR);
		}
	}

	/*
	 * Set the new value in the sync. variable, read the synch. variable
	 * information. from the process, reset its value and write it back.
	 */
	switch (generic_so.condition.mutex_magic) {
	case MUTEX_MAGIC:
		if (trunc && ps_pdread(ph_p, sh_p->sh_unique,
		    &generic_so.lock, sizeof (generic_so.lock)) != PS_OK) {
			return_val = TD_DBERR;
			break;
		}
		generic_so.lock.mutex_lockw = (uint8_t)value;
		if (ps_pdwrite(ph_p, sh_p->sh_unique, &generic_so.lock,
		    sizeof (generic_so.lock)) != PS_OK)
			return_val = TD_DBERR;
		break;
	case SEMA_MAGIC:
		if (trunc && ps_pdread(ph_p, sh_p->sh_unique,
		    &generic_so.semaphore, sizeof (generic_so.semaphore))
		    != PS_OK) {
			return_val = TD_DBERR;
			break;
		}
		generic_so.semaphore.count = value;
		if (ps_pdwrite(ph_p, sh_p->sh_unique, &generic_so.semaphore,
		    sizeof (generic_so.semaphore)) != PS_OK)
			return_val = TD_DBERR;
		break;
	case COND_MAGIC:
		/* Operation not supported on a condition variable */
		return_val = TD_ERR;
		break;
	case RWL_MAGIC:
		if (trunc && ps_pdread(ph_p, sh_p->sh_unique,
		    &generic_so.rwlock, sizeof (generic_so.rwlock)) != PS_OK) {
			return_val = TD_DBERR;
			break;
		}
		rwstate = (uint32_t *)&generic_so.rwlock.readers;
		*rwstate &= URW_HAS_WAITERS;
		if (value < 0)
			*rwstate |= URW_WRITE_LOCKED;
		else
			*rwstate |= (value & URW_READERS_MASK);
		if (ps_pdwrite(ph_p, sh_p->sh_unique, &generic_so.rwlock,
		    sizeof (generic_so.rwlock)) != PS_OK)
			return_val = TD_DBERR;
		break;
	default:
		/* Bad sync. object type */
		return_val = TD_BADSH;
		break;
	}

	(void) ps_pcontinue(ph_p);
	ph_unlock(sh_p->sh_ta_p);
	return (return_val);
}

typedef struct {
	td_thr_iter_f	*waiter_cb;
	psaddr_t	sync_obj_addr;
	uint16_t	sync_magic;
	void		*waiter_cb_arg;
	td_err_e	errcode;
} waiter_cb_ctl_t;

static int
waiters_cb(const td_thrhandle_t *th_p, void *arg)
{
	td_thragent_t	*ta_p = th_p->th_ta_p;
	struct ps_prochandle *ph_p = ta_p->ph_p;
	waiter_cb_ctl_t	*wcb = arg;
	caddr_t		wchan;

	if (ta_p->model == PR_MODEL_NATIVE) {
		ulwp_t *ulwp = (ulwp_t *)th_p->th_unique;

		if (ps_pdread(ph_p, (psaddr_t)&ulwp->ul_wchan,
		    &wchan, sizeof (wchan)) != PS_OK) {
			wcb->errcode = TD_DBERR;
			return (1);
		}
	} else {
#if defined(_LP64) && defined(_SYSCALL32)
		ulwp32_t *ulwp = (ulwp32_t *)th_p->th_unique;
		caddr32_t wchan32;

		if (ps_pdread(ph_p, (psaddr_t)&ulwp->ul_wchan,
		    &wchan32, sizeof (wchan32)) != PS_OK) {
			wcb->errcode = TD_DBERR;
			return (1);
		}
		wchan = (caddr_t)(uintptr_t)wchan32;
#else
		wcb->errcode = TD_ERR;
		return (1);
#endif	/* _SYSCALL32 */
	}

	if (wchan == NULL)
		return (0);

	if (wchan == (caddr_t)wcb->sync_obj_addr)
		return ((*wcb->waiter_cb)(th_p, wcb->waiter_cb_arg));

	return (0);
}

/*
 * For a given synchronization variable, iterate over the
 * set of waiting threads.  The call back function is passed
 * two parameters, a pointer to a thread handle and a pointer
 * to extra call back data.
 */
#pragma weak td_sync_waiters = __td_sync_waiters
td_err_e
__td_sync_waiters(const td_synchandle_t *sh_p, td_thr_iter_f *cb, void *cb_data)
{
	struct ps_prochandle *ph_p;
	waiter_cb_ctl_t	wcb;
	td_err_e	return_val;

	if ((ph_p = ph_lock_sh(sh_p, &return_val)) == NULL)
		return (return_val);
	if (ps_pdread(ph_p,
	    (psaddr_t)&((mutex_t *)sh_p->sh_unique)->mutex_magic,
	    (caddr_t)&wcb.sync_magic, sizeof (wcb.sync_magic)) != PS_OK) {
		ph_unlock(sh_p->sh_ta_p);
		return (TD_DBERR);
	}
	ph_unlock(sh_p->sh_ta_p);

	switch (wcb.sync_magic) {
	case MUTEX_MAGIC:
	case COND_MAGIC:
	case SEMA_MAGIC:
	case RWL_MAGIC:
		break;
	default:
		return (TD_BADSH);
	}

	wcb.waiter_cb = cb;
	wcb.sync_obj_addr = sh_p->sh_unique;
	wcb.waiter_cb_arg = cb_data;
	wcb.errcode = TD_OK;
	return_val = __td_ta_thr_iter(sh_p->sh_ta_p, waiters_cb, &wcb,
	    TD_THR_SLEEP, TD_THR_LOWEST_PRIORITY,
	    TD_SIGNO_MASK, TD_THR_ANY_USER_FLAGS);

	if (return_val != TD_OK)
		return (return_val);

	return (wcb.errcode);
}
