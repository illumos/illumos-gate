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
 * Copyright 2016, Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/bitmap.h>
#include <sys/var.h>
#include <sys/thread.h>
#include <sys/proc.h>
#include <sys/brand.h>
#include <sys/zone.h>
#include <sys/lx_brand.h>

#define	LINUX_PROC_FACTOR	8	/* factor down the hash table by this */
static int hash_len = 4;		/* desired average hash chain length */
static int hash_size;			/* no of buckets in the hash table */

static struct lx_pid **stol_pid_hash;
static struct lx_pid **ltos_pid_hash;

#define	LTOS_HASH(pid)		((pid) & (hash_size - 1))
#define	STOL_HASH(pid, tid)	(((pid) + (tid)) & (hash_size - 1))

static kmutex_t hash_lock;

static void
lx_pid_insert_hash(struct lx_pid *lpidp)
{
	int shash = STOL_HASH(lpidp->lxp_spid, lpidp->lxp_stid);
	int lhash = LTOS_HASH(lpidp->lxp_lpid);

	ASSERT(MUTEX_HELD(&hash_lock));

	lpidp->lxp_stol_next = stol_pid_hash[shash];
	stol_pid_hash[shash] = lpidp;

	lpidp->lxp_ltos_next = ltos_pid_hash[lhash];
	ltos_pid_hash[lhash] = lpidp;
}

static struct lx_pid *
lx_pid_remove_hash(pid_t pid, id_t tid)
{
	struct lx_pid **hpp;
	struct lx_pid *lpidp = NULL;

	ASSERT(MUTEX_HELD(&hash_lock));

	hpp = &stol_pid_hash[STOL_HASH(pid, tid)];
	while (*hpp) {
		if ((*hpp)->lxp_spid == pid && (*hpp)->lxp_stid == tid) {
			lpidp = *hpp;
			*hpp = (*hpp)->lxp_stol_next;
			break;
		}
		hpp = &(*hpp)->lxp_stol_next;
	}

	/*
	 * when called during error recovery the pid may already
	 * be released
	 */
	if (lpidp == NULL)
		return (NULL);

	hpp = &ltos_pid_hash[LTOS_HASH(lpidp->lxp_lpid)];
	while (*hpp) {
		if (*hpp == lpidp) {
			*hpp = lpidp->lxp_ltos_next;
			break;
		}
		hpp = &(*hpp)->lxp_ltos_next;
	}

	return (lpidp);
}

/*
 * given a solaris pid/tid pair, create a linux pid
 */
void
lx_pid_assign(kthread_t *t, struct lx_pid *lpidp)
{
	proc_t *p = ttoproc(t);
	lx_lwp_data_t *lwpd = ttolxlwp(t);
	pid_t spid = p->p_pid;
	id_t stid = t->t_tid;

	/*
	 * When lx_initlwp is called from lx_setbrand, p_lwpcnt will already be
	 * equal to 1. Since lx_initlwp is being called against an lwp that
	 * already exists, an additional pid allocation is not necessary.
	 *
	 * We check for this by testing br_ppid == 0.
	 */
	if (p->p_lwpcnt > 0 && lwpd->br_ppid != 0) {
		/*
		 * Assign allocated pid to any thread other than the first.
		 * The lpid and pidp fields should be populated.
		 */
		VERIFY(lpidp->lxp_pidp != NULL);
		VERIFY(lpidp->lxp_lpid != 0);
	} else {
		/*
		 * There are cases where a pid is speculatively allocated but
		 * is not needed.  We are obligated to free it here.
		 */
		if (lpidp->lxp_pidp != NULL) {
			(void) pid_rele(lpidp->lxp_pidp);
		}
		lpidp->lxp_pidp = NULL;
		lpidp->lxp_lpid = spid;
	}

	lpidp->lxp_spid = spid;
	lpidp->lxp_stid = stid;
	lpidp->lxp_start = t->t_start;
	lpidp->lxp_procp = p;

	/*
	 * Now place the pid into the Linux-SunOS and SunOS-Linux conversion
	 * hash tables.
	 */
	mutex_enter(&hash_lock);
	lx_pid_insert_hash(lpidp);
	mutex_exit(&hash_lock);

	lwpd->br_pid = lpidp->lxp_lpid;
}

/*
 * If we are exec()ing the process, this thread's tid is about to be reset
 * to 1.  Make sure the Linux PID bookkeeping reflects that change.
 */
void
lx_pid_reassign(kthread_t *t)
{
	proc_t *p = ttoproc(t);
	struct pid *old_pidp;
	struct lx_pid *lpidp;

	ASSERT(p->p_lwpcnt == 1);

	mutex_enter(&hash_lock);

	/*
	 * Clean up all the traces of this thread's 'fake' Linux PID.
	 */
	lpidp = lx_pid_remove_hash(p->p_pid, t->t_tid);
	ASSERT(lpidp != NULL);
	old_pidp = lpidp->lxp_pidp;
	lpidp->lxp_pidp = NULL;

	/*
	 * Now register this thread as (pid, 1).
	 */
	lpidp->lxp_lpid = p->p_pid;
	lpidp->lxp_spid = p->p_pid;
	lpidp->lxp_stid = 1;
	lx_pid_insert_hash(lpidp);

	mutex_exit(&hash_lock);

	if (old_pidp)
		(void) pid_rele(old_pidp);
}

/*
 * release a solaris pid/tid pair
 */
void
lx_pid_rele(pid_t pid, id_t tid)
{
	struct lx_pid *lpidp;

	mutex_enter(&hash_lock);
	lpidp = lx_pid_remove_hash(pid, tid);
	mutex_exit(&hash_lock);

	if (lpidp) {
		if (lpidp->lxp_pidp)
			(void) pid_rele(lpidp->lxp_pidp);

		kmem_free(lpidp, sizeof (*lpidp));
	}
}

/*
 * given a linux pid, return the solaris pid/tid pair
 */
int
lx_lpid_to_spair(pid_t lpid, pid_t *spid, id_t *stid)
{
	struct lx_pid *hp;

	if (lpid == 1) {
		pid_t initpid;

		/*
		 * We are trying to look up the Linux init process for the
		 * current zone, which we pretend has pid 1.
		 */
		if ((initpid = curzone->zone_proc_initpid) == -1) {
			/*
			 * We could not find the init process for this zone.
			 */
			return (-1);
		}

		if (spid != NULL)
			*spid = initpid;
		if (stid != NULL)
			*stid = 1;

		return (0);
	}

	mutex_enter(&hash_lock);
	for (hp = ltos_pid_hash[LTOS_HASH(lpid)]; hp != NULL;
	    hp = hp->lxp_ltos_next) {
		if (hp->lxp_lpid == lpid) {
			if (spid)
				*spid = hp->lxp_spid;
			if (stid)
				*stid = hp->lxp_stid;
			break;
		}
	}
	mutex_exit(&hash_lock);
	if (hp != NULL)
		return (0);

	/*
	 * We didn't find this pid in our translation table.
	 * But this still could be the pid of a native process
	 * running in the current zone so check for that here.
	 *
	 * Note that prfind() only searches for processes in the current zone.
	 */
	mutex_enter(&pidlock);
	if (prfind(lpid) != NULL) {
		mutex_exit(&pidlock);
		if (spid)
			*spid = lpid;
		if (stid)
			*stid = 0;
		return (0);
	}
	mutex_exit(&pidlock);

	return (-1);
}

/*
 * Given a Linux pid, locate the proc_t and optionally acquire P_PR_LOCK.
 * Returns 0 on success with p_lock held for the proc_t in question.
 */
int
lx_lpid_lock(pid_t lpid, zone_t *zone, lx_pid_flag_t flag, proc_t **pp,
    kthread_t **tp)
{
	proc_t *p = NULL;
	kthread_t *t;
	id_t tid = 0;

	ASSERT(MUTEX_NOT_HELD(&pidlock));
	ASSERT(pp != NULL);
	ASSERT(zone != NULL && zone->zone_brand == &lx_brand);

retry:
	if (lpid == 1) {
		pid_t initpid;

		/*
		 * Look up the init process for the zone.
		 */
		if ((initpid = zone->zone_proc_initpid) <= 0) {
			return (-1);
		}
		mutex_enter(&pidlock);
		p = prfind_zone(initpid, zone->zone_id);
		tid = 0;
	} else {
		struct lx_pid *hp;

		mutex_enter(&pidlock);
		mutex_enter(&hash_lock);
		for (hp = ltos_pid_hash[LTOS_HASH(lpid)]; hp != NULL;
		    hp = hp->lxp_ltos_next) {
			if (hp->lxp_lpid == lpid) {
				tid = hp->lxp_stid;
				p = hp->lxp_procp;
				break;
			}
		}
		mutex_exit(&hash_lock);
		/*
		 * If the pid wasn't listed in the ltos hash, it may correspond
		 * to an native process in the zone.
		 */
		if (p == NULL) {
			p = prfind_zone(lpid, zone->zone_id);
			tid = 0;
		}
	}

	if (p == NULL) {
		mutex_exit(&pidlock);
		return (-1);
	}

	/*
	 * Bail on processes belonging to the system, those which are not yet
	 * complete and zombies (unless explicitly allowed via the flags).
	 */
	if (p->p_stat == SIDL || (p->p_flag & SSYS) != 0 ||
	    (p->p_stat == SZOMB && (flag & LXP_ZOMBOK) == 0)) {
		mutex_exit(&pidlock);
		return (-1);
	}
	mutex_enter(&p->p_lock);
	mutex_exit(&pidlock);

	if (flag & LXP_PRLOCK) {
		/*
		 * It would be convenient to call sprtrylock_proc() for this
		 * task.  Unfortunately, its behavior of filtering zombies is
		 * excessive for some lx_proc use cases.  Instead, when the
		 * provided flags do not indicate that zombies are allowed,
		 * exiting processes are filtered out (as would be performed by
		 * sprtrylock_proc).
		 */
		if ((p->p_flag & (SEXITING|SEXITLWPS)) != 0 &&
		    (flag & LXP_ZOMBOK) == 0) {
			mutex_exit(&p->p_lock);
			return (-1);
		}
		if (p->p_proc_flag & P_PR_LOCK) {
			sprwaitlock_proc(p);
			goto retry;
		} else {
			p->p_proc_flag |= P_PR_LOCK;
			THREAD_KPRI_REQUEST();
		}
	}

	if (tid == 0) {
		t = p->p_tlist;
	} else {
		lwpdir_t *ld;

		ld = lwp_hash_lookup(p, tid);
		if (ld == NULL) {
			if (flag & LXP_PRLOCK) {
				sprunprlock(p);
			}
			mutex_exit(&p->p_lock);
			return (-1);
		}
		t = ld->ld_entry->le_thread;
	}
	*pp = p;
	if (tp != NULL) {
		*tp = t;
	}
	return (0);
}


/*
 * Given an lwp, return the Linux pid of its parent.  If the caller
 * wants them, we return the Solaris (pid, tid) as well.
 */
pid_t
lx_lwp_ppid(klwp_t *lwp, pid_t *ppidp, id_t *ptidp)
{
	lx_lwp_data_t *lwpd = lwptolxlwp(lwp);
	proc_t *p = lwptoproc(lwp);
	struct lx_pid *hp;
	pid_t zoneinit = curproc->p_zone->zone_proc_initpid;
	pid_t lppid, ppid;

	/*
	 * Be sure not to return a parent pid that should be invisible
	 * within this zone.
	 */
	ppid = ((p->p_flag & SZONETOP)
	    ? curproc->p_zone->zone_zsched->p_pid : p->p_ppid);

	/*
	 * If the parent process's pid is the zone's init process, force it
	 * to the Linux init pid value of 1.
	 */
	if (ppid == zoneinit)
		ppid = 1;

	/*
	 * There are two cases in which the Linux definition of a 'parent'
	 * matches that of Solaris:
	 *
	 * - if our tgid is the same as our PID, then we are either the
	 *   first thread in the process or a CLONE_THREAD thread.
	 *
	 * - if the brand lwp value for ppid is 0, then we are either the
	 *   child of a differently-branded process or a CLONE_PARENT thread.
	 */
	if (p->p_pid == lwpd->br_tgid || lwpd->br_ppid == 0) {
		if (ppidp != NULL)
			*ppidp = ppid;
		if (ptidp != NULL)
			*ptidp = -1;
		return (ppid);
	}

	/*
	 * Set the default Linux parent pid to be the pid of the zone's init
	 * process; this will get converted back to the Linux default of 1
	 * later.
	 */
	lppid = zoneinit;

	/*
	 * If the process's parent isn't init, try and look up the Linux "pid"
	 * corresponding to the process's parent.
	 */
	if (ppid != 1) {
		/*
		 * In all other cases, we are looking for the parent of this
		 * specific thread, which in Linux refers to the thread that
		 * clone()d it.   We stashed that thread's PID away when this
		 * thread was created.
		 */
		mutex_enter(&hash_lock);
		for (hp = ltos_pid_hash[LTOS_HASH(lwpd->br_ppid)]; hp != NULL;
		    hp = hp->lxp_ltos_next) {
			if (lwpd->br_ppid == hp->lxp_lpid) {
				/*
				 * We found the PID we were looking for, but
				 * since we cached its value in this LWP's brand
				 * structure, it has exited and been reused by
				 * another process.
				 */
				if (hp->lxp_start > lwptot(lwp)->t_start)
					break;

				lppid = lwpd->br_ppid;
				if (ppidp != NULL)
					*ppidp = hp->lxp_spid;
				if (ptidp != NULL)
					*ptidp = hp->lxp_stid;

				break;
			}
		}
		mutex_exit(&hash_lock);
	}

	if (lppid == zoneinit) {
		lppid = 1;

		if (ppidp != NULL)
			*ppidp = lppid;
		if (ptidp != NULL)
			*ptidp = -1;
	}

	return (lppid);
}

void
lx_pid_init(void)
{
	hash_size = 1 << highbit(v.v_proc / (hash_len * LINUX_PROC_FACTOR));

	stol_pid_hash = kmem_zalloc(sizeof (struct lx_pid *) * hash_size,
	    KM_SLEEP);
	ltos_pid_hash = kmem_zalloc(sizeof (struct lx_pid *) * hash_size,
	    KM_SLEEP);

	mutex_init(&hash_lock, NULL, MUTEX_DEFAULT, NULL);
}

void
lx_pid_fini(void)
{
	kmem_free(stol_pid_hash, sizeof (struct lx_pid *) * hash_size);
	kmem_free(ltos_pid_hash, sizeof (struct lx_pid *) * hash_size);
}
