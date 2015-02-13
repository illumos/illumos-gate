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
 * Copyright 2015, Joyent, Inc.
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
#include <sys/lx_pid.h>

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
	int shash = STOL_HASH(lpidp->s_pid, lpidp->s_tid);
	int lhash = LTOS_HASH(lpidp->l_pid);

	ASSERT(MUTEX_HELD(&hash_lock));

	lpidp->stol_next = stol_pid_hash[shash];
	stol_pid_hash[shash] = lpidp;

	lpidp->ltos_next = ltos_pid_hash[lhash];
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
		if ((*hpp)->s_pid == pid && (*hpp)->s_tid == tid) {
			lpidp = *hpp;
			*hpp = (*hpp)->stol_next;
			break;
		}
		hpp = &(*hpp)->stol_next;
	}

	/*
	 * when called during error recovery the pid may already
	 * be released
	 */
	if (lpidp == NULL)
		return (NULL);

	hpp = &ltos_pid_hash[LTOS_HASH(lpidp->l_pid)];
	while (*hpp) {
		if (*hpp == lpidp) {
			*hpp = lpidp->ltos_next;
			break;
		}
		hpp = &(*hpp)->ltos_next;
	}

	return (lpidp);
}

struct pid *pid_find(pid_t pid);

/*
 * given a solaris pid/tid pair, create a linux pid
 */
int
lx_pid_assign(kthread_t *t)
{
	proc_t *p = ttoproc(t);
	pid_t s_pid = p->p_pid;
	id_t s_tid = t->t_tid;
	struct pid *pidp;
	struct lx_pid *lpidp;
	lx_lwp_data_t *lwpd = ttolxlwp(t);
	pid_t newpid;

	/*
	 * When lx_initlwp is called from lx_setbrand, p_lwpcnt will already be
	 * equal to 1. Since lx_initlwp is being called against an lwp that
	 * already exists, pid_allocate is not necessary.
	 *
	 * We check for this by testing br_ppid == 0.
	 */
	if (p->p_lwpcnt > 0 && lwpd->br_ppid != 0) {
		/*
		 * Allocate a pid for any thread other than the first
		 */
		if ((newpid = pid_allocate(p, 0, 0)) < 0)
			return (-1);

		pidp = pid_find(newpid);
	} else {
		pidp = NULL;
		newpid = s_pid;
	}

	lpidp = kmem_alloc(sizeof (struct lx_pid), KM_SLEEP);
	lpidp->l_pid = newpid;
	lpidp->s_pid = s_pid;
	lpidp->s_tid = s_tid;
	lpidp->l_pidp = pidp;
	lpidp->l_start = t->t_start;

	/*
	 * now put the pid into the linux-solaris and solaris-linux
	 * conversion hash tables
	 */
	mutex_enter(&hash_lock);
	lx_pid_insert_hash(lpidp);
	mutex_exit(&hash_lock);

	lwpd->br_pid = newpid;

	return (0);
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
	old_pidp = lpidp->l_pidp;
	lpidp->l_pidp = NULL;

	/*
	 * Now register this thread as (pid, 1).
	 */
	lpidp->l_pid = p->p_pid;
	lpidp->s_pid = p->p_pid;
	lpidp->s_tid = 1;
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
		if (lpidp->l_pidp)
			(void) pid_rele(lpidp->l_pidp);

		kmem_free(lpidp, sizeof (*lpidp));
	}
}

/*
 * given a linux pid, return the solaris pid/tid pair
 */
int
lx_lpid_to_spair(pid_t l_pid, pid_t *s_pid, id_t *s_tid)
{
	struct lx_pid *hp;

	if (l_pid == 1) {
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

		if (s_pid != NULL)
			*s_pid = initpid;
		if (s_tid != NULL)
			*s_tid = 1;

		return (0);
	}

	mutex_enter(&hash_lock);
	for (hp = ltos_pid_hash[LTOS_HASH(l_pid)]; hp; hp = hp->ltos_next) {
		if (l_pid == hp->l_pid) {
			if (s_pid)
				*s_pid = hp->s_pid;
			if (s_tid)
				*s_tid = hp->s_tid;
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
	if (prfind(l_pid) != NULL) {
		mutex_exit(&pidlock);
		if (s_pid)
			*s_pid = l_pid;
		if (s_tid)
			*s_tid = 0;
		return (0);
	}
	mutex_exit(&pidlock);

	return (-1);
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
		for (hp = ltos_pid_hash[LTOS_HASH(lwpd->br_ppid)]; hp;
		    hp = hp->ltos_next) {
			if (lwpd->br_ppid == hp->l_pid) {
				/*
				 * We found the PID we were looking for, but
				 * since we cached its value in this LWP's brand
				 * structure, it has exited and been reused by
				 * another process.
				 */
				if (hp->l_start > lwptot(lwp)->t_start)
					break;

				lppid = lwpd->br_ppid;
				if (ppidp != NULL)
					*ppidp = hp->s_pid;
				if (ptidp != NULL)
					*ptidp = hp->s_tid;

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
