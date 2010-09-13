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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/proc.h>
#include <sys/kmem.h>
#include <sys/tuneable.h>
#include <sys/var.h>
#include <sys/cred.h>
#include <sys/systm.h>
#include <sys/prsystm.h>
#include <sys/vnode.h>
#include <sys/session.h>
#include <sys/cpuvar.h>
#include <sys/cmn_err.h>
#include <sys/bitmap.h>
#include <sys/debug.h>
#include <c2/audit.h>
#include <sys/project.h>
#include <sys/task.h>
#include <sys/zone.h>

/* directory entries for /proc */
union procent {
	proc_t *pe_proc;
	union procent *pe_next;
};

struct pid pid0 = {
	0,		/* pid_prinactive */
	1,		/* pid_pgorphaned */
	0,		/* pid_padding	*/
	0,		/* pid_prslot	*/
	0,		/* pid_id	*/
	NULL,		/* pid_pglink	*/
	NULL,		/* pid_pgtail	*/
	NULL,		/* pid_link	*/
	3		/* pid_ref	*/
};

static int pid_hashlen = 4;	/* desired average hash chain length */
static int pid_hashsz;		/* number of buckets in the hash table */

#define	HASHPID(pid)	(pidhash[((pid)&(pid_hashsz-1))])

extern uint_t nproc;
extern struct kmem_cache *process_cache;
static void	upcount_init(void);

kmutex_t	pidlock;	/* global process lock */
kmutex_t	pr_pidlock;	/* /proc global process lock */
kcondvar_t	*pr_pid_cv;	/* for /proc, one per process slot */
struct plock	*proc_lock;	/* persistent array of p_lock's */

/*
 * See the comment above pid_getlockslot() for a detailed explanation of this
 * constant.  Note that a PLOCK_SHIFT of 3 implies 64-byte coherence
 * granularity; if the coherence granularity is ever changed, this constant
 * should be modified to reflect the change to minimize proc_lock false
 * sharing (correctness, however, is guaranteed regardless of the coherence
 * granularity).
 */
#define	PLOCK_SHIFT	3

static kmutex_t	pidlinklock;
static struct pid **pidhash;
static pid_t minpid;
static pid_t mpid = FAMOUS_PIDS;	/* one more than the last famous pid */
static union procent *procdir;
static union procent *procentfree;

static struct pid *
pid_lookup(pid_t pid)
{
	struct pid *pidp;

	ASSERT(MUTEX_HELD(&pidlinklock));

	for (pidp = HASHPID(pid); pidp; pidp = pidp->pid_link) {
		if (pidp->pid_id == pid) {
			ASSERT(pidp->pid_ref > 0);
			break;
		}
	}
	return (pidp);
}

void
pid_setmin(void)
{
	if (jump_pid && jump_pid > mpid)
		minpid = mpid = jump_pid;
	else
		minpid = mpid;
}

/*
 * When prslots are simply used as an index to determine a process' p_lock,
 * adjacent prslots share adjacent p_locks.  On machines where the size
 * of a mutex is smaller than that of a cache line (which, as of this writing,
 * is true for all machines on which Solaris runs), this can potentially
 * induce false sharing.  The standard solution for false sharing is to pad
 * out one's data structures (in this case, struct plock).  However,
 * given the size and (generally) sparse use of the proc_lock array, this
 * is suboptimal.  We therefore stride through the proc_lock array with
 * a stride of PLOCK_SHIFT.  PLOCK_SHIFT should be defined as:
 *
 *   log_2 (coherence_granularity / sizeof (kmutex_t))
 *
 * Under this scheme, false sharing is still possible -- but only when
 * the number of active processes is very large.  Note that the one-to-one
 * mapping between prslots and lockslots is maintained.
 */
static int
pid_getlockslot(int prslot)
{
	int even = (v.v_proc >> PLOCK_SHIFT) << PLOCK_SHIFT;
	int perlap = even >> PLOCK_SHIFT;

	if (prslot >= even)
		return (prslot);

	return (((prslot % perlap) << PLOCK_SHIFT) + (prslot / perlap));
}

/*
 * This function allocates a pid structure, a free pid, and optionally a
 * slot in the proc table for it.
 *
 * pid_allocate() returns the new pid on success, -1 on failure.
 */
pid_t
pid_allocate(proc_t *prp, pid_t pid, int flags)
{
	struct pid *pidp;
	union procent *pep;
	pid_t newpid, startpid;

	pidp = kmem_zalloc(sizeof (struct pid), KM_SLEEP);

	mutex_enter(&pidlinklock);
	if ((flags & PID_ALLOC_PROC) && (pep = procentfree) == NULL) {
		/*
		 * ran out of /proc directory entries
		 */
		goto failed;
	}

	if (pid != 0) {
		VERIFY(minpid == 0);
		VERIFY3P(pid, <, mpid);
		VERIFY3P(pid_lookup(pid), ==, NULL);
		newpid = pid;
	} else {
		/*
		 * Allocate a pid
		 */
		ASSERT(minpid <= mpid && mpid < maxpid);

		startpid = mpid;
		for (;;) {
			newpid = mpid;
			if (++mpid == maxpid)
				mpid = minpid;

			if (pid_lookup(newpid) == NULL)
				break;

			if (mpid == startpid)
				goto failed;
		}
	}

	/*
	 * Put pid into the pid hash table.
	 */
	pidp->pid_link = HASHPID(newpid);
	HASHPID(newpid) = pidp;
	pidp->pid_ref = 1;
	pidp->pid_id = newpid;

	if (flags & PID_ALLOC_PROC) {
		procentfree = pep->pe_next;
		pidp->pid_prslot = pep - procdir;
		pep->pe_proc = prp;
		prp->p_pidp = pidp;
		prp->p_lockp = &proc_lock[pid_getlockslot(pidp->pid_prslot)];
	} else {
		pidp->pid_prslot = 0;
	}

	mutex_exit(&pidlinklock);

	return (newpid);

failed:
	mutex_exit(&pidlinklock);
	kmem_free(pidp, sizeof (struct pid));
	return (-1);
}

/*
 * decrement the reference count for pid
 */
int
pid_rele(struct pid *pidp)
{
	struct pid **pidpp;

	mutex_enter(&pidlinklock);
	ASSERT(pidp != &pid0);

	pidpp = &HASHPID(pidp->pid_id);
	for (;;) {
		ASSERT(*pidpp != NULL);
		if (*pidpp == pidp)
			break;
		pidpp = &(*pidpp)->pid_link;
	}

	*pidpp = pidp->pid_link;
	mutex_exit(&pidlinklock);

	kmem_free(pidp, sizeof (*pidp));
	return (0);
}

void
proc_entry_free(struct pid *pidp)
{
	mutex_enter(&pidlinklock);
	pidp->pid_prinactive = 1;
	procdir[pidp->pid_prslot].pe_next = procentfree;
	procentfree = &procdir[pidp->pid_prslot];
	mutex_exit(&pidlinklock);
}

/*
 * The original task needs to be passed in since the process has already been
 * detached from the task at this point in time.
 */
void
pid_exit(proc_t *prp, struct task *tk)
{
	struct pid *pidp;
	zone_t	*zone = prp->p_zone;

	ASSERT(MUTEX_HELD(&pidlock));

	/*
	 * Exit process group.  If it is NULL, it's because fork failed
	 * before calling pgjoin().
	 */
	ASSERT(prp->p_pgidp != NULL || prp->p_stat == SIDL);
	if (prp->p_pgidp != NULL)
		pgexit(prp);

	sess_rele(prp->p_sessp, B_TRUE);

	pidp = prp->p_pidp;

	proc_entry_free(pidp);

	if (audit_active)
		audit_pfree(prp);

	if (practive == prp) {
		practive = prp->p_next;
	}

	if (prp->p_next) {
		prp->p_next->p_prev = prp->p_prev;
	}
	if (prp->p_prev) {
		prp->p_prev->p_next = prp->p_next;
	}

	PID_RELE(pidp);

	mutex_destroy(&prp->p_crlock);
	kmem_cache_free(process_cache, prp);
	nproc--;

	/*
	 * Decrement the process counts of the original task, project and zone.
	 */
	mutex_enter(&zone->zone_nlwps_lock);
	tk->tk_nprocs--;
	tk->tk_proj->kpj_nprocs--;
	zone->zone_nprocs--;
	mutex_exit(&zone->zone_nlwps_lock);
}

/*
 * Find a process visible from the specified zone given its process ID.
 */
proc_t *
prfind_zone(pid_t pid, zoneid_t zoneid)
{
	struct pid *pidp;
	proc_t *p;

	ASSERT(MUTEX_HELD(&pidlock));

	mutex_enter(&pidlinklock);
	pidp = pid_lookup(pid);
	mutex_exit(&pidlinklock);
	if (pidp != NULL && pidp->pid_prinactive == 0) {
		p = procdir[pidp->pid_prslot].pe_proc;
		if (zoneid == ALL_ZONES || p->p_zone->zone_id == zoneid)
			return (p);
	}
	return (NULL);
}

/*
 * Find a process given its process ID.  This obeys zone restrictions,
 * so if the caller is in a non-global zone it won't find processes
 * associated with other zones.  Use prfind_zone(pid, ALL_ZONES) to
 * bypass this restriction.
 */
proc_t *
prfind(pid_t pid)
{
	zoneid_t zoneid;

	if (INGLOBALZONE(curproc))
		zoneid = ALL_ZONES;
	else
		zoneid = getzoneid();
	return (prfind_zone(pid, zoneid));
}

proc_t *
pgfind_zone(pid_t pgid, zoneid_t zoneid)
{
	struct pid *pidp;

	ASSERT(MUTEX_HELD(&pidlock));

	mutex_enter(&pidlinklock);
	pidp = pid_lookup(pgid);
	mutex_exit(&pidlinklock);
	if (pidp != NULL) {
		proc_t *p = pidp->pid_pglink;

		if (zoneid == ALL_ZONES || pgid == 0 || p == NULL ||
		    p->p_zone->zone_id == zoneid)
			return (p);
	}
	return (NULL);
}

/*
 * return the head of the list of processes whose process group ID is 'pgid',
 * or NULL, if no such process group
 */
proc_t *
pgfind(pid_t pgid)
{
	zoneid_t zoneid;

	if (INGLOBALZONE(curproc))
		zoneid = ALL_ZONES;
	else
		zoneid = getzoneid();
	return (pgfind_zone(pgid, zoneid));
}

/*
 * Sets P_PR_LOCK on a non-system process.  Process must be fully created
 * and not exiting to succeed.
 *
 * Returns 0 on success.
 * Returns 1 if P_PR_LOCK is set.
 * Returns -1 if proc is in invalid state.
 */
int
sprtrylock_proc(proc_t *p)
{
	ASSERT(MUTEX_HELD(&p->p_lock));

	/* skip system and incomplete processes */
	if (p->p_stat == SIDL || p->p_stat == SZOMB ||
	    (p->p_flag & (SSYS | SEXITING | SEXITLWPS))) {
		return (-1);
	}

	if (p->p_proc_flag & P_PR_LOCK)
		return (1);

	p->p_proc_flag |= P_PR_LOCK;
	THREAD_KPRI_REQUEST();

	return (0);
}

/*
 * Wait for P_PR_LOCK to become clear.  Returns with p_lock dropped,
 * and the proc pointer no longer valid, as the proc may have exited.
 */
void
sprwaitlock_proc(proc_t *p)
{
	kmutex_t *mp;

	ASSERT(MUTEX_HELD(&p->p_lock));
	ASSERT(p->p_proc_flag & P_PR_LOCK);

	/*
	 * p_lock is persistent, but p itself is not -- it could
	 * vanish during cv_wait().  Load p->p_lock now so we can
	 * drop it after cv_wait() without referencing p.
	 */
	mp = &p->p_lock;
	cv_wait(&pr_pid_cv[p->p_slot], mp);
	mutex_exit(mp);
}

/*
 * If pid exists, find its proc, acquire its p_lock and mark it P_PR_LOCK.
 * Returns the proc pointer on success, NULL on failure.  sprlock() is
 * really just a stripped-down version of pr_p_lock() to allow practive
 * walkers like dofusers() and dumpsys() to synchronize with /proc.
 */
proc_t *
sprlock_zone(pid_t pid, zoneid_t zoneid)
{
	proc_t *p;
	int ret;

	for (;;) {
		mutex_enter(&pidlock);
		if ((p = prfind_zone(pid, zoneid)) == NULL) {
			mutex_exit(&pidlock);
			return (NULL);
		}
		mutex_enter(&p->p_lock);
		mutex_exit(&pidlock);

		if (panicstr)
			return (p);

		ret = sprtrylock_proc(p);
		if (ret == -1) {
			mutex_exit(&p->p_lock);
			return (NULL);
		} else if (ret == 0) {
			break;
		}
		sprwaitlock_proc(p);
	}
	return (p);
}

proc_t *
sprlock(pid_t pid)
{
	zoneid_t zoneid;

	if (INGLOBALZONE(curproc))
		zoneid = ALL_ZONES;
	else
		zoneid = getzoneid();
	return (sprlock_zone(pid, zoneid));
}

void
sprlock_proc(proc_t *p)
{
	ASSERT(MUTEX_HELD(&p->p_lock));

	while (p->p_proc_flag & P_PR_LOCK) {
		cv_wait(&pr_pid_cv[p->p_slot], &p->p_lock);
	}

	p->p_proc_flag |= P_PR_LOCK;
	THREAD_KPRI_REQUEST();
}

void
sprunlock(proc_t *p)
{
	if (panicstr) {
		mutex_exit(&p->p_lock);
		return;
	}

	ASSERT(p->p_proc_flag & P_PR_LOCK);
	ASSERT(MUTEX_HELD(&p->p_lock));

	cv_signal(&pr_pid_cv[p->p_slot]);
	p->p_proc_flag &= ~P_PR_LOCK;
	mutex_exit(&p->p_lock);
	THREAD_KPRI_RELEASE();
}

void
pid_init(void)
{
	int i;

	pid_hashsz = 1 << highbit(v.v_proc / pid_hashlen);

	pidhash = kmem_zalloc(sizeof (struct pid *) * pid_hashsz, KM_SLEEP);
	procdir = kmem_alloc(sizeof (union procent) * v.v_proc, KM_SLEEP);
	pr_pid_cv = kmem_zalloc(sizeof (kcondvar_t) * v.v_proc, KM_SLEEP);
	proc_lock = kmem_zalloc(sizeof (struct plock) * v.v_proc, KM_SLEEP);

	nproc = 1;
	practive = proc_sched;
	proc_sched->p_next = NULL;
	procdir[0].pe_proc = proc_sched;

	procentfree = &procdir[1];
	for (i = 1; i < v.v_proc - 1; i++)
		procdir[i].pe_next = &procdir[i+1];
	procdir[i].pe_next = NULL;

	HASHPID(0) = &pid0;

	upcount_init();
}

proc_t *
pid_entry(int slot)
{
	union procent *pep;
	proc_t *prp;

	ASSERT(MUTEX_HELD(&pidlock));
	ASSERT(slot >= 0 && slot < v.v_proc);

	pep = procdir[slot].pe_next;
	if (pep >= procdir && pep < &procdir[v.v_proc])
		return (NULL);
	prp = procdir[slot].pe_proc;
	if (prp != 0 && prp->p_stat == SIDL)
		return (NULL);
	return (prp);
}

/*
 * Send the specified signal to all processes whose process group ID is
 * equal to 'pgid'
 */

void
signal(pid_t pgid, int sig)
{
	struct pid *pidp;
	proc_t *prp;

	mutex_enter(&pidlock);
	mutex_enter(&pidlinklock);
	if (pgid == 0 || (pidp = pid_lookup(pgid)) == NULL) {
		mutex_exit(&pidlinklock);
		mutex_exit(&pidlock);
		return;
	}
	mutex_exit(&pidlinklock);
	for (prp = pidp->pid_pglink; prp; prp = prp->p_pglink) {
		mutex_enter(&prp->p_lock);
		sigtoproc(prp, NULL, sig);
		mutex_exit(&prp->p_lock);
	}
	mutex_exit(&pidlock);
}

/*
 * Send the specified signal to the specified process
 */

void
prsignal(struct pid *pidp, int sig)
{
	if (!(pidp->pid_prinactive))
		psignal(procdir[pidp->pid_prslot].pe_proc, sig);
}

#include <sys/sunddi.h>

/*
 * DDI/DKI interfaces for drivers to send signals to processes
 */

/*
 * obtain an opaque reference to a process for signaling
 */
void *
proc_ref(void)
{
	struct pid *pidp;

	mutex_enter(&pidlock);
	pidp = curproc->p_pidp;
	PID_HOLD(pidp);
	mutex_exit(&pidlock);

	return (pidp);
}

/*
 * release a reference to a process
 * - a process can exit even if a driver has a reference to it
 * - one proc_unref for every proc_ref
 */
void
proc_unref(void *pref)
{
	mutex_enter(&pidlock);
	PID_RELE((struct pid *)pref);
	mutex_exit(&pidlock);
}

/*
 * send a signal to a process
 *
 * - send the process the signal
 * - if the process went away, return a -1
 * - if the process is still there return 0
 */
int
proc_signal(void *pref, int sig)
{
	struct pid *pidp = pref;

	prsignal(pidp, sig);
	return (pidp->pid_prinactive ? -1 : 0);
}


static struct upcount	**upc_hash;	/* a boot time allocated array */
static ulong_t		upc_hashmask;
#define	UPC_HASH(x, y)	((ulong_t)(x ^ y) & upc_hashmask)

/*
 * Get us off the ground.  Called once at boot.
 */
void
upcount_init(void)
{
	ulong_t	upc_hashsize;

	/*
	 * An entry per MB of memory is our current guess
	 */
	/*
	 * 2^20 is a meg, so shifting right by 20 - PAGESHIFT
	 * converts pages to megs (without overflowing a u_int
	 * if you have more than 4G of memory, like ptob(physmem)/1M
	 * would).
	 */
	upc_hashsize = (1 << highbit(physmem >> (20 - PAGESHIFT)));
	upc_hashmask = upc_hashsize - 1;
	upc_hash = kmem_zalloc(upc_hashsize * sizeof (struct upcount *),
	    KM_SLEEP);
}

/*
 * Increment the number of processes associated with a given uid and zoneid.
 */
void
upcount_inc(uid_t uid, zoneid_t zoneid)
{
	struct upcount	**upc, **hupc;
	struct upcount	*new;

	ASSERT(MUTEX_HELD(&pidlock));
	new = NULL;
	hupc = &upc_hash[UPC_HASH(uid, zoneid)];
top:
	upc = hupc;
	while ((*upc) != NULL) {
		if ((*upc)->up_uid == uid && (*upc)->up_zoneid == zoneid) {
			(*upc)->up_count++;
			if (new) {
				/*
				 * did not need `new' afterall.
				 */
				kmem_free(new, sizeof (*new));
			}
			return;
		}
		upc = &(*upc)->up_next;
	}

	/*
	 * There is no entry for this <uid,zoneid> pair.
	 * Allocate one.  If we have to drop pidlock, check
	 * again.
	 */
	if (new == NULL) {
		new = (struct upcount *)kmem_alloc(sizeof (*new), KM_NOSLEEP);
		if (new == NULL) {
			mutex_exit(&pidlock);
			new = (struct upcount *)kmem_alloc(sizeof (*new),
			    KM_SLEEP);
			mutex_enter(&pidlock);
			goto top;
		}
	}


	/*
	 * On the assumption that a new user is going to do some
	 * more forks, put the new upcount structure on the front.
	 */
	upc = hupc;

	new->up_uid = uid;
	new->up_zoneid = zoneid;
	new->up_count = 1;
	new->up_next = *upc;

	*upc = new;
}

/*
 * Decrement the number of processes a given uid and zoneid has.
 */
void
upcount_dec(uid_t uid, zoneid_t zoneid)
{
	struct	upcount **upc;
	struct	upcount *done;

	ASSERT(MUTEX_HELD(&pidlock));

	upc = &upc_hash[UPC_HASH(uid, zoneid)];
	while ((*upc) != NULL) {
		if ((*upc)->up_uid == uid && (*upc)->up_zoneid == zoneid) {
			(*upc)->up_count--;
			if ((*upc)->up_count == 0) {
				done = *upc;
				*upc = (*upc)->up_next;
				kmem_free(done, sizeof (*done));
			}
			return;
		}
		upc = &(*upc)->up_next;
	}
	cmn_err(CE_PANIC, "decr_upcount-off the end");
}

/*
 * Returns the number of processes a uid has.
 * Non-existent uid's are assumed to have no processes.
 */
int
upcount_get(uid_t uid, zoneid_t zoneid)
{
	struct	upcount *upc;

	ASSERT(MUTEX_HELD(&pidlock));

	upc = upc_hash[UPC_HASH(uid, zoneid)];
	while (upc != NULL) {
		if (upc->up_uid == uid && upc->up_zoneid == zoneid) {
			return (upc->up_count);
		}
		upc = upc->up_next;
	}
	return (0);
}
