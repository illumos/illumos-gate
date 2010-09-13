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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Inter-Process Communication Semaphore Facility.
 *
 * See os/ipc.c for a description of common IPC functionality.
 *
 * Resource controls
 * -----------------
 *
 * Control:      zone.max-sem-ids (rc_zone_semmni)
 * Description:  Maximum number of semaphore ids allowed a zone.
 *
 *   When semget() is used to allocate a semaphore set, one id is
 *   allocated.  If the id allocation doesn't succeed, semget() fails
 *   and errno is set to ENOSPC.  Upon successful semctl(, IPC_RMID)
 *   the id is deallocated.
 *
 * Control:      project.max-sem-ids (rc_project_semmni)
 * Description:  Maximum number of semaphore ids allowed a project.
 *
 *   When semget() is used to allocate a semaphore set, one id is
 *   allocated.  If the id allocation doesn't succeed, semget() fails
 *   and errno is set to ENOSPC.  Upon successful semctl(, IPC_RMID)
 *   the id is deallocated.
 *
 * Control:      process.max-sem-nsems (rc_process_semmsl)
 * Description:  Maximum number of semaphores allowed per semaphore set.
 *
 *   When semget() is used to allocate a semaphore set, the size of the
 *   set is compared with this limit.  If the number of semaphores
 *   exceeds the limit, semget() fails and errno is set to EINVAL.
 *
 * Control:      process.max-sem-ops (rc_process_semopm)
 * Description:  Maximum number of semaphore operations allowed per
 *               semop call.
 *
 *   When semget() successfully allocates a semaphore set, the minimum
 *   enforced value of this limit is used to initialize the
 *   "system-imposed maximum" number of operations a semop() call for
 *   this set can perform.
 *
 * Undo structures
 * ---------------
 *
 * Removing the undo structure tunables involved a serious redesign of
 * how they were implemented.  There is now one undo structure for
 * every process/semaphore array combination (lazily allocated, of
 * course), and each is equal in size to the semaphore it corresponds
 * to.  To avoid scalability and performance problems, the undo
 * structures are stored in two places: a per-process AVL tree sorted
 * by ksemid pointer (p_semacct, protected by p_lock) and an unsorted
 * per-semaphore linked list (sem_undos, protected by the semaphore's
 * ID lock).  The former is used by semop, where a lookup is performed
 * once and cached if SEM_UNDO is specified for any of the operations,
 * and at process exit where the undoable operations are rolled back.
 * The latter is used when removing the semaphore, so the undo
 * structures can be removed from the appropriate processes' trees.
 *
 * The undo structure itself contains pointers to the ksemid and proc
 * to which it corresponds, a list node, an AVL node, and an array of
 * adjust-on-exit (AOE) values.  When an undo structure is allocated it
 * is immediately added to both the process's tree and the semaphore's
 * list.  Lastly, the reference count on the semaphore is increased.
 *
 * Avoiding a lock ordering violation between p_lock and the ID lock,
 * wont to occur when there is a race between a process exiting and the
 * removal of a semaphore, mandates the delicate dance that exists
 * between semexit and sem_rmid.
 *
 * sem_rmid, holding the ID lock, iterates through all undo structures
 * and for each takes the appropriate process's p_lock and checks to
 * see if p_semacct is NULL.  If it is, it skips that undo structure
 * and continues to the next.  Otherwise, it removes the undo structure
 * from both the AVL tree and the semaphore's list, and releases the
 * hold that the undo structure had on the semaphore.
 *
 * The important other half of this is semexit, which will immediately
 * take p_lock, obtain the AVL pointer, clear p_semacct, and drop
 * p_lock.  From this point on it is semexit's responsibility to clean
 * up all undo structures found in the tree -- a coexecuting sem_rmid
 * will see the NULL p_semacct and skip that undo structure.  It walks
 * the AVL tree (using avl_destroy_nodes) and for each undo structure
 * takes the appropriate semaphore's ID lock (always legal since the
 * undo structure has a hold on the semaphore), updates all semaphores
 * with non-zero AOE values, and removes the structure from the
 * semaphore's list.  It then drops the structure's reference on the
 * semaphore, drops the ID lock, and frees the undo structure.
 */

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/cred.h>
#include <sys/vmem.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/ipc.h>
#include <sys/ipc_impl.h>
#include <sys/sem.h>
#include <sys/sem_impl.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/cpuvar.h>
#include <sys/debug.h>
#include <sys/var.h>
#include <sys/cmn_err.h>
#include <sys/modctl.h>
#include <sys/syscall.h>
#include <sys/avl.h>
#include <sys/list.h>
#include <sys/zone.h>

#include <c2/audit.h>

extern rctl_hndl_t rc_zone_semmni;
extern rctl_hndl_t rc_project_semmni;
extern rctl_hndl_t rc_process_semmsl;
extern rctl_hndl_t rc_process_semopm;
static ipc_service_t *sem_svc;
static zone_key_t sem_zone_key;

/*
 * The following tunables are obsolete.  Though for compatibility we
 * still read and interpret seminfo_semmsl, seminfo_semopm and
 * seminfo_semmni (see os/project.c and os/rctl_proc.c), the preferred
 * mechanism for administrating the IPC Semaphore facility is through
 * the resource controls described at the top of this file.
 */
int seminfo_semaem = 16384;	/* (obsolete) */
int seminfo_semmap = 10;	/* (obsolete) */
int seminfo_semmni = 10;	/* (obsolete) */
int seminfo_semmns = 60;	/* (obsolete) */
int seminfo_semmnu = 30;	/* (obsolete) */
int seminfo_semmsl = 25;	/* (obsolete) */
int seminfo_semopm = 10;	/* (obsolete) */
int seminfo_semume = 10;	/* (obsolete) */
int seminfo_semusz = 96;	/* (obsolete) */
int seminfo_semvmx = 32767;	/* (obsolete) */

#define	SEM_MAXUCOPS	4096	/* max # of unchecked ops per semop call */
#define	SEM_UNDOSZ(n)	(sizeof (struct sem_undo) + (n - 1) * sizeof (int))

static int semsys(int opcode, uintptr_t a0, uintptr_t a1,
    uintptr_t a2, uintptr_t a3);
static void sem_dtor(kipc_perm_t *);
static void sem_rmid(kipc_perm_t *);
static void sem_remove_zone(zoneid_t, void *);

static struct sysent ipcsem_sysent = {
	5,
	SE_NOUNLOAD | SE_ARGC | SE_32RVAL1,
	semsys
};

/*
 * Module linkage information for the kernel.
 */
static struct modlsys modlsys = {
	&mod_syscallops, "System V semaphore facility", &ipcsem_sysent
};

#ifdef _SYSCALL32_IMPL
static struct modlsys modlsys32 = {
	&mod_syscallops32, "32-bit System V semaphore facility", &ipcsem_sysent
};
#endif

static struct modlinkage modlinkage = {
	MODREV_1,
	&modlsys,
#ifdef _SYSCALL32_IMPL
	&modlsys32,
#endif
	NULL
};


int
_init(void)
{
	int result;

	sem_svc = ipcs_create("semids", rc_project_semmni, rc_zone_semmni,
	    sizeof (ksemid_t), sem_dtor, sem_rmid, AT_IPC_SEM,
	    offsetof(ipc_rqty_t, ipcq_semmni));
	zone_key_create(&sem_zone_key, NULL, sem_remove_zone, NULL);

	if ((result = mod_install(&modlinkage)) == 0)
		return (0);

	(void) zone_key_delete(sem_zone_key);
	ipcs_destroy(sem_svc);

	return (result);
}

int
_fini(void)
{
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static void
sem_dtor(kipc_perm_t *perm)
{
	ksemid_t *sp = (ksemid_t *)perm;

	kmem_free(sp->sem_base,
	    P2ROUNDUP(sp->sem_nsems * sizeof (struct sem), 64));
	list_destroy(&sp->sem_undos);
}

/*
 * sem_undo_add - Create or update adjust on exit entry.
 */
static int
sem_undo_add(short val, ushort_t num, struct sem_undo *undo)
{
	int newval = undo->un_aoe[num] - val;

	if (newval > USHRT_MAX || newval < -USHRT_MAX)
		return (ERANGE);
	undo->un_aoe[num] = newval;

	return (0);
}

/*
 * sem_undo_clear - clears all undo entries for specified semaphores
 *
 * Used when semaphores are reset by SETVAL or SETALL.
 */
static void
sem_undo_clear(ksemid_t *sp, ushort_t low, ushort_t high)
{
	struct sem_undo *undo;
	int i;

	ASSERT(low <= high);
	ASSERT(high < sp->sem_nsems);

	for (undo = list_head(&sp->sem_undos); undo;
	    undo = list_next(&sp->sem_undos, undo))
		for (i = low; i <= high; i++)
			undo->un_aoe[i] = 0;
}

/*
 * sem_rollback - roll back work done so far if unable to complete operation
 */
static void
sem_rollback(ksemid_t *sp, struct sembuf *op, int n, struct sem_undo *undo)
{
	struct sem *semp;	/* semaphore ptr */

	for (op += n - 1; n--; op--) {
		if (op->sem_op == 0)
			continue;
		semp = &sp->sem_base[op->sem_num];
		semp->semval -= op->sem_op;
		if (op->sem_flg & SEM_UNDO) {
			ASSERT(undo != NULL);
			(void) sem_undo_add(-op->sem_op, op->sem_num, undo);
		}
	}
}

static void
sem_rmid(kipc_perm_t *perm)
{
	ksemid_t *sp = (ksemid_t *)perm;
	struct sem *semp;
	struct sem_undo *undo;
	size_t size = SEM_UNDOSZ(sp->sem_nsems);
	int i;

	/*LINTED*/
	while (undo = list_head(&sp->sem_undos)) {
		list_remove(&sp->sem_undos, undo);
		mutex_enter(&undo->un_proc->p_lock);
		if (undo->un_proc->p_semacct == NULL) {
			mutex_exit(&undo->un_proc->p_lock);
			continue;
		}
		avl_remove(undo->un_proc->p_semacct, undo);
		mutex_exit(&undo->un_proc->p_lock);
		kmem_free(undo, size);
		ipc_rele_locked(sem_svc, (kipc_perm_t *)sp);
	}

	for (i = 0; i < sp->sem_nsems; i++) {
		semp = &sp->sem_base[i];
		semp->semval = semp->sempid = 0;
		if (semp->semncnt) {
			cv_broadcast(&semp->semncnt_cv);
			semp->semncnt = 0;
		}
		if (semp->semzcnt) {
			cv_broadcast(&semp->semzcnt_cv);
			semp->semzcnt = 0;
		}
	}
}

/*
 * semctl - Semctl system call.
 */
static int
semctl(int semid, uint_t semnum, int cmd, uintptr_t arg)
{
	ksemid_t		*sp;	/* ptr to semaphore header */
	struct sem		*p;	/* ptr to semaphore */
	unsigned int		i;	/* loop control */
	ushort_t		*vals, *vp;
	size_t			vsize = 0;
	int			error = 0;
	int			retval = 0;
	struct cred		*cr;
	kmutex_t		*lock;
	model_t			mdl = get_udatamodel();
	STRUCT_DECL(semid_ds, sid);
	struct semid_ds64	ds64;

	STRUCT_INIT(sid, mdl);
	cr = CRED();

	/*
	 * Perform pre- or non-lookup actions (e.g. copyins, RMID).
	 */
	switch (cmd) {
	case IPC_SET:
		if (copyin((void *)arg, STRUCT_BUF(sid), STRUCT_SIZE(sid)))
			return (set_errno(EFAULT));
		break;

	case IPC_SET64:
		if (copyin((void *)arg, &ds64, sizeof (struct semid_ds64)))
			return (set_errno(EFAULT));
		break;

	case SETALL:
		if ((lock = ipc_lookup(sem_svc, semid,
		    (kipc_perm_t **)&sp)) == NULL)
			return (set_errno(EINVAL));
		vsize = sp->sem_nsems * sizeof (*vals);
		mutex_exit(lock);

		/* allocate space to hold all semaphore values */
		vals = kmem_alloc(vsize, KM_SLEEP);

		if (copyin((void *)arg, vals, vsize)) {
			kmem_free(vals, vsize);
			return (set_errno(EFAULT));
		}
		break;

	case IPC_RMID:
		if (error = ipc_rmid(sem_svc, semid, cr))
			return (set_errno(error));
		return (0);
	}

	if ((lock = ipc_lookup(sem_svc, semid, (kipc_perm_t **)&sp)) == NULL) {
		if (vsize != 0)
			kmem_free(vals, vsize);
		return (set_errno(EINVAL));
	}
	switch (cmd) {
	/* Set ownership and permissions. */
	case IPC_SET:

		if (error = ipcperm_set(sem_svc, cr, &sp->sem_perm,
		    &STRUCT_BUF(sid)->sem_perm, mdl)) {
			mutex_exit(lock);
			return (set_errno(error));
		}
		sp->sem_ctime = gethrestime_sec();
		mutex_exit(lock);
		return (0);

	/* Get semaphore data structure. */
	case IPC_STAT:

		if (error = ipcperm_access(&sp->sem_perm, SEM_R, cr)) {
			mutex_exit(lock);
			return (set_errno(error));
		}

		ipcperm_stat(&STRUCT_BUF(sid)->sem_perm, &sp->sem_perm, mdl);
		STRUCT_FSETP(sid, sem_base, NULL);	/* kernel addr */
		STRUCT_FSET(sid, sem_nsems, sp->sem_nsems);
		STRUCT_FSET(sid, sem_otime, sp->sem_otime);
		STRUCT_FSET(sid, sem_ctime, sp->sem_ctime);
		STRUCT_FSET(sid, sem_binary, sp->sem_binary);
		mutex_exit(lock);

		if (copyout(STRUCT_BUF(sid), (void *)arg, STRUCT_SIZE(sid)))
			return (set_errno(EFAULT));
		return (0);

	case IPC_SET64:

		if (error = ipcperm_set64(sem_svc, cr, &sp->sem_perm,
		    &ds64.semx_perm)) {
			mutex_exit(lock);
			return (set_errno(error));
		}
		sp->sem_ctime = gethrestime_sec();
		mutex_exit(lock);
		return (0);

	case IPC_STAT64:

		ipcperm_stat64(&ds64.semx_perm, &sp->sem_perm);
		ds64.semx_nsems = sp->sem_nsems;
		ds64.semx_otime = sp->sem_otime;
		ds64.semx_ctime = sp->sem_ctime;

		mutex_exit(lock);
		if (copyout(&ds64, (void *)arg, sizeof (struct semid_ds64)))
			return (set_errno(EFAULT));

		return (0);

	/* Get # of processes sleeping for greater semval. */
	case GETNCNT:
		if (error = ipcperm_access(&sp->sem_perm, SEM_R, cr)) {
			mutex_exit(lock);
			return (set_errno(error));
		}
		if (semnum >= sp->sem_nsems) {
			mutex_exit(lock);
			return (set_errno(EINVAL));
		}
		retval = sp->sem_base[semnum].semncnt;
		mutex_exit(lock);
		return (retval);

	/* Get pid of last process to operate on semaphore. */
	case GETPID:
		if (error = ipcperm_access(&sp->sem_perm, SEM_R, cr)) {
			mutex_exit(lock);
			return (set_errno(error));
		}
		if (semnum >= sp->sem_nsems) {
			mutex_exit(lock);
			return (set_errno(EINVAL));
		}
		retval = sp->sem_base[semnum].sempid;
		mutex_exit(lock);
		return (retval);

	/* Get semval of one semaphore. */
	case GETVAL:
		if (error = ipcperm_access(&sp->sem_perm, SEM_R, cr)) {
			mutex_exit(lock);
			return (set_errno(error));
		}
		if (semnum >= sp->sem_nsems) {
			mutex_exit(lock);
			return (set_errno(EINVAL));
		}
		retval = sp->sem_base[semnum].semval;
		mutex_exit(lock);
		return (retval);

	/* Get all semvals in set. */
	case GETALL:
		if (error = ipcperm_access(&sp->sem_perm, SEM_R, cr)) {
			mutex_exit(lock);
			return (set_errno(error));
		}

		/* allocate space to hold all semaphore values */
		vsize = sp->sem_nsems * sizeof (*vals);
		vals = vp = kmem_alloc(vsize, KM_SLEEP);

		for (i = sp->sem_nsems, p = sp->sem_base; i--; p++, vp++)
			bcopy(&p->semval, vp, sizeof (p->semval));

		mutex_exit(lock);

		if (copyout((void *)vals, (void *)arg, vsize)) {
			kmem_free(vals, vsize);
			return (set_errno(EFAULT));
		}

		kmem_free(vals, vsize);
		return (0);

	/* Get # of processes sleeping for semval to become zero. */
	case GETZCNT:
		if (error = ipcperm_access(&sp->sem_perm, SEM_R, cr)) {
			mutex_exit(lock);
			return (set_errno(error));
		}
		if (semnum >= sp->sem_nsems) {
			mutex_exit(lock);
			return (set_errno(EINVAL));
		}
		retval = sp->sem_base[semnum].semzcnt;
		mutex_exit(lock);
		return (retval);

	/* Set semval of one semaphore. */
	case SETVAL:
		if (error = ipcperm_access(&sp->sem_perm, SEM_A, cr)) {
			mutex_exit(lock);
			return (set_errno(error));
		}
		if (semnum >= sp->sem_nsems) {
			mutex_exit(lock);
			return (set_errno(EINVAL));
		}
		if ((uint_t)arg > USHRT_MAX) {
			mutex_exit(lock);
			return (set_errno(ERANGE));
		}
		p = &sp->sem_base[semnum];
		if ((p->semval = (ushort_t)arg) != 0) {
			if (p->semncnt) {
				cv_broadcast(&p->semncnt_cv);
			}
		} else if (p->semzcnt) {
			cv_broadcast(&p->semzcnt_cv);
		}
		p->sempid = curproc->p_pid;
		sem_undo_clear(sp, (ushort_t)semnum, (ushort_t)semnum);
		mutex_exit(lock);
		return (0);

	/* Set semvals of all semaphores in set. */
	case SETALL:
		/* Check if semaphore set has been deleted and reallocated. */
		if (sp->sem_nsems * sizeof (*vals) != vsize) {
			error = set_errno(EINVAL);
			goto seterr;
		}
		if (error = ipcperm_access(&sp->sem_perm, SEM_A, cr)) {
			error = set_errno(error);
			goto seterr;
		}
		sem_undo_clear(sp, 0, sp->sem_nsems - 1);
		for (i = 0, p = sp->sem_base; i < sp->sem_nsems;
		    (p++)->sempid = curproc->p_pid) {
			if ((p->semval = vals[i++]) != 0) {
				if (p->semncnt) {
					cv_broadcast(&p->semncnt_cv);
				}
			} else if (p->semzcnt) {
				cv_broadcast(&p->semzcnt_cv);
			}
		}
seterr:
		mutex_exit(lock);
		kmem_free(vals, vsize);
		return (error);

	default:
		mutex_exit(lock);
		return (set_errno(EINVAL));
	}

	/* NOTREACHED */
}

/*
 * semexit - Called by exit() to clean up on process exit.
 */
void
semexit(proc_t *pp)
{
	avl_tree_t	*tree;
	struct sem_undo	*undo;
	void		*cookie = NULL;

	mutex_enter(&pp->p_lock);
	tree = pp->p_semacct;
	pp->p_semacct = NULL;
	mutex_exit(&pp->p_lock);

	while (undo = avl_destroy_nodes(tree, &cookie)) {
		ksemid_t *sp = undo->un_sp;
		size_t size = SEM_UNDOSZ(sp->sem_nsems);
		int i;

		(void) ipc_lock(sem_svc, sp->sem_perm.ipc_id);
		if (!IPC_FREE(&sp->sem_perm)) {
			for (i = 0; i < sp->sem_nsems; i++) {
				int adj = undo->un_aoe[i];
				if (adj) {
					struct sem *semp = &sp->sem_base[i];
					int v = (int)semp->semval + adj;

					if (v < 0 || v > USHRT_MAX)
						continue;
					semp->semval = (ushort_t)v;
					if (v == 0 && semp->semzcnt)
						cv_broadcast(&semp->semzcnt_cv);
					if (adj > 0 && semp->semncnt)
						cv_broadcast(&semp->semncnt_cv);
				}
			}
			list_remove(&sp->sem_undos, undo);
		}
		ipc_rele(sem_svc, (kipc_perm_t *)sp);
		kmem_free(undo, size);
	}

	avl_destroy(tree);
	kmem_free(tree, sizeof (avl_tree_t));
}

/*
 * Remove all semaphores associated with a given zone.  Called by
 * zone_shutdown when the zone is halted.
 */
/*ARGSUSED1*/
static void
sem_remove_zone(zoneid_t zoneid, void *arg)
{
	ipc_remove_zone(sem_svc, zoneid);
}

/*
 * semget - Semget system call.
 */
static int
semget(key_t key, int nsems, int semflg)
{
	ksemid_t	*sp;
	kmutex_t	*lock;
	int		id, error;
	proc_t		*pp = curproc;

top:
	if (error = ipc_get(sem_svc, key, semflg, (kipc_perm_t **)&sp, &lock))
		return (set_errno(error));

	if (!IPC_FREE(&sp->sem_perm)) {
		/*
		 * A semaphore with the requested key exists.
		 */
		if (!((nsems >= 0) && (nsems <= sp->sem_nsems))) {
			mutex_exit(lock);
			return (set_errno(EINVAL));
		}
	} else {
		/*
		 * This is a new semaphore set.  Finish initialization.
		 */
		if (nsems <= 0 || (rctl_test(rc_process_semmsl, pp->p_rctls, pp,
		    nsems, RCA_SAFE) & RCT_DENY)) {
			mutex_exit(lock);
			mutex_exit(&pp->p_lock);
			ipc_cleanup(sem_svc, (kipc_perm_t *)sp);
			return (set_errno(EINVAL));
		}
		mutex_exit(lock);
		mutex_exit(&pp->p_lock);

		/*
		 * We round the allocation up to coherency granularity
		 * so that multiple semaphore allocations won't result
		 * in the false sharing of their sem structures.
		 */
		sp->sem_base =
		    kmem_zalloc(P2ROUNDUP(nsems * sizeof (struct sem), 64),
		    KM_SLEEP);
		sp->sem_binary = (nsems == 1);
		sp->sem_nsems = (ushort_t)nsems;
		sp->sem_ctime = gethrestime_sec();
		sp->sem_otime = 0;
		list_create(&sp->sem_undos, sizeof (struct sem_undo),
		    offsetof(struct sem_undo, un_list));

		if (error = ipc_commit_begin(sem_svc, key, semflg,
		    (kipc_perm_t *)sp)) {
			if (error == EAGAIN)
				goto top;
			return (set_errno(error));
		}
		sp->sem_maxops =
		    rctl_enforced_value(rc_process_semopm, pp->p_rctls, pp);
		if (rctl_test(rc_process_semmsl, pp->p_rctls, pp, nsems,
		    RCA_SAFE) & RCT_DENY) {
			ipc_cleanup(sem_svc, (kipc_perm_t *)sp);
			return (set_errno(EINVAL));
		}
		lock = ipc_commit_end(sem_svc, &sp->sem_perm);
	}

	if (AU_AUDITING())
		audit_ipcget(AT_IPC_SEM, (void *)sp);

	id = sp->sem_perm.ipc_id;
	mutex_exit(lock);
	return (id);
}

/*
 * semids system call.
 */
static int
semids(int *buf, uint_t nids, uint_t *pnids)
{
	int error;

	if (error = ipc_ids(sem_svc, buf, nids, pnids))
		return (set_errno(error));

	return (0);
}


/*
 * Helper function for semop - copies in the provided timespec and
 * computes the absolute future time after which we must return.
 */
static int
compute_timeout(timespec_t **tsp, timespec_t *ts, timespec_t *now,
	timespec_t *timeout)
{
	model_t datamodel = get_udatamodel();

	if (datamodel == DATAMODEL_NATIVE) {
		if (copyin(timeout, ts, sizeof (timespec_t)))
			return (EFAULT);
	} else {
		timespec32_t ts32;

		if (copyin(timeout, &ts32, sizeof (timespec32_t)))
			return (EFAULT);
		TIMESPEC32_TO_TIMESPEC(ts, &ts32)
	}

	if (itimerspecfix(ts))
		return (EINVAL);

	/*
	 * Convert the timespec value into absolute time.
	 */
	timespecadd(ts, now);
	*tsp = ts;

	return (0);
}

/*
 * Undo structure comparator.  We sort based on ksemid_t pointer.
 */
static int
sem_undo_compar(const void *x, const void *y)
{
	struct sem_undo *undo1 = (struct sem_undo *)x;
	struct sem_undo *undo2 = (struct sem_undo *)y;

	if (undo1->un_sp < undo2->un_sp)
		return (-1);
	if (undo1->un_sp > undo2->un_sp)
		return (1);
	return (0);
}

/*
 * Helper function for semop - creates an undo structure and adds it to
 * the process's avl tree and the semaphore's list.
 */
static int
sem_undo_alloc(proc_t *pp, ksemid_t *sp, kmutex_t **lock,
    struct sem_undo *template, struct sem_undo **un)
{
	size_t size;
	struct sem_undo *undo;
	avl_tree_t *tree = NULL;
	avl_index_t where;

	mutex_exit(*lock);

	size = SEM_UNDOSZ(sp->sem_nsems);
	undo = kmem_zalloc(size, KM_SLEEP);
	undo->un_proc = pp;
	undo->un_sp = sp;

	if (pp->p_semacct == NULL)
		tree = kmem_alloc(sizeof (avl_tree_t), KM_SLEEP);

	*lock = ipc_lock(sem_svc, sp->sem_perm.ipc_id);
	if (IPC_FREE(&sp->sem_perm)) {
		kmem_free(undo, size);
		if (tree)
			kmem_free(tree, sizeof (avl_tree_t));
		return (EIDRM);
	}

	mutex_enter(&pp->p_lock);
	if (tree) {
		if (pp->p_semacct == NULL) {
			avl_create(tree, sem_undo_compar,
			    sizeof (struct sem_undo),
			    offsetof(struct sem_undo, un_avl));
			pp->p_semacct = tree;
		} else {
			kmem_free(tree, sizeof (avl_tree_t));
		}
	}

	if (*un = avl_find(pp->p_semacct, template, &where)) {
		mutex_exit(&pp->p_lock);
		kmem_free(undo, size);
	} else {
		*un = undo;
		avl_insert(pp->p_semacct, undo, where);
		mutex_exit(&pp->p_lock);
		list_insert_head(&sp->sem_undos, undo);
		ipc_hold(sem_svc, (kipc_perm_t *)sp);
	}


	return (0);
}

/*
 * semop - Semop system call.
 */
static int
semop(int semid, struct sembuf *sops, size_t nsops, timespec_t *timeout)
{
	ksemid_t	*sp = NULL;
	kmutex_t	*lock;
	struct sembuf	*op;	/* ptr to operation */
	int		i;	/* loop control */
	struct sem	*semp;	/* ptr to semaphore */
	int 		error = 0;
	struct sembuf	*uops;	/* ptr to copy of user ops */
	struct sembuf 	x_sem;	/* avoid kmem_alloc's */
	timespec_t	now, ts, *tsp = NULL;
	int		timecheck = 0;
	int		cvres, needundo, mode;
	struct sem_undo	*undo;
	proc_t		*pp = curproc;
	int		held = 0;

	CPU_STATS_ADDQ(CPU, sys, sema, 1); /* bump semaphore op count */

	/*
	 * To avoid the cost of copying in 'timeout' in the common
	 * case, we could only grab the time here and defer the copyin
	 * and associated computations until we are about to block.
	 *
	 * The down side to this is that we would then have to spin
	 * some goto top nonsense to avoid the copyin behind the semid
	 * lock.  As a common use of timed semaphores is as an explicit
	 * blocking mechanism, this could incur a greater penalty.
	 *
	 * If we eventually decide that this would be a wise route to
	 * take, the deferrable functionality is completely contained
	 * in 'compute_timeout', and the interface is defined such that
	 * we can legally not validate 'timeout' if it is unused.
	 */
	if (timeout != NULL) {
		timecheck = timechanged;
		gethrestime(&now);
		if (error = compute_timeout(&tsp, &ts, &now, timeout))
			return (set_errno(error));
	}

	/*
	 * Allocate space to hold the vector of semaphore ops.  If
	 * there is only 1 operation we use a preallocated buffer on
	 * the stack for speed.
	 *
	 * Since we don't want to allow the user to allocate an
	 * arbitrary amount of kernel memory, we need to check against
	 * the number of operations allowed by the semaphore.  We only
	 * bother doing this if the number of operations is larger than
	 * SEM_MAXUCOPS.
	 */
	if (nsops == 1)
		uops = &x_sem;
	else if (nsops == 0)
		return (0);
	else if (nsops <= SEM_MAXUCOPS)
		uops = kmem_alloc(nsops * sizeof (*uops), KM_SLEEP);

	if (nsops > SEM_MAXUCOPS) {
		if ((lock = ipc_lookup(sem_svc, semid,
		    (kipc_perm_t **)&sp)) == NULL)
			return (set_errno(EFAULT));

		if (nsops > sp->sem_maxops) {
			mutex_exit(lock);
			return (set_errno(E2BIG));
		}
		held = 1;
		ipc_hold(sem_svc, (kipc_perm_t *)sp);
		mutex_exit(lock);

		uops = kmem_alloc(nsops * sizeof (*uops), KM_SLEEP);
		if (copyin(sops, uops, nsops * sizeof (*op))) {
			error = EFAULT;
			(void) ipc_lock(sem_svc, sp->sem_perm.ipc_id);
			goto semoperr;
		}

		lock = ipc_lock(sem_svc, sp->sem_perm.ipc_id);
		if (IPC_FREE(&sp->sem_perm)) {
			error = EIDRM;
			goto semoperr;
		}
	} else {
		/*
		 * This could be interleaved with the above code, but
		 * keeping them separate improves readability.
		 */
		if (copyin(sops, uops, nsops * sizeof (*op))) {
			error = EFAULT;
			goto semoperr_unlocked;
		}

		if ((lock = ipc_lookup(sem_svc, semid,
		    (kipc_perm_t **)&sp)) == NULL) {
			error = EINVAL;
			goto semoperr_unlocked;
		}

		if (nsops > sp->sem_maxops) {
			error = E2BIG;
			goto semoperr;
		}
	}

	/*
	 * Scan all operations.  Verify that sem #s are in range and
	 * this process is allowed the requested operations.  If any
	 * operations are marked SEM_UNDO, find (or allocate) the undo
	 * structure for this process and semaphore.
	 */
	needundo = 0;
	mode = 0;
	for (i = 0, op = uops; i++ < nsops; op++) {
		mode |= op->sem_op ? SEM_A : SEM_R;
		if (op->sem_num >= sp->sem_nsems) {
			error = EFBIG;
			goto semoperr;
		}
		if ((op->sem_flg & SEM_UNDO) && op->sem_op)
			needundo = 1;
	}
	if (error = ipcperm_access(&sp->sem_perm, mode, CRED()))
		goto semoperr;

	if (needundo) {
		struct sem_undo template;

		template.un_sp = sp;
		mutex_enter(&pp->p_lock);
		if (pp->p_semacct)
			undo = avl_find(pp->p_semacct, &template, NULL);
		else
			undo = NULL;
		mutex_exit(&pp->p_lock);
		if (undo == NULL) {
			if (!held) {
				held = 1;
				ipc_hold(sem_svc, (kipc_perm_t *)sp);
			}
			if (error = sem_undo_alloc(pp, sp, &lock, &template,
			    &undo))
				goto semoperr;

			/* sem_undo_alloc unlocks the semaphore */
			if (error = ipcperm_access(&sp->sem_perm, mode, CRED()))
				goto semoperr;
		}
	}

check:
	/*
	 * Loop waiting for the operations to be satisfied atomically.
	 * Actually, do the operations and undo them if a wait is needed
	 * or an error is detected.
	 */
	for (i = 0; i < nsops; i++) {
		op = &uops[i];
		semp = &sp->sem_base[op->sem_num];

		/*
		 * Raise the semaphore (i.e. sema_v)
		 */
		if (op->sem_op > 0) {
			if (op->sem_op + (int)semp->semval > USHRT_MAX ||
			    ((op->sem_flg & SEM_UNDO) &&
			    (error = sem_undo_add(op->sem_op, op->sem_num,
			    undo)))) {
				if (i)
					sem_rollback(sp, uops, i, undo);
				if (error == 0)
					error = ERANGE;
				goto semoperr;
			}
			semp->semval += op->sem_op;
			/*
			 * If we are only incrementing the semaphore value
			 * by one on a binary semaphore, we can cv_signal.
			 */
			if (semp->semncnt) {
				if (op->sem_op == 1 && sp->sem_binary)
					cv_signal(&semp->semncnt_cv);
				else
					cv_broadcast(&semp->semncnt_cv);
			}
			if (semp->semzcnt && !semp->semval)
				cv_broadcast(&semp->semzcnt_cv);
			continue;
		}

		/*
		 * Lower the semaphore (i.e. sema_p)
		 */
		if (op->sem_op < 0) {
			if (semp->semval >= (unsigned)(-op->sem_op)) {
				if ((op->sem_flg & SEM_UNDO) &&
				    (error = sem_undo_add(op->sem_op,
				    op->sem_num, undo))) {
					if (i)
						sem_rollback(sp, uops, i, undo);
					goto semoperr;
				}
				semp->semval += op->sem_op;
				if (semp->semzcnt && !semp->semval)
					cv_broadcast(&semp->semzcnt_cv);
				continue;
			}
			if (i)
				sem_rollback(sp, uops, i, undo);
			if (op->sem_flg & IPC_NOWAIT) {
				error = EAGAIN;
				goto semoperr;
			}

			/*
			 * Mark the semaphore set as not a binary type
			 * if we are decrementing the value by more than 1.
			 *
			 * V operations will resort to cv_broadcast
			 * for this set because there are too many weird
			 * cases that have to be caught.
			 */
			if (op->sem_op < -1)
				sp->sem_binary = 0;
			if (!held) {
				held = 1;
				ipc_hold(sem_svc, (kipc_perm_t *)sp);
			}
			semp->semncnt++;
			cvres = cv_waituntil_sig(&semp->semncnt_cv, lock,
			    tsp, timecheck);
			lock = ipc_relock(sem_svc, sp->sem_perm.ipc_id, lock);

			if (!IPC_FREE(&sp->sem_perm)) {
				ASSERT(semp->semncnt != 0);
				semp->semncnt--;
				if (cvres > 0)	/* normal wakeup */
					goto check;
			}

			/* EINTR or EAGAIN overrides EIDRM */
			if (cvres == 0)
				error = EINTR;
			else if (cvres < 0)
				error = EAGAIN;
			else
				error = EIDRM;
			goto semoperr;
		}

		/*
		 * Wait for zero value
		 */
		if (semp->semval) {
			if (i)
				sem_rollback(sp, uops, i, undo);
			if (op->sem_flg & IPC_NOWAIT) {
				error = EAGAIN;
				goto semoperr;
			}

			if (!held) {
				held = 1;
				ipc_hold(sem_svc, (kipc_perm_t *)sp);
			}
			semp->semzcnt++;
			cvres = cv_waituntil_sig(&semp->semzcnt_cv, lock,
			    tsp, timecheck);
			lock = ipc_relock(sem_svc, sp->sem_perm.ipc_id, lock);

			/*
			 * Don't touch semp if the semaphores have been removed.
			 */
			if (!IPC_FREE(&sp->sem_perm)) {
				ASSERT(semp->semzcnt != 0);
				semp->semzcnt--;
				if (cvres > 0)	/* normal wakeup */
					goto check;
			}

			/* EINTR or EAGAIN overrides EIDRM */
			if (cvres == 0)
				error = EINTR;
			else if (cvres < 0)
				error = EAGAIN;
			else
				error = EIDRM;
			goto semoperr;
		}
	}

	/* All operations succeeded.  Update sempid for accessed semaphores. */
	for (i = 0, op = uops; i++ < nsops;
	    sp->sem_base[(op++)->sem_num].sempid = pp->p_pid)
		;
	sp->sem_otime = gethrestime_sec();
	if (held)
		ipc_rele(sem_svc, (kipc_perm_t *)sp);
	else
		mutex_exit(lock);

	/* Before leaving, deallocate the buffer that held the user semops */
	if (nsops != 1)
		kmem_free(uops, sizeof (*uops) * nsops);
	return (0);

	/*
	 * Error return labels
	 */
semoperr:
	if (held)
		ipc_rele(sem_svc, (kipc_perm_t *)sp);
	else
		mutex_exit(lock);

semoperr_unlocked:

	/* Before leaving, deallocate the buffer that held the user semops */
	if (nsops != 1)
		kmem_free(uops, sizeof (*uops) * nsops);
	return (set_errno(error));
}

/*
 * semsys - System entry point for semctl, semget, and semop system calls.
 */
static int
semsys(int opcode, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4)
{
	int error;

	switch (opcode) {
	case SEMCTL:
		error = semctl((int)a1, (uint_t)a2, (int)a3, a4);
		break;
	case SEMGET:
		error = semget((key_t)a1, (int)a2, (int)a3);
		break;
	case SEMOP:
		error = semop((int)a1, (struct sembuf *)a2, (size_t)a3, 0);
		break;
	case SEMIDS:
		error = semids((int *)a1, (uint_t)a2, (uint_t *)a3);
		break;
	case SEMTIMEDOP:
		error = semop((int)a1, (struct sembuf *)a2, (size_t)a3,
		    (timespec_t *)a4);
		break;
	default:
		error = set_errno(EINVAL);
		break;
	}
	return (error);
}
