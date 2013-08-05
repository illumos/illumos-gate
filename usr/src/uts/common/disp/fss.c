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
 * Copyright (c) 1994, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013, Joyent, Inc. All rights reserved.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/cred.h>
#include <sys/proc.h>
#include <sys/strsubr.h>
#include <sys/priocntl.h>
#include <sys/class.h>
#include <sys/disp.h>
#include <sys/procset.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/schedctl.h>
#include <sys/vmsystm.h>
#include <sys/atomic.h>
#include <sys/project.h>
#include <sys/modctl.h>
#include <sys/fss.h>
#include <sys/fsspriocntl.h>
#include <sys/cpupart.h>
#include <sys/zone.h>
#include <vm/rm.h>
#include <vm/seg_kmem.h>
#include <sys/tnf_probe.h>
#include <sys/policy.h>
#include <sys/sdt.h>
#include <sys/cpucaps.h>

/*
 * FSS Data Structures:
 *
 *                 fsszone
 *                  -----           -----
 *  -----          |     |         |     |
 * |     |-------->|     |<------->|     |<---->...
 * |     |          -----           -----
 * |     |          ^    ^            ^
 * |     |---       |     \            \
 *  -----    |      |      \            \
 * fsspset   |      |       \            \
 *           |      |        \            \
 *           |    -----       -----       -----
 *            -->|     |<--->|     |<--->|     |
 *               |     |     |     |     |     |
 *                -----       -----       -----
 *               fssproj
 *
 *
 * That is, fsspsets contain a list of fsszone's that are currently active in
 * the pset, and a list of fssproj's, corresponding to projects with runnable
 * threads on the pset.  fssproj's in turn point to the fsszone which they
 * are a member of.
 *
 * An fssproj_t is removed when there are no threads in it.
 *
 * An fsszone_t is removed when there are no projects with threads in it.
 *
 * Projects in a zone compete with each other for cpu time, receiving cpu
 * allocation within a zone proportional to fssproj->fssp_shares
 * (project.cpu-shares); at a higher level zones compete with each other,
 * receiving allocation in a pset proportional to fsszone->fssz_shares
 * (zone.cpu-shares).  See fss_decay_usage() for the precise formula.
 */

static pri_t fss_init(id_t, int, classfuncs_t **);

static struct sclass fss = {
	"FSS",
	fss_init,
	0
};

extern struct mod_ops mod_schedops;

/*
 * Module linkage information for the kernel.
 */
static struct modlsched modlsched = {
	&mod_schedops, "fair share scheduling class", &fss
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlsched, NULL
};

#define	FSS_MAXUPRI	60

/*
 * The fssproc_t structures are kept in an array of circular doubly linked
 * lists.  A hash on the thread pointer is used to determine which list each
 * thread should be placed in.  Each list has a dummy "head" which is never
 * removed, so the list is never empty.  fss_update traverses these lists to
 * update the priorities of threads that have been waiting on the run queue.
 */
#define	FSS_LISTS		16 /* number of lists, must be power of 2 */
#define	FSS_LIST_HASH(t)	(((uintptr_t)(t) >> 9) & (FSS_LISTS - 1))
#define	FSS_LIST_NEXT(i)	(((i) + 1) & (FSS_LISTS - 1))

#define	FSS_LIST_INSERT(fssproc)				\
{								\
	int index = FSS_LIST_HASH(fssproc->fss_tp);		\
	kmutex_t *lockp = &fss_listlock[index];			\
	fssproc_t *headp = &fss_listhead[index];		\
	mutex_enter(lockp);					\
	fssproc->fss_next = headp->fss_next;			\
	fssproc->fss_prev = headp;				\
	headp->fss_next->fss_prev = fssproc;			\
	headp->fss_next = fssproc;				\
	mutex_exit(lockp);					\
}

#define	FSS_LIST_DELETE(fssproc)				\
{								\
	int index = FSS_LIST_HASH(fssproc->fss_tp);		\
	kmutex_t *lockp = &fss_listlock[index];			\
	mutex_enter(lockp);					\
	fssproc->fss_prev->fss_next = fssproc->fss_next;	\
	fssproc->fss_next->fss_prev = fssproc->fss_prev;	\
	mutex_exit(lockp);					\
}

#define	FSS_TICK_COST	1000	/* tick cost for threads with nice level = 0 */

/*
 * Decay rate percentages are based on n/128 rather than n/100 so  that
 * calculations can avoid having to do an integer divide by 100 (divide
 * by FSS_DECAY_BASE == 128 optimizes to an arithmetic shift).
 *
 * FSS_DECAY_MIN	=  83/128 ~= 65%
 * FSS_DECAY_MAX	= 108/128 ~= 85%
 * FSS_DECAY_USG	=  96/128 ~= 75%
 */
#define	FSS_DECAY_MIN	83	/* fsspri decay pct for threads w/ nice -20 */
#define	FSS_DECAY_MAX	108	/* fsspri decay pct for threads w/ nice +19 */
#define	FSS_DECAY_USG	96	/* fssusage decay pct for projects */
#define	FSS_DECAY_BASE	128	/* base for decay percentages above */

#define	FSS_NICE_MIN	0
#define	FSS_NICE_MAX	(2 * NZERO - 1)
#define	FSS_NICE_RANGE	(FSS_NICE_MAX - FSS_NICE_MIN + 1)

static int	fss_nice_tick[FSS_NICE_RANGE];
static int	fss_nice_decay[FSS_NICE_RANGE];

static pri_t	fss_maxupri = FSS_MAXUPRI; /* maximum FSS user priority */
static pri_t	fss_maxumdpri; /* maximum user mode fss priority */
static pri_t	fss_maxglobpri;	/* maximum global priority used by fss class */
static pri_t	fss_minglobpri;	/* minimum global priority */

static fssproc_t fss_listhead[FSS_LISTS];
static kmutex_t	fss_listlock[FSS_LISTS];

static fsspset_t *fsspsets;
static kmutex_t fsspsets_lock;	/* protects fsspsets */

static id_t	fss_cid;

static time_t	fss_minrun = 2;	/* t_pri becomes 59 within 2 secs */
static time_t	fss_minslp = 2;	/* min time on sleep queue for hardswap */
static int	fss_quantum = 11;

static void	fss_newpri(fssproc_t *);
static void	fss_update(void *);
static int	fss_update_list(int);
static void	fss_change_priority(kthread_t *, fssproc_t *);

static int	fss_admin(caddr_t, cred_t *);
static int	fss_getclinfo(void *);
static int	fss_parmsin(void *);
static int	fss_parmsout(void *, pc_vaparms_t *);
static int	fss_vaparmsin(void *, pc_vaparms_t *);
static int	fss_vaparmsout(void *, pc_vaparms_t *);
static int	fss_getclpri(pcpri_t *);
static int	fss_alloc(void **, int);
static void	fss_free(void *);

static int	fss_enterclass(kthread_t *, id_t, void *, cred_t *, void *);
static void	fss_exitclass(void *);
static int	fss_canexit(kthread_t *, cred_t *);
static int	fss_fork(kthread_t *, kthread_t *, void *);
static void	fss_forkret(kthread_t *, kthread_t *);
static void	fss_parmsget(kthread_t *, void *);
static int	fss_parmsset(kthread_t *, void *, id_t, cred_t *);
static void	fss_stop(kthread_t *, int, int);
static void	fss_exit(kthread_t *);
static void	fss_active(kthread_t *);
static void	fss_inactive(kthread_t *);
static pri_t	fss_swapin(kthread_t *, int);
static pri_t	fss_swapout(kthread_t *, int);
static void	fss_trapret(kthread_t *);
static void	fss_preempt(kthread_t *);
static void	fss_setrun(kthread_t *);
static void	fss_sleep(kthread_t *);
static void	fss_tick(kthread_t *);
static void	fss_wakeup(kthread_t *);
static int	fss_donice(kthread_t *, cred_t *, int, int *);
static int	fss_doprio(kthread_t *, cred_t *, int, int *);
static pri_t	fss_globpri(kthread_t *);
static void	fss_yield(kthread_t *);
static void	fss_nullsys();

static struct classfuncs fss_classfuncs = {
	/* class functions */
	fss_admin,
	fss_getclinfo,
	fss_parmsin,
	fss_parmsout,
	fss_vaparmsin,
	fss_vaparmsout,
	fss_getclpri,
	fss_alloc,
	fss_free,

	/* thread functions */
	fss_enterclass,
	fss_exitclass,
	fss_canexit,
	fss_fork,
	fss_forkret,
	fss_parmsget,
	fss_parmsset,
	fss_stop,
	fss_exit,
	fss_active,
	fss_inactive,
	fss_swapin,
	fss_swapout,
	fss_trapret,
	fss_preempt,
	fss_setrun,
	fss_sleep,
	fss_tick,
	fss_wakeup,
	fss_donice,
	fss_globpri,
	fss_nullsys,	/* set_process_group */
	fss_yield,
	fss_doprio,
};

int
_init()
{
	return (mod_install(&modlinkage));
}

int
_fini()
{
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*ARGSUSED*/
static int
fss_project_walker(kproject_t *kpj, void *buf)
{
	return (0);
}

void *
fss_allocbuf(int op, int type)
{
	fssbuf_t *fssbuf;
	void **fsslist;
	int cnt;
	int i;
	size_t size;

	ASSERT(op == FSS_NPSET_BUF || op == FSS_NPROJ_BUF || op == FSS_ONE_BUF);
	ASSERT(type == FSS_ALLOC_PROJ || type == FSS_ALLOC_ZONE);
	ASSERT(MUTEX_HELD(&cpu_lock));

	fssbuf = kmem_zalloc(sizeof (fssbuf_t), KM_SLEEP);
	switch (op) {
	case FSS_NPSET_BUF:
		cnt = cpupart_list(NULL, 0, CP_NONEMPTY);
		break;
	case FSS_NPROJ_BUF:
		cnt = project_walk_all(ALL_ZONES, fss_project_walker, NULL);
		break;
	case FSS_ONE_BUF:
		cnt = 1;
		break;
	}

	switch (type) {
	case FSS_ALLOC_PROJ:
		size = sizeof (fssproj_t);
		break;
	case FSS_ALLOC_ZONE:
		size = sizeof (fsszone_t);
		break;
	}
	fsslist = kmem_zalloc(cnt * sizeof (void *), KM_SLEEP);
	fssbuf->fssb_size = cnt;
	fssbuf->fssb_list = fsslist;
	for (i = 0; i < cnt; i++)
		fsslist[i] = kmem_zalloc(size, KM_SLEEP);
	return (fssbuf);
}

void
fss_freebuf(fssbuf_t *fssbuf, int type)
{
	void **fsslist;
	int i;
	size_t size;

	ASSERT(fssbuf != NULL);
	ASSERT(type == FSS_ALLOC_PROJ || type == FSS_ALLOC_ZONE);
	fsslist = fssbuf->fssb_list;

	switch (type) {
	case FSS_ALLOC_PROJ:
		size = sizeof (fssproj_t);
		break;
	case FSS_ALLOC_ZONE:
		size = sizeof (fsszone_t);
		break;
	}

	for (i = 0; i < fssbuf->fssb_size; i++) {
		if (fsslist[i] != NULL)
			kmem_free(fsslist[i], size);
	}
	kmem_free(fsslist, sizeof (void *) * fssbuf->fssb_size);
	kmem_free(fssbuf, sizeof (fssbuf_t));
}

static fsspset_t *
fss_find_fsspset(cpupart_t *cpupart)
{
	int i;
	fsspset_t *fsspset = NULL;
	int found = 0;

	ASSERT(cpupart != NULL);
	ASSERT(MUTEX_HELD(&fsspsets_lock));

	/*
	 * Search for the cpupart pointer in the array of fsspsets.
	 */
	for (i = 0; i < max_ncpus; i++) {
		fsspset = &fsspsets[i];
		if (fsspset->fssps_cpupart == cpupart) {
			ASSERT(fsspset->fssps_nproj > 0);
			found = 1;
			break;
		}
	}
	if (found == 0) {
		/*
		 * If we didn't find anything, then use the first
		 * available slot in the fsspsets array.
		 */
		for (i = 0; i < max_ncpus; i++) {
			fsspset = &fsspsets[i];
			if (fsspset->fssps_cpupart == NULL) {
				ASSERT(fsspset->fssps_nproj == 0);
				found = 1;
				break;
			}
		}
		fsspset->fssps_cpupart = cpupart;
	}
	ASSERT(found == 1);
	return (fsspset);
}

static void
fss_del_fsspset(fsspset_t *fsspset)
{
	ASSERT(MUTEX_HELD(&fsspsets_lock));
	ASSERT(MUTEX_HELD(&fsspset->fssps_lock));
	ASSERT(fsspset->fssps_nproj == 0);
	ASSERT(fsspset->fssps_list == NULL);
	ASSERT(fsspset->fssps_zones == NULL);
	fsspset->fssps_cpupart = NULL;
	fsspset->fssps_maxfsspri = 0;
	fsspset->fssps_shares = 0;
}

/*
 * The following routine returns a pointer to the fsszone structure which
 * belongs to zone "zone" and cpu partition fsspset, if such structure exists.
 */
static fsszone_t *
fss_find_fsszone(fsspset_t *fsspset, zone_t *zone)
{
	fsszone_t *fsszone;

	ASSERT(MUTEX_HELD(&fsspset->fssps_lock));

	if (fsspset->fssps_list != NULL) {
		/*
		 * There are projects/zones active on this cpu partition
		 * already.  Try to find our zone among them.
		 */
		fsszone = fsspset->fssps_zones;
		do {
			if (fsszone->fssz_zone == zone) {
				return (fsszone);
			}
			fsszone = fsszone->fssz_next;
		} while (fsszone != fsspset->fssps_zones);
	}
	return (NULL);
}

/*
 * The following routine links new fsszone structure into doubly linked list of
 * zones active on the specified cpu partition.
 */
static void
fss_insert_fsszone(fsspset_t *fsspset, zone_t *zone, fsszone_t *fsszone)
{
	ASSERT(MUTEX_HELD(&fsspset->fssps_lock));

	fsszone->fssz_zone = zone;
	fsszone->fssz_rshares = zone->zone_shares;

	if (fsspset->fssps_zones == NULL) {
		/*
		 * This will be the first fsszone for this fsspset
		 */
		fsszone->fssz_next = fsszone->fssz_prev = fsszone;
		fsspset->fssps_zones = fsszone;
	} else {
		/*
		 * Insert this fsszone to the doubly linked list.
		 */
		fsszone_t *fssz_head = fsspset->fssps_zones;

		fsszone->fssz_next = fssz_head;
		fsszone->fssz_prev = fssz_head->fssz_prev;
		fssz_head->fssz_prev->fssz_next = fsszone;
		fssz_head->fssz_prev = fsszone;
		fsspset->fssps_zones = fsszone;
	}
}

/*
 * The following routine removes a single fsszone structure from the doubly
 * linked list of zones active on the specified cpu partition.  Note that
 * global fsspsets_lock must be held in case this fsszone structure is the last
 * on the above mentioned list.  Also note that the fsszone structure is not
 * freed here, it is the responsibility of the caller to call kmem_free for it.
 */
static void
fss_remove_fsszone(fsspset_t *fsspset, fsszone_t *fsszone)
{
	ASSERT(MUTEX_HELD(&fsspset->fssps_lock));
	ASSERT(fsszone->fssz_nproj == 0);
	ASSERT(fsszone->fssz_shares == 0);
	ASSERT(fsszone->fssz_runnable == 0);

	if (fsszone->fssz_next != fsszone) {
		/*
		 * This is not the last zone in the list.
		 */
		fsszone->fssz_prev->fssz_next = fsszone->fssz_next;
		fsszone->fssz_next->fssz_prev = fsszone->fssz_prev;
		if (fsspset->fssps_zones == fsszone)
			fsspset->fssps_zones = fsszone->fssz_next;
	} else {
		/*
		 * This was the last zone active in this cpu partition.
		 */
		fsspset->fssps_zones = NULL;
	}
}

/*
 * The following routine returns a pointer to the fssproj structure
 * which belongs to project kpj and cpu partition fsspset, if such structure
 * exists.
 */
static fssproj_t *
fss_find_fssproj(fsspset_t *fsspset, kproject_t *kpj)
{
	fssproj_t *fssproj;

	ASSERT(MUTEX_HELD(&fsspset->fssps_lock));

	if (fsspset->fssps_list != NULL) {
		/*
		 * There are projects running on this cpu partition already.
		 * Try to find our project among them.
		 */
		fssproj = fsspset->fssps_list;
		do {
			if (fssproj->fssp_proj == kpj) {
				ASSERT(fssproj->fssp_pset == fsspset);
				return (fssproj);
			}
			fssproj = fssproj->fssp_next;
		} while (fssproj != fsspset->fssps_list);
	}
	return (NULL);
}

/*
 * The following routine links new fssproj structure into doubly linked list
 * of projects running on the specified cpu partition.
 */
static void
fss_insert_fssproj(fsspset_t *fsspset, kproject_t *kpj, fsszone_t *fsszone,
    fssproj_t *fssproj)
{
	ASSERT(MUTEX_HELD(&fsspset->fssps_lock));

	fssproj->fssp_pset = fsspset;
	fssproj->fssp_proj = kpj;
	fssproj->fssp_shares = kpj->kpj_shares;

	fsspset->fssps_nproj++;

	if (fsspset->fssps_list == NULL) {
		/*
		 * This will be the first fssproj for this fsspset
		 */
		fssproj->fssp_next = fssproj->fssp_prev = fssproj;
		fsspset->fssps_list = fssproj;
	} else {
		/*
		 * Insert this fssproj to the doubly linked list.
		 */
		fssproj_t *fssp_head = fsspset->fssps_list;

		fssproj->fssp_next = fssp_head;
		fssproj->fssp_prev = fssp_head->fssp_prev;
		fssp_head->fssp_prev->fssp_next = fssproj;
		fssp_head->fssp_prev = fssproj;
		fsspset->fssps_list = fssproj;
	}
	fssproj->fssp_fsszone = fsszone;
	fsszone->fssz_nproj++;
	ASSERT(fsszone->fssz_nproj != 0);
}

/*
 * The following routine removes a single fssproj structure from the doubly
 * linked list of projects running on the specified cpu partition.  Note that
 * global fsspsets_lock must be held in case if this fssproj structure is the
 * last on the above mentioned list.  Also note that the fssproj structure is
 * not freed here, it is the responsibility of the caller to call kmem_free
 * for it.
 */
static void
fss_remove_fssproj(fsspset_t *fsspset, fssproj_t *fssproj)
{
	fsszone_t *fsszone;

	ASSERT(MUTEX_HELD(&fsspsets_lock));
	ASSERT(MUTEX_HELD(&fsspset->fssps_lock));
	ASSERT(fssproj->fssp_runnable == 0);

	fsspset->fssps_nproj--;

	fsszone = fssproj->fssp_fsszone;
	fsszone->fssz_nproj--;

	if (fssproj->fssp_next != fssproj) {
		/*
		 * This is not the last part in the list.
		 */
		fssproj->fssp_prev->fssp_next = fssproj->fssp_next;
		fssproj->fssp_next->fssp_prev = fssproj->fssp_prev;
		if (fsspset->fssps_list == fssproj)
			fsspset->fssps_list = fssproj->fssp_next;
		if (fsszone->fssz_nproj == 0)
			fss_remove_fsszone(fsspset, fsszone);
	} else {
		/*
		 * This was the last project part running
		 * at this cpu partition.
		 */
		fsspset->fssps_list = NULL;
		ASSERT(fsspset->fssps_nproj == 0);
		ASSERT(fsszone->fssz_nproj == 0);
		fss_remove_fsszone(fsspset, fsszone);
		fss_del_fsspset(fsspset);
	}
}

static void
fss_inactive(kthread_t *t)
{
	fssproc_t *fssproc;
	fssproj_t *fssproj;
	fsspset_t *fsspset;
	fsszone_t *fsszone;

	ASSERT(THREAD_LOCK_HELD(t));
	fssproc = FSSPROC(t);
	fssproj = FSSPROC2FSSPROJ(fssproc);
	if (fssproj == NULL)	/* if this thread already exited */
		return;
	fsspset = FSSPROJ2FSSPSET(fssproj);
	fsszone = fssproj->fssp_fsszone;
	disp_lock_enter_high(&fsspset->fssps_displock);
	ASSERT(fssproj->fssp_runnable > 0);
	if (--fssproj->fssp_runnable == 0) {
		fsszone->fssz_shares -= fssproj->fssp_shares;
		if (--fsszone->fssz_runnable == 0)
			fsspset->fssps_shares -= fsszone->fssz_rshares;
	}
	ASSERT(fssproc->fss_runnable == 1);
	fssproc->fss_runnable = 0;
	disp_lock_exit_high(&fsspset->fssps_displock);
}

static void
fss_active(kthread_t *t)
{
	fssproc_t *fssproc;
	fssproj_t *fssproj;
	fsspset_t *fsspset;
	fsszone_t *fsszone;

	ASSERT(THREAD_LOCK_HELD(t));
	fssproc = FSSPROC(t);
	fssproj = FSSPROC2FSSPROJ(fssproc);
	if (fssproj == NULL)	/* if this thread already exited */
		return;
	fsspset = FSSPROJ2FSSPSET(fssproj);
	fsszone = fssproj->fssp_fsszone;
	disp_lock_enter_high(&fsspset->fssps_displock);
	if (++fssproj->fssp_runnable == 1) {
		fsszone->fssz_shares += fssproj->fssp_shares;
		if (++fsszone->fssz_runnable == 1)
			fsspset->fssps_shares += fsszone->fssz_rshares;
	}
	ASSERT(fssproc->fss_runnable == 0);
	fssproc->fss_runnable = 1;
	disp_lock_exit_high(&fsspset->fssps_displock);
}

/*
 * Fair share scheduler initialization. Called by dispinit() at boot time.
 * We can ignore clparmsz argument since we know that the smallest possible
 * parameter buffer is big enough for us.
 */
/*ARGSUSED*/
static pri_t
fss_init(id_t cid, int clparmsz, classfuncs_t **clfuncspp)
{
	int i;

	ASSERT(MUTEX_HELD(&cpu_lock));

	fss_cid = cid;
	fss_maxumdpri = minclsyspri - 1;
	fss_maxglobpri = minclsyspri;
	fss_minglobpri = 0;
	fsspsets = kmem_zalloc(sizeof (fsspset_t) * max_ncpus, KM_SLEEP);

	/*
	 * Initialize the fssproc hash table.
	 */
	for (i = 0; i < FSS_LISTS; i++)
		fss_listhead[i].fss_next = fss_listhead[i].fss_prev =
		    &fss_listhead[i];

	*clfuncspp = &fss_classfuncs;

	/*
	 * Fill in fss_nice_tick and fss_nice_decay arrays:
	 * The cost of a tick is lower at positive nice values (so that it
	 * will not increase its project's usage as much as normal) with 50%
	 * drop at the maximum level and 50% increase at the minimum level.
	 * The fsspri decay is slower at positive nice values.  fsspri values
	 * of processes with negative nice levels must decay faster to receive
	 * time slices more frequently than normal.
	 */
	for (i = 0; i < FSS_NICE_RANGE; i++) {
		fss_nice_tick[i] = (FSS_TICK_COST * (((3 * FSS_NICE_RANGE) / 2)
		    - i)) / FSS_NICE_RANGE;
		fss_nice_decay[i] = FSS_DECAY_MIN +
		    ((FSS_DECAY_MAX - FSS_DECAY_MIN) * i) /
		    (FSS_NICE_RANGE - 1);
	}

	return (fss_maxglobpri);
}

/*
 * Calculate the new cpupri based on the usage, the number of shares and
 * the number of active threads.  Reset the tick counter for this thread.
 */
static void
fss_newpri(fssproc_t *fssproc)
{
	kthread_t *tp;
	fssproj_t *fssproj;
	fsspset_t *fsspset;
	fsszone_t *fsszone;
	fsspri_t fsspri, maxfsspri;
	pri_t invpri;
	uint32_t ticks;

	tp = fssproc->fss_tp;
	ASSERT(tp != NULL);

	if (tp->t_cid != fss_cid)
		return;

	ASSERT(THREAD_LOCK_HELD(tp));

	fssproj = FSSPROC2FSSPROJ(fssproc);
	fsszone = FSSPROJ2FSSZONE(fssproj);
	if (fssproj == NULL)
		/*
		 * No need to change priority of exited threads.
		 */
		return;

	fsspset = FSSPROJ2FSSPSET(fssproj);
	disp_lock_enter_high(&fsspset->fssps_displock);

	if (fssproj->fssp_shares == 0 || fsszone->fssz_rshares == 0) {
		/*
		 * Special case: threads with no shares.
		 */
		fssproc->fss_umdpri = fss_minglobpri;
		fssproc->fss_ticks = 0;
		disp_lock_exit_high(&fsspset->fssps_displock);
		return;
	}

	/*
	 * fsspri += shusage * nrunnable * ticks
	 */
	ticks = fssproc->fss_ticks;
	fssproc->fss_ticks = 0;
	fsspri = fssproc->fss_fsspri;
	fsspri += fssproj->fssp_shusage * fssproj->fssp_runnable * ticks;
	fssproc->fss_fsspri = fsspri;

	if (fsspri < fss_maxumdpri)
		fsspri = fss_maxumdpri;	/* so that maxfsspri is != 0 */

	/*
	 * The general priority formula:
	 *
	 *			(fsspri * umdprirange)
	 *   pri = maxumdpri - ------------------------
	 *				maxfsspri
	 *
	 * If this thread's fsspri is greater than the previous largest
	 * fsspri, then record it as the new high and priority for this
	 * thread will be one (the lowest priority assigned to a thread
	 * that has non-zero shares).
	 * Note that this formula cannot produce out of bounds priority
	 * values; if it is changed, additional checks may need  to  be
	 * added.
	 */
	maxfsspri = fsspset->fssps_maxfsspri;
	if (fsspri >= maxfsspri) {
		fsspset->fssps_maxfsspri = fsspri;
		disp_lock_exit_high(&fsspset->fssps_displock);
		fssproc->fss_umdpri = 1;
	} else {
		disp_lock_exit_high(&fsspset->fssps_displock);
		invpri = (fsspri * (fss_maxumdpri - 1)) / maxfsspri;
		fssproc->fss_umdpri = fss_maxumdpri - invpri;
	}
}

/*
 * Decays usages of all running projects and resets their tick counters.
 * Called once per second from fss_update() after updating priorities.
 */
static void
fss_decay_usage()
{
	uint32_t zone_ext_shares, zone_int_shares;
	uint32_t kpj_shares, pset_shares;
	fsspset_t *fsspset;
	fssproj_t *fssproj;
	fsszone_t *fsszone;
	fsspri_t maxfsspri;
	int psetid;

	mutex_enter(&fsspsets_lock);
	/*
	 * Go through all active processor sets and decay usages of projects
	 * running on them.
	 */
	for (psetid = 0; psetid < max_ncpus; psetid++) {
		fsspset = &fsspsets[psetid];
		mutex_enter(&fsspset->fssps_lock);

		if (fsspset->fssps_cpupart == NULL ||
		    (fssproj = fsspset->fssps_list) == NULL) {
			mutex_exit(&fsspset->fssps_lock);
			continue;
		}

		/*
		 * Decay maxfsspri for this cpu partition with the
		 * fastest possible decay rate.
		 */
		disp_lock_enter(&fsspset->fssps_displock);

		maxfsspri = (fsspset->fssps_maxfsspri *
		    fss_nice_decay[NZERO]) / FSS_DECAY_BASE;
		if (maxfsspri < fss_maxumdpri)
			maxfsspri = fss_maxumdpri;
		fsspset->fssps_maxfsspri = maxfsspri;

		do {
			/*
			 * Decay usage for each project running on
			 * this cpu partition.
			 */
			fssproj->fssp_usage =
			    (fssproj->fssp_usage * FSS_DECAY_USG) /
			    FSS_DECAY_BASE + fssproj->fssp_ticks;
			fssproj->fssp_ticks = 0;

			fsszone = fssproj->fssp_fsszone;
			/*
			 * Readjust the project's number of shares if it has
			 * changed since we checked it last time.
			 */
			kpj_shares = fssproj->fssp_proj->kpj_shares;
			if (fssproj->fssp_shares != kpj_shares) {
				if (fssproj->fssp_runnable != 0) {
					fsszone->fssz_shares -=
					    fssproj->fssp_shares;
					fsszone->fssz_shares += kpj_shares;
				}
				fssproj->fssp_shares = kpj_shares;
			}

			/*
			 * Readjust the zone's number of shares if it
			 * has changed since we checked it last time.
			 */
			zone_ext_shares = fsszone->fssz_zone->zone_shares;
			if (fsszone->fssz_rshares != zone_ext_shares) {
				if (fsszone->fssz_runnable != 0) {
					fsspset->fssps_shares -=
					    fsszone->fssz_rshares;
					fsspset->fssps_shares +=
					    zone_ext_shares;
				}
				fsszone->fssz_rshares = zone_ext_shares;
			}
			zone_int_shares = fsszone->fssz_shares;
			pset_shares = fsspset->fssps_shares;
			/*
			 * Calculate fssp_shusage value to be used
			 * for fsspri increments for the next second.
			 */
			if (kpj_shares == 0 || zone_ext_shares == 0) {
				fssproj->fssp_shusage = 0;
			} else if (FSSPROJ2KPROJ(fssproj) == proj0p) {
				/*
				 * Project 0 in the global zone has 50%
				 * of its zone.
				 */
				fssproj->fssp_shusage = (fssproj->fssp_usage *
				    zone_int_shares * zone_int_shares) /
				    (zone_ext_shares * zone_ext_shares);
			} else {
				/*
				 * Thread's priority is based on its project's
				 * normalized usage (shusage) value which gets
				 * calculated this way:
				 *
				 *	   pset_shares^2    zone_int_shares^2
				 * usage * ------------- * ------------------
				 *	   kpj_shares^2	    zone_ext_shares^2
				 *
				 * Where zone_int_shares is the sum of shares
				 * of all active projects within the zone (and
				 * the pset), and zone_ext_shares is the number
				 * of zone shares (ie, zone.cpu-shares).
				 *
				 * If there is only one zone active on the pset
				 * the above reduces to:
				 *
				 * 			zone_int_shares^2
				 * shusage = usage * ---------------------
				 * 			kpj_shares^2
				 *
				 * If there's only one project active in the
				 * zone this formula reduces to:
				 *
				 *			pset_shares^2
				 * shusage = usage * ----------------------
				 *			zone_ext_shares^2
				 */
				fssproj->fssp_shusage = fssproj->fssp_usage *
				    pset_shares * zone_int_shares;
				fssproj->fssp_shusage /=
				    kpj_shares * zone_ext_shares;
				fssproj->fssp_shusage *=
				    pset_shares * zone_int_shares;
				fssproj->fssp_shusage /=
				    kpj_shares * zone_ext_shares;
			}
			fssproj = fssproj->fssp_next;
		} while (fssproj != fsspset->fssps_list);

		disp_lock_exit(&fsspset->fssps_displock);
		mutex_exit(&fsspset->fssps_lock);
	}
	mutex_exit(&fsspsets_lock);
}

static void
fss_change_priority(kthread_t *t, fssproc_t *fssproc)
{
	pri_t new_pri;

	ASSERT(THREAD_LOCK_HELD(t));
	new_pri = fssproc->fss_umdpri;
	ASSERT(new_pri >= 0 && new_pri <= fss_maxglobpri);

	t->t_cpri = fssproc->fss_upri;
	fssproc->fss_flags &= ~FSSRESTORE;
	if (t == curthread || t->t_state == TS_ONPROC) {
		/*
		 * curthread is always onproc
		 */
		cpu_t *cp = t->t_disp_queue->disp_cpu;
		THREAD_CHANGE_PRI(t, new_pri);
		if (t == cp->cpu_dispthread)
			cp->cpu_dispatch_pri = DISP_PRIO(t);
		if (DISP_MUST_SURRENDER(t)) {
			fssproc->fss_flags |= FSSBACKQ;
			cpu_surrender(t);
		} else {
			fssproc->fss_timeleft = fss_quantum;
		}
	} else {
		/*
		 * When the priority of a thread is changed, it may be
		 * necessary to adjust its position on a sleep queue or
		 * dispatch queue.  The function thread_change_pri accomplishes
		 * this.
		 */
		if (thread_change_pri(t, new_pri, 0)) {
			/*
			 * The thread was on a run queue.
			 */
			fssproc->fss_timeleft = fss_quantum;
		} else {
			fssproc->fss_flags |= FSSBACKQ;
		}
	}
}

/*
 * Update priorities of all fair-sharing threads that are currently runnable
 * at a user mode priority based on the number of shares and current usage.
 * Called once per second via timeout which we reset here.
 *
 * There are several lists of fair-sharing threads broken up by a hash on the
 * thread pointer.  Each list has its own lock.  This avoids blocking all
 * fss_enterclass, fss_fork, and fss_exitclass operations while fss_update runs.
 * fss_update traverses each list in turn.
 */
static void
fss_update(void *arg)
{
	int i;
	int new_marker = -1;
	static int fss_update_marker;

	/*
	 * Decay and update usages for all projects.
	 */
	fss_decay_usage();

	/*
	 * Start with the fss_update_marker list, then do the rest.
	 */
	i = fss_update_marker;

	/*
	 * Go around all threads, set new priorities and decay
	 * per-thread CPU usages.
	 */
	do {
		/*
		 * If this is the first list after the current marker to have
		 * threads with priorities updates, advance the marker to this
		 * list for the next time fss_update runs.
		 */
		if (fss_update_list(i) &&
		    new_marker == -1 && i != fss_update_marker)
			new_marker = i;
	} while ((i = FSS_LIST_NEXT(i)) != fss_update_marker);

	/*
	 * Advance marker for the next fss_update call
	 */
	if (new_marker != -1)
		fss_update_marker = new_marker;

	(void) timeout(fss_update, arg, hz);
}

/*
 * Updates priority for a list of threads.  Returns 1 if the priority of one
 * of the threads was actually updated, 0 if none were for various reasons
 * (thread is no longer in the FSS class, is not runnable, has the preemption
 * control no-preempt bit set, etc.)
 */
static int
fss_update_list(int i)
{
	fssproc_t *fssproc;
	fssproj_t *fssproj;
	fsspri_t fsspri;
	kthread_t *t;
	int updated = 0;

	mutex_enter(&fss_listlock[i]);
	for (fssproc = fss_listhead[i].fss_next; fssproc != &fss_listhead[i];
	    fssproc = fssproc->fss_next) {
		t = fssproc->fss_tp;
		/*
		 * Lock the thread and verify the state.
		 */
		thread_lock(t);
		/*
		 * Skip the thread if it is no longer in the FSS class or
		 * is running with kernel mode priority.
		 */
		if (t->t_cid != fss_cid)
			goto next;
		if ((fssproc->fss_flags & FSSKPRI) != 0)
			goto next;

		fssproj = FSSPROC2FSSPROJ(fssproc);
		if (fssproj == NULL)
			goto next;
		if (fssproj->fssp_shares != 0) {
			/*
			 * Decay fsspri value.
			 */
			fsspri = fssproc->fss_fsspri;
			fsspri = (fsspri * fss_nice_decay[fssproc->fss_nice]) /
			    FSS_DECAY_BASE;
			fssproc->fss_fsspri = fsspri;
		}

		if (t->t_schedctl && schedctl_get_nopreempt(t))
			goto next;
		if (t->t_state != TS_RUN && t->t_state != TS_WAIT) {
			/*
			 * Make next syscall/trap call fss_trapret
			 */
			t->t_trapret = 1;
			aston(t);
			goto next;
		}
		fss_newpri(fssproc);
		updated = 1;

		/*
		 * Only dequeue the thread if it needs to be moved; otherwise
		 * it should just round-robin here.
		 */
		if (t->t_pri != fssproc->fss_umdpri)
			fss_change_priority(t, fssproc);
next:
		thread_unlock(t);
	}
	mutex_exit(&fss_listlock[i]);
	return (updated);
}

/*ARGSUSED*/
static int
fss_admin(caddr_t uaddr, cred_t *reqpcredp)
{
	fssadmin_t fssadmin;

	if (copyin(uaddr, &fssadmin, sizeof (fssadmin_t)))
		return (EFAULT);

	switch (fssadmin.fss_cmd) {
	case FSS_SETADMIN:
		if (secpolicy_dispadm(reqpcredp) != 0)
			return (EPERM);
		if (fssadmin.fss_quantum <= 0 || fssadmin.fss_quantum >= hz)
			return (EINVAL);
		fss_quantum = fssadmin.fss_quantum;
		break;
	case FSS_GETADMIN:
		fssadmin.fss_quantum = fss_quantum;
		if (copyout(&fssadmin, uaddr, sizeof (fssadmin_t)))
			return (EFAULT);
		break;
	default:
		return (EINVAL);
	}
	return (0);
}

static int
fss_getclinfo(void *infop)
{
	fssinfo_t *fssinfo = (fssinfo_t *)infop;
	fssinfo->fss_maxupri = fss_maxupri;
	return (0);
}

static int
fss_parmsin(void *parmsp)
{
	fssparms_t *fssparmsp = (fssparms_t *)parmsp;

	/*
	 * Check validity of parameters.
	 */
	if ((fssparmsp->fss_uprilim > fss_maxupri ||
	    fssparmsp->fss_uprilim < -fss_maxupri) &&
	    fssparmsp->fss_uprilim != FSS_NOCHANGE)
		return (EINVAL);

	if ((fssparmsp->fss_upri > fss_maxupri ||
	    fssparmsp->fss_upri < -fss_maxupri) &&
	    fssparmsp->fss_upri != FSS_NOCHANGE)
		return (EINVAL);

	return (0);
}

/*ARGSUSED*/
static int
fss_parmsout(void *parmsp, pc_vaparms_t *vaparmsp)
{
	return (0);
}

static int
fss_vaparmsin(void *parmsp, pc_vaparms_t *vaparmsp)
{
	fssparms_t *fssparmsp = (fssparms_t *)parmsp;
	int priflag = 0;
	int limflag = 0;
	uint_t cnt;
	pc_vaparm_t *vpp = &vaparmsp->pc_parms[0];

	/*
	 * FSS_NOCHANGE (-32768) is outside of the range of values for
	 * fss_uprilim and fss_upri.  If the structure fssparms_t is changed,
	 * FSS_NOCHANGE should be replaced by a flag word.
	 */
	fssparmsp->fss_uprilim = FSS_NOCHANGE;
	fssparmsp->fss_upri = FSS_NOCHANGE;

	/*
	 * Get the varargs parameter and check validity of parameters.
	 */
	if (vaparmsp->pc_vaparmscnt > PC_VAPARMCNT)
		return (EINVAL);

	for (cnt = 0; cnt < vaparmsp->pc_vaparmscnt; cnt++, vpp++) {
		switch (vpp->pc_key) {
		case FSS_KY_UPRILIM:
			if (limflag++)
				return (EINVAL);
			fssparmsp->fss_uprilim = (pri_t)vpp->pc_parm;
			if (fssparmsp->fss_uprilim > fss_maxupri ||
			    fssparmsp->fss_uprilim < -fss_maxupri)
				return (EINVAL);
			break;
		case FSS_KY_UPRI:
			if (priflag++)
				return (EINVAL);
			fssparmsp->fss_upri = (pri_t)vpp->pc_parm;
			if (fssparmsp->fss_upri > fss_maxupri ||
			    fssparmsp->fss_upri < -fss_maxupri)
				return (EINVAL);
			break;
		default:
			return (EINVAL);
		}
	}

	if (vaparmsp->pc_vaparmscnt == 0) {
		/*
		 * Use default parameters.
		 */
		fssparmsp->fss_upri = fssparmsp->fss_uprilim = 0;
	}

	return (0);
}

/*
 * Copy all selected fair-sharing class parameters to the user.  The parameters
 * are specified by a key.
 */
static int
fss_vaparmsout(void *parmsp, pc_vaparms_t *vaparmsp)
{
	fssparms_t *fssparmsp = (fssparms_t *)parmsp;
	int priflag = 0;
	int limflag = 0;
	uint_t cnt;
	pc_vaparm_t *vpp = &vaparmsp->pc_parms[0];

	ASSERT(MUTEX_NOT_HELD(&curproc->p_lock));

	if (vaparmsp->pc_vaparmscnt > PC_VAPARMCNT)
		return (EINVAL);

	for (cnt = 0; cnt < vaparmsp->pc_vaparmscnt; cnt++, vpp++) {
		switch (vpp->pc_key) {
		case FSS_KY_UPRILIM:
			if (limflag++)
				return (EINVAL);
			if (copyout(&fssparmsp->fss_uprilim,
			    (caddr_t)(uintptr_t)vpp->pc_parm, sizeof (pri_t)))
				return (EFAULT);
			break;
		case FSS_KY_UPRI:
			if (priflag++)
				return (EINVAL);
			if (copyout(&fssparmsp->fss_upri,
			    (caddr_t)(uintptr_t)vpp->pc_parm, sizeof (pri_t)))
				return (EFAULT);
			break;
		default:
			return (EINVAL);
		}
	}

	return (0);
}

/*
 * Return the user mode scheduling priority range.
 */
static int
fss_getclpri(pcpri_t *pcprip)
{
	pcprip->pc_clpmax = fss_maxupri;
	pcprip->pc_clpmin = -fss_maxupri;
	return (0);
}

static int
fss_alloc(void **p, int flag)
{
	void *bufp;

	if ((bufp = kmem_zalloc(sizeof (fssproc_t), flag)) == NULL) {
		return (ENOMEM);
	} else {
		*p = bufp;
		return (0);
	}
}

static void
fss_free(void *bufp)
{
	if (bufp)
		kmem_free(bufp, sizeof (fssproc_t));
}

/*
 * Thread functions
 */
static int
fss_enterclass(kthread_t *t, id_t cid, void *parmsp, cred_t *reqpcredp,
    void *bufp)
{
	fssparms_t	*fssparmsp = (fssparms_t *)parmsp;
	fssproc_t	*fssproc;
	pri_t		reqfssuprilim;
	pri_t		reqfssupri;
	static uint32_t fssexists = 0;
	fsspset_t	*fsspset;
	fssproj_t	*fssproj;
	fsszone_t	*fsszone;
	kproject_t	*kpj;
	zone_t		*zone;
	int		fsszone_allocated = 0;

	fssproc = (fssproc_t *)bufp;
	ASSERT(fssproc != NULL);

	ASSERT(MUTEX_HELD(&ttoproc(t)->p_lock));

	/*
	 * Only root can move threads to FSS class.
	 */
	if (reqpcredp != NULL && secpolicy_setpriority(reqpcredp) != 0)
		return (EPERM);
	/*
	 * Initialize the fssproc structure.
	 */
	fssproc->fss_umdpri = fss_maxumdpri / 2;

	if (fssparmsp == NULL) {
		/*
		 * Use default values.
		 */
		fssproc->fss_nice = NZERO;
		fssproc->fss_uprilim = fssproc->fss_upri = 0;
	} else {
		/*
		 * Use supplied values.
		 */
		if (fssparmsp->fss_uprilim == FSS_NOCHANGE) {
			reqfssuprilim = 0;
		} else {
			if (fssparmsp->fss_uprilim > 0 &&
			    secpolicy_setpriority(reqpcredp) != 0)
				return (EPERM);
			reqfssuprilim = fssparmsp->fss_uprilim;
		}
		if (fssparmsp->fss_upri == FSS_NOCHANGE) {
			reqfssupri = reqfssuprilim;
		} else {
			if (fssparmsp->fss_upri > 0 &&
			    secpolicy_setpriority(reqpcredp) != 0)
				return (EPERM);
			/*
			 * Set the user priority to the requested value or
			 * the upri limit, whichever is lower.
			 */
			reqfssupri = fssparmsp->fss_upri;
			if (reqfssupri > reqfssuprilim)
				reqfssupri = reqfssuprilim;
		}
		fssproc->fss_uprilim = reqfssuprilim;
		fssproc->fss_upri = reqfssupri;
		fssproc->fss_nice = NZERO - (NZERO * reqfssupri) / fss_maxupri;
		if (fssproc->fss_nice > FSS_NICE_MAX)
			fssproc->fss_nice = FSS_NICE_MAX;
	}

	fssproc->fss_timeleft = fss_quantum;
	fssproc->fss_tp = t;
	cpucaps_sc_init(&fssproc->fss_caps);

	/*
	 * Put a lock on our fsspset structure.
	 */
	mutex_enter(&fsspsets_lock);
	fsspset = fss_find_fsspset(t->t_cpupart);
	mutex_enter(&fsspset->fssps_lock);
	mutex_exit(&fsspsets_lock);

	zone = ttoproc(t)->p_zone;
	if ((fsszone = fss_find_fsszone(fsspset, zone)) == NULL) {
		if ((fsszone = kmem_zalloc(sizeof (fsszone_t), KM_NOSLEEP))
		    == NULL) {
			mutex_exit(&fsspset->fssps_lock);
			return (ENOMEM);
		} else {
			fsszone_allocated = 1;
			fss_insert_fsszone(fsspset, zone, fsszone);
		}
	}
	kpj = ttoproj(t);
	if ((fssproj = fss_find_fssproj(fsspset, kpj)) == NULL) {
		if ((fssproj = kmem_zalloc(sizeof (fssproj_t), KM_NOSLEEP))
		    == NULL) {
			if (fsszone_allocated) {
				fss_remove_fsszone(fsspset, fsszone);
				kmem_free(fsszone, sizeof (fsszone_t));
			}
			mutex_exit(&fsspset->fssps_lock);
			return (ENOMEM);
		} else {
			fss_insert_fssproj(fsspset, kpj, fsszone, fssproj);
		}
	}
	fssproj->fssp_threads++;
	fssproc->fss_proj = fssproj;

	/*
	 * Reset priority. Process goes to a "user mode" priority here
	 * regardless of whether or not it has slept since entering the kernel.
	 */
	thread_lock(t);
	t->t_clfuncs = &(sclass[cid].cl_funcs->thread);
	t->t_cid = cid;
	t->t_cldata = (void *)fssproc;
	t->t_schedflag |= TS_RUNQMATCH;
	fss_change_priority(t, fssproc);
	if (t->t_state == TS_RUN || t->t_state == TS_ONPROC ||
	    t->t_state == TS_WAIT)
		fss_active(t);
	thread_unlock(t);

	mutex_exit(&fsspset->fssps_lock);

	/*
	 * Link new structure into fssproc list.
	 */
	FSS_LIST_INSERT(fssproc);

	/*
	 * If this is the first fair-sharing thread to occur since boot,
	 * we set up the initial call to fss_update() here. Use an atomic
	 * compare-and-swap since that's easier and faster than a mutex
	 * (but check with an ordinary load first since most of the time
	 * this will already be done).
	 */
	if (fssexists == 0 && cas32(&fssexists, 0, 1) == 0)
		(void) timeout(fss_update, NULL, hz);

	return (0);
}

/*
 * Remove fssproc_t from the list.
 */
static void
fss_exitclass(void *procp)
{
	fssproc_t *fssproc = (fssproc_t *)procp;
	fssproj_t *fssproj;
	fsspset_t *fsspset;
	fsszone_t *fsszone;
	kthread_t *t = fssproc->fss_tp;

	/*
	 * We should be either getting this thread off the deathrow or
	 * this thread has already moved to another scheduling class and
	 * we're being called with its old cldata buffer pointer.  In both
	 * cases, the content of this buffer can not be changed while we're
	 * here.
	 */
	mutex_enter(&fsspsets_lock);
	thread_lock(t);
	if (t->t_cid != fss_cid) {
		/*
		 * We're being called as a result of the priocntl() system
		 * call -- someone is trying to move our thread to another
		 * scheduling class. We can't call fss_inactive() here
		 * because our thread's t_cldata pointer already points
		 * to another scheduling class specific data.
		 */
		ASSERT(MUTEX_HELD(&ttoproc(t)->p_lock));

		fssproj = FSSPROC2FSSPROJ(fssproc);
		fsspset = FSSPROJ2FSSPSET(fssproj);
		fsszone = fssproj->fssp_fsszone;

		if (fssproc->fss_runnable) {
			disp_lock_enter_high(&fsspset->fssps_displock);
			if (--fssproj->fssp_runnable == 0) {
				fsszone->fssz_shares -= fssproj->fssp_shares;
				if (--fsszone->fssz_runnable == 0)
					fsspset->fssps_shares -=
					    fsszone->fssz_rshares;
			}
			disp_lock_exit_high(&fsspset->fssps_displock);
		}
		thread_unlock(t);

		mutex_enter(&fsspset->fssps_lock);
		if (--fssproj->fssp_threads == 0) {
			fss_remove_fssproj(fsspset, fssproj);
			if (fsszone->fssz_nproj == 0)
				kmem_free(fsszone, sizeof (fsszone_t));
			kmem_free(fssproj, sizeof (fssproj_t));
		}
		mutex_exit(&fsspset->fssps_lock);

	} else {
		ASSERT(t->t_state == TS_FREE);
		/*
		 * We're being called from thread_free() when our thread
		 * is removed from the deathrow. There is nothing we need
		 * do here since everything should've been done earlier
		 * in fss_exit().
		 */
		thread_unlock(t);
	}
	mutex_exit(&fsspsets_lock);

	FSS_LIST_DELETE(fssproc);
	fss_free(fssproc);
}

/*ARGSUSED*/
static int
fss_canexit(kthread_t *t, cred_t *credp)
{
	/*
	 * A thread is allowed to exit FSS only if we have sufficient
	 * privileges.
	 */
	if (credp != NULL && secpolicy_setpriority(credp) != 0)
		return (EPERM);
	else
		return (0);
}

/*
 * Initialize fair-share class specific proc structure for a child.
 */
static int
fss_fork(kthread_t *pt, kthread_t *ct, void *bufp)
{
	fssproc_t *pfssproc;	/* ptr to parent's fssproc structure	*/
	fssproc_t *cfssproc;	/* ptr to child's fssproc structure	*/
	fssproj_t *fssproj;
	fsspset_t *fsspset;

	ASSERT(MUTEX_HELD(&ttoproc(pt)->p_lock));
	ASSERT(ct->t_state == TS_STOPPED);

	cfssproc = (fssproc_t *)bufp;
	ASSERT(cfssproc != NULL);
	bzero(cfssproc, sizeof (fssproc_t));

	thread_lock(pt);
	pfssproc = FSSPROC(pt);
	fssproj = FSSPROC2FSSPROJ(pfssproc);
	fsspset = FSSPROJ2FSSPSET(fssproj);
	thread_unlock(pt);

	mutex_enter(&fsspset->fssps_lock);
	/*
	 * Initialize child's fssproc structure.
	 */
	thread_lock(pt);
	ASSERT(FSSPROJ(pt) == fssproj);
	cfssproc->fss_proj = fssproj;
	cfssproc->fss_timeleft = fss_quantum;
	cfssproc->fss_umdpri = pfssproc->fss_umdpri;
	cfssproc->fss_fsspri = 0;
	cfssproc->fss_uprilim = pfssproc->fss_uprilim;
	cfssproc->fss_upri = pfssproc->fss_upri;
	cfssproc->fss_tp = ct;
	cfssproc->fss_nice = pfssproc->fss_nice;
	cpucaps_sc_init(&cfssproc->fss_caps);

	cfssproc->fss_flags =
	    pfssproc->fss_flags & ~(FSSKPRI | FSSBACKQ | FSSRESTORE);
	ct->t_cldata = (void *)cfssproc;
	ct->t_schedflag |= TS_RUNQMATCH;
	thread_unlock(pt);

	fssproj->fssp_threads++;
	mutex_exit(&fsspset->fssps_lock);

	/*
	 * Link new structure into fssproc hash table.
	 */
	FSS_LIST_INSERT(cfssproc);
	return (0);
}

/*
 * Child is placed at back of dispatcher queue and parent gives up processor
 * so that the child runs first after the fork. This allows the child
 * immediately execing to break the multiple use of copy on write pages with no
 * disk home. The parent will get to steal them back rather than uselessly
 * copying them.
 */
static void
fss_forkret(kthread_t *t, kthread_t *ct)
{
	proc_t *pp = ttoproc(t);
	proc_t *cp = ttoproc(ct);
	fssproc_t *fssproc;

	ASSERT(t == curthread);
	ASSERT(MUTEX_HELD(&pidlock));

	/*
	 * Grab the child's p_lock before dropping pidlock to ensure the
	 * process does not disappear before we set it running.
	 */
	mutex_enter(&cp->p_lock);
	continuelwps(cp);
	mutex_exit(&cp->p_lock);

	mutex_enter(&pp->p_lock);
	mutex_exit(&pidlock);
	continuelwps(pp);

	thread_lock(t);

	fssproc = FSSPROC(t);
	fss_newpri(fssproc);
	fssproc->fss_timeleft = fss_quantum;
	t->t_pri = fssproc->fss_umdpri;
	ASSERT(t->t_pri >= 0 && t->t_pri <= fss_maxglobpri);
	fssproc->fss_flags &= ~FSSKPRI;
	THREAD_TRANSITION(t);

	/*
	 * We don't want to call fss_setrun(t) here because it may call
	 * fss_active, which we don't need.
	 */
	fssproc->fss_flags &= ~FSSBACKQ;

	if (t->t_disp_time != ddi_get_lbolt())
		setbackdq(t);
	else
		setfrontdq(t);

	thread_unlock(t);
	/*
	 * Safe to drop p_lock now since it is safe to change
	 * the scheduling class after this point.
	 */
	mutex_exit(&pp->p_lock);

	swtch();
}

/*
 * Get the fair-sharing parameters of the thread pointed to by fssprocp into
 * the buffer pointed by fssparmsp.
 */
static void
fss_parmsget(kthread_t *t, void *parmsp)
{
	fssproc_t *fssproc = FSSPROC(t);
	fssparms_t *fssparmsp = (fssparms_t *)parmsp;

	fssparmsp->fss_uprilim = fssproc->fss_uprilim;
	fssparmsp->fss_upri = fssproc->fss_upri;
}

/*ARGSUSED*/
static int
fss_parmsset(kthread_t *t, void *parmsp, id_t reqpcid, cred_t *reqpcredp)
{
	char		nice;
	pri_t		reqfssuprilim;
	pri_t		reqfssupri;
	fssproc_t	*fssproc = FSSPROC(t);
	fssparms_t	*fssparmsp = (fssparms_t *)parmsp;

	ASSERT(MUTEX_HELD(&(ttoproc(t))->p_lock));

	if (fssparmsp->fss_uprilim == FSS_NOCHANGE)
		reqfssuprilim = fssproc->fss_uprilim;
	else
		reqfssuprilim = fssparmsp->fss_uprilim;

	if (fssparmsp->fss_upri == FSS_NOCHANGE)
		reqfssupri = fssproc->fss_upri;
	else
		reqfssupri = fssparmsp->fss_upri;

	/*
	 * Make sure the user priority doesn't exceed the upri limit.
	 */
	if (reqfssupri > reqfssuprilim)
		reqfssupri = reqfssuprilim;

	/*
	 * Basic permissions enforced by generic kernel code for all classes
	 * require that a thread attempting to change the scheduling parameters
	 * of a target thread be privileged or have a real or effective UID
	 * matching that of the target thread. We are not called unless these
	 * basic permission checks have already passed. The fair-sharing class
	 * requires in addition that the calling thread be privileged if it
	 * is attempting to raise the upri limit above its current value.
	 * This may have been checked previously but if our caller passed us
	 * a non-NULL credential pointer we assume it hasn't and we check it
	 * here.
	 */
	if ((reqpcredp != NULL) &&
	    (reqfssuprilim > fssproc->fss_uprilim) &&
	    secpolicy_raisepriority(reqpcredp) != 0)
		return (EPERM);

	/*
	 * Set fss_nice to the nice value corresponding to the user priority we
	 * are setting.  Note that setting the nice field of the parameter
	 * struct won't affect upri or nice.
	 */
	nice = NZERO - (reqfssupri * NZERO) / fss_maxupri;
	if (nice > FSS_NICE_MAX)
		nice = FSS_NICE_MAX;

	thread_lock(t);

	fssproc->fss_uprilim = reqfssuprilim;
	fssproc->fss_upri = reqfssupri;
	fssproc->fss_nice = nice;
	fss_newpri(fssproc);

	if ((fssproc->fss_flags & FSSKPRI) != 0) {
		thread_unlock(t);
		return (0);
	}

	fss_change_priority(t, fssproc);
	thread_unlock(t);
	return (0);

}

/*
 * The thread is being stopped.
 */
/*ARGSUSED*/
static void
fss_stop(kthread_t *t, int why, int what)
{
	ASSERT(THREAD_LOCK_HELD(t));
	ASSERT(t == curthread);

	fss_inactive(t);
}

/*
 * The current thread is exiting, do necessary adjustments to its project
 */
static void
fss_exit(kthread_t *t)
{
	fsspset_t *fsspset;
	fssproj_t *fssproj;
	fssproc_t *fssproc;
	fsszone_t *fsszone;
	int free = 0;

	/*
	 * Thread t here is either a current thread (in which case we hold
	 * its process' p_lock), or a thread being destroyed by forklwp_fail(),
	 * in which case we hold pidlock and thread is no longer on the
	 * thread list.
	 */
	ASSERT(MUTEX_HELD(&(ttoproc(t))->p_lock) || MUTEX_HELD(&pidlock));

	fssproc = FSSPROC(t);
	fssproj = FSSPROC2FSSPROJ(fssproc);
	fsspset = FSSPROJ2FSSPSET(fssproj);
	fsszone = fssproj->fssp_fsszone;

	mutex_enter(&fsspsets_lock);
	mutex_enter(&fsspset->fssps_lock);

	thread_lock(t);
	disp_lock_enter_high(&fsspset->fssps_displock);
	if (t->t_state == TS_ONPROC || t->t_state == TS_RUN) {
		if (--fssproj->fssp_runnable == 0) {
			fsszone->fssz_shares -= fssproj->fssp_shares;
			if (--fsszone->fssz_runnable == 0)
				fsspset->fssps_shares -= fsszone->fssz_rshares;
		}
		ASSERT(fssproc->fss_runnable == 1);
		fssproc->fss_runnable = 0;
	}
	if (--fssproj->fssp_threads == 0) {
		fss_remove_fssproj(fsspset, fssproj);
		free = 1;
	}
	disp_lock_exit_high(&fsspset->fssps_displock);
	fssproc->fss_proj = NULL;	/* mark this thread as already exited */
	thread_unlock(t);

	if (free) {
		if (fsszone->fssz_nproj == 0)
			kmem_free(fsszone, sizeof (fsszone_t));
		kmem_free(fssproj, sizeof (fssproj_t));
	}
	mutex_exit(&fsspset->fssps_lock);
	mutex_exit(&fsspsets_lock);

	/*
	 * A thread could be exiting in between clock ticks, so we need to
	 * calculate how much CPU time it used since it was charged last time.
	 *
	 * CPU caps are not enforced on exiting processes - it is usually
	 * desirable to exit as soon as possible to free resources.
	 */
	if (CPUCAPS_ON()) {
		thread_lock(t);
		fssproc = FSSPROC(t);
		(void) cpucaps_charge(t, &fssproc->fss_caps,
		    CPUCAPS_CHARGE_ONLY);
		thread_unlock(t);
	}
}

static void
fss_nullsys()
{
}

/*
 * fss_swapin() returns -1 if the thread is loaded or is not eligible to be
 * swapped in. Otherwise, it returns the thread's effective priority based
 * on swapout time and size of process (0 <= epri <= 0 SHRT_MAX).
 */
/*ARGSUSED*/
static pri_t
fss_swapin(kthread_t *t, int flags)
{
	fssproc_t *fssproc = FSSPROC(t);
	long epri = -1;
	proc_t *pp = ttoproc(t);

	ASSERT(THREAD_LOCK_HELD(t));

	if (t->t_state == TS_RUN && (t->t_schedflag & TS_LOAD) == 0) {
		time_t swapout_time;

		swapout_time = (ddi_get_lbolt() - t->t_stime) / hz;
		if (INHERITED(t) || (fssproc->fss_flags & FSSKPRI)) {
			epri = (long)DISP_PRIO(t) + swapout_time;
		} else {
			/*
			 * Threads which have been out for a long time,
			 * have high user mode priority and are associated
			 * with a small address space are more deserving.
			 */
			epri = fssproc->fss_umdpri;
			ASSERT(epri >= 0 && epri <= fss_maxumdpri);
			epri += swapout_time - pp->p_swrss / nz(maxpgio)/2;
		}
		/*
		 * Scale epri so that SHRT_MAX / 2 represents zero priority.
		 */
		epri += SHRT_MAX / 2;
		if (epri < 0)
			epri = 0;
		else if (epri > SHRT_MAX)
			epri = SHRT_MAX;
	}
	return ((pri_t)epri);
}

/*
 * fss_swapout() returns -1 if the thread isn't loaded or is not eligible to
 * be swapped out. Otherwise, it returns the thread's effective priority
 * based on if the swapper is in softswap or hardswap mode.
 */
static pri_t
fss_swapout(kthread_t *t, int flags)
{
	fssproc_t *fssproc = FSSPROC(t);
	long epri = -1;
	proc_t *pp = ttoproc(t);
	time_t swapin_time;

	ASSERT(THREAD_LOCK_HELD(t));

	if (INHERITED(t) ||
	    (fssproc->fss_flags & FSSKPRI) ||
	    (t->t_proc_flag & TP_LWPEXIT) ||
	    (t->t_state & (TS_ZOMB|TS_FREE|TS_STOPPED|TS_ONPROC|TS_WAIT)) ||
	    !(t->t_schedflag & TS_LOAD) ||
	    !(SWAP_OK(t)))
		return (-1);

	ASSERT(t->t_state & (TS_SLEEP | TS_RUN));

	swapin_time = (ddi_get_lbolt() - t->t_stime) / hz;

	if (flags == SOFTSWAP) {
		if (t->t_state == TS_SLEEP && swapin_time > maxslp) {
			epri = 0;
		} else {
			return ((pri_t)epri);
		}
	} else {
		pri_t pri;

		if ((t->t_state == TS_SLEEP && swapin_time > fss_minslp) ||
		    (t->t_state == TS_RUN && swapin_time > fss_minrun)) {
			pri = fss_maxumdpri;
			epri = swapin_time -
			    (rm_asrss(pp->p_as) / nz(maxpgio)/2) - (long)pri;
		} else {
			return ((pri_t)epri);
		}
	}

	/*
	 * Scale epri so that SHRT_MAX / 2 represents zero priority.
	 */
	epri += SHRT_MAX / 2;
	if (epri < 0)
		epri = 0;
	else if (epri > SHRT_MAX)
		epri = SHRT_MAX;

	return ((pri_t)epri);
}

/*
 * If thread is currently at a kernel mode priority (has slept) and is
 * returning to the userland we assign it the appropriate user mode priority
 * and time quantum here.  If we're lowering the thread's priority below that
 * of other runnable threads then we will set runrun via cpu_surrender() to
 * cause preemption.
 */
static void
fss_trapret(kthread_t *t)
{
	fssproc_t *fssproc = FSSPROC(t);
	cpu_t *cp = CPU;

	ASSERT(THREAD_LOCK_HELD(t));
	ASSERT(t == curthread);
	ASSERT(cp->cpu_dispthread == t);
	ASSERT(t->t_state == TS_ONPROC);

	t->t_kpri_req = 0;
	if (fssproc->fss_flags & FSSKPRI) {
		/*
		 * If thread has blocked in the kernel
		 */
		THREAD_CHANGE_PRI(t, fssproc->fss_umdpri);
		cp->cpu_dispatch_pri = DISP_PRIO(t);
		ASSERT(t->t_pri >= 0 && t->t_pri <= fss_maxglobpri);
		fssproc->fss_flags &= ~FSSKPRI;

		if (DISP_MUST_SURRENDER(t))
			cpu_surrender(t);
	}

	/*
	 * Swapout lwp if the swapper is waiting for this thread to reach
	 * a safe point.
	 */
	if (t->t_schedflag & TS_SWAPENQ) {
		thread_unlock(t);
		swapout_lwp(ttolwp(t));
		thread_lock(t);
	}
}

/*
 * Arrange for thread to be placed in appropriate location on dispatcher queue.
 * This is called with the current thread in TS_ONPROC and locked.
 */
static void
fss_preempt(kthread_t *t)
{
	fssproc_t *fssproc = FSSPROC(t);
	klwp_t *lwp;
	uint_t flags;

	ASSERT(t == curthread);
	ASSERT(THREAD_LOCK_HELD(curthread));
	ASSERT(t->t_state == TS_ONPROC);

	/*
	 * If preempted in the kernel, make sure the thread has a kernel
	 * priority if needed.
	 */
	lwp = curthread->t_lwp;
	if (!(fssproc->fss_flags & FSSKPRI) && lwp != NULL && t->t_kpri_req) {
		fssproc->fss_flags |= FSSKPRI;
		THREAD_CHANGE_PRI(t, minclsyspri);
		ASSERT(t->t_pri >= 0 && t->t_pri <= fss_maxglobpri);
		t->t_trapret = 1;	/* so that fss_trapret will run */
		aston(t);
	}

	/*
	 * This thread may be placed on wait queue by CPU Caps. In this case we
	 * do not need to do anything until it is removed from the wait queue.
	 * Do not enforce CPU caps on threads running at a kernel priority
	 */
	if (CPUCAPS_ON()) {
		(void) cpucaps_charge(t, &fssproc->fss_caps,
		    CPUCAPS_CHARGE_ENFORCE);

		if (!(fssproc->fss_flags & FSSKPRI) && CPUCAPS_ENFORCE(t))
			return;
	}

	/*
	 * If preempted in user-land mark the thread as swappable because it
	 * cannot be holding any kernel locks.
	 */
	ASSERT(t->t_schedflag & TS_DONT_SWAP);
	if (lwp != NULL && lwp->lwp_state == LWP_USER)
		t->t_schedflag &= ~TS_DONT_SWAP;

	/*
	 * Check to see if we're doing "preemption control" here.  If
	 * we are, and if the user has requested that this thread not
	 * be preempted, and if preemptions haven't been put off for
	 * too long, let the preemption happen here but try to make
	 * sure the thread is rescheduled as soon as possible.  We do
	 * this by putting it on the front of the highest priority run
	 * queue in the FSS class.  If the preemption has been put off
	 * for too long, clear the "nopreempt" bit and let the thread
	 * be preempted.
	 */
	if (t->t_schedctl && schedctl_get_nopreempt(t)) {
		if (fssproc->fss_timeleft > -SC_MAX_TICKS) {
			DTRACE_SCHED1(schedctl__nopreempt, kthread_t *, t);
			if (!(fssproc->fss_flags & FSSKPRI)) {
				/*
				 * If not already remembered, remember current
				 * priority for restoration in fss_yield().
				 */
				if (!(fssproc->fss_flags & FSSRESTORE)) {
					fssproc->fss_scpri = t->t_pri;
					fssproc->fss_flags |= FSSRESTORE;
				}
				THREAD_CHANGE_PRI(t, fss_maxumdpri);
				t->t_schedflag |= TS_DONT_SWAP;
			}
			schedctl_set_yield(t, 1);
			setfrontdq(t);
			return;
		} else {
			if (fssproc->fss_flags & FSSRESTORE) {
				THREAD_CHANGE_PRI(t, fssproc->fss_scpri);
				fssproc->fss_flags &= ~FSSRESTORE;
			}
			schedctl_set_nopreempt(t, 0);
			DTRACE_SCHED1(schedctl__preempt, kthread_t *, t);
			/*
			 * Fall through and be preempted below.
			 */
		}
	}

	flags = fssproc->fss_flags & (FSSBACKQ | FSSKPRI);

	if (flags == FSSBACKQ) {
		fssproc->fss_timeleft = fss_quantum;
		fssproc->fss_flags &= ~FSSBACKQ;
		setbackdq(t);
	} else if (flags == (FSSBACKQ | FSSKPRI)) {
		fssproc->fss_flags &= ~FSSBACKQ;
		setbackdq(t);
	} else {
		setfrontdq(t);
	}
}

/*
 * Called when a thread is waking up and is to be placed on the run queue.
 */
static void
fss_setrun(kthread_t *t)
{
	fssproc_t *fssproc = FSSPROC(t);

	ASSERT(THREAD_LOCK_HELD(t));	/* t should be in transition */

	if (t->t_state == TS_SLEEP || t->t_state == TS_STOPPED)
		fss_active(t);

	fssproc->fss_timeleft = fss_quantum;

	fssproc->fss_flags &= ~FSSBACKQ;
	/*
	 * If previously were running at the kernel priority then keep that
	 * priority and the fss_timeleft doesn't matter.
	 */
	if ((fssproc->fss_flags & FSSKPRI) == 0)
		THREAD_CHANGE_PRI(t, fssproc->fss_umdpri);

	if (t->t_disp_time != ddi_get_lbolt())
		setbackdq(t);
	else
		setfrontdq(t);
}

/*
 * Prepare thread for sleep. We reset the thread priority so it will run at the
 * kernel priority level when it wakes up.
 */
static void
fss_sleep(kthread_t *t)
{
	fssproc_t *fssproc = FSSPROC(t);

	ASSERT(t == curthread);
	ASSERT(THREAD_LOCK_HELD(t));

	ASSERT(t->t_state == TS_ONPROC);

	/*
	 * Account for time spent on CPU before going to sleep.
	 */
	(void) CPUCAPS_CHARGE(t, &fssproc->fss_caps, CPUCAPS_CHARGE_ENFORCE);

	fss_inactive(t);

	/*
	 * Assign a system priority to the thread and arrange for it to be
	 * retained when the thread is next placed on the run queue (i.e.,
	 * when it wakes up) instead of being given a new pri.  Also arrange
	 * for trapret processing as the thread leaves the system call so it
	 * will drop back to normal priority range.
	 */
	if (t->t_kpri_req) {
		THREAD_CHANGE_PRI(t, minclsyspri);
		fssproc->fss_flags |= FSSKPRI;
		t->t_trapret = 1;	/* so that fss_trapret will run */
		aston(t);
	} else if (fssproc->fss_flags & FSSKPRI) {
		/*
		 * The thread has done a THREAD_KPRI_REQUEST(), slept, then
		 * done THREAD_KPRI_RELEASE() (so no t_kpri_req is 0 again),
		 * then slept again all without finishing the current system
		 * call so trapret won't have cleared FSSKPRI
		 */
		fssproc->fss_flags &= ~FSSKPRI;
		THREAD_CHANGE_PRI(t, fssproc->fss_umdpri);
		if (DISP_MUST_SURRENDER(curthread))
			cpu_surrender(t);
	}
	t->t_stime = ddi_get_lbolt();	/* time stamp for the swapper */
}

/*
 * A tick interrupt has ocurrend on a running thread. Check to see if our
 * time slice has expired.  We must also clear the TS_DONT_SWAP flag in
 * t_schedflag if the thread is eligible to be swapped out.
 */
static void
fss_tick(kthread_t *t)
{
	fssproc_t *fssproc;
	fssproj_t *fssproj;
	klwp_t *lwp;
	boolean_t call_cpu_surrender = B_FALSE;
	boolean_t cpucaps_enforce = B_FALSE;

	ASSERT(MUTEX_HELD(&(ttoproc(t))->p_lock));

	/*
	 * It's safe to access fsspset and fssproj structures because we're
	 * holding our p_lock here.
	 */
	thread_lock(t);
	fssproc = FSSPROC(t);
	fssproj = FSSPROC2FSSPROJ(fssproc);
	if (fssproj != NULL) {
		fsspset_t *fsspset = FSSPROJ2FSSPSET(fssproj);
		disp_lock_enter_high(&fsspset->fssps_displock);
		fssproj->fssp_ticks += fss_nice_tick[fssproc->fss_nice];
		fssproc->fss_ticks++;
		disp_lock_exit_high(&fsspset->fssps_displock);
	}

	/*
	 * Keep track of thread's project CPU usage.  Note that projects
	 * get charged even when threads are running in the kernel.
	 * Do not surrender CPU if running in the SYS class.
	 */
	if (CPUCAPS_ON()) {
		cpucaps_enforce = cpucaps_charge(t,
		    &fssproc->fss_caps, CPUCAPS_CHARGE_ENFORCE) &&
		    !(fssproc->fss_flags & FSSKPRI);
	}

	/*
	 * A thread's execution time for threads running in the SYS class
	 * is not tracked.
	 */
	if ((fssproc->fss_flags & FSSKPRI) == 0) {
		/*
		 * If thread is not in kernel mode, decrement its fss_timeleft
		 */
		if (--fssproc->fss_timeleft <= 0) {
			pri_t new_pri;

			/*
			 * If we're doing preemption control and trying to
			 * avoid preempting this thread, just note that the
			 * thread should yield soon and let it keep running
			 * (unless it's been a while).
			 */
			if (t->t_schedctl && schedctl_get_nopreempt(t)) {
				if (fssproc->fss_timeleft > -SC_MAX_TICKS) {
					DTRACE_SCHED1(schedctl__nopreempt,
					    kthread_t *, t);
					schedctl_set_yield(t, 1);
					thread_unlock_nopreempt(t);
					return;
				}
			}
			fssproc->fss_flags &= ~FSSRESTORE;

			fss_newpri(fssproc);
			new_pri = fssproc->fss_umdpri;
			ASSERT(new_pri >= 0 && new_pri <= fss_maxglobpri);

			/*
			 * When the priority of a thread is changed, it may
			 * be necessary to adjust its position on a sleep queue
			 * or dispatch queue. The function thread_change_pri
			 * accomplishes this.
			 */
			if (thread_change_pri(t, new_pri, 0)) {
				if ((t->t_schedflag & TS_LOAD) &&
				    (lwp = t->t_lwp) &&
				    lwp->lwp_state == LWP_USER)
					t->t_schedflag &= ~TS_DONT_SWAP;
				fssproc->fss_timeleft = fss_quantum;
			} else {
				call_cpu_surrender = B_TRUE;
			}
		} else if (t->t_state == TS_ONPROC &&
		    t->t_pri < t->t_disp_queue->disp_maxrunpri) {
			/*
			 * If there is a higher-priority thread which is
			 * waiting for a processor, then thread surrenders
			 * the processor.
			 */
			call_cpu_surrender = B_TRUE;
		}
	}

	if (cpucaps_enforce && 2 * fssproc->fss_timeleft > fss_quantum) {
		/*
		 * The thread used more than half of its quantum, so assume that
		 * it used the whole quantum.
		 *
		 * Update thread's priority just before putting it on the wait
		 * queue so that it gets charged for the CPU time from its
		 * quantum even before that quantum expires.
		 */
		fss_newpri(fssproc);
		if (t->t_pri != fssproc->fss_umdpri)
			fss_change_priority(t, fssproc);

		/*
		 * We need to call cpu_surrender for this thread due to cpucaps
		 * enforcement, but fss_change_priority may have already done
		 * so. In this case FSSBACKQ is set and there is no need to call
		 * cpu-surrender again.
		 */
		if (!(fssproc->fss_flags & FSSBACKQ))
			call_cpu_surrender = B_TRUE;
	}

	if (call_cpu_surrender) {
		fssproc->fss_flags |= FSSBACKQ;
		cpu_surrender(t);
	}

	thread_unlock_nopreempt(t);	/* clock thread can't be preempted */
}

/*
 * Processes waking up go to the back of their queue.  We don't need to assign
 * a time quantum here because thread is still at a kernel mode priority and
 * the time slicing is not done for threads running in the kernel after
 * sleeping.  The proper time quantum will be assigned by fss_trapret before the
 * thread returns to user mode.
 */
static void
fss_wakeup(kthread_t *t)
{
	fssproc_t *fssproc;

	ASSERT(THREAD_LOCK_HELD(t));
	ASSERT(t->t_state == TS_SLEEP);

	fss_active(t);

	t->t_stime = ddi_get_lbolt();		/* time stamp for the swapper */
	fssproc = FSSPROC(t);
	fssproc->fss_flags &= ~FSSBACKQ;

	if (fssproc->fss_flags & FSSKPRI) {
		/*
		 * If we already have a kernel priority assigned, then we
		 * just use it.
		 */
		setbackdq(t);
	} else if (t->t_kpri_req) {
		/*
		 * Give thread a priority boost if we were asked.
		 */
		fssproc->fss_flags |= FSSKPRI;
		THREAD_CHANGE_PRI(t, minclsyspri);
		setbackdq(t);
		t->t_trapret = 1;	/* so that fss_trapret will run */
		aston(t);
	} else {
		/*
		 * Otherwise, we recalculate the priority.
		 */
		if (t->t_disp_time == ddi_get_lbolt()) {
			setfrontdq(t);
		} else {
			fssproc->fss_timeleft = fss_quantum;
			THREAD_CHANGE_PRI(t, fssproc->fss_umdpri);
			setbackdq(t);
		}
	}
}

/*
 * fss_donice() is called when a nice(1) command is issued on the thread to
 * alter the priority. The nice(1) command exists in Solaris for compatibility.
 * Thread priority adjustments should be done via priocntl(1).
 */
static int
fss_donice(kthread_t *t, cred_t *cr, int incr, int *retvalp)
{
	int newnice;
	fssproc_t *fssproc = FSSPROC(t);
	fssparms_t fssparms;

	/*
	 * If there is no change to priority, just return current setting.
	 */
	if (incr == 0) {
		if (retvalp)
			*retvalp = fssproc->fss_nice - NZERO;
		return (0);
	}

	if ((incr < 0 || incr > 2 * NZERO) && secpolicy_raisepriority(cr) != 0)
		return (EPERM);

	/*
	 * Specifying a nice increment greater than the upper limit of
	 * FSS_NICE_MAX (== 2 * NZERO - 1) will result in the thread's nice
	 * value being set to the upper limit.  We check for this before
	 * computing the new value because otherwise we could get overflow
	 * if a privileged user specified some ridiculous increment.
	 */
	if (incr > FSS_NICE_MAX)
		incr = FSS_NICE_MAX;

	newnice = fssproc->fss_nice + incr;
	if (newnice > FSS_NICE_MAX)
		newnice = FSS_NICE_MAX;
	else if (newnice < FSS_NICE_MIN)
		newnice = FSS_NICE_MIN;

	fssparms.fss_uprilim = fssparms.fss_upri =
	    -((newnice - NZERO) * fss_maxupri) / NZERO;

	/*
	 * Reset the uprilim and upri values of the thread.
	 */
	(void) fss_parmsset(t, (void *)&fssparms, (id_t)0, (cred_t *)NULL);

	/*
	 * Although fss_parmsset already reset fss_nice it may not have been
	 * set to precisely the value calculated above because fss_parmsset
	 * determines the nice value from the user priority and we may have
	 * truncated during the integer conversion from nice value to user
	 * priority and back. We reset fss_nice to the value we calculated
	 * above.
	 */
	fssproc->fss_nice = (char)newnice;

	if (retvalp)
		*retvalp = newnice - NZERO;
	return (0);
}

/*
 * Increment the priority of the specified thread by incr and
 * return the new value in *retvalp.
 */
static int
fss_doprio(kthread_t *t, cred_t *cr, int incr, int *retvalp)
{
	int newpri;
	fssproc_t *fssproc = FSSPROC(t);
	fssparms_t fssparms;

	/*
	 * If there is no change to priority, just return current setting.
	 */
	if (incr == 0) {
		*retvalp = fssproc->fss_upri;
		return (0);
	}

	newpri = fssproc->fss_upri + incr;
	if (newpri > fss_maxupri || newpri < -fss_maxupri)
		return (EINVAL);

	*retvalp = newpri;
	fssparms.fss_uprilim = fssparms.fss_upri = newpri;

	/*
	 * Reset the uprilim and upri values of the thread.
	 */
	return (fss_parmsset(t, &fssparms, (id_t)0, cr));
}

/*
 * Return the global scheduling priority that would be assigned to a thread
 * entering the fair-sharing class with the fss_upri.
 */
/*ARGSUSED*/
static pri_t
fss_globpri(kthread_t *t)
{
	ASSERT(MUTEX_HELD(&ttoproc(t)->p_lock));

	return (fss_maxumdpri / 2);
}

/*
 * Called from the yield(2) system call when a thread is yielding (surrendering)
 * the processor. The kernel thread is placed at the back of a dispatch queue.
 */
static void
fss_yield(kthread_t *t)
{
	fssproc_t *fssproc = FSSPROC(t);

	ASSERT(t == curthread);
	ASSERT(THREAD_LOCK_HELD(t));

	/*
	 * Collect CPU usage spent before yielding
	 */
	(void) CPUCAPS_CHARGE(t, &fssproc->fss_caps, CPUCAPS_CHARGE_ENFORCE);

	/*
	 * Clear the preemption control "yield" bit since the user is
	 * doing a yield.
	 */
	if (t->t_schedctl)
		schedctl_set_yield(t, 0);
	/*
	 * If fss_preempt() artifically increased the thread's priority
	 * to avoid preemption, restore the original priority now.
	 */
	if (fssproc->fss_flags & FSSRESTORE) {
		THREAD_CHANGE_PRI(t, fssproc->fss_scpri);
		fssproc->fss_flags &= ~FSSRESTORE;
	}
	if (fssproc->fss_timeleft < 0) {
		/*
		 * Time slice was artificially extended to avoid preemption,
		 * so pretend we're preempting it now.
		 */
		DTRACE_SCHED1(schedctl__yield, int, -fssproc->fss_timeleft);
		fssproc->fss_timeleft = fss_quantum;
	}
	fssproc->fss_flags &= ~FSSBACKQ;
	setbackdq(t);
}

void
fss_changeproj(kthread_t *t, void *kp, void *zp, fssbuf_t *projbuf,
    fssbuf_t *zonebuf)
{
	kproject_t *kpj_new = kp;
	zone_t *zone = zp;
	fssproj_t *fssproj_old, *fssproj_new;
	fsspset_t *fsspset;
	kproject_t *kpj_old;
	fssproc_t *fssproc;
	fsszone_t *fsszone_old, *fsszone_new;
	int free = 0;
	int id;

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(MUTEX_HELD(&pidlock));
	ASSERT(MUTEX_HELD(&ttoproc(t)->p_lock));

	if (t->t_cid != fss_cid)
		return;

	fssproc = FSSPROC(t);
	mutex_enter(&fsspsets_lock);
	fssproj_old = FSSPROC2FSSPROJ(fssproc);
	if (fssproj_old == NULL) {
		mutex_exit(&fsspsets_lock);
		return;
	}

	fsspset = FSSPROJ2FSSPSET(fssproj_old);
	mutex_enter(&fsspset->fssps_lock);
	kpj_old = FSSPROJ2KPROJ(fssproj_old);
	fsszone_old = fssproj_old->fssp_fsszone;

	ASSERT(t->t_cpupart == fsspset->fssps_cpupart);

	if (kpj_old == kpj_new) {
		mutex_exit(&fsspset->fssps_lock);
		mutex_exit(&fsspsets_lock);
		return;
	}

	if ((fsszone_new = fss_find_fsszone(fsspset, zone)) == NULL) {
		/*
		 * If the zone for the new project is not currently active on
		 * the cpu partition we're on, get one of the pre-allocated
		 * buffers and link it in our per-pset zone list.  Such buffers
		 * should already exist.
		 */
		for (id = 0; id < zonebuf->fssb_size; id++) {
			if ((fsszone_new = zonebuf->fssb_list[id]) != NULL) {
				fss_insert_fsszone(fsspset, zone, fsszone_new);
				zonebuf->fssb_list[id] = NULL;
				break;
			}
		}
	}
	ASSERT(fsszone_new != NULL);
	if ((fssproj_new = fss_find_fssproj(fsspset, kpj_new)) == NULL) {
		/*
		 * If our new project is not currently running
		 * on the cpu partition we're on, get one of the
		 * pre-allocated buffers and link it in our new cpu
		 * partition doubly linked list. Such buffers should already
		 * exist.
		 */
		for (id = 0; id < projbuf->fssb_size; id++) {
			if ((fssproj_new = projbuf->fssb_list[id]) != NULL) {
				fss_insert_fssproj(fsspset, kpj_new,
				    fsszone_new, fssproj_new);
				projbuf->fssb_list[id] = NULL;
				break;
			}
		}
	}
	ASSERT(fssproj_new != NULL);

	thread_lock(t);
	if (t->t_state == TS_RUN || t->t_state == TS_ONPROC ||
	    t->t_state == TS_WAIT)
		fss_inactive(t);
	ASSERT(fssproj_old->fssp_threads > 0);
	if (--fssproj_old->fssp_threads == 0) {
		fss_remove_fssproj(fsspset, fssproj_old);
		free = 1;
	}
	fssproc->fss_proj = fssproj_new;
	fssproc->fss_fsspri = 0;
	fssproj_new->fssp_threads++;
	if (t->t_state == TS_RUN || t->t_state == TS_ONPROC ||
	    t->t_state == TS_WAIT)
		fss_active(t);
	thread_unlock(t);
	if (free) {
		if (fsszone_old->fssz_nproj == 0)
			kmem_free(fsszone_old, sizeof (fsszone_t));
		kmem_free(fssproj_old, sizeof (fssproj_t));
	}

	mutex_exit(&fsspset->fssps_lock);
	mutex_exit(&fsspsets_lock);
}

void
fss_changepset(kthread_t *t, void *newcp, fssbuf_t *projbuf,
    fssbuf_t *zonebuf)
{
	fsspset_t *fsspset_old, *fsspset_new;
	fssproj_t *fssproj_old, *fssproj_new;
	fsszone_t *fsszone_old, *fsszone_new;
	fssproc_t *fssproc;
	kproject_t *kpj;
	zone_t *zone;
	int id;

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(MUTEX_HELD(&pidlock));
	ASSERT(MUTEX_HELD(&ttoproc(t)->p_lock));

	if (t->t_cid != fss_cid)
		return;

	fssproc = FSSPROC(t);
	zone = ttoproc(t)->p_zone;
	mutex_enter(&fsspsets_lock);
	fssproj_old = FSSPROC2FSSPROJ(fssproc);
	if (fssproj_old == NULL) {
		mutex_exit(&fsspsets_lock);
		return;
	}
	fsszone_old = fssproj_old->fssp_fsszone;
	fsspset_old = FSSPROJ2FSSPSET(fssproj_old);
	kpj = FSSPROJ2KPROJ(fssproj_old);

	if (fsspset_old->fssps_cpupart == newcp) {
		mutex_exit(&fsspsets_lock);
		return;
	}

	ASSERT(ttoproj(t) == kpj);

	fsspset_new = fss_find_fsspset(newcp);

	mutex_enter(&fsspset_new->fssps_lock);
	if ((fsszone_new = fss_find_fsszone(fsspset_new, zone)) == NULL) {
		for (id = 0; id < zonebuf->fssb_size; id++) {
			if ((fsszone_new = zonebuf->fssb_list[id]) != NULL) {
				fss_insert_fsszone(fsspset_new, zone,
				    fsszone_new);
				zonebuf->fssb_list[id] = NULL;
				break;
			}
		}
	}
	ASSERT(fsszone_new != NULL);
	if ((fssproj_new = fss_find_fssproj(fsspset_new, kpj)) == NULL) {
		for (id = 0; id < projbuf->fssb_size; id++) {
			if ((fssproj_new = projbuf->fssb_list[id]) != NULL) {
				fss_insert_fssproj(fsspset_new, kpj,
				    fsszone_new, fssproj_new);
				projbuf->fssb_list[id] = NULL;
				break;
			}
		}
	}
	ASSERT(fssproj_new != NULL);

	fssproj_new->fssp_threads++;
	thread_lock(t);
	if (t->t_state == TS_RUN || t->t_state == TS_ONPROC ||
	    t->t_state == TS_WAIT)
		fss_inactive(t);
	fssproc->fss_proj = fssproj_new;
	fssproc->fss_fsspri = 0;
	if (t->t_state == TS_RUN || t->t_state == TS_ONPROC ||
	    t->t_state == TS_WAIT)
		fss_active(t);
	thread_unlock(t);
	mutex_exit(&fsspset_new->fssps_lock);

	mutex_enter(&fsspset_old->fssps_lock);
	if (--fssproj_old->fssp_threads == 0) {
		fss_remove_fssproj(fsspset_old, fssproj_old);
		if (fsszone_old->fssz_nproj == 0)
			kmem_free(fsszone_old, sizeof (fsszone_t));
		kmem_free(fssproj_old, sizeof (fssproj_t));
	}
	mutex_exit(&fsspset_old->fssps_lock);

	mutex_exit(&fsspsets_lock);
}
