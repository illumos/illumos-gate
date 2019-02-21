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
 * This file contains global data and code shared between master and slave parts
 * of the pseudo-terminal driver.
 *
 * Pseudo terminals (or pt's for short) are allocated dynamically.
 * pt's are put in the global ptms_slots array indexed by minor numbers.
 *
 * The slots array is initially small (of the size NPTY_MIN). When more pt's are
 * needed than the slot array size, the larger slot array is allocated and all
 * opened pt's move to the new one.
 *
 * Resource allocation:
 *
 *	pt_ttys structures are allocated via pt_ttys_alloc, which uses
 *		kmem_cache_alloc().
 *	Minor number space is allocated via vmem_alloc() interface.
 *	ptms_slots arrays are allocated via kmem_alloc().
 *
 *   Minors are started from 1 instead of 0 because vmem_alloc returns 0 in case
 *   of failure. Also, in anticipation of removing clone device interface to
 *   pseudo-terminal subsystem, minor 0 should not be used. (Potential future
 *   development).
 *
 *   After the table slot size reaches pt_maxdelta, we stop 2^N extension
 *   algorithm and start extending the slot table size by pt_maxdelta.
 *
 *   Device entries /dev/pts directory are created dynamically by the
 *   /dev filesystem. We no longer call ddi_create_minor_node() on
 *   behalf of the slave driver. The /dev filesystem creates /dev/pts
 *   nodes based on the pt_ttys array.
 *
 * Synchronization:
 *
 *   All global data synchronization between ptm/pts is done via global
 *   ptms_lock mutex which is implicitly initialized by declaring it global.
 *
 *   Individual fields of pt_ttys structure (except ptm_rdq, pts_rdq and
 *   pt_nullmsg) are protected by pt_ttys.pt_lock mutex.
 *
 *   PT_ENTER_READ/PT_ENTER_WRITE are reference counter based read-write locks
 *   which allow reader locks to be reacquired by the same thread (usual
 *   reader/writer locks can't be used for that purpose since it is illegal for
 *   a thread to acquire a lock it already holds, even as a reader). The sole
 *   purpose of these macros is to guarantee that the peer queue will not
 *   disappear (due to closing peer) while it is used. It is safe to use
 *   PT_ENTER_READ/PT_EXIT_READ brackets across calls like putq/putnext (since
 *   they are not real locks but reference counts).
 *
 *   PT_ENTER_WRITE/PT_EXIT_WRITE brackets are used ONLY in master/slave
 *   open/close paths to modify ptm_rdq and pts_rdq fields. These fields should
 *   be set to appropriate queues *after* qprocson() is called during open (to
 *   prevent peer from accessing the queue with incomplete plumbing) and set to
 *   NULL before qprocsoff() is called during close. Put and service procedures
 *   use PT_ENTER_READ/PT_EXIT_READ to prevent peer closes.
 *
 *   The pt_nullmsg field is only used in open/close routines and is also
 *   protected by PT_ENTER_WRITE/PT_EXIT_WRITE brackets to avoid extra mutex
 *   holds.
 *
 * Lock Ordering:
 *
 *   If both ptms_lock and per-pty lock should be held, ptms_lock should always
 *   be entered first, followed by per-pty lock.
 *
 * Global functions:
 *
 * void ptms_init(void);
 *
 *	Called by pts/ptm _init entry points. It performes one-time
 * 	initialization needed for both pts and ptm. This initialization is done
 * 	here and not in ptms_initspace because all these data structures are not
 *	needed if pseudo-terminals are not used in the system.
 *
 * struct pt_ttys *pt_ttys_alloc(void);
 *
 *	Allocate new minor number and pseudo-terminal entry. May sleep.
 *	New minor number is recorded in pt_minor field of the entry returned.
 *	This routine also initializes pt_minor and pt_state fields of the new
 *	pseudo-terminal and puts a pointer to it into ptms_slots array.
 *
 * struct pt_ttys *ptms_minor2ptty(minor_t minor)
 *
 *	Find pt_ttys structure by minor number.
 *	Returns NULL when minor is out of range.
 *
 * int ptms_minor_valid(minor_t minor, uid_t *ruid, gid_t *rgid)
 *
 *	Check if minor refers to an allocated pty in the current zone.
 *	Returns
 *		 0 if not allocated or not for this zone.
 *		 1 if an allocated pty in the current zone.
 *	Also returns owner of pty.
 *
 * int ptms_minor_exists(minor_t minor)
 *	Check if minor refers to an allocated pty (in any zone)
 *	Returns
 *		0 if not an allocated pty
 *		1 if an allocated pty
 *
 * void ptms_set_owner(minor_t minor, uid_t ruid, gid_t rgid)
 *
 *	Sets the owner associated with a pty.
 *
 * void ptms_close(struct pt_ttys *pt, uint_t flags_to_clear);
 *
 *	Clear flags_to_clear in pt and if no one owns it (PTMOPEN/PTSOPEN not
 * 	set) free pt entry and corresponding slot.
 *
 * Tuneables and configuration:
 *
 *	pt_cnt: minimum number of pseudo-terminals in the system. The system
 *		should provide at least this number of ptys (provided sufficient
 * 		memory is available). It is different from the older semantics
 *		of pt_cnt meaning maximum number of ptys.
 *		Set to 0 by default.
 *
 *	pt_max_pty: Maximum number of pseudo-terminals in the system. The system
 *		should not allocate more ptys than pt_max_pty (although, it may
 * 		impose stricter maximum). Zero value means no user-defined
 * 		maximum. This is intended to be used as "denial-of-service"
 *		protection.
 *		Set to 0 by default.
 *
 *         Both pt_cnt and pt_max_pty may be modified during system lifetime
 *         with their semantics preserved.
 *
 *	pt_init_cnt: Initial size of ptms_slots array. Set to NPTY_INITIAL.
 *
 *	pt_ptyofmem: Approximate percentage of system memory that may be
 *		occupied by pty data structures. Initially set to NPTY_PERCENT.
 *		This variable is used once during initialization to estimate
 * 		maximum number of ptys in the system. The actual maximum is
 *		determined as minimum of pt_max_pty and calculated value.
 *
 *	pt_maxdelta: Maximum extension chunk of the slot table.
 */



#include <sys/types.h>
#include <sys/param.h>
#include <sys/termios.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/kmem.h>
#include <sys/ptms.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/ddi.h>
#include <sys/bitmap.h>
#include <sys/sysmacros.h>
#include <sys/ddi_impldefs.h>
#include <sys/zone.h>
#ifdef DEBUG
#include <sys/strlog.h>
#endif


/* Initial number of ptms slots */
#define	NPTY_INITIAL 16

#define	NPTY_PERCENT 5

/* Maximum increment of the slot table size */
#define	PTY_MAXDELTA 128

/*
 * Tuneable variables.
 */
uint_t	pt_cnt = 0;			/* Minimum number of ptys */
size_t 	pt_max_pty = 0;			/* Maximum number of ptys */
uint_t	pt_init_cnt = NPTY_INITIAL;	/* Initial number of ptms slots */
uint_t	pt_pctofmem = NPTY_PERCENT;	/* Percent of memory to use for ptys */
uint_t	pt_maxdelta = PTY_MAXDELTA;	/* Max increment for slot table size */

/* Other global variables */

kmutex_t ptms_lock;			/* Global data access lock */

/*
 * Slot array and its management variables
 */
static struct pt_ttys **ptms_slots = NULL; /* Slots for actual pt structures */
static size_t ptms_nslots = 0;		/* Size of slot array */
static size_t ptms_ptymax = 0;		/* Maximum number of ptys */
static size_t ptms_inuse = 0;		/* # of ptys currently allocated */

dev_info_t 	*pts_dip = NULL;	/* set if slave is attached */

static struct kmem_cache *ptms_cache = NULL;	/* pty cache */

static vmem_t *ptms_minor_arena = NULL; /* Arena for device minors */

static uint_t ptms_roundup(uint_t);
static int ptms_constructor(void *, void *, int);
static void ptms_destructor(void *, void *);
static minor_t ptms_grow(void);

/*
 * Total size occupied by one pty. Each pty master/slave pair consumes one
 * pointer for ptms_slots array, one pt_ttys structure and one empty message
 * preallocated for pts close.
 */

#define	PTY_SIZE (sizeof (struct pt_ttys) + \
    sizeof (struct pt_ttys *) + \
    sizeof (dblk_t))

#ifdef DEBUG
int ptms_debug = 0;
#define	PTMOD_ID 5
#endif

/*
 * Clear all bits of x except the highest bit
 */
#define	truncate(x) 	((x) <= 2 ? (x) : (1 << (highbit(x) - 1)))

/*
 * Roundup the number to the nearest power of 2
 */
static uint_t
ptms_roundup(uint_t x)
{
	uint_t p = truncate(x);	/* x with non-high bits stripped */

	/*
	 * If x is a power of 2, return x, otherwise roundup.
	 */
	return (p == x ? p : (p * 2));
}

/*
 * Allocate ptms_slots array and kmem cache for pt_ttys. This initialization is
 * only called once during system lifetime. Called from ptm or pts _init
 * routine.
 */
void
ptms_init(void)
{
	mutex_enter(&ptms_lock);

	if (ptms_slots == NULL) {
		ptms_slots = kmem_zalloc(pt_init_cnt *
		    sizeof (struct pt_ttys *), KM_SLEEP);

		ptms_cache = kmem_cache_create("pty_map",
		    sizeof (struct pt_ttys), 0, ptms_constructor,
		    ptms_destructor, NULL, NULL, NULL, 0);

		ptms_nslots = pt_init_cnt;

		/* Allocate integer space for minor numbers */
		ptms_minor_arena = vmem_create("ptms_minor", (void *)1,
		    ptms_nslots, 1, NULL, NULL, NULL, 0,
		    VM_SLEEP | VMC_IDENTIFIER);

		/*
		 * Calculate available number of ptys - how many ptys can we
		 * allocate in pt_pctofmem % of available memory. The value is
		 * rounded up to the nearest power of 2.
		 */
		ptms_ptymax = ptms_roundup((pt_pctofmem * kmem_maxavail()) /
		    (100 * PTY_SIZE));
	}
	mutex_exit(&ptms_lock);
}

/*
 * This routine attaches the pts dip.
 */
int
ptms_attach_slave(void)
{
	if (pts_dip == NULL && i_ddi_attach_pseudo_node("pts") == NULL)
		return (-1);

	ASSERT(pts_dip);
	return (0);
}

/*
 * Called from /dev fs. Checks if dip is attached,
 * and if it is, returns its major number.
 */
major_t
ptms_slave_attached(void)
{
	major_t maj = DDI_MAJOR_T_NONE;

	mutex_enter(&ptms_lock);
	if (pts_dip)
		maj = ddi_driver_major(pts_dip);
	mutex_exit(&ptms_lock);

	return (maj);
}

/*
 * Allocate new minor number and pseudo-terminal entry. Returns the new entry or
 * NULL if no memory or maximum number of entries reached.
 */
struct pt_ttys *
pt_ttys_alloc(void)
{
	minor_t dminor;
	struct pt_ttys *pt = NULL;

	mutex_enter(&ptms_lock);

	/*
	 * Always try to allocate new pty when pt_cnt minimum limit is not
	 * achieved. If it is achieved, the maximum is determined by either
	 * user-specified value (if it is non-zero) or our memory estimations -
	 * whatever is less.
	 */
	if (ptms_inuse >= pt_cnt) {
		/*
		 * When system achieved required minimum of ptys, check for the
		 *   denial of service limits.
		 *
		 * Since pt_max_pty may be zero, the formula below is used to
		 * avoid conditional expression. It will equal to pt_max_pty if
		 * it is not zero and ptms_ptymax otherwise.
		 */
		size_t user_max = (pt_max_pty == 0 ? ptms_ptymax : pt_max_pty);

		/* Do not try to allocate more than allowed */
		if (ptms_inuse >= min(ptms_ptymax, user_max)) {
			mutex_exit(&ptms_lock);
			return (NULL);
		}
	}
	ptms_inuse++;

	/*
	 * Allocate new minor number. If this fails, all slots are busy and
	 * we need to grow the hash.
	 */
	dminor = (minor_t)(uintptr_t)
	    vmem_alloc(ptms_minor_arena, 1, VM_NOSLEEP);

	if (dminor == 0) {
		/* Grow the cache and retry allocation */
		dminor = ptms_grow();
	}

	if (dminor == 0) {
		/* Not enough memory now */
		ptms_inuse--;
		mutex_exit(&ptms_lock);
		return (NULL);
	}

	pt = kmem_cache_alloc(ptms_cache, KM_NOSLEEP);
	if (pt == NULL) {
		/* Not enough memory - this entry can't be used now. */
		vmem_free(ptms_minor_arena, (void *)(uintptr_t)dminor, 1);
		ptms_inuse--;
	} else {
		pt->pt_minor = dminor;
		pt->pt_pid = curproc->p_pid;	/* For debugging */
		pt->pt_state = (PTMOPEN | PTLOCK);
		pt->pt_zoneid = getzoneid();
		pt->pt_ruid = 0; /* we don't know uid/gid yet. Report as root */
		pt->pt_rgid = 0;
		ASSERT(ptms_slots[dminor - 1] == NULL);
		ptms_slots[dminor - 1] = pt;
	}

	mutex_exit(&ptms_lock);
	return (pt);
}

/*
 * Get pt_ttys structure by minor number.
 * Returns NULL when minor is out of range.
 */
struct pt_ttys *
ptms_minor2ptty(minor_t dminor)
{
	struct pt_ttys *pt = NULL;

	ASSERT(mutex_owned(&ptms_lock));
	if ((dminor >= 1) && (dminor <= ptms_nslots) && ptms_slots != NULL)
		pt = ptms_slots[dminor - 1];

	return (pt);
}

/*
 * Invoked in response to chown on /dev/pts nodes to change the
 * permission on a pty
 */
void
ptms_set_owner(minor_t dminor, uid_t ruid, gid_t rgid)
{
	struct pt_ttys *pt;

	ASSERT(ruid >= 0);
	ASSERT(rgid >= 0);

	if (ruid < 0 || rgid < 0)
		return;

	/*
	 * /dev/pts/0 is not used, but some applications may check it. There
	 * is no pty backing it - so we have nothing to do.
	 */
	if (dminor == 0)
		return;

	mutex_enter(&ptms_lock);
	pt = ptms_minor2ptty(dminor);
	if (pt != NULL && pt->pt_zoneid == getzoneid()) {
		pt->pt_ruid = ruid;
		pt->pt_rgid = rgid;
	}
	mutex_exit(&ptms_lock);
}

/*
 * Given a ptm/pts minor number
 * returns:
 *	1 if the pty is allocated to the current zone.
 *	0 otherwise
 *
 * If the pty is allocated to the current zone, it also returns the owner.
 */
int
ptms_minor_valid(minor_t dminor, uid_t *ruid, gid_t *rgid)
{
	struct pt_ttys *pt;
	int ret;

	ASSERT(ruid);
	ASSERT(rgid);

	*ruid = (uid_t)-1;
	*rgid = (gid_t)-1;

	/*
	 * /dev/pts/0 is not used, but some applications may check it, so create
	 * it also. Report the owner as root. It belongs to all zones.
	 */
	if (dminor == 0) {
		*ruid = 0;
		*rgid = 0;
		return (1);
	}

	ret = 0;
	mutex_enter(&ptms_lock);
	pt = ptms_minor2ptty(dminor);
	if (pt != NULL) {
		ASSERT(pt->pt_ruid >= 0);
		ASSERT(pt->pt_rgid >= 0);
		if (pt->pt_zoneid == getzoneid()) {
			ret = 1;
			*ruid = pt->pt_ruid;
			*rgid = pt->pt_rgid;
		}
	}
	mutex_exit(&ptms_lock);

	return (ret);
}

/*
 * Given a ptm/pts minor number
 * returns:
 *	0 if the pty is not allocated
 *	1 if the pty is allocated
 */
int
ptms_minor_exists(minor_t dminor)
{
	int ret;

	mutex_enter(&ptms_lock);
	ret = ptms_minor2ptty(dminor) ? 1 : 0;
	mutex_exit(&ptms_lock);

	return (ret);
}

/*
 * Close the pt and clear flags_to_clear.
 * If pt device is not opened by someone else, free it and clear its slot.
 */
void
ptms_close(struct pt_ttys *pt, uint_t flags_to_clear)
{
	uint_t flags;

	ASSERT(MUTEX_NOT_HELD(&ptms_lock));
	ASSERT(pt != NULL);

	mutex_enter(&ptms_lock);

	mutex_enter(&pt->pt_lock);
	pt->pt_state &= ~flags_to_clear;
	flags = pt->pt_state;
	mutex_exit(&pt->pt_lock);

	if (! (flags & (PTMOPEN | PTSOPEN))) {
		/* No one owns the entry - free it */

		ASSERT(pt->ptm_rdq == NULL);
		ASSERT(pt->pts_rdq == NULL);
		ASSERT(pt->pt_nullmsg == NULL);
		ASSERT(pt->pt_refcnt == 0);
		ASSERT(pt->pt_minor <= ptms_nslots);
		ASSERT(ptms_slots[pt->pt_minor - 1] == pt);
		ASSERT(ptms_inuse > 0);

		ptms_inuse--;

		pt->pt_pid = 0;

		ptms_slots[pt->pt_minor - 1] = NULL;
		/* Return minor number to the pool of minors */
		vmem_free(ptms_minor_arena, (void *)(uintptr_t)pt->pt_minor, 1);
		/* Return pt to the cache */
		kmem_cache_free(ptms_cache, pt);
	}
	mutex_exit(&ptms_lock);
}

/*
 * Allocate another slot table twice as large as the original one (limited to
 * global maximum). Migrate all pt to the new slot table and free the original
 * one. Create more /devices entries for new devices.
 */
static minor_t
ptms_grow()
{
	minor_t old_size = ptms_nslots;
	minor_t delta = MIN(pt_maxdelta, old_size);
	minor_t new_size = old_size + delta;
	struct pt_ttys **ptms_old = ptms_slots;
	struct pt_ttys **ptms_new;
	void  *vaddr;			/* vmem_add return value */

	ASSERT(MUTEX_HELD(&ptms_lock));

	DDBG("ptmopen(%d): need to grow\n", (int)ptms_inuse);

	/* Allocate new ptms array */
	ptms_new = kmem_zalloc(new_size * sizeof (struct pt_ttys *),
	    KM_NOSLEEP);
	if (ptms_new == NULL)
		return ((minor_t)0);

	/* Increase clone index space */
	vaddr = vmem_add(ptms_minor_arena, (void *)(uintptr_t)(old_size + 1),
	    new_size - old_size, VM_NOSLEEP);

	if (vaddr == NULL) {
		kmem_free(ptms_new, new_size * sizeof (struct pt_ttys *));
		return ((minor_t)0);
	}

	/* Migrate pt entries to a new location */
	ptms_nslots = new_size;
	bcopy(ptms_old, ptms_new, old_size * sizeof (struct pt_ttys *));
	ptms_slots = ptms_new;
	kmem_free(ptms_old, old_size * sizeof (struct pt_ttys *));

	/* Allocate minor number and return it */
	return ((minor_t)(uintptr_t)
	    vmem_alloc(ptms_minor_arena, 1, VM_NOSLEEP));
}

/*ARGSUSED*/
static int
ptms_constructor(void *maddr, void *arg, int kmflags)
{
	struct pt_ttys *pt = maddr;

	pt->pts_rdq = NULL;
	pt->ptm_rdq = NULL;
	pt->pt_nullmsg = NULL;
	pt->pt_pid = 0;
	pt->pt_minor = 0;
	pt->pt_refcnt = 0;
	pt->pt_state = 0;
	pt->pt_zoneid = GLOBAL_ZONEID;

	cv_init(&pt->pt_cv, NULL, CV_DEFAULT, NULL);
	mutex_init(&pt->pt_lock, NULL, MUTEX_DEFAULT, NULL);
	return (0);
}

/*ARGSUSED*/
static void
ptms_destructor(void *maddr, void *arg)
{
	struct pt_ttys *pt = maddr;

	ASSERT(pt->pt_refcnt == 0);
	ASSERT(pt->pt_state == 0);
	ASSERT(pt->ptm_rdq == NULL);
	ASSERT(pt->pts_rdq == NULL);

	mutex_destroy(&pt->pt_lock);
	cv_destroy(&pt->pt_cv);
}

#ifdef DEBUG
void
ptms_log(char *str, uint_t arg)
{
	if (ptms_debug) {
		if (ptms_debug & 2)
			cmn_err(CE_CONT, str, arg);
		if (ptms_debug & 4)
			(void) strlog(PTMOD_ID, -1, 0, SL_TRACE | SL_ERROR,
			    str, arg);
		else
			(void) strlog(PTMOD_ID, -1, 0, SL_TRACE, str, arg);
	}
}

void
ptms_logp(char *str, uintptr_t arg)
{
	if (ptms_debug) {
		if (ptms_debug & 2)
			cmn_err(CE_CONT, str, arg);
		if (ptms_debug & 4)
			(void) strlog(PTMOD_ID, -1, 0, SL_TRACE | SL_ERROR,
			    str, arg);
		else
			(void) strlog(PTMOD_ID, -1, 0, SL_TRACE, str, arg);
	}
}
#endif
