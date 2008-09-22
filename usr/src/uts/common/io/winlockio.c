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
 * This is the lock device driver.
 *
 * The lock driver provides a variation of inter-process mutexes with the
 * following twist in semantics:
 *	A waiter for a lock after a set timeout can "break" the lock and
 *	grab it from the current owner (without informing the owner).
 *
 * These semantics result in temporarily multiple processes thinking they
 * own the lock. This usually does not make sense for cases where locks are
 * used to protect a critical region and it is important to serialize access
 * to data structures. As breaking the lock will also lose the serialization
 * and result in corrupt data structures.
 *
 * The usage for winlock driver is primarily driven by the graphics system
 * when doing DGA (direct graphics access) graphics. The locks are used to
 * protect access to the frame buffer (presumably reflects back to the screen)
 * between competing processes that directly write to the screen as opposed
 * to going through the window server etc.
 * In this case, the result of breaking the lock at worst causes the screen
 * image to be distorted and is easily fixed by doing a "refresh"
 *
 * In well-behaved applications, the lock is held for a very short time and
 * the breaking semantics do not come into play. Not having this feature and
 * using normal inter-process mutexes will result in a misbehaved application
 * from grabbing the screen writing capability from the window manager and
 * effectively make the system look like it is hung (mouse pointer does not
 * move).
 *
 * A secondary aspect of the winlock driver is that it allows for extremely
 * fast lock acquire/release in cases where there is low contention. A memory
 * write is all that is needed (not even a function call). And the window
 * manager is the only DGA writer usually and this optimized for. Occasionally
 * some processes might do DGA graphics and cause kernel faults to handle
 * the contention/locking (and that has got to be slow!).
 *
 * The following IOCTLs are supported:
 *
 *   GRABPAGEALLOC:
 *	Compatibility with old cgsix device driver lockpage ioctls.
 *	Lockpages created this way must be an entire page for compatibility with
 *	older software.	 This ioctl allocates a lock context with its own
 *	private lock page.  The unique "ident" that identifies this lock is
 *	returned.
 *
 *   GRABPAGEFREE:
 *	Compatibility with cgsix device driver lockpage ioctls.	 This
 *	ioctl releases the lock context allocated by GRABPAGEALLOC.
 *
 *   GRABLOCKINFO:
 *	Returns a one-word flag.  '1' means that multiple clients may
 *	access this lock page.	Older device drivers returned '0',
 *	meaning that only two clients could access a lock page.
 *
 *   GRABATTACH:
 *	Not supported.	This ioctl would have grabbed all lock pages
 *	on behalf of the calling program.
 *
 *   WINLOCKALLOC:
 *	Allocate a lock context.  This ioctl accepts a key value.  as
 *	its argument.  If the key is zero, a new lock context is
 *	created, and its "ident" is returned.	If the key is nonzero,
 *	all existing contexts are checked to see if they match they
 *	key.  If a match is found, its reference count is incremented
 *	and its ident is returned, otherwise a new context is created
 *	and its ident is returned.
 *
 *   WINLOCKFREE:
 *	Free a lock context.  This ioctl accepts the ident of a lock
 *	context and decrements its reference count.  Once the reference
 *	count reaches zero *and* all mappings are released, the lock
 *	context is freed.  When all the lock context in the lock page are
 *	freed, the lock page is freed as well.
 *
 *   WINLOCKSETTIMEOUT:
 *	Set lock timeout for a context.	 This ioctl accepts the ident
 *	of a lock context and a timeout value in milliseconds.
 *	Whenever lock contention occurs, the timer is started and the lock is
 *	broken after the timeout expires. If timeout value is zero, lock does
 *	not timeout.  This value will be rounded to the nearest clock
 *	tick, so don't try to use it for real-time control or something.
 *
 *   WINLOCKGETTIMEOUT:
 *	Get lock timeout from a context.
 *
 *   WINLOCKDUMP:
 *	Dump state of this device.
 *
 *
 * How /dev/winlock works:
 *
 *   Every lock context consists of two mappings for the client to the lock
 *   page.  These mappings are known as the "lock page" and "unlock page"
 *   to the client. The first mmap to the lock context (identified by the
 *   sy_ident field returns during alloc) allocates mapping to the lock page,
 *   the second mmap allocates a mapping to the unlock page.
 *	The mappings dont have to be ordered in virtual address space, but do
 *   need to be ordered in time. Mapping and unmapping of these lock and unlock
 *   pages should happen in pairs. Doing them one at a time or unmapping one
 *   and leaving one mapped etc cause undefined behaviors.
 *	The mappings are always of length PAGESIZE, and type MAP_SHARED.
 *
 *   The first ioctl is to ALLOC a lock, either based on a key (if trying to
 *	grab a preexisting lock) or 0 (gets a default new one)
 *	This ioctl returns a value in sy_ident which is needed to do the
 *	later mmaps and FREE/other ioctls.
 *
 *   The "page number" portion of the sy_ident needs to be passed as the
 *	file offset when doing an mmap for both the lock page and unlock page
 *
 *   The value returned by mmap ( a user virtual address) needs to be
 *	incremented by the "page offset" portion of sy_ident to obtain the
 *	pointer to the actual lock. (Skipping this step, does not cause any
 *	visible error, but the process will be using the wrong lock!)
 *
 *	On a fork(), the child process will inherit the mappings for free, but
 *   will not inherit the parent's lock ownership if any. The child should NOT
 *   do an explicit FREE on the lock context unless it did an explicit ALLOC.
 *	Only one process at a time is allowed to have a valid hat
 *   mapping to a lock page. This is enforced by this driver.
 *   A client acquires a lock by writing a '1' to the lock page.
 *   Note, that it is not necessary to read and veryify that the lock is '0'
 *	prior to writing a '1' in it.
 *   If it does not already have a valid mapping to that page, the driver
 *   takes a fault (devmap_access), loads the client mapping
 *   and allows the client to continue.	 The client releases the lock by
 *   writing a '0' to the unlock page.	Again, if it does not have a valid
 *   mapping to the unlock page, the segment driver takes a fault,
 *   loads the mapping, and lets the client continue.  From this point
 *   forward, the client can make as many locks and unlocks as it
 *   wants, without any more faults into the kernel.
 *
 *   If a different process wants to acquire a lock, it takes a page fault
 *   when it writes the '1' to the lock page.  If the segment driver sees
 *   that the lock page contained a zero, then it invalidates the owner's
 *   mappings and gives the mappings to this process.
 *
 *   If there is already a '1' in the lock page when the second client
 *   tries to access the lock page, then a lock exists.	 The segment
 *   driver sleeps the second client and, if applicable, starts the
 *   timeout on the lock.  The owner's mapping to the unlock page
 *   is invalidated so that the driver will be woken again when the owner
 *   releases the lock.
 *
 *   When the locking client finally writes a '0' to the unlock page, the
 *   segment driver takes another fault.  The client is given a valid
 *   mapping, not to the unlock page, but to the "trash page", and allowed
 *   to continue.  Meanwhile, the sleeping client is given a valid mapping
 *   to the lock/unlock pages and allowed to continue as well.
 *
 * RFE: There is a leak if process exits before freeing allocated locks
 * But currently not tracking which locks were allocated by which
 * process and we do not have a clean entry point into the driver
 * to do garbage collection. If the interface used a file descriptor for each
 * lock it allocs, then the driver can free up stuff in the _close routine
 */

#include <sys/types.h>		/* various type defn's */
#include <sys/debug.h>
#include <sys/param.h>		/* various kernel limits */
#include <sys/time.h>
#include <sys/errno.h>
#include <sys/kmem.h>		/* defines kmem_alloc() */
#include <sys/conf.h>		/* defines cdevsw */
#include <sys/file.h>		/* various file modes, etc. */
#include <sys/uio.h>		/* UIO stuff */
#include <sys/ioctl.h>
#include <sys/cred.h>		/* defines cred struct */
#include <sys/mman.h>		/* defines mmap(2) parameters */
#include <sys/stat.h>		/* defines S_IFCHR */
#include <sys/cmn_err.h>	/* use cmn_err */
#include <sys/ddi.h>		/* ddi stuff */
#include <sys/sunddi.h>		/* ddi stuff */
#include <sys/ddi_impldefs.h>	/* ddi stuff */
#include <sys/winlockio.h>	/* defines ioctls, flags, data structs */

static int	winlock_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int	winlock_devmap(dev_t, devmap_cookie_t, offset_t, size_t,
			size_t *, uint_t);
static int	winlocksegmap(dev_t, off_t, struct as *, caddr_t *, off_t,
			uint_t, uint_t, uint_t, cred_t *);

static struct cb_ops	winlock_cb_ops = {
	nulldev,		/* open */
	nulldev,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	winlock_ioctl,		/* ioctl */
	winlock_devmap,		/* devmap */
	nodev,			/* mmap */
	winlocksegmap,		/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* prop_op */
	NULL,			/* streamtab */
	D_NEW|D_MP|D_DEVMAP,	/* Driver compatibility flag */
	0,			/* rev */
	nodev,			/* aread */
	nodev			/* awrite */
};

static int winlock_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int winlock_attach(dev_info_t *, ddi_attach_cmd_t);
static int winlock_detach(dev_info_t *, ddi_detach_cmd_t);

static struct dev_ops	winlock_ops = {
	DEVO_REV,
	0,			/* refcount */
	winlock_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	winlock_attach,		/* attach */
	winlock_detach,		/* detach */
	nodev,			/* reset */
	&winlock_cb_ops,	/* driver ops */
	NULL,			/* bus ops */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

static int winlockmap_map(devmap_cookie_t, dev_t, uint_t, offset_t, size_t,
		void **);
static void winlockmap_unmap(devmap_cookie_t, void *, offset_t, size_t,
		devmap_cookie_t, void **, devmap_cookie_t, void **);
static int winlockmap_dup(devmap_cookie_t, void *,
		devmap_cookie_t, void **);
static int winlockmap_access(devmap_cookie_t, void *, offset_t, size_t,
		uint_t, uint_t);

static
struct devmap_callback_ctl winlockmap_ops = {
	DEVMAP_OPS_REV,
	winlockmap_map,
	winlockmap_access,
	winlockmap_dup,
	winlockmap_unmap,
};

#if DEBUG
static	int	lock_debug = 0;
#define	DEBUGF(level, args)	{ if (lock_debug >= (level)) cmn_err args; }
#else
#define	DEBUGF(level, args)
#endif

/* Driver supports two styles of locks */
enum winlock_style { NEWSTYLE_LOCK, OLDSTYLE_LOCK };

/*
 * These structures describe a lock context.  We permit multiple
 * clients (not just two) to access a lock page
 *
 * The "cookie" identifies the lock context. It is the page number portion
 * sy_ident returned on lock allocation. Cookie is used in later ioctls.
 * "cookie" is lockid * PAGESIZE
 * "lockptr" is the kernel virtual address to the lock itself
 * The page offset portion of lockptr is the page offset portion of sy_ident
 */

/*
 * per-process information about locks.  This is the private field of
 * a devmap mapping.  Note that usually *two* mappings point to this.
 */

/*
 * Each process using winlock is associated with a segproc structure
 * In various driver entry points, we need to search to find the right
 * segproc structure (If we were using file handles for each lock this
 * would not have been necessary).
 * It would have been simple to use the process pid (and ddi_get_pid)
 * However, during fork devmap_dup is called in the parent process context
 * and using the pid complicates the code by introducing orphans.
 * Instead we use the as pointer for the process as a cookie
 * which requires delving into various non-DDI kosher structs
 */
typedef struct segproc {
	struct segproc	*next;		/* next client of this lock */
	struct seglock	*lp;		/* associated lock context */
	devmap_cookie_t	lockseg;	/* lock mapping, if any */
	devmap_cookie_t unlockseg;	/* unlock mapping, if any */
	void		*tag;		/* process as pointer as tag */
	uint_t		flag;		/* see "flag bits" in winlockio.h */
} SegProc;

#define	ID(sdp)		((sdp)->tag)
#define	CURPROC_ID	(void *)(curproc->p_as)

/* per lock context information */

typedef struct seglock {
	struct seglock	*next;		/* next lock */
	uint_t		sleepers;	/* nthreads sleeping on this lock */
	uint_t		alloccount;	/* how many times created? */
	uint_t		cookie;		/* mmap() offset (page #) into device */
	uint_t		key;		/* key, if any */
	enum winlock_style	style;	/* style of lock - OLDSTYLE, NEWSTYLE */
	clock_t		timeout;	/* sleep time in ticks */
	ddi_umem_cookie_t umem_cookie;	/* cookie for umem allocated memory */
	int		*lockptr;	/* kernel virtual addr of lock */
	struct segproc	*clients;	/* list of clients of this lock */
	struct segproc	*owner;		/* current owner of lock */
	kmutex_t	mutex;		/* mutex for lock */
	kcondvar_t	locksleep;	/* for sleeping on lock */
} SegLock;

#define	LOCK(lp)	(*((lp)->lockptr))

/*
 * Number of locks that can fit in a page. Driver can support only that many.
 * For oldsytle locks, it is relatively easy to increase the limit as each
 * is in a separate page (MAX_LOCKS mostly serves to prevent runaway allocation
 * For newstyle locks, this is trickier as the code needs to allow for mapping
 * into the second or third page of the cookie for some locks.
 */
#define	MAX_LOCKS	(PAGESIZE/sizeof (int))

#define	LOCKTIME	3	/* Default lock timeout in seconds */


/* Protections setting for winlock user mappings */
#define	WINLOCK_PROT	(PROT_READ|PROT_WRITE|PROT_USER)

/*
 * The trash page is where unwanted writes go
 * when a process is releasing a lock.
 */
static	ddi_umem_cookie_t trashpage_cookie = NULL;

/* For newstyle allocations a common page of locks is used */
static	caddr_t	lockpage = NULL;
static	ddi_umem_cookie_t lockpage_cookie = NULL;

static	dev_info_t	*winlock_dip = NULL;
static	kmutex_t	winlock_mutex;

/*
 * winlock_mutex protects
 *	lock_list
 *	lock_free_list
 *	"next" field in SegLock
 *	next_lock
 *	trashpage_cookie
 *	lockpage & lockpage_cookie
 *
 * SegLock_mutex protects
 *	rest of fields in SegLock
 *	All fields in list of SegProc (lp->clients)
 *
 * Lock ordering is winlock_mutex->SegLock_mutex
 * During devmap/seg operations SegLock_mutex acquired without winlock_mutex
 *
 * During devmap callbacks, the pointer to SegProc is stored as the private
 * data in the devmap handle. This pointer will not go stale (i.e., the
 * SegProc getting deleted) as the SegProc is not deleted until both the
 * lockseg and unlockseg have been unmapped and the pointers stored in
 * the devmap handles have been NULL'ed.
 * But before this pointer is used to access any fields (other than the 'lp')
 * lp->mutex must be held.
 */

/*
 * The allocation code tries to allocate from lock_free_list
 * first, otherwise it uses kmem_zalloc.  When lock list is idle, all
 * locks in lock_free_list are kmem_freed
 */
static	SegLock	*lock_list = NULL;		/* in-use locks */
static	SegLock	*lock_free_list = NULL;		/* free locks */
static	int	next_lock = 0;			/* next lock cookie */

/* Routines to find a lock in lock_list based on offset or key */
static SegLock *seglock_findlock(uint_t);
static SegLock *seglock_findkey(uint_t);

/* Routines to find and allocate SegProc structures */
static SegProc *seglock_find_specific(SegLock *, void *);
static SegProc *seglock_alloc_specific(SegLock *, void *);
#define	seglock_findclient(lp)	seglock_find_specific((lp), CURPROC_ID)
#define	seglock_allocclient(lp)	seglock_alloc_specific((lp), CURPROC_ID)

/* Delete client from lock's client list */
static void seglock_deleteclient(SegLock *, SegProc *);
static void garbage_collect_lock(SegLock *, SegProc *);

/* Create a new lock */
static SegLock *seglock_createlock(enum winlock_style);
/* Destroy lock */
static void seglock_destroylock(SegLock *);
static void lock_destroyall(void);

/* Helper functions in winlockmap_access */
static int give_mapping(SegLock *, SegProc *, uint_t);
static int lock_giveup(SegLock *, int);
static int seglock_lockfault(devmap_cookie_t, SegProc *, SegLock *, uint_t);

/* routines called from ioctl */
static int seglock_graballoc(intptr_t, enum winlock_style, int);
static int seglock_grabinfo(intptr_t, int);
static int seglock_grabfree(intptr_t, int);
static int seglock_gettimeout(intptr_t, int);
static int seglock_settimeout(intptr_t, int);
static void seglock_dump_all(void);

static	int
winlock_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	DEBUGF(1, (CE_CONT, "winlock_attach, devi=%p, cmd=%d\n",
	    (void *)devi, (int)cmd));
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);
	if (ddi_create_minor_node(devi, "winlock", S_IFCHR, 0, DDI_PSEUDO, 0)
	    == DDI_FAILURE) {
		return (DDI_FAILURE);
	}
	winlock_dip = devi;
	ddi_report_dev(devi);
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static	int
winlock_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	DEBUGF(1, (CE_CONT, "winlock_detach, devi=%p, cmd=%d\n",
	    (void *)devi, (int)cmd));
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	mutex_enter(&winlock_mutex);
	if (lock_list != NULL) {
		mutex_exit(&winlock_mutex);
		return (DDI_FAILURE);
	}
	ASSERT(lock_free_list == NULL);

	DEBUGF(1, (CE_CONT, "detach freeing trashpage and lockpage\n"));
	/* destroy any common stuff created */
	if (trashpage_cookie != NULL) {
		ddi_umem_free(trashpage_cookie);
		trashpage_cookie = NULL;
	}
	if (lockpage != NULL) {
		ddi_umem_free(lockpage_cookie);
		lockpage = NULL;
		lockpage_cookie = NULL;
	}
	winlock_dip = NULL;
	mutex_exit(&winlock_mutex);
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static	int
winlock_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	register int error;

	/* initialize result */
	*result = NULL;

	/* only valid instance (i.e., getminor) is 0 */
	if (getminor((dev_t)arg) >= 1)
		return (DDI_FAILURE);

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (winlock_dip == NULL)
			error = DDI_FAILURE;
		else {
			*result = (void *)winlock_dip;
			error = DDI_SUCCESS;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}


/*ARGSUSED*/
int
winlock_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
	cred_t *cred, int *rval)
{
	DEBUGF(1, (CE_CONT, "winlockioctl: cmd=%d, arg=0x%p\n",
	    cmd, (void *)arg));

	switch (cmd) {
	/*
	 * ioctls that used to be handled by framebuffers (defined in fbio.h)
	 * RFE: No code really calls the GRAB* ioctls now. Should EOL.
	 */

	case GRABPAGEALLOC:
		return (seglock_graballoc(arg, OLDSTYLE_LOCK, mode));
	case GRABPAGEFREE:
		return (seglock_grabfree(arg, mode));
	case GRABLOCKINFO:
		return (seglock_grabinfo(arg, mode));
	case GRABATTACH:
		return (EINVAL); /* GRABATTACH is not supported (never was) */

	case WINLOCKALLOC:
		return (seglock_graballoc(arg, NEWSTYLE_LOCK, mode));
	case WINLOCKFREE:
		return (seglock_grabfree(arg, mode));
	case WINLOCKSETTIMEOUT:
		return (seglock_settimeout(arg, mode));
	case WINLOCKGETTIMEOUT:
		return (seglock_gettimeout(arg, mode));
	case WINLOCKDUMP:
		seglock_dump_all();
		return (0);

#ifdef DEBUG
	case (WIOC|255):
		lock_debug = arg;
		return (0);
#endif

	default:
		return (ENOTTY);		/* Why is this not EINVAL */
	}
}

int
winlocksegmap(
	dev_t	dev,		/* major:minor */
	off_t	off,		/* device offset from mmap(2) */
	struct as *as,		/* user's address space. */
	caddr_t	*addr,		/* address from mmap(2) */
	off_t	len,		/* length from mmap(2) */
	uint_t	prot,		/* user wants this access */
	uint_t	maxprot,	/* this is the maximum the user can have */
	uint_t	flags,		/* flags from mmap(2) */
	cred_t	*cred)
{
	DEBUGF(1, (CE_CONT, "winlock_segmap off=%lx, len=0x%lx\n", off, len));

	/* Only MAP_SHARED mappings are supported */
	if ((flags & MAP_TYPE) == MAP_PRIVATE) {
		return (EINVAL);
	}

	/* Use devmap_setup to setup the mapping */
	return (devmap_setup(dev, (offset_t)off, as, addr, (size_t)len, prot,
	    maxprot, flags, cred));
}

/*ARGSUSED*/
int
winlock_devmap(dev_t dev, devmap_cookie_t dhp, offset_t off, size_t len,
    size_t *maplen, uint_t model)
{
	SegLock *lp;
	int err;

	DEBUGF(1, (CE_CONT, "winlock devmap: off=%llx, len=%lx, dhp=%p\n",
	    off, len, (void *)dhp));

	*maplen = 0;

	/* Check if the lock exists, i.e., has been created by alloc */
	/* off is the sy_ident returned in the alloc ioctl */
	if ((lp = seglock_findlock((uint_t)off)) == NULL) {
		return (ENXIO);
	}

	/*
	 * The offset bits in mmap(2) offset has to be same as in lockptr
	 * OR the offset should be 0 (i.e. masked off)
	 */
	if (((off & PAGEOFFSET) != 0) &&
	    ((off ^ (uintptr_t)(lp->lockptr)) & (offset_t)PAGEOFFSET) != 0) {
		DEBUGF(2, (CE_CONT,
		    "mmap offset %llx mismatch with lockptr %p\n",
		    off, (void *)lp->lockptr));
		mutex_exit(&lp->mutex);	/* mutex held by seglock_findlock */
		return (EINVAL);
	}

	/* Only supports PAGESIZE length mappings */
	if (len != PAGESIZE) {
		mutex_exit(&lp->mutex);	/* mutex held by seglock_findlock */
		return (EINVAL);
	}

	/*
	 * Set up devmap to point at page associated with lock
	 * RFE: At this point we dont know if this is a lockpage or unlockpage
	 * a lockpage would not need DEVMAP_ALLOW_REMAP setting
	 * We could have kept track of the mapping order here,
	 * but devmap framework does not support storing any state in this
	 * devmap callback as it does not callback for error cleanup if some
	 * other error happens in the framework.
	 * RFE: We should modify the winlock mmap interface so that the
	 * user process marks in the offset passed in whether this is for a
	 * lock or unlock mapping instead of guessing based on order of maps
	 * This would cleanup other things (such as in fork)
	 */
	if ((err = devmap_umem_setup(dhp, winlock_dip, &winlockmap_ops,
	    lp->umem_cookie, 0, PAGESIZE, WINLOCK_PROT,
	    DEVMAP_ALLOW_REMAP, 0)) < 0) {
		mutex_exit(&lp->mutex);	/* held by seglock_findlock */
		return (err);
	}
	/*
	 * No mappings are loaded to those segments yet. The correctness
	 * of the winlock semantics depends on the devmap framework/seg_dev NOT
	 * loading the translations without calling _access callback.
	 */

	mutex_exit(&lp->mutex);	/* mutex held by seglock_findlock */
	*maplen = PAGESIZE;
	return (0);
}

/*
 * This routine is called by the devmap framework after the devmap entry point
 * above and the mapping is setup in seg_dev.
 * We store the pointer to the per-process context in the devmap private data.
 */
/*ARGSUSED*/
static int
winlockmap_map(devmap_cookie_t dhp, dev_t dev, uint_t flags, offset_t off,
	size_t len, void **pvtp)
{
	SegLock *lp = seglock_findlock((uint_t)off); /* returns w/ mutex held */
	SegProc *sdp;

	ASSERT(len == PAGESIZE);

	/* Find the per-process context for this lock, alloc one if not found */
	sdp = seglock_allocclient(lp);

	/*
	 * RFE: Determining which is a lock vs unlock seg is based on order
	 * of mmaps, we should change that to be derivable from off
	 */
	if (sdp->lockseg == NULL) {
		sdp->lockseg = dhp;
	} else if (sdp->unlockseg == NULL) {
		sdp->unlockseg = dhp;
	} else {
		/* attempting to map lock more than twice */
		mutex_exit(&lp->mutex);	/* mutex held by seglock_findlock */
		return (ENOMEM);
	}

	*pvtp = sdp;
	mutex_exit(&lp->mutex);	/* mutex held by seglock_findlock */
	return (DDI_SUCCESS);
}

/*
 * duplicate a segment, as in fork()
 * On fork, the child inherits the mappings to the lock
 *	lp->alloccount is NOT incremented, so child should not do a free().
 *	Semantics same as if done an alloc(), map(), map().
 *	This way it would work fine if doing an exec() variant later
 *	Child does not inherit any UFLAGS set in parent
 * The lock and unlock pages are started off unmapped, i.e., child does not
 *	own the lock.
 * The code assumes that the child process has a valid pid at this point
 * RFE: This semantics depends on fork not duplicating the hat mappings
 *	(which is the current implementation). To enforce it would need to
 *	call devmap_unload from here - not clear if that is allowed.
 */

static int
winlockmap_dup(devmap_cookie_t dhp, void *oldpvt, devmap_cookie_t new_dhp,
	void **newpvt)
{
	SegProc *sdp = (SegProc *)oldpvt;
	SegProc *ndp;
	SegLock *lp = sdp->lp;

	mutex_enter(&lp->mutex);
	ASSERT((dhp == sdp->lockseg) || (dhp == sdp->unlockseg));

	/*
	 * Note: At this point, the child process does have a pid, but
	 * the arguments passed to as_dup and hence to devmap_dup dont pass it
	 * down. So we cannot use normal seglock_findclient - which finds the
	 * parent sdp itself!
	 * Instead we allocate the child's SegProc by using the child as pointer
	 * RFE: we are using the as stucture which means peeking into the
	 * devmap_cookie. This is not DDI-compliant. Need a compliant way of
	 * getting at either the as or, better, a way to get the child's new pid
	 */
	ndp = seglock_alloc_specific(lp,
	    (void *)((devmap_handle_t *)new_dhp)->dh_seg->s_as);
	ASSERT(ndp != sdp);

	if (sdp->lockseg == dhp) {
		ASSERT(ndp->lockseg == NULL);
		ndp->lockseg = new_dhp;
	} else {
		ASSERT(sdp->unlockseg == dhp);
		ASSERT(ndp->unlockseg == NULL);
		ndp->unlockseg = new_dhp;
		if (sdp->flag & TRASHPAGE) {
			ndp->flag |= TRASHPAGE;
		}
	}
	mutex_exit(&lp->mutex);
	*newpvt = (void *)ndp;
	return (0);
}


/*ARGSUSED*/
static void
winlockmap_unmap(devmap_cookie_t dhp, void *pvtp, offset_t off, size_t len,
	devmap_cookie_t new_dhp1, void **newpvtp1,
	devmap_cookie_t new_dhp2, void **newpvtp2)
{
	SegProc	*sdp = (SegProc *)pvtp;
	SegLock	*lp = sdp->lp;

	/*
	 * We always create PAGESIZE length mappings, so there should never
	 * be a partial unmapping case
	 */
	ASSERT((new_dhp1 == NULL) && (new_dhp2 == NULL));

	mutex_enter(&lp->mutex);
	ASSERT((dhp == sdp->lockseg) || (dhp == sdp->unlockseg));
	/* make sure this process doesn't own the lock */
	if (sdp == lp->owner) {
		/*
		 * Not handling errors - i.e., errors in unloading mapping
		 * As part of unmapping hat/seg structure get torn down anyway
		 */
		(void) lock_giveup(lp, 0);
	}

	ASSERT(sdp != lp->owner);
	if (sdp->lockseg == dhp) {
		sdp->lockseg = NULL;
	} else {
		ASSERT(sdp->unlockseg == dhp);
		sdp->unlockseg = NULL;
		sdp->flag &= ~TRASHPAGE;	/* clear flag if set */
	}

	garbage_collect_lock(lp, sdp);
}

/*ARGSUSED*/
static int
winlockmap_access(devmap_cookie_t dhp, void *pvt, offset_t off, size_t len,
	uint_t type, uint_t rw)
{
	SegProc *sdp = (SegProc *)pvt;
	SegLock *lp = sdp->lp;
	int err;

	/* Driver handles only DEVMAP_ACCESS type of faults */
	if (type != DEVMAP_ACCESS)
		return (-1);

	mutex_enter(&lp->mutex);
	ASSERT((dhp == sdp->lockseg) || (dhp == sdp->unlockseg));

	/* should be using a SegProc that corresponds to current process */
	ASSERT(ID(sdp) == CURPROC_ID);

	/*
	 * If process is faulting but does not have both segments mapped
	 * return error (should cause a segv).
	 * RFE: could give it a permanent trashpage
	 */
	if ((sdp->lockseg == NULL) || (sdp->unlockseg == NULL)) {
		err = -1;
	} else {
		err = seglock_lockfault(dhp, sdp, lp, rw);
	}
	mutex_exit(&lp->mutex);
	return (err);
}

	/* INTERNAL ROUTINES START HERE */



/*
 * search the lock_list list for the specified cookie
 * The cookie is the sy_ident field returns by ALLOC ioctl.
 * This has two parts:
 * the pageoffset bits contain offset into the lock page.
 * the pagenumber bits contain the lock id.
 * The user code is supposed to pass in only the pagenumber portion
 *	(i.e. mask off the pageoffset bits). However the code below
 *	does the mask in case the users are not diligent
 * if found, returns with mutex for SegLock structure held
 */
static SegLock *
seglock_findlock(uint_t cookie)
{
	SegLock	*lp;

	cookie &= (uint_t)PAGEMASK;   /* remove pageoffset bits to get cookie */
	mutex_enter(&winlock_mutex);
	for (lp = lock_list; lp != NULL; lp = lp->next) {
		mutex_enter(&lp->mutex);
		if (cookie == lp->cookie) {
			break;	/* return with lp->mutex held */
		}
		mutex_exit(&lp->mutex);
	}
	mutex_exit(&winlock_mutex);
	return (lp);
}

/*
 * search the lock_list list for the specified non-zero key
 * if found, returns with lock for SegLock structure held
 */
static SegLock *
seglock_findkey(uint_t key)
{
	SegLock	*lp;

	ASSERT(MUTEX_HELD(&winlock_mutex));
	/* The driver allows multiple locks with key 0, dont search */
	if (key == 0)
		return (NULL);
	for (lp = lock_list; lp != NULL; lp = lp->next) {
		mutex_enter(&lp->mutex);
		if (key == lp->key)
			break;
		mutex_exit(&lp->mutex);
	}
	return (lp);
}

/*
 * Create a new lock context.
 * Returns with SegLock mutex held
 */

static SegLock *
seglock_createlock(enum winlock_style style)
{
	SegLock	*lp;

	DEBUGF(3, (CE_CONT, "seglock_createlock: free_list=%p, next_lock %d\n",
	    (void *)lock_free_list, next_lock));

	ASSERT(MUTEX_HELD(&winlock_mutex));
	if (lock_free_list != NULL) {
		lp = lock_free_list;
		lock_free_list = lp->next;
	} else if (next_lock >= MAX_LOCKS) {
		return (NULL);
	} else {
		lp = kmem_zalloc(sizeof (SegLock), KM_SLEEP);
		lp->cookie = (next_lock + 1) * (uint_t)PAGESIZE;
		mutex_init(&lp->mutex, NULL, MUTEX_DEFAULT, NULL);
		cv_init(&lp->locksleep, NULL, CV_DEFAULT, NULL);
		++next_lock;
	}

	mutex_enter(&lp->mutex);
	ASSERT((lp->cookie/PAGESIZE) <= next_lock);

	if (style == OLDSTYLE_LOCK) {
		lp->lockptr = (int *)ddi_umem_alloc(PAGESIZE,
		    DDI_UMEM_SLEEP, &(lp->umem_cookie));
	} else {
		lp->lockptr = ((int *)lockpage) + ((lp->cookie/PAGESIZE) - 1);
		lp->umem_cookie = lockpage_cookie;
	}

	ASSERT(lp->lockptr != NULL);
	lp->style = style;
	lp->sleepers = 0;
	lp->alloccount = 1;
	lp->timeout = LOCKTIME*hz;
	lp->clients = NULL;
	lp->owner = NULL;
	LOCK(lp) = 0;
	lp->next = lock_list;
	lock_list = lp;
	return (lp);
}

/*
 * Routine to destory a lock structure.
 * This routine is called while holding the lp->mutex but not the
 * winlock_mutex.
 */

static void
seglock_destroylock(SegLock *lp)
{
	ASSERT(MUTEX_HELD(&lp->mutex));
	ASSERT(!MUTEX_HELD(&winlock_mutex));

	DEBUGF(3, (CE_CONT, "destroying lock cookie %d key %d\n",
	    lp->cookie, lp->key));

	ASSERT(lp->alloccount == 0);
	ASSERT(lp->clients == NULL);
	ASSERT(lp->owner == NULL);
	ASSERT(lp->sleepers == 0);

	/* clean up/release fields in lp */
	if (lp->style == OLDSTYLE_LOCK) {
		ddi_umem_free(lp->umem_cookie);
	}
	lp->umem_cookie = NULL;
	lp->lockptr = NULL;
	lp->key = 0;

	/*
	 * Reduce cookie by 1, makes it non page-aligned and invalid
	 * This prevents any valid lookup from finding this lock
	 * so when we drop the lock and regrab it it will still
	 * be there and nobody else would have attached to it
	 */
	lp->cookie--;

	/* Drop and reacquire mutexes in right order */
	mutex_exit(&lp->mutex);
	mutex_enter(&winlock_mutex);
	mutex_enter(&lp->mutex);

	/* reincrement the cookie to get the original valid cookie */
	lp->cookie++;
	ASSERT((lp->cookie & PAGEOFFSET) == 0);
	ASSERT(lp->alloccount == 0);
	ASSERT(lp->clients == NULL);
	ASSERT(lp->owner == NULL);
	ASSERT(lp->sleepers == 0);

	/* Remove lp from lock_list */
	if (lock_list == lp) {
		lock_list = lp->next;
	} else {
		SegLock *tmp = lock_list;
		while (tmp->next != lp) {
			tmp = tmp->next;
			ASSERT(tmp != NULL);
		}
		tmp->next = lp->next;
	}

	/* Add to lock_free_list */
	lp->next = lock_free_list;
	lock_free_list = lp;
	mutex_exit(&lp->mutex);

	/* Check if all locks deleted and cleanup */
	if (lock_list == NULL) {
		lock_destroyall();
	}

	mutex_exit(&winlock_mutex);
}

/* Routine to find a SegProc corresponding to the tag */

static SegProc *
seglock_find_specific(SegLock *lp, void *tag)
{
	SegProc *sdp;

	ASSERT(MUTEX_HELD(&lp->mutex));
	ASSERT(tag != NULL);
	for (sdp = lp->clients; sdp != NULL; sdp = sdp->next) {
		if (ID(sdp) == tag)
			break;
	}
	return (sdp);
}

/* Routine to find (and if needed allocate) a SegProc corresponding to tag */

static SegProc *
seglock_alloc_specific(SegLock *lp, void *tag)
{
	SegProc *sdp;

	ASSERT(MUTEX_HELD(&lp->mutex));
	ASSERT(tag != NULL);

	/* Search and return if existing one found */
	sdp = seglock_find_specific(lp, tag);
	if (sdp != NULL)
		return (sdp);

	DEBUGF(3, (CE_CONT, "Allocating segproc structure for tag %p lock %d\n",
	    tag, lp->cookie));

	/* Allocate a new SegProc */
	sdp = kmem_zalloc(sizeof (SegProc), KM_SLEEP);
	sdp->next = lp->clients;
	lp->clients = sdp;
	sdp->lp = lp;
	ID(sdp) = tag;
	return (sdp);
}

/*
 * search a context's client list for the given client and delete
 */

static void
seglock_deleteclient(SegLock *lp, SegProc *sdp)
{
	ASSERT(MUTEX_HELD(&lp->mutex));
	ASSERT(lp->owner != sdp);	/* Not current owner of lock */
	ASSERT(sdp->lockseg == NULL);	/* Mappings torn down */
	ASSERT(sdp->unlockseg == NULL);

	DEBUGF(3, (CE_CONT, "Deleting segproc structure for pid %d lock %d\n",
	    ddi_get_pid(), lp->cookie));
	if (lp->clients == sdp) {
		lp->clients = sdp->next;
	} else {
		SegProc *tmp = lp->clients;
		while (tmp->next != sdp) {
			tmp = tmp->next;
			ASSERT(tmp != NULL);
		}
		tmp->next = sdp->next;
	}
	kmem_free(sdp, sizeof (SegProc));
}

/*
 * Routine to verify if a SegProc and SegLock
 * structures are empty/idle.
 * Destroys the structures if they are ready
 * Can be called with sdp == NULL if want to verify only the lock state
 * caller should hold the lp->mutex
 * and this routine drops the mutex
 */
static void
garbage_collect_lock(SegLock *lp, SegProc *sdp)
{
	ASSERT(MUTEX_HELD(&lp->mutex));
	/* see if both segments unmapped from client structure */
	if ((sdp != NULL) && (sdp->lockseg == NULL) && (sdp->unlockseg == NULL))
		seglock_deleteclient(lp, sdp);

	/* see if this is last client in the entire lock context */
	if ((lp->clients == NULL) && (lp->alloccount == 0)) {
		seglock_destroylock(lp);
	} else {
		mutex_exit(&lp->mutex);
	}
}


/* IOCTLS START HERE */

static int
seglock_grabinfo(intptr_t arg, int mode)
{
	int i = 1;

	/* multiple clients per lock supported - see comments up top */
	if (ddi_copyout((caddr_t)&i, (caddr_t)arg, sizeof (int), mode) != 0)
		return (EFAULT);
	return (0);
}

static int
seglock_graballoc(intptr_t arg, enum winlock_style style, int mode) /* IOCTL */
{
	struct seglock	*lp;
	uint_t		key;
	struct		winlockalloc wla;
	int		err;

	if (style == OLDSTYLE_LOCK) {
		key = 0;
	} else {
		if (ddi_copyin((caddr_t)arg, (caddr_t)&wla, sizeof (wla),
		    mode)) {
			return (EFAULT);
		}
		key = wla.sy_key;
	}

	DEBUGF(3, (CE_CONT,
	    "seglock_graballoc: key=%u, style=%d\n", key, style));

	mutex_enter(&winlock_mutex);
	/* Allocate lockpage on first new style alloc */
	if ((lockpage == NULL) && (style == NEWSTYLE_LOCK)) {
		lockpage = ddi_umem_alloc(PAGESIZE, DDI_UMEM_SLEEP,
		    &lockpage_cookie);
	}

	/* Allocate trashpage on first alloc (any style) */
	if (trashpage_cookie == NULL) {
		(void) ddi_umem_alloc(PAGESIZE, DDI_UMEM_TRASH | DDI_UMEM_SLEEP,
		    &trashpage_cookie);
	}

	if ((lp = seglock_findkey(key)) != NULL) {
		DEBUGF(2, (CE_CONT, "alloc: found lock key %d cookie %d\n",
		    key, lp->cookie));
		++lp->alloccount;
	} else if ((lp = seglock_createlock(style)) != NULL) {
		DEBUGF(2, (CE_CONT, "alloc: created lock key %d cookie %d\n",
		    key, lp->cookie));
		lp->key = key;
	} else {
		DEBUGF(2, (CE_CONT, "alloc: cannot create lock key %d\n", key));
		mutex_exit(&winlock_mutex);
		return (ENOMEM);
	}
	ASSERT((lp != NULL) && MUTEX_HELD(&lp->mutex));

	mutex_exit(&winlock_mutex);

	if (style == OLDSTYLE_LOCK) {
		err = ddi_copyout((caddr_t)&lp->cookie, (caddr_t)arg,
		    sizeof (lp->cookie), mode);
	} else {
		wla.sy_ident = lp->cookie +
		    (uint_t)((uintptr_t)(lp->lockptr) & PAGEOFFSET);
		err = ddi_copyout((caddr_t)&wla, (caddr_t)arg,
		    sizeof (wla), mode);
	}

	if (err) {
		/* On error, should undo allocation */
		lp->alloccount--;

		/* Verify and delete if lock is unused now */
		garbage_collect_lock(lp, NULL);
		return (EFAULT);
	}

	mutex_exit(&lp->mutex);
	return (0);
}

static int
seglock_grabfree(intptr_t arg, int mode)	/* IOCTL */
{
	struct seglock	*lp;
	uint_t	offset;

	if (ddi_copyin((caddr_t)arg, &offset, sizeof (offset), mode)
	    != 0) {
		return (EFAULT);
	}
	DEBUGF(2, (CE_CONT, "seglock_grabfree: offset=%u", offset));

	if ((lp = seglock_findlock(offset)) == NULL) {
		DEBUGF(2, (CE_CONT, "did not find lock\n"));
		return (EINVAL);
	}
	DEBUGF(3, (CE_CONT, " lock key %d, cookie %d, alloccount %d\n",
	    lp->key, lp->cookie, lp->alloccount));

	if (lp->alloccount > 0)
		lp->alloccount--;

	/* Verify and delete if lock is unused now */
	garbage_collect_lock(lp, NULL);
	return (0);
}


/*
 * Sets timeout in lock and UFLAGS in client
 *	the UFLAGS are stored in the client structure and persistent only
 *	till the unmap of the lock pages. If the process sets UFLAGS
 *	does a map of the lock/unlock pages and unmaps them, the client
 *	structure will get deleted and the UFLAGS will be lost. The process
 *	will need to resetup the flags.
 */
static int
seglock_settimeout(intptr_t arg, int mode)	/* IOCTL */
{
	SegLock		*lp;
	SegProc		*sdp;
	struct winlocktimeout		wlt;

	if (ddi_copyin((caddr_t)arg, &wlt, sizeof (wlt), mode) != 0) {
		return (EFAULT);
	}

	if ((lp = seglock_findlock(wlt.sy_ident)) == NULL)
		return (EINVAL);

	lp->timeout = MSEC_TO_TICK_ROUNDUP(wlt.sy_timeout);
	/* if timeout modified, wake up any sleepers */
	if (lp->sleepers > 0) {
		cv_broadcast(&lp->locksleep);
	}

	/*
	 * If the process is trying to set UFLAGS,
	 *	Find the client segproc and allocate one if needed
	 *	Set the flags preserving the kernel flags
	 * If the process is clearing UFLAGS
	 *	Find the client segproc but dont allocate one if does not exist
	 */
	if (wlt.sy_flags & UFLAGS) {
		sdp = seglock_allocclient(lp);
		sdp->flag = sdp->flag & KFLAGS | wlt.sy_flags & UFLAGS;
	} else if ((sdp = seglock_findclient(lp)) != NULL) {
		sdp->flag = sdp->flag & KFLAGS;
		/* If clearing UFLAGS leaves the segment or lock idle, delete */
		garbage_collect_lock(lp, sdp);
		return (0);
	}
	mutex_exit(&lp->mutex);	/* mutex held by seglock_findlock */
	return (0);
}

static int
seglock_gettimeout(intptr_t arg, int mode)
{
	SegLock		*lp;
	SegProc		*sdp;
	struct winlocktimeout		wlt;

	if (ddi_copyin((caddr_t)arg, &wlt, sizeof (wlt), mode) != 0)
		return (EFAULT);

	if ((lp = seglock_findlock(wlt.sy_ident)) == NULL)
		return (EINVAL);

	wlt.sy_timeout = TICK_TO_MSEC(lp->timeout);
	/*
	 * If this process has an active allocated lock return those flags
	 *	Dont allocate a client structure on gettimeout
	 * If not, return 0.
	 */
	if ((sdp = seglock_findclient(lp)) != NULL) {
		wlt.sy_flags = sdp->flag & UFLAGS;
	} else {
		wlt.sy_flags = 0;
	}
	mutex_exit(&lp->mutex);	/* mutex held by seglock_findlock */

	if (ddi_copyout(&wlt, (caddr_t)arg, sizeof (wlt), mode) != 0)
		return (EFAULT);

	return (0);
}

/*
 * Handle lock segment faults here...
 *
 * This is where the magic happens.
 */

/* ARGSUSED */
static	int
seglock_lockfault(devmap_cookie_t dhp, SegProc *sdp, SegLock *lp, uint_t rw)
{
	SegProc *owner = lp->owner;
	int err;

	ASSERT(MUTEX_HELD(&lp->mutex));
	DEBUGF(3, (CE_CONT,
	    "seglock_lockfault: hdl=%p, sdp=%p, lp=%p owner=%p\n",
	    (void *)dhp, (void *)sdp, (void *)lp, (void *)owner));

	/* lockfault is always called with sdp in current process context */
	ASSERT(ID(sdp) == CURPROC_ID);

	/* If Lock has no current owner, give the mapping to new owner */
	if (owner == NULL) {
		DEBUGF(4, (CE_CONT, " lock has no current owner\n"));
		return (give_mapping(lp, sdp, rw));
	}

	if (owner == sdp) {
		/*
		 * Current owner is faulting on owned lock segment OR
		 * Current owner is faulting on unlock page and has no waiters
		 * Then can give the mapping to current owner
		 */
		if ((sdp->lockseg == dhp) || (lp->sleepers == 0)) {
		DEBUGF(4, (CE_CONT, "lock owner faulting\n"));
		return (give_mapping(lp, sdp, rw));
		} else {
		/*
		 * Owner must be writing to unlock page and there are waiters.
		 * other cases have been checked earlier.
		 * Release the lock, owner, and owners mappings
		 * As the owner is trying to write to the unlock page, leave
		 * it with a trashpage mapping and wake up the sleepers
		 */
		ASSERT((dhp == sdp->unlockseg) && (lp->sleepers != 0));
		DEBUGF(4, (CE_CONT, " owner fault on unlock seg w/ sleeper\n"));
		return (lock_giveup(lp, 1));
		}
	}

	ASSERT(owner != sdp);

	/*
	 * If old owner faulting on trash unlock mapping,
	 * load hat mappings to trash page
	 * RFE: non-owners should NOT be faulting on unlock mapping as they
	 * as first supposed to fault on the lock seg. We could give them
	 * a trash page or return error.
	 */
	if ((sdp->unlockseg == dhp) && (sdp->flag & TRASHPAGE)) {
		DEBUGF(4, (CE_CONT, " old owner reloads trash mapping\n"));
		return (devmap_load(sdp->unlockseg, lp->cookie, PAGESIZE,
		    DEVMAP_ACCESS, rw));
	}

	/*
	 * Non-owner faulting. Need to check current LOCK state.
	 *
	 * Before reading lock value in LOCK(lp), we must make sure that
	 * the owner cannot change its value before we change mappings
	 * or else we could end up either with a hung process
	 * or more than one process thinking they have the lock.
	 * We do that by unloading the owner's mappings
	 */
	DEBUGF(4, (CE_CONT, " owner loses mappings to check lock state\n"));
	err = devmap_unload(owner->lockseg, lp->cookie, PAGESIZE);
	err |= devmap_unload(owner->unlockseg, lp->cookie, PAGESIZE);
	if (err != 0)
		return (err);	/* unable to remove owner mapping */

	/*
	 * If lock is not held, then current owner mappings were
	 * unloaded above and we can give the lock to the new owner
	 */
	if (LOCK(lp) == 0) {
		DEBUGF(4, (CE_CONT,
		    "Free lock (%p): Giving mapping to new owner %d\n",
		    (void *)lp, ddi_get_pid()));
		return (give_mapping(lp, sdp, rw));
	}

	DEBUGF(4, (CE_CONT, "  lock held, sleeping\n"));

	/*
	 * A non-owning process tried to write (presumably to the lockpage,
	 * but it doesn't matter) but the lock is held; we need to sleep for
	 * the lock while there is an owner.
	 */

	lp->sleepers++;
	while ((owner = lp->owner) != NULL) {
		int rval;

		if ((lp->timeout == 0) || (owner->flag & SY_NOTIMEOUT)) {
			/*
			 * No timeout has been specified for this lock;
			 * we'll simply sleep on the condition variable.
			 */
			rval = cv_wait_sig(&lp->locksleep, &lp->mutex);
		} else {
			/*
			 * A timeout _has_ been specified for this lock. We need
			 * to wake up and possibly steal this lock if the owner
			 * does not let it go. Note that all sleepers on a lock
			 * with a timeout wait; the sleeper with the earliest
			 * timeout will wakeup, and potentially steal the lock
			 * Stealing the lock will cause a broadcast on the
			 * locksleep cv and thus kick the other timed waiters
			 * and cause everyone to restart in a new timedwait
			 */
			rval = cv_timedwait_sig(&lp->locksleep,
			    &lp->mutex, ddi_get_lbolt() + lp->timeout);
		}

		/*
		 * Timeout and still old owner - steal lock
		 * Force-Release lock and give old owner a trashpage mapping
		 */
		if ((rval == -1) && (lp->owner == owner)) {
			/*
			 * if any errors in lock_giveup, go back and sleep/retry
			 * If successful, will break out of loop
			 */
			cmn_err(CE_NOTE, "Process %d timed out on lock %d\n",
			    ddi_get_pid(), lp->cookie);
			(void) lock_giveup(lp, 1);
		} else if (rval == 0) { /* signal pending */
			cmn_err(CE_NOTE,
			    "Process %d signalled while waiting on lock %d\n",
			    ddi_get_pid(), lp->cookie);
			lp->sleepers--;
			return (FC_MAKE_ERR(EINTR));
		}
	}

	lp->sleepers--;
	/*
	 * Give mapping to this process and save a fault later
	 */
	return (give_mapping(lp, sdp, rw));
}

/*
 * Utility: give a valid mapping to lock and unlock pages to current process.
 * Caller responsible for unloading old owner's mappings
 */

static int
give_mapping(SegLock *lp, SegProc *sdp, uint_t rw)
{
	int err = 0;

	ASSERT(MUTEX_HELD(&lp->mutex));
	ASSERT(!((lp->owner == NULL) && (LOCK(lp) != 0)));
	/* give_mapping is always called with sdp in current process context */
	ASSERT(ID(sdp) == CURPROC_ID);

	/* remap any old trash mappings */
	if (sdp->flag & TRASHPAGE) {
		/* current owner should not have a trash mapping */
		ASSERT(sdp != lp->owner);

		DEBUGF(4, (CE_CONT,
		    "new owner %d remapping old trash mapping\n",
		    ddi_get_pid()));
		if ((err = devmap_umem_remap(sdp->unlockseg, winlock_dip,
		    lp->umem_cookie, 0, PAGESIZE, WINLOCK_PROT, 0, 0)) != 0) {
			/*
			 * unable to remap old trash page,
			 * abort before changing owner
			 */
			DEBUGF(4, (CE_CONT,
			    "aborting: error in umem_remap %d\n", err));
			return (err);
		}
		sdp->flag &= ~TRASHPAGE;
	}

	/* we have a new owner now */
	lp->owner = sdp;

	if ((err = devmap_load(sdp->lockseg, lp->cookie, PAGESIZE,
	    DEVMAP_ACCESS, rw)) != 0) {
		return (err);
	}
	DEBUGF(4, (CE_CONT, "new owner %d gets lock mapping", ddi_get_pid()));

	if (lp->sleepers) {
		/* Force unload unlock mapping if there are waiters */
		DEBUGF(4, (CE_CONT,
		    " lock has %d sleepers => remove unlock mapping\n",
		    lp->sleepers));
		err = devmap_unload(sdp->unlockseg, lp->cookie, PAGESIZE);
	} else {
		/*
		 * while here, give new owner a valid mapping to unlock
		 * page so we don't get called again.
		 */
		DEBUGF(4, (CE_CONT, " and unlock mapping\n"));
		err = devmap_load(sdp->unlockseg, lp->cookie, PAGESIZE,
		    DEVMAP_ACCESS, PROT_WRITE);
	}
	return (err);
}

/*
 * Unload owner's mappings, release the lock and wakeup any sleepers
 * If trash, then the old owner is given a trash mapping
 *	=> old owner held lock too long and caused a timeout
 */
static int
lock_giveup(SegLock *lp, int trash)
{
	SegProc *owner = lp->owner;

	DEBUGF(4, (CE_CONT, "winlock_giveup: lp=%p, owner=%p, trash %d\n",
	    (void *)lp, (void *)ID(lp->owner), trash));

	ASSERT(MUTEX_HELD(&lp->mutex));
	ASSERT(owner != NULL);

	/*
	 * owner loses lockpage/unlockpage mappings and gains a
	 * trashpage mapping, if needed.
	 */
	if (!trash) {
		/*
		 * We do not handle errors in devmap_unload in the !trash case,
		 * as the process is attempting to unmap/exit or otherwise
		 * release the lock. Errors in unloading the mapping are not
		 * going to affect that (unmap does not take error return).
		 */
		(void) devmap_unload(owner->lockseg, lp->cookie, PAGESIZE);
		(void) devmap_unload(owner->unlockseg, lp->cookie, PAGESIZE);
	} else {
		int err;

		if (err = devmap_unload(owner->lockseg, lp->cookie, PAGESIZE)) {
			/* error unloading lockseg mapping. abort giveup */
			return (err);
		}

		/*
		 * old owner gets mapping to trash page so it can continue
		 * devmap_umem_remap does a hat_unload (and does it holding
		 * the right locks), so no need to devmap_unload on unlockseg
		 */
		if ((err = devmap_umem_remap(owner->unlockseg, winlock_dip,
		    trashpage_cookie, 0, PAGESIZE, WINLOCK_PROT, 0, 0)) != 0) {
			/* error remapping to trash page, abort giveup */
			return (err);
		}
		owner->flag |= TRASHPAGE;
		/*
		 * Preload mapping to trash page by calling devmap_load
		 * However, devmap_load can only be called on the faulting
		 * process context and not on the owner's process context
		 * we preload only if we happen to be in owner process context
		 * Other processes will fault on the unlock mapping
		 * and be given a trash mapping at that time.
		 */
		if (ID(owner) == CURPROC_ID) {
			(void) devmap_load(owner->unlockseg, lp->cookie,
			    PAGESIZE, DEVMAP_ACCESS, PROT_WRITE);
		}
	}

	lp->owner = NULL;

	/* Clear the lock value in underlying page so new owner can grab it */
	LOCK(lp) = 0;

	if (lp->sleepers) {
		DEBUGF(4, (CE_CONT, "  waking up, lp=%p\n", (void *)lp));
		cv_broadcast(&lp->locksleep);
	}
	return (0);
}

/*
 * destroy all allocated memory.
 */

static void
lock_destroyall(void)
{
	SegLock	*lp, *lpnext;

	ASSERT(MUTEX_HELD(&winlock_mutex));
	ASSERT(lock_list == NULL);

	DEBUGF(1, (CE_CONT, "Lock list empty. Releasing free list\n"));
	for (lp = lock_free_list; lp != NULL; lp = lpnext) {
		mutex_enter(&lp->mutex);
		lpnext =  lp->next;
		ASSERT(lp->clients == NULL);
		ASSERT(lp->owner == NULL);
		ASSERT(lp->alloccount == 0);
		mutex_destroy(&lp->mutex);
		cv_destroy(&lp->locksleep);
		kmem_free(lp, sizeof (SegLock));
	}
	lock_free_list = NULL;
	next_lock = 0;
}


/* RFE: create mdb walkers instead of dump routines? */
static void
seglock_dump_all(void)
{
	SegLock	*lp;

	mutex_enter(&winlock_mutex);
	cmn_err(CE_CONT, "ID\tKEY\tNALLOC\tATTCH\tOWNED\tLOCK\tWAITER\n");

	cmn_err(CE_CONT, "Lock List:\n");
	for (lp = lock_list; lp != NULL; lp = lp->next) {
		mutex_enter(&lp->mutex);
		cmn_err(CE_CONT, "%d\t%d\t%u\t%c\t%c\t%c\t%d\n",
		    lp->cookie, lp->key, lp->alloccount,
		    lp->clients ? 'Y' : 'N',
		    lp->owner ? 'Y' : 'N',
		    lp->lockptr != 0 && LOCK(lp) ? 'Y' : 'N',
		    lp->sleepers);
		mutex_exit(&lp->mutex);
	}
	cmn_err(CE_CONT, "Free Lock List:\n");
	for (lp = lock_free_list; lp != NULL; lp = lp->next) {
		mutex_enter(&lp->mutex);
		cmn_err(CE_CONT, "%d\t%d\t%u\t%c\t%c\t%c\t%d\n",
		    lp->cookie, lp->key, lp->alloccount,
		    lp->clients ? 'Y' : 'N',
		    lp->owner ? 'Y' : 'N',
		    lp->lockptr != 0 && LOCK(lp) ? 'Y' : 'N',
		    lp->sleepers);
		mutex_exit(&lp->mutex);
	}

#ifdef DEBUG
	if (lock_debug < 3) {
		mutex_exit(&winlock_mutex);
		return;
	}

	for (lp = lock_list; lp != NULL; lp = lp->next) {
		SegProc	*sdp;

		mutex_enter(&lp->mutex);
		cmn_err(CE_CONT,
		    "lock %p, key=%d, cookie=%d, nalloc=%u, lock=%d, wait=%d\n",
		    (void *)lp, lp->key, lp->cookie, lp->alloccount,
		    lp->lockptr != 0 ? LOCK(lp) : -1, lp->sleepers);

		cmn_err(CE_CONT,
		    "style=%d, lockptr=%p, timeout=%ld, clients=%p, owner=%p\n",
		    lp->style, (void *)lp->lockptr, lp->timeout,
		    (void *)lp->clients, (void *)lp->owner);


		for (sdp = lp->clients; sdp != NULL; sdp = sdp->next) {
			cmn_err(CE_CONT, "  client %p%s, lp=%p, flag=%x, "
			    "process tag=%p, lockseg=%p, unlockseg=%p\n",
			    (void *)sdp, sdp == lp->owner ? " (owner)" : "",
			    (void *)sdp->lp, sdp->flag, (void *)ID(sdp),
			    (void *)sdp->lockseg, (void *)sdp->unlockseg);
		}
		mutex_exit(&lp->mutex);
	}
#endif
	mutex_exit(&winlock_mutex);
}

#include <sys/modctl.h>

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	"Winlock Driver",	/* Name of the module */
	&winlock_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	0,
	0,
	0
};

int
_init(void)
{
	int e;

	mutex_init(&winlock_mutex, NULL, MUTEX_DEFAULT, NULL);
	e = mod_install(&modlinkage);
	if (e) {
		mutex_destroy(&winlock_mutex);
	}
	return (e);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int	e;

	e = mod_remove(&modlinkage);
	if (e == 0) {
		mutex_destroy(&winlock_mutex);
	}
	return (e);
}
