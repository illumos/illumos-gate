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
 * Copyright 2015, Joyent, Inc.  All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * VM - address spaces.
 */

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/mman.h>
#include <sys/sysmacros.h>
#include <sys/cpuvar.h>
#include <sys/sysinfo.h>
#include <sys/kmem.h>
#include <sys/vnode.h>
#include <sys/vmsystm.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/tnf_probe.h>
#include <sys/vtrace.h>

#include <vm/hat.h>
#include <vm/xhat.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/seg_vn.h>
#include <vm/seg_dev.h>
#include <vm/seg_kmem.h>
#include <vm/seg_map.h>
#include <vm/seg_spt.h>
#include <vm/page.h>

clock_t deadlk_wait = 1; /* number of ticks to wait before retrying */

static struct kmem_cache *as_cache;

static void as_setwatchprot(struct as *, caddr_t, size_t, uint_t);
static void as_clearwatchprot(struct as *, caddr_t, size_t);
int as_map_locked(struct as *, caddr_t, size_t, int ((*)()), void *);


/*
 * Verifying the segment lists is very time-consuming; it may not be
 * desirable always to define VERIFY_SEGLIST when DEBUG is set.
 */
#ifdef DEBUG
#define	VERIFY_SEGLIST
int do_as_verify = 0;
#endif

/*
 * Allocate a new callback data structure entry and fill in the events of
 * interest, the address range of interest, and the callback argument.
 * Link the entry on the as->a_callbacks list. A callback entry for the
 * entire address space may be specified with vaddr = 0 and size = -1.
 *
 * CALLERS RESPONSIBILITY: If not calling from within the process context for
 * the specified as, the caller must guarantee persistence of the specified as
 * for the duration of this function (eg. pages being locked within the as
 * will guarantee persistence).
 */
int
as_add_callback(struct as *as, void (*cb_func)(), void *arg, uint_t events,
		caddr_t vaddr, size_t size, int sleepflag)
{
	struct as_callback 	*current_head, *cb;
	caddr_t 		saddr;
	size_t 			rsize;

	/* callback function and an event are mandatory */
	if ((cb_func == NULL) || ((events & AS_ALL_EVENT) == 0))
		return (EINVAL);

	/* Adding a callback after as_free has been called is not allowed */
	if (as == &kas)
		return (ENOMEM);

	/*
	 * vaddr = 0 and size = -1 is used to indicate that the callback range
	 * is the entire address space so no rounding is done in that case.
	 */
	if (size != -1) {
		saddr = (caddr_t)((uintptr_t)vaddr & (uintptr_t)PAGEMASK);
		rsize = (((size_t)(vaddr + size) + PAGEOFFSET) & PAGEMASK) -
		    (size_t)saddr;
		/* check for wraparound */
		if (saddr + rsize < saddr)
			return (ENOMEM);
	} else {
		if (vaddr != 0)
			return (EINVAL);
		saddr = vaddr;
		rsize = size;
	}

	/* Allocate and initialize a callback entry */
	cb = kmem_zalloc(sizeof (struct as_callback), sleepflag);
	if (cb == NULL)
		return (EAGAIN);

	cb->ascb_func = cb_func;
	cb->ascb_arg = arg;
	cb->ascb_events = events;
	cb->ascb_saddr = saddr;
	cb->ascb_len = rsize;

	/* Add the entry to the list */
	mutex_enter(&as->a_contents);
	current_head = as->a_callbacks;
	as->a_callbacks = cb;
	cb->ascb_next = current_head;

	/*
	 * The call to this function may lose in a race with
	 * a pertinent event - eg. a thread does long term memory locking
	 * but before the callback is added another thread executes as_unmap.
	 * A broadcast here resolves that.
	 */
	if ((cb->ascb_events & AS_UNMAPWAIT_EVENT) && AS_ISUNMAPWAIT(as)) {
		AS_CLRUNMAPWAIT(as);
		cv_broadcast(&as->a_cv);
	}

	mutex_exit(&as->a_contents);
	return (0);
}

/*
 * Search the callback list for an entry which pertains to arg.
 *
 * This is called from within the client upon completion of the callback.
 * RETURN VALUES:
 *	AS_CALLBACK_DELETED  (callback entry found and deleted)
 *	AS_CALLBACK_NOTFOUND (no callback entry found - this is ok)
 *	AS_CALLBACK_DELETE_DEFERRED (callback is in process, delete of this
 *			entry will be made in as_do_callbacks)
 *
 * If as_delete_callback encounters a matching entry with AS_CALLBACK_CALLED
 * set, it indicates that as_do_callbacks is processing this entry.  The
 * AS_ALL_EVENT events are cleared in the entry, and a broadcast is made
 * to unblock as_do_callbacks, in case it is blocked.
 *
 * CALLERS RESPONSIBILITY: If not calling from within the process context for
 * the specified as, the caller must guarantee persistence of the specified as
 * for the duration of this function (eg. pages being locked within the as
 * will guarantee persistence).
 */
uint_t
as_delete_callback(struct as *as, void *arg)
{
	struct as_callback **prevcb = &as->a_callbacks;
	struct as_callback *cb;
	uint_t rc = AS_CALLBACK_NOTFOUND;

	mutex_enter(&as->a_contents);
	for (cb = as->a_callbacks; cb; prevcb = &cb->ascb_next, cb = *prevcb) {
		if (cb->ascb_arg != arg)
			continue;

		/*
		 * If the events indicate AS_CALLBACK_CALLED, just clear
		 * AS_ALL_EVENT in the events field and wakeup the thread
		 * that may be waiting in as_do_callbacks.  as_do_callbacks
		 * will take care of removing this entry from the list.  In
		 * that case, return AS_CALLBACK_DELETE_DEFERRED.  Otherwise
		 * (AS_CALLBACK_CALLED not set), just remove it from the
		 * list, return the memory and return AS_CALLBACK_DELETED.
		 */
		if ((cb->ascb_events & AS_CALLBACK_CALLED) != 0) {
			/* leave AS_CALLBACK_CALLED */
			cb->ascb_events &= ~AS_ALL_EVENT;
			rc = AS_CALLBACK_DELETE_DEFERRED;
			cv_broadcast(&as->a_cv);
		} else {
			*prevcb = cb->ascb_next;
			kmem_free(cb, sizeof (struct as_callback));
			rc = AS_CALLBACK_DELETED;
		}
		break;
	}
	mutex_exit(&as->a_contents);
	return (rc);
}

/*
 * Searches the as callback list for a matching entry.
 * Returns a pointer to the first matching callback, or NULL if
 * nothing is found.
 * This function never sleeps so it is ok to call it with more
 * locks held but the (required) a_contents mutex.
 *
 * See also comment on as_do_callbacks below.
 */
static struct as_callback *
as_find_callback(struct as *as, uint_t events, caddr_t event_addr,
			size_t event_len)
{
	struct as_callback	*cb;

	ASSERT(MUTEX_HELD(&as->a_contents));
	for (cb = as->a_callbacks; cb != NULL; cb = cb->ascb_next) {
		/*
		 * If the callback has not already been called, then
		 * check if events or address range pertains.  An event_len
		 * of zero means do an unconditional callback.
		 */
		if (((cb->ascb_events & AS_CALLBACK_CALLED) != 0) ||
		    ((event_len != 0) && (((cb->ascb_events & events) == 0) ||
		    (event_addr + event_len < cb->ascb_saddr) ||
		    (event_addr > (cb->ascb_saddr + cb->ascb_len))))) {
			continue;
		}
		break;
	}
	return (cb);
}

/*
 * Executes a given callback and removes it from the callback list for
 * this address space.
 * This function may sleep so the caller must drop all locks except
 * a_contents before calling this func.
 *
 * See also comments on as_do_callbacks below.
 */
static void
as_execute_callback(struct as *as, struct as_callback *cb,
				uint_t events)
{
	struct as_callback **prevcb;
	void	*cb_arg;

	ASSERT(MUTEX_HELD(&as->a_contents) && (cb->ascb_events & events));
	cb->ascb_events |= AS_CALLBACK_CALLED;
	mutex_exit(&as->a_contents);
	(*cb->ascb_func)(as, cb->ascb_arg, events);
	mutex_enter(&as->a_contents);
	/*
	 * the callback function is required to delete the callback
	 * when the callback function determines it is OK for
	 * this thread to continue. as_delete_callback will clear
	 * the AS_ALL_EVENT in the events field when it is deleted.
	 * If the callback function called as_delete_callback,
	 * events will already be cleared and there will be no blocking.
	 */
	while ((cb->ascb_events & events) != 0) {
		cv_wait(&as->a_cv, &as->a_contents);
	}
	/*
	 * This entry needs to be taken off the list. Normally, the
	 * callback func itself does that, but unfortunately the list
	 * may have changed while the callback was running because the
	 * a_contents mutex was dropped and someone else other than the
	 * callback func itself could have called as_delete_callback,
	 * so we have to search to find this entry again.  The entry
	 * must have AS_CALLBACK_CALLED, and have the same 'arg'.
	 */
	cb_arg = cb->ascb_arg;
	prevcb = &as->a_callbacks;
	for (cb = as->a_callbacks; cb != NULL;
	    prevcb = &cb->ascb_next, cb = *prevcb) {
		if (((cb->ascb_events & AS_CALLBACK_CALLED) == 0) ||
		    (cb_arg != cb->ascb_arg)) {
			continue;
		}
		*prevcb = cb->ascb_next;
		kmem_free(cb, sizeof (struct as_callback));
		break;
	}
}

/*
 * Check the callback list for a matching event and intersection of
 * address range. If there is a match invoke the callback.  Skip an entry if:
 *    - a callback is already in progress for this entry (AS_CALLBACK_CALLED)
 *    - not event of interest
 *    - not address range of interest
 *
 * An event_len of zero indicates a request for an unconditional callback
 * (regardless of event), only the AS_CALLBACK_CALLED is checked.  The
 * a_contents lock must be dropped before a callback, so only one callback
 * can be done before returning. Return -1 (true) if a callback was
 * executed and removed from the list, else return 0 (false).
 *
 * The logically separate parts, i.e. finding a matching callback and
 * executing a given callback have been separated into two functions
 * so that they can be called with different sets of locks held beyond
 * the always-required a_contents. as_find_callback does not sleep so
 * it is ok to call it if more locks than a_contents (i.e. the a_lock
 * rwlock) are held. as_execute_callback on the other hand may sleep
 * so all locks beyond a_contents must be dropped by the caller if one
 * does not want to end comatose.
 */
static int
as_do_callbacks(struct as *as, uint_t events, caddr_t event_addr,
			size_t event_len)
{
	struct as_callback *cb;

	if ((cb = as_find_callback(as, events, event_addr, event_len))) {
		as_execute_callback(as, cb, events);
		return (-1);
	}
	return (0);
}

/*
 * Search for the segment containing addr. If a segment containing addr
 * exists, that segment is returned.  If no such segment exists, and
 * the list spans addresses greater than addr, then the first segment
 * whose base is greater than addr is returned; otherwise, NULL is
 * returned unless tail is true, in which case the last element of the
 * list is returned.
 *
 * a_seglast is used to cache the last found segment for repeated
 * searches to the same addr (which happens frequently).
 */
struct seg *
as_findseg(struct as *as, caddr_t addr, int tail)
{
	struct seg *seg = as->a_seglast;
	avl_index_t where;

	ASSERT(AS_LOCK_HELD(as, &as->a_lock));

	if (seg != NULL &&
	    seg->s_base <= addr &&
	    addr < seg->s_base + seg->s_size)
		return (seg);

	seg = avl_find(&as->a_segtree, &addr, &where);
	if (seg != NULL)
		return (as->a_seglast = seg);

	seg = avl_nearest(&as->a_segtree, where, AVL_AFTER);
	if (seg == NULL && tail)
		seg = avl_last(&as->a_segtree);
	return (as->a_seglast = seg);
}

#ifdef VERIFY_SEGLIST
/*
 * verify that the linked list is coherent
 */
static void
as_verify(struct as *as)
{
	struct seg *seg, *seglast, *p, *n;
	uint_t nsegs = 0;

	if (do_as_verify == 0)
		return;

	seglast = as->a_seglast;

	for (seg = AS_SEGFIRST(as); seg != NULL; seg = AS_SEGNEXT(as, seg)) {
		ASSERT(seg->s_as == as);
		p = AS_SEGPREV(as, seg);
		n = AS_SEGNEXT(as, seg);
		ASSERT(p == NULL || p->s_as == as);
		ASSERT(p == NULL || p->s_base < seg->s_base);
		ASSERT(n == NULL || n->s_base > seg->s_base);
		ASSERT(n != NULL || seg == avl_last(&as->a_segtree));
		if (seg == seglast)
			seglast = NULL;
		nsegs++;
	}
	ASSERT(seglast == NULL);
	ASSERT(avl_numnodes(&as->a_segtree) == nsegs);
}
#endif /* VERIFY_SEGLIST */

/*
 * Add a new segment to the address space. The avl_find()
 * may be expensive so we attempt to use last segment accessed
 * in as_gap() as an insertion point.
 */
int
as_addseg(struct as  *as, struct seg *newseg)
{
	struct seg *seg;
	caddr_t addr;
	caddr_t eaddr;
	avl_index_t where;

	ASSERT(AS_WRITE_HELD(as, &as->a_lock));

	as->a_updatedir = 1;	/* inform /proc */
	gethrestime(&as->a_updatetime);

	if (as->a_lastgaphl != NULL) {
		struct seg *hseg = NULL;
		struct seg *lseg = NULL;

		if (as->a_lastgaphl->s_base > newseg->s_base) {
			hseg = as->a_lastgaphl;
			lseg = AVL_PREV(&as->a_segtree, hseg);
		} else {
			lseg = as->a_lastgaphl;
			hseg = AVL_NEXT(&as->a_segtree, lseg);
		}

		if (hseg && lseg && lseg->s_base < newseg->s_base &&
		    hseg->s_base > newseg->s_base) {
			avl_insert_here(&as->a_segtree, newseg, lseg,
			    AVL_AFTER);
			as->a_lastgaphl = NULL;
			as->a_seglast = newseg;
			return (0);
		}
		as->a_lastgaphl = NULL;
	}

	addr = newseg->s_base;
	eaddr = addr + newseg->s_size;
again:

	seg = avl_find(&as->a_segtree, &addr, &where);

	if (seg == NULL)
		seg = avl_nearest(&as->a_segtree, where, AVL_AFTER);

	if (seg == NULL)
		seg = avl_last(&as->a_segtree);

	if (seg != NULL) {
		caddr_t base = seg->s_base;

		/*
		 * If top of seg is below the requested address, then
		 * the insertion point is at the end of the linked list,
		 * and seg points to the tail of the list.  Otherwise,
		 * the insertion point is immediately before seg.
		 */
		if (base + seg->s_size > addr) {
			if (addr >= base || eaddr > base) {
#ifdef __sparc
				extern struct seg_ops segnf_ops;

				/*
				 * no-fault segs must disappear if overlaid.
				 * XXX need new segment type so
				 * we don't have to check s_ops
				 */
				if (seg->s_ops == &segnf_ops) {
					seg_unmap(seg);
					goto again;
				}
#endif
				return (-1);	/* overlapping segment */
			}
		}
	}
	as->a_seglast = newseg;
	avl_insert(&as->a_segtree, newseg, where);

#ifdef VERIFY_SEGLIST
	as_verify(as);
#endif
	return (0);
}

struct seg *
as_removeseg(struct as *as, struct seg *seg)
{
	avl_tree_t *t;

	ASSERT(AS_WRITE_HELD(as, &as->a_lock));

	as->a_updatedir = 1;	/* inform /proc */
	gethrestime(&as->a_updatetime);

	if (seg == NULL)
		return (NULL);

	t = &as->a_segtree;
	if (as->a_seglast == seg)
		as->a_seglast = NULL;
	as->a_lastgaphl = NULL;

	/*
	 * if this segment is at an address higher than
	 * a_lastgap, set a_lastgap to the next segment (NULL if last segment)
	 */
	if (as->a_lastgap &&
	    (seg == as->a_lastgap || seg->s_base > as->a_lastgap->s_base))
		as->a_lastgap = AVL_NEXT(t, seg);

	/*
	 * remove the segment from the seg tree
	 */
	avl_remove(t, seg);

#ifdef VERIFY_SEGLIST
	as_verify(as);
#endif
	return (seg);
}

/*
 * Find a segment containing addr.
 */
struct seg *
as_segat(struct as *as, caddr_t addr)
{
	struct seg *seg = as->a_seglast;

	ASSERT(AS_LOCK_HELD(as, &as->a_lock));

	if (seg != NULL && seg->s_base <= addr &&
	    addr < seg->s_base + seg->s_size)
		return (seg);

	seg = avl_find(&as->a_segtree, &addr, NULL);
	return (seg);
}

/*
 * Serialize all searches for holes in an address space to
 * prevent two or more threads from allocating the same virtual
 * address range.  The address space must not be "read/write"
 * locked by the caller since we may block.
 */
void
as_rangelock(struct as *as)
{
	mutex_enter(&as->a_contents);
	while (AS_ISCLAIMGAP(as))
		cv_wait(&as->a_cv, &as->a_contents);
	AS_SETCLAIMGAP(as);
	mutex_exit(&as->a_contents);
}

/*
 * Release hold on a_state & AS_CLAIMGAP and signal any other blocked threads.
 */
void
as_rangeunlock(struct as *as)
{
	mutex_enter(&as->a_contents);
	AS_CLRCLAIMGAP(as);
	cv_signal(&as->a_cv);
	mutex_exit(&as->a_contents);
}

/*
 * compar segments (or just an address) by segment address range
 */
static int
as_segcompar(const void *x, const void *y)
{
	struct seg *a = (struct seg *)x;
	struct seg *b = (struct seg *)y;

	if (a->s_base < b->s_base)
		return (-1);
	if (a->s_base >= b->s_base + b->s_size)
		return (1);
	return (0);
}


void
as_avlinit(struct as *as)
{
	avl_create(&as->a_segtree, as_segcompar, sizeof (struct seg),
	    offsetof(struct seg, s_tree));
	avl_create(&as->a_wpage, wp_compare, sizeof (struct watched_page),
	    offsetof(struct watched_page, wp_link));
}

/*ARGSUSED*/
static int
as_constructor(void *buf, void *cdrarg, int kmflags)
{
	struct as *as = buf;

	mutex_init(&as->a_contents, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&as->a_cv, NULL, CV_DEFAULT, NULL);
	rw_init(&as->a_lock, NULL, RW_DEFAULT, NULL);
	as_avlinit(as);
	return (0);
}

/*ARGSUSED1*/
static void
as_destructor(void *buf, void *cdrarg)
{
	struct as *as = buf;

	avl_destroy(&as->a_segtree);
	mutex_destroy(&as->a_contents);
	cv_destroy(&as->a_cv);
	rw_destroy(&as->a_lock);
}

void
as_init(void)
{
	as_cache = kmem_cache_create("as_cache", sizeof (struct as), 0,
	    as_constructor, as_destructor, NULL, NULL, NULL, 0);
}

/*
 * Allocate and initialize an address space data structure.
 * We call hat_alloc to allow any machine dependent
 * information in the hat structure to be initialized.
 */
struct as *
as_alloc(void)
{
	struct as *as;

	as = kmem_cache_alloc(as_cache, KM_SLEEP);

	as->a_flags		= 0;
	as->a_vbits		= 0;
	as->a_hrm		= NULL;
	as->a_seglast		= NULL;
	as->a_size		= 0;
	as->a_resvsize		= 0;
	as->a_updatedir		= 0;
	gethrestime(&as->a_updatetime);
	as->a_objectdir		= NULL;
	as->a_sizedir		= 0;
	as->a_userlimit		= (caddr_t)USERLIMIT;
	as->a_lastgap		= NULL;
	as->a_lastgaphl		= NULL;
	as->a_callbacks		= NULL;

	AS_LOCK_ENTER(as, &as->a_lock, RW_WRITER);
	as->a_hat = hat_alloc(as);	/* create hat for default system mmu */
	AS_LOCK_EXIT(as, &as->a_lock);

	as->a_xhat = NULL;

	return (as);
}

/*
 * Free an address space data structure.
 * Need to free the hat first and then
 * all the segments on this as and finally
 * the space for the as struct itself.
 */
void
as_free(struct as *as)
{
	struct hat *hat = as->a_hat;
	struct seg *seg, *next;
	int called = 0;

top:
	/*
	 * Invoke ALL callbacks. as_do_callbacks will do one callback
	 * per call, and not return (-1) until the callback has completed.
	 * When as_do_callbacks returns zero, all callbacks have completed.
	 */
	mutex_enter(&as->a_contents);
	while (as->a_callbacks && as_do_callbacks(as, AS_ALL_EVENT, 0, 0))
		;

	/* This will prevent new XHATs from attaching to as */
	if (!called)
		AS_SETBUSY(as);
	mutex_exit(&as->a_contents);
	AS_LOCK_ENTER(as, &as->a_lock, RW_WRITER);

	if (!called) {
		called = 1;
		hat_free_start(hat);
		if (as->a_xhat != NULL)
			xhat_free_start_all(as);
	}
	for (seg = AS_SEGFIRST(as); seg != NULL; seg = next) {
		int err;

		next = AS_SEGNEXT(as, seg);
retry:
		err = SEGOP_UNMAP(seg, seg->s_base, seg->s_size);
		if (err == EAGAIN) {
			mutex_enter(&as->a_contents);
			if (as->a_callbacks) {
				AS_LOCK_EXIT(as, &as->a_lock);
			} else if (!AS_ISNOUNMAPWAIT(as)) {
				/*
				 * Memory is currently locked. Wait for a
				 * cv_signal that it has been unlocked, then
				 * try the operation again.
				 */
				if (AS_ISUNMAPWAIT(as) == 0)
					cv_broadcast(&as->a_cv);
				AS_SETUNMAPWAIT(as);
				AS_LOCK_EXIT(as, &as->a_lock);
				while (AS_ISUNMAPWAIT(as))
					cv_wait(&as->a_cv, &as->a_contents);
			} else {
				/*
				 * We may have raced with
				 * segvn_reclaim()/segspt_reclaim(). In this
				 * case clean nounmapwait flag and retry since
				 * softlockcnt in this segment may be already
				 * 0.  We don't drop as writer lock so our
				 * number of retries without sleeping should
				 * be very small. See segvn_reclaim() for
				 * more comments.
				 */
				AS_CLRNOUNMAPWAIT(as);
				mutex_exit(&as->a_contents);
				goto retry;
			}
			mutex_exit(&as->a_contents);
			goto top;
		} else {
			/*
			 * We do not expect any other error return at this
			 * time. This is similar to an ASSERT in seg_unmap()
			 */
			ASSERT(err == 0);
		}
	}
	hat_free_end(hat);
	if (as->a_xhat != NULL)
		xhat_free_end_all(as);
	AS_LOCK_EXIT(as, &as->a_lock);

	/* /proc stuff */
	ASSERT(avl_numnodes(&as->a_wpage) == 0);
	if (as->a_objectdir) {
		kmem_free(as->a_objectdir, as->a_sizedir * sizeof (vnode_t *));
		as->a_objectdir = NULL;
		as->a_sizedir = 0;
	}

	/*
	 * Free the struct as back to kmem.  Assert it has no segments.
	 */
	ASSERT(avl_numnodes(&as->a_segtree) == 0);
	kmem_cache_free(as_cache, as);
}

int
as_dup(struct as *as, struct proc *forkedproc)
{
	struct as *newas;
	struct seg *seg, *newseg;
	size_t	purgesize = 0;
	int error;

	AS_LOCK_ENTER(as, &as->a_lock, RW_WRITER);
	as_clearwatch(as);
	newas = as_alloc();
	newas->a_userlimit = as->a_userlimit;
	newas->a_proc = forkedproc;

	AS_LOCK_ENTER(newas, &newas->a_lock, RW_WRITER);

	/* This will prevent new XHATs from attaching */
	mutex_enter(&as->a_contents);
	AS_SETBUSY(as);
	mutex_exit(&as->a_contents);
	mutex_enter(&newas->a_contents);
	AS_SETBUSY(newas);
	mutex_exit(&newas->a_contents);

	(void) hat_dup(as->a_hat, newas->a_hat, NULL, 0, HAT_DUP_SRD);

	for (seg = AS_SEGFIRST(as); seg != NULL; seg = AS_SEGNEXT(as, seg)) {

		if (seg->s_flags & S_PURGE) {
			purgesize += seg->s_size;
			continue;
		}

		newseg = seg_alloc(newas, seg->s_base, seg->s_size);
		if (newseg == NULL) {
			AS_LOCK_EXIT(newas, &newas->a_lock);
			as_setwatch(as);
			mutex_enter(&as->a_contents);
			AS_CLRBUSY(as);
			mutex_exit(&as->a_contents);
			AS_LOCK_EXIT(as, &as->a_lock);
			as_free(newas);
			return (-1);
		}
		if ((error = SEGOP_DUP(seg, newseg)) != 0) {
			/*
			 * We call seg_free() on the new seg
			 * because the segment is not set up
			 * completely; i.e. it has no ops.
			 */
			as_setwatch(as);
			mutex_enter(&as->a_contents);
			AS_CLRBUSY(as);
			mutex_exit(&as->a_contents);
			AS_LOCK_EXIT(as, &as->a_lock);
			seg_free(newseg);
			AS_LOCK_EXIT(newas, &newas->a_lock);
			as_free(newas);
			return (error);
		}
		newas->a_size += seg->s_size;
	}
	newas->a_resvsize = as->a_resvsize - purgesize;

	error = hat_dup(as->a_hat, newas->a_hat, NULL, 0, HAT_DUP_ALL);
	if (as->a_xhat != NULL)
		error |= xhat_dup_all(as, newas, NULL, 0, HAT_DUP_ALL);

	mutex_enter(&newas->a_contents);
	AS_CLRBUSY(newas);
	mutex_exit(&newas->a_contents);
	AS_LOCK_EXIT(newas, &newas->a_lock);

	as_setwatch(as);
	mutex_enter(&as->a_contents);
	AS_CLRBUSY(as);
	mutex_exit(&as->a_contents);
	AS_LOCK_EXIT(as, &as->a_lock);
	if (error != 0) {
		as_free(newas);
		return (error);
	}
	forkedproc->p_as = newas;
	return (0);
}

/*
 * Handle a ``fault'' at addr for size bytes.
 */
faultcode_t
as_fault(struct hat *hat, struct as *as, caddr_t addr, size_t size,
	enum fault_type type, enum seg_rw rw)
{
	struct seg *seg;
	caddr_t raddr;			/* rounded down addr */
	size_t rsize;			/* rounded up size */
	size_t ssize;
	faultcode_t res = 0;
	caddr_t addrsav;
	struct seg *segsav;
	int as_lock_held;
	klwp_t *lwp = ttolwp(curthread);
	int is_xhat = 0;
	int holding_wpage = 0;
	extern struct seg_ops   segdev_ops;



	if (as->a_hat != hat) {
		/* This must be an XHAT then */
		is_xhat = 1;

		if ((type != F_INVAL) || (as == &kas))
			return (FC_NOSUPPORT);
	}

retry:
	if (!is_xhat) {
		/*
		 * Indicate that the lwp is not to be stopped while waiting
		 * for a pagefault.  This is to avoid deadlock while debugging
		 * a process via /proc over NFS (in particular).
		 */
		if (lwp != NULL)
			lwp->lwp_nostop++;

		/*
		 * same length must be used when we softlock and softunlock.
		 * We don't support softunlocking lengths less than
		 * the original length when there is largepage support.
		 * See seg_dev.c for more comments.
		 */
		switch (type) {

		case F_SOFTLOCK:
			CPU_STATS_ADD_K(vm, softlock, 1);
			break;

		case F_SOFTUNLOCK:
			break;

		case F_PROT:
			CPU_STATS_ADD_K(vm, prot_fault, 1);
			break;

		case F_INVAL:
			CPU_STATS_ENTER_K();
			CPU_STATS_ADDQ(CPU, vm, as_fault, 1);
			if (as == &kas)
				CPU_STATS_ADDQ(CPU, vm, kernel_asflt, 1);
			CPU_STATS_EXIT_K();
			break;
		}
	}

	/* Kernel probe */
	TNF_PROBE_3(address_fault, "vm pagefault", /* CSTYLED */,
	    tnf_opaque,	address,	addr,
	    tnf_fault_type,	fault_type,	type,
	    tnf_seg_access,	access,		rw);

	raddr = (caddr_t)((uintptr_t)addr & (uintptr_t)PAGEMASK);
	rsize = (((size_t)(addr + size) + PAGEOFFSET) & PAGEMASK) -
	    (size_t)raddr;

	/*
	 * XXX -- Don't grab the as lock for segkmap. We should grab it for
	 * correctness, but then we could be stuck holding this lock for
	 * a LONG time if the fault needs to be resolved on a slow
	 * filesystem, and then no-one will be able to exec new commands,
	 * as exec'ing requires the write lock on the as.
	 */
	if (as == &kas && segkmap && segkmap->s_base <= raddr &&
	    raddr + size < segkmap->s_base + segkmap->s_size) {
		/*
		 * if (as==&kas), this can't be XHAT: we've already returned
		 * FC_NOSUPPORT.
		 */
		seg = segkmap;
		as_lock_held = 0;
	} else {
		AS_LOCK_ENTER(as, &as->a_lock, RW_READER);
		if (is_xhat && avl_numnodes(&as->a_wpage) != 0) {
			/*
			 * Grab and hold the writers' lock on the as
			 * if the fault is to a watched page.
			 * This will keep CPUs from "peeking" at the
			 * address range while we're temporarily boosting
			 * the permissions for the XHAT device to
			 * resolve the fault in the segment layer.
			 *
			 * We could check whether faulted address
			 * is within a watched page and only then grab
			 * the writer lock, but this is simpler.
			 */
			AS_LOCK_EXIT(as, &as->a_lock);
			AS_LOCK_ENTER(as, &as->a_lock, RW_WRITER);
		}

		seg = as_segat(as, raddr);
		if (seg == NULL) {
			AS_LOCK_EXIT(as, &as->a_lock);
			if ((lwp != NULL) && (!is_xhat))
				lwp->lwp_nostop--;
			return (FC_NOMAP);
		}

		as_lock_held = 1;
	}

	addrsav = raddr;
	segsav = seg;

	for (; rsize != 0; rsize -= ssize, raddr += ssize) {
		if (raddr >= seg->s_base + seg->s_size) {
			seg = AS_SEGNEXT(as, seg);
			if (seg == NULL || raddr != seg->s_base) {
				res = FC_NOMAP;
				break;
			}
		}
		if (raddr + rsize > seg->s_base + seg->s_size)
			ssize = seg->s_base + seg->s_size - raddr;
		else
			ssize = rsize;

		if (!is_xhat || (seg->s_ops != &segdev_ops)) {

			if (is_xhat && avl_numnodes(&as->a_wpage) != 0 &&
			    pr_is_watchpage_as(raddr, rw, as)) {
				/*
				 * Handle watch pages.  If we're faulting on a
				 * watched page from an X-hat, we have to
				 * restore the original permissions while we
				 * handle the fault.
				 */
				as_clearwatch(as);
				holding_wpage = 1;
			}

			res = SEGOP_FAULT(hat, seg, raddr, ssize, type, rw);

			/* Restore watchpoints */
			if (holding_wpage) {
				as_setwatch(as);
				holding_wpage = 0;
			}

			if (res != 0)
				break;
		} else {
			/* XHAT does not support seg_dev */
			res = FC_NOSUPPORT;
			break;
		}
	}

	/*
	 * If we were SOFTLOCKing and encountered a failure,
	 * we must SOFTUNLOCK the range we already did. (Maybe we
	 * should just panic if we are SOFTLOCKing or even SOFTUNLOCKing
	 * right here...)
	 */
	if (res != 0 && type == F_SOFTLOCK) {
		for (seg = segsav; addrsav < raddr; addrsav += ssize) {
			if (addrsav >= seg->s_base + seg->s_size)
				seg = AS_SEGNEXT(as, seg);
			ASSERT(seg != NULL);
			/*
			 * Now call the fault routine again to perform the
			 * unlock using S_OTHER instead of the rw variable
			 * since we never got a chance to touch the pages.
			 */
			if (raddr > seg->s_base + seg->s_size)
				ssize = seg->s_base + seg->s_size - addrsav;
			else
				ssize = raddr - addrsav;
			(void) SEGOP_FAULT(hat, seg, addrsav, ssize,
			    F_SOFTUNLOCK, S_OTHER);
		}
	}
	if (as_lock_held)
		AS_LOCK_EXIT(as, &as->a_lock);
	if ((lwp != NULL) && (!is_xhat))
		lwp->lwp_nostop--;

	/*
	 * If the lower levels returned EDEADLK for a fault,
	 * It means that we should retry the fault.  Let's wait
	 * a bit also to let the deadlock causing condition clear.
	 * This is part of a gross hack to work around a design flaw
	 * in the ufs/sds logging code and should go away when the
	 * logging code is re-designed to fix the problem. See bug
	 * 4125102 for details of the problem.
	 */
	if (FC_ERRNO(res) == EDEADLK) {
		delay(deadlk_wait);
		res = 0;
		goto retry;
	}
	return (res);
}



/*
 * Asynchronous ``fault'' at addr for size bytes.
 */
faultcode_t
as_faulta(struct as *as, caddr_t addr, size_t size)
{
	struct seg *seg;
	caddr_t raddr;			/* rounded down addr */
	size_t rsize;			/* rounded up size */
	faultcode_t res = 0;
	klwp_t *lwp = ttolwp(curthread);

retry:
	/*
	 * Indicate that the lwp is not to be stopped while waiting
	 * for a pagefault.  This is to avoid deadlock while debugging
	 * a process via /proc over NFS (in particular).
	 */
	if (lwp != NULL)
		lwp->lwp_nostop++;

	raddr = (caddr_t)((uintptr_t)addr & (uintptr_t)PAGEMASK);
	rsize = (((size_t)(addr + size) + PAGEOFFSET) & PAGEMASK) -
	    (size_t)raddr;

	AS_LOCK_ENTER(as, &as->a_lock, RW_READER);
	seg = as_segat(as, raddr);
	if (seg == NULL) {
		AS_LOCK_EXIT(as, &as->a_lock);
		if (lwp != NULL)
			lwp->lwp_nostop--;
		return (FC_NOMAP);
	}

	for (; rsize != 0; rsize -= PAGESIZE, raddr += PAGESIZE) {
		if (raddr >= seg->s_base + seg->s_size) {
			seg = AS_SEGNEXT(as, seg);
			if (seg == NULL || raddr != seg->s_base) {
				res = FC_NOMAP;
				break;
			}
		}
		res = SEGOP_FAULTA(seg, raddr);
		if (res != 0)
			break;
	}
	AS_LOCK_EXIT(as, &as->a_lock);
	if (lwp != NULL)
		lwp->lwp_nostop--;
	/*
	 * If the lower levels returned EDEADLK for a fault,
	 * It means that we should retry the fault.  Let's wait
	 * a bit also to let the deadlock causing condition clear.
	 * This is part of a gross hack to work around a design flaw
	 * in the ufs/sds logging code and should go away when the
	 * logging code is re-designed to fix the problem. See bug
	 * 4125102 for details of the problem.
	 */
	if (FC_ERRNO(res) == EDEADLK) {
		delay(deadlk_wait);
		res = 0;
		goto retry;
	}
	return (res);
}

/*
 * Set the virtual mapping for the interval from [addr : addr + size)
 * in address space `as' to have the specified protection.
 * It is ok for the range to cross over several segments,
 * as long as they are contiguous.
 */
int
as_setprot(struct as *as, caddr_t addr, size_t size, uint_t prot)
{
	struct seg *seg;
	struct as_callback *cb;
	size_t ssize;
	caddr_t raddr;			/* rounded down addr */
	size_t rsize;			/* rounded up size */
	int error = 0, writer = 0;
	caddr_t saveraddr;
	size_t saversize;

setprot_top:
	raddr = (caddr_t)((uintptr_t)addr & (uintptr_t)PAGEMASK);
	rsize = (((size_t)(addr + size) + PAGEOFFSET) & PAGEMASK) -
	    (size_t)raddr;

	if (raddr + rsize < raddr)		/* check for wraparound */
		return (ENOMEM);

	saveraddr = raddr;
	saversize = rsize;

	/*
	 * Normally we only lock the as as a reader. But
	 * if due to setprot the segment driver needs to split
	 * a segment it will return IE_RETRY. Therefore we re-acquire
	 * the as lock as a writer so the segment driver can change
	 * the seg list. Also the segment driver will return IE_RETRY
	 * after it has changed the segment list so we therefore keep
	 * locking as a writer. Since these opeartions should be rare
	 * want to only lock as a writer when necessary.
	 */
	if (writer || avl_numnodes(&as->a_wpage) != 0) {
		AS_LOCK_ENTER(as, &as->a_lock, RW_WRITER);
	} else {
		AS_LOCK_ENTER(as, &as->a_lock, RW_READER);
	}

	as_clearwatchprot(as, raddr, rsize);
	seg = as_segat(as, raddr);
	if (seg == NULL) {
		as_setwatch(as);
		AS_LOCK_EXIT(as, &as->a_lock);
		return (ENOMEM);
	}

	for (; rsize != 0; rsize -= ssize, raddr += ssize) {
		if (raddr >= seg->s_base + seg->s_size) {
			seg = AS_SEGNEXT(as, seg);
			if (seg == NULL || raddr != seg->s_base) {
				error = ENOMEM;
				break;
			}
		}
		if ((raddr + rsize) > (seg->s_base + seg->s_size))
			ssize = seg->s_base + seg->s_size - raddr;
		else
			ssize = rsize;
retry:
		error = SEGOP_SETPROT(seg, raddr, ssize, prot);

		if (error == IE_NOMEM) {
			error = EAGAIN;
			break;
		}

		if (error == IE_RETRY) {
			AS_LOCK_EXIT(as, &as->a_lock);
			writer = 1;
			goto setprot_top;
		}

		if (error == EAGAIN) {
			/*
			 * Make sure we have a_lock as writer.
			 */
			if (writer == 0) {
				AS_LOCK_EXIT(as, &as->a_lock);
				writer = 1;
				goto setprot_top;
			}

			/*
			 * Memory is currently locked.  It must be unlocked
			 * before this operation can succeed through a retry.
			 * The possible reasons for locked memory and
			 * corresponding strategies for unlocking are:
			 * (1) Normal I/O
			 *	wait for a signal that the I/O operation
			 *	has completed and the memory is unlocked.
			 * (2) Asynchronous I/O
			 *	The aio subsystem does not unlock pages when
			 *	the I/O is completed. Those pages are unlocked
			 *	when the application calls aiowait/aioerror.
			 *	So, to prevent blocking forever, cv_broadcast()
			 *	is done to wake up aio_cleanup_thread.
			 *	Subsequently, segvn_reclaim will be called, and
			 *	that will do AS_CLRUNMAPWAIT() and wake us up.
			 * (3) Long term page locking:
			 *	Drivers intending to have pages locked for a
			 *	period considerably longer than for normal I/O
			 *	(essentially forever) may have registered for a
			 *	callback so they may unlock these pages on
			 *	request. This is needed to allow this operation
			 *	to succeed. Each entry on the callback list is
			 *	examined. If the event or address range pertains
			 *	the callback is invoked (unless it already is in
			 *	progress). The a_contents lock must be dropped
			 *	before the callback, so only one callback can
			 *	be done at a time. Go to the top and do more
			 *	until zero is returned. If zero is returned,
			 *	either there were no callbacks for this event
			 *	or they were already in progress.
			 */
			mutex_enter(&as->a_contents);
			if (as->a_callbacks &&
			    (cb = as_find_callback(as, AS_SETPROT_EVENT,
			    seg->s_base, seg->s_size))) {
				AS_LOCK_EXIT(as, &as->a_lock);
				as_execute_callback(as, cb, AS_SETPROT_EVENT);
			} else if (!AS_ISNOUNMAPWAIT(as)) {
				if (AS_ISUNMAPWAIT(as) == 0)
					cv_broadcast(&as->a_cv);
				AS_SETUNMAPWAIT(as);
				AS_LOCK_EXIT(as, &as->a_lock);
				while (AS_ISUNMAPWAIT(as))
					cv_wait(&as->a_cv, &as->a_contents);
			} else {
				/*
				 * We may have raced with
				 * segvn_reclaim()/segspt_reclaim(). In this
				 * case clean nounmapwait flag and retry since
				 * softlockcnt in this segment may be already
				 * 0.  We don't drop as writer lock so our
				 * number of retries without sleeping should
				 * be very small. See segvn_reclaim() for
				 * more comments.
				 */
				AS_CLRNOUNMAPWAIT(as);
				mutex_exit(&as->a_contents);
				goto retry;
			}
			mutex_exit(&as->a_contents);
			goto setprot_top;
		} else if (error != 0)
			break;
	}
	if (error != 0) {
		as_setwatch(as);
	} else {
		as_setwatchprot(as, saveraddr, saversize, prot);
	}
	AS_LOCK_EXIT(as, &as->a_lock);
	return (error);
}

/*
 * Check to make sure that the interval [addr, addr + size)
 * in address space `as' has at least the specified protection.
 * It is ok for the range to cross over several segments, as long
 * as they are contiguous.
 */
int
as_checkprot(struct as *as, caddr_t addr, size_t size, uint_t prot)
{
	struct seg *seg;
	size_t ssize;
	caddr_t raddr;			/* rounded down addr */
	size_t rsize;			/* rounded up size */
	int error = 0;

	raddr = (caddr_t)((uintptr_t)addr & (uintptr_t)PAGEMASK);
	rsize = (((size_t)(addr + size) + PAGEOFFSET) & PAGEMASK) -
	    (size_t)raddr;

	if (raddr + rsize < raddr)		/* check for wraparound */
		return (ENOMEM);

	/*
	 * This is ugly as sin...
	 * Normally, we only acquire the address space readers lock.
	 * However, if the address space has watchpoints present,
	 * we must acquire the writer lock on the address space for
	 * the benefit of as_clearwatchprot() and as_setwatchprot().
	 */
	if (avl_numnodes(&as->a_wpage) != 0)
		AS_LOCK_ENTER(as, &as->a_lock, RW_WRITER);
	else
		AS_LOCK_ENTER(as, &as->a_lock, RW_READER);
	as_clearwatchprot(as, raddr, rsize);
	seg = as_segat(as, raddr);
	if (seg == NULL) {
		as_setwatch(as);
		AS_LOCK_EXIT(as, &as->a_lock);
		return (ENOMEM);
	}

	for (; rsize != 0; rsize -= ssize, raddr += ssize) {
		if (raddr >= seg->s_base + seg->s_size) {
			seg = AS_SEGNEXT(as, seg);
			if (seg == NULL || raddr != seg->s_base) {
				error = ENOMEM;
				break;
			}
		}
		if ((raddr + rsize) > (seg->s_base + seg->s_size))
			ssize = seg->s_base + seg->s_size - raddr;
		else
			ssize = rsize;

		error = SEGOP_CHECKPROT(seg, raddr, ssize, prot);
		if (error != 0)
			break;
	}
	as_setwatch(as);
	AS_LOCK_EXIT(as, &as->a_lock);
	return (error);
}

int
as_unmap(struct as *as, caddr_t addr, size_t size)
{
	struct seg *seg, *seg_next;
	struct as_callback *cb;
	caddr_t raddr, eaddr;
	size_t ssize, rsize = 0;
	int err;

top:
	raddr = (caddr_t)((uintptr_t)addr & (uintptr_t)PAGEMASK);
	eaddr = (caddr_t)(((uintptr_t)(addr + size) + PAGEOFFSET) &
	    (uintptr_t)PAGEMASK);

	AS_LOCK_ENTER(as, &as->a_lock, RW_WRITER);

	as->a_updatedir = 1;	/* inform /proc */
	gethrestime(&as->a_updatetime);

	/*
	 * Use as_findseg to find the first segment in the range, then
	 * step through the segments in order, following s_next.
	 */
	as_clearwatchprot(as, raddr, eaddr - raddr);

	for (seg = as_findseg(as, raddr, 0); seg != NULL; seg = seg_next) {
		if (eaddr <= seg->s_base)
			break;		/* eaddr was in a gap; all done */

		/* this is implied by the test above */
		ASSERT(raddr < eaddr);

		if (raddr < seg->s_base)
			raddr = seg->s_base; 	/* raddr was in a gap */

		if (eaddr > (seg->s_base + seg->s_size))
			ssize = seg->s_base + seg->s_size - raddr;
		else
			ssize = eaddr - raddr;

		/*
		 * Save next segment pointer since seg can be
		 * destroyed during the segment unmap operation.
		 */
		seg_next = AS_SEGNEXT(as, seg);

		/*
		 * We didn't count /dev/null mappings, so ignore them here.
		 * We'll handle MAP_NORESERVE cases in segvn_unmap(). (Again,
		 * we have to do this check here while we have seg.)
		 */
		rsize = 0;
		if (!SEG_IS_DEVNULL_MAPPING(seg) &&
		    !SEG_IS_PARTIAL_RESV(seg))
			rsize = ssize;

retry:
		err = SEGOP_UNMAP(seg, raddr, ssize);
		if (err == EAGAIN) {
			/*
			 * Memory is currently locked.  It must be unlocked
			 * before this operation can succeed through a retry.
			 * The possible reasons for locked memory and
			 * corresponding strategies for unlocking are:
			 * (1) Normal I/O
			 *	wait for a signal that the I/O operation
			 *	has completed and the memory is unlocked.
			 * (2) Asynchronous I/O
			 *	The aio subsystem does not unlock pages when
			 *	the I/O is completed. Those pages are unlocked
			 *	when the application calls aiowait/aioerror.
			 *	So, to prevent blocking forever, cv_broadcast()
			 *	is done to wake up aio_cleanup_thread.
			 *	Subsequently, segvn_reclaim will be called, and
			 *	that will do AS_CLRUNMAPWAIT() and wake us up.
			 * (3) Long term page locking:
			 *	Drivers intending to have pages locked for a
			 *	period considerably longer than for normal I/O
			 *	(essentially forever) may have registered for a
			 *	callback so they may unlock these pages on
			 *	request. This is needed to allow this operation
			 *	to succeed. Each entry on the callback list is
			 *	examined. If the event or address range pertains
			 *	the callback is invoked (unless it already is in
			 *	progress). The a_contents lock must be dropped
			 *	before the callback, so only one callback can
			 *	be done at a time. Go to the top and do more
			 *	until zero is returned. If zero is returned,
			 *	either there were no callbacks for this event
			 *	or they were already in progress.
			 */
			mutex_enter(&as->a_contents);
			if (as->a_callbacks &&
			    (cb = as_find_callback(as, AS_UNMAP_EVENT,
			    seg->s_base, seg->s_size))) {
				AS_LOCK_EXIT(as, &as->a_lock);
				as_execute_callback(as, cb, AS_UNMAP_EVENT);
			} else if (!AS_ISNOUNMAPWAIT(as)) {
				if (AS_ISUNMAPWAIT(as) == 0)
					cv_broadcast(&as->a_cv);
				AS_SETUNMAPWAIT(as);
				AS_LOCK_EXIT(as, &as->a_lock);
				while (AS_ISUNMAPWAIT(as))
					cv_wait(&as->a_cv, &as->a_contents);
			} else {
				/*
				 * We may have raced with
				 * segvn_reclaim()/segspt_reclaim(). In this
				 * case clean nounmapwait flag and retry since
				 * softlockcnt in this segment may be already
				 * 0.  We don't drop as writer lock so our
				 * number of retries without sleeping should
				 * be very small. See segvn_reclaim() for
				 * more comments.
				 */
				AS_CLRNOUNMAPWAIT(as);
				mutex_exit(&as->a_contents);
				goto retry;
			}
			mutex_exit(&as->a_contents);
			goto top;
		} else if (err == IE_RETRY) {
			AS_LOCK_EXIT(as, &as->a_lock);
			goto top;
		} else if (err) {
			as_setwatch(as);
			AS_LOCK_EXIT(as, &as->a_lock);
			return (-1);
		}

		as->a_size -= ssize;
		if (rsize)
			as->a_resvsize -= rsize;
		raddr += ssize;
	}
	AS_LOCK_EXIT(as, &as->a_lock);
	return (0);
}

static int
as_map_segvn_segs(struct as *as, caddr_t addr, size_t size, uint_t szcvec,
    int (*crfp)(), struct segvn_crargs *vn_a, int *segcreated)
{
	uint_t szc;
	uint_t nszc;
	int error;
	caddr_t a;
	caddr_t eaddr;
	size_t segsize;
	struct seg *seg;
	size_t pgsz;
	int do_off = (vn_a->vp != NULL || vn_a->amp != NULL);
	uint_t save_szcvec;

	ASSERT(AS_WRITE_HELD(as, &as->a_lock));
	ASSERT(IS_P2ALIGNED(addr, PAGESIZE));
	ASSERT(IS_P2ALIGNED(size, PAGESIZE));
	ASSERT(vn_a->vp == NULL || vn_a->amp == NULL);
	if (!do_off) {
		vn_a->offset = 0;
	}

	if (szcvec <= 1) {
		seg = seg_alloc(as, addr, size);
		if (seg == NULL) {
			return (ENOMEM);
		}
		vn_a->szc = 0;
		error = (*crfp)(seg, vn_a);
		if (error != 0) {
			seg_free(seg);
		} else {
			as->a_size += size;
			as->a_resvsize += size;
		}
		return (error);
	}

	eaddr = addr + size;
	save_szcvec = szcvec;
	szcvec >>= 1;
	szc = 0;
	nszc = 0;
	while (szcvec) {
		if ((szcvec & 0x1) == 0) {
			nszc++;
			szcvec >>= 1;
			continue;
		}
		nszc++;
		pgsz = page_get_pagesize(nszc);
		a = (caddr_t)P2ROUNDUP((uintptr_t)addr, pgsz);
		if (a != addr) {
			ASSERT(a < eaddr);
			segsize = a - addr;
			seg = seg_alloc(as, addr, segsize);
			if (seg == NULL) {
				return (ENOMEM);
			}
			vn_a->szc = szc;
			error = (*crfp)(seg, vn_a);
			if (error != 0) {
				seg_free(seg);
				return (error);
			}
			as->a_size += segsize;
			as->a_resvsize += segsize;
			*segcreated = 1;
			if (do_off) {
				vn_a->offset += segsize;
			}
			addr = a;
		}
		szc = nszc;
		szcvec >>= 1;
	}

	ASSERT(addr < eaddr);
	szcvec = save_szcvec | 1; /* add 8K pages */
	while (szcvec) {
		a = (caddr_t)P2ALIGN((uintptr_t)eaddr, pgsz);
		ASSERT(a >= addr);
		if (a != addr) {
			segsize = a - addr;
			seg = seg_alloc(as, addr, segsize);
			if (seg == NULL) {
				return (ENOMEM);
			}
			vn_a->szc = szc;
			error = (*crfp)(seg, vn_a);
			if (error != 0) {
				seg_free(seg);
				return (error);
			}
			as->a_size += segsize;
			as->a_resvsize += segsize;
			*segcreated = 1;
			if (do_off) {
				vn_a->offset += segsize;
			}
			addr = a;
		}
		szcvec &= ~(1 << szc);
		if (szcvec) {
			szc = highbit(szcvec) - 1;
			pgsz = page_get_pagesize(szc);
		}
	}
	ASSERT(addr == eaddr);

	return (0);
}

static int
as_map_vnsegs(struct as *as, caddr_t addr, size_t size,
    int (*crfp)(), struct segvn_crargs *vn_a, int *segcreated)
{
	uint_t mapflags = vn_a->flags & (MAP_TEXT | MAP_INITDATA);
	int type = (vn_a->type == MAP_SHARED) ? MAPPGSZC_SHM : MAPPGSZC_PRIVM;
	uint_t szcvec = map_pgszcvec(addr, size, (uintptr_t)addr, mapflags,
	    type, 0);
	int error;
	struct seg *seg;
	struct vattr va;
	u_offset_t eoff;
	size_t save_size = 0;
	extern size_t textrepl_size_thresh;

	ASSERT(AS_WRITE_HELD(as, &as->a_lock));
	ASSERT(IS_P2ALIGNED(addr, PAGESIZE));
	ASSERT(IS_P2ALIGNED(size, PAGESIZE));
	ASSERT(vn_a->vp != NULL);
	ASSERT(vn_a->amp == NULL);

again:
	if (szcvec <= 1) {
		seg = seg_alloc(as, addr, size);
		if (seg == NULL) {
			return (ENOMEM);
		}
		vn_a->szc = 0;
		error = (*crfp)(seg, vn_a);
		if (error != 0) {
			seg_free(seg);
		} else {
			as->a_size += size;
			as->a_resvsize += size;
		}
		return (error);
	}

	va.va_mask = AT_SIZE;
	if (VOP_GETATTR(vn_a->vp, &va, ATTR_HINT, vn_a->cred, NULL) != 0) {
		szcvec = 0;
		goto again;
	}
	eoff = vn_a->offset & PAGEMASK;
	if (eoff >= va.va_size) {
		szcvec = 0;
		goto again;
	}
	eoff += size;
	if (btopr(va.va_size) < btopr(eoff)) {
		save_size = size;
		size = va.va_size - (vn_a->offset & PAGEMASK);
		size = P2ROUNDUP_TYPED(size, PAGESIZE, size_t);
		szcvec = map_pgszcvec(addr, size, (uintptr_t)addr, mapflags,
		    type, 0);
		if (szcvec <= 1) {
			size = save_size;
			goto again;
		}
	}

	if (size > textrepl_size_thresh) {
		vn_a->flags |= _MAP_TEXTREPL;
	}
	error = as_map_segvn_segs(as, addr, size, szcvec, crfp, vn_a,
	    segcreated);
	if (error != 0) {
		return (error);
	}
	if (save_size) {
		addr += size;
		size = save_size - size;
		szcvec = 0;
		goto again;
	}
	return (0);
}

/*
 * as_map_ansegs: shared or private anonymous memory.  Note that the flags
 * passed to map_pgszvec cannot be MAP_INITDATA, for anon.
 */
static int
as_map_ansegs(struct as *as, caddr_t addr, size_t size,
    int (*crfp)(), struct segvn_crargs *vn_a, int *segcreated)
{
	uint_t szcvec;
	uchar_t type;

	ASSERT(vn_a->type == MAP_SHARED || vn_a->type == MAP_PRIVATE);
	if (vn_a->type == MAP_SHARED) {
		type = MAPPGSZC_SHM;
	} else if (vn_a->type == MAP_PRIVATE) {
		if (vn_a->szc == AS_MAP_HEAP) {
			type = MAPPGSZC_HEAP;
		} else if (vn_a->szc == AS_MAP_STACK) {
			type = MAPPGSZC_STACK;
		} else {
			type = MAPPGSZC_PRIVM;
		}
	}
	szcvec = map_pgszcvec(addr, size, vn_a->amp == NULL ?
	    (uintptr_t)addr : (uintptr_t)P2ROUNDUP(vn_a->offset, PAGESIZE),
	    (vn_a->flags & MAP_TEXT), type, 0);
	ASSERT(AS_WRITE_HELD(as, &as->a_lock));
	ASSERT(IS_P2ALIGNED(addr, PAGESIZE));
	ASSERT(IS_P2ALIGNED(size, PAGESIZE));
	ASSERT(vn_a->vp == NULL);

	return (as_map_segvn_segs(as, addr, size, szcvec,
	    crfp, vn_a, segcreated));
}

int
as_map(struct as *as, caddr_t addr, size_t size, int (*crfp)(), void *argsp)
{
	AS_LOCK_ENTER(as, &as->a_lock, RW_WRITER);
	return (as_map_locked(as, addr, size, crfp, argsp));
}

int
as_map_locked(struct as *as, caddr_t addr, size_t size, int (*crfp)(),
		void *argsp)
{
	struct seg *seg = NULL;
	caddr_t raddr;			/* rounded down addr */
	size_t rsize;			/* rounded up size */
	int error;
	int unmap = 0;
	struct proc *p = curproc;
	struct segvn_crargs crargs;

	raddr = (caddr_t)((uintptr_t)addr & (uintptr_t)PAGEMASK);
	rsize = (((size_t)(addr + size) + PAGEOFFSET) & PAGEMASK) -
	    (size_t)raddr;

	/*
	 * check for wrap around
	 */
	if ((raddr + rsize < raddr) || (as->a_size > (ULONG_MAX - size))) {
		AS_LOCK_EXIT(as, &as->a_lock);
		return (ENOMEM);
	}

	as->a_updatedir = 1;	/* inform /proc */
	gethrestime(&as->a_updatetime);

	if (as != &kas && as->a_size + rsize > (size_t)p->p_vmem_ctl) {
		AS_LOCK_EXIT(as, &as->a_lock);

		(void) rctl_action(rctlproc_legacy[RLIMIT_VMEM], p->p_rctls, p,
		    RCA_UNSAFE_ALL);

		return (ENOMEM);
	}

	if (AS_MAP_CHECK_VNODE_LPOOB(crfp, argsp)) {
		crargs = *(struct segvn_crargs *)argsp;
		error = as_map_vnsegs(as, raddr, rsize, crfp, &crargs, &unmap);
		if (error != 0) {
			AS_LOCK_EXIT(as, &as->a_lock);
			if (unmap) {
				(void) as_unmap(as, addr, size);
			}
			return (error);
		}
	} else if (AS_MAP_CHECK_ANON_LPOOB(crfp, argsp)) {
		crargs = *(struct segvn_crargs *)argsp;
		error = as_map_ansegs(as, raddr, rsize, crfp, &crargs, &unmap);
		if (error != 0) {
			AS_LOCK_EXIT(as, &as->a_lock);
			if (unmap) {
				(void) as_unmap(as, addr, size);
			}
			return (error);
		}
	} else {
		seg = seg_alloc(as, addr, size);
		if (seg == NULL) {
			AS_LOCK_EXIT(as, &as->a_lock);
			return (ENOMEM);
		}

		error = (*crfp)(seg, argsp);
		if (error != 0) {
			seg_free(seg);
			AS_LOCK_EXIT(as, &as->a_lock);
			return (error);
		}
		/*
		 * Add size now so as_unmap will work if as_ctl fails.
		 */
		as->a_size += rsize;
		as->a_resvsize += rsize;
	}

	as_setwatch(as);

	/*
	 * If the address space is locked,
	 * establish memory locks for the new segment.
	 */
	mutex_enter(&as->a_contents);
	if (AS_ISPGLCK(as)) {
		mutex_exit(&as->a_contents);
		AS_LOCK_EXIT(as, &as->a_lock);
		error = as_ctl(as, addr, size, MC_LOCK, 0, 0, NULL, 0);
		if (error != 0)
			(void) as_unmap(as, addr, size);
	} else {
		mutex_exit(&as->a_contents);
		AS_LOCK_EXIT(as, &as->a_lock);
	}
	return (error);
}


/*
 * Delete all segments in the address space marked with S_PURGE.
 * This is currently used for Sparc V9 nofault ASI segments (seg_nf.c).
 * These segments are deleted as a first step before calls to as_gap(), so
 * that they don't affect mmap() or shmat().
 */
void
as_purge(struct as *as)
{
	struct seg *seg;
	struct seg *next_seg;

	/*
	 * the setting of NEEDSPURGE is protect by as_rangelock(), so
	 * no need to grab a_contents mutex for this check
	 */
	if ((as->a_flags & AS_NEEDSPURGE) == 0)
		return;

	AS_LOCK_ENTER(as, &as->a_lock, RW_WRITER);
	next_seg = NULL;
	seg = AS_SEGFIRST(as);
	while (seg != NULL) {
		next_seg = AS_SEGNEXT(as, seg);
		if (seg->s_flags & S_PURGE)
			SEGOP_UNMAP(seg, seg->s_base, seg->s_size);
		seg = next_seg;
	}
	AS_LOCK_EXIT(as, &as->a_lock);

	mutex_enter(&as->a_contents);
	as->a_flags &= ~AS_NEEDSPURGE;
	mutex_exit(&as->a_contents);
}

/*
 * Find a hole within [*basep, *basep + *lenp), which contains a mappable
 * range of addresses at least "minlen" long, where the base of the range is
 * at "off" phase from an "align" boundary and there is space for a
 * "redzone"-sized redzone on eithe rside of the range.  Thus,
 * if align was 4M and off was 16k, the user wants a hole which will start
 * 16k into a 4M page.
 *
 * If flags specifies AH_HI, the hole will have the highest possible address
 * in the range.  We use the as->a_lastgap field to figure out where to
 * start looking for a gap.
 *
 * Otherwise, the gap will have the lowest possible address.
 *
 * If flags specifies AH_CONTAIN, the hole will contain the address addr.
 *
 * If an adequate hole is found, *basep and *lenp are set to reflect the part of
 * the hole that is within range, and 0 is returned. On failure, -1 is returned.
 *
 * NOTE: This routine is not correct when base+len overflows caddr_t.
 */
int
as_gap_aligned(struct as *as, size_t minlen, caddr_t *basep, size_t *lenp,
    uint_t flags, caddr_t addr, size_t align, size_t redzone, size_t off)
{
	caddr_t lobound = *basep;
	caddr_t hibound = lobound + *lenp;
	struct seg *lseg, *hseg;
	caddr_t lo, hi;
	int forward;
	caddr_t save_base;
	size_t save_len;
	size_t save_minlen;
	size_t save_redzone;
	int fast_path = 1;

	save_base = *basep;
	save_len = *lenp;
	save_minlen = minlen;
	save_redzone = redzone;

	/*
	 * For the first pass/fast_path, just add align and redzone into
	 * minlen since if we get an allocation, we can guarantee that it
	 * will fit the alignment and redzone requested.
	 * This increases the chance that hibound will be adjusted to
	 * a_lastgap->s_base which will likely allow us to find an
	 * acceptable hole in the address space quicker.
	 * If we can't find a hole with this fast_path, then we look for
	 * smaller holes in which the alignment and offset may allow
	 * the allocation to fit.
	 */
	minlen += align;
	minlen += 2 * redzone;
	redzone = 0;

	AS_LOCK_ENTER(as, &as->a_lock, RW_READER);
	if (AS_SEGFIRST(as) == NULL) {
		if (valid_va_range_aligned(basep, lenp, minlen, flags & AH_DIR,
		    align, redzone, off)) {
			AS_LOCK_EXIT(as, &as->a_lock);
			return (0);
		} else {
			AS_LOCK_EXIT(as, &as->a_lock);
			*basep = save_base;
			*lenp = save_len;
			return (-1);
		}
	}

retry:
	/*
	 * Set up to iterate over all the inter-segment holes in the given
	 * direction.  lseg is NULL for the lowest-addressed hole and hseg is
	 * NULL for the highest-addressed hole.  If moving backwards, we reset
	 * sseg to denote the highest-addressed segment.
	 */
	forward = (flags & AH_DIR) == AH_LO;
	if (forward) {
		hseg = as_findseg(as, lobound, 1);
		lseg = AS_SEGPREV(as, hseg);
	} else {

		/*
		 * If allocating at least as much as the last allocation,
		 * use a_lastgap's base as a better estimate of hibound.
		 */
		if (as->a_lastgap &&
		    minlen >= as->a_lastgap->s_size &&
		    hibound >= as->a_lastgap->s_base)
			hibound = as->a_lastgap->s_base;

		hseg = as_findseg(as, hibound, 1);
		if (hseg->s_base + hseg->s_size < hibound) {
			lseg = hseg;
			hseg = NULL;
		} else {
			lseg = AS_SEGPREV(as, hseg);
		}
	}

	for (;;) {
		/*
		 * Set lo and hi to the hole's boundaries.  (We should really
		 * use MAXADDR in place of hibound in the expression below,
		 * but can't express it easily; using hibound in its place is
		 * harmless.)
		 */
		lo = (lseg == NULL) ? 0 : lseg->s_base + lseg->s_size;
		hi = (hseg == NULL) ? hibound : hseg->s_base;
		/*
		 * If the iteration has moved past the interval from lobound
		 * to hibound it's pointless to continue.
		 */
		if ((forward && lo > hibound) || (!forward && hi < lobound))
			break;
		else if (lo > hibound || hi < lobound)
			goto cont;
		/*
		 * Candidate hole lies at least partially within the allowable
		 * range.  Restrict it to fall completely within that range,
		 * i.e., to [max(lo, lobound), min(hi, hibound)].
		 */
		if (lo < lobound)
			lo = lobound;
		if (hi > hibound)
			hi = hibound;
		/*
		 * Verify that the candidate hole is big enough and meets
		 * hardware constraints.  If the hole is too small, no need
		 * to do the further checks since they will fail.
		 */
		*basep = lo;
		*lenp = hi - lo;
		if (*lenp >= minlen && valid_va_range_aligned(basep, lenp,
		    minlen, forward ? AH_LO : AH_HI, align, redzone, off) &&
		    ((flags & AH_CONTAIN) == 0 ||
		    (*basep <= addr && *basep + *lenp > addr))) {
			if (!forward)
				as->a_lastgap = hseg;
			if (hseg != NULL)
				as->a_lastgaphl = hseg;
			else
				as->a_lastgaphl = lseg;
			AS_LOCK_EXIT(as, &as->a_lock);
			return (0);
		}
	cont:
		/*
		 * Move to the next hole.
		 */
		if (forward) {
			lseg = hseg;
			if (lseg == NULL)
				break;
			hseg = AS_SEGNEXT(as, hseg);
		} else {
			hseg = lseg;
			if (hseg == NULL)
				break;
			lseg = AS_SEGPREV(as, lseg);
		}
	}
	if (fast_path && (align != 0 || save_redzone != 0)) {
		fast_path = 0;
		minlen = save_minlen;
		redzone = save_redzone;
		goto retry;
	}
	*basep = save_base;
	*lenp = save_len;
	AS_LOCK_EXIT(as, &as->a_lock);
	return (-1);
}

/*
 * Find a hole of at least size minlen within [*basep, *basep + *lenp).
 *
 * If flags specifies AH_HI, the hole will have the highest possible address
 * in the range.  We use the as->a_lastgap field to figure out where to
 * start looking for a gap.
 *
 * Otherwise, the gap will have the lowest possible address.
 *
 * If flags specifies AH_CONTAIN, the hole will contain the address addr.
 *
 * If an adequate hole is found, base and len are set to reflect the part of
 * the hole that is within range, and 0 is returned, otherwise,
 * -1 is returned.
 *
 * NOTE: This routine is not correct when base+len overflows caddr_t.
 */
int
as_gap(struct as *as, size_t minlen, caddr_t *basep, size_t *lenp, uint_t flags,
    caddr_t addr)
{

	return (as_gap_aligned(as, minlen, basep, lenp, flags, addr, 0, 0, 0));
}

/*
 * Return the next range within [base, base + len) that is backed
 * with "real memory".  Skip holes and non-seg_vn segments.
 * We're lazy and only return one segment at a time.
 */
int
as_memory(struct as *as, caddr_t *basep, size_t *lenp)
{
	extern struct seg_ops segspt_shmops;	/* needs a header file */
	struct seg *seg;
	caddr_t addr, eaddr;
	caddr_t segend;

	AS_LOCK_ENTER(as, &as->a_lock, RW_READER);

	addr = *basep;
	eaddr = addr + *lenp;

	seg = as_findseg(as, addr, 0);
	if (seg != NULL)
		addr = MAX(seg->s_base, addr);

	for (;;) {
		if (seg == NULL || addr >= eaddr || eaddr <= seg->s_base) {
			AS_LOCK_EXIT(as, &as->a_lock);
			return (EINVAL);
		}

		if (seg->s_ops == &segvn_ops) {
			segend = seg->s_base + seg->s_size;
			break;
		}

		/*
		 * We do ISM by looking into the private data
		 * to determine the real size of the segment.
		 */
		if (seg->s_ops == &segspt_shmops) {
			segend = seg->s_base + spt_realsize(seg);
			if (addr < segend)
				break;
		}

		seg = AS_SEGNEXT(as, seg);

		if (seg != NULL)
			addr = seg->s_base;
	}

	*basep = addr;

	if (segend > eaddr)
		*lenp = eaddr - addr;
	else
		*lenp = segend - addr;

	AS_LOCK_EXIT(as, &as->a_lock);
	return (0);
}

/*
 * Swap the pages associated with the address space as out to
 * secondary storage, returning the number of bytes actually
 * swapped.
 *
 * The value returned is intended to correlate well with the process's
 * memory requirements.  Its usefulness for this purpose depends on
 * how well the segment-level routines do at returning accurate
 * information.
 */
size_t
as_swapout(struct as *as)
{
	struct seg *seg;
	size_t swpcnt = 0;

	/*
	 * Kernel-only processes have given up their address
	 * spaces.  Of course, we shouldn't be attempting to
	 * swap out such processes in the first place...
	 */
	if (as == NULL)
		return (0);

	AS_LOCK_ENTER(as, &as->a_lock, RW_READER);

	/* Prevent XHATs from attaching */
	mutex_enter(&as->a_contents);
	AS_SETBUSY(as);
	mutex_exit(&as->a_contents);


	/*
	 * Free all mapping resources associated with the address
	 * space.  The segment-level swapout routines capitalize
	 * on this unmapping by scavanging pages that have become
	 * unmapped here.
	 */
	hat_swapout(as->a_hat);
	if (as->a_xhat != NULL)
		xhat_swapout_all(as);

	mutex_enter(&as->a_contents);
	AS_CLRBUSY(as);
	mutex_exit(&as->a_contents);

	/*
	 * Call the swapout routines of all segments in the address
	 * space to do the actual work, accumulating the amount of
	 * space reclaimed.
	 */
	for (seg = AS_SEGFIRST(as); seg != NULL; seg = AS_SEGNEXT(as, seg)) {
		struct seg_ops *ov = seg->s_ops;

		/*
		 * We have to check to see if the seg has
		 * an ops vector because the seg may have
		 * been in the middle of being set up when
		 * the process was picked for swapout.
		 */
		if ((ov != NULL) && (ov->swapout != NULL))
			swpcnt += SEGOP_SWAPOUT(seg);
	}
	AS_LOCK_EXIT(as, &as->a_lock);
	return (swpcnt);
}

/*
 * Determine whether data from the mappings in interval [addr, addr + size)
 * are in the primary memory (core) cache.
 */
int
as_incore(struct as *as, caddr_t addr,
    size_t size, char *vec, size_t *sizep)
{
	struct seg *seg;
	size_t ssize;
	caddr_t raddr;		/* rounded down addr */
	size_t rsize;		/* rounded up size */
	size_t isize;			/* iteration size */
	int error = 0;		/* result, assume success */

	*sizep = 0;
	raddr = (caddr_t)((uintptr_t)addr & (uintptr_t)PAGEMASK);
	rsize = ((((size_t)addr + size) + PAGEOFFSET) & PAGEMASK) -
	    (size_t)raddr;

	if (raddr + rsize < raddr)		/* check for wraparound */
		return (ENOMEM);

	AS_LOCK_ENTER(as, &as->a_lock, RW_READER);
	seg = as_segat(as, raddr);
	if (seg == NULL) {
		AS_LOCK_EXIT(as, &as->a_lock);
		return (-1);
	}

	for (; rsize != 0; rsize -= ssize, raddr += ssize) {
		if (raddr >= seg->s_base + seg->s_size) {
			seg = AS_SEGNEXT(as, seg);
			if (seg == NULL || raddr != seg->s_base) {
				error = -1;
				break;
			}
		}
		if ((raddr + rsize) > (seg->s_base + seg->s_size))
			ssize = seg->s_base + seg->s_size - raddr;
		else
			ssize = rsize;
		*sizep += isize = SEGOP_INCORE(seg, raddr, ssize, vec);
		if (isize != ssize) {
			error = -1;
			break;
		}
		vec += btopr(ssize);
	}
	AS_LOCK_EXIT(as, &as->a_lock);
	return (error);
}

static void
as_segunlock(struct seg *seg, caddr_t addr, int attr,
	ulong_t *bitmap, size_t position, size_t npages)
{
	caddr_t	range_start;
	size_t	pos1 = position;
	size_t	pos2;
	size_t	size;
	size_t  end_pos = npages + position;

	while (bt_range(bitmap, &pos1, &pos2, end_pos)) {
		size = ptob((pos2 - pos1));
		range_start = (caddr_t)((uintptr_t)addr +
		    ptob(pos1 - position));

		(void) SEGOP_LOCKOP(seg, range_start, size, attr, MC_UNLOCK,
		    (ulong_t *)NULL, (size_t)NULL);
		pos1 = pos2;
	}
}

static void
as_unlockerr(struct as *as, int attr, ulong_t *mlock_map,
	caddr_t raddr, size_t rsize)
{
	struct seg *seg = as_segat(as, raddr);
	size_t ssize;

	while (rsize != 0) {
		if (raddr >= seg->s_base + seg->s_size)
			seg = AS_SEGNEXT(as, seg);

		if ((raddr + rsize) > (seg->s_base + seg->s_size))
			ssize = seg->s_base + seg->s_size - raddr;
		else
			ssize = rsize;

		as_segunlock(seg, raddr, attr, mlock_map, 0, btopr(ssize));

		rsize -= ssize;
		raddr += ssize;
	}
}

/*
 * Cache control operations over the interval [addr, addr + size) in
 * address space "as".
 */
/*ARGSUSED*/
int
as_ctl(struct as *as, caddr_t addr, size_t size, int func, int attr,
    uintptr_t arg, ulong_t *lock_map, size_t pos)
{
	struct seg *seg;	/* working segment */
	caddr_t raddr;		/* rounded down addr */
	caddr_t initraddr;	/* saved initial rounded down addr */
	size_t rsize;		/* rounded up size */
	size_t initrsize;	/* saved initial rounded up size */
	size_t ssize;		/* size of seg */
	int error = 0;			/* result */
	size_t mlock_size;	/* size of bitmap */
	ulong_t *mlock_map;	/* pointer to bitmap used */
				/* to represent the locked */
				/* pages. */
retry:
	if (error == IE_RETRY)
		AS_LOCK_ENTER(as, &as->a_lock, RW_WRITER);
	else
		AS_LOCK_ENTER(as, &as->a_lock, RW_READER);

	/*
	 * If these are address space lock/unlock operations, loop over
	 * all segments in the address space, as appropriate.
	 */
	if (func == MC_LOCKAS) {
		size_t npages, idx;
		size_t rlen = 0;	/* rounded as length */

		idx = pos;

		if (arg & MCL_FUTURE) {
			mutex_enter(&as->a_contents);
			AS_SETPGLCK(as);
			mutex_exit(&as->a_contents);
		}
		if ((arg & MCL_CURRENT) == 0) {
			AS_LOCK_EXIT(as, &as->a_lock);
			return (0);
		}

		seg = AS_SEGFIRST(as);
		if (seg == NULL) {
			AS_LOCK_EXIT(as, &as->a_lock);
			return (0);
		}

		do {
			raddr = (caddr_t)((uintptr_t)seg->s_base &
			    (uintptr_t)PAGEMASK);
			rlen += (((uintptr_t)(seg->s_base + seg->s_size) +
			    PAGEOFFSET) & PAGEMASK) - (uintptr_t)raddr;
		} while ((seg = AS_SEGNEXT(as, seg)) != NULL);

		mlock_size = BT_BITOUL(btopr(rlen));
		if ((mlock_map = (ulong_t *)kmem_zalloc(mlock_size *
		    sizeof (ulong_t), KM_NOSLEEP)) == NULL) {
				AS_LOCK_EXIT(as, &as->a_lock);
				return (EAGAIN);
		}

		for (seg = AS_SEGFIRST(as); seg; seg = AS_SEGNEXT(as, seg)) {
			error = SEGOP_LOCKOP(seg, seg->s_base,
			    seg->s_size, attr, MC_LOCK, mlock_map, pos);
			if (error != 0)
				break;
			pos += seg_pages(seg);
		}

		if (error) {
			for (seg = AS_SEGFIRST(as); seg != NULL;
			    seg = AS_SEGNEXT(as, seg)) {

				raddr = (caddr_t)((uintptr_t)seg->s_base &
				    (uintptr_t)PAGEMASK);
				npages = seg_pages(seg);
				as_segunlock(seg, raddr, attr, mlock_map,
				    idx, npages);
				idx += npages;
			}
		}

		kmem_free(mlock_map, mlock_size * sizeof (ulong_t));
		AS_LOCK_EXIT(as, &as->a_lock);
		goto lockerr;
	} else if (func == MC_UNLOCKAS) {
		mutex_enter(&as->a_contents);
		AS_CLRPGLCK(as);
		mutex_exit(&as->a_contents);

		for (seg = AS_SEGFIRST(as); seg; seg = AS_SEGNEXT(as, seg)) {
			error = SEGOP_LOCKOP(seg, seg->s_base,
			    seg->s_size, attr, MC_UNLOCK, NULL, 0);
			if (error != 0)
				break;
		}

		AS_LOCK_EXIT(as, &as->a_lock);
		goto lockerr;
	}

	/*
	 * Normalize addresses and sizes.
	 */
	initraddr = raddr = (caddr_t)((uintptr_t)addr & (uintptr_t)PAGEMASK);
	initrsize = rsize = (((size_t)(addr + size) + PAGEOFFSET) & PAGEMASK) -
	    (size_t)raddr;

	if (raddr + rsize < raddr) {		/* check for wraparound */
		AS_LOCK_EXIT(as, &as->a_lock);
		return (ENOMEM);
	}

	/*
	 * Get initial segment.
	 */
	if ((seg = as_segat(as, raddr)) == NULL) {
		AS_LOCK_EXIT(as, &as->a_lock);
		return (ENOMEM);
	}

	if (func == MC_LOCK) {
		mlock_size = BT_BITOUL(btopr(rsize));
		if ((mlock_map = (ulong_t *)kmem_zalloc(mlock_size *
		    sizeof (ulong_t), KM_NOSLEEP)) == NULL) {
				AS_LOCK_EXIT(as, &as->a_lock);
				return (EAGAIN);
		}
	}

	/*
	 * Loop over all segments.  If a hole in the address range is
	 * discovered, then fail.  For each segment, perform the appropriate
	 * control operation.
	 */
	while (rsize != 0) {

		/*
		 * Make sure there's no hole, calculate the portion
		 * of the next segment to be operated over.
		 */
		if (raddr >= seg->s_base + seg->s_size) {
			seg = AS_SEGNEXT(as, seg);
			if (seg == NULL || raddr != seg->s_base) {
				if (func == MC_LOCK) {
					as_unlockerr(as, attr, mlock_map,
					    initraddr, initrsize - rsize);
					kmem_free(mlock_map,
					    mlock_size * sizeof (ulong_t));
				}
				AS_LOCK_EXIT(as, &as->a_lock);
				return (ENOMEM);
			}
		}
		if ((raddr + rsize) > (seg->s_base + seg->s_size))
			ssize = seg->s_base + seg->s_size - raddr;
		else
			ssize = rsize;

		/*
		 * Dispatch on specific function.
		 */
		switch (func) {

		/*
		 * Synchronize cached data from mappings with backing
		 * objects.
		 */
		case MC_SYNC:
			if (error = SEGOP_SYNC(seg, raddr, ssize,
			    attr, (uint_t)arg)) {
				AS_LOCK_EXIT(as, &as->a_lock);
				return (error);
			}
			break;

		/*
		 * Lock pages in memory.
		 */
		case MC_LOCK:
			if (error = SEGOP_LOCKOP(seg, raddr, ssize,
			    attr, func, mlock_map, pos)) {
				as_unlockerr(as, attr, mlock_map, initraddr,
				    initrsize - rsize + ssize);
				kmem_free(mlock_map, mlock_size *
				    sizeof (ulong_t));
				AS_LOCK_EXIT(as, &as->a_lock);
				goto lockerr;
			}
			break;

		/*
		 * Unlock mapped pages.
		 */
		case MC_UNLOCK:
			(void) SEGOP_LOCKOP(seg, raddr, ssize, attr, func,
			    (ulong_t *)NULL, (size_t)NULL);
			break;

		/*
		 * Store VM advise for mapped pages in segment layer.
		 */
		case MC_ADVISE:
			error = SEGOP_ADVISE(seg, raddr, ssize, (uint_t)arg);

			/*
			 * Check for regular errors and special retry error
			 */
			if (error) {
				if (error == IE_RETRY) {
					/*
					 * Need to acquire writers lock, so
					 * have to drop readers lock and start
					 * all over again
					 */
					AS_LOCK_EXIT(as, &as->a_lock);
					goto retry;
				} else if (error == IE_REATTACH) {
					/*
					 * Find segment for current address
					 * because current segment just got
					 * split or concatenated
					 */
					seg = as_segat(as, raddr);
					if (seg == NULL) {
						AS_LOCK_EXIT(as, &as->a_lock);
						return (ENOMEM);
					}
				} else {
					/*
					 * Regular error
					 */
					AS_LOCK_EXIT(as, &as->a_lock);
					return (error);
				}
			}
			break;

		case MC_INHERIT_ZERO:
			if (seg->s_ops->inherit == NULL) {
				error = ENOTSUP;
			} else {
				error = SEGOP_INHERIT(seg, raddr, ssize,
				    SEGP_INH_ZERO);
			}
			if (error != 0) {
				AS_LOCK_EXIT(as, &as->a_lock);
				return (error);
			}
			break;

		/*
		 * Can't happen.
		 */
		default:
			panic("as_ctl: bad operation %d", func);
			/*NOTREACHED*/
		}

		rsize -= ssize;
		raddr += ssize;
	}

	if (func == MC_LOCK)
		kmem_free(mlock_map, mlock_size * sizeof (ulong_t));
	AS_LOCK_EXIT(as, &as->a_lock);
	return (0);
lockerr:

	/*
	 * If the lower levels returned EDEADLK for a segment lockop,
	 * it means that we should retry the operation.  Let's wait
	 * a bit also to let the deadlock causing condition clear.
	 * This is part of a gross hack to work around a design flaw
	 * in the ufs/sds logging code and should go away when the
	 * logging code is re-designed to fix the problem. See bug
	 * 4125102 for details of the problem.
	 */
	if (error == EDEADLK) {
		delay(deadlk_wait);
		error = 0;
		goto retry;
	}
	return (error);
}

int
fc_decode(faultcode_t fault_err)
{
	int error = 0;

	switch (FC_CODE(fault_err)) {
	case FC_OBJERR:
		error = FC_ERRNO(fault_err);
		break;
	case FC_PROT:
		error = EACCES;
		break;
	default:
		error = EFAULT;
		break;
	}
	return (error);
}

/*
 * Pagelock pages from a range that spans more than 1 segment.  Obtain shadow
 * lists from each segment and copy them to one contiguous shadow list (plist)
 * as expected by the caller.  Save pointers to per segment shadow lists at
 * the tail of plist so that they can be used during as_pageunlock().
 */
static int
as_pagelock_segs(struct as *as, struct seg *seg, struct page ***ppp,
    caddr_t addr, size_t size, enum seg_rw rw)
{
	caddr_t sv_addr = addr;
	size_t sv_size = size;
	struct seg *sv_seg = seg;
	ulong_t segcnt = 1;
	ulong_t cnt;
	size_t ssize;
	pgcnt_t npages = btop(size);
	page_t **plist;
	page_t **pl;
	int error;
	caddr_t eaddr;
	faultcode_t fault_err = 0;
	pgcnt_t pl_off;
	extern struct seg_ops segspt_shmops;

	ASSERT(AS_LOCK_HELD(as, &as->a_lock));
	ASSERT(seg != NULL);
	ASSERT(addr >= seg->s_base && addr < seg->s_base + seg->s_size);
	ASSERT(addr + size > seg->s_base + seg->s_size);
	ASSERT(IS_P2ALIGNED(size, PAGESIZE));
	ASSERT(IS_P2ALIGNED(addr, PAGESIZE));

	/*
	 * Count the number of segments covered by the range we are about to
	 * lock. The segment count is used to size the shadow list we return
	 * back to the caller.
	 */
	for (; size != 0; size -= ssize, addr += ssize) {
		if (addr >= seg->s_base + seg->s_size) {

			seg = AS_SEGNEXT(as, seg);
			if (seg == NULL || addr != seg->s_base) {
				AS_LOCK_EXIT(as, &as->a_lock);
				return (EFAULT);
			}
			/*
			 * Do a quick check if subsequent segments
			 * will most likely support pagelock.
			 */
			if (seg->s_ops == &segvn_ops) {
				vnode_t *vp;

				if (SEGOP_GETVP(seg, addr, &vp) != 0 ||
				    vp != NULL) {
					AS_LOCK_EXIT(as, &as->a_lock);
					goto slow;
				}
			} else if (seg->s_ops != &segspt_shmops) {
				AS_LOCK_EXIT(as, &as->a_lock);
				goto slow;
			}
			segcnt++;
		}
		if (addr + size > seg->s_base + seg->s_size) {
			ssize = seg->s_base + seg->s_size - addr;
		} else {
			ssize = size;
		}
	}
	ASSERT(segcnt > 1);

	plist = kmem_zalloc((npages + segcnt) * sizeof (page_t *), KM_SLEEP);

	addr = sv_addr;
	size = sv_size;
	seg = sv_seg;

	for (cnt = 0, pl_off = 0; size != 0; size -= ssize, addr += ssize) {
		if (addr >= seg->s_base + seg->s_size) {
			seg = AS_SEGNEXT(as, seg);
			ASSERT(seg != NULL && addr == seg->s_base);
			cnt++;
			ASSERT(cnt < segcnt);
		}
		if (addr + size > seg->s_base + seg->s_size) {
			ssize = seg->s_base + seg->s_size - addr;
		} else {
			ssize = size;
		}
		pl = &plist[npages + cnt];
		error = SEGOP_PAGELOCK(seg, addr, ssize, (page_t ***)pl,
		    L_PAGELOCK, rw);
		if (error) {
			break;
		}
		ASSERT(plist[npages + cnt] != NULL);
		ASSERT(pl_off + btop(ssize) <= npages);
		bcopy(plist[npages + cnt], &plist[pl_off],
		    btop(ssize) * sizeof (page_t *));
		pl_off += btop(ssize);
	}

	if (size == 0) {
		AS_LOCK_EXIT(as, &as->a_lock);
		ASSERT(cnt == segcnt - 1);
		*ppp = plist;
		return (0);
	}

	/*
	 * one of pagelock calls failed. The error type is in error variable.
	 * Unlock what we've locked so far and retry with F_SOFTLOCK if error
	 * type is either EFAULT or ENOTSUP. Otherwise just return the error
	 * back to the caller.
	 */

	eaddr = addr;
	seg = sv_seg;

	for (cnt = 0, addr = sv_addr; addr < eaddr; addr += ssize) {
		if (addr >= seg->s_base + seg->s_size) {
			seg = AS_SEGNEXT(as, seg);
			ASSERT(seg != NULL && addr == seg->s_base);
			cnt++;
			ASSERT(cnt < segcnt);
		}
		if (eaddr > seg->s_base + seg->s_size) {
			ssize = seg->s_base + seg->s_size - addr;
		} else {
			ssize = eaddr - addr;
		}
		pl = &plist[npages + cnt];
		ASSERT(*pl != NULL);
		(void) SEGOP_PAGELOCK(seg, addr, ssize, (page_t ***)pl,
		    L_PAGEUNLOCK, rw);
	}

	AS_LOCK_EXIT(as, &as->a_lock);

	kmem_free(plist, (npages + segcnt) * sizeof (page_t *));

	if (error != ENOTSUP && error != EFAULT) {
		return (error);
	}

slow:
	/*
	 * If we are here because pagelock failed due to the need to cow fault
	 * in the pages we want to lock F_SOFTLOCK will do this job and in
	 * next as_pagelock() call for this address range pagelock will
	 * hopefully succeed.
	 */
	fault_err = as_fault(as->a_hat, as, sv_addr, sv_size, F_SOFTLOCK, rw);
	if (fault_err != 0) {
		return (fc_decode(fault_err));
	}
	*ppp = NULL;

	return (0);
}

/*
 * lock pages in a given address space. Return shadow list. If
 * the list is NULL, the MMU mapping is also locked.
 */
int
as_pagelock(struct as *as, struct page ***ppp, caddr_t addr,
    size_t size, enum seg_rw rw)
{
	size_t rsize;
	caddr_t raddr;
	faultcode_t fault_err;
	struct seg *seg;
	int err;

	TRACE_2(TR_FAC_PHYSIO, TR_PHYSIO_AS_LOCK_START,
	    "as_pagelock_start: addr %p size %ld", addr, size);

	raddr = (caddr_t)((uintptr_t)addr & (uintptr_t)PAGEMASK);
	rsize = (((size_t)(addr + size) + PAGEOFFSET) & PAGEMASK) -
	    (size_t)raddr;

	/*
	 * if the request crosses two segments let
	 * as_fault handle it.
	 */
	AS_LOCK_ENTER(as, &as->a_lock, RW_READER);

	seg = as_segat(as, raddr);
	if (seg == NULL) {
		AS_LOCK_EXIT(as, &as->a_lock);
		return (EFAULT);
	}
	ASSERT(raddr >= seg->s_base && raddr < seg->s_base + seg->s_size);
	if (raddr + rsize > seg->s_base + seg->s_size) {
		return (as_pagelock_segs(as, seg, ppp, raddr, rsize, rw));
	}
	if (raddr + rsize <= raddr) {
		AS_LOCK_EXIT(as, &as->a_lock);
		return (EFAULT);
	}

	TRACE_2(TR_FAC_PHYSIO, TR_PHYSIO_SEG_LOCK_START,
	    "seg_lock_1_start: raddr %p rsize %ld", raddr, rsize);

	/*
	 * try to lock pages and pass back shadow list
	 */
	err = SEGOP_PAGELOCK(seg, raddr, rsize, ppp, L_PAGELOCK, rw);

	TRACE_0(TR_FAC_PHYSIO, TR_PHYSIO_SEG_LOCK_END, "seg_lock_1_end");

	AS_LOCK_EXIT(as, &as->a_lock);

	if (err == 0 || (err != ENOTSUP && err != EFAULT)) {
		return (err);
	}

	/*
	 * Use F_SOFTLOCK to lock the pages because pagelock failed either due
	 * to no pagelock support for this segment or pages need to be cow
	 * faulted in. If fault is needed F_SOFTLOCK will do this job for
	 * this as_pagelock() call and in the next as_pagelock() call for the
	 * same address range pagelock call will hopefull succeed.
	 */
	fault_err = as_fault(as->a_hat, as, addr, size, F_SOFTLOCK, rw);
	if (fault_err != 0) {
		return (fc_decode(fault_err));
	}
	*ppp = NULL;

	TRACE_0(TR_FAC_PHYSIO, TR_PHYSIO_AS_LOCK_END, "as_pagelock_end");
	return (0);
}

/*
 * unlock pages locked by as_pagelock_segs().  Retrieve per segment shadow
 * lists from the end of plist and call pageunlock interface for each segment.
 * Drop as lock and free plist.
 */
static void
as_pageunlock_segs(struct as *as, struct seg *seg, caddr_t addr, size_t size,
    struct page **plist, enum seg_rw rw)
{
	ulong_t cnt;
	caddr_t eaddr = addr + size;
	pgcnt_t npages = btop(size);
	size_t ssize;
	page_t **pl;

	ASSERT(AS_LOCK_HELD(as, &as->a_lock));
	ASSERT(seg != NULL);
	ASSERT(addr >= seg->s_base && addr < seg->s_base + seg->s_size);
	ASSERT(addr + size > seg->s_base + seg->s_size);
	ASSERT(IS_P2ALIGNED(size, PAGESIZE));
	ASSERT(IS_P2ALIGNED(addr, PAGESIZE));
	ASSERT(plist != NULL);

	for (cnt = 0; addr < eaddr; addr += ssize) {
		if (addr >= seg->s_base + seg->s_size) {
			seg = AS_SEGNEXT(as, seg);
			ASSERT(seg != NULL && addr == seg->s_base);
			cnt++;
		}
		if (eaddr > seg->s_base + seg->s_size) {
			ssize = seg->s_base + seg->s_size - addr;
		} else {
			ssize = eaddr - addr;
		}
		pl = &plist[npages + cnt];
		ASSERT(*pl != NULL);
		(void) SEGOP_PAGELOCK(seg, addr, ssize, (page_t ***)pl,
		    L_PAGEUNLOCK, rw);
	}
	ASSERT(cnt > 0);
	AS_LOCK_EXIT(as, &as->a_lock);

	cnt++;
	kmem_free(plist, (npages + cnt) * sizeof (page_t *));
}

/*
 * unlock pages in a given address range
 */
void
as_pageunlock(struct as *as, struct page **pp, caddr_t addr, size_t size,
    enum seg_rw rw)
{
	struct seg *seg;
	size_t rsize;
	caddr_t raddr;

	TRACE_2(TR_FAC_PHYSIO, TR_PHYSIO_AS_UNLOCK_START,
	    "as_pageunlock_start: addr %p size %ld", addr, size);

	/*
	 * if the shadow list is NULL, as_pagelock was
	 * falling back to as_fault
	 */
	if (pp == NULL) {
		(void) as_fault(as->a_hat, as, addr, size, F_SOFTUNLOCK, rw);
		return;
	}

	raddr = (caddr_t)((uintptr_t)addr & (uintptr_t)PAGEMASK);
	rsize = (((size_t)(addr + size) + PAGEOFFSET) & PAGEMASK) -
	    (size_t)raddr;

	AS_LOCK_ENTER(as, &as->a_lock, RW_READER);
	seg = as_segat(as, raddr);
	ASSERT(seg != NULL);

	TRACE_2(TR_FAC_PHYSIO, TR_PHYSIO_SEG_UNLOCK_START,
	    "seg_unlock_start: raddr %p rsize %ld", raddr, rsize);

	ASSERT(raddr >= seg->s_base && raddr < seg->s_base + seg->s_size);
	if (raddr + rsize <= seg->s_base + seg->s_size) {
		SEGOP_PAGELOCK(seg, raddr, rsize, &pp, L_PAGEUNLOCK, rw);
	} else {
		as_pageunlock_segs(as, seg, raddr, rsize, pp, rw);
		return;
	}
	AS_LOCK_EXIT(as, &as->a_lock);
	TRACE_0(TR_FAC_PHYSIO, TR_PHYSIO_AS_UNLOCK_END, "as_pageunlock_end");
}

int
as_setpagesize(struct as *as, caddr_t addr, size_t size, uint_t szc,
    boolean_t wait)
{
	struct seg *seg;
	size_t ssize;
	caddr_t raddr;			/* rounded down addr */
	size_t rsize;			/* rounded up size */
	int error = 0;
	size_t pgsz = page_get_pagesize(szc);

setpgsz_top:
	if (!IS_P2ALIGNED(addr, pgsz) || !IS_P2ALIGNED(size, pgsz)) {
		return (EINVAL);
	}

	raddr = addr;
	rsize = size;

	if (raddr + rsize < raddr)		/* check for wraparound */
		return (ENOMEM);

	AS_LOCK_ENTER(as, &as->a_lock, RW_WRITER);
	as_clearwatchprot(as, raddr, rsize);
	seg = as_segat(as, raddr);
	if (seg == NULL) {
		as_setwatch(as);
		AS_LOCK_EXIT(as, &as->a_lock);
		return (ENOMEM);
	}

	for (; rsize != 0; rsize -= ssize, raddr += ssize) {
		if (raddr >= seg->s_base + seg->s_size) {
			seg = AS_SEGNEXT(as, seg);
			if (seg == NULL || raddr != seg->s_base) {
				error = ENOMEM;
				break;
			}
		}
		if ((raddr + rsize) > (seg->s_base + seg->s_size)) {
			ssize = seg->s_base + seg->s_size - raddr;
		} else {
			ssize = rsize;
		}

retry:
		error = SEGOP_SETPAGESIZE(seg, raddr, ssize, szc);

		if (error == IE_NOMEM) {
			error = EAGAIN;
			break;
		}

		if (error == IE_RETRY) {
			AS_LOCK_EXIT(as, &as->a_lock);
			goto setpgsz_top;
		}

		if (error == ENOTSUP) {
			error = EINVAL;
			break;
		}

		if (wait && (error == EAGAIN)) {
			/*
			 * Memory is currently locked.  It must be unlocked
			 * before this operation can succeed through a retry.
			 * The possible reasons for locked memory and
			 * corresponding strategies for unlocking are:
			 * (1) Normal I/O
			 *	wait for a signal that the I/O operation
			 *	has completed and the memory is unlocked.
			 * (2) Asynchronous I/O
			 *	The aio subsystem does not unlock pages when
			 *	the I/O is completed. Those pages are unlocked
			 *	when the application calls aiowait/aioerror.
			 *	So, to prevent blocking forever, cv_broadcast()
			 *	is done to wake up aio_cleanup_thread.
			 *	Subsequently, segvn_reclaim will be called, and
			 *	that will do AS_CLRUNMAPWAIT() and wake us up.
			 * (3) Long term page locking:
			 *	This is not relevant for as_setpagesize()
			 *	because we cannot change the page size for
			 *	driver memory. The attempt to do so will
			 *	fail with a different error than EAGAIN so
			 *	there's no need to trigger as callbacks like
			 *	as_unmap, as_setprot or as_free would do.
			 */
			mutex_enter(&as->a_contents);
			if (!AS_ISNOUNMAPWAIT(as)) {
				if (AS_ISUNMAPWAIT(as) == 0) {
					cv_broadcast(&as->a_cv);
				}
				AS_SETUNMAPWAIT(as);
				AS_LOCK_EXIT(as, &as->a_lock);
				while (AS_ISUNMAPWAIT(as)) {
					cv_wait(&as->a_cv, &as->a_contents);
				}
			} else {
				/*
				 * We may have raced with
				 * segvn_reclaim()/segspt_reclaim(). In this
				 * case clean nounmapwait flag and retry since
				 * softlockcnt in this segment may be already
				 * 0.  We don't drop as writer lock so our
				 * number of retries without sleeping should
				 * be very small. See segvn_reclaim() for
				 * more comments.
				 */
				AS_CLRNOUNMAPWAIT(as);
				mutex_exit(&as->a_contents);
				goto retry;
			}
			mutex_exit(&as->a_contents);
			goto setpgsz_top;
		} else if (error != 0) {
			break;
		}
	}
	as_setwatch(as);
	AS_LOCK_EXIT(as, &as->a_lock);
	return (error);
}

/*
 * as_iset3_default_lpsize() just calls SEGOP_SETPAGESIZE() on all segments
 * in its chunk where s_szc is less than the szc we want to set.
 */
static int
as_iset3_default_lpsize(struct as *as, caddr_t raddr, size_t rsize, uint_t szc,
    int *retry)
{
	struct seg *seg;
	size_t ssize;
	int error;

	ASSERT(AS_WRITE_HELD(as, &as->a_lock));

	seg = as_segat(as, raddr);
	if (seg == NULL) {
		panic("as_iset3_default_lpsize: no seg");
	}

	for (; rsize != 0; rsize -= ssize, raddr += ssize) {
		if (raddr >= seg->s_base + seg->s_size) {
			seg = AS_SEGNEXT(as, seg);
			if (seg == NULL || raddr != seg->s_base) {
				panic("as_iset3_default_lpsize: as changed");
			}
		}
		if ((raddr + rsize) > (seg->s_base + seg->s_size)) {
			ssize = seg->s_base + seg->s_size - raddr;
		} else {
			ssize = rsize;
		}

		if (szc > seg->s_szc) {
			error = SEGOP_SETPAGESIZE(seg, raddr, ssize, szc);
			/* Only retry on EINVAL segments that have no vnode. */
			if (error == EINVAL) {
				vnode_t *vp = NULL;
				if ((SEGOP_GETTYPE(seg, raddr) & MAP_SHARED) &&
				    (SEGOP_GETVP(seg, raddr, &vp) != 0 ||
				    vp == NULL)) {
					*retry = 1;
				} else {
					*retry = 0;
				}
			}
			if (error) {
				return (error);
			}
		}
	}
	return (0);
}

/*
 * as_iset2_default_lpsize() calls as_iset3_default_lpsize() to set the
 * pagesize on each segment in its range, but if any fails with EINVAL,
 * then it reduces the pagesizes to the next size in the bitmap and
 * retries as_iset3_default_lpsize(). The reason why the code retries
 * smaller allowed sizes on EINVAL is because (a) the anon offset may not
 * match the bigger sizes, and (b) it's hard to get this offset (to begin
 * with) to pass to map_pgszcvec().
 */
static int
as_iset2_default_lpsize(struct as *as, caddr_t addr, size_t size, uint_t szc,
    uint_t szcvec)
{
	int error;
	int retry;

	ASSERT(AS_WRITE_HELD(as, &as->a_lock));

	for (;;) {
		error = as_iset3_default_lpsize(as, addr, size, szc, &retry);
		if (error == EINVAL && retry) {
			szcvec &= ~(1 << szc);
			if (szcvec <= 1) {
				return (EINVAL);
			}
			szc = highbit(szcvec) - 1;
		} else {
			return (error);
		}
	}
}

/*
 * as_iset1_default_lpsize() breaks its chunk into areas where existing
 * segments have a smaller szc than we want to set. For each such area,
 * it calls as_iset2_default_lpsize()
 */
static int
as_iset1_default_lpsize(struct as *as, caddr_t raddr, size_t rsize, uint_t szc,
    uint_t szcvec)
{
	struct seg *seg;
	size_t ssize;
	caddr_t setaddr = raddr;
	size_t setsize = 0;
	int set;
	int error;

	ASSERT(AS_WRITE_HELD(as, &as->a_lock));

	seg = as_segat(as, raddr);
	if (seg == NULL) {
		panic("as_iset1_default_lpsize: no seg");
	}
	if (seg->s_szc < szc) {
		set = 1;
	} else {
		set = 0;
	}

	for (; rsize != 0; rsize -= ssize, raddr += ssize, setsize += ssize) {
		if (raddr >= seg->s_base + seg->s_size) {
			seg = AS_SEGNEXT(as, seg);
			if (seg == NULL || raddr != seg->s_base) {
				panic("as_iset1_default_lpsize: as changed");
			}
			if (seg->s_szc >= szc && set) {
				ASSERT(setsize != 0);
				error = as_iset2_default_lpsize(as,
				    setaddr, setsize, szc, szcvec);
				if (error) {
					return (error);
				}
				set = 0;
			} else if (seg->s_szc < szc && !set) {
				setaddr = raddr;
				setsize = 0;
				set = 1;
			}
		}
		if ((raddr + rsize) > (seg->s_base + seg->s_size)) {
			ssize = seg->s_base + seg->s_size - raddr;
		} else {
			ssize = rsize;
		}
	}
	error = 0;
	if (set) {
		ASSERT(setsize != 0);
		error = as_iset2_default_lpsize(as, setaddr, setsize,
		    szc, szcvec);
	}
	return (error);
}

/*
 * as_iset_default_lpsize() breaks its chunk according to the size code bitmap
 * returned by map_pgszcvec() (similar to as_map_segvn_segs()), and passes each
 * chunk to as_iset1_default_lpsize().
 */
static int
as_iset_default_lpsize(struct as *as, caddr_t addr, size_t size, int flags,
    int type)
{
	int rtype = (type & MAP_SHARED) ? MAPPGSZC_SHM : MAPPGSZC_PRIVM;
	uint_t szcvec = map_pgszcvec(addr, size, (uintptr_t)addr,
	    flags, rtype, 1);
	uint_t szc;
	uint_t nszc;
	int error;
	caddr_t a;
	caddr_t eaddr;
	size_t segsize;
	size_t pgsz;
	uint_t save_szcvec;

	ASSERT(AS_WRITE_HELD(as, &as->a_lock));
	ASSERT(IS_P2ALIGNED(addr, PAGESIZE));
	ASSERT(IS_P2ALIGNED(size, PAGESIZE));

	szcvec &= ~1;
	if (szcvec <= 1) {	/* skip if base page size */
		return (0);
	}

	/* Get the pagesize of the first larger page size. */
	szc = lowbit(szcvec) - 1;
	pgsz = page_get_pagesize(szc);
	eaddr = addr + size;
	addr = (caddr_t)P2ROUNDUP((uintptr_t)addr, pgsz);
	eaddr = (caddr_t)P2ALIGN((uintptr_t)eaddr, pgsz);

	save_szcvec = szcvec;
	szcvec >>= (szc + 1);
	nszc = szc;
	while (szcvec) {
		if ((szcvec & 0x1) == 0) {
			nszc++;
			szcvec >>= 1;
			continue;
		}
		nszc++;
		pgsz = page_get_pagesize(nszc);
		a = (caddr_t)P2ROUNDUP((uintptr_t)addr, pgsz);
		if (a != addr) {
			ASSERT(szc > 0);
			ASSERT(a < eaddr);
			segsize = a - addr;
			error = as_iset1_default_lpsize(as, addr, segsize, szc,
			    save_szcvec);
			if (error) {
				return (error);
			}
			addr = a;
		}
		szc = nszc;
		szcvec >>= 1;
	}

	ASSERT(addr < eaddr);
	szcvec = save_szcvec;
	while (szcvec) {
		a = (caddr_t)P2ALIGN((uintptr_t)eaddr, pgsz);
		ASSERT(a >= addr);
		if (a != addr) {
			ASSERT(szc > 0);
			segsize = a - addr;
			error = as_iset1_default_lpsize(as, addr, segsize, szc,
			    save_szcvec);
			if (error) {
				return (error);
			}
			addr = a;
		}
		szcvec &= ~(1 << szc);
		if (szcvec) {
			szc = highbit(szcvec) - 1;
			pgsz = page_get_pagesize(szc);
		}
	}
	ASSERT(addr == eaddr);

	return (0);
}

/*
 * Set the default large page size for the range. Called via memcntl with
 * page size set to 0. as_set_default_lpsize breaks the range down into
 * chunks with the same type/flags, ignores-non segvn segments, and passes
 * each chunk to as_iset_default_lpsize().
 */
int
as_set_default_lpsize(struct as *as, caddr_t addr, size_t size)
{
	struct seg *seg;
	caddr_t raddr;
	size_t rsize;
	size_t ssize;
	int rtype, rflags;
	int stype, sflags;
	int error;
	caddr_t	setaddr;
	size_t setsize;
	int segvn;

	if (size == 0)
		return (0);

	AS_LOCK_ENTER(as, &as->a_lock, RW_WRITER);
again:
	error = 0;

	raddr = (caddr_t)((uintptr_t)addr & (uintptr_t)PAGEMASK);
	rsize = (((size_t)(addr + size) + PAGEOFFSET) & PAGEMASK) -
	    (size_t)raddr;

	if (raddr + rsize < raddr) {		/* check for wraparound */
		AS_LOCK_EXIT(as, &as->a_lock);
		return (ENOMEM);
	}
	as_clearwatchprot(as, raddr, rsize);
	seg = as_segat(as, raddr);
	if (seg == NULL) {
		as_setwatch(as);
		AS_LOCK_EXIT(as, &as->a_lock);
		return (ENOMEM);
	}
	if (seg->s_ops == &segvn_ops) {
		rtype = SEGOP_GETTYPE(seg, addr);
		rflags = rtype & (MAP_TEXT | MAP_INITDATA);
		rtype = rtype & (MAP_SHARED | MAP_PRIVATE);
		segvn = 1;
	} else {
		segvn = 0;
	}
	setaddr = raddr;
	setsize = 0;

	for (; rsize != 0; rsize -= ssize, raddr += ssize, setsize += ssize) {
		if (raddr >= (seg->s_base + seg->s_size)) {
			seg = AS_SEGNEXT(as, seg);
			if (seg == NULL || raddr != seg->s_base) {
				error = ENOMEM;
				break;
			}
			if (seg->s_ops == &segvn_ops) {
				stype = SEGOP_GETTYPE(seg, raddr);
				sflags = stype & (MAP_TEXT | MAP_INITDATA);
				stype &= (MAP_SHARED | MAP_PRIVATE);
				if (segvn && (rflags != sflags ||
				    rtype != stype)) {
					/*
					 * The next segment is also segvn but
					 * has different flags and/or type.
					 */
					ASSERT(setsize != 0);
					error = as_iset_default_lpsize(as,
					    setaddr, setsize, rflags, rtype);
					if (error) {
						break;
					}
					rflags = sflags;
					rtype = stype;
					setaddr = raddr;
					setsize = 0;
				} else if (!segvn) {
					rflags = sflags;
					rtype = stype;
					setaddr = raddr;
					setsize = 0;
					segvn = 1;
				}
			} else if (segvn) {
				/* The next segment is not segvn. */
				ASSERT(setsize != 0);
				error = as_iset_default_lpsize(as,
				    setaddr, setsize, rflags, rtype);
				if (error) {
					break;
				}
				segvn = 0;
			}
		}
		if ((raddr + rsize) > (seg->s_base + seg->s_size)) {
			ssize = seg->s_base + seg->s_size - raddr;
		} else {
			ssize = rsize;
		}
	}
	if (error == 0 && segvn) {
		/* The last chunk when rsize == 0. */
		ASSERT(setsize != 0);
		error = as_iset_default_lpsize(as, setaddr, setsize,
		    rflags, rtype);
	}

	if (error == IE_RETRY) {
		goto again;
	} else if (error == IE_NOMEM) {
		error = EAGAIN;
	} else if (error == ENOTSUP) {
		error = EINVAL;
	} else if (error == EAGAIN) {
		mutex_enter(&as->a_contents);
		if (!AS_ISNOUNMAPWAIT(as)) {
			if (AS_ISUNMAPWAIT(as) == 0) {
				cv_broadcast(&as->a_cv);
			}
			AS_SETUNMAPWAIT(as);
			AS_LOCK_EXIT(as, &as->a_lock);
			while (AS_ISUNMAPWAIT(as)) {
				cv_wait(&as->a_cv, &as->a_contents);
			}
			mutex_exit(&as->a_contents);
			AS_LOCK_ENTER(as, &as->a_lock, RW_WRITER);
		} else {
			/*
			 * We may have raced with
			 * segvn_reclaim()/segspt_reclaim(). In this case
			 * clean nounmapwait flag and retry since softlockcnt
			 * in this segment may be already 0.  We don't drop as
			 * writer lock so our number of retries without
			 * sleeping should be very small. See segvn_reclaim()
			 * for more comments.
			 */
			AS_CLRNOUNMAPWAIT(as);
			mutex_exit(&as->a_contents);
		}
		goto again;
	}

	as_setwatch(as);
	AS_LOCK_EXIT(as, &as->a_lock);
	return (error);
}

/*
 * Setup all of the uninitialized watched pages that we can.
 */
void
as_setwatch(struct as *as)
{
	struct watched_page *pwp;
	struct seg *seg;
	caddr_t vaddr;
	uint_t prot;
	int  err, retrycnt;

	if (avl_numnodes(&as->a_wpage) == 0)
		return;

	ASSERT(AS_WRITE_HELD(as, &as->a_lock));

	for (pwp = avl_first(&as->a_wpage); pwp != NULL;
	    pwp = AVL_NEXT(&as->a_wpage, pwp)) {
		retrycnt = 0;
	retry:
		vaddr = pwp->wp_vaddr;
		if (pwp->wp_oprot != 0 ||	/* already set up */
		    (seg = as_segat(as, vaddr)) == NULL ||
		    SEGOP_GETPROT(seg, vaddr, 0, &prot) != 0)
			continue;

		pwp->wp_oprot = prot;
		if (pwp->wp_read)
			prot &= ~(PROT_READ|PROT_WRITE|PROT_EXEC);
		if (pwp->wp_write)
			prot &= ~PROT_WRITE;
		if (pwp->wp_exec)
			prot &= ~(PROT_READ|PROT_WRITE|PROT_EXEC);
		if (!(pwp->wp_flags & WP_NOWATCH) && prot != pwp->wp_oprot) {
			err = SEGOP_SETPROT(seg, vaddr, PAGESIZE, prot);
			if (err == IE_RETRY) {
				pwp->wp_oprot = 0;
				ASSERT(retrycnt == 0);
				retrycnt++;
				goto retry;
			}
		}
		pwp->wp_prot = prot;
	}
}

/*
 * Clear all of the watched pages in the address space.
 */
void
as_clearwatch(struct as *as)
{
	struct watched_page *pwp;
	struct seg *seg;
	caddr_t vaddr;
	uint_t prot;
	int err, retrycnt;

	if (avl_numnodes(&as->a_wpage) == 0)
		return;

	ASSERT(AS_WRITE_HELD(as, &as->a_lock));

	for (pwp = avl_first(&as->a_wpage); pwp != NULL;
	    pwp = AVL_NEXT(&as->a_wpage, pwp)) {
		retrycnt = 0;
	retry:
		vaddr = pwp->wp_vaddr;
		if (pwp->wp_oprot == 0 ||	/* not set up */
		    (seg = as_segat(as, vaddr)) == NULL)
			continue;

		if ((prot = pwp->wp_oprot) != pwp->wp_prot) {
			err = SEGOP_SETPROT(seg, vaddr, PAGESIZE, prot);
			if (err == IE_RETRY) {
				ASSERT(retrycnt == 0);
				retrycnt++;
				goto retry;
			}
		}
		pwp->wp_oprot = 0;
		pwp->wp_prot = 0;
	}
}

/*
 * Force a new setup for all the watched pages in the range.
 */
static void
as_setwatchprot(struct as *as, caddr_t addr, size_t size, uint_t prot)
{
	struct watched_page *pwp;
	struct watched_page tpw;
	caddr_t eaddr = addr + size;
	caddr_t vaddr;
	struct seg *seg;
	int err, retrycnt;
	uint_t	wprot;
	avl_index_t where;

	if (avl_numnodes(&as->a_wpage) == 0)
		return;

	ASSERT(AS_WRITE_HELD(as, &as->a_lock));

	tpw.wp_vaddr = (caddr_t)((uintptr_t)addr & (uintptr_t)PAGEMASK);
	if ((pwp = avl_find(&as->a_wpage, &tpw, &where)) == NULL)
		pwp = avl_nearest(&as->a_wpage, where, AVL_AFTER);

	while (pwp != NULL && pwp->wp_vaddr < eaddr) {
		retrycnt = 0;
		vaddr = pwp->wp_vaddr;

		wprot = prot;
		if (pwp->wp_read)
			wprot &= ~(PROT_READ|PROT_WRITE|PROT_EXEC);
		if (pwp->wp_write)
			wprot &= ~PROT_WRITE;
		if (pwp->wp_exec)
			wprot &= ~(PROT_READ|PROT_WRITE|PROT_EXEC);
		if (!(pwp->wp_flags & WP_NOWATCH) && wprot != pwp->wp_oprot) {
		retry:
			seg = as_segat(as, vaddr);
			if (seg == NULL) {
				panic("as_setwatchprot: no seg");
				/*NOTREACHED*/
			}
			err = SEGOP_SETPROT(seg, vaddr, PAGESIZE, wprot);
			if (err == IE_RETRY) {
				ASSERT(retrycnt == 0);
				retrycnt++;
				goto retry;
			}
		}
		pwp->wp_oprot = prot;
		pwp->wp_prot = wprot;

		pwp = AVL_NEXT(&as->a_wpage, pwp);
	}
}

/*
 * Clear all of the watched pages in the range.
 */
static void
as_clearwatchprot(struct as *as, caddr_t addr, size_t size)
{
	caddr_t eaddr = addr + size;
	struct watched_page *pwp;
	struct watched_page tpw;
	uint_t prot;
	struct seg *seg;
	int err, retrycnt;
	avl_index_t where;

	if (avl_numnodes(&as->a_wpage) == 0)
		return;

	tpw.wp_vaddr = (caddr_t)((uintptr_t)addr & (uintptr_t)PAGEMASK);
	if ((pwp = avl_find(&as->a_wpage, &tpw, &where)) == NULL)
		pwp = avl_nearest(&as->a_wpage, where, AVL_AFTER);

	ASSERT(AS_WRITE_HELD(as, &as->a_lock));

	while (pwp != NULL && pwp->wp_vaddr < eaddr) {

		if ((prot = pwp->wp_oprot) != 0) {
			retrycnt = 0;

			if (prot != pwp->wp_prot) {
			retry:
				seg = as_segat(as, pwp->wp_vaddr);
				if (seg == NULL)
					continue;
				err = SEGOP_SETPROT(seg, pwp->wp_vaddr,
				    PAGESIZE, prot);
				if (err == IE_RETRY) {
					ASSERT(retrycnt == 0);
					retrycnt++;
					goto retry;

				}
			}
			pwp->wp_oprot = 0;
			pwp->wp_prot = 0;
		}

		pwp = AVL_NEXT(&as->a_wpage, pwp);
	}
}

void
as_signal_proc(struct as *as, k_siginfo_t *siginfo)
{
	struct proc *p;

	mutex_enter(&pidlock);
	for (p = practive; p; p = p->p_next) {
		if (p->p_as == as) {
			mutex_enter(&p->p_lock);
			if (p->p_as == as)
				sigaddq(p, NULL, siginfo, KM_NOSLEEP);
			mutex_exit(&p->p_lock);
		}
	}
	mutex_exit(&pidlock);
}

/*
 * return memory object ID
 */
int
as_getmemid(struct as *as, caddr_t addr, memid_t *memidp)
{
	struct seg	*seg;
	int		sts;

	AS_LOCK_ENTER(as, &as->a_lock, RW_READER);
	seg = as_segat(as, addr);
	if (seg == NULL) {
		AS_LOCK_EXIT(as, &as->a_lock);
		return (EFAULT);
	}
	/*
	 * catch old drivers which may not support getmemid
	 */
	if (seg->s_ops->getmemid == NULL) {
		AS_LOCK_EXIT(as, &as->a_lock);
		return (ENODEV);
	}

	sts = SEGOP_GETMEMID(seg, addr, memidp);

	AS_LOCK_EXIT(as, &as->a_lock);
	return (sts);
}
