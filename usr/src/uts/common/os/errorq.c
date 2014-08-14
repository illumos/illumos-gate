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

/*
 * Kernel Error Queues
 *
 * A common problem when handling hardware error traps and interrupts is that
 * these errors frequently must be handled at high interrupt level, where
 * reliably producing error messages and safely examining and manipulating
 * other kernel state may not be possible.  The kernel error queue primitive is
 * a common set of routines that allow a subsystem to maintain a queue of
 * errors that can be processed by an explicit call from a safe context or by a
 * soft interrupt that fires at a specific lower interrupt level.  The queue
 * management code also ensures that if the system panics, all in-transit
 * errors are logged prior to reset.  Each queue has an associated kstat for
 * observing the number of errors dispatched and logged, and mdb(1) debugging
 * support is provided for live and post-mortem observability.
 *
 * Memory Allocation
 *
 * 	All of the queue data structures are allocated in advance as part of
 * 	the errorq_create() call.  No additional memory allocations are
 * 	performed as part of errorq_dispatch(), errorq_reserve(),
 *	errorq_commit() or errorq_drain().  This design
 * 	facilitates reliable error queue processing even when the system is low
 * 	on memory, and ensures that errorq_dispatch() can be called from any
 * 	context.  When the queue is created, the maximum queue length is
 * 	specified as a parameter to errorq_create() and errorq_nvcreate().  This
 *	length should represent a reasonable upper bound on the number of
 *	simultaneous errors.  If errorq_dispatch() or errorq_reserve() is
 *	invoked and no free queue elements are available, the error is
 *	dropped and will not be logged.  Typically, the queue will only be
 *	exhausted by an error storm, and in this case
 * 	the earlier errors provide the most important data for analysis.
 * 	When a new error is dispatched, the error data is copied into the
 * 	preallocated queue element so that the caller's buffer can be reused.
 *
 *	When a new error is reserved, an element is moved from the free pool
 *	and returned to the caller.  The element buffer data, eqe_data, may be
 *	managed by the caller and dispatched to the errorq by calling
 *	errorq_commit().  This is useful for additions to errorq's
 *	created with errorq_nvcreate() to handle name-value pair (nvpair) data.
 *	See below for a discussion on nvlist errorq's.
 *
 * Queue Drain Callback
 *
 *      When the error queue is drained, the caller's queue drain callback is
 *      invoked with a pointer to the saved error data.  This function may be
 *      called from passive kernel context or soft interrupt context at or
 *      below LOCK_LEVEL, or as part of panic().  As such, the callback should
 *      basically only be calling cmn_err (but NOT with the CE_PANIC flag).
 *      The callback must not call panic(), attempt to allocate memory, or wait
 *      on a condition variable.  The callback may not call errorq_destroy()
 *      or errorq_drain() on the same error queue that called it.
 *
 *      The queue drain callback will always be called for each pending error
 *      in the order in which errors were enqueued (oldest to newest).  The
 *      queue drain callback is guaranteed to provide at *least* once semantics
 *      for all errors that are successfully dispatched (i.e. for which
 *      errorq_dispatch() has successfully completed).  If an unrelated panic
 *      occurs while the queue drain callback is running on a vital queue, the
 *      panic subsystem will continue the queue drain and the callback may be
 *      invoked again for the same error.  Therefore, the callback should
 *      restrict itself to logging messages and taking other actions that are
 *      not destructive if repeated.
 *
 * Name-Value Pair Error Queues
 *
 *	During error handling, it may be more convenient to store error
 *	queue element data as a fixed buffer of name-value pairs.  The
 *	nvpair library allows construction and destruction of nvlists
 *	in pre-allocated memory buffers.
 *
 *	Error queues created via errorq_nvcreate() store queue element
 *	data as fixed buffer nvlists (ereports).  errorq_reserve()
 *	allocates an errorq element from eqp->eq_bitmap and returns a valid
 *	pointer	to a errorq_elem_t (queue element) and a pre-allocated
 *	fixed buffer nvlist.  errorq_elem_nvl() is used to gain access
 *	to the nvlist to add name-value ereport members prior to
 *	dispatching the error queue element in errorq_commit().
 *
 *	Once dispatched, the drain function will return the element to
 *	eqp->eq_bitmap and reset the associated nv_alloc structure.
 *	error_cancel() may be called to cancel an element reservation
 *	element that was never dispatched (committed).  This is useful in
 *	cases where a programming error prevents a queue element from being
 *	dispatched.
 *
 * Queue Management
 *
 *      The queue element structures and error data buffers are allocated in
 *      two contiguous chunks as part of errorq_create() or errorq_nvcreate().
 *	Each queue element structure contains a next pointer,
 *	a previous pointer, and a pointer to the corresponding error data
 *	buffer.  The data buffer for a nvlist errorq is a shared buffer
 *	for the allocation of name-value pair lists. The elements are kept on
 *      one of four lists:
 *
 *	Unused elements are kept in the free pool, managed by eqp->eq_bitmap.
 *	The eqe_prev and eqe_next pointers are not used while in the free pool
 *	and will be set to NULL.
 *
 *      Pending errors are kept on the pending list, a singly-linked list
 *      pointed to by eqp->eq_pend, and linked together using eqe_prev.  This
 *      list is maintained in order from newest error to oldest.  The eqe_next
 *      pointer is not used by the pending list and will be set to NULL.
 *
 *      The processing list is a doubly-linked list pointed to by eqp->eq_phead
 *      (the oldest element) and eqp->eq_ptail (the newest element).  The
 *      eqe_next pointer is used to traverse from eq_phead to eq_ptail, and the
 *      eqe_prev pointer is used to traverse from eq_ptail to eq_phead.  Once a
 *      queue drain operation begins, the current pending list is moved to the
 *      processing list in a two-phase commit fashion (eq_ptail being cleared
 *	at the beginning but eq_phead only at the end), allowing the panic code
 *      to always locate and process all pending errors in the event that a
 *      panic occurs in the middle of queue processing.
 *
 *	A fourth list is maintained for nvlist errorqs.  The dump list,
 *	eq_dump is used to link all errorq elements that should be stored
 *	in a crash dump file in the event of a system panic.  During
 *	errorq_panic(), the list is created and subsequently traversed
 *	in errorq_dump() during the final phases of a crash dump.
 *
 * Platform Considerations
 *
 *      In order to simplify their implementation, error queues make use of the
 *      C wrappers for compare-and-swap.  If the platform itself does not
 *      support compare-and-swap in hardware and the kernel emulation routines
 *      are used instead, then the context in which errorq_dispatch() can be
 *      safely invoked is further constrained by the implementation of the
 *      compare-and-swap emulation.  Specifically, if errorq_dispatch() is
 *      called from a code path that can be executed above ATOMIC_LEVEL on such
 *      a platform, the dispatch code could potentially deadlock unless the
 *      corresponding error interrupt is blocked or disabled prior to calling
 *      errorq_dispatch().  Error queues should therefore be deployed with
 *      caution on these platforms.
 *
 * Interfaces
 *
 * errorq_t *errorq_create(name, func, private, qlen, eltsize, ipl, flags);
 * errorq_t *errorq_nvcreate(name, func, private, qlen, eltsize, ipl, flags);
 *
 *      Create a new error queue with the specified name, callback, and
 *      properties.  A pointer to the new error queue is returned upon success,
 *      or NULL is returned to indicate that the queue could not be created.
 *      This function must be called from passive kernel context with no locks
 *      held that can prevent a sleeping memory allocation from occurring.
 *      errorq_create() will return failure if the queue kstats cannot be
 *      created, or if a soft interrupt handler cannot be registered.
 *
 *      The queue 'name' is a string that is recorded for live and post-mortem
 *      examination by a debugger.  The queue callback 'func' will be invoked
 *      for each error drained from the queue, and will receive the 'private'
 *      pointer as its first argument.  The callback must obey the rules for
 *      callbacks described above.  The queue will have maximum length 'qlen'
 *      and each element will be able to record up to 'eltsize' bytes of data.
 *      The queue's soft interrupt (see errorq_dispatch(), below) will fire
 *      at 'ipl', which should not exceed LOCK_LEVEL.  The queue 'flags' may
 *      include the following flag:
 *
 *      ERRORQ_VITAL    - This queue contains information that is considered
 *         vital to problem diagnosis.  Error queues that are marked vital will
 *         be automatically drained by the panic subsystem prior to printing
 *         the panic messages to the console.
 *
 * void errorq_destroy(errorq);
 *
 *      Destroy the specified error queue.  The queue is drained of any
 *      pending elements and these are logged before errorq_destroy returns.
 *      Once errorq_destroy() begins draining the queue, any simultaneous
 *      calls to dispatch errors will result in the errors being dropped.
 *      The caller must invoke a higher-level abstraction (e.g. disabling
 *      an error interrupt) to ensure that error handling code does not
 *      attempt to dispatch errors to the queue while it is being freed.
 *
 * void errorq_dispatch(errorq, data, len, flag);
 *
 *      Attempt to enqueue the specified error data.  If a free queue element
 *      is available, the data is copied into a free element and placed on a
 *      pending list.  If no free queue element is available, the error is
 *      dropped.  The data length (len) is specified in bytes and should not
 *      exceed the queue's maximum element size.  If the data length is less
 *      than the maximum element size, the remainder of the queue element is
 *      filled with zeroes.  The flag parameter should be one of:
 *
 *      ERRORQ_ASYNC    - Schedule a soft interrupt at the previously specified
 *         IPL to asynchronously drain the queue on behalf of the caller.
 *
 *      ERRORQ_SYNC     - Do not schedule a soft interrupt to drain the queue.
 *         The caller is presumed to be calling errorq_drain() or panic() in
 *         the near future in order to drain the queue and log the error.
 *
 *      The errorq_dispatch() function may be called from any context, subject
 *      to the Platform Considerations described above.
 *
 * void errorq_drain(errorq);
 *
 *      Drain the error queue of all pending errors.  The queue's callback
 *      function is invoked for each error in order from oldest to newest.
 *      This function may be used at or below LOCK_LEVEL or from panic context.
 *
 * errorq_elem_t *errorq_reserve(errorq);
 *
 *	Reserve an error queue element for later processing and dispatching.
 *	The element is returned to the caller who may add error-specific data
 *	to element.  The element is retured to the free pool when either
 *	errorq_commit() is called and the element asynchronously processed
 *	or immediately when errorq_cancel() is called.
 *
 * void errorq_commit(errorq, errorq_elem, flag);
 *
 *	Commit an errorq element (eqep) for dispatching, see
 *	errorq_dispatch().
 *
 * void errorq_cancel(errorq, errorq_elem);
 *
 *	Cancel a pending errorq element reservation.  The errorq element is
 *	returned to the free pool upon cancelation.
 */

#include <sys/errorq_impl.h>
#include <sys/sysmacros.h>
#include <sys/machlock.h>
#include <sys/cmn_err.h>
#include <sys/atomic.h>
#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/bootconf.h>
#include <sys/spl.h>
#include <sys/dumphdr.h>
#include <sys/compress.h>
#include <sys/time.h>
#include <sys/panic.h>
#include <sys/bitmap.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>

static struct errorq_kstat errorq_kstat_template = {
	{ "dispatched", KSTAT_DATA_UINT64 },
	{ "dropped", KSTAT_DATA_UINT64 },
	{ "logged", KSTAT_DATA_UINT64 },
	{ "reserved", KSTAT_DATA_UINT64 },
	{ "reserve_fail", KSTAT_DATA_UINT64 },
	{ "committed", KSTAT_DATA_UINT64 },
	{ "commit_fail", KSTAT_DATA_UINT64 },
	{ "cancelled", KSTAT_DATA_UINT64 }
};

static uint64_t errorq_lost = 0;
static errorq_t *errorq_list = NULL;
static kmutex_t errorq_lock;
static uint64_t errorq_vitalmin = 5;

static uint_t
errorq_intr(caddr_t eqp)
{
	errorq_drain((errorq_t *)eqp);
	return (DDI_INTR_CLAIMED);
}

/*
 * Create a new error queue with the specified properties and add a software
 * interrupt handler and kstat for it.  This function must be called from
 * passive kernel context with no locks held that can prevent a sleeping
 * memory allocation from occurring.  This function will return NULL if the
 * softint or kstat for this queue cannot be created.
 */
errorq_t *
errorq_create(const char *name, errorq_func_t func, void *private,
    ulong_t qlen, size_t size, uint_t ipl, uint_t flags)
{
	errorq_t *eqp = kmem_alloc(sizeof (errorq_t), KM_SLEEP);
	ddi_iblock_cookie_t ibc = (ddi_iblock_cookie_t)(uintptr_t)ipltospl(ipl);
	dev_info_t *dip = ddi_root_node();

	errorq_elem_t *eep;
	ddi_softintr_t id = NULL;
	caddr_t data;

	ASSERT(qlen != 0 && size != 0);
	ASSERT(ipl > 0 && ipl <= LOCK_LEVEL);

	/*
	 * If a queue is created very early in boot before device tree services
	 * are available, the queue softint handler cannot be created.  We
	 * manually drain these queues and create their softint handlers when
	 * it is safe to do so as part of errorq_init(), below.
	 */
	if (modrootloaded && ddi_add_softintr(dip, DDI_SOFTINT_FIXED, &id,
	    &ibc, NULL, errorq_intr, (caddr_t)eqp) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "errorq_create: failed to register "
		    "IPL %u softint for queue %s", ipl, name);
		kmem_free(eqp, sizeof (errorq_t));
		return (NULL);
	}

	if ((eqp->eq_ksp = kstat_create("unix", 0, name, "errorq",
	    KSTAT_TYPE_NAMED, sizeof (struct errorq_kstat) /
	    sizeof (kstat_named_t), KSTAT_FLAG_VIRTUAL)) == NULL) {
		cmn_err(CE_WARN, "errorq_create: failed to create kstat "
		    "for queue %s", name);
		if (id != NULL)
			ddi_remove_softintr(id);
		kmem_free(eqp, sizeof (errorq_t));
		return (NULL);
	}

	bcopy(&errorq_kstat_template, &eqp->eq_kstat,
	    sizeof (struct errorq_kstat));
	eqp->eq_ksp->ks_data = &eqp->eq_kstat;
	eqp->eq_ksp->ks_private = eqp;
	kstat_install(eqp->eq_ksp);

	(void) strncpy(eqp->eq_name, name, ERRORQ_NAMELEN);
	eqp->eq_name[ERRORQ_NAMELEN] = '\0';
	eqp->eq_func = func;
	eqp->eq_private = private;
	eqp->eq_data = kmem_alloc(qlen * size, KM_SLEEP);
	eqp->eq_qlen = qlen;
	eqp->eq_size = size;
	eqp->eq_ipl = ipl;
	eqp->eq_flags = flags | ERRORQ_ACTIVE;
	eqp->eq_id = id;
	mutex_init(&eqp->eq_lock, NULL, MUTEX_DEFAULT, NULL);
	eqp->eq_elems = kmem_alloc(qlen * sizeof (errorq_elem_t), KM_SLEEP);
	eqp->eq_phead = NULL;
	eqp->eq_ptail = NULL;
	eqp->eq_pend = NULL;
	eqp->eq_dump = NULL;
	eqp->eq_bitmap = kmem_zalloc(BT_SIZEOFMAP(qlen), KM_SLEEP);
	eqp->eq_rotor = 0;

	/*
	 * Iterate over the array of errorq_elem_t structures and set its
	 * data pointer.
	 */
	for (eep = eqp->eq_elems, data = eqp->eq_data; qlen > 1; qlen--) {
		eep->eqe_next = NULL;
		eep->eqe_dump = NULL;
		eep->eqe_prev = NULL;
		eep->eqe_data = data;
		data += size;
		eep++;
	}
	eep->eqe_next = NULL;
	eep->eqe_prev = NULL;
	eep->eqe_data = data;
	eep->eqe_dump = NULL;

	/*
	 * Once the errorq is initialized, add it to the global list of queues,
	 * and then return a pointer to the new queue to the caller.
	 */
	mutex_enter(&errorq_lock);
	eqp->eq_next = errorq_list;
	errorq_list = eqp;
	mutex_exit(&errorq_lock);

	return (eqp);
}

/*
 * Create a new errorq as if by errorq_create(), but set the ERRORQ_NVLIST
 * flag and initialize each element to have the start of its data region used
 * as an errorq_nvelem_t with a nvlist allocator that consumes the data region.
 */
errorq_t *
errorq_nvcreate(const char *name, errorq_func_t func, void *private,
    ulong_t qlen, size_t size, uint_t ipl, uint_t flags)
{
	errorq_t *eqp;
	errorq_elem_t *eep;

	eqp = errorq_create(name, func, private, qlen,
	    size + sizeof (errorq_nvelem_t), ipl, flags | ERRORQ_NVLIST);

	if (eqp == NULL)
		return (NULL);

	mutex_enter(&eqp->eq_lock);

	for (eep = eqp->eq_elems; qlen != 0; eep++, qlen--) {
		errorq_nvelem_t *eqnp = eep->eqe_data;
		eqnp->eqn_buf = (char *)eqnp + sizeof (errorq_nvelem_t);
		eqnp->eqn_nva = fm_nva_xcreate(eqnp->eqn_buf, size);
	}

	mutex_exit(&eqp->eq_lock);
	return (eqp);
}

/*
 * To destroy an error queue, we mark it as disabled and then explicitly drain
 * all pending errors.  Once the drain is complete, we can remove the queue
 * from the global list of queues examined by errorq_panic(), and then free
 * the various queue data structures.  The caller must use some higher-level
 * abstraction (e.g. disabling an error interrupt) to ensure that no one will
 * attempt to enqueue new errors while we are freeing this queue.
 */
void
errorq_destroy(errorq_t *eqp)
{
	errorq_t *p, **pp;
	errorq_elem_t *eep;
	ulong_t i;

	ASSERT(eqp != NULL);
	eqp->eq_flags &= ~ERRORQ_ACTIVE;
	errorq_drain(eqp);

	mutex_enter(&errorq_lock);
	pp = &errorq_list;

	for (p = errorq_list; p != NULL; p = p->eq_next) {
		if (p == eqp) {
			*pp = p->eq_next;
			break;
		}
		pp = &p->eq_next;
	}

	mutex_exit(&errorq_lock);
	ASSERT(p != NULL);

	if (eqp->eq_flags & ERRORQ_NVLIST) {
		for (eep = eqp->eq_elems, i = 0; i < eqp->eq_qlen; i++, eep++) {
			errorq_nvelem_t *eqnp = eep->eqe_data;
			fm_nva_xdestroy(eqnp->eqn_nva);
		}
	}

	mutex_destroy(&eqp->eq_lock);
	kstat_delete(eqp->eq_ksp);

	if (eqp->eq_id != NULL)
		ddi_remove_softintr(eqp->eq_id);

	kmem_free(eqp->eq_elems, eqp->eq_qlen * sizeof (errorq_elem_t));
	kmem_free(eqp->eq_bitmap, BT_SIZEOFMAP(eqp->eq_qlen));
	kmem_free(eqp->eq_data, eqp->eq_qlen * eqp->eq_size);

	kmem_free(eqp, sizeof (errorq_t));
}

/*
 * private version of bt_availbit which makes a best-efforts attempt
 * at allocating in a round-robin fashion in order to facilitate post-mortem
 * diagnosis.
 */
static index_t
errorq_availbit(ulong_t *bitmap, size_t nbits, index_t curindex)
{
	ulong_t bit, maxbit, bx;
	index_t rval, nextindex = curindex + 1;
	index_t nextword = nextindex >> BT_ULSHIFT;
	ulong_t nextbitindex = nextindex & BT_ULMASK;
	index_t maxindex = nbits - 1;
	index_t maxword = maxindex >> BT_ULSHIFT;
	ulong_t maxbitindex = maxindex & BT_ULMASK;

	/*
	 * First check if there are still some bits remaining in the current
	 * word, and see if any of those are available. We need to do this by
	 * hand as the bt_availbit() function always starts at the beginning
	 * of a word.
	 */
	if (nextindex <= maxindex && nextbitindex != 0) {
		maxbit = (nextword == maxword) ? maxbitindex : BT_ULMASK;
		for (bx = 0, bit = 1; bx <= maxbit; bx++, bit <<= 1)
			if (bx >= nextbitindex && !(bitmap[nextword] & bit))
				return ((nextword << BT_ULSHIFT) + bx);
		nextword++;
	}
	/*
	 * Now check if there are any words remaining before the end of the
	 * bitmap. Use bt_availbit() to find any free bits.
	 */
	if (nextword <= maxword)
		if ((rval = bt_availbit(&bitmap[nextword],
		    nbits - (nextword << BT_ULSHIFT))) != -1)
			return ((nextword << BT_ULSHIFT) + rval);
	/*
	 * Finally loop back to the start and look for any free bits starting
	 * from the beginning of the bitmap to the current rotor position.
	 */
	return (bt_availbit(bitmap, nextindex));
}

/*
 * Dispatch a new error into the queue for later processing.  The specified
 * data buffer is copied into a preallocated queue element.  If 'len' is
 * smaller than the queue element size, the remainder of the queue element is
 * filled with zeroes.  This function may be called from any context subject
 * to the Platform Considerations described above.
 */
void
errorq_dispatch(errorq_t *eqp, const void *data, size_t len, uint_t flag)
{
	errorq_elem_t *eep, *old;

	if (eqp == NULL || !(eqp->eq_flags & ERRORQ_ACTIVE)) {
		atomic_inc_64(&errorq_lost);
		return; /* drop error if queue is uninitialized or disabled */
	}

	for (;;) {
		int i, rval;

		if ((i = errorq_availbit(eqp->eq_bitmap, eqp->eq_qlen,
		    eqp->eq_rotor)) == -1) {
			atomic_inc_64(&eqp->eq_kstat.eqk_dropped.value.ui64);
			return;
		}
		BT_ATOMIC_SET_EXCL(eqp->eq_bitmap, i, rval);
		if (rval == 0) {
			eqp->eq_rotor = i;
			eep = &eqp->eq_elems[i];
			break;
		}
	}

	ASSERT(len <= eqp->eq_size);
	bcopy(data, eep->eqe_data, MIN(eqp->eq_size, len));

	if (len < eqp->eq_size)
		bzero((caddr_t)eep->eqe_data + len, eqp->eq_size - len);

	for (;;) {
		old = eqp->eq_pend;
		eep->eqe_prev = old;
		membar_producer();

		if (atomic_cas_ptr(&eqp->eq_pend, old, eep) == old)
			break;
	}

	atomic_inc_64(&eqp->eq_kstat.eqk_dispatched.value.ui64);

	if (flag == ERRORQ_ASYNC && eqp->eq_id != NULL)
		ddi_trigger_softintr(eqp->eq_id);
}

/*
 * Drain the specified error queue by calling eq_func() for each pending error.
 * This function must be called at or below LOCK_LEVEL or from panic context.
 * In order to synchronize with other attempts to drain the queue, we acquire
 * the adaptive eq_lock, blocking other consumers.  Once this lock is held,
 * we must use compare-and-swap to move the pending list to the processing
 * list and to return elements to the free pool in order to synchronize
 * with producers, who do not acquire any locks and only use atomic set/clear.
 *
 * An additional constraint on this function is that if the system panics
 * while this function is running, the panic code must be able to detect and
 * handle all intermediate states and correctly dequeue all errors.  The
 * errorq_panic() function below will be used for detecting and handling
 * these intermediate states.  The comments in errorq_drain() below explain
 * how we make sure each intermediate state is distinct and consistent.
 */
void
errorq_drain(errorq_t *eqp)
{
	errorq_elem_t *eep, *dep;

	ASSERT(eqp != NULL);
	mutex_enter(&eqp->eq_lock);

	/*
	 * If there are one or more pending errors, set eq_ptail to point to
	 * the first element on the pending list and then attempt to compare-
	 * and-swap NULL to the pending list.  We use membar_producer() to
	 * make sure that eq_ptail will be visible to errorq_panic() below
	 * before the pending list is NULLed out.  This section is labeled
	 * case (1) for errorq_panic, below.  If eq_ptail is not yet set (1A)
	 * eq_pend has all the pending errors.  If atomic_cas_ptr fails or
	 * has not been called yet (1B), eq_pend still has all the pending
	 * errors.  If atomic_cas_ptr succeeds (1C), eq_ptail has all the
	 * pending errors.
	 */
	while ((eep = eqp->eq_pend) != NULL) {
		eqp->eq_ptail = eep;
		membar_producer();

		if (atomic_cas_ptr(&eqp->eq_pend, eep, NULL) == eep)
			break;
	}

	/*
	 * If no errors were pending, assert that eq_ptail is set to NULL,
	 * drop the consumer lock, and return without doing anything.
	 */
	if (eep == NULL) {
		ASSERT(eqp->eq_ptail == NULL);
		mutex_exit(&eqp->eq_lock);
		return;
	}

	/*
	 * Now iterate from eq_ptail (a.k.a. eep, the newest error) to the
	 * oldest error, setting the eqe_next pointer so that we can iterate
	 * over the errors from oldest to newest.  We use membar_producer()
	 * to make sure that these stores are visible before we set eq_phead.
	 * If we panic before, during, or just after this loop (case 2),
	 * errorq_panic() will simply redo this work, as described below.
	 */
	for (eep->eqe_next = NULL; eep->eqe_prev != NULL; eep = eep->eqe_prev)
		eep->eqe_prev->eqe_next = eep;
	membar_producer();

	/*
	 * Now set eq_phead to the head of the processing list (the oldest
	 * error) and issue another membar_producer() to make sure that
	 * eq_phead is seen as non-NULL before we clear eq_ptail.  If we panic
	 * after eq_phead is set (case 3), we will detect and log these errors
	 * in errorq_panic(), as described below.
	 */
	eqp->eq_phead = eep;
	membar_producer();

	eqp->eq_ptail = NULL;
	membar_producer();

	/*
	 * If we enter from errorq_panic_drain(), we may already have
	 * errorq elements on the dump list.  Find the tail of
	 * the list ready for append.
	 */
	if (panicstr && (dep = eqp->eq_dump) != NULL) {
		while (dep->eqe_dump != NULL)
			dep = dep->eqe_dump;
	}

	/*
	 * Now iterate over the processing list from oldest (eq_phead) to
	 * newest and log each error.  Once an error is logged, we use
	 * atomic clear to return it to the free pool.  If we panic before,
	 * during, or after calling eq_func() (case 4), the error will still be
	 * found on eq_phead and will be logged in errorq_panic below.
	 */

	while ((eep = eqp->eq_phead) != NULL) {
		eqp->eq_func(eqp->eq_private, eep->eqe_data, eep);
		eqp->eq_kstat.eqk_logged.value.ui64++;

		eqp->eq_phead = eep->eqe_next;
		membar_producer();

		eep->eqe_next = NULL;

		/*
		 * On panic, we add the element to the dump list for each
		 * nvlist errorq.  Elements are stored oldest to newest.
		 * Then continue, so we don't free and subsequently overwrite
		 * any elements which we've put on the dump queue.
		 */
		if (panicstr && (eqp->eq_flags & ERRORQ_NVLIST)) {
			if (eqp->eq_dump == NULL)
				dep = eqp->eq_dump = eep;
			else
				dep = dep->eqe_dump = eep;
			membar_producer();
			continue;
		}

		eep->eqe_prev = NULL;
		BT_ATOMIC_CLEAR(eqp->eq_bitmap, eep - eqp->eq_elems);
	}

	mutex_exit(&eqp->eq_lock);
}

/*
 * Now that device tree services are available, set up the soft interrupt
 * handlers for any queues that were created early in boot.  We then
 * manually drain these queues to report any pending early errors.
 */
void
errorq_init(void)
{
	dev_info_t *dip = ddi_root_node();
	ddi_softintr_t id;
	errorq_t *eqp;

	ASSERT(modrootloaded != 0);
	ASSERT(dip != NULL);

	mutex_enter(&errorq_lock);

	for (eqp = errorq_list; eqp != NULL; eqp = eqp->eq_next) {
		ddi_iblock_cookie_t ibc =
		    (ddi_iblock_cookie_t)(uintptr_t)ipltospl(eqp->eq_ipl);

		if (eqp->eq_id != NULL)
			continue; /* softint already initialized */

		if (ddi_add_softintr(dip, DDI_SOFTINT_FIXED, &id, &ibc, NULL,
		    errorq_intr, (caddr_t)eqp) != DDI_SUCCESS) {
			panic("errorq_init: failed to register IPL %u softint "
			    "for queue %s", eqp->eq_ipl, eqp->eq_name);
		}

		eqp->eq_id = id;
		errorq_drain(eqp);
	}

	mutex_exit(&errorq_lock);
}

/*
 * This function is designed to be called from panic context only, and
 * therefore does not need to acquire errorq_lock when iterating over
 * errorq_list.  This function must be called no more than once for each
 * 'what' value (if you change this then review the manipulation of 'dep'.
 */
static uint64_t
errorq_panic_drain(uint_t what)
{
	errorq_elem_t *eep, *nep, *dep;
	errorq_t *eqp;
	uint64_t loggedtmp;
	uint64_t logged = 0;

	for (eqp = errorq_list; eqp != NULL; eqp = eqp->eq_next) {
		if ((eqp->eq_flags & (ERRORQ_VITAL | ERRORQ_NVLIST)) != what)
			continue; /* do not drain this queue on this pass */

		loggedtmp = eqp->eq_kstat.eqk_logged.value.ui64;

		/*
		 * In case (1B) above, eq_ptail may be set but the
		 * atomic_cas_ptr may not have been executed yet or may have
		 * failed.  Either way, we must log errors in chronological
		 * order.  So we search the pending list for the error
		 * pointed to by eq_ptail.  If it is found, we know that all
		 * subsequent errors are also still on the pending list, so
		 * just NULL out eq_ptail and let errorq_drain(), below,
		 * take care of the logging.
		 */
		for (eep = eqp->eq_pend; eep != NULL; eep = eep->eqe_prev) {
			if (eep == eqp->eq_ptail) {
				ASSERT(eqp->eq_phead == NULL);
				eqp->eq_ptail = NULL;
				break;
			}
		}

		/*
		 * In cases (1C) and (2) above, eq_ptail will be set to the
		 * newest error on the processing list but eq_phead will still
		 * be NULL.  We set the eqe_next pointers so we can iterate
		 * over the processing list in order from oldest error to the
		 * newest error.  We then set eq_phead to point to the oldest
		 * error and fall into the for-loop below.
		 */
		if (eqp->eq_phead == NULL && (eep = eqp->eq_ptail) != NULL) {
			for (eep->eqe_next = NULL; eep->eqe_prev != NULL;
			    eep = eep->eqe_prev)
				eep->eqe_prev->eqe_next = eep;

			eqp->eq_phead = eep;
			eqp->eq_ptail = NULL;
		}

		/*
		 * In cases (3) and (4) above (or after case (1C/2) handling),
		 * eq_phead will be set to the oldest error on the processing
		 * list.  We log each error and return it to the free pool.
		 *
		 * Unlike errorq_drain(), we don't need to worry about updating
		 * eq_phead because errorq_panic() will be called at most once.
		 * However, we must use atomic_cas_ptr to update the
		 * freelist in case errors are still being enqueued during
		 * panic.
		 */
		for (eep = eqp->eq_phead; eep != NULL; eep = nep) {
			eqp->eq_func(eqp->eq_private, eep->eqe_data, eep);
			eqp->eq_kstat.eqk_logged.value.ui64++;

			nep = eep->eqe_next;
			eep->eqe_next = NULL;

			/*
			 * On panic, we add the element to the dump list for
			 * each nvlist errorq, stored oldest to newest. Then
			 * continue, so we don't free and subsequently overwrite
			 * any elements which we've put on the dump queue.
			 */
			if (eqp->eq_flags & ERRORQ_NVLIST) {
				if (eqp->eq_dump == NULL)
					dep = eqp->eq_dump = eep;
				else
					dep = dep->eqe_dump = eep;
				membar_producer();
				continue;
			}

			eep->eqe_prev = NULL;
			BT_ATOMIC_CLEAR(eqp->eq_bitmap, eep - eqp->eq_elems);
		}

		/*
		 * Now go ahead and drain any other errors on the pending list.
		 * This call transparently handles case (1A) above, as well as
		 * any other errors that were dispatched after errorq_drain()
		 * completed its first compare-and-swap.
		 */
		errorq_drain(eqp);

		logged += eqp->eq_kstat.eqk_logged.value.ui64 - loggedtmp;
	}
	return (logged);
}

/*
 * Drain all error queues - called only from panic context.  Some drain
 * functions may enqueue errors to ERRORQ_NVLIST error queues so that
 * they may be written out in the panic dump - so ERRORQ_NVLIST queues
 * must be drained last.  Drain ERRORQ_VITAL queues before nonvital queues
 * so that vital errors get to fill the ERRORQ_NVLIST queues first, and
 * do not drain the nonvital queues if there are many vital errors.
 */
void
errorq_panic(void)
{
	ASSERT(panicstr != NULL);

	if (errorq_panic_drain(ERRORQ_VITAL) <= errorq_vitalmin)
		(void) errorq_panic_drain(0);
	(void) errorq_panic_drain(ERRORQ_VITAL | ERRORQ_NVLIST);
	(void) errorq_panic_drain(ERRORQ_NVLIST);
}

/*
 * Reserve an error queue element for later processing and dispatching.  The
 * element is returned to the caller who may add error-specific data to
 * element.  The element is retured to the free pool when either
 * errorq_commit() is called and the element asynchronously processed
 * or immediately when errorq_cancel() is called.
 */
errorq_elem_t *
errorq_reserve(errorq_t *eqp)
{
	errorq_elem_t *eqep;

	if (eqp == NULL || !(eqp->eq_flags & ERRORQ_ACTIVE)) {
		atomic_inc_64(&errorq_lost);
		return (NULL);
	}

	for (;;) {
		int i, rval;

		if ((i = errorq_availbit(eqp->eq_bitmap, eqp->eq_qlen,
		    eqp->eq_rotor)) == -1) {
			atomic_inc_64(&eqp->eq_kstat.eqk_dropped.value.ui64);
			return (NULL);
		}
		BT_ATOMIC_SET_EXCL(eqp->eq_bitmap, i, rval);
		if (rval == 0) {
			eqp->eq_rotor = i;
			eqep = &eqp->eq_elems[i];
			break;
		}
	}

	if (eqp->eq_flags & ERRORQ_NVLIST) {
		errorq_nvelem_t *eqnp = eqep->eqe_data;
		nv_alloc_reset(eqnp->eqn_nva);
		eqnp->eqn_nvl = fm_nvlist_create(eqnp->eqn_nva);
	}

	atomic_inc_64(&eqp->eq_kstat.eqk_reserved.value.ui64);
	return (eqep);
}

/*
 * Commit an errorq element (eqep) for dispatching.
 * This function may be called from any context subject
 * to the Platform Considerations described above.
 */
void
errorq_commit(errorq_t *eqp, errorq_elem_t *eqep, uint_t flag)
{
	errorq_elem_t *old;

	if (eqep == NULL || !(eqp->eq_flags & ERRORQ_ACTIVE)) {
		atomic_inc_64(&eqp->eq_kstat.eqk_commit_fail.value.ui64);
		return;
	}

	for (;;) {
		old = eqp->eq_pend;
		eqep->eqe_prev = old;
		membar_producer();

		if (atomic_cas_ptr(&eqp->eq_pend, old, eqep) == old)
			break;
	}

	atomic_inc_64(&eqp->eq_kstat.eqk_committed.value.ui64);

	if (flag == ERRORQ_ASYNC && eqp->eq_id != NULL)
		ddi_trigger_softintr(eqp->eq_id);
}

/*
 * Cancel an errorq element reservation by returning the specified element
 * to the free pool.  Duplicate or invalid frees are not supported.
 */
void
errorq_cancel(errorq_t *eqp, errorq_elem_t *eqep)
{
	if (eqep == NULL || !(eqp->eq_flags & ERRORQ_ACTIVE))
		return;

	BT_ATOMIC_CLEAR(eqp->eq_bitmap, eqep - eqp->eq_elems);

	atomic_inc_64(&eqp->eq_kstat.eqk_cancelled.value.ui64);
}

/*
 * Write elements on the dump list of each nvlist errorq to the dump device.
 * Upon reboot, fmd(1M) will extract and replay them for diagnosis.
 */
void
errorq_dump(void)
{
	errorq_elem_t *eep;
	errorq_t *eqp;

	if (ereport_dumpbuf == NULL)
		return; /* reboot or panic before errorq is even set up */

	for (eqp = errorq_list; eqp != NULL; eqp = eqp->eq_next) {
		if (!(eqp->eq_flags & ERRORQ_NVLIST) ||
		    !(eqp->eq_flags & ERRORQ_ACTIVE))
			continue; /* do not dump this queue on panic */

		for (eep = eqp->eq_dump; eep != NULL; eep = eep->eqe_dump) {
			errorq_nvelem_t *eqnp = eep->eqe_data;
			size_t len = 0;
			erpt_dump_t ed;
			int err;

			(void) nvlist_size(eqnp->eqn_nvl,
			    &len, NV_ENCODE_NATIVE);

			if (len > ereport_dumplen || len == 0) {
				cmn_err(CE_WARN, "%s: unable to save error "
				    "report %p due to size %lu\n",
				    eqp->eq_name, (void *)eep, len);
				continue;
			}

			if ((err = nvlist_pack(eqnp->eqn_nvl,
			    (char **)&ereport_dumpbuf, &ereport_dumplen,
			    NV_ENCODE_NATIVE, KM_NOSLEEP)) != 0) {
				cmn_err(CE_WARN, "%s: unable to save error "
				    "report %p due to pack error %d\n",
				    eqp->eq_name, (void *)eep, err);
				continue;
			}

			ed.ed_magic = ERPT_MAGIC;
			ed.ed_chksum = checksum32(ereport_dumpbuf, len);
			ed.ed_size = (uint32_t)len;
			ed.ed_pad = 0;
			ed.ed_hrt_nsec = 0;
			ed.ed_hrt_base = panic_hrtime;
			ed.ed_tod_base.sec = panic_hrestime.tv_sec;
			ed.ed_tod_base.nsec = panic_hrestime.tv_nsec;

			dumpvp_write(&ed, sizeof (ed));
			dumpvp_write(ereport_dumpbuf, len);
		}
	}
}

nvlist_t *
errorq_elem_nvl(errorq_t *eqp, const errorq_elem_t *eqep)
{
	errorq_nvelem_t *eqnp = eqep->eqe_data;

	ASSERT(eqp->eq_flags & ERRORQ_ACTIVE && eqp->eq_flags & ERRORQ_NVLIST);

	return (eqnp->eqn_nvl);
}

nv_alloc_t *
errorq_elem_nva(errorq_t *eqp, const errorq_elem_t *eqep)
{
	errorq_nvelem_t *eqnp = eqep->eqe_data;

	ASSERT(eqp->eq_flags & ERRORQ_ACTIVE && eqp->eq_flags & ERRORQ_NVLIST);

	return (eqnp->eqn_nva);
}

/*
 * Reserve a new element and duplicate the data of the original into it.
 */
void *
errorq_elem_dup(errorq_t *eqp, const errorq_elem_t *eqep, errorq_elem_t **neqep)
{
	ASSERT(eqp->eq_flags & ERRORQ_ACTIVE);
	ASSERT(!(eqp->eq_flags & ERRORQ_NVLIST));

	if ((*neqep = errorq_reserve(eqp)) == NULL)
		return (NULL);

	bcopy(eqep->eqe_data, (*neqep)->eqe_data, eqp->eq_size);
	return ((*neqep)->eqe_data);
}
