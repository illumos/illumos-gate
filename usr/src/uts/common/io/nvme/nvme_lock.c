/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2024 Oxide Computer Company
 */

/*
 * This implements the general locking routines. See the big theory section
 * 'ioctls, Errors, and Exclusive Access' for more information.
 */

#include <sys/stddef.h>
#include <sys/nvme.h>

#include "nvme_reg.h"
#include "nvme_var.h"

/*
 * Do we have a writer or someone pending. Note, some cases require checking
 * both of these and others do not. Please see each individual check for the
 * nuance here. As a general rule of thumb, when locking, the pending writers
 * are important. However, when passing the lock on to the next owner (the
 * handoff functions below), one doesn't check it.
 */
static boolean_t
nvme_rwlock_wr_or_pend(nvme_lock_t *lock)
{
	return (lock->nl_writer != NULL ||
	    list_is_empty(&lock->nl_pend_writers) == 0);
}

/*
 * Taking a namespace read lock requires that there is no writer (or pending) on
 * the controller and the namespace.
 */
static boolean_t
nvme_rwlock_block_ns_rdlock(nvme_t *nvme, nvme_namespace_t *ns)
{
	return (nvme_rwlock_wr_or_pend(&nvme->n_lock) ||
	    nvme_rwlock_wr_or_pend(&ns->ns_lock));
}

/*
 * The following entities all block a namespace write lock from being taken:
 *
 * 1) Any active or pending writer on the controller lock. They block and starve
 *    namespace writers respectively.
 * 2) Any active or pending writers on the namespace lock. We must wait in line.
 * 3) Any active readers on the namespace lock. We ignore pending namespace
 *    readers as by definition that implies some other situation will cause
 *    this.
 */
static boolean_t
nvme_rwlock_block_ns_wrlock(nvme_t *nvme, nvme_namespace_t *ns)
{
	return (nvme_rwlock_wr_or_pend(&nvme->n_lock) ||
	    nvme_rwlock_wr_or_pend(&ns->ns_lock) ||
	    list_is_empty(&ns->ns_lock.nl_readers) == 0);
}


/*
 * The only thing that blocks acquisition of a controller read lock is if
 * there are outstanding or pending writers on the controller lock. We can
 * ignore the state of all namespaces here.
 */
static boolean_t
nvme_rwlock_block_ctrl_rdlock(nvme_t *nvme)
{
	return (nvme_rwlock_wr_or_pend(&nvme->n_lock));
}

/*
 * Taking the controller write lock is the most challenging of all, but also
 * takes priority. The following all block a controller write lock from being
 * taken:
 *
 * 1) Any controller write lock or pending write
 * 2) Any controller read lock. We skip pending reads because if they exist,
 *    some other situation causes that that will trip us.
 * 3) Any namespace having a write lock. We ignore pending writes because by
 *    definition there is some condition that causes that to be the case.
 * 4) Any read lock on a namespace. We ignore pending reads like in the
 *    controller case.
 */
static boolean_t
nvme_rwlock_block_ctrl_wrlock(nvme_t *nvme)
{
	if (nvme_rwlock_wr_or_pend(&nvme->n_lock) ||
	    list_is_empty(&nvme->n_lock.nl_readers) == 0) {
		return (B_TRUE);
	}

	for (uint32_t i = 1; i <= nvme->n_namespace_count; i++) {
		nvme_namespace_t *ns = nvme_nsid2ns(nvme, i);
		if (ns->ns_lock.nl_writer != NULL ||
		    list_is_empty(&ns->ns_lock.nl_readers) == 0) {
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

/*
 * Answer can we hand off the world to a pending controller write lock. This has
 * similar rules to the above; however, we critically _ignore_ pending
 * controller write lock holds, as the assumption is that they are here, so the
 * only consideration from above are controller reader locks and namespace
 * locks.
 */
static boolean_t
nvme_rwlock_handoff_ctrl_wrlock(nvme_t *nvme)
{
	/* See nvme_rwlock_wakeup() for on why this can be done. */
	ASSERT3P(nvme->n_lock.nl_writer, ==, NULL);

	if (list_is_empty(&nvme->n_lock.nl_readers) == 0) {
		return (B_FALSE);
	}

	for (uint32_t i = 1; i <= nvme->n_namespace_count; i++) {
		nvme_namespace_t *ns = nvme_nsid2ns(nvme, i);
		if (ns->ns_lock.nl_writer != NULL ||
		    list_is_empty(&ns->ns_lock.nl_readers) == 0) {
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

/*
 * Namespace handoff variant. It skips pending writers on the namespace lock,
 * but fully considers them on the controller due to their priority. Otherwise
 * this follows the same rules as the normal blocking check.
 */
static boolean_t
nvme_rwlock_handoff_ns_wrlock(nvme_t *nvme, nvme_namespace_t *ns)
{
	if (nvme_rwlock_wr_or_pend(&nvme->n_lock) ||
	    list_is_empty(&nvme->n_lock.nl_readers) == 0) {
		return (B_FALSE);
	}

	if (ns->ns_lock.nl_writer != NULL ||
	    list_is_empty(&ns->ns_lock.nl_readers) == 0) {
		return (B_FALSE);
	}

	return (B_TRUE);
}

static void
nvme_rwlock_rdlock(nvme_minor_lock_info_t *info, nvme_lock_t *lock)
{
	ASSERT3U(list_is_empty(&lock->nl_pend_writers), !=, 0);
	ASSERT3P(lock->nl_writer, ==, NULL);
	ASSERT3U(info->nli_state, ==, NVME_LOCK_STATE_UNLOCKED);
	ASSERT3U(list_link_active(&info->nli_node), ==, 0);
	ASSERT3P(info->nli_minor, !=, NULL);
	ASSERT3P(info->nli_nvme, !=, NULL);
	ASSERT3U(info->nli_curlevel, ==, NVME_LOCK_L_READ);

	info->nli_state = NVME_LOCK_STATE_ACQUIRED;
	info->nli_last_change = gethrtime();
	info->nli_acq_kthread = (uintptr_t)curthread;
	info->nli_acq_pid = (uint32_t)curproc->p_pid;

	list_insert_tail(&lock->nl_readers, info);
	lock->nl_nread_locks++;
}

static void
nvme_rwlock_wrlock(nvme_minor_lock_info_t *info, nvme_lock_t *lock)
{
	ASSERT3P(lock->nl_writer, ==, NULL);
	ASSERT3U(info->nli_state, ==, NVME_LOCK_STATE_UNLOCKED);
	ASSERT3U(list_link_active(&info->nli_node), ==, 0);
	ASSERT3P(info->nli_minor, !=, NULL);
	ASSERT3P(info->nli_nvme, !=, NULL);

	info->nli_state = NVME_LOCK_STATE_ACQUIRED;
	info->nli_curlevel = NVME_LOCK_L_WRITE;
	info->nli_last_change = gethrtime();
	info->nli_acq_kthread = (uintptr_t)curthread;
	info->nli_acq_pid = (uint32_t)curproc->p_pid;

	lock->nl_writer = info;
	lock->nl_nwrite_locks++;
}

#ifdef	DEBUG
/*
 * This is just a sanity check for our lock logic.
 */
static boolean_t
nvme_rwlock_is_reader(nvme_lock_t *lock, const nvme_minor_lock_info_t *info)
{
	for (nvme_minor_lock_info_t *i = list_head(&lock->nl_readers);
	    i != NULL; i = list_next(&lock->nl_readers, i)) {
		if (i == info) {
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}
#endif

static void
nvme_rwlock_signal_one(nvme_minor_lock_info_t *info, nvme_ioctl_errno_t err)
{
	ASSERT3P(info->nli_ioc, !=, NULL);
	ASSERT3P(info->nli_minor, !=, NULL);
	ASSERT3P(info->nli_state, !=, NVME_LOCK_STATE_BLOCKED);

	if (err == NVME_IOCTL_E_OK) {
		nvme_ioctl_success(info->nli_ioc);
	} else {
		(void) nvme_ioctl_error(info->nli_ioc, err, 0, 0);
	}

	cv_signal(&info->nli_minor->nm_cv);
}

static void
nvme_rwlock_wakeup_readers(nvme_lock_t *lock)
{
	nvme_minor_lock_info_t *info;

	if (list_is_empty(&lock->nl_pend_readers) != 0) {
		return;
	}

	ASSERT3U(list_is_empty(&lock->nl_readers), !=, 0);
	ASSERT3P(lock->nl_writer, ==, NULL);
	ASSERT3U(list_is_empty(&lock->nl_pend_writers), !=, 0);
	while ((info = list_remove_head(&lock->nl_pend_readers)) != NULL) {
		info->nli_state = NVME_LOCK_STATE_UNLOCKED;
		nvme_rwlock_rdlock(info, lock);
		nvme_rwlock_signal_one(info, NVME_IOCTL_E_OK);
	}
}

/*
 * An unlock occurred somewhere. We need to evaluate the total state of the
 * world. An unlock of a namespace can allow a controller lock to proceed. On
 * the other hand, dropping the controller write lock allows every namespace to
 * proceed. While we know the context of where the unlock occurred, it's simpler
 * right now to just allow everything to continue. This is somewhat expensive,
 * but this can be sped up with more cached information when it's justified. We
 * process things in the following order:
 *
 * 1) Evaluate if someone can now take a controller write lock. If so, wake up
 * the head of the list and then all subsequent processing is done.
 * 2) Evaluate if there are pending readers for the controller. If so, wake up
 * each and every waiter. Always continue to namespaces in this case.
 *
 * For each namespace:
 *
 * 1) Evaluate if there are pending writers and they can take the write lock. If
 * so, wake up the head of the list.  If so, continue to the next namespace.
 * 2) Otherwise, if there are pending readers. If so, wake up each and every
 * reader. Continue onto the next namespace.
 */
static void
nvme_rwlock_wakeup(nvme_t *nvme)
{
	nvme_lock_t *ctrl_lock = &nvme->n_lock;

	/*
	 * This assertion may seem weird, but it's actually a bit of an
	 * invariant. When the controller's write lock is taken, by definition
	 * there are no other locks that can be taken. Therefore if we were
	 * somehow unable to unlock a lock on this controller, then we'd be
	 * violating our rules.
	 */
	VERIFY3P(ctrl_lock->nl_writer, ==, NULL);

	/*
	 * If there are pending writers, either one of them will be woken up or
	 * no one will. Writers trump readers, but it's possible that we may not
	 * be able to wake up a waiting writer yet. If we take this arm, we
	 * should not process anything else. The same logic applies in the
	 * namespace case as well.
	 */
	if (list_is_empty(&ctrl_lock->nl_pend_writers) == 0) {
		nvme_minor_lock_info_t *info;

		if (!nvme_rwlock_handoff_ctrl_wrlock(nvme))
			return;

		/*
		 * We opt to indicate that this is unlocked ahead of
		 * taking the lock for state tracking purposes.
		 */
		info = list_remove_head(&ctrl_lock->nl_pend_writers);
		info->nli_state = NVME_LOCK_STATE_UNLOCKED;
		nvme_rwlock_wrlock(info, ctrl_lock);
		nvme_rwlock_signal_one(info, NVME_IOCTL_E_OK);
		return;
	}

	nvme_rwlock_wakeup_readers(ctrl_lock);
	for (uint32_t i = 1; i <= nvme->n_namespace_count; i++) {
		nvme_namespace_t *ns = nvme_nsid2ns(nvme, i);
		nvme_lock_t *ns_lock = &ns->ns_lock;

		if (list_is_empty(&ns_lock->nl_pend_writers) == 0) {
			nvme_minor_lock_info_t *info;

			if (!nvme_rwlock_handoff_ns_wrlock(nvme, ns))
				continue;

			info = list_remove_head(&ns_lock->nl_pend_writers);
			info->nli_state = NVME_LOCK_STATE_UNLOCKED;
			nvme_rwlock_wrlock(info, ns_lock);
			nvme_rwlock_signal_one(info, NVME_IOCTL_E_OK);
		} else {
			nvme_rwlock_wakeup_readers(ns_lock);
		}
	}
}

/*
 * This cleans up all the state in the minor for returning without a lock held.
 */
static void
nvme_rwunlock_cleanup_minor(nvme_minor_lock_info_t *info)
{
	info->nli_lock = NULL;
	info->nli_state = NVME_LOCK_STATE_UNLOCKED;
	info->nli_curlevel = 0;
	info->nli_ns = NULL;
}

/*
 * We've been asked to unlock a lock. Not only must we remove our hold from this
 * lock, we must go through and wake up the next waiter. The waiters that we
 * have to wake up vary depending on our lock. See section 'ioctls, Errors, and
 * Exclusive Access' in the theory statement for more information.
 */

void
nvme_rwunlock(nvme_minor_lock_info_t *info, nvme_lock_t *lock)
{
	nvme_t *const nvme = info->nli_nvme;
	boolean_t is_read;

	VERIFY(MUTEX_HELD(&nvme->n_minor_mutex));
	VERIFY3P(info->nli_lock, ==, lock);
	VERIFY(info->nli_curlevel == NVME_LOCK_L_READ ||
	    info->nli_curlevel == NVME_LOCK_L_WRITE);
	is_read = info->nli_curlevel == NVME_LOCK_L_READ;

	/*
	 * First we need to remove this minor from the lock and clean up all of
	 * the state this lock in the info structure.
	 */
	info->nli_last_change = gethrtime();
	if (is_read) {
		VERIFY3U(list_link_active(&info->nli_node), !=, 0);
		ASSERT3U(nvme_rwlock_is_reader(lock, info), ==, B_TRUE);
		list_remove(&lock->nl_readers, info);
	} else {
		VERIFY3U(list_link_active(&info->nli_node), ==, 0);
		VERIFY3P(lock->nl_writer, ==, info);
		lock->nl_writer = NULL;
	}

	nvme_rwunlock_cleanup_minor(info);
	nvme_rwlock_wakeup(nvme);
}

/*
 * We were just interrupted due to a signal. However, just because our block was
 * interrupted due to a signal doesn't mean that other activity didn't occur. In
 * particular, the signal wake up could race with a subsequent wake up that was
 * due to the device being removed or actually acquiring the lock. Depending on
 * which state we were in, we need to perform the appropriate clean up. In all
 * cases, the signal trumps all, which may mean actually unlocking!
 */
static void
nvme_rwlock_signal(nvme_minor_lock_info_t *info, nvme_lock_t *lock,
    boolean_t is_read)
{
	ASSERT3P(info->nli_ioc, !=, NULL);

	/*
	 * We're changing the state here, so update the minor's last change
	 * time.
	 */
	info->nli_last_change = gethrtime();
	lock->nl_nsignals++;

	/*
	 * This is the simplest case. We've already been removed from the lock
	 * that we're on. All we need to do is change the error to indicate that
	 * we received a signal.
	 */
	if (info->nli_state == NVME_LOCK_STATE_UNLOCKED) {
		ASSERT3P(info->nli_lock, ==, NULL);
		(void) nvme_ioctl_error(info->nli_ioc,
		    NVME_IOCTL_E_LOCK_WAIT_SIGNAL, 0, 0);
		lock->nl_nsig_unlock++;
		return;
	}

	/*
	 * For all others, the lock should be set here.
	 */
	ASSERT3P(info->nli_lock, ==, lock);

	/*
	 * For someone that was blocked, we need to remove them from the pending
	 * lists.
	 */
	if (info->nli_state == NVME_LOCK_STATE_BLOCKED) {
		ASSERT3S(list_link_active(&info->nli_node), !=, 0);
		if (is_read) {
			list_remove(&lock->nl_pend_readers, info);
		} else {
			list_remove(&lock->nl_pend_writers, info);
		}

		nvme_rwunlock_cleanup_minor(info);
		(void) nvme_ioctl_error(info->nli_ioc,
		    NVME_IOCTL_E_LOCK_WAIT_SIGNAL, 0, 0);
		lock->nl_nsig_blocks++;
		return;
	}

	/*
	 * Now, the most nuanced thing that we need to do. We need to unlock
	 * this node. We synthesize an unlock request and submit that.
	 */
	lock->nl_nsig_acq++;
	nvme_rwunlock(info, lock);
}

/*
 * Here we need to implement our read-write lock policy. Refer to the big theory
 * statement for more information. Here's a summary of the priority that's
 * relevant here:
 *
 * 1) Waiting writers starve waiting readers
 * 2) Waiting writers for the controller starve all namespace writers and
 *    readers
 * 3) A read lock can be taken if there are no pending or active writers on the
 *    lock (and the controller lock for a namespace).
 */
void
nvme_rwlock(nvme_minor_t *minor, nvme_ioctl_lock_t *req)
{
	nvme_t *const nvme = minor->nm_ctrl;
	const boolean_t is_nonblock = (req->nil_flags &
	    NVME_LOCK_F_DONT_BLOCK) != 0;
	const boolean_t is_read = req->nil_level == NVME_LOCK_L_READ;
	const boolean_t is_ctrl = req->nil_ent == NVME_LOCK_E_CTRL;
	nvme_minor_lock_info_t *info;
	nvme_lock_t *lock;
	boolean_t waiters;
	hrtime_t sleep_time;

	VERIFY(MUTEX_HELD(&nvme->n_minor_mutex));

	if (is_ctrl) {
		info = &minor->nm_ctrl_lock;
		lock = &nvme->n_lock;

		if (is_read) {
			waiters = nvme_rwlock_block_ctrl_rdlock(nvme);
		} else {
			waiters = nvme_rwlock_block_ctrl_wrlock(nvme);
		}
	} else {
		nvme_namespace_t *ns;
		const uint32_t nsid = req->nil_common.nioc_nsid;
		info = &minor->nm_ns_lock;

		VERIFY3U(req->nil_ent, ==, NVME_LOCK_E_NS);
		ns = nvme_nsid2ns(nvme, nsid);
		minor->nm_ns_lock.nli_ns = ns;
		lock = &ns->ns_lock;

		if (is_read) {
			waiters = nvme_rwlock_block_ns_rdlock(nvme, ns);
		} else {
			waiters = nvme_rwlock_block_ns_wrlock(nvme, ns);
		}
	}

	/*
	 * Set the information that indicates what kind of lock we're attempting
	 * to acquire and that we're operating on.
	 */
	info->nli_curlevel = is_read ? NVME_LOCK_L_READ : NVME_LOCK_L_WRITE;
	info->nli_lock = lock;


	/*
	 * We think we can get the lock, hurrah.
	 */
	if (!waiters) {
		if (is_read) {
			nvme_rwlock_rdlock(info, lock);
		} else {
			nvme_rwlock_wrlock(info, lock);
		}
		(void) nvme_ioctl_success(&req->nil_common);
		return;
	}

	/*
	 * We failed to get the lock. At this point we will set ourselves up to
	 * block. Once we go to sleep on the CV, our assumption is that anyone
	 * who has woken us up will have filled in the information the status of
	 * this operation and therefore after this point, all we have to do is
	 * return.
	 */
	if (is_nonblock) {
		nvme_rwunlock_cleanup_minor(info);
		lock->nl_nnonblock++;
		(void) nvme_ioctl_error(&req->nil_common,
		    NVME_IOCTL_E_LOCK_WOULD_BLOCK, 0, 0);
		return;
	}

	ASSERT3P(info->nli_ioc, ==, NULL);
	info->nli_ioc = &req->nil_common;
	if (is_read) {
		list_insert_tail(&lock->nl_pend_readers, info);
		lock->nl_npend_reads++;
	} else {
		list_insert_tail(&lock->nl_pend_writers, info);
		lock->nl_npend_writes++;
	}

	ASSERT3U(info->nli_state, ==, NVME_LOCK_STATE_UNLOCKED);
	info->nli_state = NVME_LOCK_STATE_BLOCKED;
	sleep_time = gethrtime();
	info->nli_last_change = sleep_time;
	while (info->nli_state == NVME_LOCK_STATE_BLOCKED) {
		/*
		 * Block until we receive a signal. Note, a signal trumps all
		 * other processing. We may be woken up here because we acquired
		 * a lock, we may also end up woken up here if the controller is
		 * marked as dead.
		 */
		if (cv_wait_sig(&minor->nm_cv, &nvme->n_minor_mutex) == 0) {
			nvme_rwlock_signal(info, lock, is_read);
			break;
		}
	}

	/*
	 * Before we return, clean up and sanity check our state.
	 */
	info->nli_ioc = NULL;
#ifdef	DEBUG
	ASSERT3S(info->nli_last_change, !=, sleep_time);
	if (info->nli_state == NVME_LOCK_STATE_UNLOCKED) {
		ASSERT3S(list_link_active(&info->nli_node), ==, 0);
		ASSERT3P(info->nli_ns, ==, NULL);
		ASSERT3U(req->nil_common.nioc_drv_err, !=, NVME_IOCTL_E_OK);
	} else {
		ASSERT3U(info->nli_state, ==, NVME_LOCK_STATE_ACQUIRED);
		ASSERT3U(req->nil_common.nioc_drv_err, ==, NVME_IOCTL_E_OK);
		if (is_read) {
			ASSERT3S(list_link_active(&info->nli_node), !=, 0);
		} else {
			ASSERT3P(lock->nl_writer, ==, info);
		}
	}
	ASSERT3P(info->nli_minor, ==, minor);
	ASSERT3P(info->nli_nvme, ==, minor->nm_ctrl);
#endif
}

/*
 * This is used to clean up a single minor that was blocking trying to get a
 * lock prior to a controller going dead. In particular, the key here is we need
 * to change its state to unlocked by cleaning it up and then signal it to wake
 * up and process things. The clean up also helps deal with the case of a racing
 * signal, though it does leave the state a little awkward in this intermediate
 * moment; however, since it's been removed from a list that's really the proper
 * action and no one can issue new lock ioctls at this point.
 */
static void
nvme_rwlock_ctrl_dead_cleanup_one(nvme_t *nvme, nvme_minor_lock_info_t *info)
{
	ASSERT3U(info->nli_state, ==, NVME_LOCK_STATE_BLOCKED);
	ASSERT3P(info->nli_ioc, !=, NULL);

	/*
	 * Update the last time this has changed for our snaity checks.
	 */
	info->nli_last_change = gethrtime();
	nvme_rwunlock_cleanup_minor(info);
	nvme_rwlock_signal_one(info, nvme->n_dead_status);
}

/*
 * We've just been informed that this controller has set n_dead. This is most
 * unfortunate for anyone trying to actively use it right now and we must notify
 * them. Anyone who has successfully obtained a lock gets to keep it until they
 * drop it (hopefully soon). Anyone who is asleep should be kicked out being
 * told they are not getting it.
 *
 * The moment we grab n_minor_mutex, no other state here can change. So we can
 * go ahead and wake up all waiters with impunity. This is being called from the
 * nvme_dead_taskq.
 */
void
nvme_rwlock_ctrl_dead(void *arg)
{
	nvme_t *nvme = arg;
	nvme_lock_t *ctrl_lock = &nvme->n_lock;
	nvme_minor_lock_info_t *info;

	mutex_enter(&nvme->n_minor_mutex);
	for (uint32_t i = 1; i <= nvme->n_namespace_count; i++) {
		nvme_namespace_t *ns = nvme_nsid2ns(nvme, i);
		nvme_lock_t *ns_lock = &ns->ns_lock;

		while ((info = list_remove_head(&ns_lock->nl_pend_readers)) !=
		    NULL) {
			nvme_rwlock_ctrl_dead_cleanup_one(nvme, info);
		}

		while ((info = list_remove_head(&ns_lock->nl_pend_writers)) !=
		    NULL) {
			nvme_rwlock_ctrl_dead_cleanup_one(nvme, info);
		}
	}

	while ((info = list_remove_head(&ctrl_lock->nl_pend_readers)) != NULL) {
		nvme_rwlock_ctrl_dead_cleanup_one(nvme, info);
	}

	while ((info = list_remove_head(&ctrl_lock->nl_pend_writers)) != NULL) {

		nvme_rwlock_ctrl_dead_cleanup_one(nvme, info);
	}
	mutex_exit(&nvme->n_minor_mutex);
}

void
nvme_lock_fini(nvme_lock_t *lock)
{
	VERIFY3P(lock->nl_writer, ==, NULL);
	list_destroy(&lock->nl_pend_writers);
	list_destroy(&lock->nl_pend_readers);
	list_destroy(&lock->nl_readers);
}

void
nvme_lock_init(nvme_lock_t *lock)
{
	list_create(&lock->nl_readers, sizeof (nvme_minor_lock_info_t),
	    offsetof(nvme_minor_lock_info_t, nli_node));
	list_create(&lock->nl_pend_readers, sizeof (nvme_minor_lock_info_t),
	    offsetof(nvme_minor_lock_info_t, nli_node));
	list_create(&lock->nl_pend_writers, sizeof (nvme_minor_lock_info_t),
	    offsetof(nvme_minor_lock_info_t, nli_node));
}
