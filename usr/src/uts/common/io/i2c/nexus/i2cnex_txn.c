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
 * Copyright 2025 Oxide Computer Company
 */

/*
 * This file implements the core controller locking logic and mechanisms. See
 * the Locking section in the theory statement for more background and
 * information.
 */

#include "i2cnex.h"

void
i2c_txn_free(i2c_txn_t *txn)
{
	if (txn == NULL) {
		return;
	}

	VERIFY3U(txn->txn_state, ==, I2C_TXN_STATE_UNLOCKED);
	i2c_ctrl_t *ctrl = txn->txn_ctrl;

	mutex_enter(&ctrl->ic_txn_lock);
	list_remove(&ctrl->ic_txns, txn);
	mutex_exit(&ctrl->ic_txn_lock);

	cv_destroy(&txn->txn_cv);
	kmem_free(txn, sizeof (i2c_txn_t));
}

i2c_txn_t *
i2c_txn_alloc(i2c_ctrl_t *ctrl, i2c_txn_tag_t tag, const void *debug)
{
	i2c_txn_t *txn = kmem_zalloc(sizeof (i2c_txn_t), KM_SLEEP);

	txn->txn_tag = tag;
	txn->txn_debug = debug;
	txn->txn_alloc_kthread = (uintptr_t)curthread;
	txn->txn_ctrl = ctrl;
	cv_init(&txn->txn_cv, NULL, CV_DRIVER, NULL);

	mutex_enter(&ctrl->ic_txn_lock);
	list_insert_tail(&ctrl->ic_txns, txn);
	mutex_exit(&ctrl->ic_txn_lock);

	return (txn);
}


bool
i2c_txn_held(i2c_txn_t *txn)
{
	if (txn == NULL) {
		return (false);
	}

	i2c_ctrl_t *ctrl = txn->txn_ctrl;
	i2c_ctrl_lock_t *lock = &ctrl->ic_lock;

	mutex_enter(&lock->cl_mutex);
	bool ret = lock->cl_owner == txn;
	mutex_exit(&lock->cl_mutex);

	return (ret);
}

static void
i2c_txn_lock_acquire(i2c_ctrl_lock_t *lock, i2c_txn_t *txn)
{
	VERIFY3P(lock->cl_owner, ==, NULL);
	VERIFY3P(txn->txn_state, ==, I2C_TXN_STATE_UNLOCKED);
	VERIFY3U(list_link_active(&txn->txn_wait_link), ==, 0);
	VERIFY3P(&txn->txn_ctrl->ic_lock, ==, lock);

	txn->txn_state = I2C_TXN_STATE_ACQUIRED;
	txn->txn_last_change = gethrtime();
	txn->txn_acq_kthread = (uintptr_t)curthread;
	txn->txn_acq_pid = curproc->p_pid;

	lock->cl_owner = txn;
	lock->cl_nlocks++;
}

static void
i2c_txn_lock_wakeup(i2c_ctrl_t *ctrl)
{
	i2c_ctrl_lock_t *lock = &ctrl->ic_lock;

	VERIFY(MUTEX_HELD(&lock->cl_mutex));
	VERIFY3P(lock->cl_owner, ==, NULL);

	/*
	 * If there is no one next in line, then we're done. Otherwise we need
	 * to reset that callers state to unlocked and then allow them to
	 * acquire it. After that we will need to signal them.
	 */
	i2c_txn_t *next = list_remove_head(&lock->cl_waiters);
	if (next == NULL)
		return;

	/*
	 * As we're about to acquire this, we're going to note that we're no
	 * longer blocked.
	 */
	next->txn_state = I2C_TXN_STATE_UNLOCKED;
	next->txn_last_change = gethrtime();
	i2c_txn_lock_acquire(lock, next);
	cv_signal(&next->txn_cv);
}

/*
 * Our txn was interrupted due to a signal. However, other activity could have
 * still been going on and we cannot guarantee that the caller didn't actually
 * acquire this and then raced with receiving a signal compared to the
 * cv_signal(). If they did acquire it, then we treat this as a case where we
 * need to go ahead and wake up the next person.
 */
static void
i2c_txn_lock_signal(i2c_ctrl_t *ctrl, i2c_txn_t *txn)
{
	i2c_ctrl_lock_t *lock = &ctrl->ic_lock;

	/*
	 * We don't believe that we should be able to enter here with the lock
	 * unlocked. Either we were blocked waiting for this or the next person
	 * woke us up because we had acquired the controller. There should be no
	 * other state.
	 */
	VERIFY3U(txn->txn_state, !=, I2C_TXN_STATE_UNLOCKED);
	VERIFY(MUTEX_HELD(&lock->cl_mutex));

	/*
	 * As we're changing the state of the this node, we're going to update
	 * the txn's change time now as well as setting the error that'll get
	 * propagated back.
	 */
	txn->txn_last_change = gethrtime();
	txn->txn_err = I2C_CORE_E_LOCK_WAIT_SIGNAL;
	lock->cl_nsig++;

	if (txn->txn_state == I2C_TXN_STATE_BLOCKED) {
		VERIFY3U(lock->cl_owner, !=, txn);
		VERIFY3U(list_link_active(&txn->txn_wait_link), !=, 0);
		list_remove(&lock->cl_waiters, txn);
		txn->txn_state = I2C_TXN_STATE_UNLOCKED;

		lock->cl_nsig_block++;
		return;
	}

	/*
	 * This caller had actually managed to acquire this and now has to give
	 * it up. We treat this as an immediate unlock request.
	 */
	lock->cl_nsig_acq++;
	i2c_txn_ctrl_unlock(txn);
}

void
i2c_txn_ctrl_unlock(i2c_txn_t *txn)
{
	i2c_ctrl_t *ctrl = txn->txn_ctrl;
	i2c_ctrl_lock_t *lock = &ctrl->ic_lock;

	mutex_enter(&lock->cl_mutex);
	VERIFY3P(lock->cl_owner, ==, txn);
	VERIFY3U(txn->txn_state, ==, I2C_TXN_STATE_ACQUIRED);

	txn->txn_last_change = gethrtime();
	txn->txn_state = I2C_TXN_STATE_UNLOCKED;

	/*
	 * Before we proceed to wake anyone up, check to see if we have anything
	 * in our stack. If so, then basically we're in the recursive nexus case
	 * and we need to resume them as the rightful owner without waking
	 * anyone up.
	 */
	lock->cl_owner = list_remove_head(&lock->cl_stack);
	if (lock->cl_owner == NULL) {
		i2c_txn_lock_wakeup(ctrl);
	}
	mutex_exit(&lock->cl_mutex);
}

i2c_errno_t
i2c_txn_ctrl_lock(i2c_txn_t *txn, bool block)
{
	i2c_ctrl_t *ctrl = txn->txn_ctrl;
	i2c_ctrl_lock_t *lock = &ctrl->ic_lock;
	hrtime_t sleep_time;
	i2c_errno_t ret;

	mutex_enter(&lock->cl_mutex);
	/*
	 * First check if this controller is currently held. If it is not, then
	 * this is easy, we get it right away. Note, this implies that there are
	 * no waiters as part of our invariants.
	 */
	VERIFY3P(lock->cl_owner, !=, txn);
	if (lock->cl_owner == NULL) {
		VERIFY3U(list_is_empty(&lock->cl_waiters), !=, 0);
		i2c_txn_lock_acquire(lock, txn);
		mutex_exit(&lock->cl_mutex);
		return (I2C_CORE_E_OK);
	}

	/*
	 * Now, we must see if this is a nexus related operation and we're in
	 * the nexus thread. If so, lock inheritance is basically allowed. That
	 * means that we're allowed to basically "obtain" the lock. This should
	 * only really happen during a device's attach / detach operation.
	 */
	if (lock->cl_nexus_thr == (uintptr_t)curthread) {
		list_insert_head(&lock->cl_stack, lock->cl_owner);
		lock->cl_owner = NULL;
		i2c_txn_lock_acquire(lock, txn);
		lock->cl_nstack++;
		mutex_exit(&lock->cl_mutex);
		return (I2C_CORE_E_OK);
	}

	if (!block) {
		mutex_exit(&lock->cl_mutex);
		return (I2C_CORE_E_LOCK_WOULD_BLOCK);
	}

	VERIFY3U(txn->txn_state, ==, I2C_TXN_STATE_UNLOCKED);
	txn->txn_state = I2C_TXN_STATE_BLOCKED;
	sleep_time = gethrtime();
	list_insert_tail(&lock->cl_waiters, txn);

	while (txn->txn_state == I2C_TXN_STATE_BLOCKED) {
		/*
		 * Block until we receive a signal. Signals to interrupt us
		 * trump any other action that could occur. It's important to
		 * note that we could raise with being signaled and handed the
		 * controller. In that case, we defer to the signal.
		 */
		if (cv_wait_sig(&txn->txn_cv, &lock->cl_mutex) == 0) {
			i2c_txn_lock_signal(ctrl, txn);
			break;
		}
	}

	VERIFY3S(txn->txn_last_change, !=, sleep_time);
	VERIFY3U(list_link_active(&txn->txn_wait_link), ==, 0);
	if (txn->txn_state == I2C_TXN_STATE_UNLOCKED) {
		ret = txn->txn_err;
	} else {
		VERIFY3U(txn->txn_state, ==, I2C_TXN_STATE_ACQUIRED);
		VERIFY3P(lock->cl_owner, ==, txn);
		ret = I2C_CORE_E_OK;
	}

	mutex_exit(&lock->cl_mutex);
	return (ret);
}

void
i2c_txn_nexus_op_end(i2c_txn_t *txn)
{
	i2c_ctrl_t *ctrl = txn->txn_ctrl;
	i2c_ctrl_lock_t *lock = &ctrl->ic_lock;

	mutex_enter(&lock->cl_mutex);
	VERIFY3P(lock->cl_owner, ==, txn);
	VERIFY3U(txn->txn_state, ==, I2C_TXN_STATE_ACQUIRED);
	VERIFY3U(lock->cl_nexus_thr, ==, curthread);

	/*
	 * It is possible for us to have multiple layers of nexus stacking. For
	 * example, a user is doing a device create, which in turn calls a bus
	 * config operation. If this has happened, then we'll have a non-empty
	 * stack.
	 */
	if (list_is_empty(&lock->cl_stack) != 0) {
		lock->cl_nexus_thr = 0;
	}
	mutex_exit(&lock->cl_mutex);
}

void
i2c_txn_nexus_op_begin(i2c_txn_t *txn)
{
	i2c_ctrl_t *ctrl = txn->txn_ctrl;
	i2c_ctrl_lock_t *lock = &ctrl->ic_lock;

	mutex_enter(&lock->cl_mutex);
	VERIFY3P(lock->cl_owner, ==, txn);
	VERIFY3U(txn->txn_state, ==, I2C_TXN_STATE_ACQUIRED);
	VERIFY0(lock->cl_nexus_thr);
	if (lock->cl_nexus_thr != 0) {
		VERIFY3U(lock->cl_nexus_thr, ==, curthread);
	}
	lock->cl_nexus_thr = (uintptr_t)curthread;
	lock->cl_nnexus++;
	mutex_exit(&lock->cl_mutex);
}
