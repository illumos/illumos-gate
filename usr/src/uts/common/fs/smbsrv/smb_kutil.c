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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Nexenta Systems, Inc. All rights reserved.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/tzfile.h>
#include <sys/atomic.h>
#include <sys/kidmap.h>
#include <sys/time.h>
#include <sys/spl.h>
#include <sys/cpuvar.h>
#include <sys/random.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/smb_xdr.h>
#include <smbsrv/smb_vops.h>
#include <smbsrv/smb_idmap.h>

#include <sys/sid.h>
#include <sys/priv_names.h>

static kmem_cache_t	*smb_dtor_cache;
static boolean_t	smb_llist_initialized = B_FALSE;

static boolean_t smb_thread_continue_timedwait_locked(smb_thread_t *, int);

static boolean_t smb_avl_hold(smb_avl_t *);
static void smb_avl_rele(smb_avl_t *);

time_t tzh_leapcnt = 0;

struct tm
*smb_gmtime_r(time_t *clock, struct tm *result);

time_t
smb_timegm(struct tm *tm);

struct	tm {
	int	tm_sec;
	int	tm_min;
	int	tm_hour;
	int	tm_mday;
	int	tm_mon;
	int	tm_year;
	int	tm_wday;
	int	tm_yday;
	int	tm_isdst;
};

static int days_in_month[] = {
	31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

int
smb_ascii_or_unicode_strlen(struct smb_request *sr, char *str)
{
	if (sr->smb_flg2 & SMB_FLAGS2_UNICODE)
		return (smb_wcequiv_strlen(str));
	return (strlen(str));
}

int
smb_ascii_or_unicode_strlen_null(struct smb_request *sr, char *str)
{
	if (sr->smb_flg2 & SMB_FLAGS2_UNICODE)
		return (smb_wcequiv_strlen(str) + 2);
	return (strlen(str) + 1);
}

int
smb_ascii_or_unicode_null_len(struct smb_request *sr)
{
	if (sr->smb_flg2 & SMB_FLAGS2_UNICODE)
		return (2);
	return (1);
}

/*
 *
 * Convert old-style (DOS, LanMan) wildcard strings to NT style.
 * This should ONLY happen to patterns that come from old clients,
 * meaning dialect LANMAN2_1 etc. (dialect < NT_LM_0_12).
 *
 *	? is converted to >
 *	* is converted to < if it is followed by .
 *	. is converted to " if it is followed by ? or * or end of pattern
 *
 * Note: modifies pattern in place.
 */
void
smb_convert_wildcards(char *pattern)
{
	char	*p;

	for (p = pattern; *p != '\0'; p++) {
		switch (*p) {
		case '?':
			*p = '>';
			break;
		case '*':
			if (p[1] == '.')
				*p = '<';
			break;
		case '.':
			if (p[1] == '?' || p[1] == '*' || p[1] == '\0')
				*p = '\"';
			break;
		}
	}
}

/*
 * smb_sattr_check
 *
 * Check file attributes against a search attribute (sattr) mask.
 *
 * Normal files, which includes READONLY and ARCHIVE, always pass
 * this check.  If the DIRECTORY, HIDDEN or SYSTEM special attributes
 * are set then they must appear in the search mask.  The special
 * attributes are inclusive, i.e. all special attributes that appear
 * in sattr must also appear in the file attributes for the check to
 * pass.
 *
 * The following examples show how this works:
 *
 *		fileA:	READONLY
 *		fileB:	0 (no attributes = normal file)
 *		fileC:	READONLY, ARCHIVE
 *		fileD:	HIDDEN
 *		fileE:	READONLY, HIDDEN, SYSTEM
 *		dirA:	DIRECTORY
 *
 * search attribute: 0
 *		Returns: fileA, fileB and fileC.
 * search attribute: HIDDEN
 *		Returns: fileA, fileB, fileC and fileD.
 * search attribute: SYSTEM
 *		Returns: fileA, fileB and fileC.
 * search attribute: DIRECTORY
 *		Returns: fileA, fileB, fileC and dirA.
 * search attribute: HIDDEN and SYSTEM
 *		Returns: fileA, fileB, fileC, fileD and fileE.
 *
 * Returns true if the file and sattr match; otherwise, returns false.
 */
boolean_t
smb_sattr_check(uint16_t dosattr, uint16_t sattr)
{
	if ((dosattr & FILE_ATTRIBUTE_DIRECTORY) &&
	    !(sattr & FILE_ATTRIBUTE_DIRECTORY))
		return (B_FALSE);

	if ((dosattr & FILE_ATTRIBUTE_HIDDEN) &&
	    !(sattr & FILE_ATTRIBUTE_HIDDEN))
		return (B_FALSE);

	if ((dosattr & FILE_ATTRIBUTE_SYSTEM) &&
	    !(sattr & FILE_ATTRIBUTE_SYSTEM))
		return (B_FALSE);

	return (B_TRUE);
}

int
microtime(timestruc_t *tvp)
{
	tvp->tv_sec = gethrestime_sec();
	tvp->tv_nsec = 0;
	return (0);
}

int32_t
clock_get_milli_uptime()
{
	return (TICK_TO_MSEC(ddi_get_lbolt()));
}

/*
 * smb_idpool_increment
 *
 * This function increments the ID pool by doubling the current size. This
 * function assumes the caller entered the mutex of the pool.
 */
static int
smb_idpool_increment(
    smb_idpool_t	*pool)
{
	uint8_t		*new_pool;
	uint32_t	new_size;

	ASSERT(pool->id_magic == SMB_IDPOOL_MAGIC);

	new_size = pool->id_size * 2;
	if (new_size <= SMB_IDPOOL_MAX_SIZE) {
		new_pool = kmem_alloc(new_size / 8, KM_NOSLEEP);
		if (new_pool) {
			bzero(new_pool, new_size / 8);
			bcopy(pool->id_pool, new_pool, pool->id_size / 8);
			kmem_free(pool->id_pool, pool->id_size / 8);
			pool->id_pool = new_pool;
			pool->id_free_counter += new_size - pool->id_size;
			pool->id_max_free_counter += new_size - pool->id_size;
			pool->id_size = new_size;
			pool->id_idx_msk = (new_size / 8) - 1;
			if (new_size >= SMB_IDPOOL_MAX_SIZE) {
				/* id -1 made unavailable */
				pool->id_pool[pool->id_idx_msk] = 0x80;
				pool->id_free_counter--;
				pool->id_max_free_counter--;
			}
			return (0);
		}
	}
	return (-1);
}

/*
 * smb_idpool_constructor
 *
 * This function initializes the pool structure provided.
 */
int
smb_idpool_constructor(
    smb_idpool_t	*pool)
{

	ASSERT(pool->id_magic != SMB_IDPOOL_MAGIC);

	pool->id_size = SMB_IDPOOL_MIN_SIZE;
	pool->id_idx_msk = (SMB_IDPOOL_MIN_SIZE / 8) - 1;
	pool->id_free_counter = SMB_IDPOOL_MIN_SIZE - 1;
	pool->id_max_free_counter = SMB_IDPOOL_MIN_SIZE - 1;
	pool->id_bit = 0x02;
	pool->id_bit_idx = 1;
	pool->id_idx = 0;
	pool->id_pool = (uint8_t *)kmem_alloc((SMB_IDPOOL_MIN_SIZE / 8),
	    KM_SLEEP);
	bzero(pool->id_pool, (SMB_IDPOOL_MIN_SIZE / 8));
	/* -1 id made unavailable */
	pool->id_pool[0] = 0x01;		/* id 0 made unavailable */
	mutex_init(&pool->id_mutex, NULL, MUTEX_DEFAULT, NULL);
	pool->id_magic = SMB_IDPOOL_MAGIC;
	return (0);
}

/*
 * smb_idpool_destructor
 *
 * This function tears down and frees the resources associated with the
 * pool provided.
 */
void
smb_idpool_destructor(
    smb_idpool_t	*pool)
{
	ASSERT(pool->id_magic == SMB_IDPOOL_MAGIC);
	ASSERT(pool->id_free_counter == pool->id_max_free_counter);
	pool->id_magic = (uint32_t)~SMB_IDPOOL_MAGIC;
	mutex_destroy(&pool->id_mutex);
	kmem_free(pool->id_pool, (size_t)(pool->id_size / 8));
}

/*
 * smb_idpool_alloc
 *
 * This function allocates an ID from the pool provided.
 */
int
smb_idpool_alloc(
    smb_idpool_t	*pool,
    uint16_t		*id)
{
	uint32_t	i;
	uint8_t		bit;
	uint8_t		bit_idx;
	uint8_t		byte;

	ASSERT(pool->id_magic == SMB_IDPOOL_MAGIC);

	mutex_enter(&pool->id_mutex);
	if ((pool->id_free_counter == 0) && smb_idpool_increment(pool)) {
		mutex_exit(&pool->id_mutex);
		return (-1);
	}

	i = pool->id_size;
	while (i) {
		bit = pool->id_bit;
		bit_idx = pool->id_bit_idx;
		byte = pool->id_pool[pool->id_idx];
		while (bit) {
			if (byte & bit) {
				bit = bit << 1;
				bit_idx++;
				continue;
			}
			pool->id_pool[pool->id_idx] |= bit;
			*id = (uint16_t)(pool->id_idx * 8 + (uint32_t)bit_idx);
			pool->id_free_counter--;
			pool->id_bit = bit;
			pool->id_bit_idx = bit_idx;
			mutex_exit(&pool->id_mutex);
			return (0);
		}
		pool->id_bit = 1;
		pool->id_bit_idx = 0;
		pool->id_idx++;
		pool->id_idx &= pool->id_idx_msk;
		--i;
	}
	/*
	 * This section of code shouldn't be reached. If there are IDs
	 * available and none could be found there's a problem.
	 */
	ASSERT(0);
	mutex_exit(&pool->id_mutex);
	return (-1);
}

/*
 * smb_idpool_free
 *
 * This function frees the ID provided.
 */
void
smb_idpool_free(
    smb_idpool_t	*pool,
    uint16_t		id)
{
	ASSERT(pool->id_magic == SMB_IDPOOL_MAGIC);
	ASSERT(id != 0);
	ASSERT(id != 0xFFFF);

	mutex_enter(&pool->id_mutex);
	if (pool->id_pool[id >> 3] & (1 << (id & 7))) {
		pool->id_pool[id >> 3] &= ~(1 << (id & 7));
		pool->id_free_counter++;
		ASSERT(pool->id_free_counter <= pool->id_max_free_counter);
		mutex_exit(&pool->id_mutex);
		return;
	}
	/* Freeing a free ID. */
	ASSERT(0);
	mutex_exit(&pool->id_mutex);
}

/*
 * Initialize the llist delete queue object cache.
 */
void
smb_llist_init(void)
{
	if (smb_llist_initialized)
		return;

	smb_dtor_cache = kmem_cache_create("smb_dtor_cache",
	    sizeof (smb_dtor_t), 8, NULL, NULL, NULL, NULL, NULL, 0);

	smb_llist_initialized = B_TRUE;
}

/*
 * Destroy the llist delete queue object cache.
 */
void
smb_llist_fini(void)
{
	if (!smb_llist_initialized)
		return;

	kmem_cache_destroy(smb_dtor_cache);
	smb_llist_initialized = B_FALSE;
}

/*
 * smb_llist_constructor
 *
 * This function initializes a locked list.
 */
void
smb_llist_constructor(
    smb_llist_t	*ll,
    size_t	size,
    size_t	offset)
{
	rw_init(&ll->ll_lock, NULL, RW_DEFAULT, NULL);
	mutex_init(&ll->ll_mutex, NULL, MUTEX_DEFAULT, NULL);
	list_create(&ll->ll_list, size, offset);
	list_create(&ll->ll_deleteq, sizeof (smb_dtor_t),
	    offsetof(smb_dtor_t, dt_lnd));
	ll->ll_count = 0;
	ll->ll_wrop = 0;
	ll->ll_deleteq_count = 0;
	ll->ll_flushing = B_FALSE;
}

/*
 * Flush the delete queue and destroy a locked list.
 */
void
smb_llist_destructor(
    smb_llist_t	*ll)
{
	smb_llist_flush(ll);

	ASSERT(ll->ll_count == 0);
	ASSERT(ll->ll_deleteq_count == 0);

	rw_destroy(&ll->ll_lock);
	list_destroy(&ll->ll_list);
	list_destroy(&ll->ll_deleteq);
	mutex_destroy(&ll->ll_mutex);
}

/*
 * Post an object to the delete queue.  The delete queue will be processed
 * during list exit or list destruction.  Objects are often posted for
 * deletion during list iteration (while the list is locked) but that is
 * not required, and an object can be posted at any time.
 */
void
smb_llist_post(smb_llist_t *ll, void *object, smb_dtorproc_t dtorproc)
{
	smb_dtor_t	*dtor;

	ASSERT((object != NULL) && (dtorproc != NULL));

	dtor = kmem_cache_alloc(smb_dtor_cache, KM_SLEEP);
	bzero(dtor, sizeof (smb_dtor_t));
	dtor->dt_magic = SMB_DTOR_MAGIC;
	dtor->dt_object = object;
	dtor->dt_proc = dtorproc;

	mutex_enter(&ll->ll_mutex);
	list_insert_tail(&ll->ll_deleteq, dtor);
	++ll->ll_deleteq_count;
	mutex_exit(&ll->ll_mutex);
}

/*
 * Exit the list lock and process the delete queue.
 */
void
smb_llist_exit(smb_llist_t *ll)
{
	rw_exit(&ll->ll_lock);
	smb_llist_flush(ll);
}

/*
 * Flush the list delete queue.  The mutex is dropped across the destructor
 * call in case this leads to additional objects being posted to the delete
 * queue.
 */
void
smb_llist_flush(smb_llist_t *ll)
{
	smb_dtor_t    *dtor;

	mutex_enter(&ll->ll_mutex);
	if (ll->ll_flushing) {
		mutex_exit(&ll->ll_mutex);
		return;
	}
	ll->ll_flushing = B_TRUE;

	dtor = list_head(&ll->ll_deleteq);
	while (dtor != NULL) {
		SMB_DTOR_VALID(dtor);
		ASSERT((dtor->dt_object != NULL) && (dtor->dt_proc != NULL));
		list_remove(&ll->ll_deleteq, dtor);
		--ll->ll_deleteq_count;
		mutex_exit(&ll->ll_mutex);

		dtor->dt_proc(dtor->dt_object);

		dtor->dt_magic = (uint32_t)~SMB_DTOR_MAGIC;
		kmem_cache_free(smb_dtor_cache, dtor);
		mutex_enter(&ll->ll_mutex);
		dtor = list_head(&ll->ll_deleteq);
	}
	ll->ll_flushing = B_FALSE;

	mutex_exit(&ll->ll_mutex);
}

/*
 * smb_llist_upgrade
 *
 * This function tries to upgrade the lock of the locked list. It assumes the
 * locked has already been entered in RW_READER mode. It first tries using the
 * Solaris function rw_tryupgrade(). If that call fails the lock is released
 * and reentered in RW_WRITER mode. In that last case a window is opened during
 * which the contents of the list may have changed. The return code indicates
 * whether or not the list was modified when the lock was exited.
 */
int smb_llist_upgrade(
    smb_llist_t *ll)
{
	uint64_t	wrop;

	if (rw_tryupgrade(&ll->ll_lock) != 0) {
		return (0);
	}
	wrop = ll->ll_wrop;
	rw_exit(&ll->ll_lock);
	rw_enter(&ll->ll_lock, RW_WRITER);
	return (wrop != ll->ll_wrop);
}

/*
 * smb_llist_insert_head
 *
 * This function inserts the object passed a the beginning of the list. This
 * function assumes the lock of the list has already been entered.
 */
void
smb_llist_insert_head(
    smb_llist_t	*ll,
    void	*obj)
{
	list_insert_head(&ll->ll_list, obj);
	++ll->ll_wrop;
	++ll->ll_count;
}

/*
 * smb_llist_insert_tail
 *
 * This function appends to the object passed to the list. This function assumes
 * the lock of the list has already been entered.
 *
 */
void
smb_llist_insert_tail(
    smb_llist_t	*ll,
    void	*obj)
{
	list_insert_tail(&ll->ll_list, obj);
	++ll->ll_wrop;
	++ll->ll_count;
}

/*
 * smb_llist_remove
 *
 * This function removes the object passed from the list. This function assumes
 * the lock of the list has already been entered.
 */
void
smb_llist_remove(
    smb_llist_t	*ll,
    void	*obj)
{
	list_remove(&ll->ll_list, obj);
	++ll->ll_wrop;
	--ll->ll_count;
}

/*
 * smb_llist_get_count
 *
 * This function returns the number of elements in the specified list.
 */
uint32_t
smb_llist_get_count(
    smb_llist_t *ll)
{
	return (ll->ll_count);
}

/*
 * smb_slist_constructor
 *
 * Synchronized list constructor.
 */
void
smb_slist_constructor(
    smb_slist_t	*sl,
    size_t	size,
    size_t	offset)
{
	mutex_init(&sl->sl_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&sl->sl_cv, NULL, CV_DEFAULT, NULL);
	list_create(&sl->sl_list, size, offset);
	sl->sl_count = 0;
	sl->sl_waiting = B_FALSE;
}

/*
 * smb_slist_destructor
 *
 * Synchronized list destructor.
 */
void
smb_slist_destructor(
    smb_slist_t	*sl)
{
	VERIFY(sl->sl_count == 0);

	mutex_destroy(&sl->sl_mutex);
	cv_destroy(&sl->sl_cv);
	list_destroy(&sl->sl_list);
}

/*
 * smb_slist_insert_head
 *
 * This function inserts the object passed a the beginning of the list.
 */
void
smb_slist_insert_head(
    smb_slist_t	*sl,
    void	*obj)
{
	mutex_enter(&sl->sl_mutex);
	list_insert_head(&sl->sl_list, obj);
	++sl->sl_count;
	mutex_exit(&sl->sl_mutex);
}

/*
 * smb_slist_insert_tail
 *
 * This function appends the object passed to the list.
 */
void
smb_slist_insert_tail(
    smb_slist_t	*sl,
    void	*obj)
{
	mutex_enter(&sl->sl_mutex);
	list_insert_tail(&sl->sl_list, obj);
	++sl->sl_count;
	mutex_exit(&sl->sl_mutex);
}

/*
 * smb_llist_remove
 *
 * This function removes the object passed by the caller from the list.
 */
void
smb_slist_remove(
    smb_slist_t	*sl,
    void	*obj)
{
	mutex_enter(&sl->sl_mutex);
	list_remove(&sl->sl_list, obj);
	if ((--sl->sl_count == 0) && (sl->sl_waiting)) {
		sl->sl_waiting = B_FALSE;
		cv_broadcast(&sl->sl_cv);
	}
	mutex_exit(&sl->sl_mutex);
}

/*
 * smb_slist_move_tail
 *
 * This function transfers all the contents of the synchronized list to the
 * list_t provided. It returns the number of objects transferred.
 */
uint32_t
smb_slist_move_tail(
    list_t	*lst,
    smb_slist_t	*sl)
{
	uint32_t	rv;

	mutex_enter(&sl->sl_mutex);
	rv = sl->sl_count;
	if (sl->sl_count) {
		list_move_tail(lst, &sl->sl_list);
		sl->sl_count = 0;
		if (sl->sl_waiting) {
			sl->sl_waiting = B_FALSE;
			cv_broadcast(&sl->sl_cv);
		}
	}
	mutex_exit(&sl->sl_mutex);
	return (rv);
}

/*
 * smb_slist_obj_move
 *
 * This function moves an object from one list to the end of the other list. It
 * assumes the mutex of each list has been entered.
 */
void
smb_slist_obj_move(
    smb_slist_t	*dst,
    smb_slist_t	*src,
    void	*obj)
{
	ASSERT(dst->sl_list.list_offset == src->sl_list.list_offset);
	ASSERT(dst->sl_list.list_size == src->sl_list.list_size);

	list_remove(&src->sl_list, obj);
	list_insert_tail(&dst->sl_list, obj);
	dst->sl_count++;
	src->sl_count--;
	if ((src->sl_count == 0) && (src->sl_waiting)) {
		src->sl_waiting = B_FALSE;
		cv_broadcast(&src->sl_cv);
	}
}

/*
 * smb_slist_wait_for_empty
 *
 * This function waits for a list to be emptied.
 */
void
smb_slist_wait_for_empty(
    smb_slist_t	*sl)
{
	mutex_enter(&sl->sl_mutex);
	while (sl->sl_count) {
		sl->sl_waiting = B_TRUE;
		cv_wait(&sl->sl_cv, &sl->sl_mutex);
	}
	mutex_exit(&sl->sl_mutex);
}

/*
 * smb_slist_exit
 *
 * This function exits the muetx of the list and signal the condition variable
 * if the list is empty.
 */
void
smb_slist_exit(smb_slist_t *sl)
{
	if ((sl->sl_count == 0) && (sl->sl_waiting)) {
		sl->sl_waiting = B_FALSE;
		cv_broadcast(&sl->sl_cv);
	}
	mutex_exit(&sl->sl_mutex);
}

/*
 * smb_thread_entry_point
 *
 * Common entry point for all the threads created through smb_thread_start.
 * The state of the thread is set to "running" at the beginning and moved to
 * "exiting" just before calling thread_exit(). The condition variable is
 *  also signaled.
 */
static void
smb_thread_entry_point(
    smb_thread_t	*thread)
{
	ASSERT(thread->sth_magic == SMB_THREAD_MAGIC);
	mutex_enter(&thread->sth_mtx);
	ASSERT(thread->sth_state == SMB_THREAD_STATE_STARTING);
	thread->sth_th = curthread;
	thread->sth_did = thread->sth_th->t_did;

	if (!thread->sth_kill) {
		thread->sth_state = SMB_THREAD_STATE_RUNNING;
		cv_signal(&thread->sth_cv);
		mutex_exit(&thread->sth_mtx);
		thread->sth_ep(thread, thread->sth_ep_arg);
		mutex_enter(&thread->sth_mtx);
	}
	thread->sth_th = NULL;
	thread->sth_state = SMB_THREAD_STATE_EXITING;
	cv_broadcast(&thread->sth_cv);
	mutex_exit(&thread->sth_mtx);
	thread_exit();
}

/*
 * smb_thread_init
 */
void
smb_thread_init(
    smb_thread_t	*thread,
    char		*name,
    smb_thread_ep_t	ep,
    void		*ep_arg,
    pri_t		pri)
{
	ASSERT(thread->sth_magic != SMB_THREAD_MAGIC);

	bzero(thread, sizeof (*thread));

	(void) strlcpy(thread->sth_name, name, sizeof (thread->sth_name));
	thread->sth_ep = ep;
	thread->sth_ep_arg = ep_arg;
	thread->sth_state = SMB_THREAD_STATE_EXITED;
	thread->sth_pri = pri;
	mutex_init(&thread->sth_mtx, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&thread->sth_cv, NULL, CV_DEFAULT, NULL);
	thread->sth_magic = SMB_THREAD_MAGIC;
}

/*
 * smb_thread_destroy
 */
void
smb_thread_destroy(
    smb_thread_t	*thread)
{
	ASSERT(thread->sth_magic == SMB_THREAD_MAGIC);
	ASSERT(thread->sth_state == SMB_THREAD_STATE_EXITED);
	thread->sth_magic = 0;
	mutex_destroy(&thread->sth_mtx);
	cv_destroy(&thread->sth_cv);
}

/*
 * smb_thread_start
 *
 * This function starts a thread with the parameters provided. It waits until
 * the state of the thread has been moved to running.
 */
/*ARGSUSED*/
int
smb_thread_start(
    smb_thread_t	*thread)
{
	int		rc = 0;
	kthread_t	*tmpthread;

	ASSERT(thread->sth_magic == SMB_THREAD_MAGIC);

	mutex_enter(&thread->sth_mtx);
	switch (thread->sth_state) {
	case SMB_THREAD_STATE_EXITED:
		thread->sth_state = SMB_THREAD_STATE_STARTING;
		mutex_exit(&thread->sth_mtx);
		tmpthread = thread_create(NULL, 0, smb_thread_entry_point,
		    thread, 0, &p0, TS_RUN, thread->sth_pri);
		ASSERT(tmpthread != NULL);
		mutex_enter(&thread->sth_mtx);
		while (thread->sth_state == SMB_THREAD_STATE_STARTING)
			cv_wait(&thread->sth_cv, &thread->sth_mtx);
		if (thread->sth_state != SMB_THREAD_STATE_RUNNING)
			rc = -1;
		break;
	default:
		ASSERT(0);
		rc = -1;
		break;
	}
	mutex_exit(&thread->sth_mtx);
	return (rc);
}

/*
 * smb_thread_stop
 *
 * This function signals a thread to kill itself and waits until the "exiting"
 * state has been reached.
 */
void
smb_thread_stop(smb_thread_t *thread)
{
	ASSERT(thread->sth_magic == SMB_THREAD_MAGIC);

	mutex_enter(&thread->sth_mtx);
	switch (thread->sth_state) {
	case SMB_THREAD_STATE_RUNNING:
	case SMB_THREAD_STATE_STARTING:
		if (!thread->sth_kill) {
			thread->sth_kill = B_TRUE;
			cv_broadcast(&thread->sth_cv);
			while (thread->sth_state != SMB_THREAD_STATE_EXITING)
				cv_wait(&thread->sth_cv, &thread->sth_mtx);
			mutex_exit(&thread->sth_mtx);
			thread_join(thread->sth_did);
			mutex_enter(&thread->sth_mtx);
			thread->sth_state = SMB_THREAD_STATE_EXITED;
			thread->sth_did = 0;
			thread->sth_kill = B_FALSE;
			cv_broadcast(&thread->sth_cv);
			break;
		}
		/*FALLTHRU*/

	case SMB_THREAD_STATE_EXITING:
		if (thread->sth_kill) {
			while (thread->sth_state != SMB_THREAD_STATE_EXITED)
				cv_wait(&thread->sth_cv, &thread->sth_mtx);
		} else {
			thread->sth_state = SMB_THREAD_STATE_EXITED;
			thread->sth_did = 0;
		}
		break;

	case SMB_THREAD_STATE_EXITED:
		break;

	default:
		ASSERT(0);
		break;
	}
	mutex_exit(&thread->sth_mtx);
}

/*
 * smb_thread_signal
 *
 * This function signals a thread.
 */
void
smb_thread_signal(smb_thread_t *thread)
{
	ASSERT(thread->sth_magic == SMB_THREAD_MAGIC);

	mutex_enter(&thread->sth_mtx);
	switch (thread->sth_state) {
	case SMB_THREAD_STATE_RUNNING:
		cv_signal(&thread->sth_cv);
		break;

	default:
		break;
	}
	mutex_exit(&thread->sth_mtx);
}

boolean_t
smb_thread_continue(smb_thread_t *thread)
{
	boolean_t result;

	ASSERT(thread->sth_magic == SMB_THREAD_MAGIC);

	mutex_enter(&thread->sth_mtx);
	result = smb_thread_continue_timedwait_locked(thread, 0);
	mutex_exit(&thread->sth_mtx);

	return (result);
}

boolean_t
smb_thread_continue_nowait(smb_thread_t *thread)
{
	boolean_t result;

	ASSERT(thread->sth_magic == SMB_THREAD_MAGIC);

	mutex_enter(&thread->sth_mtx);
	/*
	 * Setting ticks=-1 requests a non-blocking check.  We will
	 * still block if the thread is in "suspend" state.
	 */
	result = smb_thread_continue_timedwait_locked(thread, -1);
	mutex_exit(&thread->sth_mtx);

	return (result);
}

boolean_t
smb_thread_continue_timedwait(smb_thread_t *thread, int seconds)
{
	boolean_t result;

	ASSERT(thread->sth_magic == SMB_THREAD_MAGIC);

	mutex_enter(&thread->sth_mtx);
	result = smb_thread_continue_timedwait_locked(thread,
	    SEC_TO_TICK(seconds));
	mutex_exit(&thread->sth_mtx);

	return (result);
}

/*
 * smb_thread_continue_timedwait_locked
 *
 * Internal only.  Ticks==-1 means don't block, Ticks == 0 means wait
 * indefinitely
 */
static boolean_t
smb_thread_continue_timedwait_locked(smb_thread_t *thread, int ticks)
{
	boolean_t	result;

	/* -1 means don't block */
	if (ticks != -1 && !thread->sth_kill) {
		if (ticks == 0) {
			cv_wait(&thread->sth_cv, &thread->sth_mtx);
		} else {
			(void) cv_reltimedwait(&thread->sth_cv,
			    &thread->sth_mtx, (clock_t)ticks, TR_CLOCK_TICK);
		}
	}
	result = (thread->sth_kill == 0);

	return (result);
}

/*
 * smb_rwx_init
 */
void
smb_rwx_init(
    smb_rwx_t	*rwx)
{
	bzero(rwx, sizeof (smb_rwx_t));
	cv_init(&rwx->rwx_cv, NULL, CV_DEFAULT, NULL);
	mutex_init(&rwx->rwx_mutex, NULL, MUTEX_DEFAULT, NULL);
	rw_init(&rwx->rwx_lock, NULL, RW_DEFAULT, NULL);
}

/*
 * smb_rwx_destroy
 */
void
smb_rwx_destroy(
    smb_rwx_t	*rwx)
{
	mutex_destroy(&rwx->rwx_mutex);
	cv_destroy(&rwx->rwx_cv);
	rw_destroy(&rwx->rwx_lock);
}

/*
 * smb_rwx_rwexit
 */
void
smb_rwx_rwexit(
    smb_rwx_t	*rwx)
{
	if (rw_write_held(&rwx->rwx_lock)) {
		ASSERT(rw_owner(&rwx->rwx_lock) == curthread);
		mutex_enter(&rwx->rwx_mutex);
		if (rwx->rwx_waiting) {
			rwx->rwx_waiting = B_FALSE;
			cv_broadcast(&rwx->rwx_cv);
		}
		mutex_exit(&rwx->rwx_mutex);
	}
	rw_exit(&rwx->rwx_lock);
}

/*
 * smb_rwx_rwupgrade
 */
krw_t
smb_rwx_rwupgrade(
    smb_rwx_t	*rwx)
{
	if (rw_write_held(&rwx->rwx_lock)) {
		ASSERT(rw_owner(&rwx->rwx_lock) == curthread);
		return (RW_WRITER);
	}
	if (!rw_tryupgrade(&rwx->rwx_lock)) {
		rw_exit(&rwx->rwx_lock);
		rw_enter(&rwx->rwx_lock, RW_WRITER);
	}
	return (RW_READER);
}

/*
 * smb_rwx_rwrestore
 */
void
smb_rwx_rwdowngrade(
    smb_rwx_t	*rwx,
    krw_t	mode)
{
	ASSERT(rw_write_held(&rwx->rwx_lock));
	ASSERT(rw_owner(&rwx->rwx_lock) == curthread);

	if (mode == RW_WRITER) {
		return;
	}
	ASSERT(mode == RW_READER);
	mutex_enter(&rwx->rwx_mutex);
	if (rwx->rwx_waiting) {
		rwx->rwx_waiting = B_FALSE;
		cv_broadcast(&rwx->rwx_cv);
	}
	mutex_exit(&rwx->rwx_mutex);
	rw_downgrade(&rwx->rwx_lock);
}

/*
 * smb_rwx_wait
 *
 * This function assumes the smb_rwx lock was enter in RW_READER or RW_WRITER
 * mode. It will:
 *
 *	1) release the lock and save its current mode.
 *	2) wait until the condition variable is signaled. This can happen for
 *	   2 reasons: When a writer releases the lock or when the time out (if
 *	   provided) expires.
 *	3) re-acquire the lock in the mode saved in (1).
 */
int
smb_rwx_rwwait(
    smb_rwx_t	*rwx,
    clock_t	timeout)
{
	int	rc;
	krw_t	mode;

	mutex_enter(&rwx->rwx_mutex);
	rwx->rwx_waiting = B_TRUE;
	mutex_exit(&rwx->rwx_mutex);

	if (rw_write_held(&rwx->rwx_lock)) {
		ASSERT(rw_owner(&rwx->rwx_lock) == curthread);
		mode = RW_WRITER;
	} else {
		ASSERT(rw_read_held(&rwx->rwx_lock));
		mode = RW_READER;
	}
	rw_exit(&rwx->rwx_lock);

	mutex_enter(&rwx->rwx_mutex);
	if (rwx->rwx_waiting) {
		if (timeout == -1) {
			rc = 1;
			cv_wait(&rwx->rwx_cv, &rwx->rwx_mutex);
		} else {
			rc = cv_reltimedwait(&rwx->rwx_cv, &rwx->rwx_mutex,
			    timeout, TR_CLOCK_TICK);
		}
	}
	mutex_exit(&rwx->rwx_mutex);

	rw_enter(&rwx->rwx_lock, mode);
	return (rc);
}

/*
 * SMB ID mapping
 *
 * Solaris ID mapping service (aka Winchester) works with domain SIDs
 * and RIDs where domain SIDs are in string format. CIFS service works
 * with binary SIDs understandable by CIFS clients. A layer of SMB ID
 * mapping functions are implemeted to hide the SID conversion details
 * and also hide the handling of array of batch mapping requests.
 *
 * IMPORTANT NOTE The Winchester API requires a zone. Because CIFS server
 * currently only runs in the global zone the global zone is specified.
 * This needs to be fixed when the CIFS server supports zones.
 */

static int smb_idmap_batch_binsid(smb_idmap_batch_t *sib);

/*
 * smb_idmap_getid
 *
 * Maps the given Windows SID to a Solaris ID using the
 * simple mapping API.
 */
idmap_stat
smb_idmap_getid(smb_sid_t *sid, uid_t *id, int *idtype)
{
	smb_idmap_t sim;
	char sidstr[SMB_SID_STRSZ];

	smb_sid_tostr(sid, sidstr);
	if (smb_sid_splitstr(sidstr, &sim.sim_rid) != 0)
		return (IDMAP_ERR_SID);
	sim.sim_domsid = sidstr;
	sim.sim_id = id;

	switch (*idtype) {
	case SMB_IDMAP_USER:
		sim.sim_stat = kidmap_getuidbysid(global_zone, sim.sim_domsid,
		    sim.sim_rid, sim.sim_id);
		break;

	case SMB_IDMAP_GROUP:
		sim.sim_stat = kidmap_getgidbysid(global_zone, sim.sim_domsid,
		    sim.sim_rid, sim.sim_id);
		break;

	case SMB_IDMAP_UNKNOWN:
		sim.sim_stat = kidmap_getpidbysid(global_zone, sim.sim_domsid,
		    sim.sim_rid, sim.sim_id, &sim.sim_idtype);
		break;

	default:
		ASSERT(0);
		return (IDMAP_ERR_ARG);
	}

	*idtype = sim.sim_idtype;

	return (sim.sim_stat);
}

/*
 * smb_idmap_getsid
 *
 * Maps the given Solaris ID to a Windows SID using the
 * simple mapping API.
 */
idmap_stat
smb_idmap_getsid(uid_t id, int idtype, smb_sid_t **sid)
{
	smb_idmap_t sim;

	switch (idtype) {
	case SMB_IDMAP_USER:
		sim.sim_stat = kidmap_getsidbyuid(global_zone, id,
		    (const char **)&sim.sim_domsid, &sim.sim_rid);
		break;

	case SMB_IDMAP_GROUP:
		sim.sim_stat = kidmap_getsidbygid(global_zone, id,
		    (const char **)&sim.sim_domsid, &sim.sim_rid);
		break;

	case SMB_IDMAP_EVERYONE:
		/* Everyone S-1-1-0 */
		sim.sim_domsid = "S-1-1";
		sim.sim_rid = 0;
		sim.sim_stat = IDMAP_SUCCESS;
		break;

	default:
		ASSERT(0);
		return (IDMAP_ERR_ARG);
	}

	if (sim.sim_stat != IDMAP_SUCCESS)
		return (sim.sim_stat);

	if (sim.sim_domsid == NULL)
		return (IDMAP_ERR_NOMAPPING);

	sim.sim_sid = smb_sid_fromstr(sim.sim_domsid);
	if (sim.sim_sid == NULL)
		return (IDMAP_ERR_INTERNAL);

	*sid = smb_sid_splice(sim.sim_sid, sim.sim_rid);
	smb_sid_free(sim.sim_sid);
	if (*sid == NULL)
		sim.sim_stat = IDMAP_ERR_INTERNAL;

	return (sim.sim_stat);
}

/*
 * smb_idmap_batch_create
 *
 * Creates and initializes the context for batch ID mapping.
 */
idmap_stat
smb_idmap_batch_create(smb_idmap_batch_t *sib, uint16_t nmap, int flags)
{
	ASSERT(sib);

	bzero(sib, sizeof (smb_idmap_batch_t));

	sib->sib_idmaph = kidmap_get_create(global_zone);

	sib->sib_flags = flags;
	sib->sib_nmap = nmap;
	sib->sib_size = nmap * sizeof (smb_idmap_t);
	sib->sib_maps = kmem_zalloc(sib->sib_size, KM_SLEEP);

	return (IDMAP_SUCCESS);
}

/*
 * smb_idmap_batch_destroy
 *
 * Frees the batch ID mapping context.
 * If ID mapping is Solaris -> Windows it frees memories
 * allocated for binary SIDs.
 */
void
smb_idmap_batch_destroy(smb_idmap_batch_t *sib)
{
	char *domsid;
	int i;

	ASSERT(sib);
	ASSERT(sib->sib_maps);

	if (sib->sib_idmaph)
		kidmap_get_destroy(sib->sib_idmaph);

	if (sib->sib_flags & SMB_IDMAP_ID2SID) {
		/*
		 * SIDs are allocated only when mapping
		 * UID/GID to SIDs
		 */
		for (i = 0; i < sib->sib_nmap; i++)
			smb_sid_free(sib->sib_maps[i].sim_sid);
	} else if (sib->sib_flags & SMB_IDMAP_SID2ID) {
		/*
		 * SID prefixes are allocated only when mapping
		 * SIDs to UID/GID
		 */
		for (i = 0; i < sib->sib_nmap; i++) {
			domsid = sib->sib_maps[i].sim_domsid;
			if (domsid)
				smb_mem_free(domsid);
		}
	}

	if (sib->sib_size && sib->sib_maps)
		kmem_free(sib->sib_maps, sib->sib_size);
}

/*
 * smb_idmap_batch_getid
 *
 * Queue a request to map the given SID to a UID or GID.
 *
 * sim->sim_id should point to variable that's supposed to
 * hold the returned UID/GID. This needs to be setup by caller
 * of this function.
 *
 * If requested ID type is known, it's passed as 'idtype',
 * if it's unknown it'll be returned in sim->sim_idtype.
 */
idmap_stat
smb_idmap_batch_getid(idmap_get_handle_t *idmaph, smb_idmap_t *sim,
    smb_sid_t *sid, int idtype)
{
	char strsid[SMB_SID_STRSZ];
	idmap_stat idm_stat;

	ASSERT(idmaph);
	ASSERT(sim);
	ASSERT(sid);

	smb_sid_tostr(sid, strsid);
	if (smb_sid_splitstr(strsid, &sim->sim_rid) != 0)
		return (IDMAP_ERR_SID);
	sim->sim_domsid = smb_mem_strdup(strsid);

	switch (idtype) {
	case SMB_IDMAP_USER:
		idm_stat = kidmap_batch_getuidbysid(idmaph, sim->sim_domsid,
		    sim->sim_rid, sim->sim_id, &sim->sim_stat);
		break;

	case SMB_IDMAP_GROUP:
		idm_stat = kidmap_batch_getgidbysid(idmaph, sim->sim_domsid,
		    sim->sim_rid, sim->sim_id, &sim->sim_stat);
		break;

	case SMB_IDMAP_UNKNOWN:
		idm_stat = kidmap_batch_getpidbysid(idmaph, sim->sim_domsid,
		    sim->sim_rid, sim->sim_id, &sim->sim_idtype,
		    &sim->sim_stat);
		break;

	default:
		ASSERT(0);
		return (IDMAP_ERR_ARG);
	}

	return (idm_stat);
}

/*
 * smb_idmap_batch_getsid
 *
 * Queue a request to map the given UID/GID to a SID.
 *
 * sim->sim_domsid and sim->sim_rid will contain the mapping
 * result upon successful process of the batched request.
 */
idmap_stat
smb_idmap_batch_getsid(idmap_get_handle_t *idmaph, smb_idmap_t *sim,
    uid_t id, int idtype)
{
	idmap_stat idm_stat;

	switch (idtype) {
	case SMB_IDMAP_USER:
		idm_stat = kidmap_batch_getsidbyuid(idmaph, id,
		    (const char **)&sim->sim_domsid, &sim->sim_rid,
		    &sim->sim_stat);
		break;

	case SMB_IDMAP_GROUP:
		idm_stat = kidmap_batch_getsidbygid(idmaph, id,
		    (const char **)&sim->sim_domsid, &sim->sim_rid,
		    &sim->sim_stat);
		break;

	case SMB_IDMAP_OWNERAT:
		/* Current Owner S-1-5-32-766 */
		sim->sim_domsid = NT_BUILTIN_DOMAIN_SIDSTR;
		sim->sim_rid = SECURITY_CURRENT_OWNER_RID;
		sim->sim_stat = IDMAP_SUCCESS;
		idm_stat = IDMAP_SUCCESS;
		break;

	case SMB_IDMAP_GROUPAT:
		/* Current Group S-1-5-32-767 */
		sim->sim_domsid = NT_BUILTIN_DOMAIN_SIDSTR;
		sim->sim_rid = SECURITY_CURRENT_GROUP_RID;
		sim->sim_stat = IDMAP_SUCCESS;
		idm_stat = IDMAP_SUCCESS;
		break;

	case SMB_IDMAP_EVERYONE:
		/* Everyone S-1-1-0 */
		sim->sim_domsid = NT_WORLD_AUTH_SIDSTR;
		sim->sim_rid = 0;
		sim->sim_stat = IDMAP_SUCCESS;
		idm_stat = IDMAP_SUCCESS;
		break;

	default:
		ASSERT(0);
		return (IDMAP_ERR_ARG);
	}

	return (idm_stat);
}

/*
 * smb_idmap_batch_binsid
 *
 * Convert sidrids to binary sids
 *
 * Returns 0 if successful and non-zero upon failure.
 */
static int
smb_idmap_batch_binsid(smb_idmap_batch_t *sib)
{
	smb_sid_t *sid;
	smb_idmap_t *sim;
	int i;

	if (sib->sib_flags & SMB_IDMAP_SID2ID)
		/* This operation is not required */
		return (0);

	sim = sib->sib_maps;
	for (i = 0; i < sib->sib_nmap; sim++, i++) {
		ASSERT(sim->sim_domsid);
		if (sim->sim_domsid == NULL)
			return (1);

		if ((sid = smb_sid_fromstr(sim->sim_domsid)) == NULL)
			return (1);

		sim->sim_sid = smb_sid_splice(sid, sim->sim_rid);
		smb_sid_free(sid);
	}

	return (0);
}

/*
 * smb_idmap_batch_getmappings
 *
 * trigger ID mapping service to get the mappings for queued
 * requests.
 *
 * Checks the result of all the queued requests.
 * If this is a Solaris -> Windows mapping it generates
 * binary SIDs from returned (domsid, rid) pairs.
 */
idmap_stat
smb_idmap_batch_getmappings(smb_idmap_batch_t *sib)
{
	idmap_stat idm_stat = IDMAP_SUCCESS;
	int i;

	idm_stat = kidmap_get_mappings(sib->sib_idmaph);
	if (idm_stat != IDMAP_SUCCESS)
		return (idm_stat);

	/*
	 * Check the status for all the queued requests
	 */
	for (i = 0; i < sib->sib_nmap; i++) {
		if (sib->sib_maps[i].sim_stat != IDMAP_SUCCESS)
			return (sib->sib_maps[i].sim_stat);
	}

	if (smb_idmap_batch_binsid(sib) != 0)
		idm_stat = IDMAP_ERR_OTHER;

	return (idm_stat);
}

uint64_t
smb_time_unix_to_nt(timestruc_t *unix_time)
{
	uint64_t nt_time;

	if ((unix_time->tv_sec == 0) && (unix_time->tv_nsec == 0))
		return (0);

	nt_time = unix_time->tv_sec;
	nt_time *= 10000000;  /* seconds to 100ns */
	nt_time += unix_time->tv_nsec / 100;
	return (nt_time + NT_TIME_BIAS);
}

void
smb_time_nt_to_unix(uint64_t nt_time, timestruc_t *unix_time)
{
	uint32_t seconds;

	ASSERT(unix_time);

	if ((nt_time == 0) || (nt_time == -1)) {
		unix_time->tv_sec = 0;
		unix_time->tv_nsec = 0;
		return;
	}

	nt_time -= NT_TIME_BIAS;
	seconds = nt_time / 10000000;
	unix_time->tv_sec = seconds;
	unix_time->tv_nsec = (nt_time  % 10000000) * 100;
}

/*
 * smb_time_gmt_to_local, smb_time_local_to_gmt
 *
 * Apply the gmt offset to convert between local time and gmt
 */
int32_t
smb_time_gmt_to_local(smb_request_t *sr, int32_t gmt)
{
	if ((gmt == 0) || (gmt == -1))
		return (0);

	return (gmt - sr->sr_gmtoff);
}

int32_t
smb_time_local_to_gmt(smb_request_t *sr, int32_t local)
{
	if ((local == 0) || (local == -1))
		return (0);

	return (local + sr->sr_gmtoff);
}


/*
 * smb_time_dos_to_unix
 *
 * Convert SMB_DATE & SMB_TIME values to a unix timestamp.
 *
 * A date/time field of 0 means that that server file system
 * assigned value need not be changed. The behaviour when the
 * date/time field is set to -1 is not documented but is
 * generally treated like 0.
 * If date or time is 0 or -1 the unix time is returned as 0
 * so that the caller can identify and handle this special case.
 */
int32_t
smb_time_dos_to_unix(int16_t date, int16_t time)
{
	struct tm	atm;

	if (((date == 0) || (time == 0)) ||
	    ((date == -1) || (time == -1))) {
		return (0);
	}

	atm.tm_year = ((date >>  9) & 0x3F) + 80;
	atm.tm_mon  = ((date >>  5) & 0x0F) - 1;
	atm.tm_mday = ((date >>  0) & 0x1F);
	atm.tm_hour = ((time >> 11) & 0x1F);
	atm.tm_min  = ((time >>  5) & 0x3F);
	atm.tm_sec  = ((time >>  0) & 0x1F) << 1;

	return (smb_timegm(&atm));
}

void
smb_time_unix_to_dos(int32_t ux_time, int16_t *date_p, int16_t *time_p)
{
	struct tm	atm;
	int		i;
	time_t		tmp_time;

	if (ux_time == 0) {
		*date_p = 0;
		*time_p = 0;
		return;
	}

	tmp_time = (time_t)ux_time;
	(void) smb_gmtime_r(&tmp_time, &atm);

	if (date_p) {
		i = 0;
		i += atm.tm_year - 80;
		i <<= 4;
		i += atm.tm_mon + 1;
		i <<= 5;
		i += atm.tm_mday;

		*date_p = (short)i;
	}
	if (time_p) {
		i = 0;
		i += atm.tm_hour;
		i <<= 6;
		i += atm.tm_min;
		i <<= 5;
		i += atm.tm_sec >> 1;

		*time_p = (short)i;
	}
}


/*
 * smb_gmtime_r
 *
 * Thread-safe version of smb_gmtime. Returns a null pointer if either
 * input parameter is a null pointer. Otherwise returns a pointer
 * to result.
 *
 * Day of the week calculation: the Epoch was a thursday.
 *
 * There are no timezone corrections so tm_isdst and tm_gmtoff are
 * always zero, and the zone is always WET.
 */
struct tm *
smb_gmtime_r(time_t *clock, struct tm *result)
{
	time_t tsec;
	int year;
	int month;
	int sec_per_month;

	if (clock == 0 || result == 0)
		return (0);

	bzero(result, sizeof (struct tm));
	tsec = *clock;
	tsec -= tzh_leapcnt;

	result->tm_wday = tsec / SECSPERDAY;
	result->tm_wday = (result->tm_wday + TM_THURSDAY) % DAYSPERWEEK;

	year = EPOCH_YEAR;
	while (tsec >= (isleap(year) ? (SECSPERDAY * DAYSPERLYEAR) :
	    (SECSPERDAY * DAYSPERNYEAR))) {
		if (isleap(year))
			tsec -= SECSPERDAY * DAYSPERLYEAR;
		else
			tsec -= SECSPERDAY * DAYSPERNYEAR;

		++year;
	}

	result->tm_year = year - TM_YEAR_BASE;
	result->tm_yday = tsec / SECSPERDAY;

	for (month = TM_JANUARY; month <= TM_DECEMBER; ++month) {
		sec_per_month = days_in_month[month] * SECSPERDAY;

		if (month == TM_FEBRUARY && isleap(year))
			sec_per_month += SECSPERDAY;

		if (tsec < sec_per_month)
			break;

		tsec -= sec_per_month;
	}

	result->tm_mon = month;
	result->tm_mday = (tsec / SECSPERDAY) + 1;
	tsec %= SECSPERDAY;
	result->tm_sec = tsec % 60;
	tsec /= 60;
	result->tm_min = tsec % 60;
	tsec /= 60;
	result->tm_hour = (int)tsec;

	return (result);
}


/*
 * smb_timegm
 *
 * Converts the broken-down time in tm to a time value, i.e. the number
 * of seconds since the Epoch (00:00:00 UTC, January 1, 1970). This is
 * not a POSIX or ANSI function. Per the man page, the input values of
 * tm_wday and tm_yday are ignored and, as the input data is assumed to
 * represent GMT, we force tm_isdst and tm_gmtoff to 0.
 *
 * Before returning the clock time, we use smb_gmtime_r to set up tm_wday
 * and tm_yday, and bring the other fields within normal range. I don't
 * think this is really how it should be done but it's convenient for
 * now.
 */
time_t
smb_timegm(struct tm *tm)
{
	time_t tsec;
	int dd;
	int mm;
	int yy;
	int year;

	if (tm == 0)
		return (-1);

	year = tm->tm_year + TM_YEAR_BASE;
	tsec = tzh_leapcnt;

	for (yy = EPOCH_YEAR; yy < year; ++yy) {
		if (isleap(yy))
			tsec += SECSPERDAY * DAYSPERLYEAR;
		else
			tsec += SECSPERDAY * DAYSPERNYEAR;
	}

	for (mm = TM_JANUARY; mm < tm->tm_mon; ++mm) {
		dd = days_in_month[mm] * SECSPERDAY;

		if (mm == TM_FEBRUARY && isleap(year))
			dd += SECSPERDAY;

		tsec += dd;
	}

	tsec += (tm->tm_mday - 1) * SECSPERDAY;
	tsec += tm->tm_sec;
	tsec += tm->tm_min * SECSPERMIN;
	tsec += tm->tm_hour * SECSPERHOUR;

	tm->tm_isdst = 0;
	(void) smb_gmtime_r(&tsec, tm);
	return (tsec);
}

/*
 * smb_pad_align
 *
 * Returns the number of bytes required to pad an offset to the
 * specified alignment.
 */
uint32_t
smb_pad_align(uint32_t offset, uint32_t align)
{
	uint32_t pad = offset % align;

	if (pad != 0)
		pad = align - pad;

	return (pad);
}

/*
 * smb_panic
 *
 * Logs the file name, function name and line number passed in and panics the
 * system.
 */
void
smb_panic(char *file, const char *func, int line)
{
	cmn_err(CE_PANIC, "%s:%s:%d\n", file, func, line);
}

/*
 * Creates an AVL tree and initializes the given smb_avl_t
 * structure using the passed args
 */
void
smb_avl_create(smb_avl_t *avl, size_t size, size_t offset, smb_avl_nops_t *ops)
{
	ASSERT(avl);
	ASSERT(ops);

	rw_init(&avl->avl_lock, NULL, RW_DEFAULT, NULL);
	mutex_init(&avl->avl_mutex, NULL, MUTEX_DEFAULT, NULL);

	avl->avl_nops = ops;
	avl->avl_state = SMB_AVL_STATE_READY;
	avl->avl_refcnt = 0;
	(void) random_get_pseudo_bytes((uint8_t *)&avl->avl_sequence,
	    sizeof (uint32_t));

	avl_create(&avl->avl_tree, ops->avln_cmp, size, offset);
}

/*
 * Destroys the specified AVL tree.
 * It waits for all the in-flight operations to finish
 * before destroying the AVL.
 */
void
smb_avl_destroy(smb_avl_t *avl)
{
	void *cookie = NULL;
	void *node;

	ASSERT(avl);

	mutex_enter(&avl->avl_mutex);
	if (avl->avl_state != SMB_AVL_STATE_READY) {
		mutex_exit(&avl->avl_mutex);
		return;
	}

	avl->avl_state = SMB_AVL_STATE_DESTROYING;

	while (avl->avl_refcnt > 0)
		(void) cv_wait(&avl->avl_cv, &avl->avl_mutex);
	mutex_exit(&avl->avl_mutex);

	rw_enter(&avl->avl_lock, RW_WRITER);
	while ((node = avl_destroy_nodes(&avl->avl_tree, &cookie)) != NULL)
		avl->avl_nops->avln_destroy(node);

	avl_destroy(&avl->avl_tree);
	rw_exit(&avl->avl_lock);

	rw_destroy(&avl->avl_lock);

	mutex_destroy(&avl->avl_mutex);
	bzero(avl, sizeof (smb_avl_t));
}

/*
 * Adds the given item to the AVL if it's
 * not already there.
 *
 * Returns:
 *
 * 	ENOTACTIVE	AVL is not in READY state
 * 	EEXIST		The item is already in AVL
 */
int
smb_avl_add(smb_avl_t *avl, void *item)
{
	avl_index_t where;

	ASSERT(avl);
	ASSERT(item);

	if (!smb_avl_hold(avl))
		return (ENOTACTIVE);

	rw_enter(&avl->avl_lock, RW_WRITER);
	if (avl_find(&avl->avl_tree, item, &where) != NULL) {
		rw_exit(&avl->avl_lock);
		smb_avl_rele(avl);
		return (EEXIST);
	}

	avl_insert(&avl->avl_tree, item, where);
	avl->avl_sequence++;
	rw_exit(&avl->avl_lock);

	smb_avl_rele(avl);
	return (0);
}

/*
 * Removes the given item from the AVL.
 * If no reference is left on the item
 * it will also be destroyed by calling the
 * registered destroy operation.
 */
void
smb_avl_remove(smb_avl_t *avl, void *item)
{
	avl_index_t where;
	void *rm_item;

	ASSERT(avl);
	ASSERT(item);

	if (!smb_avl_hold(avl))
		return;

	rw_enter(&avl->avl_lock, RW_WRITER);
	if ((rm_item = avl_find(&avl->avl_tree, item, &where)) == NULL) {
		rw_exit(&avl->avl_lock);
		smb_avl_rele(avl);
		return;
	}

	avl_remove(&avl->avl_tree, rm_item);
	if (avl->avl_nops->avln_rele(rm_item))
		avl->avl_nops->avln_destroy(rm_item);
	avl->avl_sequence++;
	rw_exit(&avl->avl_lock);

	smb_avl_rele(avl);
}

/*
 * Looks up the AVL for the given item.
 * If the item is found a hold on the object
 * is taken before the pointer to it is
 * returned to the caller. The caller MUST
 * always call smb_avl_release() after it's done
 * using the returned object to release the hold
 * taken on the object.
 */
void *
smb_avl_lookup(smb_avl_t *avl, void *item)
{
	void *node = NULL;

	ASSERT(avl);
	ASSERT(item);

	if (!smb_avl_hold(avl))
		return (NULL);

	rw_enter(&avl->avl_lock, RW_READER);
	node = avl_find(&avl->avl_tree, item, NULL);
	if (node != NULL)
		avl->avl_nops->avln_hold(node);
	rw_exit(&avl->avl_lock);

	if (node == NULL)
		smb_avl_rele(avl);

	return (node);
}

/*
 * The hold on the given object is released.
 * This function MUST always be called after
 * smb_avl_lookup() and smb_avl_iterate() for
 * the returned object.
 *
 * If AVL is in DESTROYING state, the destroying
 * thread will be notified.
 */
void
smb_avl_release(smb_avl_t *avl, void *item)
{
	ASSERT(avl);
	ASSERT(item);

	if (avl->avl_nops->avln_rele(item))
		avl->avl_nops->avln_destroy(item);

	smb_avl_rele(avl);
}

/*
 * Initializes the given cursor for the AVL.
 * The cursor will be used to iterate through the AVL
 */
void
smb_avl_iterinit(smb_avl_t *avl, smb_avl_cursor_t *cursor)
{
	ASSERT(avl);
	ASSERT(cursor);

	cursor->avlc_next = NULL;
	cursor->avlc_sequence = avl->avl_sequence;
}

/*
 * Iterates through the AVL using the given cursor.
 * It always starts at the beginning and then returns
 * a pointer to the next object on each subsequent call.
 *
 * If a new object is added to or removed from the AVL
 * between two calls to this function, the iteration
 * will terminate prematurely.
 *
 * The caller MUST always call smb_avl_release() after it's
 * done using the returned object to release the hold taken
 * on the object.
 */
void *
smb_avl_iterate(smb_avl_t *avl, smb_avl_cursor_t *cursor)
{
	void *node;

	ASSERT(avl);
	ASSERT(cursor);

	if (!smb_avl_hold(avl))
		return (NULL);

	rw_enter(&avl->avl_lock, RW_READER);
	if (cursor->avlc_sequence != avl->avl_sequence) {
		rw_exit(&avl->avl_lock);
		smb_avl_rele(avl);
		return (NULL);
	}

	if (cursor->avlc_next == NULL)
		node = avl_first(&avl->avl_tree);
	else
		node = AVL_NEXT(&avl->avl_tree, cursor->avlc_next);

	if (node != NULL)
		avl->avl_nops->avln_hold(node);

	cursor->avlc_next = node;
	rw_exit(&avl->avl_lock);

	if (node == NULL)
		smb_avl_rele(avl);

	return (node);
}

/*
 * Increments the AVL reference count in order to
 * prevent the avl from being destroyed while it's
 * being accessed.
 */
static boolean_t
smb_avl_hold(smb_avl_t *avl)
{
	mutex_enter(&avl->avl_mutex);
	if (avl->avl_state != SMB_AVL_STATE_READY) {
		mutex_exit(&avl->avl_mutex);
		return (B_FALSE);
	}
	avl->avl_refcnt++;
	mutex_exit(&avl->avl_mutex);

	return (B_TRUE);
}

/*
 * Decrements the AVL reference count to release the
 * hold. If another thread is trying to destroy the
 * AVL and is waiting for the reference count to become
 * 0, it is signaled to wake up.
 */
static void
smb_avl_rele(smb_avl_t *avl)
{
	mutex_enter(&avl->avl_mutex);
	ASSERT(avl->avl_refcnt > 0);
	avl->avl_refcnt--;
	if (avl->avl_state == SMB_AVL_STATE_DESTROYING)
		cv_broadcast(&avl->avl_cv);
	mutex_exit(&avl->avl_mutex);
}

/*
 * smb_latency_init
 */
void
smb_latency_init(smb_latency_t *lat)
{
	bzero(lat, sizeof (*lat));
	mutex_init(&lat->ly_mutex, NULL, MUTEX_SPIN, (void *)ipltospl(SPL7));
}

/*
 * smb_latency_destroy
 */
void
smb_latency_destroy(smb_latency_t *lat)
{
	mutex_destroy(&lat->ly_mutex);
}

/*
 * smb_latency_add_sample
 *
 * Uses the new sample to calculate the new mean and standard deviation. The
 * sample must be a scaled value.
 */
void
smb_latency_add_sample(smb_latency_t *lat, hrtime_t sample)
{
	hrtime_t	a_mean;
	hrtime_t	d_mean;

	mutex_enter(&lat->ly_mutex);
	lat->ly_a_nreq++;
	lat->ly_a_sum += sample;
	if (lat->ly_a_nreq != 0) {
		a_mean = lat->ly_a_sum / lat->ly_a_nreq;
		lat->ly_a_stddev =
		    (sample - a_mean) * (sample - lat->ly_a_mean);
		lat->ly_a_mean = a_mean;
	}
	lat->ly_d_nreq++;
	lat->ly_d_sum += sample;
	if (lat->ly_d_nreq != 0) {
		d_mean = lat->ly_d_sum / lat->ly_d_nreq;
		lat->ly_d_stddev =
		    (sample - d_mean) * (sample - lat->ly_d_mean);
		lat->ly_d_mean = d_mean;
	}
	mutex_exit(&lat->ly_mutex);
}

/*
 * smb_srqueue_init
 */
void
smb_srqueue_init(smb_srqueue_t *srq)
{
	bzero(srq, sizeof (*srq));
	mutex_init(&srq->srq_mutex, NULL, MUTEX_SPIN, (void *)ipltospl(SPL7));
	srq->srq_wlastupdate = srq->srq_rlastupdate = gethrtime_unscaled();
}

/*
 * smb_srqueue_destroy
 */
void
smb_srqueue_destroy(smb_srqueue_t *srq)
{
	mutex_destroy(&srq->srq_mutex);
}

/*
 * smb_srqueue_waitq_enter
 */
void
smb_srqueue_waitq_enter(smb_srqueue_t *srq)
{
	hrtime_t	new;
	hrtime_t	delta;
	uint32_t	wcnt;

	mutex_enter(&srq->srq_mutex);
	new = gethrtime_unscaled();
	delta = new - srq->srq_wlastupdate;
	srq->srq_wlastupdate = new;
	wcnt = srq->srq_wcnt++;
	if (wcnt != 0) {
		srq->srq_wlentime += delta * wcnt;
		srq->srq_wtime += delta;
	}
	mutex_exit(&srq->srq_mutex);
}

/*
 * smb_srqueue_runq_exit
 */
void
smb_srqueue_runq_exit(smb_srqueue_t *srq)
{
	hrtime_t	new;
	hrtime_t	delta;
	uint32_t	rcnt;

	mutex_enter(&srq->srq_mutex);
	new = gethrtime_unscaled();
	delta = new - srq->srq_rlastupdate;
	srq->srq_rlastupdate = new;
	rcnt = srq->srq_rcnt--;
	ASSERT(rcnt > 0);
	srq->srq_rlentime += delta * rcnt;
	srq->srq_rtime += delta;
	mutex_exit(&srq->srq_mutex);
}

/*
 * smb_srqueue_waitq_to_runq
 */
void
smb_srqueue_waitq_to_runq(smb_srqueue_t *srq)
{
	hrtime_t	new;
	hrtime_t	delta;
	uint32_t	wcnt;
	uint32_t	rcnt;

	mutex_enter(&srq->srq_mutex);
	new = gethrtime_unscaled();
	delta = new - srq->srq_wlastupdate;
	srq->srq_wlastupdate = new;
	wcnt = srq->srq_wcnt--;
	ASSERT(wcnt > 0);
	srq->srq_wlentime += delta * wcnt;
	srq->srq_wtime += delta;
	delta = new - srq->srq_rlastupdate;
	srq->srq_rlastupdate = new;
	rcnt = srq->srq_rcnt++;
	if (rcnt != 0) {
		srq->srq_rlentime += delta * rcnt;
		srq->srq_rtime += delta;
	}
	mutex_exit(&srq->srq_mutex);
}

/*
 * smb_srqueue_update
 *
 * Takes a snapshot of the smb_sr_stat_t structure passed in.
 */
void
smb_srqueue_update(smb_srqueue_t *srq, smb_kstat_utilization_t *kd)
{
	hrtime_t	delta;
	hrtime_t	snaptime;

	mutex_enter(&srq->srq_mutex);
	snaptime = gethrtime_unscaled();
	delta = snaptime - srq->srq_wlastupdate;
	srq->srq_wlastupdate = snaptime;
	if (srq->srq_wcnt != 0) {
		srq->srq_wlentime += delta * srq->srq_wcnt;
		srq->srq_wtime += delta;
	}
	delta = snaptime - srq->srq_rlastupdate;
	srq->srq_rlastupdate = snaptime;
	if (srq->srq_rcnt != 0) {
		srq->srq_rlentime += delta * srq->srq_rcnt;
		srq->srq_rtime += delta;
	}
	kd->ku_rlentime = srq->srq_rlentime;
	kd->ku_rtime = srq->srq_rtime;
	kd->ku_wlentime = srq->srq_wlentime;
	kd->ku_wtime = srq->srq_wtime;
	mutex_exit(&srq->srq_mutex);
	scalehrtime(&kd->ku_rlentime);
	scalehrtime(&kd->ku_rtime);
	scalehrtime(&kd->ku_wlentime);
	scalehrtime(&kd->ku_wtime);
}

void
smb_threshold_init(smb_cmd_threshold_t *ct, char *cmd, int threshold,
    int timeout)
{
	bzero(ct, sizeof (smb_cmd_threshold_t));
	mutex_init(&ct->ct_mutex, NULL, MUTEX_DEFAULT, NULL);
	ct->ct_cmd = cmd;
	ct->ct_threshold = threshold;
	ct->ct_event = smb_event_create(timeout);
	ct->ct_event_id = smb_event_txid(ct->ct_event);

	if (smb_threshold_debug) {
		cmn_err(CE_NOTE, "smb_threshold_init[%s]: threshold (%d), "
		    "timeout (%d)", cmd, threshold, timeout);
	}
}

/*
 * This function must be called prior to SMB_SERVER_STATE_STOPPING state
 * so that ct_event can be successfully removed from the event list.
 * It should not be called when the server mutex is held or when the
 * server is removed from the server list.
 */
void
smb_threshold_fini(smb_cmd_threshold_t *ct)
{
	smb_event_destroy(ct->ct_event);
	mutex_destroy(&ct->ct_mutex);
	bzero(ct, sizeof (smb_cmd_threshold_t));
}

/*
 * This threshold mechanism can be used to limit the number of simultaneous
 * requests, which serves to limit the stress that can be applied to the
 * service and also allows the service to respond to requests before the
 * client times out and reports that the server is not responding,
 *
 * If the number of requests exceeds the threshold, new requests will be
 * stalled until the number drops back to the threshold.  Stalled requests
 * will be notified as appropriate, in which case 0 will be returned.
 * If the timeout expires before the request is notified, a non-zero errno
 * value will be returned.
 *
 * To avoid a flood of messages, the message rate is throttled as well.
 */
int
smb_threshold_enter(smb_cmd_threshold_t *ct)
{
	int	rc;

	mutex_enter(&ct->ct_mutex);
	if (ct->ct_active_cnt >= ct->ct_threshold && ct->ct_event != NULL) {
		atomic_inc_32(&ct->ct_blocked_cnt);

		if (smb_threshold_debug) {
			cmn_err(CE_NOTE, "smb_threshold_enter[%s]: blocked "
			    "(blocked ops: %u, inflight ops: %u)",
			    ct->ct_cmd, ct->ct_blocked_cnt, ct->ct_active_cnt);
		}

		mutex_exit(&ct->ct_mutex);

		if ((rc = smb_event_wait(ct->ct_event)) != 0) {
			if (rc == ECANCELED)
				return (rc);

			mutex_enter(&ct->ct_mutex);
			if (ct->ct_active_cnt >= ct->ct_threshold) {

				if ((ct->ct_error_cnt %
				    SMB_THRESHOLD_REPORT_THROTTLE) == 0) {
					cmn_err(CE_NOTE, "%s: server busy: "
					    "threshold %d exceeded)",
					    ct->ct_cmd, ct->ct_threshold);
				}

				atomic_inc_32(&ct->ct_error_cnt);
				mutex_exit(&ct->ct_mutex);
				return (rc);
			}

			mutex_exit(&ct->ct_mutex);

		}

		mutex_enter(&ct->ct_mutex);
		atomic_dec_32(&ct->ct_blocked_cnt);
		if (smb_threshold_debug) {
			cmn_err(CE_NOTE, "smb_threshold_enter[%s]: resumed "
			    "(blocked ops: %u, inflight ops: %u)", ct->ct_cmd,
			    ct->ct_blocked_cnt, ct->ct_active_cnt);
		}
	}

	atomic_inc_32(&ct->ct_active_cnt);
	mutex_exit(&ct->ct_mutex);
	return (0);
}

void
smb_threshold_exit(smb_cmd_threshold_t *ct, smb_server_t *sv)
{
	mutex_enter(&ct->ct_mutex);
	atomic_dec_32(&ct->ct_active_cnt);
	mutex_exit(&ct->ct_mutex);
	smb_event_notify(sv, ct->ct_event_id);
}
