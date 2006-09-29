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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "nscd_db.h"
#include "nscd_log.h"

/*
 * Access control structure for a piece of nscd data. This structure
 * is always tagged before the nscd data. nscd_alloc, which should
 * be used to allocate memory that requires access control or usage
 * count control, will initialize this access control structure at the
 * start of the memory returned to the caller.
 */
struct nscd_access_s {
	void		*data;			/* addr of real data */
	void		(*free_func)(nscd_acc_data_t *data); /* destructor */
	mutex_t		mutex;			/* protect this structure */
	mutex_t		*data_mutex;
	rwlock_t	*data_rwlock;
	cond_t		*data_cond;
	int		nUse;			/* usage count */
	int		type;
	int		delete;			/* no longer available */
	nscd_seq_num_t	seq_num;		/* sequence number */
};

/* size should be in multiple of 8 */
static int sizeof_access = roundup(sizeof (nscd_access_t));

#define	ABORT_DUE_TO_NO_VALID_NSCD_ACCESS_DATA 0
#define	ASSERT_ACCESS_DATA \
	if (access->data != data) \
		assert(ABORT_DUE_TO_NO_VALID_NSCD_ACCESS_DATA)

#define	SET_ACCESS_PTR \
		access = (nscd_access_t *) \
			((void *)((char *)data - sizeof_access))

static void _nscd_free(nscd_acc_data_t	*data);

/*
 * FUNCTION: _nscd_release
 *
 * Decrements the usage count maintained in the access data
 * tagged before 'data'. Delete the nscd data item if the delete
 * flag is set and the usage count reaches 0.
 */
void
_nscd_release(
	nscd_acc_data_t	*data)
{
	nscd_access_t	*access;
	char		*me = "_nscd_release";

	if (data == NULL)
		return;

	SET_ACCESS_PTR;

	_NSCD_LOG(NSCD_LOG_ACCESS_INFO, NSCD_LOG_LEVEL_DEBUG)
		(me, "data = %p, access->data = %p, "
		"seq = %lld, nUse = %d\n",
		data, access->data, access->seq_num, access->nUse);
	ASSERT_ACCESS_DATA;

	(void) mutex_lock(&access->mutex);
	access->nUse--;
	if (access->nUse < 0) {
#define	ACCESS_NUSE_LESS_THAN_ZERO 0
		assert(ACCESS_NUSE_LESS_THAN_ZERO);
	}
	if (access->nUse <= 0 &&
		access->delete == 1) {

		_NSCD_LOG(NSCD_LOG_ACCESS_INFO, NSCD_LOG_LEVEL_DEBUG)
		(me, "deleting data %p\n", access->data);
		(access->free_func)(access->data);

		/*
		 * if we get here, no other thread could be
		 * holding the access->mutex lock, It is safe
		 * to free the memory containing the mutex
		 * structure. No mutex_unlock is necessary.
		 */
		_nscd_free(data);
	} else
		(void) mutex_unlock(&access->mutex);
}


/*
 * FUNCTION: _nscd_destroy
 *
 * Marks the nscd data item as to-be-deleted and then releases
 * (If the usage count happens to be zero, then _nscd_release()
 * will destroy the data.)
 *
 * Note that _nscd_destroy should only be called if the
 * caller has created the nscd data with _nscd_alloc
 * (with the exception of _nscd_set). That nscd data
 * item should be private to the caller.
 */
static void
_nscd_destroy(
	nscd_acc_data_t	*data)
{
	nscd_access_t	*access;
	char		*me = "_nscd_destroy";

	if (data == NULL)
		return;

	SET_ACCESS_PTR;

	_NSCD_LOG(NSCD_LOG_ACCESS_INFO, NSCD_LOG_LEVEL_DEBUG)
	(me, "data = %p, access->data = %p\n", data, access->data);
	ASSERT_ACCESS_DATA;

	(void) mutex_lock(&access->mutex);
	access->delete = 1;
	(void) mutex_unlock(&access->mutex);

	_nscd_release(data);
}

/*
 * FUNCTION: _nscd_get
 *
 * Increment the usage count by one if 'data' can
 * be found in the internal address database.
 */
nscd_acc_data_t *
_nscd_get(
	nscd_acc_data_t	*data)
{
	nscd_access_t	*access;
	void		*ret = data;
	rwlock_t	*addr_rwlock;
	char		*me = "_nscd_get";

	if (data == NULL)
		return (NULL);

	SET_ACCESS_PTR;

	_NSCD_LOG(NSCD_LOG_ACCESS_INFO, NSCD_LOG_LEVEL_DEBUG)
	(me, "data = %p, access->data = %p, seq#= %lld, nUse = %d\n",
		data, access->data, access->seq_num, access->nUse);
	ASSERT_ACCESS_DATA;

	/*
	 * see if this addr is still valid,
	 * if so, _nscd_is_int_addr will
	 * do a read lock on the returned
	 * multiple readers/single writer lock
	 * to prevent the access data from being
	 * deleted while it is being accessed.
	 */
	if ((addr_rwlock = _nscd_is_int_addr(data,
			access->seq_num)) == NULL) {
		_NSCD_LOG(NSCD_LOG_ACCESS_INFO, NSCD_LOG_LEVEL_DEBUG)
		(me, "internal address %p not found\n", data);
		assert(addr_rwlock != NULL);
		return (NULL);
	}

	(void) mutex_lock(&access->mutex);
	if (access->delete == 1)
		ret = NULL;
	else
		access->nUse++;
	(void) mutex_unlock(&access->mutex);

	/*
	 * done with the multiple readers/single writer lock
	 */
	(void) rw_unlock(addr_rwlock);

	return (ret);
}

/*
 * FUNCTION: _nscd_set
 *
 * _nscd_set sets the address of a nscd data item
 * to 'new' and delete the old nscd data (old).
 * The pointer 'new' is returned.
 */
nscd_acc_data_t *
_nscd_set(
	nscd_acc_data_t	*old,
	nscd_acc_data_t	*new)
{
	nscd_acc_data_t	*old_data, *new_data;
	char		*me = "_nscd_set";

	if (new == old)
		return (old);

	_NSCD_LOG(NSCD_LOG_ACCESS_INFO, NSCD_LOG_LEVEL_DEBUG)
	(me, "new = %p, old = %p\n", new, old);

	old_data = _nscd_get(old);
	new_data = _nscd_get(new);

	if (old_data != new_data) {

		_nscd_destroy(old_data);
		_nscd_release(new_data);
		return (new_data);
	}

	/* if old_data == new_data, both must be NULL */
	return (NULL);
}

/*
 * FUNCTION: _nscd_rdlock
 *
 * Lock (rw_rdlock) a nscd data item for reading. The caller
 * needs to call _nscd_rw_unlock() to unlock the data item
 * when done using the data.
 */
nscd_acc_data_t *
_nscd_rdlock(
	nscd_acc_data_t	*data)
{
	nscd_access_t	*access;
	void		*ret;
	char		*me = "_nscd_rdlock";

	ret = _nscd_get(data);

	if (ret == NULL)
		return (NULL);

	SET_ACCESS_PTR;

	_NSCD_LOG(NSCD_LOG_ACCESS_INFO, NSCD_LOG_LEVEL_DEBUG)
	(me, "data = %p, access->data = %p\n", data, access->data);
	ASSERT_ACCESS_DATA;

	assert(access->data_rwlock != NULL);

	(void) rw_rdlock(access->data_rwlock);

	return (ret);
}

/*
 * FUNCTION: _nscd_wrlock
 *
 * Lock (rw_wrlock) a nscd data item for writing. The caller
 * needs to call _nscd_rw_unlock() to unlock the data item
 * when done using the data.
 */
nscd_acc_data_t *
_nscd_wrlock(
	nscd_acc_data_t	*data)
{
	nscd_access_t	*access;
	void		*ret;
	char		*me = "_nscd_wrlock";

	ret = _nscd_get(data);

	if (ret == NULL)
		return (NULL);

	SET_ACCESS_PTR;

	_NSCD_LOG(NSCD_LOG_ACCESS_INFO, NSCD_LOG_LEVEL_DEBUG)
	(me, "data = %p, access->data = %p\n", data, access->data);
	ASSERT_ACCESS_DATA;

	assert(access->data_rwlock != NULL);

	(void) rw_wrlock(access->data_rwlock);

	return (ret);
}

/*
 * FUNCTION: _nscd_rw_unlock
 *
 * Unlock (rw_unlock) a locked nscd data item.
 */
void
_nscd_rw_unlock(
	nscd_acc_data_t	*data)
{
	nscd_access_t	*access;
	char		*me = "_nscd_rw_unlock";

	if (data == NULL)
		return;

	SET_ACCESS_PTR;

	_NSCD_LOG(NSCD_LOG_ACCESS_INFO, NSCD_LOG_LEVEL_DEBUG)
	(me, "data = %p, access->data = %p\n",
		data, access->data);
	ASSERT_ACCESS_DATA;

	assert(access->data_rwlock != NULL);

	(void) rw_unlock(access->data_rwlock);
	_nscd_release(data);
}

/*
 * FUNCTION: _nscd_rw_unlock_no_release
 *
 * Unlock (rw_unlock) a locked nscd data item but without release
 * it, i.e., without decrement the usage count to indicate that
 * the data item is still being referenced.
 */
void
_nscd_rw_unlock_no_release(
	nscd_acc_data_t	*data)
{
	nscd_access_t	*access;

	if (data == NULL)
		return;

	SET_ACCESS_PTR;
	ASSERT_ACCESS_DATA;

	assert(access->data_rwlock != NULL);

	(void) rw_unlock(access->data_rwlock);
}

/*
 * FUNCTION: _nscd_mutex_lock
 *
 * Lock (mutex_lock) a nscd data item. The caller needs
 * to call _nscd_mutex_unlock() to unlock the data item
 * when done using the data.
 */
nscd_acc_data_t *
_nscd_mutex_lock(
	nscd_acc_data_t	*data)
{
	nscd_access_t	*access;
	void		*ret;
	char		*me = "_nscd_mutex_lock";

	ret = _nscd_get(data);

	if (ret == NULL)
		return (NULL);

	SET_ACCESS_PTR;

	_NSCD_LOG(NSCD_LOG_ACCESS_INFO, NSCD_LOG_LEVEL_DEBUG)
	(me, "data = %p, access->data = %p\n", data, access->data);
	ASSERT_ACCESS_DATA;

	assert(access->data_mutex != NULL);

	(void) mutex_lock(access->data_mutex);

	return (ret);
}


/*
 * FUNCTION: _nscd_mutex_unlock
 *
 * Unlock a locked nscd data item (that were locked by _nscd_mutex_lock)..
 */
void
_nscd_mutex_unlock(
	nscd_acc_data_t	*data)
{
	nscd_access_t	*access;
	char		*me = "_nscd_mutex_unlock";

	if (data == NULL)
		return;

	SET_ACCESS_PTR;

	_NSCD_LOG(NSCD_LOG_ACCESS_INFO, NSCD_LOG_LEVEL_DEBUG)
	(me, "data = %p, access->data = %p\n", data, access->data);
	ASSERT_ACCESS_DATA;

	assert(access->data_mutex != NULL);

	(void) mutex_unlock(access->data_mutex);
	_nscd_release(data);
}

/*
 * FUNCTION: _nscd_cond_wait
 *
 * Perform a condition wait with the cond_t and mutex_t associated
 * with data.
 */
void
_nscd_cond_wait(
	nscd_acc_data_t	*data, cond_t *cond)
{
	nscd_access_t	*access;
	char		*me = "_nscd_cond_wait";

	if (data == NULL)
		return;

	SET_ACCESS_PTR;

	_NSCD_LOG(NSCD_LOG_ACCESS_INFO, NSCD_LOG_LEVEL_DEBUG)
	(me, "data = %p, access->data = %p\n", data, access->data);
	ASSERT_ACCESS_DATA;

	assert(access->data_cond != NULL && access->data_mutex != NULL);

	if (cond == NULL)
		(void) cond_wait(access->data_cond, access->data_mutex);
	else
		(void) cond_wait(cond, access->data_mutex);
}

/*
 * FUNCTION: _nscd_cond_signal
 *
 * Perform a condition signal with the cond_t associated with 'data'.
 */
void
_nscd_cond_signal(
	nscd_acc_data_t	*data)
{
	nscd_access_t	*access;
	char		*me = "_nscd_cond_signal";

	if (data == NULL)
		return;

	SET_ACCESS_PTR;

	_NSCD_LOG(NSCD_LOG_ACCESS_INFO, NSCD_LOG_LEVEL_DEBUG)
	(me, "data = %p, access->data = %p\n", data, access->data);
	ASSERT_ACCESS_DATA;

	assert(access->data_cond != NULL);

	(void) cond_signal(access->data_cond);
}

/*
 * FUNCTION: _nscd_alloc
 *
 * Allocate a piece of nscd memory. 'data_free'
 * is the function to invoke to free the data
 * stored in this memory, i.e., the desctrctor.
 * 'option' indicate whether a mutex or a
 * readers/writer (or both, or none) should also
 * be allocated.
 */
nscd_acc_data_t	*
_nscd_alloc(
	int		type,
	size_t		size,
	void 		(*data_free)(nscd_acc_data_t *data),
	int		option)
{
	nscd_access_t	*access;
	nscd_acc_data_t *ptr;
	nscd_seq_num_t	seq_num;
	rwlock_t	*rwlock = NULL;
	mutex_t		*mutex = NULL;
	cond_t		*cond = NULL;

	if ((ptr = (nscd_acc_data_t *)calloc(1,
			size + sizeof_access)) == NULL)
		return (NULL);
	if (option & NSCD_ALLOC_MUTEX) {
		if ((mutex = (mutex_t *)calloc(1, sizeof (mutex_t))) ==
				NULL) {
			free(ptr);
			return (NULL);
		} else
			(void) mutex_init(mutex, USYNC_THREAD, NULL);
	}
	if (option & NSCD_ALLOC_RWLOCK) {
		if ((rwlock = (rwlock_t *)calloc(1, sizeof (rwlock_t))) ==
				NULL) {
			free(ptr);
			free(mutex);
			return (NULL);
		} else
			(void) rwlock_init(rwlock, USYNC_THREAD, NULL);
	}
	if (option & NSCD_ALLOC_COND) {
		if ((cond = (cond_t *)calloc(1, sizeof (cond_t))) ==
				NULL) {
			free(ptr);
			free(mutex);
			free(rwlock);
			return (NULL);
		} else
			(void) cond_init(cond, USYNC_THREAD, NULL);
	}

	/* get current sequence number */
	seq_num = _nscd_get_seq_num();

	access = (nscd_access_t *)ptr;
	access->data = (char *)ptr + sizeof_access;
	access->data_mutex = mutex;
	access->data_rwlock = rwlock;
	access->data_cond = cond;
	access->nUse = 0;
	access->delete = 0;
	access->type = type;
	access->free_func = data_free;
	access->seq_num = seq_num;

	/* add the address to the internal address database */
	if (_nscd_add_int_addr(access->data, type,
			seq_num) != NSCD_SUCCESS) {
		free(ptr);
		return (NULL);
	}

	return (access->data);
}

/*
 * FUNCTION: _nscd_free
 *
 * Free a piece of nscd memory.
 */
static void
_nscd_free(
	nscd_acc_data_t	*data)
{
	nscd_access_t	*access;

	if (data == NULL)
		return;

	SET_ACCESS_PTR;
	ASSERT_ACCESS_DATA;

	/* remove the address from the internal address database */
	_nscd_del_int_addr(access->data, access->seq_num);

	if (access->data_mutex)
		free(access->data_mutex);
	if (access->data_rwlock)
		free(access->data_rwlock);
	if (access->data_cond)
		free(access->data_cond);

	(void) memset(access, 0, sizeof (*access));

	free(access);
}
