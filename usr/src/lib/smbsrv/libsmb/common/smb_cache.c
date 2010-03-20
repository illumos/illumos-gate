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

#include <assert.h>
#include <sys/avl.h>
#include <smbsrv/libsmb.h>

/*
 * Cache lock modes
 */
#define	SMB_CACHE_RDLOCK	0
#define	SMB_CACHE_WRLOCK	1

#define	SMB_CACHE_STATE_NOCACHE		0
#define	SMB_CACHE_STATE_READY		1
#define	SMB_CACHE_STATE_REFRESHING	2
#define	SMB_CACHE_STATE_DESTROYING	3

static int smb_cache_lock(smb_cache_t *, int);
static int smb_cache_rdlock(smb_cache_t *);
static int smb_cache_wrlock(smb_cache_t *);
static void smb_cache_unlock(smb_cache_t *);
static boolean_t smb_cache_wait(smb_cache_t *);
static void smb_cache_destroy_nodes(smb_cache_t *);

/*
 * Creates an AVL tree and initializes the given cache handle.
 * Transfers the cache to READY state.
 *
 * This function does not populate the cache.
 *
 * chandle	pointer to a smb_cache_t structure
 * waittime	see smb_cache_refreshing() comments
 * cmpfn	compare function used by AVL tree
 * freefn	if set, it will be used to free any allocated
 * 		memory for the node data stored in the cache when
 * 		that node is removed.
 * copyfn	this function has to be set and it is used
 * 		to provide a copy of the node data stored in the
 * 		cache to the caller of smb_cache_iterate or any other
 * 		function that is used to access nodes data.
 * 		This can typically be 'bcopy' if data is fixed size.
 * datasz	Size of data stored in the cache if it's fixed size.
 * 		This size will be passed to the copy function.
 */
void
smb_cache_create(smb_cache_t *chandle, uint32_t waittime,
    int (*cmpfn) (const void *, const void *),
    void (*freefn)(void *),
    void (*copyfn)(const void *, void *, size_t),
    size_t datasz)
{
	assert(chandle);
	assert(copyfn);

	(void) mutex_lock(&chandle->ch_mtx);
	if (chandle->ch_state != SMB_CACHE_STATE_NOCACHE) {
		(void) mutex_unlock(&chandle->ch_mtx);
		return;
	}

	avl_create(&chandle->ch_cache, cmpfn, sizeof (smb_cache_node_t),
	    offsetof(smb_cache_node_t, cn_link));

	chandle->ch_state = SMB_CACHE_STATE_READY;
	chandle->ch_nops = 0;
	chandle->ch_wait = waittime;
	chandle->ch_sequence = random();
	chandle->ch_datasz = datasz;
	chandle->ch_free = freefn;
	chandle->ch_copy = copyfn;
	(void) mutex_unlock(&chandle->ch_mtx);
}

/*
 * Destroys the cache.
 *
 * Transfers the cache to DESTROYING state while it's waiting for
 * in-flight operation to finish, this will prevent any new operation
 * to start. When all entries are removed the cache is transferred to
 * NOCACHE state.
 */
void
smb_cache_destroy(smb_cache_t *chandle)
{
	(void) mutex_lock(&chandle->ch_mtx);
	switch (chandle->ch_state) {
	case SMB_CACHE_STATE_NOCACHE:
	case SMB_CACHE_STATE_DESTROYING:
		(void) mutex_unlock(&chandle->ch_mtx);
		return;

	default:
		break;
	}

	chandle->ch_state = SMB_CACHE_STATE_DESTROYING;

	while (chandle->ch_nops > 0)
		(void) cond_wait(&chandle->ch_cv, &chandle->ch_mtx);

	smb_cache_destroy_nodes(chandle);

	avl_destroy(&chandle->ch_cache);
	chandle->ch_state = SMB_CACHE_STATE_NOCACHE;
	(void) mutex_unlock(&chandle->ch_mtx);
}

/*
 * Removes and frees all the cache entries without destroy
 * the cache itself.
 */
void
smb_cache_flush(smb_cache_t *chandle)
{
	if (smb_cache_wrlock(chandle) == 0) {
		smb_cache_destroy_nodes(chandle);
		chandle->ch_sequence++;
		smb_cache_unlock(chandle);
	}
}

/*
 * Based on the specified flag either add or replace given
 * data. If ADD flag is specified and the item is already in
 * the cache EEXIST error code is returned.
 */
int
smb_cache_add(smb_cache_t *chandle, const void *data, int flags)
{
	smb_cache_node_t *newnode;
	smb_cache_node_t *node;
	avl_index_t where;
	int rc = 0;

	assert(data);

	if ((rc = smb_cache_wrlock(chandle)) != 0)
		return (rc);

	if ((newnode = malloc(sizeof (smb_cache_node_t))) == NULL) {
		smb_cache_unlock(chandle);
		return (ENOMEM);
	}

	newnode->cn_data = (void *)data;
	node = avl_find(&chandle->ch_cache, newnode, &where);
	if (node != NULL) {
		if (flags & SMB_CACHE_REPLACE) {
			avl_remove(&chandle->ch_cache, node);
			if (chandle->ch_free)
				chandle->ch_free(node->cn_data);
			free(node);
		} else {
			free(newnode);
			smb_cache_unlock(chandle);
			return (EEXIST);
		}
	}

	avl_insert(&chandle->ch_cache, newnode, where);
	chandle->ch_sequence++;

	smb_cache_unlock(chandle);
	return (rc);
}

/*
 * Uses the given 'data' as key to find a cache entry
 * and remove it. The memory allocated for the found node
 * and its data is freed.
 */
void
smb_cache_remove(smb_cache_t *chandle, const void *data)
{
	smb_cache_node_t keynode;
	smb_cache_node_t *node;

	assert(data);

	if (smb_cache_wrlock(chandle) != 0)
		return;

	keynode.cn_data = (void *)data;
	node = avl_find(&chandle->ch_cache, &keynode, NULL);
	if (node) {
		chandle->ch_sequence++;
		avl_remove(&chandle->ch_cache, node);
		if (chandle->ch_free)
			chandle->ch_free(node->cn_data);
		free(node);
	}

	smb_cache_unlock(chandle);
}

/*
 * Initializes the given cursor for iterating the cache
 */
void
smb_cache_iterinit(smb_cache_t *chandle, smb_cache_cursor_t *cursor)
{
	cursor->cc_sequence = chandle->ch_sequence;
	cursor->cc_next = NULL;
}

/*
 * Iterate the cache using the given cursor.
 *
 * Data is copied to the given buffer ('data') using the copy function
 * specified at cache creation time.
 *
 * If the cache is modified while an iteration is in progress it causes
 * the iteration to finish prematurely. This is to avoid the need to lock
 * the whole cache while it is being iterated.
 */
boolean_t
smb_cache_iterate(smb_cache_t *chandle, smb_cache_cursor_t *cursor, void *data)
{
	smb_cache_node_t *node;

	assert(data);

	if (smb_cache_rdlock(chandle) != 0)
		return (B_FALSE);

	if (cursor->cc_sequence != chandle->ch_sequence) {
		smb_cache_unlock(chandle);
		return (B_FALSE);
	}

	if (cursor->cc_next == NULL)
		node = avl_first(&chandle->ch_cache);
	else
		node = AVL_NEXT(&chandle->ch_cache, cursor->cc_next);

	if (node != NULL)
		chandle->ch_copy(node->cn_data, data, chandle->ch_datasz);

	cursor->cc_next = node;
	smb_cache_unlock(chandle);

	return (node != NULL);
}

/*
 * Returns the number of cache entries
 */
uint32_t
smb_cache_num(smb_cache_t *chandle)
{
	uint32_t num = 0;

	if (smb_cache_rdlock(chandle) == 0) {
		num = (uint32_t)avl_numnodes(&chandle->ch_cache);
		smb_cache_unlock(chandle);
	}

	return (num);
}

/*
 * Transfers the cache into REFRESHING state. This function needs
 * to be called when the whole cache is being populated or refereshed
 * and not for individual changes.
 *
 * Calling this function will ensure any read access to the cache will
 * be stalled until the update is finished, which is to avoid providing
 * incomplete, inconsistent or stale information. Read accesses will be
 * stalled for 'ch_wait' seconds (see smb_cache_lock), which is set at
 * the cache creation time.
 *
 * If it is okay for the cache to be accessed while it's being populated
 * or refreshed, then there is no need to call this function.
 *
 * If another thread is already updating the cache, other callers will wait
 * until cache is no longer in REFRESHING state. The return code is decided
 * based on the new state of the cache.
 *
 * This function does NOT perform the actual refresh.
 */
int
smb_cache_refreshing(smb_cache_t *chandle)
{
	int rc = 0;

	(void) mutex_lock(&chandle->ch_mtx);
	switch (chandle->ch_state) {
	case SMB_CACHE_STATE_READY:
		chandle->ch_state = SMB_CACHE_STATE_REFRESHING;
		rc = 0;
		break;

	case SMB_CACHE_STATE_REFRESHING:
		while (chandle->ch_state == SMB_CACHE_STATE_REFRESHING)
			(void) cond_wait(&chandle->ch_cv,
			    &chandle->ch_mtx);

		if (chandle->ch_state == SMB_CACHE_STATE_READY) {
			chandle->ch_state = SMB_CACHE_STATE_REFRESHING;
			rc = 0;
		} else {
			rc = ENODATA;
		}
		break;

	case SMB_CACHE_STATE_NOCACHE:
	case SMB_CACHE_STATE_DESTROYING:
		rc = ENODATA;
		break;

	default:
		assert(0);
	}

	(void) mutex_unlock(&chandle->ch_mtx);
	return (rc);
}

/*
 * Transfers the cache from REFRESHING to READY state.
 *
 * Nothing will happen if the cache is no longer available
 * or it is being destroyed.
 *
 * This function should only be called if smb_cache_refreshing()
 * has already been invoked.
 */
void
smb_cache_ready(smb_cache_t *chandle)
{
	(void) mutex_lock(&chandle->ch_mtx);
	switch (chandle->ch_state) {
	case SMB_CACHE_STATE_REFRESHING:
		chandle->ch_state = SMB_CACHE_STATE_READY;
		(void) cond_broadcast(&chandle->ch_cv);
		break;

	case SMB_CACHE_STATE_NOCACHE:
	case SMB_CACHE_STATE_DESTROYING:
		break;

	case SMB_CACHE_STATE_READY:
	default:
		assert(0);
	}
	(void) mutex_unlock(&chandle->ch_mtx);
}

/*
 * Lock the cache with the specified mode.
 * If the cache is in updating state and a read lock is
 * requested, the lock won't be granted until either the
 * update is finished or SMB_CACHE_UPDATE_WAIT has passed.
 *
 * Whenever a lock is granted, the number of inflight cache
 * operations is incremented.
 */
static int
smb_cache_lock(smb_cache_t *chandle, int mode)
{
	(void) mutex_lock(&chandle->ch_mtx);
	switch (chandle->ch_state) {
	case SMB_CACHE_STATE_NOCACHE:
	case SMB_CACHE_STATE_DESTROYING:
		(void) mutex_unlock(&chandle->ch_mtx);
		return (ENODATA);

	case SMB_CACHE_STATE_REFRESHING:
		/*
		 * Read operations should wait until the update
		 * is completed.
		 */
		if (mode == SMB_CACHE_RDLOCK) {
			if (!smb_cache_wait(chandle)) {
				(void) mutex_unlock(&chandle->ch_mtx);
				return (ETIME);
			}
		}
	/* FALLTHROUGH */
	case SMB_CACHE_STATE_READY:
		chandle->ch_nops++;
		break;

	default:
		assert(0);
	}
	(void) mutex_unlock(&chandle->ch_mtx);

	/*
	 * Lock has to be taken outside the mutex otherwise
	 * there could be a deadlock
	 */
	if (mode == SMB_CACHE_RDLOCK)
		(void) rw_rdlock(&chandle->ch_cache_lck);
	else
		(void) rw_wrlock(&chandle->ch_cache_lck);

	return (0);
}

/*
 * Lock the cache for reading
 */
static int
smb_cache_rdlock(smb_cache_t *chandle)
{
	return (smb_cache_lock(chandle, SMB_CACHE_RDLOCK));
}

/*
 * Lock the cache for modification
 */
static int
smb_cache_wrlock(smb_cache_t *chandle)
{
	return (smb_cache_lock(chandle, SMB_CACHE_WRLOCK));
}

/*
 * Unlock the cache
 */
static void
smb_cache_unlock(smb_cache_t *chandle)
{
	(void) mutex_lock(&chandle->ch_mtx);
	assert(chandle->ch_nops > 0);
	chandle->ch_nops--;
	(void) cond_broadcast(&chandle->ch_cv);
	(void) mutex_unlock(&chandle->ch_mtx);

	(void) rw_unlock(&chandle->ch_cache_lck);
}


/*
 * Waits for ch_wait seconds if cache is in UPDATING state.
 * Upon wake up returns true if cache is ready to be used,
 * otherwise it returns false.
 */
static boolean_t
smb_cache_wait(smb_cache_t *chandle)
{
	timestruc_t to;
	int err;

	if (chandle->ch_wait == 0)
		return (B_TRUE);

	to.tv_sec = chandle->ch_wait;
	to.tv_nsec = 0;
	while (chandle->ch_state == SMB_CACHE_STATE_REFRESHING) {
		err = cond_reltimedwait(&chandle->ch_cv,
		    &chandle->ch_mtx, &to);
		if (err == ETIME)
			break;
	}

	return (chandle->ch_state == SMB_CACHE_STATE_READY);
}

/*
 * Removes and frees all the cache entries
 */
static void
smb_cache_destroy_nodes(smb_cache_t *chandle)
{
	void *cookie = NULL;
	smb_cache_node_t *cnode;
	avl_tree_t *cache;

	cache = &chandle->ch_cache;
	while ((cnode = avl_destroy_nodes(cache, &cookie)) != NULL) {
		if (chandle->ch_free)
			chandle->ch_free(cnode->cn_data);
		free(cnode);
	}
}
