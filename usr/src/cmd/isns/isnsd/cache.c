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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "isns_server.h"
#include "isns_cache.h"
#include "isns_msgq.h"
#include "isns_obj.h"
#include "isns_htab.h"

/*
 * external variables
 */
extern msg_queue_t *sys_q;

#ifdef DEBUG
extern int verbose_lock;
#endif

/*
 * global data
 */
int cache_flag = 0;

/*
 * local variables
 */
static cache_t *imc;

/*
 * local functions.
 */

/*
 * ****************************************************************************
 * cache_init:
 *	create the cache data initially, including to invoke individual
 *	functions for creating the hash tables for object storage and
 *	discovery domain membership matrix.
 *
 * return - 0: no error; 1: otherwise.
 *
 * ****************************************************************************
 */
int
cache_init(void)
{
	/*
	 * allocate global cache memory.
	 */
	imc = (cache_t *)calloc(sizeof (cache_t), 1);
	if (imc == NULL ||
	    obj_tab_init(imc) != 0 ||
	    dd_matrix_init(imc) != 0) {
		cache_destroy();
		return (1); /* no memory */
	}

	/*
	 * initialize global cache rwlock.
	 */
	(void) rwlock_init(&imc->l, USYNC_PROCESS, NULL);

	/*
	 * inintialize global cache functions.
	 */
	imc->get_hval = obj_hval;
	imc->get_uid = get_obj_uid;
	imc->set_uid = set_obj_uid;
	imc->timestamp = get_timestamp;
	imc->add_hook = add_object;
	imc->replace_hook = replace_object;
	imc->cmp = obj_cmp;
	imc->clone = assoc_clone;
	imc->ddd = update_ddd;
#ifdef DEBUG
	imc->dump = obj_dump;
#endif

	return (0);
}

/*
 * ****************************************************************************
 * cache_destroy:
 *	destroy the cache data.
 *
 * ****************************************************************************
 */
void
cache_destroy(void)
{
	/* do nothing */
}

/*
 * ****************************************************************************
 * cache_lock:
 *	grab the lock on the cache data.
 *
 * mode - the read/write mode of the lock.
 * return - error code.
 *
 * ****************************************************************************
 */
int
cache_lock(int mode)
{
	int ret = 0;

	switch (mode) {
	case CACHE_WRITE:
		ret = rw_wrlock(&imc->l);
#ifdef DEBUG
		if (verbose_lock) {
			printf("cache locked for writing.\n");
		}
#endif
		break;
	case CACHE_READ:
		ret = rw_rdlock(&imc->l);
#ifdef DEBUG
		if (verbose_lock) {
			printf("cache locked for reading.\n");
		}
#endif
		break;
	case CACHE_TRY_READ:
		ret = rw_tryrdlock(&imc->l);
#ifdef DEBUG
		if (verbose_lock) {
			if (ret == 0) {
				printf("cache locked for reading.\n");
			} else {
				printf("cache locked for reading failed.\n");
			}
		}
#endif
		break;
	default:
		break;
	}

	return (ret);
}

/*
 * ****************************************************************************
 * cache_unlock:
 *	release the lock on the cache data.
 *	if the cache was locked for writing, a synchronization between
 *	the cache and persistent data store needs to be performed.
 *
 * mode - the read/write mode which the cache data was locked for.
 * ec - 0: commit the cache update; otherwise retreat it.
 * return - error code.
 *
 * ****************************************************************************
 */
int
cache_unlock(int mode, int ec)
{
	if (mode != CACHE_NO_ACTION) {
		/* sync between cache and data store */
		if (mode == CACHE_WRITE) {
			if (sys_q) {
				ec = data_sync(ec);
			}

			/* rest the cache update flag */
			RESET_CACHE_UPDATED();
		}

		ASSERT(!IS_CACHE_UPDATED());

		/* unlock it */
		(void) rw_unlock(&imc->l);
#ifdef DEBUG
		if (verbose_lock) {
			printf("cache unlocked.\n");
		}
#endif
	}

	return (ec);
}

/*
 * ****************************************************************************
 * cache_lock_read:
 *	grab the read lock on the cache.
 *
 * return - error code.
 *
 * ****************************************************************************
 */
int
cache_lock_read(void)
{
	return (cache_lock(CACHE_READ));
}

/*
 * ****************************************************************************
 * cache_lock_write:
 *	grab the write lock on the cache.
 *
 * return - error code.
 *
 * ****************************************************************************
 */
int
cache_lock_write(void)
{
	return (cache_lock(CACHE_WRITE));
}

/*
 * ****************************************************************************
 * cache_unlock_sync:
 *	synchronize the cache with persistent data store and
 *	release the lock.
 *
 * ec - 0: commit the cache update; otherwise retreat it.
 * return - error code.
 *
 * ****************************************************************************
 */
int
cache_unlock_sync(int ec)
{
	return (cache_unlock(CACHE_WRITE, ec));
}

/*
 * ****************************************************************************
 * cache_unlock_nosync:
 *	release the lock, no need to sync the data between cache and
 *	data store.
 *	if the cache has been updated, do not call this function, call
 *	cache_unlock_sync() with non-zero error code to indicate the
 *	sync action.
 *
 * return - error code.
 *
 * ****************************************************************************
 */
int
cache_unlock_nosync(void)
{
	return (cache_unlock(CACHE_READ, 0));
}

/*
 * ****************************************************************************
 * cache_get_htab:
 *	get the hash table for individual type of object.
 *
 * type - the object type.
 * return - the hash table.
 *
 * ****************************************************************************
 */
htab_t *
cache_get_htab(isns_type_t type)
{
	if (type > 0 && type < MAX_OBJ_TYPE) {
		return (imc->t[type]);
	}

	return (NULL);
}

/*
 * ****************************************************************************
 * cache_get_matrix:
 *	get the membership matrix for a discovery domain or a
 *	discovery domain set.
 *
 * type - the discovery domain or discovery domain set object type.
 * return - the matrix.
 *
 * ****************************************************************************
 */
matrix_t *
cache_get_matrix(isns_type_t type)
{
	matrix_t *x = NULL;

	switch (type) {
	case OBJ_DD:
		x = imc->x[0];
		break;
	case OBJ_DDS:
		x = imc->x[1];
		break;
	default:
		break;
	}

	return (x);
}

/*
 * ****************************************************************************
 * cache_lookup:
 *	invoke the hash table lookup for looking up a specific object and
 *	perform the callback function on the object.
 *
 * lcp - the object lookup control data.
 * uid_p - the pointer of object UID for returning.
 * callback - the callback function for the object.
 * return - error code.
 *
 * ****************************************************************************
 */
int
cache_lookup(lookup_ctrl_t *lcp, uint32_t *uid_p,
    int (*callback)(void *, void *))
{
	return (htab_lookup(imc->t[lcp->type],
	    lcp,
	    (lcp->op[0] == OP_INTEGER) ? lcp->data[0].ui : 0,
	    uid_p,
	    callback,
	    0));
}

/*
 * ****************************************************************************
 * cache_lookup:
 *	invoke the hash table lookup for looking up a specific object,
 *	the callback function is going to change the key of the object.
 *
 * lcp - the object lookup control data.
 * uid_p - the pointer of object UID for returning.
 * callback - the callback function for the object.
 * return - error code.
 *
 * ****************************************************************************
 */
int
cache_rekey(lookup_ctrl_t *lcp, uint32_t *uid_p,
    int (*callback)(void *, void *))
{
	return (htab_lookup(imc->t[lcp->type],
	    lcp,
	    (lcp->op[0] == OP_INTEGER) ? lcp->data[0].ui : 0,
	    uid_p,
	    callback,
	    1));
}

/*
 * ****************************************************************************
 * cache_add:
 *	invoke hash table add to add an object.
 *
 * obj - the object being added.
 * flag - 0: a real object;
 *	  otherwise an association object for discovery domain membership.
 * uid_p - the pointer of object UID for returning.
 * update_p - the pointer of flag (update object or newly register)
 *		for returning.
 * return - error code.
 *
 * ****************************************************************************
 */
int
cache_add(isns_obj_t *obj, int flag, uint32_t *uid_p, int *update_p)
{
	return (htab_add(imc->t[obj->type], obj, flag, uid_p, update_p));
}

/*
 * ****************************************************************************
 * cache_remove:
 *	invoke hash table remove to remove an object.
 *
 * lcp - the lookup control data for the object being removed.
 * flag - 0: a real object;
 *	  otherwise an association object for discovery domain membership.
 * return - the removed object.
 *
 * ****************************************************************************
 */
isns_obj_t *
cache_remove(lookup_ctrl_t *lcp, int flag)
{
	return (htab_remove(imc->t[lcp->type],
	    lcp,
	    (lcp->op[0] == OP_INTEGER) ? lcp->data[0].ui : 0,
	    flag));
}

/*
 * ****************************************************************************
 * cache_dump_htab:
 *	dump the hash table for debugging purpose.
 *
 * type - the object type.
 *
 * ****************************************************************************
 */
#ifdef DEBUG
void
cache_dump_htab(isns_type_t type)
{
	(void) htab_dump(imc->t[type]);
}
#endif
