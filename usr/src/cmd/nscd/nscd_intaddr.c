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

#include <stdlib.h>
#include <stdio.h>
#include "nscd_db.h"
#include "nscd_log.h"

static rwlock_t		addrDB_rwlock = DEFAULTRWLOCK;
static nscd_db_t	*addrDB = NULL;

/*
 * internal structure representing a nscd internal address
 */
typedef struct nscd_int_addr {
	int		to_delete;	/* no longer valid */
	int		type;
	void		*ptr;
	nscd_seq_num_t	seq_num;
	rwlock_t	rwlock;		/* used to serialize get and destroy */
} nscd_int_addr_t;

/*
 * FUNCTION: _nscd_create_int_addrDB
 *
 * Create the internal address database to keep track of the
 * memory allocated by _nscd_alloc.
 */
void *
_nscd_create_int_addrDB()
{

	nscd_db_t	*ret;
	char		*me = "_nscd_create_int_addrDB";

	_NSCD_LOG(NSCD_LOG_INT_ADDR | NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_DEBUG)
	(me, "initializing the internal address database\n");

	(void) rw_wrlock(&addrDB_rwlock);

	if (addrDB != NULL) {
		(void) rw_unlock(&addrDB_rwlock);
		return (addrDB);
	}

	ret = _nscd_alloc_db(NSCD_DB_SIZE_LARGE);

	if (ret != NULL)
		addrDB = ret;

	(void) rw_unlock(&addrDB_rwlock);

	return (ret);
}

/*
 * FUNCTION: _nscd_add_int_addr
 *
 * Add an address of 'type' to the internal address database.
 */
nscd_rc_t
_nscd_add_int_addr(
	void		*ptr,
	int		type,
	nscd_seq_num_t	seq_num)
{
	int		size;
	char		buf[2 * sizeof (ptr) + 1];
	nscd_db_entry_t	*db_entry;
	nscd_int_addr_t	*int_addr;

	if (ptr == NULL)
		return (NSCD_INVALID_ARGUMENT);

	(void) snprintf(buf, sizeof (buf), "%p", ptr);

	size = sizeof (*int_addr);

	db_entry = _nscd_alloc_db_entry(NSCD_DATA_ADDR,
			(const char *)buf, size, 1, 1);
	if (db_entry == NULL)
		return (NSCD_NO_MEMORY);

	int_addr = (nscd_int_addr_t *)*(db_entry->data_array);
	int_addr->ptr = ptr;
	int_addr->type = type;
	int_addr->seq_num = seq_num;
	(void) rwlock_init(&int_addr->rwlock, USYNC_THREAD, NULL);

	(void) rw_wrlock(&addrDB_rwlock);
	(void) _nscd_add_db_entry(addrDB, buf, db_entry,
		NSCD_ADD_DB_ENTRY_FIRST);
	(void) rw_unlock(&addrDB_rwlock);

	return (NSCD_SUCCESS);
}

/*
 * FUNCTION: _nscd_is_int_addr
 *
 * Check to see if an address can be found in the internal
 * address database, if so, obtain a reader lock on the
 * associated rw_lock. The caller needs to unlock it when
 * done using the data.
 */
rwlock_t *
_nscd_is_int_addr(
	void			*ptr,
	nscd_seq_num_t		seq_num)
{
	char			*me = "_nscd_is_int_addr";
	char			ptrstr[1 + 2 * sizeof (ptr)];
	rwlock_t		*addr_rwlock;
	const nscd_db_entry_t	*db_entry;

	if (ptr == NULL)
		return (NULL);

	(void) snprintf(ptrstr, sizeof (ptrstr), "%p", ptr);

	(void) rw_rdlock(&addrDB_rwlock);

	db_entry = _nscd_get_db_entry(addrDB, NSCD_DATA_ADDR,
		(const char *)ptrstr, NSCD_GET_FIRST_DB_ENTRY, 0);

	if (db_entry != NULL) {
		nscd_int_addr_t *int_addr;

		int_addr = (nscd_int_addr_t *)*(db_entry->data_array);
		addr_rwlock = &int_addr->rwlock;
		(void) rw_rdlock(addr_rwlock);

		/*
		 * If the data is marked as to be deleted
		 * or the sequence number does not match,
		 * return NULL.
		 */
		if (int_addr->to_delete == 1 ||
			int_addr->seq_num != seq_num) {
			(void) rw_unlock(addr_rwlock);
			addr_rwlock = NULL;
		}

		_NSCD_LOG(NSCD_LOG_INT_ADDR, NSCD_LOG_LEVEL_DEBUG)
		(me, "found %p, seq# = %lld\n", ptr, int_addr->seq_num);
	} else
		addr_rwlock = NULL;

	(void) rw_unlock(&addrDB_rwlock);

	return (addr_rwlock);
}

/*
 * FUNCTION: _nscd_del_int_addr
 *
 * Delete an address from the internal address database.
 */
void
_nscd_del_int_addr(
	void		*ptr,
	nscd_seq_num_t	seq_num)
{
	char			*me = "_nscd_del_int_addr";
	char			ptrstr[1 + 2 * sizeof (ptr)];
	rwlock_t		*addr_rwlock;
	nscd_int_addr_t		*int_addr;
	const nscd_db_entry_t	*db_entry;

	if (ptr == NULL)
		return;

	_NSCD_LOG(NSCD_LOG_INT_ADDR, NSCD_LOG_LEVEL_DEBUG)
	(me, "deleting int addr %p (%d)\n", ptr, seq_num);
	(void) snprintf(ptrstr, sizeof (ptrstr), "%p", ptr);

	(void) rw_rdlock(&addrDB_rwlock);
	/*
	 * first find the db entry and make sure that
	 * no one is currently locking it. i.e.,
	 * no one is waiting to use the same address.
	 * If it is locked, rw_wrlock() will not return
	 * until it is unlocked.
	 */
	db_entry = _nscd_get_db_entry(addrDB,
		NSCD_DATA_ADDR,
		(const char *)ptrstr,
		NSCD_GET_FIRST_DB_ENTRY, 0);
	if (db_entry != NULL) {
		int_addr = (nscd_int_addr_t *)*(db_entry->data_array);
		addr_rwlock = &int_addr->rwlock;
		(void) rw_wrlock(addr_rwlock);
	} else {
		(void) rw_unlock(&addrDB_rwlock);
		return;
	}
	(void) rw_unlock(&addrDB_rwlock);

	/*
	 * delete the db entry if the sequence numbers match
	 */
	if (int_addr->seq_num == seq_num) {
		(void) rw_wrlock(&addrDB_rwlock);
		(void) _nscd_delete_db_entry(addrDB,
			NSCD_DATA_ADDR,
			(const char *)ptrstr,
			NSCD_DEL_FIRST_DB_ENTRY, 0);
		(void) rw_unlock(&addrDB_rwlock);
	}
}

/*
 * FUNCTION: _nscd_destroy_int_addrDB
 *
 * Destroy the internal address database.
 */
void
_nscd_destroy_int_addrDB()
{
	(void) rw_wrlock(&addrDB_rwlock);
	_nscd_free_db(addrDB);
	addrDB = NULL;
	(void) rw_unlock(&addrDB_rwlock);
}
