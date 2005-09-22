/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <string.h>
#include <pthread.h>
#include <syslog.h>
#include <rpcsvc/nis.h>

#include "nis_hashitem.h"

/* We're the magician, so undefine the define-magic */
#undef	NIS_HASH_ITEM
#undef	NIS_HASH_TABLE
#undef	nis_insert_item
#undef	nis_find_item
#undef	nis_pop_item
#undef	nis_remove_item

#define	set_thread_status(msg, state)

/*
 * The hash table routines below implement nested (or recursive)
 * one-writer-or-many-readers locking. The following restrictions
 * exist:
 *
 *	Unless an item destructor has been established, an item
 *	MUST NOT be removed from a list (__nis_pop_item_mt() or
 *	(__nis_remove_item_mt()) when the thread performing
 *	the deletion is holding a read-only lock on the item.
 *	Doing so will result in the thread blocking in
 *	pthread_cond_wait() waiting for itself to signal on
 *	the condition variable. Deletion when the invoking
 *	thread is holding a write lock (any level of nesting),
 *	or no lock, is OK.
 */

void
__nis_init_hash_table(__nis_hash_table_mt *table,
			void (*itemDestructor)(void *)) {

	int	errorcode;

	if (table != 0) {
		errorcode = pthread_mutex_init(&table->lock, 0);
		if (errorcode != 0) {
			syslog(LOG_WARNING, "__nis_init_hash_table: "
			    "(table->lock) pthread_mutex_init returned %d (%s)",
			    errorcode, strerror(errorcode));
		}

		errorcode = pthread_cond_init(&table->cond, 0);
		if (errorcode != 0) {
			syslog(LOG_WARNING, "__nis_init_hash_table: "
			    "(table->cond) pthread_cond_init returned %d (%s)",
			    errorcode, strerror(errorcode));
		}

		errorcode = pthread_mutex_init(&table->traverser_id_lock, 0);
		if (errorcode != 0) {
			syslog(LOG_WARNING, "__nis_init_hash_table: "
			    "(table->traverser_id_lock) "
			    "pthread_mutex_init returned %d (%s)",
			    errorcode, strerror(errorcode));
		}

		table->traversed = 0;
		table->locked_items = 0;
		(void) memset(table->keys, 0, sizeof (table->keys));
		table->first = 0;
		table->destroyItem = itemDestructor;
	}
}

int
__nis_lock_hash_table(__nis_hash_table_mt *table, int traverse, char *msg) {

	pthread_t	myself = pthread_self();

	if (table != 0) {
		if (traverse) {
			/*
			 * We want exclusive access to everything in the
			 * table (list). Wait until there are no threads
			 * either traversing the list, or with exclusive
			 * access to an item.
			 */
			set_thread_status(msg, "table WL");
			(void) pthread_mutex_lock(&table->lock);
			set_thread_status(msg, "table L");
			while ((table->traversed != 0 &&
					table->traverser_id != myself) ||
				table->locked_items != 0) {
				set_thread_status(msg, "traverse cond_wait");
				MT_LOG(1, (LOG_NOTICE,
					"%d: lh table 0x%x trav cond wait",
					myself, table));
				(void) pthread_cond_wait(&table->cond,
							&table->lock);
			}
			set_thread_status(msg, "traverser_id WL");
			(void) pthread_mutex_lock(&table->traverser_id_lock);
			set_thread_status(msg, "traverser_id L");
			table->traversed = 1;
			table->traverser_id = myself;
			(void) pthread_mutex_unlock(&table->traverser_id_lock);
			set_thread_status(msg, "traverser_id U");
		} else {
			/*
			 * Called from the nis_*_item() functions. If no one's
			 * locked the table, lock it. If the table already is
			 * being traversed by us, do nothing. Otherwise, wait
			 * for the lock.
			 */
			set_thread_status(msg, "non-traverse TL");
			if (pthread_mutex_trylock(&table->lock) == EBUSY) {
				int	dolock = 1;
				/* Already locked; find out if it's us */
				set_thread_status(msg, "traverser_id L");
				(void) pthread_mutex_lock(
						&table->traverser_id_lock);
				if (table->traversed != 0 &&
					table->traverser_id == myself) {
					/* It's us. No action. */
					dolock = 0;
				}
				(void) pthread_mutex_unlock(
						&table->traverser_id_lock);
				set_thread_status(msg, "traverser_id U");
				/* Not us. Wait for the lock */
				if (dolock) {
					MT_LOG(1, (LOG_NOTICE,
					"%d: lh table 0x%x cond wait",
						myself, table));
					set_thread_status(msg, "table WL");
					(void) pthread_mutex_lock(&table->lock);
					set_thread_status(msg, "table L");
				}
			}
		}
		MT_LOG(1, (LOG_NOTICE, "%d: lh table %s lock acquired 0x%x",
		myself, traverse?"traverse":"non-traverse", table));
		return (1);
	} else {
		return (0);
	}
}

int
__nis_ulock_hash_table(__nis_hash_table_mt *table, int traverse, char *msg) {

	int	dounlock = 0;

	if (table != 0) {
		if (traverse) {
			/*
			 * Since we're keeping track of who's traversing the
			 * table in order to avoid recursive locking in the
			 * nis_*item() functions, we might as well sanity check
			 * here.
			 */
			set_thread_status(msg, "traverser_id WL");
			(void) pthread_mutex_lock(&table->traverser_id_lock);
			set_thread_status(msg, "traverser_id L");
			if (table->traversed != 0 &&
				table->traverser_id == pthread_self()) {
				table->traversed = 0;
				/*
				 * Leave traverser_id as it is, so that it
				 * possible to see which thread last held
				 * the traverser lock.
				 */
				dounlock = 1;
				/* Wake up other traversers-to-be */
				set_thread_status(msg, "table cond_signal");
				(void) pthread_cond_signal(&table->cond);
			}
			(void) pthread_mutex_unlock(&table->traverser_id_lock);
			set_thread_status(msg, "traverser_id U");
		} else {
			/*
			 * Called from the nis_*_item() functions. If we're
			 * traversing the table, leave it locked.
			 */
			set_thread_status(msg, "traverser_id WL");
			(void) pthread_mutex_lock(&table->traverser_id_lock);
			set_thread_status(msg, "traverser_id L");
			if (table->traversed == 0) {
				dounlock = 1;
			}
			(void) pthread_mutex_unlock(&table->traverser_id_lock);
			set_thread_status(msg, "traverser_id U");
		}
		if (dounlock) {
			(void) pthread_mutex_unlock(&table->lock);
			set_thread_status(msg, "table U");
		}
		MT_LOG(1, (LOG_NOTICE, "%d: lh table %s release 0x%x (%s)",
		pthread_self(), traverse?"traverse":"non-traverse", table,
			dounlock?"unlocked":"still held"));
		return (1);
	} else {
		return (0);
	}
}

static __nis_hash_item_mt **
__find_item_mt(nis_name name, __nis_hash_table_mt *table, int *keyp) {

	int			key = 0;
	unsigned char		*s;
	__nis_hash_item_mt	*it, **pp;

	/* Assume table!=0, table lock held */

	for (s = (unsigned char *)name;  *s != 0;  s++) {
		key += *s;
	}
	key %= (sizeof (table->keys) / sizeof (table->keys[0]));

	if (keyp != 0) {
		*keyp = key;
	}
	for (pp = &table->keys[key];  (it = *pp) != 0;  pp = &it->next) {
		if (strcmp(name, it->name) == 0) {
			break;
		}
	}

	return (pp);
}

/*
 * The 'readwrite' argument is interpreted as follows on a successful
 * return:
 *
 *	< 0	Exclusive access to item
 *	0	Item must not be used or referenced in any way
 *	> 0	Non-exclusive access (read-only) to item
 *
 * Except when 'readwrite' ==  0, the caller must explicitly release the
 * item (__nis_release_item()).
 */
int
__nis_insert_item_mt(void *arg, __nis_hash_table_mt *table, int readwrite) {

	__nis_hash_item_mt	*item = arg;
	int			key;
	__nis_hash_item_mt	**pp;

	if (item == 0 || __nis_lock_hash_table(table, 0, "nitmt") == 0)
		return (0);

	if ((*(pp = __find_item_mt(item->name, table, &key))) != 0) {
		(void) __nis_ulock_hash_table(table, 0, "nitmt");
		return (0);
	}

	(void) pthread_cond_init(&item->lock, 0);
	item->readers = item->writer = 0;
	item->last_reader_id = item->writer_id = INV_PTHREAD_ID;
	if (readwrite < 0) {
		item->writer = 1;
		item->writer_id = pthread_self();
		table->locked_items++;
	} else if (readwrite > 0) {
		item->readers = 1;
		item->last_reader_id = pthread_self();
		table->locked_items++;
	}
	item->next	= *pp;
	*pp		= item;
	item->keychain	= key;

	if (table->first)
		table->first->prv_item = item;

	item->nxt_item	= table->first;
	item->prv_item	= NULL;
	table->first	= item;

	(void) __nis_ulock_hash_table(table, 0, "nitmt");

	return (1);
}

void
__nis_insert_name_mt(nis_name name, __nis_hash_table_mt *table) {

	__nis_hash_item_mt	*item;

	if (name == 0 || table == 0)
		return;

	if ((item = malloc(sizeof (*item))) == 0) {
		syslog(LOG_WARNING, "__nis_insert_name_mt: malloc failed\n");
		return;
	}

	if ((item->name = strdup(name)) == 0) {
		syslog(LOG_WARNING, "__nis_insert_name_mt: strdup failed\n");
		free(item);
		return;
	}

	if (! __nis_insert_item_mt(item, table, 0)) {
		free(item->name);
		free(item);
	}
}

/*
 * readwrite:	< 0	Exclusive access
 *		0	No access; must not use returned item in any way,
 *			other than to confirm existence indicated by a non-NULL
 *			return value.
 *		> 0	Non-exclusive (read-only) access
 *
 * If trylock != 0 and *trylock != 0 and the item exists but the requested
 * lock type cannot be acquired, set *trylock = -1 and return 0.
 */
void *
__nis_find_item_mt(nis_name name, __nis_hash_table_mt *table, int readwrite,
			int *trylock) {

	__nis_hash_item_mt	*item;
	pthread_t		me = pthread_self();

	if (name == 0 || __nis_lock_hash_table(table, 0, "nfimt") == 0)
		return (0);

	/*
	 * Block waiting for more favorable conditions unless:
	 *
	 *	The item doesn't exist anymore
	 *
	 *	'readwrite' == 0 (verify existence only)
	 *
	 *	There's a writer, but it's us
	 *
	 *	There are no writers, and we're satisfied by RO access
	 *
	 *	A trylock was requested
	 */
	while ((item = *__find_item_mt(name, table, 0)) != 0) {
		if (readwrite == 0 ||
				(item->writer == 0 && item->readers == 0))
			break;
		if (item->writer == 0 && readwrite > 0)
			break;
		if ((item->writer != 0 && item->writer_id == me))
			break;
		if (trylock != 0 && *trylock != 0) {
			*trylock = -1;
			(void) __nis_ulock_hash_table(table, 0, "nfimt");
			return (0);
		}
		(void) pthread_cond_wait(&item->lock, &table->lock);
	}

	if (item != 0) {
		if (readwrite < 0) {
			if (item->writer == 0) {
				item->writer_id = me;
				table->locked_items++;
			}
			item->writer++;
		} else if (readwrite > 0) {
			if (item->readers == 0) {
				table->locked_items++;
			}
			item->last_reader_id = me;
			item->readers++;
		}
	}

	(void) __nis_ulock_hash_table(table, 0, "nfimt");

	return (item);
}

void *
__nis_pop_item_mt(__nis_hash_table_mt *table) {

	__nis_hash_item_mt	*item, *cur, *prev;
	pthread_t		mtid;

	if (__nis_lock_hash_table(table, 0, "npimt") == 0)
		return (0);

	/* Wait until the first item isn't in use by another thread */
	mtid = pthread_self();
	while ((item = table->first) != 0) {
		if (table->destroyItem != 0)
			break;
		if (item->readers == 0 && item->writer == 0)
			break;
		if (item->writer != 0 && item->writer_id == mtid)
			break;
		(void) pthread_cond_wait(&item->lock, &table->lock);
	}

	/* List might be empty now */
	if (item == 0) {
		__nis_ulock_hash_table(table, 0, "npimt");
		return (0);
	}

	prev = 0;
	for (cur = table->keys[item->keychain]; cur;
					prev = cur, cur = cur->next) {
		if (cur == item) {
			if (prev)
				prev->next = cur->next;
			else
				table->keys[cur->keychain] = cur->next;
			if (cur->prv_item)
				cur->prv_item->nxt_item = cur->nxt_item;
			else
				table->first = cur->nxt_item;
			if (cur->nxt_item)
				cur->nxt_item->prv_item = cur->prv_item;
			break;
		}
	}

	/*
	 * We use keychain < 0 to indicate that the item isn't linked
	 * into the table anymore.
	 */
	item->keychain = -1;

	/* Adjust the count of locked items in the table */
	if (table->locked_items != 0 &&
			(item->writer > 0 || item->readers > 0)) {
		table->locked_items--;
		if (table->locked_items == 0) {
			/* Wake up traversers-to-be */
			(void) pthread_cond_signal(&table->cond);
		}
	}

	/*
	 * Wake up any threads that were waiting for this item. Obviously,
	 * such threads must start over scanning the list.
	 */
	(void) pthread_cond_signal(&item->lock);
	(void) pthread_cond_destroy(&item->lock);

	/*
	 * If the item isn't locked, and an item destructor has been
	 * established, invoke the destructor.
	 */
	if (item->readers == 0 && item->writer == 0 &&
			table->destroyItem != 0) {
		(*table->destroyItem)(item);
		item = 0;
	} else {
		item->next = 0;
		item->prv_item = 0;
		item->nxt_item = 0;
	}

	(void) __nis_ulock_hash_table(table, 0, "npimt");

	/*
	 * If we get here, and the 'item' is NULL, we've popped the
	 * item, but also destroyed it. Returning NULL would make
	 * our caller believe the list is empty, so instead, we invoke
	 * ourselves to pop the next item.
	 */
	return ((item != 0) ? item : __nis_pop_item_mt(table));
}

void *
__nis_remove_item_mt(nis_name name, __nis_hash_table_mt *table) {

	__nis_hash_item_mt	*nl, **pp;
	pthread_t		mtid;

	if (__nis_lock_hash_table(table, 0, "nrimt") == 0)
		return (0);

	/* Find the item, and make sure it's not in use */
	mtid = pthread_self();
	while ((nl = *(pp = __find_item_mt(name, table, (int *)0))) != 0) {
		if (table->destroyItem != 0)
			break;
		if (nl->readers == 0 && nl->writer == 0)
			break;
		if (nl->writer != 0 && nl->writer_id == mtid)
			break;
		(void) pthread_cond_wait(&nl->lock, &table->lock);
	}

	if (nl == 0) {
		(void) __nis_ulock_hash_table(table, 0, "nrimt");
		return (0);
	}

	/* Remove nl from the hash chain */
	*pp = nl->next;
	nl->next = 0;

	/* Remove nl from the linked list of all names */
	if (nl->prv_item)
		nl->prv_item->nxt_item = nl->nxt_item;
	else
		table->first = nl->nxt_item;

	if (nl->nxt_item)
		nl->nxt_item->prv_item = nl->prv_item;
	nl->prv_item = 0;
	nl->nxt_item = 0;

	/* keychain < 0 means not in table anymore */
	nl->keychain = -1;

	/*
	 * If this item was locked, we can now decrement the count of
	 * locked items for the table.
	 */
	if (table->locked_items != 0 &&
		(nl->writer > 0 || nl->readers > 0)) {
		table->locked_items--;
		if (table->locked_items == 0) {
			/* Wake up traversers-to-be */
			(void) pthread_cond_signal(&table->cond);
		}
	}
	(void) pthread_cond_signal(&nl->lock);
	(void) pthread_cond_destroy(&nl->lock);

	/*
	 * If the item isn't locked, and an item destructor has been
	 * established, invoke the destructor. In that case, we return
	 * NULL, so that our caller doesn't try to reference the
	 * deleted item.
	 */
	if (nl->readers == 0 && nl->writer == 0 && table->destroyItem != 0) {
		(*table->destroyItem)(nl);
		nl = 0;
	}

	(void) __nis_ulock_hash_table(table, 0, "nrimt");

	return (nl);
}

/*
 * Release an item that had been acquired exclusively or non-exclusively.
 * Note that 'readwrite' can assume any integer value, and thus can be
 * used to release any level of recursive locking. It's the responsibility
 * of the caller to make sure that proper nesting is maintained.
 */
int
__nis_release_item(void *arg, __nis_hash_table_mt *table, int readwrite) {

	__nis_hash_item_mt	*item = arg;
	int			wakeup = 0;

	if (item == 0 || __nis_lock_hash_table(table, 0, "nreli") == 0)
		return (0);

	if ((readwrite < 0 && abs(readwrite) > item->writer) ||
		(readwrite < 0 && item->writer > 0 &&
			item->writer_id != pthread_self()) ||
		(readwrite > 0 && readwrite > item->readers)) {
		/* Caller confused; ignore */
		(void) __nis_ulock_hash_table(table, 0, "nreli");
		return (0);
	}

	if (readwrite < 0) {
		item->writer += readwrite;
		if (item->writer == 0 && item->keychain >= 0) {
			if (table->locked_items != 0)
				table->locked_items--;
			wakeup = 1;
		}
	} else if (readwrite > 0) {
		item->readers -= readwrite;
		item->last_reader_id = INV_PTHREAD_ID;
		if (item->readers == 0 && item->keychain >= 0) {
			if (table->locked_items != 0)
				table->locked_items--;
			wakeup = 1;
		}
	}

	if (table->locked_items == 0) {
		/* Wake up traversers-to-be */
		(void) pthread_cond_signal(&table->cond);
	}
	if (wakeup) {
		/* Wake up anyone else who wants this item */
		(void) pthread_cond_signal(&item->lock);
	}

	/*
	 * Delete if no references, not linked into list, and destructor
	 * established.
	 */
	if (item->keychain < 0 &&
			item->readers == 0 && item->writer == 0 &&
			item->next == 0 &&
			item->prv_item == 0 && item->nxt_item == 0 &&
			table->destroyItem != 0)
		(*table->destroyItem)(item);

	(void) __nis_ulock_hash_table(table, 0, "nreli");

	return (1);
}

/*
 * Return -1 if item checked out for both reading and writing, 1 if
 * readonly, and 0 otherwise.
 */
int
__nis_item_access(void *arg) {

	__nis_hash_item_mt	*item = arg;

	if (item != 0) {
		if (item->writer > 0) {
			if (item->writer_id != pthread_self())
				abort();
			return (-1);
		} else if (item->readers > 0) {
			return (1);
		}
	}

	return (0);
}

/*
 * __nis_scan_table_mt()
 *
 * Iterate over all items in a __nis_hash_table_mt. We ignore
 * first/prv_item/nxt_item and scan in hash-chain order.  The iterator
 * function should *not* insert or delete items. If the iterator
 * function returns TRUE the scan terminates. For compatibility with
 * the existing non-MT nis_scan_table() this function has no return
 * value.
 */
void
__nis_scan_table_mt(
	__nis_hash_table_mt	*table,
	bool_t		(*func)(__nis_hash_item_mt *, void *),
	void		*funcarg)
{
	int slot;

	if (table == 0) {
		return;
	}

	if (__nis_lock_hash_table(table, 1, "nstmt") == 0) {
		syslog(LOG_DEBUG, "__nis_scan_table_mt: mutex lock failed ");
		return;
	}

	for (slot = 0;
	    slot < sizeof (table->keys) / sizeof (table->keys[0]);
	    slot++) {
		__nis_hash_item_mt *it;

		for (it = table->keys[slot]; it != 0; it = it->next) {
			if (TRUE == (*func)(it, funcarg)) {
				break;
			}
		}
	}
	    if (__nis_ulock_hash_table(table, 1, "nstmt") == 0)
		syslog(LOG_DEBUG, "__nis_scan_table_mt: mutex unlock failed ");
}
