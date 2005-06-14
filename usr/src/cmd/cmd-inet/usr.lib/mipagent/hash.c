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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * file: hash.c
 *
 * This file contains all routines used to manage hash tables.
 *
 * The locking strategy behind hash.c is actually quite simple,
 * but does need some explaining. Basically, we have three different
 * locks to worry about; one at the hash table level, one at the
 * bucket level and one at the node level.
 *
 *	+===================+
 *	|   Hash   |  Hash  |     +---------+     +---------+
 *	|  Table   | Bucket |<--->|HashEntry|<--->|HashEntry|
 *	|          |        |     +---------+     +---------+
 *	|    *     |   *    |         / \             / \
 *	|          |        |          |               |
 *	|          |        |         \ /             \ /
 *	|          |        |     +---------+     +---------+
 *      |          |        |     | * Node  |     | * Node  |
 *	+===================+     +---------+     +---------+
 *
 *	* = Lock is present
 *
 * When we walk through the Hash Table to add an item, it first
 * gets the hash bucket index, and locks the whole row (or bucket)
 * with a write lock. a HashEntry is then added at the head of the
 * bucket queue. If a node lock was requested, via a function
 * parameter, the node is locked. This is particularly useful if
 * additional work will be done to the node. The Hash Table lock
 * is then locked with a write lock, and the table counter is
 * incremented, then the lock is unlocked. Lastly, the hash
 * bucket is unlocked, and the function returns.
 *
 * When the code needs to find a node in the hash table, the
 * hash bucket (row) is locked, and all nodes in the row are
 * compare with the key provided. The caller may also provide
 * a pointer to a helper routine, which is used to further
 * qualify searches. If a match is found, the node is locked
 * (if requested), and the pointer to the node is retruned to
 * the caller.
 *
 * If a node is to be deleted from the table, the row is write
 * locked, the row is searched for a match, based on the key and
 * the data to the pointer. If a match is found, the HashEntry
 * is deleted. The table lock is then write locked, decremented
 * and unlocked. Finally, the bucket lock is released.
 *
 */
#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include "md5.h"
#include "mip.h"
#include "agent.h"

extern boolean_t shutdown_flag;

/*
 * The following macro is used to lock a node.
 */
#define	LOCK_NODE(lockType, data)                                        \
	switch (lockType) {                                              \
	case LOCK_WRITE:                                                 \
		(void) rw_wrlock((rwlock_t *)data);                      \
		break;                                                   \
	case LOCK_READ:                                                  \
		(void) rw_rdlock((rwlock_t *)data);                      \
		break;                                                   \
	case LOCK_NONE:                                                  \
	default:                                                         \
		break;                                                   \
	}

/*
 * Function: InitHash
 *
 * Arguments:	htbl - Pointer to Hash Table
 *
 * Description: This function will memset the Hash Table and
 *		initialize the hash table's read/write locks.
 *		We do not need to destroy the locks since
 *		Hash Tables are never released until the daemon
 *		is shutdown.
 *
 * Returns: int, 0 if successful
 */
int
InitHash(struct hash_table *htbl)
{
	int i;

	(void) memset(htbl, 0, sizeof (struct hash_table));
	if (rwlock_init(&htbl->hashLock, USYNC_THREAD, NULL)) {
		syslog(LOG_CRIT, "Unable to initialize read/write lock");
		return (-1);
	}
	for (i = 0; i < HASH_TBL_SIZE; i++) {
		if (rwlock_init(&htbl->bucketLock[i], USYNC_THREAD, NULL)) {
		    syslog(LOG_CRIT, "Unable to initialize read/write lock");
		    return (-1);
		}
	}

	return (0);
}

/*
 * Function: hashStr
 *
 * Arguments:	str - String to be hashed
 *		length - Length of string
 *
 * Description: This function will generate a hash
 *		based on the string provided to
 *		allow for strings to be used as keys
 *		in the hashing functions.
 *
 *		Note that we currently use MD5, and a
 *		more suitable algorithm will be implemented
 *		in the future (i.e. patricia)
 *
 * Returns: unsigned char containing the hash value.
 */
static unsigned char
hashStr(unsigned char *str, int length)
{
#define	TRY_EFFICIENT_HASH
#ifdef TRY_EFFICIENT_HASH
	int h = 0;
	int i;

	for (i = 0; i < length; i++)
		h = (64 * h + str[i]) % 256; /* Keep it within a char */
	return (h);
#else
	MD5_CTX context;
	unsigned char authenticator[16];

	if (str == NULL || length <= 0)
		return (0);

	MD5Init(&context);
	MD5Update(&context, str, length);
	MD5Final(authenticator, &context);

	return (authenticator[0]);
#endif

} /* hashStr */

/*
 * Function: linkHashTableEntryUint
 *
 * Arguments:	htbl - Pointer to Hash Table
 *		key - key to be used for bucket generation
 *		data - Pointer to the data
 *		lockType - The Lock type, which can be:
 *				LOCK_NONE - No Lock
 *				LOCK_READ - Read Lock
 *				LOCK_WRITE - Write Lock
 *
 * Description: This function will allocate a Hash Entry,
 *		find the appropriate bucket based on the key
 *		provided, and add the node to the bucket's
 *		queue.
 *
 *		If a lock type was selected, the node's will
 *		be locked upon return. The caller is then
 *		responsible for unlocking the node when it is
 *		finished with the data.
 *
 * Returns: int, 0 if successful
 */
int
linkHashTableEntryUint(HashTable *htbl, uint32_t key, void *data, int lockType)
{
	HashEntry *p;
	HashEntry *q;
	int index;

	if ((p = (HashEntry *)malloc(sizeof (HashEntry))) == NULL) {
		syslog(LOG_CRIT, "FATAL: Unable to allocate HashEntry");
		return (-1);
	}

	index = HASHIT(key);

	(void) rw_wrlock(&htbl->bucketLock[index]);

	q = htbl->buckets[index];

	/*
	 * If the unique flag is set, make sure the entry
	 * is not in this bucket.
	 */
	if (htbl->uniqueData) {
		HashEntry *r;
		/* Make sure value is not already in the table */
		for (r = q; r != NULL; r = r->next)
			if (r->key == key) {
				/* Error!  It is here! */
				syslog(LOG_ERR, "ERROR: Key already exists!");
				(void) rw_unlock(&htbl->bucketLock[index]);
				return (-2);
			}
	} /* end if unuque */

	htbl->buckets[index] = p;
	p->next = q;
	p->data = (void *)data;
	p->key = key;
	p->hashKeyType = HASH_INT_KEY;

	/*
	 * Lock and increment the counter.
	 */
	(void) rw_wrlock(&htbl->hashLock);
	htbl->size++;
	(void) rw_unlock(&htbl->hashLock);

	/*
	 * We now lock the data structure using the locking type
	 * specified by the caller.
	 */
	LOCK_NODE(lockType, data);

	(void) rw_unlock(&htbl->bucketLock[index]);


	return (0);
}

/*
 * Function: linkHashTableEntryString
 *
 * Arguments:	htbl - Pointer to Hash Table
 *		p - Pointer to Hash Entry (if available)
 *		key - Pointer to the keying information
 *		keyLen - Length of the keying information
 *		data - Pointer to the data
 *		lockType - The Lock type, which can be:
 *				LOCK_NONE - No Lock
 *				LOCK_READ - Read Lock
 *				LOCK_WRITE - Write Lock
 *
 * Description: This function will allocate a Hash Entry,
 *		find the appropriate bucket based on the key
 *		provided, and add the node to the bucket's
 *		queue.
 *
 *		It is possible to provide a HashEntry pointer,
 *		and if one is provided this function will not
 *		allocate a new one. This allows for the caller
 *		to move a Hash Entry from one Hash Table to
 *		another.
 *
 *		If a lock type was selected, the node's will
 *		be locked upon return. The caller is then
 *		responsible for unlocking the node when it is
 *		finished with the data.
 *
 * Returns: int, 0 if successful
 */
int
linkHashTableEntryString(HashTable *htbl, unsigned char *key, uint32_t keyLen,
    void *data, int lockType)
{
	HashEntry *p;
	HashEntry *q;
	int index;

	if (keyLen > 255) {
		syslog(LOG_ERR, "FATAL: Keys must be 255 chars or less");
		return (-1);
	}

	if ((p = (HashEntry *)malloc(sizeof (HashEntry))) == NULL) {
		syslog(LOG_CRIT, "FATAL: Unable to allocate HashEntry");
		return (-1);
	}

	if ((p->keyData = (unsigned char *)malloc(keyLen)) == NULL) {
		syslog(LOG_CRIT, "FATAL: Unable to allocate HashEntry");
		free(p);
		return (-1);
	}


	index = hashStr(key, keyLen);

	(void) rw_wrlock(&htbl->bucketLock[index]);

	q = htbl->buckets[index];

	/*
	 * If the unique flag is set, make sure the entry
	 * is not in this bucket.
	 */
	if (htbl->uniqueData) {
		HashEntry *r;
		/* Make sure value is not already in the table */
		for (r = q; r != NULL; r = r->next)
			if (r->keyLen == keyLen &&
			    strncmp((const char *)r->keyData,
				    (const char *)key,
				    keyLen) == 0) {
				/* Error!  It is here! */
				syslog(LOG_ERR, "ERROR: Key already exists!");
				(void) rw_unlock(&htbl->bucketLock[index]);
				return (-2);
			}
	} /* end if unuque */

	htbl->buckets[index] = p;
	p->next = q;
	p->data = (void *)data;
	p->key = 0;
	p->hashKeyType = HASH_STR_KEY;
	(void) memcpy(p->keyData, key, keyLen);
	p->keyLen = keyLen;

	/*
	 * Lock and increment the counter.
	 */
	(void) rw_wrlock(&htbl->hashLock);
	htbl->size++;
	(void) rw_unlock(&htbl->hashLock);

	/*
	 * We now lock the data structure using the locking type
	 * specified by the caller.
	 */
	LOCK_NODE(lockType, data);

	(void) rw_unlock(&htbl->bucketLock[index]);

	return (0);
}

/*
 * Function: delHashTableEntryUint
 *
 * Arguments:	htbl - Pointer to Hash Table
 *		data - Pointer to the data
 *		key - key to be used for bucket generation
 *		lockType - The Lock type, which can be:
 *				LOCK_NONE - No Lock
 *				LOCK_READ - Read Lock
 *				LOCK_WRITE - Write Lock
 *
 * Description: This function will find the node in the
 *		hash table, and delete the entry.
 *
 *		If a lock type was selected, the node's will
 *		be locked upon return. The caller is then
 *		responsible for unlocking the node when it is
 *		finished with the data.
 *
 * Returns: int, 0 if successful
 */
boolean_t
delHashTableEntryUint(HashTable *htbl, void *data, uint32_t key,
    int lockType)
{
	HashEntry *p, *tmp;
	HashEntry *q = NULL;
	int index;
	int found = _B_FALSE;

	index = HASHIT(key);

	(void) rw_wrlock(&htbl->bucketLock[index]);

	p = htbl->buckets[index];
	while (p) {
		if (p->hashKeyType == HASH_INT_KEY &&
		    p->data == data && p->key == key) {
			if (p == htbl->buckets[index])
				htbl->buckets[index] = p->next;
			else
				q->next = p->next;

			tmp = p;
			p = p->next;

			free(tmp);

			/*
			 * We delete the entry, let's decrement the counter.
			 */
			(void) rw_wrlock(&htbl->hashLock);
			htbl->size--;
			(void) rw_unlock(&htbl->hashLock);

			found = _B_TRUE;

			break;
		} else {
			q = p;
			p = p->next;
		}
	}

	/*
	 * We now lock the data structure using the locking type
	 * specified by the caller.
	 */
	LOCK_NODE(lockType, data);

	(void) rw_unlock(&htbl->bucketLock[index]);

	return (found);
}


/*
 * Function: delHashTableEntryString
 *
 * Arguments:	htbl - Pointer to Hash Table
 *		data - Pointer to the data
 *		key - key to be used for bucket generation
 *		lockType - The Lock type, which can be:
 *				LOCK_NONE - No Lock
 *				LOCK_READ - Read Lock
 *				LOCK_WRITE - Write Lock
 *
 * Description: This function will find the node in the
 *		hash table, and delete the entry.
 *
 *		If a lock type was selected, the node's will
 *		be locked upon return. The caller is then
 *		responsible for unlocking the node when it is
 *		finished with the data.
 *
 * Returns: int, 0 if successful
 */
boolean_t
delHashTableEntryString(HashTable *htbl, void *data, unsigned char *key,
    uint32_t keyLen, int lockType)
{
	HashEntry *p, *tmp;
	HashEntry *q = NULL;
	int index;
	int found = _B_FALSE;

	index = hashStr(key, keyLen);

	/*
	 * Lock the bucket
	 */
	(void) rw_wrlock(&htbl->bucketLock[index]);

	p = htbl->buckets[index];
	while (p) {
		if (p->hashKeyType == HASH_STR_KEY && p->data == data &&
		    p->keyLen == keyLen &&
		    !memcmp(p->keyData, key, keyLen)) {
			if (p == htbl->buckets[index])
				htbl->buckets[index] = p->next;
			else
				q->next = p->next;

			tmp = p;
			p = p->next;

			/*
			 * Free the key data AND the Hash Entry.
			 */
			free(tmp->keyData);
			free(tmp);

			/*
			 * We delete the entry, let's decrement the counter.
			 */
			(void) rw_wrlock(&htbl->hashLock);
			htbl->size--;
			(void) rw_unlock(&htbl->hashLock);

			found = _B_TRUE;

			break;
		} else {
			q = p;
			p = p->next;
		}
	}

	/*
	 * We now lock the data structure using the locking type
	 * specified by the caller.
	 */
	LOCK_NODE(lockType, data);

	(void) rw_unlock(&htbl->bucketLock[index]);

	return (found);
}


/*
 * Function: findHashTableEntryUint
 *
 * Arguments:	htbl - Pointer to Hash Table
 *		key - key to be used for bucket generation
 *		lockType - The Lock type, which can be:
 *				LOCK_NONE - No Lock
 *				LOCK_READ - Read Lock
 *				LOCK_WRITE - Write Lock
 *		fcnt() - Function Pointer
 *		p1 - First parameter to match
 *		p2 - Second parameter to match
 *		p3 - Third parameter to match
 *
 * Description: This function will find the node in the
 *		hash table using the key, and return the
 *		data associated with the entry. If a function
 *		pointer was passed, this function will call
 *		the pointer to further qualify the search.
 *
 *		If the function called returns _B_TRUE, this
 *		function will assume that the hash entry in
 *		question is the one we were looking for.
 *
 *		If a lock type was selected, the node's will
 *		be locked upon return. The caller is then
 *		responsible for unlocking the node when it is
 *		finished with the data.
 *
 * Returns: int, 0 if successful
 */
void *
findHashTableEntryUint(HashTable *htbl, uint32_t key, int lockType,
    boolean_t (*fcnt)(void *, uint32_t, uint32_t, uint32_t), uint32_t p1,
    uint32_t p2, uint32_t p3)
{
	HashEntry *p;
	int index;

	index = HASHIT(key);

	/*
	 * Lock the bucket
	 */
	(void) rw_rdlock(&htbl->bucketLock[index]);

	p = htbl->buckets[index];
	while (p) {
		if (p->hashKeyType == HASH_INT_KEY && p->key == key) {
			if ((fcnt == NULL) ||
			    (fcnt && fcnt(p->data, p1, p2, p3))) {
				/*
				 * We now lock the data structure using the
				 * locking type specified by the caller.
				 */
				LOCK_NODE(lockType, p->data);
				break;
			}
		}
		p = p->next;
	}

	/*
	 * Unlock the bucket
	 */
	(void) rw_unlock(&htbl->bucketLock[index]);

	if (p) {
		return (p->data);
	} else {
		return (NULL);
	}
}


/*
 * Function: findHashTableEntryString
 *
 * Arguments:	htbl - Pointer to Hash Table
 *		key - Pointer to the keying information
 *		keyLen - Length of the keying information
 *		lockType - The Lock type, which can be:
 *				LOCK_NONE - No Lock
 *				LOCK_READ - Read Lock
 *				LOCK_WRITE - Write Lock
 *		fcnt() - Function Pointer
 *		p1 - First parameter to match
 *		p2 - Second parameter to match
 *		p3 - Third parameter to match
 *
 * Description: This function will find the node in the
 *		hash table using the key, which is a string,
 *		and return the data associated with the entry.
 *
 *		If a lock type was selected, the node's will
 *		be locked upon return. The caller is then
 *		responsible for unlocking the node when it is
 *		finished with the data.
 *
 * Returns: int, 0 if successful
 */
void *
findHashTableEntryString(HashTable *htbl, unsigned char *key,
    uint32_t keyLen, int lockType,
    boolean_t (*fcnt)(void *, uint32_t, uint32_t, uint32_t), uint32_t p1,
    uint32_t p2, uint32_t p3)
{
	HashEntry *p;
	int index;

	index = hashStr(key, keyLen);

	/*
	 * Lock the bucket
	 */
	(void) rw_rdlock(&htbl->bucketLock[index]);

	p = htbl->buckets[index];
	while (p) {
		if (p->hashKeyType == HASH_STR_KEY && p->keyLen == keyLen &&
		    !memcmp(p->keyData, key, keyLen)) {
			if ((fcnt == NULL) ||
			    (fcnt && fcnt(p->data, p1, p2, p3))) {
				/*
				 * We now lock the data structure using the
				 * locking type specified by the caller.
				 */
				LOCK_NODE(lockType, p->data);
				break;
			}
		}
		p = p->next;
	}

	/*
	 * Unlock the bucket
	 */
	(void) rw_unlock(&htbl->bucketLock[index]);

	if (p) {
		return (p->data);
	} else {
		return (NULL);
	}
} /* findHashTableEntryString */

/*
 * Function: findHashTableEntryString
 *
 * Arguments:	htbl - Pointer to Hash Table
 *		data - Pointer to the data
 *		key - Pointer to the keying information
 *		keyLen - Length of the keying information
 *		newkey - key of type uint32_t used to find new bucket
 *
 * Description: This function is used to move a node that
 *		was previously hashed based on a string to
 *		a new bucket, now hashed with a 32 bit integer.
 *
 * Returns: boolean_t, _B_TRUE if successful
 */
boolean_t
changeHashEntryStringToUint(HashTable *htbl, void *data, unsigned char *key,
    uint32_t keyLen, uint32_t newKey)
{
	HashEntry *p;
	HashEntry *q = NULL;
	HashEntry *pToMove = NULL;
	int index;

	/*
	 * First let's remove the Hash Entry from the old bucket
	 */
	index = hashStr(key, keyLen);

	(void) rw_wrlock(&htbl->bucketLock[index]);

	p = htbl->buckets[index];
	while (p) {
		if (p->data == data && p->keyLen == keyLen &&
		    !memcmp(p->keyData, key, keyLen) &&
		    p->hashKeyType == HASH_STR_KEY) {
			if (p == htbl->buckets[index])
				htbl->buckets[index] = p->next;
			else
				q->next = p->next;

			/*
			 * Free the keyData since this one was
			 * a string.
			 */
			p->keyLen = 0;
			free(p->keyData);
			p->keyData = NULL;

			pToMove = p;

			break;
		} else {
			q = p;
			p = p->next;
		}
	}

	/*
	 * Unlock the bucket
	 */
	(void) rw_unlock(&htbl->bucketLock[index]);

	if (pToMove) {
		/*
		 * Cool, we've found it. Now let's move it to
		 * a new bucket, index on an uint32_t instead.
		 * If uniqueness is requested, we need to make
		 * the check here. XXX
		 */
		index = HASHIT(newKey);

		(void) rw_wrlock(&htbl->bucketLock[index]);

		q = htbl->buckets[index];

		htbl->buckets[index] = pToMove;

		pToMove->next = q;

		pToMove->hashKeyType = HASH_INT_KEY;
		pToMove->key = newKey;

		(void) rw_unlock(&htbl->bucketLock[index]);
	}

	return (pToMove != NULL);
} /* changeHashEntryStringToUint */

/*
 * Function: getAllHashTableEntries
 *
 * Arguments:	htbl - Pointer to Hash Table
 *		fcnt() - Function Pointer
 *		lockType - The Lock type, which can be:
 *				LOCK_NONE - No Lock
 *				LOCK_READ - Read Lock
 *				LOCK_WRITE - Write Lock
 *		p1 - First parameter to match
 *		shutdown_flag - If set, we are shutting down
 *
 * Description: This function is mostly used by the gargabe collected
 *		to get all the items in the hash table, and perform
 *		a check. The function provided MAY delete the node, and
 *		will inform this function by returning a _B_FALSE. If
 *		such a return code is seen, we will delete the Hash
 *		Entry.
 *
 *		This function is also called by the shutdown routine,
 *		so the shutdown flag is used to determine if we need
 *		to lock the buckets and the hash table.
 *
 * Returns: int, 0 if successful
 */
void
getAllHashTableEntries(HashTable *htbl, boolean_t (*fcnt)(void *, uint32_t),
    int lockType, uint32_t p1, boolean_t shutdown_flag)
{
	HashEntry *p;
	HashEntry *q = NULL;
	HashEntry *tmp;
	int i;
	int nentry;
	int result;

	/*
	 * If we are shutting down, we do not want to lock.
	 */
	if (shutdown_flag == _B_TRUE) {
		lockType = LOCK_NONE;
	}

	for (i = 0, nentry = 0;
		i < HASH_TBL_SIZE && (nentry < htbl->size); i++) {

		/*
		 * If we are shutting down, we do not want to lock.
		 */
		if (shutdown_flag == _B_FALSE) {
			(void) rw_wrlock(&htbl->bucketLock[i]);
		}

		p = htbl->buckets[i];
		while (p) {
			nentry++;
			/*
			 * The calling function is responsible for unlocking
			 * the node!!!! Note that since this function is
			 * mostly called by the garbage collector, we do not
			 * REALLY need to lock right away. If the lock
			 * request fails, we can try later.
			 */
			switch (lockType) {
			case LOCK_WRITE:
				result = rw_trywrlock((rwlock_t *)p->data);
				break;
			case LOCK_READ:
				result = rw_tryrdlock((rwlock_t *)p->data);
				break;
			case LOCK_NONE:
			default:
				result = 0;
				break;
			}

			if (result == 0 && (fcnt(p->data, p1) == _B_FALSE)) {
				/*
				 * If a failure was returned, we need to
				 * free this one.
				 */
				if (p == htbl->buckets[i])
					htbl->buckets[i] = p->next;
				else
					q->next = p->next;

				tmp = p;
				p = p->next;

				free(tmp);

				if (shutdown_flag == _B_FALSE) {
					/*
					 * We delete the entry, let's decrement
					 * the counter.
					 */
					(void) rw_wrlock(&htbl->hashLock);
					htbl->size--;
					(void) rw_unlock(&htbl->hashLock);
				} else {
					htbl->size--;
				}
				/*
				 * We need to reduce the entry
				 * table size, otherwise resources aren't
				 * released properly.
				 */
				nentry--;
			} else {
				if (result == 0) {
					switch (lockType) {
					case LOCK_WRITE:
					case LOCK_READ:
						(void) rw_unlock(
							(rwlock_t *)p->data);
						break;
					}
				}

				q = p;
				p = p->next;
			}
		}

		if (shutdown_flag == _B_FALSE) {
			/*
			 * Unlock the bucket
			 */
			(void) rw_unlock(&htbl->bucketLock[i]);
		}
	}
}

/*
 * Function: enumerateAllHashTableEntries
 *
 * Arguments:	table - Pointer to Hash Table
 *		bucket - IN/OUT determines which bucket to start
 *				enumerating from
 *		offset - IN/OUT determines which offset from bucket
 *				the last enumeration operation reached
 *		lockType - IN The Lock type, which can be:
 *				LOCK_NONE - No Lock
 *				LOCK_READ - Read Lock
 *				LOCK_WRITE - Write Lock
 *
 * Description: Enumerates synchronously the entire HashTable
 *		refered to by table; each call will set bucket
 *		and offset appropriately, and return the next
 *		HashEntry in the table. The caller should
 *		generally not need to mess with bucket and offset,
 *		except to ensure that the enumerator cookie
 *		(an array of uint32_ts) has been initialized
 *		the first time around with initEnumeratorState.
 *
 *		If a lock type was selected, the node's will
 *		be locked upon return. The caller is then
 *		responsible for unlocking the node when it is
 *		finished with the data.
 *
 *		This function is similar to getAllHashTableEntries,
 *		except that entries are returned to the caller
 *		directly, rather than through a callback, and
 *		the entries are not freed after enumeration (hence
 *		this enumeration function is read-only WRT the
 *		HashTable).
 *
 *		Note that this function has snapshot semantics --
 *		that is, it returns the next entry in the table
 *		as the table state is when the next enumeration
 *		call is made, not when the enumeration started.
 *		Hence if entries are removed or added while the
 *		the enumeration is proceeding, they may or may not
 *		show up in the enumeration. As such, this function
 *		is most useful for gathering stats for mechanisms
 *		like SNMP and mipagentstat.
 *
 * Returns:	void * on success (this implies more entries to come)
 *		NULL on enumeration completion
 */
void *enumerateAllHashTableEntries(HashTable *table,
					uint32_t *bucket,
					uint32_t *offset,
					int lockType) {
	HashEntry *p;
	void *answer = NULL;
	int i;

	/*
	 * Traverse the buckets of the hashtable, starting at the given
	 * bucket. Increment the offset here as well.
	 */
	for (; *bucket < HASH_TBL_SIZE; (*bucket)++) {
	    (void) rw_rdlock(&(table->bucketLock[*bucket]));
	    p = table->buckets[*bucket];

		/*
		 * Walk down the bucket's chain until either we find the
		 * next offset, or the chain ends.
		 */
	    for (i = 0; p; p = p->next, i++) {
		if (i == *offset) {
			/*
			 * got it; lock the node if requested, and
			 * bump the offset.
			 */
			LOCK_NODE(lockType, p->data);

			(*offset)++;
			answer = p->data;
			break;
		}
	    }

	    (void) rw_unlock(&(table->bucketLock[*bucket]));

	    if (answer != NULL) {
		return (answer);
	    }

		/*
		 * If we get here, the offset given was at the end of
		 * the chain. Reset it now to zero and move on to the
		 * next bucket.
		 */
	    *offset = 0;
	}

	/*
	 * If we get here, there are no more elements in the table,
	 * so the enumeration is finished. Inform the caller by
	 * returning NULL;
	 */
	return (NULL);
}

/*
 * Function: initEnumeratorState
 *
 * Arguments:	state - IN/OUT a pointer to the state cookie
 *		statelen - IN size of the state cookie
 *
 * Description: Initializes the enumerator state used by
 *		enumerateAllHashTableEntries such that when this
 *		state cookie is passed to enumerateAllHashTableEntries,
 *		the enumeration will commence at the first entry.
 */
void initEnumeratorState(void *state, size_t statelen) {
	(void)  memset(state, 0, statelen);
}
