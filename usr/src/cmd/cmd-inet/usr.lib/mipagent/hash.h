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
 * Copyright (c) 1999, 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _HASH_H
#define	_HASH_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * hash.h: Hash Table structures, defines, and prototypes.
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

#ifdef __cplusplus
extern "C" {
#endif

enum {
	LOCK_NONE,
	LOCK_READ,
	LOCK_WRITE
};

typedef struct hash_entry {
	struct hash_entry   *next;
	enum {
		HASH_INT_KEY,
		HASH_STR_KEY
	} hashKeyType;
	void *data;
	uint32_t key;		/* Hopefully somewhere in *data */
	unsigned char keyLen;   /* keyLen can't be more than 255 chars now */
	unsigned char *keyData;
} HashEntry;

#define	HASH_TBL_SIZE   256

/*
 * If uniqueData is set to non-zero, then the bucket will be searched for
 * for uniqueness.
 */
typedef struct hash_table {
	size_t	size;
	int	uniqueData;
	rwlock_t hashLock;
	rwlock_t bucketLock[HASH_TBL_SIZE];
	HashEntry	*buckets[HASH_TBL_SIZE];
} HashTable;

#define	HASH_BIT_COUNT	8

#ifdef _BIG_ENDIAN
#define	HASHIT(key)                                          \
	((uint32_t)((key >> HASH_BIT_COUNT) ^ (key))         \
	& ~(~0 << HASH_BIT_COUNT))
#else
#define	HASHIT(key)                                          \
	((uint32_t)((key << HASH_BIT_COUNT) ^ (key)) >>      \
	(uint32_t)(32 - HASH_BIT_COUNT))
#endif

extern int InitHash(HashTable *);
extern int   linkHashTableEntryUint(HashTable *, uint32_t, void *, int);
extern int   linkHashTableEntryString(HashTable *, unsigned char *, uint32_t,
    void *, int);
extern boolean_t delHashTableEntryUint(HashTable *, void *,
    uint32_t, int);
extern  boolean_t delHashTableEntryString(HashTable *, void *, unsigned char *,
    uint32_t, int);
extern void *findHashTableEntryUint(HashTable *, uint32_t, int,
    boolean_t (*fcnt)(void *, uint32_t, uint32_t, uint32_t), uint32_t,
    uint32_t,
    uint32_t);
extern void *findHashTableEntryString(HashTable *, unsigned char *, uint32_t,
    int, boolean_t (*fcnt)(void *, uint32_t, uint32_t, uint32_t), uint32_t,
    uint32_t, uint32_t);
extern boolean_t changeHashEntryStringToUint(HashTable *, void *,
    unsigned char *, uint32_t, uint32_t);
extern void getAllHashTableEntries(HashTable *, boolean_t (*fcnt)(void *,
    uint32_t), int, uint32_t, boolean_t shutdown_flag);
extern void *enumerateAllHashTableEntries(HashTable *,
						uint32_t *,
						uint32_t *,
						int);
extern void initEnumeratorState(void *, size_t);

#ifdef __cplusplus
}
#endif

#endif /* _HASH_H */
