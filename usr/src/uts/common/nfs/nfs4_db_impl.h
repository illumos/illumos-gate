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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_NFS4_DB_IMPL_H
#define	_NFS4_DB_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This is a private header file.  Applications should not directly include
 * this file.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#define	SEARCH_DEBUG	0x0001
#define	CREATE_DEBUG	0x0002
#define	CACHED_DEBUG	0x0004
#define	DESTROY_DEBUG	0x0008
#define	REAP_DEBUG	0x0010
#define	OTHER_DEBUG	0x0020
#define	WALK_DEBUG	0x0040

/*
 * A database is made up of a collection of tables.
 * Tables are in turn made up of a collection of
 * entries. Each table may haveone or more indices
 * associtated with it.
 */

/* Private implementation */
typedef struct rfs4_link {
	struct rfs4_link *next;
	struct rfs4_link *prev;
	rfs4_dbe_t *entry;
} rfs4_link;

struct rfs4_dbe {
	kmutex_t lock[1];		/* Exclusive lock for entry */
	uint32_t refcnt;		/* # of references */
	unsigned skipsearch:1;		/* skip search */
	unsigned invalid:1;		/* invalid/"freed" entry */
	unsigned reserved:31;
	time_t	 time_rele;		/* Time of last rele */
	id_t	 id;			/* unique identifier */
	kcondvar_t cv[1];
	rfs4_entry_t data;
	rfs4_table_t *table;
	rfs4_link indices[1];		/* Array of indices for entry */
};

typedef struct rfs4_bucket {
	krwlock_t lock[1];			/* lock hash chain */
	rfs4_link *head;
} rfs4_bucket;

struct rfs4_index {
	uint32_t tblidx;			/* which indice in entry */
	bool_t createable;			/* Can create entries */
	rfs4_table_t *table;			/* Pointer to table */
	char *keyname;				/* String rep of key */
	rfs4_bucket *buckets;			/* Hash buckets */
	uint32_t (*hash)(void *key);		/* Given key find bucket */
	bool_t (*compare)(rfs4_entry_t, void *key);	/* Key match entry? */
	void *(*mkkey)(rfs4_entry_t);		/* Given data generate a key */
	struct rfs4_index *inext;		/* next index on table */
};

struct rfs4_table {
	rfs4_table_t *tnext;			/* next table in db */
	struct rfs4_database *dbp;		/* db that holds this table */
	krwlock_t t_lock[1];			/* lock table for resize */
	kmutex_t lock[1];			/* mutex for count and cached */
	char *name;				/* Table name */
	id_space_t *id_space;			/* space for unique entry ids */
	time_t	min_cache_time;			/* How long to cache entries */
	time_t	max_cache_time;			/* How long to cache entries */
	uint32_t usize;				/* User entry size */
	uint32_t maxentries;			/* max # of entries in table */
	uint32_t len;				/* # of buckets in table */
	uint32_t count;				/* # of entries in table */
	uint32_t idxcnt;			/* # of indices in table */
	uint32_t maxcnt;			/* max # of indices */
	uint32_t ccnt;				/* # of creatable entries */
	rfs4_index_t *indices;			/* list of indices */
	/* Given entry and data construct entry */
	bool_t (*create)(rfs4_entry_t, void *data);
	void (*destroy)(rfs4_entry_t);		/* Destroy entry */
	bool_t (*expiry)(rfs4_entry_t);		/* Has this entry expired */
	kmem_cache_t *mem_cache;		/* Cache for table entries */
	uint32_t debug;				/* Debug Flags */
	/* set of vars used for managing the reaper thread */
	unsigned	reaper_shutdown:1;	/* table shutting down? */
	kcondvar_t reaper_wait;			/* reaper thread waits here */
	kmutex_t	reaper_cv_lock;		/* lock used for cpr wait */
	callb_cpr_t	reaper_cpr_info;	/* cpr the reaper thread */
};

struct rfs4_database {
	kmutex_t lock[1];
	uint32_t debug_flags;			/* Table debug flags to set */
	uint32_t shutdown_count;		/* count to manage shutdown */
	kcondvar_t shutdown_wait;		/* where the shutdown waits */
	rfs4_table_t *tables;			/* list of tables in db */
};

#define	RFS4_RECLAIM_PERCENT 10
#define	RFS4_REAP_INTERVAL 300

#define	HASH(idx, key) (idx->hash(key) % idx->table->len)

#define	ENQUEUE(head, l) { \
	(l)->prev = NULL; \
	(l)->next = (head); \
	if ((l)->next) \
	    (l)->next->prev = (l); \
	(head) = (l); \
}

#define	DEQUEUE(head, l) { \
	if ((l)->prev) \
		(l)->prev->next = (l)->next; \
	else \
		(head) = (l)->next; \
	if ((l)->next) \
		(l)->next->prev = (l)->prev; \
}

#define	INVALIDATE_ADDR(a) ((a) = (void *)((unsigned long)(a) | 1L))
#define	VALIDATE_ADDR(a) ((a) = (void *)((unsigned long)(a) & ~1L))
#define	INVALID_ADDR(a) (((unsigned long)(a) & 1L))
#define	INVALID_LINK(l) (INVALID_ADDR(l->entry))

#define	ENQUEUE_IDX(bp, l) { \
	rw_enter((bp)->lock, RW_WRITER); \
	ENQUEUE((bp)->head, l); \
	VALIDATE_ADDR((l)->entry); \
	rw_exit((bp)->lock); \
}

#define	DEQUEUE_IDX(bp, l) { \
	rw_enter((bp)->lock, RW_WRITER); \
	INVALIDATE_ADDR((l)->entry); \
	DEQUEUE((bp)->head, l); \
	rw_exit((bp)->lock); \
}

#ifdef	__cplusplus
}
#endif

#endif /* _NFS4_DB_IMPL_H */
