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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_NFS4_DB_IMPL_H
#define	_NFS4_DB_IMPL_H

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
} rfs4_link_t;

struct rfs4_dbe {
	kmutex_t	dbe_lock[1];		/* Exclusive lock for entry */
	uint32_t	dbe_refcnt;		/* # of references */
	unsigned	dbe_skipsearch:1;	/* skip search */
	unsigned	dbe_invalid:1;		/* invalid/"freed" entry */
	unsigned	dbe_reserved:31;
	time_t		dbe_time_rele;		/* Time of last rele */
	id_t		dbe_id;			/* unique identifier */
	kcondvar_t	dbe_cv[1];
	rfs4_entry_t	dbe_data;
	rfs4_table_t	*dbe_table;
	rfs4_link_t	dbe_indices[1];		/* Array of indices for entry */
};

typedef struct rfs4_bucket {
	krwlock_t	dbk_lock[1];		/* lock hash chain */
	rfs4_link_t	*dbk_head;
} rfs4_bucket_t;

struct rfs4_index {
	uint32_t	dbi_tblidx;		/* which indice in entry */
	bool_t		dbi_createable;		/* Can create entries */
	rfs4_table_t	*dbi_table;		/* Pointer to table */
	char		*dbi_keyname;		/* String rep of key */
	rfs4_bucket_t	*dbi_buckets;		/* Hash buckets */
	uint32_t (*dbi_hash)(void *);		/* Given key find bucket */
	bool_t (*dbi_compare)(rfs4_entry_t, void *);	/* Key match entry? */
	void *(*dbi_mkkey)(rfs4_entry_t);	/* Given data generate a key */
	struct rfs4_index *dbi_inext;		/* next index on table */
};

struct rfs4_table {
	rfs4_table_t	*dbt_tnext;		/* next table in db */
	struct rfs4_database *dbt_db;		/* db that holds this table */
	krwlock_t	dbt_t_lock[1];		/* lock table for resize */
	kmutex_t	dbt_lock[1];		/* mutex for count and cached */
	char		*dbt_name;		/* Table name */
	id_space_t	*dbt_id_space;		/* space for unique entry ids */
	time_t	dbt_min_cache_time;		/* How long to cache entries */
	time_t	dbt_max_cache_time;		/* How long to cache entries */
	uint32_t	dbt_usize;		/* User entry size */
	uint32_t	dbt_maxentries;		/* max # of entries in table */
	uint32_t	dbt_len;		/* # of buckets in table */
	uint32_t	dbt_count;		/* # of entries in table */
	uint32_t	dbt_idxcnt;		/* # of indices in table */
	uint32_t	dbt_maxcnt;		/* max # of indices */
	uint32_t	dbt_ccnt;		/* # of creatable entries */
	uint32_t	dbt_id_lwat;		/* lo wtrmrk; 50% ids in use */
	uint32_t	dbt_id_hwat;		/* hi wtrmrk; 75% ids in use */
	time_t		dbt_id_reap;		/* table's reap interval */
	rfs4_index_t	*dbt_indices;		/* list of indices */
	/* Given entry and data construct entry */
	bool_t (*dbt_create)(rfs4_entry_t, void *data);
	void (*dbt_destroy)(rfs4_entry_t);	/* Destroy entry */
	bool_t (*dbt_expiry)(rfs4_entry_t);	/* Has this entry expired */
	kmem_cache_t	*dbt_mem_cache;		/* Cache for table entries */
	uint32_t	dbt_debug;		/* Debug Flags */
	/* set of vars used for managing the reaper thread */
	unsigned	dbt_reaper_shutdown:1;	/* table shutting down? */
	kcondvar_t	dbt_reaper_wait;	/* reaper thread waits here */
	kmutex_t	dbt_reaper_cv_lock;	/* lock used for cpr wait */
	callb_cpr_t	dbt_reaper_cpr_info;	/* cpr the reaper thread */
};

struct rfs4_database {
	kmutex_t	db_lock[1];
	uint32_t	db_debug_flags;		/* Table debug flags to set */
	uint32_t	db_shutdown_count;	/* count to manage shutdown */
	kcondvar_t	db_shutdown_wait;	/* where the shutdown waits */
	rfs4_table_t	*db_tables;		/* list of tables in db */
};

#define	RFS4_RECLAIM_PERCENT 10
#define	RFS4_REAP_INTERVAL 300

#define	HASH(idx, key) (idx->dbi_hash(key) % idx->dbi_table->dbt_len)

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
	rw_enter((bp)->dbk_lock, RW_WRITER); \
	ENQUEUE((bp)->dbk_head, l); \
	VALIDATE_ADDR((l)->entry); \
	rw_exit((bp)->dbk_lock); \
}

#define	DEQUEUE_IDX(bp, l) { \
	rw_enter((bp)->dbk_lock, RW_WRITER); \
	INVALIDATE_ADDR((l)->entry); \
	DEQUEUE((bp)->dbk_head, l); \
	rw_exit((bp)->dbk_lock); \
}

#ifdef	__cplusplus
}
#endif

#endif /* _NFS4_DB_IMPL_H */
