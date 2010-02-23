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

#ifndef _NSCD_H
#define	_NSCD_H

/*
 * This is a private header file.  Applications should not directly include
 * this file.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/avl.h>
#include <thread.h>
#include <synch.h>
#include <nss_dbdefs.h>
#include "getxby_door.h"
#include "nscd_common.h"
#include "nscd_config.h"

/*
 * OR'D in by server to call self for updates
 */
#define	UPDATEBIT	(1<<30)
#define	MASKUPDATEBIT(a) ((~UPDATEBIT)&(a))

/*
 * debug levels
 */
#define	DBG_OFF		0
#define	DBG_CANT_FIND	2
#define	DBG_NETLOOKUPS	4
#define	DBG_ALL		6

/*
 * Max size name we allow to be passed to avoid
 * buffer overflow problems
 */
#define	NSCDMAXNAMELEN	255

/*
 * cached entry status
 */
#define	ST_UPDATE_PENDING	0x1
#define	ST_LOOKUP_PENDING	0x2
#define	ST_PENDING		(ST_LOOKUP_PENDING | ST_UPDATE_PENDING)
#define	ST_NEW_ENTRY		0x4
#define	ST_DISCARD		0x8

/*
 * Cache eviction start and stop levels
 */
#define	_NSC_EVICTION_START_LEVEL	90
#define	_NSC_EVICTION_SAFE_LEVEL	80

/*
 * other internal constants
 */
#define	_NSC_MAX_DB		3
#define	_NSC_PUBLIC_ACCESS	-1
#define	_NSC_FILE_CHECK_TIME	0	/* check always for backwards compat */

/*
 * Macros used for logging purposes
 */
#define	yes_no(flag)	(flag == nscd_true)?"yes":"no"
#define	check_null(str)	(str)?str:"<null>"

/*
 * Macros used by compare routines
 */
#define	_NSC_INT_KEY_CMP(n1, n2) \
	(n1 > n2)?1:((n1 == n2)?0:-1)

#define	_NSC_GET_HITRATE(sp) \
	sp->hitrate = sp->pos_misses + sp->neg_misses + \
		sp->pos_hits + sp->neg_hits; \
	if (sp->hitrate > 0.0) \
		sp->hitrate = (100.0 * \
			((double)sp->pos_hits + \
			(double)sp->neg_hits)) / sp->hitrate;

/*
 * nsc_lookup action
 */
typedef enum {
	_NSC_NSLOOKUP = 0,
	_NSC_WAIT,
	_NSC_USECACHED
} nsc_action_t;

/*
 *  What each entry in the nameserver cache looks like.
 */

typedef struct nsc_entry_stat {
	uint_t		hits;		/* number of hits */
	uint8_t		status;		/* activity status */
	time_t		timestamp;	/* expiry time */
	int 		refcount;	/* reference count */
} nsc_entry_stat_t;

typedef struct nsc_entry {
	avl_node_t		avl_link;	/* libavl requirement */
	struct nsc_entry 	*qnext;		/* next on pqueue */
	struct nsc_entry 	*qprev;		/* prev on pqueue */
	nsc_entry_stat_t	stats;		/* entry's statistics */
	nss_XbyY_key_t		key;		/* entry's key */
	void			*buffer;	/* data buffer */
	size_t			bufsize;	/* data buffer length */
} nsc_entry_t;

typedef struct nsc_keephot {
	void	*ptr;
	uint_t	num;
} nsc_keephot_t;

/*
 * Structure to handle waiting for pending name service requests
 */
typedef struct waiter {
	cond_t		w_waitcv;
	uint8_t		w_signaled;
	nsc_entry_t	*w_key;
	struct waiter	*w_next, *w_prev;
} waiter_t;

/*
 * Macros used by hash table
 *
 * _NSC_HTSIZE_PRIMES are prime numbers that are used as hash table
 * sizes when hash table type is nsc_ht_prime. For hash tables of
 * type nsc_ht_power2, the size is automatically calculated.
 * Number of primes listed below is _NSC_HTSIZE_NUM_SLOTS + 1.
 * Each number (except the first) is a prime closest to a
 * power of 2 in increasing order. Ex: 509 is the closest prime to
 * 512 (2**9), 1021 is closest to 1024 (2**10), and so on.
 * The first prime is chosen as 211 for historical reasons.
 */
#define	_NSC_INIT_HTSIZE_PRIME	211
#define	_NSC_INIT_HTSIZE_POWER2	256
#define	_NSC_INIT_HTSIZE_SLOT_VALUE	2896
#define	_NSC_HTSIZE_NUM_SLOTS	10
#define	_NSC_HTSIZE_PRIMES	211, 509, 1021, 2053, 4099, 8191, \
				16381, 32771, 65537, 131071, 262147

#define	_NSC_DB_CES_KEY(ptr) \
		((ptr)->db_type == nsc_key_ces)
#define	_NSC_DB_CIS_KEY(ptr) \
		((ptr)->db_type == nsc_key_cis)
#define	_NSC_DB_STR_KEY(ptr) \
		_NSC_DB_CES_KEY(ptr) || _NSC_DB_CIS_KEY(ptr)
#define	_NSC_DB_INT_KEY(ptr) \
		((ptr)->db_type == nsc_key_int)

/*
 * cache backend param group (global)
 */
#define	NSCD_CFG_GROUP_INFO_GLOBAL_CACHE	{1, 0x0001}
typedef struct nscd_cfg_global_cache {
	nscd_cfg_group_info_t	gi;	/* config requirement */
	nscd_bool_t	enable;
} nscd_cfg_global_cache_t;

#define	NSCD_CFG_GLOBAL_CACHE_DEFAULTS \
	{ NSCD_CFG_GROUP_INFO_GLOBAL_CACHE, nscd_true }

/*
 * cache backend param group (per database)
 */
#define	NSCD_CFG_GROUP_INFO_CACHE	{12, 0x0fff}
typedef struct nscd_cfg_cache {
	nscd_cfg_group_info_t	gi;	/* config requirement */
	nscd_bool_t	enable;		/* if false return NOSERVER */
	nscd_bool_t	per_user;	/* if true per user access */
	nscd_bool_t	avoid_ns;	/* if true avoid name service */
	nscd_bool_t	check_files;	/* if true check file */
	int		check_interval;	/* check interval */
	int		pos_ttl;	/* time to live for +ve entries */
	int		neg_ttl;	/* time to live for -ve entries */
	int		keephot;	/* keep hot count */
	int		hint_size;	/* size to return for a GETHINTS */
	ulong_t		maxentries;	/* maximum entries allowed */
	int		suggestedsize;	/* obsolete */
	nscd_bool_t	old_data_ok;	/* obsolete */
} nscd_cfg_cache_t;

#define	NSCD_CFG_CACHE_DEFAULTS \
	{ \
		NSCD_CFG_GROUP_INFO_CACHE, \
		nscd_true, nscd_false, nscd_false, nscd_true, \
		_NSC_FILE_CHECK_TIME, 600, 10, 0, 1 << 11, 0, \
		0,  nscd_false \
	}

/*
 * cache backend stat group (per database)
 */
#define	NSCD_CFG_STAT_GROUP_INFO_CACHE	{9, 0x01ff}
typedef struct nscd_cfg_stat_cache {
	nscd_cfg_group_info_t	gi;	/* config requirement */
	ulong_t	pos_hits;		/* hits on +ve entries */
	ulong_t	neg_hits;		/* hits on -ve entries */
	ulong_t	pos_misses;		/* misses on +ve entries */
	ulong_t	neg_misses;		/* misses on -ve entries */
	ulong_t	entries;		/* count of cache entries */
	ulong_t	drop_count;		/* cache queries dropped */
	ulong_t	wait_count;		/* cache queries queued */
	ulong_t	invalidate_count;	/* count for cache invalidation */
	double	hitrate;		/* computed from other fields */
} nscd_cfg_stat_cache_t;

typedef struct nsc_db {
	/*
	 * Data
	 */
	avl_tree_t	tree;
	nsc_entry_t	**htable;
	nsc_entry_t	*qhead;
	nsc_entry_t	*qtail;
	nsc_entry_t	*reap_node;
	int 		callnumber;
	int		dbop;
	char 		*name;
	mutex_t		db_mutex;
	waiter_t	db_wait;	/* lookup wait CV */
	int		htsize;
	enum hash_type {
		nsc_ht_default = 0,
		nsc_ht_prime = 1,
		nsc_ht_power2 = 2
	} hash_type;
	enum db_type {
		nsc_key_ces = 0,
		nsc_key_cis = 1,
		nsc_key_int = 2,
		nsc_key_other = 3
	} db_type;
	/*
	 * Methods
	 */
	uint_t (*gethash)(nss_XbyY_key_t *, int);
	int (*compar)(const void *, const void *);
	void (*getlogstr)(char *, char *, size_t, nss_XbyY_args_t *);
	/*
	 * Config
	 */
	nscd_cfg_cache_t	cfg;
	time_t			cfg_mtime;
} nsc_db_t;


typedef struct nsc_ctx {
	char 		*dbname;		/* cache name */
	nscd_cfg_stat_cache_t	stats;		/* statistics */
	nscd_cfg_cache_t	cfg;		/* configs */
	time_t		cfg_mtime;		/* config last modified time */
	rwlock_t	cfg_rwlp;		/* config rwlock */
	mutex_t		stats_mutex;		/* stats mutex */
	mutex_t		file_mutex;		/* file mutex */
	time_t		file_mtime;		/* file last modified time */
	time_t		file_chktime; 		/* file last checked time */
	off_t		file_size;		/* file size at last check */
	ino_t		file_ino;		/* file inode at last check */
	const char 	*file_name;		/* filename for check_files */
	int		db_count;	/* number of caches, max _NSC_MAX_DB */
	nsc_db_t 	*nsc_db[_NSC_MAX_DB];	/* caches */
	sema_t		throttle_sema;		/* throttle lookups */
	sema_t		revalidate_sema;	/* revalidation threads */
	nscd_bool_t	revalidate_on;		/* reval. thread started */
	nscd_bool_t	reaper_on;		/* reaper thread started */
} nsc_ctx_t;

typedef struct nsc_lookup_args {
	nsc_ctx_t	*ctx;
	nsc_db_t	*nscdb;
	void		*buffer;
	size_t		bufsize;
} nsc_lookup_args_t;

#define	CACHE_CTX_COUNT	20

/* Context initialization */
extern void passwd_init_ctx(nsc_ctx_t *);
extern void group_init_ctx(nsc_ctx_t *);
extern void host_init_ctx(nsc_ctx_t *);
extern void ipnode_init_ctx(nsc_ctx_t *);
extern void exec_init_ctx(nsc_ctx_t *);
extern void prof_init_ctx(nsc_ctx_t *);
extern void user_init_ctx(nsc_ctx_t *);
extern void ether_init_ctx(nsc_ctx_t *);
extern void rpc_init_ctx(nsc_ctx_t *);
extern void proto_init_ctx(nsc_ctx_t *);
extern void net_init_ctx(nsc_ctx_t *);
extern void bootp_init_ctx(nsc_ctx_t *);
extern void auuser_init_ctx(nsc_ctx_t *);
extern void auth_init_ctx(nsc_ctx_t *);
extern void serv_init_ctx(nsc_ctx_t *);
extern void netmask_init_ctx(nsc_ctx_t *);
extern void printer_init_ctx(nsc_ctx_t *);
extern void project_init_ctx(nsc_ctx_t *);
extern void tnrhtp_init_ctx(nsc_ctx_t *);
extern void tnrhdb_init_ctx(nsc_ctx_t *);

/* Functions used to throttle threads */
extern int nscd_wait(nsc_ctx_t *, nsc_db_t *, nsc_entry_t *);
extern int nscd_signal(nsc_ctx_t *, nsc_db_t *, nsc_entry_t *);

/* Cache creation and initialization */
extern nscd_rc_t init_cache();
extern nsc_db_t *make_cache(enum db_type, int, char *,
	int (*compar) (const void *, const void *),
	void (*getlogstr)(char *, char *, size_t, nss_XbyY_args_t *),
	uint_t (*gethash)(nss_XbyY_key_t *, int),
	enum hash_type, int);

/* Cache backend lookup */
extern void nsc_lookup(nsc_lookup_args_t *, int);

/* Cache backend info */
extern void nsc_info(nsc_ctx_t *, char *, nscd_cfg_cache_t cfg[],
		nscd_cfg_stat_cache_t stats[]);
#ifdef NSCD_DEBUG
extern int nsc_dump(char *, int);
#endif	/* NSCD_DEBUG */

/* Cache invalidate */
extern void nsc_invalidate(nsc_ctx_t *, char *, nsc_ctx_t **);

/* Keep hot functions */
extern nsc_keephot_t *maken(int);
extern void *insertn(nsc_keephot_t *, uint_t, void *);

/* hash related routines */
extern uint_t cis_gethash(const char *, int);
extern uint_t ces_gethash(const char *, int);
extern uint_t db_gethash(const void *, int, int);

extern void leave(int n);
extern int get_cache_idx(char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _NSCD_H */
