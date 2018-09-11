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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Milan Jurik. All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*
 * Cache routines for nscd
 */
#include <assert.h>
#include <errno.h>
#include <memory.h>
#include <signal.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <ucred.h>
#include <nss_common.h>
#include <locale.h>
#include <ctype.h>
#include <strings.h>
#include <string.h>
#include <umem.h>
#include <fcntl.h>
#include "cache.h"
#include "nscd_door.h"
#include "nscd_log.h"
#include "nscd_config.h"
#include "nscd_frontend.h"
#include "nscd_switch.h"

#define	SUCCESS		0
#define	NOTFOUND	-1
#define	SERVERERROR	-2
#define	NOSERVER	-3
#define	CONTINUE	-4

static nsc_db_t *nsc_get_db(nsc_ctx_t *, int);
static nscd_rc_t lookup_cache(nsc_lookup_args_t *, nscd_cfg_cache_t *,
		nss_XbyY_args_t *, char *, nsc_entry_t **);
static uint_t reap_cache(nsc_ctx_t *, uint_t, uint_t);
static void delete_entry(nsc_db_t *, nsc_ctx_t *, nsc_entry_t *);
static void print_stats(nscd_cfg_stat_cache_t *);
static void print_cfg(nscd_cfg_cache_t *);
static int lookup_int(nsc_lookup_args_t *, int);

#ifdef	NSCD_DEBUG
static void print_entry(nsc_db_t *, time_t, nsc_entry_t *);
static void avl_dump(nsc_db_t *, time_t);
static void hash_dump(nsc_db_t *, time_t);
#endif	/* NSCD_DEBUG */
static nsc_entry_t *hash_find(nsc_db_t *, nsc_entry_t *, uint_t *, nscd_bool_t);

static void queue_adjust(nsc_db_t *, nsc_entry_t *);
static void queue_remove(nsc_db_t *, nsc_entry_t *);
#ifdef	NSCD_DEBUG
static void queue_dump(nsc_db_t *, time_t);
#endif	/* NSCD_DEBUG */

static int launch_update(nsc_lookup_args_t *);
static void do_update(nsc_lookup_args_t *);
static void getxy_keepalive(nsc_ctx_t *, nsc_db_t *, int, int);

static void ctx_info(nsc_ctx_t *);
static void ctx_info_nolock(nsc_ctx_t *);
static void ctx_invalidate(nsc_ctx_t *);

static void nsc_db_str_key_getlogstr(char *, char *, size_t, nss_XbyY_args_t *);
static void nsc_db_int_key_getlogstr(char *, char *, size_t, nss_XbyY_args_t *);
static void nsc_db_any_key_getlogstr(char *, char *, size_t, nss_XbyY_args_t *);

static int nsc_db_cis_key_compar(const void *, const void *);
static int nsc_db_ces_key_compar(const void *, const void *);
static int nsc_db_int_key_compar(const void *, const void *);

static uint_t nsc_db_cis_key_gethash(nss_XbyY_key_t *, int);
static uint_t nsc_db_ces_key_gethash(nss_XbyY_key_t *, int);
static uint_t nsc_db_int_key_gethash(nss_XbyY_key_t *, int);

static umem_cache_t	*nsc_entry_cache;

static nsc_ctx_t *init_cache_ctx(int);
static void reaper(nsc_ctx_t *);
static void revalidate(nsc_ctx_t *);

static nss_status_t
dup_packed_buffer(void *src, void *dst) {
	nsc_lookup_args_t	*s = (nsc_lookup_args_t *)src;
	nsc_entry_t		*d = (nsc_entry_t *)dst;
	nss_pheader_t		*sphdr = (nss_pheader_t *)s->buffer;
	nss_pheader_t		*dphdr = (nss_pheader_t *)d->buffer;
	int			slen, new_pbufsiz = 0;

	if (NSCD_GET_STATUS(sphdr) != NSS_SUCCESS) {

		/* no result, copy header only (status, errno, etc) */
		slen = sphdr->data_off;
	} else {
		/*
		 * lookup result returned, data to copy is the packed
		 * header plus result (add 1 for the terminating NULL
		 * just in case)
		 */
		slen = sphdr->data_off + sphdr->data_len + 1;
	}

	/* allocate cache packed buffer */
	if (dphdr != NULL && d->bufsize <= slen && d->bufsize != 0) {
		/* old buffer too small, free it */
		free(dphdr);
		d->buffer = NULL;
		d->bufsize = 0;
		dphdr = NULL;
	}
	if (dphdr == NULL) {
		/* get new buffer */
		dphdr = calloc(1, slen + 1);
		if (dphdr == NULL)
			return (NSS_ERROR);
		d->buffer = dphdr;
		d->bufsize = slen + 1;
		new_pbufsiz = slen + 1;
	}

	(void) memcpy(dphdr, sphdr, slen);
	if (new_pbufsiz != 0)
		dphdr->pbufsiz = new_pbufsiz;

	return (NSS_SUCCESS);
}

char *cache_name[CACHE_CTX_COUNT] = {
	NSS_DBNAM_PASSWD,
	NSS_DBNAM_GROUP,
	NSS_DBNAM_HOSTS,
	NSS_DBNAM_IPNODES,
	NSS_DBNAM_EXECATTR,
	NSS_DBNAM_PROFATTR,
	NSS_DBNAM_USERATTR,
	NSS_DBNAM_ETHERS,
	NSS_DBNAM_RPC,
	NSS_DBNAM_PROTOCOLS,
	NSS_DBNAM_NETWORKS,
	NSS_DBNAM_BOOTPARAMS,
	NSS_DBNAM_AUTHATTR,
	NSS_DBNAM_SERVICES,
	NSS_DBNAM_NETMASKS,
	NSS_DBNAM_PRINTERS,
	NSS_DBNAM_PROJECT,
	NSS_DBNAM_TSOL_TP,
	NSS_DBNAM_TSOL_RH
};

typedef void (*cache_init_ctx_t)(nsc_ctx_t *);
static cache_init_ctx_t cache_init_ctx[CACHE_CTX_COUNT] = {
	passwd_init_ctx,
	group_init_ctx,
	host_init_ctx,
	ipnode_init_ctx,
	exec_init_ctx,
	prof_init_ctx,
	user_init_ctx,
	ether_init_ctx,
	rpc_init_ctx,
	proto_init_ctx,
	net_init_ctx,
	bootp_init_ctx,
	auth_init_ctx,
	serv_init_ctx,
	netmask_init_ctx,
	printer_init_ctx,
	project_init_ctx,
	tnrhtp_init_ctx,
	tnrhdb_init_ctx
};

nsc_ctx_t *cache_ctx_p[CACHE_CTX_COUNT] = { 0 };
static nscd_cfg_stat_cache_t	null_stats = { 0 };
static nscd_cfg_global_cache_t	global_cfg;

/*
 * Given database name 'dbname' find cache index
 */
int
get_cache_idx(char *dbname) {
	int	i;
	char	*nsc_name;

	for (i = 0; i < CACHE_CTX_COUNT; i++) {
		nsc_name = cache_name[i];
		if (strcmp(nsc_name, dbname) == 0)
			return (i);
	}
	return (-1);
}

/*
 * Given database name 'dbname' retrieve cache context,
 * if not created yet, allocate and initialize it.
 */
static nscd_rc_t
get_cache_ctx(char *dbname, nsc_ctx_t **ctx) {
	int	i;

	*ctx = NULL;

	i = get_cache_idx(dbname);
	if (i == -1)
		return (NSCD_INVALID_ARGUMENT);
	if ((*ctx = cache_ctx_p[i]) == NULL) {
		*ctx = init_cache_ctx(i);
		if (*ctx == NULL)
			return (NSCD_NO_MEMORY);
	}

	return (NSCD_SUCCESS);
}

/*
 * Generate a log string to identify backend operation in debug logs
 */
static void
nsc_db_str_key_getlogstr(char *name, char *whoami, size_t len,
		nss_XbyY_args_t *argp) {
	(void) snprintf(whoami, len, "%s [key=%s]", name, argp->key.name);
}


static void
nsc_db_int_key_getlogstr(char *name, char *whoami, size_t len,
		nss_XbyY_args_t *argp) {
	(void) snprintf(whoami, len, "%s [key=%d]", name, argp->key.number);
}

/*ARGSUSED*/
static void
nsc_db_any_key_getlogstr(char *name, char *whoami, size_t len,
		nss_XbyY_args_t *argp) {
	(void) snprintf(whoami, len, "%s", name);
}


/*
 * Returns cache based on dbop
 */
static nsc_db_t *
nsc_get_db(nsc_ctx_t *ctx, int dbop) {
	int	i;

	for (i = 0; i < ctx->db_count; i++) {
		if (ctx->nsc_db[i] && dbop == ctx->nsc_db[i]->dbop)
			return (ctx->nsc_db[i]);
	}
	return (NULL);
}


/*
 * integer compare routine for _NSC_DB_INT_KEY
 */
static int
nsc_db_int_key_compar(const void *n1, const void *n2) {
	nsc_entry_t	*e1, *e2;

	e1 = (nsc_entry_t *)n1;
	e2 = (nsc_entry_t *)n2;
	return (_NSC_INT_KEY_CMP(e1->key.number, e2->key.number));
}


/*
 * case sensitive name compare routine for _NSC_DB_CES_KEY
 */
static int
nsc_db_ces_key_compar(const void *n1, const void *n2) {
	nsc_entry_t	*e1, *e2;
	int		res, l1, l2;

	e1 = (nsc_entry_t *)n1;
	e2 = (nsc_entry_t *)n2;
	l1 = strlen(e1->key.name);
	l2 = strlen(e2->key.name);
	res = strncmp(e1->key.name, e2->key.name, (l1 > l2)?l1:l2);
	return (_NSC_INT_KEY_CMP(res, 0));
}


/*
 * case insensitive name compare routine _NSC_DB_CIS_KEY
 */
static int
nsc_db_cis_key_compar(const void *n1, const void *n2) {
	nsc_entry_t	*e1, *e2;
	int		res, l1, l2;

	e1 = (nsc_entry_t *)n1;
	e2 = (nsc_entry_t *)n2;
	l1 = strlen(e1->key.name);
	l2 = strlen(e2->key.name);
	res = strncasecmp(e1->key.name, e2->key.name, (l1 > l2)?l1:l2);
	return (_NSC_INT_KEY_CMP(res, 0));
}

/*
 * macro used to generate elf hashes for strings
 */
#define	_NSC_ELF_STR_GETHASH(func, str, htsize, hval) \
	hval = 0; \
	while (*str) { \
		uint_t  g; \
		hval = (hval << 4) + func(*str++); \
		if ((g = (hval & 0xf0000000)) != 0) \
			hval ^= g >> 24; \
		hval &= ~g; \
	} \
	hval %= htsize;


/*
 * cis hash function
 */
uint_t
cis_gethash(const char *key, int htsize) {
	uint_t	hval;
	if (key == NULL)
		return (0);
	_NSC_ELF_STR_GETHASH(tolower, key, htsize, hval);
	return (hval);
}


/*
 * ces hash function
 */
uint_t
ces_gethash(const char *key, int htsize) {
	uint_t	hval;
	if (key == NULL)
		return (0);
	_NSC_ELF_STR_GETHASH(, key, htsize, hval);
	return (hval);
}


/*
 * one-at-a-time hash function
 */
uint_t
db_gethash(const void *key, int len, int htsize) {
	uint_t	hval, i;
	const char *str = key;

	if (str == NULL)
		return (0);

	for (hval = 0, i = 0; i < len; i++) {
		hval += str[i];
		hval += (hval << 10);
		hval ^= (hval >> 6);
	}
	hval += (hval << 3);
	hval ^= (hval >> 11);
	hval += (hval << 15);
	return (hval % htsize);
}


/*
 * case insensitive name gethash routine _NSC_DB_CIS_KEY
 */
static uint_t
nsc_db_cis_key_gethash(nss_XbyY_key_t *key, int htsize) {
	return (cis_gethash(key->name, htsize));
}


/*
 * case sensitive name gethash routine _NSC_DB_CES_KEY
 */
static uint_t
nsc_db_ces_key_gethash(nss_XbyY_key_t *key, int htsize) {
	return (ces_gethash(key->name, htsize));
}


/*
 * integer gethash routine _NSC_DB_INT_KEY
 */
static uint_t
nsc_db_int_key_gethash(nss_XbyY_key_t *key, int htsize) {
	return (db_gethash(&key->number, sizeof (key->number), htsize));
}


/*
 * Find entry in the hash table
 * if cmp == nscd_true)
 *	return entry only if the keys match
 * else
 *	return entry in the hash location without checking the keys
 *
 */
static nsc_entry_t *
hash_find(nsc_db_t *nscdb, nsc_entry_t *entry, uint_t *hash,
			nscd_bool_t cmp) {

	nsc_entry_t	*hashentry;

	if (nscdb->gethash)
		*hash = nscdb->gethash(&entry->key, nscdb->htsize);
	else
		return (NULL);

	hashentry = nscdb->htable[*hash];
	if (cmp == nscd_false || hashentry == NULL)
		return (hashentry);
	if (nscdb->compar) {
		if (nscdb->compar(entry, hashentry) == 0)
			return (hashentry);
	}
	return (NULL);
}


#define	HASH_REMOVE(nscdb, entry, hash, cmp) \
	if (nscdb->htable) { \
		if (entry == hash_find(nscdb, entry, &hash, cmp)) \
			nscdb->htable[hash] = NULL; \
	}


#define	HASH_INSERT(nscdb, entry, hash, cmp) \
	if (nscdb->htable) { \
		(void) hash_find(nscdb, entry, &hash, cmp); \
		nscdb->htable[hash] = entry; \
	}


#ifdef	NSCD_DEBUG
static void
print_entry(nsc_db_t *nscdb, time_t now, nsc_entry_t *entry) {
	nss_XbyY_args_t args;
	char		whoami[512];

	switch (entry->stats.status) {
	case ST_NEW_ENTRY:
		(void) fprintf(stdout, gettext("\t status: new entry\n"));
		return;
	case ST_UPDATE_PENDING:
		(void) fprintf(stdout, gettext("\t status: update pending\n"));
		return;
	case ST_LOOKUP_PENDING:
		(void) fprintf(stdout, gettext("\t status: lookup pending\n"));
		return;
	case ST_DISCARD:
		(void) fprintf(stdout, gettext("\t status: discarded entry\n"));
		return;
	default:
		if (entry->stats.timestamp < now)
			(void) fprintf(stdout,
			gettext("\t status: expired (%d seconds ago)\n"),
			now - entry->stats.timestamp);
		else
			(void) fprintf(stdout,
			gettext("\t status: valid (expiry in %d seconds)\n"),
			entry->stats.timestamp - now);
		break;
	}
	(void) fprintf(stdout, gettext("\t hits: %u\n"), entry->stats.hits);
	args.key = entry->key;
	(void) nscdb->getlogstr(nscdb->name, whoami, sizeof (whoami), &args);
	(void) fprintf(stdout, "\t %s\n", whoami);
}
#endif	/* NSCD_DEBUG */

static void
print_stats(nscd_cfg_stat_cache_t *statsp) {

	(void) fprintf(stdout, gettext("\n\t STATISTICS:\n"));
	(void) fprintf(stdout, gettext("\t positive hits: %lu\n"),
			statsp->pos_hits);
	(void) fprintf(stdout, gettext("\t negative hits: %lu\n"),
			statsp->neg_hits);
	(void) fprintf(stdout, gettext("\t positive misses: %lu\n"),
			statsp->pos_misses);
	(void) fprintf(stdout, gettext("\t negative misses: %lu\n"),
			statsp->neg_misses);
	(void) fprintf(stdout, gettext("\t total entries: %lu\n"),
			statsp->entries);
	(void) fprintf(stdout, gettext("\t queries queued: %lu\n"),
			statsp->wait_count);
	(void) fprintf(stdout, gettext("\t queries dropped: %lu\n"),
			statsp->drop_count);
	(void) fprintf(stdout, gettext("\t cache invalidations: %lu\n"),
			statsp->invalidate_count);

	_NSC_GET_HITRATE(statsp);
	(void) fprintf(stdout, gettext("\t cache hit rate: %10.1f\n"),
			statsp->hitrate);
}


static void
print_cfg(nscd_cfg_cache_t *cfgp) {
	(void) fprintf(stdout, gettext("\n\t CONFIG:\n"));
	(void) fprintf(stdout, gettext("\t enabled: %s\n"),
			yes_no(cfgp->enable));
	(void) fprintf(stdout, gettext("\t per user cache: %s\n"),
			yes_no(cfgp->per_user));
	(void) fprintf(stdout, gettext("\t avoid name service: %s\n"),
			yes_no(cfgp->avoid_ns));
	(void) fprintf(stdout, gettext("\t check file: %s\n"),
			yes_no(cfgp->check_files));
	(void) fprintf(stdout, gettext("\t check file interval: %d\n"),
			cfgp->check_interval);
	(void) fprintf(stdout, gettext("\t positive ttl: %d\n"),
			cfgp->pos_ttl);
	(void) fprintf(stdout, gettext("\t negative ttl: %d\n"),
			cfgp->neg_ttl);
	(void) fprintf(stdout, gettext("\t keep hot count: %d\n"),
			cfgp->keephot);
	(void) fprintf(stdout, gettext("\t hint size: %d\n"),
			cfgp->hint_size);
	(void) fprintf(stdout, gettext("\t max entries: %lu%s"),
			cfgp->maxentries,
			cfgp->maxentries?"\n":" (unlimited)\n");
}


#ifdef	NSCD_DEBUG
static void
hash_dump(nsc_db_t *nscdb, time_t now) {
	nsc_entry_t	*entry;
	int		i;

	(void) fprintf(stdout, gettext("\n\nHASH TABLE:\n"));
	for (i = 0; i < nscdb->htsize; i++) {
		if ((entry = nscdb->htable[i]) != NULL) {
			(void) fprintf(stdout, "hash[%d]:\n", i);
			print_entry(nscdb, now, entry);
		}
	}
}
#endif	/* NSCD_DEBUG */


#ifdef	NSCD_DEBUG
static void
avl_dump(nsc_db_t *nscdb, time_t now) {
	nsc_entry_t	*entry;
	int		i;

	(void) fprintf(stdout, gettext("\n\nAVL TREE:\n"));
	for (entry = avl_first(&nscdb->tree), i = 0; entry != NULL;
			entry = avl_walk(&nscdb->tree, entry, AVL_AFTER)) {
		(void) fprintf(stdout, "avl node[%d]:\n", i++);
		print_entry(nscdb, now, entry);
	}
}
#endif	/* NSCD_DEBUG */


#ifdef	NSCD_DEBUG
static void
queue_dump(nsc_db_t *nscdb, time_t now) {
	nsc_entry_t	*entry;
	int		i;

	(void) fprintf(stdout,
		gettext("\n\nCACHE [name=%s, nodes=%lu]:\n"),
		nscdb->name, avl_numnodes(&nscdb->tree));

	(void) fprintf(stdout,
		gettext("Starting with the most recently accessed:\n"));

	for (entry = nscdb->qtail, i = 0; entry; entry = entry->qnext) {
		(void) fprintf(stdout, "entry[%d]:\n", i++);
		print_entry(nscdb, now, entry);
	}
}
#endif	/* NSCD_DEBUG */

static void
queue_remove(nsc_db_t *nscdb, nsc_entry_t *entry) {

	if (nscdb->qtail == entry)
		nscdb->qtail = entry->qnext;
	else
		entry->qprev->qnext = entry->qnext;

	if (nscdb->qhead == entry)
		nscdb->qhead = entry->qprev;
	else
		entry->qnext->qprev = entry->qprev;

	if (nscdb->reap_node == entry)
		nscdb->reap_node = entry->qnext;
	entry->qnext = entry->qprev = NULL;
}


static void
queue_adjust(nsc_db_t *nscdb, nsc_entry_t *entry) {

#ifdef NSCD_DEBUG
	assert(nscdb->qtail || entry->qnext == NULL &&
			entry->qprev == NULL);

	assert(nscdb->qtail && nscdb->qhead ||
		nscdb->qtail == NULL && nscdb->qhead == NULL);

	assert(entry->qprev || entry->qnext == NULL ||
		nscdb->qtail == entry);
#endif /* NSCD_DEBUG */

	/* already in the desired position */
	if (nscdb->qtail == entry)
		return;

	/* new queue */
	if (nscdb->qtail == NULL) {
		nscdb->qhead = nscdb->qtail = entry;
		return;
	}

	/* new entry (prev == NULL AND tail != entry) */
	if (entry->qprev == NULL) {
		nscdb->qtail->qprev = entry;
		entry->qnext = nscdb->qtail;
		nscdb->qtail = entry;
		return;
	}

	/* existing entry */
	if (nscdb->reap_node == entry)
		nscdb->reap_node = entry->qnext;
	if (nscdb->qhead == entry)
		nscdb->qhead = entry->qprev;
	else
		entry->qnext->qprev = entry->qprev;
	entry->qprev->qnext = entry->qnext;
	entry->qprev = NULL;
	entry->qnext = nscdb->qtail;
	nscdb->qtail->qprev = entry;
	nscdb->qtail = entry;
}


/*
 * Init cache
 */
nscd_rc_t
init_cache(int debug_level) {
	int cflags;

	cflags = (debug_level > 0)?0:UMC_NODEBUG;
	nsc_entry_cache = umem_cache_create("nsc_entry_cache",
				sizeof (nsc_entry_t), 0, NULL, NULL, NULL,
				NULL, NULL, cflags);
	if (nsc_entry_cache == NULL)
		return (NSCD_NO_MEMORY);
	return (NSCD_SUCCESS);
}


/*
 * Create cache
 */
nsc_db_t *
make_cache(enum db_type dbtype, int dbop, char *name,
    int (*compar) (const void *, const void *),
    void (*getlogstr)(char *, char *, size_t, nss_XbyY_args_t *),
    uint_t (*gethash)(nss_XbyY_key_t *, int),
    enum hash_type httype, int htsize)
{
	nsc_db_t	*nscdb;
	char		*me = "make_cache";

	nscdb = (nsc_db_t *)malloc(sizeof (*nscdb));
	if (nscdb == NULL) {
		_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_ERROR)
		(me, "%s: memory allocation failure\n", name);
		goto out;
	}
	(void) memset(nscdb, 0, sizeof (*nscdb));

	nscdb->dbop = dbop;
	nscdb->name = name;
	nscdb->db_type = dbtype;

	/* Assign compare routine */
	if (compar == NULL) {
		if (_NSC_DB_CES_KEY(nscdb))
			nscdb->compar = nsc_db_ces_key_compar;
		else if (_NSC_DB_CIS_KEY(nscdb))
			nscdb->compar = nsc_db_cis_key_compar;
		else if (_NSC_DB_INT_KEY(nscdb))
			nscdb->compar = nsc_db_int_key_compar;
		else
			assert(0);
	} else {
		nscdb->compar = compar;
	}

	/* The cache is an AVL tree */
	avl_create(&nscdb->tree, nscdb->compar, sizeof (nsc_entry_t),
	    offsetof(nsc_entry_t, avl_link));

	/* Assign log routine */
	if (getlogstr == NULL) {
		if (_NSC_DB_STR_KEY(nscdb))
			nscdb->getlogstr = nsc_db_str_key_getlogstr;
		else if (_NSC_DB_INT_KEY(nscdb))
			nscdb->getlogstr = nsc_db_int_key_getlogstr;
		else
			nscdb->getlogstr = nsc_db_any_key_getlogstr;
	} else {
		nscdb->getlogstr = getlogstr;
	}

	/* The AVL tree based cache uses a hash table for quick access */
	if (htsize != 0) {
		/* Determine hash table size based on type */
		nscdb->hash_type = httype;
		if (htsize < 0) {
			switch (httype) {
			case nsc_ht_power2:
				htsize = _NSC_INIT_HTSIZE_POWER2;
				break;
			case nsc_ht_prime:
			case nsc_ht_default:
			default:
				htsize = _NSC_INIT_HTSIZE_PRIME;
			}
		}
		nscdb->htsize = htsize;

		/* Create the hash table */
		nscdb->htable = calloc(htsize, sizeof (*(nscdb->htable)));
		if (nscdb->htable == NULL) {
			_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_ERROR)
			(me, "%s: memory allocation failure\n", name);
			goto out;
		}

		/* Assign gethash routine */
		if (gethash == NULL) {
			if (_NSC_DB_CES_KEY(nscdb))
				nscdb->gethash = nsc_db_ces_key_gethash;
			else if (_NSC_DB_CIS_KEY(nscdb))
				nscdb->gethash = nsc_db_cis_key_gethash;
			else if (_NSC_DB_INT_KEY(nscdb))
				nscdb->gethash = nsc_db_int_key_gethash;
			else
				assert(0);
		} else {
			nscdb->gethash = gethash;
		}
	}

	(void) mutex_init(&nscdb->db_mutex, USYNC_THREAD, NULL);
	return (nscdb);

out:
	if (nscdb->htable)
		free(nscdb->htable);
	if (nscdb)
		free(nscdb);
	return (NULL);
}


/*
 * verify
 */
/* ARGSUSED */
nscd_rc_t
_nscd_cfg_cache_verify(
	void				*data,
	struct nscd_cfg_param_desc	*pdesc,
	nscd_cfg_id_t			*nswdb,
	nscd_cfg_flag_t			dflag,
	nscd_cfg_error_t		**errorp,
	void				**cookie)
{

	return (NSCD_SUCCESS);
}

/*
 * notify
 */
/* ARGSUSED */
nscd_rc_t
_nscd_cfg_cache_notify(
	void				*data,
	struct nscd_cfg_param_desc	*pdesc,
	nscd_cfg_id_t			*nswdb,
	nscd_cfg_flag_t			dflag,
	nscd_cfg_error_t		**errorp,
	void				**cookie)
{
	nsc_ctx_t	*ctx;
	void		*dp;
	int		i;

	/* group data */
	if (_nscd_cfg_flag_is_set(dflag, NSCD_CFG_DFLAG_GROUP)) {
		if (_nscd_cfg_flag_is_set(pdesc->pflag,
		    NSCD_CFG_PFLAG_GLOBAL)) {
			/* global config */
			global_cfg = *(nscd_cfg_global_cache_t *)data;
		} else if (_nscd_cfg_flag_is_set(dflag,
		    NSCD_CFG_DFLAG_SET_ALL_DB)) {
			/* non-global config for all dbs */
			for (i = 0; i < CACHE_CTX_COUNT; i++) {
				ctx = cache_ctx_p[i];
				if (ctx == NULL)
					return (NSCD_CTX_NOT_FOUND);
				(void) rw_wrlock(&ctx->cfg_rwlp);
				ctx->cfg = *(nscd_cfg_cache_t *)data;
				ctx->cfg_mtime = time(NULL);
				(void) rw_unlock(&ctx->cfg_rwlp);
			}
		} else {
			/* non-global config for a specific db */

			/* ignore non-caching databases */
			if (get_cache_ctx(nswdb->name, &ctx) != NSCD_SUCCESS)
				return (NSCD_SUCCESS);
			(void) rw_wrlock(&ctx->cfg_rwlp);
			ctx->cfg = *(nscd_cfg_cache_t *)data;
			ctx->cfg_mtime = time(NULL);
			(void) rw_unlock(&ctx->cfg_rwlp);
		}
		return (NSCD_SUCCESS);
	}

	/* individual data */
	if (_nscd_cfg_flag_is_set(pdesc->pflag, NSCD_CFG_PFLAG_GLOBAL)) {
		/* global config */
		dp = (char *)&global_cfg + pdesc->p_offset;
		(void) memcpy(dp, data, pdesc->p_size);
	} else if (_nscd_cfg_flag_is_set(dflag,
	    NSCD_CFG_DFLAG_SET_ALL_DB)) {
		/* non-global config for all dbs */
		for (i = 0; i < CACHE_CTX_COUNT; i++) {
			ctx = cache_ctx_p[i];
			if (ctx == NULL)
				return (NSCD_CTX_NOT_FOUND);
			dp = (char *)&ctx->cfg + pdesc->p_offset;
			(void) rw_wrlock(&ctx->cfg_rwlp);
			(void) memcpy(dp, data, pdesc->p_size);
			ctx->cfg_mtime = time(NULL);
			(void) rw_unlock(&ctx->cfg_rwlp);
		}
	} else {
		/* non-global config for a specific db */

		/* ignore non-caching databases */
		if (get_cache_ctx(nswdb->name, &ctx) != NSCD_SUCCESS)
			return (NSCD_SUCCESS);
		dp = (char *)&ctx->cfg + pdesc->p_offset;
		(void) rw_wrlock(&ctx->cfg_rwlp);
		(void) memcpy(dp, data, pdesc->p_size);
		ctx->cfg_mtime = time(NULL);
		(void) rw_unlock(&ctx->cfg_rwlp);
	}
	return (NSCD_SUCCESS);
}


/*
 * get stat
 */
/* ARGSUSED */
nscd_rc_t
_nscd_cfg_cache_get_stat(
	void				**stat,
	struct nscd_cfg_stat_desc	*sdesc,
	nscd_cfg_id_t			*nswdb,
	nscd_cfg_flag_t			*dflag,
	void				(**free_stat)(void *stat),
	nscd_cfg_error_t		**errorp)
{
	nscd_cfg_stat_cache_t	*statsp, stats;
	nsc_ctx_t		*ctx;
	int			i;
	nscd_rc_t		rc;

	statsp = calloc(1, sizeof (*statsp));
	if (statsp == NULL)
		return (NSCD_NO_MEMORY);

	if (_nscd_cfg_flag_is_set(sdesc->sflag, NSCD_CFG_SFLAG_GLOBAL)) {
		for (i = 0; i < CACHE_CTX_COUNT; i++) {
			if (cache_ctx_p[i] == NULL)
				stats = null_stats;
			else {
				(void) mutex_lock(&cache_ctx_p[i]->stats_mutex);
				stats = cache_ctx_p[i]->stats;
				(void) mutex_unlock(
				    &cache_ctx_p[i]->stats_mutex);
			}
			statsp->pos_hits += stats.pos_hits;
			statsp->neg_hits += stats.neg_hits;
			statsp->pos_misses += stats.pos_misses;
			statsp->neg_misses += stats.neg_misses;
			statsp->entries += stats.entries;
			statsp->drop_count += stats.drop_count;
			statsp->wait_count += stats.wait_count;
			statsp->invalidate_count +=
			    stats.invalidate_count;
		}
	} else {
		if ((rc = get_cache_ctx(nswdb->name, &ctx)) != NSCD_SUCCESS) {
			free(statsp);
			return (rc);
		}
		(void) mutex_lock(&ctx->stats_mutex);
		*statsp = ctx->stats;
		(void) mutex_unlock(&ctx->stats_mutex);
	}

	_NSC_GET_HITRATE(statsp);
	*stat = statsp;
	return (NSCD_SUCCESS);
}

/*
 * This function should only be called when nscd is
 * not a daemon.
 */
void
nsc_info(nsc_ctx_t *ctx, char *dbname, nscd_cfg_cache_t cfg[],
    nscd_cfg_stat_cache_t stats[])
{
	int		i;
	char		*me = "nsc_info";
	nsc_ctx_t	*ctx1;
	nsc_ctx_t	ctx2;
	nscd_rc_t	rc;

	if (ctx) {
		ctx_info(ctx);
		return;
	}

	if (dbname) {
		rc = get_cache_ctx(dbname, &ctx1);
		if (rc == NSCD_INVALID_ARGUMENT) {
			_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_WARNING)
			(me, "%s: no cache context found\n", dbname);
			return;
		} else if (rc == NSCD_NO_MEMORY) {
			_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_WARNING)
	(me, "%s: unable to create cache context - no memory\n",
	    dbname);
			return;
		}
		ctx_info(ctx1);
		return;
	}

	if (cfg == NULL || stats == NULL)
		return;

	for (i = 0; i < CACHE_CTX_COUNT; i++) {

		ctx2.dbname = cache_name[i];
		ctx2.cfg = cfg[i];
		ctx2.stats = stats[i];
		ctx_info_nolock(&ctx2);
	}
}

static void
ctx_info_nolock(nsc_ctx_t *ctx) {
	nscd_cfg_cache_t	cfg;
	nscd_cfg_stat_cache_t	stats;

	cfg = ctx->cfg;
	(void) fprintf(stdout, gettext("\n\nCACHE: %s\n"), ctx->dbname);
	(void) print_cfg(&cfg);

	if (cfg.enable == nscd_false)
		return;

	stats = ctx->stats;
	(void) print_stats(&stats);
}

static void
ctx_info(nsc_ctx_t *ctx) {
	nscd_cfg_cache_t	cfg;
	nscd_cfg_stat_cache_t	stats;

	(void) rw_rdlock(&ctx->cfg_rwlp);
	cfg = ctx->cfg;
	(void) rw_unlock(&ctx->cfg_rwlp);
	(void) fprintf(stdout, gettext("\n\nCACHE: %s\n"), ctx->dbname);
	(void) print_cfg(&cfg);

	if (cfg.enable == nscd_false)
		return;

	(void) mutex_lock(&ctx->stats_mutex);
	stats = ctx->stats;
	(void) mutex_unlock(&ctx->stats_mutex);
	(void) print_stats(&stats);
}

#ifdef	NSCD_DEBUG
/*
 * This function should only be called when nscd is
 * not a daemon.
 */
int
nsc_dump(char *dbname, int dbop)
{
	nsc_ctx_t	*ctx;
	nsc_db_t	*nscdb;
	nscd_bool_t	enabled;
	time_t		now;
	char		*me = "nsc_dump";
	int		i;

	if ((i = get_cache_idx(dbname)) == -1) {
		(void) fprintf(stdout, gettext("invalid cache name\n"));

		_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_WARNING)
		(me, "%s: invalid cache name\n", dbname);
		return (NSCD_CACHE_INVALID_CACHE_NAME);
	}

	if ((ctx = cache_ctx_p[i]) == NULL)  {
		(void) fprintf(stdout, gettext("no cache context\n"));

		_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_WARNING)
		(me, "%s: no cache context\n", dbname);
		return (NSCD_CACHE_NO_CACHE_CTX);
	}

	now = time(NULL);
	(void) rw_rdlock(&ctx->cfg_rwlp);
	enabled = ctx->cfg.enable;
	(void) rw_unlock(&ctx->cfg_rwlp);

	if (enabled == nscd_false)
		return (NSCD_CACHE_DISABLED);

	nscdb = nsc_get_db(ctx, dbop);
	if (nscdb == NULL) {
		_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_WARNING)
		(me, "%s:%d: no cache found\n", dbname, dbop);
		return (NSCD_CACHE_NO_CACHE_FOUND);
	}

	(void) mutex_lock(&nscdb->db_mutex);
	(void) queue_dump(nscdb, now);
	(void) hash_dump(nscdb, now);
	(void) avl_dump(nscdb, now);
	(void) mutex_unlock(&nscdb->db_mutex);
	return (NSCD_SUCCESS);
}
#endif	/* NSCD_DEBUG */

/*
 * These macros are for exclusive use of nsc_lookup
 */
#define	NSC_LOOKUP_LOG(loglevel, fmt) \
	_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_##loglevel) \
		(me, fmt, whoami);

static int
nsc_lookup_no_cache(nsc_lookup_args_t *largs, const char *str)
{
	char *me = "nsc_lookup_no_cache";
	nss_status_t status;

	_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_DEBUG)
		(me, "%s: name service lookup (bypassing cache)\n", str);
	nss_psearch(largs->buffer, largs->bufsize);
	status = NSCD_GET_STATUS(largs->buffer);
	_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_DEBUG)
		(me, "%s: name service lookup status = %d\n", str, status);
	if (status == NSS_SUCCESS) {
		return (SUCCESS);
	} else if (status == NSS_NOTFOUND) {
		return (NOTFOUND);
	} else {
		return (SERVERERROR);
	}
}

/*
 * This function starts the revalidation and reaper threads
 * for a cache
 */
static void
start_threads(nsc_ctx_t *ctx)
{
	int	errnum;
	char	*me = "start_threads";

	/*
	 *  kick off the revalidate thread (if necessary)
	 */
	if (ctx->revalidate_on != nscd_true) {
		if (thr_create(NULL, NULL, (void *(*)(void *))revalidate,
		    ctx, 0, NULL) != 0) {
			errnum = errno;
			_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_ERROR)
			(me, "thr_create (revalidate thread for %s): %s\n",
			    ctx->dbname, strerror(errnum));
			exit(1);
		}
		ctx->revalidate_on = nscd_true;
	}

	/*
	 *  kick off the reaper thread (if necessary)
	 */
	if (ctx->reaper_on != nscd_true) {
		if (thr_create(NULL, NULL, (void *(*)(void *))reaper,
		    ctx, 0, NULL) != 0) {
			errnum = errno;
			_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_ERROR)
			(me, "thr_create (reaper thread for %s): %s\n",
			    ctx->dbname, strerror(errnum));
			exit(1);
		}
		ctx->reaper_on = nscd_true;
	}
}

/*
 * Examine the packed buffer, see if the front-end parameters
 * indicate that the caller specified nsswitch config should be
 * used for the lookup. Return 1 if yes, otherwise 0.
 */
static int
nsw_config_in_phdr(void *buf)
{
	nss_pheader_t		*pbuf = (nss_pheader_t *)buf;
	nssuint_t		off;
	nss_dbd_t		*pdbd;
	char			*me = "nsw_config_in_phdr";

	off = pbuf->dbd_off;
	if (off == 0)
		return (0);
	pdbd = (nss_dbd_t *)((void *)((char *)pbuf + off));
	if (pdbd->o_default_config == 0)
		return (0);

	if ((enum nss_dbp_flags)pdbd->flags & NSS_USE_DEFAULT_CONFIG) {
		_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_DEBUG)
		(me, "use caller specified nsswitch config\n");
		return (1);
	} else
		return (0);
}

static nss_status_t
copy_result(void *rbuf, void *cbuf)
{
	nss_pheader_t	*rphdr = (nss_pheader_t *)rbuf;
	nss_pheader_t	*cphdr = (nss_pheader_t *)cbuf;
	char		*me = "copy_result";

	/* return NSS_ERROR if not enough room to copy result */
	if (cphdr->data_len + 1 > rphdr->data_len) {
		NSCD_SET_STATUS(rphdr, NSS_ERROR, ERANGE);
		return (NSS_ERROR);
	} else {
		char	*dst;

		if (cphdr->data_len == 0)
			return (NSS_SUCCESS);

		dst = (char *)rphdr + rphdr->data_off;
		(void) memcpy(dst, (char *)cphdr + cphdr->data_off,
		    cphdr->data_len);
		rphdr->data_len = cphdr->data_len;
		/* some frontend code expects a terminating NULL char */
		*(dst + rphdr->data_len) = '\0';

		_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_DEBUG)
		(me, "cache data (len = %lld): >>%s<<\n",
		    cphdr->data_len, (char *)cphdr + cphdr->data_off);

		return (NSS_SUCCESS);
	}
}

static int
get_dns_ttl(void *pbuf, char *dbname)
{
	nss_pheader_t	*phdr = (nss_pheader_t *)pbuf;
	int		ttl;
	char		*me = "get_dns_ttl";

	/* if returned, dns ttl is stored in the extended data area */
	if (phdr->ext_off == 0)
		return (-1);

	if (strcmp(dbname, NSS_DBNAM_HOSTS) != 0 &&
	    strcmp(dbname, NSS_DBNAM_IPNODES) != 0)
		return (-1);

	ttl = *(nssuint_t *)((void *)((char *)pbuf + phdr->ext_off));

	_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_DEBUG)
	(me, "dns ttl is %d seconds\n", ttl);

	return (ttl);
}

static int
check_config(nsc_lookup_args_t *largs, nscd_cfg_cache_t *cfgp,
    char *whoami, int flag)
{
	nsc_db_t	*nscdb;
	nsc_ctx_t	*ctx;
	char		*me = "check_config";

	ctx = largs->ctx;
	nscdb = largs->nscdb;

	/* see if the cached config needs update */
	if (nscdb->cfg_mtime != ctx->cfg_mtime) {
		(void) rw_rdlock(&ctx->cfg_rwlp);
		nscdb->cfg = ctx->cfg;
		nscdb->cfg_mtime = ctx->cfg_mtime;
		(void) rw_unlock(&ctx->cfg_rwlp);
		_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_DEBUG)
		(me, "config for context %s, database %s updated\n",
		    ctx->dbname, nscdb->name);
	}
	*cfgp = nscdb->cfg;

	if (cfgp->enable == nscd_false) {
		_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_DEBUG)
			(me, "%s: cache disabled\n", ctx->dbname);

		if (UPDATEBIT & flag)
			return (NOTFOUND);
		else
			return (nsc_lookup_no_cache(largs, whoami));
	}

	/*
	 * if caller requests lookup using its
	 * own nsswitch config, bypass cache
	 */
	if (nsw_config_in_phdr(largs->buffer))
		return (nsc_lookup_no_cache(largs, whoami));

	/* no need of cache if we are dealing with 0 ttls */
	if (cfgp->pos_ttl <= 0 && cfgp->neg_ttl <= 0) {
		if (flag & UPDATEBIT)
			return (NOTFOUND);
		else if (cfgp->avoid_ns == nscd_true)
			return (SERVERERROR);
		return (nsc_lookup_no_cache(largs, whoami));
	}

	return (CONTINUE);
}

/*
 * Invalidate cache if database file has been modified.
 * See check_files config param for details.
 */
static void
check_db_file(nsc_ctx_t *ctx, nscd_cfg_cache_t cfg,
    char *whoami, time_t now)
{
	struct stat	buf;
	nscd_bool_t	file_modified = nscd_false;
	char		*me = "check_db_file";

	if (cfg.check_interval != 0 &&
	    (now - ctx->file_chktime) < cfg.check_interval)
		return;

	ctx->file_chktime = now;
	if (stat(ctx->file_name, &buf) == 0) {
		if (ctx->file_mtime == 0) {
			(void) mutex_lock(&ctx->file_mutex);
			if (ctx->file_mtime == 0) {
				ctx->file_mtime = buf.st_mtime;
				ctx->file_size = buf.st_size;
				ctx->file_ino = buf.st_ino;
			}
			(void) mutex_unlock(&ctx->file_mutex);
		} else if (ctx->file_mtime < buf.st_mtime ||
		    ctx->file_size != buf.st_size ||
		    ctx->file_ino != buf.st_ino) {
			(void) mutex_lock(&ctx->file_mutex);
			if (ctx->file_mtime < buf.st_mtime ||
			    ctx->file_size != buf.st_size ||
			    ctx->file_ino != buf.st_ino) {
				file_modified = nscd_true;
				ctx->file_mtime = buf.st_mtime;
				ctx->file_size = buf.st_size;
				ctx->file_ino = buf.st_ino;
			}
			(void) mutex_unlock(&ctx->file_mutex);
		}
	}

	if (file_modified == nscd_true) {
		_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_DEBUG)
		(me, "%s: file %s has been modified - invalidating cache\n",
		    whoami, ctx->file_name);
		ctx_invalidate(ctx);
	}
}

static int
lookup_int(nsc_lookup_args_t *largs, int flag)
{
	nsc_ctx_t		*ctx;
	nsc_db_t		*nscdb;
	nscd_cfg_cache_t	cfg;
	nsc_entry_t		*this_entry;
	nsc_entry_stat_t	*this_stats;
	nsc_action_t		next_action;
	nss_status_t		status;
	nscd_bool_t		delete;
	nscd_rc_t		rc;
	char			*dbname;
	int			dbop, errnum;
	int			cfg_rc;
	nss_XbyY_args_t		args;
	char			whoami[128];
	time_t			now = time(NULL); /* current time */
	char			*me = "lookup_int";

	/* extract dbop, dbname, key and cred */
	status = nss_packed_getkey(largs->buffer, largs->bufsize, &dbname,
	    &dbop, &args);
	if (status != NSS_SUCCESS) {
		_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_ERROR)
			(me, "nss_packed_getkey failure (%d)\n", status);
		return (SERVERERROR);
	}

	/* get the cache context */
	if (largs->ctx == NULL) {
		if (get_cache_ctx(dbname, &largs->ctx) != NSCD_SUCCESS) {
			_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_WARNING)
				(me, "%s: no cache context found\n", dbname);

			if (UPDATEBIT & flag)
				return (NOTFOUND);
			else
				return (nsc_lookup_no_cache(largs, dbname));
		}
	}
	ctx = largs->ctx;

	if (largs->nscdb == NULL) {
		if ((largs->nscdb = nsc_get_db(ctx, dbop)) == NULL) {
			_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_WARNING)
				(me, "%s:%d: no cache found\n",
				    dbname, dbop);

			if (UPDATEBIT & flag)
				return (NOTFOUND);
			else
				return (nsc_lookup_no_cache(largs, dbname));
		}
	}

	nscdb = largs->nscdb;

	_NSCD_LOG_IF(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_ALL) {
		(void) nscdb->getlogstr(nscdb->name, whoami,
		    sizeof (whoami), &args);
	}

	if (UPDATEBIT & flag) {
		_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_DEBUG)
			(me, "%s: refresh start\n", whoami);
	} else {
		_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_DEBUG)
			(me, "%s: lookup start\n", whoami);
	}

	cfg_rc = check_config(largs, &cfg, whoami, flag);
	if (cfg_rc != CONTINUE)
		return (cfg_rc);

	/*
	 * Invalidate cache if file has been modified.
	 */
	if (cfg.check_files == nscd_true)
		check_db_file(ctx, cfg, whoami, now);

	(void) mutex_lock(&nscdb->db_mutex);

	/* Lookup the cache table */
	for (;;) {
		delete = nscd_false;
		rc = lookup_cache(largs, &cfg, &args, whoami, &this_entry);
		if (rc != NSCD_SUCCESS) {
			(void) mutex_unlock(&nscdb->db_mutex);

			/* Either no entry and avoid name service */
			if (rc == NSCD_DB_ENTRY_NOT_FOUND ||
			    rc == NSCD_INVALID_ARGUMENT)
				return (NOTFOUND);

			/* OR memory error */
			return (SERVERERROR);
		}

		/* get the stats from the entry */
		this_stats = &this_entry->stats;

		/*
		 * What should we do next ?
		 */
		switch (this_stats->status) {
		case ST_NEW_ENTRY:
			delete = nscd_true;
			next_action = _NSC_NSLOOKUP;
			break;
		case ST_UPDATE_PENDING:
			if (flag & UPDATEBIT) {
				(void) mutex_unlock(&nscdb->db_mutex);
				return (NOTFOUND);
			} else if (this_stats->timestamp < now)
				next_action = _NSC_WAIT;
			else
				next_action = _NSC_USECACHED;
			break;
		case ST_LOOKUP_PENDING:
			if (flag & UPDATEBIT) {
				(void) mutex_unlock(&nscdb->db_mutex);
				return (NOTFOUND);
			}
			next_action = _NSC_WAIT;
			break;
		case ST_DISCARD:
			if (cfg.avoid_ns == nscd_true) {
				(void) mutex_unlock(&nscdb->db_mutex);
				return (NOTFOUND);
			}
			/* otherwise reuse the entry */
			(void) memset(this_stats, 0, sizeof (*this_stats));
			next_action = _NSC_NSLOOKUP;
			break;
		default:
			if (cfg.avoid_ns == nscd_true)
				next_action = _NSC_USECACHED;
			else if ((flag & UPDATEBIT) ||
			    (this_stats->timestamp < now)) {
				_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_DEBUG)
			(me, "%s: cached entry needs to be updated\n",
			    whoami);
				next_action = _NSC_NSLOOKUP;
			} else
				next_action = _NSC_USECACHED;
			break;
		}

		if (next_action == _NSC_WAIT) {
			_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_DEBUG)
			(me, "%s: need to wait\n", whoami);

			/* do we have clearance ? */
			if (_nscd_get_clearance(&ctx->throttle_sema) != 0) {
				/* nope. quit */
				(void) mutex_lock(&ctx->stats_mutex);
				ctx->stats.drop_count++;
				(void) mutex_unlock(&ctx->stats_mutex);
				_NSCD_LOG(NSCD_LOG_CACHE,
				    NSCD_LOG_LEVEL_DEBUG_6)
				(me, "%s: throttling load\n", whoami);
				(void) mutex_unlock(&nscdb->db_mutex);
				NSC_LOOKUP_LOG(WARNING,
				    "%s: no clearance to wait\n");
				return (NOSERVER);
			}
			/* yes can wait */
			(void) nscd_wait(ctx, nscdb, this_entry);
			(void) _nscd_release_clearance(&ctx->throttle_sema);
			continue;
		}

		break;
	}


	if (!(UPDATEBIT & flag))
		this_stats->hits++;		/* update hit count */

	if (next_action == _NSC_NSLOOKUP) {

		_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_DEBUG)
		(me, "%s: name service lookup required\n", whoami);

		if (_nscd_get_clearance(&ctx->throttle_sema) != 0) {
			if (delete == nscd_true)
				delete_entry(nscdb, ctx, this_entry);
			else
				this_stats->status = ST_DISCARD;
			(void) mutex_lock(&ctx->stats_mutex);
			ctx->stats.drop_count++;
			(void) mutex_unlock(&ctx->stats_mutex);
			(void) mutex_unlock(&nscdb->db_mutex);
			NSC_LOOKUP_LOG(WARNING,
			    "%s: no clearance for lookup\n");
			return (NOSERVER);
		}

		/* block any threads accessing this entry */
		this_stats->status = (flag & UPDATEBIT) ?
		    ST_UPDATE_PENDING : ST_LOOKUP_PENDING;

		/* release lock and do name service lookup */
		(void) mutex_unlock(&nscdb->db_mutex);
		nss_psearch(largs->buffer, largs->bufsize);
		status = NSCD_GET_STATUS(largs->buffer);
		(void) mutex_lock(&nscdb->db_mutex);
		this_stats->status = 0;
		(void) _nscd_release_clearance(&ctx->throttle_sema);

		/* signal waiting threads */
		(void) nscd_signal(ctx, nscdb, this_entry);

		_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_DEBUG)
		(me, "%s: name service lookup status = %d\n",
		    whoami, status);

		if (status == NSS_SUCCESS) {
			int ttl;

			/*
			 * data found in name service
			 * update cache
			 */
			status = dup_packed_buffer(largs, this_entry);
			if (status != NSS_SUCCESS) {
				delete_entry(nscdb, ctx, this_entry);
				(void) mutex_unlock(&nscdb->db_mutex);
				NSC_LOOKUP_LOG(ERROR,
				    "%s: failed to update cache\n");
				return (SERVERERROR);
			}

			/*
			 * store unpacked key in cache
			 */
			status = nss_packed_getkey(this_entry->buffer,
			    this_entry->bufsize,
			    &dbname, &dbop, &args);
			if (status != NSS_SUCCESS) {
				delete_entry(nscdb, ctx, this_entry);
				(void) mutex_unlock(&nscdb->db_mutex);
				NSC_LOOKUP_LOG(ERROR,
				    "%s: failed to extract key\n");
				return (SERVERERROR);
			}
			this_entry->key = args.key; /* struct copy */

			/* update +ve miss count */
			if (!(UPDATEBIT & flag)) {
				(void) mutex_lock(&ctx->stats_mutex);
				ctx->stats.pos_misses++;
				(void) mutex_unlock(&ctx->stats_mutex);
			}

			/* update +ve ttl */
			ttl = get_dns_ttl(largs->buffer, dbname);
			/* honor the dns ttl less than postive ttl */
			if (ttl < 0 || ttl > cfg.pos_ttl)
				ttl = cfg.pos_ttl;
			this_stats->timestamp = time(NULL) + ttl;

			/*
			 * start the revalidation and reaper threads
			 * if not already started
			 */
			start_threads(ctx);

			(void) mutex_unlock(&nscdb->db_mutex);
			NSC_LOOKUP_LOG(DEBUG,
			    "%s: cache updated with positive entry\n");
			return (SUCCESS);
		} else if (status == NSS_NOTFOUND) {
			/*
			 * data not found in name service
			 * update cache
			 */
			_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_DEBUG_6)
			(me, "%s: name service lookup failed\n", whoami);

			if (NSCD_GET_ERRNO(largs->buffer) == ERANGE) {
				delete_entry(nscdb, ctx, this_entry);
				(void) mutex_unlock(&nscdb->db_mutex);
				NSC_LOOKUP_LOG(DEBUG,
				    "%s: ERANGE, cache not updated "
				    "with negative entry\n");
				return (NOTFOUND);
			}

			status = dup_packed_buffer(largs, this_entry);
			if (status != NSS_SUCCESS) {
				delete_entry(nscdb, ctx, this_entry);
				(void) mutex_unlock(&nscdb->db_mutex);
				NSC_LOOKUP_LOG(ERROR,
				    "%s: failed to update cache\n");
				return (SERVERERROR);
			}

			/* store unpacked key in cache */
			status = nss_packed_getkey(this_entry->buffer,
			    this_entry->bufsize,
			    &dbname, &dbop, &args);
			if (status != NSS_SUCCESS) {
				delete_entry(nscdb, ctx, this_entry);
				(void) mutex_unlock(&nscdb->db_mutex);
				NSC_LOOKUP_LOG(ERROR,
				    "%s: failed to extract key\n");
				return (SERVERERROR);
			}
			this_entry->key = args.key; /* struct copy */

			/* update -ve ttl */
			this_stats->timestamp = time(NULL) + cfg.neg_ttl;

			/* update -ve miss count */
			if (!(UPDATEBIT & flag)) {
				(void) mutex_lock(&ctx->stats_mutex);
				ctx->stats.neg_misses++;
				(void) mutex_unlock(&ctx->stats_mutex);
			}

			/*
			 * start the revalidation and reaper threads
			 * if not already started
			 */
			start_threads(ctx);

			(void) mutex_unlock(&nscdb->db_mutex);
			NSC_LOOKUP_LOG(DEBUG,
			    "%s: cache updated with negative entry\n");
			return (NOTFOUND);
		} else {
			/*
			 * name service lookup failed
			 */
			_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_DEBUG_6)
			(me, "%s: name service lookup failed\n", whoami);

			errnum = NSCD_GET_ERRNO(largs->buffer);
			if (delete == nscd_true)
				delete_entry(nscdb, ctx, this_entry);
			else
				this_stats->status = ST_DISCARD;

			(void) mutex_unlock(&nscdb->db_mutex);
			_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_WARNING)
			(me, "%s: name service lookup failed "
			    "(status=%d, errno=%d)\n",
			    whoami, status, errnum);

			return (SERVERERROR);
		}
	} else if (next_action == _NSC_USECACHED) {
		/*
		 * found entry in cache
		 */
		if (UPDATEBIT & flag) {
			(void) mutex_unlock(&nscdb->db_mutex);
			NSC_LOOKUP_LOG(DEBUG, "%s: no need to update\n");
			return (SUCCESS);
		}

		if (NSCD_GET_STATUS((nss_pheader_t *)this_entry->buffer) ==
		    NSS_SUCCESS) {
			/* positive hit */
			(void) mutex_lock(&ctx->stats_mutex);
			ctx->stats.pos_hits++;
			(void) mutex_unlock(&ctx->stats_mutex);

			/* update response buffer */
			if (copy_result(largs->buffer,
			    this_entry->buffer) != NSS_SUCCESS) {
				(void) mutex_unlock(&nscdb->db_mutex);
				NSC_LOOKUP_LOG(ERROR,
				    "%s: response buffer insufficient\n");
				return (SERVERERROR);
			}

			(void) mutex_unlock(&nscdb->db_mutex);
			NSC_LOOKUP_LOG(DEBUG,
			    "%s: positive entry in cache\n");
			return (SUCCESS);
		} else {
			/* negative hit */
			(void) mutex_lock(&ctx->stats_mutex);
			ctx->stats.neg_hits++;
			(void) mutex_unlock(&ctx->stats_mutex);

			NSCD_SET_STATUS((nss_pheader_t *)largs->buffer,
			    NSCD_GET_STATUS(this_entry->buffer),
			    NSCD_GET_ERRNO(this_entry->buffer));
			NSCD_SET_HERRNO((nss_pheader_t *)largs->buffer,
			    NSCD_GET_HERRNO(this_entry->buffer));

			(void) mutex_unlock(&nscdb->db_mutex);
			NSC_LOOKUP_LOG(DEBUG,
			    "%s: negative entry in cache\n");
			return (NOTFOUND);
		}
	}

	(void) mutex_unlock(&nscdb->db_mutex);
	NSC_LOOKUP_LOG(ERROR, "%s: cache backend failure\n");
	return (SERVERERROR);
}

/*
 * NSCD cache backend lookup function
 */
/*ARGSUSED*/
void
nsc_lookup(nsc_lookup_args_t *largs, int flag) {

	nss_pheader_t	*phdr = (nss_pheader_t *)largs->buffer;
	int		rc;

	rc = lookup_int(largs, 0);

	if (NSCD_GET_STATUS(phdr) == NSS_TRYLOCAL)
		return;

	switch (rc) {

	case SUCCESS:
		NSCD_SET_STATUS(phdr, NSS_SUCCESS, 0);
		break;

	case NOTFOUND:
		NSCD_SET_STATUS(phdr, NSS_NOTFOUND, -1);
		break;

	case SERVERERROR:
		/*
		 * status and errno should have been set in the phdr,
		 * if not, set status to NSS_ERROR
		 */
		if (NSCD_STATUS_IS_OK(phdr)) {
			NSCD_SET_STATUS(phdr, NSS_ERROR, 0);
		}
		break;

	case NOSERVER:
		NSCD_SET_STATUS(phdr, NSS_TRYLOCAL, -1);
		break;
	}
}


static nsc_ctx_t *
init_cache_ctx(int i) {
	nsc_ctx_t	*ctx;

	ctx = calloc(1, sizeof (nsc_ctx_t));
	if (ctx == NULL)
		return (NULL);

	/* init locks and semaphores */
	(void) mutex_init(&ctx->file_mutex, USYNC_THREAD, NULL);
	(void) rwlock_init(&ctx->cfg_rwlp, USYNC_THREAD, NULL);
	(void) mutex_init(&ctx->stats_mutex, USYNC_THREAD, NULL);
	(void) _nscd_init_cache_sema(&ctx->throttle_sema, cache_name[i]);
	cache_init_ctx[i](ctx);
	cache_ctx_p[i] = ctx;

	return (ctx);
}


static void
revalidate(nsc_ctx_t *ctx)
{
	for (;;) {
		int 		i, slp, interval, count;

		(void) rw_rdlock(&ctx->cfg_rwlp);
		slp = ctx->cfg.pos_ttl;
		count = ctx->cfg.keephot;
		(void) rw_unlock(&ctx->cfg_rwlp);

		if (slp < 60)
			slp = 60;
		if (count != 0) {
			interval = (slp/2)/count;
			if (interval == 0)
				interval = 1;
			(void) sleep(slp*2/3);
			for (i = 0; i < ctx->db_count; i++) {
				getxy_keepalive(ctx, ctx->nsc_db[i],
				    count, interval);
			}
		} else {
			(void) sleep(slp);
		}
	}
}


static void
getxy_keepalive(nsc_ctx_t *ctx, nsc_db_t *nscdb, int keep, int interval)
{
	nsc_keephot_t		*table;
	nsc_entry_t		*entry, *ptr;
	int			i;
	nsc_lookup_args_t	*largs;
	nss_pheader_t		*phdr;
	int			bufsiz;
	char			*me = "getxy_keepalive";

	/* we won't be here if keep == 0 so need to check that */

	_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_DEBUG)
	(me, "%s: keep alive\n", nscdb->name);

	if ((table = maken(keep)) == NULL) {
		_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_ERROR)
			(me, "memory allocation failure\n");
		exit(1);
	}

	(void) mutex_lock(&nscdb->db_mutex);
	entry = nscdb->qtail;
	while (entry != NULL) {
		/* leave pending calls alone */
		if (!(entry->stats.status & ST_PENDING)) {
			/* do_revalidate */
			(void) insertn(table, entry->stats.hits, entry);
		}
		entry = entry->qnext;
	}
	for (i = 1; i <= keep; i++) {
		if (table[i].ptr == NULL)
			continue;
		ptr = (nsc_entry_t *)table[i].ptr;
		phdr = (nss_pheader_t *)ptr->buffer;
		if (NSCD_GET_STATUS(phdr) == NSS_SUCCESS)
			/*
			 * for positive cache, in addition to the packed
			 * header size, allocate twice the size of the
			 * existing result (in case the result grows
			 * larger) plus 2K (for the file/compat backend to
			 * process a possible large entry in the /etc files)
			 */
			bufsiz = phdr->data_off + 2 * phdr->data_len + 2048;
		else
			/*
			 * for negative cache, allocate 8K buffer to
			 * hold result in case the next lookup may
			 * return something (in addition to the
			 * packed header size)
			 */
			bufsiz = phdr->data_off + 8096;
		table[i].ptr = malloc(bufsiz);
		if (table[i].ptr == NULL) {
			(void) mutex_unlock(&nscdb->db_mutex);
			_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_ERROR)
				(me, "memory allocation failure\n");
			exit(1);
		}
		(void) memcpy(table[i].ptr, ptr->buffer,  ptr->bufsize);
		((nss_pheader_t *)table[i].ptr)->pbufsiz = bufsiz;
		table[i].num = bufsiz;
	}
	(void) mutex_unlock(&nscdb->db_mutex);

	/* launch update thread for each keep hot entry */
	for (i = keep; i > 0; i--) {
		if (table[i].ptr == NULL)
			continue; /* unused slot in table */
		_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_DEBUG)
		(me, "%s: launching update\n", nscdb->name);
		largs = (nsc_lookup_args_t *)malloc(sizeof (*largs));
		if (largs == NULL) {
			_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_ERROR)
				(me, "memory allocation failure\n");
			exit(1);
		}
		largs->buffer = table[i].ptr;
		largs->bufsize = table[i].num;
		largs->ctx = ctx;
		largs->nscdb = nscdb;
		if (launch_update(largs) < 0)
			exit(1);
		(void) sleep(interval);
	}

	/*
	 * The update thread will handle freeing of buffer and largs.
	 * Free the table here.
	 */
	free(table);
}


static int
launch_update(nsc_lookup_args_t *in)
{
	char	*me = "launch_update";
	int	errnum;

	errnum = thr_create(NULL, NULL, (void *(*)(void*))do_update,
	    in, 0|THR_DETACHED, NULL);
	if (errnum != 0) {
		_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_ERROR)
		(me, "%s: thread creation failure (%d)\n",
		    in->nscdb->name, errnum);
		return (-1);
	}
	return (0);
}


static void
do_update(nsc_lookup_args_t *in) {
	nss_pheader_t	*phdr = (nss_pheader_t *)in->buffer;

	/* update the length of the data buffer */
	phdr->data_len = phdr->pbufsiz - phdr->data_off;

	(void) lookup_int(in, UPDATEBIT);
	if (in->buffer)
		free(in->buffer);
	free(in);
}


/*
 * Invalidate cache
 */
void
nsc_invalidate(nsc_ctx_t *ctx, char *dbname, nsc_ctx_t **ctxs)
{
	int	i;
	char	*me = "nsc_invalidate";

	if (ctx) {
		ctx_invalidate(ctx);
		return;
	}

	if (dbname) {
		if ((i = get_cache_idx(dbname)) == -1) {
			_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_WARNING)
			(me, "%s: invalid cache name\n", dbname);
			return;
		}
		if ((ctx = cache_ctx_p[i]) == NULL)  {
			_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_WARNING)
			(me, "%s: no cache context found\n",
			    dbname);
			return;
		}
		ctx_invalidate(ctx);
		return;
	}

	if (ctxs == NULL)
		ctxs =  cache_ctx_p;

	for (i = 0; i < CACHE_CTX_COUNT; i++) {
		if (ctxs[i] != NULL)
		ctx_invalidate(ctxs[i]);
	}
}


/*
 * Invalidate cache by context
 */
static void
ctx_invalidate(nsc_ctx_t *ctx)
{
	int 		i;
	nsc_entry_t	*entry;
	char		*me = "ctx_invalidate";

	_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_DEBUG)
	(me, "%s: invalidate cache\n", ctx->dbname);

	for (i = 0; i < ctx->db_count; i++) {
		if (ctx->nsc_db[i] == NULL)
			continue;
		(void) mutex_lock(&ctx->nsc_db[i]->db_mutex);
		entry = ctx->nsc_db[i]->qtail;
		while (entry != NULL) {
			/* leave pending calls alone */
			if (!(entry->stats.status & ST_PENDING))
				entry->stats.status = ST_DISCARD;
			entry = entry->qnext;
		}
		(void) mutex_unlock(&ctx->nsc_db[i]->db_mutex);
	}

	(void) mutex_lock(&ctx->stats_mutex);
	ctx->stats.invalidate_count++;
	(void) mutex_unlock(&ctx->stats_mutex);
}


/*
 * Free nsc_entry_t
 *
 * Pre-reqs:
 * nscdb->db_mutex lock must be held before calling this function
 */
static void
delete_entry(nsc_db_t *nscdb, nsc_ctx_t *ctx, nsc_entry_t *entry) {
	uint_t		hash;

	avl_remove(&nscdb->tree, entry);
	HASH_REMOVE(nscdb, entry, hash, nscd_false);
	queue_remove(nscdb, entry);
	if (entry->buffer != NULL) {
		free(entry->buffer);
		entry->buffer = NULL;
	}
	umem_cache_free(nsc_entry_cache, entry);
	(void) mutex_lock(&ctx->stats_mutex);
	ctx->stats.entries--;
	(void) mutex_unlock(&ctx->stats_mutex);
}


static nscd_rc_t
lookup_cache(nsc_lookup_args_t *largs, nscd_cfg_cache_t *cfgp,
    nss_XbyY_args_t *argp, char *whoami, nsc_entry_t **entry)
{
	nsc_db_t	*nscdb;
	nsc_ctx_t	*ctx;
	uint_t		hash;
	avl_index_t	pos;
	ulong_t		nentries;
	nsc_entry_t	find_entry, *node;
	char		*me = "lookup_cache";

	ctx = largs->ctx;
	nscdb = largs->nscdb;

	/* set the search key */
	find_entry.key = argp->key;	/* struct copy (not deep) */

	/* lookup the hash table ==> O(1) */
	if (nscdb->htable) {
		*entry = hash_find(nscdb, &find_entry, &hash, nscd_true);
		if (*entry != NULL) {
			(void) queue_adjust(nscdb, *entry);
			return (NSCD_SUCCESS);
		}
	}

	/* if not found, lookup the AVL tree ==> O(log n) */
	*entry = (nsc_entry_t *)avl_find(&nscdb->tree, &find_entry, &pos);
	if (*entry != NULL) {
		(void) queue_adjust(nscdb, *entry);
		/* move it to the hash table */
		if (nscdb->htable) {
			if (nscdb->htable[hash] == NULL ||
			    (*entry)->stats.hits >=
			    nscdb->htable[hash]->stats.hits) {
				nscdb->htable[hash] = *entry;
			}
		}
		return (NSCD_SUCCESS);
	}

	/* entry not found in the cache */
	_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_DEBUG)
		(me, "%s: cache miss\n", whoami);

	if (cfgp->avoid_ns == nscd_true) {
		_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_DEBUG)
			(me, "%s: avoid name service\n", whoami);
		return (NSCD_DB_ENTRY_NOT_FOUND);
	}

	/* allocate memory for new entry (stub) */
	*entry = (nsc_entry_t *)umem_cache_alloc(nsc_entry_cache,
	    UMEM_DEFAULT);
	if (*entry == NULL) {
		_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_ERROR)
			(me, "%s: memory allocation failure\n", whoami);
		return (NSCD_NO_MEMORY);
	}
	(void) memset(*entry, 0, sizeof (**entry));

	/*
	 * Note that the actual data for the key is stored within
	 * the largs->buffer (input buffer to nsc_lookup).
	 * find_entry.key only contains pointers to this data.
	 *
	 * If largs->buffer will be re-allocated by nss_psearch
	 * then (*entry)->key will have dangling pointers.
	 * In such case, the following assignment needs to be
	 * replaced by code that duplicates the key.
	 */
	(*entry)->key = find_entry.key;

	/*
	 * Add the entry to the cache.
	 */
	avl_insert(&nscdb->tree, *entry, pos);	/* O(log n) */
	(void) queue_adjust(nscdb, *entry);	/* constant */
	if (nscdb->htable)			/* constant */
		nscdb->htable[hash] = *entry;
	(*entry)->stats.status = ST_NEW_ENTRY;

	(void) mutex_lock(&ctx->stats_mutex);
	nentries = ++(ctx->stats.entries);
	(void) mutex_unlock(&ctx->stats_mutex);

	/* Have we exceeded max entries ? */
	if (cfgp->maxentries > 0 && nentries > cfgp->maxentries) {
		_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_DEBUG)
			(me, "%s: maximum entries exceeded -- "
			    "deleting least recently used entry\n",
			    whoami);

		node = nscdb->qhead;
		while (node != NULL && node != *entry) {
			if (node->stats.status == ST_DISCARD ||
			    !(node->stats.status & ST_PENDING)) {
				delete_entry(nscdb, ctx, node);
				break;
			}
			node = node->qprev;
		}

		/*
		 * It's okay if we were not able to find one to delete.
		 * The reaper (when invoked) will return the cache to a
		 * safe level.
		 */
	}

	return (NSCD_SUCCESS);
}

static void
reaper(nsc_ctx_t *ctx)
{
	uint_t		ttl, extra_sleep, total_sleep, intervals;
	uint_t		nodes_per_interval, seconds_per_interval;
	ulong_t		nsc_entries;
	char		*me = "reaper";

	for (;;) {
		(void) mutex_lock(&ctx->stats_mutex);
		nsc_entries = ctx->stats.entries;
		(void) mutex_unlock(&ctx->stats_mutex);

		(void) rw_rdlock(&ctx->cfg_rwlp);
		ttl = ctx->cfg.pos_ttl;
		(void) rw_unlock(&ctx->cfg_rwlp);

		if (nsc_entries == 0) {
			_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_DEBUG)
				(me, "%s: nothing to reap\n", ctx->dbname);

			/* sleep for atleast 60 seconds */
			if (ttl < 60)
				ttl = 60;
			_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_DEBUG)
			(me, "%s: sleep %d\n", ctx->dbname, ttl);
			(void) sleep(ttl);
			continue;
		}

		if (ttl < 32) ttl = 32;
		if (ttl > (1<<28)) ttl = 1<<28;

		/*
		 * minimum nodes_per_interval = 256 or 1<<8
		 * maximum nodes_per_interval = nsc_entries
		 * minimum seconds_per_interval = 32 or 1<<5
		 * maximum_seconds_per_interval = ttl
		 */
		if (nsc_entries <= ttl) {
			intervals = (nsc_entries >> 8) + 1;
			seconds_per_interval = ttl / intervals;
			nodes_per_interval = 256;
		} else {
			intervals = (ttl >> 5) + 1;
			seconds_per_interval = 32;
			nodes_per_interval = nsc_entries / intervals;
			if (nodes_per_interval < 256)
				nodes_per_interval = 256;
		}

		_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_DEBUG)
			(me, "%s: total entries = %d, "
			    "seconds per interval = %d, "
			    "nodes per interval = %d\n",
			    ctx->dbname, nsc_entries, seconds_per_interval,
			    nodes_per_interval);
		total_sleep = reap_cache(ctx, nodes_per_interval,
		    seconds_per_interval);
		extra_sleep = 1 + ttl - total_sleep;
		if (extra_sleep > 0)
			(void) sleep(extra_sleep);
	}
}


static uint_t
reap_cache(nsc_ctx_t *ctx, uint_t nodes_per_interval,
    uint_t seconds_per_interval)
{
	uint_t		nodes_togo, total_sleep;
	time_t		now;
	nsc_entry_t	*node, *next_node;
	nsc_db_t	*nscdb;
	uint_t		primes[] = {_NSC_HTSIZE_PRIMES};
	ulong_t		count, nentries, maxentries;
	int		i, slot, value, newhtsize;
	char		*me = "reap_cache";

	count = 0;
	total_sleep = 0;
	nodes_togo = nodes_per_interval;
	now = time(NULL);

	for (i = 0; i < ctx->db_count; i++) {
		nscdb = ctx->nsc_db[i];
		(void) mutex_lock(&nscdb->db_mutex);
		nscdb->reap_node = nscdb->qtail;
		while (nscdb->reap_node != NULL) {
			if (nodes_togo == 0) {
				(void) mutex_unlock(&nscdb->db_mutex);
				(void) sleep(seconds_per_interval);
				total_sleep += seconds_per_interval;
				nodes_togo = nodes_per_interval;
				now = time(NULL);
				(void) mutex_lock(&nscdb->db_mutex);
			}
			/* delete ST_DISCARD and expired nodes */
			if ((node = nscdb->reap_node) == NULL)
				break;
			if (node->stats.status == ST_DISCARD ||
			    (!(node->stats.status & ST_PENDING) &&
			    node->stats.timestamp < now)) {
				/*
				 * Delete entry if its discard flag is
				 * set OR if it has expired. Entries
				 * with pending updates are not
				 * deleted.
				 * nscdb->reap_node will be adjusted
				 * by delete_entry()
				 */
				delete_entry(nscdb, ctx, node);
				count++;
			} else {
				nscdb->reap_node = node->qnext;
			}
			nodes_togo--;
		}

		if (nscdb->htsize == 0) {
			(void) mutex_unlock(&nscdb->db_mutex);
			continue;
		}

		/*
		 * Dynamic adjustment of hash table size.
		 *
		 * Hash table size is roughly 1/8th of the
		 * total entries. However the size is changed
		 * only when the number of entries double or
		 * reduced by half
		 */
		nentries = avl_numnodes(&nscdb->tree);
		for (slot = 0, value = _NSC_INIT_HTSIZE_SLOT_VALUE;
		    slot < _NSC_HTSIZE_NUM_SLOTS && nentries > value;
		    value = (value << 1) + 1, slot++)
			;
		if (nscdb->hash_type == nsc_ht_power2)
			newhtsize = _NSC_INIT_HTSIZE_POWER2 << slot;
		else
			newhtsize = primes[slot];

		/* Recommended size is same as the current size. Done */
		if (nscdb->htsize == newhtsize) {
			(void) mutex_unlock(&nscdb->db_mutex);
			continue;
		}

		_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_DEBUG)
			(me, "%s: resizing hash table from %d to %d\n",
			    nscdb->name, nscdb->htsize, newhtsize);

		/*
		 * Dump old hashes because it would be time
		 * consuming to rehash them.
		 */
		(void) free(nscdb->htable);
		nscdb->htable = calloc(newhtsize, sizeof (*(nscdb->htable)));
		if (nscdb->htable == NULL) {
			_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_ERROR)
				(me, "%s: memory allocation failure\n",
				    nscdb->name);
			/* -1 to try later */
			nscdb->htsize = -1;
		} else {
			nscdb->htsize = newhtsize;
		}
		(void) mutex_unlock(&nscdb->db_mutex);
	}

	_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_DEBUG)
		(me, "%s: reaped %lu entries\n", ctx->dbname, count);

	/*
	 * if cache is almost full then reduce it to a safe level by
	 * evicting LRU entries
	 */

	(void) rw_rdlock(&ctx->cfg_rwlp);
	maxentries = ctx->cfg.maxentries;
	(void) rw_unlock(&ctx->cfg_rwlp);

	/* No limit on number of entries. Done */
	if (maxentries == 0)
		goto out;

	(void) mutex_lock(&ctx->stats_mutex);
	nentries = ctx->stats.entries;
	(void) mutex_unlock(&ctx->stats_mutex);

	/* what is the percentage of cache used ? */
	value = (nentries * 100) / maxentries;
	if (value < _NSC_EVICTION_START_LEVEL)
		goto out;

	/*
	 * cache needs to be reduced to a safe level
	 */
	value -= _NSC_EVICTION_SAFE_LEVEL;
	for (i = 0, count = 0; i < ctx->db_count; i++) {
		/*
		 * Reduce each subcache by 'value' percent
		 */
		nscdb = ctx->nsc_db[i];
		(void) mutex_lock(&nscdb->db_mutex);
		nodes_togo = (value * avl_numnodes(&nscdb->tree)) / 100;

		/* Start from LRU entry i.e queue head */
		next_node = nscdb->qhead;
		while (nodes_togo > 0 && next_node != NULL) {
			node = next_node;
			next_node = next_node->qprev;
			if (node->stats.status == ST_DISCARD ||
			    !(node->stats.status & ST_PENDING)) {
				/* Leave nodes with pending updates alone  */
				delete_entry(nscdb, ctx, node);
				count++;
				nodes_togo--;
			}
		}
		(void) mutex_unlock(&nscdb->db_mutex);
	}

	_NSCD_LOG(NSCD_LOG_CACHE, NSCD_LOG_LEVEL_DEBUG)
		(me, "%s: evicted %lu LRU entries\n", ctx->dbname, count);

out:
	return (total_sleep);
}
