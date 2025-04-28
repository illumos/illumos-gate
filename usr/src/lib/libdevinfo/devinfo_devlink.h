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
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef _DEVINFO_DEVLINK_H
#define	_DEVINFO_DEVLINK_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	_POSIX_PTHREAD_SEMANTICS	/* For readdir_r */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <thread.h>
#include <synch.h>
#include <libdevinfo.h>
#include <limits.h>
#include <stdlib.h>
#include <dirent.h>
#include <regex.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <door.h>
#include <signal.h>
#include <sys/statvfs.h>

struct db_link {
	uint32_t attr;		/* primary or secondary */
	uint32_t path;		/* link path */
	uint32_t content;	/* link content */
	uint32_t sib;		/* next link for same minor */
};

struct db_minor {
	uint32_t name;		/* minor name */
	uint32_t nodetype;	/* minor node type */
	uint32_t sib;		/* next minor for same node */
	uint32_t link;		/* next minor for same node */
};

struct db_node {
	uint32_t path;		/* node path */
	uint32_t sib;		/* node's sibling */
	uint32_t child;		/* first child for this node */
	uint32_t minor;		/* first minor for node */
};

typedef enum db_seg {
	DB_NODE = 0,
	DB_MINOR,
	DB_LINK,
	DB_STR,
	DB_TYPES,	/* Number of non-header segments */
	DB_HEADER
} db_seg_t;

struct db_hdr {
	uint32_t magic;			/* Magic number	*/
	uint32_t vers;			/* database format version */
	uint32_t root_idx;		/* index for root node */
	uint32_t dngl_idx;		/* head of DB dangling links */
	uint32_t page_sz;		/* page size for mmap alignment	*/
	uint32_t update_count;		/* updates since last /dev synch up */
	uint32_t nelems[DB_TYPES];	/* Number of elements of each type */
};


typedef	struct cache_link {
	char   *path;			/* link path */
	char   *content;		/* link content	*/
	uint_t attr;			/* link attributes */
	struct cache_link *hash;	/* next link on same hash chain */
	struct cache_link *sib;		/* next link for same minor */
	struct cache_minor *minor;	/* minor for this link */
} cache_link_t;

typedef	struct cache_minor {
	char *name;			/* minor name */
	char *nodetype;			/* minor nodetype */
	struct cache_node *node;	/* node for this minor */
	struct cache_minor *sib;	/* next minor for same node */
	struct cache_link *link;	/* first link pointing to minor */
} cache_minor_t;

typedef struct cache_node {
	char	*path;			/* path	*/
	struct cache_node *parent;	/* node's parent */
	struct cache_node *sib;		/* node's sibling */
	struct cache_node *child;	/* first child for this node */
	struct cache_minor *minor;	/* first minor for node */
} cache_node_t;

struct cache {
	uint_t	flags;			/* cache state */
	uint_t	update_count;		/* updates since /dev synchronization */
	uint_t	hash_sz;		/* number of hash chains */
	cache_link_t **hash;		/* hash table */
	cache_node_t *root;		/* root of cache tree */
	cache_link_t *dngl;		/* list of dangling links */
	cache_minor_t *last_minor;	/* last minor looked up	*/
};

struct db {
	int db_fd;			/* database file */
	uint_t flags;			/* database open mode */
	struct db_hdr *hdr;		/* DB header */
	int  seg_prot[DB_TYPES];	/* protection for  segments */
	caddr_t seg_base[DB_TYPES];	/* base address for segments */
};

struct di_devlink_handle {
	char *dev_dir;			/* <root-dir>/dev */
	char *db_dir;			/* <root-dir>/etc/dev */
	uint_t	flags;			/* handle flags	*/
	uint_t  error;			/* records errors encountered */
	int lock_fd;			/* lock file for updates */
	struct cache cache;
	struct db db;
};

typedef struct link_desc {
	regex_t *regp;
	const char *minor_path;
	uint_t flags;
	void *arg;
	int (*fcn)(di_devlink_t, void *);
	int retval;
} link_desc_t;

struct tnode {
	void *node;
	int flags;
	struct di_devlink_handle *handle;
};

struct di_devlink {
	char *rel_path;
	char *abs_path;
	char *content;
	int type;
};

typedef struct recurse {
	void *data;
	int (*fcn)(struct di_devlink_handle *, void *, const char *);
} recurse_t;

/*
 * Debug levels currently defined.
 */
typedef enum {
	DBG_ERR = 1,
	DBG_LCK,
	DBG_INFO,
	DBG_STEP,
	DBG_ALL
} debug_level_t;


#define	DB_MAGIC	0xBAC2ACAB
#define	DB_FILE		".devlink_db"
#define	DB_TMP		".devlink_db_tmp"
#define	DB_LOCK		".devlink_db_lock"
#define	DB_PERMS	(S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR)
#define	DB_LOCK_PERMS	DB_PERMS
#define	DB_VERSION	1

#define	DB_NIL		0

#define	DEV		"/dev"
#define	ETCDEV		"/etc/dev"
#define	DEVICES_SUFFIX	"ices"

#define	HDR_LEN			sizeof (struct db_hdr)

#define	AVG_CHAIN_SIZE		20   /* Average number of links per chain */
#define	MIN_HASH_SIZE		1024 /* Min number of chains in hash table */
#define	MAX_UPDATE_INTERVAL	5 /* Max DB writes before synching with /dev */
#define	MAX_LOCK_RETRY		5 /* Max attempts at locking the update lock */

/*
 * Various flags private to the implementation
 */
#define	A_PRIMARY		0x0001U
#define	A_SECONDARY		0x0002U
#define	A_LINK_TYPES		0x0003U	/* Mask */
#define	A_VALID			0x0004U

#define	TYPE_DB			0x0008U
#define	TYPE_CACHE		0x0010U
#define	CREATE_FLAG		0x0020U

#define	INSERT_HEAD		0x0040U
#define	INSERT_TAIL		0x0080U
#define	OPEN_RDWR		0x0100U
#define	OPEN_RDONLY		0x0200U
#define	OPEN_FLAGS		0x0300U	/* Mask */
#define	UNLINK_FROM_HASH	0x0400U

#define	SET_VALID_ATTR(a)	((a) |= A_VALID)
#define	CLR_VALID_ATTR(a)	((a) &= ~A_VALID)
#define	GET_VALID_ATTR(a)	((a) & A_VALID)

#define	SET_DB_ERR(h)	((h)->error = 1)
#define	DB_ERR(h)	((h)->error)

#define	LOOKUP_DB(f)	((f) & TYPE_DB)
#define	LOOKUP_CACHE(f)	((f) & TYPE_CACHE)
#define	CREATE_ELEM(f)	((f) & CREATE_FLAG)

#define	IS_RDWR(f)	(((f) & OPEN_FLAGS) == OPEN_RDWR)
#define	IS_RDONLY(f)	(((f) & OPEN_FLAGS) == OPEN_RDONLY)

#define	HDL_RDWR(h)	(((h)->flags & OPEN_FLAGS) == OPEN_RDWR)
#define	HDL_RDONLY(h)	(((h)->flags & OPEN_FLAGS) == OPEN_RDONLY)

#define	CACHE(h)		(&(h)->cache)
#define	CACHE_ROOT(h)		(CACHE(h)->root)
#define	CACHE_HASH(h, i)	(CACHE(h)->hash[i])
#define	CACHE_LAST(h)	(CACHE(h)->last_minor)
#define	CACHE_EMPTY(h)	(CACHE(h)->root == NULL && CACHE(h)->dngl == NULL)

#define	DB(h)			(&(h)->db)
#define	DB_HDR(h)		(DB(h)->hdr)
#define	DB_NUM(h, t)		(DB_HDR(h)->nelems[t])
#define	DB_SEG(h, t)		(DB(h)->seg_base[t])
#define	DB_SEG_PROT(h, t)	(DB(h)->seg_prot[t])

#define	DB_OPEN(h)	(DB_HDR(h) != NULL)
#define	DB_RDWR(h)	((DB(h)->flags & OPEN_FLAGS) == OPEN_RDWR)
#define	DB_RDONLY(h)	((DB(h)->flags & OPEN_FLAGS) == OPEN_RDONLY)

#define	DB_EMPTY(h)	(DB_HDR(h)->root_idx == DB_NIL && \
			    DB_HDR(h)->dngl_idx == DB_NIL)

#define	TYPE_NONE(f)	(((f) & DI_LINK_TYPES) == 0)
#define	TYPE_PRI(f)	(((f) & DI_LINK_TYPES) == DI_PRIMARY_LINK)
#define	TYPE_SEC(f)	(((f) & DI_LINK_TYPES) == DI_SECONDARY_LINK)
#define	LINK_TYPE(f)	((f) & DI_LINK_TYPES)
#define	VALID_TYPE(f)	(TYPE_NONE(f) || TYPE_PRI(f) || TYPE_SEC(f))

#define	VALID_STR(h, i, s)   ((i) + strlen(s) + 1 <= DB_HDR(h)->nelems[DB_STR])
#define	VALID_INDEX(h, t, i) ((i) < DB_HDR(h)->nelems[t])

/*
 * Environment variables used by DEBUG version of code.
 */
#define	SKIP_DB		"DEBUG_SKIP_DB"
#define	SKIP_LAST_CACHE	"DEBUG_SKIP_LAST_CACHE"
#define	ALT_DB_DIR	"DEBUG_ALT_DB_DIR"

/*
 * Function prototypes
 */
static struct di_devlink_handle *handle_alloc(const char *dev_dir,
    uint_t flags);
static int cache_alloc(struct di_devlink_handle *hdp);
static int open_db(struct di_devlink_handle *hdp, int flags);
static int invalid_db(struct di_devlink_handle *hdp, size_t fsize, long pg_sz);
static int read_nodes(struct di_devlink_handle *hdp, cache_node_t *pcnp,
    uint32_t nidx);
static int read_minors(struct di_devlink_handle *hdp, cache_node_t *pcnp,
    uint32_t nidx);
static int read_links(struct di_devlink_handle *hdp, cache_minor_t *pcmp,
    uint32_t nidx);
static int init_hdr(struct di_devlink_handle *hdp, long page_sz,
    uint32_t *count);
static size_t size_db(struct di_devlink_handle *hdp, long page_sz,
    uint32_t *count);
static size_t seg_size(struct di_devlink_handle *hdp, int seg);

static cache_node_t *node_insert(struct di_devlink_handle *hdp,
    cache_node_t *pcnp, const char *path, int insert);
static cache_minor_t *minor_insert(struct di_devlink_handle *hdp,
    cache_node_t *pcnp, const char *name, const char *nodetype,
    cache_minor_t **prev);
static cache_link_t *link_insert(struct di_devlink_handle *hdp,
    cache_minor_t *mnp, const char *path, const char *content, uint32_t attr);

static void minor_delete(di_devlink_handle_t hdp, cache_minor_t *cmnp);
static void link_delete(di_devlink_handle_t hdp, cache_link_t *clp);

static int write_nodes(struct di_devlink_handle *hdp, struct db_node *pdnp,
    cache_node_t *cnp, uint32_t *next);
static int write_minors(struct di_devlink_handle *hdp, struct db_node *pdnp,
    cache_minor_t *cmnp, uint32_t *next);
static int write_links(struct di_devlink_handle *hdp, struct db_minor *pdmp,
    cache_link_t *clp, uint32_t *next);
static void rm_link_from_hash(struct di_devlink_handle *hdp, cache_link_t *clp);
static uint32_t write_string(struct di_devlink_handle *hdp, const char *str,
    uint32_t *next);
static int close_db(struct di_devlink_handle *hdp);
static void cache_free(struct di_devlink_handle *hdp);
static void handle_free(struct di_devlink_handle **pp);
static void resolve_dangling_links(struct di_devlink_handle *hdp);
static void subtree_free(struct di_devlink_handle *hdp, cache_node_t **pp);
static void node_free(cache_node_t **pp);
static void minor_free(struct di_devlink_handle *hdp, cache_minor_t **pp);
static void link_free(cache_link_t **pp);
static void count_node(cache_node_t *cnp, uint32_t *count);
static void count_minor(cache_minor_t *mnp, uint32_t *count);
static void count_link(cache_link_t *clp, uint32_t *count);
static void count_string(const char *str, uint32_t *count);
static int visit_node(const char *path, void *arg);
static int walk_tree(char *cur, void *arg,
    int (*node_callback)(const char *path, void *arg));
static void *lookup_node(struct di_devlink_handle *hdp, char *path,
    const int flags);
static cache_link_t *add_link(struct di_devlink_handle *hdp, const char *link,
    const char *content, int primary);

static void *lookup_minor(struct di_devlink_handle *hdp, const char *minor_path,
    const char *nodetype, const int flags);
static cache_link_t *link_hash(di_devlink_handle_t hdp, const char *link,
    uint_t flags);

static void hash_insert(struct di_devlink_handle *hdp, cache_link_t *clp);
static uint_t hashfn(struct di_devlink_handle *hdp, const char *str);
static void get_db_path(struct di_devlink_handle *hdp, const char *fname,
    char *buf, size_t blen);

static struct db_node *get_node(struct di_devlink_handle *hdp, uint32_t idx);
static struct db_node *set_node(struct di_devlink_handle *hdp, uint32_t idx);

static struct db_minor *get_minor(struct di_devlink_handle *hdp, uint32_t idx);
static struct db_minor *set_minor(struct di_devlink_handle *hdp, uint32_t idx);

static struct db_link *get_link(struct di_devlink_handle *hdp, uint32_t idx);
static struct db_link *set_link(struct di_devlink_handle *hdp, uint32_t idx);

static char *get_string(struct di_devlink_handle *hdp, uint32_t idx);
static char *set_string(struct di_devlink_handle *hdp, uint32_t idx);

static void *map_seg(struct di_devlink_handle *hdp, uint32_t idx, int prot,
    db_seg_t seg);

static int walk_db(struct di_devlink_handle *hdp, link_desc_t *linkp);
static int walk_all_links(struct di_devlink_handle *hdp, link_desc_t *linkp);
static int walk_matching_links(struct di_devlink_handle *hdp,
    link_desc_t *linkp);
static int visit_link(struct di_devlink_handle *hdp, link_desc_t *linkp,
    struct di_devlink *vlp);

static void walk_cache_minor(di_devlink_handle_t hdp, const char *mpath,
    link_desc_t *linkp);
static int walk_cache_links(di_devlink_handle_t hdp, cache_link_t *clp,
    link_desc_t *linkp);
static void walk_all_cache(di_devlink_handle_t hdp, link_desc_t *linkp);
static int cache_dev_link(struct di_devlink_handle *hdp, void *data,
    const char *link_path);

static int walk_dev(struct di_devlink_handle *hdp, link_desc_t *linkp);
static int recurse_dev(struct di_devlink_handle *hdp, recurse_t *rp);
static int do_recurse(const char *dir, struct di_devlink_handle *hdp,
    recurse_t *rp, int *retp);

static int check_attr(uint32_t attr);
static int attr2type(uint32_t attr);

static int check_args(link_desc_t *linkp);

static void *get_last_node(struct di_devlink_handle *hdp, const char *path,
    int flags);
static void *get_last_minor(struct di_devlink_handle *hdp,
    const char *devfs_path, const char *minor_name, int flags);
static void set_last_minor(struct di_devlink_handle *hdp, cache_minor_t *cmnp,
    int flags);

static int enter_db_lock(struct di_devlink_handle *hdp, const char *root_dir);
static void exit_db_lock(struct di_devlink_handle *hdp);

static char *minor_colon(const char *path);
static const char *rel_path(struct di_devlink_handle *hdp, const char *path);
static int link_flag(uint_t flags);
static int s_readlink(const char *link, char *buf, size_t blen);
static cache_minor_t *link2minor(struct di_devlink_handle *hdp,
    cache_link_t *clp);
static int link_cmp(cache_link_t *clp, const char *content, int type);
static void delete_unused_nodes(di_devlink_handle_t hdp, cache_node_t *cnp);
static void delete_unused_minor(di_devlink_handle_t hdp, cache_minor_t *cmnp);
static int synchronize_db(di_devlink_handle_t hdp);
static void devlink_dprintf(debug_level_t msglevel, const char *fmt, ...);
static di_devlink_handle_t devlink_snapshot(const char *root_dir);
static int devlink_create(const char *root, const char *name, int dca_flags);
static int dca_init(const char *name, struct dca_off *dcp, int dca_flags);
static void exec_cmd(const char *root, struct dca_off *dcp);
static int do_exec(const char *path, char *const argv[]);
static int start_daemon(const char *root, int install);
static int daemon_call(const char *root, struct dca_off *dcp);

int is_minor_node(const char *contents, const char **mn_root);
char *s_realpath(const char *path, char *resolved_path);

#ifdef	__cplusplus
}
#endif

#endif /* _DEVINFO_DEVLINK_H */
