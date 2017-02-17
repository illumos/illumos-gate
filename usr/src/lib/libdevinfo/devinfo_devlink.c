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
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#include "libdevinfo.h"
#include "devinfo_devlink.h"
#include "device_info.h"

#undef	DEBUG
#ifndef	DEBUG
#define	NDEBUG 1
#else
#undef	NDEBUG
#endif

#include <assert.h>

static mutex_t update_mutex = DEFAULTMUTEX; /* Protects update record lock */
static mutex_t temp_file_mutex = DEFAULTMUTEX; /* for file creation tests */

static const size_t elem_sizes[DB_TYPES] = {
	sizeof (struct db_node),
	sizeof (struct db_minor),
	sizeof (struct db_link),
	sizeof (char)
};

/*
 * List of directories/files skipped while physically walking /dev
 * Paths are relative to "<root>/dev/"
 */
static const char *skip_dirs[] = {"fd"};
static const char *skip_files[] = {
	"stdout",
	"stdin",
	"stderr"
};

#define	N_SKIP_DIRS	(sizeof (skip_dirs) / sizeof (skip_dirs[0]))
#define	N_SKIP_FILES	(sizeof (skip_files) / sizeof (skip_files[0]))

#define	DI_TEST_DB	ETCDEV "di_test_db"

/*
 *
 * This file contains two sets of interfaces which operate on the reverse
 * links database. One set (which includes di_devlink_open()/_close())
 * allows link generators like devfsadm(1M) and ucblinks(1B) (writers) to
 * populate the database with /devices -> /dev mappings. Another set
 * of interfaces (which includes di_devlink_init()/_fini()) allows
 * applications (readers) to lookup the database for /dev links corresponding
 * to a given minor.
 *
 * Writers operate on a cached version of the database. The cache is created
 * when di_devlink_open() is called. As links in /dev are created and removed,
 * the cache is updated to keep it in synch with /dev. When the /dev updates
 * are complete, the link generator calls di_devlink_close() which writes
 * out the cache to the database.
 *
 * Applications which need to lookup the database, call di_devlink_init().
 * di_devlink_init() checks the database file (if one exists). If the
 * database is valid, it is mapped into the address space of the
 * application. The database file consists of several segments. Each
 * segment can be mapped in independently and is mapped on demand.
 *
 *		   Database Layout
 *
 *		---------------------
 *		|	Magic #     |
 *		| ----------------- |
 *		|       Version	    |	HEADER
 *		| ----------------- |
 *		|        ...        |
 *		---------------------
 *		|		    |
 *		|		    |	NODES
 *		|	            |
 *		|		    |
 *		---------------------
 *		|		    |
 *		|		    |	MINORS
 *		|	            |
 *		|		    |
 *		---------------------
 *		|		    |
 *		|		    |   LINKS
 *		|	            |
 *		|		    |
 *		---------------------
 *		|		    |
 *		|		    |	STRINGS
 *		|	            |
 *		|		    |
 *		---------------------
 *
 * Readers can lookup /dev links for a specific minor or
 * lookup all /dev links. In the latter case, the node
 * and minor segments are not mapped in and the reader
 * walks through every link in the link segment.
 *
 */
di_devlink_handle_t
di_devlink_open(const char *root_dir, uint_t flags)
{
	int err;
	char path[PATH_MAX];
	struct di_devlink_handle *hdp;
	int retried = 0;

retry:
	/*
	 * Allocate a read-write handle but open the DB in readonly
	 * mode. We do writes only to a temporary copy of the database.
	 */
	if ((hdp = handle_alloc(root_dir, OPEN_RDWR)) == NULL) {
		return (NULL);
	}

	err = open_db(hdp, OPEN_RDONLY);

	/*
	 * We don't want to unlink the db at this point - if we did we
	 * would be creating a window where consumers would take a slow
	 * code path (and those consumers might also trigger requests for
	 * db creation, which we are already in the process of doing).
	 * When we are done with our update, we use rename to install the
	 * latest version of the db file.
	 */
	get_db_path(hdp, DB_FILE, path, sizeof (path));

	/*
	 * The flags argument is reserved for future use.
	 */
	if (flags != 0) {
		handle_free(&hdp); /* also closes the DB */
		errno = EINVAL;
		return (NULL);
	}

	if (cache_alloc(hdp) != 0) {
		handle_free(&hdp);
		return (NULL);
	}

	if (err) {
		/*
		 * Failed to open DB.
		 * The most likely cause is that DB file did not exist.
		 * Call di_devlink_close() to recreate the DB file and
		 * retry di_devlink_open().
		 */
		if (retried == 0) {
			(void) di_devlink_close(&hdp, 0);
			retried = 1;
			goto retry;
		}

		/*
		 * DB cannot be opened, just return the
		 * handle. We will recreate the DB later.
		 */
		return (hdp);
	}

	/* Read the database into the cache */
	CACHE(hdp)->update_count = DB_HDR(hdp)->update_count;
	(void) read_nodes(hdp, NULL, DB_HDR(hdp)->root_idx);
	(void) read_links(hdp, NULL, DB_HDR(hdp)->dngl_idx);

	(void) close_db(hdp);

	return (hdp);
}

static void
get_db_path(
	struct di_devlink_handle *hdp,
	const char *fname,
	char *buf,
	size_t blen)
{
	char *dir = NULL;

#ifdef	DEBUG
	if (dir = getenv(ALT_DB_DIR)) {
		(void) dprintf(DBG_INFO, "get_db_path: alternate db dir: %s\n",
		    dir);
	}
#endif
	if (dir == NULL) {
		dir = hdp->db_dir;
	}

	(void) snprintf(buf, blen, "%s/%s", dir, fname);
}

static int
open_db(struct di_devlink_handle *hdp, int flags)
{
	size_t sz;
	long page_sz;
	int fd, rv, flg;
	struct stat sbuf;
	uint32_t count[DB_TYPES] = {0};
	char path[PATH_MAX];
	void *cp;

	assert(!DB_OPEN(hdp));

#ifdef	DEBUG
	if (getenv(SKIP_DB)) {
		(void) dprintf(DBG_INFO, "open_db: skipping database\n");
		return (-1);
	}
#endif
	if ((page_sz = sysconf(_SC_PAGE_SIZE)) == -1) {
		return (-1);
	}

	/*
	 * Use O_TRUNC flag for write access, so that the subsequent ftruncate()
	 * call will zero-fill the entire file
	 */
	if (IS_RDONLY(flags)) {
		flg = O_RDONLY;
		get_db_path(hdp, DB_FILE, path, sizeof (path));
	} else {
		flg = O_RDWR|O_CREAT|O_TRUNC;
		get_db_path(hdp, DB_TMP, path, sizeof (path));
	}

	/*
	 * Avoid triggering /dev reconfigure for read when not present
	 */
	if (IS_RDONLY(flags) &&
	    (strncmp(path, "/dev/", 5) == 0) && !device_exists(path)) {
		return (-1);
	}

	if ((fd = open(path, flg, DB_PERMS)) == -1) {
		return (-1);
	}

	if (IS_RDONLY(flags)) {
		flg = PROT_READ;
		rv = fstat(fd, &sbuf);
		sz = sbuf.st_size;
	} else {
		flg = PROT_READ | PROT_WRITE;
		sz = size_db(hdp, page_sz, count);
		rv = ftruncate(fd, sz);
	}

	if (rv == -1 || sz < HDR_LEN) {
		if (rv != -1)
			errno = EINVAL;
		(void) close(fd);
		return (-1);
	}

	cp = mmap(0, HDR_LEN, flg, MAP_SHARED, fd, 0);
	if (cp == MAP_FAILED) {
		(void) close(fd);
		return (-1);
	}
	DB(hdp)->hdr = (struct db_hdr *)cp;
	DB(hdp)->db_fd = fd;
	DB(hdp)->flags = flags;

	if (IS_RDONLY(flags)) {
		rv = invalid_db(hdp, sz, page_sz);
	} else {
		rv = init_hdr(hdp, page_sz, count);
	}

	if (rv) {
		(void) dprintf(DBG_ERR, "open_db: invalid DB(%s)\n", path);
		(void) close_db(hdp);
		return (-1);
	} else {
		(void) dprintf(DBG_STEP, "open_db: DB(%s): opened\n", path);
		return (0);
	}
}

/*
 * A handle can be allocated for read-only or read-write access
 */
static struct di_devlink_handle *
handle_alloc(const char *root_dir, uint_t flags)
{
	char dev_dir[PATH_MAX], path[PATH_MAX], db_dir[PATH_MAX];
	struct di_devlink_handle *hdp, proto = {0};
	int install = 0;
	int isroot = 0;
	struct stat sb;
	char can_path[PATH_MAX];

	assert(flags == OPEN_RDWR || flags == OPEN_RDONLY);

	dev_dir[0] = '\0';
	db_dir[0] = '\0';

	/*
	 * NULL and the empty string are equivalent to "/"
	 */
	if (root_dir && root_dir[0] != '\0') {

		if (root_dir[0] != '/') {
			errno = EINVAL;
			return (NULL);
		}

#ifdef	DEBUG
		/*LINTED*/
		assert(sizeof (dev_dir) >= PATH_MAX);
#endif
		if ((realpath(root_dir, dev_dir) == NULL) ||
		    (realpath(root_dir, db_dir) == NULL)) {
			return (NULL);
		}
	} else {
		/*
		 * The dev dir is at /dev i.e. we are not doing a -r /altroot
		 */
		isroot = 1;
	}

	if (strcmp(dev_dir, "/") == 0) {
		dev_dir[0] = 0;
		db_dir[0] = 0;
	} else {
		(void) strlcpy(db_dir, dev_dir, sizeof (db_dir));
	}

	(void) strlcat(dev_dir, DEV, sizeof (dev_dir));
	(void) strlcat(db_dir, ETCDEV, sizeof (db_dir));

	/*
	 * The following code is for install. Readers and writers need
	 * to be redirected to /tmp/etc/dev for the database file.
	 * Note that we test for readonly /etc by actually creating a
	 * file since statvfs is not a reliable method for determining
	 * readonly filesystems.
	 */
	install = 0;
	(void) snprintf(can_path, sizeof (can_path), "%s/%s", ETCDEV, DB_FILE);
	if (flags == OPEN_RDWR && isroot) {
		char di_test_db[PATH_MAX];
		int fd;
		(void) mutex_lock(&temp_file_mutex);
		(void) snprintf(di_test_db, sizeof (di_test_db), "%s.%d",
		    DI_TEST_DB, getpid());
		fd = open(di_test_db, O_CREAT|O_RDWR|O_EXCL, 0644);
		if (fd == -1 && errno == EROFS && stat(can_path, &sb) == -1)
			install = 1;
		if (fd != -1) {
			(void) close(fd);
			(void) unlink(di_test_db);
		}
		(void) mutex_unlock(&temp_file_mutex);
	} else if (isroot) {
		/*
		 * Readers can be non-privileged so we cannot test by creating
		 * a file in /etc/dev. Instead we check if the database
		 * file is missing in /etc/dev and is present in /tmp/etc/dev
		 * and is owned by root.
		 */
		char install_path[PATH_MAX];

		(void) snprintf(install_path, sizeof (install_path),
		    "/tmp%s/%s", ETCDEV, DB_FILE);
		if (stat(can_path, &sb) == -1 && stat(install_path, &sb)
		    != -1 && sb.st_uid == 0) {
			install = 1;
		}
	}

	/*
	 * Check if we are in install. If we are, the database will be in
	 * /tmp/etc/dev
	 */
	if (install)
		(void) snprintf(db_dir, sizeof (db_dir), "/tmp%s", ETCDEV);

	proto.dev_dir = dev_dir;
	proto.db_dir = db_dir;
	proto.flags = flags;
	proto.lock_fd = -1;

	/*
	 * Lock database if a read-write handle is being allocated.
	 * Locks are needed to protect against multiple writers.
	 * Readers don't need locks.
	 */
	if (HDL_RDWR(&proto)) {
		if (enter_db_lock(&proto, root_dir) != 1) {
			return (NULL);
		}
	}

	DB(&proto)->db_fd = -1;

	hdp = calloc(1, sizeof (struct di_devlink_handle));
	if (hdp == NULL) {
		goto error;
	}

	*hdp = proto;

	/*
	 * The handle hdp now contains a pointer to local storage
	 * in the dev_dir field (obtained from the proto handle).
	 * In the following line, a dynamically allocated version
	 * is substituted.
	 */

	if ((hdp->dev_dir = strdup(proto.dev_dir)) == NULL) {
		free(hdp);
		goto error;
	}

	if ((hdp->db_dir = strdup(proto.db_dir)) == NULL) {
		free(hdp->dev_dir);
		free(hdp);
		goto error;
	}

	return (hdp);

error:
	if (HDL_RDWR(&proto)) {
		/* Unlink DB file on error */
		get_db_path(&proto, DB_FILE, path, sizeof (path));
		(void) unlink(path);
		exit_db_lock(&proto);
	}
	return (NULL);
}


static int
cache_alloc(struct di_devlink_handle *hdp)
{
	size_t hash_sz = 0;

	assert(HDL_RDWR(hdp));

	if (DB_OPEN(hdp)) {
		hash_sz = DB_NUM(hdp, DB_LINK) / AVG_CHAIN_SIZE;
	}
	hash_sz = (hash_sz >= MIN_HASH_SIZE) ? hash_sz : MIN_HASH_SIZE;

	CACHE(hdp)->hash = calloc(hash_sz, sizeof (cache_link_t *));
	if (CACHE(hdp)->hash == NULL) {
		return (-1);
	}
	CACHE(hdp)->hash_sz = hash_sz;

	return (0);
}


static int
invalid_db(struct di_devlink_handle *hdp, size_t fsize, long page_sz)
{
	int i;
	char *cp;
	size_t sz;

	if (DB_HDR(hdp)->magic != DB_MAGIC || DB_HDR(hdp)->vers != DB_VERSION) {
		return (1);
	}

	if (DB_HDR(hdp)->page_sz == 0 || DB_HDR(hdp)->page_sz != page_sz) {
		return (1);
	}

	sz = seg_size(hdp, DB_HEADER);
	for (i = 0; i < DB_TYPES; i++) {
		(void) dprintf(DBG_INFO, "N[%u] = %u\n", i, DB_NUM(hdp, i));
		/* There must be at least 1 element of each type */
		if (DB_NUM(hdp, i) < 1) {
			return (1);
		}
		sz += seg_size(hdp, i);
		assert(sz % page_sz == 0);
	}

	if (sz != fsize) {
		return (1);
	}

	if (!VALID_INDEX(hdp, DB_NODE, DB_HDR(hdp)->root_idx)) {
		return (1);
	}

	if (!VALID_INDEX(hdp, DB_LINK, DB_HDR(hdp)->dngl_idx)) {
		return (1);
	}

	if (DB_EMPTY(hdp)) {
		return (1);
	}

	/*
	 * The last character in the string segment must be a NUL char.
	 */
	cp = get_string(hdp, DB_NUM(hdp, DB_STR) - 1);
	if (cp == NULL || *cp != '\0') {
		return (1);
	}

	return (0);
}

static int
read_nodes(struct di_devlink_handle *hdp, cache_node_t *pcnp, uint32_t nidx)
{
	char *path;
	cache_node_t *cnp;
	struct db_node *dnp;
	const char *fcn = "read_nodes";

	assert(HDL_RDWR(hdp));

	/*
	 * parent node should be NULL only for the root node
	 */
	if ((pcnp == NULL) ^ (nidx == DB_HDR(hdp)->root_idx)) {
		(void) dprintf(DBG_ERR, "%s: invalid parent or index(%u)\n",
		    fcn, nidx);
		SET_DB_ERR(hdp);
		return (-1);
	}

	for (; dnp = get_node(hdp, nidx); nidx = dnp->sib) {

		path = get_string(hdp, dnp->path);

		/*
		 * Insert at head of list to recreate original order
		 */
		cnp = node_insert(hdp, pcnp, path, INSERT_HEAD);
		if (cnp == NULL) {
			SET_DB_ERR(hdp);
			break;
		}

		assert(strcmp(path, "/") ^ (nidx == DB_HDR(hdp)->root_idx));
		assert(strcmp(path, "/") != 0 || dnp->sib == DB_NIL);

		if (read_minors(hdp, cnp, dnp->minor) != 0 ||
		    read_nodes(hdp, cnp, dnp->child) != 0) {
			break;
		}

		(void) dprintf(DBG_STEP, "%s: node[%u]: %s\n", fcn, nidx,
		    cnp->path);
	}

	return (dnp ? -1 : 0);
}

static int
read_minors(struct di_devlink_handle *hdp, cache_node_t *pcnp, uint32_t nidx)
{
	cache_minor_t *cmnp;
	struct db_minor *dmp;
	char *name, *nodetype;
	const char *fcn = "read_minors";

	assert(HDL_RDWR(hdp));

	if (pcnp == NULL) {
		(void) dprintf(DBG_ERR, "%s: minor[%u]: orphan minor\n", fcn,
		    nidx);
		SET_DB_ERR(hdp);
		return (-1);
	}

	for (; dmp = get_minor(hdp, nidx); nidx = dmp->sib) {

		name = get_string(hdp, dmp->name);
		nodetype = get_string(hdp, dmp->nodetype);

		cmnp = minor_insert(hdp, pcnp, name, nodetype, NULL);
		if (cmnp == NULL) {
			SET_DB_ERR(hdp);
			break;
		}

		(void) dprintf(DBG_STEP, "%s: minor[%u]: %s\n", fcn, nidx,
		    cmnp->name);

		if (read_links(hdp, cmnp, dmp->link) != 0) {
			break;
		}
	}

	return (dmp ? -1 : 0);
}

/*
 * If the link is dangling the corresponding minor will be absent.
 */
static int
read_links(struct di_devlink_handle *hdp, cache_minor_t *pcmp, uint32_t nidx)
{
	cache_link_t *clp;
	struct db_link *dlp;
	char *path, *content;

	assert(HDL_RDWR(hdp));

	if (nidx != DB_NIL &&
	    ((pcmp == NULL) ^ (nidx == DB_HDR(hdp)->dngl_idx))) {
		(void) dprintf(DBG_ERR, "read_links: invalid minor or"
		    " index(%u)\n", nidx);
		SET_DB_ERR(hdp);
		return (-1);
	}

	for (; dlp = get_link(hdp, nidx); nidx = dlp->sib) {

		path = get_string(hdp, dlp->path);
		content = get_string(hdp, dlp->content);

		clp = link_insert(hdp, pcmp, path, content, dlp->attr);
		if (clp == NULL) {
			SET_DB_ERR(hdp);
			break;
		}

		(void) dprintf(DBG_STEP, "read_links: link[%u]: %s%s\n",
		    nidx, clp->path, pcmp == NULL ? "(DANGLING)" : "");
	}

	return (dlp ? -1 : 0);
}

int
di_devlink_close(di_devlink_handle_t *pp, int flag)
{
	int i, rv;
	char tmp[PATH_MAX];
	char file[PATH_MAX];
	uint32_t next[DB_TYPES] = {0};
	struct di_devlink_handle *hdp;

	if (pp == NULL || *pp == NULL || !HDL_RDWR(*pp)) {
		errno = EINVAL;
		return (-1);
	}

	hdp = *pp;
	*pp = NULL;

	/*
	 * The caller encountered some error in their processing.
	 * so handle isn't valid. Discard it and return success.
	 */
	if (flag == DI_LINK_ERROR) {
		handle_free(&hdp);
		return (0);
	}

	if (DB_ERR(hdp)) {
		handle_free(&hdp);
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Extract the DB path before the handle is freed.
	 */
	get_db_path(hdp, DB_FILE, file, sizeof (file));
	get_db_path(hdp, DB_TMP, tmp, sizeof (tmp));

	/*
	 * update database with actual contents of /dev
	 */
	(void) dprintf(DBG_INFO, "di_devlink_close: update_count = %u\n",
	    CACHE(hdp)->update_count);

	/*
	 * For performance reasons, synchronization of the database
	 * with /dev is turned off by default. However, applications
	 * with appropriate permissions can request a "sync" by
	 * calling di_devlink_update().
	 */
	if (CACHE(hdp)->update_count == 0) {
		CACHE(hdp)->update_count = 1;
		(void) dprintf(DBG_INFO,
		    "di_devlink_close: synchronizing DB\n");
		(void) synchronize_db(hdp);
	}

	/*
	 * Resolve dangling links AFTER synchronizing DB with /dev as the
	 * synchronization process may create dangling links.
	 */
	resolve_dangling_links(hdp);

	/*
	 * All changes to the cache are complete. Write out the cache
	 * to the database only if it is not empty.
	 */
	if (CACHE_EMPTY(hdp)) {
		(void) dprintf(DBG_INFO, "di_devlink_close: skipping write\n");
		(void) unlink(file);
		handle_free(&hdp);
		return (0);
	}

	if (open_db(hdp, OPEN_RDWR) != 0) {
		handle_free(&hdp);
		return (-1);
	}

	/*
	 * Keep track of array assignments. There is at least
	 * 1 element (the "NIL" element) per type.
	 */
	for (i = 0; i < DB_TYPES; i++) {
		next[i] = 1;
	}

	(void) write_nodes(hdp, NULL, CACHE_ROOT(hdp), next);
	(void) write_links(hdp, NULL, CACHE(hdp)->dngl, next);
	DB_HDR(hdp)->update_count = CACHE(hdp)->update_count;

	rv = close_db(hdp);

	if (rv != 0 || DB_ERR(hdp) || rename(tmp, file) != 0) {
		(void) dprintf(DBG_ERR, "di_devlink_close: %s error: %s\n",
		    rv ? "close_db" : "DB or rename", strerror(errno));
		(void) unlink(tmp);
		(void) unlink(file);
		handle_free(&hdp);
		return (-1);
	}

	handle_free(&hdp);

	(void) dprintf(DBG_INFO, "di_devlink_close: wrote DB(%s)\n", file);

	return (0);
}

/*
 * Inits the database header.
 */
static int
init_hdr(struct di_devlink_handle *hdp, long page_sz, uint32_t *count)
{
	int i;

	DB_HDR(hdp)->magic = DB_MAGIC;
	DB_HDR(hdp)->vers = DB_VERSION;
	DB_HDR(hdp)->root_idx = DB_NIL;
	DB_HDR(hdp)->dngl_idx = DB_NIL;
	DB_HDR(hdp)->page_sz = (uint32_t)page_sz;

	for (i = 0; i < DB_TYPES; i++) {
		assert(count[i] >= 1);
		DB_NUM(hdp, i) = count[i];
	}

	return (0);
}

static int
write_nodes(
	struct di_devlink_handle *hdp,
	struct db_node *pdnp,
	cache_node_t *cnp,
	uint32_t *next)
{
	uint32_t idx;
	struct db_node *dnp;
	const char *fcn = "write_nodes";

	assert(HDL_RDWR(hdp));

	for (; cnp != NULL; cnp = cnp->sib) {

		assert(cnp->path != NULL);

		/* parent node should only be NULL for root node */
		if ((pdnp == NULL) ^ (cnp == CACHE_ROOT(hdp))) {
			(void) dprintf(DBG_ERR, "%s: invalid parent for: %s\n",
			    fcn, cnp->path);
			SET_DB_ERR(hdp);
			break;
		}

		assert((strcmp(cnp->path, "/") != 0) ^
		    (cnp == CACHE_ROOT(hdp)));

		idx = next[DB_NODE];
		if ((dnp = set_node(hdp, idx)) == NULL) {
			SET_DB_ERR(hdp);
			break;
		}

		dnp->path = write_string(hdp, cnp->path, next);
		if (dnp->path == DB_NIL) {
			SET_DB_ERR(hdp);
			break;
		}
		/* commit write for this node */
		next[DB_NODE]++;

		if (pdnp == NULL) {
			assert(DB_HDR(hdp)->root_idx == DB_NIL);
			DB_HDR(hdp)->root_idx = idx;
		} else {
			dnp->sib = pdnp->child;
			pdnp->child = idx;
		}

		(void) dprintf(DBG_STEP, "%s: node[%u]: %s\n", fcn, idx,
		    cnp->path);

		if (write_minors(hdp, dnp, cnp->minor, next) != 0 ||
		    write_nodes(hdp, dnp, cnp->child, next) != 0) {
			break;
		}
	}

	return (cnp ? -1 : 0);
}

static int
write_minors(
	struct di_devlink_handle *hdp,
	struct db_node *pdnp,
	cache_minor_t *cmnp,
	uint32_t *next)
{
	uint32_t idx;
	struct db_minor *dmp;
	const char *fcn = "write_minors";

	assert(HDL_RDWR(hdp));

	if (pdnp == NULL) {
		(void) dprintf(DBG_ERR, "%s: no node for minor: %s\n", fcn,
		    cmnp ? cmnp->name : "<NULL>");
		SET_DB_ERR(hdp);
		return (-1);
	}

	for (; cmnp != NULL; cmnp = cmnp->sib) {

		assert(cmnp->name != NULL);

		idx = next[DB_MINOR];
		if ((dmp = set_minor(hdp, idx)) == NULL) {
			SET_DB_ERR(hdp);
			break;
		}

		dmp->name = write_string(hdp, cmnp->name, next);
		dmp->nodetype = write_string(hdp, cmnp->nodetype, next);
		if (dmp->name == DB_NIL || dmp->nodetype == DB_NIL) {
			dmp->name = dmp->nodetype = DB_NIL;
			SET_DB_ERR(hdp);
			break;
		}

		/* Commit writes to this minor */
		next[DB_MINOR]++;

		dmp->sib = pdnp->minor;
		pdnp->minor = idx;

		(void) dprintf(DBG_STEP, "%s: minor[%u]: %s\n", fcn, idx,
		    cmnp->name);

		if (write_links(hdp, dmp, cmnp->link, next) != 0) {
			break;
		}
	}

	return (cmnp ? -1 : 0);
}

static int
write_links(
	struct di_devlink_handle *hdp,
	struct db_minor *pdmp,
	cache_link_t *clp,
	uint32_t *next)
{
	uint32_t idx;
	struct db_link *dlp;
	const char *fcn = "write_links";

	assert(HDL_RDWR(hdp));

	/* A NULL minor if and only if the links are dangling */
	if (clp != NULL && ((pdmp == NULL) ^ (clp == CACHE(hdp)->dngl))) {
		(void) dprintf(DBG_ERR, "%s: invalid minor for link\n", fcn);
		SET_DB_ERR(hdp);
		return (-1);
	}

	for (; clp != NULL; clp = clp->sib) {

		assert(clp->path != NULL);

		if ((pdmp == NULL) ^ (clp->minor == NULL)) {
			(void) dprintf(DBG_ERR, "%s: invalid minor for link"
			    "(%s)\n", fcn, clp->path);
			SET_DB_ERR(hdp);
			break;
		}

		idx = next[DB_LINK];
		if ((dlp = set_link(hdp, idx)) == NULL) {
			SET_DB_ERR(hdp);
			break;
		}

		dlp->path = write_string(hdp, clp->path, next);
		dlp->content = write_string(hdp, clp->content, next);
		if (dlp->path == DB_NIL || dlp->content == DB_NIL) {
			dlp->path = dlp->content = DB_NIL;
			SET_DB_ERR(hdp);
			break;
		}

		dlp->attr = clp->attr;

		/* Commit writes to this link */
		next[DB_LINK]++;

		if (pdmp != NULL) {
			dlp->sib = pdmp->link;
			pdmp->link = idx;
		} else {
			dlp->sib = DB_HDR(hdp)->dngl_idx;
			DB_HDR(hdp)->dngl_idx = idx;
		}

		(void) dprintf(DBG_STEP, "%s: link[%u]: %s%s\n", fcn, idx,
		    clp->path, pdmp == NULL ? "(DANGLING)" : "");
	}

	return (clp ? -1 : 0);
}


static uint32_t
write_string(struct di_devlink_handle *hdp, const char *str, uint32_t *next)
{
	char *dstr;
	uint32_t idx;

	assert(HDL_RDWR(hdp));

	if (str == NULL) {
		(void) dprintf(DBG_ERR, "write_string: NULL argument\n");
		return (DB_NIL);
	}

	idx = next[DB_STR];
	if (!VALID_STR(hdp, idx, str)) {
		(void) dprintf(DBG_ERR, "write_string: invalid index[%u],"
		    " string(%s)\n", idx, str);
		return (DB_NIL);
	}

	if ((dstr = set_string(hdp, idx)) == NULL) {
		return (DB_NIL);
	}

	(void) strcpy(dstr, str);

	next[DB_STR] += strlen(dstr) + 1;

	return (idx);
}

static int
close_db(struct di_devlink_handle *hdp)
{
	int i, rv = 0;
	size_t sz;

	if (!DB_OPEN(hdp)) {
#ifdef	DEBUG
		assert(DB(hdp)->db_fd == -1);
		assert(DB(hdp)->flags == 0);
		for (i = 0; i < DB_TYPES; i++) {
			assert(DB_SEG(hdp, i) == NULL);
			assert(DB_SEG_PROT(hdp, i) == 0);
		}
#endif
		return (0);
	}

	/* Unmap header after unmapping all other mapped segments */
	for (i = 0; i < DB_TYPES; i++) {
		if (DB_SEG(hdp, i)) {
			sz = seg_size(hdp, i);
			if (DB_RDWR(hdp))
				rv += msync(DB_SEG(hdp, i), sz, MS_SYNC);
			(void) munmap(DB_SEG(hdp, i), sz);
			DB_SEG(hdp, i) = NULL;
			DB_SEG_PROT(hdp, i) = 0;
		}
	}

	if (DB_RDWR(hdp))
		rv += msync((caddr_t)DB_HDR(hdp), HDR_LEN, MS_SYNC);
	(void) munmap((caddr_t)DB_HDR(hdp), HDR_LEN);
	DB(hdp)->hdr = NULL;

	(void) close(DB(hdp)->db_fd);
	DB(hdp)->db_fd = -1;
	DB(hdp)->flags = 0;

	return (rv ? -1 : 0);
}


static void
cache_free(struct di_devlink_handle *hdp)
{
	cache_link_t *clp;

	subtree_free(hdp, &(CACHE_ROOT(hdp)));
	assert(CACHE_LAST(hdp) == NULL);

	/*
	 * Don't bother removing links from hash table chains,
	 * as we are freeing the hash table itself.
	 */
	while (CACHE(hdp)->dngl != NULL) {
		clp = CACHE(hdp)->dngl;
		CACHE(hdp)->dngl = clp->sib;
		assert(clp->minor == NULL);
		link_free(&clp);
	}

	assert((CACHE(hdp)->hash == NULL) ^ (CACHE(hdp)->hash_sz != 0));

	free(CACHE(hdp)->hash);
	CACHE(hdp)->hash = NULL;
	CACHE(hdp)->hash_sz = 0;
}

static void
handle_free(struct di_devlink_handle **pp)
{
	struct di_devlink_handle *hdp = *pp;

	*pp = NULL;

	if (hdp == NULL)
		return;

	(void) close_db(hdp);
	cache_free(hdp);

	if (HDL_RDWR(hdp))
		exit_db_lock(hdp);
	assert(hdp->lock_fd == -1);

	free(hdp->dev_dir);
	free(hdp->db_dir);
	free(hdp);
}

/*
 * Frees the tree rooted at a node. Siblings of the subtree root
 * have to be handled by the caller.
 */
static void
subtree_free(struct di_devlink_handle *hdp, cache_node_t **pp)
{
	cache_node_t *np;
	cache_link_t *clp;
	cache_minor_t *cmnp;

	if (pp == NULL || *pp == NULL)
		return;

	while ((*pp)->child != NULL) {
		np = (*pp)->child;
		(*pp)->child = np->sib;
		subtree_free(hdp, &np);
	}

	while ((*pp)->minor != NULL) {
		cmnp = (*pp)->minor;
		(*pp)->minor = cmnp->sib;

		while (cmnp->link != NULL) {
			clp = cmnp->link;
			cmnp->link = clp->sib;
			rm_link_from_hash(hdp, clp);
			link_free(&clp);
		}
		minor_free(hdp, &cmnp);
	}

	node_free(pp);
}

static void
rm_link_from_hash(struct di_devlink_handle *hdp, cache_link_t *clp)
{
	int hval;
	cache_link_t **pp;

	if (clp == NULL)
		return;

	if (clp->path == NULL)
		return;

	hval = hashfn(hdp, clp->path);
	pp = &(CACHE_HASH(hdp, hval));
	for (; *pp != NULL; pp = &(*pp)->hash) {
		if (*pp == clp) {
			*pp = clp->hash;
			clp->hash = NULL;
			return;
		}
	}

	dprintf(DBG_ERR, "rm_link_from_hash: link(%s) not found\n", clp->path);
}

static cache_link_t *
link_hash(di_devlink_handle_t hdp, const char *link, uint_t flags)
{
	int hval;
	cache_link_t **pp, *clp;

	if (link == NULL)
		return (NULL);

	hval = hashfn(hdp, link);
	pp = &(CACHE_HASH(hdp, hval));
	for (; (clp = *pp) != NULL; pp = &clp->hash) {
		if (strcmp(clp->path, link) == 0) {
			break;
		}
	}

	if (clp == NULL)
		return (NULL);

	if ((flags & UNLINK_FROM_HASH) == UNLINK_FROM_HASH) {
		*pp = clp->hash;
		clp->hash = NULL;
	}

	return (clp);
}

static cache_minor_t *
link2minor(struct di_devlink_handle *hdp, cache_link_t *clp)
{
	cache_link_t *plp;
	const char *minor_path;
	char *cp, buf[PATH_MAX], link[PATH_MAX];
	char abspath[PATH_MAX];
	struct stat st;

	if (TYPE_PRI(attr2type(clp->attr))) {
		/*
		 * For primary link, content should point to a /devices node.
		 */
		if (!is_minor_node(clp->content, &minor_path)) {
			return (NULL);
		}

		return (lookup_minor(hdp, minor_path, NULL,
		    TYPE_CACHE|CREATE_FLAG));

	}

	/*
	 * If secondary, the primary link is derived from the secondary
	 * link contents. Secondary link contents can have two formats:
	 *	audio -> /dev/sound/0
	 *	fb0 -> fbs/afb0
	 */

	buf[0] = '\0';
	if (strncmp(clp->content, DEV"/", strlen(DEV"/")) == 0) {
		cp = &clp->content[strlen(DEV"/")];
	} else if (clp->content[0] != '/') {
		if ((cp = strrchr(clp->path, '/')) != NULL) {
			char savechar = *(cp + 1);
			*(cp + 1) = '\0';
			(void) snprintf(buf, sizeof (buf), "%s", clp->path);
			*(cp + 1) = savechar;
		}
		(void) strlcat(buf, clp->content, sizeof (buf));
		cp = buf;
	} else {
		goto follow_link;
	}

	/*
	 * Lookup the primary link if possible and find its minor.
	 */
	if ((plp = link_hash(hdp, cp, 0)) != NULL && plp->minor != NULL) {
		return (plp->minor);
	}

	/* realpath() used only as a last resort because it is expensive */
follow_link:
	(void) snprintf(link, sizeof (link), "%s/%s", hdp->dev_dir, clp->path);

#ifdef	DEBUG
	/*LINTED*/
	assert(sizeof (buf) >= PATH_MAX);
#endif

	/*
	 * A realpath attempt to lookup a dangling link can invoke implicit
	 * reconfig so verify there's an actual device behind the link first.
	 */
	if (lstat(link, &st) == -1)
		return (NULL);
	if (S_ISLNK(st.st_mode)) {
		if (s_readlink(link, buf, sizeof (buf)) < 0)
			return (NULL);
		if (buf[0] != '/') {
			char *p;
			size_t n = sizeof (abspath);
			if (strlcpy(abspath, link, n) >= n)
				return (NULL);
			p = strrchr(abspath, '/') + 1;
			*p = 0;
			n = sizeof (abspath) - strlen(p);
			if (strlcpy(p, buf, n) >= n)
				return (NULL);
		} else {
			if (strlcpy(abspath, buf, sizeof (abspath)) >=
			    sizeof (abspath))
				return (NULL);
		}
		if (!device_exists(abspath))
			return (NULL);
	}

	if (s_realpath(link, buf) == NULL || !is_minor_node(buf, &minor_path)) {
		return (NULL);
	}
	return (lookup_minor(hdp, minor_path, NULL, TYPE_CACHE|CREATE_FLAG));
}


static void
resolve_dangling_links(struct di_devlink_handle *hdp)
{
	cache_minor_t *cmnp;
	cache_link_t *clp, **pp;

	for (pp = &(CACHE(hdp)->dngl); *pp != NULL; ) {
		clp = *pp;
		if ((cmnp = link2minor(hdp, clp)) != NULL) {
			*pp = clp->sib;
			clp->sib = cmnp->link;
			cmnp->link = clp;
			assert(clp->minor == NULL);
			clp->minor = cmnp;
		} else {
			dprintf(DBG_INFO, "resolve_dangling_links: link(%s):"
			    " unresolved\n", clp->path);
			pp = &clp->sib;
		}
	}
}


/*
 * The elements are assumed to be detached from the cache tree.
 */
static void
node_free(cache_node_t **pp)
{
	cache_node_t *cnp = *pp;

	*pp = NULL;

	if (cnp == NULL)
		return;

	free(cnp->path);
	free(cnp);
}

static void
minor_free(struct di_devlink_handle *hdp, cache_minor_t **pp)
{
	cache_minor_t *cmnp = *pp;

	*pp = NULL;

	if (cmnp == NULL)
		return;

	if (CACHE_LAST(hdp) == cmnp) {
		dprintf(DBG_STEP, "minor_free: last_minor(%s)\n", cmnp->name);
		CACHE_LAST(hdp) = NULL;
	}

	free(cmnp->name);
	free(cmnp->nodetype);
	free(cmnp);
}

static void
link_free(cache_link_t **pp)
{
	cache_link_t *clp = *pp;

	*pp = NULL;

	if (clp == NULL)
		return;

	free(clp->path);
	free(clp->content);
	free(clp);
}

/*
 * Returns the ':' preceding the minor name
 */
static char *
minor_colon(const char *path)
{
	char *cp;

	if ((cp = strrchr(path, '/')) == NULL) {
		return (NULL);
	}

	return (strchr(cp, ':'));
}

static void *
lookup_minor(
	struct di_devlink_handle *hdp,
	const char *minor_path,
	const char *nodetype,
	const int flags)
{
	void *vp;
	char *colon;
	char pdup[PATH_MAX];
	const char *fcn = "lookup_minor";

	if (minor_path == NULL) {
		errno = EINVAL;
		return (NULL);
	}

	(void) snprintf(pdup, sizeof (pdup), "%s", minor_path);

	if ((colon = minor_colon(pdup)) == NULL) {
		(void) dprintf(DBG_ERR, "%s: invalid minor path(%s)\n", fcn,
		    minor_path);
		errno = EINVAL;
		return (NULL);
	}
	*colon = '\0';

	if ((vp = get_last_minor(hdp, pdup, colon + 1, flags)) != NULL) {
		return (vp);
	}

	if ((vp = lookup_node(hdp, pdup, flags)) == NULL) {
		(void) dprintf(DBG_ERR, "%s: node(%s) not found\n", fcn, pdup);
		return (NULL);
	}
	*colon = ':';

	if (LOOKUP_CACHE(flags)) {
		cache_minor_t **pp;

		pp = &((cache_node_t *)vp)->minor;
		for (; *pp != NULL; pp = &(*pp)->sib) {
			if (strcmp((*pp)->name, colon + 1) == 0)
				break;
		}

		if (*pp == NULL && CREATE_ELEM(flags)) {
			*pp = minor_insert(hdp, vp, colon + 1, nodetype, pp);
		}
		set_last_minor(hdp, *pp, flags);

		return (*pp);
	} else {
		char *cp;
		uint32_t nidx;
		struct db_minor *dmp;

		nidx = (((struct db_node *)vp)->minor);
		for (; dmp = get_minor(hdp, nidx); nidx = dmp->sib) {
			cp = get_string(hdp, dmp->name);
			if (cp && strcmp(cp, colon + 1) == 0)
				break;
		}
		return (dmp);
	}
}

static void *
lookup_node(struct di_devlink_handle *hdp, char *path, const int flags)
{
	struct tnode tnd = {NULL};

	if (tnd.node = get_last_node(hdp, path, flags))
		return (tnd.node);

	tnd.handle = hdp;
	tnd.flags = flags;

	if (walk_tree(path, &tnd, visit_node) != 0)
		return (NULL);

	return (tnd.node);
}

/*
 * last_minor is used for nodes of TYPE_CACHE only.
 */
static void *
get_last_node(struct di_devlink_handle *hdp, const char *path, int flags)
{
	cache_node_t *cnp;

#ifdef	DEBUG
	if (getenv(SKIP_LAST_CACHE)) {
		(void) dprintf(DBG_INFO, "get_last_node: SKIPPING \"last\" "
		    "node cache\n");
		return (NULL);
	}
#endif

	if (!LOOKUP_CACHE(flags) || CACHE_LAST(hdp) == NULL ||
	    CACHE_LAST(hdp)->node == NULL) {
		return (NULL);
	}

	cnp = CACHE_LAST(hdp)->node;
	if (strcmp(cnp->path, path) == 0) {
		return (cnp);
	}

	cnp = cnp->sib;
	if (cnp && strcmp(cnp->path, path) == 0) {
		return (cnp);
	}

	return (NULL);
}

static void *
get_last_minor(
	struct di_devlink_handle *hdp,
	const char *devfs_path,
	const char *minor_name,
	int flags)
{
	cache_minor_t *cmnp;

#ifdef	DEBUG
	if (getenv(SKIP_LAST_CACHE)) {
		(void) dprintf(DBG_INFO, "get_last_minor: SKIPPING \"last\" "
		    "minor cache\n");
		return (NULL);
	}
#endif

	if (!LOOKUP_CACHE(flags) || CACHE_LAST(hdp) == NULL) {
		return (NULL);
	}

	cmnp = CACHE_LAST(hdp);
	if (strcmp(cmnp->name, minor_name) == 0 && cmnp->node &&
	    strcmp(cmnp->node->path, devfs_path) == 0) {
		return (cmnp);
	}

	cmnp = cmnp->sib;
	if (cmnp && strcmp(cmnp->name, minor_name) == 0 && cmnp->node &&
	    strcmp(cmnp->node->path, devfs_path) == 0) {
		set_last_minor(hdp, cmnp, TYPE_CACHE);
		return (cmnp);
	}

	return (NULL);
}

static void
set_last_minor(struct di_devlink_handle *hdp, cache_minor_t *cmnp, int flags)
{
#ifdef	DEBUG
	if (getenv(SKIP_LAST_CACHE)) {
		(void) dprintf(DBG_INFO, "set_last_minor: SKIPPING \"last\" "
		    "minor cache\n");
		return;
	}
#endif

	if (LOOKUP_CACHE(flags) && cmnp) {
		CACHE_LAST(hdp) = cmnp;
	}
}


/*
 * Returns 0 if normal return or -1 otherwise.
 */
static int
walk_tree(
	char *cur,
	void *arg,
	int (*node_callback)(const char *path, void *arg))
{
	char *slash, buf[PATH_MAX];

	if (cur == NULL || cur[0] != '/' || strlen(cur) > sizeof (buf) - 1) {
		errno = EINVAL;
		return (-1);
	}

	(void) strcpy(buf, "/");

	for (;;) {

		if (node_callback(buf, arg) != DI_WALK_CONTINUE)
			break;

		while (*cur == '/')
			cur++;

		if (*cur == '\0')
			break;

		/*
		 * There is a next component(s). Append a "/" separator for all
		 * but the first (root) component.
		 */
		if (buf[1] != '\0') {
			(void) strlcat(buf, "/", sizeof (buf));
		}

		if (slash = strchr(cur, '/')) {
			*slash = '\0';
			(void) strlcat(buf, cur, sizeof (buf));
			*slash = '/';
			cur = slash;
		} else {
			(void) strlcat(buf, cur, sizeof (buf));
			cur += strlen(cur);
		}

	}

	return (0);
}


static int
visit_node(const char *path, void *arg)
{
	struct tnode *tnp = arg;

	if (LOOKUP_CACHE(tnp->flags)) {

		cache_node_t *cnp = tnp->node;

		cnp = (cnp) ? cnp->child : CACHE_ROOT(tnp->handle);

		for (; cnp != NULL; cnp = cnp->sib) {
			if (strcmp(cnp->path, path) == 0)
				break;
		}
		if (cnp == NULL && CREATE_ELEM(tnp->flags)) {
			cnp = node_insert(tnp->handle, tnp->node, path,
			    INSERT_TAIL);
		}
		tnp->node = cnp;
	} else {
		char *cp;
		struct db_node *dnp = tnp->node;

		dnp = (dnp) ? get_node(tnp->handle, dnp->child)
		    : get_node(tnp->handle, DB_HDR(tnp->handle)->root_idx);

		for (; dnp != NULL; dnp = get_node(tnp->handle, dnp->sib)) {
			cp = get_string(tnp->handle, dnp->path);
			if (cp && strcmp(cp, path) == 0) {
				break;
			}
		}
		tnp->node = dnp;
	}

	/*
	 * Terminate walk if node is not found for a path component.
	 */
	return (tnp->node ? DI_WALK_CONTINUE : DI_WALK_TERMINATE);
}

static void
minor_delete(di_devlink_handle_t hdp, cache_minor_t *cmnp)
{
	cache_link_t **lpp;
	cache_minor_t **mpp;
	const char *fcn = "minor_delete";

	(void) dprintf(DBG_STEP, "%s: removing minor: %s\n", fcn, cmnp->name);

	/* detach minor from node */
	if (cmnp->node != NULL) {
		mpp = &cmnp->node->minor;
		for (; *mpp != NULL; mpp = &(*mpp)->sib) {
			if (*mpp == cmnp)
				break;
		}

		if (*mpp == NULL) {
			(void) dprintf(DBG_ERR, "%s: dangling minor: %s\n",
			    fcn, cmnp->name);
		} else {
			*mpp = cmnp->sib;
		}
	} else {
		(void) dprintf(DBG_ERR, "%s: orphan minor(%s)\n", fcn,
		    cmnp->name);
	}

	delete_unused_nodes(hdp, cmnp->node);

	cmnp->node = NULL;
	cmnp->sib = NULL;

	/* Move all remaining links to dangling list */
	for (lpp = &cmnp->link; *lpp != NULL; lpp = &(*lpp)->sib) {
		(*lpp)->minor = NULL;
	}
	*lpp = CACHE(hdp)->dngl;
	CACHE(hdp)->dngl = cmnp->link;
	cmnp->link = NULL;

	minor_free(hdp, &cmnp);
}

static void
delete_unused_nodes(di_devlink_handle_t hdp, cache_node_t *cnp)
{
	cache_node_t **npp;
	const char *fcn = "delete_unused_nodes";

	if (cnp == NULL)
		return;

	if (cnp->minor != NULL || cnp->child != NULL)
		return;

	(void) dprintf(DBG_INFO, "%s: removing unused node: %s\n", fcn,
	    cnp->path);

	/* Unlink node from tree */
	if (cnp->parent != NULL) {
		npp = &cnp->parent->child;
		for (; *npp != NULL; npp = &(*npp)->sib) {
			if (*npp == cnp)
				break;
		}

		if (*npp == NULL) {
			(void) dprintf(DBG_ERR, "%s: dangling node: %s\n", fcn,
			    cnp->path);
		} else {
			*npp = cnp->sib;
		}
	} else if (cnp == CACHE_ROOT(hdp)) {
		CACHE_ROOT(hdp) = NULL;
	} else {
		(void) dprintf(DBG_ERR, "%s: orphan node (%s)\n", fcn,
		    cnp->path);
	}

	delete_unused_nodes(hdp, cnp->parent);

	cnp->parent = cnp->sib = NULL;

	node_free(&cnp);
}

static int
rm_link(di_devlink_handle_t hdp, const char *link)
{
	cache_link_t *clp;
	const char *fcn = "rm_link";

	if (hdp == NULL || DB_ERR(hdp) || link == NULL || link[0] == '/' ||
	    (!HDL_RDWR(hdp) && !HDL_RDONLY(hdp))) {
		dprintf(DBG_ERR, "%s: %s: invalid args\n",
		    fcn, link ? link : "<NULL>");
		errno = EINVAL;
		return (-1);
	}

	dprintf(DBG_STEP, "%s: link(%s)\n", fcn, link);

	if ((clp = link_hash(hdp, link, UNLINK_FROM_HASH)) == NULL) {
		return (0);
	}

	link_delete(hdp, clp);

	return (0);
}

int
di_devlink_rm_link(di_devlink_handle_t hdp, const char *link)
{
	if (hdp == NULL || !HDL_RDWR(hdp)) {
		errno = EINVAL;
		return (-1);
	}

	return (rm_link(hdp, link));
}

static void
link_delete(di_devlink_handle_t hdp, cache_link_t *clp)
{
	cache_link_t **pp;
	const char *fcn = "link_delete";

	(void) dprintf(DBG_STEP, "%s: removing link: %s\n", fcn, clp->path);

	if (clp->minor == NULL)
		pp = &(CACHE(hdp)->dngl);
	else
		pp = &clp->minor->link;

	for (; *pp != NULL; pp = &(*pp)->sib) {
		if (*pp == clp)
			break;
	}

	if (*pp == NULL) {
		(void) dprintf(DBG_ERR, "%s: link(%s) not on list\n",
		    fcn, clp->path);
	} else {
		*pp = clp->sib;
	}

	delete_unused_minor(hdp, clp->minor);

	clp->minor = NULL;

	link_free(&clp);
}

static void
delete_unused_minor(di_devlink_handle_t hdp, cache_minor_t *cmnp)
{
	if (cmnp == NULL)
		return;

	if (cmnp->link != NULL)
		return;

	dprintf(DBG_STEP, "delete_unused_minor: removing minor(%s)\n",
	    cmnp->name);

	minor_delete(hdp, cmnp);
}

int
di_devlink_add_link(
	di_devlink_handle_t hdp,
	const char *link,
	const char *content,
	int flags)
{
	return (add_link(hdp, link, content, flags) != NULL ? 0 : -1);
}

static cache_link_t *
add_link(
	struct di_devlink_handle *hdp,
	const char *link,
	const char *content,
	int flags)
{
	uint32_t attr;
	cache_link_t *clp;
	cache_minor_t *cmnp;
	const char *fcn = "add_link";

	if (hdp == NULL || DB_ERR(hdp) || link == NULL ||
	    link[0] == '/' || content == NULL || !link_flag(flags) ||
	    (!HDL_RDWR(hdp) && !HDL_RDONLY(hdp))) {
		dprintf(DBG_ERR, "%s: %s: invalid args\n",
		    fcn, link ? link : "<NULL>");
		errno = EINVAL;
		return (NULL);
	}

	if ((clp = link_hash(hdp, link, 0)) != NULL) {
		if (link_cmp(clp, content, LINK_TYPE(flags)) != 0) {
			(void) rm_link(hdp, link);
		} else {
			return (clp);
		}
	}

	if (TYPE_PRI(flags)) {
		const char *minor_path = NULL;

		if (!is_minor_node(content, &minor_path)) {
			(void) dprintf(DBG_ERR, "%s: invalid content(%s)"
			    " for primary link\n", fcn, content);
			errno = EINVAL;
			return (NULL);
		}
		if ((cmnp = lookup_minor(hdp, minor_path, NULL,
		    TYPE_CACHE|CREATE_FLAG)) == NULL) {
			return (NULL);
		}
		attr = A_PRIMARY;
	} else {
		/*
		 * Defer resolving a secondary link to a minor until the
		 * database is closed. This ensures that the primary link
		 * (required for a successful resolve) has also been created.
		 */
		cmnp = NULL;
		attr = A_SECONDARY;
	}

	return (link_insert(hdp, cmnp, link, content, attr));
}

/*
 * Returns 0 on match or 1 otherwise.
 */
static int
link_cmp(cache_link_t *clp, const char *content, int type)
{
	if (strcmp(clp->content, content) != 0)
		return (1);

	if (attr2type(clp->attr) != type)
		return (1);

	return (0);
}

int
di_devlink_update(di_devlink_handle_t hdp)
{
	if (hdp == NULL || !HDL_RDWR(hdp) || DB_ERR(hdp)) {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Reset the counter to schedule a synchronization with /dev on the next
	 * di_devlink_close().
	 */
	CACHE(hdp)->update_count = 0;

	return (0);
}

static int
synchronize_db(di_devlink_handle_t hdp)
{
	int hval;
	cache_link_t *clp;
	char pdup[PATH_MAX];
	recurse_t rec = {NULL};
	const char *fcn = "synchronize_db";

	rec.data = NULL;
	rec.fcn = cache_dev_link;

	/*
	 * Walk through $ROOT/dev, reading every link and marking the
	 * corresponding cached version as valid(adding new links as needed).
	 * Then walk through the cache and remove all unmarked links.
	 */
	if (recurse_dev(hdp, &rec) != 0) {
		return (-1);
	}

	for (hval = 0; hval < CACHE(hdp)->hash_sz; hval++) {
		for (clp = CACHE_HASH(hdp, hval); clp != NULL; ) {
			if (GET_VALID_ATTR(clp->attr)) {
				CLR_VALID_ATTR(clp->attr);
				clp = clp->hash;
				continue;
			}

			/*
			 * The link is stale, so remove it. Since the link
			 * will be destroyed, use a copy of the link path to
			 * invoke the remove function.
			 */
			(void) snprintf(pdup, sizeof (pdup), "%s", clp->path);
			clp = clp->hash;
			(void) dprintf(DBG_STEP, "%s: removing invalid link:"
			    " %s\n", fcn, pdup);
			(void) di_devlink_rm_link(hdp, pdup);
		}
	}

	(void) dprintf(DBG_STEP, "%s: update completed\n", fcn);

	return (0);
}

static di_devlink_handle_t
di_devlink_init_impl(const char *root, const char *name, uint_t flags)
{
	int	err = 0;

	if ((flags != 0 && flags != DI_MAKE_LINK) ||
	    (flags == 0 && name != NULL)) {
		errno = EINVAL;
		return (NULL);
	}

	if ((flags == DI_MAKE_LINK) &&
	    (err = devlink_create(root, name, DCA_DEVLINK_CACHE))) {
		errno = err;
		return (NULL);
	}

	(void) dprintf(DBG_INFO, "devlink_init_impl: success\n");

	return (devlink_snapshot(root));
}

di_devlink_handle_t
di_devlink_init(const char *name, uint_t flags)
{
	return (di_devlink_init_impl("/", name, flags));
}

di_devlink_handle_t
di_devlink_init_root(const char *root, const char *name, uint_t flags)
{
	return (di_devlink_init_impl(root, name, flags));
}

static di_devlink_handle_t
devlink_snapshot(const char *root_dir)
{
	struct di_devlink_handle *hdp;
	int		err;
	static int	retried = 0;

	if ((hdp = handle_alloc(root_dir, OPEN_RDONLY)) == NULL) {
		return (NULL);
	}

	/*
	 * We don't need to lock.  If a consumer wants the very latest db
	 * then it must perform a di_devlink_init with the DI_MAKE_LINK
	 * flag to force a sync with devfsadm first.  Otherwise, the
	 * current database file is opened and mmaped on demand: the rename
	 * associated with a db update does not change the contents
	 * of files already opened.
	 */
again:	err = open_db(hdp, OPEN_RDONLY);

	/*
	 * If we failed to open DB the most likely cause is that DB file did
	 * not exist. If we have not done a retry, signal devfsadmd to
	 * recreate the DB file and retry. If we fail to open the DB after
	 * retry, we will walk /dev in di_devlink_walk.
	 */
	if (err && (retried == 0)) {
		retried++;
		(void) devlink_create(root_dir, NULL, DCA_DEVLINK_SYNC);
		goto again;
	}
	return (hdp);
}

int
di_devlink_fini(di_devlink_handle_t *pp)
{
	if (pp == NULL || *pp == NULL || !HDL_RDONLY(*pp)) {
		errno = EINVAL;
		return (-1);
	}

	/* Freeing the handle also closes the DB */
	handle_free(pp);

	return (0);
}

int
di_devlink_walk(
	di_devlink_handle_t hdp,
	const char *re,
	const char *minor_path,
	uint_t flags,
	void *arg,
	int (*devlink_callback)(di_devlink_t, void *))
{
	int rv;
	regex_t reg;
	link_desc_t linkd = {NULL};

	if (hdp == NULL || !HDL_RDONLY(hdp)) {
		errno = EINVAL;
		return (-1);
	}

	linkd.minor_path = minor_path;
	linkd.flags = flags;
	linkd.arg = arg;
	linkd.fcn = devlink_callback;

	if (re) {
		if (regcomp(&reg, re, REG_EXTENDED) != 0)
			return (-1);
		linkd.regp = &reg;
	}

	if (check_args(&linkd)) {
		errno = EINVAL;
		rv = -1;
		goto out;
	}

	if (DB_OPEN(hdp)) {
		rv = walk_db(hdp, &linkd);
	} else {
		rv = walk_dev(hdp, &linkd);
	}

out:
	if (re) {
		regfree(&reg);
	}

	return (rv ? -1 : 0);
}

static int
link_flag(uint_t flags)
{
	if (flags != 0 && flags != DI_PRIMARY_LINK &&
	    flags != DI_SECONDARY_LINK) {
		return (0);
	}

	return (1);
}

/*
 * Currently allowed flags are:
 *	DI_PRIMARY_LINK
 *	DI_SECONDARY_LINK
 */
static int
check_args(link_desc_t *linkp)
{
	if (linkp->fcn == NULL)
		return (-1);

	if (!link_flag(linkp->flags)) {
		return (-1);
	}

	/*
	 * Minor path can be NULL. In that case, all links will be
	 * selected.
	 */
	if (linkp->minor_path) {
		if (linkp->minor_path[0] != '/' ||
		    minor_colon(linkp->minor_path) == NULL) {
			return (-1);
		}
	}

	return (0);
}


/*
 * Walk all links in database if no minor path is specified.
 */
static int
walk_db(struct di_devlink_handle *hdp, link_desc_t *linkp)
{
	assert(DB_OPEN(hdp));

	if (linkp->minor_path == NULL) {
		return (walk_all_links(hdp, linkp));
	} else {
		return (walk_matching_links(hdp, linkp));
	}
}

static int
cache_dev(struct di_devlink_handle *hdp)
{
	size_t sz;
	recurse_t rec = {NULL};

	assert(hdp);
	assert(HDL_RDONLY(hdp));

	if (hdp == NULL || !HDL_RDONLY(hdp)) {
		dprintf(DBG_ERR, "cache_dev: invalid arg\n");
		return (-1);
	}

	sz = MIN_HASH_SIZE;

	CACHE(hdp)->hash = calloc(sz, sizeof (cache_link_t *));
	if (CACHE(hdp)->hash == NULL) {
		return (-1);
	}
	CACHE(hdp)->hash_sz = sz;

	rec.data = NULL;
	rec.fcn = cache_dev_link;

	return (recurse_dev(hdp, &rec));
}

static int
walk_dev(struct di_devlink_handle *hdp, link_desc_t *linkp)
{
	assert(hdp && linkp);
	assert(!DB_OPEN(hdp));
	assert(HDL_RDONLY(hdp));

	if (hdp == NULL || !HDL_RDONLY(hdp) || DB_OPEN(hdp)) {
		dprintf(DBG_ERR, "walk_dev: invalid args\n");
		return (-1);
	}

	if (CACHE_EMPTY(hdp) && cache_dev(hdp) != 0) {
		dprintf(DBG_ERR, "walk_dev: /dev caching failed\n");
		return (-1);
	}

	if (linkp->minor_path)
		walk_cache_minor(hdp, linkp->minor_path, linkp);
	else
		walk_all_cache(hdp, linkp);

	return (linkp->retval);
}

/* ARGSUSED */
static int
cache_dev_link(struct di_devlink_handle *hdp, void *data, const char *link)
{
	int flags;
	cache_link_t *clp;
	char content[PATH_MAX];

	assert(HDL_RDWR(hdp) || HDL_RDONLY(hdp));

	if (s_readlink(link, content, sizeof (content)) < 0) {
		return (DI_WALK_CONTINUE);
	}

	if (is_minor_node(content, NULL)) {
		flags = DI_PRIMARY_LINK;
	} else {
		flags = DI_SECONDARY_LINK;
	}

	assert(strncmp(link, hdp->dev_dir, strlen(hdp->dev_dir)) == 0);

	/*
	 * Store only the part after <root-dir>/dev/
	 */
	link += strlen(hdp->dev_dir) + 1;

	if ((clp = add_link(hdp, link, content, flags)) != NULL) {
		SET_VALID_ATTR(clp->attr);
	}

	return (DI_WALK_CONTINUE);
}


static int
walk_all_links(struct di_devlink_handle *hdp, link_desc_t *linkp)
{
	struct db_link *dlp;
	uint32_t nidx, eidx;

	assert(DB_NUM(hdp, DB_LINK) >= 1);

	eidx = DB_NUM(hdp, DB_LINK);

	/* Skip the "NIL" (index == 0) link. */
	for (nidx = 1; nidx < eidx; nidx++) {
		/*
		 * Declare this local to the block with zero
		 * initializer so that it gets rezeroed
		 * for each iteration.
		 */
		struct di_devlink vlink = {NULL};

		if ((dlp = get_link(hdp, nidx)) == NULL)
			continue;

		vlink.rel_path = get_string(hdp, dlp->path);
		vlink.content = get_string(hdp, dlp->content);
		vlink.type = attr2type(dlp->attr);

		if (visit_link(hdp, linkp, &vlink) != DI_WALK_CONTINUE) {
			break;
		}
	}

	return (linkp->retval);
}

static int
walk_matching_links(struct di_devlink_handle *hdp, link_desc_t *linkp)
{
	uint32_t nidx;
	struct db_link *dlp;
	struct db_minor *dmp;

	assert(linkp->minor_path != NULL);

	dmp = lookup_minor(hdp, linkp->minor_path, NULL, TYPE_DB);

	/*
	 * If a minor matching the path exists, walk that minor's devlinks list.
	 * Then walk the dangling devlinks list. Non-matching devlinks will be
	 * filtered out in visit_link.
	 */
	for (;;) {
		nidx = dmp ? dmp->link : DB_HDR(hdp)->dngl_idx;
		for (; dlp = get_link(hdp, nidx); nidx = dlp->sib) {
			struct di_devlink vlink = {NULL};

			vlink.rel_path = get_string(hdp, dlp->path);
			vlink.content = get_string(hdp, dlp->content);
			vlink.type = attr2type(dlp->attr);

			if (visit_link(hdp, linkp, &vlink) != DI_WALK_CONTINUE)
				goto out;
		}
		if (dmp == NULL) {
			break;
		} else {
			dmp = NULL;
		}
	}

out:
	return (linkp->retval);
}

static int
visit_link(
	struct di_devlink_handle *hdp,
	link_desc_t *linkp,
	struct di_devlink *vlp)
{
	struct stat sbuf;
	const char *minor_path = NULL;
	char abs_path[PATH_MAX], cont[PATH_MAX];

	/*
	 * It is legal for the link's content and type to be unknown.
	 * but one of absolute or relative path must be set.
	 */
	if (vlp->rel_path == NULL && vlp->abs_path == NULL) {
		(void) dprintf(DBG_ERR, "visit_link: invalid arguments\n");
		return (DI_WALK_CONTINUE);
	}

	if (vlp->rel_path == NULL) {
		vlp->rel_path = (char *)rel_path(hdp, vlp->abs_path);
		if (vlp->rel_path == NULL || vlp->rel_path[0] == '\0')
			return (DI_WALK_CONTINUE);
	}

	if (linkp->regp) {
		if (regexec(linkp->regp, vlp->rel_path, 0, NULL, 0) != 0)
			return (DI_WALK_CONTINUE);
	}

	if (vlp->abs_path == NULL) {
		assert(vlp->rel_path[0] != '/');
		(void) snprintf(abs_path, sizeof (abs_path), "%s/%s",
		    hdp->dev_dir, vlp->rel_path);
		vlp->abs_path = abs_path;
	}

	if (vlp->content == NULL) {
		if (s_readlink(vlp->abs_path, cont, sizeof (cont)) < 0) {
			return (DI_WALK_CONTINUE);
		}
		vlp->content = cont;
	}


	if (vlp->type == 0) {
		if (is_minor_node(vlp->content, &minor_path)) {
			vlp->type = DI_PRIMARY_LINK;
		} else {
			vlp->type = DI_SECONDARY_LINK;
		}
	}

	/*
	 * Filter based on minor path
	 */
	if (linkp->minor_path) {
		char tmp[PATH_MAX];

		/*
		 * derive minor path
		 */
		if (vlp->type == DI_SECONDARY_LINK) {

#ifdef	DEBUG
			/*LINTED*/
			assert(sizeof (tmp) >= PATH_MAX);
#endif
			if (s_realpath(vlp->abs_path, tmp) == NULL)
				return (DI_WALK_CONTINUE);

			if (!is_minor_node(tmp, &minor_path))
				return (DI_WALK_CONTINUE);

		} else if (minor_path == NULL) {
			if (!is_minor_node(vlp->content, &minor_path))
				return (DI_WALK_CONTINUE);
		}

		assert(minor_path != NULL);

		if (strcmp(linkp->minor_path, minor_path) != 0)
			return (DI_WALK_CONTINUE);
	}

	/*
	 * Filter based on link type
	 */
	if (!TYPE_NONE(linkp->flags) && LINK_TYPE(linkp->flags) != vlp->type) {
		return (DI_WALK_CONTINUE);
	}

	if (lstat(vlp->abs_path, &sbuf) < 0) {
		dprintf(DBG_ERR, "visit_link: %s: lstat failed: %s\n",
		    vlp->abs_path, strerror(errno));
		return (DI_WALK_CONTINUE);
	}

	return (linkp->fcn(vlp, linkp->arg));
}

static int
devlink_valid(di_devlink_t devlink)
{
	if (devlink == NULL || devlink->rel_path == NULL ||
	    devlink->abs_path == NULL || devlink->content == NULL ||
	    TYPE_NONE(devlink->type)) {
		return (0);
	}

	return (1);
}

const char *
di_devlink_path(di_devlink_t devlink)
{
	if (!devlink_valid(devlink)) {
		errno = EINVAL;
		return (NULL);
	}

	return (devlink->abs_path);
}

const char *
di_devlink_content(di_devlink_t devlink)
{
	if (!devlink_valid(devlink)) {
		errno = EINVAL;
		return (NULL);
	}

	return (devlink->content);
}

int
di_devlink_type(di_devlink_t devlink)
{
	if (!devlink_valid(devlink)) {
		errno = EINVAL;
		return (-1);
	}

	return (devlink->type);
}

di_devlink_t
di_devlink_dup(di_devlink_t devlink)
{
	struct di_devlink *duplink;

	if (!devlink_valid(devlink)) {
		errno = EINVAL;
		return (NULL);
	}

	if ((duplink = calloc(1, sizeof (struct di_devlink))) == NULL) {
		return (NULL);
	}

	duplink->rel_path = strdup(devlink->rel_path);
	duplink->abs_path = strdup(devlink->abs_path);
	duplink->content  = strdup(devlink->content);
	duplink->type	  = devlink->type;

	if (!devlink_valid(duplink)) {
		(void) di_devlink_free(duplink);
		errno = ENOMEM;
		return (NULL);
	}

	return (duplink);
}

int
di_devlink_free(di_devlink_t devlink)
{
	if (devlink == NULL) {
		errno = EINVAL;
		return (-1);
	}

	free(devlink->rel_path);
	free(devlink->abs_path);
	free(devlink->content);
	free(devlink);

	return (0);
}

/*
 * Obtain path relative to dev_dir
 */
static const char *
rel_path(struct di_devlink_handle *hdp, const char *path)
{
	const size_t len = strlen(hdp->dev_dir);

	if (strncmp(path, hdp->dev_dir, len) != 0)
		return (NULL);

	if (path[len] == '\0')
		return (&path[len]);

	if (path[len] != '/')
		return (NULL);

	return (&path[len+1]);
}

static int
recurse_dev(struct di_devlink_handle *hdp, recurse_t *rp)
{
	int ret = 0;

	(void) do_recurse(hdp->dev_dir, hdp, rp, &ret);

	return (ret);
}

static int
do_recurse(
	const char *dir,
	struct di_devlink_handle *hdp,
	recurse_t *rp,
	int *retp)
{
	size_t len;
	const char *rel;
	struct stat sbuf;
	char cur[PATH_MAX], *cp;
	int i, rv = DI_WALK_CONTINUE;
	finddevhdl_t handle;
	char *d_name;


	if ((rel = rel_path(hdp, dir)) == NULL)
		return (DI_WALK_CONTINUE);

	/*
	 * Skip directories we are not interested in.
	 */
	for (i = 0; i < N_SKIP_DIRS; i++) {
		if (strcmp(rel, skip_dirs[i]) == 0) {
			(void) dprintf(DBG_STEP, "do_recurse: skipping %s\n",
			    dir);
			return (DI_WALK_CONTINUE);
		}
	}

	(void) dprintf(DBG_STEP, "do_recurse: dir = %s\n", dir);

	if (finddev_readdir(dir, &handle) != 0)
		return (DI_WALK_CONTINUE);

	(void) snprintf(cur, sizeof (cur), "%s/", dir);
	len = strlen(cur);
	cp = cur + len;
	len = sizeof (cur) - len;

	for (;;) {
		if ((d_name = (char *)finddev_next(handle)) == NULL)
			break;

		if (strlcpy(cp, d_name, len) >= len)
			break;

		/*
		 * Skip files we are not interested in.
		 */
		for (i = 0; i < N_SKIP_FILES; i++) {

			rel = rel_path(hdp, cur);
			if (rel == NULL || strcmp(rel, skip_files[i]) == 0) {
				(void) dprintf(DBG_STEP,
				    "do_recurse: skipping %s\n", cur);
				goto next_entry;
			}
		}

		if (lstat(cur, &sbuf) == 0) {
			if (S_ISDIR(sbuf.st_mode)) {
				rv = do_recurse(cur, hdp, rp, retp);
			} else if (S_ISLNK(sbuf.st_mode)) {
				rv = rp->fcn(hdp, rp->data, cur);
			} else {
				(void) dprintf(DBG_STEP,
				    "do_recurse: Skipping entry: %s\n", cur);
			}
		} else {
			(void) dprintf(DBG_ERR, "do_recurse: cur(%s): lstat"
			    " failed: %s\n", cur, strerror(errno));
		}

next_entry:
		*cp = '\0';

		if (rv != DI_WALK_CONTINUE)
			break;
	}

	finddev_close(handle);

	return (rv);
}


static int
check_attr(uint32_t attr)
{
	switch (attr & A_LINK_TYPES) {
		case A_PRIMARY:
		case A_SECONDARY:
			return (1);
		default:
			dprintf(DBG_ERR, "check_attr: incorrect attr(%u)\n",
			    attr);
			return (0);
	}
}

static int
attr2type(uint32_t attr)
{
	switch (attr & A_LINK_TYPES) {
		case A_PRIMARY:
			return (DI_PRIMARY_LINK);
		case A_SECONDARY:
			return (DI_SECONDARY_LINK);
		default:
			dprintf(DBG_ERR, "attr2type: incorrect attr(%u)\n",
			    attr);
			return (0);
	}
}

/* Allocate new node and link it in */
static cache_node_t *
node_insert(
	struct di_devlink_handle *hdp,
	cache_node_t *pcnp,
	const char *path,
	int insert)
{
	cache_node_t *cnp;

	if (path == NULL) {
		errno = EINVAL;
		SET_DB_ERR(hdp);
		return (NULL);
	}

	if ((cnp = calloc(1, sizeof (cache_node_t))) == NULL) {
		SET_DB_ERR(hdp);
		return (NULL);
	}

	if ((cnp->path = strdup(path)) == NULL) {
		SET_DB_ERR(hdp);
		free(cnp);
		return (NULL);
	}

	cnp->parent = pcnp;

	if (pcnp == NULL) {
		assert(strcmp(path, "/") == 0);
		assert(CACHE(hdp)->root == NULL);
		CACHE(hdp)->root = cnp;
	} else if (insert == INSERT_HEAD) {
		cnp->sib = pcnp->child;
		pcnp->child = cnp;
	} else if (CACHE_LAST(hdp) && CACHE_LAST(hdp)->node &&
	    CACHE_LAST(hdp)->node->parent == pcnp &&
	    CACHE_LAST(hdp)->node->sib == NULL) {

		CACHE_LAST(hdp)->node->sib = cnp;

	} else {
		cache_node_t **pp;

		for (pp = &pcnp->child; *pp != NULL; pp = &(*pp)->sib)
			;
		*pp = cnp;
	}

	return (cnp);
}

/*
 * Allocate a new minor and link it in either at the tail or head
 * of the minor list depending on the value of "prev".
 */
static cache_minor_t *
minor_insert(
	struct di_devlink_handle *hdp,
	cache_node_t *pcnp,
	const char *name,
	const char *nodetype,
	cache_minor_t **prev)
{
	cache_minor_t *cmnp;

	if (pcnp == NULL || name == NULL) {
		errno = EINVAL;
		SET_DB_ERR(hdp);
		return (NULL);
	}

	/*
	 * Some pseudo drivers don't specify nodetype. Assume pseudo if
	 * nodetype is not specified.
	 */
	if (nodetype == NULL)
		nodetype = DDI_PSEUDO;

	if ((cmnp = calloc(1, sizeof (cache_minor_t))) == NULL) {
		SET_DB_ERR(hdp);
		return (NULL);
	}

	cmnp->name = strdup(name);
	cmnp->nodetype = strdup(nodetype);
	if (cmnp->name == NULL || cmnp->nodetype == NULL) {
		SET_DB_ERR(hdp);
		free(cmnp->name);
		free(cmnp->nodetype);
		free(cmnp);
		return (NULL);
	}

	cmnp->node = pcnp;

	/* Add to node's minor list */
	if (prev == NULL) {
		cmnp->sib = pcnp->minor;
		pcnp->minor = cmnp;
	} else {
		assert(*prev == NULL);
		*prev = cmnp;
	}

	return (cmnp);
}

static cache_link_t *
link_insert(
	struct di_devlink_handle *hdp,
	cache_minor_t *cmnp,
	const char *path,
	const char *content,
	uint32_t attr)
{
	cache_link_t *clp;

	if (path == NULL || content == NULL || !check_attr(attr)) {
		errno = EINVAL;
		SET_DB_ERR(hdp);
		return (NULL);
	}

	if ((clp = calloc(1, sizeof (cache_link_t))) == NULL) {
		SET_DB_ERR(hdp);
		return (NULL);
	}

	clp->path = strdup(path);
	clp->content = strdup(content);
	if (clp->path == NULL || clp->content == NULL) {
		SET_DB_ERR(hdp);
		link_free(&clp);
		return (NULL);
	}

	clp->attr = attr;
	hash_insert(hdp, clp);
	clp->minor = cmnp;

	/* Add to minor's link list */
	if (cmnp != NULL) {
		clp->sib = cmnp->link;
		cmnp->link = clp;
	} else {
		clp->sib = CACHE(hdp)->dngl;
		CACHE(hdp)->dngl = clp;
	}

	return (clp);
}

static void
hash_insert(struct di_devlink_handle *hdp, cache_link_t *clp)
{
	uint_t hval;

	hval = hashfn(hdp, clp->path);
	clp->hash = CACHE_HASH(hdp, hval);
	CACHE_HASH(hdp, hval) = clp;
}


static struct db_node *
get_node(struct di_devlink_handle *hdp, uint32_t idx)
{
	return (map_seg(hdp, idx, PROT_READ, DB_NODE));
}

static struct db_node *
set_node(struct di_devlink_handle *hdp, uint32_t idx)
{
	return (map_seg(hdp, idx, PROT_READ | PROT_WRITE, DB_NODE));
}

static struct db_minor *
get_minor(struct di_devlink_handle *hdp, uint32_t idx)
{
	return (map_seg(hdp, idx, PROT_READ, DB_MINOR));
}

static struct db_minor *
set_minor(struct di_devlink_handle *hdp, uint32_t idx)
{
	return (map_seg(hdp, idx, PROT_READ | PROT_WRITE, DB_MINOR));
}

static struct db_link *
get_link(struct di_devlink_handle *hdp, uint32_t idx)
{
	return (map_seg(hdp, idx, PROT_READ, DB_LINK));
}

static struct db_link *
set_link(struct di_devlink_handle *hdp, uint32_t idx)
{
	return (map_seg(hdp, idx, PROT_READ | PROT_WRITE, DB_LINK));
}

static char *
get_string(struct di_devlink_handle *hdp, uint32_t idx)
{
	return (map_seg(hdp, idx, PROT_READ, DB_STR));
}

static char *
set_string(struct di_devlink_handle *hdp, uint32_t idx)
{
	return (map_seg(hdp, idx, PROT_READ | PROT_WRITE, DB_STR));
}


/*
 * Returns the element corresponding to idx. If the portion of file involved
 * is not yet mapped, does an mmap() as well. Existing mappings are not changed.
 */
static void *
map_seg(
	struct di_devlink_handle *hdp,
	uint32_t idx,
	int prot,
	db_seg_t seg)
{
	int s;
	off_t off;
	size_t slen;
	caddr_t addr;

	if (idx == DB_NIL) {
		return (NULL);
	}

	if (!VALID_INDEX(hdp, seg, idx)) {
		(void) dprintf(DBG_ERR, "map_seg: seg(%d): invalid idx(%u)\n",
		    seg, idx);
		return (NULL);
	}

	/*
	 * If the seg is already mapped in, use it if the access type is
	 * valid.
	 */
	if (DB_SEG(hdp, seg) != NULL) {
		if (DB_SEG_PROT(hdp, seg) != prot) {
			(void) dprintf(DBG_ERR, "map_seg: illegal access: "
			    "seg[%d]: idx=%u, seg_prot=%d, access=%d\n",
			    seg, idx, DB_SEG_PROT(hdp, seg), prot);
			return (NULL);
		}
		return (DB_SEG(hdp, seg) + idx * elem_sizes[seg]);
	}

	/*
	 * Segment is not mapped. Mmap() the segment.
	 */
	off = seg_size(hdp, DB_HEADER);
	for (s = 0; s < seg; s++) {
		off += seg_size(hdp, s);
	}
	slen = seg_size(hdp, seg);

	addr = mmap(0, slen, prot, MAP_SHARED, DB(hdp)->db_fd, off);
	if (addr == MAP_FAILED) {
		(void) dprintf(DBG_ERR, "map_seg: seg[%d]: mmap failed: %s\n",
		    seg, strerror(errno));
		(void) dprintf(DBG_ERR, "map_seg: args: len=%lu, prot=%d,"
		    " fd=%d, off=%ld\n", (ulong_t)slen, prot, DB(hdp)->db_fd,
		    off);
		return (NULL);
	}

	DB_SEG(hdp, seg) = addr;
	DB_SEG_PROT(hdp, seg) = prot;

	(void) dprintf(DBG_STEP, "map_seg: seg[%d]: len=%lu, prot=%d, fd=%d, "
	    "off=%ld, seg_base=%p\n", seg, (ulong_t)slen, prot, DB(hdp)->db_fd,
	    off, (void *)addr);

	return (DB_SEG(hdp, seg) + idx * elem_sizes[seg]);
}

/*
 * Computes the size of a segment rounded up to the nearest page boundary.
 */
static size_t
seg_size(struct di_devlink_handle *hdp, int seg)
{
	size_t sz;

	assert(DB_HDR(hdp)->page_sz);

	if (seg == DB_HEADER) {
		sz = HDR_LEN;
	} else {
		assert(DB_NUM(hdp, seg) >= 1);
		sz = DB_NUM(hdp, seg) * elem_sizes[seg];
	}

	sz = (sz / DB_HDR(hdp)->page_sz) + 1;

	sz *= DB_HDR(hdp)->page_sz;

	return (sz);
}

static size_t
size_db(struct di_devlink_handle *hdp, long page_sz, uint32_t *count)
{
	int i;
	size_t sz;
	cache_link_t *clp;

	assert(page_sz > 0);

	/* Take "NIL" element into account */
	for (i = 0; i < DB_TYPES; i++) {
		count[i] = 1;
	}

	count_node(CACHE(hdp)->root, count);

	for (clp = CACHE(hdp)->dngl; clp != NULL; clp = clp->sib) {
		count_link(clp, count);
	}

	sz = ((HDR_LEN / page_sz) + 1) * page_sz;
	for (i = 0; i < DB_TYPES; i++) {
		assert(count[i] >= 1);
		sz += (((count[i] * elem_sizes[i]) / page_sz) + 1) * page_sz;
		(void) dprintf(DBG_INFO, "N[%u]=%u\n", i, count[i]);
	}
	(void) dprintf(DBG_INFO, "DB size=%lu\n", (ulong_t)sz);

	return (sz);
}


static void
count_node(cache_node_t *cnp, uint32_t *count)
{
	cache_minor_t *cmnp;

	if (cnp == NULL)
		return;

	count[DB_NODE]++;
	count_string(cnp->path, count);

	for (cmnp = cnp->minor; cmnp != NULL; cmnp = cmnp->sib) {
		count_minor(cmnp, count);
	}

	for (cnp = cnp->child; cnp != NULL; cnp = cnp->sib) {
		count_node(cnp, count);
	}

}

static void
count_minor(cache_minor_t *cmnp, uint32_t *count)
{
	cache_link_t *clp;

	if (cmnp == NULL)
		return;

	count[DB_MINOR]++;
	count_string(cmnp->name, count);
	count_string(cmnp->nodetype, count);

	for (clp = cmnp->link; clp != NULL; clp = clp->sib) {
		count_link(clp, count);
	}
}

static void
count_link(cache_link_t *clp, uint32_t *count)
{
	if (clp == NULL)
		return;

	count[DB_LINK]++;
	count_string(clp->path, count);
	count_string(clp->content, count);
}


static void
count_string(const char *str, uint32_t *count)
{
	if (str == NULL) {
		(void) dprintf(DBG_ERR, "count_string: NULL argument\n");
		return;
	}

	count[DB_STR] += strlen(str) + 1;
}

static uint_t
hashfn(struct di_devlink_handle *hdp, const char *str)
{
	const char *cp;
	ulong_t hval = 0;

	if (str == NULL) {
		return (0);
	}

	assert(CACHE(hdp)->hash_sz >= MIN_HASH_SIZE);

	for (cp = str; *cp != '\0'; cp++) {
		hval += *cp;
	}

	return (hval % CACHE(hdp)->hash_sz);
}

/*
 * enter_db_lock()
 *
 * If the handle is IS_RDWR then we lock as writer to "update" database,
 * if IS_RDONLY then we lock as reader to "snapshot" database. The
 * implementation uses advisory file locking.
 *
 * This function returns:
 *   == 1	success and grabbed the lock file, we can open the DB.
 *   == 0	success but did not lock the lock file,	reader must walk
 *		the /dev directory.
 *   == -1	failure.
 */
static int
enter_db_lock(struct di_devlink_handle *hdp, const char *root_dir)
{
	int		fd;
	struct flock	lock;
	char		lockfile[PATH_MAX];
	int		rv;
	int		writer = HDL_RDWR(hdp);
	static int	did_sync = 0;
	int		eintrs;

	assert(hdp->lock_fd < 0);

	get_db_path(hdp, DB_LOCK, lockfile, sizeof (lockfile));

	dprintf(DBG_LCK, "enter_db_lock: %s BEGIN\n",
	    writer ? "update" : "snapshot");

	/* Record locks are per-process. Protect against multiple threads. */
	(void) mutex_lock(&update_mutex);

again:	if ((fd = open(lockfile,
	    (writer ? (O_RDWR|O_CREAT) : O_RDONLY), DB_LOCK_PERMS)) < 0) {
		/*
		 * Typically the lock file and the database go hand in hand.
		 * If we find that the lock file does not exist (for some
		 * unknown reason) and we are the reader then we return
		 * success (after triggering devfsadm to create the file and
		 * a retry) so that we can still provide service via slow
		 * /dev walk.  If we get a failure as a writer we want the
		 * error to manifests itself.
		 */
		if ((errno == ENOENT) && !writer) {
			/* If reader, signal once to get files created */
			if (did_sync == 0) {
				did_sync = 1;
				dprintf(DBG_LCK, "enter_db_lock: %s OSYNC\n",
				    writer ? "update" : "snapshot");

				/* signal to get files created */
				(void) devlink_create(root_dir, NULL,
				    DCA_DEVLINK_SYNC);
				goto again;
			}
			dprintf(DBG_LCK, "enter_db_lock: %s OPENFAILD %s: "
			    "WALK\n", writer ? "update" : "snapshot",
			    strerror(errno));
			(void) mutex_unlock(&update_mutex);
			return (0);		/* success, but not locked */
		} else {
			dprintf(DBG_LCK, "enter_db_lock: %s OPENFAILD %s\n",
			    writer ? "update" : "snapshot", strerror(errno));
			(void) mutex_unlock(&update_mutex);
			return (-1);		/* failed */
		}
	}

	lock.l_type = writer ? F_WRLCK : F_RDLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	/* Enter the lock. */
	for (eintrs = 0; eintrs < MAX_LOCK_RETRY; eintrs++) {
		rv = fcntl(fd, F_SETLKW, &lock);
		if ((rv != -1) || (errno != EINTR))
			break;
	}

	if (rv != -1) {
		hdp->lock_fd = fd;
		dprintf(DBG_LCK, "enter_db_lock: %s LOCKED\n",
		    writer ? "update" : "snapshot");
		return (1);		/* success, locked */
	}

	(void) close(fd);
	dprintf(DBG_ERR, "enter_db_lock: %s FAILED: %s: WALK\n",
	    writer ? "update" : "snapshot", strerror(errno));
	(void) mutex_unlock(&update_mutex);
	return (-1);
}

/*
 * Close and re-open lock file every time so that it is recreated if deleted.
 */
static void
exit_db_lock(struct di_devlink_handle *hdp)
{
	struct flock	unlock;
	int		writer = HDL_RDWR(hdp);

	if (hdp->lock_fd < 0) {
		return;
	}

	unlock.l_type = F_UNLCK;
	unlock.l_whence = SEEK_SET;
	unlock.l_start = 0;
	unlock.l_len = 0;

	dprintf(DBG_LCK, "exit_db_lock : %s UNLOCKED\n",
	    writer ? "update" : "snapshot");
	if (fcntl(hdp->lock_fd, F_SETLK, &unlock) == -1) {
		dprintf(DBG_ERR, "exit_db_lock : %s failed: %s\n",
		    writer ? "update" : "snapshot", strerror(errno));
	}

	(void) close(hdp->lock_fd);

	hdp->lock_fd = -1;

	(void) mutex_unlock(&update_mutex);
}

/*
 * returns 1 if contents is a minor node in /devices.
 * If mn_root is not NULL, mn_root is set to:
 *	if contents is a /dev node, mn_root = contents
 *			OR
 *	if contents is a /devices node, mn_root set to the '/'
 *	following /devices.
 */
int
is_minor_node(const char *contents, const char **mn_root)
{
	char *ptr, *prefix;

	prefix = "../devices/";

	if ((ptr = strstr(contents, prefix)) != NULL) {

		/* mn_root should point to the / following /devices */
		if (mn_root != NULL) {
			*mn_root = ptr += strlen(prefix) - 1;
		}
		return (1);
	}

	prefix = "/devices/";

	if (strncmp(contents, prefix, strlen(prefix)) == 0) {

		/* mn_root should point to the / following /devices/ */
		if (mn_root != NULL) {
			*mn_root = contents + strlen(prefix) - 1;
		}
		return (1);
	}

	if (mn_root != NULL) {
		*mn_root = contents;
	}
	return (0);
}

static int
s_readlink(const char *link, char *buf, size_t blen)
{
	int rv;

	if ((rv = readlink(link, buf, blen)) == -1)
		goto bad;

	if (rv >= blen && buf[blen - 1] != '\0') {
		errno = ENAMETOOLONG;
		goto bad;
	} else if (rv < blen) {
		buf[rv] = '\0';
	}

	return (0);
bad:
	dprintf(DBG_ERR, "s_readlink: %s: failed: %s\n",
	    link, strerror(errno));
	return (-1);
}

/*
 * Synchronous link creation interface routines
 * The scope of the operation is determined by the "name" arg.
 * "name" can be NULL, a driver name or a devfs pathname (without /devices)
 *
 *	"name"				creates
 *	======				=======
 *
 *	NULL		=>		All devlinks in system
 *	<driver>	=>		devlinks for named driver
 *	/pci@1		=>		devlinks for subtree rooted at pci@1
 *	/pseudo/foo@0:X	=>		devlinks for minor X
 *
 * devlink_create() returns 0 on success or an errno value on failure
 */

#define	MAX_DAEMON_ATTEMPTS 2

static int
devlink_create(const char *root, const char *name, int dca_devlink_flag)
{
	int i;
	int install;
	struct dca_off dca;

	assert(root);

	/*
	 * Convert name into arg for door_call
	 */
	if (dca_init(name, &dca, dca_devlink_flag) != 0)
		return (EINVAL);

	/*
	 * Attempt to use the daemon first
	 */
	i = 0;
	do {
		install = daemon_call(root, &dca);

		dprintf(DBG_INFO, "daemon_call() retval=%d\n", dca.dca_error);

		/*
		 * Retry only if door server isn't running
		 */
		if (dca.dca_error != ENOENT && dca.dca_error != EBADF) {
			return (dca.dca_error);
		}

		dca.dca_error = 0;

		/*
		 * To improve performance defer this check until the first
		 * failure. Safe to defer as door server checks perms.
		 */
		if (geteuid() != 0)
			return (EPERM);
	/*
	 * Daemon may not be running. Try to start it.
	 */
	} while ((++i < MAX_DAEMON_ATTEMPTS) &&
	    start_daemon(root, install) == 0);

	dprintf(DBG_INFO, "devlink_create: can't start daemon\n");

	assert(dca.dca_error == 0);

	/*
	 * If the daemon cannot be started execute the devfsadm command.
	 */
	exec_cmd(root, &dca);

	return (dca.dca_error);
}

/*
 * The "name" member of "struct dca" contains data in the following order
 *	root'\0'minor'\0'driver'\0'
 * The root component is always present at offset 0 in the "name" field.
 * The driver and minor are optional. If present they have a non-zero
 * offset in the "name" member.
 */
static int
dca_init(const char *name, struct dca_off *dcp, int dca_flags)
{
	char *cp;

	dcp->dca_root = 0;
	dcp->dca_minor = 0;
	dcp->dca_driver = 0;
	dcp->dca_error = 0;
	dcp->dca_flags = dca_flags;
	dcp->dca_name[0] = '\0';

	name = name ? name : "/";

	/*
	 *  Check if name is a driver name
	 */
	if (*name != '/') {
		(void) snprintf(dcp->dca_name, sizeof (dcp->dca_name),
		    "/ %s", name);
		dcp->dca_root = 0;
		*(dcp->dca_name + 1) = '\0';
		dcp->dca_driver = 2;
		return (0);
	}

	(void) snprintf(dcp->dca_name, sizeof (dcp->dca_name), "%s", name);

	/*
	 * "/devices" not allowed in devfs pathname
	 */
	if (is_minor_node(name, NULL))
		return (-1);

	dcp->dca_root = 0;
	if (cp = strrchr(dcp->dca_name, ':')) {
		*cp++ = '\0';
		dcp->dca_minor = cp - dcp->dca_name;
	}

	return (0);
}


#define	DAEMON_STARTUP_TIME	1 /* 1 second. This may need to be adjusted */
#define	DEVNAME_CHECK_FILE	"/etc/devname_check_RDONLY"

static int
daemon_call(const char *root, struct dca_off *dcp)
{
	door_arg_t	arg;
	int		fd, door_error;
	sigset_t	oset, nset;
	char		synch_door[PATH_MAX];
	struct stat	sb;
	char		*prefix;
	int		rofd;
	int		rdonly;
	int		install = 0;

	/*
	 * If root is readonly, there are two possibilities:
	 *	- we are in some sort of install scenario
	 *	- we are early in boot
	 * If the latter we don't want daemon_call()  to succeed.
	 * else we want to use /tmp/etc/dev
	 *
	 * Both of these requrements are fulfilled if we check for
	 * for a root owned door file in /tmp/etc/dev. If we are
	 * early in boot, the door file won't exist, so this call
	 * will fail.
	 *
	 * If we are in install, the door file will be present.
	 *
	 * If root is read-only, try only once, since libdevinfo
	 * isn't capable of starting devfsadmd correctly in that
	 * situation.
	 *
	 * Don't use statvfs() to check for readonly roots since it
	 * doesn't always report the truth.
	 */
	rofd = -1;
	rdonly = 0;
	if ((rofd = open(DEVNAME_CHECK_FILE, O_WRONLY|O_CREAT|O_TRUNC, 0644))
	    == -1 && errno == EROFS) {
		rdonly = 1;
		prefix = "/tmp";
	} else {
		if (rofd != -1) {
			(void) close(rofd);
			(void) unlink(DEVNAME_CHECK_FILE);
		}
		prefix = (char *)root;
	}

	if (rdonly && stat(DEVNAME_CHECK_FILE, &sb) != -1)
		install = 1;

	(void) snprintf(synch_door, sizeof (synch_door),
	    "%s/etc/dev/%s", prefix, DEVFSADM_SYNCH_DOOR);

	/*
	 * Return ENOTSUP to prevent retries if root is readonly
	 */
	if (stat(synch_door, &sb) == -1 || sb.st_uid != 0) {
		if (rdonly)
			dcp->dca_error = ENOTSUP;
		else
			dcp->dca_error = ENOENT;
		dprintf(DBG_ERR, "stat failed: %s: no file or not root owned\n",
		    synch_door);
		return (install);
	}

	if ((fd = open(synch_door, O_RDONLY)) == -1) {
		dcp->dca_error = errno;
		dprintf(DBG_ERR, "open of %s failed: %s\n",
		    synch_door, strerror(errno));
		return (install);
	}

	arg.data_ptr = (char *)dcp;
	arg.data_size = sizeof (*dcp);
	arg.desc_ptr = NULL;
	arg.desc_num = 0;
	arg.rbuf = (char *)dcp;
	arg.rsize = sizeof (*dcp);

	/*
	 * Block signals to this thread until door call
	 * completes.
	 */
	(void) sigfillset(&nset);
	(void) sigemptyset(&oset);
	(void) sigprocmask(SIG_SETMASK, &nset, &oset);
	if (door_call(fd, &arg)) {
		door_error = 1;
		dcp->dca_error = errno;
	}
	(void) sigprocmask(SIG_SETMASK, &oset, NULL);

	(void) close(fd);

	if (door_error)
		return (install);

	assert(arg.data_ptr);

	/*LINTED*/
	dcp->dca_error = ((struct dca_off *)arg.data_ptr)->dca_error;

	/*
	 * The doors interface may return data in a different buffer
	 * If that happens, deallocate buffer via munmap()
	 */
	if (arg.rbuf != (char *)dcp)
		(void) munmap(arg.rbuf, arg.rsize);

	return (install);
}

#define	DEVFSADM_PATH	"/usr/sbin/devfsadm"
#define	DEVFSADM	"devfsadm"

#define	DEVFSADMD_PATH	"/usr/lib/devfsadm/devfsadmd"
#define	DEVFSADM_DAEMON	"devfsadmd"

static int
start_daemon(const char *root, int install)
{
	int rv, i = 0;
	char *argv[20];

	argv[i++] = DEVFSADM_DAEMON;
	if (install) {
		argv[i++] = "-a";
		argv[i++] = "/tmp";
		argv[i++] = "-p";
		argv[i++] = "/tmp/root/etc/path_to_inst";
	} else if (strcmp(root, "/")) {
		argv[i++] = "-r";
		argv[i++] = (char *)root;
	}
	argv[i++] = NULL;

	rv = do_exec(DEVFSADMD_PATH, argv);

	(void) sleep(DAEMON_STARTUP_TIME);

	return (rv);
}

static void
exec_cmd(const char *root, struct dca_off *dcp)
{
	int i;
	char *argv[20];

	i = 0;
	argv[i++] = DEVFSADM;

	/*
	 * Load drivers only if -i is specified
	 */
	if (dcp->dca_driver) {
		argv[i++] = "-i";
		argv[i++] = &dcp->dca_name[dcp->dca_driver];
	} else {
		argv[i++] = "-n";
	}

	if (root != NULL && strcmp(root, "/") != 0) {
		argv[i++] = "-r";
		argv[i++] = (char *)root;
	}

	argv[i] = NULL;

	if (do_exec(DEVFSADM_PATH, argv))
		dcp->dca_error = errno;
}

static int
do_exec(const char *path, char *const argv[])
{
	int i;
	pid_t cpid;

#ifdef	DEBUG
	dprintf(DBG_INFO, "Executing %s\n\tArgument list:", path);
	for (i = 0; argv[i] != NULL; i++) {
		dprintf(DBG_INFO, " %s", argv[i]);
	}
	dprintf(DBG_INFO, "\n");
#endif

	if ((cpid = fork1()) == -1) {
		dprintf(DBG_ERR, "fork1 failed: %s\n", strerror(errno));
		return (-1);
	}

	if (cpid == 0) { /* child process */
		int fd;

		if ((fd = open("/dev/null", O_RDWR)) >= 0) {
			(void) dup2(fd, fileno(stdout));
			(void) dup2(fd, fileno(stderr));
			(void) close(fd);

			(void) execv(path, argv);
		} else {
			dprintf(DBG_ERR, "open of /dev/null failed: %s\n",
			    strerror(errno));
		}

		_exit(-1);
	}

	/* Parent process */
	if (waitpid(cpid, &i, 0) == cpid) {
		if (WIFEXITED(i)) {
			if (WEXITSTATUS(i) == 0) {
				dprintf(DBG_STEP,
				    "do_exec: child exited normally\n");
				return (0);
			} else
				errno = EINVAL;
		} else {
			/*
			 * The child was interrupted by a signal
			 */
			errno = EINTR;
		}
		dprintf(DBG_ERR, "child terminated abnormally: %s\n",
		    strerror(errno));
	} else {
		dprintf(DBG_ERR, "waitpid failed: %s\n", strerror(errno));
	}

	return (-1);
}

static int
walk_cache_links(di_devlink_handle_t hdp, cache_link_t *clp, link_desc_t *linkp)
{
	int i;

	assert(HDL_RDWR(hdp) || HDL_RDONLY(hdp));

	dprintf(DBG_INFO, "walk_cache_links: initial link: %s\n",
	    clp ? clp->path : "<NULL>");

	/*
	 * First search the links under the specified minor. On the
	 * 2nd pass, search the dangling list - secondary links may
	 * exist on this list since they are not resolved during the
	 * /dev walk.
	 */
	for (i = 0; i < 2; i++) {
		for (; clp != NULL; clp = clp->sib) {
			struct di_devlink vlink = {NULL};

			assert(clp->path[0] != '/');

			vlink.rel_path = clp->path;
			vlink.content = clp->content;
			vlink.type = attr2type(clp->attr);

			if (visit_link(hdp, linkp, &vlink)
			    != DI_WALK_CONTINUE) {
				dprintf(DBG_INFO, "walk_cache_links: "
				    "terminating at link: %s\n", clp->path);
				goto out;
			}
		}

		clp = CACHE(hdp)->dngl;
	}

out:

	/* If i < 2, we terminated the walk prematurely */
	return (i < 2 ? DI_WALK_TERMINATE : DI_WALK_CONTINUE);
}

static void
walk_all_cache(di_devlink_handle_t hdp, link_desc_t *linkp)
{
	int i;
	cache_link_t *clp;

	dprintf(DBG_INFO, "walk_all_cache: entered\n");

	for (i = 0; i < CACHE(hdp)->hash_sz; i++) {
		clp = CACHE_HASH(hdp, i);
		for (; clp; clp = clp->hash) {
			struct di_devlink vlink = {NULL};

			assert(clp->path[0] != '/');

			vlink.rel_path = clp->path;
			vlink.content = clp->content;
			vlink.type = attr2type(clp->attr);
			if (visit_link(hdp, linkp, &vlink) !=
			    DI_WALK_CONTINUE) {
				dprintf(DBG_INFO, "walk_all_cache: terminating "
				    "walk at link: %s\n", clp->path);
				return;
			}
		}
	}
}

static void
walk_cache_minor(di_devlink_handle_t hdp, const char *mpath, link_desc_t *linkp)
{
	cache_minor_t *cmnp;

	assert(mpath);

	if ((cmnp = lookup_minor(hdp, mpath, NULL, TYPE_CACHE)) != NULL) {
		(void) walk_cache_links(hdp, cmnp->link, linkp);
	} else {
		dprintf(DBG_ERR, "lookup minor failed: %s\n", mpath);
	}
}

static void
walk_cache_node(di_devlink_handle_t hdp, const char *path, link_desc_t *linkp)
{
	cache_minor_t *cmnp;
	cache_node_t *cnp;

	assert(path);

	if ((cnp = lookup_node(hdp, (char *)path, TYPE_CACHE)) == NULL) {
		dprintf(DBG_ERR, "lookup node failed: %s\n", path);
		return;
	}

	for (cmnp = cnp->minor; cmnp != NULL; cmnp = cmnp->sib) {
		if (walk_cache_links(hdp, cmnp->link, linkp)
		    == DI_WALK_TERMINATE)
			break;
	}
}

/*
 * Private function
 *
 * Walk cached links corresponding to the given path.
 *
 * path		path to a node or minor node.
 *
 * flags	specifies the type of devlinks to be selected.
 *		If DI_PRIMARY_LINK is used, only primary links are selected.
 *		If DI_SECONDARY_LINK is specified, only secondary links
 *		are selected.
 *		If neither flag is specified, all devlinks are selected.
 *
 * re		An extended regular expression in regex(5) format which
 *		selects the /dev links to be returned. The regular
 *		expression should use link pathnames relative to
 *		/dev. i.e. without the leading "/dev/" prefix.
 *		A NULL value matches all devlinks.
 */
int
di_devlink_cache_walk(di_devlink_handle_t hdp,
	const char *re,
	const char *path,
	uint_t flags,
	void *arg,
	int (*devlink_callback)(di_devlink_t, void *))
{
	regex_t reg;
	link_desc_t linkd = {NULL};

	if (hdp == NULL || path == NULL || !link_flag(flags) ||
	    !HDL_RDWR(hdp) || devlink_callback == NULL) {
		errno = EINVAL;
		return (-1);
	}

	linkd.flags = flags;
	linkd.arg = arg;
	linkd.fcn = devlink_callback;

	if (re) {
		if (regcomp(&reg, re, REG_EXTENDED) != 0)
			return (-1);
		linkd.regp = &reg;
	}

	if (minor_colon(path) == NULL) {
		walk_cache_node(hdp, path, &linkd);
	} else {
		walk_cache_minor(hdp, path, &linkd);
	}

	if (re)
		regfree(&reg);

	return (0);
}

#define	DEBUG_ENV_VAR	"_DEVLINK_DEBUG"
static int _devlink_debug = -1;

/*
 * debug level is initialized to -1.
 * On first call into this routine, debug level is set.
 * If debug level is zero, debugging msgs are disabled.
 */
static void
debug_print(debug_level_t msglevel, const char *fmt, va_list ap)
{
	char	*cp;
	int	save;

	/*
	 * We shouldn't be here if debug is disabled
	 */
	assert(_devlink_debug != 0);

	/*
	 * Set debug level on first call into this routine
	 */
	if (_devlink_debug < 0) {
		if ((cp = getenv(DEBUG_ENV_VAR)) == NULL) {
			_devlink_debug = 0;
			return;
		}

		save = errno;
		errno = 0;
		_devlink_debug = strtol(cp, NULL, 10);
		if (errno != 0 || _devlink_debug < 0)  {
			_devlink_debug = 0;
			errno = save;
			return;
		}
		errno = save;

		if (!_devlink_debug)
			return;
	}

	/* debug msgs are enabled */
	assert(_devlink_debug > 0);

	if (_devlink_debug < msglevel)
		return;
	if ((_devlink_debug == DBG_LCK) && (msglevel != _devlink_debug))
		return;

	/* Print a distinctive label for error msgs */
	if (msglevel == DBG_ERR) {
		(void) fprintf(stderr, "[ERROR]: ");
	}

	(void) vfprintf(stderr, fmt, ap);
	(void) fflush(stderr);
}

/* ARGSUSED */
/* PRINTFLIKE2 */
void
dprintf(debug_level_t msglevel, const char *fmt, ...)
{
	va_list ap;

	assert(msglevel > 0);
	if (!_devlink_debug)
		return;

	va_start(ap, fmt);
	debug_print(msglevel, fmt, ap);
	va_end(ap);
}
