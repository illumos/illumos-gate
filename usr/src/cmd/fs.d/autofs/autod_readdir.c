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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *	autod_readdir.c
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/param.h>
#include <errno.h>
#include <pwd.h>
#include <locale.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include "automount.h"

static void build_dir_entry_list(struct autofs_rddir_cache *rdcp,
				struct dir_entry *list);
static int autofs_rddir_cache_enter(char *map, ulong_t bucket_size,
				struct autofs_rddir_cache **rdcpp);
int autofs_rddir_cache_lookup(char *map, struct autofs_rddir_cache **rdcpp);
static int autofs_rddir_cache_delete(struct autofs_rddir_cache *rdcp);
static int create_dirents(struct autofs_rddir_cache *rdcp, ulong_t offset,
				autofs_rddirres *res);
struct dir_entry *rddir_entry_lookup(char *name, struct dir_entry *list);
static void free_offset_tbl(struct off_tbl *head);
static void free_dir_list(struct dir_entry *head);

#define	OFFSET_BUCKET_SIZE	100

rwlock_t autofs_rddir_cache_lock;		/* readdir cache lock */
struct autofs_rddir_cache *rddir_head;		/* readdir cache head */

int
do_readdir(autofs_rddirargs *rda, autofs_rddirres *rd)
{
	struct dir_entry *list = NULL, *l;
	struct autofs_rddir_cache *rdcp = NULL;
	int error;
	int cache_time = RDDIR_CACHE_TIME;

	if (automountd_nobrowse) {
		/*
		 * Browsability was disabled return an empty list.
		 */
		rd->rd_status = AUTOFS_OK;
		rd->rd_rddir.rddir_size = 0;
		rd->rd_rddir.rddir_eof = 1;
		rd->rd_rddir.rddir_entries = NULL;

		return (0);
	}

	rw_rdlock(&autofs_rddir_cache_lock);
	error = autofs_rddir_cache_lookup(rda->rda_map, &rdcp);
	if (error) {
		rw_unlock(&autofs_rddir_cache_lock);
		rw_wrlock(&autofs_rddir_cache_lock);
		error = autofs_rddir_cache_lookup(rda->rda_map, &rdcp);
		if (error) {
			if (trace > 2)
				trace_prt(1,
				"map %s not found, adding...\n", rda->rda_map);
			/*
			 * entry doesn't exist, add it.
			 */
			error = autofs_rddir_cache_enter(rda->rda_map,
					OFFSET_BUCKET_SIZE, &rdcp);
		}
	}
	rw_unlock(&autofs_rddir_cache_lock);

	if (error)
		return (error);

	assert(rdcp != NULL);
	assert(rdcp->in_use);

	if (!rdcp->full) {
		rw_wrlock(&rdcp->rwlock);
		if (!rdcp->full) {
			/*
			 * cache entry hasn't been filled up, do it now.
			 */
			char *stack[STACKSIZ];
			char **stkptr;

			/*
			 * Initialize the stack of open files
			 * for this thread
			 */
			stack_op(INIT, NULL, stack, &stkptr);
			(void) getmapkeys(rda->rda_map, &list, &error,
			    &cache_time, stack, &stkptr, rda->uid);
			if (!error)
				build_dir_entry_list(rdcp, list);
			else if (list) {
				free_dir_list(list);
				list = NULL;
			}
		}
	} else
		rw_rdlock(&rdcp->rwlock);

	rd->rd_bufsize = rda->rda_count;
	if (!error) {
		error = create_dirents(rdcp, rda->rda_offset, rd);
		if (error) {
			if (rdcp->offtp) {
				free_offset_tbl(rdcp->offtp);
				rdcp->offtp = NULL;
			}
			if (rdcp->entp) {
				free_dir_list(rdcp->entp);
				rdcp->entp = NULL;
			}
			rdcp->full = 0;
			list = NULL;
		}
	}

	if (trace > 2) {
		/*
		 * print this list only once
		 */
		for (l = list; l != NULL; l = l->next)
			trace_prt(0, "%s\n", l->name);
		trace_prt(0, "\n");
	}

	if (!error) {
		rd->rd_status = AUTOFS_OK;
		if (cache_time) {
			/*
			 * keep list of entries for up to
			 * 'cache_time' seconds
			 */
			rdcp->ttl = time((time_t *)NULL) + cache_time;
		} else {
			/*
			 * the underlying name service indicated not
			 * to cache contents.
			 */
			if (rdcp->offtp) {
				free_offset_tbl(rdcp->offtp);
				rdcp->offtp = NULL;
			}
			if (rdcp->entp) {
				free_dir_list(rdcp->entp);
				rdcp->entp = NULL;
			}
			rdcp->full = 0;
		}
	} else {
		/*
		 * return an empty list
		 */
		rd->rd_rddir.rddir_size = 0;
		rd->rd_rddir.rddir_eof = 1;
		rd->rd_rddir.rddir_entries = NULL;

		/*
		 * Invalidate cache and set error
		 */
		switch (error) {
		case ENOENT:
			rd->rd_status = AUTOFS_NOENT;
			break;
		case ENOMEM:
			rd->rd_status = AUTOFS_NOMEM;
			break;
		default:
			rd->rd_status = AUTOFS_ECOMM;
		}
	}
	rw_unlock(&rdcp->rwlock);

	mutex_lock(&rdcp->lock);
	rdcp->in_use--;
	mutex_unlock(&rdcp->lock);

	assert(rdcp->in_use >= 0);

	return (error);
}

#define	roundtoint(x)	(((x) + sizeof (int) - 1) & ~(sizeof (int) - 1))
#define	DIRENT64_RECLEN(namelen)	\
	(((int)(((dirent64_t *)0)->d_name) + 1 + (namelen) + 7) & ~ 7)

static int
create_dirents(
	struct autofs_rddir_cache *rdcp,
	ulong_t offset,
	autofs_rddirres *res)
{
	uint_t total_bytes_wanted;
	int bufsize;
	ushort_t this_reclen;
	int outcount = 0;
	int namelen;
	struct dir_entry *list = NULL, *l, *nl;
	struct dirent64 *dp;
	char *outbuf;
	struct off_tbl *offtp, *next = NULL;
	int this_bucket = 0;
	int error = 0;
	int x = 0, y = 0;

	assert(RW_LOCK_HELD(&rdcp->rwlock));
	for (offtp = rdcp->offtp; offtp != NULL; offtp = next) {
		x++;
		next = offtp->next;
		this_bucket = (next == NULL);
		if (!this_bucket)
			this_bucket = (offset < next->offset);
		if (this_bucket) {
			/*
			 * has to be in this bucket
			 */
			assert(offset >= offtp->offset);
			list = offtp->first;
			break;
		}
		/*
		 * loop to look in next bucket
		 */
	}

	for (l = list; l != NULL && l->offset < offset; l = l->next)
		y++;

	if (l == NULL) {
		/*
		 * reached end of directory
		 */
		error = 0;
		goto empty;
	}

	if (trace > 2)
		trace_prt(1, "%s: offset searches (%d, %d)\n", rdcp->map, x, y);

	total_bytes_wanted = res->rd_bufsize;
	bufsize = total_bytes_wanted + sizeof (struct dirent64);
	outbuf = malloc(bufsize);
	if (outbuf == NULL) {
		syslog(LOG_ERR, "memory allocation error\n");
		error = ENOMEM;
		goto empty;
	}
	memset(outbuf, 0, bufsize);
	/* LINTED pointer alignment */
	dp = (struct dirent64 *)outbuf;

	while (l) {
		nl = l->next;
		namelen = strlen(l->name);
		this_reclen = DIRENT64_RECLEN(namelen);
		if (outcount + this_reclen > total_bytes_wanted) {
			break;
		}
		dp->d_ino = (ino64_t)l->nodeid;
		if (nl) {
			/*
			 * get the next elements offset
			 */
			dp->d_off = (off64_t)nl->offset;
		} else {
			/*
			 * This is the last element
			 * make offset one plus the current.
			 */
			dp->d_off = (off64_t)l->offset + 1;
		}
		(void) strcpy(dp->d_name, l->name);
		dp->d_reclen = (ushort_t)this_reclen;
		outcount += dp->d_reclen;
		dp = (struct dirent64 *)((int)dp + dp->d_reclen);
		assert(outcount <= total_bytes_wanted);
		l = l->next;
	}

	res->rd_rddir.rddir_size = (long)outcount;
	if (outcount > 0) {
		/*
		 * have some entries
		 */
		res->rd_rddir.rddir_eof = (l == NULL);
		/* LINTED pointer alignment */
		res->rd_rddir.rddir_entries = (struct dirent64 *)outbuf;
		error = 0;
	} else {
		/*
		 * total_bytes_wanted is not large enough for one
		 * directory entry
		 */
		res->rd_rddir.rddir_eof = 0;
		res->rd_rddir.rddir_entries = NULL;
		free(outbuf);
		error = EIO;
	}
	return (error);

empty:
	res->rd_rddir.rddir_size = 0L;
	res->rd_rddir.rddir_eof = TRUE;
	res->rd_rddir.rddir_entries = NULL;
	return (error);
}


/*
 * add new entry to cache for 'map'
 */
static int
autofs_rddir_cache_enter(
	char *map,
	ulong_t bucket_size,
	struct autofs_rddir_cache **rdcpp)
{
	struct autofs_rddir_cache *p;
	assert(RW_LOCK_HELD(&autofs_rddir_cache_lock));

	/*
	 * Add to front of the list at this time
	 */
	p = (struct autofs_rddir_cache *)malloc(sizeof (*p));
	if (p == NULL) {
		syslog(LOG_ERR,
			"autofs_rddir_cache_enter: memory allocation failed\n");
		return (ENOMEM);
	}
	memset((char *)p, 0, sizeof (*p));

	p->map = malloc(strlen(map) + 1);
	if (p->map == NULL) {
		syslog(LOG_ERR,
			"autofs_rddir_cache_enter: memory allocation failed\n");
		free(p);
		return (ENOMEM);
	}
	strcpy(p->map, map);

	p->bucket_size = bucket_size;
	/*
	 * no need to grab mutex lock since I haven't yet made the
	 * node visible to the list
	 */
	p->in_use = 1;
	(void) rwlock_init(&p->rwlock, USYNC_THREAD, NULL);
	(void) mutex_init(&p->lock, USYNC_THREAD, NULL);

	if (rddir_head == NULL)
		rddir_head = p;
	else {
		p->next = rddir_head;
		rddir_head = p;
	}
	*rdcpp = p;

	return (0);
}

/*
 * find 'map' in readdir cache
 */
int
autofs_rddir_cache_lookup(char *map, struct autofs_rddir_cache **rdcpp)
{
	struct autofs_rddir_cache *p;

	assert(RW_LOCK_HELD(&autofs_rddir_cache_lock));
	for (p = rddir_head; p != NULL; p = p->next) {
		if (strcmp(p->map, map) == 0) {
			/*
			 * found matching entry
			 */
			*rdcpp = p;
			mutex_lock(&p->lock);
			p->in_use++;
			mutex_unlock(&p->lock);
			return (0);
		}
	}
	/*
	 * didn't find entry
	 */
	return (ENOENT);
}

/*
 * free the offset table
 */
static void
free_offset_tbl(struct off_tbl *head)
{
	struct off_tbl *p, *next = NULL;

	for (p = head; p != NULL; p = next) {
		next = p->next;
		free(p);
	}
}

/*
 * free the directory entries
 */
static void
free_dir_list(struct dir_entry *head)
{
	struct dir_entry *p, *next = NULL;

	for (p = head; p != NULL; p = next) {
		next = p->next;
		assert(p->name);
		free(p->name);
		free(p);
	}
}

static void
autofs_rddir_cache_entry_free(struct autofs_rddir_cache *p)
{
	assert(RW_LOCK_HELD(&autofs_rddir_cache_lock));
	assert(!p->in_use);
	if (p->map)
		free(p->map);
	if (p->offtp)
		free_offset_tbl(p->offtp);
	if (p->entp)
		free_dir_list(p->entp);
	free(p);
}

/*
 * Remove entry from the rddircache
 * the caller must own the autofs_rddir_cache_lock.
 */
static int
autofs_rddir_cache_delete(struct autofs_rddir_cache *rdcp)
{
	struct autofs_rddir_cache *p, *prev;

	assert(RW_LOCK_HELD(&autofs_rddir_cache_lock));
	/*
	 * Search cache for entry
	 */
	prev = NULL;
	for (p = rddir_head; p != NULL; p = p->next) {
		if (p == rdcp) {
			/*
			 * entry found, remove from list if not in use
			 */
			if (p->in_use)
				return (EBUSY);
			if (prev)
				prev->next = p->next;
			else
				rddir_head = p->next;
			autofs_rddir_cache_entry_free(p);
			return (0);
		}
		prev = p;
	}
	syslog(LOG_ERR, "Couldn't find entry %x in cache\n", p);
	return (ENOENT);
}

/*
 * Return entry that matches name, NULL otherwise.
 * Assumes the readers lock for this list has been grabed.
 */
struct dir_entry *
rddir_entry_lookup(char *name, struct dir_entry *list)
{
	return (btree_lookup(list, name));
}

static void
build_dir_entry_list(struct autofs_rddir_cache *rdcp, struct dir_entry *list)
{
	struct dir_entry *p;
	ulong_t offset = AUTOFS_DAEMONCOOKIE, offset_list = AUTOFS_DAEMONCOOKIE;
	struct off_tbl *offtp, *last = NULL;
	ino_t inonum = 4;

	assert(RW_LOCK_HELD(&rdcp->rwlock));
	assert(rdcp->entp == NULL);
	rdcp->entp = list;
	for (p = list; p != NULL; p = p->next) {
		p->nodeid = inonum;
		p->offset = offset;
		if (offset >= offset_list) {
			/*
			 * add node to index table
			 */
			offtp = (struct off_tbl *)
				malloc(sizeof (struct off_tbl));
			if (offtp != NULL) {
				offtp->offset = offset;
				offtp->first = p;
				offtp->next = NULL;
				offset_list += rdcp->bucket_size;
			} else {
				syslog(LOG_ERR,
"WARNING: build_dir_entry_list: could not add offset to index table\n");
				continue;
			}
			/*
			 * add to cache
			 */
			if (rdcp->offtp == NULL)
				rdcp->offtp = offtp;
			else
				last->next = offtp;
			last = offtp;
		}
		offset++;
		inonum += 2;		/* use even numbers in daemon */
	}
	rdcp->full = 1;
}

mutex_t cleanup_lock;
cond_t cleanup_start_cv;
cond_t cleanup_done_cv;

/*
 * cache cleanup thread starting point
 */
void
cache_cleanup(void)
{
	timestruc_t reltime;
	struct autofs_rddir_cache *p, *next = NULL;
	int error;

	mutex_init(&cleanup_lock, USYNC_THREAD, NULL);
	cond_init(&cleanup_start_cv, USYNC_THREAD, NULL);
	cond_init(&cleanup_done_cv, USYNC_THREAD, NULL);

	mutex_lock(&cleanup_lock);
	for (;;) {
		reltime.tv_sec = RDDIR_CACHE_TIME/2;
		reltime.tv_nsec = 0;

		/*
		 * delay RDDIR_CACHE_TIME seconds, or until some other thread
		 * requests that I cleanup the caches
		 */
		if (error = cond_reltimedwait(
		    &cleanup_start_cv, &cleanup_lock, &reltime)) {
			if (error != ETIME) {
				if (trace > 1)
					trace_prt(1,
					"cleanup thread wakeup (%d)\n", error);
				continue;
			}
		}
		mutex_unlock(&cleanup_lock);

		/*
		 * Perform the cache cleanup
		 */
		rw_wrlock(&autofs_rddir_cache_lock);
		for (p = rddir_head; p != NULL; p = next) {
			next = p->next;
			if (p->in_use > 0) {
				/*
				 * cache entry busy, skip it
				 */
				if (trace > 1) {
					trace_prt(1,
					"%s cache in use\n", p->map);
				}
				continue;
			}
			/*
			 * Cache entry is not in use, and nobody can grab a
			 * new reference since I'm holding the
			 * autofs_rddir_cache_lock
			 */

			/*
			 * error will be zero if some thread signaled us asking
			 * that the caches be freed. In such case, free caches
			 * even if they're still valid and nobody is referencing
			 * them at this time. Otherwise, free caches only
			 * if their time to live (ttl) has expired.
			 */
			if (error == ETIME && (p->ttl > time((time_t *)NULL))) {
				/*
				 * Scheduled cache cleanup, if cache is still
				 * valid don't free.
				 */
				if (trace > 1) {
					trace_prt(1,
					"%s cache still valid\n", p->map);
				}
				continue;
			}
			if (trace > 1)
				trace_prt(1, "%s freeing cache\n", p->map);
			assert(!p->in_use);
			error = autofs_rddir_cache_delete(p);
			assert(!error);
		}
		rw_unlock(&autofs_rddir_cache_lock);

		/*
		 * wakeup the thread/threads waiting for the
		 * cleanup to finish
		 */
		mutex_lock(&cleanup_lock);
		cond_broadcast(&cleanup_done_cv);
	}
	/* NOTREACHED */
}
