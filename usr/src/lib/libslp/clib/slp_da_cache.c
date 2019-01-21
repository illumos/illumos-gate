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

/*
 * This module contains a cache used to optimized scope and DA
 * discovery. Entries live for a short duration only (about 10 seconds),
 * although their lifetime can be advanced somewhat by frequent use.
 * The intent is that the canonical source for DAs will always be slpd,
 * so the short lifetime of cache entries is designed to force clients
 * to consult slpd frequently so as to pick up the latest DA state
 * quickly.
 *
 * The cache is managed by a thread which monitors calls into the cache.
 * If the cache has been unused for a certain amount of time, the thread
 * frees the cache and exits.
 *
 * The cache is keyed on the queries sent to slpd to access slpd's DA
 * table. Associated with each query is a reply (in the format of an
 * on-the-wire SLP SRVRPLY message).
 * The cache is accessed by the following two functions:
 *
 * slp_find_das_cached:		searches the cache
 * slp_put_das_cached:		adds a reply to the cache
 *
 * All parameters added to the cache are copied in first, and all results
 * read from the cache are copied out, so all memory must be freed by
 * the caller.
 */

#include <stdio.h>
#include <stdlib.h>
#include <thread.h>
#include <synch.h>
#include <syslog.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>
#include <slp-internal.h>

/* These constants control the behaviour of the cache */
#define	MAX_LIFETIME	25	/* max lifetime, in seconds */
#define	ADVANCE_PER_USE	5	/* seconds lifetime is extended on each use */
#define	INIT_LIFETIME	10	/* cache entries start with this lifetime */

/* Management thread components */
#define	IDLE_TIMEOUT	30	/* thread will exit after this idle time */
static int cache_thr_running;
static mutex_t start_lock = DEFAULTMUTEX;
static int cache_called;
static cond_t cache_called_cond;
static mutex_t cache_called_lock = DEFAULTMUTEX;
static SLPError start_cache_thr();
static void cache_thr();

/* The cache and cache synchronization */
static void *da_cache;
static mutex_t cache_lock = DEFAULTMUTEX;
struct cache_entry {
	const char *query;
	const char *reply;
	unsigned int reply_len;
	time_t max_life;
	time_t expires;
};
typedef struct cache_entry cache_entry_t;

/* cache management and searching */
static int compare_entries(const void *, const void *);
static void free_cache_entry(void *, VISIT);

/*
 * Searches the cache for the reply to 'query'. Returns the reply if
 * found, otherwise NULL.
 * The caller must free the result.
 */
char *slp_find_das_cached(const char *query) {
	cache_entry_t ce[1], **ans;
	char *reply = NULL;
	time_t now;

	if (!cache_thr_running) {
		if (start_cache_thr() != SLP_OK) {
			return (NULL);
		}
	}

	(void) mutex_lock(&cache_lock);
	ce->query = query;

	ans = slp_tfind(ce, &da_cache, compare_entries);
	if (ans) {
		now = time(NULL);
		if ((*ans)->expires < now || (*ans)->max_life < now) {
			goto done;
		}

		/* copy out the reply */
		if (!(reply = malloc((*ans)->reply_len))) {
			slp_err(LOG_CRIT, 0, "slp_find_das_cached",
						"out of memory");
			goto done;
		}
		(void) memcpy(reply, (*ans)->reply, (*ans)->reply_len);
		(*ans)->expires += ADVANCE_PER_USE;
	}

	/* notify cache thread of call */
	(void) mutex_lock(&cache_called_lock);
	cache_called = 1;
	(void) cond_signal(&cache_called_cond);
	(void) mutex_unlock(&cache_called_lock);

done:
	(void) mutex_unlock(&cache_lock);
	return (reply);
}

/*
 * Adds 'reply' to the cache under the index 'query'. Both parameters
 * are copied in first, so the caller may free them after the call.
 * 'len' is the length of 'reply' in bytes.
 */
void slp_put_das_cached(const char *query, const char *reply,
			unsigned int len) {
	cache_entry_t *ce, **ce2;
	time_t now;

	if (!cache_thr_running) {
		if (start_cache_thr() != SLP_OK) {
			return;
		}
	}

	/* create the cache entry for this reply */
	if (!(ce = malloc(sizeof (*ce)))) {
		slp_err(LOG_CRIT, 0, "slp_put_das_cached", "out of memory");
		return;
	}

	if (!(ce->query = strdup(query))) {
		free(ce);
		slp_err(LOG_CRIT, 0, "slp_put_das_cached", "out of memory");
		return;
	}

	if (!(ce->reply = malloc(len))) {
		free((void *) (ce->query));
		free(ce);
		slp_err(LOG_CRIT, 0, "slp_put_das_cached", "out of memory");
		return;
	}
	(void) memcpy((void *) (ce->reply), reply, len);
	ce->reply_len = len;
	now = time(NULL);
	ce->max_life = now + MAX_LIFETIME;
	ce->expires = now + INIT_LIFETIME;

	/* write to the cache */
	(void) mutex_lock(&cache_lock);
	ce2 = slp_tsearch((void *) ce, &da_cache, compare_entries);
	if (ce != *ce2) {
		/* overwrite existing entry */
		free((void *) ((*ce2)->query));
		free((void *) ((*ce2)->reply));
		free(*ce2);
		*ce2 = ce;
	}

	(void) mutex_unlock(&cache_lock);
}

static int compare_entries(const void *x1, const void *x2) {
	cache_entry_t *e1 = (cache_entry_t *)x1;
	cache_entry_t *e2 = (cache_entry_t *)x2;

	return (strcasecmp(e1->query, e2->query));
}

static void free_cache_entry(void *node, VISIT order) {
	if (order == endorder || order == leaf) {
		cache_entry_t *ce = *(cache_entry_t **)node;

		free((void *) (ce->query));
		free((void *) (ce->reply));
		free(ce);
		free(node);
	}
}

static SLPError start_cache_thr() {
	int terr;
	SLPError err = SLP_OK;

	(void) mutex_lock(&start_lock);

	if (cache_thr_running) {
		goto start_done;
	}

	(void) cond_init(&cache_called_cond, 0, NULL);

	if ((terr = thr_create(
		0, 0, (void *(*)(void *)) cache_thr,
		NULL, 0, NULL)) != 0) {
		slp_err(LOG_CRIT, 0, "start_cache_thr",
			"could not start thread: %s", strerror(terr));
		err = SLP_INTERNAL_SYSTEM_ERROR;
		goto start_done;
	}
	cache_thr_running = 1;

start_done:
	(void) mutex_unlock(&start_lock);
	return (err);
}

static void cache_thr() {
	timestruc_t timeout;
	timeout.tv_nsec = 0;

	(void) mutex_lock(&cache_called_lock);
	cache_called = 0;

	while (cache_called == 0) {
		int err;

		timeout.tv_sec = IDLE_TIMEOUT;
		err = cond_reltimedwait(&cache_called_cond,
					&cache_called_lock, &timeout);

		if (err == ETIME) {
			(void) mutex_lock(&cache_lock);
			/* free cache */
			if (da_cache) {
				slp_twalk(da_cache,
			(void (*)(void *, VISIT, int, void *))free_cache_entry,
						0, NULL);
			}
			da_cache = NULL;
			(void) mutex_unlock(&cache_lock);
			cache_thr_running = 0;
			(void) mutex_unlock(&cache_called_lock);
			thr_exit(NULL);
		} else {
			cache_called = 0;
		}
	}
}
