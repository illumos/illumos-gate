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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <syslog.h>
#include <sys/param.h>
#include <rpc/rpc.h>
#include <sys/stat.h>
#include <netconfig.h>
#include <netdir.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/errno.h>
#include <sys/resource.h>
#include <rpcsvc/mount.h>
#include <sys/pathconf.h>
#include <sys/systeminfo.h>
#include <sys/utsname.h>
#include <signal.h>
#include <locale.h>
#include <unistd.h>
#include <thread.h>
#include <sharefs/share.h>
#include "../lib/sharetab.h"
#include "mountd.h"

struct cache_entry {
	char	*cache_host;
	time_t	cache_time;
	int	cache_belong;
	char	**cache_grl;
	int	cache_grc;
	struct cache_entry *cache_next;
};

static struct cache_entry *cache_head;

#define	VALID_TIME	60  /* seconds */

static rwlock_t cache_lock;	/* protect the cache chain */

static void cache_free(struct cache_entry *entry);
static int cache_check(char *host, char **grl, int grc, int *belong);
static void cache_enter(char *host, char **grl, int grc, int belong);


void
netgroup_init()
{
	(void) rwlock_init(&cache_lock, USYNC_THREAD, NULL);
}

/*
 * Check whether any of the hostnames in clnames are
 * members (or non-members) of the netgroups in glist.
 * Since the innetgr lookup is rather expensive, the
 * result is cached. The cached entry is valid only
 * for VALID_TIME seconds.  This works well because
 * typically these lookups occur in clusters when
 * a client is mounting.
 *
 * Note that this routine establishes a host membership
 * in a list of netgroups - we've no idea just which
 * netgroup in the list it is a member of.
 *
 * glist is a character array containing grc strings
 * representing netgroup names (optionally prefixed
 * with '-'). Each string is ended with '\0'  and
 * followed immediately by the next string.
 */
int
netgroup_check(struct nd_hostservlist *clnames, char  *glist, int grc)
{
	char **grl;
	char *gr;
	int nhosts = clnames->h_cnt;
	char *host0, *host;
	int i, j, n;
	int response;
	int belong = 0;
	static char *domain;

	if (domain == NULL) {
		int	ssize;

		domain = exmalloc(SYS_NMLN);
		ssize = sysinfo(SI_SRPC_DOMAIN, domain, SYS_NMLN);
		if (ssize > SYS_NMLN) {
			free(domain);
			domain = exmalloc(ssize);
			ssize = sysinfo(SI_SRPC_DOMAIN, domain, ssize);
		}
		/* Check for error in syscall or NULL domain name */
		if (ssize <= 1) {
			syslog(LOG_ERR, "No default domain set");
			return (0);
		}
	}

	grl = calloc(grc, sizeof (char *));
	if (grl == NULL)
		return (0);

	for (i = 0, gr = glist; i < grc && !belong; ) {
		/*
		 * If the netgroup name has a '-' prepended
		 * then a match of this name implies a failure
		 * instead of success.
		 */
		response = (*gr != '-') ? 1 : 0;

		/*
		 * Subsequent names with or without a '-' (but no mix)
		 * can be grouped together for a single check.
		 */
		for (n = 0; i < grc; i++, n++, gr += strlen(gr) + 1) {
			if ((response && *gr == '-') ||
			    (!response && *gr != '-'))
				break;

			grl[n] = response ? gr : gr + 1;
		}

		host0 = clnames->h_hostservs[0].h_host;

		/*
		 * If not in cache check the netgroup for each
		 * of the hosts names (usually just one).
		 * Enter the result into the cache.
		 */
		if (!cache_check(host0, grl, n, &belong)) {
			for (j = 0; j < nhosts && !belong; j++) {
				host = clnames->h_hostservs[j].h_host;

				if (__multi_innetgr(n, grl,
				    1, &host,
				    0, NULL,
				    1, &domain))
					belong = 1;
			}

			cache_enter(host0, grl, n, belong);
		}
	}

	free(grl);
	return (belong ? response : 0);
}

/*
 * Free a cache entry and all entries
 * further down the chain since they
 * will also be expired.
 */
static void
cache_free(struct cache_entry *entry)
{
	struct cache_entry *ce, *next;
	int i;

	for (ce = entry; ce; ce = next) {
		if (ce->cache_host)
			free(ce->cache_host);
		for (i = 0; i < ce->cache_grc; i++)
			if (ce->cache_grl[i])
				free(ce->cache_grl[i]);
		if (ce->cache_grl)
			free(ce->cache_grl);
		next = ce->cache_next;
		free(ce);
	}
}

/*
 * Search the entries in the cache chain looking
 * for an entry with a matching hostname and group
 * list.  If a match is found then return the "belong"
 * value which may be 1 or 0 depending on whether the
 * client is a member of the list or not.  This is
 * both a positive and negative cache.
 *
 * Cache entries have a validity of VALID_TIME seconds.
 * If we find an expired entry then blow away the entry
 * and the rest of the chain since entries further down
 * the chain will be expired too because we always add
 * new entries to the head of the chain.
 */
static int
cache_check(char *host, char **grl, int grc, int *belong)
{
	struct cache_entry *ce, *prev;
	time_t timenow = time(NULL);
	int i;

	(void) rw_rdlock(&cache_lock);

	for (ce = cache_head; ce; ce = ce->cache_next) {

		/*
		 * If we find a stale entry, there can't
		 * be any valid entries from here on.
		 * Acquire a write lock, search the chain again
		 * and delete the stale entry and all following
		 * entries.
		 */
		if (timenow > ce->cache_time) {
			(void) rw_unlock(&cache_lock);
			(void) rw_wrlock(&cache_lock);

			for (prev = NULL, ce = cache_head; ce;
			    prev = ce, ce = ce->cache_next)
				if (timenow > ce->cache_time)
					break;

			if (ce != NULL) {
				if (prev)
					prev->cache_next = NULL;
				else
					cache_head = NULL;

				cache_free(ce);
			}
			(void) rw_unlock(&cache_lock);

			return (0);
		}
		if (ce->cache_grc != grc)
			continue;	/* no match */

		if (strcasecmp(host, ce->cache_host) != 0)
			continue;	/* no match */

		for (i = 0; i < grc; i++)
			if (strcasecmp(ce->cache_grl[i], grl[i]) != 0)
				break;	/* no match */
		if (i < grc)
			continue;

		*belong = ce->cache_belong;
		(void) rw_unlock(&cache_lock);

		return (1);
	}

	(void) rw_unlock(&cache_lock);

	return (0);
}

/*
 * Put a new entry in the cache chain by
 * prepending it to the front.
 * If there isn't enough memory then just give up.
 */
static void
cache_enter(char *host, char **grl, int grc, int belong)
{
	struct cache_entry *entry;
	int i;

	entry = malloc(sizeof (*entry));
	if (entry == NULL)
		return;

	(void) memset((caddr_t)entry, 0, sizeof (*entry));
	entry->cache_host = strdup(host);
	if (entry->cache_host == NULL) {
		cache_free(entry);
		return;
	}

	entry->cache_time = time(NULL) + VALID_TIME;
	entry->cache_belong = belong;
	entry->cache_grl = malloc(grc * sizeof (char *));
	if (entry->cache_grl == NULL) {
		cache_free(entry);
		return;
	}

	for (i = 0; i < grc; i++) {
		entry->cache_grl[i] = strdup(grl[i]);
		if (entry->cache_grl[i] == NULL) {
			entry->cache_grc = i;
			cache_free(entry);
			return;
		}
	}

	entry->cache_grc = grc;

	(void) rw_wrlock(&cache_lock);
	entry->cache_next = cache_head;
	cache_head = entry;
	(void) rw_unlock(&cache_lock);
}

/*
 * Full cache flush
 */
void
netgrp_cache_flush(void)
{
	(void) rw_wrlock(&cache_lock);
	cache_free(cache_head);
	cache_head = NULL;
	(void) rw_unlock(&cache_lock);
}
