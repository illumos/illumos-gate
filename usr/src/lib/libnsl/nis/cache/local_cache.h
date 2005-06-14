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
 * Copyright 1996-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	__LOCAL_CACHE_H
#define	__LOCAL_CACHE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "cache.h"

struct LocalCacheEntry {
	char *name;
	int levels;
	char **components;
	uint32_t expTime;
	int generation;
	int binding_len;
	void *binding_val;
	LocalCacheEntry *next;

	void *operator new(size_t bytes) { return calloc(1, bytes); }
	void operator delete(void *arg) { free(arg); }
};

struct LocalActiveEntry {
	nis_active_endpoint *act;
	LocalActiveEntry *next;

	void *operator new(size_t bytes) { return calloc(1, bytes); }
	void operator delete(void *arg) { free(arg); }
};

class NisLocalCache : public NisCache {
    public:
	NisLocalCache(nis_error &error);
	NisLocalCache(nis_error &error, uint32_t *expt_time);
	~NisLocalCache();

	nis_error searchDir(char *dname,
		nis_bound_directory **info, int near);
	void addBinding(nis_bound_directory *info);
	void removeBinding(nis_bound_directory *info);
	void print();

	void activeAdd(nis_active_endpoint *act);
	void activeRemove(endpoint *ep, int all);
	int activeCheck(endpoint *ep);
	int activeGet(endpoint *ep, nis_active_endpoint **act);
	int getAllActive(nis_active_endpoint ***actlist);

	void *operator new(size_t bytes) { return calloc(1, bytes); }
	void operator delete(void *arg) { free(arg); }
	uint32_t loadPreferredServers();
	uint32_t refreshCache();
	int resetBinding(nis_bound_directory *);

    private:
	rwlock_t lock;
	LocalCacheEntry *head;
	LocalCacheEntry *tail;
	LocalActiveEntry *act_list;
	int have_coldstart;
	int sem_writer;

	void lockShared();
	void unlockShared();
	void lockExclusive();
	void unlockExclusive();

	LocalCacheEntry *createCacheEntry(nis_bound_directory *info);
	void freeCacheEntry(LocalCacheEntry *entry);

	LocalActiveEntry *createActiveEntry(nis_active_endpoint *act);
	void freeActiveEntry(LocalActiveEntry *entry);

	int mgrUp();
};

#endif	/* __LOCAL_CACHE_H */
