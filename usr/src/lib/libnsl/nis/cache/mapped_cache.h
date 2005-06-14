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

#ifndef	__MAPPED_CACHE_H
#define	__MAPPED_CACHE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#ifdef __cplusplus
extern "C" {
#endif

#include "cache.h"


#define	SECTION_UADDR	0	/* cache manager's uaddr */
#define	SECTION_BINDING	1	/* list of bound directories */
#define	SECTION_ACTIVE	2	/* list of active servers */
#define	NUM_SECTIONS	3

#define	SHARED_CACHE_TTL	(6*24*60*60)

struct CacheSection {
	int count;
	int offset;
	int length;
};

struct CacheHeader {
	int version;
	int valid;
	int map_size;
	int data_size;
	CacheSection sections[NUM_SECTIONS];
};

struct BindingEntry {
	char *base;
	int offset;
	int length;
	uint32_t exp_time;
	int min_rank;
	int optimal_rank;
	int levels;
	char **broken_name;
	int binding_len;
	void *binding;
};

struct ActiveEntry {
	char *base;
	int offset;
	int length;
	endpoint ep;
	int active_len;
	void *active;
};

class NisMappedCache : public NisCache {
    public:
	NisMappedCache(nis_error &error, int serverMode = 0,
			int discardOldCache = 0);
	~NisMappedCache();

	nis_error searchDir(char *dname,
		nis_bound_directory **binding, int near);
	void addBinding(nis_bound_directory *binding);
	void removeBinding(nis_bound_directory *binding);
	void print();

	void activeAdd(nis_active_endpoint *act);
	void activeRemove(endpoint *ep, int all);
	int activeCheck(endpoint *ep);
	int activeGet(endpoint *ep, nis_active_endpoint **act);
	int activeCheckInternal(endpoint *ep);
	int activeGetInternal(endpoint *ep, nis_active_endpoint **act);

	int getStaleEntries(nis_bound_directory ***bindings);
	int getAllEntries(nis_bound_directory ***bindings);
	int nextStale();
	int getAllActive(nis_active_endpoint ***actlist);

	int updateUaddr(char *uaddr);
	char *getUaddr();
	void markUp();
	void markDown();
	int checkUp();

	void *operator new(size_t bytes) { return calloc(1, bytes); }
	void operator delete(void *arg) { free(arg); }

    private:
	rwlock_t lock;
	int up;
	int serverMode;
	char *mapBase;
	int mapSize;
	ino_t mapInode;
	dev_t mapDev;
	CacheHeader *header;
	int sem_writer;
	time_t mapTime;

	int checkUID();
	int createSemaphores();
	int getSemaphores();
	int mapCache(int discardOldCache);
	int mapCache();
	void unmapCache();
	int createCache();

	void freeSpace(int offset, int size, int section);
	int addSpace(int offset, int size, int sect);
	void writeCache(int offset, char *src, int len);

	int createBindingEntry(nis_bound_directory *binding,
			BindingEntry *entry);
	void readBinding(BindingEntry *entry, int offset);
	void firstBinding(BindingEntry *entry);
	void nextBinding(BindingEntry *entry);

	int createActiveEntry(ActiveEntry *entry, nis_active_endpoint *act);
	void readActiveEntry(ActiveEntry *entry, int offset);
	void firstActiveEntry(ActiveEntry *entry);
	void nextActiveEntry(ActiveEntry *entry);

	int align(int n);
	intptr_t align_ipt(intptr_t n);
	int updatePublicCache();
	int lockExclusive();
	void unlockExclusive();
	int lockShared();
	void unlockShared();

	CacheHeader *mapSharedCacheHeader();
	void markSharedCacheInvalid(CacheHeader *hdr);
};

#ifdef __cplusplus
}
#endif

#endif	/* __MAPPED_CACHE_H */
