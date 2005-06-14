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
 * Copyright 1988-1992,2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mt.h"
#include "../../rpc/rpc_mt.h"
#include  <stdlib.h>
#include  <rpc/rpc.h>
#include  <values.h>
#include  <string.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <syslog.h>
#include  <rpcsvc/nis.h>
#include "local_cache.h"
#include "cold_start.h"

NisLocalCache::NisLocalCache(nis_error &status)
{
	rwlock_init(&lock, USYNC_THREAD, NULL);
	head = NULL;
	tail = NULL;
	act_list = NULL;
	have_coldstart = 0;
	sem_writer = -1;

	//  read in entry from coldstart file
	if (readColdStart())
		status = NIS_SUCCESS;
	else
		status = NIS_COLDSTART_ERR;
}


NisLocalCache::NisLocalCache(nis_error &status, uint32_t *exp_time)
{
	rwlock_init(&lock, USYNC_THREAD, NULL);
	head = NULL;
	tail = NULL;
	act_list = NULL;
	have_coldstart = 0;
	sem_writer = -1;

	//  read in entry from coldstart file
	if (readServerColdStart(exp_time))
		status = NIS_SUCCESS;
	else
		status = NIS_COLDSTART_ERR;
}

NisLocalCache::~NisLocalCache()
{
	// We don't free anything because we don't know
	// how many threads have a reference to us.
}

// Return the binding for the directory name if it exists in the cache.
// If 'near' is set, then we return a binding to a directory that is
// close to 'dname'.
nis_error
NisLocalCache::searchDir(char *dname, nis_bound_directory **binding, int near)
{
	int		distance;
	int 		minDistance = MAXINT;
	int  		minLevels = MAXINT;
	nis_error	err;
	struct timeval 	now;
	char		**target;
	int		target_levels;
	LocalCacheEntry	*scan;
	LocalCacheEntry	*found = NULL;

	*binding = NULL;
	target = __break_name(dname, &target_levels);
	if (target == 0)
		return (NIS_NOMEMORY);

	(void) gettimeofday(&now, NULL);

	lockShared();
	for (scan = head; scan; scan = scan->next) {
		distance = __name_distance(target, scan->components);
		if (distance <= minDistance) {
			// if two directories are at the same distance
			// then we want to select the directory closer to
			// the root.
			if (distance == minDistance &&
			    scan->levels >= minLevels) {
				// this one is further from the root, ignore it
				continue;
			}
			found = scan;
			minDistance = distance;
			minLevels = scan->levels;
		}
		if (distance == 0)
			break;
	}

	if (found == 0) {
		// cache is empty (no coldstart even)
		err = NIS_NAMEUNREACHABLE;
	} else if (near == 0 && distance != 0) {
		// we wanted an exact match, but it's not there
		err = NIS_NOTFOUND;
	} else {
		// we got an exact match or something near target
		err = NIS_SUCCESS;
		*binding = unpackBinding(found->binding_val,
					found->binding_len);
		if (*binding == NULL) {
			err = NIS_NOMEMORY;
		} else {
			struct timeval now;
			gettimeofday(&now, 0);
			if (found->expTime < now.tv_sec) {
				err = NIS_CACHEEXPIRED;
			}
		}

	}
	unlockShared();
	if (*binding)
		addAddresses(*binding);

	__free_break_name(target, target_levels);
	return (err);
}

void
NisLocalCache::addBinding(nis_bound_directory *binding)
{
	LocalCacheEntry *new_entry;
	LocalCacheEntry *scan;
	LocalCacheEntry *prev;
	int is_coldstart = 0;

	new_entry = createCacheEntry(binding);
	if (new_entry == 0)
		return;

	if (nis_dir_cmp(new_entry->name, coldStartDir()) == SAME_NAME)
		is_coldstart = 1;

	lockExclusive();
	prev = NULL;
	for (scan = head; scan; scan = scan->next) {
		if (nis_dir_cmp(scan->name, new_entry->name) == SAME_NAME) {
			if (scan == head) {
				head = scan->next;
			} else {
				prev->next = scan->next;
			}
			if (scan == tail) {
				if (prev)
					tail = prev;
				else
					tail = NULL;
			}
			freeCacheEntry(scan);
			break;
		}
		prev = scan;
	}

	if (is_coldstart) {
		have_coldstart = 1;
		new_entry->next = head;
		head = new_entry;
		if (tail == 0)
			tail = new_entry;
	} else {
		if (tail)
			tail->next = new_entry;
		tail = new_entry;
		if (head == 0)
			head = new_entry;
	}

	unlockExclusive();
}

void
NisLocalCache::removeBinding(nis_bound_directory *binding)
{
	LocalCacheEntry *scan;
	LocalCacheEntry *prev;
	char *dname;

	dname = binding->dobj.do_name;
	lockExclusive();
	prev = NULL;
	for (scan = head; scan; scan = scan->next) {
		if (nis_dir_cmp(scan->name, dname) == SAME_NAME) {
			if (scan == head) {
				have_coldstart = 0;
				head = scan->next;
			} else {
				prev->next = scan->next;
			}
			if (scan == tail) {
				if (prev)
					tail = prev;
				else
					tail = NULL;
			}
			freeCacheEntry(scan);
			break;
		}
		prev = scan;
	}
	unlockExclusive();
}

LocalCacheEntry *
NisLocalCache::createCacheEntry(nis_bound_directory *binding)
{
	LocalCacheEntry *entry;

	entry = new LocalCacheEntry;
	if (!entry)
		return (NULL);

	entry->name = strdup(binding->dobj.do_name);
	entry->components = __break_name(binding->dobj.do_name, &entry->levels);
	entry->expTime = expireTime(binding->dobj.do_ttl);
	entry->generation = nextGeneration();
	entry->binding_val = packBinding(binding, &entry->binding_len);
	entry->next = NULL;

	if (entry->name == NULL ||
	    entry->components == NULL ||
	    entry->binding_val == NULL) {
		freeCacheEntry(entry);
		return (NULL);
	}

	return (entry);
}

void
NisLocalCache::freeCacheEntry(LocalCacheEntry *entry)
{
	free(entry->name);
	if (entry->components)
		__free_break_name(entry->components, entry->levels);
	free(entry->binding_val);
	delete entry;
}

void
NisLocalCache::activeAdd(nis_active_endpoint *act)
{
	LocalActiveEntry *entry;

	lockExclusive();
	entry = createActiveEntry(act);
	if (entry) {
		entry->next = act_list;
		act_list = entry;
	}
	unlockExclusive();
}

void
NisLocalCache::activeRemove(endpoint *ep, int all)
{
	LocalActiveEntry *entry;
	LocalActiveEntry *prev = NULL;

	lockExclusive();
restart:
	for (entry = act_list; entry; entry = entry->next) {
		if (strcmp(entry->act->ep.family, ep->family) == 0 &&
		    (all || strcmp(entry->act->ep.proto, ep->proto) == 0) &&
		    strcmp(entry->act->ep.uaddr, ep->uaddr) == 0) {
			if (prev)
				prev->next = entry->next;
			else
				act_list = entry->next;
			activeFree(entry->act);
			freeActiveEntry(entry);
			if (all)
				goto restart;
			break;
		}
	}
	unlockExclusive();
}

int
NisLocalCache::activeCheck(endpoint *ep)
{
	int ret = 0;
	LocalActiveEntry *entry;

	lockShared();
	for (entry = act_list; entry; entry = entry->next) {
		if (strcmp(entry->act->ep.family, ep->family) == 0 &&
		    strcmp(entry->act->ep.proto, ep->proto) == 0 &&
		    strcmp(entry->act->ep.uaddr, ep->uaddr) == 0) {

			ret = 1;
			break;
		}
	}
	unlockShared();
	return (ret);
}


int
NisLocalCache::activeGet(endpoint *ep, nis_active_endpoint **act)
{
	int ret = 0;
	LocalActiveEntry *entry;

	lockShared();
	for (entry = act_list; entry; entry = entry->next) {
		if (strcmp(entry->act->ep.family, ep->family) == 0 &&
		    strcmp(entry->act->ep.proto, ep->proto) == 0 &&
		    strcmp(entry->act->ep.uaddr, ep->uaddr) == 0) {
			*act = activeDup(entry->act);
			ret = 1;
			break;
		}
	}
	unlockShared();
	return (ret);
}

int
NisLocalCache::getAllActive(nis_active_endpoint ***actlist)
{
	int ret = 0;
	LocalActiveEntry *entry;

	lockShared();
	for (entry = act_list; entry; entry = entry->next) {
		ret++;
	}

	*actlist = (nis_active_endpoint **)
		malloc(ret * sizeof (nis_active_endpoint *));
	if (*actlist == NULL) {
		unlockShared();
		return (0);
	}

	for (ret = 0, entry = act_list; entry; entry = entry->next) {
		(*actlist)[ret++] = activeDup(entry->act);
	}

	unlockShared();
	return (ret);
}

LocalActiveEntry *
NisLocalCache::createActiveEntry(nis_active_endpoint *act)
{
	LocalActiveEntry *entry;

	entry = new LocalActiveEntry;
	if (entry == NULL)
		return (NULL);

	entry->act = act;
	entry->next = NULL;
	return (entry);
}

void
NisLocalCache::freeActiveEntry(LocalActiveEntry *entry)
{
	delete entry;
}

void
NisLocalCache::print()
{
	int i;
	LocalCacheEntry *entry;
	LocalActiveEntry *act_entry;
	nis_bound_directory *binding;

	lockShared();
	for (entry = head, i = 0; entry; entry = entry->next, i++) {
		// hack for special format in nisshowcache
		if (__nis_debuglevel != 6) {
			if (i == 0 && have_coldstart)
				(void) printf("\nCold Start directory:\n");
			else
				(void) printf("\nNisLocalCacheEntry[%d]:\n", i);
		}

		if (__nis_debuglevel == 1) {
			(void) printf("\tdir_name:'%s'\n", entry->name);
		}

		if (__nis_debuglevel > 2) {
			binding = unpackBinding(entry->binding_val,
					entry->binding_len);
			if (binding != NULL) {
				printBinding_exptime(binding, entry->expTime);
				nis_free_binding(binding);
			}
		}
	}

	(void) printf("\nActive servers:\n");
	for (act_entry = act_list; act_entry; act_entry = act_entry->next) {
		printActive(act_entry->act);
	}
	unlockShared();
}

void
NisLocalCache::lockShared()
{
	sig_rw_rdlock(&lock);
}

void
NisLocalCache::unlockShared()
{
	sig_rw_unlock(&lock);
}

void
NisLocalCache::lockExclusive()
{
	sig_rw_wrlock(&lock);
}

void
NisLocalCache::unlockExclusive()
{
	sig_rw_unlock(&lock);
}

int
NisLocalCache::mgrUp()
{
	u_short w_array[NIS_W_NSEMS];
	union semun {
		int val;
		struct semid_ds *buf;
		ushort *array;
	} semarg;

	lockExclusive();
	if (sem_writer == -1) {
		// get writer semaphore
		sem_writer = semget(NIS_SEM_W_KEY, NIS_W_NSEMS, 0);
		if (sem_writer == -1) {
			syslog(LOG_DEBUG, "can't create writer semaphore: %m");
			unlockExclusive();
			return (0);
		}
	}
	unlockExclusive();

	// get writer semaphore value
	semarg.array = w_array;
	if (semctl(sem_writer, 0, GETALL, semarg) == -1) {
		syslog(LOG_DEBUG, "can't get writer value: %m");
		return (0);
	}

	// check to see if a manager is already handling the cache
	if (w_array[NIS_SEM_MGR_UP] == 0)
		return (0);

	return (1);
}


uint32_t
NisLocalCache::loadPreferredServers()
{
	uint32_t ul = 0;

	if (!mgrUp()) {
		return (0);
	}

	/*
	 * read from the "dot" file first.  If successful, return the
	 * TTL value.
	 */
	lockExclusive();
	ul = loadDotFile();
	unlockExclusive();
	if (ul > 0)
		return (ul);

	/* failed to load the Dot file. */
	return (0);
}

uint32_t
NisLocalCache::refreshCache()
{
	uint32_t ul;

	backupPreference();
	ul = loadPreferredServers();
	if (ul > 0) {
		delBackupPref();
		rerankServers();
		return (ul);
	}
	restorePreference();
	return (expireTime(ONE_HOUR));
}

int
NisLocalCache::resetBinding(nis_bound_directory *binding) {
	removeBinding(binding);
	return (1);
}
