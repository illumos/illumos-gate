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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "mt.h"
#include <sys/types.h>
#include <unistd.h>
#include <values.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <malloc.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include "mapped_cache.h"
#include "cold_start.h"
#include "nis_cache.h"
#include <rpcsvc/daemon_utils.h>

#define	CACHE_VERSION 3
#define	CACHE_MAGIC   0xbabeeeeeU

union semun {
	int val;
	struct semid_ds *buf;
	ushort *array;
} arg;

NisMappedCache::NisMappedCache(nis_error &err, int mode, int discardOldCache)
{
	err = NIS_SUCCESS;

	rwlock_init(&lock, USYNC_THREAD, NULL);
	serverMode = mode;
	mapBase = (char *)-1;
	mapSize = -1;
	if (serverMode) {
		up = 0;
		if (!checkUID()) {
			err = NIS_PERMISSION;
			return;
		}

		if (!createSemaphores()) {
			err = NIS_SYSTEMERROR;
			return;
		}

		(void) lockExclusive();
		if (discardOldCache || !mapCache()) {
			if (!createCache()) {
				unlockExclusive();
				err = NIS_SYSTEMERROR;
				return;
			}

			if (!mapCache()) {
				unlockExclusive();
				err = NIS_SYSTEMERROR;
				return;
			}
		}
		unlockExclusive();
	} else {
		if (!getSemaphores()) {
			err = NIS_SYSTEMERROR;
			return;
		}
		/* lockShared() will map in the cache */
		if (!lockShared()) {
			err = NIS_SYSTEMERROR;
			return;
		}
		unlockShared();
	}
}

NisMappedCache::~NisMappedCache()
{
}

int
NisMappedCache::checkUID()
{
	int uid = geteuid();
	if (uid != 0 && uid != DAEMON_UID) {
		syslog(LOG_ERR, "must be root to manage cache. uid = %d", uid);
		return (0);
	}

	return (1);
}

int
NisMappedCache::createSemaphores()
{
	int st;
	u_short w_array[NIS_W_NSEMS];
	union semun semarg;
	int semflg;

	semflg = IPC_CREAT |
		SEM_OWNER_READ | SEM_OWNER_ALTER |
		SEM_GROUP_READ | SEM_GROUP_ALTER |
		SEM_OTHER_READ | SEM_OTHER_ALTER;

	// get writer semaphore
	if ((sem_writer = semget(NIS_SEM_W_KEY, NIS_W_NSEMS, semflg)) == -1) {
		syslog(LOG_ERR, "can't create writer semaphore: %m");
		return (0);
	}

	// get writer semaphore value
	semarg.array = w_array;
	if (semctl(sem_writer, 0, GETALL, semarg) == -1) {
		syslog(LOG_ERR, "can't get writer value: %m");
		return (0);
	}

	// check to see if a manager is already handling the cache
	if (w_array[NIS_SEM_MGR_UP] != 0) {
		syslog(LOG_ERR, "WARNING: cache already being managed: %m");
		semarg.val = 0;
		st = semctl(sem_writer, NIS_SEM_MGR_UP, SETVAL, semarg);
		if (st == -1) {
			syslog(LOG_ERR, "can't clear write semaphore: %m");
			return (0);
		}
	}

	return (1);
}

int
NisMappedCache::getSemaphores()
{
	int semflg = 0;

	// get writer semaphore
	if ((sem_writer = semget(NIS_SEM_W_KEY, NIS_W_NSEMS, semflg)) == -1) {
		return (0);
	}

	return (1);
}

int
NisMappedCache::mapCache()
{
	const char *name;
	int open_mode;
	int map_mode;
	int status = 0;
	int fd = -1;
	struct stat stbuf;
	struct timeval now;

	if (serverMode) {
		name = PRIVATE_CACHE_FILE;
		open_mode = O_RDWR | O_SYNC;
		map_mode = PROT_READ|PROT_WRITE;
	} else {
		name = CACHE_FILE;
		open_mode = O_RDONLY;
		map_mode = PROT_READ;
	}

	fd = open(name, open_mode);
	if (fd == -1)
		goto done;
	if (fstat(fd, &stbuf) == -1) {
		syslog(LOG_ERR, "can't stat %s:  %m", name);
		goto done;
	}
	mapSize = (int)stbuf.st_size;
	mapBase = (char *)mmap(0, mapSize, map_mode, MAP_SHARED, fd, 0);
	if (mapBase == (char *)-1) {
		mapSize = -1;
		syslog(LOG_ERR, "can't mmap %s:  %m", name);
		goto done;
	}

	/* Record time of mapping */
	(void) gettimeofday(&now, 0);
	mapTime = now.tv_sec;

	header = (CacheHeader *)mapBase;
	if (header->version != CACHE_VERSION) {
		goto done;
	}
	if (header->valid == 0) {
		if (serverMode) {
			syslog(LOG_ERR, "cache left in invalid state");
			goto done;
		} else {
			/*
			 *  If the header is not valid and the cache manager
			 *  is not running, then all is lost.
			 */
			if (!checkUp())
				goto done;
		}

	}
	if (serverMode)
		header->map_size = mapSize;

	status = 1;

done:
	if (fd != -1)
		(void) close(fd);

	if (status == 0) {
		if (mapBase != (char *)-1) {
			(void) munmap(mapBase, mapSize);
			mapBase = (char *)-1;
			mapSize = -1;
		}
	}

	return (status);
}

void
NisMappedCache::unmapCache()
{
	if (mapBase != (char *)-1)
		(void) munmap(mapBase, mapSize);
}

int
NisMappedCache::createCache()
{
	int i;
	int fd;
	int st;
	CacheHeader hdr;
	int status = 0;

	/*
	 * Remove any left-over private cache file. The shared cache
	 * file (if any) will be marked invalid and replaced when we're
	 * done recreating the private cache.
	 */
	(void) unlink(PRIVATE_CACHE_FILE);
	fd = open(PRIVATE_CACHE_FILE, O_RDWR|O_CREAT, 0644);
	if (fd == -1) {
		syslog(LOG_ERR, "can't create cache file:  %m");
		goto done;
	}

	hdr.version = CACHE_VERSION;
	hdr.valid = 1;
	hdr.data_size = sizeof (CacheHeader);
	hdr.map_size = sizeof (CacheHeader);
	for (i = 0; i < NUM_SECTIONS; i++) {
		hdr.sections[i].count = 0;
		hdr.sections[i].offset = sizeof (CacheHeader);
		hdr.sections[i].length = 0;
	}

	st = write(fd, &hdr, hdr.data_size);
	if (st == -1) {
		syslog(LOG_ERR, "error writing cache file: %m");
		goto done;
	} else if (st != hdr.data_size) {
		syslog(LOG_ERR, "short write to cache file (%d, %d)",
				st, hdr.data_size);
		goto done;
	}

	(void) close(fd);

	status = 1;

done:
	if (status == 0) {
		if (fd != -1)
			(void) close(fd);
		/* Remove broken private cache; mark shared cache invalid. */
		(void) unlink(PRIVATE_CACHE_FILE);
		markSharedCacheInvalid(mapSharedCacheHeader());
	}

	return (status);
}

int
NisMappedCache::updateUaddr(char *uaddr)
{
	int size;
	int offset;
	int length;

	if (!lockExclusive())
		return (0);

	size = align(strlen(uaddr) + 1);	/* include null terminator */

	offset = header->sections[SECTION_UADDR].offset;
	length = header->sections[SECTION_UADDR].length;
	freeSpace(offset, length, SECTION_UADDR);

	offset = header->sections[SECTION_UADDR].offset;
	if (!addSpace(offset, size, SECTION_UADDR)) {
		unlockExclusive();
		return (0);
	}
	writeCache(offset, uaddr, strlen(uaddr) + 1);	/* include null */
	unlockExclusive();
	return (1);
}

char *
NisMappedCache::getUaddr()
{
	int offset;
	int length;
	char *uaddr;

	if (!lockShared())
		return (0);

	offset = header->sections[SECTION_UADDR].offset;
	length = header->sections[SECTION_UADDR].length;

	uaddr = (char *)malloc(length);
	if (uaddr) {
		(void) strcpy(uaddr, mapBase + offset);
	}
	unlockShared();
	return (uaddr);
}

void
NisMappedCache::markUp()
{
	struct sembuf buf;

	buf.sem_num = NIS_SEM_MGR_UP;
	buf.sem_op = 1;
	buf.sem_flg = SEM_UNDO;

	if (semop(sem_writer, &buf, 1) == -1) {
		syslog(LOG_ERR, "NIS_SEM_MGR_UP semop failed: %m");
	}
	up = 1;
}

void
NisMappedCache::markDown()
{
	struct sembuf buf;

	/* if we never successfully started, just return */
	if (!up)
		return;

	/*
	 *  Sync the cache file in case we were in the middle
	 *  of an update.
	 */
	if (mapBase != (char *)-1) {
		if (msync(mapBase, mapSize, MS_SYNC) == -1) {
			syslog(LOG_ERR, "msync failed:  %m");
			/* what should we do here? */
		}
	}

	buf.sem_num = NIS_SEM_MGR_UP;
	buf.sem_op = -1;
	buf.sem_flg = SEM_UNDO | IPC_NOWAIT;

	if (semop(sem_writer, &buf, 1) == -1) {
		syslog(LOG_ERR, "NIS_SEM_MGR_UP semop failed: %m");
	}
}

int
NisMappedCache::checkUp()
{
	ushort w_array[NIS_W_NSEMS];
	union semun semarg;

	if (sem_writer == -1)
		return (FALSE);

	semarg.array = w_array;
	if (semctl(sem_writer, 0, GETALL, semarg) == -1)
		return (FALSE);

	if (w_array[NIS_SEM_MGR_UP] == 0) {
		// cache manager not running
		return (FALSE);
	}
	return (TRUE);
}

nis_error
NisMappedCache::searchDir(char *dname, nis_bound_directory **binding, int near)
{
	int i;
	nis_error err;
	int distance;
	int minDistance = MAXINT;
	int minLevels = MAXINT;
	char **target;
	int target_levels;
	int found = 0;
	CacheSection *section;
	BindingEntry scan;
	BindingEntry found_entry;

	found_entry.broken_name = 0;

	*binding = NULL;

	target = __break_name(dname, &target_levels);
	if (target == 0)
		return (NIS_NOMEMORY);

	if (!lockShared()) {
		__free_break_name(target, target_levels);
		return (NIS_SYSTEMERROR);
	}

	section = &header->sections[SECTION_BINDING];
	for (i = 0; i < section->count; i++) {
		if (i == 0)
			firstBinding(&scan);
		else
			nextBinding(&scan);

		distance = __name_distance(target, scan.broken_name);
		if (distance <= minDistance) {
			// if two directories are at the same distance
			// then we want to select the directory closer to
			// the root.
			if (distance == minDistance &&
			    scan.levels >= minLevels) {
				free(scan.broken_name);
				continue;
			}
			/*
			 *  Free broken name of old saved entry.
			 */
			if (found)
				free(found_entry.broken_name);
			/*
			 *  Save this entry.
			 */
			found = 1;
			found_entry = scan;
			minDistance = distance;
			minLevels = scan.levels;
			/*
			 *  If we got an exact match, then we are done.
			 */
			if (distance == 0)
				break;
		} else {
			free(scan.broken_name);
		}
	}

	if (found == 0) {
		// cache is empty (no coldstart even)
		unlockShared();
		err = NIS_NAMEUNREACHABLE;
	} else if (near == 0 && distance != 0) {
		// we wanted an exact match, but it's not there
		unlockShared();
		err = NIS_NOTFOUND;
		free(found_entry.broken_name);
	} else {
		// we got an exact match or something near target
		err = NIS_SUCCESS;
		free(found_entry.broken_name);
		*binding = unpackBinding(found_entry.binding,
				found_entry.binding_len);
		unlockShared();
		if (*binding == NULL)
			err = NIS_NOMEMORY;
		else
			addAddresses(*binding);
	}
	__free_break_name(target, target_levels);

	return (err);
}

void
NisMappedCache::addBinding(nis_bound_directory *binding)
{
	int i;
	char *dname;
	int is_coldstart = 0;
	BindingEntry entry;
	BindingEntry scan;
	CacheSection *section;

	if (!createBindingEntry(binding, &entry))
		return;

	dname = binding->dobj.do_name;
	if (nis_dir_cmp(dname, coldStartDir()) == SAME_NAME)
		is_coldstart = 1;

	if (!lockExclusive())
		return;

	section = &header->sections[SECTION_BINDING];
	for (i = 0; i < section->count; i++) {
		if (i == 0)
			firstBinding(&scan);
		else
			nextBinding(&scan);
		if (__dir_same(scan.broken_name, entry.broken_name)) {
			free(scan.broken_name);
			freeSpace(scan.offset, scan.length,
					SECTION_BINDING);
			section->count -= 1;
			break;
		}
		free(scan.broken_name);
	}

	if (is_coldstart)
		entry.offset = section->offset;
	else
		entry.offset = section->offset + section->length;

	if (!addSpace(entry.offset, entry.length, SECTION_BINDING)) {
		free(entry.broken_name);
		free(entry.base);
		unlockExclusive();
		return;
	}
	writeCache(entry.offset, entry.base, entry.length);
	header->sections[SECTION_BINDING].count += 1;

	free(entry.broken_name);
	free(entry.base);

	unlockExclusive();
	if (is_coldstart)
		(void) writeColdStartFile(&binding->dobj);
}

void
NisMappedCache::removeBinding(nis_bound_directory *binding)
{
	int i;
	int levels;
	char **broken_name;
	BindingEntry scan;
	CacheSection *section;

	if (!lockExclusive())
		return;

	broken_name = __break_name(binding->dobj.do_name, &levels);
	if (broken_name == NULL) {
		unlockExclusive();
		return;
	}

	section = &header->sections[SECTION_BINDING];
	for (i = 0; i < section->count; i++) {
		if (i == 0)
			firstBinding(&scan);
		else
			nextBinding(&scan);
		if (__dir_same(scan.broken_name, broken_name)) {
			free(scan.broken_name);
			freeSpace(scan.offset, scan.length,
					SECTION_BINDING);
			section->count -= 1;
			break;
		}
		free(scan.broken_name);
	}
	__free_break_name(broken_name, levels);

	unlockExclusive();
}

void
NisMappedCache::print()
{
	int i;
	CacheSection *section;
	BindingEntry scan;
	nis_bound_directory *binding;
	ActiveEntry act_scan;
	nis_active_endpoint *act;

	if (!lockShared())
		return;

	section = &header->sections[SECTION_BINDING];
	for (i = 0; i < section->count; i++) {
		if (i == 0)
			firstBinding(&scan);
		else
			nextBinding(&scan);

		// hack for special format in nisshowcache
		if (__nis_debuglevel != 6) {
			if (i == 0)
				(void) printf("\nCold Start directory:\n");
			else
				(void) printf("\nNisSharedCacheEntry[%d]:\n",
				    i);
		}

		if (__nis_debuglevel == 1) {
			(void) printf("\tdir_name:'");
			__broken_name_print(scan.broken_name, scan.levels);
			(void) printf("'\n");
		}

		if (__nis_debuglevel > 2) {
			binding = unpackBinding(scan.binding, scan.binding_len);
			if (binding != NULL) {
				printBinding_exptime(binding, scan.exp_time);
				nis_free_binding(binding);
			}
		}
		free(scan.broken_name);
	}

	(void) printf("\nActive servers:\n");
	section = &header->sections[SECTION_ACTIVE];
	for (i = 0; i < section->count; i++) {
		if (i == 0)
			firstActiveEntry(&act_scan);
		else
			nextActiveEntry(&act_scan);

		act = unpackActive(act_scan.active, act_scan.active_len);
		printActive(act);
		activeFree(act);
	}

	unlockShared();

}

int
NisMappedCache::addSpace(int offset, int size, int sect)
{
	int i;
	int n;
	int extra;
	int fd = -1;
	char *buf = 0;
	int status = 0;
	char *src;
	char *dst;
	int amount;

	if (header->data_size + size > mapSize) {
		/* need to increase the size of the cache file */
		extra = header->data_size + size - mapSize;
		(void) munmap(mapBase, mapSize);
		buf = (char *)calloc(1, extra);
		if (buf == 0) {
			syslog(LOG_ERR, "out of memory");
			goto done;
		}
		fd = open(PRIVATE_CACHE_FILE, O_RDWR|O_APPEND);
		if (fd == -1) {
			syslog(LOG_ERR, "can't open %s:  %m",
					PRIVATE_CACHE_FILE);
			goto done;
		}

		n = write(fd, buf, extra);
		if (n == -1) {
			syslog(LOG_ERR, "error writing to %s: %m",
					PRIVATE_CACHE_FILE);
			goto done;
		} else if (n != extra) {
			syslog(LOG_ERR, "short write (%d, %d)", n, extra);
			goto done;
		}
		mapSize += extra;
		mapBase = (char *)mmap(0, mapSize,
				PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
		if (mapBase == (char *)-1) {
			syslog(LOG_ERR, "can't mmap %s:  %m",
					PRIVATE_CACHE_FILE);
			mapSize = -1;
			goto done;
		}
		header = (CacheHeader *)mapBase;
		header->map_size = mapSize;
	}

	src = mapBase + offset;
	dst = mapBase + offset + size;
	amount = header->data_size - offset;
	(void) memmove(dst, src, amount);

	header->sections[sect].length += size;
	for (i = sect+1; i < NUM_SECTIONS; i++) {
		header->sections[i].offset += size;
	}
	header->data_size += size;

	status = 1;

done:
	if (fd != -1)
		(void) close(fd);
	free(buf);

	return (status);
}

void
NisMappedCache::freeSpace(int offset, int size, int sect)
{
	int i;
	char *src;
	char *dst;
	int amount;

	src = mapBase + offset + size;
	dst = mapBase + offset;
	amount = header->data_size - offset - size;
	(void) memmove(dst, src, amount);

	header->sections[sect].length -= size;
	for (i = sect+1; i < NUM_SECTIONS; i++) {
		header->sections[i].offset -= size;
	}
	header->data_size -= size;
}

void
NisMappedCache::writeCache(int offset, char *src, int len)
{
	(void) memcpy(mapBase + offset, src, len);
}

int
NisMappedCache::createBindingEntry(nis_bound_directory *binding,
		BindingEntry *entry)
{
	int i;
	int size;
	int offset;
	int levels;
	char **broken_name;
	void *packed;
	int packed_len;
	char *buf;
	char *name_start;
	u_int magic = CACHE_MAGIC;
	int status = 0;

	packed = packBinding(binding, &packed_len);
	if (packed == NULL)
		goto done;

	broken_name = __break_name(binding->dobj.do_name, &levels);
	if (broken_name == NULL)
		goto done;

	/* determine space needed to store entry */
	size = 0;
	size += sizeof (u_int);		/* magic number */
	size += sizeof (int);		/* entry length */
	size += sizeof (uint32_t);		/* expire time */
	size += sizeof (int);		/* levels in directory name */
	for (i = 0; i < levels; i++) {
		size += strlen(broken_name[i]) + 1;	/* include null */
	}
	size = align(size);
	size += sizeof (int);		/* data length */
	size += packed_len;		/* room needed for data */
	size = align(size);

	/* create buffer to hold data */
	buf = (char *)malloc(size);
	if (buf == NULL)
		goto done;

	/* write data to buffer */
	offset = 0;
	entry->base = buf;
	entry->offset = 0;
	entry->length = size;
	entry->exp_time = expireTime(binding->dobj.do_ttl);
	entry->levels = levels;

	(void) memcpy(buf+offset, (char *)&magic, sizeof (u_int));
	offset += sizeof (u_int);

	(void) memcpy(buf+offset, (char *)&size, sizeof (int));
	offset += sizeof (int);

	(void) memcpy(buf+offset, (char *)&entry->exp_time, sizeof (uint32_t));
	offset += sizeof (uint32_t);

	(void) memcpy(buf+offset, (char *)&levels, sizeof (int));
	offset += sizeof (int);

	name_start = buf+offset;
	for (i = 0; i < levels; i++) {
		(void) strcpy(buf+offset, broken_name[i]);
		offset += strlen(broken_name[i]) + 1;
	}

	offset = align(offset);

	(void) memcpy(buf+offset, (char *)&packed_len, sizeof (int));
	offset += sizeof (int);

	entry->binding_len = packed_len;
	entry->binding = entry->base + offset;
	(void) memcpy(buf+offset, (char *)packed, packed_len);

	entry->broken_name = (char **)
			malloc((entry->levels + 1) * sizeof (char *));
	for (i = 0; i < entry->levels; i++) {
		entry->broken_name[i] = name_start;
		name_start += strlen(name_start) + 1;
	}
	entry->broken_name[i] = NULL;

	status = 1;

done:
	free(packed);
	if (broken_name)
		__free_break_name(broken_name, levels);

	return (status);
}

void
NisMappedCache::firstBinding(BindingEntry *entry)
{
	readBinding(entry, header->sections[SECTION_BINDING].offset);
}

void
NisMappedCache::nextBinding(BindingEntry *entry)
{
	readBinding(entry, entry->offset + entry->length);
}

void
NisMappedCache::readBinding(BindingEntry *entry, int offset)
{
	int i;
	char *p;
	u_int magic;

	entry->offset = offset;

	p = mapBase + offset;
	entry->base = (char *)p;

	magic = *(u_int *)p;
	if (magic != CACHE_MAGIC) {
		syslog(LOG_ERR, "corrupted cache (binding): 0x%x", magic);
		return;
	}
	p += sizeof (int);

	entry->length = *(int *)p;
	p += sizeof (int);

	entry->exp_time = *(uint32_t *)p;
	p += sizeof (uint32_t);

	entry->levels = *(int *)p;
	p += sizeof (int);

	entry->broken_name = (char **)
			malloc((entry->levels + 1) * sizeof (char *));
	for (i = 0; i < entry->levels; i++) {
		entry->broken_name[i] = p;
		p += strlen(p) + 1;
	}
	entry->broken_name[i] = NULL;

	p = (char *)align_ipt((intptr_t)p);
	entry->binding_len = *(int *)p;
	p += sizeof (int);

	entry->binding = p;
}

int
NisMappedCache::createActiveEntry(ActiveEntry *entry, nis_active_endpoint *act)
{
	int size;
	int offset;
	char *buf;
	void *packed;
	int packed_len;
	u_int magic = CACHE_MAGIC;
	int status = 0;

	packed = packActive(act, &packed_len);
	if (packed == NULL)
		goto done;

	/* determine space needed to store entry */
	size = 0;
	size += sizeof (u_int);		/* magic number */
	size += sizeof (int);		/* entry length */
	size += strlen(act->ep.family) + 1;	/* family */
	size += strlen(act->ep.proto) + 1;	/* proto */
	size += strlen(act->ep.uaddr) + 1;	/* uaddr */
	size = align(size);
	size += sizeof (int);		/* data length */
	size += packed_len;		/* room needed for data */
	size = align(size);

	/* create buffer to hold data */
	buf = (char *)malloc(size);
	if (buf == NULL)
		goto done;

	/* write data to buffer */
	offset = 0;
	entry->base = buf;
	entry->offset = 0;
	entry->length = size;

	(void) memcpy(buf+offset, (char *)&magic, sizeof (u_int));
	offset += sizeof (u_int);

	(void) memcpy(buf+offset, (char *)&size, sizeof (int));
	offset += sizeof (int);

	entry->ep.family = entry->base + offset;
	(void) strcpy(buf+offset, act->ep.family);
	offset += strlen(act->ep.family) + 1;

	entry->ep.proto = entry->base + offset;
	(void) strcpy(buf+offset, act->ep.proto);
	offset += strlen(act->ep.proto) + 1;

	entry->ep.uaddr = entry->base + offset;
	(void) strcpy(buf+offset, act->ep.uaddr);
	offset += strlen(act->ep.uaddr) + 1;

	offset = align(offset);

	(void) memcpy(buf+offset, (char *)&packed_len, sizeof (int));
	offset += sizeof (int);

	entry->active_len = packed_len;
	entry->active = entry->base + offset;
	(void) memcpy(buf+offset, (char *)packed, packed_len);
	offset += packed_len;

	status = 1;

done:
	free(packed);
	return (status);
}

void
NisMappedCache::readActiveEntry(ActiveEntry *entry, int offset)
{
	char *p;
	u_int magic;

	entry->offset = offset;

	p = mapBase + offset;
	entry->base = (char *)p;

	magic = *(u_int *)p;
	if (magic != CACHE_MAGIC) {
		syslog(LOG_ERR, "corrupted cache (endpoint): 0x%x", magic);
		return;
	}
	p += sizeof (u_int);

	entry->length = *(int *)p;
	p += sizeof (int);

	entry->ep.family = p;
	p += strlen(p) + 1;

	entry->ep.proto = p;
	p += strlen(p) + 1;

	entry->ep.uaddr = p;
	p += strlen(p) + 1;

	p = (char *)align_ipt((intptr_t)p);
	entry->active_len = *(int *)p;
	p += sizeof (int);

	entry->active = p;
}

void
NisMappedCache::firstActiveEntry(ActiveEntry *entry)
{
	readActiveEntry(entry, header->sections[SECTION_ACTIVE].offset);
}

void
NisMappedCache::nextActiveEntry(ActiveEntry *entry)
{
	readActiveEntry(entry, entry->offset + entry->length);
}

void
NisMappedCache::activeAdd(nis_active_endpoint *act)
{
	ActiveEntry entry;

	if (!lockExclusive())
		return;

	if (!createActiveEntry(&entry, act)) {
		unlockExclusive();
		return;
	}
	activeFree(act);	/* no longer needed */
	entry.offset = header->sections[SECTION_ACTIVE].offset;
	if (!addSpace(entry.offset, entry.length, SECTION_ACTIVE)) {
		free(entry.base);
		unlockExclusive();
		return;
	}
	writeCache(entry.offset, entry.base, entry.length);
	header->sections[SECTION_ACTIVE].count += 1;

	free(entry.base);
	unlockExclusive();
}

void
NisMappedCache::activeRemove(endpoint *ep, int all)
{
	int i;
	ActiveEntry scan;
	CacheSection *section;

	if (!lockExclusive())
		return;

restart:
	section = &header->sections[SECTION_ACTIVE];
	for (i = 0; i < section->count; i++) {
		if (i == 0)
			firstActiveEntry(&scan);
		else
			nextActiveEntry(&scan);

		if (strcmp(scan.ep.family, ep->family) == 0 &&
		    (all || strcmp(scan.ep.proto, ep->proto) == 0) &&
		    strcmp(scan.ep.uaddr, ep->uaddr) == 0) {
			freeSpace(scan.offset, scan.length, SECTION_ACTIVE);
			header->sections[SECTION_ACTIVE].count -= 1;
			/*
			 *  If we are getting rid of all servers regardless
			 *  of protocol, then we need to restart the
			 *  search because removing an entry invalidates
			 *  our "iteration".  If we are just removing
			 *  a single server, then we are done.
			 */
			if (all)
				goto restart;
			break;
		}
	}
	unlockExclusive();
}

int
NisMappedCache::activeCheck(endpoint *ep)
{
	int ret = 0;

	if (!lockShared())
		return (ret);

	ret = activeCheckInternal(ep);

	unlockShared();

	return (ret);
}

int
NisMappedCache::activeCheckInternal(endpoint *ep)
{
	int i;
	ActiveEntry scan;
	CacheSection *section;

	section = &header->sections[SECTION_ACTIVE];
	for (i = 0; i < section->count; i++) {
		if (i == 0)
			firstActiveEntry(&scan);
		else
			nextActiveEntry(&scan);

		if (strcmp(scan.ep.family, ep->family) == 0 &&
		    strcmp(scan.ep.proto, ep->proto) == 0 &&
		    strcmp(scan.ep.uaddr, ep->uaddr) == 0) {
			return (1);
		}
	}
	return (0);
}

int
NisMappedCache::activeGet(endpoint *ep, nis_active_endpoint **act)
{
	int ret = 0;

	if (!lockShared())
		return (ret);

	ret = activeGetInternal(ep, act);

	unlockShared();
	return (ret);
}

int
NisMappedCache::activeGetInternal(endpoint *ep, nis_active_endpoint **act)
{
	int i;
	ActiveEntry scan;
	CacheSection *section;

	section = &header->sections[SECTION_ACTIVE];
	for (i = 0; i < section->count; i++) {
		if (i == 0)
			firstActiveEntry(&scan);
		else
			nextActiveEntry(&scan);

		if (strcmp(scan.ep.family, ep->family) == 0 &&
		    strcmp(scan.ep.proto, ep->proto) == 0 &&
		    strcmp(scan.ep.uaddr, ep->uaddr) == 0) {
			*act = unpackActive(scan.active,
					scan.active_len);
			if (*act)
				return (1);
			else
				return (0);
		}
	}
	return (0);
}

int
NisMappedCache::getStaleEntries(nis_bound_directory ***bindings)
{
	int i;
	struct timeval now;
	int stale_count = 0;
	CacheSection *section;
	BindingEntry scan;

	(void) gettimeofday(&now, NULL);

	if (!lockShared()) {
		*bindings = 0;
		return (0);
	}

	/*
	 * We allocate more than we need so that we don't have to
	 * figure out how many stale entries there are ahead of time.
	 */
	section = &header->sections[SECTION_BINDING];
	*bindings = (nis_bound_directory **)
		    malloc(section->count * sizeof (nis_bound_directory *));
	if (*bindings == NULL) {
		unlockShared();
		return (0);
	}
	for (i = 0; i < section->count; i++) {
		if (i == 0)
			firstBinding(&scan);
		else
			nextBinding(&scan);

		if (now.tv_sec > scan.exp_time) {
			/*
			 *  Unpack the binding, but don't bother adding
			 *  the bound addresses, because purging doesn't
			 *  need them.
			 */
			(*bindings)[stale_count] =
				unpackBinding(scan.binding, scan.binding_len);
			if ((*bindings)[stale_count] != NULL)
				stale_count++;
		}
		free(scan.broken_name);
	}
	unlockShared();

	return (stale_count);
}

int
NisMappedCache::getAllEntries(nis_bound_directory ***bindings)
{
	int i;
	int n;
	CacheSection *section;
	BindingEntry scan;

	if (!lockShared()) {
		*bindings = 0;
		return (0);
	}

	section = &header->sections[SECTION_BINDING];
	*bindings = (nis_bound_directory **)
		    malloc(section->count * sizeof (nis_bound_directory *));
	if (*bindings == NULL) {
		unlockShared();
		return (0);
	}
	n = 0;
	for (i = 0; i < section->count; i++) {
		if (i == 0)
			firstBinding(&scan);
		else
			nextBinding(&scan);

		/*
		 *  Unpack the binding, but don't bother adding
		 *  the bound addresses, because we don't
		 *  need them.
		 */
		(*bindings)[n] =
			unpackBinding(scan.binding, scan.binding_len);
		if ((*bindings)[n] != NULL)
			n++;
		free(scan.broken_name);
	}
	unlockShared();

	return (n);
}

int
NisMappedCache::getAllActive(nis_active_endpoint ***actlist)
{
	int i;
	CacheSection *section;
	ActiveEntry scan;

	if (!lockShared()) {
		*actlist = 0;
		return (0);
	}

	section = &header->sections[SECTION_ACTIVE];
	*actlist = (nis_active_endpoint **)
		    malloc(section->count * sizeof (nis_active_endpoint *));
	if (*actlist == NULL) {
		unlockShared();
		return (0);
	}
	for (i = 0; i < section->count; i++) {
		if (i == 0)
			firstActiveEntry(&scan);
		else
			nextActiveEntry(&scan);

		/*
		 *  Unpack the entry, but don't bother adding
		 *  the bound addresses, because we don't
		 *  need them.
		 */
		(*actlist)[i] = unpackActive(scan.active, scan.active_len);
	}
	unlockShared();

	return (i);
}

int
NisMappedCache::nextStale()
{
	int i;
	int diff;
	int min = -1;
	struct timeval now;
	CacheSection *section;
	BindingEntry scan;

	(void) gettimeofday(&now, NULL);

	if (!lockShared()) {
		return (-1);
	}

	section = &header->sections[SECTION_BINDING];
	for (i = 0; i < section->count; i++) {
		if (i == 0)
			firstBinding(&scan);
		else
			nextBinding(&scan);

		diff = scan.exp_time - now.tv_sec;
		if (diff < 0)
			diff = 0;
		if (min == -1 || diff < min)
			min = diff;
		free(scan.broken_name);
	}
	unlockShared();

	return (min);
}

int
NisMappedCache::align(int n)
{
	return ((n + 3) & ~3);
}

/*
 * The mapped cache is shared by both ILP32 and LP64 processes.
 * Both need to see the mapped cache identically, hence all
 * padding is aligned to an int i.e 4 byte boundary.
 */

intptr_t
NisMappedCache::align_ipt(intptr_t n)
{
	size_t asize;

	asize = (sizeof (int) - 1);
	return ((intptr_t) ((n + asize) & ~asize));
}

CacheHeader *
NisMappedCache::mapSharedCacheHeader()
{
	int fd;
	CacheHeader *hdr = (CacheHeader *)MAP_FAILED;

	fd = open(CACHE_FILE, O_RDWR);
	if (fd >= 0) {
		hdr = (CacheHeader *)mmap(0, sizeof (CacheHeader),
				PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
		if (hdr == (CacheHeader *)MAP_FAILED) {
			syslog(LOG_ERR,
				"mapSharedCacheHeader: mmap(\"%s\"): %m",
					CACHE_FILE);
		}
		close(fd);
	}

	return (hdr);
}

void
NisMappedCache::markSharedCacheInvalid(CacheHeader *hdr)
{
	if (hdr != (CacheHeader *)MAP_FAILED) {
		hdr->valid = 0;
		if (msync((caddr_t)hdr, sizeof (CacheHeader), MS_SYNC) ==
			-1) {
			syslog(LOG_ERR,
				"markSharedCacheInvalid: msync(\"%s\"): %m",
					CACHE_FILE);
		}
		if (munmap((caddr_t)hdr, sizeof (CacheHeader)) < 0) {
			syslog(LOG_ERR,
				"markSharedCacheInvalid: munmap<old>: %m");
		}
	}
}

int
NisMappedCache::updatePublicCache()
{
	int fd;
	CacheHeader *pub;
	size_t pubsize = sizeof (CacheHeader);
	char *buf;
	int st;
	int count;

	/*
	 *  Create a copy of the private cache in TMP_CACHE_FILE.
	 */
	(void) unlink(TMP_CACHE_FILE);
	fd = open(TMP_CACHE_FILE, O_RDWR|O_CREAT, 0644);
	if (fd == -1) {
		syslog(LOG_ERR, "updatePublicCache: open(\"%s\"): %m",
				TMP_CACHE_FILE);
		return (0);
	}
	count = mapSize;
	buf = mapBase;
	while (count > 0) {
		st = write(fd, buf, count);
		if (st == -1) {
			syslog(LOG_ERR, "updatePublicCache: write(\"%s\"): %m",
					TMP_CACHE_FILE);
			(void) close(fd);
			(void) unlink(TMP_CACHE_FILE);
			return (0);
		}
		buf += st;
		count -= st;
	}
	st = close(fd);
	if (st == -1) {
		syslog(LOG_ERR, "updatePublicCache: close(\"%s\"): %m",
				TMP_CACHE_FILE);
		(void) unlink(TMP_CACHE_FILE);
		return (0);
	}

	/*
	 *  Open the current public cache file and map in the
	 *  header so that we will be able to mark it invalid
	 *  even after we clobber it with the new cache file.
	 */
	pub = mapSharedCacheHeader();

	/*
	 *  Rename the tmp cache file to the new name.  This is an
	 *  atomic operation; other processes opening CACHE_FILE will
	 *  either get the old one or the new one.
	 */
	st = rename(TMP_CACHE_FILE, CACHE_FILE);
	if (st == -1) {
		syslog(LOG_ERR, "updatePublicCache: rename: %m");
		(void) unlink(TMP_CACHE_FILE);
		return (FALSE);
	}

	/*
	 * Now mark the old incarnation of the public cache invalid.
	 * We delay doing this until after the rename that replaces
	 * the old file, so that any process that (re-)opens the public
	 * cache will always get a valid file.
	 */
	markSharedCacheInvalid(pub);

	return (1);
}

int
NisMappedCache::lockExclusive()
{
	sig_rw_wrlock(&lock);
	return (1);
}

void
NisMappedCache::unlockExclusive()
{
	if (serverMode)
		updatePublicCache();
	sig_rw_unlock(&lock);
}

int
NisMappedCache::lockShared()
{
	struct sembuf buf;
	int save_errno;
	struct timeval now;

	sig_rw_rdlock(&lock);

	while (1) {
		/*
		 *  Make sure that we have mapped the whole cache.  It is
		 *  okay to map more than the size of the cache; we won't
		 *  read that far.  We release our shared lock and then
		 *  grab an exclusive lock.  This will prevent any
		 *  interaction between threads on the cache pointers.
		 */
		(void) gettimeofday(&now, 0);
		if (mapBase == (char *)-1 ||
			now.tv_sec - mapTime > SHARED_CACHE_TTL ||
		    mapSize < header->map_size ||
		    header->valid == 0) {
			unlockShared();
			(void) lockExclusive();
			unmapCache();
			if (!mapCache()) {
				unlockExclusive();
				return (0);
			}
			unlockExclusive();
			sig_rw_rdlock(&lock);
			continue;
		}

		break;
	}

	return (1);
}

void
NisMappedCache::unlockShared()
{
	sig_rw_unlock(&lock);
}
