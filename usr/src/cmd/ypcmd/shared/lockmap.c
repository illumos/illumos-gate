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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <unistd.h>
#include <syslog.h>
#include <sys/mman.h>
#include <thread.h>
#include <synch.h>
#include <strings.h>
#include <ndbm.h>
#include "../ypsym.h"
#include "../ypdefs.h"
#include "shim.h"

/*
 *  These routines provide mutual exclusion between ypserv and ypxfr.
 *  Mutual exclusion is needed so that ypxfr doesn't try to rename
 *  dbm files while ypserv is trying to open them.  After ypserv has
 *  opened a dbm file, it is safe to rename it because ypserv still
 *  has access to the file through its file descriptor.
 */

#define	LOCKFILE "/var/run/yp_maplock"
struct lockarray {
	mutex_t		locknode[MAXHASH];
};
typedef struct lockarray lockarray;

/*
 * Cross-process robust mutex locks.
 * Provide synchronization between YP processes
 * by implementing an exclusive locking mechanism
 * via a memory-mapped file.
 */
static struct lockarray	*shmlockarray;
static int	lockfile;

/*
 * Hash functions, used for by the locking mechanism.
 *
 * - hash() is the front-end function that gets called.
 * - get_map_id() returns a unique int value per map.
 *      It is used in N2L mode only.
 *      It is called by hash() in N2L mode.
 */
int
get_map_id(char *map_name, int index)
{
	map_id_elt_t *cur_elt;
	/*
	 * Local references to hash table for map lists
	 * and to max number of maps
	 */
	map_id_elt_t **map_list_p;
	int max_map;

	/* initializes map_list_p & max_map */
	get_list_max(&map_list_p, &max_map);

	cur_elt = map_list_p[index];
	while (cur_elt != NULL) {
		if (strcmp(map_name, cur_elt->map_name) == 0) {
			/* found */
			return (cur_elt->map_id);
		}
		cur_elt = cur_elt->next;
	}
	syslog(LOG_WARNING, "get_map_id: no hash id found for %s"
		", giving max_map value (%d)",
		map_name, max_map);
	/*
	 * max_map does not match any map id, hence
	 * will not trigger any lock collision
	 * with existing maps.
	 * Needed for yp regular locking mechanism.
	 */
	return (max_map);
}

int
hash(char *s)
{
	unsigned int n = 0;
	int i;
	char *map_name = s;

	for (i = 1; *s; i += 10, s++) {
		n += i * (*s);
	}
	n %= MAXHASH;

	if (yptol_mode & yptol_newlock) {
		return (get_map_id(map_name, n));
	} else {
		return (n);
	}
}

bool
init_locks_mem()
{
	int iiter, rc;
	int ebusy_cnt = 0;

	/*
	 * Initialize cross-process locks in memory-mapped file.
	 */
	for (iiter = 0; iiter < MAXHASH; iiter++) {
		if (rc = mutex_init(&(shmlockarray->locknode[iiter]),
		    USYNC_PROCESS | LOCK_ROBUST, 0)) {
			if (rc == EBUSY) {
				ebusy_cnt++;
			} else {
				syslog(LOG_ERR,
				    "init_locks_mem():mutex_init():error=%d",
				    rc);
				return (FALSE);
			}
		}
	}

	/*
	 * EBUSY for all locks OK, it means another process
	 * has already initialized locks.
	 */
	if ((ebusy_cnt > 0) && (ebusy_cnt != MAXHASH)) {
		syslog(LOG_ERR,
		    "%s inconsistent. Remove and restart NIS (YP).", LOCKFILE);
		return (FALSE);
	}
	return (TRUE);
}

bool
init_lock_map()
{
	char buff[ sizeof (lockarray) ];
	int write_cnt, lf_size;
	struct stat fdata;

	/*
	 * Locking file initialization algorithm, with recovery mechanism.
	 * This mechanism has been devised to ensure proper creation
	 * of a memory-mapped lock file containing mutexes for robust,
	 * inter-process communication.
	 * File name is /var/run/yp_maplock (LOCKFILE).  It might or might
	 * not exist.
	 *
	 * Algorithm:
	 * Try to open the file. If file doesn't exist, or size is too small,
	 * create/rewrite the file, m-map it into memory and initialize the
	 * mutexes in it.
	 * If file exists and size is at least large enough, assume it's a
	 * good file, and m-map the lock structure directly to it.
	 *
	 * Recovery from inconsistent state is easy - simply delete the file
	 * and restart NIS (YP).
	 */

	lockfile = open(LOCKFILE, O_RDWR|O_CREAT, 0600);
	if (lockfile != -1) {
		if (lockf(lockfile, F_LOCK, 0) == 0) {
			if (fstat(lockfile, &fdata) == 0) {
				lf_size = fdata.st_size;
				if (lf_size < sizeof (lockarray)) {
					bzero(buff, sizeof (buff));
					if ((write_cnt = write(lockfile, buff,
					    sizeof (buff)) != sizeof (buff))) {
						if (write_cnt < 0) {
							syslog(LOG_ERR,
						    "write(%s) => errno=%d",
							    LOCKFILE, errno);
						} else {
							syslog(LOG_ERR,
		    "write(%s) => %d!=%d: wrong number of bytes written.",
							    LOCKFILE,
							    write_cnt,
							    sizeof (buff));
						}
						lockf(lockfile, F_ULOCK, 0);
						close(lockfile);
						return (FALSE);
					}
				}
			} else {
				syslog(LOG_ERR,
				    "fstat(%s) => errno=%d", LOCKFILE, errno);
				lockf(lockfile, F_ULOCK, 0);
				close(lockfile);
				return (FALSE);
			}
		} else {
			syslog(LOG_ERR,
			    "lockf(%s,F_LOCK) => errno=%d", LOCKFILE, errno);
			close(lockfile);
			return (FALSE);
		}
	} else {
		syslog(LOG_ERR,
		    "open(%s) => errno=%d", LOCKFILE, errno);
		return (FALSE);
	}

	/*
	 * File exists with correct size, is open, and we're holding
	 * the file lock.
	 */
	shmlockarray = (lockarray *)mmap((caddr_t)0, sizeof (lockarray),
	    PROT_READ | PROT_WRITE, MAP_SHARED, lockfile, 0);
	if (shmlockarray == MAP_FAILED) {
		syslog(LOG_ERR, "mmap(%s) => errno=%d", LOCKFILE, errno);
		lockf(lockfile, F_ULOCK, 0);
		close(lockfile);
		return (FALSE);
	}

	/*
	 * If we wrote zeroes to the file, we also need to initialize
	 * the mutex locks.
	 */
	if (lf_size < sizeof (lockarray)) {
		if (init_locks_mem() == FALSE) {
			lockf(lockfile, F_ULOCK, 0);
			close(lockfile);
			if (remove(LOCKFILE) != 0) {
				syslog(LOG_ERR,
			    "remove(%s) => errno=%d: Please delete file.",
				    LOCKFILE, errno);
			}
			return (FALSE);
		}
	}

	if (lockf(lockfile, F_ULOCK, 0) != 0) {
		syslog(LOG_ERR,
		    "lockf(%s,F_ULOCK) => errno=%d",
		    LOCKFILE, errno);
		close(lockfile);
		return (FALSE);
	}

	if (close(lockfile) == 0) {
		return (TRUE);
	} else {
		syslog(LOG_ERR,
		    "close(%s) => errno=%d", LOCKFILE, errno);
		return (FALSE);
	}
}

/*
 * FUNCTION : 	lock_map()
 *
 * DESCRIPTION: Front end to the lock routine taking map name as argument.
 *
 * GIVEN :	Map name.
 *
 * RETURNS :	Same as lock_core
 */
int
lock_map(char *mapname)
{
	int hashval;

	hashval = hash(mapname);

	return (lock_core(hashval));
}

/*
 * FUNCTION : 	lock_core()
 *
 * DESCRIPTION: The core map locking function
 *
 * GIVEN :	Map hash value
 *
 * RETURNS :	0 = Failure
 *		1 = Success
 */
int
lock_core(int hashval)
{
	int rc;

	/*
	 * Robust, cross-process lock implementation
	 */
	rc = mutex_lock(&(shmlockarray->locknode[hashval]));
	while (rc != 0) {
		switch (rc) {
		case EOWNERDEAD:
			/*
			 * Previous lock owner died, resetting lock
			 * to recover from error.
			 */
			rc = mutex_consistent(
			    &(shmlockarray->locknode[hashval]));
			if (rc != 0) {
				syslog(LOG_ERR,
				    "mutex_consistent(): error=%d", rc);
				return (0);
			}
			rc = mutex_unlock(&(shmlockarray->locknode[hashval]));
			if (rc != 0) {
				syslog(LOG_ERR,
				    "mutex_unlock(): error=%d", rc);
				return (0);
			}
			break;
		default:
			/*
			 * Unrecoverable problem - nothing to do
			 * but exit YP and delete lock file.
			 */
			syslog(LOG_ERR,
			    "mutex_lock(): error=%d", rc);
			syslog(LOG_ERR,
			    "Please restart NIS (ypstop/ypstart).");
			if (remove(LOCKFILE) != 0) {
				syslog(LOG_ERR,
			    "remove(%s) => errno=%d: Please delete file.",
				    LOCKFILE, errno);
			}
			return (0);
		}
		rc = mutex_lock(&(shmlockarray->locknode[hashval]));
	}

	/* Success */
	return (1);
}


/*
 * FUNCTION : 	unlock_map()
 *
 * DESCRIPTION: Front end to the unlock routine taking map name as argument.
 *
 * GIVEN :	Map name.
 *
 * RETURNS :	Same as unlock_core
 */
int
unlock_map(char *mapname)
{
	int hashval;

	hashval = hash(mapname);

	return (unlock_core(hashval));
}

/*
 * FUNCTION : 	unlock_core()
 *
 * DESCRIPTION: The core map locking function
 *
 * GIVEN :	Map hash value
 *
 * RETURNS :	0 = Failure
 *		1 = Success
 */
int
unlock_core(int hashval)
{
	int rc;

	rc = mutex_unlock(&(shmlockarray->locknode[hashval]));
	if (rc != 0) {
		syslog(LOG_ERR,
		    "mutex_unlock(): error=%d", rc);
		syslog(LOG_ERR,
		    "Please restart NIS (ypstop/ypstart).");
		if (remove(LOCKFILE) != 0) {
			syslog(LOG_ERR,
			    "remove(%s) => errno=%d: Please delete file.",
			    LOCKFILE, errno);
		}
		return (0);
	}

	/* Success */
	return (1);
}
