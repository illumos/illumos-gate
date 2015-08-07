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
 * Copyright 2015 Gary Mills
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * DESCRIPTION: Contains code supporting the 'update in progress' flag. This is
 *		a near copy of lock flag code (in
 *		usr/src/cmd/ypcmd/shared/lockmp.c) If we implement a clean
 *		version	of the locking code this file will probably disappear.
 *
 *		These locks are held while a map is being updated from the
 *		DIT. They prevent a second update being started while this is
 *		in progress. This is independant from the `lockmap` mechanism
 *		which protects maps, generally for a much shorter period,
 *		while their control structures are modified.
 */

#include <unistd.h>
#include <syslog.h>
#include <sys/mman.h>
#include <thread.h>
#include <synch.h>
#include <ndbm.h>
#include <strings.h>
#include "ypsym.h"
#include "shim.h"
#include "yptol.h"
#include "../ldap_util.h"

#define	LOCKFILE "/var/run/yp_mapupdate"
struct updatearray {
	mutex_t		updatenode[MAXHASH];
};
typedef struct updatearray updatearray;

/*
 * Cross-process robust mutex locks.
 * Provide synchronization between YP processes
 * by implementing an exclusive locking mechanism
 * via a memory-mapped file.
 */
static struct updatearray	*shmupdatearray;
static int	lockfile;

bool_t
init_update_locks_mem()
{
	int iiter, rc;
	int ebusy_cnt = 0;

	/*
	 * Initialize cross-process locks in memory-mapped file.
	 */
	for (iiter = 0; iiter < MAXHASH; iiter++) {
		if ((rc = mutex_init(&(shmupdatearray->updatenode[iiter]),
		    USYNC_PROCESS | LOCK_ROBUST, 0)) != 0) {
			if (rc == EBUSY) {
				ebusy_cnt++;
			} else {
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"init_update_locks_mem():mutex_init():"
					"error=%d", rc);
				return (FALSE);
			}
		}
	}

	/*
	 * EBUSY for all locks OK, it means another process
	 * has already initialized locks.
	 */
	if ((ebusy_cnt > 0) && (ebusy_cnt != MAXHASH)) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
		"%s inconsistent. Remove this file and restart NIS (YP)",
								LOCKFILE);
		return (FALSE);
	}
	return (TRUE);
}

bool_t
init_update_lock_map()
{
	char buff[ sizeof (updatearray) ];
	int write_cnt, lf_size;
	struct stat fdata;

	/*
	 * Locking file initialization algorithm, with recovery mechanism.
	 * This mechanism has been devised to ensure proper creation
	 * of a memory-mapped lock file containing mutexes for robust,
	 * inter-process communication.
	 * File name is /var/run/yp_mapupate (LOCKFILE).  It might or might
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
				if (lf_size < sizeof (updatearray)) {
					bzero(buff, sizeof (buff));
					if ((write_cnt = write(lockfile, buff,
					    sizeof (buff)) != sizeof (buff))) {
						if (write_cnt < 0) {
							logmsg(MSG_NOTIMECHECK,
								LOG_ERR,
						"write(%s) => errno=%d",
							    LOCKFILE, errno);
						} else {
							logmsg(MSG_NOTIMECHECK,
								LOG_ERR,
		    "write(%s) => %d!=%d: wrong number of bytes written",
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
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
				    "fstat(%s) => errno=%d", LOCKFILE, errno);
				lockf(lockfile, F_ULOCK, 0);
				close(lockfile);
				return (FALSE);
			}
		} else {
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
			    "lockf(%s,F_LOCK) => errno=%d", LOCKFILE, errno);
			close(lockfile);
			return (FALSE);
		}
	} else {
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"open(%s) => errno=%d", LOCKFILE, errno);
		return (FALSE);
	}

	/*
	 * File exists with correct size, is open, and we're holding
	 * the file lock.
	 */
	shmupdatearray = (updatearray *)mmap((caddr_t)0, sizeof (updatearray),
	    PROT_READ | PROT_WRITE, MAP_SHARED, lockfile, 0);
	if (shmupdatearray == MAP_FAILED) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"mmap(%s) => errno=%d", LOCKFILE, errno);
		lockf(lockfile, F_ULOCK, 0);
		close(lockfile);
		return (FALSE);
	}

	/*
	 * If we wrote zeroes to the file, we also need to initialize
	 * the mutex locks.
	 */
	if (lf_size < sizeof (updatearray)) {
		if (init_update_locks_mem() == FALSE) {
			lockf(lockfile, F_ULOCK, 0);
			close(lockfile);
			if (remove(LOCKFILE) != 0) {
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"remove(%s) => errno=%d: Please delete file",
							LOCKFILE, errno);
			}
			return (FALSE);
		}
	}

	if (lockf(lockfile, F_ULOCK, 0) != 0) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"lockf(%s,F_ULOCK) => errno=%d", LOCKFILE, errno);
		close(lockfile);
		return (FALSE);
	}

	if (close(lockfile) == 0) {
		return (TRUE);
	} else {
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"close(%s) => errno=%d", LOCKFILE, errno);
		return (FALSE);
	}
}

suc_code
lock_map_update(map_ctrl *map)
{
	int hashval = map->hash_val;
	int rc;

	/*
	 * Robust, cross-process lock implementation
	 */
	rc = mutex_lock(&(shmupdatearray->updatenode[hashval]));
	while (rc != 0) {
		switch (rc) {
		case EOWNERDEAD:
			/*
			 * Previous lock owner died, resetting lock
			 * to recover from error.
			 */
			rc = mutex_consistent(
			    &(shmupdatearray->updatenode[hashval]));
			if (rc != 0) {
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"mutex_consistent(): error=%d", rc);
				return (FAILURE);
			}
			rc = mutex_unlock(
			    &(shmupdatearray->updatenode[hashval]));
			if (rc != 0) {
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"mutex_unlock(): error=%d", rc);
				return (FAILURE);
			}
			break;
		default:
			/*
			 * Unrecoverable problem - nothing to do
			 * but exit YP and delete lock file.
			 */
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
						"mutex_lock(): error=%d", rc);
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"Please restart NIS (ypstop/ypstart)");
			if (remove(LOCKFILE) != 0) {
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"remove(%s) => errno=%d: Please delete file",
							LOCKFILE, errno);
			}
			return (FAILURE);
		}
		rc = mutex_lock(&(shmupdatearray->updatenode[hashval]));
	}

	/* Success */
	return (SUCCESS);
}


suc_code
unlock_map_update(map_ctrl *map)
{
	int hashval = map->hash_val;
	int rc;

	rc = mutex_unlock(&(shmupdatearray->updatenode[hashval]));
	if (rc != 0) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
						"mutex_unlock(): error=%d", rc);
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"Please restart NIS (ypstop/ypstart)");
		if (remove(LOCKFILE) != 0) {
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
			    "remove(%s) => errno=%d: Please delete file",
			    LOCKFILE, errno);
		}
		return (FAILURE);
	}

	/* Success */
	return (SUCCESS);
}

/*
 * FUNCTION :   is_map_updating()
 *
 * DESCRIPTION: Determines if a map is currently locked for update
 *
 * GIVEN :      Pointer to map_ctrl structure
 *
 * RETURNS :    TRUE = Map is locked
 *              FALSE = Map is not locked
 */
bool_t
is_map_updating(map_ctrl *map)
{
	int ret;

	/* It appears not to be possible to just read a mutex. Try to lock it */
	ret = mutex_trylock(&(shmupdatearray->updatenode[map->hash_val]));

	if (0 != ret) {
		/* Didn't get the lock ... was already locked */
		return (TRUE);
	}

	/* Didn't need the lock so free it again */
	mutex_unlock(&(shmupdatearray->updatenode[map->hash_val]));
	return (FALSE);
}

/*
 * FUNCTION :	try_lock_map_update()
 *
 * DESCRIPTION: Tries to to lock a map for update.
 *
 * GIVEN :	Pointer to the map to lock
 *
 * RETURNS :	0 = The map is now locked
 *		EBUSY = The map was already locked lock not obtained.
 *		Other = There was an error
 */
int
try_lock_map_update(map_ctrl *map)
{
	int hashval = map->hash_val;
	int rc;

	/*
	 * Robust, cross-process lock implementation
	 *
	 * Keep trying until either lock is obtained or somebody else gets it.
	 */
	while (1) {
		rc = mutex_trylock(&(shmupdatearray->updatenode[hashval]));

		switch (rc) {

		case 0:
		case EBUSY:
			/* Either got it or somebody else has it */
			return (rc);

		case EOWNERDEAD:
			/*
			 * Previous lock owner died, resetting lock
			 * to recover from error.
			 */
			rc = mutex_consistent(
			    &(shmupdatearray->updatenode[hashval]));
			if (rc != 0) {
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"mutex_consistent(): error=%d", rc);
				return (rc);
			}
			rc = mutex_unlock(
			    &(shmupdatearray->updatenode[hashval]));
			if (rc != 0) {
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"mutex_unlock(): error=%d", rc);
				return (rc);
			}
			break;
		default:
			/*
			 * Unrecoverable problem - nothing to do
			 * but exit YP and delete lock file.
			 */
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
						"mutex_lock(): error=%d", rc);
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"Please restart NIS (ypstop/ypstart)");
			if (remove(LOCKFILE) != 0) {
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"remove(%s) => errno=%d: Please delete file",
							LOCKFILE, errno);
			}
			return (rc);
		}
	}
}
