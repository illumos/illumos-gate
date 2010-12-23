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
 */



/*
 * Module:	zones_locks.c
 * Group:	libinstzones
 * Description:	Provide "zones" locking interfaces for install consolidation
 *		code
 *
 * Public Methods:
 *
 * _z_acquire_lock - acquire a lock on an object on a zone
 * _z_adjust_lock_object_for_rootpath - Given a lock object and a root path,
 *	if the root path is not
 * _z_lock_zone - Acquire specified locks on specified zone
 * _z_lock_zone_object - lock a single lock object in a specified zone
 * _z_release_lock - release a lock held on a zone
 * _z_unlock_zone - Released specified locks on specified zone
 * _z_unlock_zone_object - unlock a single lock object in a specified zone
 */

/*
 * System includes
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/param.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <limits.h>
#include <errno.h>
#include <time.h>
#include <stropts.h>
#include <libintl.h>
#include <locale.h>
#include <assert.h>

/*
 * local includes
 */

#include "instzones_lib.h"
#include "zones_strings.h"

/*
 * Private structures
 */

/*
 * Library Function Prototypes
 */

/*
 * Local Function Prototypes
 */

boolean_t	_z_adjust_lock_object_for_rootpath(char **r_result,
		    char *a_lockObject);
boolean_t	_z_acquire_lock(char **r_lockKey, char *a_zoneName,
		    char *a_lock, pid_t a_pid, boolean_t a_wait);
boolean_t	_z_lock_zone(zoneListElement_t *a_zlst,
		    ZLOCKS_T a_lflags);
boolean_t	_z_lock_zone_object(char **r_objectLocks,
		    char *a_zoneName, char *a_lockObject,
		    pid_t a_pid, char *a_waitingMsg,
		    char *a_busyMsg);
boolean_t	_z_release_lock(char *a_zoneName, char *a_lock,
		    char *a_key, boolean_t a_wait);
		    boolean_t	_z_unlock_zone(zoneListElement_t *a_zlst,
		    ZLOCKS_T a_lflags);
boolean_t	_z_unlock_zone_object(char **r_objectLocks,
		    char *a_zoneName, char *a_lockObject,
		    char *a_errMsg);

/*
 * global internal (private) declarations
 */

/*
 * *****************************************************************************
 * global external (public) functions
 * *****************************************************************************
 */

/*
 * Name:	_z_acquire_lock
 * Description:	acquire a lock on an object on a zone
 * Arguments:	r_lockKey - [RW, *RW] - (char *)
 *			Pointer to handle to string representing the lock key
 *			associated with the lock object to be acquired - this
 *			key is returned when the lock is acquired and must be
 *			provided when releasing the lock
 *			== (char *)NULL - lock not acquired
 *		a_zoneName - [RO, *RO] - (char *)
 *			Pointer to string representing the name of the zone to
 *			acquire the specified lock on
 *		a_lockObject - [RO, *RO] - (char *)
 *			Pointer to string representing the lock object to
 *			acquire on the specified zone
 *		a_pid - [RO, *RO] - (pid_t)
 *			Process i.d. to associate with this lock
 *			== 0 - no process i.d. associated with the lock
 *		a_wait - [RO, *RO] - (int)
 *			Determines what to do if the lock cannot be acquired:
 *			== B_TRUE - wait for the lock to be acquired
 *			== B_FALSE - do not wait for the lock to be acquired
 * Returns:	boolean_t
 *			B_TRUE - lock acquired
 *			B_FALSE - lock not acquired
 */

boolean_t
_z_acquire_lock(char **r_lockKey, char *a_zoneName, char *a_lockObject,
	pid_t a_pid, boolean_t a_wait)
{
	argArray_t	*args;
	boolean_t	b;
	char		*adjustedLockObject = (char *)NULL;
	char		*p;
	char		*results = (char *)NULL;
	int		r;
	int		status;

	/* entry assertions */

	assert(a_zoneName != (char *)NULL);
	assert(a_lockObject != (char *)NULL);
	assert(*a_lockObject != '\0');
	assert(r_lockKey != (char **)NULL);

	/* entry debugging info */

	_z_echoDebug(DBG_ZONES_APLK, a_zoneName, a_lockObject, a_pid);

	/* reset returned lock key handle */

	*r_lockKey = (char *)NULL;

	/*
	 * Only one lock file must ever be used - the one located on the root
	 * file system of the currently running Solaris instance. To allow for
	 * alternative roots to be properly locked, adjust the lock object to
	 * take root path into account; if necessary, the root path will be
	 * prepended to the lock object.
	 */

	b = _z_adjust_lock_object_for_rootpath(&adjustedLockObject,
	    a_lockObject);
	if (!b) {
		return (B_FALSE);
	}

	/*
	 * construct command arguments:
	 * pkgadm lock -a -q -o adjustedLockObject [ -w -W timeout ]
	 *		[ -p a_pid -z zoneid ]
	 */

	args = _z_new_args(20);			/* generate new arg list */
	(void) _z_add_arg(args, PKGADM_CMD);	/* pkgadm command */
	(void) _z_add_arg(args, "lock");		/* lock sub-command */
	(void) _z_add_arg(args, "-a");		/* acquire lock */
	(void) _z_add_arg(args, "-q");		/* quiet (no extra messages) */
	(void) _z_add_arg(args, "-o");		/* object to acquire */
	(void) _z_add_arg(args, "%s", adjustedLockObject);

	/* add [ -w -W timeout ] if waiting for lock */

	if (a_wait == B_TRUE) {
		(void) _z_add_arg(args, "-w");		/* wait */
		(void) _z_add_arg(args, "-W");		/* wait timeout */
		(void) _z_add_arg(args, "%ld",
		    (long)MAX_RETRIES*RETRY_DELAY_SECS);
	}

	/* add process/zone i.d.s if process i.d. provided */

	if (a_pid > 0) {
		(void) _z_add_arg(args, "-p");	/* lock valid process i.d. */
		(void) _z_add_arg(args, "%ld", getpid());
		(void) _z_add_arg(args, "-z");	/* lock valid zone i.d. */
		(void) _z_add_arg(args, "%ld", getzoneid());
	}

	/* execute command */

	r = _z_zone_exec(&status, &results, (char *)NULL, PKGADM_CMD,
	    _z_get_argv(args), a_zoneName, (int *)NULL);

	/* free generated argument list */

	_z_free_args(args);

	/* return error if failed to acquire */

	if ((r != 0) || (status != 0)) {
		_z_echoDebug(DBG_ZONES_APLK_EXIT, a_zoneName,
		    adjustedLockObject, a_pid, r, status,
		    results ? results : "");

		/* free up results if returned */
		if (results) {
			free(results);
		}

		/* free adjusted lock object */
		free(adjustedLockObject);

		/* return failure */
		return (B_FALSE);
	}

	/* return success if no results returned */

	if (results == (char *)NULL) {
		return (B_TRUE);
	}

	/* return the lock key */

	p = _z_strGetToken((char *)NULL, results, 0, "\n");
	_z_strRemoveLeadingWhitespace(&p);
	*r_lockKey = p;

	/* exit debugging info */

	_z_echoDebug(DBG_ZONES_APLK_RESULTS, a_zoneName, adjustedLockObject, p,
	    results);

	/* free up results */

	free(results);

	/* free adjusted lock object */

	free(adjustedLockObject);

	/* return success */

	return (B_TRUE);
}

/*
 * Name:	_z_adjust_lock_object_for_rootpath
 * Description:	Given a lock object and a root path, if the root path is not
 *		the current running system root, then alter the lock object
 *		to contain a reference to the root path. Only one lock file must
 *		ever be used to create and maintain locks - the lock file that
 *		is located in /tmp on the root file system of the currently
 *		running Solaris instance. To allow for alternative roots to be
 *		properly locked, if necessary adjust the lock object to take
 *		root path into account. If the root path does not indicate the
 *		current running Solaris instance, then the root path will be
 *		prepended to the lock object.
 * Arguments:	r_result - [RW, *RW] - (char **)
 *			Pointer to handle to character string that will contain
 *			the lock object to use.
 *		a_lockObject - [RO, *RO] - (char *)
 *			Pointer to string representing the lock object to adjust
 * Returns:	boolean_t
 *			B_TRUE - lock object adjusted and returned
 *			B_FALSE - unable to adjust lock object
 * NOTE:    	Any string returned is placed in new storage for the
 *		calling function. The caller must use 'free' to dispose
 *		of the storage once the string is no longer needed.
 *
 * A lock object has this form:
 *
 * name.value [ /name.value [ /name.value ... ] ]
 *
 * The "value is either a specific object or a "*", for example:
 *
 *     package.test
 *
 * This locks the package "test"
 *
 *     zone.* /package.*
 *
 * This locks all packages on all zones.
 *
 *     zone.* /package.SUNWluu
 *
 * This locks the package SUNWluu on all zones.
 *
 * If a -R rootpath is specified, since there is only one lock file in
 * the current /tmp, the lock object is modified to include the root
 * path:
 *
 *     rootpath.rootpath/zone.* /package.*
 *
 * locks all packages on all zones in the root path "?"
 *
 * The characters "/" and "*" and "." cannot be part of the "value"; that
 * is if "-R /tmp/gmg*dir.test-path" is specified, the final object
 * cannot be:
 *
 *     rootpath./tmp/gmg*dir.test-path/zone.* /package.*
 *
 * This would be parsed as:
 *
 *      "rootpath." "/tmp" "gmg*dir.test-path" "zone.*" "package.*"
 *
 * which is not correct.
 *
 * So the path is modified by the loop, in this case it would result in
 * this lock object:
 *
 *     rootpath.-1tmp-1gmg-3dir-2test---path/zone.* /package.*
 *
 * This is parsed as:
 *
 *     "rootpath.-1tmp-1gmg-3dir-2test---path" "zone.*" "package.*"
 *
 * which is then interpreted as:
 *
 *     "rootpath./tmp/gmg*dir.test-path" "zone.*" "package.*"
 */

boolean_t
_z_adjust_lock_object_for_rootpath(char **r_result, char *a_lockObject)
{
	char		realRootPath[PATH_MAX] = {'\0'};
	const char	*a_rootPath;

	/* entry assertions */

	assert(r_result != (char **)NULL);
	assert(a_lockObject != (char *)NULL);
	assert(*a_lockObject != '\0');

	/* reset returned lock object handle */

	*r_result = (char *)NULL;

	/*
	 * if root path points to "/" return a duplicate of the passed in
	 * lock objects; otherwise, resolve root path and adjust lock object by
	 * prepending the rootpath to the lock object (using LOBJ_ROOTPATH).
	 */

	a_rootPath = _z_global_data._z_root_dir;
	if ((a_rootPath == (char *)NULL) ||
	    (*a_rootPath == '\0') ||
	    (strcmp(a_rootPath, "/") == 0)) {

		/* root path not specified or is only "/" - no -R specified */

		*r_result = _z_strdup(a_lockObject);
	} else {
		/*
		 * root path is not "" or "/" - -R to an alternative root has
		 * been specified; resolve all symbolic links and relative nodes
		 * of path name and determine absolute path to the root path.
		 */

		if (realpath(a_rootPath, realRootPath) == (char *)NULL) {
			/* cannot determine absolute path; use path specified */
			(void) strlcpy(realRootPath, a_rootPath,
			    sizeof (realRootPath));
		}

		/*
		 * if root path points to "/" duplicate existing lock object;
		 * otherwise, resolve root path and adjust lock object by
		 * prepending the rootpath to the lock object
		 */

		if (strcmp(realRootPath, "/") == 0) {
			*r_result = _z_strdup(a_lockObject);
		} else {
			char *p1, *p2, *p3;

			/* prefix out /.* which cannot be part of lock object */

			p1 = _z_calloc((strlen(realRootPath)*2)+1);
			for (p3 = p1, p2 = realRootPath; *p2 != '\0'; p2++) {
				switch (*p2) {
				case '/':	/* / becomes -1 */
					*p3++ = '-';
					*p3++ = '1';
					break;
				case '.':	/* . becomes -2 */
					*p3++ = '-';
					*p3++ = '2';
					break;
				case '*':	/* * becomes -3 */
					*p3++ = '-';
					*p3++ = '3';
					break;
				case '-':	/* - becomes -- */
					*p3++ = '-';
					*p3++ = '-';
					break;
				default:	/* do not prefix out char */
					*p3++ = *p2;
					break;
				}
			}

			/* create "realpath.%s" object */

			p2 = _z_strPrintf(LOBJ_ROOTPATH, p1);
			free(p1);
			if (p2 == (char *)NULL) {
				_z_program_error(ERR_MALLOC, "<path>", errno,
				    strerror(errno));
				return (B_FALSE);
			}

			/* create "realpath.%s/..." final lock object */

			*r_result = _z_strPrintf("%s/%s", p2, a_lockObject);
			free(p2);
			if (*r_result == (char *)NULL) {
				_z_program_error(ERR_MALLOC, "<path>", errno,
				    strerror(errno));
				return (B_FALSE);
			}
		}
	}

	/* exit debugging info */

	_z_echoDebug(DBG_ZONES_ADJLCKOBJ_EXIT, a_lockObject, *r_result,
	    a_rootPath ? a_rootPath : "",
	    realRootPath ? realRootPath : "");

	/* return success */

	return (B_TRUE);
}

/*
 * Name:	_z_lock_zone
 * Description:	Acquire specified locks on specified zone
 * Arguments:	a_zlst - [RO, *RW] - (zoneListElement_t *)
 *			Pointer to zone list structure element describing
 *			the zone the lock - the structure is updated with
 *			the lock objects and keys if the locks are acquired
 *		a_lflags - [RO, *RO] - (ZLOCKS_T)
 *			Flags indicating which locks to acquire on the zone
 * Returns:	boolean_t
 *			== B_TRUE - locks successfully acquired
 *			== B_FALSE - failed to acquire the locks
 */

boolean_t
_z_lock_zone(zoneListElement_t *a_zlst, ZLOCKS_T a_lflags)
{
	char *scratchName;
	boolean_t	b;

	/* entry assertions */

	assert(a_zlst != (zoneListElement_t *)NULL);

	/* entry debugging info */

	_z_echoDebug(DBG_ZONES_LCK_ZONE, a_zlst->_zlName, a_lflags);

	scratchName = a_zlst->_zlScratchName == NULL ? a_zlst->_zlName :
	    a_zlst->_zlScratchName;

	/*
	 * acquire zone lock
	 */

	if (a_lflags & ZLOCKS_ZONE_ADMIN) {
		/*
		 * lock zone administration if not already locked
		 * if the lock cannot be released, stop and return an error
		 */

		_z_echoDebug(DBG_ZONES_LCK_ZONE_ZONEADM, a_zlst->_zlName,
		    LOBJ_ZONEADMIN);

		b = _z_lock_zone_object(&a_zlst->_zlLockObjects,
		    scratchName, LOBJ_ZONEADMIN, (pid_t)0,
		    MSG_ZONES_LCK_ZONE_ZONEADM,
		    ERR_ZONES_LCK_ZONE_ZONEADM);
		if (b == B_FALSE) {
			return (b);
		}
	}

	/*
	 * acquire package lock
	 */

	if (a_lflags & ZLOCKS_PKG_ADMIN) {

		/*
		 * zone administration is locked; lock package administration if
		 * not already locked; if the lock cannot be released, stop,
		 * release the zone administration lock and return an error
		 */

		_z_echoDebug(DBG_ZONES_LCK_ZONE_PKGADM, a_zlst->_zlName,
		    LOBJ_PKGADMIN);

		b = _z_lock_zone_object(&a_zlst->_zlLockObjects,
		    scratchName, LOBJ_PKGADMIN, (pid_t)0,
		    MSG_ZONES_LCK_ZONE_PKGADM,
		    ERR_ZONES_LCK_ZONE_PKGADM);
		if (b == B_FALSE) {
			(void) _z_unlock_zone(a_zlst, a_lflags);
			return (b);
		}
	}

	/*
	 * acquire patch lock
	 */

	if (a_lflags & ZLOCKS_PATCH_ADMIN) {

		/*
		 * zone and package administration is locked; lock patch
		 * administration; if the lock cannot be released, stop,
		 * release the other locks and return an error
		 */

		_z_echoDebug(DBG_ZONES_LCK_ZONE_PATCHADM, a_zlst->_zlName,
		    LOBJ_PATCHADMIN);

		b = _z_lock_zone_object(&a_zlst->_zlLockObjects,
		    scratchName, LOBJ_PATCHADMIN, (pid_t)0,
		    MSG_ZONES_LCK_ZONE_PATCHADM,
		    ERR_ZONES_LCK_ZONE_PATCHADM);
		if (b == B_FALSE) {
			(void) _z_unlock_zone(a_zlst, a_lflags);
			return (b);
		}
	}

	/*
	 * all locks have been obtained - return success!
	 */

	return (B_TRUE);
}

/*
 * Name:	_z_lock_zone_object
 * Description:	lock a single lock object in a specified zone
 * Arguments:	r_objectLocks - [RW, *RW] - (char **)
 *			Pointer to handle to character string containing a list
 *			of all objects locked for this zone - this string will
 *			have the key to release the specified object added to it
 *			if the lock is acquired.
 *		a_zoneName - [RO, *RO] - (char *)
 *			Pointer to string representing the name of the zone to
 *			acquire the specified lock on
 *		a_lockObject - [RO, *RO] - (char *)
 *			Pointer to string representing the lock object to
 *			acquire on the specified zone
 *		a_pid - [RO, *RO] - (pid_t)
 *			Process i.d. to associate with this lock
 *			== 0 - no process i.d. associated with the lock
 *		a_waitingMsg - [RO, *RO] - (char *)
 *			Localized message to be output if waiting for the lock
 *			because the lock cannot be immediately be acquired
 *		a_busyMsg - [RO, *RO] - (char *)
 *			Localized message to be output if the lock cannot be
 *			released
 * Returns:	boolean_t
 *			B_TRUE - lock released
 *			B_FALSE - lock not released
 */

boolean_t
_z_lock_zone_object(char **r_objectLocks, char *a_zoneName, char *a_lockObject,
	pid_t a_pid, char *a_waitingMsg, char *a_busyMsg)
{
	boolean_t	b;
	char		*p = (char *)NULL;
	char		lockItem[LOCK_OBJECT_MAXLEN+LOCK_KEY_MAXLEN+4];
	char		lockKey[LOCK_KEY_MAXLEN+2];
	char		lockObject[LOCK_OBJECT_MAXLEN+2];
	int		i;

	/* entry assertions */

	assert(r_objectLocks != (char **)NULL);
	assert(a_zoneName != (char *)NULL);
	assert(a_waitingMsg != (char *)NULL);
	assert(a_busyMsg != (char *)NULL);
	assert(a_lockObject != (char *)NULL);
	assert(*a_lockObject != '\0');

	/* entry debugging info */

	_z_echoDebug(DBG_ZONES_LCK_OBJ, a_lockObject, a_zoneName, a_pid,
	    *r_objectLocks ? *r_objectLocks : "");

	/* if lock objects held search for object to lock */

	if (*r_objectLocks != (char *)NULL) {
		for (i = 0; ; i++) {
			/* get next object locked on this zone */
			_z_strGetToken_r((char *)NULL, *r_objectLocks, i, "\n",
			    lockItem, sizeof (lockItem));

			/* break out of loop if no more locks in list */

			if (lockItem[0] == '\0') {
				_z_echoDebug(DBG_ZONES_LCK_OBJ_NOTHELD,
				    a_lockObject, a_zoneName);
				break;
			}

			/* get object and key for this lock */
			_z_strGetToken_r((char *)NULL, lockItem, 0, "\t",
			    lockObject, sizeof (lockObject));
			_z_strGetToken_r((char *)NULL, lockItem, 1, "\t",
			    lockKey, sizeof (lockKey));

			/* return success if the lock is held */

			if (strcmp(lockObject, a_lockObject) == 0) {
				_z_echoDebug(DBG_ZONES_LCK_OBJ_FOUND,
				    lockObject, lockKey);
				return (B_TRUE);
			}

			/* not the object to lock - scan next object */
			_z_echoDebug(DBG_ZONES_LCK_OBJ_NOTFOUND, lockObject,
			    lockKey);
		}
	}

	/*
	 * the object to lock is not held - acquire the lock
	 */

	/* acquire object with no wait */
	b = _z_acquire_lock(&p, a_zoneName, a_lockObject, a_pid, B_FALSE);
	if (b == B_FALSE) {
		/* failure - output message and acquire with wait */
		_z_echo(a_waitingMsg, (long)MAX_RETRIES*RETRY_DELAY_SECS,
		    a_zoneName, _z_global_data._z_root_dir);
		b = _z_acquire_lock(&p, a_zoneName, a_lockObject, a_pid,
		    B_TRUE);
	}

	/* output error message and return failure if both acquires failed */
	if (b == B_FALSE) {
		_z_program_error(a_busyMsg, a_zoneName);
		return (b);
	}

	/* add object/key to held locks */

	_z_strPrintf_r(lockItem, sizeof (lockItem), "%s\t%s", a_lockObject, p);
	_z_strAddToken(r_objectLocks, lockItem, '\n');

	free(p);

	/* return success */
	return (B_TRUE);
}

/*
 * Name:	_z_release_lock
 * Description:	release a lock held on a zone
 * Arguments:	a_zoneName - [RO, *RO] - (char *)
 *			Pointer to string representing the name of the zone to
 *			release the specified lock on
 *		a_lockObject - [RO, *RO] - (char *)
 *			Pointer to string representing the lock object to
 *			release on the specified zone
 *		a_lockKey - [RO, *RO] - (char *)
 *			Pointer to string representing the lock key associated
 *			with the lock object to be released - this key is
 *			returned when the lock is acquired and must be provided
 *			when releasing the lock
 *		a_wait - [RO, *RO] - (int)
 *			Determines what to do if the lock cannot be released:
 *			== B_TRUE - wait for the lock to be released
 *			== B_FALSE - do not wait for the lock to be released
 * Returns:	boolean_t
 *			B_TRUE - lock released
 *			B_FALSE - lock not released
 */

boolean_t
_z_release_lock(char *a_zoneName, char *a_lockObject, char *a_lockKey,
	boolean_t a_wait)
{
	argArray_t	*args;
	boolean_t	b;
	char		*adjustedLockObject = (char *)NULL;
	char		*results = (char *)NULL;
	int		r;
	int		status;

	/* entry assertions */

	assert(a_zoneName != (char *)NULL);
	assert(a_lockObject != (char *)NULL);
	assert(*a_lockObject != '\0');
	assert(a_lockKey != (char *)NULL);
	assert(*a_lockKey != '\0');

	/* entry debugging info */

	_z_echoDebug(DBG_ZONES_RELK, a_zoneName, a_lockObject,
	    a_lockKey ? a_lockKey : "");

	/*
	 * Only one lock file must ever be used - the one located on the root
	 * file system of the currently running Solaris instance. To allow for
	 * alternative roots to be properly locked, adjust the lock object to
	 * take root path into account; if necessary, the root path will be
	 * prepended to the lock object.
	 */

	b = _z_adjust_lock_object_for_rootpath(&adjustedLockObject,
	    a_lockObject);
	if (!b) {
		return (B_FALSE);
	}

	/*
	 * construct command arguments:
	 * pkgadm lock -r -o adjustedLockObject -k a_lockKey [-w -W timeout]
	 */

	args = _z_new_args(20);			/* generate new arg list */
	(void) _z_add_arg(args, PKGADM_CMD);		/* pkgadm command */
	(void) _z_add_arg(args, "lock");		/* lock sub-command */
	(void) _z_add_arg(args, "-r");			/* release lock */
	(void) _z_add_arg(args, "-o");			/* object to release */
	(void) _z_add_arg(args, "%s", adjustedLockObject);
	(void) _z_add_arg(args, "-k");			/* object's key */
	(void) _z_add_arg(args, "%s", a_lockKey);

	/* add [ -w -W timeout ] if waiting for lock */

	if (a_wait == B_TRUE) {
		(void) _z_add_arg(args, "-w");		/* wait */
		(void) _z_add_arg(args, "-W");		/* wait timeout */
		(void) _z_add_arg(args, "%ld",
		    (long)MAX_RETRIES*RETRY_DELAY_SECS);
	}

	/* execute command */

	r = _z_zone_exec(&status, &results, (char *)NULL, PKGADM_CMD,
	    _z_get_argv(args), a_zoneName, (int *)NULL);

	/* free generated argument list */

	_z_free_args(args);

	/* exit debugging info */

	_z_echoDebug(DBG_ZONES_RELK_EXIT, adjustedLockObject, a_lockKey,
	    a_zoneName, r, status, results ? results : "");

	/* free adjusted lock object */

	free(adjustedLockObject);
	free(results);

	return (((r == 0) && (status == 0)) ? B_TRUE : B_FALSE);
}



/*
 * Name:	_z_unlock_zone
 * Description:	Released specified locks on specified zone
 * Arguments:	a_zlst - [RO, *RW] - (zoneListElement_t *)
 *			Pointer to zone list structure element describing
 *			the zone the unlock - the structure is updated by
 *			removing the lock object and key if the locks are
 *			successfully released
 *		a_lflags - [RO, *RO] - (ZLOCKS_T)
 *			Flags indicating which locks to release on the zone
 * Returns:	boolean_t
 *			== B_TRUE - locks successfully released
 *			== B_FALSE - failed to release the locks
 */

boolean_t
_z_unlock_zone(zoneListElement_t *a_zlst, ZLOCKS_T a_lflags)
{
	char		*scratchName;
	boolean_t	b;
	boolean_t	errors = B_FALSE;

	/* entry assertions */

	assert(a_zlst != (zoneListElement_t *)NULL);

	/* entry debugging info */

	_z_echoDebug(DBG_ZONES_ULK_ZONE, a_zlst->_zlName, a_lflags);

	scratchName = a_zlst->_zlScratchName == NULL ? a_zlst->_zlName :
	    a_zlst->_zlScratchName;

	if (a_lflags & ZLOCKS_PATCH_ADMIN) {
		/*
		 * if locked, unlock patch administration lock
		 * if the lock cannot be released, continue anyway
		 */

		_z_echoDebug(DBG_ZONES_ULK_ZONE_PATCHADM, a_zlst->_zlName,
		    LOBJ_PATCHADMIN);

		b = _z_unlock_zone_object(&a_zlst->_zlLockObjects,
		    scratchName, LOBJ_PATCHADMIN,
		    WRN_ZONES_ULK_ZONE_PATCHADM);
		if (b == B_FALSE) {
			errors = B_TRUE;
		}
	}

	if (a_lflags & ZLOCKS_PKG_ADMIN) {
		/*
		 * if locked, unlock package administration lock
		 * if the lock cannot be released, continue anyway
		 */

		_z_echoDebug(DBG_ZONES_ULK_ZONE_PKGADM, a_zlst->_zlName,
		    LOBJ_PKGADMIN);

		b = _z_unlock_zone_object(&a_zlst->_zlLockObjects,
		    scratchName, LOBJ_PKGADMIN,
		    WRN_ZONES_ULK_ZONE_PKGADM);
		if (b == B_FALSE) {
			errors = B_TRUE;
		}
	}

	if (a_lflags & ZLOCKS_ZONE_ADMIN) {

		/*
		 * if locked, unlock zone administration lock
		 * if the lock cannot be released, continue anyway
		 */

		_z_echoDebug(DBG_ZONES_ULK_ZONE_ZONEADM, a_zlst->_zlName,
		    LOBJ_ZONEADMIN);

		b = _z_unlock_zone_object(&a_zlst->_zlLockObjects,
		    scratchName, LOBJ_ZONEADMIN,
		    WRN_ZONES_ULK_ZONE_ZONEADM);
		if (b == B_FALSE) {
			errors = B_TRUE;
		}
	}

	return (!errors);
}

/*
 * Name:	_z_unlock_zone_object
 * Description:	unlock a single lock object in a specified zone
 * Arguments:	r_objectLocks - [RW, *RW] - (char **)
 *			Pointer to handle to character string containing a list
 *			of all objects locked for this zone - this string must
 *			contain the key to release the specified object - if not
 *			then the lock is not released - if so then the lock is
 *			released and the key is removed from this list.
 *		a_zoneName - [RO, *RO] - (char *)
 *			Pointer to string representing the name of the zone to
 *			release the specified lock on
 *		a_lockObject - [RO, *RO] - (char *)
 *			Pointer to string representing the lock object to
 *			release on the specified zone
 *		a_errMsg - [RO, *RO] - (char *)
 *			Localized message to be output if the lock cannot be
 *			released
 * Returns:	boolean_t
 *			B_TRUE - lock released
 *			B_FALSE - lock not released
 */

boolean_t
_z_unlock_zone_object(char **r_objectLocks, char *a_zoneName,
	char *a_lockObject, char *a_errMsg)
{
	boolean_t	b;
	char		lockItem[LOCK_OBJECT_MAXLEN+LOCK_KEY_MAXLEN+4];
	char		lockKey[LOCK_KEY_MAXLEN+2];
	char		lockObject[LOCK_OBJECT_MAXLEN+2];
	int		i;

	/* entry assertions */

	assert(r_objectLocks != (char **)NULL);
	assert(a_zoneName != (char *)NULL);
	assert(a_errMsg != (char *)NULL);
	assert(a_lockObject != (char *)NULL);
	assert(*a_lockObject != '\0');

	/* entry debugging info */

	_z_echoDebug(DBG_ZONES_ULK_OBJ, a_lockObject, a_zoneName,
	    *r_objectLocks ? *r_objectLocks : "");

	/* return success if no objects are locked */

	if (*r_objectLocks == (char *)NULL) {
		_z_echoDebug(DBG_ZONES_ULK_OBJ_NONE, a_zoneName);
		return (B_TRUE);
	}

	/* see if the specified lock is held on this zone */

	for (i = 0; ; i++) {
		/* get next object locked on this zone */
		_z_strGetToken_r((char *)NULL, *r_objectLocks, i, "\n",
		    lockItem, sizeof (lockItem));

		/* return success if no more objects locked */
		if (lockItem[0] == '\0') {
			_z_echoDebug(DBG_ZONES_ULK_OBJ_NOTHELD, a_lockObject,
			    a_zoneName);
			return (B_TRUE);
		}

		/* get object and key for this lock */
		_z_strGetToken_r((char *)NULL, lockItem, 0, "\t",
		    lockObject, sizeof (lockObject));
		_z_strGetToken_r((char *)NULL, lockItem, 1, "\t",
		    lockKey, sizeof (lockKey));

		/* break out of loop if object is the one to unlock */

		if (strcmp(lockObject, a_lockObject) == 0) {
			_z_echoDebug(DBG_ZONES_ULK_OBJ_FOUND, lockObject,
			    lockKey);
			break;
		}

		/* not the object to unlock - scan next object */
		_z_echoDebug(DBG_ZONES_ULK_OBJ_NOTFOUND, lockObject, lockKey);
	}

	/*
	 * the object to unlock is held - release the lock
	 */

	/* release object with wait */

	b = _z_release_lock(a_zoneName, a_lockObject, lockKey, B_TRUE);
	if (b == B_FALSE) {
		/* failure - issue error message and return failure */
		_z_program_error(a_errMsg, a_zoneName);
		return (b);
	}

	/* remove object/key from held locks */

	_z_strRemoveToken(r_objectLocks, lockItem, "\n", 0);

	/* return success */

	return (B_TRUE);
}
