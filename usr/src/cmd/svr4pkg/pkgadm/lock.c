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
 * Copyright (c) 2017 Peter Tribble.
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * Module: lock.c
 * Program: pkgadm (/usr/bin/pkgadm)
 * Synopsis: implements the zone/package administrative lock interface
 * Public methods:
 *	admin_lock
 * Usage:
 *  Acquire: -a [ -e | -s ] [ -o obj ] [ -k key ] [ -R root ] [ -q ] \
 *		[ -w ] [ -W timeout ]
 *  Release: -r -o object -k key [ -R altRoot ] [ -q ]
 *  Status: [ -o object ] [ -k key ] [ -R altRoot ] [ -q ]
 */

/* enable extentions to standard Unix libraries */

#define	__EXTENSIONS__

/* unix system includes */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <locale.h>
#include <libgen.h>
#include <sys/param.h>
#include <errno.h>
#include <assert.h>
#include <time.h>
#include <fnmatch.h>
#include <zone.h>

/* local includes */

#include <libinst.h>
#include <pkglib.h>
#include "pkgadm.h"
#include "pkgadm_msgs.h"

/* definition and conversion of sleep units */

#define	SECONDS(x)		((unsigned int)(x))
#define	MINUTES(x)		((unsigned int)(seconds(x)*60))

/* define how waits are timed */

#define	WAITER_INITIAL		SECONDS(1)
#define	WAITER_MAX		SECONDS(60)
#define	WAITER_NEXT(x)		((x)*2)

typedef unsigned int		WAITER_T;

/*
 * The administrative lock file resides in /tmp
 * It does not survive a reboot
 * It consists of fixed length records
 * Each record has the following information:
 * 	record number - record position within the lock file
 * 	lock count - number of lock holders maintaining this lock
 * 	lock object - object being locked
 * 	lock key - key needed to manipulate existing lock
 *	lock exclusive - is the lock exclusive (single locker only)
 */

#define	LOCK_OBJECT_MAXLEN	512-1
#define	LOCK_KEY_MAXLEN		37

#define	LOCK_DIRECTORY		"/tmp"

/*
 * this is the "well known name" of the lock file that is used by the
 * package, patch, and zone administration commands to synchronize their
 * various efforts - it must live in a temporary directory that is cleared
 * on system reboot but it is NOT a temporary file in that it survives
 * the process that creates and updates it - if the format of the lock
 * file ever changes, this path should be updated with a later "uuid"
 * so that previous (incompatible) pkgadm's will not use the later data.
 */

#define	LOCK_FILENAME	\
	"/tmp/.ai.pkg.zone.lock-afdb66cf-1dd1-11b2-a049-000d560ddc3e"

/* mode to use for LOCK_FILENAME */

#define	LOCK_FILEMODE	\
	(S_ISGID|S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)

#define	LOCK_SLEEP_INTERVAL	SECONDS(2)

/* lock contents types */

typedef unsigned long RECORDNUM_T;

#define	RECORDNUM_NONE	0xFFFFFFFF

/* actual lock data */

struct _adminLock
{
	RECORDNUM_T	lockRecordNum;
	unsigned long	lockCount;
	unsigned long	lockExclusive;
	pid_t		lockPid;
	zoneid_t	lockZoneId;
	char		lockKey[LOCK_KEY_MAXLEN+1];
	char		lockObject[LOCK_OBJECT_MAXLEN+1];
};

typedef struct _adminLock ADMINLOCK_T;

/* size of an individual "lock" */

#define	LOCK_SIZE		sizeof (ADMINLOCK_T)

/* union to allow lock to be accessed as raw or structured data */

union _lockRecord
{
	char		_lrLockData[LOCK_SIZE];
	ADMINLOCK_T	_lrLock;
};

typedef union _lockRecord LOCK_T;

/* return codes from "_findLock" */

typedef unsigned long FINDLOCK_T;

#define	FINDLOCK_FOUND		((FINDLOCK_T)0)
#define	FINDLOCK_ERROR		((FINDLOCK_T)-1)
#define	FINDLOCK_NOTFOUND	((FINDLOCK_T)-2)
#define	FINDLOCK_KEYMISMATCH	((FINDLOCK_T)-3)
#define	FINDLOCK_LOCKED		((FINDLOCK_T)-4)
#define	FINDLOCK_NOTLOCKED	((FINDLOCK_T)-5)
#define	FINDLOCK_LOCKACQUIRED	((FINDLOCK_T)-6)

/*
 * Forward declarations
 */

/* local main function implementation methods */

static FINDLOCK_T	lock_acquire(LOCK_T *a_lock, int *a_fd, char *a_root,
				char *a_key, char *a_object, int a_quiet,
				int a_wait, long a_timeout, int a_exclusive,
				char *a_altRoot, pid_t a_pid, zoneid_t a_zid);
static int		lock_release(int a_fd, char *a_key, char *a_object,
				int a_quiet);
static int		lock_status(int a_fd, char *a_key, char *a_object,
				int a_quiet);

/* local utility functions */

static int		_lockMatch(char *a_s1Lock, char *a_s2Lock);
static FINDLOCK_T	_findLock(LOCK_T *a_theLock, RECORDNUM_T *r_recordNum,
				int a_fd, char *a_object, char *a_key);
static int		_decrementLockCount(int a_fd, LOCK_T *a_theLock);
static int		_addLock(char *r_key, int a_fd, char *a_object,
				int a_exclusive, pid_t a_pid, zoneid_t a_zid);
static int		_incrementLockCount(int a_fd, LOCK_T *a_theLock);
static FINDLOCK_T	_lock_acquire(LOCK_T *a_lock, int a_fd, char *a_key,
				char *a_object, int a_quiet, int a_exclusive,
				pid_t a_pid, zoneid_t a_zid);
static char		*_getUniqueId(void);
static int		_openLockFile(char *a_root);
static void		sighup_handler(int a_signo);
static void		sigint_handler(int a_signo);
static boolean_t	_validateLock(int a_fd, LOCK_T *a_theLock, int a_quiet);

static int		signal_received = 0;

/*
 * main methods with external entry points
 */

/*
 * Name:	admin_lock
 * Synopsis:	main entry point for pkgadm "lock" subcommand
 * Description:	Control zone/package administrative locking
 * Returns: 0 on success, non-zero otherwise.
 */

int
admin_lock(int argc, char **argv)
{
	FINDLOCK_T		tResult;
	LOCK_T			theLock;
	char			*RFlag = "/";	/* altRoot */
	char			*endptr;
	char			*kFlag = "";	/* key */
	char			*oFlag = "";	/* object */
	char			*p;
	char			c;
	int			aFlag = 0;	/* acquire lock */
	int			eFlag = 0;	/* exclusive lock */
	int			exclusive = 1;	/* exclusive vs shared lock */
	int			fd;
	int			qFlag = 0;	/* quiet */
	int			rFlag = 0;	/* release lock */
	int			result;
	int			sFlag = 0;	/* shared lock */
	int			tFlag = 0;	/* test comparison */
	int			wFlag = 0;	/* wait */
	long			WFlag = 0;	/* wait timeout */
	pid_t			pFlag = 0;	/* process # */
	struct sigaction	nact;
	struct sigaction	oact;
	void			(*funcSighup)();
	void			(*funcSigint)();
	zoneid_t		zFlag = -1;	/* zone i.d. */

	while ((c = getopt(argc, argv, ":aek:o:p:qrR:stwW:z:")) != EOF) {
		switch (c) {
		case 'a':	/* acquire lock */
			aFlag++;
			break;

		case 'e':	/* exclusive lock */
			eFlag++;
			break;

		case 'k':	/* lock-key */
			kFlag = optarg;
			if (strlen(optarg) > LOCK_KEY_MAXLEN) {
				log_msg(LOG_MSG_ERR,
				    MSG_LOCK_kARG_TOOLONG,
				    strlen(optarg), LOCK_KEY_MAXLEN);
				return (1);
			}
			break;

		case 'o':	/* object */
			oFlag = optarg;
			if (strlen(optarg) > LOCK_OBJECT_MAXLEN) {
				log_msg(LOG_MSG_ERR,
				    MSG_LOCK_oARG_TOOLONG,
				    strlen(optarg), LOCK_OBJECT_MAXLEN);
				return (1);
			}
			break;

		case 'p':	/* process i.d. */
			errno = 0;
			endptr = 0;
			pFlag = strtol(optarg, &endptr, 10);
			if ((endptr != (char *)NULL) && (*endptr != '\0')) {
				log_msg(LOG_MSG_ERR, MSG_LOCK_pFLAG_BADINT,
				    optarg, *endptr);
				return (1);
			}
			if ((pFlag == 0) && (errno != 0)) {
				log_msg(LOG_MSG_ERR,
				    MSG_LOCK_pFLAG_ERROR,
				    optarg,  strerror(errno));
				return (1);
			}
			break;

		case 'q':	/* quiet */
			qFlag++;
			break;

		case 'r':	/* release lock */
			rFlag++;
			break;

		case 'R':	/* alternative root */
			/* if root directory is not absolute path, error */
			if (*optarg != '/') {
				log_msg(LOG_MSG_ERR,
				    MSG_LOCK_RARG_NOT_ABSOLUTE, optarg);
				return (1);
			}

			/* if root directory does not exist, create it */
			if (access(optarg, F_OK) != 0) {

				/* create top level root directory */
				if (mkdirp(optarg, 0755) != 0) {
					log_msg(LOG_MSG_ERR,
					    MSG_LOCK_ALTROOT_CANTCREATE,
					    optarg, strerror(errno));
					return (1);
				}
			}

			/* if $ALTROOT/tmp directory does not exist create it */
			p = pkgstrPrintf("%s/tmp", optarg);
			if (access(p, F_OK) != 0) {

				/* create $ALTROOT/tmp directory */
				if (mkdirp(p, 0777) != 0) {
					log_msg(LOG_MSG_ERR,
					    MSG_LOCK_ALTROOT_CANTCREATE,
					    p, strerror(errno));
					return (1);
				}
			}

			/* if $ALTROOT/tmp directory cannot be created, exit */
			if (access(p, F_OK) != 0) {
				log_msg(LOG_MSG_ERR, MSG_LOCK_ALTROOT_NONEXIST,
				    optarg, strerror(errno));
				return (1);
			}

			(void) free(p);

			RFlag = optarg;
			break;

		case 's':	/* shared */
			sFlag++;
			break;

		case 't':	/* test comparison */
			tFlag++;
			break;

		case 'w':	/* wait */
			wFlag++;
			break;

		case 'W':	/* wait with timeout */
			errno = 0;
			endptr = 0;
			WFlag = strtol(optarg, &endptr, 10);
			if ((endptr != (char *)NULL) && (*endptr != '\0')) {
				log_msg(LOG_MSG_ERR, MSG_LOCK_WFLAG_BADINT,
				    optarg, *endptr);
				return (1);
			}
			if ((WFlag == 0) && (errno != 0)) {
				log_msg(LOG_MSG_ERR,
				    MSG_LOCK_WFLAG_ERROR,
				    optarg,  strerror(errno));
				return (1);
			}
			wFlag++;
			break;

		case 'z':	/* zone i.d. */
			errno = 0;
			endptr = 0;
			zFlag = strtol(optarg, &endptr, 10);
			if ((endptr != (char *)NULL) && (*endptr != '\0')) {
				log_msg(LOG_MSG_ERR, MSG_LOCK_zFLAG_BADINT,
				    optarg, *endptr);
				return (1);
			}
			if ((zFlag == 0) && (errno != 0)) {
				log_msg(LOG_MSG_ERR,
				    MSG_LOCK_zFLAG_ERROR,
				    optarg,  strerror(errno));
				return (1);
			}
			break;

		case ':':
			log_msg(LOG_MSG_ERR, MSG_MISSING_OPERAND, optopt);
			/* LINTED fallthrough on case statement */
		case '?':

		default:
			log_msg(LOG_MSG_ERR, MSG_USAGE);
			return (1);
		}
	}

	/*
	 * validate arguments
	 */

	/* if -t option is specified, override all other options */

	if (tFlag) {
		int	rs;
		int	rx;
		int	a;

		/* only 2 or 3 args are valid */

		a = argc-optind;
		if ((a < 2) || (a > 3)) {
			(void) fprintf(stderr, MSG_T_OPTION_ARGS, argc-optind);
			return (1);
		}

		/* if 3rd argument given, it is return value to check */

		if (a == 3) {
			rs = atoi(argv[optind+2]);
		}
		rx = _lockMatch(argv[optind+0], argv[optind+1]);

		/* if 3rd argument not given, code to check is code returned */

		if (a == 2) {
			rs = rx;
		}

		/* report results */

		if (a == 2) {
			(void) fprintf(stderr, MSG_T_RESULT_TWO,
			    rx, argv[optind+0], argv[optind+1]);
			return (rx);
		}

		if (rx != rs) {
			(void) fprintf(stderr, MSG_T_RESULT_THREE,
			    rs, rx, argv[optind+0], argv[optind+1]);
		}

		/* always successful */

		return (rx == rs ? 0 : 1);
	}

	/* must be no non-option arguments left */

	if ((argc-optind) > 0) {
		log_msg(LOG_MSG_ERR, MSG_USAGE);
		return (1);
	}

	/* -a and -r cannot be used together */

	if (aFlag && rFlag) {
		log_msg(LOG_MSG_ERR, MSG_LOCK_ar_TOGETHER);
		return (1);
	}

	/* -e and -s cannot be used together */

	if (eFlag && sFlag) {
		log_msg(LOG_MSG_ERR, MSG_LOCK_es_TOGETHER);
		return (1);
	}

	/* -e can only be used if -a is used */

	if (!aFlag && eFlag) {
		log_msg(LOG_MSG_ERR, MSG_LOCK_e_without_a);
		return (1);
	}

	/* -s can only be used if -a is used */

	if (!aFlag && sFlag) {
		log_msg(LOG_MSG_ERR, MSG_LOCK_s_without_a);
		return (1);
	}

	/*
	 * perform the requested operation
	 */

	/*
	 * hook SIGINT and SIGHUP interrupts into quit.c's trap handler
	 */

	/* hold SIGINT/SIGHUP interrupts */

	(void) sighold(SIGHUP);
	(void) sighold(SIGINT);

	/* connect sigint_handler() to SIGINT */

	nact.sa_handler = sigint_handler;
	nact.sa_flags = SA_RESTART;
	(void) sigemptyset(&nact.sa_mask);

	if (sigaction(SIGINT, &nact, &oact) < 0) {
		funcSigint = SIG_DFL;
	} else {
		funcSigint = oact.sa_handler;
	}

	/* connect sighupt_handler() to SIGHUP */

	nact.sa_handler = sighup_handler;
	nact.sa_flags = SA_RESTART;
	(void) sigemptyset(&nact.sa_mask);

	if (sigaction(SIGHUP, &nact, &oact) < 0) {
		funcSighup = SIG_DFL;
	} else {
		funcSighup = oact.sa_handler;
	}

	/* release hold on signals */

	(void) sigrelse(SIGHUP);
	(void) sigrelse(SIGINT);

	/* open the lock file */

	fd = _openLockFile(RFlag);
	if (fd < 0) {
		return (1);
	}

	if (aFlag) {
		/* set "exclusive" mode based on -e/-s flag used */

		if (sFlag) {
			exclusive = 0;
		} else if (eFlag) {
			exclusive = 1;
		}

		/* acquire lock */

		tResult = lock_acquire(&theLock, &fd, RFlag, kFlag, oFlag,
		    qFlag, wFlag, WFlag, exclusive, RFlag, pFlag, zFlag);

		switch (tResult) {
		case FINDLOCK_LOCKACQUIRED:
			(void) fprintf(stdout, "%s\n",
			    theLock._lrLock.lockKey);
			result = 0;
			break;
		case FINDLOCK_LOCKED:
			(void) fprintf(stdout, "%s\n",
			    theLock._lrLock.lockObject);
			result = 1;
			break;
		default:
			result = 1;
			break;
		}

	} else if (rFlag) {
		/* release lock */
		result = lock_release(fd, kFlag, oFlag, qFlag);
	} else {
		/* lock status */
		result = lock_status(fd, kFlag, oFlag, qFlag);
	}

	/* close the lock file */

	(void) close(fd);

	/* return results of operation */

	return (result);
}

/*
 * local main function implementation methods
 */

/*
 * Name:	lock_acquire
 * Description:	implement lock acquisition implementing the wait/timeouts
 *		Calls _lock_acquire to attempt lock acquisition.
 * Arguments:
 *	a_theLock - lock object filled with contents of existing lock
 *	a_fd - file descriptor opened on the lock file
 *	a_root - root of file system to manipulate locks on
 *	a_key - key associated with lock to acquire
 *	a_object - object associated with lock to acquire
 *	a_wait - wait if lock cannot be acquired flag:
 *			== 0 - do not wait
 *			!= 0 - wait
 *	a_timeout - timeout if waiting to acquire busy lock:
 *			== 0 - no timeout (wait forever)
 *			!= 0 - max # seconds to wait to acquire busy lock
 *	a_quiet - quiet mode enabled flag
 *	a_exclusive - exclusive/shared lock flag
 *	a_pid - if != 0 process i.d. to associate with this lock
 *	a_zid - if >= 0 - zone i.d. to associate with this lock
 * Returns: int
 *		== 0 - successful
 *		!= 0 - not successful
 */

static FINDLOCK_T
lock_acquire(LOCK_T *a_theLock, int *a_fd, char *a_root, char *a_key,
    char *a_object, int a_quiet, int a_wait, long a_timeout,
    int a_exclusive, char *a_altRoot, pid_t a_pid, zoneid_t a_zid)
{
	int		notified = 0;
	FINDLOCK_T	result;
	time_t		timeout;
	int		closeOnExit = 0;

	/* reset the lock */

	bzero(a_theLock, sizeof (LOCK_T));

	/* open file if not open */

	if ((*a_fd) < 0) {
		(*a_fd) = _openLockFile(a_altRoot);
		if ((*a_fd) < 0) {
			return (FINDLOCK_ERROR);
		}
		closeOnExit++;
	}

	/* compute time after which acquire times out */

	timeout = time((time_t *)NULL) + a_timeout;

	for (;;) {
		time_t	curtime;

		/* attempt to aquire the lock */

		result = _lock_acquire(a_theLock, *a_fd, a_key, a_object,
		    a_quiet, a_exclusive, a_pid, a_zid);

		/* return result if any result other than object is locked */

		switch (result) {
		case FINDLOCK_LOCKACQUIRED:

			/* close lock file if opened in this function */

			if (closeOnExit) {
				(void) close(*a_fd);
				*a_fd = -1;
			}

			return (FINDLOCK_LOCKACQUIRED);

		case FINDLOCK_FOUND:
		case FINDLOCK_NOTFOUND:
		case FINDLOCK_KEYMISMATCH:
		case FINDLOCK_NOTLOCKED:
		case FINDLOCK_ERROR:
		default:
			/* close lock file if opened in this function */

			if (closeOnExit) {
				(void) close(*a_fd);
				*a_fd = -1;
			}

			return (result);

		case FINDLOCK_LOCKED:
			;
			/* FALLTHROUGH */
		}

		/*
		 * object locked OR SIGINT/SIGHUP interrupt received;
		 * return error if not waiting for lock OR signal received
		 */

		if ((a_wait == 0) || (signal_received != 0)) {
			log_msg(a_quiet ? LOG_MSG_DEBUG : LOG_MSG_ERR,
			    MSG_LOCK_ACQUIRE_BUSY_FIRST,
			    a_exclusive ? MSG_LOCK_EXC : MSG_LOCK_SHR,
			    a_object, a_key,
			    a_theLock->_lrLock.lockObject,
			    a_theLock->_lrLock.lockExclusive ?
			    MSG_LOCK_EXC : MSG_LOCK_SHR,
			    a_theLock->_lrLock.lockExclusive !=
			    a_exclusive ? "" :
			    MSG_LOCK_ACQUIRE_BUSY_ADDITIONAL);

			/* close lock file if opened in this function */

			if (closeOnExit) {
				(void) close(*a_fd);
				*a_fd = -1;
			}

			return (FINDLOCK_LOCKED);
		}

		/* waiting for lock - if timeout specified see if time left */

		if (a_timeout > 0) {
			curtime = time((time_t *)NULL);
			if (curtime > timeout) {
				log_msg(a_quiet ? LOG_MSG_DEBUG : LOG_MSG_ERR,
				    MSG_LOCK_ACQUIRE_TIMEDOUT,
				    a_exclusive ?
				    MSG_LOCK_EXC : MSG_LOCK_SHR,
				    a_object, a_key);

				/* close lock file if opened in this function */

				if (closeOnExit) {
					(void) close(*a_fd);
					*a_fd = -1;
				}

				return (FINDLOCK_ERROR);
			}
		}

		/*
		 * waiting to aquire lock:
		 * - notify waiting (one time only)
		 * - close lock file
		 * - sleep
		 * - open lock file
		 * - try again
		 */

		/* notify once */

		if (notified++ == 0) {
			log_msg(a_quiet ? LOG_MSG_DEBUG : LOG_MSG_WRN,
			    MSG_LOCK_ACQUIRE_WAITING,
			    a_object);
		}

		/* close lock file */

		(void) close(*a_fd);

		/* wait (sleep) */

		(void) sleep(LOCK_SLEEP_INTERVAL);

		/* open the lock file and try again */

		*a_fd = _openLockFile(a_root);
		if (*a_fd < 0) {
			log_msg(LOG_MSG_ERR, MSG_LOCK_ACQUIRE_REOPEN_FAILED,
			    a_object);

			/* close lock file if opened in this function */

			if (closeOnExit) {
				(void) close(*a_fd);
				*a_fd = -1;
			}

			return (FINDLOCK_ERROR);
		}
	}
}

/*
 * Name:	lock_release
 * Description:	implement lock release
 * Arguments:
 *	a_fd - file descriptor opened on the lock file
 *	a_key - key associated with lock to release
 *	a_object - object associated with lock to release
 *	a_quiet - quiet mode enabled flag
 * Returns: int
 *		== 0 - successful
 *		!= 0 - not successful
 */

static int
lock_release(int a_fd, char *a_key, char *a_object, int a_quiet)
{
	RECORDNUM_T	recordNum;
	LOCK_T		theLock;
	FINDLOCK_T	result;

	/* entry debugging info */

	log_msg(LOG_MSG_DEBUG, MSG_LOCK_RELEASE_ENTRY,
	    a_key, a_object, a_quiet);

	/* find the lock to be released */

	result = _findLock(&theLock, &recordNum, a_fd, a_object, a_key);

	log_msg(LOG_MSG_DEBUG, MSG_LOCK_RELEASE_FINDRESULT,
	    result, recordNum);

	/* determine how to release the lock if found */

	switch (result) {
		/*
		 * object is not locked but a key was specified
		 */
		case FINDLOCK_NOTLOCKED:
			log_msg(a_quiet ? LOG_MSG_DEBUG : LOG_MSG_ERR,
			    MSG_LOCK_RELEASE_NOTLOCKED,
			    a_object, a_key);
			return (result);

		/*
		 * object is locked and no matching key was specified
		 */
		case FINDLOCK_LOCKED:
			log_msg(a_quiet ? LOG_MSG_DEBUG : LOG_MSG_ERR,
			    MSG_LOCK_RELEASE_LOCKED,
			    a_object, a_key);
			return (result);

		/*
		 * object is not locked
		 */
		case FINDLOCK_NOTFOUND:
			log_msg(a_quiet ? LOG_MSG_DEBUG : LOG_MSG_ERR,
			    MSG_LOCK_RELEASE_NOTFOUND,
			    a_object, a_key);
			return (result);

		/*
		 * object is locked and specified key does not match
		 */
		case FINDLOCK_KEYMISMATCH:
			log_msg(a_quiet ? LOG_MSG_DEBUG : LOG_MSG_ERR,
			    MSG_LOCK_RELEASE_KEYMISMATCH,
			    a_object);
			return (result);

		/*
		 * error determining if object is locked
		 */
		case FINDLOCK_ERROR:
			log_msg(a_quiet ? LOG_MSG_DEBUG : LOG_MSG_ERR,
			    MSG_LOCK_RELEASE_ERROR,
			    a_object, a_key);
			perror(LOCK_FILENAME);
			return (result);

		/*
		 * object is locked and specified key matches
		 */
		case FINDLOCK_FOUND:
			log_msg(LOG_MSG_DEBUG, MSG_LOCK_RELEASE_FOUND,
			    a_object, a_key);
			(void) _decrementLockCount(a_fd, &theLock);
			break;

		/*
		 * unknown return
		 */
		default:
			result = FINDLOCK_ERROR;
			break;

	}
	return (result);
}

/*
 * Name:	lock_status
 * Description:	implement lock status display/inquiry
 * Arguments:
 *	a_fd - file descriptor opened on the lock file
 *	a_key - key associated with lock to look up
 *	a_object - object associated with lock to look up
 *	a_quiet - quiet mode enabled flag
 * Returns: int
 *		== 0 - successful
 *		!= 0 - not successful
 */

static int
lock_status(int a_fd, char *a_key, char *a_object, int a_quiet)
{
	ADMINLOCK_T	*pll;
	LOCK_T		theLock;
	RECORDNUM_T	recordNum = 0;
	char		*pld;
	int		found = 0;
	long		pls;

	/* entry debugging info */

	log_msg(LOG_MSG_DEBUG, MSG_LOCK_STATUS_ENTRY,
	    a_key, a_object);

	/* localize references to lock object */

	pld = &theLock._lrLockData[0];
	pll = &theLock._lrLock;
	pls = sizeof (theLock._lrLockData);

	bzero(pld, pls);

	/* read and process each lock */

	for (; pread(a_fd, pld, pls, pls*recordNum) == pls; recordNum++) {
		/* debug info on this lock */

		log_msg(LOG_MSG_DEBUG, MSG_LOCK_STATUS_READRECORD,
		    recordNum, pll->lockCount,
		    pll->lockObject, pll->lockKey, pll->lockPid,
		    pll->lockZoneId);

		/* ignore if key specified and key does not match */

		if ((*a_key != '\0') &&
		    (strcmp(pll->lockKey, a_key) != 0)) {
			continue;
		}

		/* ignore if object specified and object does not match */

		if ((*a_object != '\0') &&
		    (strcmp(pll->lockObject, a_object) != 0)) {
			continue;
		}

		found++;

		/* process next lock if quiet operation */

		if (a_quiet != 0) {
			continue;
		}

		/* output header if first lock object */

		if (found == 1) {
			(void) fprintf(stdout,
			    "%2s %2s %3s %8s %3s %9s %37s %s\n",
			    "i#", "l#", "cnt", "pid", "zid", "lock-type",
			    "---------------lock-key-------------",
			    "lock-object");
		}

		/* output status line for this lock object */

		(void) fprintf(stdout,
		    "%2ld %2ld %3ld %8ld %3d %9s %37s %s\n",
		    recordNum, pll->lockRecordNum, pll->lockCount,
		    pll->lockPid, pll->lockZoneId,
		    pll->lockExclusive ? MSG_LOCK_EXC : MSG_LOCK_SHR,
		    pll->lockKey,
		    *pll->lockObject == '\0' ? "*" : pll->lockObject);
	}

	/* return == 0 if found, != 0 if not found */

	return (found == 0 ? 1 : 0);
}

/*
 * local utility functions
 */

/*
 * Name:	_lock_acquire
 * Description:	implement lock acquisition without wait/timeouts
 * Arguments:
 *	a_theLock - lock object filled with contents of existing lock
 *	a_fd - file descriptor opened on the lock file
 *	a_key - key associated with lock to acquire
 *	a_object - object associated with lock to acquire
 *	a_quiet - quiet mode enabled flag
 *	a_exclusive - exclusive/shared lock flag
 *	a_pid - if != 0 process i.d. to associate with this lock
 *	a_zid - if >= 0 zone i.d. to associate with this lock
 * Returns: FINDLOCK_T
 */

static FINDLOCK_T
_lock_acquire(LOCK_T *a_theLock, int a_fd, char *a_key,
    char *a_object, int a_quiet, int a_exclusive, pid_t a_pid,
    zoneid_t a_zid)
{
	RECORDNUM_T	recordNum;
	FINDLOCK_T	result;
	char		key[LOCK_KEY_MAXLEN+1] = {'\0'};

	/* entry debugging info */

	log_msg(LOG_MSG_DEBUG, MSG_LOCK_ACQUIRE_ENTRY,
	    a_key, a_object, a_quiet, a_exclusive);

	/* is the specified object already locked? */

	for (;;) {
		result = _findLock(a_theLock, &recordNum, a_fd, a_object,
		    a_key);

		if (result != FINDLOCK_LOCKED) {
			break;
		}

		if (_validateLock(a_fd, a_theLock, a_quiet) == B_TRUE) {
			break;
		}
	}


	/* debug info on result of find of lock */

	log_msg(LOG_MSG_DEBUG, MSG_LOCK_ACQUIRE_FINDRESULT,
	    a_exclusive ? MSG_LOCK_EXC : MSG_LOCK_SHR,
	    result, recordNum);

	/* determine how to acquire the lock */

	switch (result) {
		/*
		 * object is not locked but a key was specified
		 */
		case FINDLOCK_NOTLOCKED:
			log_msg(a_quiet ? LOG_MSG_DEBUG : LOG_MSG_ERR,
			    MSG_LOCK_ACQUIRE_NOTLOCKED,
			    a_exclusive ? MSG_LOCK_EXC : MSG_LOCK_SHR,
			    a_object, a_key);
			break;

		/*
		 * object is locked and no key was specified:
		 * - if lock is exclusively held, return "locked"
		 * - if exclusive lock requested, return "locked"
		 * - otherwise lock is shared and shared lock requested,
		 *   - increment lock count and return the key
		 */
		case FINDLOCK_LOCKED:
			/* return error if current lock exclusive */

			if (a_theLock->_lrLock.lockExclusive) {
				break;
			}

			/* return error if requesting exclusive lock */

			if (a_exclusive) {
				break;
			}

			/* shared requesting shared - add to shared lock */

			log_msg(LOG_MSG_DEBUG,
			    MSG_LOCK_ACQUIRE_LOCKED_SHARED,
			    a_object, a_key);

			/* increment shared lock count */

			if (_incrementLockCount(a_fd, a_theLock) == 0) {
				result = FINDLOCK_LOCKACQUIRED;
			} else {
				result = FINDLOCK_ERROR;
			}

			break;

		/*
		 * object is not locked
		 */
		case FINDLOCK_NOTFOUND:
			log_msg(LOG_MSG_DEBUG,
			    MSG_LOCK_ACQUIRE_NOTFOUND,
			    a_exclusive ? MSG_LOCK_EXC : MSG_LOCK_SHR,
			    a_object);

			if (_addLock(key, a_fd, a_object, a_exclusive,
			    a_pid, a_zid) == 0) {
				(void) strncpy(a_theLock->_lrLock.lockKey, key,
				    sizeof (a_theLock->_lrLock.lockKey));
				result = FINDLOCK_LOCKACQUIRED;
			} else {
				result = FINDLOCK_ERROR;
			}
			break;

		/*
		 * object is locked, key specified, specified key does not match
		 */
		case FINDLOCK_KEYMISMATCH:
			log_msg(a_quiet ? LOG_MSG_DEBUG : LOG_MSG_ERR,
			    MSG_LOCK_ACQUIRE_KEYMISMATCH,
			    a_exclusive ? MSG_LOCK_EXC : MSG_LOCK_SHR,
			    a_object);
			break;

		/*
		 * error determining if object is locked
		 */
		case FINDLOCK_ERROR:
			log_msg(LOG_MSG_ERR, MSG_LOCK_ACQUIRE_ERROR,
			    a_object, a_key, strerror(errno));
			break;

		/*
		 * object is locked and specified key matches
		 */
		case FINDLOCK_FOUND:
			/* return locked if object currently locked */
			if (a_exclusive != a_theLock->_lrLock.lockExclusive) {
				result = FINDLOCK_LOCKED;
				break;
			}

			log_msg(LOG_MSG_DEBUG, MSG_LOCK_ACQUIRE_FOUND_INC,
			    a_object, a_key,
			    a_exclusive ? MSG_LOCK_EXC : MSG_LOCK_SHR);

			/* increment shared lock */

			if (_incrementLockCount(a_fd, a_theLock) == 0) {
				result = FINDLOCK_LOCKACQUIRED;
			} else {
				result = FINDLOCK_ERROR;
			}
			break;

		/*
		 * unknown return
		 */
		default:
			result = FINDLOCK_ERROR;
			break;
	}

	return (result);
}

/*
 * Name:	_openLockFile
 * Description:	open the lock file, acquiring exclusive record locks
 * Arguments:
 *	a_root - root of file system to manipulate locks on
 * Returns: int
 *		>= 0 - successful - file descriptor lock file opened on
 *		< 0 - not successful
 */

static int
_openLockFile(char *a_root)
{
	WAITER_T	waiter;
	char		lockpath[MAXPATHLEN];
	int		fd;
	int		result;

	/* entry debugging info */

	log_msg(LOG_MSG_DEBUG, MSG_LOCK_OPENFILE_ENTRY,
	    a_root, LOCK_FILENAME);

	/* generate path to lock directory */

	(void) snprintf(lockpath, sizeof (lockpath), "%s/%s",
	    a_root, LOCK_DIRECTORY);

	if (access(lockpath, F_OK) != 0) {
		log_msg(LOG_MSG_ERR, MSG_LOCK_ROOTDIR_INVALID,
		    lockpath, strerror(errno));
		return (-1);
	}

	/* generate path to lock file */

	(void) snprintf(lockpath, sizeof (lockpath),
	    "%s/%s", a_root, LOCK_FILENAME);

	/* wait for open to succeed up to limits */

	for (waiter = WAITER_INITIAL;
	    waiter < WAITER_MAX;
	    waiter = WAITER_NEXT(waiter)) {

		/* LINTED O_CREAT without O_EXCL specified in call to open() */
		fd = open(lockpath, O_CREAT|O_RDWR, LOCK_FILEMODE);

		/* break out of loop if file opened */

		if (fd >= 0) {
			break;
		}

		/* failed - exit loop if due to access (permissions) failure */

		if (errno == EACCES) {
			break;
		}

		/* file is busy - wait and try again */

		if (waiter == WAITER_INITIAL) {
			log_msg(LOG_MSG_DEBUG,
			    MSG_LOCK_OPENFILE_SLEEPING,
			    strerror(errno), waiter);
		}

		(void) sleep(waiter);
	}

	/* if open filed generate error message and return error */

	if (fd < 0) {
		log_msg(LOG_MSG_DEBUG, MSG_LOCK_OPENFILE_FAILURE,
		    strerror(errno));
		perror(lockpath);
		return (-1);
	}

	/*
	 * lock file opened - acquire exclusive section lock on entire file;
	 * wait for lockf to succeed up to limits
	 */

	for (waiter = WAITER_INITIAL;
	    waiter < WAITER_MAX;
	    waiter = WAITER_NEXT(waiter)) {

		/* acquire exclusive section lock on entire file */

		result = lockf(fd, F_LOCK, 0xFFFFF);

		/* break out of loop if entire file locked */

		if (result == 0) {
			break;
		}

		/* file is busy - wait and try again */

		if (waiter == WAITER_INITIAL) {
			log_msg(LOG_MSG_DEBUG, MSG_LOCK_OPENFILE_SLEEP2,
			    strerror(errno), waiter);
		}

		(void) sleep(waiter);
	}

	/* if section lock failed generate error message and return error */

	if (result < 0) {
		log_msg(LOG_MSG_DEBUG, MSG_LOCK_OPENFILE_FAIL2,
		    strerror(errno));
		perror(lockpath);
		(void) close(fd);
		return (-1);
	}

	/* file opened and locked - return success */

	log_msg(LOG_MSG_DEBUG, MSG_LOCK_OPENFILE_SUCCESS, fd);

	return (fd);
}

/*
 * Name:	_lockMatch
 * Description:	Compare two lock objects using file name match criteria
 * Arguments:
 *	a_s1Lock - first lock object to compare against the second
 *	a_s2Lock - second lock object to compare against the first
 * Returns:
 * 	== 0 - the locks match at some level
 *	!= 0 - the locks do not match at any level
 */

static int
_lockMatch(char *a_s1Lock, char *a_s2Lock)
{
	boolean_t	s1Sfx = B_FALSE;
	boolean_t	s2Sfx = B_FALSE;
	char		*final1Lock = (char *)NULL;
	char		*final2Lock = (char *)NULL;
	char		s1Buf[MAXPATHLEN] = {'\0'};
	char		s1Prefix[MAXPATHLEN] = {'\0'};
	char		s2Buf[MAXPATHLEN] = {'\0'};
	char		s2Prefix[MAXPATHLEN] = {'\0'};
	int		result = 0;
	int		s1Cnt;
	int		s2Cnt;

	/* entry assertions */

	assert(a_s1Lock != (char *)NULL);
	assert(a_s2Lock != (char *)NULL);

	/* entry debugging info */

	log_msg(LOG_MSG_DEBUG, MSG_LCKMCH_ENTRY, a_s1Lock, a_s2Lock);

	/*
	 * attempt to find a common anchor between the two locks; that is,
	 * find the first node in the first lock that matches any node
	 * in the second lock; for example:
	 * --> a/b/c vs b/c/d
	 * -> common anchor is "b"; comparison would expand to:
	 * --> a/b/c/? vs ?/b/c/d
	 */

	/* process each node in the first lock */

	for (s1Cnt = 0; ; s1Cnt++) {
		/* get next first lock node */

		pkgstrGetToken_r((char *)NULL, a_s1Lock, s1Cnt, "/",
		    s1Buf, sizeof (s1Buf));

		log_msg(LOG_MSG_DEBUG, MSG_LCKMCH_FSTNODE, s1Cnt, s1Buf);

		/* exit if no more nodes left */

		if (s1Buf[0] == '\0') {
			break;
		}

		/* discover "." prefix for this node */

		pkgstrGetToken_r((char *)NULL, s1Buf, 0, ".", s1Prefix,
		    sizeof (s1Prefix));

		s1Sfx = (strlen(s1Prefix) == strlen(s1Buf) ? B_FALSE : B_TRUE);

		/* search each second lock node; look for the first node lock */

		for (s2Cnt = 0; ; s2Cnt++) {
			/* get next second lock node */

			pkgstrGetToken_r((char *)NULL, a_s2Lock, s2Cnt, "/",
			    s2Buf, sizeof (s2Buf));

			log_msg(LOG_MSG_DEBUG, MSG_LCKMCH_SCNDNODE, s2Cnt,
			    s2Buf);

			/* exit if no nodes left */

			if (s2Buf[0] == '\0') {
				break;
			}

			/* discover "." prefix for this node */

			pkgstrGetToken_r((char *)NULL, s2Buf, 0, ".", s2Prefix,
			    sizeof (s2Prefix));

			s2Sfx = (strlen(s2Prefix) ==
			    strlen(s2Buf) ? B_FALSE : B_TRUE);

			/*
			 * process this pair of nodes:
			 * if both nodes do not have a prefix, then directly
			 * compare the nodes (e.g. a/b vs c/d: a vs c, b vs d)
			 * and break out of the loop if there is a match;
			 * otherwise, compare prefixes and break out of the
			 * loop if there is a match (e.g. a.* / b.* vs
			 * vs c.* / d.*: a.* vs c.*, a.* vs d.*, b.* vs c.*,
			 * b.* vs d.*).
			 */

			log_msg(LOG_MSG_DEBUG, MSG_LCKMCH_NODES, s1Buf,
			    s1Prefix, s1Sfx, s2Buf, s2Prefix, s2Sfx);

			if ((s1Sfx == B_FALSE) || (s2Sfx == B_FALSE)) {
				/* one doesnt have a prefix direct comparison */

				if (strcmp(s1Buf, s2Buf) == 0) {
					log_msg(LOG_MSG_DEBUG,
					    MSG_LCKMCH_DIRMCH,
					    s1Buf, s2Buf);
					break;
				}

				/* nodes do not directly match, continue */

				log_msg(LOG_MSG_DEBUG, MSG_LCKMCH_DIRNOMCH,
				    s1Buf, s2Buf);
				continue;
			}

			/* both have prefix, compare prefixes */

			if (strcmp(s1Prefix, s2Prefix) == 0) {
				log_msg(LOG_MSG_DEBUG, MSG_LCKMCH_PFXMCH,
				    s1Prefix, s2Prefix);
				break;
			}

			/* prefixes do not match, continue */

			log_msg(LOG_MSG_DEBUG, MSG_LCKMCH_PFXNOMCH, s1Prefix,
			    s2Prefix);
		}

		/*
		 * match found if not at the end of the second lock node list,
		 * break out of loop because some match between the two lock
		 * objects has been found
		 */

		if (s2Buf[0] != '\0') {
			break;
		}
	}

	/*
	 * at this point, either a match has been found between the nodes in
	 * the two lock objects, or there is no commonality at all between
	 * the two lock objects.
	 *
	 * s1Buf[0] == '\0' && s2Buf[0] == '\0':
	 * --> nothing in first lock matches anything in second lock:
	 * ----> (s1Cnt == 1) || (s2Cnt == 1) && (s1Sfx == B_FALSE)
	 * ----> || (s2Sfx == B_FALSE)
	 * --------> an absolute lock do not match
	 * ----> else both object locks have nothing in common - match
	 *
	 * s2Buf[0] != '\0' && s1Buf[0] != '\0' && s1Cnt > 0 && s2Cnt > 0
	 * --> locks have incompatible overlaps - no match, such as:
	 * ---->  a.* / b.* / c.* / d.*   and   y.* / b.* / c.*
	 *
	 * s1Cnt == 0 && s2Cnt == 0:
	 * --> locks begin with same node - do comparison
	 *
	 * s1Cnt != 0 && s2Cnt == 0 && s2Buf[0] != '\0'
	 * --> second lock is subset of first lock
	 *
	 * s2Cnt == 0 && s2Buf[0] != '\0':
	 * --> s1Buf[s1Cnt] matches s2Buf[0] - second is subset of first
	 *
	 * s2Cnt != 0 && s1Cnt == 0 && s1Buf[0] != '\0':
	 * --> first lock is subset of second lock
	 *
	 */

	log_msg(LOG_MSG_DEBUG, MSG_LCKMCH_FSTLCK, s1Cnt, s1Buf,
	    s1Prefix, s1Sfx);
	log_msg(LOG_MSG_DEBUG, MSG_LCKMCH_SCNDLCK, s2Cnt, s2Buf,
	    s2Prefix, s2Sfx);

	/* process any direct comparisons that might be possible */

	if ((s1Buf[0] == '\0') && (s2Buf[0] == '\0')) {
		/* nothing in first matches anything in second lock */

		if (((s1Cnt == 1) || (s2Cnt == 1)) &&
		    ((s1Sfx == B_FALSE) || (s2Sfx == B_FALSE))) {
			/* two absolute locks match (e.g. 'file' and 'dir') */
			log_msg(LOG_MSG_DEBUG, MSG_LCKMCH_ABSNOMCH, a_s1Lock,
			    a_s2Lock);
			return (1);
		}

		/* two object locks have nothing in common: match */

		log_msg(LOG_MSG_DEBUG, MSG_LCKMCH_OBJMCH, a_s1Lock, a_s2Lock);

		return (0);
	}

	if ((s2Buf[0] != '\0') && (s1Buf[0] != '\0') &&
	    (s1Cnt > 0) && (s2Cnt > 0)) {
		/* incompatible overlapping objects */

		log_msg(LOG_MSG_DEBUG, MSG_LCKMCH_OVLPNOMCH, a_s1Lock, a_s2Lock,
		    s1Cnt+1, s1Buf);

		return (1);
	}

	/*
	 * must compare each node of each lock to determine match;
	 * start off at the first byte of both locks
	 */

	final1Lock = a_s1Lock;
	final2Lock = a_s2Lock;

	if ((s1Cnt == 0) && (s2Cnt == 0)) {
		/* both have first match - start comparison from the begining */

		log_msg(LOG_MSG_DEBUG, MSG_LCKMCH_SAME, a_s1Lock, a_s2Lock,
		    s1Buf);

	} else if ((s1Cnt != 0) && (s2Cnt == 0) && (s2Buf[0] != '\0')) {
		/* second lock begins somewhere inside of the first lock */

		log_msg(LOG_MSG_DEBUG, MSG_LCKMCH_SCNDSUB, a_s2Lock, a_s1Lock,
		    s1Cnt+1, s1Buf);

		/* advance first lock to matching node in second lock */

		if (strchr(a_s1Lock, '/') != (char *)NULL) {
			for (; s1Cnt > 0 && (*final1Lock != '\0');
			    final1Lock++) {
				if (*final1Lock == '/') {
					s1Cnt--;
				}
			}
		}
	} else if ((s2Cnt != 0) && (s1Cnt == 0) && (s1Buf[0] != '\0')) {
		/* first lock begins somewhere inside of the second lock */

		log_msg(LOG_MSG_DEBUG, MSG_LCKMCH_FRSTSUB, a_s1Lock, a_s2Lock,
		    s2Cnt+1, s2Buf);

		/* advance second lock to matching node in first lock */

		if (strchr(a_s2Lock, '/') != (char *)NULL) {
			for (; s2Cnt > 0 && (*final2Lock != '\0');
			    final2Lock++) {
				if (*final2Lock == '/') {
					s2Cnt--;
				}
			}
		}
	} else {
		/* unknown condition (probably impossible): directly compare */

		log_msg(LOG_MSG_ERR, MSG_LCKMCH_DONTKNOW, a_s1Lock, a_s2Lock);
	}

	/*
	 * locks have common node - compare from that node forward
	 */

	log_msg(LOG_MSG_DEBUG, MSG_LCKMCH_READY, final1Lock, final2Lock);

	/* compare each node (prefix) - success when no more nodes to compare */

	for (s1Cnt = 0; ; s1Cnt++) {
		/* get next node from first lock */

		pkgstrGetToken_r((char *)NULL, final1Lock, s1Cnt, "/", s1Buf,
		    sizeof (s1Buf));

		/* success if at end of lock */

		if (s1Buf[0] == '\0') {
			break;
		}

		/* get next node from second lock */

		pkgstrGetToken_r((char *)NULL, final2Lock, s1Cnt, "/", s2Buf,
		    sizeof (s2Buf));

		/* success if at end of lock */

		if (s2Buf[0] == '\0') {
			break;
		}

		/* compare both nodes */

		result = fnmatch(s1Buf, s2Buf, 0);
		if (result != 0) {
			result = fnmatch(s2Buf, s1Buf, 0);
		}

		/* failure if nodes do not match */

		if (result != 0) {
			log_msg(LOG_MSG_DEBUG, MSG_LCKMCH_NODEFAIL,
			    s1Cnt, s1Buf, s2Buf);
			return (1);
		}

		/* nodes match, continue and compare next set of nodes */

		log_msg(LOG_MSG_DEBUG, MSG_LCKMCH_NODEOK, s1Cnt, s1Buf, s2Buf);
	}

	/* no more nodes to compare - locks match */

	log_msg(LOG_MSG_DEBUG, MSG_LCKMCH_MATCHOK, final1Lock, final2Lock);

	return (0);
}

/*
 * Name:	_findLock
 * Description:	Locate specified lock in lock file
 * Arguments:
 *	a_theLock - lock object filled with contents of lock (if found)
 *	r_recordNum - will contain record number if lock found
 *		- will be RECORDNUM_NONE if lock not found
 *	a_fd - file descriptor opened on the lock file
 *	a_key - key associated with lock to look up
 *	a_object - object associated with lock to look up
 * Returns:
 *	FINDLOCK_FOUND - specified lock found; a_theLock contains contents
 *		of found lock, r_recordNum contain record number of lock
 *	FINDLOCK_ERROR - failed - error occurred looking up the lock
 *	FINDLOCK_NOTFOUND - specified object is not locked
 *	FINDLOCK_KEYMISMATCH - object lock found but specified key doesnt match
 *	FINDLOCK_LOCKED - object lock found but no key specified
 *	FINDLOCK_NOTLOCKED - object not locked
 */

static FINDLOCK_T
_findLock(LOCK_T *a_theLock, RECORDNUM_T *r_recordNum,
    int a_fd, char *a_object, char *a_key)
{
	ADMINLOCK_T	*pll;
	char		*pld;
	int		recordNum = 0;
	long		pls;
	off_t		pos;

	/* reset returned record number to "none" */

	*r_recordNum = RECORDNUM_NONE;

	/* localize references to lock object */

	pld = &a_theLock->_lrLockData[0];
	pll = &a_theLock->_lrLock;
	pls = sizeof (a_theLock->_lrLockData);

	/* zero out returned lock data */

	bzero(pld, pls);

	/* debug info before processing lock file */

	log_msg(LOG_MSG_DEBUG, MSG_LOCK_FINDLOCK_ENTRY,
	    a_object, a_key);

	/* rewind to beginning of lock file */

	pos = lseek(a_fd, 0L, SEEK_SET);
	if (pos == (off_t)-1) {
		log_msg(LOG_MSG_ERR, MSG_LOCK_FINDLOCK_LSEEK_FAILURE,
		    a_object, a_key, strerror(errno));
		return (FINDLOCK_ERROR);
	}

	/* read and process each lock */

	for (; pread(a_fd, pld, pls, pls*recordNum) == pls; recordNum++) {
		/* debug info on this lock */

		log_msg(LOG_MSG_DEBUG, MSG_LOCK_FINDLOCK_READRECORD,
		    recordNum, pll->lockCount,
		    pll->lockObject, pll->lockKey, pll->lockPid,
		    pll->lockZoneId);

		/* continue if object is not the one we are looking for */

		if (_lockMatch(a_object, pll->lockObject) != 0) {
			continue;
		}

		/*
		 * object found; return locked if searching for no key
		 */

		if (*a_key == '\0') {
			/* no key specified - object is locked */
			*r_recordNum = recordNum;
			return (FINDLOCK_LOCKED);
		}

		/*
		 * object found and keys present; see if keys match
		 */

		if (strcmp(pll->lockKey, a_key) != 0) {
			/* keys do not match */
			*r_recordNum = recordNum;
			return (FINDLOCK_KEYMISMATCH);
		}

		/* object found and keys match - return match */

		log_msg(LOG_MSG_DEBUG, MSG_LOCK_FINDLOCK_FOUND);

		*r_recordNum = recordNum;
		return (FINDLOCK_FOUND);
	}

	/* object not locked - return error if key supplied */

	if (*a_key != '\0') {
		return (FINDLOCK_NOTLOCKED);
	}

	/* object not locked and key not supplied - no lock found */

	log_msg(LOG_MSG_DEBUG, MSG_LOCK_FINDLOCK_NOTFOUND);

	return (FINDLOCK_NOTFOUND);
}

/*
 * Name:	_addLock
 * Description:	Add a new lock to the lock file
 * Arguments:
 *	r_key - if lock acquired key is placed here
 *	a_fd - file descriptor opened on the lock file
 *	a_object - object to lock
 *	a_exclusive - type of lock to add:
 *		== 0 - shared lock
 *		!= 0 - exclusive lock
 *	a_pid - if != 0 process i.d. to associate with this lock
 *	a_zid - if >= 0 zone i.d. to associate with this lock
 * Returns:	int
 *			== 0 - success
 *			!= 0 - failure
 */

static int
_addLock(char *r_key, int a_fd, char *a_object, int a_exclusive, pid_t a_pid,
    zoneid_t a_zid)
{
	LOCK_T	theLock;
	char	*key;
	off_t	pos;
	ssize_t	result;

	/* get unique i.d. for this lock */

	key = _getUniqueId();

	/* determine record number for next record in lock file */

	pos = lseek(a_fd, 0L, SEEK_END);
	if (pos == (off_t)-1) {
		log_msg(LOG_MSG_ERR, MSG_LOCK_ADDLOCK_LSEEK_FAILURE,
		    a_exclusive ? MSG_LOCK_EXC : MSG_LOCK_SHR,
		    a_object, strerror(errno));
		return (1);
	}

	/* allocate storace for this lock */

	bzero(&theLock, sizeof (theLock));

	/* fill in components of the lock */

	(void) strlcpy(theLock._lrLock.lockObject, a_object,
	    LOCK_OBJECT_MAXLEN);
	(void) strlcpy(theLock._lrLock.lockKey, key, LOCK_KEY_MAXLEN);
	theLock._lrLock.lockCount = 1;
	theLock._lrLock.lockPid = (a_pid > 0 ? a_pid : 0);
	theLock._lrLock.lockRecordNum = (pos == 0 ? 0 : (pos/sizeof (LOCK_T)));
	theLock._lrLock.lockExclusive = a_exclusive;
	theLock._lrLock.lockZoneId = (a_zid >= 0 ? a_zid : -1);

	/* debug info on new lock */

	log_msg(LOG_MSG_DEBUG, MSG_LOCK_ADDLOCK_ADDING,
	    a_exclusive ? MSG_LOCK_EXC : MSG_LOCK_SHR,
	    pos, theLock._lrLock.lockObject, theLock._lrLock.lockKey,
	    theLock._lrLock.lockPid, theLock._lrLock.lockZoneId);

	/* write the new lock record to the end of the lock file */

	result = pwrite(a_fd, &theLock, LOCK_SIZE, pos);
	if (result != LOCK_SIZE) {
		log_msg(LOG_MSG_ERR, MSG_LOCK_ADDLOCK_PWRITE_FAILURE,
		    a_exclusive ? MSG_LOCK_EXC : MSG_LOCK_SHR,
		    a_object, strerror(errno));
		return (1);
	}

	/* output the key assigned to standard out */

	(void) strncpy(r_key, key, LOCK_KEY_MAXLEN);

	return (0);
}

static int
_incrementLockCount(int a_fd, LOCK_T *a_theLock)
{
	ADMINLOCK_T	*pll;
	char		*pld;
	long		pls;
	ssize_t		result;

	/* localize references to lock object */

	pld = &a_theLock->_lrLockData[0];
	pll = &a_theLock->_lrLock;
	pls = sizeof (a_theLock->_lrLockData);

	/* debug info on incrementing lock */

	log_msg(LOG_MSG_DEBUG, MSG_LOCK_INCLOCK_ENTRY,
	    a_theLock->_lrLock.lockExclusive ?
	    MSG_LOCK_EXC : MSG_LOCK_SHR,
	    pll->lockRecordNum, pll->lockCount);

	/* increment lock count */

	pll->lockCount++;

	/* write out updated lock */

	result = pwrite(a_fd, pld, pls, pll->lockRecordNum*pls);
	if (result != pls) {
		log_msg(LOG_MSG_ERR, MSG_LOCK_INCLOCK_PWRITE_FAILURE,
		    a_theLock->_lrLock.lockExclusive ?
		    MSG_LOCK_EXC : MSG_LOCK_SHR,
		    a_theLock->_lrLock.lockObject,
		    strerror(errno));
		return (1);
	}

	/* debug info lock incremented */

	log_msg(LOG_MSG_DEBUG, MSG_LOCK_INCLOCK_DONE,
	    pll->lockRecordNum, pll->lockCount,
	    pll->lockObject, pll->lockKey);

	return (0);
}

/*
 * Name:	_validateLock
 * Description:	determine if a specified lock is valid; if the lock is not valid
 *		then remove the lock
 * Arguments:	a_fd - file descriptor opened on the lock file
 *		a_theLock - lock object to validate
 * Returns:	boolean_t
 *			B_TRUE - the lock is valid
 *			B_FALSE - the lock is not valid and has been removed
 */

static boolean_t
_validateLock(int a_fd, LOCK_T *a_theLock, int a_quiet)
{
	ADMINLOCK_T	*pll;
	char		*pld;
	long		pls;
	char		path[MAXPATHLEN];

	/* localize references to lock object */

	pld = &a_theLock->_lrLockData[0];
	pll = &a_theLock->_lrLock;
	pls = sizeof (a_theLock->_lrLockData);

	/* return true if no process i.d. associated with lock */

	if (pll->lockPid <= 0) {
		log_msg(LOG_MSG_DEBUG, MSG_VALID_NOPID, pll->lockObject);
		return (B_TRUE);
	}

	/* see if the zone i.d. matches */

	if (pll->lockZoneId != getzoneid()) {
		log_msg(LOG_MSG_DEBUG, MSG_VALID_BADZID, pll->lockObject,
		    pll->lockZoneId, getzoneid());
		return (B_TRUE);
	} else {
		log_msg(LOG_MSG_DEBUG, MSG_VALID_ZIDOK, pll->lockObject,
		    pll->lockZoneId, getzoneid());
	}

	/* see if the process is still active */

	pkgstrPrintf_r(path, sizeof (path), "/proc/%d", pll->lockPid);
	if (access(path, F_OK) == 0) {
		log_msg(LOG_MSG_DEBUG, MSG_VALID_OK, pll->lockObject,
		    pll->lockPid, path);
		return (B_TRUE);
	}

	log_msg(LOG_MSG_DEBUG, MSG_VALID_NOTOK, pll->lockObject, pll->lockPid,
	    path);

	/* delete this lock */

	log_msg(a_quiet ? LOG_MSG_DEBUG : LOG_MSG_WRN,
	    MSG_VALID_STALE, pll->lockObject, pll->lockPid,
	    pll->lockZoneId);

	_decrementLockCount(a_fd, a_theLock);

	return (B_FALSE);
}

static int
_decrementLockCount(int a_fd, LOCK_T *a_theLock)
{
	ADMINLOCK_T	*pll;
	LOCK_T		tmpLock;
	RECORDNUM_T	lastRecord;
	char		*pld;
	long		pls;
	off_t		lastPos;
	ssize_t		result;
	int		res;

	/* localize references to lock object */

	pld = &a_theLock->_lrLockData[0];
	pll = &a_theLock->_lrLock;
	pls = sizeof (a_theLock->_lrLockData);

	/* decrement lock count */

	pll->lockCount--;

	/* if lock count > 0 then write out and leave locked */

	if (pll->lockCount > 0) {
		log_msg(LOG_MSG_DEBUG, MSG_LOCK_DECLOCK_DECING,
		    a_theLock->_lrLock.lockExclusive ?
		    MSG_LOCK_EXC : MSG_LOCK_SHR,
		    pll->lockRecordNum, pll->lockCount);

		result = pwrite(a_fd, pld, pls, pll->lockRecordNum*pls);
		if (result != pls) {
			log_msg(LOG_MSG_ERR, MSG_LOCK_DECLOCK_PWRITE_FAILURE,
			    a_theLock->_lrLock.lockExclusive ?
			    MSG_LOCK_EXC : MSG_LOCK_SHR,
			    a_theLock->_lrLock.lockObject,
			    strerror(errno));
			return (1);
		}

		log_msg(LOG_MSG_DEBUG, MSG_LOCK_DECLOCK_DONE,
		    pll->lockRecordNum, pll->lockCount,
		    pll->lockObject, pll->lockKey);

		return (0);
	}

	/*
	 * lock count zero - erase the record
	 */

	/* find last record in the lock file */

	lastPos = lseek(a_fd, 0L, SEEK_END);	/* get size of lock file */
	if (lastPos == (off_t)-1) {
		log_msg(LOG_MSG_ERR, MSG_LOCK_DECLOCK_LSEEK_FAILURE,
		    a_theLock->_lrLock.lockExclusive ?
		    MSG_LOCK_EXC : MSG_LOCK_SHR,
		    a_theLock->_lrLock.lockObject,
		    strerror(errno));
		return (1);
	}

	lastRecord = (lastPos/pls)-1;	/* convert size to record # */

	log_msg(LOG_MSG_DEBUG, MSG_LOCK_DECLOCK_REMOVE,
	    lastPos, lastRecord, pll->lockRecordNum);

	/* see if removing last record of file */

	if (lastRecord == pll->lockRecordNum) {
		/* debug info removing last record */

		log_msg(LOG_MSG_DEBUG, MSG_LOCK_DECLOCK_LASTONE,
		    a_theLock->_lrLock.lockExclusive ?
		    MSG_LOCK_EXC : MSG_LOCK_SHR,
		    lastRecord, lastPos-pls);

		/* removing last record of file, truncate */

		res = ftruncate(a_fd, lastPos-pls);
		if (res == -1) {
			log_msg(LOG_MSG_ERR, MSG_LOCK_DECLOCK_FTRUNCATE_FAILURE,
			    a_theLock->_lrLock.lockExclusive ?
			    MSG_LOCK_EXC : MSG_LOCK_SHR,
			    a_theLock->_lrLock.lockObject,
			    strerror(errno));
			return (1);
		}
		return (0);
	}

	/*
	 * not removing last record of file:
	 * read last record, truncate file one record,
	 * replace record to be removed with last record read
	 */

	log_msg(LOG_MSG_DEBUG, MSG_LOCK_DECLOCK_REMOVING,
	    pll->lockRecordNum, lastRecord, lastPos-pls);

	/* read in the last record */

	result = pread(a_fd, tmpLock._lrLockData, pls, lastRecord*pls);
	if (result != pls) {
		log_msg(LOG_MSG_ERR, MSG_LOCK_DECLOCK_PREAD_FAILURE,
		    a_theLock->_lrLock.lockExclusive ?
		    MSG_LOCK_EXC : MSG_LOCK_SHR,
		    a_theLock->_lrLock.lockObject,
		    strerror(errno));
		return (1);

	}

	/* truncate lock file removing the last record (just read in) */

	res = ftruncate(a_fd, lastPos-pls);
	if (res == -1) {
		log_msg(LOG_MSG_ERR, MSG_LOCK_DECLOCK_FTRUNCATE_FAILURE,
		    a_theLock->_lrLock.lockExclusive ?
		    MSG_LOCK_EXC : MSG_LOCK_SHR,
		    a_theLock->_lrLock.lockObject,
		    strerror(errno));
			return (1);
	}

	/* update record to indicate its new position in the lock file */

	tmpLock._lrLock.lockRecordNum = pll->lockRecordNum;

	/* write out the updated record to the new location */

	result = pwrite(a_fd, tmpLock._lrLockData, pls, pll->lockRecordNum*pls);
	if (result != pls) {
		log_msg(LOG_MSG_ERR, MSG_LOCK_DECLOCK_PWRITE_FAILURE,
		    a_theLock->_lrLock.lockExclusive ?
		    MSG_LOCK_EXC : MSG_LOCK_SHR,
		    a_theLock->_lrLock.lockObject,
		    strerror(errno));
		return (1);
	}

	return (0);
}

/*
 * Name:	_getUniqueId
 * Description:	Generate a unique ID that can be used as a key for a new lock
 * Arguments:	None
 * Returns:	char *
 *			== NULL - error, no key generated
 *			!= NULL - generated key
 * NOTE:    	Any results returned is placed in new storage for the
 *		calling method. The caller must use 'lu_memFree' to dispose
 *		of the storage once the results are no longer needed.
 */

static char *
_getUniqueId(void)
{
	char		newkey[LOCK_KEY_MAXLEN];
	hrtime_t	hretime;
	struct tm	tstruct;
	time_t		thetime;

	/*
	 * generate own unique key - the key is the
	 * same length as unique uid but contains different information that
	 * is as unique as can be made - include current hires time (nanosecond
	 * real timer). Such a unique i.d. will look like:
	 * 	0203104092-1145345-0004e94d6af481a0
	 */

	hretime = gethrtime();

	thetime = time((time_t *)NULL);
	(void) localtime_r(&thetime, &tstruct);

	(void) snprintf(newkey, sizeof (newkey),
	    "%02d%02d%02d%03d-%02d%02d%02d%d-%016llx", tstruct.tm_mday,
	    tstruct.tm_mon, tstruct.tm_year, tstruct.tm_yday,
	    tstruct.tm_hour, tstruct.tm_min, tstruct.tm_sec,
	    tstruct.tm_wday, hretime);

	log_msg(LOG_MSG_DEBUG, MSG_LOCK_GENUID_INTERNAL, newkey);
	return (strdup(newkey));
}

/*
 * Name:	sigint_handler
 * Synopsis:	SIGINT interrupt handler
 * Description:	Catch the "SIGINT" signal; increment signal_received
 *		global variable,
 * Arguments:	signo - [RO, *RO] - (int)
 *			Signal number that was caught
 * Returns:	void
 */

static void
sigint_handler(int a_signo)
{
	signal_received++;
}

/*
 * Name:	sighup_handler
 * Synopsis:	SIGHUP interrupt handler
 * Description:	Catch the "SIGHUP" signal; increment signal_received
 *		global variable,
 * Arguments:	signo - [RO, *RO] - (int)
 *			Signal number that was caught
 * Returns:	void
 */

static void
sighup_handler(int a_signo)
{
	signal_received++;
}
