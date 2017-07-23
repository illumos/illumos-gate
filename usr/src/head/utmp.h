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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/


/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef _UTMP_H
#define	_UTMP_H

/*
 * Note:  The getutent(3c) family of interfaces are obsolete.
 * The getutxent(3c) family provide a superset of this functionality
 * and should be used in place of getutent(3c).
 */

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
#define	UTMP_FILE	"/var/adm/utmp"
#define	WTMP_FILE	"/var/adm/wtmp"
#endif

#define	ut_name	ut_user

#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
struct exit_status {
	short e_termination;	/* Process termination status */
	short e_exit;		/* Process exit status */
};
#else
struct ut_exit_status {
	short ut_e_termination;	/* Process termination status */
	short ut_e_exit;	/* Process exit status */
};
#endif /* !defined(_XPG4_2) || defined(__EXTENSIONS__) */

#if !defined(_XPG4_2) || defined(__EXTENSIONS__)

/*
 * This data structure describes the utmp entries returned by
 * the getutent(3c) family of APIs.  It does not (necessarily)
 * correspond to the contents of the utmp or wtmp files.
 *
 * Applications should only interact with this subsystem via
 * the getutxent(3c) family of APIs, as the getutent(3c) family
 * are obsolete.
 */
struct utmp {
	char ut_user[8];		/* User login name */
	char ut_id[4];			/* /etc/inittab id(usually line #) */
	char ut_line[12];		/* device name (console, lnxx) */
	short ut_pid;			/* short for compat. - process id */
	short ut_type;			/* type of entry */
	struct exit_status ut_exit;	/* The exit status of a process */
					/* marked as DEAD_PROCESS. */
	time_t ut_time;			/* time entry was made */
};

#include <sys/types32.h>
#include <inttypes.h>

/*
 * This data structure describes the utmp *file* contents using
 * fixed-width data types.  It should only be used by the implementation.
 *
 * Applications should use the getutxent(3c) family of routines to interact
 * with this database.
 */

struct futmp {
	char ut_user[8];		/* User login name */
	char ut_id[4];			/* /etc/inittab id */
	char ut_line[12];		/* device name (console, lnxx) */
	int16_t ut_pid;			/* process id */
	int16_t ut_type;		/* type of entry */
	struct {
		int16_t	e_termination;	/* Process termination status */
		int16_t e_exit;		/* Process exit status */
	} ut_exit;			/* The exit status of a process */
	time32_t ut_time;		/* time entry was made */
};

#endif /* !defined(_XPG4_2) || defined(__EXTENSIONS__) */

/*	Definitions for ut_type						*/

#define	EMPTY		0
#define	RUN_LVL		1
#define	BOOT_TIME	2
#define	OLD_TIME	3
#define	NEW_TIME	4
#define	INIT_PROCESS	5	/* Process spawned by "init" */
#define	LOGIN_PROCESS	6	/* A "getty" process waiting for login */
#define	USER_PROCESS	7	/* A user process */
#define	DEAD_PROCESS	8

#if !defined(_XPG4_2) || defined(__EXTENSIONS__)

#define	ACCOUNTING	9
#define	DOWN_TIME	10

#define	UTMAXTYPE	DOWN_TIME	/* Largest legal value of ut_type */

/*	Special strings or formats used in the "ut_line" field when	*/
/*	accounting for something other than a process.			*/
/*	No string for the ut_line field can be more than 11 chars +	*/
/*	a NULL in length.						*/

#define	RUNLVL_MSG	"run-level %c"
#define	BOOT_MSG	"system boot"
#define	OTIME_MSG	"old time"
#define	NTIME_MSG	"new time"
#define	PSRADM_MSG	"%03d  %s"	/* processor on or off */
#define	DOWN_MSG	"system down"

/*	Define and macro for determing if a normal user wrote the entry */
/*	 and marking the utmpx entry as a normal user */
#define	NONROOT_USR	2
#define	nonuser(ut)	((ut).ut_exit.e_exit == NONROOT_USR ? 1 : 0)
#define	setuser(ut)	((ut).ut_exit.e_exit = NONROOT_USR)


extern void endutent(void);
extern struct utmp *getutent(void);
extern struct utmp *getutid(const struct utmp *);
extern struct utmp *getutline(const struct utmp *);
extern struct utmp *pututline(const struct utmp *);
extern void setutent(void);
extern int utmpname(const char *);

#endif /* !defined(_XPG4_2) || defined(__EXTENSIONS__) */

#ifdef	__cplusplus
}
#endif

#endif	/* _UTMP_H */
