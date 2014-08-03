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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983,1984,1985,1986,1987,1988,1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#ifndef _UTMPX_H
#define	_UTMPX_H

#include <sys/feature_tests.h>
#include <sys/types.h>
#include <sys/time.h>
#include <utmp.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	_UTMPX_FILE	"/var/adm/utmpx"
#define	_WTMPX_FILE	"/var/adm/wtmpx"
#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
#define	UTMPX_FILE	_UTMPX_FILE
#define	WTMPX_FILE	_WTMPX_FILE
#endif

#define	ut_name	ut_user
#define	ut_xtime ut_tv.tv_sec

/*
 * This data structure describes the utmpx entries returned by
 * the getutxent(3c) family of APIs.  It does not (necessarily)
 * correspond to the contents of the utmpx or wtmpx files.
 *
 * Applications should only interact with this subsystem via
 * the getutxent(3c) family of APIs.
 */
struct utmpx {
	char	ut_user[32];		/* user login name */
	char	ut_id[4];		/* inittab id */
	char	ut_line[32];		/* device name (console, lnxx) */
	pid_t	ut_pid;			/* process id */
	short	ut_type;		/* type of entry */
#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
	struct exit_status ut_exit;	/* process termination/exit status */
#else
	struct ut_exit_status ut_exit;	/* process termination/exit status */
#endif
	struct timeval ut_tv;		/* time entry was made */
	int	ut_session;		/* session ID, used for windowing */
#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
	int	pad[5];			/* reserved for future use */
#else
	int	__pad[5];		/* reserved for future use */
#endif
	short	ut_syslen;		/* significant length of ut_host */
					/*   including terminating null */
	char	ut_host[257];		/* remote host name */
};

#if !defined(_XPG4_2) || defined(__EXTENSIONS__)

#include <sys/types32.h>
#include <inttypes.h>

/*
 * This data structure describes the utmp *file* contents using
 * fixed-width data types.  It should only be used by the implementation.
 *
 * Applications should use the getutxent(3c) family of routines to interact
 * with this database.
 */

struct futmpx {
	char	ut_user[32];		/* user login name */
	char	ut_id[4];		/* inittab id */
	char	ut_line[32];		/* device name (console, lnxx) */
	pid32_t	ut_pid;			/* process id */
	int16_t ut_type;		/* type of entry */
	struct {
		int16_t	e_termination;	/* process termination status */
		int16_t	e_exit;		/* process exit status */
	} ut_exit;			/* exit status of a process */
	struct timeval32 ut_tv;		/* time entry was made */
	int32_t	ut_session;		/* session ID, user for windowing */
	int32_t	pad[5];			/* reserved for future use */
	int16_t ut_syslen;		/* significant length of ut_host */
	char	ut_host[257];		/* remote host name */
};

#define	MOD_WIN		10

/*	Define and macro for determing if a normal user wrote the entry */
/*	and marking the utmpx entry as a normal user */
#define	NONROOT_USRX	2
#define	nonuserx(utx)	((utx).ut_exit.e_exit == NONROOT_USRX ? 1 : 0)
#define	setuserx(utx)	((utx).ut_exit.e_exit = NONROOT_USRX)

#endif /* !defined(_XPG4_2) || defined(__EXTENSIONS__) */

extern void endutxent(void);
extern struct utmpx *getutxent(void);
extern struct utmpx *getutxid(const struct utmpx *);
extern struct utmpx *getutxline(const struct utmpx *);
extern struct utmpx *pututxline(const struct utmpx *);
extern void setutxent(void);

#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
extern int utmpxname(const char *);
extern struct utmpx *makeutx(const struct utmpx *);
extern struct utmpx *modutx(const struct utmpx *);
extern void getutmp(const struct utmpx *, struct utmp *);
extern void getutmpx(const struct utmp *, struct utmpx *);
extern void updwtmp(const char *, struct utmp *);
extern void updwtmpx(const char *, struct utmpx *);
#endif /* !defined(_XPG4_2) || defined(__EXTENSIONS__) */

#ifdef	__cplusplus
}
#endif

#endif	/* _UTMPX_H */
