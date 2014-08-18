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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef	_SHADOW_H
#define	_SHADOW_H


#ifdef	__cplusplus
extern "C" {
#endif

#define	PASSWD 		"/etc/passwd"
#define	SHADOW		"/etc/shadow"
#define	OPASSWD		"/etc/opasswd"
#define	OSHADOW 	"/etc/oshadow"
#define	PASSTEMP	"/etc/ptmp"
#define	SHADTEMP	"/etc/stmp"

#define	DAY		(24L * 60 * 60) /* 1 day in seconds */
#define	DAY_NOW		(time_t)time((time_t *)0) / DAY
			/* The above timezone variable is set by a call to */
			/* any ctime(3c) routine.  Programs using the DAY_NOW */
			/* macro must call one of the ctime routines, */
			/* e.g. tzset(), BEFORE referencing DAY_NOW */

#define	LOCKSTRING	"*LK*"	/* prefix to/string in sp_pwdp to lock acct */
#define	NOLOGINSTRING	"NP"	/* sp_pwdp for no-login accounts */
#define	NOPWDRTR	"*NP*"	/* password is not retrievable */
/*
 * The spwd structure is used in the retreval of information from
 * /etc/shadow.  It is used by routines in the libos library.
 */
struct spwd {
	char *sp_namp;	/* user name */
	char *sp_pwdp;	/* user password */
	int sp_lstchg;	/* password lastchanged date */
	int sp_min;	/* minimum number of days between password changes */
	int sp_max;	/* number of days password is valid */
	int sp_warn;	/* number of days to warn user to change passwd */
	int sp_inact;	/* number of days the login may be inactive */
	int sp_expire;	/* date when the login is no longer valid */
	unsigned int sp_flag;	/* currently low 4 bits are used */

	/* low 4 bits of sp_flag for counting failed login attempts */
#define	FAILCOUNT_MASK 0xF
};

#ifndef _STDIO_H
#include <stdio.h>
#endif

/* Declare all shadow password functions */

extern struct spwd *getspnam_r(const char *,  struct spwd *, char *, int);
extern struct spwd *getspent_r(struct spwd *, char *, int);
extern struct spwd *fgetspent_r(FILE *, struct spwd *, char *, int);

extern void	setspent(void);
extern void	endspent(void);
extern struct spwd	*getspent(void);			/* MT-unsafe */
extern struct spwd	*fgetspent(FILE *);			/* MT-unsafe */
extern struct spwd	*getspnam(const char *);	/* MT-unsafe */

extern int	putspent(const struct spwd *, FILE *);
extern int	lckpwdf(void);
extern int	ulckpwdf(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _SHADOW_H */
