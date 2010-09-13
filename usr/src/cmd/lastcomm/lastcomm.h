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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_LASTCOMM_H
#define	_LASTCOMM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/acct.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/mkdev.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <limits.h>
#include <stdio.h>
#include <utmpx.h>
#include <ctype.h>
#include <pwd.h>
#include <dirent.h>
#include <libintl.h>
#include <exacct.h>

#define	AHZ	64
#define	fldsiz(str, fld)	(sizeof (((struct str *)0)->fld))

#define	BUF_MAX		4096
#define	NACCT		(BUF_MAX / sizeof (struct acct))
#define	BUF_SIZ		(NACCT * sizeof (struct acct))
#define	PATHNAMLEN	32
#define	EXACCT_CREATOR	"SunOS"

/*
 * utmpx defines wider fields for user and line.  For compatibility of output,
 * we are limiting these to the old maximums in utmp. Define UTMPX_NAMELEN
 * to use the full lengths.
 */
#ifndef UTMPX_NAMELEN
/* XXX - utmp - fix name length */
#define	NMAX		(_POSIX_LOGIN_NAME_MAX - 1)
#define	LMAX		12
#else   /* UTMPX_NAMELEN */
static struct utmpx dummy;
#define	NMAX		(sizeof (dummy.ut_user))
#define	LMAX		(sizeof (dummy.ut_line))
#endif /* UTMPX_NAMELEN */

extern char *getdev(dev_t);
extern char *getname(uid_t);
extern char *flagbits(int);

extern int lc_pacct(char *, int, char **, int);
extern int lc_exacct(char *, int, char **, int);

#ifdef	__cplusplus
}
#endif

#endif	/* _LASTCOMM_H */
