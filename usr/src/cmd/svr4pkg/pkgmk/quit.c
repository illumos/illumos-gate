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
 * Copyright 1993 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */


#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <pkgdev.h>
#include <locale.h>
#include <libintl.h>
#include <pkglib.h>
#include "libadm.h"

extern struct pkgdev pkgdev;
extern char	pkgloc[], *t_pkgmap, *t_pkginfo;

extern int	started;

#define	MSG_COMPLETE	"## Packaging complete.\n"
#define	MSG_TERM	"## Packaging terminated at user request.\n"
#define	MSG_ERROR	"## Packaging was not successful.\n"

void
quit(int retcode)
{
	(void) signal(SIGINT, SIG_IGN);
	(void) signal(SIGHUP, SIG_IGN);

	if (retcode == 3)
		(void) fprintf(stderr, gettext(MSG_TERM));
	else if (retcode)
		(void) fprintf(stderr, gettext(MSG_ERROR));
	else
		(void) fprintf(stderr, gettext(MSG_COMPLETE));

	if (retcode && started)
		(void) rrmdir(pkgloc); /* clean up output directory */

	if (pkgdev.mount)
		(void) pkgumount(&pkgdev);

	if (t_pkgmap)
		(void) unlink(t_pkgmap);
	if (t_pkginfo)
		(void) unlink(t_pkginfo);
	exit(retcode);
}
