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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>	/* EFT abs k16 */
#include "wish.h"
#include "token.h"
#include "slk.h"
#include "actrec.h"
#include "proc.h"
#include "terror.h"
#include	"moremacros.h"

struct actrec *Proc_list = NULL;
extern struct proc_rec PR_all[];

int
proc_open(int flags, char *title, char *path, ...)
{
	char *argv[MAX_ARGS+2];
	register int i;
	va_list list;

	va_start(list, path);
	for (i = 0; i < MAX_ARGS+1 && (argv[i] = va_arg(list, char *)); i++)
		;
	argv[MAX_ARGS+1] = NULL;
	va_end(list);

	return(proc_openv(flags, title, path, argv));
}

int
proc_opensys(flags, title, path, arg)
int flags;
char *title, *path;
char *arg;
{
	return(proc_open(flags, title, path,  "/bin/sh", "-c", arg, NULL));
}

int
proc_openv(flags, title, path, argv)
int flags;
char *title, *path;
char *argv[];
{
	struct actrec a, *rec;
	extern struct slk No_slks[];
	int proc_close(), proc_current(), proc_noncurrent(), proc_ctl();
	struct actrec *ar_create(), *path_to_ar();

	a.serial = 0;
	a.interrupt = (char *)NULL;
	a.oninterrupt = (char *)NULL;
	a.slks = (struct slk *)NULL;
	a.prevrec = (struct actrec *)NULL;
	a.nextrec = (struct actrec *)NULL;
	a.backup = (struct actrec *)NULL;

	/* if no path is specified, consider all the arguments put together
	 * to be the path.
	 */

	if (path == NULL) {
		char buf[BUFSIZ];
		register int i, len;

		for (i = len = 0; argv[i]; i++)
			len += sprintf(buf+len, "%s\t", argv[i]);
		a.path = strsave(buf);
	} else
		a.path = strsave(path);

	if ((rec = path_to_ar(a.path)) != NULL) {
		free(a.path);
		return(ar_current(rec, TRUE)); /* abs k15 */
	}

	a.odptr = title?strsave(title):NULL;

	a.fcntbl[AR_CLOSE] = proc_close;
	a.fcntbl[AR_REREAD] = AR_NOP;
	a.fcntbl[AR_REINIT] = AR_NOP;
	a.fcntbl[AR_CURRENT] = proc_current;
/*	a.fcntbl[AR_TEMP_CUR] = proc_current; */ /* abs k15 optimize later */
	a.fcntbl[AR_TEMP_CUR] = AR_NOP; /* miked */
	a.fcntbl[AR_NONCUR] = proc_noncurrent;
	a.fcntbl[AR_CTL] = proc_ctl;
	a.fcntbl[AR_HELP] = AR_NOHELP;
	a.fcntbl[AR_ODSH] = AR_NOP;
	a.id = proc_default(flags, argv);
	if (a.id == FAIL)
		return(FAIL);
	a.lifetime = AR_LONGTERM;
	a.flags = AR_SKIP;
	a.slks = No_slks;

	if (Proc_list)
		(void) ar_close(Proc_list, FALSE);

	PR_all[a.id].ar = ar_create(&a);

	return(ar_current(PR_all[a.id].ar, FALSE)?SUCCESS:FAIL); /* abs k15 */
}
