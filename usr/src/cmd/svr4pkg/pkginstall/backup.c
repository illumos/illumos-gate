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
#include <locale.h>
#include <libintl.h>
#include <pkglib.h>

extern char	savlog[];
extern int	warnflag;

void
backup(char *path, int mode)
{
	static int	count = 0;
	static FILE	*fp;

	/* mode probably used in the future */
	if (count++ == 0) {
		if ((fp = fopen(savlog, "w")) == NULL) {
			logerr(gettext("WARNING: unable to open logfile <%s>"),
			    savlog);
			warnflag++;
		}
	}

	if (fp == NULL)
		return;

	(void) fprintf(fp, "%s%s", path, mode ? "\n" :
	    gettext(" <attributes only>\n"));
	/* we don't really back anything up; we just log the pathname */
}
