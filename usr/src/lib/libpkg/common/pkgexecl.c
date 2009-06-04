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
 * Copyright 2004 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */


#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <wait.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <fcntl.h>
#include "pkglocale.h"
#include "pkglibmsgs.h"
#include "pkglib.h"

#define	MAXARGS	64

/*VARARGS4*/
int
pkgexecl(char *filein, char *fileout, char *uname, char *gname, ...)
{
	char		*arg[MAXARGS+1];
	char		*pt;
	int		n;
	va_list		ap;

	/* construct arg[] array from varargs passed in */

	va_start(ap, gname);

	n = 0;
	while ((pt = va_arg(ap, char *)) != NULL) {
		if (n >= MAXARGS) {
			va_end(ap);
			progerr(pkg_gt(ERR_TOO_MANY_ARGS),
				arg[0] ? arg[0] : "??");
			return (-1);
		}
		arg[n++] = pt;
	}

	arg[n] = NULL;
	va_end(ap);

	/* return results of executing command based on arg[] list */

	return (pkgexecv(filein, fileout, uname, gname, arg));
}
