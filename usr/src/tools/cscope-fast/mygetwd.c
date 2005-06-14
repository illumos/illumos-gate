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
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>	/* needed by stat.h */
#include <sys/stat.h>	/* stat */
#include <stdio.h>	/* NULL */
#include <string.h>	/* string functions */
#include <stdlib.h>

/*
 * if the ksh PWD environment variable matches the current
 * working directory, don't call getwd()
 */

char *
mygetwd(char *dir)
{
	char	*pwd;			/* PWD environment variable value */
	struct	stat	d_sb;  		/* current directory status */
	struct	stat	tmp_sb; 	/* temporary stat buffer */
	char	*getwd();

	/* get the current directory's status */
	if (stat(".", &d_sb) < 0) {
		return (NULL);
	}
	/* use $PWD if it matches this directory */
	if ((pwd = getenv("PWD")) != NULL && *pwd != '\0' &&
	    stat(pwd, &tmp_sb) == 0 &&
	    d_sb.st_ino == tmp_sb.st_ino && d_sb.st_dev == tmp_sb.st_dev) {
		(void) strcpy(dir, pwd);
		return (pwd);
	}
	return (getwd(dir));
}
