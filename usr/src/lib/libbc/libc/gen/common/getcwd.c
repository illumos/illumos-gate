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
 * Copyright 1989 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*      Copyright (c) 1984 AT&T */
/*        All Rights Reserved   */
#pragma ident	"%Z%%M%	%I%	%E% SMI"  /* from S5R2 1.2 */

/*LINTLIBRARY*/
/*
 * Library routine to GET the Current Working Directory.
 * arg1 is a pointer to a character buffer into which the
 * path name of the current directory is placed by the
 * subroutine.  arg1 may be zero, in which case the 
 * subroutine will call malloc to get the required space.
 * arg2 is the length of the buffer space for the path-name.
 * If the actual path-name is longer than (arg2-2), or if
 * the value of arg2 is not at least 3, the subroutine will
 * return a value of zero, with errno set as appropriate.
 */

#include <stdio.h>
#include <sys/errno.h>

extern FILE *popen();
extern char *malloc(), *fgets(), *strchr();
extern int errno, pclose();

char *
getcwd(arg1, arg2)
char	*arg1;
int	arg2;
{
	FILE	*pipe;
	char	*trm;

	if(arg2 <= 0) {
		errno = EINVAL;
		return(0);
	}
	if(arg1 == 0)
		if((arg1 = malloc((unsigned)arg2)) == 0) {
			errno = ENOMEM;
			return(0);
		}
	errno = 0;
	if((pipe = popen("pwd", "r")) == 0)
		return(0);
	(void) fgets(arg1, arg2, pipe);
	(void) pclose(pipe);
	trm = strchr(arg1, '\0');
	if(*(trm-1) != '\n') {
		errno = ERANGE;
		return(0);
	}
	*(trm-1) = '\0';
	return(arg1);
}
