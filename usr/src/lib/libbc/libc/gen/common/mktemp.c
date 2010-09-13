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

#pragma ident	"%Z%%M%	%I%	%E% SMI"  /* from S5R3 1.11 */

/*	Copyright (c) 1984 AT&T	*/
/*	  All Rights Reserved  	*/


/*LINTLIBRARY*/
/****************************************************************
 *	Routine expects a string of length at least 6, with
 *	six trailing 'X's.  These will be overlaid with a
 *	letter and the last (5) digigts of the proccess ID.
 *	If every letter (a thru z) thus inserted leads to
 *	an existing file name, your string is shortened to
 *	length zero upon return (first character set to '\0').
 ***************************************************************/
#include <sys/types.h>
#include <sys/stat.h>

#define XCNT  6

extern int strlen(), access(), getpid();

char *
mktemp(as)
char *as;
{
	register char *s=as;
	register unsigned pid;
	register unsigned xcnt=0; /* keeps track of number of X's seen */
	struct stat buf;

	pid = getpid();
	s += strlen(as);	/* point at the terminal null */
	while(*--s == 'X' && ++xcnt <= XCNT) {
		*s = (pid%10) + '0';
		pid /= 10;
	}
	if(*++s) {		/* maybe there were no 'X's */
		*s = 'a';
		while (stat(as, &buf) == 0) {
			if(++*s > 'z') {
				*as = '\0';
				break;
			}
		}
	} else
		if (stat(as, &buf) == 0)
			*as = '\0';
	return(as);
}
