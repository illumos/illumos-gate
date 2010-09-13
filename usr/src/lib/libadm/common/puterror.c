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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1997, by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*LINTLIBRARY*/
#pragma	ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1 */

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "libadm.h"

#define	DEFMSG	"ERROR: "
#define	MS	sizeof (DEFMSG)
#define	INVINP	"invalid input"

void
puterror(FILE *fp, char *defmesg, char *error)
{
	char	*tmp;
	size_t	n;

	if (error == NULL) {
		/* use default message since no error was provided */
		n = (defmesg ?  strlen(defmesg) : strlen(INVINP));
		tmp = calloc(MS+n+1, sizeof (char));
		(void) strcpy(tmp, DEFMSG);
		(void) strcat(tmp, defmesg ? defmesg : INVINP);

	} else if (defmesg != NULL) {
		n = strlen(error);
		if (error[0] == '~') {
			/* prepend default message */
			tmp = calloc(MS+n+strlen(defmesg)+2, sizeof (char));
			(void) strcpy(tmp, DEFMSG);
			(void) strcat(tmp, defmesg);
			(void) strcat(tmp, "\n");
			++error;
			(void) strcat(tmp, error);
		} else if (n && (error[n-1] == '~')) {
			/* append default message */
			tmp = calloc(MS+n+strlen(defmesg)+2, sizeof (char));
			(void) strcpy(tmp, DEFMSG);
			(void) strcat(tmp, error);
			/* first -1 'cuz sizeof (DEFMSG) includes terminator */
			tmp[MS-1+n-1] = '\0';
			(void) strcat(tmp, "\n");
			(void) strcat(tmp, defmesg);
		} else {
			tmp = calloc(MS+n+1, sizeof (char));
			(void) strcpy(tmp, DEFMSG);
			(void) strcat(tmp, error);
		}
	} else {
		n = strlen(error);
		tmp = calloc(MS+n+1, sizeof (char));
		(void) strcpy(tmp, DEFMSG);
		(void) strcat(tmp, error);
	}
	(void) puttext(fp, tmp, ckindent, ckwidth);
	(void) fputc('\n', fp);
	free(tmp);
}
