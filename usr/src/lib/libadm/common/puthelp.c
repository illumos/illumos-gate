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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include "libadm.h"

void
puthelp(FILE *fp, char *defmesg, char *help)
{
	char	*tmp;
	size_t	n;

	tmp = NULL;
	if (help == NULL) {
		/* use default message since no help was provided */
		help = defmesg ? defmesg : "No help available.";
	} else if (defmesg != NULL) {
		n = strlen(help);
		if (help[0] == '~') {
			/* prepend default message */
			tmp = calloc(n+strlen(defmesg)+1, sizeof (char));
			(void) strcpy(tmp, defmesg);
			(void) strcat(tmp, "\n");
			++help;
			(void) strcat(tmp, help);
			help = tmp;
		} else if (n && (help[n-1] == '~')) {
			/* append default message */
			tmp = calloc(n+strlen(defmesg)+2, sizeof (char));
			(void) strcpy(tmp, help);
			tmp[n-1] = '\0';
			(void) strcat(tmp, "\n");
			(void) strcat(tmp, defmesg);
			help = tmp;
		}
	}
	(void) puttext(fp, help, ckindent, ckwidth);
	(void) fputc('\n', fp);
	if (tmp)
		free(tmp);
}
