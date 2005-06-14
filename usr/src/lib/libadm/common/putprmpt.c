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
 * Copyright (c) 1997-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*LINTLIBRARY*/

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "libadm.h"

void
putprmpt(FILE *fp, char *prompt, char *choices[], char *defstr)
{
	char buffer[1024] = ""; /* NB: code should prevent overflow... */
	int i, n;

	(void) fputc('\n', fp);
	if (prompt == NULL) {
		(void) strlcpy(buffer, defstr ? defstr : "No default prompt.",
				sizeof (buffer));
	} else if (n = (int)strlen(prompt)) {
		if (defstr == NULL)
			defstr = "";
		if (prompt[0] == '~')
			(void) snprintf(buffer, sizeof (buffer), "%s%s",
				defstr, prompt + 1);
		else if (prompt[n-1] == '~')
			(void) snprintf(buffer, sizeof (buffer), "%.*s%s",
				n - 1, prompt, defstr);
		else
			(void) strlcpy(buffer, prompt, sizeof (buffer));
	} else
		(void) strlcpy(buffer, "", sizeof (buffer));

	(void) strlcat(buffer, "\\ [", sizeof (buffer));
	for (i = 0; choices && choices[i]; ++i) {
		(void) strlcat(buffer, choices[i], sizeof (buffer));
		(void) strlcat(buffer, ",", sizeof (buffer));
	}
	(void) strlcat(buffer, ckquit ? "?,q] " : "?] ", sizeof (buffer));

	(void) puttext(fp, buffer, 0, ckwidth);
}
