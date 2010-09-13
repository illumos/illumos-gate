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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include <sys/types.h>
#include <stdio.h>
#include "curses_inc.h"

int
traceon(void)
{
#ifdef DEBUG
	if (outf == NULL) {
		outf = fopen("trace", "a");
		if (outf == NULL) {
			perror("trace");
			exit(-1);
		}
		fprintf(outf, "trace turned on\n");
	}
#endif /* DEBUG */
	return (OK);
}

int
traceoff(void)
{
#ifdef DEBUG
	if (outf != NULL) {
		fprintf(outf, "trace turned off\n");
		fclose(outf);
		outf = NULL;
	}
#endif /* DEBUG */
	return (OK);
}

#ifdef DEBUG
#include <ctype.h>

char *
_asciify(char *str)
{
	static	char	string[1024];
	char	*p1 = string;
	char	*p2;
	char	c;

	while (c = *str++) {
		p2 = unctrl(c);
		while (*p1 = *p2++)
			p1++;
	}
	return (string);
}
#endif /* DEBUG */
