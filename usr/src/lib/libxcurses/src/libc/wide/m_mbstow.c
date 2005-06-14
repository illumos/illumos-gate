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
 * Copyright (c) 1996, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *       wchar_t *m_mbstowcsdup(char *s)
 * (per strdup, only converting at the same time.)
 * Takes a multibyte string, figures out how long it will be in wide chars,
 * allocates that wide char string, copies to that wide char string.
 * returns (wchar_t *)0 on
 *       - out of memory
 *       - invalid multibyte character
 * Caller must free returned memory by calling free.
 *
 * Copyright 1992 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */
#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/wide/rcs/m_mbstow.c 1.6 1995/09/20 19:11:56 ant Exp $";
#endif /*lint*/
#endif /*M_RCSID*/

#include <mks.h>
#include <stdlib.h>
#include <string.h>

wchar_t *
m_mbstowcsdup(const char *s)
{
	int n;
	wchar_t *w;

	n = strlen(s) + 1;
	if ((w = (wchar_t *)m_malloc(n * sizeof(wchar_t))) == NULL) {
		m_error(m_textmsg(3581, "!memory allocation failure", "E"));
		return(NULL);
	}

	if (mbstowcs(w, s, n) == -1) {
		m_error(m_textmsg(3642, "!multibyte string", "E"));
		return(NULL);
	}
	return w;
}
