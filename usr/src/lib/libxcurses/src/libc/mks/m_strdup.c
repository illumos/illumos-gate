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
 * Copyright 1992 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */
#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Id: m_strdup.c 1.8 1993/05/28 07:43:26 scott Exp $";
#endif
#endif

#include <mks.h>
#include <string.h>
#include <stdlib.h>

/*f
 * Return a copy of the string `s', issue an error and return NULL.
 */
LDEFN char *
m_strdup(s)
const char *s;
{
	char *cp;
	int len;

	if ((cp = m_malloc(len = strlen(s)+1)) == NULL) {
		m_error(m_textmsg(3581, "!memory allocation failure", "E"));
		return NULL;
	}
	return (memcpy(cp, s, len));
}
