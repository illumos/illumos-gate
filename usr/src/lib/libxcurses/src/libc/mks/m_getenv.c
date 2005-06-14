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
 * MKS interface extension.
 * A version of getenv() that doesn't overwrite it's return value
 * on each call.
 *
 * Copyright 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char const rcsID[] = "$Header: /rd/src/libc/mks/rcs/m_getenv.c 1.2 1995/07/11 16:53:01 ross Exp $";
#endif /*lint*/
#endif /*M_RCSID*/

#include <mks.h>
#include <stdlib.h>
#include <string.h>

#ifdef M_NON_STATIC_GETENV

#undef __m_getenv

/*f
 *  Assume getenv() works the way we expect it to on PC systems.
 */
char *
__m_getenv(char const *name) {
	return getenv(name);
}

#else /* M_NON_STATIC_GETENV */

extern char **environ;

/*f
 *  A version of getenv safe to use in library functions.  According to
 *  ANSI C and XPG 4 no library function shall behave as if it called
 *  getenv.  This is a problem on systems that have getenv functions
 *  that overwrite their return value on each call.
 */

char *
__m_getenv(char const *name) {
	if (m_setenv() != NULL) {
		int len = strlen(name);
		char **envp = environ;
		char *s = *envp++;

		while(s != NULL) {
			if (strncmp(name, s, len) == 0 && s[len] == '=') {
				return s + len + 1;
			}
			s = *envp++;
		}
	}
	return NULL;
}
	
#endif /* M_NON_STATIC_GETENV */
