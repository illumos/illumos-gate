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
 * m_pathcat: mks specific library routine.
 * 
 * Copyright 1992 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/mks/rcs/m_pathca.c 1.11 1995/04/12 14:14:19 miked Exp $";
#endif
#endif

#include <mks.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

/*f
 * Concatenate a directory and filename, inserting / if necessary.
 * Return dynamically allocated pointer to result string.
 * On error: return NULL and set errno.
 *
 * Errors can occur if:
 *    dir == NULL
 *    file == NULL
 *    dir is an invalid pathname
 *    strlen(dir) + strlen(file) +2 > maximum allowable pathlength
 *
 * note: if PATH_MAX has to be retrieved by m_pathmax(dir),
 * we may return error if the dir name has problems,
 * which the caller had best expect.
 */
char *
m_pathcat(dir, file)
const char *dir;
const char *file;
{
	char *dest;
	int dir_len;
	int file_len;
	int m;
	int l;

	if ((dir == NULL) || (file == NULL))
		goto err;

#ifdef	PATH_MAX
	l = PATH_MAX;
#else
	l = m_pathmax(dir);
	if (l < 0)
		return (NULL);	/* Errno is set by m_pathmax() */
#endif

	dir_len = strlen(dir);
	/*
	 * add one for seperator eg. '/'
	 */
	m = dir_len+1;

	file_len = strlen(file);
	if (file_len > 0) {
		/*
		 * add one null termination char
		 */
		m += file_len+1;
	}

	if (m > l) {
err:
#ifdef	ENAMETOOLONG
		errno = ENAMETOOLONG;
#else
		/* 
		 * we need to return an errno. So pick EINVAL.
		 * This should be common on all systems.
		 */
		errno = EINVAL;
#endif
		return (NULL);
	}

	/*
	 * use m_malloc() - this guarantees a valid errno return on error
	 */
	if ((dest = m_malloc(m)) == NULL) {
		return (NULL);
	}

	strcpy(dest, dir);
	if (file_len > 0) {
		if (dir_len > 0
		    && !M_FSDELIM(dest[dir_len-1])
		    && !M_DRDELIM(dest[dir_len-1])) {
			dest[dir_len++] = '/';
		}
		strcpy(dest+dir_len, file);
	}
	return (dest);
}
