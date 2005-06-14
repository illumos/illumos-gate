/*-
 * See the file LICENSE for redistribution information.
 *
 * Copyright (c) 1997
 *	Sleepycat Software.  All rights reserved.
 */
/*
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include "config.h"

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef lint
static const char sccsid[] = "@(#)os_rpath.c	10.2 (Sleepycat) 10/24/97";
static const char sccsi2[] = "%W% (Sun) %G%";
#endif /* not lint */

#ifndef NO_SYSTEM_INCLUDES
#include <string.h>
#endif

#include "db_int.h"

/*
 * __db_rpath --
 *	Return the last path separator in the path or NULL if none found.
 *
 * PUBLIC: char *__db_rpath __P((const char *));
 */
char *
__db_rpath(path)
	const char *path;
{
	const char *s, *last;

	last = NULL;
	if (PATH_SEPARATOR[1] != '\0') {
		for (s = path; s[0] != '\0'; ++s)
			if (strchr(PATH_SEPARATOR, s[0]) != NULL)
				last = s;
	} else
		for (s = path; s[0] != '\0'; ++s)
			if (s[0] == PATH_SEPARATOR[0])
				last = s;
	return ((char *)last);
}
