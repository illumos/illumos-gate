/*-
 * See the file LICENSE for redistribution information.
 *
 * Copyright (c) 1996, 1997
 *	Sleepycat Software.  All rights reserved.
 */
/*
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include "config.h"

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef lint
static const char sccsid[] = "@(#)log_compare.c	10.2 (Sleepycat) 6/21/97";
static const char sccsi2[] = "%W% (Sun) %G%";
#endif /* not lint */

#ifndef NO_SYSTEM_INCLUDES
#include <sys/types.h>
#endif

#include "db_int.h"

/*
 * log_compare --
 *	Compare two LSN's.
 */
int
log_compare(lsn0, lsn1)
	const DB_LSN *lsn0, *lsn1;
{
	if (lsn0->file != lsn1->file)
		return (lsn0->file < lsn1->file ? -1 : 1);

	if (lsn0->offset != lsn1->offset)
		return (lsn0->offset < lsn1->offset ? -1 : 1);

	return (0);
}
