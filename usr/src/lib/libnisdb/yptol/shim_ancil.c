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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef	lint
static	char sccsid[] = "%Z%%M% %I%     %E% SMI";
#endif

#include <dirent.h>
#include <strings.h>
#include "ypsym.h"
#include "ypdefs.h"
USE_YPDBPATH
USE_DBM
#include "shim.h"

/*
 * This constructs a file name from a passed domain name, a passed map name,
 * and a globally known YP data base path prefix.
 *
 * Has to be in shim because it needs the N2L prefix
 *
 * RETURNS :	TRUE = A name was successfully created
 *		FALSE = A name could not be created
 */

bool_t
ypmkfilename(domain, map, path)
	char *domain;
	char *map;
	char *path;
{
	int length;

	/* Do not allow any path as a domain name. */
	if (strchr(domain, '/') != NULL)
		return (FALSE);

	length = strlen(domain) + strlen(map) + ypdbpath_sz + 3;
	if (yptol_mode)
		length += strlen(NTOL_PREFIX) + 1;

	if ((MAXNAMLEN + 1) < length) {
		fprintf(stderr, "ypserv:  Map name string too long.\n");
		return (FALSE);
	}

	strcpy(path, ypdbpath);
	strcat(path, "/");
	strcat(path, domain);
	strcat(path, "/");

	/* If in N2L mode add N2L prefix */
	if (yptol_mode)
		strcat(path, NTOL_PREFIX);
	strcat(path, map);

	return (TRUE);
}
