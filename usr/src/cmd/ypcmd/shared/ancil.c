/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <dirent.h>
#include "../ypsym.h"
#include "../ypdefs.h"
USE_YPDBPATH
USE_DBM

bool onmaplist();
extern unsigned int strlen();
extern int strcmp();
extern int isvar_sysv();
extern char *strncpy();
extern bool ypcheck_domain_yptol();

/*
 * This checks to see whether a domain name is present at the local node as a
 * subdirectory of ypdbpath
 *
 * Calls ypcheck_domain_yptol() defined in
 * usr/src/lib/libnisdb/yptol/shim_ancil.c
 */
bool
ypcheck_domain(domain)
	char *domain;
{
	return (ypcheck_domain_yptol(domain));
}

/*
 * This returns TRUE if map is on list, and FALSE otherwise.
 */
bool
onmaplist(map, list)
	char *map;
	struct ypmaplist *list;
{
	struct ypmaplist *scan;

	for (scan = list; scan; scan = scan->ypml_next) {

		if (strcmp(map, scan->ypml_name) == 0) {
			return (TRUE);
		}
	}

	return (FALSE);
}
