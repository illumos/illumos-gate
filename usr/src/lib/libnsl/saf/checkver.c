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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define	VSTR	"# VERSION="


/*
 * check_version - check to make sure designated file is the correct version
 *		returns : 0 - version correct
 *			  1 - version incorrect
 *			  2 - could not open file
 *			  3 - corrupt file
 */


int
check_version(int ver, char *fname)
{
	FILE *fp;		/* file pointer for sactab */
	char line[BUFSIZ];	/* temp buffer for input */
	char *p;		/* working pointer */
	int version;		/* version number from sactab */

	if ((fp = fopen(fname, "rF")) == NULL)
		return (2);
	p = line;
	while (fgets(p, BUFSIZ, fp)) {
		if (strncmp(p, VSTR, strlen(VSTR)) == 0) {
			p += strlen(VSTR);
			if (*p)
				version = atoi(p);
			else
				return (3);
			(void) fclose(fp);
			return ((version != ver) ? 1 : 0);
		}
		p = line;
	}
	return (3);
}
