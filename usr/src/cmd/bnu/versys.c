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
 * Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "uucp.h"

extern int getsysline();
extern void sysreset();

/*
 * verify system name
 * input:
 *	name	-> system name (char name[NAMESIZE])
 * returns:  
 *	0	-> success
 *	FAIL	-> failure
 */
int
versys(name)
char *name;
{
	register char *iptr;
	char line[BUFSIZ];
	extern char *aliasFind();
	char	*prev;

	if (name == 0 || *name == 0)
		return(FAIL);

	prev = _uu_setlocale(LC_ALL, "C");
	if ((iptr = aliasFind(name)) != NULL) {
		/* overwrite the original name with the real name */
		strncpy(name, iptr, MAXBASENAME);
		name[MAXBASENAME] = '\0';
	}

	if (EQUALS(name, Myname)) {
		(void) _uu_resetlocale(LC_ALL, prev);
		return(0);
	}

	while (getsysline(line, sizeof(line))) {
		if((line[0] == '#') || (line[0] == ' ') || (line[0] == '\t') || 
			(line[0] == '\n'))
			continue;

		if ((iptr=strpbrk(line, " \t")) == NULL)
		    continue;	/* why? */
		*iptr = '\0';
		if (EQUALS(name, line)) {
			sysreset();
			(void) _uu_resetlocale(LC_ALL, prev);
			return(0);
		}
	}
	sysreset();
	(void) _uu_resetlocale(LC_ALL, prev);
	return(FAIL);
}
