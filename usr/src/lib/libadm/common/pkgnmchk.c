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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1997-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"    /* SVr4.0 1.2 */
/*LINTLIBRARY*/

#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include "libadm.h"

static char	*rsvrd[] = {
	"all",
	"install",
	"new",
	NULL
};

#define	NMBRK	".*"
#define	WILD1	".*"
#define	WILD2	"*"
#define	WILD3	".name"
#define	ABI_NAMELNGTH		9
#define	NON_ABI_NAMELNGTH	32

static int abi_namelngth = 0;

static int
valname(char *pkg, int wild, int presvr4flg)
{
	int	count, i, n;
	char	*pt;

	/* wild == 1	allow wildcard specification as a name */
	if (wild && (strcmp(pkg, "all") == 0))
		return (0);

	/* check for reserved package names */
	for (i = 0; rsvrd[i]; i++) {
		n = (int)strlen(rsvrd[i]);
		if ((strncmp(pkg, rsvrd[i], n) == 0) &&
		    (!pkg[n] || strchr(NMBRK, pkg[n])))
			return (1);
	}

	/*
	 * check for valid extensions; we must do this
	 * first since we need to look for SVR3 ".name"
	 * before we validate the package abbreviation
	 */
	if (pt = strpbrk(pkg, NMBRK)) {
		if (presvr4flg && (strcmp(pt, WILD3) == 0))
			return (0); /* SVR3 packages have no validation */
		else if ((strcmp(pt, WILD1) == 0) || (strcmp(pt, WILD2) == 0)) {
			/* wildcard specification */
			if (!wild)
				return (1);
		} else {
			count = 0;
			while (*++pt) {
				count++;
				if (!isalpha((unsigned char)*pt) &&
					!isdigit((unsigned char)*pt) &&
				    !strpbrk(pt, "-+"))
					return (-1);
			}
			if (!count || (count > 4))
				return (-1);
		}
	}

	/* check for valid package name */
	count = 0;
	if (!isalnum((unsigned char)*pkg) ||
		(!presvr4flg && !isalpha((unsigned char)*pkg)))
		return (-1);
	while (*pkg && !strchr(NMBRK, *pkg)) {
		if (!isalnum((unsigned char)*pkg) && !strpbrk(pkg, "-+"))
			return (-1);
		count++, pkg++;
	}

	/* Check for ABI package name length */
	if (get_ABI_namelngth() == 1) {
		if (count > ABI_NAMELNGTH)
			return (-1);
	} else if (count > NON_ABI_NAMELNGTH)
			return (-1);

	return (0); /* pkg is valid */
}

/* presvr4flg - check for pre-svr4 package names also ? */
int
pkgnmchk(char *pkg, char *spec, int presvr4flg)
{
	/* pkg is assumed to be non-NULL upon entry */

	/*
	 * this routine reacts based on the value passed in spec:
	 * 	NULL	pkg must be valid and may be a wildcard spec
	 *	"all"	pkg must be valid and must be an instance
	 *	"x.*"	pkg must be valid and must be an instance of "x"
	 *	"x*"	pkg must be valid and must be an instance of "x"
	 */

	if (valname(pkg, ((spec == NULL) ? 1 : 0), presvr4flg))
		return (1); /* invalid or reserved name */

	if ((spec == NULL) || (strcmp(spec, "all") == 0))
		return (0);

	while (*pkg == *spec) {
		if ((strcmp(spec, WILD1) == 0) || (strcmp(spec, WILD2) == 0) ||
		(strcmp(spec, WILD3) == 0))
			break; /* wildcard spec, so stop right here */
		else if (*pkg++ == '\0')
			return (0); /* identical match */
		spec++;
	}

	if ((strcmp(spec, WILD1) == 0) || (strcmp(spec, WILD2) == 0) ||
	    (strcmp(spec, WILD3) == 0)) {
		if ((pkg[0] == '\0') || (pkg[0] == '.'))
			return (0);
	}
	if ((spec[0] == '\0') && (strcmp(pkg, WILD3) == 0))
		return (0); /* compare pkg.name to pkg */
	return (1);
}

void
set_ABI_namelngth(void)
{
	abi_namelngth = 1;
}

int
get_ABI_namelngth(void)
{
	return (abi_namelngth);
}
