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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <libintl.h>
#include <zone.h>
#include <libzonecfg.h>
#include <dlfcn.h>

#if !defined(TEXT_DOMAIN)		/* should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it wasn't */
#endif

int
main(void)
{
	char zonename[ZONENAME_MAX];
	FILE *fp;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if (getzonenamebyid(getzoneid(), zonename, sizeof (zonename)) < 0) {
		(void) fputs(gettext("could not determine zone name\n"),
		    stderr);
		return (1);
	}

	/*
	 * The use of dlopen here is a bit ugly, but it allows zonename to
	 * function properly before /usr is mounted.  On such a system, scratch
	 * zones don't exist, so no translation is necessary.
	 */
	if (dlopen("libzonecfg.so.1", RTLD_NOW | RTLD_GLOBAL) != NULL &&
	    zonecfg_is_scratch(zonename) &&
	    (fp = zonecfg_open_scratch("", B_FALSE)) != NULL) {
		(void) zonecfg_reverse_scratch(fp, zonename, zonename,
		    sizeof (zonename), NULL, 0);
		zonecfg_close_scratch(fp);
	}
	(void) puts(zonename);
	return (0);
}
