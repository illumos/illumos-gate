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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This program extracts network interface parameters from the information
 * passed to the kernel from the bootstrap (i.e. as properties of /chosen).
 *
 * Returns:
 *	= 0	- success
 *	> 0	- error (see exit codes below)
 */

#include <libintl.h>
#include <locale.h>
#include <stdio.h>
#include <strings.h>
#include <parseURL.h>
#include <wanbootutil.h>
#include <bootinfo.h>

/*
 * Exit codes:
 */
#define	NETBOOTINFO_SUCCESS		0
#define	NETBOOTINFO_UNKNOWN_PARAM	1
#define	NETBOOTINFO_BOOTINFO_ERR	2
#define	NETBOOTINFO_USAGE		3

int
main(int argc, char **argv)
{
	int	i;

	/*
	 * Do the necessary magic for localization support.
	 */
	(void) setlocale(LC_ALL, "");
#if	!defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif	/* !defined(TEXT_DOMAIN) */
	(void) textdomain(TEXT_DOMAIN);

	/*
	 * Initialize program name for use by wbku_printerr().
	 */
	wbku_errinit(argv[0]);

	/*
	 * Check usage is legal.
	 */
	if (argc < 2) {
		(void) fprintf(stderr,
		    gettext("Usage: %s param [ param ... ]\n"), argv[0]);
		return (NETBOOTINFO_USAGE);
	}

	/*
	 * Initialize bootinfo.
	 */
	if (!bootinfo_init()) {
		wbku_printerr("Internal error\n");
		return (NETBOOTINFO_BOOTINFO_ERR);
	}

	/*
	 * Retrieve and print parameter value(s).
	 */
	for (i = 1; i < argc; ++i) {
		char	*name = argv[i];
		char	valbuf[URL_MAX_STRLEN];
		size_t	vallen = sizeof (valbuf);

		/*
		 * Call get_bootinfo() to fetch it's value.
		 */
		switch (bootinfo_get(name, valbuf, &vallen, NULL)) {
		case BI_E_SUCCESS:
			break;

		case BI_E_NOVAL:
			(void) strlcpy(valbuf, "none", sizeof (valbuf));
			break;

		case BI_E_ILLNAME:
			wbku_printerr("Unknown parameter %s\n", name);
			bootinfo_end();
			return (NETBOOTINFO_UNKNOWN_PARAM);

		default:
			wbku_printerr("Internal error\n");
			bootinfo_end();
			return (NETBOOTINFO_BOOTINFO_ERR);
		}
		(void) printf("%s\n", valbuf);
	}
	bootinfo_end();

	return (NETBOOTINFO_SUCCESS);
}
