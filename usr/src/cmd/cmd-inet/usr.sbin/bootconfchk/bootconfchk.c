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
 * This program parses and validates a wanboot.conf(4) file, and reports
 * any errors on standard error.
 *
 * Returns:
 *	= 0	- success
 *	> 0	- error (see exit codes below)
 */

#include <libintl.h>
#include <locale.h>
#include <stdio.h>
#include <wanbootutil.h>
#include <wanboot_conf.h>

/*
 * Exit codes:
 */
#define	BOOTCONFCHK_OK		0
#define	BOOTCONFCHK_INVALID	1
#define	BOOTCONFCHK_USAGE	2

int
main(int argc, char **argv)
{
	int		ret = BOOTCONFCHK_OK;
	char		*bootconf;
	bc_handle_t	bc_handle;

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
	if (argc != 2) {
		(void) fprintf(stderr,
		    gettext("Usage: %s bootconf_file\n"), argv[0]);
		return (BOOTCONFCHK_USAGE);
	}
	bootconf = argv[1];

	/*
	 * Parse and validate the given wanboot.conf(4) file.
	 */
	if (bootconf_init(&bc_handle, bootconf) != BC_SUCCESS) {
		wbku_printerr("Error parsing/validating %s: %s\n",
		    bootconf, bootconf_errmsg(&bc_handle));
		ret = BOOTCONFCHK_INVALID;
	}
	bootconf_end(&bc_handle);

	return (ret);
}
