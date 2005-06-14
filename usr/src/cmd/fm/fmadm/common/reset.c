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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <strings.h>
#include <fmadm.h>

int
cmd_reset(fmd_adm_t *adm, int argc, char *argv[])
{
	const char *opt_s = NULL;
	const char *mod;
	int c;

	while ((c = getopt(argc, argv, "s:")) != EOF) {
		switch (c) {
		case 's':
			opt_s = optarg;
			break;
		default:
			return (FMADM_EXIT_USAGE);
		}
	}

	if (argc - optind != 1)
		return (FMADM_EXIT_USAGE);

	if ((mod = strrchr(argv[optind], '/')) == NULL)
		mod = argv[optind];
	else
		mod++;

	if (opt_s != NULL) {
		if (fmd_adm_serd_reset(adm, mod, opt_s) != 0)
			die("failed to reset serd engine %s", opt_s);
		note("%s serd engine '%s' has been reset\n", mod, opt_s);
	} else {
		if (fmd_adm_module_reset(adm, mod) != 0)
			die("failed to reset module %s", mod);
		note("%s module has been reset\n", mod);
	}

	return (FMADM_EXIT_SUCCESS);
}
