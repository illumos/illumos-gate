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
cmd_load(fmd_adm_t *adm, int argc, char *argv[])
{
	if (argc != 2)
		return (FMADM_EXIT_USAGE);

	if (argv[1][0] != '/')
		die("module name must be specified using absolute path\n");

	if (fmd_adm_module_load(adm, argv[1]) != 0)
		die("failed to load %s", argv[1]);

	note("module '%s' loaded into fault manager\n", argv[1]);
	return (FMADM_EXIT_SUCCESS);
}

int
cmd_unload(fmd_adm_t *adm, int argc, char *argv[])
{
	if (argc != 2)
		return (FMADM_EXIT_USAGE);

	if (strchr(argv[1], '/') != NULL)
		die("module must be specified using basename only\n");

	if (fmd_adm_module_unload(adm, argv[1]) != 0)
		die("failed to unload %s", argv[1]);

	note("module '%s' unloaded from fault manager\n", argv[1]);
	return (FMADM_EXIT_SUCCESS);
}
