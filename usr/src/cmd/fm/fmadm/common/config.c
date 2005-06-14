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

#include <fmadm.h>

/*ARGSUSED*/
static int
config_modinfo(const fmd_adm_modinfo_t *ami, void *unused)
{
	const char *state;

	if (ami->ami_flags & FMD_ADM_MOD_FAILED)
		state = "failed";
	else
		state = "active";

	(void) printf("%-24s %-7s %-6s  %s\n",
	    ami->ami_name, ami->ami_vers, state, ami->ami_desc);

	return (0);
}

/*ARGSUSED*/
int
cmd_config(fmd_adm_t *adm, int argc, char *argv[])
{
	if (argc != 1)
		return (FMADM_EXIT_USAGE);

	(void) printf("%-24s %-7s %-6s  %s\n",
	    "MODULE", "VERSION", "STATUS", "DESCRIPTION");

	if (fmd_adm_module_iter(adm, config_modinfo, NULL) != 0)
		die("failed to retrieve configuration");

	return (FMADM_EXIT_SUCCESS);
}

int
cmd_rotate(fmd_adm_t *adm, int argc, char *argv[])
{
	if (argc != 2)
		return (FMADM_EXIT_USAGE);

	if (fmd_adm_log_rotate(adm, argv[1]) != 0)
		die("failed to rotate %s", argv[1]);

	note("%s has been rotated out and can now be archived\n", argv[1]);
	return (FMADM_EXIT_SUCCESS);
}
