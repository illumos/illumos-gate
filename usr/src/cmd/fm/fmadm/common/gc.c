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

/*ARGSUSED*/
int
cmd_gc(fmd_adm_t *adm, int argc, char *argv[])
{
	const char *mod;

	if (argc != 2)
		return (FMADM_EXIT_USAGE);

	if ((mod = strrchr(argv[1], '/')) == NULL)
		mod = argv[1];
	else
		mod++;

	if (fmd_adm_module_gc(adm, mod) != 0)
		die("failed to garbage-collect module %s", mod);
	note("%s module has been garbage-collected\n", mod);

	return (FMADM_EXIT_SUCCESS);
}
