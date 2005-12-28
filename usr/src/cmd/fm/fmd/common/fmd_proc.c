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

/*
 * External Module Support
 *
 * The Fault Manager is designed to support external modules running as other
 * processes but using the same set of APIs.  These support routines are a
 * placeholder for when that feature set is added to fmd in the near future.
 */

#include <fmd_module.h>
#include <fmd_error.h>
#include <fmd_event.h>

/*ARGSUSED*/
static int
proc_init(fmd_module_t *mp)
{
	return (fmd_set_errno(ENOTSUP));
}

/*ARGSUSED*/
static int
proc_fini(fmd_module_t *mp)
{
	return (fmd_set_errno(ENOTSUP));
}

const fmd_modops_t fmd_proc_ops = {
	proc_init,
	proc_fini,
	fmd_module_dispatch,
	fmd_module_transport,
};
