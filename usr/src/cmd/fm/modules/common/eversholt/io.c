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
 *
 * io.c -- input/output routines for the eft DE
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fm/fmd_api.h>
#include "io.h"

extern fmd_hdl_t *Hdl;		/* handle in global for platform.c */

void
io_abort(const char *buf)
{
	fmd_hdl_abort(Hdl, "%s\n", buf);
}

void
io_die(const char *buf)
{
	fmd_hdl_abort(Hdl, "%s\n", buf);
}

void
io_err(const char *buf)
{
	fmd_hdl_abort(Hdl, "%s\n", buf);
}

void
io_out(const char *buf)
{
	fmd_hdl_debug(Hdl, "%s\n", buf);
}

void
io_exit(int code)
{
	fmd_hdl_abort(Hdl, "eft: exitcode %d\n", code);
}
