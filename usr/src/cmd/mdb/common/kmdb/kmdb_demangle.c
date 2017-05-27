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
 * Copyright 2017 Jason King.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_demangle.h>
#include <mdb/mdb_err.h>

/*ARGSUSED*/
mdb_demangler_t *
mdb_dem_load(void)
{
	(void) set_errno(ENOTSUP);
	return (NULL);
}

void
mdb_dem_unload(mdb_demangler_t *dmp)
{
	if (dmp != NULL)
		fail("attempted to unload demangler %p\n", (void *)dmp);
}

/*ARGSUSED*/
const char *
mdb_dem_convert(mdb_demangler_t *dmp, const char *name)
{
	return (name);
}

/*ARGSUSED*/
int
cmd_demangle(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_warn("C++ symbol demangling not available\n");
	return (DCMD_ERR);
}

/*ARGSUSED*/
int
cmd_demflags(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_warn("C++ demangling facility is currently disabled\n");
	return (DCMD_ERR);
}

/*ARGSUSED*/
int
cmd_demstr(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_warn("C++ symbol demangling not available\n");
	return (DCMD_ERR);
}
