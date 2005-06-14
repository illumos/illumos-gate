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

#include "misc.h"

#define	UMEM_OBJNAME "libumem.so"

int umem_debug_level = 0;
int umem_is_standalone = 0;

/*ARGSUSED*/
int
umem_debug(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	umem_debug_level ^= 1;

	mdb_printf("umem: debugging is now %s\n",
	    umem_debug_level ? "on" : "off");

	return (DCMD_OK);
}

void
umem_set_standalone(void)
{
	umem_is_standalone = 1;
}

ssize_t
umem_lookup_by_name(const char *name, GElf_Sym *sym)
{
	return (mdb_lookup_by_obj((umem_is_standalone ? MDB_OBJ_EXEC :
	    UMEM_OBJNAME), name, sym));
}

/* This is like mdb_readvar, only for libumem.so's symbols */
ssize_t
umem_readvar(void *buf, const char *name)
{
	GElf_Sym sym;

	if (umem_lookup_by_name(name, &sym))
		return (-1);

	if (mdb_vread(buf, sym.st_size, (uintptr_t)sym.st_value)
	    == sym.st_size)
		return ((ssize_t)sym.st_size);

	return (-1);
}

int
is_umem_sym(const char *sym, const char *prefix)
{
	char *tick_p = strrchr(sym, '`');

	return (strncmp(sym, "libumem", 7) == 0 && tick_p != NULL &&
		strncmp(tick_p + 1, prefix, strlen(prefix)) == 0);
}
