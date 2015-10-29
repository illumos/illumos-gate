/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "misc.h"

#define	UMEM_OBJNAME "libumem.so.1"

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

/*
 * To further confuse the issue, this dmod can run against either
 * libumem.so.1 *or* the libstandumem.so linked into kmdb(1M).  To figure
 * out which one we are working against, we look up "umem_alloc" in both
 * libumem.so and the executable.
 *
 * A further wrinkle is that libumem.so may not yet be loaded into the
 * process' address space.  That can lead to either the lookup failing, or
 * being unable to read from the data segment.  We treat either case as
 * an error.
 */
int
umem_set_standalone(void)
{
	GElf_Sym sym;
	int ready;

	if (mdb_lookup_by_obj(UMEM_OBJNAME, "umem_alloc", &sym) == 0)
		umem_is_standalone = 0;
	else if (mdb_lookup_by_obj(MDB_OBJ_EXEC, "umem_alloc", &sym) == 0)
		umem_is_standalone = 1;
	else
		return (-1);

	/*
	 * now that we know where things should be, make sure we can actually
	 * read things out.
	 */
	if (umem_readvar(&ready, "umem_ready") == -1)
		return (-1);
	return (0);
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
