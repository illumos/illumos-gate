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
 * Copyright (c) 1991-1995, 1996, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This module provides kernel callbacks to IEEE 1275-1994 system.
 * such that address and name lookups can work and use kernel symbol names.
 * For example "ctrace" will provide symbolic names, if they are available.
 * Also, normal firmware name to address lookups should work, though be
 * careful with clashing kernel names, such as "startup" and "reset" which
 * may be the firmware names and *not* the kernel names.
 *
 * This file contains the glue that gets control from the firmware and
 * transfers data from/to the firmware.
 *
 * The platform code needs to provide the routines add_vx_handler
 * and remove_vx_handler, which add/remove an Open Firmware callback
 * handler for a given callback name.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/modctl.h>
#include <sys/kobj.h>
#include <sys/promif.h>
#include <sys/prom_isa.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/reboot.h>
#include <rpc/types.h>
#include <rpc/xdr.h>

#define	DPRINTF(str)		if (obpsym_debug) prom_printf(str)
#define	DPRINTF1(str, a)	if (obpsym_debug) prom_printf(str, a);
#define	DPRINTF2(str, a, b)	if (obpsym_debug) prom_printf(str, a, b);
#define	DXPRINTF		if (obpsym_debug > 1) prom_printf

#define	MAX_NAME	128


static void
ieee_sym_to_value(cell_t *cif)
{
	int	error = -1;
	uintptr_t symvalue = 0;
	unsigned int nargs, nresults;
	char	*symname;
	extern	int name_to_value(char *name, uintptr_t *value);

	nargs = p1275_cell2uint(cif[1]);
	nresults = p1275_cell2uint(cif[2]);

	if (nresults == 0)
		return;		/* No room for results. Just return. */

	/*
	 * If there are no arguments, fall through and return an error.
	 * Otherwise, try to translate the symbol name arg to a value.
	 */
	if (nargs != 0) {
		symname = p1275_cell2ptr(cif[3]);	/* argument 0 */
		error = name_to_value(symname, &symvalue);
	}

	/*
	 * Stuff the results in the argument array and set the
	 * nresults element to the number of results actually returned
	 * in the argument array. (It's a maximum of 2).
	 *
	 * cif[0]:	service name	( Pointer to service name )
	 * cif[1]:	nargs		( number of argument cells)
	 * cif[2]:	nresults	( number of result cells)
	 * cif[3]:	argument{0}	( First argument cell )
	 * ...
	 * cif[3 + nargs]: result{0}	( First result cell )
	 * ...
	 */

	cif[3 + nargs] = p1275_int2cell(error);
	if (nresults > 1) {
		cif[3 + nargs + 1] = p1275_uintptr2cell(symvalue);
		cif[2] = p1275_int2cell(2);	/* there are 2 results */
	} else {
		cif[2] = p1275_int2cell(1);	/* there is 1 result */
	}
}

static char symbol[MAX_NAME];

static void
ieee_value_to_sym(cell_t *cif)
{
	u_int	nargs, nresults;
	u_long	value;
	u_int	offset;
	char	*name = symbol;
	extern u_long value_to_name(uintptr_t value, char *symbol);

	nargs = p1275_cell2uint(cif[1]);
	nresults = p1275_cell2uint(cif[2]);

	if (nresults == 0)
		return;		/* No room for results. Just return. */

	/*
	 * If there are no arguments, fall through and return "not found".
	 * Otherwise, try to translate the value to a symbol-name/offset.
	 */
	*name = (char)0;
	offset = (u_int)-1;
	if (nargs != 0) {
		value = p1275_cell2uintptr(cif[3]); /* argument 0 */
		offset = value_to_name(value, name);
	}

	/*
	 * Stuff the results in the argument array and set the
	 * nresults element to the number of results actually returned
	 * in the argument array. (It's a maximum of 2).
	 *
	 * cif[0]:	service name	( Pointer to service name )
	 * cif[1]:	nargs		( number of argument cells)
	 * cif[2]:	nresults	( number of result cells)
	 * cif[3]:	argument{0}	( First argument cell )
	 * ...
	 * cif[3 + nargs]: result{0}	( First result cell )
	 * ...
	 */

	/*
	 * Treat this as an integer, so we sign-extend -1, offsets
	 * are always postive, -1 indicates not found.
	 */
	cif[3 + nargs] = p1275_int2cell((int)offset);

	if (nresults > 1) {
		cif[3 + nargs + 1] = p1275_ptr2cell(name);
		cif[2] = p1275_int2cell(2);	/* there are 2 results */
	} else {
		cif[2] = p1275_int2cell(1);	/* there is 1 result */
	}
}

void
set_sym_callbacks()
{
	extern int callback_handler(cell_t *arg_array);

	/*
	 * This code assumes a wrapper for the callbacks,
	 * though not all implementations will need them,
	 * they should be easy enough to provide. It might
	 * be better to provide these as 2 macros set by each
	 * platform, this assumes there's a single handler.
	 */
	(void) prom_set_symbol_lookup((void *)callback_handler,
	    (void *)callback_handler);
}

int
install_callbacks(void)
{
	void add_vx_handler(char *, int, void (*f)(cell_t *));

	add_vx_handler("sym-to-value", 0, ieee_sym_to_value);
	add_vx_handler("value-to-sym", 0, ieee_value_to_sym);
	set_sym_callbacks();

	return (0);
}

void
remove_callbacks(void)
{
	void remove_vx_handler(char *);

	(void) prom_set_symbol_lookup((void *)0, (void *)0);

	remove_vx_handler("sym-to-value");
	remove_vx_handler("value-to-sym");
}
