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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This module supports callbacks from the firmware
 * such that address and name lookups can work and use kernel symbol names.
 * For example "ctrace" will provide symbolic names, if they are available.
 * Also, normal firmware name to address lookups should work, though be
 * careful with clashing kernel names, such as "startup" and "reset" which
 * may be the firmware names and *not* the kernel names.
 *
 * The module locks the symbol tables in memory, when it's installed,
 * and unlocks them when it is removed.  The module is loaded automatically
 * on cobp systems and is replaced by forthdebug on all other systems.
 *
 * This file contains the actual code the does the lookups, and interfaces
 * with the kernel kobj stuff.  The transfer of data and control to/from
 * the firmware is handled in prom-dependent code.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/modctl.h>
#include <sys/kobj.h>
#include <sys/promif.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/reboot.h>
#include <sys/callb.h>

int obpsym_debug = 0;
#define	DPRINTF(str)		if (obpsym_debug) prom_printf(str)
#define	DPRINTF1(str, a)	if (obpsym_debug) prom_printf(str, a);
#define	DPRINTF2(str, a, b)	if (obpsym_debug) prom_printf(str, a, b);
#define	DXPRINTF		if (obpsym_debug > 1) prom_printf

int obpheld = 1;		/* Prevents unloading when set */

/*
 * name_to_value - translate a string into an address
 *
 * The string may be one of two forms - 'symname' or 'modname:symname'.
 * (We also accept 'unix:symname' as a synonymn for 'symname'.)
 * The latter form causes a kobj_lookup() to occur only in the given module,
 * the former causes a kobj_getsymvalue() on the entire kernel symbol table.
 *
 * mod_lock locking is not needed for the &modules list because
 * modctl structures are never unlinked from the &modules list.
 */
int
name_to_value(char *name, uintptr_t *value)
{
	register char *symname = name;
	register char *modname = "";
	char *p;
	int retval = 0;
	uintptr_t symvalue = 0;
	char c = (char)0;

	/*
	 * we take names of the form: "modname:symbol", "unix:symbol", "symbol"
	 */
	if ((p = strchr(name, ':')) != NULL && p[1] != (char)0) {
		symname = p + 1;
		modname = name;
		c = *p;
		*p = (char)0;
	}

	if (*modname == (char)0) {
		symvalue = kobj_getsymvalue(symname, 0);
	} else  {
		struct modctl *mp = &modules;

		do {
			if (strcmp(modname, mp->mod_modname) == 0) {
				symvalue = kobj_lookup(mp->mod_mp, symname);
				break;
			}
		} while ((mp = mp->mod_next) != &modules);
	}

	if (symvalue == 0)
		retval = -1;
	if (c != (char)0)		/* Restore incoming cstr */
		*p = c;

	*value = symvalue;
	return (retval);
}

/*
 * value_to_name - translate an address into a string + offset
 *
 * mod_lock locking is not needed fro the modules list because
 * modctl structures are never unlinked from the &modules list.
 */
ulong_t
value_to_name(uintptr_t value, char *symbol)
{
	struct modctl *modp = &modules;
	ulong_t offset;
	char *name;

	DPRINTF1("value_to_name: Looking for %p\n", (void *)value);

	do {
		if (modp->mod_mp &&
		    (name = kobj_searchsym(modp->mod_mp, value, &offset))) {
			(void) strcpy(symbol, modp->mod_modname);
			(void) strcat(symbol, ":");
			(void) strcat(symbol, name);
			return (offset);
		}
	} while ((modp = modp->mod_next) != &modules);

	*symbol = (char)0;
	return ((ulong_t)-1l);
}

/*
 * loadable module wrapper
 */
static struct modlmisc modlmisc = {
	&mod_miscops, "OBP symbol callbacks %I%"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

/*ARGSUSED*/
static boolean_t
reset_callbacks(void *arg, int code)
{
	extern void set_sym_callbacks();

	if (code == CB_CODE_CPR_RESUME)
		set_sym_callbacks();
	return (B_TRUE);
}

int
_init(void)
{
	int retval;
	extern int install_callbacks(void);
	extern void remove_callbacks(void);

	if (install_callbacks() != 0)
		return (ENXIO);

	if (boothowto & RB_HALT)
		debug_enter("obpsym: halt flag (-h) is set.\n");

	retval = mod_install(&modlinkage);

	/*
	 * if load fails remove callback and unlock symbols
	 */
	if (retval) {
		printf("obpsym: Error %d installing OBP syms module\n", retval);
		remove_callbacks();
	}
	else
		(void) callb_add(reset_callbacks, 0, CB_CL_CPR_OBP, "obpsym");

	return (retval);
}

int
_fini(void)
{
	int retval;
	extern void remove_callbacks(void);

	if (obpheld != 0)
		return (EBUSY);

	retval = mod_remove(&modlinkage);

	/*
	 * if unload succeeds remove callback and unlock symbols
	 */
	if (retval == 0) {
		remove_callbacks();
	}
	return (retval);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
