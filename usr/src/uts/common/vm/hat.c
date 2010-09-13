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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <sys/modctl.h>
#include <sys/kobj.h>
#include <vm/hat.h>

/*
 * PSARC 2004/405 made hat_getkpfnum(9F) obsolete. As part of the
 * obsolecense, the original documented behavior will begin to be
 * enforced in the future; namely, hat_getkpfnum(9F) may _only_
 * be called with device-mapped memory virtual addresses. Since
 * changing hat_getkpfnum(9F) to return PFN_INVALID on kernel memory
 * would break a lot of modules without any warning, we've implemented
 * the following mechanism as a stop-gap. In a future release, this
 * can all be ripped out and hat_getkpfnum(9F) changed to return
 * PFN_INVALID if it isn't called with a device-mapped memory address.
 *
 * We keep track of each module that has used hat_getkpfnum(9F)
 * incorrectly. This allows us to avoid flooding the console/logs
 * with too many warnings about a bad module that has already been
 * flagged.
 *
 * On amd64 hat_getkpfnum() is never supported.
 */

#if !defined(__amd64)

#define	HAT_STACK_MAXDEPTH	15

struct badcall_node {
	char	*bc_modname;
	int	bc_stackdepth;
	pc_t	bc_callstack[HAT_STACK_MAXDEPTH];
	struct badcall_node *bc_linkage;
};

static struct badcall_node *bad_getkpfnum_callers;

/*
 * Common VM HAT routines.
 */

static void
printwarn(struct badcall_node *bc)
{
	int sf;
	char *ksym;
	ulong_t off;

	cmn_err(CE_WARN, "Module %s is using the obsolete hat_getkpfnum(9F)",
	    bc->bc_modname);
	cmn_err(CE_CONT, "interface in a way that will not be supported in\n");
	cmn_err(CE_CONT, "a future release of Solaris. Please contact the\n");
	cmn_err(CE_CONT, "vendor that supplied the module for assistance,\n");
	cmn_err(CE_CONT, "or consult the Writing Device Drivers guide,\n");
	cmn_err(CE_CONT, "available from http://www.sun.com for migration\n");
	cmn_err(CE_CONT, "advice.\n");
	cmn_err(CE_CONT, "---\n");
	cmn_err(CE_CONT, "Callstack of bad caller:\n");

	for (sf = 0; sf < bc->bc_stackdepth; sf++) {
		ksym = kobj_getsymname(bc->bc_callstack[sf], &off);
		cmn_err(CE_CONT, "\t%s+%lx\n", ksym? ksym : "?", off);
	}
}


void
hat_getkpfnum_badcall(void *caller)
{
	struct badcall_node bcs;
	char *modname = mod_containing_pc((caddr_t)caller);
	struct badcall_node *bc;

#ifdef	__sparc
	/*
	 * This is a hack until the ifb and jfb framebuffer drivers
	 * are fixed. Right now they use hat_getkpfnum() in a way that
	 * is really safe but will be incorrectly flagged as being
	 * buggy.
	 */
	if (strcmp(modname, "ifb") == 0 || strcmp(modname, "jfb") == 0)
		return;
#elif defined(__i386)
	/*
	 * This is a hack until these ethernet drivers can be fixed
	 * or EOL'd.  hat_getkpfnum() will continue to work correctly
	 * until this list can be removed.
	 */
	if (strcmp(modname, "dnet") == 0 || strcmp(modname, "pcn") == 0 ||
	    strcmp(modname, "adp") == 0)
		return;
#endif	/* __sparc / __i386 */

	for (bc = bad_getkpfnum_callers; bc != NULL; bc = bc->bc_linkage)
		if (strcmp(bc->bc_modname, modname) == 0)
			return;

	/*
	 * We haven't seen this caller before, so create a log of
	 * the callstack and module name, and emit a warning to the
	 * user.
	 */
	bc = kmem_zalloc(sizeof (struct badcall_node), KM_NOSLEEP);
	if (bc != NULL) {
		bc->bc_linkage = bad_getkpfnum_callers;
		bc->bc_modname = modname;
		bad_getkpfnum_callers = bc;
	} else {
		bc = &bcs;
		bc->bc_modname = modname;
	}

	bc->bc_stackdepth = getpcstack(bc->bc_callstack, HAT_STACK_MAXDEPTH);

	printwarn(bc);
}
#endif /* __amd64 */
