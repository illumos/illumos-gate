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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<debug.h>
#include	"_libld.h"


/*
 * This file contains stub routines since currently register symbols
 * are not relevant to the i386 architecture.  But - having these
 * stub routines avoids #ifdefs in common codes - and I hate that.
 */
/* ARGSUSED */
int
ld_reg_check(Sym_desc *sdp, Sym *nsym, const char *nname, Ifl_desc *ifl,
    Ofl_desc * ofl)
{
	return (1);
}

/* ARGSUSED */
int
ld_mach_sym_typecheck(Sym_desc *sdp, Sym *nsym, Ifl_desc *ifl, Ofl_desc *ofl)
{
	return (0);
}

/* ARGSUSED */
const char *
ld_is_regsym(Ofl_desc *ofl, Ifl_desc *ifl, Sym *sym, const char *strs,
    int symndx, Word shndx, const char *symsecname, Word * flags)
{
	return (0);
}

/* ARGSUSED */
Sym_desc *
ld_reg_find(Sym * sym, Ofl_desc * ofl)
{
	return (0);
}

/* ARGSUSED */
int
ld_reg_enter(Sym_desc * sdp, Ofl_desc * ofl)
{
	return (0);
}
