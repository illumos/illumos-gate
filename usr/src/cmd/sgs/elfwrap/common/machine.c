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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<_elfwrap.h>

#if	defined(lint)
#include	<machdep.h>
#else
#if	defined(ELFWRAP_X86)
#include	<i386/machdep_x86.h>
#if	defined(_ELF64)
#define	target_init	target_init_amd64
#else
#define	target_init	target_init_i386
#endif
#endif
#if	defined(ELFWRAP_SPARC)
#include	<sparc/machdep_sparc.h>
#if	defined(_ELF64)
#define	target_init	target_init_sparcv9
#else
#define	target_init	target_init_sparc
#endif
#endif
#endif

/*
 * Establish any target specific data.  This module is compiled using the
 * defines shown above, to provide data for each target machine elfwrap(1)
 * supports - each target module being assigned a unique interface name.
 */
void
target_init(TargDesc_t *tdp)
{
	/*
	 * ELF header information.
	 */
	tdp->td_class = M_CLASS;		/* e_ident[EI_CLASS] */
	tdp->td_data = M_DATA;			/* e_ident[EI_DATA] */
	tdp->td_mach = M_MACH;			/* e_machine */

	/*
	 * Default data buffer alignment.
	 */
	tdp->td_align = M_WORD_ALIGN;		/* d_align */

	/*
	 * Symbol table entry size.
	 */
	tdp->td_symsz = sizeof (Sym);		/* d_size */
}
