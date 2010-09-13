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

/*
 * Most of the source files in libld.so are not allowed to
 * include the machdep.h header, because it supplies machine
 * values that are specific to the platform running the linker,
 * instead of the target machine. This module is used to provide
 * information about the currently running host to the rest
 * of the linker code.
 */

#include	<stdio.h>
#include	<stdarg.h>
#include	<_libld.h>
#include	<machdep.h>

/*
 * Return an ELF machine code that reflects the currently executing
 * linker. This information can be used in cross link situations to
 * know which platform the linker was running on, and whether the linker
 * itself was a 32 or 64-bit program.
 */
Half
ld_sunw_ldmach(void)
{
#ifdef _LP64
	return (M_MACH_64);
#else
	return (M_MACH_32);
#endif
}
