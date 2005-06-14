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

/*
 * String conversion routine for relocation types.
 */
#include	<stdio.h>
#include	"_conv.h"

/*
 * Generic front-end that determines machine specific relocations.
 */
const char *
conv_reloc_type_str(ushort_t mach, uint_t rel)
{
	static char	string[STRSIZE] = { '\0' };

	if (mach == EM_386)
		return (conv_reloc_386_type_str(rel));

	if ((mach == EM_SPARC) || (mach == EM_SPARC32PLUS) ||
	    (mach == EM_SPARCV9))
		return (conv_reloc_SPARC_type_str(rel));

	if (mach == EM_AMD64)
		return (conv_reloc_amd64_type_str(rel));

	return (conv_invalid_str(string, STRSIZE, rel, 0));
}
