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
 * String conversion routine for relocation types.
 */
#include	<stdio.h>
#include	"_conv.h"

/*
 * Generic front-end that determines machine specific relocations.
 */
const char *
conv_reloc_type(Half mach, Word type, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	switch (mach) {
	case EM_386:
		return (conv_reloc_386_type(type, fmt_flags, inv_buf));

	case EM_SPARC:
	case EM_SPARC32PLUS:
	case EM_SPARCV9:
		return (conv_reloc_SPARC_type(type, fmt_flags, inv_buf));

	case EM_AMD64:
		return (conv_reloc_amd64_type(type, fmt_flags, inv_buf));
	}

	/* If didn't match a machine type, use integer value */
	return (conv_invalid_val(inv_buf, type, fmt_flags));
}

/*
 * This version supplies a static buffer. It is for the benefit of
 * do_reloc().
 */
const char *
conv_reloc_type_static(Half mach, Word type, Conv_fmt_flags_t fmt_flags)
{
	static Conv_inv_buf_t inv_buf;

	return (conv_reloc_type(mach, type, fmt_flags, &inv_buf));
}
