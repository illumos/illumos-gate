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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file contains bignum implementation code that
 * is specific to AMD64, but which is still more appropriate
 * to write in C, rather than assembly language.
 * bignum_amd64_asm.s does all the assembly language code
 * for AMD64 specific bignum support.  The assembly language
 * source file has pure code, no data.  Let the C compiler
 * generate what is needed to handle the variations in
 * data representation and addressing, for example,
 * statically linked vs PIC.
 */

#include "bignum.h"

/*
 * The bignum interface deals with arrays of 64-bit "chunks" or "digits".
 * Data should be aligned on 8-byte address boundaries for best performance.
 */


void
big_mul_vec(BIG_CHUNK_TYPE *r, BIG_CHUNK_TYPE *a, int alen,
    BIG_CHUNK_TYPE *b, int blen)
{
	int	i;

	r[alen] = big_mul_set_vec(r, a, alen, b[0]);
	for (i = 1; i < blen; ++i)
		r[alen + i] = big_mul_add_vec(r + i, a, alen, b[i]);
}
