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

#define	ARCFOUR_LOOP_OPTIMIZED

#ifndef _KERNEL
#include <stdint.h>
#endif	/* _KERNEL */

#include "arcfour.h"

#if defined(__amd64)
/* ARCFour_key.flag values */
#define	ARCFOUR_ON_INTEL	1
#define	ARCFOUR_ON_AMD64	0

#ifdef _KERNEL
#include <sys/x86_archext.h>
#include <sys/cpuvar.h>

#else
#include <sys/auxv.h>
#endif	/* _KERNEL */
#endif	/* __amd64 */

#ifndef __amd64
/*
 * Initialize the key stream 'key' using the key value.
 *
 * Input:
 * keyval	User-provided key
 * keyvallen	Length, in bytes, of keyval
 * Output:
 * key		Initialized ARCFOUR key schedule, based on keyval
 */
void
arcfour_key_init(ARCFour_key *key, uchar_t *keyval, int keyvallen)
{
	uchar_t ext_keyval[256];
	uchar_t tmp;
	int i, j;

	/* Normalize key length to 256 */
	for (i = j = 0; i < 256; i++, j++) {
		if (j == keyvallen)
			j = 0;
		ext_keyval[i] = keyval[j];
	}

	for (i = 0; i < 256; i++)
		key->arr[i] = (uchar_t)i;

	j = 0;
	for (i = 0; i < 256; i++) {
		j = (j + key->arr[i] + ext_keyval[i]) & 0xff;
		tmp = key->arr[i];
		key->arr[i] = key->arr[j];
		key->arr[j] = tmp;
	}
	key->i = 0;
	key->j = 0;
}
#endif	/* !__amd64 */


/*
 * Encipher 'in' using 'key'.
 *
 * Input:
 * key		ARCFOUR key, initialized by arcfour_key_init()
 * in		Input text
 * out		Buffer to contain output text
 * len		Length, in bytes, of the in and out buffers
 *
 * Output:
 * out		Buffer containing output text
 *
 * Note: in and out can point to the same location
 */
void
arcfour_crypt(ARCFour_key *key, uchar_t *in, uchar_t *out, size_t len)
{
#ifdef	__amd64
	if (key->flag == ARCFOUR_ON_AMD64) {
		arcfour_crypt_asm(key, in, out, len);
	} else { /* Intel EM64T */
#endif	/* amd64 */

	size_t		ii;
	uchar_t		i, j, ti, tj;
#ifdef ARCFOUR_LOOP_OPTIMIZED
	uchar_t		arr_ij;
#endif
#ifdef __amd64
	uint32_t	*arr;
#else
	uchar_t		*arr;
#endif

#ifdef	sun4u
	/*
	 * The sun4u has a version of arcfour_crypt_aligned() hand-tuned for
	 * the cases where the input and output buffers are aligned on
	 * a multiple of 8-byte boundary.
	 */
	int		index;
	uchar_t		tmp;

	index = (((uint64_t)(uintptr_t)in) & 0x7);

	/* Get the 'in' on an 8-byte alignment */
	if (index > 0) {
		i = key->i;
		j = key->j;
		for (index = 8 - (uint64_t)(uintptr_t)in & 0x7;
		    (index-- > 0) && len > 0;
		    len--, in++, out++) {
			++i;
			j = j + key->arr[i];
			tmp = key->arr[i];
			key->arr[i] = key->arr[j];
			key->arr[j] = tmp;
			tmp = key->arr[i] + key->arr[j];
			*out = *in ^ key->arr[tmp];
		}
		key->i = i;
		key->j = j;
	}

	if (len == 0)
		return;

	/* See if we're fortunate and 'out' got aligned as well */

	if ((((uint64_t)(uintptr_t)out) & 7) != 0) {
#endif	/* sun4u */

	i = key->i;
	j = key->j;
	arr = key->arr;

#ifndef ARCFOUR_LOOP_OPTIMIZED
	/*
	 * This loop is hasn't been reordered, but is kept for reference
	 * purposes as it's more readable
	 */
	for (ii = 0; ii < len; ++ii) {
		++i;
		ti = arr[i];
		j = j + ti;
		tj = arr[j];
		arr[j] = ti;
		arr[i] = tj;
		out[ii] = in[ii] ^ arr[(ti + tj) & 0xff];
	}

#else
	/*
	 * This for loop is optimized by carefully spreading out
	 * memory access and storage to avoid conflicts,
	 * allowing the processor to process operations in parallel
	 */

	/* for loop setup */
	++i;
	ti = arr[i];
	j = j + ti;
	tj = arr[j];
	arr[j] = ti;
	arr[i] = tj;
	arr_ij = arr[(ti + tj) & 0xff];
	--len;

	for (ii = 0; ii < len; ) {
		++i;
		ti = arr[i];
		j = j + ti;
		tj = arr[j];
		arr[j] = ti;
		arr[i] = tj;

		/* save result from previous loop: */
		out[ii] = in[ii] ^ arr_ij;

		++ii;
		arr_ij = arr[(ti + tj) & 0xff];
	}
	/* save result from last loop: */
	out[ii] = in[ii] ^ arr_ij;
#endif

	key->i = i;
	key->j = j;

#ifdef	sun4u
	} else {
		arcfour_crypt_aligned(key, len, in, out);
	}
#endif	/* sun4u */
#ifdef	__amd64
	}
#endif	/* amd64 */
}


#ifdef	__amd64
/*
 * Return 1 if executing on Intel, otherwise 0 (e.g., AMD64).
 * Cache the result, as the CPU can't change.
 *
 * Note: the userland version uses getisax() and checks for an AMD-64-only
 * feature.  The kernel version uses cpuid_getvendor().
 */
int
arcfour_crypt_on_intel(void)
{
	static int	cached_result = -1;

	if (cached_result == -1) { /* first time */
#ifdef _KERNEL
		cached_result = (cpuid_getvendor(CPU) == X86_VENDOR_Intel);
#else
		uint_t	ui;

		(void) getisax(&ui, 1);
		cached_result = ((ui & AV_386_AMD_MMX) == 0);
#endif	/* _KERNEL */
	}

	return (cached_result);
}
#endif	/* __amd64 */
