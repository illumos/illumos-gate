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

#include "arcfour.h"

#if defined(__amd64)
/*
 * Use hand-tuned, processor-specific assembly version of arcfour_crypt()
 * for 64-bit x86:
 */
#define	USE_PSR_VERSION_OF_ARCFOUR_CRYPT
#endif /* __amd64 */

/* Initialize the key stream 'key' using the key value */
void
arcfour_key_init(ARCFour_key *key, uchar_t *keyval, int keyvallen)
{
/* EXPORT DELETE START */

	uchar_t ext_keyval[256];
	uchar_t tmp;
	int i, j;

	for (i = j = 0; i < 256; i++, j++) {
		if (j == keyvallen)
			j = 0;

		ext_keyval[i] = keyval[j];
	}
	for (i = 0; i < 256; i++)
		key->arr[i] = (uchar_t)i;

	j = 0;
	for (i = 0; i < 256; i++) {
		j = (j + key->arr[i] + ext_keyval[i]) % 256;
		tmp = key->arr[i];
		key->arr[i] = key->arr[j];
		key->arr[j] = tmp;
	}
	key->i = 0;
	key->j = 0;

/* EXPORT DELETE END */
}


#if !defined(USE_PSR_VERSION_OF_ARCFOUR_CRYPT)
/*
 * Encipher 'in' using 'key'.
 * in and out can point to the same location
 */
void
arcfour_crypt(ARCFour_key *key, uchar_t *in, uchar_t *out, size_t len)
{
	size_t ii;
	uchar_t tmp, i, j;

/* EXPORT DELETE START */

	/*
	 * The sun4u has a version of arcfour_crypt_aligned() hand-tuned for
	 * the cases where the input and output  buffers are aligned on
	 * a multiple of 8-byte boundary.
	 */
#ifdef	sun4u
	int index;

	index = (((uint64_t)(uintptr_t)in) & 0x7);

	/* Get the 'in' on an 8-byte alignment */
	if (index > 0) {
		i = key->i;
		j = key->j;
		for (index = 8 - (uint64_t)(uintptr_t)in & 0x7;
		    (index-- > 0) && len > 0;
		    len--, in++, out++) {
			i = i + 1;
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
		for (ii = 0; ii < len; ii++) {
			i = i + 1;
			j = j + key->arr[i];
			tmp = key->arr[i];
			key->arr[i] = key->arr[j];
			key->arr[j] = tmp;
			tmp = key->arr[i] + key->arr[j];
			out[ii] = in[ii] ^ key->arr[tmp];
		}
		key->i = i;
		key->j = j;
#ifdef	sun4u
	} else {
		arcfour_crypt_aligned(key, len, in, out);
	}
#endif	/* sun4u */

/* EXPORT DELETE END */
}
#endif	/* !USE_PSR_VERSION_OF_ARCFOUR_CRYPT */
