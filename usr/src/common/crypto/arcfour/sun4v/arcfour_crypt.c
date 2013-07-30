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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include "../arcfour.h"

/* Initialize the key stream 'key' using the key value */
void
arcfour_key_init(ARCFour_key *key, uchar_t *keyval, int keyvallen)
{
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
}


/*
 * Encipher 'in' using 'key.
 * in and out can point to the same location
 */
void
arcfour_crypt(ARCFour_key *key, uchar_t *in, uchar_t *out, size_t len)
{
	size_t ii;
	unsigned long long in0, merge = 0, merge0 = 0, merge1, mask = 0;
	uchar_t i, j, *base, jj, *base1, tmp;
	unsigned int tmp0, tmp1, i_accum, shift = 0, i1;

	int index;

	base = key->arr;

	index = (((uintptr_t)in) & 0x7);

	/* Get the 'in' on an 8-byte alignment */
	if (index > 0) {
		i = key->i;
		j = key->j;

		for (index = 8 - index; (index-- > 0) && len > 0;
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


	/*
	 * Niagara optimized version for
	 * the cases where the input and output  buffers are aligned on
	 * a multiple of 8-byte boundary.
	 */
#ifdef	sun4v
	if ((((uintptr_t)out) & 7) != 0) {
#endif	/* sun4v */
		i = key->i;
		j = key->j;
		for (ii = 0; ii < len; ii++) {
			i = i + 1;
			tmp0 = base[i];
			j = j + tmp0;
			tmp1 = base[j];
			base[i] = (uchar_t)tmp1;
			base[j] = (uchar_t)tmp0;
			tmp0 += tmp1;
			tmp0 = tmp0 & 0xff;
			out[ii] = in[ii] ^ base[tmp0];
		}
		key->i = i;
		key->j = j;
#ifdef	sun4v
	} else {
		i = key->i;
		j = key->j;

		/*
		 * Want to align base[i] on a 2B boundary -- allows updates
		 * via [i] to be performed in 2B chunks (reducing # of stores).
		 * Requires appropriate alias detection.
		 */

		if (((i+1) % 2) != 0) {
			i = i + 1;
			tmp0 = base[i];
			j = j + tmp0;
			tmp1 = base[j];

			base[i] = (uchar_t)tmp1;
			base[j] = (uchar_t)tmp0;

			tmp0 += tmp1;
			tmp0 = tmp0 & 0xff;

			merge0 = (unsigned long long)(base[tmp0]) << 56;
			shift = 8; mask = 0xff;
		}

		/*
		 * Note - in and out may now be misaligned -
		 * as updating [out] in 8B chunks need to handle this
		 * possibility. Also could have a 1B overrun.
		 * Need to drop out of loop early as a result.
		 */

		for (ii = 0, i1 = i; ii < ((len-1)  & (~7));
		    ii += 8, i1 = i1&0xff) {

			/*
			 * If i < less than 248, know wont wrap around
			 * (i % 256), so don't need to bother with masking i
			 * after each increment
			 */
			if (i1 < 248) {

				/* BYTE 0 */
				i1 = (i1 + 1);

				/*
				 * Creating this base pointer reduces subsequent
				 * arihmetic ops required to load [i]
				 *
				 * N.B. don't need to check if [j] aliases.
				 * [i] and [j] end up with the same values
				 * anyway.
				 */
				base1 = &base[i1];

				tmp0 = base1[0];
				j = j + tmp0;

				tmp1 = base[j];
				/*
				 * Don't store [i] yet
				 */
				i_accum = tmp1;
				base[j] = (uchar_t)tmp0;

				tmp0 += tmp1;
				tmp0 = tmp0 & 0xff;

				/*
				 * Check [tmp0] doesn't alias with [i]
				 */

				/*
				 * Updating [out] in 8B chunks
				 */
				if (i1 == tmp0) {
					merge =
					    (unsigned long long)(i_accum) << 56;
				} else {
					merge =
					    (unsigned long long)(base[tmp0]) <<
					    56;
				}

				/* BYTE 1 */
				tmp0 = base1[1];

				j = j + tmp0;

				/*
				 * [j] can now alias with [i] and [i-1]
				 * If alias abort speculation
				 */
				if ((i1 ^ j) < 2) {
					base1[0] = (uchar_t)i_accum;

					tmp1 = base[j];

					base1[1] = (uchar_t)tmp1;
					base[j] = (uchar_t)tmp0;

					tmp0 += tmp1;
					tmp0 = tmp0 & 0xff;

					merge |= (unsigned long long)
					    (base[tmp0]) << 48;
				} else {

					tmp1 = base[j];

					i_accum = i_accum << 8;
					i_accum |= tmp1;

					base[j] = (uchar_t)tmp0;

					tmp0 += tmp1;
					tmp0 = tmp0 & 0xff;

					/*
					 * Speculation suceeded! Update [i]
					 * in 2B chunk
					 */
					/* LINTED E_BAD_PTR_CAST_ALIGN */
					*((unsigned short *) &base[i1]) =
					    i_accum;

					merge |=
					    (unsigned long long)(base[tmp0]) <<
					    48;
				}


				/*
				 * Too expensive to perform [i] speculation for
				 * every byte. Just need to reduce frequency
				 * of stores until store buffer full stalls
				 * are not the bottleneck.
				 */

				/* BYTE 2 */
				tmp0 = base1[2];
				j = j + tmp0;
				tmp1 = base[j];
				base1[2] = (uchar_t)tmp1;
				base[j] = (uchar_t)tmp0;
				tmp1 += tmp0;
				tmp1 = tmp1 & 0xff;
				merge |= (unsigned long long)(base[tmp1]) << 40;

				/* BYTE 3 */
				tmp0 = base1[3];
				j = j + tmp0;
				tmp1 = base[j];
				base1[3] = (uchar_t)tmp1;
				base[j] = (uchar_t)tmp0;
				tmp0 += tmp1;
				tmp0 = tmp0 & 0xff;
				merge |= (unsigned long long)(base[tmp0]) << 32;

				/* BYTE 4 */
				tmp0 = base1[4];
				j = j + tmp0;
				tmp1 = base[j];
				base1[4] = (uchar_t)tmp1;
				base[j] = (uchar_t)tmp0;
				tmp0 += tmp1;
				tmp0 = tmp0 & 0xff;
				merge |= (unsigned long long)(base[tmp0]) << 24;

				/* BYTE 5 */
				tmp0 = base1[5];
				j = j + tmp0;
				tmp1 = base[j];
				base1[5] = (uchar_t)tmp1;
				base[j] = (uchar_t)tmp0;
				tmp0 += tmp1;
				tmp0 = tmp0 & 0xff;
				merge |= (unsigned long long)(base[tmp0]) << 16;

				/* BYTE 6 */
				i1 = (i1+6);
				tmp0 = base1[6];
				j = j + tmp0;
				tmp1 = base[j];
				i_accum = tmp1;
				base[j] = (uchar_t)tmp0;

				tmp0 += tmp1;
				tmp0 = tmp0 & 0xff;

				if (i1 == tmp0) {
					merge |=
					    (unsigned long long)(i_accum) << 8;
				} else {
					merge |=
					    (unsigned long long)(base[tmp0]) <<
					    8;
				}

				/* BYTE 7 */
				tmp0 = base1[7];

				/*
				 * Perform [i] speculation again. Indentical
				 * to that performed for BYTE0 and BYTE1.
				 */
				j = j + tmp0;
				if ((i1 ^ j) < 2) {
					base1[6] = (uchar_t)i_accum;
					tmp1 = base[j];

					base1[7] = (uchar_t)tmp1;
					base[j] = (uchar_t)tmp0;

					tmp0 += tmp1;
					tmp0 = tmp0 & 0xff;

					merge |=
					    (unsigned long long)(base[tmp0]);

				} else {
					tmp1 = base[j];

					i_accum = i_accum << 8;
					i_accum |= tmp1;

					base[j] = (uchar_t)tmp0;

					tmp0 += tmp1;
					tmp0 = tmp0 & 0xff;

					/* LINTED E_BAD_PTR_CAST_ALIGN */
					*((unsigned short *) &base[i1]) =
					    i_accum;

					merge |=
					    (unsigned long long)(base[tmp0]);
				}
				i1++;
			} else {
				/*
				 * i is too close to wrap-around to allow
				 * masking to be disregarded
				 */

				/*
				 * Same old speculation for BYTE 0 and BYTE 1
				 */

				/* BYTE 0 */
				i1 = (i1 + 1) & 0xff;
				jj = (uchar_t)i1;

				tmp0 = base[i1];
				j = j + tmp0;

				tmp1 = base[j];
				i_accum = tmp1;
				base[j] = (uchar_t)tmp0;

				tmp0 += tmp1;
				tmp0 = tmp0 & 0xff;

				if (i1 == tmp0) {
					merge =
					    (unsigned long long)(i_accum) << 56;
				} else {
					merge =
					    (unsigned long long)(base[tmp0]) <<
					    56;
				}

				/* BYTE 1 */
				tmp0 = base[i1+1];

				j = j + tmp0;

				if ((jj ^ j) < 2) {
					base[jj] = (uchar_t)i_accum;

					tmp1 = base[j];

					base[i1+1] = (uchar_t)tmp1;
					base[j] = (uchar_t)tmp0;

					tmp0 += tmp1;
					tmp0 = tmp0 & 0xff;

					merge |=
					    (unsigned long long)(base[tmp0]) <<
					    48;
				} else {

					tmp1 = base[j];

					i_accum = i_accum << 8;
					i_accum |= tmp1;

					base[j] = (uchar_t)tmp0;

					tmp0 += tmp1;
					tmp0 = tmp0 & 0xff;

					/* LINTED E_BAD_PTR_CAST_ALIGN */
					*((unsigned short *) &base[jj]) =
					    i_accum;

					merge |=
					    (unsigned long long)(base[tmp0]) <<
					    48;
				}

				/* BYTE 2 */
				/*
				 * As know i must be even when enter loop (to
				 * satisfy alignment), can only wrap around
				 * on the even bytes. So just need to perform
				 * mask every 2nd byte
				 */
				i1 = (i1 + 2) & 0xff;
				tmp0 = base[i1];
				j = j + tmp0;
				tmp1 = base[j];
				base[i1] = (uchar_t)tmp1;
				base[j] = (uchar_t)tmp0;
				tmp0 += tmp1;
				tmp0 = tmp0 & 0xff;
				merge |= (unsigned long long)(base[tmp0]) << 40;

				/* BYTE 3 */
				tmp0 = base[i1+1];
				j = j + tmp0;
				tmp1 = base[j];
				base[i1+1] = (uchar_t)tmp1;
				base[j] = (uchar_t)tmp0;
				tmp0 += tmp1;
				tmp0 = tmp0 & 0xff;
				merge |= (unsigned long long)(base[tmp0]) << 32;

				/* BYTE 4 */
				i1 = (i1 + 2) & 0xff;
				tmp0 = base[i1];
				j = j + tmp0;
				tmp1 = base[j];
				base[i1] = (uchar_t)tmp1;
				base[j] = (uchar_t)tmp0;
				tmp0 += tmp1;
				tmp0 = tmp0 & 0xff;
				merge |= (unsigned long long)(base[tmp0]) << 24;

				/* BYTE 5 */
				tmp0 = base[i1+1];
				j = j + tmp0;
				tmp1 = base[j];
				base[i1+1] = (uchar_t)tmp1;
				base[j] = (uchar_t)tmp0;
				tmp0 += tmp1;
				tmp0 = tmp0 & 0xff;
				merge |= (unsigned long long)(base[tmp0]) << 16;

				/* BYTE 6 */
				i1 = (i1+2) &0xff;
				jj = (uchar_t)i1;
				tmp0 = base[i1];

				j = j + tmp0;

				tmp1 = base[j];
				i_accum = tmp1;
				base[j] = (uchar_t)tmp0;


				tmp0 += tmp1;
				tmp0 = tmp0 & 0xff;

				if (i1 == tmp0) {
					merge |=
					    (unsigned long long)(i_accum) << 8;
				} else {
					merge |=
					    (unsigned long long)(base[tmp0]) <<
					    8;
				}

				/* BYTE 7 */
				i1++;
				tmp0 = base[i1];

				j = j + tmp0;
				if ((jj ^ j) < 2) {
					base[jj] = (uchar_t)i_accum;
					tmp1 = base[j];

					base[i1] = (uchar_t)tmp1;
					base[j] = (uchar_t)tmp0;

					tmp0 += tmp1;
					tmp0 = tmp0 & 0xff;

					merge |=
					    (unsigned long long)(base[tmp0]);

				} else {

					tmp1 = base[j];

					i_accum = i_accum << 8;
					i_accum |= tmp1;

					base[j] = (uchar_t)tmp0;

					tmp0 += tmp1;
					tmp0 = tmp0 & 0xff;

					/* LINTED E_BAD_PTR_CAST_ALIGN */
					*((unsigned short *) &base[jj]) =
					    i_accum;

					merge |=
					    (unsigned long long)(base[tmp0]);
				}
			}

			/*
			 * Perform update to [out]
			 * Remember could be alignment issues
			 */
			/* LINTED E_BAD_PTR_CAST_ALIGN */
			in0 = *((unsigned long long *) (&in[ii]));

			merge1 = merge0 | (merge >> shift);

			merge0 = (merge & mask) << 56;

			in0 = in0 ^ merge1;

			/* LINTED E_BAD_PTR_CAST_ALIGN */
			*((unsigned long long *) (&out[ii])) = in0;
		}

		i = (uchar_t)i1;

		/*
		 * Handle any overrun
		 */
		if (shift) {
			out[ii] = in[ii] ^ (merge0 >> 56);
			ii++;
		}

		/*
		 * Handle final few bytes
		 */
		for (; ii < len; ii++) {
			i = i + 1;
			tmp0 = base[i];
			j = j + tmp0;
			tmp1 = base[j];

			base[i] = (uchar_t)tmp1;
			base[j] = (uchar_t)tmp0;

			tmp0 += tmp1;
			tmp0 = tmp0 & 0xff;
			out[ii] = in[ii] ^ base[tmp0];
		}
		key->i = i;
		key->j = j;
	}
#endif /* sun4v */
}
