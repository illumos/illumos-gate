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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma weak _des_encrypt1 = des_encrypt1

#include <sys/types.h>

void
des_encrypt1(char *block, char *L, char *IP, char *R, char *preS, char *E,
	char KS[][48], char S[][64], char *f, char *tempL, char *P, char *FP)
{
	int	i;
	int	t, j, k;
	char	t2;

	/*
	 * First, permute the bits in the input
	 */
	for (j = 0; j < 64; j++)
		L[j] = block[IP[j]-1];
	/*
	 * Perform an encryption operation 16 times.
	 */
	for (i = 0; i < 16; i++) {
		/*
		 * Save the R array,
		 * which will be the new L.
		 */
		for (j = 0; j < 32; j++)
			tempL[j] = R[j];
		/*
		 * Expand R to 48 bits using the E selector;
		 * exclusive-or with the current key bits.
		 */
		for (j = 0; j < 48; j++)
			preS[j] = R[E[j]-1] ^ KS[i][j];
		/*
		 * The pre-select bits are now considered
		 * in 8 groups of 6 bits each.
		 * The 8 selection functions map these
		 * 6-bit quantities into 4-bit quantities
		 * and the results permuted
		 * to make an f(R, K).
		 * The indexing into the selection functions
		 * is peculiar; it could be simplified by
		 * rewriting the tables.
		 */
		for (j = 0; j < 8; j++) {
			t = 6*j;
			k = S[j][(preS[t+0]<<5)+
			    (preS[t+1]<<3)+
			    (preS[t+2]<<2)+
			    (preS[t+3]<<1)+
			    (preS[t+4]<<0)+
			    (preS[t+5]<<4)];
			t = 4*j;
			f[t+0] = (k>>3)&01;
			f[t+1] = (k>>2)&01;
			f[t+2] = (k>>1)&01;
			f[t+3] = (k>>0)&01;
		}
		/*
		 * The new R is L ^ f(R, K).
		 * The f here has to be permuted first, though.
		 */
		for (j = 0; j < 32; j++)
			R[j] = L[j] ^ f[P[j]-1];
		/*
		 * Finally, the new L (the original R)
		 * is copied back.
		 */
		for (j = 0; j < 32; j++)
			L[j] = tempL[j];
	}
	/*
	 * The output L and R are reversed.
	 */
	for (j = 0; j < 32; j++) {
		t2 = L[j];
		L[j] = R[j];
		R[j] = t2;
	}
	/*
	 * The final output
	 * gets the inverse permutation of the very original.
	 */
	for (j = 0; j < 64; j++)
		block[j] = L[FP[j]-1];
}
