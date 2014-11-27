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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma weak __logf = logf

/*
 * Algorithm:
 *
 * Let y = x rounded to six significant bits.  Then for any choice
 * of e and z such that y = 2^e z, we have
 *
 * log(x) = e log(2) + log(z) + log(1+(x-y)/y)
 *
 * Note that (x-y)/y = (x'-y')/y' for any scaled x' = sx, y' = sy;
 * in particular, we can take s to be the power of two that makes
 * ulp(x') = 1.
 *
 * From a table, obtain l = log(z) and r = 1/y'.  For |s| <= 2^-6,
 * approximate log(1+s) by a polynomial p(s) where p(s) := s+s*s*
 * (K1+s*(K2+s*K3)).  Then we compute the expression above as
 * e*ln2 + l + p(r*(x'-y')) all evaluated in double precision.
 *
 * When x is subnormal, we first scale it to the normal range,
 * adjusting e accordingly.
 *
 * Accuracy:
 *
 * The largest error is less than 0.6 ulps.
 */

#include "libm.h"

/*
 * For i = 0, ..., 12,
 *   TBL[2i] = log(1 + i/32) and TBL[2i+1] = 2^-23 / (1 + i/32)
 *
 * For i = 13, ..., 32,
 *   TBL[2i] = log(1/2 + i/64) and TBL[2i+1] = 2^-23 / (1 + i/32)
 */
static const double TBL[] = {
	0.000000000000000000e+00, 1.192092895507812500e-07,
	3.077165866675368733e-02, 1.155968868371212153e-07,
	6.062462181643483994e-02, 1.121969784007352926e-07,
	8.961215868968713805e-02, 1.089913504464285680e-07,
	1.177830356563834557e-01, 1.059638129340277719e-07,
	1.451820098444978890e-01, 1.030999260979729787e-07,
	1.718502569266592284e-01, 1.003867701480263102e-07,
	1.978257433299198675e-01, 9.781275040064102225e-08,
	2.231435513142097649e-01, 9.536743164062500529e-08,
	2.478361639045812692e-01, 9.304139672256097884e-08,
	2.719337154836417580e-01, 9.082612537202380448e-08,
	2.954642128938358980e-01, 8.871388989825581272e-08,
	3.184537311185345887e-01, 8.669766512784091150e-08,
	-3.522205935893520934e-01, 8.477105034722222546e-08,
	-3.302416868705768671e-01, 8.292820142663043248e-08,
	-3.087354816496132859e-01, 8.116377160904255122e-08,
	-2.876820724517809014e-01, 7.947285970052082892e-08,
	-2.670627852490452536e-01, 7.785096460459183052e-08,
	-2.468600779315257843e-01, 7.629394531250000159e-08,
	-2.270574506353460753e-01, 7.479798560049019504e-08,
	-2.076393647782444896e-01, 7.335956280048077330e-08,
	-1.885911698075500298e-01, 7.197542010613207272e-08,
	-1.698990367953974734e-01, 7.064254195601851460e-08,
	-1.515498981272009327e-01, 6.935813210227272390e-08,
	-1.335313926245226268e-01, 6.811959402901785336e-08,
	-1.158318155251217008e-01, 6.692451343201754014e-08,
	-9.844007281325252434e-02, 6.577064251077586116e-08,
	-8.134563945395240081e-02, 6.465588585805084723e-08,
	-6.453852113757117814e-02, 6.357828776041666578e-08,
	-4.800921918636060631e-02, 6.253602074795082293e-08,
	-3.174869831458029812e-02, 6.152737525201612732e-08,
	-1.574835696813916761e-02, 6.055075024801586965e-08,
	0.000000000000000000e+00, 5.960464477539062500e-08,
};

static const double C[] = {
	6.931471805599452862e-01,
	-2.49887584306188944706e-01,
	3.33368809981254554946e-01,
	-5.00000008402474976565e-01
};

#define	ln2	C[0]
#define	K3	C[1]
#define	K2	C[2]
#define	K1	C[3]

float
logf(float x)
{
	double	v, t;
	float	f;
	int	hx, ix, i, exp, iy;

	hx = *(int *)&x;
	ix = hx & ~0x80000000;

	if (ix >= 0x7f800000)	/* nan or inf */
		return ((hx < 0)? x * 0.0f : x * x);

	exp = 0;
	if (hx < 0x00800000) { /* negative, zero, or subnormal */
		if (hx <= 0) {
			f = 0.0f;
			return ((ix == 0)? -1.0f / f : f / f);
		}

		/* subnormal; scale by 2^149 */
		f = (float)ix;
		ix = *(int *)&f;
		exp = -149;
	}

	exp += (ix - 0x3f320000) >> 23;
	ix &= 0x007fffff;
	iy = (ix + 0x20000) & 0xfffc0000;
	i = iy >> 17;
	t = ln2 * (double)exp + TBL[i];
	v = (double)(ix - iy) * TBL[i + 1];
	v += (v * v) * (K1 + v * (K2 + v * K3));
	f = (float)(t + v);
	return (f);
}
