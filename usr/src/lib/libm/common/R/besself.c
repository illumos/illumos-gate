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

#pragma weak __j0f = j0f
#pragma weak __j1f = j1f
#pragma weak __jnf = jnf
#pragma weak __y0f = y0f
#pragma weak __y1f = y1f
#pragma weak __ynf = ynf

#include "libm.h"
#include <float.h>

#if defined(__i386) && !defined(__amd64)
extern int __swapRP(int);
#endif

static const float
	zerof	= 0.0f,
	onef	= 1.0f;

static const double C[] = {
	0.0,
	-0.125,
	0.25,
	0.375,
	0.5,
	1.0,
	2.0,
	8.0,
	0.5641895835477562869480794515607725858441,	/* 1/sqrt(pi) */
	0.636619772367581343075535053490057448,	/* 2/pi */
	1.0e9,
};

#define	zero	C[0]
#define	neighth	C[1]
#define	quarter	C[2]
#define	three8	C[3]
#define	half	C[4]
#define	one	C[5]
#define	two	C[6]
#define	eight   C[7]
#define	isqrtpi	C[8]
#define	tpi	C[9]
#define	big	C[10]

static const double Cj0y0[] = {
	0.4861344183386052721391238447e5,	/* pr */
	0.1377662549407112278133438945e6,
	0.1222466364088289731869114004e6,
	0.4107070084315176135583353374e5,
	0.5026073801860637125889039915e4,
	0.1783193659125479654541542419e3,
	0.88010344055383421691677564e0,
	0.4861344183386052721414037058e5,	/* ps */
	0.1378196632630384670477582699e6,
	0.1223967185341006542748936787e6,
	0.4120150243795353639995862617e5,
	0.5068271181053546392490184353e4,
	0.1829817905472769960535671664e3,
	1.0,
	-0.1731210995701068539185611951e3,	/* qr */
	-0.5522559165936166961235240613e3,
	-0.5604935606637346590614529613e3,
	-0.2200430300226009379477365011e3,
	-0.323869355375648849771296746e2,
	-0.14294979207907956223499258e1,
	-0.834690374102384988158918e-2,
	0.1107975037248683865326709645e5,	/* qs */
	0.3544581680627082674651471873e5,
	0.3619118937918394132179019059e5,
	0.1439895563565398007471485822e5,
	0.2190277023344363955930226234e4,
	0.106695157020407986137501682e3,
	1.0,
};

#define	pr	Cj0y0
#define	ps	(Cj0y0+7)
#define	qr	(Cj0y0+14)
#define	qs	(Cj0y0+21)

static const double Cj0[] = {
	-2.500000000000003622131880894830476755537e-0001,	/* r0 */
	1.095597547334830263234433855932375353303e-0002,
	-1.819734750463320921799187258987098087697e-0004,
	9.977001946806131657544212501069893930846e-0007,
	1.0,							/* s0 */
	1.867609810662950169966782360588199673741e-0002,
	1.590389206181565490878430827706972074208e-0004,
	6.520867386742583632375520147714499522721e-0007,
	9.999999999999999942156495584397047660949e-0001,	/* r1 */
	-2.389887722731319130476839836908143731281e-0001,
	1.293359476138939027791270393439493640570e-0002,
	-2.770985642343140122168852400228563364082e-0004,
	2.905241575772067678086738389169625218912e-0006,
	-1.636846356264052597969042009265043251279e-0008,
	5.072306160724884775085431059052611737827e-0011,
	-8.187060730684066824228914775146536139112e-0014,
	5.422219326959949863954297860723723423842e-0017,
	1.0,							/* s1 */
	1.101122772686807702762104741932076228349e-0002,
	6.140169310641649223411427764669143978228e-0005,
	2.292035877515152097976946119293215705250e-0007,
	6.356910426504644334558832036362219583789e-0010,
	1.366626326900219555045096999553948891401e-0012,
	2.280399586866739522891837985560481180088e-0015,
	2.801559820648939665270492520004836611187e-0018,
	2.073101088320349159764410261466350732968e-0021,
};

#define	r0	Cj0
#define	s0	(Cj0+4)
#define	r1	(Cj0+8)
#define	s1	(Cj0+17)

static const double Cy0[] = {
	-7.380429510868722526754723020704317641941e-0002,	/* u0 */
	1.772607102684869924301459663049874294814e-0001,
	-1.524370666542713828604078090970799356306e-0002,
	4.650819100693891757143771557629924591915e-0004,
	-7.125768872339528975036316108718239946022e-0006,
	6.411017001656104598327565004771515257146e-0008,
	-3.694275157433032553021246812379258781665e-0010,
	1.434364544206266624252820889648445263842e-0012,
	-3.852064731859936455895036286874139896861e-0015,
	7.182052899726138381739945881914874579696e-0018,
	-9.060556574619677567323741194079797987200e-0021,
	7.124435467408860515265552217131230511455e-0024,
	-2.709726774636397615328813121715432044771e-0027,
	1.0,							/* v0 */
	4.678678931512549002587702477349214886475e-0003,
	9.486828955529948534822800829497565178985e-0006,
	1.001495929158861646659010844136682454906e-0008,
	4.725338116256021660204443235685358593611e-0012,
};

#define	u0	Cy0
#define	v0	(Cy0+13)

static const double Cj1y1[] = {
	-0.4435757816794127857114720794e7,	/* pr0 */
	-0.9942246505077641195658377899e7,
	-0.6603373248364939109255245434e7,
	-0.1523529351181137383255105722e7,
	-0.1098240554345934672737413139e6,
	-0.1611616644324610116477412898e4,
	-0.4435757816794127856828016962e7,	/* ps0 */
	-0.9934124389934585658967556309e7,
	-0.6585339479723087072826915069e7,
	-0.1511809506634160881644546358e7,
	-0.1072638599110382011903063867e6,
	-0.1455009440190496182453565068e4,
	0.3322091340985722351859704442e5,	/* qr0 */
	0.8514516067533570196555001171e5,
	0.6617883658127083517939992166e5,
	0.1849426287322386679652009819e5,
	0.1706375429020768002061283546e4,
	0.3526513384663603218592175580e2,
	0.7087128194102874357377502472e6,	/* qs0 */
	0.1819458042243997298924553839e7,
	0.1419460669603720892855755253e7,
	0.4002944358226697511708610813e6,
	0.3789022974577220264142952256e5,
	0.8638367769604990967475517183e3,
};

#define	pr0	Cj1y1
#define	ps0	(Cj1y1+6)
#define	qr0	(Cj1y1+12)
#define	qs0	(Cj1y1+18)

static const double Cj1[] = {
	-6.250000000000002203053200981413218949548e-0002,	/* a0 */
	1.600998455640072901321605101981501263762e-0003,
	-1.963888815948313758552511884390162864930e-0005,
	8.263917341093549759781339713418201620998e-0008,
	1.0e0,							/* b0 */
	1.605069137643004242395356851797873766927e-0002,
	1.149454623251299996428500249509098499383e-0004,
	3.849701673735260970379681807910852327825e-0007,
	4.999999999999999995517408894340485471724e-0001,
	-6.003825028120475684835384519945468075423e-0002,
	2.301719899263321828388344461995355419832e-0003,
	-4.208494869238892934859525221654040304068e-0005,
	4.377745135188837783031540029700282443388e-0007,
	-2.854106755678624335145364226735677754179e-0009,
	1.234002865443952024332943901323798413689e-0011,
	-3.645498437039791058951273508838177134310e-0014,
	7.404320596071797459925377103787837414422e-0017,
	-1.009457448277522275262808398517024439084e-0019,
	8.520158355824819796968771418801019930585e-0023,
	-3.458159926081163274483854614601091361424e-0026,
	1.0e0,							/* b1 */
	4.923499437590484879081138588998986303306e-0003,
	1.054389489212184156499666953501976688452e-0005,
	1.180768373106166527048240364872043816050e-0008,
	5.942665743476099355323245707680648588540e-0012,
};

#define	a0	Cj1
#define	b0	(Cj1+4)
#define	a1	(Cj1+8)
#define	b1	(Cj1+20)

static const double Cy1[] = {
	-1.960570906462389461018983259589655961560e-0001,	/* c0 */
	4.931824118350661953459180060007970291139e-0002,
	-1.626975871565393656845930125424683008677e-0003,
	1.359657517926394132692884168082224258360e-0005,
	1.0e0,							/* d0 */
	2.565807214838390835108224713630901653793e-0002,
	3.374175208978404268650522752520906231508e-0004,
	2.840368571306070719539936935220728843177e-0006,
	1.396387402048998277638900944415752207592e-0008,
	-1.960570906462389473336339614647555351626e-0001,	/* c1 */
	5.336268030335074494231369159933012844735e-0002,
	-2.684137504382748094149184541866332033280e-0003,
	5.737671618979185736981543498580051903060e-0005,
	-6.642696350686335339171171785557663224892e-0007,
	4.692417922568160354012347591960362101664e-0009,
	-2.161728635907789319335231338621412258355e-0011,
	6.727353419738316107197644431844194668702e-0014,
	-1.427502986803861372125234355906790573422e-0016,
	2.020392498726806769468143219616642940371e-0019,
	-1.761371948595104156753045457888272716340e-0022,
	7.352828391941157905175042420249225115816e-0026,
	1.0e0,							/* d1 */
	5.029187436727947764916247076102283399442e-0003,
	1.102693095808242775074856548927801750627e-0005,
	1.268035774543174837829534603830227216291e-0008,
	6.579416271766610825192542295821308730206e-0012,
};

#define	c0	Cy1
#define	d0	(Cy1+4)
#define	c1	(Cy1+9)
#define	d1	(Cy1+21)


/* core of j0f computation; assumes fx is finite */
static double
__k_j0f(float fx)
{
	double	x, z, s, c, ss, cc, r, t, p0, q0;
	int	ix, i;

	ix = *(int *)&fx & ~0x80000000;
	x = fabs((double)fx);
	if (ix > 0x41000000) {
		/* x > 8; see comments in j0.c */
		s = sin(x);
		c = cos(x);
		if (signbit(s) != signbit(c)) {
			ss = s - c;
			cc = -cos(x + x) / ss;
		} else {
			cc = s + c;
			ss = -cos(x + x) / cc;
		}
		if (ix > 0x501502f9) {
			/* x > 1.0e10 */
			p0 = one;
			q0 = neighth / x;
		} else {
			t = eight / x;
			z = t * t;
			p0 = (pr[0] + z * (pr[1] + z * (pr[2] + z * (pr[3] +
			    z * (pr[4] + z * (pr[5] + z * pr[6])))))) /
			    (ps[0] + z * (ps[1] + z * (ps[2] + z * (ps[3] +
			    z * (ps[4] + z * (ps[5] + z))))));
			q0 = ((qr[0] + z * (qr[1] + z * (qr[2] + z * (qr[3] +
			    z * (qr[4] + z * (qr[5] + z * qr[6])))))) /
			    (qs[0] + z * (qs[1] + z * (qs[2] + z * (qs[3] +
			    z * (qs[4] + z * (qs[5] + z))))))) * t;
		}
		return (isqrtpi * (p0 * cc - q0 * ss) / sqrt(x));
	}
	if (ix <= 0x3727c5ac) {
		/* x <= 1.0e-5 */
		if (ix <= 0x219392ef) /* x <= 1.0e-18 */
			return (one - x);
		return (one - x * x * quarter);
	}
	z = x * x;
	if (ix <= 0x3fa3d70a) {
		/* x <= 1.28 */
		r = r0[0] + z * (r0[1] + z * (r0[2] + z * r0[3]));
		s = s0[0] + z * (s0[1] + z * (s0[2] + z * s0[3]));
		return (one + z * (r / s));
	}
	r = r1[8];
	s = s1[8];
	for (i = 7; i >= 0; i--) {
		r = r * z + r1[i];
		s = s * z + s1[i];
	}
	return (r / s);
}

float
j0f(float fx)
{
	float	f;
	int	ix;
#if defined(__i386) && !defined(__amd64)
	int	rp;
#endif

	ix = *(int *)&fx & ~0x80000000;
	if (ix >= 0x7f800000) {			/* nan or inf */
		if (ix > 0x7f800000)
			return (fx * fx);
		return (zerof);
	}

#if defined(__i386) && !defined(__amd64)
	rp = __swapRP(fp_extended);
#endif
	f = (float)__k_j0f(fx);
#if defined(__i386) && !defined(__amd64)
	if (rp != fp_extended)
		(void) __swapRP(rp);
#endif
	return (f);
}

/* core of y0f computation; assumes fx is finite and positive */
static double
__k_y0f(float fx)
{
	double	x, z, s, c, ss, cc, t, p0, q0, u, v;
	int	ix, i;

	ix = *(int *)&fx;
	x = (double)fx;
	if (ix > 0x41000000) {
		/* x > 8; see comments in j0.c */
		s = sin(x);
		c = cos(x);
		if (signbit(s) != signbit(c)) {
			ss = s - c;
			cc = -cos(x + x) / ss;
		} else {
			cc = s + c;
			ss = -cos(x + x) / cc;
		}
		if (ix > 0x501502f9) {
			/* x > 1.0e10 */
			p0 = one;
			q0 = neighth / x;
		} else {
			t = eight / x;
			z = t * t;
			p0 = (pr[0] + z * (pr[1] + z * (pr[2] + z * (pr[3] +
			    z * (pr[4] + z * (pr[5] + z * pr[6])))))) /
			    (ps[0] + z * (ps[1] + z * (ps[2] + z * (ps[3] +
			    z * (ps[4] + z * (ps[5] + z))))));
			q0 = ((qr[0] + z * (qr[1] + z * (qr[2] + z * (qr[3] +
			    z * (qr[4] + z * (qr[5] + z * qr[6])))))) /
			    (qs[0] + z * (qs[1] + z * (qs[2] + z * (qs[3] +
			    z * (qs[4] + z * (qs[5] + z))))))) * t;
		}
		return (isqrtpi * (p0 * ss + q0 * cc) / sqrt(x));
	}
	if (ix <= 0x219392ef) /* x <= 1.0e-18 */
		return (u0[0] + tpi * log(x));
	z = x * x;
	u = u0[12];
	for (i = 11; i >= 0; i--)
		u = u * z + u0[i];
	v = v0[0] + z * (v0[1] + z * (v0[2] + z * (v0[3] + z * v0[4])));
	return (u / v + tpi * (__k_j0f(fx) * log(x)));
}

float
y0f(float fx)
{
	float	f;
	int	ix;
#if defined(__i386) && !defined(__amd64)
	int	rp;
#endif

	ix = *(int *)&fx;
	if ((ix & ~0x80000000) > 0x7f800000)	/* nan */
		return (fx * fx);
	if (ix <= 0) {				/* zero or negative */
		if ((ix << 1) == 0)
			return (-onef / zerof);
		return (zerof / zerof);
	}
	if (ix == 0x7f800000)			/* +inf */
		return (zerof);

#if defined(__i386) && !defined(__amd64)
	rp = __swapRP(fp_extended);
#endif
	f = (float)__k_y0f(fx);
#if defined(__i386) && !defined(__amd64)
	if (rp != fp_extended)
		(void) __swapRP(rp);
#endif
	return (f);
}

/* core of j1f computation; assumes fx is finite */
static double
__k_j1f(float fx)
{
	double	x, z, s, c, ss, cc, r, t, p1, q1;
	int	i, ix, sgn;

	ix = *(int *)&fx;
	sgn = (unsigned)ix >> 31;
	ix &= ~0x80000000;
	x = fabs((double)fx);
	if (ix > 0x41000000) {
		/* x > 8; see comments in j1.c */
		s = sin(x);
		c = cos(x);
		if (signbit(s) != signbit(c)) {
			cc = s - c;
			ss = cos(x + x) / cc;
		} else {
			ss = -s - c;
			cc = cos(x + x) / ss;
		}
		if (ix > 0x501502f9) {
			/* x > 1.0e10 */
			p1 = one;
			q1 = three8 / x;
		} else {
			t = eight / x;
			z = t * t;
			p1 = (pr0[0] + z * (pr0[1] + z * (pr0[2] + z *
			    (pr0[3] + z * (pr0[4] + z * pr0[5]))))) /
			    (ps0[0] + z * (ps0[1] + z * (ps0[2] + z *
			    (ps0[3] + z * (ps0[4] + z * (ps0[5] + z))))));
			q1 = ((qr0[0] + z * (qr0[1] + z * (qr0[2] + z *
			    (qr0[3] + z * (qr0[4] + z * qr0[5]))))) /
			    (qs0[0] + z * (qs0[1] + z * (qs0[2] + z *
			    (qs0[3] + z * (qs0[4] + z * (qs0[5] + z))))))) * t;
		}
		t = isqrtpi * (p1 * cc - q1 * ss) / sqrt(x);
		return ((sgn)? -t : t);
	}
	if (ix <= 0x3727c5ac) {
		/* x <= 1.0e-5 */
		if (ix <= 0x219392ef) /* x <= 1.0e-18 */
			t = half * x;
		else
			t = x * (half + neighth * x * x);
		return ((sgn)? -t : t);
	}
	z = x * x;
	if (ix < 0x3fa3d70a) {
		/* x < 1.28 */
		r = a0[0] + z * (a0[1] + z * (a0[2] + z * a0[3]));
		s = b0[0] + z * (b0[1] + z * (b0[2] + z * b0[3]));
		t = x * half + x * (z * (r / s));
	} else {
		r = a1[11];
		for (i = 10; i >= 0; i--)
			r = r * z + a1[i];
		s = b1[0] + z * (b1[1] + z * (b1[2] + z * (b1[3] + z * b1[4])));
		t = x * (r / s);
	}
	return ((sgn)? -t : t);
}

float
j1f(float fx)
{
	float	f;
	int	ix;
#if defined(__i386) && !defined(__amd64)
	int	rp;
#endif

	ix = *(int *)&fx & ~0x80000000;
	if (ix >= 0x7f800000)			/* nan or inf */
		return (onef / fx);

#if defined(__i386) && !defined(__amd64)
	rp = __swapRP(fp_extended);
#endif
	f = (float)__k_j1f(fx);
#if defined(__i386) && !defined(__amd64)
	if (rp != fp_extended)
		(void) __swapRP(rp);
#endif
	return (f);
}

/* core of y1f computation; assumes fx is finite and positive */
static double
__k_y1f(float fx)
{
	double	x, z, s, c, ss, cc, u, v, p1, q1, t;
	int	i, ix;

	ix = *(int *)&fx;
	x = (double)fx;
	if (ix > 0x41000000) {
		/* x > 8; see comments in j1.c */
		s = sin(x);
		c = cos(x);
		if (signbit(s) != signbit(c)) {
			cc = s - c;
			ss = cos(x + x) / cc;
		} else {
			ss = -s - c;
			cc = cos(x + x) / ss;
		}
		if (ix > 0x501502f9) {
			/* x > 1.0e10 */
			p1 = one;
			q1 = three8 / x;
		} else {
			t = eight / x;
			z = t * t;
			p1 = (pr0[0] + z * (pr0[1] + z * (pr0[2] + z *
			    (pr0[3] + z * (pr0[4] + z * pr0[5]))))) /
			    (ps0[0] + z * (ps0[1] + z * (ps0[2] + z *
			    (ps0[3] + z * (ps0[4] + z * (ps0[5] + z))))));
			q1 = ((qr0[0] + z * (qr0[1] + z * (qr0[2] + z *
			    (qr0[3] + z * (qr0[4] + z * qr0[5]))))) /
			    (qs0[0] + z * (qs0[1] + z * (qs0[2] + z *
			    (qs0[3] + z * (qs0[4] + z * (qs0[5] + z))))))) * t;
		}
		return (isqrtpi * (p1 * ss + q1 * cc) / sqrt(x));
	}
	if (ix <= 0x219392ef) /* x <= 1.0e-18 */
		return (-tpi / x);
	z = x * x;
	if (ix < 0x3fa3d70a) {
		/* x < 1.28 */
		u = c0[0] + z * (c0[1] + z * (c0[2] + z * c0[3]));
		v = d0[0] + z * (d0[1] + z * (d0[2] + z * (d0[3] + z * d0[4])));
	} else {
		u = c1[11];
		for (i = 10; i >= 0; i--)
			u = u * z + c1[i];
		v = d1[0] + z * (d1[1] + z * (d1[2] + z * (d1[3] + z * d1[4])));
	}
	return (x * (u / v) + tpi * (__k_j1f(fx) * log(x) - one / x));
}

float
y1f(float fx)
{
	float	f;
	int	ix;
#if defined(__i386) && !defined(__amd64)
	int	rp;
#endif

	ix = *(int *)&fx;
	if ((ix & ~0x80000000) > 0x7f800000)	/* nan */
		return (fx * fx);
	if (ix <= 0) {				/* zero or negative */
		if ((ix << 1) == 0)
			return (-onef / zerof);
		return (zerof / zerof);
	}
	if (ix == 0x7f800000)			/* +inf */
		return (zerof);

#if defined(__i386) && !defined(__amd64)
	rp = __swapRP(fp_extended);
#endif
	f = (float)__k_y1f(fx);
#if defined(__i386) && !defined(__amd64)
	if (rp != fp_extended)
		(void) __swapRP(rp);
#endif
	return (f);
}

float
jnf(int n, float fx)
{
	double	a, b, temp, x, z, w, t, q0, q1, h;
	float	f;
	int	i, ix, sgn, m, k;
#if defined(__i386) && !defined(__amd64)
	int	rp;
#endif

	if (n < 0) {
		n = -n;
		fx = -fx;
	}
	if (n == 0)
		return (j0f(fx));
	if (n == 1)
		return (j1f(fx));

	ix = *(int *)&fx;
	sgn = (n & 1)? ((unsigned)ix >> 31) : 0;
	ix &= ~0x80000000;
	if (ix >= 0x7f800000) {		/* nan or inf */
		if (ix > 0x7f800000)
			return (fx * fx);
		return ((sgn)? -zerof : zerof);
	}
	if ((ix << 1) == 0)
		return ((sgn)? -zerof : zerof);

#if defined(__i386) && !defined(__amd64)
	rp = __swapRP(fp_extended);
#endif
	fx = fabsf(fx);
	x = (double)fx;
	if ((double)n <= x) {
		/* safe to use J(n+1,x) = 2n/x * J(n,x) - J(n-1,x) */
		a = __k_j0f(fx);
		b = __k_j1f(fx);
		for (i = 1; i < n; i++) {
			temp = b;
			b = b * ((double)(i + i) / x) - a;
			a = temp;
		}
		f = (float)b;
#if defined(__i386) && !defined(__amd64)
		if (rp != fp_extended)
			(void) __swapRP(rp);
#endif
		return ((sgn)? -f : f);
	}
	if (ix < 0x3089705f) {
		/* x < 1.0e-9; use J(n,x) = 1/n! * (x / 2)^n */
		if (n > 6)
			n = 6;	/* result underflows to zero for n >= 6 */
		b = t = half * x;
		a = one;
		for (i = 2; i <= n; i++) {
			b *= t;
			a *= (double)i;
		}
		b /= a;
	} else {
		/*
		 * Use the backward recurrence:
		 *
		 * 			x      x^2	x^2
		 *  J(n,x)/J(n-1,x) =  ---- - ------ - ------   .....
		 *			2n    2(n+1)   2(n+2)
		 *
		 * Let w = 2n/x and h = 2/x.  Then the above quotient
		 * is equal to the continued fraction:
		 *		     1
		 *	= -----------------------
		 *			1
		 *	   w - -----------------
		 *			  1
		 * 		w+h - ---------
		 *			w+2h - ...
		 *
		 * To determine how many terms are needed, run the
		 * recurrence
		 *
		 *	Q(0) = w,
		 *	Q(1) = w(w+h) - 1,
		 *	Q(k) = (w+k*h)*Q(k-1) - Q(k-2).
		 *
		 * Then when Q(k) > 1e4, k is large enough for single
		 * precision.
		 */
/* XXX NOT DONE - rework this */
		w = (n + n) / x;
		h = two / x;
		q0 = w;
		z = w + h;
		q1 = w * z - one;
		k = 1;
		while (q1 < big) {
			k++;
			z += h;
			temp = z * q1 - q0;
			q0 = q1;
			q1 = temp;
		}
		m = n + n;
		t = zero;
		for (i = (n + k) << 1; i >= m; i -= 2)
			t = one / ((double)i / x - t);
		a = t;
		b = one;
		/*
		 * estimate log((2/x)^n*n!) = n*log(2/x)+n*ln(n)
		 * hence, if n*(log(2n/x)) > ...
		 *	single 8.8722839355e+01
		 *	double 7.09782712893383973096e+02
		 *	then recurrent value may overflow and the result is
		 *	likely underflow to zero
		 */
		temp = (double)n;
		temp *= log((two / x) * temp);
		if (temp < 7.09782712893383973096e+02) {
			for (i = n - 1; i > 0; i--) {
				temp = b;
				b = b * ((double)(i + i) / x) - a;
				a = temp;
			}
		} else {
			for (i = n - 1; i > 0; i--) {
				temp = b;
				b = b * ((double)(i + i) / x) - a;
				a = temp;
				if (b > 1.0e100) {
					a /= b;
					t /= b;
					b = one;
				}
			}
		}
		b = (t * __k_j0f(fx) / b);
	}
	f = (float)b;
#if defined(__i386) && !defined(__amd64)
	if (rp != fp_extended)
		(void) __swapRP(rp);
#endif
	return ((sgn)? -f : f);
}

float
ynf(int n, float fx)
{
	double	a, b, temp, x;
	float	f;
	int	i, sign, ix;
#if defined(__i386) && !defined(__amd64)
	int	rp;
#endif

	sign = 0;
	if (n < 0) {
		n = -n;
		if (n & 1)
			sign = 1;
	}
	if (n == 0)
		return (y0f(fx));
	if (n == 1)
		return ((sign)? -y1f(fx) : y1f(fx));

	ix = *(int *)&fx;
	if ((ix & ~0x80000000) > 0x7f800000)	/* nan */
		return (fx * fx);
	if (ix <= 0) {				/* zero or negative */
		if ((ix << 1) == 0)
			return (-onef / zerof);
		return (zerof / zerof);
	}
	if (ix == 0x7f800000)			/* +inf */
		return (zerof);

#if defined(__i386) && !defined(__amd64)
	rp = __swapRP(fp_extended);
#endif
	a = __k_y0f(fx);
	b = __k_y1f(fx);
	x = (double)fx;
	for (i = 1; i < n; i++) {
		temp = b;
		b *= (double)(i + i) / x;
		if (b <= -DBL_MAX)
			break;
		b -= a;
		a = temp;
	}
	f = (float)b;
#if defined(__i386) && !defined(__amd64)
	if (rp != fp_extended)
		(void) __swapRP(rp);
#endif
	return ((sign)? -f : f);
}
