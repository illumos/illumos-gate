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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * floating point Bessel's function of the first and second kinds
 * of order zero: j1(x),y1(x);
 *
 * Special cases:
 *	y0(0)=y1(0)=yn(n,0) = -inf with division by zero signal;
 *	y0(-ve)=y1(-ve)=yn(n,-ve) are NaN with invalid signal.
 */

#pragma weak j1 = __j1
#pragma weak y1 = __y1

#include "libm.h"
#include "libm_synonyms.h"
#include "libm_protos.h"
#include <math.h>
#include <values.h>

#define	GENERIC double
static const GENERIC
zero    = 0.0,
small	= 1.0e-5,
tiny 	= 1.0e-20,
one	= 1.0,
invsqrtpi = 5.641895835477562869480794515607725858441e-0001,
tpi	= 0.636619772367581343075535053490057448;

static GENERIC pone(GENERIC), qone(GENERIC);
static const GENERIC r0[4] = {
	-6.250000000000002203053200981413218949548e-0002,
	1.600998455640072901321605101981501263762e-0003,
	-1.963888815948313758552511884390162864930e-0005,
	8.263917341093549759781339713418201620998e-0008,
};
static const GENERIC s0[7] = {
	1.0e0,
	1.605069137643004242395356851797873766927e-0002,
	1.149454623251299996428500249509098499383e-0004,
	3.849701673735260970379681807910852327825e-0007,
};
static const GENERIC r1[12] = {
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
};
static const GENERIC s1[5] = {
	1.0e0,
	4.923499437590484879081138588998986303306e-0003,
	1.054389489212184156499666953501976688452e-0005,
	1.180768373106166527048240364872043816050e-0008,
	5.942665743476099355323245707680648588540e-0012,
};

GENERIC
j1(GENERIC x) {
	GENERIC z, d, s, c, ss, cc, r;
	int i, sgn;

	if (!finite(x))
		return (one/x);
	sgn = signbit(x);
	x = fabs(x);
	if (x > 8.00) {
		s = sin(x);
		c = cos(x);
	/*
	 * j1(x) = sqrt(2/(pi*x))*(p1(x)*cos(x0)-q1(x)*sin(x0))
	 * where x0 = x-3pi/4
	 * 	Better formula:
	 *		cos(x0) = cos(x)cos(3pi/4)+sin(x)sin(3pi/4)
	 *			=  1/sqrt(2) * (sin(x) - cos(x))
	 *		sin(x0) = sin(x)cos(3pi/4)-cos(x)sin(3pi/4)
	 *			= -1/sqrt(2) * (cos(x) + sin(x))
	 * To avoid cancellation, use
	 *		sin(x) +- cos(x) = -cos(2x)/(sin(x) -+ cos(x))
	 * to compute the worse one.
	 */
		if (x > 8.9e307) {	/* x+x may overflow */
			ss = -s-c;
			cc =  s-c;
		} else if (signbit(s) != signbit(c)) {
			cc = s - c;
			ss = cos(x+x)/cc;
		} else {
			ss = -s-c;
			cc = cos(x+x)/ss;
		}
	/*
	 * j1(x) = 1/sqrt(pi*x) * (P(1,x)*cc - Q(1,x)*ss)
	 * y1(x) = 1/sqrt(pi*x) * (P(1,x)*ss + Q(1,x)*cc)
	 */
		if (x > 1.0e40)
		    d = (invsqrtpi*cc)/sqrt(x);
		else
			d =  invsqrtpi*(pone(x)*cc-qone(x)*ss)/sqrt(x);

		if (x > X_TLOSS) {
		    if (sgn != 0) { d = -d; x = -x; }
			return (_SVID_libm_err(x, d, 36));
		} else
		    if (sgn == 0)
				return (d);
			else
				return (-d);
	}
	if (x <= small) {
		if (x <= tiny)
			d = 0.5*x;
		else
			d =  x*(0.5-x*x*0.125);
		if (sgn == 0)
			return (d);
		else
			return (-d);
	}
	z = x*x;
	if (x < 1.28) {
	    r = r0[3];
	    s = s0[3];
	    for (i = 2; i >= 0; i--) {
		r = r*z + r0[i];
		s = s*z + s0[i];
	    }
	    d = x*0.5+x*(z*(r/s));
	} else {
	    r = r1[11];
	    for (i = 10; i >= 0; i--) r = r*z + r1[i];
	    s = s1[0]+z*(s1[1]+z*(s1[2]+z*(s1[3]+z*s1[4])));
	    d = x*(r/s);
	}
	if (sgn == 0)
		return (d);
	else
		return (-d);
}

static const GENERIC u0[4] = {
	-1.960570906462389461018983259589655961560e-0001,
	4.931824118350661953459180060007970291139e-0002,
	-1.626975871565393656845930125424683008677e-0003,
	1.359657517926394132692884168082224258360e-0005,
};
static const GENERIC v0[5] = {
	1.0e0,
	2.565807214838390835108224713630901653793e-0002,
	3.374175208978404268650522752520906231508e-0004,
	2.840368571306070719539936935220728843177e-0006,
	1.396387402048998277638900944415752207592e-0008,
};
static const GENERIC u1[12] = {
	-1.960570906462389473336339614647555351626e-0001,
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
};
static const GENERIC v1[5] = {
	1.0e0,
	5.029187436727947764916247076102283399442e-0003,
	1.102693095808242775074856548927801750627e-0005,
	1.268035774543174837829534603830227216291e-0008,
	6.579416271766610825192542295821308730206e-0012,
};


GENERIC
y1(GENERIC x) {
	GENERIC z, d, s, c, ss, cc, u, v;
	int i;

	if (isnan(x))
		return (x*x);	/* + -> * for Cheetah */
	if (x <= zero) {
		if (x == zero)
		    /* return -one/zero;  */
		    return (_SVID_libm_err(x, x, 10));
		else
		    /* return zero/zero; */
		    return (_SVID_libm_err(x, x, 11));
	}
	if (x > 8.0) {
		if (!finite(x))
			return (zero);
		s = sin(x);
		c = cos(x);
	/*
	 * j1(x) = sqrt(2/(pi*x))*(p1(x)*cos(x0)-q1(x)*sin(x0))
	 * where x0 = x-3pi/4
	 * 	Better formula:
	 *		cos(x0) = cos(x)cos(3pi/4)+sin(x)sin(3pi/4)
	 *			=  1/sqrt(2) * (sin(x) - cos(x))
	 *		sin(x0) = sin(x)cos(3pi/4)-cos(x)sin(3pi/4)
	 *			= -1/sqrt(2) * (cos(x) + sin(x))
	 * To avoid cancellation, use
	 *		sin(x) +- cos(x) = -cos(2x)/(sin(x) -+ cos(x))
	 * to compute the worse one.
	 */
		if (x > 8.9e307) {	/* x+x may overflow */
			ss = -s-c;
			cc =  s-c;
		} else if (signbit(s) != signbit(c)) {
			cc = s - c;
			ss = cos(x+x)/cc;
		} else {
			ss = -s-c;
			cc = cos(x+x)/ss;
		}
	/*
	 * j1(x) = 1/sqrt(pi*x) * (P(1,x)*cc - Q(1,x)*ss)
	 * y1(x) = 1/sqrt(pi*x) * (P(1,x)*ss + Q(1,x)*cc)
	 */
		if (x > 1.0e91)
		    d =  (invsqrtpi*ss)/sqrt(x);
		else
			d = invsqrtpi*(pone(x)*ss+qone(x)*cc)/sqrt(x);

		if (x > X_TLOSS)
			return (_SVID_libm_err(x, d, 37));
		else
			return (d);
	}
		if (x <= tiny) {
			return (-tpi/x);
		}
	z = x*x;
	if (x < 1.28) {
	    u = u0[3]; v = v0[3]+z*v0[4];
	    for (i = 2; i >= 0; i--) {
		u = u*z + u0[i];
		v = v*z + v0[i];
	    }
	} else {
	    for (u = u1[11], i = 10; i >= 0; i--) u = u*z+u1[i];
	    v = v1[0]+z*(v1[1]+z*(v1[2]+z*(v1[3]+z*v1[4])));
	}
	return (x*(u/v) + tpi*(j1(x)*log(x)-one/x));
}

static const GENERIC pr0[6] = {
	-.4435757816794127857114720794e7,
	-.9942246505077641195658377899e7,
	-.6603373248364939109255245434e7,
	-.1523529351181137383255105722e7,
	-.1098240554345934672737413139e6,
	-.1611616644324610116477412898e4,
};
static const GENERIC ps0[6] = {
	-.4435757816794127856828016962e7,
	-.9934124389934585658967556309e7,
	-.6585339479723087072826915069e7,
	-.1511809506634160881644546358e7,
	-.1072638599110382011903063867e6,
	-.1455009440190496182453565068e4,
};
static const GENERIC huge    = 1.0e10;

static GENERIC
pone(GENERIC x) {
	GENERIC s, r, t, z;
	int i;
		/* assume x > 8 */
	if (x > huge)
		return (one);

	t = 8.0/x; z = t*t;
	r = pr0[5]; s = ps0[5]+z;
	for (i = 4; i >= 0; i--) {
		r = z*r + pr0[i];
		s = z*s + ps0[i];
	}
	return (r/s);
}


static const GENERIC qr0[6] = {
	0.3322091340985722351859704442e5,
	0.8514516067533570196555001171e5,
	0.6617883658127083517939992166e5,
	0.1849426287322386679652009819e5,
	0.1706375429020768002061283546e4,
	0.3526513384663603218592175580e2,
};
static const GENERIC qs0[6] = {
	0.7087128194102874357377502472e6,
	0.1819458042243997298924553839e7,
	0.1419460669603720892855755253e7,
	0.4002944358226697511708610813e6,
	0.3789022974577220264142952256e5,
	0.8638367769604990967475517183e3,
};

static GENERIC
qone(GENERIC x) {
	GENERIC s, r, t, z;
	int i;
	if (x > huge)
		return (0.375/x);

	t = 8.0/x; z = t*t;
		/* assume x > 8 */
	r = qr0[5]; s = qs0[5]+z;
	for (i = 4; i >= 0; i--) {
		r = z*r + qr0[i];
		s = z*s + qs0[i];
	}
	return (t*(r/s));
}
