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
 * Floating point Bessel's function of the first and second kinds
 * of order zero: j0(x),y0(x);
 *
 * Special cases:
 *	y0(0)=y1(0)=yn(n,0) = -inf with division by zero signal;
 *	y0(-ve)=y1(-ve)=yn(n,-ve) are NaN with invalid signal.
 */

#pragma weak j0 = __j0
#pragma weak y0 = __y0

#include "libm.h"
#include "libm_synonyms.h"
#include "libm_protos.h"
#include <math.h>
#include <values.h>

#define	GENERIC double
static const GENERIC
zero    = 0.0,
small	= 1.0e-5,
tiny	= 1.0e-18,
one	= 1.0,
eight   = 8.0,
invsqrtpi = 5.641895835477562869480794515607725858441e-0001,
tpi	= 0.636619772367581343075535053490057448;

static GENERIC pzero(GENERIC), qzero(GENERIC);
static const GENERIC r0[4] = {	/* [1.e-5, 1.28] */
	-2.500000000000003622131880894830476755537e-0001,
	1.095597547334830263234433855932375353303e-0002,
	-1.819734750463320921799187258987098087697e-0004,
	9.977001946806131657544212501069893930846e-0007,
};
static const GENERIC s0[4] = {	/* [1.e-5, 1.28] */
	1.0,
	1.867609810662950169966782360588199673741e-0002,
	1.590389206181565490878430827706972074208e-0004,
	6.520867386742583632375520147714499522721e-0007,
};
static const GENERIC r1[9] = {	/* [1.28,8] */
	9.999999999999999942156495584397047660949e-0001,
	-2.389887722731319130476839836908143731281e-0001,
	1.293359476138939027791270393439493640570e-0002,
	-2.770985642343140122168852400228563364082e-0004,
	2.905241575772067678086738389169625218912e-0006,
	-1.636846356264052597969042009265043251279e-0008,
	5.072306160724884775085431059052611737827e-0011,
	-8.187060730684066824228914775146536139112e-0014,
	5.422219326959949863954297860723723423842e-0017,
};
static const GENERIC s1[9] = {	/* [1.28,8] */
	1.0,
	1.101122772686807702762104741932076228349e-0002,
	6.140169310641649223411427764669143978228e-0005,
	2.292035877515152097976946119293215705250e-0007,
	6.356910426504644334558832036362219583789e-0010,
	1.366626326900219555045096999553948891401e-0012,
	2.280399586866739522891837985560481180088e-0015,
	2.801559820648939665270492520004836611187e-0018,
	2.073101088320349159764410261466350732968e-0021,
};

GENERIC
j0(GENERIC x) {
	GENERIC z, s, c, ss, cc, r, u, v, ox;
	int i;

	if (isnan(x))
		return (x*x);	/* + -> * for Cheetah */
	ox = x;
	x = fabs(x);
	if (x > 8.0) {
		if (!finite(x))
			return (zero);
		s = sin(x);
		c = cos(x);
	/*
	 * j0(x) = sqrt(2/(pi*x))*(p0(x)*cos(x0)-q0(x)*sin(x0))
	 * where x0 = x-pi/4
	 * 	Better formula:
	 *		cos(x0) = cos(x)cos(pi/4)+sin(x)sin(pi/4)
	 *			= 1/sqrt(2) * (cos(x) + sin(x))
	 *		sin(x0) = sin(x)cos(pi/4)-cos(x)sin(pi/4)
	 *			= 1/sqrt(2) * (sin(x) - cos(x))
	 * To avoid cancellation, use
	 *		sin(x) +- cos(x) = -cos(2x)/(sin(x) -+ cos(x))
	 * to compute the worse one.
	 */
		if (x > 8.9e307) {	/* x+x may overflow */
			ss = s-c;
			cc = s+c;
		} else if (signbit(s) != signbit(c)) {
			ss = s - c;
			cc = -cos(x+x)/ss;
		} else {
			cc = s + c;
			ss = -cos(x+x)/cc;
		}
	/*
	 * j0(x) = 1/sqrt(pi) * (P(0,x)*cc - Q(0,x)*ss) / sqrt(x)
	 * y0(x) = 1/sqrt(pi) * (P(0,x)*ss + Q(0,x)*cc) / sqrt(x)
	 */
		if (x > 1.0e40) z = (invsqrtpi*cc)/sqrt(x);
		else {
		    u = pzero(x); v = qzero(x);
		    z = invsqrtpi*(u*cc-v*ss)/sqrt(x);
		}
	/* force to pass SVR4 even the result is wrong (sign) */
		if (x > X_TLOSS)
		    return (_SVID_libm_err(ox, z, 34));
		else
		    return (z);
	}
	if (x <= small) {
	    if (x <= tiny)
			return (one-x);
	    else
			return (one-x*x*0.25);
	}
	z = x*x;
	if (x <= 1.28) {
	    r =  r0[0]+z*(r0[1]+z*(r0[2]+z*r0[3]));
	    s =  s0[0]+z*(s0[1]+z*(s0[2]+z*s0[3]));
	    return (one + z*(r/s));
	} else {
	    for (r = r1[8], s = s1[8], i = 7; i >= 0; i--) {
		r = r*z + r1[i];
		s = s*z + s1[i];
	    }
	    return (r/s);
	}
}

static const GENERIC u0[13] = {
	-7.380429510868722526754723020704317641941e-0002,
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
};
static const GENERIC v0[5] = {
	1.0,
	4.678678931512549002587702477349214886475e-0003,
	9.486828955529948534822800829497565178985e-0006,
	1.001495929158861646659010844136682454906e-0008,
	4.725338116256021660204443235685358593611e-0012,
};

GENERIC
y0(GENERIC x) {
	GENERIC z, /* d, */ s, c, ss, cc, u, v;
	int i;

	if (isnan(x))
		return (x*x);	/* + -> * for Cheetah */
	if (x <= zero) {
		if (x == zero)
		    /* d= -one/(x-x); */
		    return (_SVID_libm_err(x, x, 8));
		else
		    /* d = zero/(x-x); */
		    return (_SVID_libm_err(x, x, 9));
	}
	if (x > 8.0) {
		if (!finite(x))
			return (zero);
		s = sin(x);
		c = cos(x);
	/*
	 * j0(x) = sqrt(2/(pi*x))*(p0(x)*cos(x0)-q0(x)*sin(x0))
	 * where x0 = x-pi/4
	 * 	Better formula:
	 *		cos(x0) = cos(x)cos(pi/4)+sin(x)sin(pi/4)
	 *			= 1/sqrt(2) * (cos(x) + sin(x))
	 *		sin(x0) = sin(x)cos(pi/4)-cos(x)sin(pi/4)
	 *			= 1/sqrt(2) * (sin(x) - cos(x))
	 * To avoid cancellation, use
	 *		sin(x) +- cos(x) = -cos(2x)/(sin(x) -+ cos(x))
	 * to compute the worse one.
	 */
		if (x > 8.9e307) {	/* x+x may overflow */
			ss = s-c;
			cc = s+c;
		} else if (signbit(s) != signbit(c)) {
			ss = s - c;
			cc = -cos(x+x)/ss;
		} else {
			cc = s + c;
			ss = -cos(x+x)/cc;
		}
	/*
	 * j0(x) = 1/sqrt(pi*x) * (P(0,x)*cc - Q(0,x)*ss)
	 * y0(x) = 1/sqrt(pi*x) * (P(0,x)*ss + Q(0,x)*cc)
	 */
		if (x > 1.0e40)
		    z = (invsqrtpi*ss)/sqrt(x);
		else
		    z =  invsqrtpi*(pzero(x)*ss+qzero(x)*cc)/sqrt(x);
		if (x > X_TLOSS)
		    return (_SVID_libm_err(x, z, 35));
		else
		    return (z);

	}
	if (x <= tiny) {
	    return (u0[0] + tpi*log(x));
	}
	z = x*x;
	for (u = u0[12], i = 11; i >= 0; i--) u = u*z + u0[i];
	v = v0[0]+z*(v0[1]+z*(v0[2]+z*(v0[3]+z*v0[4])));
	return (u/v + tpi*(j0(x)*log(x)));
}

static const GENERIC pr[7] = {	/* [8 -- inf]  pzero 6550 */
	.4861344183386052721391238447e5,
	.1377662549407112278133438945e6,
	.1222466364088289731869114004e6,
	.4107070084315176135583353374e5,
	.5026073801860637125889039915e4,
	.1783193659125479654541542419e3,
	.88010344055383421691677564e0,
};
static const GENERIC ps[7] = {	/* [8 -- inf] pzero 6550 */
	.4861344183386052721414037058e5,
	.1378196632630384670477582699e6,
	.1223967185341006542748936787e6,
	.4120150243795353639995862617e5,
	.5068271181053546392490184353e4,
	.1829817905472769960535671664e3,
	1.0,
};
static const GENERIC huge    = 1.0e10;

static GENERIC
pzero(GENERIC x) {
	GENERIC s, r, t, z;
	int i;
	if (x > huge)
		return (one);
	t = eight/x; z = t*t;
	r = pr[5]+z*pr[6];
	s = ps[5]+z;
	for (i = 4; i >= 0; i--) {
	    r = r*z + pr[i];
	    s = s*z + ps[i];
	}
	return (r/s);
}

static const GENERIC qr[7] = {	/* [8 -- inf]  qzero 6950 */
	-.1731210995701068539185611951e3,
	-.5522559165936166961235240613e3,
	-.5604935606637346590614529613e3,
	-.2200430300226009379477365011e3,
	-.323869355375648849771296746e2,
	-.14294979207907956223499258e1,
	-.834690374102384988158918e-2,
};
static const GENERIC qs[7] = {	/* [8 -- inf] qzero 6950 */
	.1107975037248683865326709645e5,
	.3544581680627082674651471873e5,
	.3619118937918394132179019059e5,
	.1439895563565398007471485822e5,
	.2190277023344363955930226234e4,
	.106695157020407986137501682e3,
	1.0,
};

static GENERIC
qzero(GENERIC x) {
	GENERIC s, r, t, z;
	int i;
	if (x > huge)
		return (-0.125/x);
	t = eight/x; z = t*t;
	r = qr[5]+z*qr[6];
	s = qs[5]+z;
	for (i = 4; i >= 0; i--) {
	    r = r*z + qr[i];
	    s = s*z + qs[i];
	}
	return (t*(r/s));
}
