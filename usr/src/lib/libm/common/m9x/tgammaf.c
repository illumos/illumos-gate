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

#pragma weak __tgammaf = tgammaf

/*
 * True gamma function
 *
 * float tgammaf(float x)
 *
 * Algorithm: see tgamma.c
 *
 * Maximum error observed: 0.87ulp (both positive and negative arguments)
 */

#include "libm.h"
#include <math.h>
#if defined(__SUNPRO_C)
#include <sunmath.h>
#endif
#include <sys/isa_defs.h>

#if defined(_BIG_ENDIAN)
#define	HIWORD	0
#define	LOWORD	1
#else
#define	HIWORD	1
#define	LOWORD	0
#endif
#define	__HI(x)	((int *) &x)[HIWORD]
#define	__LO(x)	((unsigned *) &x)[LOWORD]

/* Coefficients for primary intervals GTi() */
static const double cr[] = {
	/* p1 */
	+7.09087253435088360271451613398019280077561279443e-0001,
	-5.17229560788652108545141978238701790105241761089e-0001,
	+5.23403394528150789405825222323770647162337764327e-0001,
	-4.54586308717075010784041566069480411732634814899e-0001,
	+4.20596490915239085459964590559256913498190955233e-0001,
	-3.57307589712377520978332185838241458642142185789e-0001,

	/* p2 */
	+4.28486983980295198166056119223984284434264344578e-0001,
	-1.30704539487709138528680121627899735386650103914e-0001,
	+1.60856285038051955072861219352655851542955430871e-0001,
	-9.22285161346010583774458802067371182158937943507e-0002,
	+7.19240511767225260740890292605070595560626179357e-0002,
	-4.88158265593355093703112238534484636193260459574e-0002,

	/* p3 */
	+3.82409531118807759081121479786092134814808872880e-0001,
	+2.65309888180188647956400403013495759365167853426e-0002,
	+8.06815109775079171923561169415370309376296739835e-0002,
	-1.54821591666137613928840890835174351674007764799e-0002,
	+1.76308239242717268530498313416899188157165183405e-0002,

	/* GZi and TZi */
	+0.9382046279096824494097535615803269576988,	/* GZ1 */
	+0.8856031944108887002788159005825887332080,	/* GZ2 */
	+0.9367814114636523216188468970808378497426,	/* GZ3 */
	-0.3517214357852935791015625,	/* TZ1 */
	+0.280530631542205810546875,	/* TZ3 */
};

#define	P10	cr[0]
#define	P11	cr[1]
#define	P12	cr[2]
#define	P13	cr[3]
#define	P14	cr[4]
#define	P15	cr[5]
#define	P20	cr[6]
#define	P21	cr[7]
#define	P22	cr[8]
#define	P23	cr[9]
#define	P24	cr[10]
#define	P25	cr[11]
#define	P30	cr[12]
#define	P31	cr[13]
#define	P32	cr[14]
#define	P33	cr[15]
#define	P34	cr[16]
#define	GZ1	cr[17]
#define	GZ2	cr[18]
#define	GZ3	cr[19]
#define	TZ1	cr[20]
#define	TZ3	cr[21]

/* compute gamma(y) for y in GT1 = [1.0000, 1.2845] */
static double
GT1(double y) {
	double z, r;

	z = y * y;
	r = TZ1 * y + z * ((P10 + y * P11 + z * P12) + (z * y) * (P13 + y *
		P14 + z * P15));
	return (GZ1 + r);
}

/* compute gamma(y) for y in GT2 = [1.2844, 1.6374] */
static double
GT2(double y) {
	double z;

	z = y * y;
	return (GZ2 + z * ((P20 + y * P21 + z * P22) + (z * y) * (P23 + y *
		P24 + z * P25)));
}

/* compute gamma(y) for y in GT3 = [1.6373, 2.0000] */
static double
GT3(double y) {
double z, r;

	z = y * y;
	r = TZ3 * y + z * ((P30 + y * P31 + z * P32) + (z * y) * (P33 + y *
		P34));
	return (GZ3 + r);
}

/* INDENT OFF */
static const double c[] = {
+1.0,
+2.0,
+0.5,
+1.0e-300,
+6.666717231848518054693623697539230e-0001,			/* A1=T3[0] */
+8.33333330959694065245736888749042811909994573178e-0002,	/* GP[0] */
-2.77765545601667179767706600890361535225507762168e-0003,	/* GP[1] */
+7.77830853479775281781085278324621033523037489883e-0004,	/* GP[2] */
+4.18938533204672741744150788368695779923320328369e-0001,	/* hln2pi   */
+2.16608493924982901946e-02,					/* ln2_32 */
+4.61662413084468283841e+01,					/* invln2_32 */
+5.00004103388988968841156421415669985414073453720e-0001,	/* Et1 */
+1.66667656752800761782778277828110208108687545908e-0001,	/* Et2 */
};

#define	one		c[0]
#define	two		c[1]
#define	half		c[2]
#define	tiny		c[3]
#define	A1		c[4]
#define	GP0		c[5]
#define	GP1		c[6]
#define	GP2		c[7]
#define	hln2pi		c[8]
#define	ln2_32		c[9]
#define	invln2_32	c[10]
#define	Et1		c[11]
#define	Et2		c[12]

/* S[j] = 2**(j/32.) for the final computation of exp(w) */
static const double S[] = {
+1.00000000000000000000e+00,	/* 3FF0000000000000 */
+1.02189714865411662714e+00,	/* 3FF059B0D3158574 */
+1.04427378242741375480e+00,	/* 3FF0B5586CF9890F */
+1.06714040067682369717e+00,	/* 3FF11301D0125B51 */
+1.09050773266525768967e+00,	/* 3FF172B83C7D517B */
+1.11438674259589243221e+00,	/* 3FF1D4873168B9AA */
+1.13878863475669156458e+00,	/* 3FF2387A6E756238 */
+1.16372485877757747552e+00,	/* 3FF29E9DF51FDEE1 */
+1.18920711500272102690e+00,	/* 3FF306FE0A31B715 */
+1.21524735998046895524e+00,	/* 3FF371A7373AA9CB */
+1.24185781207348400201e+00,	/* 3FF3DEA64C123422 */
+1.26905095719173321989e+00,	/* 3FF44E086061892D */
+1.29683955465100964055e+00,	/* 3FF4BFDAD5362A27 */
+1.32523664315974132322e+00,	/* 3FF5342B569D4F82 */
+1.35425554693689265129e+00,	/* 3FF5AB07DD485429 */
+1.38390988196383202258e+00,	/* 3FF6247EB03A5585 */
+1.41421356237309514547e+00,	/* 3FF6A09E667F3BCD */
+1.44518080697704665027e+00,	/* 3FF71F75E8EC5F74 */
+1.47682614593949934623e+00,	/* 3FF7A11473EB0187 */
+1.50916442759342284141e+00,	/* 3FF82589994CCE13 */
+1.54221082540794074411e+00,	/* 3FF8ACE5422AA0DB */
+1.57598084510788649659e+00,	/* 3FF93737B0CDC5E5 */
+1.61049033194925428347e+00,	/* 3FF9C49182A3F090 */
+1.64575547815396494578e+00,	/* 3FFA5503B23E255D */
+1.68179283050742900407e+00,	/* 3FFAE89F995AD3AD */
+1.71861929812247793414e+00,	/* 3FFB7F76F2FB5E47 */
+1.75625216037329945351e+00,	/* 3FFC199BDD85529C */
+1.79470907500310716820e+00,	/* 3FFCB720DCEF9069 */
+1.83400808640934243066e+00,	/* 3FFD5818DCFBA487 */
+1.87416763411029996256e+00,	/* 3FFDFC97337B9B5F */
+1.91520656139714740007e+00,	/* 3FFEA4AFA2A490DA */
+1.95714412417540017941e+00,	/* 3FFF50765B6E4540 */
};
/* INDENT ON */

/* INDENT OFF */
/*
 * return tgammaf(x) in double for 8<x<=35.040096283... using Stirling's formula
 *     log(G(x)) ~= (x-.5)*(log(x)-1) + .5(log(2*pi)-1) + (1/x)*P(1/(x*x))
 */
/*
 * compute ss = log(x)-1
 *
 *  log(x) - 1 = T1(n) + T2(j) + T3(s), where x = 2**n * y,  1<=y<2,
 *  j=[64*y], z[j]=1+j/64+1/128, s = (y-z[j])/(y+z[j]), and
 *       T1(n-3) = n*log(2)-1,  n=3,4,5
 *       T2(j) = log(z[j]),
 *       T3(s) = 2s + A1*s^3
 *  Note
 *  (1) Remez error for T3(s) is bounded by 2**(-35.8)
 *	(see mpremez/work/Log/tgamma_log_2_outr1)
 */

static const double T1[] = { /* T1[j]=(j+3)*log(2)-1 */
+1.079441541679835928251696364375e+00,
+1.772588722239781237668928485833e+00,
+2.465735902799726547086160607291e+00,
};

static const double T2[] = {   /* T2[j]=log(1+j/64+1/128) */
+7.782140442054948947462900061137e-03,
+2.316705928153437822879916096229e-02,
+3.831886430213659919375532512380e-02,
+5.324451451881228286587019378653e-02,
+6.795066190850774939456527777263e-02,
+8.244366921107459126816006866831e-02,
+9.672962645855111229557105648746e-02,
+1.108143663402901141948061693232e-01,
+1.247034785009572358634065153809e-01,
+1.384023228591191356853258736016e-01,
+1.519160420258419750718034248969e-01,
+1.652495728953071628756114492772e-01,
+1.784076574728182971194002415109e-01,
+1.913948529996294546092988075613e-01,
+2.042155414286908915038203861962e-01,
+2.168739383006143596190895257443e-01,
+2.293741010648458299914807250461e-01,
+2.417199368871451681443075159135e-01,
+2.539152099809634441373232979066e-01,
+2.659635484971379413391259265375e-01,
+2.778684510034563061863500329234e-01,
+2.896332925830426768788930555257e-01,
+3.012613305781617810128755382338e-01,
+3.127557100038968883862465596883e-01,
+3.241194686542119760906707604350e-01,
+3.353555419211378302571795798142e-01,
+3.464667673462085809184621884258e-01,
+3.574558889218037742260094901409e-01,
+3.683255611587076530482301540504e-01,
+3.790783529349694583908533456310e-01,
+3.897167511400252133704636040035e-01,
+4.002431641270127069293251019951e-01,
+4.106599249852683859343062031758e-01,
+4.209692946441296361288671615068e-01,
+4.311734648183713408591724789556e-01,
+4.412745608048752294894964416613e-01,
+4.512746441394585851446923830790e-01,
+4.611757151221701663679999255979e-01,
+4.709797152187910125468978560564e-01,
+4.806885293457519076766184554480e-01,
+4.903039880451938381503461596457e-01,
+4.998278695564493298213314152470e-01,
+5.092619017898079468040749192283e-01,
+5.186077642080456321529769963648e-01,
+5.278670896208423851138922177783e-01,
+5.370414658968836545667292441538e-01,
+5.461324375981356503823972092312e-01,
+5.551415075405015927154803595159e-01,
+5.640701382848029660713842900902e-01,
+5.729197535617855090927567266263e-01,
+5.816917396346224825206107537254e-01,
+5.903874466021763746419167081236e-01,
+5.990081896460833993816000244617e-01,
+6.075552502245417955010851527911e-01,
+6.160298772155140196475659281967e-01,
+6.244332880118935010425387440547e-01,
+6.327666695710378295457864685036e-01,
+6.410311794209312910556013344054e-01,
+6.492279466251098188908399699053e-01,
+6.573580727083600301418900232459e-01,
+6.654226325450904489500926100067e-01,
+6.734226752121667202979603888010e-01,
+6.813592248079030689480715595681e-01,
+6.892332812388089803249143378146e-01,
};
/* INDENT ON */

static double
large_gam(double x) {
	double ss, zz, z, t1, t2, w, y, u;
	unsigned lx;
	int k, ix, j, m;

	ix = __HI(x);
	lx = __LO(x);
	m = (ix >> 20) - 0x3ff;			/* exponent of x, range:3-5 */
	ix = (ix & 0x000fffff) | 0x3ff00000;	/* y = scale x to [1,2] */
	__HI(y) = ix;
	__LO(y) = lx;
	__HI(z) = (ix & 0xffffc000) | 0x2000;	/* z[j]=1+j/64+1/128 */
	__LO(z) = 0;
	j = (ix >> 14) & 0x3f;
	t1 = y + z;
	t2 = y - z;
	u = t2 / t1;
	ss = T1[m - 3] + T2[j] + u * (two + A1 * (u * u));
							/* ss = log(x)-1 */
	/*
	 * compute ww = (x-.5)*(log(x)-1) + .5*(log(2pi)-1) + 1/x*(P(1/x^2)))
	 * where ss = log(x) - 1
	 */
	z = one / x;
	zz = z * z;
	w = ((x - half) * ss + hln2pi) + z * (GP0 + zz * GP1 + (zz * zz) * GP2);
	k = (int) (w * invln2_32 + half);

	/* compute the exponential of w */
	j = k & 0x1f;
	m = k >> 5;
	z = w - (double) k *ln2_32;
	zz = S[j] * (one + z + (z * z) * (Et1 + z * Et2));
	__HI(zz) += m << 20;
	return (zz);
}
/* INDENT OFF */
/*
 * kpsin(x)= sin(pi*x)/pi
 *                 3        5        7        9
 *	= x+ks[0]*x +ks[1]*x +ks[2]*x +ks[3]*x
 */
static const double ks[] = {
-1.64493404985645811354476665052005342839447790544e+0000,
+8.11740794458351064092797249069438269367389272270e-0001,
-1.90703144603551216933075809162889536878854055202e-0001,
+2.55742333994264563281155312271481108635575331201e-0002,
};
/* INDENT ON */

static double
kpsin(double x) {
	double z;

	z = x * x;
	return (x + (x * z) * ((ks[0] + z * ks[1]) + (z * z) * (ks[2] + z *
		ks[3])));
}

/* INDENT OFF */
/*
 * kpcos(x)= cos(pi*x)/pi
 *                     2        4        6
 *	= kc[0]+kc[1]*x +kc[2]*x +kc[3]*x
 */
static const double kc[] = {
+3.18309886183790671537767526745028724068919291480e-0001,
-1.57079581447762568199467875065854538626594937791e+0000,
+1.29183528092558692844073004029568674027807393862e+0000,
-4.20232949771307685981015914425195471602739075537e-0001,
};
/* INDENT ON */

static double
kpcos(double x) {
	double z;

	z = x * x;
	return (kc[0] + z * (kc[1] + z * kc[2] + (z * z) * kc[3]));
}

/* INDENT OFF */
static const double
t0z1 = 0.134861805732790769689793935774652917006,
t0z2 = 0.461632144968362341262659542325721328468,
t0z3 = 0.819773101100500601787868704921606996312;
	/* 1.134861805732790769689793935774652917006 */
/* INDENT ON */

/*
 * gamma(x+i) for 0 <= x < 1
 */
static double
gam_n(int i, double x) {
	double rr = 0.0L, yy;
	double z1, z2;

	/* compute yy = gamma(x+1) */
	if (x > 0.2845) {
		if (x > 0.6374)
			yy = GT3(x - t0z3);
		else
			yy = GT2(x - t0z2);
	} else
		yy = GT1(x - t0z1);

	/* compute gamma(x+i) = (x+i-1)*...*(x+1)*yy, 0<i<8 */
	switch (i) {
	case 0:		/* yy/x */
		rr = yy / x;
		break;
	case 1:		/* yy */
		rr = yy;
		break;
	case 2:		/* (x+1)*yy */
		rr = (x + one) * yy;
		break;
	case 3:		/* (x+2)*(x+1)*yy */
		rr = (x + one) * (x + two) * yy;
		break;

	case 4:		/* (x+1)*(x+3)*(x+2)*yy */
		rr = (x + one) * (x + two) * ((x + 3.0) * yy);
		break;
	case 5:		/* ((x+1)*(x+4)*(x+2)*(x+3))*yy */
		z1 = (x + two) * (x + 3.0) * yy;
		z2 = (x + one) * (x + 4.0);
		rr = z1 * z2;
		break;
	case 6:		/* ((x+1)*(x+2)*(x+3)*(x+4)*(x+5))*yy */
		z1 = (x + two) * (x + 3.0);
		z2 = (x + 5.0) * yy;
		rr = z1 * (z1 - two) * z2;
		break;
	case 7:		/* ((x+1)*(x+2)*(x+3)*(x+4)*(x+5)*(x+6))*yy */
		z1 = (x + two) * (x + 3.0);
		z2 = (x + 5.0) * (x + 6.0) * yy;
		rr = z1 * (z1 - two) * z2;
		break;
	}
	return (rr);
}

float
tgammaf(float xf) {
	float zf;
	double ss, ww;
	double x, y, z;
	int i, j, k, ix, hx, xk;

	hx = *(int *) &xf;
	ix = hx & 0x7fffffff;

	x = (double) xf;
	if (ix < 0x33800000)
		return (1.0F / xf);	/* |x| < 2**-24 */

	if (ix >= 0x7f800000)
		return (xf * ((hx < 0)? 0.0F : xf)); /* +-Inf or NaN */

	if (hx > 0x420C290F) 	/* x > 35.040096283... overflow */
		return (float)(x / tiny);

	if (hx >= 0x41000000)	/* x >= 8 */
		return ((float) large_gam(x));

	if (hx > 0) {		/* 0 < x < 8 */
		i = (int) xf;
		return ((float) gam_n(i, x - (double) i));
	}

	/* negative x */
	/* INDENT OFF */
	/*
	 * compute xk =
	 *	-2 ... x is an even int (-inf is considered even)
	 *	-1 ... x is an odd int
	 *	+0 ... x is not an int but chopped to an even int
	 *	+1 ... x is not an int but chopped to an odd int
	 */
	/* INDENT ON */
	xk = 0;
	if (ix >= 0x4b000000) {
		if (ix > 0x4b000000)
			xk = -2;
		else
			xk = -2 + (ix & 1);
	} else if (ix >= 0x3f800000) {
		k = (ix >> 23) - 0x7f;
		j = ix >> (23 - k);
		if ((j << (23 - k)) == ix)
			xk = -2 + (j & 1);
		else
			xk = j & 1;
	}
	if (xk < 0) {
		/* 0/0 invalid NaN, ideally gamma(-n)= (-1)**(n+1) * inf */
		zf = xf - xf;
		return (zf / zf);
	}

	/* negative underflow thresold */
	if (ix > 0x4224000B) {	/* x < -(41+11ulp) */
		if (xk == 0)
			z = -tiny;
		else
			z = tiny;
		return ((float)z);
	}

	/* INDENT OFF */
	/* now compute gamma(x) by  -1/((sin(pi*y)/pi)*gamma(1+y)), y = -x */
	/*
	 * First compute ss = -sin(pi*y)/pi , so that
	 * gamma(x) = 1/(ss*gamma(1+y))
	 */
	/* INDENT ON */
	y = -x;
	j = (int) y;
	z = y - (double) j;
	if (z > 0.3183098861837906715377675)
		if (z > 0.6816901138162093284622325)
			ss = kpsin(one - z);
		else
			ss = kpcos(0.5 - z);
	else
		ss = kpsin(z);
	if (xk == 0)
		ss = -ss;

	/* Then compute ww = gamma(1+y)  */
	if (j < 7)
		ww = gam_n(j + 1, z);
	else
		ww = large_gam(y + one);

	/* return 1/(ss*ww) */
	return ((float) (one / (ww * ss)));
}
