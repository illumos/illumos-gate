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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */
/*
 * Copyright 2011 Jason King.  All rights reserved
 */

/*
 * Generic XDR routines impelmentation.
 *
 * These are the "floating point" xdr routines used to (de)serialize
 * most common data items.  See xdr.h for more info on the interface to
 * xdr.
 */

#include "mt.h"
#include <sys/types.h>
#include <stdio.h>
#include <rpc/types.h>
#include <rpc/xdr.h>

#if defined(_IEEE_754)
static bool_t ieee_float_to_xdr(XDR *, float *);
static bool_t ieee_xdr_to_float(XDR *, float *);
static bool_t ieee_double_to_xdr(XDR *, double *);
static bool_t ieee_xdr_to_double(XDR *, double *);
#define	cvt_float_to_xdr ieee_float_to_xdr
#define	cvt_xdr_to_float ieee_xdr_to_float
#define	cvt_double_to_xdr ieee_double_to_xdr
#define	cvt_xdr_to_double ieee_xdr_to_double
#else
#warning No platform specific float and double conversion routines defined
static bool_t def_float_to_xdr(XDR *, float *);
static bool_t def_xdr_to_float(XDR *, float *);
static bool_t def_double_to_xdr(XDR *, double *);
static bool_t def_xdr_to_double(XDR *, double *);
#define	cvt_float_to_xdr def_float_to_xdr
#define	cvt_xdr_to_float def_xdr_to_float
#define	cvt_double_to_xdr def_double_to_xdr
#define	cvt_xdr_to_double def_xdr_to_double
#endif

bool_t
xdr_float(XDR *xdrs, float *fp)
{
	switch (xdrs->x_op) {

	case XDR_ENCODE:
		return (cvt_float_to_xdr(xdrs, fp));

	case XDR_DECODE:
		return (cvt_xdr_to_float(xdrs, fp));

	case XDR_FREE:
		return (TRUE);
	}
	return (FALSE);
}

bool_t
xdr_double(XDR *xdrs, double *dp)
{
	switch (xdrs->x_op) {

	case XDR_ENCODE:
		return (cvt_double_to_xdr(xdrs, dp));

	case XDR_DECODE:
		return (cvt_xdr_to_double(xdrs, dp));

	case XDR_FREE:
		return (TRUE);
	}

	return (FALSE);
}

/* ARGSUSED */
bool_t
xdr_quadruple(XDR *xdrs, long double *fp)
{
/*
 * The Sparc uses IEEE FP encoding, so just do a byte copy
 */

#if !defined(sparc)
	return (FALSE);
#else
	switch (xdrs->x_op) {
	case XDR_ENCODE:
		return (XDR_PUTBYTES(xdrs, (char *)fp, sizeof (long double)));
	case XDR_DECODE:
		return (XDR_GETBYTES(xdrs, (char *)fp, sizeof (long double)));
	case XDR_FREE:
		return (TRUE);
	}
	return (FALSE);
#endif
}

#if defined(_IEEE_754)

/*
 * Over-the-wire format is IEEE, so just copy.  Includes CPUs:
 * amd64, i386, sparc, sparcv9
 */

static bool_t
ieee_float_to_xdr(XDR *xdrs, float *fp)
{
	return (XDR_PUTBYTES(xdrs, (char *)fp, sizeof (float)));
}

static bool_t
ieee_xdr_to_float(XDR *xdrs, float *fp)
{
	return (XDR_GETBYTES(xdrs, (char *)fp, sizeof (float)));
}

static bool_t
ieee_double_to_xdr(XDR *xdrs, double *dp)
{
	return (XDR_PUTBYTES(xdrs, (char *)dp, sizeof (double)));
}

static bool_t
ieee_xdr_to_double(XDR *xdrs, double *dp)
{
	return (XDR_GETBYTES(xdrs, (char *)dp, sizeof (double)));
}

#else /* !defined (_IEEE_794) */

static bool_t
def_float_to_xdr(XDR *xdrs, float *fp)
{
	/*
	 * Every machine can do this, its just not very efficient.
	 * In addtion, some rounding errors may occur do to the
	 * calculations involved.
	 */
	float f;
	int neg = 0;
	int exp = 0;
	int32_t val;

	f = *fp;
	if (f == 0) {
		val = 0;
		return (XDR_PUTINT32(xdrs, &val));
	}
	if (f < 0) {
		f = 0 - f;
		neg = 1;
	}
	while (f < 1) {
		f = f * 2;
		--exp;
	}
	while (f >= 2) {
		f = f/2;
		++exp;
	}
	if ((exp > 128) || (exp < -127)) {
		/* over or under flowing ieee exponent */
		return (FALSE);
	}
	val = neg;
	val = val << 8;		/* for the exponent */
	val += 127 + exp;	/* 127 is the bias */
	val = val << 23;	/* for the mantissa */
	val += (int32_t)((f - 1) * 8388608);	/* 2 ^ 23 */
	return (XDR_PUTINT32(xdrs, &val));
}

static bool_t
def_xdr_to_float(XDR *xdrs, float *fp)
{
	/*
	 * Every machine can do this, its just not very
	 * efficient.  It assumes that the decoding machine's
	 * float can represent any value in the range of
	 *	ieee largest  float  = (2 ^ 128)  * 0x1.fffff
	 *	to
	 *	ieee smallest float  = (2 ^ -127) * 0x1.00000
	 * In addtion, some rounding errors may occur do to the
	 * calculations involved.
	 */
	float f;
	int neg = 0;
	int exp = 0;
	int32_t val;

	if (!XDR_GETINT32(xdrs, (int32_t *)&val))
		return (FALSE);
	neg = val & 0x80000000;
	exp = (val & 0x7f800000) >> 23;
	exp -= 127;		/* subtract exponent base */
	f = (val & 0x007fffff) * 0.00000011920928955078125;
	/* 2 ^ -23 */
	f++;

	while (exp != 0) {
		if (exp < 0) {
			f = f/2.0;
			++exp;
		} else {
			f = f * 2.0;
			--exp;
		}
	}

	if (neg)
		f = 0 - f;

	*fp = f;
	return (TRUE);
}

static bool_t
def_double_to_xdr(XDR *xdrs, double *dp)
{
	/*
	 * Every machine can do this, its just not very efficient.
	 * In addtion, some rounding errors may occur do to the
	 * calculations involved.
	 */

	int *lp;
	double d;
	int neg = 0;
	int exp = 0;
	int32_t val[2];

	d = *dp;
	if (d == 0) {
		val[0] = 0;
		val[1] = 0;
		lp = val;
		return (XDR_PUTINT32(xdrs, lp++) && XDR_PUTINT32(xdrs, lp));
	}
	if (d < 0) {
		d = 0 - d;
		neg = 1;
	}
	while (d < 1) {
		d = d * 2;
		--exp;
	}
	while (d >= 2) {
		d = d/2;
		++exp;
	}
	if ((exp > 1024) || (exp < -1023)) {
		/* over or under flowing ieee exponent */
		return (FALSE);
	}
	val[0] = neg;
	val[0] = val[0] << 11;	/* for the exponent */
	val[0] += 1023 + exp;	/* 1023 is the bias */
	val[0] = val[0] << 20;	/* for the mantissa */
	val[0] += (int32_t)((d - 1) * 1048576);	/* 2 ^ 20 */
	val[1] += (int32_t)((((d - 1) * 1048576) - val[0]) * 4294967296);
	/* 2 ^ 32 */
	lp = val;

	return (XDR_PUTINT32(xdrs, lp++) && XDR_PUTINT32(xdrs, lp));
}

static bool_t
def_xdr_to_double(XDR *, double *dp)
{
	/*
	 * Every machine can do this, its just not very
	 * efficient.  It assumes that the decoding machine's
	 * double can represent any value in the range of
	 *	ieee largest  double  = (2 ^ 1024)  * 0x1.fffffffffffff
	 *	to
	 *	ieee smallest double  = (2 ^ -1023) * 0x1.0000000000000
	 * In addtion, some rounding errors may occur do to the
	 * calculations involved.
	 */
	int *lp;
	double d;
	int neg = 0;
	int exp = 0;
	int32_t val[2];

	lp = val;
	if (!XDR_GETINT32(xdrs, lp++) || !XDR_GETINT32(xdrs, lp))
		return (FALSE);
	neg = val[0] & 0x80000000;
	exp = (val[0] & 0x7ff00000) >> 20;
	exp -= 1023;		/* subtract exponent base */
	d = (val[0] & 0x000fffff) * 0.00000095367431640625;
	/* 2 ^ -20 */
	d += (val[1] * 0.0000000000000002220446049250313);
	/* 2 ^ -52 */
	d++;
	while (exp != 0) {
		if (exp < 0) {
			d = d/2.0;
			++exp;
		} else {
			d = d * 2.0;
			--exp;
		}
	}
	if (neg)
		d = 0 - d;

	*dp = d;
	return (TRUE);
}

#endif /* _IEEE_794 */
