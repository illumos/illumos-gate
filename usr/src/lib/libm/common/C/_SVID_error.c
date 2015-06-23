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

#include "libm.h"
#include "xpg6.h"	/* __xpg6 */
#include <stdio.h>
#include <float.h>		/* DBL_MAX, DBL_MIN */
#include <unistd.h>		/* write */
#if defined(__x86)
#include <ieeefp.h>
#undef	fp_class
#define	fp_class	fpclass
#define	fp_quiet	FP_QNAN
#endif
#include <errno.h>
#undef fflush
#include <sys/isa_defs.h>

/* INDENT OFF */
/*
 * Report libm exception error according to System V Interface Definition
 * (SVID).
 * Error mapping:
 *	1 -- acos(|x|>1)
 *	2 -- asin(|x|>1)
 *	3 -- atan2(+-0,+-0)
 *	4 -- hypot overflow
 *	5 -- cosh overflow
 *	6 -- exp overflow
 *	7 -- exp underflow
 *	8 -- y0(0)
 *	9 -- y0(-ve)
 *	10-- y1(0)
 *	11-- y1(-ve)
 *	12-- yn(0)
 *	13-- yn(-ve)
 *	14-- lgamma(finite) overflow
 *	15-- lgamma(-integer)
 *	16-- log(0)
 *	17-- log(x<0)
 *	18-- log10(0)
 *	19-- log10(x<0)
 *	20-- pow(0.0,0.0)
 *	21-- pow(x,y) overflow
 *	22-- pow(x,y) underflow
 *	23-- pow(0,negative)
 *	24-- pow(neg,non-integral)
 *	25-- sinh(finite) overflow
 *	26-- sqrt(negative)
 *	27-- fmod(x,0)
 *	28-- remainder(x,0)
 *	29-- acosh(x<1)
 *	30-- atanh(|x|>1)
 *	31-- atanh(|x|=1)
 *	32-- scalb overflow
 *	33-- scalb underflow
 *	34-- j0(|x|>X_TLOSS)
 *	35-- y0(x>X_TLOSS)
 *	36-- j1(|x|>X_TLOSS)
 *	37-- y1(x>X_TLOSS)
 *	38-- jn(|x|>X_TLOSS, n)
 *	39-- yn(x>X_TLOSS, n)
 *	40-- gamma(finite) overflow
 *	41-- gamma(-integer)
 *	42-- pow(NaN,0.0) return NaN for SVID/XOPEN
 *	43-- log1p(-1)
 *	44-- log1p(x<-1)
 *	45-- logb(0)
 *	46-- nextafter overflow
 *	47-- scalb(x,inf)
 */
/* INDENT ON */

static double setexception(int, double);

static const union {
	unsigned	x[2];
	double		d;
} C[] = {
#ifdef _LITTLE_ENDIAN
	{ 0xffffffff, 0x7fffffff },
	{ 0x54442d18, 0x400921fb },
#else
	{ 0x7fffffff, 0xffffffff },
	{ 0x400921fb, 0x54442d18 },
#endif
};

#define	NaN	C[0].d
#define	PI_RZ	C[1].d

#define	__HI(x)	((unsigned *)&x)[HIWORD]
#define	__LO(x)	((unsigned *)&x)[LOWORD]
#undef	Inf
#define	Inf	HUGE_VAL

double
_SVID_libm_err(double x, double y, int type) {
	struct exception	exc;
	double			t, w, ieee_retval = 0;
	enum version		lib_version = _lib_version;
	int			iy;

	/* force libm_ieee behavior in SUSv3 mode */
	if ((__xpg6 & _C99SUSv3_math_errexcept) != 0)
		lib_version = libm_ieee;
	if (lib_version == c_issue_4) {
		(void) fflush(stdout);
	}
	exc.arg1 = x;
	exc.arg2 = y;
	switch (type) {
	case 1:
		/* acos(|x|>1) */
		exc.type = DOMAIN;
		exc.name = "acos";
		ieee_retval = setexception(3, 1.0);
		exc.retval = 0.0;
		if (lib_version == strict_ansi) {
			errno = EDOM;
		} else if (!matherr(&exc)) {
			if (lib_version == c_issue_4) {
				(void) write(2, "acos: DOMAIN error\n", 19);
			}
			errno = EDOM;
		}
		break;
	case 2:
		/* asin(|x|>1) */
		exc.type = DOMAIN;
		exc.name = "asin";
		exc.retval = 0.0;
		ieee_retval = setexception(3, 1.0);
		if (lib_version == strict_ansi) {
			errno = EDOM;
		} else if (!matherr(&exc)) {
			if (lib_version == c_issue_4) {
				(void) write(2, "asin: DOMAIN error\n", 19);
			}
			errno = EDOM;
		}
		break;
	case 3:
		/* atan2(+-0,+-0) */
		exc.arg1 = y;
		exc.arg2 = x;
		exc.type = DOMAIN;
		exc.name = "atan2";
		ieee_retval = copysign(1.0, x) == 1.0 ? y :
			copysign(PI_RZ + DBL_MIN, y);
		exc.retval = 0.0;
		if (lib_version == strict_ansi) {
			errno = EDOM;
		} else if (!matherr(&exc)) {
			if (lib_version == c_issue_4) {
				(void) write(2, "atan2: DOMAIN error\n", 20);
			}
			errno = EDOM;
		}
		break;
	case 4:
		/* hypot(finite,finite) overflow */
		exc.type = OVERFLOW;
		exc.name = "hypot";
		ieee_retval = Inf;
		if (lib_version == c_issue_4)
			exc.retval = HUGE;
		else
			exc.retval = HUGE_VAL;
		if (lib_version == strict_ansi)
			errno = ERANGE;
		else if (!matherr(&exc))
			errno = ERANGE;
		break;
	case 5:
		/* cosh(finite) overflow */
		exc.type = OVERFLOW;
		exc.name = "cosh";
		ieee_retval = setexception(2, 1.0);
		if (lib_version == c_issue_4)
			exc.retval = HUGE;
		else
			exc.retval = HUGE_VAL;
		if (lib_version == strict_ansi)
			errno = ERANGE;
		else if (!matherr(&exc))
			errno = ERANGE;
		break;
	case 6:
		/* exp(finite) overflow */
		exc.type = OVERFLOW;
		exc.name = "exp";
		ieee_retval = setexception(2, 1.0);
		if (lib_version == c_issue_4)
			exc.retval = HUGE;
		else
			exc.retval = HUGE_VAL;
		if (lib_version == strict_ansi)
			errno = ERANGE;
		else if (!matherr(&exc))
			errno = ERANGE;
		break;
	case 7:
		/* exp(finite) underflow */
		exc.type = UNDERFLOW;
		exc.name = "exp";
		ieee_retval = setexception(1, 1.0);
		exc.retval = 0.0;
		if (lib_version == strict_ansi)
			errno = ERANGE;
		else if (!matherr(&exc))
			errno = ERANGE;
		break;
	case 8:
		/* y0(0) = -inf */
		exc.type = DOMAIN;	/* should be SING for IEEE */
		exc.name = "y0";
		ieee_retval = setexception(0, -1.0);
		if (lib_version == c_issue_4)
			exc.retval = -HUGE;
		else
			exc.retval = -HUGE_VAL;
		if (lib_version == strict_ansi) {
			errno = EDOM;
		} else if (!matherr(&exc)) {
			if (lib_version == c_issue_4) {
				(void) write(2, "y0: DOMAIN error\n", 17);
			}
			errno = EDOM;
		}
		break;
	case 9:
		/* y0(x<0) = NaN */
		exc.type = DOMAIN;
		exc.name = "y0";
		ieee_retval = setexception(3, 1.0);
		if (lib_version == c_issue_4)
			exc.retval = -HUGE;
		else
			exc.retval = -HUGE_VAL;
		if (lib_version == strict_ansi) {
			errno = EDOM;
		} else if (!matherr(&exc)) {
			if (lib_version == c_issue_4) {
				(void) write(2, "y0: DOMAIN error\n", 17);
			}
			errno = EDOM;
		}
		break;
	case 10:
		/* y1(0) = -inf */
		exc.type = DOMAIN;	/* should be SING for IEEE */
		exc.name = "y1";
		ieee_retval = setexception(0, -1.0);
		if (lib_version == c_issue_4)
			exc.retval = -HUGE;
		else
			exc.retval = -HUGE_VAL;
		if (lib_version == strict_ansi) {
			errno = EDOM;
		} else if (!matherr(&exc)) {
			if (lib_version == c_issue_4) {
				(void) write(2, "y1: DOMAIN error\n", 17);
			}
			errno = EDOM;
		}
		break;
	case 11:
		/* y1(x<0) = NaN */
		exc.type = DOMAIN;
		exc.name = "y1";
		ieee_retval = setexception(3, 1.0);
		if (lib_version == c_issue_4)
			exc.retval = -HUGE;
		else
			exc.retval = -HUGE_VAL;
		if (lib_version == strict_ansi) {
			errno = EDOM;
		} else if (!matherr(&exc)) {
			if (lib_version == c_issue_4) {
				(void) write(2, "y1: DOMAIN error\n", 17);
			}
			errno = EDOM;
		}
		break;
	case 12:
		/* yn(n,0) = -inf */
		exc.type = DOMAIN;	/* should be SING for IEEE */
		exc.name = "yn";
		ieee_retval = setexception(0, -1.0);
		if (lib_version == c_issue_4)
			exc.retval = -HUGE;
		else
			exc.retval = -HUGE_VAL;
		if (lib_version == strict_ansi) {
			errno = EDOM;
		} else if (!matherr(&exc)) {
			if (lib_version == c_issue_4) {
				(void) write(2, "yn: DOMAIN error\n", 17);
			}
			errno = EDOM;
		}
		break;
	case 13:
		/* yn(x<0) = NaN */
		exc.type = DOMAIN;
		exc.name = "yn";
		ieee_retval = setexception(3, 1.0);
		if (lib_version == c_issue_4)
			exc.retval = -HUGE;
		else
			exc.retval = -HUGE_VAL;
		if (lib_version == strict_ansi) {
			errno = EDOM;
		} else if (!matherr(&exc)) {
			if (lib_version == c_issue_4) {
				(void) write(2, "yn: DOMAIN error\n", 17);
			}
			errno = EDOM;
		}
		break;
	case 14:
		/* lgamma(finite) overflow */
		exc.type = OVERFLOW;
		exc.name = "lgamma";
		ieee_retval = setexception(2, 1.0);
		if (lib_version == c_issue_4)
			exc.retval = HUGE;
		else
			exc.retval = HUGE_VAL;
		if (lib_version == strict_ansi)
			errno = ERANGE;
		else if (!matherr(&exc))
			errno = ERANGE;
		break;
	case 15:
		/* lgamma(-integer) or lgamma(0) */
		exc.type = SING;
		exc.name = "lgamma";
		ieee_retval = setexception(0, 1.0);
		if (lib_version == c_issue_4)
			exc.retval = HUGE;
		else
			exc.retval = HUGE_VAL;
		if (lib_version == strict_ansi) {
			errno = EDOM;
		} else if (!matherr(&exc)) {
			if (lib_version == c_issue_4) {
				(void) write(2, "lgamma: SING error\n", 19);
			}
			errno = EDOM;
		}
		break;
	case 16:
		/* log(0) */
		exc.type = SING;
		exc.name = "log";
		ieee_retval = setexception(0, -1.0);
		if (lib_version == c_issue_4)
			exc.retval = -HUGE;
		else
			exc.retval = -HUGE_VAL;
		if (lib_version == strict_ansi) {
			errno = ERANGE;
		} else if (!matherr(&exc)) {
			if (lib_version == c_issue_4) {
				(void) write(2, "log: SING error\n", 16);
				errno = EDOM;
			} else {
				errno = ERANGE;
			}
		}
		break;
	case 17:
		/* log(x<0) */
		exc.type = DOMAIN;
		exc.name = "log";
		ieee_retval = setexception(3, 1.0);
		if (lib_version == c_issue_4)
			exc.retval = -HUGE;
		else
			exc.retval = -HUGE_VAL;
		if (lib_version == strict_ansi) {
			errno = EDOM;
		} else if (!matherr(&exc)) {
			if (lib_version == c_issue_4) {
				(void) write(2, "log: DOMAIN error\n", 18);
			}
			errno = EDOM;
		}
		break;
	case 18:
		/* log10(0) */
		exc.type = SING;
		exc.name = "log10";
		ieee_retval = setexception(0, -1.0);
		if (lib_version == c_issue_4)
			exc.retval = -HUGE;
		else
			exc.retval = -HUGE_VAL;
		if (lib_version == strict_ansi) {
			errno = ERANGE;
		} else if (!matherr(&exc)) {
			if (lib_version == c_issue_4) {
				(void) write(2, "log10: SING error\n", 18);
				errno = EDOM;
			} else {
				errno = ERANGE;
			}
		}
		break;
	case 19:
		/* log10(x<0) */
		exc.type = DOMAIN;
		exc.name = "log10";
		ieee_retval = setexception(3, 1.0);
		if (lib_version == c_issue_4)
			exc.retval = -HUGE;
		else
			exc.retval = -HUGE_VAL;
		if (lib_version == strict_ansi) {
			errno = EDOM;
		} else if (!matherr(&exc)) {
			if (lib_version == c_issue_4) {
				(void) write(2, "log10: DOMAIN error\n", 20);
			}
			errno = EDOM;
		}
		break;
	case 20:
		/* pow(0.0,0.0) */
		/* error only if lib_version == c_issue_4 */
		exc.type = DOMAIN;
		exc.name = "pow";
		exc.retval = 0.0;
		ieee_retval = 1.0;
		if (lib_version != c_issue_4) {
			exc.retval = 1.0;
		} else if (!matherr(&exc)) {
			(void) write(2, "pow(0,0): DOMAIN error\n", 23);
			errno = EDOM;
		}
		break;
	case 21:
		/* pow(x,y) overflow */
		exc.type = OVERFLOW;
		exc.name = "pow";
		exc.retval = (lib_version == c_issue_4)? HUGE : HUGE_VAL;
		if (signbit(x)) {
			t = rint(y);
			if (t == y) {
				w = rint(0.5 * y);
				if (t != w + w)	{	/* y is odd */
					exc.retval = -exc.retval;
				}
			}
		}
		ieee_retval = setexception(2, exc.retval);
		if (lib_version == strict_ansi)
			errno = ERANGE;
		else if (!matherr(&exc))
			errno = ERANGE;
		break;
	case 22:
		/* pow(x,y) underflow */
		exc.type = UNDERFLOW;
		exc.name = "pow";
		exc.retval = 0.0;
		if (signbit(x)) {
			t = rint(y);
			if (t == y) {
				w = rint(0.5 * y);
				if (t != w + w)	/* y is odd */
					exc.retval = -exc.retval;
			}
		}
		ieee_retval = setexception(1, exc.retval);
		if (lib_version == strict_ansi)
			errno = ERANGE;
		else if (!matherr(&exc))
			errno = ERANGE;
		break;
	case 23:
		/* (+-0)**neg */
		exc.type = DOMAIN;
		exc.name = "pow";
		ieee_retval = setexception(0, 1.0);
		{
			int ahy, k, j, yisint, ly, hx;
			/* INDENT OFF */
			/*
			 * determine if y is an odd int when x = -0
			 * yisint = 0       ... y is not an integer
			 * yisint = 1       ... y is an odd int
			 * yisint = 2       ... y is an even int
			 */
			/* INDENT ON */
			hx  = __HI(x);
			ahy = __HI(y)&0x7fffffff;
			ly  = __LO(y);

			yisint = 0;
			if (ahy >= 0x43400000) {
				yisint = 2;	/* even integer y */
			} else if (ahy >= 0x3ff00000) {
				k = (ahy >> 20) - 0x3ff;	/* exponent */
				if (k > 20) {
					j = ly >> (52 - k);
					if ((j << (52 - k)) == ly)
						yisint = 2 - (j & 1);
				} else if (ly == 0) {
					j = ahy >> (20 - k);
					if ((j << (20 - k)) == ahy)
						yisint = 2 - (j & 1);
				}
			}
			if (hx < 0 && yisint == 1)
				ieee_retval = -ieee_retval;
		}
		if (lib_version == c_issue_4)
			exc.retval = 0.0;
		else
			exc.retval = -HUGE_VAL;
		if (lib_version == strict_ansi) {
			errno = EDOM;
		} else if (!matherr(&exc)) {
			if (lib_version == c_issue_4) {
				(void) write(2, "pow(0,neg): DOMAIN error\n",
				    25);
			}
			errno = EDOM;
		}
		break;
	case 24:
		/* neg**non-integral */
		exc.type = DOMAIN;
		exc.name = "pow";
		ieee_retval = setexception(3, 1.0);
		if (lib_version == c_issue_4)
			exc.retval = 0.0;
		else
			exc.retval = ieee_retval;	/* X/Open allow NaN */
		if (lib_version == strict_ansi) {
			errno = EDOM;
		} else if (!matherr(&exc)) {
			if (lib_version == c_issue_4) {
				(void) write(2,
				    "neg**non-integral: DOMAIN error\n", 32);
			}
			errno = EDOM;
		}
		break;
	case 25:
		/* sinh(finite) overflow */
		exc.type = OVERFLOW;
		exc.name = "sinh";
		ieee_retval = copysign(Inf, x);
		if (lib_version == c_issue_4)
			exc.retval = x > 0.0 ? HUGE : -HUGE;
		else
			exc.retval = x > 0.0 ? HUGE_VAL : -HUGE_VAL;
		if (lib_version == strict_ansi)
			errno = ERANGE;
		else if (!matherr(&exc))
			errno = ERANGE;
		break;
	case 26:
		/* sqrt(x<0) */
		exc.type = DOMAIN;
		exc.name = "sqrt";
		ieee_retval = setexception(3, 1.0);
		if (lib_version == c_issue_4)
			exc.retval = 0.0;
		else
			exc.retval = ieee_retval;	/* quiet NaN */
		if (lib_version == strict_ansi) {
			errno = EDOM;
		} else if (!matherr(&exc)) {
			if (lib_version == c_issue_4) {
				(void) write(2, "sqrt: DOMAIN error\n", 19);
			}
			errno = EDOM;
		}
		break;
	case 27:
		/* fmod(x,0) */
		exc.type = DOMAIN;
		exc.name = "fmod";
		if (fp_class(x) == fp_quiet)
			ieee_retval = NaN;
		else
			ieee_retval = setexception(3, 1.0);
		if (lib_version == c_issue_4)
			exc.retval = x;
		else
			exc.retval = ieee_retval;
		if (lib_version == strict_ansi) {
			errno = EDOM;
		} else if (!matherr(&exc)) {
			if (lib_version == c_issue_4) {
				(void) write(2, "fmod:  DOMAIN error\n", 20);
			}
			errno = EDOM;
		}
		break;
	case 28:
		/* remainder(x,0) */
		exc.type = DOMAIN;
		exc.name = "remainder";
		if (fp_class(x) == fp_quiet)
			ieee_retval = NaN;
		else
			ieee_retval = setexception(3, 1.0);
		exc.retval = NaN;
		if (lib_version == strict_ansi) {
			errno = EDOM;
		} else if (!matherr(&exc)) {
			if (lib_version == c_issue_4) {
				(void) write(2, "remainder: DOMAIN error\n",
				    24);
			}
			errno = EDOM;
		}
		break;
	case 29:
		/* acosh(x<1) */
		exc.type = DOMAIN;
		exc.name = "acosh";
		ieee_retval = setexception(3, 1.0);
		exc.retval = NaN;
		if (lib_version == strict_ansi) {
			errno = EDOM;
		} else if (!matherr(&exc)) {
			if (lib_version == c_issue_4) {
				(void) write(2, "acosh: DOMAIN error\n", 20);
			}
			errno = EDOM;
		}
		break;
	case 30:
		/* atanh(|x|>1) */
		exc.type = DOMAIN;
		exc.name = "atanh";
		ieee_retval = setexception(3, 1.0);
		exc.retval = NaN;
		if (lib_version == strict_ansi) {
			errno = EDOM;
		} else if (!matherr(&exc)) {
			if (lib_version == c_issue_4) {
				(void) write(2, "atanh: DOMAIN error\n", 20);
			}
			errno = EDOM;
		}
		break;
	case 31:
		/* atanh(|x|=1) */
		exc.type = SING;
		exc.name = "atanh";
		ieee_retval = setexception(0, x);
		exc.retval = ieee_retval;
		if (lib_version == strict_ansi) {
			errno = ERANGE;
		} else if (!matherr(&exc)) {
			if (lib_version == c_issue_4) {
				(void) write(2, "atanh: SING error\n", 18);
				errno = EDOM;
			} else {
				errno = ERANGE;
			}
		}
		break;
	case 32:
		/* scalb overflow; SVID also returns +-HUGE_VAL */
		exc.type = OVERFLOW;
		exc.name = "scalb";
		ieee_retval = setexception(2, x);
		exc.retval = x > 0.0 ? HUGE_VAL : -HUGE_VAL;
		if (lib_version == strict_ansi)
			errno = ERANGE;
		else if (!matherr(&exc))
			errno = ERANGE;
		break;
	case 33:
		/* scalb underflow */
		exc.type = UNDERFLOW;
		exc.name = "scalb";
		ieee_retval = setexception(1, x);
		exc.retval = ieee_retval;	/* +-0.0 */
		if (lib_version == strict_ansi)
			errno = ERANGE;
		else if (!matherr(&exc))
			errno = ERANGE;
		break;
	case 34:
		/* j0(|x|>X_TLOSS) */
		exc.type = TLOSS;
		exc.name = "j0";
		exc.retval = 0.0;
		ieee_retval = y;
		if (lib_version == strict_ansi) {
			errno = ERANGE;
		} else if (!matherr(&exc)) {
			if (lib_version == c_issue_4) {
				(void) write(2, exc.name, 2);
				(void) write(2, ": TLOSS error\n", 14);
			}
			errno = ERANGE;
		}
		break;
	case 35:
		/* y0(x>X_TLOSS) */
		exc.type = TLOSS;
		exc.name = "y0";
		exc.retval = 0.0;
		ieee_retval = y;
		if (lib_version == strict_ansi) {
			errno = ERANGE;
		} else if (!matherr(&exc)) {
			if (lib_version == c_issue_4) {
				(void) write(2, exc.name, 2);
				(void) write(2, ": TLOSS error\n", 14);
			}
			errno = ERANGE;
		}
		break;
	case 36:
		/* j1(|x|>X_TLOSS) */
		exc.type = TLOSS;
		exc.name = "j1";
		exc.retval = 0.0;
		ieee_retval = y;
		if (lib_version == strict_ansi) {
			errno = ERANGE;
		} else if (!matherr(&exc)) {
			if (lib_version == c_issue_4) {
				(void) write(2, exc.name, 2);
				(void) write(2, ": TLOSS error\n", 14);
			}
			errno = ERANGE;
		}
		break;
	case 37:
		/* y1(x>X_TLOSS) */
		exc.type = TLOSS;
		exc.name = "y1";
		exc.retval = 0.0;
		ieee_retval = y;
		if (lib_version == strict_ansi) {
			errno = ERANGE;
		} else if (!matherr(&exc)) {
			if (lib_version == c_issue_4) {
				(void) write(2, exc.name, 2);
				(void) write(2, ": TLOSS error\n", 14);
			}
			errno = ERANGE;
		}
		break;
	case 38:
		/* jn(|x|>X_TLOSS) */
		/* incorrect ieee value: ieee should never be here */
		exc.type = TLOSS;
		exc.name = "jn";
		exc.retval = 0.0;
		ieee_retval = 0.0;	/* shall not be used */
		if (lib_version == strict_ansi) {
			errno = ERANGE;
		} else if (!matherr(&exc)) {
			if (lib_version == c_issue_4) {
				(void) write(2, exc.name, 2);
				(void) write(2, ": TLOSS error\n", 14);
			}
			errno = ERANGE;
		}
		break;
	case 39:
		/* yn(x>X_TLOSS) */
		/* incorrect ieee value: ieee should never be here */
		exc.type = TLOSS;
		exc.name = "yn";
		exc.retval = 0.0;
		ieee_retval = 0.0;	/* shall not be used */
		if (lib_version == strict_ansi) {
			errno = ERANGE;
		} else if (!matherr(&exc)) {
			if (lib_version == c_issue_4) {
				(void) write(2, exc.name, 2);
				(void) write(2, ": TLOSS error\n", 14);
			}
			errno = ERANGE;
		}
		break;
	case 40:
		/* gamma(finite) overflow */
		exc.type = OVERFLOW;
		exc.name = "gamma";
		ieee_retval = setexception(2, 1.0);
		if (lib_version == c_issue_4)
			exc.retval = HUGE;
		else
			exc.retval = HUGE_VAL;
		if (lib_version == strict_ansi)
			errno = ERANGE;
		else if (!matherr(&exc))
			errno = ERANGE;
		break;
	case 41:
		/* gamma(-integer) or gamma(0) */
		exc.type = SING;
		exc.name = "gamma";
		ieee_retval = setexception(0, 1.0);
		if (lib_version == c_issue_4)
			exc.retval = HUGE;
		else
			exc.retval = HUGE_VAL;
		if (lib_version == strict_ansi) {
			errno = EDOM;
		} else if (!matherr(&exc)) {
			if (lib_version == c_issue_4) {
				(void) write(2, "gamma: SING error\n", 18);
			}
			errno = EDOM;
		}
		break;
	case 42:
		/* pow(NaN,0.0) */
		/* error if lib_version == c_issue_4 or ansi_1 */
		exc.type = DOMAIN;
		exc.name = "pow";
		exc.retval = x;
		ieee_retval = 1.0;
		if (lib_version == strict_ansi) {
			exc.retval = 1.0;
		} else if (!matherr(&exc)) {
			if ((lib_version == c_issue_4) || (lib_version == ansi_1))
				errno = EDOM;
		}
		break;
	case 43:
		/* log1p(-1) */
		exc.type = SING;
		exc.name = "log1p";
		ieee_retval = setexception(0, -1.0);
		if (lib_version == c_issue_4)
			exc.retval = -HUGE;
		else
			exc.retval = -HUGE_VAL;
		if (lib_version == strict_ansi) {
			errno = ERANGE;
		} else if (!matherr(&exc)) {
			if (lib_version == c_issue_4) {
				(void) write(2, "log1p: SING error\n", 18);
				errno = EDOM;
			} else {
				errno = ERANGE;
			}
		}
		break;
	case 44:
		/* log1p(x<-1) */
		exc.type = DOMAIN;
		exc.name = "log1p";
		ieee_retval = setexception(3, 1.0);
		exc.retval = ieee_retval;
		if (lib_version == strict_ansi) {
			errno = EDOM;
		} else if (!matherr(&exc)) {
			if (lib_version == c_issue_4) {
				(void) write(2, "log1p: DOMAIN error\n", 20);
			}
			errno = EDOM;
		}
		break;
	case 45:
		/* logb(0) */
		exc.type = DOMAIN;
		exc.name = "logb";
		ieee_retval = setexception(0, -1.0);
		exc.retval = -HUGE_VAL;
		if (lib_version == strict_ansi)
			errno = EDOM;
		else if (!matherr(&exc))
			errno = EDOM;
		break;
	case 46:
		/* nextafter overflow */
		exc.type = OVERFLOW;
		exc.name = "nextafter";
		/*
		 * The value as returned by setexception is +/-DBL_MAX in
		 * round-to-{zero,-/+Inf} mode respectively, which is not
		 * usable.
		 */
		(void) setexception(2, x);
		ieee_retval = x > 0 ? Inf : -Inf;
		exc.retval = x > 0 ? HUGE_VAL : -HUGE_VAL;
		if (lib_version == strict_ansi)
			errno = ERANGE;
		else if (!matherr(&exc))
			errno = ERANGE;
		break;
	case 47:
		/* scalb(x,inf) */
		iy = ((int *)&y)[HIWORD];
		if (lib_version == c_issue_4)
			/* SVID3: ERANGE in all cases */
			errno = ERANGE;
		else if ((x == 0.0 && iy > 0) || (!finite(x) && iy < 0))
			/* EDOM for scalb(0,+inf) or scalb(inf,-inf) */
			errno = EDOM;
		exc.retval = ieee_retval = ((iy < 0)? x / -y : x * y);
		break;
	}
	switch (lib_version) {
	case c_issue_4:
	case ansi_1:
	case strict_ansi:
		return (exc.retval);
		/* NOTREACHED */
	default:
		return (ieee_retval);
	}
	/* NOTREACHED */
}

static double
setexception(int n, double x) {
	/*
	 * n =
	 * 0	division by zero
	 * 1	underflow
	 * 2	overflow
	 * 3	invalid
	 */
	volatile double one = 1.0, zero = 0.0, retv;

	switch (n) {
	case 0:		/* division by zero */
		retv = copysign(one / zero, x);
		break;
	case 1:		/* underflow */
		retv = DBL_MIN * copysign(DBL_MIN, x);
		break;
	case 2:		/* overflow */
		retv = DBL_MAX * copysign(DBL_MAX, x);
		break;
	case 3:		/* invalid */
		retv = zero * Inf;	/* for Cheetah */
		break;
	}
	return (retv);
}
