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

#if defined(__sparc)
#include "fenv_synonyms.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <siginfo.h>
#include <thread.h>
#include <ucontext.h>
#include <math.h>
#if defined(__SUNPRO_C)
#include <sunmath.h>
#endif
#include <fenv.h>

#include "fenv_inlines.h"
#include "libm_inlines.h"

#ifdef __sparcv9

#define FPreg(X)	&uap->uc_mcontext.fpregs.fpu_fr.fpu_regs[X]

#define FPREG(X)	&uap->uc_mcontext.fpregs.fpu_fr.fpu_dregs[(X>>1)| \
					((X&1)<<4)]

#else

#include <sys/procfs.h>

#define FPxreg(X)	&((prxregset_t*)uap->uc_mcontext.xrs.xrs_ptr)->pr_un.pr_v8p.pr_xfr.pr_regs[X]

#define FPreg(X)	&uap->uc_mcontext.fpregs.fpu_fr.fpu_regs[X]

#define FPREG(X)	((X & 1)? FPxreg(X - 1) : FPreg(X))

#endif	/* __sparcv9 */

#include "fex_handler.h"

/* avoid dependence on libsunmath */
static enum fp_class_type
my_fp_classl(long double *a)
{
	int		msw = *(int*)a & ~0x80000000;

	if (msw >= 0x7fff0000) {
		if (((msw & 0xffff) | *(1+(int*)a) | *(2+(int*)a) | *(3+(int*)a)) == 0)
			return fp_infinity;
		else if (msw & 0x8000)
			return fp_quiet;
		else
			return fp_signaling;
	} else if (msw < 0x10000) {
		if ((msw | *(1+(int*)a) | *(2+(int*)a) | *(3+(int*)a)) == 0)
			return fp_zero;
		else
			return fp_subnormal;
	} else
		return fp_normal;
}

/*
*  Determine which type of invalid operation exception occurred
*/
enum fex_exception
__fex_get_invalid_type(siginfo_t *sip, ucontext_t *uap)
{
	unsigned			instr, opf, rs1, rs2;
	enum fp_class_type	t1, t2;

	/* parse the instruction which caused the exception */
	instr = uap->uc_mcontext.fpregs.fpu_q->FQu.fpq.fpq_instr;
	opf = (instr >> 5) & 0x1ff;
	rs1 = (instr >> 14) & 0x1f;
	rs2 = instr & 0x1f;

	/* determine the classes of the operands */
	switch (opf & 3) {
	case 1: /* single */
		t1 = fp_classf(*(float*)FPreg(rs1));
		t2 = fp_classf(*(float*)FPreg(rs2));
		break;

	case 2: /* double */
		t1 = fp_class(*(double*)FPREG(rs1));
		t2 = fp_class(*(double*)FPREG(rs2));
		break;

	case 3: /* quad */
		t1 = my_fp_classl((long double*)FPREG(rs1));
		t2 = my_fp_classl((long double*)FPREG(rs2));
		break;

	default: /* integer operands never cause an invalid operation */
		return (enum fex_exception) -1;
	}

	/* if rs2 is snan, return immediately */
	if (t2 == fp_signaling)
		return fex_inv_snan;

	/* determine the type of operation */
	switch ((instr >> 19) & 0x183f) {
	case 0x1034: /* add, subtract, multiply, divide, square root, convert */
		switch (opf & 0x1fc) {
		case 0x40:
		case 0x44: /* add or subtract */
			if (t1 == fp_signaling)
				return fex_inv_snan;
			else
				return fex_inv_isi;

		case 0x48:
		case 0x68:
		case 0x6c: /* multiply */
			if (t1 == fp_signaling)
				return fex_inv_snan;
			else
				return fex_inv_zmi;

		case 0x4c: /* divide */
			if (t1 == fp_signaling)
				return fex_inv_snan;
			else if (t1 == fp_zero)
				return fex_inv_zdz;
			else
				return fex_inv_idi;

		case 0x28: /* square root */
			return fex_inv_sqrt;

		case 0x80:
		case 0xd0: /* convert to integer */
			return fex_inv_int;
		}
		break;

	case 0x1035: /* compare */
		if (t1 == fp_signaling)
			return fex_inv_snan;
		else
			return fex_inv_cmp;
	}

	return (enum fex_exception) -1;
}

#ifdef __sparcv9
extern void _Qp_sqrt(long double *, const long double *);
#else
extern long double _Q_sqrt(long double);
#endif

/*
*  Get the operands, generate the default untrapped result with
*  exceptions, and set a code indicating the type of operation
*/
void
__fex_get_op(siginfo_t *sip, ucontext_t *uap, fex_info_t *info)
{
	unsigned long	fsr;
	unsigned		instr, opf, rs1, rs2;
	volatile int	c;

	/* parse the instruction which caused the exception */
	instr = uap->uc_mcontext.fpregs.fpu_q->FQu.fpq.fpq_instr;
	opf = (instr >> 5) & 0x1ff;
	rs1 = (instr >> 14) & 0x1f;
	rs2 = instr & 0x1f;

	/* get the operands */
	switch (opf & 3) {
	case 0: /* integer */
		info->op1.type = fex_nodata;
		if (opf & 0x40) {
			info->op2.type = fex_int;
			info->op2.val.i = *(int*)FPreg(rs2);
		}
		else {
			info->op2.type = fex_llong;
			info->op2.val.l = *(long long*)FPREG(rs2);
		}
		break;

	case 1: /* single */
		info->op1.type = info->op2.type = fex_float;
		info->op1.val.f = *(float*)FPreg(rs1);
		info->op2.val.f = *(float*)FPreg(rs2);
		break;

	case 2: /* double */
		info->op1.type = info->op2.type = fex_double;
		info->op1.val.d = *(double*)FPREG(rs1);
		info->op2.val.d = *(double*)FPREG(rs2);
		break;

	case 3: /* quad */
		info->op1.type = info->op2.type = fex_ldouble;
		info->op1.val.q = *(long double*)FPREG(rs1);
		info->op2.val.q = *(long double*)FPREG(rs2);
		break;
	}

	/* initialize res to the default untrapped result and ex to the
	   corresponding flags (assume trapping is disabled and flags
	   are clear) */
	info->op = fex_other;
	info->res.type = fex_nodata;
	switch ((instr >> 19) & 0x183f) {
	case 0x1035: /* compare */
		info->op = fex_cmp;
		switch (opf) {
		case 0x51: /* compare single */
			c = (info->op1.val.f == info->op2.val.f);
			break;

		case 0x52: /* compare double */
			c = (info->op1.val.d == info->op2.val.d);
			break;

		case 0x53: /* compare quad */
			c = (info->op1.val.q == info->op2.val.q);
			break;

		case 0x55: /* compare single with exception */
			c = (info->op1.val.f < info->op2.val.f);
			break;

		case 0x56: /* compare double with exception */
			c = (info->op1.val.d < info->op2.val.d);
			break;

		case 0x57: /* compare quad with exception */
			c = (info->op1.val.q < info->op2.val.q);
			break;
		}
		break;

	case 0x1034: /* add, subtract, multiply, divide, square root, convert */
		switch (opf) {
		case 0x41: /* add single */
			info->op = fex_add;
			info->res.type = fex_float;
			info->res.val.f = info->op1.val.f + info->op2.val.f;
			break;

		case 0x42: /* add double */
			info->op = fex_add;
			info->res.type = fex_double;
			info->res.val.d = info->op1.val.d + info->op2.val.d;
			break;

		case 0x43: /* add quad */
			info->op = fex_add;
			info->res.type = fex_ldouble;
			info->res.val.q = info->op1.val.q + info->op2.val.q;
			break;

		case 0x45: /* subtract single */
			info->op = fex_sub;
			info->res.type = fex_float;
			info->res.val.f = info->op1.val.f - info->op2.val.f;
			break;

		case 0x46: /* subtract double */
			info->op = fex_sub;
			info->res.type = fex_double;
			info->res.val.d = info->op1.val.d - info->op2.val.d;
			break;

		case 0x47: /* subtract quad */
			info->op = fex_sub;
			info->res.type = fex_ldouble;
			info->res.val.q = info->op1.val.q - info->op2.val.q;
			break;

		case 0x49: /* multiply single */
			info->op = fex_mul;
			info->res.type = fex_float;
			info->res.val.f = info->op1.val.f * info->op2.val.f;
			break;

		case 0x4a: /* multiply double */
			info->op = fex_mul;
			info->res.type = fex_double;
			info->res.val.d = info->op1.val.d * info->op2.val.d;
			break;

		case 0x4b: /* multiply quad */
			info->op = fex_mul;
			info->res.type = fex_ldouble;
			info->res.val.q = info->op1.val.q * info->op2.val.q;
			break;

		case 0x69: /* fsmuld */
			info->op = fex_mul;
			info->res.type = fex_double;
			info->res.val.d = (double)info->op1.val.f * (double)info->op2.val.f;
			break;

		case 0x6e: /* fdmulq */
			info->op = fex_mul;
			info->res.type = fex_ldouble;
			info->res.val.q = (long double)info->op1.val.d *
				(long double)info->op2.val.d;
			break;

		case 0x4d: /* divide single */
			info->op = fex_div;
			info->res.type = fex_float;
			info->res.val.f = info->op1.val.f / info->op2.val.f;
			break;

		case 0x4e: /* divide double */
			info->op = fex_div;
			info->res.type = fex_double;
			info->res.val.d = info->op1.val.d / info->op2.val.d;
			break;

		case 0x4f: /* divide quad */
			info->op = fex_div;
			info->res.type = fex_ldouble;
			info->res.val.q = info->op1.val.q / info->op2.val.q;
			break;

		case 0x29: /* square root single */
			info->op = fex_sqrt;
			info->op1 = info->op2;
			info->op2.type = fex_nodata;
			info->res.type = fex_float;
			info->res.val.f = sqrtf(info->op1.val.f);
			break;

		case 0x2a: /* square root double */
			info->op = fex_sqrt;
			info->op1 = info->op2;
			info->op2.type = fex_nodata;
			info->res.type = fex_double;
			info->res.val.d = sqrt(info->op1.val.d);
			break;

		case 0x2b: /* square root quad */
			info->op = fex_sqrt;
			info->op1 = info->op2;
			info->op2.type = fex_nodata;
			info->res.type = fex_ldouble;
#ifdef __sparcv9
			_Qp_sqrt(&info->res.val.q, &info->op1.val.q);
#else
			info->res.val.q = _Q_sqrt(info->op1.val.q);
#endif
			break;

		default: /* conversions */
			info->op = fex_cnvt;
			info->op1 = info->op2;
			info->op2.type = fex_nodata;
			switch (opf) {
			case 0xd1: /* convert single to int */
				info->res.type = fex_int;
				info->res.val.i = (int) info->op1.val.f;
				break;

			case 0xd2: /* convert double to int */
				info->res.type = fex_int;
				info->res.val.i = (int) info->op1.val.d;
				break;

			case 0xd3: /* convert quad to int */
				info->res.type = fex_int;
				info->res.val.i = (int) info->op1.val.q;
				break;

			case 0x81: /* convert single to long long */
				info->res.type = fex_llong;
				info->res.val.l = (long long) info->op1.val.f;
				break;

			case 0x82: /* convert double to long long */
				info->res.type = fex_llong;
				info->res.val.l = (long long) info->op1.val.d;
				break;

			case 0x83: /* convert quad to long long */
				info->res.type = fex_llong;
				info->res.val.l = (long long) info->op1.val.q;
				break;

			case 0xc4: /* convert int to single */
				info->res.type = fex_float;
				info->res.val.f = (float) info->op1.val.i;
				break;

			case 0x84: /* convert long long to single */
				info->res.type = fex_float;
				info->res.val.f = (float) info->op1.val.l;
				break;

			case 0x88: /* convert long long to double */
				info->res.type = fex_double;
				info->res.val.d = (double) info->op1.val.l;
				break;

			case 0xc6: /* convert double to single */
				info->res.type = fex_float;
				info->res.val.f = (float) info->op1.val.d;
				break;

			case 0xc7: /* convert quad to single */
				info->res.type = fex_float;
				info->res.val.f = (float) info->op1.val.q;
				break;

			case 0xc9: /* convert single to double */
				info->res.type = fex_double;
				info->res.val.d = (double) info->op1.val.f;
				break;

			case 0xcb: /* convert quad to double */
				info->res.type = fex_double;
				info->res.val.d = (double) info->op1.val.q;
				break;

			case 0xcd: /* convert single to quad */
				info->res.type = fex_ldouble;
				info->res.val.q = (long double) info->op1.val.f;
				break;

			case 0xce: /* convert double to quad */
				info->res.type = fex_ldouble;
				info->res.val.q = (long double) info->op1.val.d;
				break;
			}
		}
		break;
	}
	__fenv_getfsr(&fsr);
	info->flags = (int)__fenv_get_ex(fsr);
	__fenv_set_ex(fsr, 0);
	__fenv_setfsr(&fsr);
}

/*
*  Store the specified result; if no result is given but the exception
*  is underflow or overflow, supply the default trapped result
*/
void
__fex_st_result(siginfo_t *sip, ucontext_t *uap, fex_info_t *info)
{
	unsigned		instr, opf, rs1, rs2, rd;
	long double		qscl;
	double			dscl;
	float			fscl;

	/* parse the instruction which caused the exception */
	instr = uap->uc_mcontext.fpregs.fpu_q->FQu.fpq.fpq_instr;
	opf = (instr >> 5) & 0x1ff;
	rs1 = (instr >> 14) & 0x1f;
	rs2 = instr & 0x1f;
	rd = (instr >> 25) & 0x1f;

	/* if the instruction is a compare, just set fcc to unordered */
	if (((instr >> 19) & 0x183f) == 0x1035) {
		if (rd == 0)
			uap->uc_mcontext.fpregs.fpu_fsr |= 0xc00;
		else {
#ifdef __sparcv9
			uap->uc_mcontext.fpregs.fpu_fsr |= (3l << ((rd << 1) + 30));
#else
			((prxregset_t*)uap->uc_mcontext.xrs.xrs_ptr)->pr_un.pr_v8p.pr_xfsr |= (3 << ((rd - 1) << 1));
#endif
		}
		return;
	}

	/* if there is no result available, try to generate the untrapped
	   default */
	if (info->res.type == fex_nodata) {
		/* set scale factors for exponent wrapping */
		switch (sip->si_code) {
		case FPE_FLTOVF:
			fscl = 1.262177448e-29f;	/* 2^-96 */
			dscl = 6.441148769597133308e-232;	/* 2^-768 */
			qscl = 8.778357852076208839765066529179033145e-3700l;/* 2^-12288 */
			break;

		case FPE_FLTUND:
			fscl = 7.922816251e+28f;	/* 2^96 */
			dscl = 1.552518092300708935e+231;	/* 2^768 */
			qscl = 1.139165225263043370845938579315932009e+3699l;/* 2^12288 */
			break;

		default:
			/* user may have blown away the default result by mistake,
			   so try to regenerate it */
			(void) __fex_get_op(sip, uap, info);
			if (info->res.type != fex_nodata)
				goto stuff;
			/* couldn't do it */
			return;
		}

		/* get the operands */
		switch (opf & 3) {
		case 1: /* single */
			info->op1.val.f = *(float*)FPreg(rs1);
			info->op2.val.f = *(float*)FPreg(rs2);
			break;

		case 2: /* double */
			info->op1.val.d = *(double*)FPREG(rs1);
			info->op2.val.d = *(double*)FPREG(rs2);
			break;

		case 3: /* quad */
			info->op1.val.q = *(long double*)FPREG(rs1);
			info->op2.val.q = *(long double*)FPREG(rs2);
			break;
		}

		/* generate the wrapped result */
		switch (opf) {
		case 0x41: /* add single */
			info->res.type = fex_float;
			info->res.val.f = fscl * (fscl * info->op1.val.f +
				fscl * info->op2.val.f);
			break;

		case 0x42: /* add double */
			info->res.type = fex_double;
			info->res.val.d = dscl * (dscl * info->op1.val.d +
				dscl * info->op2.val.d);
			break;

		case 0x43: /* add quad */
			info->res.type = fex_ldouble;
			info->res.val.q = qscl * (qscl * info->op1.val.q +
				qscl * info->op2.val.q);
			break;

		case 0x45: /* subtract single */
			info->res.type = fex_float;
			info->res.val.f = fscl * (fscl * info->op1.val.f -
				fscl * info->op2.val.f);
			break;

		case 0x46: /* subtract double */
			info->res.type = fex_double;
			info->res.val.d = dscl * (dscl * info->op1.val.d -
				dscl * info->op2.val.d);
			break;

		case 0x47: /* subtract quad */
			info->res.type = fex_ldouble;
			info->res.val.q = qscl * (qscl * info->op1.val.q -
				qscl * info->op2.val.q);
			break;

		case 0x49: /* multiply single */
			info->res.type = fex_float;
			info->res.val.f = (fscl * info->op1.val.f) *
				(fscl * info->op2.val.f);
			break;

		case 0x4a: /* multiply double */
			info->res.type = fex_double;
			info->res.val.d = (dscl * info->op1.val.d) *
				(dscl * info->op2.val.d);
			break;

		case 0x4b: /* multiply quad */
			info->res.type = fex_ldouble;
			info->res.val.q = (qscl * info->op1.val.q) *
				(qscl * info->op2.val.q);
			break;

		case 0x4d: /* divide single */
			info->res.type = fex_float;
			info->res.val.f = (fscl * info->op1.val.f) /
				(info->op2.val.f / fscl);
			break;

		case 0x4e: /* divide double */
			info->res.type = fex_double;
			info->res.val.d = (dscl * info->op1.val.d) /
				(info->op2.val.d / dscl);
			break;

		case 0x4f: /* divide quad */
			info->res.type = fex_ldouble;
			info->res.val.q = (qscl * info->op1.val.q) /
				(info->op2.val.q / qscl);
			break;

		case 0xc6: /* convert double to single */
			info->res.type = fex_float;
			info->res.val.f = (float) (fscl * (fscl * info->op1.val.d));
			break;

		case 0xc7: /* convert quad to single */
			info->res.type = fex_float;
			info->res.val.f = (float) (fscl * (fscl * info->op1.val.q));
			break;

		case 0xcb: /* convert quad to double */
			info->res.type = fex_double;
			info->res.val.d = (double) (dscl * (dscl * info->op1.val.q));
			break;
		}

		if (info->res.type == fex_nodata)
			/* couldn't do it */
			return;
	}

stuff:
	/* stick the result in the destination */
	if (opf & 0x80) { /* conversion */
		if (opf & 0x10) { /* result is an int */
			switch (info->res.type) {
			case fex_llong:
				info->res.val.i = (int) info->res.val.l;
				break;

			case fex_float:
				info->res.val.i = (int) info->res.val.f;
				break;

			case fex_double:
				info->res.val.i = (int) info->res.val.d;
				break;

			case fex_ldouble:
				info->res.val.i = (int) info->res.val.q;
				break;

			default:
				break;
			}
			*(int*)FPreg(rd) = info->res.val.i;
			return;
		}

		switch (opf & 0xc) {
		case 0: /* result is long long */
			switch (info->res.type) {
			case fex_int:
				info->res.val.l = (long long) info->res.val.i;
				break;

			case fex_float:
				info->res.val.l = (long long) info->res.val.f;
				break;

			case fex_double:
				info->res.val.l = (long long) info->res.val.d;
				break;

			case fex_ldouble:
				info->res.val.l = (long long) info->res.val.q;
				break;

			default:
				break;
			}
			*(long long*)FPREG(rd) = info->res.val.l;
			break;

		case 0x4: /* result is float */
			switch (info->res.type) {
			case fex_int:
				info->res.val.f = (float) info->res.val.i;
				break;

			case fex_llong:
				info->res.val.f = (float) info->res.val.l;
				break;

			case fex_double:
				info->res.val.f = (float) info->res.val.d;
				break;

			case fex_ldouble:
				info->res.val.f = (float) info->res.val.q;
				break;

			default:
				break;
			}
			*(float*)FPreg(rd) = info->res.val.f;
			break;

		case 0x8: /* result is double */
			switch (info->res.type) {
			case fex_int:
				info->res.val.d = (double) info->res.val.i;
				break;

			case fex_llong:
				info->res.val.d = (double) info->res.val.l;
				break;

			case fex_float:
				info->res.val.d = (double) info->res.val.f;
				break;

			case fex_ldouble:
				info->res.val.d = (double) info->res.val.q;
				break;

			default:
				break;
			}
			*(double*)FPREG(rd) = info->res.val.d;
			break;

		case 0xc: /* result is long double */
			switch (info->res.type) {
			case fex_int:
				info->res.val.q = (long double) info->res.val.i;
				break;

			case fex_llong:
				info->res.val.q = (long double) info->res.val.l;
				break;

			case fex_float:
				info->res.val.q = (long double) info->res.val.f;
				break;

			case fex_double:
				info->res.val.q = (long double) info->res.val.d;
				break;

			default:
				break;
			}
			*(long double*)FPREG(rd) = info->res.val.q;
			break;
		}
		return;
	}

	if ((opf & 0xf0) == 0x60) { /* fsmuld, fdmulq */
		switch (opf & 0xc0) {
		case 0x8: /* result is double */
			switch (info->res.type) {
			case fex_int:
				info->res.val.d = (double) info->res.val.i;
				break;

			case fex_llong:
				info->res.val.d = (double) info->res.val.l;
				break;

			case fex_float:
				info->res.val.d = (double) info->res.val.f;
				break;

			case fex_ldouble:
				info->res.val.d = (double) info->res.val.q;
				break;

			default:
				break;
			}
			*(double*)FPREG(rd) = info->res.val.d;
			break;

		case 0xc: /* result is long double */
			switch (info->res.type) {
			case fex_int:
				info->res.val.q = (long double) info->res.val.i;
				break;

			case fex_llong:
				info->res.val.q = (long double) info->res.val.l;
				break;

			case fex_float:
				info->res.val.q = (long double) info->res.val.f;
				break;

			case fex_double:
				info->res.val.q = (long double) info->res.val.d;
				break;

			default:
				break;
			}
			*(long double*)FPREG(rd) = info->res.val.q;
			break;
		}
		return;
	}

	switch (opf & 3) { /* other arithmetic op */
	case 1: /* result is float */
		switch (info->res.type) {
		case fex_int:
			info->res.val.f = (float) info->res.val.i;
			break;

		case fex_llong:
			info->res.val.f = (float) info->res.val.l;
			break;

		case fex_double:
			info->res.val.f = (float) info->res.val.d;
			break;

		case fex_ldouble:
			info->res.val.f = (float) info->res.val.q;
			break;

		default:
			break;
		}
		*(float*)FPreg(rd) = info->res.val.f;
		break;

	case 2: /* result is double */
		switch (info->res.type) {
		case fex_int:
			info->res.val.d = (double) info->res.val.i;
			break;

		case fex_llong:
			info->res.val.d = (double) info->res.val.l;
			break;

		case fex_float:
			info->res.val.d = (double) info->res.val.f;
			break;

		case fex_ldouble:
			info->res.val.d = (double) info->res.val.q;
			break;

		default:
			break;
		}
		*(double*)FPREG(rd) = info->res.val.d;
		break;

	case 3: /* result is long double */
		switch (info->res.type) {
		case fex_int:
			info->res.val.q = (long double) info->res.val.i;
			break;

		case fex_llong:
			info->res.val.q = (long double) info->res.val.l;
			break;

		case fex_float:
			info->res.val.q = (long double) info->res.val.f;
			break;

		case fex_double:
			info->res.val.q = (long double) info->res.val.d;
			break;

		default:
			break;
		}
		*(long double*)FPREG(rd) = info->res.val.q;
		break;
	}
}
#endif	/* defined(__sparc) */
