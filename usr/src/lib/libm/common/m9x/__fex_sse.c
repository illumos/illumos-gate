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

#include <ucontext.h>
#include <fenv.h>
#if defined(__SUNPRO_C)
#include <sunmath.h>
#else
#include <sys/ieeefp.h>
#endif
#include "fex_handler.h"
#include "fenv_inlines.h"

#if !defined(REG_PC)
#define REG_PC	EIP
#endif

#if !defined(REG_PS)
#define REG_PS	EFL
#endif

#ifdef __amd64
#define regno(X)	((X < 4)? REG_RAX - X : \
			((X > 4)? REG_RAX + 1 - X : REG_RSP))
#else
#define regno(X)	(EAX - X)
#endif

/*
 * Support for SSE instructions
 */

/*
 * Decode an SSE instruction.  Fill in *inst and return the length of the
 * instruction in bytes.  Return 0 if the instruction is not recognized.
 */
int
__fex_parse_sse(ucontext_t *uap, sseinst_t *inst)
{
	unsigned char	*ip;
	char		*addr;
	int		i, dbl, simd, rex, modrm, sib, r;

	i = 0;
	ip = (unsigned char *)uap->uc_mcontext.gregs[REG_PC];

	/* look for pseudo-prefixes */
	dbl = 0;
	simd = SIMD;
	if (ip[i] == 0xF3) {
		simd = 0;
		i++;
	} else if (ip[i] == 0x66) {
		dbl = DOUBLE;
		i++;
	} else if (ip[i] == 0xF2) {
		dbl = DOUBLE;
		simd = 0;
		i++;
	}

	/* look for AMD64 REX prefix */
	rex = 0;
	if (ip[i] >= 0x40 && ip[i] <= 0x4F) {
		rex = ip[i];
		i++;
	}

	/* parse opcode */
	if (ip[i++] != 0x0F)
		return 0;
	switch (ip[i++]) {
	case 0x2A:
		inst->op = (int)cvtsi2ss + simd + dbl;
		if (!simd)
			inst->op = (int)inst->op + (rex & 8);
		break;

	case 0x2C:
		inst->op = (int)cvttss2si + simd + dbl;
		if (!simd)
			inst->op = (int)inst->op + (rex & 8);
		break;

	case 0x2D:
		inst->op = (int)cvtss2si + simd + dbl;
		if (!simd)
			inst->op = (int)inst->op + (rex & 8);
		break;

	case 0x2E:
		/* oddball: scalar instruction in a SIMD opcode group */
		if (!simd)
			return 0;
		inst->op = (int)ucomiss + dbl;
		break;

	case 0x2F:
		/* oddball: scalar instruction in a SIMD opcode group */
		if (!simd)
			return 0;
		inst->op = (int)comiss + dbl;
		break;

	case 0x51:
		inst->op = (int)sqrtss + simd + dbl;
		break;

	case 0x58:
		inst->op = (int)addss + simd + dbl;
		break;

	case 0x59:
		inst->op = (int)mulss + simd + dbl;
		break;

	case 0x5A:
		inst->op = (int)cvtss2sd + simd + dbl;
		break;

	case 0x5B:
		if (dbl) {
			if (simd)
				inst->op = cvtps2dq;
			else
				return 0;
		} else {
			inst->op = (simd)? cvtdq2ps : cvttps2dq;
		}
		break;

	case 0x5C:
		inst->op = (int)subss + simd + dbl;
		break;

	case 0x5D:
		inst->op = (int)minss + simd + dbl;
		break;

	case 0x5E:
		inst->op = (int)divss + simd + dbl;
		break;

	case 0x5F:
		inst->op = (int)maxss + simd + dbl;
		break;

	case 0xC2:
		inst->op = (int)cmpss + simd + dbl;
		break;

	case 0xE6:
		if (simd) {
			if (dbl)
				inst->op = cvttpd2dq;
			else
				return 0;
		} else {
			inst->op = (dbl)? cvtpd2dq : cvtdq2pd;
		}
		break;

	default:
		return 0;
	}

	/* locate operands */
	modrm = ip[i++];

	if (inst->op == cvtss2si || inst->op == cvttss2si ||
	    inst->op == cvtsd2si || inst->op == cvttsd2si ||
	    inst->op == cvtss2siq || inst->op == cvttss2siq ||
	    inst->op == cvtsd2siq || inst->op == cvttsd2siq) {
		/* op1 is a gp register */
		r = ((rex & 4) << 1) | ((modrm >> 3) & 7);
		inst->op1 = (sseoperand_t *)&uap->uc_mcontext.gregs[regno(r)];
	} else if (inst->op == cvtps2pi || inst->op == cvttps2pi ||
	    inst->op == cvtpd2pi || inst->op == cvttpd2pi) {
		/* op1 is a mmx register */
#ifdef __amd64
		inst->op1 = (sseoperand_t *)&uap->uc_mcontext.fpregs.fp_reg_set.
		    fpchip_state.st[(modrm >> 3) & 7];
#else
		inst->op1 = (sseoperand_t *)(10 * ((modrm >> 3) & 7) +
		    (char *)&uap->uc_mcontext.fpregs.fp_reg_set.
		    fpchip_state.state[7]);
#endif
	} else {
		/* op1 is a xmm register */
		r = ((rex & 4) << 1) | ((modrm >> 3) & 7);
		inst->op1 = (sseoperand_t *)&uap->uc_mcontext.fpregs.
		    fp_reg_set.fpchip_state.xmm[r];
	}

	if ((modrm >> 6) == 3) {
		if (inst->op == cvtsi2ss || inst->op == cvtsi2sd ||
		    inst->op == cvtsi2ssq || inst->op == cvtsi2sdq) {
			/* op2 is a gp register */
			r = ((rex & 1) << 3) | (modrm & 7);
			inst->op2 = (sseoperand_t *)&uap->uc_mcontext.
			    gregs[regno(r)];
		} else if (inst->op == cvtpi2ps || inst->op == cvtpi2pd) {
			/* op2 is a mmx register */
#ifdef __amd64
			inst->op2 = (sseoperand_t *)&uap->uc_mcontext.fpregs.
			    fp_reg_set.fpchip_state.st[modrm & 7];
#else
			inst->op2 = (sseoperand_t *)(10 * (modrm & 7) +
			    (char *)&uap->uc_mcontext.fpregs.fp_reg_set.
			    fpchip_state.state[7]);
#endif
		} else {
			/* op2 is a xmm register */
			r = ((rex & 1) << 3) | (modrm & 7);
			inst->op2 = (sseoperand_t *)&uap->uc_mcontext.fpregs.
			    fp_reg_set.fpchip_state.xmm[r];
		}
	} else if ((modrm & 0xc7) == 0x05) {
#ifdef __amd64
		/* address of next instruction + offset */
		r = i + 4;
		if (inst->op == cmpss || inst->op == cmpps ||
		    inst->op == cmpsd || inst->op == cmppd)
			r++;
		inst->op2 = (sseoperand_t *)(ip + r + *(int *)(ip + i));
#else
		/* absolute address */
		inst->op2 = (sseoperand_t *)(*(int *)(ip + i));
#endif
		i += 4;
	} else {
		/* complex address */
		if ((modrm & 7) == 4) {
			/* parse sib byte */
			sib = ip[i++];
			if ((sib & 7) == 5 && (modrm >> 6) == 0) {
				/* start with absolute address */
				addr = (char *)(uintptr_t)(*(int *)(ip + i));
				i += 4;
			} else {
				/* start with base */
				r = ((rex & 1) << 3) | (sib & 7);
				addr = (char *)uap->uc_mcontext.gregs[regno(r)];
			}
			r = ((rex & 2) << 2) | ((sib >> 3) & 7);
			if (r != 4) {
				/* add scaled index */
				addr += uap->uc_mcontext.gregs[regno(r)]
				    << (sib >> 6);
			}
		} else {
			r = ((rex & 1) << 3) | (modrm & 7);
			addr = (char *)uap->uc_mcontext.gregs[regno(r)];
		}

		/* add displacement, if any */
		if ((modrm >> 6) == 1) {
			addr += (char)ip[i++];
		} else if ((modrm >> 6) == 2) {
			addr += *(int *)(ip + i);
			i += 4;
		}
		inst->op2 = (sseoperand_t *)addr;
	}

	if (inst->op == cmpss || inst->op == cmpps || inst->op == cmpsd ||
	    inst->op == cmppd) {
		/* get the immediate operand */
		inst->imm = ip[i++];
	}

	return i;
}

static enum fp_class_type
my_fp_classf(float *x)
{
	int	i = *(int *)x & ~0x80000000;

	if (i < 0x7f800000) {
		if (i < 0x00800000)
			return ((i == 0)? fp_zero : fp_subnormal);
		return fp_normal;
	}
	else if (i == 0x7f800000)
		return fp_infinity;
	else if (i & 0x400000)
		return fp_quiet;
	else
		return fp_signaling;
}

static enum fp_class_type
my_fp_class(double *x)
{
	int	i = *(1+(int *)x) & ~0x80000000;

	if (i < 0x7ff00000) {
		if (i < 0x00100000)
			return (((i | *(int *)x) == 0)? fp_zero : fp_subnormal);
		return fp_normal;
	}
	else if (i == 0x7ff00000 && *(int *)x == 0)
		return fp_infinity;
	else if (i & 0x80000)
		return fp_quiet;
	else
		return fp_signaling;
}

/*
 * Inspect a scalar SSE instruction that incurred an invalid operation
 * exception to determine which type of exception it was.
 */
static enum fex_exception
__fex_get_sse_invalid_type(sseinst_t *inst)
{
	enum fp_class_type	t1, t2;

	/* check op2 for signaling nan */
	t2 = ((int)inst->op & DOUBLE)? my_fp_class(&inst->op2->d[0]) :
	    my_fp_classf(&inst->op2->f[0]);
	if (t2 == fp_signaling)
		return fex_inv_snan;

	/* eliminate all single-operand instructions */
	switch (inst->op) {
	case cvtsd2ss:
	case cvtss2sd:
		/* hmm, this shouldn't have happened */
		return (enum fex_exception) -1;

	case sqrtss:
	case sqrtsd:
		return fex_inv_sqrt;

	case cvtss2si:
	case cvtsd2si:
	case cvttss2si:
	case cvttsd2si:
	case cvtss2siq:
	case cvtsd2siq:
	case cvttss2siq:
	case cvttsd2siq:
		return fex_inv_int;
	default:
		break;
	}

	/* check op1 for signaling nan */
	t1 = ((int)inst->op & DOUBLE)? my_fp_class(&inst->op1->d[0]) :
	    my_fp_classf(&inst->op1->f[0]);
	if (t1 == fp_signaling)
		return fex_inv_snan;

	/* check two-operand instructions for other cases */
	switch (inst->op) {
	case cmpss:
	case cmpsd:
	case minss:
	case minsd:
	case maxss:
	case maxsd:
	case comiss:
	case comisd:
		return fex_inv_cmp;

	case addss:
	case addsd:
	case subss:
	case subsd:
		if (t1 == fp_infinity && t2 == fp_infinity)
			return fex_inv_isi;
		break;

	case mulss:
	case mulsd:
		if ((t1 == fp_zero && t2 == fp_infinity) ||
		    (t2 == fp_zero && t1 == fp_infinity))
			return fex_inv_zmi;
		break;

	case divss:
	case divsd:
		if (t1 == fp_zero && t2 == fp_zero)
			return fex_inv_zdz;
		if (t1 == fp_infinity && t2 == fp_infinity)
			return fex_inv_idi;
	default:
		break;
	}

	return (enum fex_exception)-1;
}

/* inline templates */
extern void sse_cmpeqss(float *, float *, int *);
extern void sse_cmpltss(float *, float *, int *);
extern void sse_cmpless(float *, float *, int *);
extern void sse_cmpunordss(float *, float *, int *);
extern void sse_minss(float *, float *, float *);
extern void sse_maxss(float *, float *, float *);
extern void sse_addss(float *, float *, float *);
extern void sse_subss(float *, float *, float *);
extern void sse_mulss(float *, float *, float *);
extern void sse_divss(float *, float *, float *);
extern void sse_sqrtss(float *, float *);
extern void sse_ucomiss(float *, float *);
extern void sse_comiss(float *, float *);
extern void sse_cvtss2sd(float *, double *);
extern void sse_cvtsi2ss(int *, float *);
extern void sse_cvttss2si(float *, int *);
extern void sse_cvtss2si(float *, int *);
#ifdef __amd64
extern void sse_cvtsi2ssq(long long *, float *);
extern void sse_cvttss2siq(float *, long long *);
extern void sse_cvtss2siq(float *, long long *);
#endif
extern void sse_cmpeqsd(double *, double *, long long *);
extern void sse_cmpltsd(double *, double *, long long *);
extern void sse_cmplesd(double *, double *, long long *);
extern void sse_cmpunordsd(double *, double *, long long *);
extern void sse_minsd(double *, double *, double *);
extern void sse_maxsd(double *, double *, double *);
extern void sse_addsd(double *, double *, double *);
extern void sse_subsd(double *, double *, double *);
extern void sse_mulsd(double *, double *, double *);
extern void sse_divsd(double *, double *, double *);
extern void sse_sqrtsd(double *, double *);
extern void sse_ucomisd(double *, double *);
extern void sse_comisd(double *, double *);
extern void sse_cvtsd2ss(double *, float *);
extern void sse_cvtsi2sd(int *, double *);
extern void sse_cvttsd2si(double *, int *);
extern void sse_cvtsd2si(double *, int *);
#ifdef __amd64
extern void sse_cvtsi2sdq(long long *, double *);
extern void sse_cvttsd2siq(double *, long long *);
extern void sse_cvtsd2siq(double *, long long *);
#endif

/*
 * Fill in *info with the operands, default untrapped result, and
 * flags produced by a scalar SSE instruction, and return the type
 * of trapped exception (if any).  On entry, the mxcsr must have
 * all exceptions masked and all flags clear.  The same conditions
 * will hold on exit.
 *
 * This routine does not work if the instruction specified by *inst
 * is not a scalar instruction.
 */
enum fex_exception
__fex_get_sse_op(ucontext_t *uap, sseinst_t *inst, fex_info_t *info)
{
	unsigned int	e, te, mxcsr, oldmxcsr, subnorm;

	/*
	 * Perform the operation with traps disabled and check the
	 * exception flags.  If the underflow trap was enabled, also
	 * check for an exact subnormal result.
	 */
	__fenv_getmxcsr(&oldmxcsr);
	subnorm = 0;
	if ((int)inst->op & DOUBLE) {
		if (inst->op == cvtsi2sd) {
			info->op1.type = fex_int;
			info->op1.val.i = inst->op2->i[0];
			info->op2.type = fex_nodata;
		} else if (inst->op == cvtsi2sdq) {
			info->op1.type = fex_llong;
			info->op1.val.l = inst->op2->l[0];
			info->op2.type = fex_nodata;
		} else if (inst->op == sqrtsd || inst->op == cvtsd2ss ||
		    inst->op == cvttsd2si || inst->op == cvtsd2si ||
		    inst->op == cvttsd2siq || inst->op == cvtsd2siq) {
			info->op1.type = fex_double;
			info->op1.val.d = inst->op2->d[0];
			info->op2.type = fex_nodata;
		} else {
			info->op1.type = fex_double;
			info->op1.val.d = inst->op1->d[0];
			info->op2.type = fex_double;
			info->op2.val.d = inst->op2->d[0];
		}
		info->res.type = fex_double;
		switch (inst->op) {
		case cmpsd:
			info->op = fex_cmp;
			info->res.type = fex_llong;
			switch (inst->imm & 3) {
			case 0:
				sse_cmpeqsd(&info->op1.val.d, &info->op2.val.d,
				    &info->res.val.l);
				break;

			case 1:
				sse_cmpltsd(&info->op1.val.d, &info->op2.val.d,
				    &info->res.val.l);
				break;

			case 2:
				sse_cmplesd(&info->op1.val.d, &info->op2.val.d,
				    &info->res.val.l);
				break;

			case 3:
				sse_cmpunordsd(&info->op1.val.d,
				    &info->op2.val.d, &info->res.val.l);
			}
			if (inst->imm & 4)
				info->res.val.l ^= 0xffffffffffffffffull;
			break;

		case minsd:
			info->op = fex_other;
			sse_minsd(&info->op1.val.d, &info->op2.val.d,
			    &info->res.val.d);
			break;

		case maxsd:
			info->op = fex_other;
			sse_maxsd(&info->op1.val.d, &info->op2.val.d,
			    &info->res.val.d);
			break;

		case addsd:
			info->op = fex_add;
			sse_addsd(&info->op1.val.d, &info->op2.val.d,
			    &info->res.val.d);
			if (my_fp_class(&info->res.val.d) == fp_subnormal)
				subnorm = 1;
			break;

		case subsd:
			info->op = fex_sub;
			sse_subsd(&info->op1.val.d, &info->op2.val.d,
			    &info->res.val.d);
			if (my_fp_class(&info->res.val.d) == fp_subnormal)
				subnorm = 1;
			break;

		case mulsd:
			info->op = fex_mul;
			sse_mulsd(&info->op1.val.d, &info->op2.val.d,
			    &info->res.val.d);
			if (my_fp_class(&info->res.val.d) == fp_subnormal)
				subnorm = 1;
			break;

		case divsd:
			info->op = fex_div;
			sse_divsd(&info->op1.val.d, &info->op2.val.d,
			    &info->res.val.d);
			if (my_fp_class(&info->res.val.d) == fp_subnormal)
				subnorm = 1;
			break;

		case sqrtsd:
			info->op = fex_sqrt;
			sse_sqrtsd(&info->op1.val.d, &info->res.val.d);
			break;

		case cvtsd2ss:
			info->op = fex_cnvt;
			info->res.type = fex_float;
			sse_cvtsd2ss(&info->op1.val.d, &info->res.val.f);
			if (my_fp_classf(&info->res.val.f) == fp_subnormal)
				subnorm = 1;
			break;

		case cvtsi2sd:
			info->op = fex_cnvt;
			sse_cvtsi2sd(&info->op1.val.i, &info->res.val.d);
			break;

		case cvttsd2si:
			info->op = fex_cnvt;
			info->res.type = fex_int;
			sse_cvttsd2si(&info->op1.val.d, &info->res.val.i);
			break;

		case cvtsd2si:
			info->op = fex_cnvt;
			info->res.type = fex_int;
			sse_cvtsd2si(&info->op1.val.d, &info->res.val.i);
			break;

#ifdef __amd64
		case cvtsi2sdq:
			info->op = fex_cnvt;
			sse_cvtsi2sdq(&info->op1.val.l, &info->res.val.d);
			break;

		case cvttsd2siq:
			info->op = fex_cnvt;
			info->res.type = fex_llong;
			sse_cvttsd2siq(&info->op1.val.d, &info->res.val.l);
			break;

		case cvtsd2siq:
			info->op = fex_cnvt;
			info->res.type = fex_llong;
			sse_cvtsd2siq(&info->op1.val.d, &info->res.val.l);
			break;
#endif

		case ucomisd:
			info->op = fex_cmp;
			info->res.type = fex_nodata;
			sse_ucomisd(&info->op1.val.d, &info->op2.val.d);
			break;

		case comisd:
			info->op = fex_cmp;
			info->res.type = fex_nodata;
			sse_comisd(&info->op1.val.d, &info->op2.val.d);
			break;
		default:
			break;
		}
	} else {
		if (inst->op == cvtsi2ss) {
			info->op1.type = fex_int;
			info->op1.val.i = inst->op2->i[0];
			info->op2.type = fex_nodata;
		} else if (inst->op == cvtsi2ssq) {
			info->op1.type = fex_llong;
			info->op1.val.l = inst->op2->l[0];
			info->op2.type = fex_nodata;
		} else if (inst->op == sqrtss || inst->op == cvtss2sd ||
		    inst->op == cvttss2si || inst->op == cvtss2si ||
		    inst->op == cvttss2siq || inst->op == cvtss2siq) {
			info->op1.type = fex_float;
			info->op1.val.f = inst->op2->f[0];
			info->op2.type = fex_nodata;
		} else {
			info->op1.type = fex_float;
			info->op1.val.f = inst->op1->f[0];
			info->op2.type = fex_float;
			info->op2.val.f = inst->op2->f[0];
		}
		info->res.type = fex_float;
		switch (inst->op) {
		case cmpss:
			info->op = fex_cmp;
			info->res.type = fex_int;
			switch (inst->imm & 3) {
			case 0:
				sse_cmpeqss(&info->op1.val.f, &info->op2.val.f,
				    &info->res.val.i);
				break;

			case 1:
				sse_cmpltss(&info->op1.val.f, &info->op2.val.f,
				    &info->res.val.i);
				break;

			case 2:
				sse_cmpless(&info->op1.val.f, &info->op2.val.f,
				    &info->res.val.i);
				break;

			case 3:
				sse_cmpunordss(&info->op1.val.f,
				    &info->op2.val.f, &info->res.val.i);
			}
			if (inst->imm & 4)
				info->res.val.i ^= 0xffffffffu;
			break;

		case minss:
			info->op = fex_other;
			sse_minss(&info->op1.val.f, &info->op2.val.f,
			    &info->res.val.f);
			break;

		case maxss:
			info->op = fex_other;
			sse_maxss(&info->op1.val.f, &info->op2.val.f,
			    &info->res.val.f);
			break;

		case addss:
			info->op = fex_add;
			sse_addss(&info->op1.val.f, &info->op2.val.f,
			    &info->res.val.f);
			if (my_fp_classf(&info->res.val.f) == fp_subnormal)
				subnorm = 1;
			break;

		case subss:
			info->op = fex_sub;
			sse_subss(&info->op1.val.f, &info->op2.val.f,
			    &info->res.val.f);
			if (my_fp_classf(&info->res.val.f) == fp_subnormal)
				subnorm = 1;
			break;

		case mulss:
			info->op = fex_mul;
			sse_mulss(&info->op1.val.f, &info->op2.val.f,
			    &info->res.val.f);
			if (my_fp_classf(&info->res.val.f) == fp_subnormal)
				subnorm = 1;
			break;

		case divss:
			info->op = fex_div;
			sse_divss(&info->op1.val.f, &info->op2.val.f,
			    &info->res.val.f);
			if (my_fp_classf(&info->res.val.f) == fp_subnormal)
				subnorm = 1;
			break;

		case sqrtss:
			info->op = fex_sqrt;
			sse_sqrtss(&info->op1.val.f, &info->res.val.f);
			break;

		case cvtss2sd:
			info->op = fex_cnvt;
			info->res.type = fex_double;
			sse_cvtss2sd(&info->op1.val.f, &info->res.val.d);
			break;

		case cvtsi2ss:
			info->op = fex_cnvt;
			sse_cvtsi2ss(&info->op1.val.i, &info->res.val.f);
			break;

		case cvttss2si:
			info->op = fex_cnvt;
			info->res.type = fex_int;
			sse_cvttss2si(&info->op1.val.f, &info->res.val.i);
			break;

		case cvtss2si:
			info->op = fex_cnvt;
			info->res.type = fex_int;
			sse_cvtss2si(&info->op1.val.f, &info->res.val.i);
			break;

#ifdef __amd64
		case cvtsi2ssq:
			info->op = fex_cnvt;
			sse_cvtsi2ssq(&info->op1.val.l, &info->res.val.f);
			break;

		case cvttss2siq:
			info->op = fex_cnvt;
			info->res.type = fex_llong;
			sse_cvttss2siq(&info->op1.val.f, &info->res.val.l);
			break;

		case cvtss2siq:
			info->op = fex_cnvt;
			info->res.type = fex_llong;
			sse_cvtss2siq(&info->op1.val.f, &info->res.val.l);
			break;
#endif

		case ucomiss:
			info->op = fex_cmp;
			info->res.type = fex_nodata;
			sse_ucomiss(&info->op1.val.f, &info->op2.val.f);
			break;

		case comiss:
			info->op = fex_cmp;
			info->res.type = fex_nodata;
			sse_comiss(&info->op1.val.f, &info->op2.val.f);
			break;
		default:
			break;
		}
	}
	__fenv_getmxcsr(&mxcsr);
	info->flags = mxcsr & 0x3d;
	__fenv_setmxcsr(&oldmxcsr);

	/* determine which exception would have been trapped */
	te = ~(uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.mxcsr
	    >> 7) & 0x3d;
	e = mxcsr & te;
	if (e & FE_INVALID)
		return __fex_get_sse_invalid_type(inst);
	if (e & FE_DIVBYZERO)
		return fex_division;
	if (e & FE_OVERFLOW)
		return fex_overflow;
	if ((e & FE_UNDERFLOW) || (subnorm && (te & FE_UNDERFLOW)))
		return fex_underflow;
	if (e & FE_INEXACT)
		return fex_inexact;
	return (enum fex_exception)-1;
}

/*
 * Emulate a SIMD SSE instruction to determine which exceptions occur
 * in each part.  For i = 0, 1, 2, and 3, set e[i] to indicate the
 * trapped exception that would occur if the i-th part of the SIMD
 * instruction were executed in isolation; set e[i] to -1 if no
 * trapped exception would occur in this part.  Also fill in info[i]
 * with the corresponding operands, default untrapped result, and
 * flags.
 *
 * This routine does not work if the instruction specified by *inst
 * is not a SIMD instruction.
 */
void
__fex_get_simd_op(ucontext_t *uap, sseinst_t *inst, enum fex_exception *e,
    fex_info_t *info)
{
	sseinst_t	dummy;
	int		i;

	e[0] = e[1] = e[2] = e[3] = -1;

	/* perform each part of the SIMD operation */
	switch (inst->op) {
	case cmpps:
		dummy.op = cmpss;
		dummy.imm = inst->imm;
		for (i = 0; i < 4; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->f[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->f[i];
			e[i] = __fex_get_sse_op(uap, &dummy, &info[i]);
		}
		break;

	case minps:
		dummy.op = minss;
		for (i = 0; i < 4; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->f[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->f[i];
			e[i] = __fex_get_sse_op(uap, &dummy, &info[i]);
		}
		break;

	case maxps:
		dummy.op = maxss;
		for (i = 0; i < 4; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->f[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->f[i];
			e[i] = __fex_get_sse_op(uap, &dummy, &info[i]);
		}
		break;

	case addps:
		dummy.op = addss;
		for (i = 0; i < 4; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->f[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->f[i];
			e[i] = __fex_get_sse_op(uap, &dummy, &info[i]);
		}
		break;

	case subps:
		dummy.op = subss;
		for (i = 0; i < 4; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->f[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->f[i];
			e[i] = __fex_get_sse_op(uap, &dummy, &info[i]);
		}
		break;

	case mulps:
		dummy.op = mulss;
		for (i = 0; i < 4; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->f[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->f[i];
			e[i] = __fex_get_sse_op(uap, &dummy, &info[i]);
		}
		break;

	case divps:
		dummy.op = divss;
		for (i = 0; i < 4; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->f[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->f[i];
			e[i] = __fex_get_sse_op(uap, &dummy, &info[i]);
		}
		break;

	case sqrtps:
		dummy.op = sqrtss;
		for (i = 0; i < 4; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->f[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->f[i];
			e[i] = __fex_get_sse_op(uap, &dummy, &info[i]);
		}
		break;

	case cvtdq2ps:
		dummy.op = cvtsi2ss;
		for (i = 0; i < 4; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->f[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->i[i];
			e[i] = __fex_get_sse_op(uap, &dummy, &info[i]);
		}
		break;

	case cvttps2dq:
		dummy.op = cvttss2si;
		for (i = 0; i < 4; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->i[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->f[i];
			e[i] = __fex_get_sse_op(uap, &dummy, &info[i]);
		}
		break;

	case cvtps2dq:
		dummy.op = cvtss2si;
		for (i = 0; i < 4; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->i[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->f[i];
			e[i] = __fex_get_sse_op(uap, &dummy, &info[i]);
		}
		break;

	case cvtpi2ps:
		dummy.op = cvtsi2ss;
		for (i = 0; i < 2; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->f[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->i[i];
			e[i] = __fex_get_sse_op(uap, &dummy, &info[i]);
		}
		break;

	case cvttps2pi:
		dummy.op = cvttss2si;
		for (i = 0; i < 2; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->i[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->f[i];
			e[i] = __fex_get_sse_op(uap, &dummy, &info[i]);
		}
		break;

	case cvtps2pi:
		dummy.op = cvtss2si;
		for (i = 0; i < 2; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->i[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->f[i];
			e[i] = __fex_get_sse_op(uap, &dummy, &info[i]);
		}
		break;

	case cmppd:
		dummy.op = cmpsd;
		dummy.imm = inst->imm;
		for (i = 0; i < 2; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->d[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->d[i];
			e[i] = __fex_get_sse_op(uap, &dummy, &info[i]);
		}
		break;

	case minpd:
		dummy.op = minsd;
		for (i = 0; i < 2; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->d[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->d[i];
			e[i] = __fex_get_sse_op(uap, &dummy, &info[i]);
		}
		break;

	case maxpd:
		dummy.op = maxsd;
		for (i = 0; i < 2; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->d[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->d[i];
			e[i] = __fex_get_sse_op(uap, &dummy, &info[i]);
		}
		break;

	case addpd:
		dummy.op = addsd;
		for (i = 0; i < 2; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->d[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->d[i];
			e[i] = __fex_get_sse_op(uap, &dummy, &info[i]);
		}
		break;

	case subpd:
		dummy.op = subsd;
		for (i = 0; i < 2; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->d[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->d[i];
			e[i] = __fex_get_sse_op(uap, &dummy, &info[i]);
		}
		break;

	case mulpd:
		dummy.op = mulsd;
		for (i = 0; i < 2; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->d[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->d[i];
			e[i] = __fex_get_sse_op(uap, &dummy, &info[i]);
		}
		break;

	case divpd:
		dummy.op = divsd;
		for (i = 0; i < 2; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->d[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->d[i];
			e[i] = __fex_get_sse_op(uap, &dummy, &info[i]);
		}
		break;

	case sqrtpd:
		dummy.op = sqrtsd;
		for (i = 0; i < 2; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->d[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->d[i];
			e[i] = __fex_get_sse_op(uap, &dummy, &info[i]);
		}
		break;

	case cvtpi2pd:
	case cvtdq2pd:
		dummy.op = cvtsi2sd;
		for (i = 0; i < 2; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->d[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->i[i];
			e[i] = __fex_get_sse_op(uap, &dummy, &info[i]);
		}
		break;

	case cvttpd2pi:
	case cvttpd2dq:
		dummy.op = cvttsd2si;
		for (i = 0; i < 2; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->i[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->d[i];
			e[i] = __fex_get_sse_op(uap, &dummy, &info[i]);
		}
		break;

	case cvtpd2pi:
	case cvtpd2dq:
		dummy.op = cvtsd2si;
		for (i = 0; i < 2; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->i[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->d[i];
			e[i] = __fex_get_sse_op(uap, &dummy, &info[i]);
		}
		break;

	case cvtps2pd:
		dummy.op = cvtss2sd;
		for (i = 0; i < 2; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->d[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->f[i];
			e[i] = __fex_get_sse_op(uap, &dummy, &info[i]);
		}
		break;

	case cvtpd2ps:
		dummy.op = cvtsd2ss;
		for (i = 0; i < 2; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->f[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->d[i];
			e[i] = __fex_get_sse_op(uap, &dummy, &info[i]);
		}
	default:
		break;
	}
}

/*
 * Store the result value from *info in the destination of the scalar
 * SSE instruction specified by *inst.  If no result is given but the
 * exception is underflow or overflow, supply the default trapped result.
 *
 * This routine does not work if the instruction specified by *inst
 * is not a scalar instruction.
 */
void
__fex_st_sse_result(ucontext_t *uap, sseinst_t *inst, enum fex_exception e,
    fex_info_t *info)
{
	int		i = 0;
	long long	l = 0L;;
	float		f = 0.0, fscl;
	double		d = 0.0L, dscl;

	/* for compares that write eflags, just set the flags
	   to indicate "unordered" */
	if (inst->op == ucomiss || inst->op == comiss ||
	    inst->op == ucomisd || inst->op == comisd) {
		uap->uc_mcontext.gregs[REG_PS] |= 0x45;
		return;
	}

	/* if info doesn't specify a result value, try to generate
	   the default trapped result */
	if (info->res.type == fex_nodata) {
		/* set scale factors for exponent wrapping */
		switch (e) {
		case fex_overflow:
			fscl = 1.262177448e-29f; /* 2^-96 */
			dscl = 6.441148769597133308e-232; /* 2^-768 */
			break;

		case fex_underflow:
			fscl = 7.922816251e+28f; /* 2^96 */
			dscl = 1.552518092300708935e+231; /* 2^768 */
			break;

		default:
			(void) __fex_get_sse_op(uap, inst, info);
			if (info->res.type == fex_nodata)
				return;
			goto stuff;
		}

		/* generate the wrapped result */
		if (inst->op == cvtsd2ss) {
			info->op1.type = fex_double;
			info->op1.val.d = inst->op2->d[0];
			info->op2.type = fex_nodata;
			info->res.type = fex_float;
			info->res.val.f = (float)(fscl * (fscl *
			    info->op1.val.d));
		} else if ((int)inst->op & DOUBLE) {
			info->op1.type = fex_double;
			info->op1.val.d = inst->op1->d[0];
			info->op2.type = fex_double;
			info->op2.val.d = inst->op2->d[0];
			info->res.type = fex_double;
			switch (inst->op) {
			case addsd:
				info->res.val.d = dscl * (dscl *
				    info->op1.val.d + dscl * info->op2.val.d);
				break;

			case subsd:
				info->res.val.d = dscl * (dscl *
				    info->op1.val.d - dscl * info->op2.val.d);
				break;

			case mulsd:
				info->res.val.d = (dscl * info->op1.val.d) *
				    (dscl * info->op2.val.d);
				break;

			case divsd:
				info->res.val.d = (dscl * info->op1.val.d) /
				    (info->op2.val.d / dscl);
				break;

			default:
				return;
			}
		} else {
			info->op1.type = fex_float;
			info->op1.val.f = inst->op1->f[0];
			info->op2.type = fex_float;
			info->op2.val.f = inst->op2->f[0];
			info->res.type = fex_float;
			switch (inst->op) {
			case addss:
				info->res.val.f = fscl * (fscl *
				    info->op1.val.f + fscl * info->op2.val.f);
				break;

			case subss:
				info->res.val.f = fscl * (fscl *
				    info->op1.val.f - fscl * info->op2.val.f);
				break;

			case mulss:
				info->res.val.f = (fscl * info->op1.val.f) *
				    (fscl * info->op2.val.f);
				break;

			case divss:
				info->res.val.f = (fscl * info->op1.val.f) /
				    (info->op2.val.f / fscl);
				break;

			default:
				return;
			}
		}
	}

	/* put the result in the destination */
stuff:
	if (inst->op == cmpss || inst->op == cvttss2si || inst->op == cvtss2si
	    || inst->op == cvttsd2si || inst->op == cvtsd2si) {
		switch (info->res.type) {
		case fex_int:
			i = info->res.val.i;
			break;

		case fex_llong:
			i = info->res.val.l;
			break;

		case fex_float:
			i = info->res.val.f;
			break;

		case fex_double:
			i = info->res.val.d;
			break;

		case fex_ldouble:
			i = info->res.val.q;
			break;

		default:
			break;
		}
		inst->op1->i[0] = i;
	} else if (inst->op == cmpsd || inst->op == cvttss2siq ||
	    inst->op == cvtss2siq || inst->op == cvttsd2siq ||
	    inst->op == cvtsd2siq) {
		switch (info->res.type) {
		case fex_int:
			l = info->res.val.i;
			break;

		case fex_llong:
			l = info->res.val.l;
			break;

		case fex_float:
			l = info->res.val.f;
			break;

		case fex_double:
			l = info->res.val.d;
			break;

		case fex_ldouble:
			l = info->res.val.q;
			break;

		default:
			break;
		}
		inst->op1->l[0] = l;
	} else if ((((int)inst->op & DOUBLE) && inst->op != cvtsd2ss) ||
	    inst->op == cvtss2sd) {
		switch (info->res.type) {
		case fex_int:
			d = info->res.val.i;
			break;

		case fex_llong:
			d = info->res.val.l;
			break;

		case fex_float:
			d = info->res.val.f;
			break;

		case fex_double:
			d = info->res.val.d;
			break;

		case fex_ldouble:
			d = info->res.val.q;
			break;

		default:
			break;
		}
		inst->op1->d[0] = d;
	} else {
		switch (info->res.type) {
		case fex_int:
			f = info->res.val.i;
			break;

		case fex_llong:
			f = info->res.val.l;
			break;

		case fex_float:
			f = info->res.val.f;
			break;

		case fex_double:
			f = info->res.val.d;
			break;

		case fex_ldouble:
			f = info->res.val.q;
			break;

		default:
			break;
		}
		inst->op1->f[0] = f;
	}
}

/*
 * Store the results from a SIMD instruction.  For each i, store
 * the result value from info[i] in the i-th part of the destination
 * of the SIMD SSE instruction specified by *inst.  If no result
 * is given but the exception indicated by e[i] is underflow or
 * overflow, supply the default trapped result.
 *
 * This routine does not work if the instruction specified by *inst
 * is not a SIMD instruction.
 */
void
__fex_st_simd_result(ucontext_t *uap, sseinst_t *inst, enum fex_exception *e,
    fex_info_t *info)
{
	sseinst_t	dummy;
	int		i;

	/* store each part */
	switch (inst->op) {
	case cmpps:
		dummy.op = cmpss;
		dummy.imm = inst->imm;
		for (i = 0; i < 4; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->f[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->f[i];
			__fex_st_sse_result(uap, &dummy, e[i], &info[i]);
		}
		break;

	case minps:
		dummy.op = minss;
		for (i = 0; i < 4; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->f[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->f[i];
			__fex_st_sse_result(uap, &dummy, e[i], &info[i]);
		}
		break;

	case maxps:
		dummy.op = maxss;
		for (i = 0; i < 4; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->f[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->f[i];
			__fex_st_sse_result(uap, &dummy, e[i], &info[i]);
		}
		break;

	case addps:
		dummy.op = addss;
		for (i = 0; i < 4; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->f[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->f[i];
			__fex_st_sse_result(uap, &dummy, e[i], &info[i]);
		}
		break;

	case subps:
		dummy.op = subss;
		for (i = 0; i < 4; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->f[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->f[i];
			__fex_st_sse_result(uap, &dummy, e[i], &info[i]);
		}
		break;

	case mulps:
		dummy.op = mulss;
		for (i = 0; i < 4; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->f[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->f[i];
			__fex_st_sse_result(uap, &dummy, e[i], &info[i]);
		}
		break;

	case divps:
		dummy.op = divss;
		for (i = 0; i < 4; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->f[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->f[i];
			__fex_st_sse_result(uap, &dummy, e[i], &info[i]);
		}
		break;

	case sqrtps:
		dummy.op = sqrtss;
		for (i = 0; i < 4; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->f[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->f[i];
			__fex_st_sse_result(uap, &dummy, e[i], &info[i]);
		}
		break;

	case cvtdq2ps:
		dummy.op = cvtsi2ss;
		for (i = 0; i < 4; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->f[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->i[i];
			__fex_st_sse_result(uap, &dummy, e[i], &info[i]);
		}
		break;

	case cvttps2dq:
		dummy.op = cvttss2si;
		for (i = 0; i < 4; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->i[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->f[i];
			__fex_st_sse_result(uap, &dummy, e[i], &info[i]);
		}
		break;

	case cvtps2dq:
		dummy.op = cvtss2si;
		for (i = 0; i < 4; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->i[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->f[i];
			__fex_st_sse_result(uap, &dummy, e[i], &info[i]);
		}
		break;

	case cvtpi2ps:
		dummy.op = cvtsi2ss;
		for (i = 0; i < 2; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->f[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->i[i];
			__fex_st_sse_result(uap, &dummy, e[i], &info[i]);
		}
		break;

	case cvttps2pi:
		dummy.op = cvttss2si;
		for (i = 0; i < 2; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->i[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->f[i];
			__fex_st_sse_result(uap, &dummy, e[i], &info[i]);
		}
		break;

	case cvtps2pi:
		dummy.op = cvtss2si;
		for (i = 0; i < 2; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->i[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->f[i];
			__fex_st_sse_result(uap, &dummy, e[i], &info[i]);
		}
		break;

	case cmppd:
		dummy.op = cmpsd;
		dummy.imm = inst->imm;
		for (i = 0; i < 2; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->d[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->d[i];
			__fex_st_sse_result(uap, &dummy, e[i], &info[i]);
		}
		break;

	case minpd:
		dummy.op = minsd;
		for (i = 0; i < 2; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->d[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->d[i];
			__fex_st_sse_result(uap, &dummy, e[i], &info[i]);
		}
		break;

	case maxpd:
		dummy.op = maxsd;
		for (i = 0; i < 2; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->d[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->d[i];
			__fex_st_sse_result(uap, &dummy, e[i], &info[i]);
		}
		break;

	case addpd:
		dummy.op = addsd;
		for (i = 0; i < 2; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->d[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->d[i];
			__fex_st_sse_result(uap, &dummy, e[i], &info[i]);
		}
		break;

	case subpd:
		dummy.op = subsd;
		for (i = 0; i < 2; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->d[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->d[i];
			__fex_st_sse_result(uap, &dummy, e[i], &info[i]);
		}
		break;

	case mulpd:
		dummy.op = mulsd;
		for (i = 0; i < 2; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->d[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->d[i];
			__fex_st_sse_result(uap, &dummy, e[i], &info[i]);
		}
		break;

	case divpd:
		dummy.op = divsd;
		for (i = 0; i < 2; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->d[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->d[i];
			__fex_st_sse_result(uap, &dummy, e[i], &info[i]);
		}
		break;

	case sqrtpd:
		dummy.op = sqrtsd;
		for (i = 0; i < 2; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->d[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->d[i];
			__fex_st_sse_result(uap, &dummy, e[i], &info[i]);
		}
		break;

	case cvtpi2pd:
	case cvtdq2pd:
		dummy.op = cvtsi2sd;
		for (i = 0; i < 2; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->d[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->i[i];
			__fex_st_sse_result(uap, &dummy, e[i], &info[i]);
		}
		break;

	case cvttpd2pi:
	case cvttpd2dq:
		dummy.op = cvttsd2si;
		for (i = 0; i < 2; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->i[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->d[i];
			__fex_st_sse_result(uap, &dummy, e[i], &info[i]);
		}
		/* for cvttpd2dq, zero the high 64 bits of the destination */
		if (inst->op == cvttpd2dq)
			inst->op1->l[1] = 0ll;
		break;

	case cvtpd2pi:
	case cvtpd2dq:
		dummy.op = cvtsd2si;
		for (i = 0; i < 2; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->i[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->d[i];
			__fex_st_sse_result(uap, &dummy, e[i], &info[i]);
		}
		/* for cvtpd2dq, zero the high 64 bits of the destination */
		if (inst->op == cvtpd2dq)
			inst->op1->l[1] = 0ll;
		break;

	case cvtps2pd:
		dummy.op = cvtss2sd;
		for (i = 0; i < 2; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->d[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->f[i];
			__fex_st_sse_result(uap, &dummy, e[i], &info[i]);
		}
		break;

	case cvtpd2ps:
		dummy.op = cvtsd2ss;
		for (i = 0; i < 2; i++) {
			dummy.op1 = (sseoperand_t *)&inst->op1->f[i];
			dummy.op2 = (sseoperand_t *)&inst->op2->d[i];
			__fex_st_sse_result(uap, &dummy, e[i], &info[i]);
		}
		/* zero the high 64 bits of the destination */
		inst->op1->l[1] = 0ll;

	default:
		break;
	}
}

