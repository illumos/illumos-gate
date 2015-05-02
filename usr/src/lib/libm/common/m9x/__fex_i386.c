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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <siginfo.h>
#include <ucontext.h>
#include <thread.h>
#include <math.h>
#if defined(__SUNPRO_C)
#include <sunmath.h>
#endif
#include <fenv.h>
#include <sys/regset.h>
#include "fex_handler.h"
#include "fenv_inlines.h"

#if defined(__amd64)
#define test_sse_hw	1
#else
/*
 * The following variable lives in libc on Solaris 10, where it
 * gets set to a nonzero value at startup time on systems with SSE.
 */
extern int _sse_hw;
#define test_sse_hw	_sse_hw
#endif

static int accrued = 0;
static thread_key_t accrued_key;
static mutex_t accrued_key_lock = DEFAULTMUTEX;

int *
__fex_accrued()
{
	int		*p;

	if (thr_main())
		return &accrued;
	else {
		p = NULL;
		mutex_lock(&accrued_key_lock);
		if (thr_getspecific(accrued_key, (void **)&p) != 0 &&
			thr_keycreate(&accrued_key, free) != 0) {
			mutex_unlock(&accrued_key_lock);
			return NULL;
		}
		mutex_unlock(&accrued_key_lock);
		if (!p) {
			if ((p = (int*) malloc(sizeof(int))) == NULL)
				return NULL;
			if (thr_setspecific(accrued_key, (void *)p) != 0) {
				(void)free(p);
				return NULL;
			}
			*p = 0;
		}
		return p;
	}
}

void
__fenv_getfsr(unsigned long *fsr)
{
	unsigned int	cwsw, mxcsr;

	__fenv_getcwsw(&cwsw);
	/* clear reserved bits for no particularly good reason */
	cwsw &= ~0xe0c00000u;
	if (test_sse_hw) {
		/* pick up exception flags (excluding denormal operand
		   flag) from mxcsr */
		__fenv_getmxcsr(&mxcsr);
		cwsw |= (mxcsr & 0x3d);
	}
	cwsw |= *__fex_accrued();
	*fsr = cwsw ^ 0x003f0000u;
}

void
__fenv_setfsr(const unsigned long *fsr)
{
	unsigned int	cwsw, mxcsr;
	int				te;

	/* save accrued exception flags corresponding to enabled exceptions */
	cwsw = (unsigned int)*fsr;
	te = __fenv_get_te(cwsw);
	*__fex_accrued() = cwsw & te;
	cwsw = (cwsw & ~te) ^ 0x003f0000;
	if (test_sse_hw) {
		/* propagate rounding direction, masks, and exception flags
		   (excluding denormal operand mask and flag) to mxcsr */
		__fenv_getmxcsr(&mxcsr);
		mxcsr = (mxcsr & ~0x7ebd) | ((cwsw >> 13) & 0x6000) |
			((cwsw >> 9) & 0x1e80) | (cwsw & 0x3d);
		__fenv_setmxcsr(&mxcsr);
	}
	__fenv_setcwsw(&cwsw);
}

/* Offsets into the fp environment save area (assumes 32-bit protected mode) */
#define CW	0	/* control word */
#define SW	1	/* status word */
#define TW	2	/* tag word */
#define IP	3	/* instruction pointer */
#define OP	4	/* opcode */
#define EA	5	/* operand address */

/* macro for accessing fp registers in the save area */
#if defined(__amd64)
#define fpreg(u,x)	*(long double *)(10*(x)+(char*)&(u)->uc_mcontext.fpregs.fp_reg_set.fpchip_state.st)
#else
#define fpreg(u,x)	*(long double *)(10*(x)+(char*)&(u)->uc_mcontext.fpregs.fp_reg_set.fpchip_state.state[7])
#endif

/*
*  Fix sip->si_code; the Solaris x86 kernel can get it wrong
*/
void
__fex_get_x86_exc(siginfo_t *sip, ucontext_t *uap)
{
	unsigned	sw, cw;

	sw = uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.status;
#if defined(__amd64)
	cw = uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.cw;
#else
	cw = uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.state[CW];
#endif
	if ((sw & FE_INVALID) && !(cw & (1 << fp_trap_invalid)))
		/* store 0 for stack fault, FPE_FLTINV for IEEE invalid op */
		sip->si_code = ((sw & 0x40)? 0 : FPE_FLTINV);
	else if ((sw & FE_DIVBYZERO) && !(cw & (1 << fp_trap_division)))
		sip->si_code = FPE_FLTDIV;
	else if ((sw & FE_OVERFLOW) && !(cw & (1 << fp_trap_overflow)))
		sip->si_code = FPE_FLTOVF;
	else if ((sw & FE_UNDERFLOW) && !(cw & (1 << fp_trap_underflow)))
		sip->si_code = FPE_FLTUND;
	else if ((sw & FE_INEXACT) && !(cw & (1 << fp_trap_inexact)))
		sip->si_code = FPE_FLTRES;
	else
		sip->si_code = 0;
}

static enum fp_class_type
my_fp_classf(float *x)
{
	int		i = *(int*)x & ~0x80000000;

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
	int		i = *(1+(int*)x) & ~0x80000000;

	if (i < 0x7ff00000) {
		if (i < 0x00100000)
			return (((i | *(int*)x) == 0)? fp_zero : fp_subnormal);
		return fp_normal;
	}
	else if (i == 0x7ff00000 && *(int*)x == 0)
		return fp_infinity;
	else if (i & 0x80000)
		return fp_quiet;
	else
		return fp_signaling;
}

static enum fp_class_type
my_fp_classl(long double *x)
{
	int		i = *(2+(int*)x) & 0x7fff;

	if (i < 0x7fff) {
		if (i < 1) {
			if (*(1+(int*)x) < 0) return fp_normal; /* pseudo-denormal */
			return (((*(1+(int*)x) | *(int*)x) == 0)?
				fp_zero : fp_subnormal);
		}
		return ((*(1+(int*)x) < 0)? fp_normal :
			(enum fp_class_type) -1); /* unsupported format */
	}
	else if (*(1+(int*)x) == 0x80000000 && *(int*)x == 0)
		return fp_infinity;
	else if (*(1+(unsigned*)x) >= 0xc0000000)
		return fp_quiet;
	else if (*(1+(int*)x) < 0)
		return fp_signaling;
	else
		return (enum fp_class_type) -1; /* unsupported format */
}

/*
*  Determine which type of invalid operation exception occurred
*/
enum fex_exception
__fex_get_invalid_type(siginfo_t *sip, ucontext_t *uap)
{
	unsigned			op;
	unsigned long			ea;
	enum fp_class_type	t1, t2;

	/* get the opcode and data address */
#if defined(__amd64)
	op = uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.fop >> 16;
	ea = uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.rdp;
#else
	op = uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.state[OP] >> 16;
	ea = uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.state[EA];
#endif

	/* if the instruction is fld, the source must be snan (it can't be
	   an unsupported format, since fldt doesn't raise any exceptions) */
	switch (op & 0x7f8) {
	case 0x100:
	case 0x140:
	case 0x180:
	case 0x500:
	case 0x540:
	case 0x580:
		return fex_inv_snan;
	}

	/* otherwise st is one of the operands; see if it's snan */
	t1 = my_fp_classl(&fpreg(uap, 0));
	if (t1 == fp_signaling)
		return fex_inv_snan;
	else if (t1 == (enum fp_class_type) -1)
		return (enum fex_exception) -1;

	/* determine the class of the second operand if there is one */
	t2 = fp_normal;
	switch (op & 0x7e0) {
	case 0x600:
	case 0x620:
	case 0x640:
	case 0x660:
	case 0x680:
	case 0x6a0:
		/* short memory operand */
		if (!ea)
			return (enum fex_exception) -1;
		if (*(short *)ea == 0)
			t2 = fp_zero;
		break;

	case 0x200:
	case 0x220:
	case 0x240:
	case 0x260:
	case 0x280:
	case 0x2a0:
		/* int memory operand */
		if (!ea)
			return (enum fex_exception) -1;
		if (*(int *)ea == 0)
			t2 = fp_zero;
		break;

	case 0x000:
	case 0x020:
	case 0x040:
	case 0x060:
	case 0x080:
	case 0x0a0:
		/* single precision memory operand */
		if (!ea)
			return (enum fex_exception) -1;
		t2 = my_fp_classf((float *)ea);
		break;

	case 0x400:
	case 0x420:
	case 0x440:
	case 0x460:
	case 0x480:
	case 0x4a0:
		/* double precision memory operand */
		if (!ea)
			return (enum fex_exception) -1;
		t2 = my_fp_class((double *)ea);
		break;

	case 0x0c0:
	case 0x0e0:
	case 0x3e0:
	case 0x4c0:
	case 0x4e0:
	case 0x5e0:
	case 0x6c0:
	case 0x6e0:
	case 0x7e0:
		/* register operand determined by opcode */
		switch (op & 0x7f8) {
		case 0x3e0:
		case 0x3f8:
		case 0x5f0:
		case 0x5f8:
		case 0x7e0:
		case 0x7f8:
			/* weed out nonexistent opcodes */
			break;

		default:
			t2 = my_fp_classl(&fpreg(uap, op & 7));
		}
		break;

	case 0x1e0:
	case 0x2e0:
		/* special forms */
		switch (op) {
		case 0x1f1: /* fyl2x */
		case 0x1f3: /* fpatan */
		case 0x1f5: /* fprem1 */
		case 0x1f8: /* fprem */
		case 0x1f9: /* fyl2xp1 */
		case 0x1fd: /* fscale */
		case 0x2e9: /* fucompp */
			t2 = my_fp_classl(&fpreg(uap, 1));
			break;
		}
		break;
	}

	/* see if the second op is snan */
	if (t2 == fp_signaling)
		return fex_inv_snan;
	else if (t2 == (enum fp_class_type) -1)
		return (enum fex_exception) -1;

	/* determine the type of operation */
	switch (op & 0x7f8) {
	case 0x000:
	case 0x020:
	case 0x028:
	case 0x040:
	case 0x060:
	case 0x068:
	case 0x080:
	case 0x0a0:
	case 0x0a8:
	case 0x0c0:
	case 0x0e0:
	case 0x0e8:
	case 0x400:
	case 0x420:
	case 0x428:
	case 0x440:
	case 0x460:
	case 0x468:
	case 0x480:
	case 0x4a0:
	case 0x4a8:
	case 0x4c0:
	case 0x4e0:
	case 0x4e8:
	case 0x6c0:
	case 0x6e0:
	case 0x6e8:
		/* fadd, fsub, fsubr */
		if (t1 == fp_infinity && t2 == fp_infinity)
			return fex_inv_isi;
		break;

	case 0x008:
	case 0x048:
	case 0x088:
	case 0x0c8:
	case 0x208:
	case 0x248:
	case 0x288:
	case 0x408:
	case 0x448:
	case 0x488:
	case 0x4c8:
	case 0x608:
	case 0x648:
	case 0x688:
	case 0x6c8:
		/* fmul */
		if ((t1 == fp_zero && t2 == fp_infinity) || (t2 == fp_zero &&
		  t1 == fp_infinity))
			return fex_inv_zmi;
		break;

	case 0x030:
	case 0x038:
	case 0x070:
	case 0x078:
	case 0x0b0:
	case 0x0b8:
	case 0x0f0:
	case 0x0f8:
	case 0x230:
	case 0x238:
	case 0x270:
	case 0x278:
	case 0x2b0:
	case 0x2b8:
	case 0x430:
	case 0x438:
	case 0x470:
	case 0x478:
	case 0x4b0:
	case 0x4b8:
	case 0x4f0:
	case 0x4f8:
	case 0x630:
	case 0x638:
	case 0x670:
	case 0x678:
	case 0x6b0:
	case 0x6b8:
	case 0x6f0:
	case 0x6f8:
		/* fdiv */
		if (t1 == fp_zero && t2 == fp_zero)
			return fex_inv_zdz;
		else if (t1 == fp_infinity && t2 == fp_infinity)
			return fex_inv_idi;
		break;

	case 0x1f0:
	case 0x1f8:
		/* fsqrt, other special ops */
		return fex_inv_sqrt;

	case 0x010:
	case 0x018:
	case 0x050:
	case 0x058:
	case 0x090:
	case 0x098:
	case 0x0d0:
	case 0x0d8:
	case 0x210:
	case 0x218:
	case 0x250:
	case 0x258:
	case 0x290:
	case 0x298:
	case 0x2e8:
	case 0x3f0:
	case 0x410:
	case 0x418:
	case 0x450:
	case 0x458:
	case 0x490:
	case 0x498:
	case 0x4d0:
	case 0x4d8:
	case 0x5e0:
	case 0x5e8:
	case 0x610:
	case 0x618:
	case 0x650:
	case 0x658:
	case 0x690:
	case 0x698:
	case 0x6d0:
	case 0x6d8:
	case 0x7f0:
		/* fcom */
		if (t1 == fp_quiet || t2 == fp_quiet)
			return fex_inv_cmp;
		break;

	case 0x1e0:
		/* ftst */
		if (op == 0x1e4 && t1 == fp_quiet)
			return fex_inv_cmp;
		break;

	case 0x310:
	case 0x318:
	case 0x350:
	case 0x358:
	case 0x390:
	case 0x398:
	case 0x710:
	case 0x718:
	case 0x730:
	case 0x738:
	case 0x750:
	case 0x758:
	case 0x770:
	case 0x778:
	case 0x790:
	case 0x798:
	case 0x7b0:
	case 0x7b8:
		/* fist, fbst */
		return fex_inv_int;
	}

	return (enum fex_exception) -1;
}

/* scale factors for exponent unwrapping */
static const long double
	two12288 = 1.139165225263043370845938579315932009e+3699l,	/* 2^12288 */
	twom12288 = 8.778357852076208839765066529179033145e-3700l,	/* 2^-12288 */
	twom12288mulp = 8.778357852076208839289190796475222545e-3700l;
		/* (")*(1-2^-64) */

/* inline templates */
extern long double f2xm1(long double);
extern long double fyl2x(long double, long double);
extern long double fptan(long double);
extern long double fpatan(long double, long double);
extern long double fxtract(long double);
extern long double fprem1(long double, long double);
extern long double fprem(long double, long double);
extern long double fyl2xp1(long double, long double);
extern long double fsqrt(long double);
extern long double fsincos(long double);
extern long double frndint(long double);
extern long double fscale(long double, long double);
extern long double fsin(long double);
extern long double fcos(long double);

/*
*  Get the operands, generate the default untrapped result with
*  exceptions, and set a code indicating the type of operation
*/
void
__fex_get_op(siginfo_t *sip, ucontext_t *uap, fex_info_t *info)
{
	fex_numeric_t			t;
	long double			op2v, x;
	unsigned int			cwsw, ex, sw, op;
	unsigned long			ea;
	volatile int			c;

	/* get the exception type, status word, opcode, and data address */
	ex = sip->si_code;
	sw = uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.status;
#if defined(__amd64)
	op = uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.fop >> 16;
	ea = uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.rdp;
#else
	op = uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.state[OP] >> 16;
	ea = uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.state[EA];
#endif

	/* initialize res to the default untrapped result and ex to the
	   corresponding flags (assume trapping is disabled and flags
	   are clear) */

	/* single operand instructions */
	info->op = fex_cnvt;
	info->op2.type = fex_nodata;
	switch (op & 0x7f8) {
	/* load instructions */
	case 0x100:
	case 0x140:
	case 0x180:
		if (!ea) {
			info->op = fex_other;
			info->op1.type = info->op2.type = info->res.type = fex_nodata;
			info->flags = 0;
			return;
		}
		info->op1.type = fex_float;
		info->op1.val.f = *(float *)ea;
		info->res.type = fex_ldouble;
		info->res.val.q = (long double) info->op1.val.f;
		goto done;

	case 0x500:
	case 0x540:
	case 0x580:
		if (!ea) {
			info->op = fex_other;
			info->op1.type = info->op2.type = info->res.type = fex_nodata;
			info->flags = 0;
			return;
		}
		info->op1.type = fex_double;
		info->op1.val.d = *(double *)ea;
		info->res.type = fex_ldouble;
		info->res.val.q = (long double) info->op1.val.d;
		goto done;

	/* store instructions */
	case 0x110:
	case 0x118:
	case 0x150:
	case 0x158:
	case 0x190:
	case 0x198:
		info->res.type = fex_float;
		if (ex == FPE_FLTRES && (op & 8) != 0) {
			/* inexact, stack popped */
			if (!ea) {
				info->op = fex_other;
				info->op1.type = info->op2.type = info->res.type = fex_nodata;
				info->flags = 0;
				return;
			}
			info->op1.type = fex_nodata;
			info->res.val.f = *(float *)ea;
			info->flags = FE_INEXACT;
			return;
		}
		info->op1.type = fex_ldouble;
		info->op1.val.q = fpreg(uap, 0);
		info->res.val.f = (float) info->op1.val.q;
		goto done;

	case 0x310:
	case 0x318:
	case 0x350:
	case 0x358:
	case 0x390:
	case 0x398:
		info->res.type = fex_int;
		if (ex == FPE_FLTRES && (op & 8) != 0) {
			/* inexact, stack popped */
			if (!ea) {
				info->op = fex_other;
				info->op1.type = info->op2.type = info->res.type = fex_nodata;
				info->flags = 0;
				return;
			}
			info->op1.type = fex_nodata;
			info->res.val.i = *(int *)ea;
			info->flags = FE_INEXACT;
			return;
		}
		info->op1.type = fex_ldouble;
		info->op1.val.q = fpreg(uap, 0);
		info->res.val.i = (int) info->op1.val.q;
		goto done;

	case 0x510:
	case 0x518:
	case 0x550:
	case 0x558:
	case 0x590:
	case 0x598:
		info->res.type = fex_double;
		if (ex == FPE_FLTRES && (op & 8) != 0) {
			/* inexact, stack popped */
			if (!ea) {
				info->op = fex_other;
				info->op1.type = info->op2.type = info->res.type = fex_nodata;
				info->flags = 0;
				return;
			}
			info->op1.type = fex_nodata;
			info->res.val.d = *(double *)ea;
			info->flags = FE_INEXACT;
			return;
		}
		info->op1.type = fex_ldouble;
		info->op1.val.q = fpreg(uap, 0);
		info->res.val.d = (double) info->op1.val.q;
		goto done;

	case 0x710:
	case 0x718:
	case 0x750:
	case 0x758:
	case 0x790:
	case 0x798:
		info->res.type = fex_int;
		if (ex == FPE_FLTRES && (op & 8) != 0) {
			/* inexact, stack popped */
			if (!ea) {
				info->op = fex_other;
				info->op1.type = info->op2.type = info->res.type = fex_nodata;
				info->flags = 0;
				return;
			}
			info->op1.type = fex_nodata;
			info->res.val.i = *(short *)ea;
			info->flags = FE_INEXACT;
			return;
		}
		info->op1.type = fex_ldouble;
		info->op1.val.q = fpreg(uap, 0);
		info->res.val.i = (short) info->op1.val.q;
		goto done;

	case 0x730:
	case 0x770:
	case 0x7b0:
		/* fbstp; don't bother */
		info->op = fex_other;
		info->op1.type = info->res.type = fex_nodata;
		info->flags = 0;
		return;

	case 0x738:
	case 0x778:
	case 0x7b8:
		info->res.type = fex_llong;
		if (ex == FPE_FLTRES) {
			/* inexact, stack popped */
			if (!ea) {
				info->op = fex_other;
				info->op1.type = info->op2.type = info->res.type = fex_nodata;
				info->flags = 0;
				return;
			}
			info->op1.type = fex_nodata;
			info->res.val.l = *(long long *)ea;
			info->flags = FE_INEXACT;
			return;
		}
		info->op1.type = fex_ldouble;
		info->op1.val.q = fpreg(uap, 0);
		info->res.val.l = (long long) info->op1.val.q;
		goto done;
	}

	/* all other ops (except compares) have destinations on the stack
	   so overflow, underflow, and inexact will stomp their operands */
	if (ex == FPE_FLTOVF || ex == FPE_FLTUND || ex == FPE_FLTRES) {
		/* find the trapped result */
		info->op1.type = info->op2.type = fex_nodata;
		info->res.type = fex_ldouble;
		switch (op & 0x7f8) {
		case 0x1f0:
			/* fptan pushes 1.0 afterward, so result is in st(1) */
			info->res.val.q = ((op == 0x1f2)? fpreg(uap, 1) :
				fpreg(uap, 0));
			break;

		case 0x4c0:
		case 0x4c8:
		case 0x4e0:
		case 0x4e8:
		case 0x4f0:
		case 0x4f8:
			info->res.val.q = fpreg(uap, op & 7);
			break;

		case 0x6c0:
		case 0x6c8:
		case 0x6e0:
		case 0x6e8:
		case 0x6f0:
		case 0x6f8:
			/* stack was popped afterward */
			info->res.val.q = fpreg(uap, (op - 1) & 7);
			break;

		default:
			info->res.val.q = fpreg(uap, 0);
		}

		/* reconstruct default untrapped result */
		if (ex == FPE_FLTOVF) {
			/* generate an overflow with the sign of the result */
			x = two12288;
			*(4+(short*)&x) |= (*(4+(short*)&info->res.val.q) & 0x8000);
			info->res.val.q = x * two12288;
			info->flags = FE_OVERFLOW | FE_INEXACT;
			__fenv_getcwsw(&cwsw);
			cwsw &= ~FE_ALL_EXCEPT;
			__fenv_setcwsw(&cwsw);
		}
		else if (ex == FPE_FLTUND) {
			/* undo the scaling; we can't distinguish a chopped result
			   from an exact one without futzing around to trap all in-
			   exact exceptions so as to keep the flag clear, so we just
			   punt */
			if (sw & 0x200) /* result was rounded up */
				info->res.val.q = (info->res.val.q * twom12288) * twom12288mulp;
			else
				info->res.val.q = (info->res.val.q * twom12288) * twom12288;
			__fenv_getcwsw(&cwsw);
			info->flags = (cwsw & FE_INEXACT) | FE_UNDERFLOW;
			cwsw &= ~FE_ALL_EXCEPT;
			__fenv_setcwsw(&cwsw);
		}
		else
			info->flags = FE_INEXACT;

		/* determine the operation code */
		switch (op) {
		case 0x1f0: /* f2xm1 */
		case 0x1f1: /* fyl2x */
		case 0x1f2: /* fptan */
		case 0x1f3: /* fpatan */
		case 0x1f5: /* fprem1 */
		case 0x1f8: /* fprem */
		case 0x1f9: /* fyl2xp1 */
		case 0x1fb: /* fsincos */
		case 0x1fc: /* frndint */
		case 0x1fd: /* fscale */
		case 0x1fe: /* fsin */
		case 0x1ff: /* fcos */
			info->op = fex_other;
			return;

		case 0x1fa: /* fsqrt */
			info->op = fex_sqrt;
			return;
		}

		info->op = fex_other;
		switch (op & 0x7c0) {
		case 0x000:
		case 0x040:
		case 0x080:
		case 0x0c0:
		case 0x200:
		case 0x240:
		case 0x280:
		case 0x400:
		case 0x440:
		case 0x480:
		case 0x4c0:
		case 0x600:
		case 0x640:
		case 0x680:
		case 0x6c0:
			switch (op & 0x38) {
			case 0x00:
				info->op = fex_add;
				break;

			case 0x08:
				info->op = fex_mul;
				break;

			case 0x20:
			case 0x28:
				info->op = fex_sub;
				break;

			case 0x30:
			case 0x38:
				info->op = fex_div;
				break;
			}
		}
		return;
	}

	/* for other exceptions, the operands are preserved, so we can
	   just emulate the operation with traps disabled */

	/* one operand is always in st */
	info->op1.type = fex_ldouble;
	info->op1.val.q = fpreg(uap, 0);

	/* oddball instructions */
	info->op = fex_other;
	switch (op) {
	case 0x1e4: /* ftst */
		info->op = fex_cmp;
		info->op2.type = fex_ldouble;
		info->op2.val.q = 0.0l;
		info->res.type = fex_nodata;
		c = (info->op1.val.q < info->op2.val.q);
		goto done;

	case 0x1f0: /* f2xm1 */
		info->res.type = fex_ldouble;
		info->res.val.q = f2xm1(info->op1.val.q);
		goto done;

	case 0x1f1: /* fyl2x */
		info->op2.type = fex_ldouble;
		info->op2.val.q = fpreg(uap, 1);
		info->res.type = fex_ldouble;
		info->res.val.q = fyl2x(info->op1.val.q, info->op2.val.q);
		goto done;

	case 0x1f2: /* fptan */
		info->res.type = fex_ldouble;
		info->res.val.q = fptan(info->op1.val.q);
		goto done;

	case 0x1f3: /* fpatan */
		info->op2.type = fex_ldouble;
		info->op2.val.q = fpreg(uap, 1);
		info->res.type = fex_ldouble;
		info->res.val.q = fpatan(info->op1.val.q, info->op2.val.q);
		goto done;

	case 0x1f4: /* fxtract */
		info->res.type = fex_ldouble;
		info->res.val.q = fxtract(info->op1.val.q);
		goto done;

	case 0x1f5: /* fprem1 */
		info->op2.type = fex_ldouble;
		info->op2.val.q = fpreg(uap, 1);
		info->res.type = fex_ldouble;
		info->res.val.q = fprem1(info->op1.val.q, info->op2.val.q);
		goto done;

	case 0x1f8: /* fprem */
		info->op2.type = fex_ldouble;
		info->op2.val.q = fpreg(uap, 1);
		info->res.type = fex_ldouble;
		info->res.val.q = fprem(info->op1.val.q, info->op2.val.q);
		goto done;

	case 0x1f9: /* fyl2xp1 */
		info->op2.type = fex_ldouble;
		info->op2.val.q = fpreg(uap, 1);
		info->res.type = fex_ldouble;
		info->res.val.q = fyl2xp1(info->op1.val.q, info->op2.val.q);
		goto done;

	case 0x1fa: /* fsqrt */
		info->op = fex_sqrt;
		info->res.type = fex_ldouble;
		info->res.val.q = fsqrt(info->op1.val.q);
		goto done;

	case 0x1fb: /* fsincos */
		info->res.type = fex_ldouble;
		info->res.val.q = fsincos(info->op1.val.q);
		goto done;

	case 0x1fc: /* frndint */
		info->res.type = fex_ldouble;
		info->res.val.q = frndint(info->op1.val.q);
		goto done;

	case 0x1fd: /* fscale */
		info->op2.type = fex_ldouble;
		info->op2.val.q = fpreg(uap, 1);
		info->res.type = fex_ldouble;
		info->res.val.q = fscale(info->op1.val.q, info->op2.val.q);
		goto done;

	case 0x1fe: /* fsin */
		info->res.type = fex_ldouble;
		info->res.val.q = fsin(info->op1.val.q);
		goto done;

	case 0x1ff: /* fcos */
		info->res.type = fex_ldouble;
		info->res.val.q = fcos(info->op1.val.q);
		goto done;

	case 0x2e9: /* fucompp */
		info->op = fex_cmp;
		info->op2.type = fex_ldouble;
		info->op2.val.q = fpreg(uap, 1);
		info->res.type = fex_nodata;
		c = (info->op1.val.q == info->op2.val.q);
		goto done;
	}

	/* fucom[p], fcomi[p], fucomi[p] */
	switch (op & 0x7f8) {
	case 0x3e8:
	case 0x5e0:
	case 0x5e8:
	case 0x7e8: /* unordered compares */
		info->op = fex_cmp;
		info->op2.type = fex_ldouble;
		info->op2.val.q = fpreg(uap, op & 7);
		info->res.type = fex_nodata;
		c = (info->op1.val.q == info->op2.val.q);
		goto done;

	case 0x3f0:
	case 0x7f0: /* ordered compares */
		info->op = fex_cmp;
		info->op2.type = fex_ldouble;
		info->op2.val.q = fpreg(uap, op & 7);
		info->res.type = fex_nodata;
		c = (info->op1.val.q < info->op2.val.q);
		goto done;
	}

	/* all other instructions come in groups of the form
	   fadd, fmul, fcom, fcomp, fsub, fsubr, fdiv, fdivr */

	/* get the second operand */
	switch (op & 0x7c0) {
	case 0x000:
	case 0x040:
	case 0x080:
		if (!ea) {
			info->op = fex_other;
			info->op1.type = info->op2.type = info->res.type = fex_nodata;
			info->flags = 0;
			return;
		}
		info->op2.type = fex_float;
		info->op2.val.f = *(float *)ea;
		op2v = (long double) info->op2.val.f;
		break;

	case 0x0c0:
		info->op2.type = fex_ldouble;
		op2v = info->op2.val.q = fpreg(uap, op & 7);
		break;

	case 0x200:
	case 0x240:
	case 0x280:
		if (!ea) {
			info->op = fex_other;
			info->op1.type = info->op2.type = info->res.type = fex_nodata;
			info->flags = 0;
			return;
		}
		info->op2.type = fex_int;
		info->op2.val.i = *(int *)ea;
		op2v = (long double) info->op2.val.i;
		break;

	case 0x400:
	case 0x440:
	case 0x480:
		if (!ea) {
			info->op = fex_other;
			info->op1.type = info->op2.type = info->res.type = fex_nodata;
			info->flags = 0;
			return;
		}
		info->op2.type = fex_double;
		info->op2.val.d = *(double *)ea;
		op2v = (long double) info->op2.val.d;
		break;

	case 0x4c0:
	case 0x6c0:
		info->op2.type = fex_ldouble;
		info->op2.val.q = fpreg(uap, op & 7);
		t = info->op1;
		info->op1 = info->op2;
		info->op2 = t;
		op2v = info->op2.val.q;
		break;

	case 0x600:
	case 0x640:
	case 0x680:
		if (!ea) {
			info->op = fex_other;
			info->op1.type = info->op2.type = info->res.type = fex_nodata;
			info->flags = 0;
			return;
		}
		info->op2.type = fex_int;
		info->op2.val.i = *(short *)ea;
		op2v = (long double) info->op2.val.i;
		break;

	default:
		info->op = fex_other;
		info->op1.type = info->op2.type = info->res.type = fex_nodata;
		info->flags = 0;
		return;
	}

	/* distinguish different operations in the group */
	info->res.type = fex_ldouble;
	switch (op & 0x38) {
	case 0x00:
		info->op = fex_add;
		info->res.val.q = info->op1.val.q + op2v;
		break;

	case 0x08:
		info->op = fex_mul;
		info->res.val.q = info->op1.val.q * op2v;
		break;

	case 0x10:
	case 0x18:
		info->op = fex_cmp;
		info->res.type = fex_nodata;
		c = (info->op1.val.q < op2v);
		break;

	case 0x20:
		info->op = fex_sub;
		info->res.val.q = info->op1.val.q - op2v;
		break;

	case 0x28:
		info->op = fex_sub;
		info->res.val.q = op2v - info->op1.val.q;
		t = info->op1;
		info->op1 = info->op2;
		info->op2 = t;
		break;

	case 0x30:
		info->op = fex_div;
		info->res.val.q = info->op1.val.q / op2v;
		break;

	case 0x38:
		info->op = fex_div;
		info->res.val.q = op2v / info->op1.val.q;
		t = info->op1;
		info->op1 = info->op2;
		info->op2 = t;
		break;

	default:
		info->op = fex_other;
		info->op1.type = info->op2.type = info->res.type = fex_nodata;
		info->flags = 0;
		return;
	}

done:
	__fenv_getcwsw(&cwsw);
	info->flags = cwsw & FE_ALL_EXCEPT;
	cwsw &= ~FE_ALL_EXCEPT;
	__fenv_setcwsw(&cwsw);
}

/* pop the saved stack */
static void pop(ucontext_t *uap)
{
	unsigned top;

	fpreg(uap, 0) = fpreg(uap, 1);
	fpreg(uap, 1) = fpreg(uap, 2);
	fpreg(uap, 2) = fpreg(uap, 3);
	fpreg(uap, 3) = fpreg(uap, 4);
	fpreg(uap, 4) = fpreg(uap, 5);
	fpreg(uap, 5) = fpreg(uap, 6);
	fpreg(uap, 6) = fpreg(uap, 7);
#if defined(__amd64)
	top = (uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.sw >> 10)
		& 0xe;
	uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.fctw |= (3 << top);
	top = (top + 2) & 0xe;
	uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.sw =
		(uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.sw & ~0x3800)
		| (top << 10);
#else
	top = (uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.state[SW] >> 10)
		& 0xe;
	uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.state[TW] |= (3 << top);
	top = (top + 2) & 0xe;
	uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.state[SW] =
		(uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.state[SW] & ~0x3800)
		| (top << 10);
#endif
}

/* push x onto the saved stack */
static void push(long double x, ucontext_t *uap)
{
	unsigned top;

	fpreg(uap, 7) = fpreg(uap, 6);
	fpreg(uap, 6) = fpreg(uap, 5);
	fpreg(uap, 5) = fpreg(uap, 4);
	fpreg(uap, 4) = fpreg(uap, 3);
	fpreg(uap, 3) = fpreg(uap, 2);
	fpreg(uap, 2) = fpreg(uap, 1);
	fpreg(uap, 1) = fpreg(uap, 0);
	fpreg(uap, 0) = x;
#if defined(__amd64)
	top = (uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.sw >> 10)
		& 0xe;
	top = (top - 2) & 0xe;
	uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.fctw &= ~(3 << top);
	uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.sw =
		(uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.sw & ~0x3800)
		| (top << 10);
#else
	top = (uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.state[SW] >> 10)
		& 0xe;
	top = (top - 2) & 0xe;
	uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.state[TW] &= ~(3 << top);
	uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.state[SW] =
		(uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.state[SW] & ~0x3800)
		| (top << 10);
#endif
}

/* scale factors for exponent wrapping */
static const float
	fun = 7.922816251e+28f,	/* 2^96 */
	fov = 1.262177448e-29f;	/* 2^-96 */
static const double
	dun = 1.552518092300708935e+231,	/* 2^768 */
	dov = 6.441148769597133308e-232;	/* 2^-768 */

/*
*  Store the specified result; if no result is given but the exception
*  is underflow or overflow, use the default trapped result
*/
void
__fex_st_result(siginfo_t *sip, ucontext_t *uap, fex_info_t *info)
{
	fex_numeric_t	r;
	unsigned long		ex, op, ea, stack;

	/* get the exception type, opcode, and data address */
	ex = sip->si_code;
#if defined(__amd64)
	op = uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.fop >> 16;
	ea = uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.rdp; /*???*/
#else
	op = uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.state[OP] >> 16;
	ea = uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.state[EA];
#endif

	/* if the instruction is a compare, set the condition codes
	   to unordered and update the stack */
	switch (op & 0x7f8) {
	case 0x010:
	case 0x050:
	case 0x090:
	case 0x0d0:
	case 0x210:
	case 0x250:
	case 0x290:
	case 0x410:
	case 0x450:
	case 0x490:
	case 0x4d0:
	case 0x5e0:
	case 0x610:
	case 0x650:
	case 0x690:
		/* f[u]com */
#if defined(__amd64)
		uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.sw |= 0x4500;
#else
		uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.state[SW] |= 0x4500;
#endif
		return;

	case 0x018:
	case 0x058:
	case 0x098:
	case 0x0d8:
	case 0x218:
	case 0x258:
	case 0x298:
	case 0x418:
	case 0x458:
	case 0x498:
	case 0x4d8:
	case 0x5e8:
	case 0x618:
	case 0x658:
	case 0x698:
	case 0x6d0:
		/* f[u]comp */
#if defined(__amd64)
		uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.sw |= 0x4500;
#else
		uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.state[SW] |= 0x4500;
#endif
		pop(uap);
		return;

	case 0x2e8:
	case 0x6d8:
		/* f[u]compp */
#if defined(__amd64)
		uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.sw |= 0x4500;
#else
		uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.state[SW] |= 0x4500;
#endif
		pop(uap);
		pop(uap);
		return;

	case 0x1e0:
		if (op == 0x1e4) { /* ftst */
#if defined(__amd64)
			uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.sw |= 0x4500;
#else
			uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.state[SW] |= 0x4500;
#endif
			return;
		}
		break;

	case 0x3e8:
	case 0x3f0:
		/* f[u]comi */
#if defined(__amd64)
		uap->uc_mcontext.gregs[REG_PS] |= 0x45;
#else
		uap->uc_mcontext.gregs[EFL] |= 0x45;
#endif
		return;

	case 0x7e8:
	case 0x7f0:
		/* f[u]comip */
#if defined(__amd64)
		uap->uc_mcontext.gregs[REG_PS] |= 0x45;
#else
		uap->uc_mcontext.gregs[EFL] |= 0x45;
#endif
		pop(uap);
		return;
	}

	/* if there is no result available and the exception is overflow
	   or underflow, use the wrapped result */
	r = info->res;
	if (r.type == fex_nodata) {
		if (ex == FPE_FLTOVF || ex == FPE_FLTUND) {
			/* for store instructions, do the scaling and store */
			switch (op & 0x7f8) {
			case 0x110:
			case 0x118:
			case 0x150:
			case 0x158:
			case 0x190:
			case 0x198:
				if (!ea)
					return;
				if (ex == FPE_FLTOVF)
					*(float *)ea = (fpreg(uap, 0) * fov) * fov;
				else
					*(float *)ea = (fpreg(uap, 0) * fun) * fun;
				if ((op & 8) != 0)
					pop(uap);
				break;

			case 0x510:
			case 0x518:
			case 0x550:
			case 0x558:
			case 0x590:
			case 0x598:
				if (!ea)
					return;
				if (ex == FPE_FLTOVF)
					*(double *)ea = (fpreg(uap, 0) * dov) * dov;
				else
					*(double *)ea = (fpreg(uap, 0) * dun) * dun;
				if ((op & 8) != 0)
					pop(uap);
				break;
			}
		}
#ifdef DEBUG
		else if (ex != FPE_FLTRES)
			printf("No result supplied, stack may be hosed\n");
#endif
		return;
	}

	/* otherwise convert the supplied result to the correct type,
	   put it in the destination, and update the stack as need be */

	/* store instructions */
	switch (op & 0x7f8) {
	case 0x110:
	case 0x118:
	case 0x150:
	case 0x158:
	case 0x190:
	case 0x198:
		if (!ea)
			return;
		switch (r.type) {
		case fex_int:
			*(float *)ea = (float) r.val.i;
			break;

		case fex_llong:
			*(float *)ea = (float) r.val.l;
			break;

		case fex_float:
			*(float *)ea = r.val.f;
			break;

		case fex_double:
			*(float *)ea = (float) r.val.d;
			break;

		case fex_ldouble:
			*(float *)ea = (float) r.val.q;
			break;

		default:
			break;
		}
		if (ex != FPE_FLTRES && (op & 8) != 0)
			pop(uap);
		return;

	case 0x310:
	case 0x318:
	case 0x350:
	case 0x358:
	case 0x390:
	case 0x398:
		if (!ea)
			return;
		switch (r.type) {
		case fex_int:
			*(int *)ea = r.val.i;
			break;

		case fex_llong:
			*(int *)ea = (int) r.val.l;
			break;

		case fex_float:
			*(int *)ea = (int) r.val.f;
			break;

		case fex_double:
			*(int *)ea = (int) r.val.d;
			break;

		case fex_ldouble:
			*(int *)ea = (int) r.val.q;
			break;

		default:
			break;
		}
		if (ex != FPE_FLTRES && (op & 8) != 0)
			pop(uap);
		return;

	case 0x510:
	case 0x518:
	case 0x550:
	case 0x558:
	case 0x590:
	case 0x598:
		if (!ea)
			return;
		switch (r.type) {
		case fex_int:
			*(double *)ea = (double) r.val.i;
			break;

		case fex_llong:
			*(double *)ea = (double) r.val.l;
			break;

		case fex_float:
			*(double *)ea = (double) r.val.f;
			break;

		case fex_double:
			*(double *)ea = r.val.d;
			break;

		case fex_ldouble:
			*(double *)ea = (double) r.val.q;
			break;

		default:
			break;
		}
		if (ex != FPE_FLTRES && (op & 8) != 0)
			pop(uap);
		return;

	case 0x710:
	case 0x718:
	case 0x750:
	case 0x758:
	case 0x790:
	case 0x798:
		if (!ea)
			return;
		switch (r.type) {
		case fex_int:
			*(short *)ea = (short) r.val.i;
			break;

		case fex_llong:
			*(short *)ea = (short) r.val.l;
			break;

		case fex_float:
			*(short *)ea = (short) r.val.f;
			break;

		case fex_double:
			*(short *)ea = (short) r.val.d;
			break;

		case fex_ldouble:
			*(short *)ea = (short) r.val.q;
			break;

		default:
			break;
		}
		if (ex != FPE_FLTRES && (op & 8) != 0)
			pop(uap);
		return;

	case 0x730:
	case 0x770:
	case 0x7b0:
		/* fbstp; don't bother */
		if (ea && ex != FPE_FLTRES)
			pop(uap);
		return;

	case 0x738:
	case 0x778:
	case 0x7b8:
		if (!ea)
			return;
		switch (r.type) {
		case fex_int:
			*(long long *)ea = (long long) r.val.i;
			break;

		case fex_llong:
			*(long long *)ea = r.val.l;
			break;

		case fex_float:
			*(long long *)ea = (long long) r.val.f;
			break;

		case fex_double:
			*(long long *)ea = (long long) r.val.d;
			break;

		case fex_ldouble:
			*(long long *)ea = (long long) r.val.q;
			break;

		default:
			break;
		}
		if (ex != FPE_FLTRES)
			pop(uap);
		return;
	}

	/* for all other instructions, the result goes into a register */
	switch (r.type) {
	case fex_int:
		r.val.q = (long double) r.val.i;
		break;

	case fex_llong:
		r.val.q = (long double) r.val.l;
		break;

	case fex_float:
		r.val.q = (long double) r.val.f;
		break;

	case fex_double:
		r.val.q = (long double) r.val.d;
		break;

	default:
		break;
	}

	/* for load instructions, push the result onto the stack */
	switch (op & 0x7f8) {
	case 0x100:
	case 0x140:
	case 0x180:
	case 0x500:
	case 0x540:
	case 0x580:
		if (ea)
			push(r.val.q, uap);
		return;
	}

	/* for all other instructions, if the exception is overflow,
	   underflow, or inexact, the stack has already been updated */
	stack = (ex == FPE_FLTOVF || ex == FPE_FLTUND || ex == FPE_FLTRES);
	switch (op & 0x7f8) {
	case 0x1f0: /* oddballs */
		switch (op) {
		case 0x1f1: /* fyl2x */
		case 0x1f3: /* fpatan */
		case 0x1f9: /* fyl2xp1 */
			/* pop the stack, leaving the result in st */
			if (!stack)
				pop(uap);
			fpreg(uap, 0) = r.val.q;
			return;

		case 0x1f2: /* fpatan */
			/* fptan pushes 1.0 afterward */
			if (stack)
				fpreg(uap, 1) = r.val.q;
			else {
				fpreg(uap, 0) = r.val.q;
				push(1.0L, uap);
			}
			return;

		case 0x1f4: /* fxtract */
		case 0x1fb: /* fsincos */
			/* leave the supplied result in st */
			if (stack)
				fpreg(uap, 0) = r.val.q;
			else {
				fpreg(uap, 0) = 0.0; /* punt */
				push(r.val.q, uap);
			}
			return;
		}

		/* all others leave the stack alone and the result in st */
		fpreg(uap, 0) = r.val.q;
		return;

	case 0x4c0:
	case 0x4c8:
	case 0x4e0:
	case 0x4e8:
	case 0x4f0:
	case 0x4f8:
		fpreg(uap, op & 7) = r.val.q;
		return;

	case 0x6c0:
	case 0x6c8:
	case 0x6e0:
	case 0x6e8:
	case 0x6f0:
	case 0x6f8:
		/* stack is popped afterward */
		if (stack)
			fpreg(uap, (op - 1) & 7) = r.val.q;
		else {
			fpreg(uap, op & 7) = r.val.q;
			pop(uap);
		}
		return;

	default:
		fpreg(uap, 0) = r.val.q;
		return;
	}
}
