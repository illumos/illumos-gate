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

#include "fenv_synonyms.h"
#undef lint
#include <signal.h>
#include <siginfo.h>
#include <ucontext.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <thread.h>
#include <math.h>
#if defined(__SUNPRO_C)
#include <sunmath.h>
#endif
#include <fenv.h>
#include "fex_handler.h"
#include "fenv_inlines.h"

#if defined(__sparc) && !defined(__sparcv9)
#include <sys/procfs.h>
#endif

/* 2.x signal.h doesn't declare sigemptyset or sigismember
   if they're #defined (see sys/signal.h) */
extern int sigemptyset(sigset_t *);
extern int sigismember(const sigset_t *, int);

/* external globals */
void (*__mt_fex_sync)() = NULL; /* for synchronization with libmtsk */
#pragma weak __mt_fex_sync

#ifdef LIBM_MT_FEX_SYNC
void (*__libm_mt_fex_sync)() = NULL; /* new, improved version of above */
#pragma weak __libm_mt_fex_sync
#endif

/* private variables */
static fex_handler_t main_handlers;
static int handlers_initialized = 0;
static thread_key_t handlers_key;
static mutex_t handlers_key_lock = DEFAULTMUTEX;

static struct sigaction oact = { 0, SIG_DFL };
static mutex_t hdlr_lock = DEFAULTMUTEX;
static int hdlr_installed = 0;

/* private const data */
static const int te_bit[FEX_NUM_EXC] = {
	1 << fp_trap_inexact,
	1 << fp_trap_division,
	1 << fp_trap_underflow,
	1 << fp_trap_overflow,
	1 << fp_trap_invalid,
	1 << fp_trap_invalid,
	1 << fp_trap_invalid,
	1 << fp_trap_invalid,
	1 << fp_trap_invalid,
	1 << fp_trap_invalid,
	1 << fp_trap_invalid,
	1 << fp_trap_invalid
};

/*
*  Return the traps to be enabled given the current handling modes
*  and flags
*/
static int
__fex_te_needed(struct fex_handler_data *thr_handlers, unsigned long fsr)
{
	int		i, ex, te;

	/* set traps for handling modes */
	te = 0;
	for (i = 0; i < FEX_NUM_EXC; i++)
		if (thr_handlers[i].__mode != FEX_NONSTOP)
			te |= te_bit[i];

	/* add traps for retrospective diagnostics */
	if (fex_get_log()) {
		ex = (int)__fenv_get_ex(fsr);
		if (!(ex & FE_INEXACT))
			te |= (1 << fp_trap_inexact);
		if (!(ex & FE_UNDERFLOW))
			te |= (1 << fp_trap_underflow);
		if (!(ex & FE_OVERFLOW))
			te |= (1 << fp_trap_overflow);
		if (!(ex & FE_DIVBYZERO))
			te |= (1 << fp_trap_division);
		if (!(ex & FE_INVALID))
			te |= (1 << fp_trap_invalid);
	}

	return te;
}

/*
*  The following function synchronizes with libmtsk (SPARC only, for now)
*/
static void
__fex_sync_with_libmtsk(int begin, int master)
{
	static fenv_t master_env;
	static int env_initialized = 0;
	static mutex_t env_lock = DEFAULTMUTEX;

	if (begin) {
		mutex_lock(&env_lock);
		if (master) {
			(void) fegetenv(&master_env);
			env_initialized = 1;
		}
		else if (env_initialized)
			(void) fesetenv(&master_env);
		mutex_unlock(&env_lock);
	}
	else if (master && fex_get_log())
		__fex_update_te();
}

#ifdef LIBM_MT_FEX_SYNC
/*
*  The following function may be used for synchronization with any
*  internal project that manages multiple threads
*/
enum __libm_mt_fex_sync_actions {
	__libm_mt_fex_start_master = 0,
	__libm_mt_fex_start_slave,
	__libm_mt_fex_finish_master,
	__libm_mt_fex_finish_slave
};

struct __libm_mt_fex_sync_data {
	fenv_t	master_env;
	int		initialized;
	mutex_t	lock;
};

static void
__fex_sync_with_threads(enum __libm_mt_fex_sync_actions action,
	struct __libm_mt_fex_sync_data *thr_env)
{
	switch (action) {
	case __libm_mt_fex_start_master:
		mutex_lock(&thr_env->lock);
		(void) fegetenv(&thr_env->master_env);
		thr_env->initialized = 1;
		mutex_unlock(&thr_env->lock);
		break;

	case __libm_mt_fex_start_slave:
		mutex_lock(&thr_env->lock);
		if (thr_env->initialized)
			(void) fesetenv(&thr_env->master_env);
		mutex_unlock(&thr_env->lock);
		break;

	case __libm_mt_fex_finish_master:
#if defined(__x86)
		__fex_update_te();
#else
		if (fex_get_log())
			__fex_update_te();
#endif
		break;

	case __libm_mt_fex_finish_slave:
#if defined(__x86)
		/* clear traps, making all accrued flags visible in status word */
		{
			unsigned long   fsr;
			__fenv_getfsr(&fsr);
			__fenv_set_te(fsr, 0);
			__fenv_setfsr(&fsr);
		}
#endif
		break;
	}
}
#endif

#if defined(__sparc)

/*
*  Code for setting or clearing interval mode on US-III and above.
*  This is embedded as data so we don't have to mark the library
*  as a v8plusb/v9b object.  (I could have just used one entry and
*  modified the second word to set the bits I want, but that would
*  have required another mutex.)
*/
static const unsigned int siam[][2] = {
	{ 0x81c3e008, 0x81b01020 }, /* retl, siam 0 */
	{ 0x81c3e008, 0x81b01024 }, /* retl, siam 4 */
	{ 0x81c3e008, 0x81b01025 }, /* retl, siam 5 */
	{ 0x81c3e008, 0x81b01026 }, /* retl, siam 6 */
	{ 0x81c3e008, 0x81b01027 }  /* retl, siam 7 */
};

/*
*  If a handling mode is in effect, apply it; otherwise invoke the
*  saved handler
*/
static void
__fex_hdlr(int sig, siginfo_t *sip, ucontext_t *uap)
{
	struct fex_handler_data	*thr_handlers;
	struct sigaction	act;
	void			(*handler)(), (*siamp)();
	int			mode, i;
	enum fex_exception	e;
	fex_info_t		info;
	unsigned long		fsr, tmpfsr, addr;
	unsigned int		gsr;

	/* determine which exception occurred */
	switch (sip->si_code) {
	case FPE_FLTDIV:
		e = fex_division;
		break;
	case FPE_FLTOVF:
		e = fex_overflow;
		break;
	case FPE_FLTUND:
		e = fex_underflow;
		break;
	case FPE_FLTRES:
		e = fex_inexact;
		break;
	case FPE_FLTINV:
		if ((int)(e = __fex_get_invalid_type(sip, uap)) < 0)
			goto not_ieee;
		break;
	default:
		/* not an IEEE exception */
		goto not_ieee;
	}

	/* get the handling mode */
	mode = FEX_NOHANDLER;
	handler = oact.sa_handler; /* for log; just looking, no need to lock */
	thr_handlers = __fex_get_thr_handlers();
	if (thr_handlers && thr_handlers[(int)e].__mode != FEX_NOHANDLER) {
		mode = thr_handlers[(int)e].__mode;
		handler = thr_handlers[(int)e].__handler;
	}

	/* make an entry in the log of retro. diag. if need be */
	i = ((int)uap->uc_mcontext.fpregs.fpu_fsr >> 5) & 0x1f;
	__fex_mklog(uap, (char *)sip->si_addr, i, e, mode, (void *)handler);

	/* handle the exception based on the mode */
	if (mode == FEX_NOHANDLER)
		goto not_ieee;
	else if (mode == FEX_ABORT)
		abort();
	else if (mode == FEX_SIGNAL) {
		handler(sig, sip, uap);
		return;
	}

	/* custom or nonstop mode; disable traps and clear flags */
	__fenv_getfsr(&fsr);
	__fenv_set_te(fsr, 0);
	__fenv_set_ex(fsr, 0);

	/* if interval mode was set, clear it, then substitute the
	   interval rounding direction and clear ns mode in the fsr */
#ifdef __sparcv9
	gsr = uap->uc_mcontext.asrs[3];
#else
	gsr = 0;
	if (uap->uc_mcontext.xrs.xrs_id == XRS_ID)
		gsr = (*(unsigned long long*)((prxregset_t*)uap->uc_mcontext.
		    xrs.xrs_ptr)->pr_un.pr_v8p.pr_filler);
#endif
	gsr = (gsr >> 25) & 7;
	if (gsr & 4) {
		siamp = (void (*)()) siam[0];
		siamp();
		tmpfsr = fsr;
		fsr = (fsr & ~0xc0400000ul) | ((gsr & 3) << 30);
	}
	__fenv_setfsr(&fsr);

	/* decode the operation */
	__fex_get_op(sip, uap, &info);

	/* if a custom mode handler is installed, invoke it */
	if (mode == FEX_CUSTOM) {
		/* if we got here from feraiseexcept, pass dummy info */
		addr = (unsigned long)sip->si_addr;
		if (addr >= (unsigned long)feraiseexcept &&
		    addr < (unsigned long)fetestexcept) {
			info.op = fex_other;
			info.op1.type = info.op2.type = info.res.type =
			    fex_nodata;
		}

		/* restore interval mode if it was set, and put the original
		   rounding direction and ns mode back in the fsr */
		if (gsr & 4) {
			__fenv_setfsr(&tmpfsr);
			siamp = (void (*)()) siam[1 + (gsr & 3)];
			siamp();
		}

		handler(1 << (int)e, &info);

		/* restore modes in case the user's handler changed them */
		if (gsr & 4) {
			siamp = (void (*)()) siam[0];
			siamp();
		}
		__fenv_setfsr(&fsr);
	}

	/* stuff the result */
	__fex_st_result(sip, uap, &info);

	/* "or" in any exception flags and update traps */
	fsr = uap->uc_mcontext.fpregs.fpu_fsr;
	fsr |= ((info.flags & 0x1f) << 5);
	i = __fex_te_needed(thr_handlers, fsr);
	__fenv_set_te(fsr, i);
	uap->uc_mcontext.fpregs.fpu_fsr = fsr;
	return;

not_ieee:
	/* revert to the saved handler (if any) */
	mutex_lock(&hdlr_lock);
	act = oact;
	mutex_unlock(&hdlr_lock);
	switch ((unsigned long)act.sa_handler) {
	case (unsigned long)SIG_DFL:
		/* simulate trap with no handler installed */
		sigaction(SIGFPE, &act, NULL);
		kill(getpid(), SIGFPE);
		break;
#if !defined(__lint)
	case (unsigned long)SIG_IGN:
		break;
#endif
	default:
		act.sa_handler(sig, sip, uap);
	}
}

#elif defined(__x86)

#if defined(__amd64)
#define test_sse_hw	1
#else
extern int _sse_hw;
#define test_sse_hw	_sse_hw
#endif

#if !defined(REG_PC)
#define REG_PC	EIP
#endif

/*
*  If a handling mode is in effect, apply it; otherwise invoke the
*  saved handler
*/
static void
__fex_hdlr(int sig, siginfo_t *sip, ucontext_t *uap)
{
	struct fex_handler_data	*thr_handlers;
	struct sigaction	act;
	void			(*handler)() = NULL, (*simd_handler[4])();
	int			mode, simd_mode[4], i, len, accrued, *ap;
	unsigned int		cwsw, oldcwsw, mxcsr, oldmxcsr;
	enum fex_exception	e, simd_e[4];
	fex_info_t		info, simd_info[4];
	unsigned long		addr;
	siginfo_t		osip = *sip;
	sseinst_t		inst;

	/* check for an exception caused by an SSE instruction */
	if (!(uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.status & 0x80)) {
		len = __fex_parse_sse(uap, &inst);
		if (len == 0)
			goto not_ieee;

		/* disable all traps and clear flags */
		__fenv_getcwsw(&oldcwsw);
		cwsw = (oldcwsw & ~0x3f) | 0x003f0000;
		__fenv_setcwsw(&cwsw);
		__fenv_getmxcsr(&oldmxcsr);
		mxcsr = (oldmxcsr & ~0x3f) | 0x1f80;
		__fenv_setmxcsr(&mxcsr);

		if ((int)inst.op & SIMD) {
			__fex_get_simd_op(uap, &inst, simd_e, simd_info);

			thr_handlers = __fex_get_thr_handlers();
			addr = (unsigned long)uap->uc_mcontext.gregs[REG_PC];
			accrued = uap->uc_mcontext.fpregs.fp_reg_set.
			    fpchip_state.mxcsr;

			e = (enum fex_exception)-1;
			mode = FEX_NONSTOP;
			for (i = 0; i < 4; i++) {
				if ((int)simd_e[i] < 0)
					continue;

				e = simd_e[i];
				simd_mode[i] = FEX_NOHANDLER;
				simd_handler[i] = oact.sa_handler;
				if (thr_handlers &&
				    thr_handlers[(int)e].__mode !=
				    FEX_NOHANDLER) {
					simd_mode[i] =
					    thr_handlers[(int)e].__mode;
					simd_handler[i] =
					    thr_handlers[(int)e].__handler;
				}
				accrued &= ~te_bit[(int)e];
				switch (simd_mode[i]) {
				case FEX_ABORT:
					mode = FEX_ABORT;
					break;
				case FEX_SIGNAL:
					if (mode != FEX_ABORT)
						mode = FEX_SIGNAL;
					handler = simd_handler[i];
					break;
				case FEX_NOHANDLER:
					if (mode != FEX_ABORT && mode !=
					    FEX_SIGNAL)
						mode = FEX_NOHANDLER;
					break;
				}
			}
			if (e == (enum fex_exception)-1) {
				__fenv_setcwsw(&oldcwsw);
				__fenv_setmxcsr(&oldmxcsr);
				goto not_ieee;
			}
			accrued |= uap->uc_mcontext.fpregs.fp_reg_set.
			    fpchip_state.status;
			ap = __fex_accrued();
			accrued |= *ap;
			accrued &= 0x3d;

			for (i = 0; i < 4; i++) {
				if ((int)simd_e[i] < 0)
					continue;

				__fex_mklog(uap, (char *)addr, accrued,
				    simd_e[i], simd_mode[i],
				    (void *)simd_handler[i]);
			}

			if (mode == FEX_NOHANDLER) {
				__fenv_setcwsw(&oldcwsw);
				__fenv_setmxcsr(&oldmxcsr);
				goto not_ieee;
			} else if (mode == FEX_ABORT) {
				abort();
			} else if (mode == FEX_SIGNAL) {
				__fenv_setcwsw(&oldcwsw);
				__fenv_setmxcsr(&oldmxcsr);
				handler(sig, &osip, uap);
				return;
			}

			*ap = 0;
			for (i = 0; i < 4; i++) {
				if ((int)simd_e[i] < 0)
					continue;

				if (simd_mode[i] == FEX_CUSTOM) {
					handler(1 << (int)simd_e[i],
					    &simd_info[i]);
					__fenv_setcwsw(&cwsw);
					__fenv_setmxcsr(&mxcsr);
				}
			}

			__fex_st_simd_result(uap, &inst, simd_e, simd_info);
			for (i = 0; i < 4; i++) {
				if ((int)simd_e[i] < 0)
					continue;

				accrued |= simd_info[i].flags;
			}

			if ((int)inst.op & INTREG) {
				/* set MMX mode */
#if defined(__amd64)
				uap->uc_mcontext.fpregs.fp_reg_set.
				    fpchip_state.sw &= ~0x3800;
				uap->uc_mcontext.fpregs.fp_reg_set.
				    fpchip_state.fctw = 0;
#else
				uap->uc_mcontext.fpregs.fp_reg_set.
				    fpchip_state.state[1] &= ~0x3800;
				uap->uc_mcontext.fpregs.fp_reg_set.
				    fpchip_state.state[2] = 0;
#endif
			}
		} else {
			e = __fex_get_sse_op(uap, &inst, &info);
			if ((int)e < 0) {
				__fenv_setcwsw(&oldcwsw);
				__fenv_setmxcsr(&oldmxcsr);
				goto not_ieee;
			}

			mode = FEX_NOHANDLER;
			handler = oact.sa_handler;
			thr_handlers = __fex_get_thr_handlers();
			if (thr_handlers && thr_handlers[(int)e].__mode !=
			    FEX_NOHANDLER) {
				mode = thr_handlers[(int)e].__mode;
				handler = thr_handlers[(int)e].__handler;
			}

			addr = (unsigned long)uap->uc_mcontext.gregs[REG_PC];
			accrued = uap->uc_mcontext.fpregs.fp_reg_set.
			    fpchip_state.mxcsr & ~te_bit[(int)e];
			accrued |= uap->uc_mcontext.fpregs.fp_reg_set.
			    fpchip_state.status;
			ap = __fex_accrued();
			accrued |= *ap;
			accrued &= 0x3d;
			__fex_mklog(uap, (char *)addr, accrued, e, mode,
			    (void *)handler);

			if (mode == FEX_NOHANDLER) {
				__fenv_setcwsw(&oldcwsw);
				__fenv_setmxcsr(&oldmxcsr);
				goto not_ieee;
			} else if (mode == FEX_ABORT) {
				abort();
			} else if (mode == FEX_SIGNAL) {
				__fenv_setcwsw(&oldcwsw);
				__fenv_setmxcsr(&oldmxcsr);
				handler(sig, &osip, uap);
				return;
			} else if (mode == FEX_CUSTOM) {
				*ap = 0;
				if (addr >= (unsigned long)feraiseexcept &&
				    addr < (unsigned long)fetestexcept) {
					info.op = fex_other;
					info.op1.type = info.op2.type =
					    info.res.type = fex_nodata;
				}
				handler(1 << (int)e, &info);
				__fenv_setcwsw(&cwsw);
				__fenv_setmxcsr(&mxcsr);
			}

			__fex_st_sse_result(uap, &inst, e, &info);
			accrued |= info.flags;

#if defined(__amd64)
			/*
			 * In 64-bit mode, the 32-bit convert-to-integer
			 * instructions zero the upper 32 bits of the
			 * destination.  (We do this here and not in
			 * __fex_st_sse_result because __fex_st_sse_result
			 * can be called from __fex_st_simd_result, too.)
			 */
			if (inst.op == cvtss2si || inst.op == cvttss2si ||
			    inst.op == cvtsd2si || inst.op == cvttsd2si)
				inst.op1->i[1] = 0;
#endif
		}

		/* advance the pc past the SSE instruction */
		uap->uc_mcontext.gregs[REG_PC] += len;
		goto update_state;
	}

	/* determine which exception occurred */
	__fex_get_x86_exc(sip, uap);
	switch (sip->si_code) {
	case FPE_FLTDIV:
		e = fex_division;
		break;
	case FPE_FLTOVF:
		e = fex_overflow;
		break;
	case FPE_FLTUND:
		e = fex_underflow;
		break;
	case FPE_FLTRES:
		e = fex_inexact;
		break;
	case FPE_FLTINV:
		if ((int)(e = __fex_get_invalid_type(sip, uap)) < 0)
			goto not_ieee;
		break;
	default:
		/* not an IEEE exception */
		goto not_ieee;
	}

	/* get the handling mode */
	mode = FEX_NOHANDLER;
	handler = oact.sa_handler; /* for log; just looking, no need to lock */
	thr_handlers = __fex_get_thr_handlers();
	if (thr_handlers && thr_handlers[(int)e].__mode != FEX_NOHANDLER) {
		mode = thr_handlers[(int)e].__mode;
		handler = thr_handlers[(int)e].__handler;
	}

	/* make an entry in the log of retro. diag. if need be */
#if defined(__amd64)
	addr = (unsigned long)uap->uc_mcontext.fpregs.fp_reg_set.
	    fpchip_state.rip;
#else
	addr = (unsigned long)uap->uc_mcontext.fpregs.fp_reg_set.
	    fpchip_state.state[3];
#endif
	accrued = uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.status & 
	    ~te_bit[(int)e];
	if (test_sse_hw)
		accrued |= uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.
		    mxcsr;
	ap = __fex_accrued();
	accrued |= *ap;
	accrued &= 0x3d;
	__fex_mklog(uap, (char *)addr, accrued, e, mode, (void *)handler);

	/* handle the exception based on the mode */
	if (mode == FEX_NOHANDLER)
		goto not_ieee;
	else if (mode == FEX_ABORT)
		abort();
	else if (mode == FEX_SIGNAL) {
		handler(sig, &osip, uap);
		return;
	}

	/* disable all traps and clear flags */
	__fenv_getcwsw(&cwsw);
	cwsw = (cwsw & ~0x3f) | 0x003f0000;
	__fenv_setcwsw(&cwsw);
	if (test_sse_hw) {
		__fenv_getmxcsr(&mxcsr);
		mxcsr = (mxcsr & ~0x3f) | 0x1f80;
		__fenv_setmxcsr(&mxcsr);
	}
	*ap = 0;

	/* decode the operation */
	__fex_get_op(sip, uap, &info);

	/* if a custom mode handler is installed, invoke it */
	if (mode == FEX_CUSTOM) {
		/* if we got here from feraiseexcept, pass dummy info */
		if (addr >= (unsigned long)feraiseexcept &&
		    addr < (unsigned long)fetestexcept) {
			info.op = fex_other;
			info.op1.type = info.op2.type = info.res.type =
			    fex_nodata;
		}

		handler(1 << (int)e, &info);

		/* restore modes in case the user's handler changed them */
		__fenv_setcwsw(&cwsw);
		if (test_sse_hw)
			__fenv_setmxcsr(&mxcsr);
	}

	/* stuff the result */
	__fex_st_result(sip, uap, &info);
	accrued |= info.flags;

update_state:
	accrued &= 0x3d;
	i = __fex_te_needed(thr_handlers, accrued);
	*ap = accrued & i;
#if defined(__amd64)
	uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.sw &= ~0x3d;
	uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.sw |= (accrued & ~i);
	uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.cw |= 0x3d;
	uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.cw &= ~i;
#else
	uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.state[1] &= ~0x3d;
	uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.state[1] |=
	    (accrued & ~i);
	uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.state[0] |= 0x3d;
	uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.state[0] &= ~i;
#endif
	if (test_sse_hw) {
		uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.mxcsr &= ~0x3d;
		uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.mxcsr |=
		    0x1e80 | (accrued & ~i);
		uap->uc_mcontext.fpregs.fp_reg_set.fpchip_state.mxcsr &=
		    ~(i << 7);
	}
	return;

not_ieee:
	/* revert to the saved handler (if any) */
	mutex_lock(&hdlr_lock);
	act = oact;
	mutex_unlock(&hdlr_lock);
	switch ((unsigned long)act.sa_handler) {
	case (unsigned long)SIG_DFL:
		/* simulate trap with no handler installed */
		sigaction(SIGFPE, &act, NULL);
		kill(getpid(), SIGFPE);
		break;
#if !defined(__lint)
	case (unsigned long)SIG_IGN:
		break;
#endif
	default:
		act.sa_handler(sig, &osip, uap);
	}
}

#else
#error Unknown architecture
#endif

/*
*  Return a pointer to the thread-specific handler data, and
*  initialize it if necessary
*/
struct fex_handler_data *
__fex_get_thr_handlers()
{
	struct fex_handler_data	*ptr;
	unsigned long			fsr;
	int						i, te;

	if (thr_main()) {
		if (!handlers_initialized) {
			/* initialize to FEX_NOHANDLER if trap is enabled,
			   FEX_NONSTOP if trap is disabled */
			__fenv_getfsr(&fsr);
			te = (int)__fenv_get_te(fsr);
			for (i = 0; i < FEX_NUM_EXC; i++)
				main_handlers[i].__mode =
					((te & te_bit[i])? FEX_NOHANDLER : FEX_NONSTOP);
			handlers_initialized = 1;
		}
		return main_handlers;
	}
	else {
		ptr = NULL;
		mutex_lock(&handlers_key_lock);
		if (thr_getspecific(handlers_key, (void **)&ptr) != 0 &&
			thr_keycreate(&handlers_key, free) != 0) {
			mutex_unlock(&handlers_key_lock);
			return NULL;
		}
		mutex_unlock(&handlers_key_lock);
		if (!ptr) {
			if ((ptr = (struct fex_handler_data *)
				malloc(sizeof(fex_handler_t))) == NULL) {
				return NULL;
			}
			if (thr_setspecific(handlers_key, (void *)ptr) != 0) {
				(void)free(ptr);
				return NULL;
			}
			/* initialize to FEX_NOHANDLER if trap is enabled,
			   FEX_NONSTOP if trap is disabled */
			__fenv_getfsr(&fsr);
			te = (int)__fenv_get_te(fsr);
			for (i = 0; i < FEX_NUM_EXC; i++)
				ptr[i].__mode = ((te & te_bit[i])? FEX_NOHANDLER : FEX_NONSTOP);
		}
		return ptr;
	}
}

/*
*  Update the trap enable bits according to the selected modes
*/
void
__fex_update_te()
{
	struct fex_handler_data	*thr_handlers;
	struct sigaction		act, tmpact;
	sigset_t				blocked;
	unsigned long			fsr;
	int						te;

	/* determine which traps are needed */
	thr_handlers = __fex_get_thr_handlers();
	__fenv_getfsr(&fsr);
	te = __fex_te_needed(thr_handlers, fsr);

	/* install __fex_hdlr as necessary */
	if (!hdlr_installed && te) {
		act.sa_handler = __fex_hdlr;
		sigemptyset(&act.sa_mask);
		act.sa_flags = SA_SIGINFO;
		sigaction(SIGFPE, &act, &tmpact);
		if (tmpact.sa_handler != __fex_hdlr)
		{
			mutex_lock(&hdlr_lock);
			oact = tmpact;
			mutex_unlock(&hdlr_lock);
		}
		hdlr_installed = 1;
	}

	/* set the new trap enable bits (only if SIGFPE is not blocked) */
	if (sigprocmask(0, NULL, &blocked) == 0 &&
		!sigismember(&blocked, SIGFPE)) {
		__fenv_set_te(fsr, te);
		__fenv_setfsr(&fsr);
	}

	/* synchronize with libmtsk */
	__mt_fex_sync = __fex_sync_with_libmtsk;

#ifdef LIBM_MT_FEX_SYNC
	/* synchronize with other projects */
	__libm_mt_fex_sync = __fex_sync_with_threads;
#endif
}
