/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
#pragma ident	"%Z%%M%	%I%	%E% SMI" 

/*
 * Copyright (c) 1987 by Sun Microsystems, Inc. 
 */

/* Swap handler for SIGFPE codes.	 */

#include <errno.h>
#include <signal.h>
#include <floatingpoint.h>

#ifndef FPE_INTDIV_TRAP
#define     FPE_INTDIV_TRAP     0x14	/* integer divide by zero */
#endif
#ifndef FPE_CHKINST_TRAP
#define     FPE_CHKINST_TRAP    0x18	/* CHK [CHK2] instruction */
#endif
#ifndef FPE_TRAPV_TRAP
#define     FPE_TRAPV_TRAP      0x1c	/* TRAPV [cpTRAPcc TRAPcc] instr */
#endif
#ifndef FPE_FLTBSUN_TRAP
#define     FPE_FLTBSUN_TRAP    0xc0	/* [branch or set on unordered cond] */
#endif
#ifndef FPE_FLTINEX_TRAP
#define     FPE_FLTINEX_TRAP    0xc4	/* [floating inexact result] */
#endif
#ifndef FPE_FLTDIV_TRAP
#define     FPE_FLTDIV_TRAP     0xc8	/* [floating divide by zero] */
#endif
#ifndef FPE_FLTUND_TRAP
#define     FPE_FLTUND_TRAP     0xcc	/* [floating underflow] */
#endif
#ifndef FPE_FLTOPERR_TRAP
#define     FPE_FLTOPERR_TRAP   0xd0	/* [floating operand error] */
#endif
#ifndef FPE_FLTOVF_TRAP
#define     FPE_FLTOVF_TRAP     0xd4	/* [floating overflow] */
#endif
#ifndef FPE_FLTNAN_TRAP
#define     FPE_FLTNAN_TRAP     0xd8	/* [floating Not-A-Number] */
#endif
#ifndef FPE_FPA_ENABLE
#define     FPE_FPA_ENABLE      0x400	/* [FPA not enabled] */
#endif
#ifndef FPE_FPA_ERROR
#define     FPE_FPA_ERROR       0x404	/* [FPA arithmetic exception] */
#endif

#define N_SIGFPE_CODE 13

/* Array of SIGFPE codes. */

static sigfpe_code_type sigfpe_codes[N_SIGFPE_CODE] = {
						       FPE_INTDIV_TRAP,
						       FPE_CHKINST_TRAP,
						       FPE_TRAPV_TRAP,
						       FPE_FLTBSUN_TRAP,
						       FPE_FLTINEX_TRAP,
						       FPE_FLTDIV_TRAP,
						       FPE_FLTUND_TRAP,
						       FPE_FLTOPERR_TRAP,
						       FPE_FLTOVF_TRAP,
						       FPE_FLTNAN_TRAP,
						       FPE_FPA_ENABLE,
						       FPE_FPA_ERROR,
						       0};

/* Array of handlers. */

static sigfpe_handler_type sigfpe_handlers[N_SIGFPE_CODE];

static int      _sigfpe_master_enabled;
/* Originally zero, set to 1 by _enable_sigfpe_master. */

void
_sigfpe_master(sig, code, scp, addr)
	int             sig;
	sigfpe_code_type code;
	struct sigcontext *scp;
	char *addr;
{
	int             i;
	enum fp_exception_type exception;

	for (i = 0; (i < N_SIGFPE_CODE) && (code != sigfpe_codes[i]); i++);
	/* Find index of handler. */
	if (i >= N_SIGFPE_CODE)
		i = N_SIGFPE_CODE - 1;
	switch ((unsigned int)sigfpe_handlers[i]) {
	case (unsigned int)SIGFPE_DEFAULT:
		switch (code) {
		case FPE_FLTBSUN_TRAP:
		case FPE_FLTOPERR_TRAP:
		case FPE_FLTNAN_TRAP:
			exception = fp_invalid;
			goto ieee;
		case FPE_FLTINEX_TRAP:
			exception = fp_inexact;
			goto ieee;
		case FPE_FLTDIV_TRAP:
			exception = fp_division;
			goto ieee;
		case FPE_FLTUND_TRAP:
			exception = fp_underflow;
			goto ieee;
		case FPE_FLTOVF_TRAP:
			exception = fp_overflow;
			goto ieee;
		default:	/* The common default treatment is to abort. */
			break;
		}
	case (unsigned int)SIGFPE_ABORT:
		abort();
	case (unsigned int)SIGFPE_IGNORE:
		return;
	default:		/* User-defined not SIGFPE_DEFAULT or
				 * SIGFPE_ABORT. */
		(sigfpe_handlers[i]) (sig, code, scp, addr);
		return;
	}
ieee:
	switch ((unsigned int)ieee_handlers[(int) exception]) {
	case (unsigned int)SIGFPE_DEFAULT:	
					/* Error condition but ignore it. */
	case (unsigned int)SIGFPE_IGNORE:	
					/* Error condition but ignore it. */
		return;
	case (unsigned int)SIGFPE_ABORT:
		abort();
	default:
		(ieee_handlers[(int) exception]) (sig, code, scp, addr);
		return;
	}
}

int
_enable_sigfpe_master()
{
	/* Enable the sigfpe master handler always.	 */
	struct sigvec   newsigvec, oldsigvec;

	newsigvec.sv_handler = _sigfpe_master;
	newsigvec.sv_mask = 0;
	newsigvec.sv_onstack = 0;
	_sigfpe_master_enabled = 1;
	return sigvec(SIGFPE, &newsigvec, &oldsigvec);
}

int
_test_sigfpe_master()
{
	/*
	 * Enable the sigfpe master handler if it's never been enabled
	 * before. 
	 */

	if (_sigfpe_master_enabled == 0)
		return _enable_sigfpe_master();
	else
		return _sigfpe_master_enabled;
}

sigfpe_handler_type
sigfpe(code, hdl)
	sigfpe_code_type code;
	sigfpe_handler_type hdl;
{
	sigfpe_handler_type oldhdl;
	int             i;

	_test_sigfpe_master();
	for (i = 0; (i < N_SIGFPE_CODE) && (code != sigfpe_codes[i]); i++);
	/* Find index of handler. */
	if (i >= N_SIGFPE_CODE) {
		errno = EINVAL;
		return (sigfpe_handler_type) BADSIG;/* Not 0 or SIGFPE code */
	}
	oldhdl = sigfpe_handlers[i];
	sigfpe_handlers[i] = hdl;
	return oldhdl;
}
