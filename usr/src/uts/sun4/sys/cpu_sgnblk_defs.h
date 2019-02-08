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
/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2019 Peter Tribble.
 */

#ifndef	_CPU_SGNBLK_DEFS_H
#define	_CPU_SGNBLK_DEFS_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _ASM

#include <sys/types.h>
#include <sys/cpuvar.h>

#endif /* _ASM */

/*
 * Build a CPU signature given a signature, state and sub-state.
 */
#define	CPU_SIG_BLD(sig, state, sub_state) \
	(((sig) << 16) | ((state) << 8) | (sub_state))

/*
 * Definition of a CPU signature.
 */
typedef union {
	struct cpu_signature {
		ushort_t	sig;		/* see xxxx_SIG below. */
		uchar_t		state;		/* see SIGBST_xxxx below. */
		uchar_t		sub_state;	/* EXIT_xxx if SIGBST_EXIT. */
	} state_t;
	uint32_t	signature;
} sig_state_t;

/*
 * CPU Signatures - the signature defines the entity that the CPU is executing.
 * This entity can be the OS, OPB or the debugger.  This signature consists of
 * two ASCII characters.
 */
#define	SIG_BLD(f, s)	(((f) << 8) | (s))

#define	OBP_SIG		SIG_BLD('O', 'B')
#define	OS_SIG		SIG_BLD('O', 'S')
#define	DBG_SIG		SIG_BLD('D', 'B')
#define	POST_SIG	SIG_BLD('P', 'O')

/*
 * CPU State - the state identifies what the CPU is doing.
 * The states should be defined in an increasing, linear
 * manner.
 */
#define	SIGST_NONE			0
#define	SIGST_RUN			1
#define	SIGST_EXIT			2
#define	SIGST_PRERUN			3
#define	SIGST_DOMAINSTOP		4
#define	SIGST_RESET			5
#define	SIGST_POWEROFF			6
#define	SIGST_DETACHED			7
#define	SIGST_CALLBACK			8
#define	SIGST_OFFLINE			9
#define	SIGST_BOOTING			10
#define	SIGST_UNKNOWN			11
#define	SIGST_ERROR_RESET		12
#define	SIGST_ERROR_RESET_SYNC		13
#define	SIGST_QUIESCED			14
#define	SIGST_QUIESCE_INPROGRESS	15
#define	SIGST_RESUME_INPROGRESS		16
#define	SIGST_INIT			17
#define	SIGST_LOADING			18

/*
 *  CPU sub-state - the sub-state is used to further qualify
 *  the state.
 */
#define	SIGSUBST_NULL			0
#define	SIGSUBST_HALT			1
#define	SIGSUBST_ENVIRON		2
#define	SIGSUBST_REBOOT			3
#define	SIGSUBST_PANIC			4
#define	SIGSUBST_PANIC_CONT		5
#define	SIGSUBST_HUNG			6
#define	SIGSUBST_WATCH			7
#define	SIGSUBST_PANIC_REBOOT		8
#define	SIGSUBST_ERROR_RESET_REBOOT	9
#define	SIGSUBST_OBP_RESET		10
#define	SIGSUBST_DEBUG			11
#define	SIGSUBST_DUMP			12
#define	SIGSUBST_FAILED			13

#ifdef _KERNEL

#define	CPU_SIGNATURE(sig, state, sub_state, cpuid)			\
{									\
	if (cpu_sgn_func)						\
		(*cpu_sgn_func)((sig), (state), (sub_state), (cpuid));	\
}

extern void (*cpu_sgn_func)(ushort_t, uchar_t, uchar_t, int);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _CPU_SGNBLK_DEFS_H */
