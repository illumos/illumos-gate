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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SN1_MISC_H
#define	_SN1_MISC_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This header file must uses _ASM defines to allow it to be included
 * in assmebly source files
 */
#include <sys/asm_linkage.h>
#include <sys/regset.h>
#include <sys/syscall.h>
#include "assym.h"

/*
 * Our syscall emulation callback handler adds one argument to each
 * system call, so we'll need to allocate space for one more argument
 * above the maximum number of arguments that a system call can normally
 * take.  Also, we assume that each syscall argument is a long, ie, we
 * don't support long long syscall parameters.
 */
#if defined(__sparc)
/*
 * 32-bit and 64-bit sparc syscalls can take up to 8 arguments.
 * 32-bit sparc indirect syscalls can take up to 9 arguments.
 * Arguments 1 - 6 are passed via %o0 - %o5.
 * Additional arguments are passed on the stack.
 * So make space for 4 arguments on the stack.
 */
#define	EH_ARGS_COUNT		4
#elif defined(__amd64)
/*
 * amd64 syscalls can take up to 8 arguments.
 * Arguments 1 - 6 are passed via: %rdi, %rsi, %rdx, %r10, %r8, %r9
 * Additional arguments are passed on the stack.
 * So make space for 3 arguments on the stack.
 */
#define	EH_ARGS_COUNT		3
#else /* !__sparc && !__amd64 */
/*
 * ia32 syscalls can take up to 8 arguments.
 * All arguments are passed on the stack.
 * So make space for 9 arguments on the stack.
 */
#define	EH_ARGS_COUNT		9
#endif /* !__sparc && !__amd64 */


#define	EH_ARGS_SIZE		(CPTRSIZE * EH_ARGS_COUNT)
#define	EH_ARGS_OFFSET(x)	(STACK_BIAS + MINFRAME + (CPTRSIZE * (x)))
#define	EH_LOCALS_SIZE		(EH_ARGS_SIZE + SIZEOF_GREGSET_T + \
				    SIZEOF_SYSRET_T + CPTRSIZE)

#if defined(__sparc)
/*
 * On sparc, all emulation callback handler variable access is done
 * relative to %sp, so access offsets are positive.
 */
#define	EH_LOCALS_START		(STACK_BIAS + MINFRAME + EH_ARGS_SIZE)
#define	EH_LOCALS_END_TGT	(STACK_BIAS + MINFRAME + EH_LOCALS_SIZE)
#else /* !__sparc */
/*
 * On x86, all emulation callback handler variable access is done
 * relative to %ebp/%rbp, so access offsets are negative.
 */
#define	EH_LOCALS_START		(-(EH_LOCALS_SIZE - \
				    (STACK_BIAS + MINFRAME + EH_ARGS_SIZE)))
#define	EH_LOCALS_END_TGT	0
#endif /* !__sparc */

/*
 * In our emulation callback handler, our stack will look like:
 *		-------------------------------------------------
 *	  %bp   | long		rvflag				|
 *	   |    | sysret_t	sysret				|
 *	   v    | gregset_t	gregs				|
 *	  %sp   | long		callback args[EH_ARGS_COUNT]	|
 *		-------------------------------------------------
 * For ia32, use %ebp and %esp instead of %bp and %sp.
 * For amd64, use %rbp and %rsp instead of %bp and %sp.
 *
 * Our emulation callback handler always saves enough space to hold the
 * maximum number of stack arguments to a system call.  This is architecture
 * specific and is defined via EH_ARGS_COUNT.
 */
#define	EH_LOCALS_GREGS		(EH_LOCALS_START)
#define	EH_LOCALS_GREG(x)	(EH_LOCALS_GREGS + (SIZEOF_GREG_T * (x)))
#define	EH_LOCALS_SYSRET	(EH_LOCALS_GREGS + SIZEOF_GREGSET_T)
#define	EH_LOCALS_SYSRET1	(EH_LOCALS_SYSRET)
#define	EH_LOCALS_SYSRET2	(EH_LOCALS_SYSRET + CPTRSIZE)
#define	EH_LOCALS_RVFLAG	(EH_LOCALS_SYSRET + SIZEOF_SYSRET_T)
#define	EH_LOCALS_END		(EH_LOCALS_RVFLAG + CPTRSIZE)

#if (EH_LOCALS_END != EH_LOCALS_END_TGT)
#error "sn1_misc.h EH_LOCALS_* macros don't add up"
#endif /* (EH_LOCALS_END != EH_LOCALS_END_TGT) */

/*
 * The second parameter of each entry in the sn1_sysent_table
 * contains the number of parameters and flags that describe the
 * syscall return value encoding.  See the block comments at the
 * top of ../common/sn1_brand.c for more information about the
 * syscall return value flags and when they should be used.
 */
#define	NARGS_MASK	0x000000FF	/* Mask for syscalls argument count */
#define	RV_MASK		0x0000FF00	/* Mask for return value flags */
#define	RV_DEFAULT	0x00000100	/* syscall returns "default" values */
#define	RV_32RVAL2	0x00000200	/* syscall returns two 32-bit values */
#define	RV_64RVAL	0x00000400	/* syscall returns a 64-bit value */

#if !defined(_ASM)

/*
 * We define our own version of assert because the default one will
 * try to emit a localized message.  That is bad because first, we can't
 * emit messages to random file descriptors, and second localizing a message
 * requires allocating memory and we can't do that either.
 */
#define	sn1_assert(ex)	(void)((ex) || \
				(_sn1_abort(0, #ex, __FILE__, __LINE__), 0))
#define	sn1_abort(err, msg)	_sn1_abort((err), (msg), __FILE__, __LINE__)

/*
 * From sn1_runexe.s
 */
extern void sn1_runexe(void *, ulong_t);

/*
 * From sn1_handler.s
 */
extern void sn1_handler(void);
extern void sn1_error(void);
extern void sn1_success(void);

/*
 * From sn1_brand.c
 */
extern void _sn1_abort(int, const char *, const char *, int);

#endif	/* !_ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SN1_MISC_H */
