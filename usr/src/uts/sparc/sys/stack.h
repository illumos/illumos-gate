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

#ifndef _SYS_STACK_H
#define	_SYS_STACK_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if !defined(_ASM)

#include <sys/types.h>

#endif

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * A stack frame looks like:
 *
 * %fp->|				|
 *	|-------------------------------|
 *	|  Locals, temps, saved floats	|
 *	|-------------------------------|
 *	|  outgoing parameters past 6	|
 *	|-------------------------------|-\
 *	|  6 words for callee to dump	| |
 *	|  register arguments		| |
 *	|-------------------------------|  > minimum stack frame
 *	|  One word struct-ret address	| |
 *	|-------------------------------| |
 *	|  16 words to save IN and	| |
 * %sp->|  LOCAL register on overflow	| |
 *	|-------------------------------|-/
 */

/*
 * Constants defining a 32-bit stack frame.
 */
#define	WINDOWSIZE32	(16*4)		/* size of window save area */
#define	ARGPUSHSIZE32	(6*4)		/* size of arg dump area */
#define	ARGPUSH32	(WINDOWSIZE32 + 4)	/* arg dump area offset */
#define	MINFRAME32	(WINDOWSIZE32 + ARGPUSHSIZE32 + 4) /* min frame */

#define	STACK_GROWTH_DOWN /* stacks grow from high to low addresses */

/*
 * Stack alignment macros.
 */
#define	STACK_ALIGN32		8
#define	STACK_ENTRY_ALIGN32	8
#define	SA32(X)			(((X)+(STACK_ALIGN32-1)) & ~(STACK_ALIGN32-1))

#if defined(__sparcv9)
/*
 * The 64-bit C ABI uses a stack frame that looks like:
 *
 *      |				|
 *	|-------------------------------|
 *	|  Locals, temps, saved floats	|
 *	|-------------------------------|
 *	|  outgoing parameters past 6	|
 *	|-------------------------------|-\
 *	|  outgoing parameters thru 6	| |
 *	|-------------------------------|  > minimum stack frame
 *	|  16 xwords to save IN and	| |
 *      |  LOCAL register on overflow	| |
 *	|-------------------------------|-/-\
 *      |				|   |
 *      |				|    > v9 abi bias
 *      |				|   |
 * %sp->|-------------------------------|---/
 */

/*
 * Constants defining a stack frame.
 */
#define	WINDOWSIZE64		(16*8)		/* size of window save area */
#define	ARGPUSHSIZE64		(6*8)		/* size of arg dump area */
#define	MINFRAME64		(WINDOWSIZE64 + 48)	/* min frame */
#define	ARGPUSH64		(WINDOWSIZE64)	/* arg dump area offset */
#define	V9BIAS64		(2048-1)	/* v9 abi stack bias */

#define	STACK_ALIGN64		16
#define	STACK_ENTRY_ALIGN64	16
#define	SA64(X)			(((X)+(STACK_ALIGN64-1)) & ~(STACK_ALIGN64-1))

#define	IS_V9STACK(x)		((((uintptr_t)(x) + V9BIAS64) & \
				(STACK_ALIGN64-1)) == 0)

#define	WINDOWSIZE		WINDOWSIZE64
#define	ARGPUSHSIZE		ARGPUSHSIZE64
#define	ARGPUSH			ARGPUSH64
#define	MINFRAME		MINFRAME64
#define	STACK_ALIGN		STACK_ALIGN64
#define	STACK_ENTRY_ALIGN	STACK_ENTRY_ALIGN64
#define	STACK_BIAS		V9BIAS64
#define	SA(x)			SA64(x)

#else

#define	WINDOWSIZE		WINDOWSIZE32
#define	ARGPUSHSIZE		ARGPUSHSIZE32
#define	ARGPUSH			ARGPUSH32
#define	MINFRAME		MINFRAME32
#define	STACK_ALIGN		STACK_ALIGN32
#define	STACK_ENTRY_ALIGN	STACK_ENTRY_ALIGN32
#define	STACK_BIAS		0
#define	SA(x)			SA32(x)
#define	STACK_V9BIAS64		(2048-1)	/* v9 abi stack bias */

#endif /* __sparcv9 */

#if defined(_KERNEL) && !defined(_ASM)

#if defined(DEBUG)
#if STACK_ALIGN == 8
#define	ASSERT_STACK_ALIGNED()						\
	{								\
		uint64_t __tmp;						\
		ASSERT((((uintptr_t)&__tmp) & (STACK_ALIGN - 1)) == 0);	\
	}
#elif (STACK_ALIGN == 16) && (_LONG_DOUBLE_ALIGNMENT == 16)
#define	ASSERT_STACK_ALIGNED()						\
	{								\
		long double __tmp;					\
		ASSERT((((uintptr_t)&__tmp) & (STACK_ALIGN - 1)) == 0);	\
	}
#endif
#else	/* DEBUG */
#define	ASSERT_STACK_ALIGNED()
#endif	/* DEBUG */

struct regs;

void flush_windows(void);
void flush_user_windows(void);
int  flush_user_windows_to_stack(caddr_t *);
void trash_user_windows(void);
void traceregs(struct regs *);
void traceback(caddr_t);

#endif	/* defined(_KERNEL) && !defined(_ASM) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_STACK_H */
