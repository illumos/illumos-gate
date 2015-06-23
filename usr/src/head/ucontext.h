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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _UCONTEXT_H
#define	_UCONTEXT_H

#include <sys/ucontext.h>

#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
#include <sys/siginfo.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef __sparc
#ifdef __PRAGMA_REDEFINE_EXTNAME
#pragma	redefine_extname	makecontext	__makecontext_v2
#else
#define	makecontext	__makecontext_v2
#endif
#endif

extern int getcontext(ucontext_t *) __RETURNS_TWICE;
#pragma unknown_control_flow(getcontext)
extern int setcontext(const ucontext_t *) __NORETURN;
extern int swapcontext(ucontext_t *_RESTRICT_KYWD,
		const ucontext_t *_RESTRICT_KYWD);
extern void makecontext(ucontext_t *, void(*)(), int, ...);

#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
extern int walkcontext(const ucontext_t *, int (*)(uintptr_t, int, void *),
    void *);
extern int printstack(int);
extern int addrtosymstr(void *, char *, int);
extern int getustack(stack_t **);
extern int setustack(stack_t *);

extern int stack_getbounds(stack_t *);
extern int stack_setbounds(const stack_t *);
extern int stack_inbounds(void *);
extern int stack_violation(int, const siginfo_t *, const ucontext_t *);

extern void *_stack_grow(void *);
#endif	/* !_XPG4_2 || __EXTENSIONS__ */

#ifdef	__cplusplus
}
#endif

#endif	/* _UCONTEXT_H */
