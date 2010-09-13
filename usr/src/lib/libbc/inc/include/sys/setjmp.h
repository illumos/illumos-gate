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
/*	from UCB 4.1 83/05/03	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef	__sparc_setjmp_h
#define	__sparc_setjmp_h

/*
 * onsstack,sigmask,sp,pc,npc,psr,g1,o0,wbcnt (sigcontext).
 * All else recovered by under/over(flow) handling.
 */
#define	_JBLEN	9

typedef	int jmp_buf[_JBLEN];

/*
 * One extra word for the "signal mask saved here" flag.
 */
typedef	int sigjmp_buf[_JBLEN+1];

int	setjmp(/* jmp_buf env */);
int	_setjmp(/* jmp_buf env */);
int	sigsetjmp(/* sigjmp_buf env, int savemask */);
void	longjmp(/* jmp_buf env, int val */);
void	_longjmp(/* jmp_buf env, int val */);
void	siglongjmp(/* sigjmp_buf env, int val */);

/*
 * Routines that call setjmp have strange control flow graphs,
 * since a call to a routine that calls resume/longjmp will eventually
 * return at the setjmp site, not the original call site.  This
 * utterly wrecks control flow analysis.
 */
#pragma unknown_control_flow(sigsetjmp, setjmp, _setjmp)

#endif	/* !__sparc_setjmp_h */
