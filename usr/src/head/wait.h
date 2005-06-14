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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef _WAIT_H
#define	_WAIT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1	*/

#include <sys/types.h>
#include <sys/siginfo.h>
#include <sys/procset.h>
#include <sys/wait.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(__STDC__)

extern pid_t wait(int *);
extern pid_t waitpid(pid_t, int *, int);
extern int waitid(idtype_t, id_t, siginfo_t *, int);

#else

extern pid_t wait();
extern pid_t waitpid();
extern int waitid();

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _WAIT_H */
