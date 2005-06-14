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


#ifndef	_SIGINFO_H
#define	_SIGINFO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1	*/

#include <sys/types.h>
#include <sys/siginfo.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct siginfolist {
	int nsiginfo;
	char **vsiginfo;
};

#ifdef __STDC__
extern const char * _sys_illlist[];
extern const char * _sys_fpelist[];
extern const char * _sys_segvlist[];
extern const char * _sys_buslist[];
extern const char * _sys_traplist[];
extern const char * _sys_cldlist[];
extern const struct siginfolist *_sys_siginfolistp;
#define	_sys_siginfolist	_sys_siginfolistp
#else
extern char * _sys_illlist[];
extern char * _sys_fpelist[];
extern char * _sys_segvlist[];
extern char * _sys_buslist[];
extern char * _sys_traplist[];
extern char * _sys_cldlist[];
extern struct siginfolist *_sys_siginfolistp;
#define	_sys_siginfolist	_sys_siginfolistp
#endif

#if defined(__STDC__)

extern void psignal(int, const char *);
extern void psiginfo(siginfo_t *, char *);

#else

extern void psignal();
extern void psiginfo();

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SIGINFO_H */
