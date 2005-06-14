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
 * Copyright 1997-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This is where all the interfaces that are internal to libucb
 * which do not have a better home live
 */

#ifndef _LIBC_H
#define	_LIBC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/regset.h>
#include <sys/times.h>
#include <sys/ucontext.h>
#include <sys/dirent.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * getdents64 transitional interface is intentionally internal to libc
 */
extern int getdents64(int, struct dirent64 *, size_t);

/*
 * defined in port/stdio/doprnt.c
 */
extern int _doprnt(char *format, va_list in_args, FILE *iop);

/*
 * defined in port/gen/_psignal.c
 */
extern void _psignal(unsigned int sig, char *s);

/*
 * defined in _getsp.s
 */
extern greg_t _getsp(void);

/*
 * defined in ucontext.s
 */
extern int __getcontext(ucontext_t *);

/*
 * defined in libc
 */
extern int _sigaction(int, const struct sigaction *, struct sigaction *);

/*
 * External Variables
 */
extern void (*_siguhandler[])(int, int, struct sigcontext *, char *);
	/* for BSD */

/*
 * defined in port/gen/siglist.c
 */
extern char *sys_siglist[];

#ifdef __cplusplus
}
#endif

#endif /* _LIBC_H */
