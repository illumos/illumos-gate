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
 * Copyright (c) 1991,1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _RMT_H
#define	_RMT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/mtio.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef __STDC__
extern void rmtinit(void (*)(const char *, ...), void (*)(int));
extern int rmthost(char *, uint_t);
extern int rmtopen(char *, int);
extern void rmtclose(void);
extern int rmtstatus(struct mtget *);
extern int rmtread(char *, uint_t);
extern int rmtwrite(char *, uint_t);
extern int rmtseek(int, int);
extern int rmtioctl(int, long);
#else
extern void rmtinit();
extern int rmthost();
extern int rmtopen();
extern void rmtclose();
extern int rmtstatus();
extern int rmtread();
extern int rmtwrite();
extern int rmtseek();
extern int rmtioctl();
#endif

#ifdef	__cplusplus
}
#endif

#endif /* _RMT_H */
