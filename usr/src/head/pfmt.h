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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 */
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

#ifndef	_PFMT_H
#define	_PFMT_H

#include <stdio.h>
#ifndef va_args
#include <stdarg.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#define	MM_STD		0
#define	MM_NOSTD	0x100
#define	MM_GET		0
#define	MM_NOGET	0x200

#define	MM_ACTION	0x400

#define	MM_NOCONSOLE	0
#define	MM_CONSOLE	0x800

/* Classification */
#define	MM_NULLMC	0
#define	MM_HARD		0x1000
#define	MM_SOFT		0x2000
#define	MM_FIRM		0x4000
#define	MM_APPL		0x8000
#define	MM_UTIL		0x10000
#define	MM_OPSYS	0x20000

/* Most commonly used combinations */
#define	MM_SVCMD	MM_UTIL|MM_SOFT

#define	MM_ERROR	0
#define	MM_HALT		1
#define	MM_WARNING	2
#define	MM_INFO		3

int pfmt(FILE *, long, const char *, ...);
int lfmt(FILE *, long, const char *, ...);
int vpfmt(FILE *, long, const char *, va_list);
int vlfmt(FILE *, long, const char *, va_list);
const char *setcat(const char *);
int setlabel(const char *);
int addsev(int, const char *);

#define	DB_NAME_LEN		15
#define	MAXLABEL		25

#ifdef	__cplusplus
}
#endif

#endif	/* _PFMT_H */
