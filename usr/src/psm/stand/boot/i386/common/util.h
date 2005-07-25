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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_STRINGS_H
#define	_STRINGS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/varargs.h>
#include <sys/promif.h>
#include "asm/sunddi.h"

/*
 * This header file contains most of the libc-like interfaces
 */

#ifdef	__cplusplus
extern "C" {
#endif

extern uchar_t inb(int);
extern void outb(int, uint8_t);
extern void sync_instruction_memory(caddr_t v, size_t len);

extern void bzero(void *, size_t);
extern void bcopy(const void *, void *, size_t);
extern size_t strlen(const char *);
extern int strcmp(const char *, const char *);
extern int strncmp(const char *, const char *, size_t);
extern char *strcat(char *, const char *);
extern char *strcpy(char *, const char *);
extern char *strrchr(const char *, int);
extern char *strstr(const char *, const char *);

extern void prom_init(char *, void *);
extern int openfile(char *, char *);
extern int close(int);

extern void printf(const char *, ...);

extern void reset(void) __NORETURN;
extern void prom_panic(char *fmt) __NORETURN;
extern void panic(const char *fmt, ...) __NORETURN;

#ifdef	__cplusplus
}
#endif

#endif	/* _STRINGS_H */
