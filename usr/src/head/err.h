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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
 */

#ifndef	_ERR_H
#define	_ERR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdarg.h>
#include <sys/ccompile.h>

/* Program exit and warning calls */
void err(int, const char *, ...) __PRINTFLIKE(2) __NORETURN;
void verr(int, const char *, va_list) __VPRINTFLIKE(2) __NORETURN;
void errc(int, int, const char *, ...) __PRINTFLIKE(3) __NORETURN;
void verrc(int, int, const char *, va_list) __VPRINTFLIKE(3) __NORETURN;
void errx(int, const char *, ...) __PRINTFLIKE(2) __NORETURN;
void verrx(int, const char *, va_list) __VPRINTFLIKE(2) __NORETURN;
void warn(const char *, ...) __PRINTFLIKE(1);
void vwarn(const char *, va_list) __VPRINTFLIKE(1);
void warnc(int, const char *, ...) __PRINTFLIKE(2);
void vwarnc(int, const char *, va_list) __VPRINTFLIKE(2);
void warnx(const char *, ...) __PRINTFLIKE(1);
void vwarnx(const char *, va_list) __VPRINTFLIKE(1);

#ifdef __cplusplus
}
#endif

#endif	/* _ERR_H */
