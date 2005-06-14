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

#ifndef	_AMD64_PRINT_H
#define	_AMD64_PRINT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/varargs.h>

#undef printf	/* unbelievably broken bootsvcs.h */

extern int amd64_vsnprintf(char *, size_t, const char *, va_list)
	__VPRINTFLIKE(3);
extern int amd64_vsnprintf64(char *, size_t, const char *, va_list)
	__VPRINTFLIKE(3);
extern int amd64_snprintf(char *, size_t, const char *, ...)
	__PRINTFLIKE(3);
extern int amd64_snprintf64(char *, size_t, const char *, ...)
	__PRINTFLIKE(3);
extern void amd64_vpanic(const char *, va_list)
	__VPRINTFLIKE(1);
extern void amd64_panic(const char *, ...)
	__PRINTFLIKE(1);
extern void amd64_warning(const char *, ...)
	__PRINTFLIKE(1);
extern int amd64_assfail(const char *, const char *, int);

#ifdef	__cplusplus
}
#endif

#endif	/* _AMD64_PRINT_H */
