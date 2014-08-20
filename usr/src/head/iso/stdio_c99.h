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
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * An application should not include this header directly.  Instead it
 * should be included only through the inclusion of other Sun headers.
 *
 * The contents of this header is limited to identifiers specified in
 * the C99 standard and in conflict with the C++ implementation of the
 * standard header.  The C++ standard may adopt the C99 standard at
 * which point it is expected that the symbols included here will
 * become part of the C++ std namespace.
 */

#ifndef _ISO_STDIO_C99_H
#define	_ISO_STDIO_C99_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The following have been added as a result of the ISO/IEC 9899:1999
 * standard. For a strictly conforming C application, visibility is
 * contingent on the value of __STDC_VERSION__ (see sys/feature_tests.h).
 * For non-strictly conforming C applications, there are no restrictions
 * on the C namespace.
 */

#if defined(__EXTENSIONS__) || defined(_STDC_C99) || \
	(!defined(_STRICT_STDC) && !defined(__XOPEN_OR_POSIX))

#if !defined(_LP64) && !defined(_LONGLONG_TYPE)
#ifdef __PRAGMA_REDEFINE_EXTNAME
#pragma	redefine_extname snprintf	_snprintf_c89
#pragma	redefine_extname vsnprintf	_vsnprintf_c89
#pragma	redefine_extname vfscanf	_vfscanf_c89
#pragma	redefine_extname vscanf		_vscanf_c89
#pragma	redefine_extname vsscanf	_vsscanf_c89
#else
#define	snprintf	_snprintf_c89
#define	vsnprintf	_vsnprintf_c89
#define	vfscanf		_vfscanf_c89
#define	vscanf		_vscanf_c89
#define	vsscanf		_vsscanf_c89
#endif
#endif /* !defined(_LP64) && !defined(_LONGLONG_TYPE) */

extern int vfscanf(FILE *_RESTRICT_KYWD, const char *_RESTRICT_KYWD, __va_list);
extern int vscanf(const char *_RESTRICT_KYWD, __va_list);
extern int vsscanf(const char *_RESTRICT_KYWD, const char *_RESTRICT_KYWD,
		__va_list);
#endif /* defined(__EXTENSIONS__) ... */
#if defined(__EXTENSIONS__) || defined(_STDC_C99) || \
	(!defined(_STRICT_STDC) && !defined(__XOPEN_OR_POSIX)) || \
	defined(_XPG5)
extern int snprintf(char *_RESTRICT_KYWD, size_t, const char *_RESTRICT_KYWD,
	...);
extern int vsnprintf(char *_RESTRICT_KYWD, size_t, const char *_RESTRICT_KYWD,
	__va_list);

#endif /* defined(__EXTENSIONS__) || defined(_STDC_C99) ... */

#ifdef	__cplusplus
}
#endif

#endif	/* _ISO_STDIO_C99_H */
