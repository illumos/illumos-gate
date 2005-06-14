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
/*	  All Rights Reserved	*/


/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _ISO_STDARG_C99_H
#define	_ISO_STDARG_C99_H

#pragma ident	"%Z%%M%	%I%	%E% SMI" /* SVr4.0 1.8 */

/*
 * An application should not include this header directly.  Instead it
 * should be included only through the inclusion of other Sun headers.
 *
 * This header defines the va_copy variable argument macro, which is
 * new in ISO C 1999, and thus not present in ISO C 1989 and ISO C++
 * 1998.  Because this macro is a long-standing Solaris extension, it
 * is also permitted in other contexts.
 *
 * The varargs definitions within this header are defined in terms of
 * implementation definitions.  These implementation definitions reside
 * in <sys/va_list.h>.  This organization enables protected use of
 * the implementation by other standard headers without introducing
 * names into the users' namespace.
 */

#include <sys/feature_tests.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * va_copy was initially a Solaris extension to provide a portable
 * way to perform a variable argument list ``bookmarking'' function.
 * It is now specified in the ISO/IEC 9899:1999 standard.
 */
#if defined(__EXTENSIONS__) || defined(_STDC_C99) || \
	(!defined(_STRICT_STDC) && !defined(__XOPEN_OR_POSIX)) || \
	defined(_XPG6)

#define	va_copy(to, from)	__va_copy(to, from)

#endif	/* defined(__EXTENSIONS__) || defined(_STDC_C99)... */

#ifdef	__cplusplus
}
#endif

#endif	/* _ISO_STDARG_C99_H */
