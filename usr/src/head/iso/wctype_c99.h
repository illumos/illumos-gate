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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
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

#ifndef _ISO_WCTYPE_C99_H
#define	_ISO_WCTYPE_C99_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

/*
 * Visibility of the iswblank() function is not allowed in the X/Open
 * or POSIX namespace prior to SUSv3.  However, since SUSv3 aligns
 * with the C99 standard, visibility is controlled by the version of
 * the C standard as indicated by the value of __STDC_VERSION__ (see
 * sys/feature_tests.h and _STDC_C99) rather than if the X/Open or POSIX
 * feature test macros are used.  Conforming SUSv3 applications are
 * required to use c99, therefore, iswblank() will be made visible by
 * default.
 */

#if (!defined(_STRICT_STDC) && !defined(__XOPEN_OR_POSIX)) || \
	defined(_STDC_C99) || defined(__EXTENSIONS__)
#ifdef __STDC__
extern int iswblank(wint_t);
#else
extern int iswblank();
#endif
#endif /* defined(__EXTENSIONS__)... */

#ifdef	__cplusplus
}
#endif

#endif	/* _ISO_WCTYPE_C99_H */
