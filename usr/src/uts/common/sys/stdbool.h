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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_STDBOOL_H
#define	_SYS_STDBOOL_H

/*
 * This header is included for alignment with the ISO/IEC 9899:1999 standard.
 * The contents are only visible when using a c99 compiler. In the case of
 * the Sun compiler, some C99 features, including the _Bool built-in type,
 * are provided in the default compilation mode. This is a subset of what
 * is provided when __STDC_VERSION__ is 199901; hence the contents of this
 * header are made visible when either __STDC_VERSION__ >= 199901 (_STDC_C99
 * as defined in sys/feature_tests.h) or if __C99FEATURES__ (a Sun compiler
 * built-in) is defined. Likewise for GNU C, support for C99 features,
 * including this header, is provided in versions 3.0 or greater. In no
 * case should the contents of this header be visible in a C++ build
 * environment.
 *
 * Note that the ability to undefine and redefine the macros bool,
 * true, and false  is an obsolescent feature which may be withdrawn
 * in a future version of the standards specifications.
 */

#include <sys/feature_tests.h>

#ifndef __cplusplus
#if defined(_STDC_C99) || defined(__C99FEATURES__) || __GNUC__ >= 3

#undef	bool
#undef	true
#undef	false

#define	bool	_Bool
#define	true	1
#define	false	0

#define	__bool_true_false_are_defined	1

#endif /* defined(_STDC_C99) || defined(__C99FEATURES__) || __GNUC__ >= 3 */
#endif /* __cplusplus */

#endif /* !_SYS_STDBOOL_H */
