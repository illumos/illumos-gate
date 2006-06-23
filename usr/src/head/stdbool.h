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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _STDBOOL_H
#define	_STDBOOL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Included for alignment with the ISO/IEC 9899:1999 standard. The
 * contents of this header are only visible when using a c99
 * compiler.
 *
 * Note that the ability to undefine and redefine the macros bool,
 * true, and false  is an obsolescent feature which may be withdrawn
 * in a future version of the standards specifications.
 */

#include <sys/feature_tests.h>

#if defined(_STDC_C99)

#undef	bool
#undef	true
#undef	false

#define	bool	_Bool
#define	true	1
#define	false	0

#define	__bool_true_false_are_defined	1

#endif /* _STDC_C99 */

#endif /* _STDBOOL_H */
