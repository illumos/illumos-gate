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
/*	  All Rights Reserved  	*/


/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.8	*/

/*
 * contains the definitions
 * of the global constant __huge_val used
 * by the floating point environment
 */

/*
 * XXX - the preferred fix for this sits in delta 1.12.
 * But the following code is the only way to fix this given the lint and cc
 * we use now.  Newer compilers and lints should fix this so we can
 * put delta 1.12 back.  See 6208626.
 */

#include <sys/feature_tests.h>

#undef _STDC_C99	/* to force the definition of '_h_val' */
#undef __C99FEATURES__	/* to force the definition of '_h_val' */

#include <math.h>		/* for '_h_val' */

/* IEEE infinity */
const _h_val __huge_val =
#if defined(_LP64)			/* long == long long */
	{ 0x7ff0000000000000ull };
#elif defined(_LONG_LONG_HTOL)		/* like 32-bit sparc */
	{ 0x7ff00000ul, 0x00000000ul };
#elif defined(_LONG_LONG_LTOH)		/* like 32-bit x86 */
	{ 0x00000000ul, 0x7ff00000ul };
#else
#error "none of { _LP64 _LONG_LONG_HTOL _LONG_LONG_LTOH } is defined"
#endif
