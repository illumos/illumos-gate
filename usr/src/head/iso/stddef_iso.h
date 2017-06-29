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
 * Copyright 1999-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2014 PALO, Richard.
 * Copyright 2016 Joyent, Inc.
 */

/*
 * An application should not include this header directly.  Instead it
 * should be included only through the inclusion of other Sun headers.
 *
 * The contents of this header is limited to identifiers specified in the
 * C Standard.  Any new identifiers specified in future amendments to the
 * C Standard must be placed in this header.  If these new identifiers
 * are required to also be in the C++ Standard "std" namespace, then for
 * anything other than macro definitions, corresponding "using" directives
 * must also be added to <stddef.h.h>.
 */

#ifndef _ISO_STDDEF_ISO_H
#define	_ISO_STDDEF_ISO_H

#include <sys/isa_defs.h>
#include <sys/feature_tests.h>
#include <sys/null.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if __cplusplus >= 199711L
namespace std {
#endif

#if !defined(_PTRDIFF_T) || __cplusplus >= 199711L
#define	_PTRDIFF_T
#if defined(_LP64) || defined(_I32LPx)
typedef	long	ptrdiff_t;		/* pointer difference */
#else
typedef int	ptrdiff_t;		/* (historical version) */
#endif
#endif	/* !_PTRDIFF_T */

#if !defined(_SIZE_T) || __cplusplus >= 199711L
#define	_SIZE_T
#if defined(_LP64) || defined(_I32LPx)
typedef unsigned long	size_t;		/* size of something in bytes */
#else
typedef unsigned int	size_t;		/* (historical version) */
#endif
#endif	/* !_SIZE_T */

#if __cplusplus >= 199711L
}
#endif /* end of namespace std */

#if !defined(_MAX_ALIGN_T)
#if !defined(_STRICT_SYMBOLS) || defined(_STDC_C11)
#define	_MAX_ALIGN_T
typedef	_MAX_ALIGNMENT_TYPE max_align_t;
#endif /* !_STRICT_SYMBOLS || _STDC_C11 */
#endif	/* _MAX_ALIGN_T */

#ifdef	__cplusplus
}
#endif

#endif	/* _ISO_STDDEF_ISO_H */
