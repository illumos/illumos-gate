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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _STDARG_H
#define	_STDARG_H

/*
 * This header defines the ISO C 1989, ISO C++ 1998, and ISO C 1999
 * variable argument definitions.  For legacy support, it also defines
 * the pre-standard variable argument definitions.
 *
 * The varargs definitions within this header are defined in terms of
 * implementation definitions.  These implementation definitions reside
 * in <sys/va_list.h>.  This organization enables protected use of
 * the implementation by other standard headers without introducing
 * names into the users' namespace.
 */

#include <iso/stdarg_iso.h>
#include <iso/stdarg_c99.h>

/*
 * Allow global visibility for symbols defined in
 * C++ "std" namespace in <iso/stdarg_iso.h>.
 */
#if __cplusplus >= 199711L
using std::va_list;
#endif

#endif	/* _STDARG_H */
