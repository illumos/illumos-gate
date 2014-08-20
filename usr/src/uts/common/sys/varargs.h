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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_VARARGS_H
#define	_SYS_VARARGS_H

/*
 * This header defines the Solaris system definitions for variable
 * argument lists.  For the most part, it follows the definitions of
 * ISO C 1999.  It does not follow the namespace rules for ISO C++
 * 1998.
 *
 * The varargs definitions within this header are defined in terms of
 * implementation definitions.  These implementation definitions reside
 * in <sys/va_impl.h>.  This organization enables protected use of
 * the implementation by other standard headers without introducing
 * names into the users' namespace.
 */

#include <sys/va_impl.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	_VA_LIST
#define	_VA_LIST
typedef __va_list va_list;
#endif

/*
 * This file provides stdarg semantics despite the name of the file.
 */

#define	va_start(list, name)	__va_start(list, name)
#define	va_arg(list, type)	__va_arg(list, type)
#define	va_copy(to, from)	__va_copy(to, from)
#define	va_end(list)		__va_end(list)


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_VARARGS_H */
