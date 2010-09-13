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

#ifndef _EXCEPTION_LIST_H
#define	_EXCEPTION_LIST_H

#if defined(sparc)
#define	EXCEPTION_FILE "/opt/onbld/etc/exception_list"
#elif defined(i386)
#define	EXCEPTION_FILE "/opt/onbld/etc/exception_list_i386"
#elif defined(__ppc)
#define	EXCEPTION_FILE "/opt/onbld/etc/exception_list_ppc"
#else
#error "Unknown instruction set"
#endif

extern int read_in_exceptions(const char *, int);
extern elem_list exception_list;

#endif /* _EXCEPTION_LIST_H */
