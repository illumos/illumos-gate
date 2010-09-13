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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Global include file for all sgs machine dependent macros, constants
 * and declarations applicable to the current system. This header is
 * to be used for code that supports the native system only. Code that
 * needs to support non-native targets should avoid it, and use the
 * target-specific versions found in the subdirectories below the include
 * directory holding this file.
 */

#ifndef	_MACHDEP_H
#define	_MACHDEP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if defined(__sparc)

#include <sparc/machdep_sparc.h>

#elif defined(__i386) || defined(__amd64)

#include <i386/machdep_x86.h>

#else

#error "machdep.h does not understand current machine"

#endif

#endif /* _MACHDEP_H */
