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

#ifndef _LOCAL_TYPES_H
#define	_LOCAL_TYPES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Block comment which describes the contents of this file.
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MIN
#define	MIN(x, y)	((x) < (y) ? (x) : (y))
#endif
#ifndef MAX
#define	MAX(x, y)	((x) > (y) ? (x) : (y))
#endif

/*
 * Solaris typedefs boolean_t to be an enum with B_TRUE and B_FALSE.
 * MacOS X typedefs boolean_t to be an int with #defines for TRUE & FALSE
 * I like the use of enum's for return codes so that compilers can catch
 * sloppy coding practices so I've defined a Boolean_t which is unique here.
 */
typedef enum {
	False = 0,
	True = 1
} Boolean_t;

#ifndef DTYPE_OSD
#define	DTYPE_OSD	0x11
#endif

#ifdef __cplusplus
}
#endif

#endif /* _LOCAL_TYPES_H */
