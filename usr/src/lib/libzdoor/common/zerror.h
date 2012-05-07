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
 * Copyright 2011 Joyent, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _ZERROR_H
#define	_ZERROR_H

#include <stdio.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

extern void zdoor_debug(const char *fmt, ...);
extern void zdoor_info(const char *fmt, ...);
extern void zdoor_warn(const char *fmt, ...);
extern void zdoor_error(const char *fmt, ...);

#define	OUT_OF_MEMORY()	\
	zdoor_error("Out of Memory at %s:%d", __FILE__, __LINE__)

#ifdef __cplusplus
}
#endif

#endif /* _ZERROR_H */
