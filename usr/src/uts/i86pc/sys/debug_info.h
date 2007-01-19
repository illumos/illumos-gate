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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_DEBUG_INFO_H
#define	_SYS_DEBUG_INFO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/machparam.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	DEBUG_INFO_MAGIC 0xdeb116ed
#define	DEBUG_INFO_VERSION 0x1

typedef struct debug_info {
	uint32_t di_magic;
	uint32_t di_version;
} debug_info_t;

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_DEBUG_INFO_H */
