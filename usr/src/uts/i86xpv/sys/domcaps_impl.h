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

#ifndef	_SYS_DOMCAPS_IMPL_H
#define	_SYS_DOMCAPS_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * /dev names:
 *	/dev/xen/			- containing directory
 *		capabilities		- domain properties
 */

#define	DOMCAPS_DRIVER_NAME	"domcaps"

#define	DOMCAPS_MINOR		0

#define	DOMCAPS_DEV_NAME	"capabilities"
#define	DOMCAPS_PATHNAME	"xen/" DOMCAPS_DEV_NAME

#ifdef __cplusplus
}
#endif

#endif /* _SYS_DOMCAPS_IMPL_H */
