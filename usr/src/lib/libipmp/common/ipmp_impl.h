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
/*
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _IPMP_IMPL_H
#define	_IPMP_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <ipmp.h>
#include <ipmp_query_impl.h>

/*
 * Implementation-private definitions for the IPMP library.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Private IPMP state structure.
 */
typedef struct ipmp_state {
	uint32_t	st_magic;	/* magic tag */
	int		st_fd; 		/* socket to in.mpathd */
	ipmp_snap_t	*st_snap;	/* current snapshot, if any */
} ipmp_state_t;

#define	IPMP_MAGIC	0x49504D50	/* "IPMP" */

#ifdef __cplusplus
}
#endif

#endif /* _IPMP_IMPL_H */
