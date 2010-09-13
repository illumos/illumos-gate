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
 * Copyright (c) 1997-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _PXFS_KI_H
#define	_PXFS_KI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/aio_req.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Kernel interface to pxfs routines: definition of stubs.
 */

/*
 * kaio interface to pxfs
 */

extern int clpxfs_aio_write(vnode_t *vp, struct aio_req *aio, cred_t *cred_p);
extern int clpxfs_aio_read(vnode_t *vp, struct aio_req *aio, cred_t *cred_p);

#ifdef __cplusplus
}
#endif

#endif /* _PXFS_KI_H */
