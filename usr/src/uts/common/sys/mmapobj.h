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
 */

#ifndef _SYS_MMAPOBJ_H
#define	_SYS_MMAPOBJ_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Number of mmapobj_result_t structures created on stack for quick allocation.
 * More will be manually kmem_alloc'ed if needed.
 * Should be enough for most ELF objects.
 */
#define	LIBVA_CACHED_SEGS 3

#ifdef _KERNEL
extern void mmapobj_unmap(mmapobj_result_t *, int, int, ushort_t);
#endif

extern int mmapobj(vnode_t *, uint_t, mmapobj_result_t *, uint_t *, size_t,
    cred_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MMAPOBJ_H */
