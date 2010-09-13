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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_FS_UFS_SNAP_H
#define	_SYS_FS_UFS_SNAP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/fssnap_if.h>
#include <sys/vnode.h>
#include <sys/cred.h>

/* debug levels */
#define	UFSSNAPDB_CREATE	0x01
#define	UFSSNAPDB_DELETE	0x02

/* Constants */
#define	UFS_MAX_SNAPBACKFILESIZE	(1LL << 39)  /* 512 GB */

extern int ufs_snap_create(struct vnode *, struct fiosnapcreate_multi *,
    cred_t *);
extern int ufs_snap_delete(struct vnode *, struct fiosnapdelete *, cred_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_FS_UFS_SNAP_H */
