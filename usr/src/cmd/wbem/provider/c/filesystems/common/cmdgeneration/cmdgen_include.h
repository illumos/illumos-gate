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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _CMDGEN_INCLUDE_H
#define	_CMDGEN_INCLUDE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <cimapi.h>
#include <errno.h>

/*
 * Public data type declarations
 */

/*
 * Supported fstypes
 */
#define	CMDGEN_NFS	0

/*
 * Method declarations
 */
char	*cmdgen_mount(int fstype, CCIMInstance *inst, CCIMObjectPath *objPath,
		int *errp);
char	*cmdgen_mountall(CCIMPropertyList *paramList, int *errp);
char	*cmdgen_mount_nfs(CCIMInstance *inst, CCIMObjectPath *objPath,
		int *errp);
char	*cmdgen_share(int fstype, CCIMInstance *inst, CCIMObjectPath *objPath,
		int *errp);
char	*cmdgen_shareall(CCIMPropertyList *paramList, int *errp);
char	*cmdgen_share_nfs(CCIMInstance *inst, CCIMObjectPath *objPath,
		int *errp);
char	*cmdgen_umount(CCIMInstance *inst, CCIMObjectPath *objPath, int *errp);
char	*cmdgen_umountall(CCIMPropertyList *paramList, int *errp);
char	*cmdgen_unshare(int fstype, CCIMInstance *inst, CCIMObjectPath *objPath,
		int *errp);
char	*cmdgen_unshareall(CCIMPropertyList *paramList, int *errp);
char	*cmdgen_unshare_nfs(CCIMInstance *inst, CCIMObjectPath *objPath,
		int *errp);

#ifdef __cplusplus
}
#endif

#endif /* _CMDGEN_INCLUDE_H */
