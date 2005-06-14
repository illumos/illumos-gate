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

#ifndef _CMDGEN_H
#define	_CMDGEN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <cimapi.h>

/*
 * Public data type declaration
 */

/*
 * The supported command types.
 */
#define	CMDGEN_NFS_MOUNT	0
#define	CMDGEN_MOUNTALL		1
#define	CMDGEN_NFS_UMOUNT	2
#define	CMDGEN_UMOUNTALL	3
#define	CMDGEN_NFS_SHARE	4
#define	CMDGEN_NFS_UNSHARE	5
#define	CMDGEN_SHAREALL		6
#define	CMDGEN_UNSHAREALL	7

char *cmdgen_generate_command(int cmd_type, CCIMInstance *inst,
	CCIMObjectPath *objPath, CCIMPropertyList *paramList, int *errp);

#ifdef __cplusplus
}
#endif

#endif /* _CMDGEN_H */
