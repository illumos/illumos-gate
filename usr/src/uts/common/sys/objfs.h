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

#ifndef	_OBJFS_H
#define	_OBJFS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Root directory of the object filesystem
 */
#define	OBJFS_ROOT	"/system/object"

/*
 * Given an inode number, return the module ID for the given node.  When given
 * the root inode, the results are undefined.
 */
#define	OBJFS_MODID(ino)	\
	((ino) & 0xffffffff)

/*
 * Private data structure found in '.info' section
 */
typedef struct objfs_info {
	int		objfs_info_primary;
} objfs_info_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _OBJFS_H */
