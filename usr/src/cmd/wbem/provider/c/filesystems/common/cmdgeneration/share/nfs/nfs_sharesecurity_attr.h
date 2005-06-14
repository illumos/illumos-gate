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

#ifndef	_NFS_SHARESECURITY_ATTR_H
#define	_NFS_SHARESECURITY_ATTR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * NFS Share Security attributes
 */

#define	MAXLIFE "MaxLife"
#define	READONLY "ReadOnly"
#define	READWRITELIST "ReadWriteList"
#define	READONLYLIST "ReadOnlyList"
#define	ROOTSERVERS "RootServers"
#define	PATH "SettingID" /* This is the Setting ID */
#define	SEC_MODE "Mode"

#ifdef __cplusplus
}
#endif

#endif /* _NFS_SHARESECURITY_ATTR_H */
