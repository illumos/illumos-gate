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

#ifndef	_ZFS_DELEG_H
#define	_ZFS_DELEG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/fs/zfs.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	ZFS_DELEG_SET_NAME_CHR		'@'		/* set name lead char */
#define	ZFS_DELEG_FIELD_SEP_CHR		'$'		/* field separator */

/*
 * Max name length for a delegation attribute
 */
#define	ZFS_MAX_DELEG_NAME	128

#define	ZFS_DELEG_LOCAL		'l'
#define	ZFS_DELEG_DESCENDENT	'd'
#define	ZFS_DELEG_NA		'-'

extern char *zfs_deleg_perm_tab[];

int zfs_deleg_verify_nvlist(nvlist_t *nvlist);
void zfs_deleg_whokey(char *attr, zfs_deleg_who_type_t type,
    char checkflag, void *data);
const char *zfs_deleg_canonicalize_perm(const char *perm);

#ifdef	__cplusplus
}
#endif

#endif	/* _ZFS_DELEG_H */
