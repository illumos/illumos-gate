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

#ifndef _SMBSRV_SMB_FSD_H
#define	_SMBSRV_SMB_FSD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/vfs.h>
#include <sys/refstr_impl.h>
#include <sys/stat.h>

#ifndef _KERNEL
#include <stdio.h>
#include <sys/mnttab.h>
#endif

#include <smbsrv/smb_i18n.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * VOL_NAME_MAX is derived from Montana's FSOL_NAME_MAX (32).
 * This is consistent with MAX_FS_NAME from PB fsadm (QFS).
 */

#define	VOL_NAME_MAX 32

typedef struct fsvol_attr {
	char name[VOL_NAME_MAX];
	char fs_typename[_ST_FSTYPSZ];
	unsigned flags;
	uint32_t fs_sequence;
} fsvol_attr_t;

/*
 * Note: fsid_t consists of two 32-bit values.
 * The first corresponds to the dev and the second to the file system type.
 * The fsid_t uniquely (and persistently) denotes a file system in a running
 * system.
 *
 * For the CIFS volume serial number, fsid.val[0] is used (a 32-bit value
 * is expected by TRANS2_QUERY_FS_INFORMATION).
 */

#define	fs_desc_t fsid_t

extern fs_desc_t null_fsd;

#ifdef _KERNEL

void	*fsd_lookup(char *, unsigned, fs_desc_t *);
int	fsd_cmp(fs_desc_t *, fs_desc_t *);
int	fsd_getattr(fs_desc_t *, fsvol_attr_t *);
int	fsd_chkcap(fs_desc_t *, unsigned);

void	*fsd_hold(fs_desc_t *fsd);
void	fsd_rele(void *vfsp);

#endif /*  _KERNEL    */

#ifdef __cplusplus
}
#endif

#endif /* _SMBSRV_SMB_FSD_H */
