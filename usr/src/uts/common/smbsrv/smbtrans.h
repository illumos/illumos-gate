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

#ifndef _SMBSRV_SMBTRANS_H
#define	_SMBSRV_SMBTRANS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Note that name can be variable length; therefore, it has to
 * stay last.
 */
typedef struct smb_dent_info {
	uint32_t cookie;
	smb_attr_t attr;
	struct smb_node *snode;
	char name83[14];
	char shortname[14];
	char name[1];
} smb_dent_info_t;

#define	SMB_MAX_DENT_INFO_SIZE (sizeof (smb_dent_info_t) + MAXNAMELEN - 1)
#define	SMB_MAX_DENTS_BUF_SIZE (64 * 1024) /* 64k */
#define	SMB_MAX_DENTS_IOVEC (SMB_MAX_DENTS_BUF_SIZE / SMB_MAX_DENT_INFO_SIZE)

typedef struct smb_dent_info_hdr {
	struct smb_request *sr;
	char *pattern;
	unsigned short sattr;
	struct uio uio;
	struct iovec iov[SMB_MAX_DENTS_IOVEC];
} smb_dent_info_hdr_t;

int smb_get_dents(struct smb_request *sr, uint32_t *cookie,
    struct smb_node *dir_snode, unsigned int wildcards,
    smb_dent_info_hdr_t *ihdr, int *more);

#ifdef __cplusplus
}
#endif

#endif /* _SMBSRV_SMBTRANS_H */
