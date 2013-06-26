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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _SMBSRV_SMB_FSOPS_H
#define	_SMBSRV_SMB_FSOPS_H

/*
 * This header file contains all the functions for the interface between
 * the smb layer and the fs layer.
 */
#include <smbsrv/string.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/smb_ktypes.h>
#include <smbsrv/smb_vops.h>
#include <sys/callb.h>
#include <sys/flock.h>

#ifdef	__cplusplus
extern "C" {
#endif

int smb_fsop_amask_to_omode(uint32_t);

int smb_fsop_open(smb_node_t *, int, cred_t *);
void smb_fsop_close(smb_node_t *, int, cred_t *);

int smb_fsop_oplock_install(smb_node_t *, int);
void smb_fsop_oplock_uninstall(smb_node_t *);

int smb_fsop_create(smb_request_t *, cred_t *, smb_node_t *,
    char *, smb_attr_t *, smb_node_t **);

int smb_fsop_mkdir(smb_request_t *, cred_t *, smb_node_t *,
    char *, smb_attr_t *, smb_node_t **);

int smb_fsop_remove(smb_request_t *sr, cred_t *cr, smb_node_t *,
    char *, uint32_t);

int smb_fsop_rmdir(smb_request_t *, cred_t *, smb_node_t *, char *, uint32_t);

int smb_fsop_getattr(smb_request_t *, cred_t *, smb_node_t *, smb_attr_t *);

int smb_maybe_mangled_name(char *);

int smb_fsop_link(smb_request_t *, cred_t *, smb_node_t *, smb_node_t *,
    char *);

int smb_fsop_rename(smb_request_t *, cred_t *,
    smb_node_t *, char *, smb_node_t *,	char *);

int smb_fsop_setattr(smb_request_t *, cred_t *, smb_node_t *, smb_attr_t *);
int smb_fsop_set_data_length(smb_request_t *sr, cred_t *cr, smb_node_t *,
    offset_t);

int smb_fsop_read(smb_request_t *, cred_t *, smb_node_t *, uio_t *);

int smb_fsop_write(smb_request_t *, cred_t *, smb_node_t *, uio_t *,
    uint32_t *, int);

int smb_fsop_statfs(cred_t *, smb_node_t *, struct statvfs64 *);

uint32_t smb_fsop_remove_streams(smb_request_t *, cred_t *, smb_node_t *);

int smb_fsop_access(smb_request_t *, cred_t *, smb_node_t *, uint32_t);

void smb_fsop_eaccess(smb_request_t *, cred_t *, smb_node_t *, uint32_t *);

int smb_fsop_lookup_name(smb_request_t *, cred_t *, int,
    smb_node_t *, smb_node_t *, char *, smb_node_t **);

int smb_fsop_lookup(smb_request_t *, cred_t *, int,
    smb_node_t *, smb_node_t *, char *, smb_node_t **);

int smb_fsop_commit(smb_request_t *, cred_t *, smb_node_t *);

int smb_fsop_aclread(smb_request_t *, cred_t *, smb_node_t *, smb_fssd_t *);
int smb_fsop_aclwrite(smb_request_t *, cred_t *, smb_node_t *, smb_fssd_t *);
acl_type_t smb_fsop_acltype(smb_node_t *);
int smb_fsop_sdread(smb_request_t *, cred_t *, smb_node_t *, smb_fssd_t *);
int smb_fsop_sdwrite(smb_request_t *, cred_t *, smb_node_t *, smb_fssd_t *,
    int);

uint32_t smb_fsop_shrlock(cred_t *, smb_node_t *, uint32_t, uint32_t, uint32_t);
void smb_fsop_unshrlock(cred_t *, smb_node_t *, uint32_t);
int smb_fsop_frlock(smb_node_t *, smb_lock_t *, boolean_t, cred_t *);

/*
 * Lookup-related flags
 *
 * SMB_FOLLOW_LINKS	Follow symbolic links.
 * SMB_IGNORE_CASE	Perform case-insensitive lookup.
 * SMB_CATIA		Perform CATIA character substitution.
 * SMB_ABE		Perform Access based enumeration/lookup.
 * SMB_CASE_SENSITIVE	Don't set SMB_IGNORE_CASE based on tree.
 */

#define	SMB_FOLLOW_LINKS	0x00000001
#define	SMB_IGNORE_CASE		0x00000002
#define	SMB_CATIA		0x00000004
#define	SMB_ABE			0x00000008
#define	SMB_CASE_SENSITIVE	0x00000010

/*
 * Increased MAXPATHLEN for SMB.  Essentially, we want to allow a
 * share path up to MAXPATHLEN plus a relative path of MAXPATHLEN.
 */
#define	SMB_MAXPATHLEN	(2 * MAXPATHLEN)

#ifdef	__cplusplus
}
#endif

#endif /* _SMBSRV_SMB_FSOPS_H */
