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

#ifndef _SMBSRV_SMB_FSOPS_H
#define	_SMBSRV_SMB_FSOPS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This header file contains all the functions for the interface between
 * the smb layer and the fs layer.
 */
#include <smbsrv/smb_i18n.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/smb_vops.h>
#include <smbsrv/smbvar.h>
#include <sys/callb.h>
#include <sys/flock.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern caller_context_t smb_ct;

int smb_fsop_open(smb_ofile_t *of);

int smb_fsop_close(smb_ofile_t *of);

int smb_fsop_create(struct smb_request *sr, cred_t *cr, smb_node_t *snode,
    char *name, smb_attr_t *attr, smb_node_t **ret_snode, smb_attr_t *ret_attr);

int smb_fsop_mkdir(struct smb_request *sr, cred_t *cr, smb_node_t *snode,
    char *name, smb_attr_t *attr, smb_node_t **ret_snode, smb_attr_t *ret_attr);

int smb_fsop_remove(struct smb_request *sr, cred_t *cr, smb_node_t *dir_snode,
    char *name, int od);

int smb_fsop_rmdir(struct smb_request *sr, cred_t *cr, smb_node_t *dir_snode,
    char *name, int od);

int smb_fsop_getattr(struct smb_request *sr, cred_t *cr, smb_node_t *snode,
    smb_attr_t *attr);

int smb_fsop_readdir(struct smb_request *sr, cred_t *cr, smb_node_t *snode,
    uint32_t *cookie, char *name, int *namelen, ino64_t *fileid,
    struct fs_stream_info *stream_info, smb_node_t **ret_snode,
    smb_attr_t *ret_attr);

int smb_fsop_getdents(struct smb_request *sr, cred_t *cr,
    struct smb_node *dir_snode, uint32_t *cookie, uint64_t *verifierp,
    int32_t *maxcnt, char *args, char *pattern);

int smb_maybe_mangled_name(char *name);

int smb_fsop_rename(struct smb_request *sr, cred_t *cr,
    smb_node_t *from_snode, char *from_name, smb_node_t *to_snode,
    char *to_name);

int smb_fsop_setattr(struct smb_request *sr, cred_t *cr, smb_node_t *snode,
    smb_attr_t *set_attr, smb_attr_t *ret_attr);

int smb_fsop_read(struct smb_request *sr, cred_t *cr,
    smb_node_t *snode, uio_t *uio, smb_attr_t *ret_attr);

int smb_fsop_write(struct smb_request *sr, cred_t *cr, smb_node_t *snode,
    uio_t *uio, uint32_t *lcount, smb_attr_t *ret_attr,
    uint32_t *stability);

int smb_fsop_statfs(cred_t *cr, struct smb_node *snode,
    struct statvfs64 *statp);

int smb_fsop_remove_streams(struct smb_request *sr, cred_t *cr,
    smb_node_t *fnode);

int smb_fsop_access(smb_request_t *sr, cred_t *cr, smb_node_t *snode,
    uint32_t faccess);

void smb_fsop_eaccess(smb_request_t *sr, cred_t *cr, smb_node_t *snode,
    uint32_t *faccess);

int smb_fsop_lookup_name(struct smb_request *sr, cred_t *cr, int flags,
    smb_node_t *root_node, smb_node_t *dir_snode, char *name,
    smb_node_t **ret_snode, smb_attr_t *ret_attr);

int smb_fsop_lookup(struct smb_request *sr, cred_t *cr, int flags,
    smb_node_t *root_node, smb_node_t *dir_snode, char *name,
    smb_node_t **ret_snode, smb_attr_t *ret_attr, char *ret_shortname,
    char *ret_name83);

int smb_fsop_commit(smb_request_t *sr, cred_t *cr, struct smb_node *snode);

int smb_fsop_stream_readdir(struct smb_request *sr, cred_t *cr,
    smb_node_t *fnode, uint32_t *cookiep, struct fs_stream_info *stream_info,
    smb_node_t **ret_snode, smb_attr_t *ret_attr);

int smb_fsop_aclread(smb_request_t *, cred_t *, smb_node_t *, smb_fssd_t *);
int smb_fsop_aclwrite(smb_request_t *, cred_t *, smb_node_t *, smb_fssd_t *);
acl_type_t smb_fsop_acltype(smb_node_t *);
int smb_fsop_sdread(smb_request_t *, cred_t *, smb_node_t *, smb_fssd_t *);
int smb_fsop_sdwrite(smb_request_t *, cred_t *, smb_node_t *, smb_fssd_t *,
    int);

uint32_t smb_fsop_shrlock(cred_t *cr, smb_node_t *node, uint32_t uniq_fid,
    uint32_t desired_access, uint32_t share_access);

void smb_fsop_unshrlock(cred_t *cr, smb_node_t *node, uint32_t uniq_fid);

int smb_fsop_frlock(smb_request_t *sr, smb_node_t *node, smb_lock_t *lock,
    boolean_t unlock);

/*
 * Lookup-related flags
 *
 * SMB_FOLLOW_LINKS	Follow symbolic links.
 * SMB_IGNORE_CASE	Perform case-insensitive lookup.
 *
 * Misc flags
 *
 * SMB_STREAM_RDDIR	use eflags=0 for streams readdirs this
 *			is currently a workaround because the
 *			vfs isn't filling in this flag
 */

#define	SMB_FOLLOW_LINKS	0x00000001
#define	SMB_IGNORE_CASE		0x00000002
#define	SMB_STREAM_RDDIR	0x00000004

#ifdef	__cplusplus
}
#endif

#endif /* _SMBSRV_SMB_FSOPS_H */
