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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2015 Joyent, Inc.
 */

#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_fsops.h>
#include <sys/sdt.h>
#include <sys/fcntl.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/vnode.h>
#include <sys/fem.h>

extern caller_context_t	smb_ct;

static boolean_t	smb_fem_initialized = B_FALSE;
static fem_t		*smb_fcn_ops = NULL;
static fem_t		*smb_oplock_ops = NULL;

/*
 * Declarations for FCN (file change notification) FEM monitors
 */

static int smb_fem_fcn_create(femarg_t *, char *, vattr_t *, vcexcl_t, int,
    vnode_t **, cred_t *, int, caller_context_t *, vsecattr_t *);
static int smb_fem_fcn_remove(femarg_t *, char *, cred_t *,
    caller_context_t *, int);
static int smb_fem_fcn_rename(femarg_t *, char *, vnode_t *, char *,
    cred_t *, caller_context_t *, int);
static int smb_fem_fcn_mkdir(femarg_t *, char *, vattr_t *, vnode_t **,
    cred_t *, caller_context_t *, int, vsecattr_t *);
static int smb_fem_fcn_rmdir(femarg_t *, char *, vnode_t *, cred_t *,
    caller_context_t *, int);
static int smb_fem_fcn_link(femarg_t *, vnode_t *, char *, cred_t *,
    caller_context_t *, int);
static int smb_fem_fcn_symlink(femarg_t *, char *, vattr_t *,
    char *, cred_t *, caller_context_t *, int);

static const fs_operation_def_t smb_fcn_tmpl[] = {
	VOPNAME_CREATE, { .femop_create = smb_fem_fcn_create },
	VOPNAME_REMOVE, {.femop_remove = smb_fem_fcn_remove},
	VOPNAME_RENAME, {.femop_rename = smb_fem_fcn_rename},
	VOPNAME_MKDIR, {.femop_mkdir = smb_fem_fcn_mkdir},
	VOPNAME_RMDIR, {.femop_rmdir = smb_fem_fcn_rmdir},
	VOPNAME_LINK, {.femop_link = smb_fem_fcn_link},
	VOPNAME_SYMLINK, {.femop_symlink = smb_fem_fcn_symlink},
	NULL, NULL
};

/*
 * Declarations for oplock FEM monitors
 */

static int smb_fem_oplock_open(femarg_t *, int, cred_t *,
    struct caller_context *);
static int smb_fem_oplock_read(femarg_t *, uio_t *, int, cred_t *,
    struct caller_context *);
static int smb_fem_oplock_write(femarg_t *, uio_t *, int, cred_t *,
    struct caller_context *);
static int smb_fem_oplock_setattr(femarg_t *, vattr_t *, int, cred_t *,
    caller_context_t *);
static int smb_fem_oplock_space(femarg_t *, int, flock64_t *, int,
    offset_t, cred_t *, caller_context_t *);
static int smb_fem_oplock_vnevent(femarg_t *, vnevent_t, vnode_t *, char *,
    caller_context_t *);

static const fs_operation_def_t smb_oplock_tmpl[] = {
	VOPNAME_OPEN,	{ .femop_open = smb_fem_oplock_open },
	VOPNAME_READ,	{ .femop_read = smb_fem_oplock_read },
	VOPNAME_WRITE,	{ .femop_write = smb_fem_oplock_write },
	VOPNAME_SETATTR, { .femop_setattr = smb_fem_oplock_setattr },
	VOPNAME_SPACE,	{ .femop_space = smb_fem_oplock_space },
	VOPNAME_VNEVENT, { .femop_vnevent = smb_fem_oplock_vnevent },
	NULL, NULL
};

static int smb_fem_oplock_wait(smb_node_t *, caller_context_t *);

/*
 * smb_fem_init
 *
 * This function is not multi-thread safe. The caller must make sure only one
 * thread makes the call.
 */
int
smb_fem_init(void)
{
	int	rc = 0;

	if (smb_fem_initialized)
		return (0);

	rc = fem_create("smb_fcn_ops", smb_fcn_tmpl, &smb_fcn_ops);
	if (rc)
		return (rc);

	rc = fem_create("smb_oplock_ops", smb_oplock_tmpl,
	    &smb_oplock_ops);

	if (rc) {
		fem_free(smb_fcn_ops);
		smb_fcn_ops = NULL;
		return (rc);
	}

	smb_fem_initialized = B_TRUE;

	return (0);
}

/*
 * smb_fem_fini
 *
 * This function is not multi-thread safe. The caller must make sure only one
 * thread makes the call.
 */
void
smb_fem_fini(void)
{
	if (!smb_fem_initialized)
		return;

	if (smb_fcn_ops != NULL) {
		fem_free(smb_fcn_ops);
		smb_fcn_ops = NULL;
	}
	if (smb_oplock_ops != NULL) {
		fem_free(smb_oplock_ops);
		smb_oplock_ops = NULL;
	}
	smb_fem_initialized = B_FALSE;
}

/*
 * Install our fem hooks for change notify.
 * Not using hold/rele function here because we
 * remove the fem hooks before node destroy.
 */
int
smb_fem_fcn_install(smb_node_t *node)
{
	int rc;

	if (smb_fcn_ops == NULL)
		return (ENOSYS);
	rc = fem_install(node->vp, smb_fcn_ops, (void *)node, OPARGUNIQ,
	    NULL, NULL);
	return (rc);
}

void
smb_fem_fcn_uninstall(smb_node_t *node)
{
	if (smb_fcn_ops == NULL)
		return;
	VERIFY0(fem_uninstall(node->vp, smb_fcn_ops, (void *)node));
}

int
smb_fem_oplock_install(smb_node_t *node)
{
	int rc;

	if (smb_oplock_ops == NULL)
		return (ENOSYS);
	rc = fem_install(node->vp, smb_oplock_ops, (void *)node, OPARGUNIQ,
	    (fem_func_t)smb_node_ref, (fem_func_t)smb_node_release);
	return (rc);
}

void
smb_fem_oplock_uninstall(smb_node_t *node)
{
	if (smb_oplock_ops == NULL)
		return;
	VERIFY0(fem_uninstall(node->vp, smb_oplock_ops, (void *)node));
}

/*
 * FEM FCN monitors
 *
 * The FCN monitors intercept the respective VOP_* call regardless
 * of whether the call originates from CIFS, NFS, or a local process.
 */

/*
 * smb_fem_fcn_create()
 *
 * This monitor will catch only changes to VREG files and not to extended
 * attribute files.  This is fine because, for CIFS files, stream creates
 * should not trigger any file change notification on the VDIR directory
 * being monitored.  Creates of any other kind of extended attribute in
 * the directory will also not trigger any file change notification on the
 * VDIR directory being monitored.
 */

static int
smb_fem_fcn_create(
    femarg_t *arg,
    char *name,
    vattr_t *vap,
    vcexcl_t excl,
    int mode,
    vnode_t **vpp,
    cred_t *cr,
    int flag,
    caller_context_t *ct,
    vsecattr_t *vsecp)
{
	smb_node_t *dnode;
	int error;

	dnode = (smb_node_t *)arg->fa_fnode->fn_available;

	ASSERT(dnode);

	error = vnext_create(arg, name, vap, excl, mode, vpp, cr, flag,
	    ct, vsecp);

	if (error == 0 && ct != &smb_ct)
		smb_node_notify_change(dnode, FILE_ACTION_ADDED, name);

	return (error);
}

/*
 * smb_fem_fcn_remove()
 *
 * This monitor will catch only changes to VREG files and to not extended
 * attribute files.  This is fine because, for CIFS files, stream deletes
 * should not trigger any file change notification on the VDIR directory
 * being monitored.  Deletes of any other kind of extended attribute in
 * the directory will also not trigger any file change notification on the
 * VDIR directory being monitored.
 */

static int
smb_fem_fcn_remove(
    femarg_t *arg,
    char *name,
    cred_t *cr,
    caller_context_t *ct,
    int flags)
{
	smb_node_t *dnode;
	int error;

	dnode = (smb_node_t *)arg->fa_fnode->fn_available;

	ASSERT(dnode);

	error = vnext_remove(arg, name, cr, ct, flags);

	if (error == 0 && ct != &smb_ct)
		smb_node_notify_change(dnode, FILE_ACTION_REMOVED, name);

	return (error);
}

static int
smb_fem_fcn_rename(
    femarg_t *arg,
    char *snm,
    vnode_t *tdvp,
    char *tnm,
    cred_t *cr,
    caller_context_t *ct,
    int flags)
{
	smb_node_t *dnode;
	int error;

	dnode = (smb_node_t *)arg->fa_fnode->fn_available;

	ASSERT(dnode);

	error = vnext_rename(arg, snm, tdvp, tnm, cr, ct, flags);

	if (error == 0 && ct != &smb_ct) {
		/*
		 * Note that renames in the same directory are normally
		 * delivered in {old,new} pairs, and clients expect them
		 * in that order, if both events are delivered.
		 */
		smb_node_notify_change(dnode,
		    FILE_ACTION_RENAMED_OLD_NAME, snm);
		smb_node_notify_change(dnode,
		    FILE_ACTION_RENAMED_NEW_NAME, tnm);
	}

	return (error);
}

static int
smb_fem_fcn_mkdir(
    femarg_t *arg,
    char *name,
    vattr_t *vap,
    vnode_t **vpp,
    cred_t *cr,
    caller_context_t *ct,
    int flags,
    vsecattr_t *vsecp)
{
	smb_node_t *dnode;
	int error;

	dnode = (smb_node_t *)arg->fa_fnode->fn_available;

	ASSERT(dnode);

	error = vnext_mkdir(arg, name, vap, vpp, cr, ct, flags, vsecp);

	if (error == 0 && ct != &smb_ct)
		smb_node_notify_change(dnode, FILE_ACTION_ADDED, name);

	return (error);
}

static int
smb_fem_fcn_rmdir(
    femarg_t *arg,
    char *name,
    vnode_t *cdir,
    cred_t *cr,
    caller_context_t *ct,
    int flags)
{
	smb_node_t *dnode;
	int error;

	dnode = (smb_node_t *)arg->fa_fnode->fn_available;

	ASSERT(dnode);

	error = vnext_rmdir(arg, name, cdir, cr, ct, flags);

	if (error == 0 && ct != &smb_ct)
		smb_node_notify_change(dnode, FILE_ACTION_REMOVED, name);

	return (error);
}

static int
smb_fem_fcn_link(
    femarg_t *arg,
    vnode_t *svp,
    char *tnm,
    cred_t *cr,
    caller_context_t *ct,
    int flags)
{
	smb_node_t *dnode;
	int error;

	dnode = (smb_node_t *)arg->fa_fnode->fn_available;

	ASSERT(dnode);

	error = vnext_link(arg, svp, tnm, cr, ct, flags);

	if (error == 0 && ct != &smb_ct)
		smb_node_notify_change(dnode, FILE_ACTION_ADDED, tnm);

	return (error);
}

static int
smb_fem_fcn_symlink(
    femarg_t *arg,
    char *linkname,
    vattr_t *vap,
    char *target,
    cred_t *cr,
    caller_context_t *ct,
    int flags)
{
	smb_node_t *dnode;
	int error;

	dnode = (smb_node_t *)arg->fa_fnode->fn_available;

	ASSERT(dnode);

	error = vnext_symlink(arg, linkname, vap, target, cr, ct, flags);

	if (error == 0 && ct != &smb_ct)
		smb_node_notify_change(dnode, FILE_ACTION_ADDED, linkname);

	return (error);
}

/*
 * FEM oplock monitors
 *
 * The monitors below are not intended to intercept CIFS calls.
 * CIFS higher-level routines will break oplocks as needed prior
 * to getting to the VFS layer.
 */
static int
smb_fem_oplock_open(
    femarg_t		*arg,
    int			mode,
    cred_t		*cr,
    caller_context_t	*ct)
{
	smb_node_t	*node;
	uint32_t	status;
	int		rc = 0;

	if (ct != &smb_ct) {
		uint32_t req_acc = FILE_READ_DATA;
		uint32_t cr_disp = FILE_OPEN_IF;

		node = (smb_node_t *)(arg->fa_fnode->fn_available);
		SMB_NODE_VALID(node);

		/*
		 * Get req_acc, cr_disp just accurate enough so
		 * the oplock break call does the right thing.
		 */
		if (mode & FWRITE) {
			req_acc = FILE_READ_DATA | FILE_WRITE_DATA;
			cr_disp = (mode & FTRUNC) ?
			    FILE_OVERWRITE_IF : FILE_OPEN_IF;
		} else {
			req_acc = FILE_READ_DATA;
			cr_disp = FILE_OPEN_IF;
		}

		status = smb_oplock_break_OPEN(node, NULL,
		    req_acc, cr_disp);
		if (status == NT_STATUS_OPLOCK_BREAK_IN_PROGRESS)
			rc = smb_fem_oplock_wait(node, ct);
		else if (status != 0)
			rc = EIO;
	}
	if (rc == 0)
		rc = vnext_open(arg, mode, cr, ct);

	return (rc);
}

/*
 * Should normally be hit only via NFSv2/v3.  All other accesses
 * (CIFS/NFS/local) should call VOP_OPEN first.
 */

static int
smb_fem_oplock_read(
    femarg_t		*arg,
    uio_t		*uiop,
    int			ioflag,
    cred_t		*cr,
    caller_context_t	*ct)
{
	smb_node_t	*node;
	uint32_t	status;
	int	rc = 0;

	if (ct != &smb_ct) {
		node = (smb_node_t *)(arg->fa_fnode->fn_available);
		SMB_NODE_VALID(node);

		status = smb_oplock_break_READ(node, NULL);
		if (status == NT_STATUS_OPLOCK_BREAK_IN_PROGRESS)
			rc = smb_fem_oplock_wait(node, ct);
		else if (status != 0)
			rc = EIO;
	}
	if (rc == 0)
		rc = vnext_read(arg, uiop, ioflag, cr, ct);

	return (rc);
}

/*
 * Should normally be hit only via NFSv2/v3.  All other accesses
 * (CIFS/NFS/local) should call VOP_OPEN first.
 */

static int
smb_fem_oplock_write(
    femarg_t		*arg,
    uio_t		*uiop,
    int			ioflag,
    cred_t		*cr,
    caller_context_t	*ct)
{
	smb_node_t	*node;
	uint32_t	status;
	int	rc = 0;

	if (ct != &smb_ct) {
		node = (smb_node_t *)(arg->fa_fnode->fn_available);
		SMB_NODE_VALID(node);

		status = smb_oplock_break_WRITE(node, NULL);
		if (status == NT_STATUS_OPLOCK_BREAK_IN_PROGRESS)
			rc = smb_fem_oplock_wait(node, ct);
		else if (status != 0)
			rc = EIO;
	}
	if (rc == 0)
		rc = vnext_write(arg, uiop, ioflag, cr, ct);

	return (rc);
}

static int
smb_fem_oplock_setattr(
    femarg_t		*arg,
    vattr_t		*vap,
    int			flags,
    cred_t		*cr,
    caller_context_t	*ct)
{
	smb_node_t	*node;
	uint32_t	status;
	int	rc = 0;

	if (ct != &smb_ct && (vap->va_mask & AT_SIZE) != 0) {
		node = (smb_node_t *)(arg->fa_fnode->fn_available);
		SMB_NODE_VALID(node);

		status = smb_oplock_break_SETINFO(node, NULL,
		    FileEndOfFileInformation);
		if (status == NT_STATUS_OPLOCK_BREAK_IN_PROGRESS)
			rc = smb_fem_oplock_wait(node, ct);
		else if (status != 0)
			rc = EIO;
	}
	if (rc == 0)
		rc = vnext_setattr(arg, vap, flags, cr, ct);
	return (rc);
}

static int
smb_fem_oplock_space(
    femarg_t		*arg,
    int			cmd,
    flock64_t		*bfp,
    int			flag,
    offset_t		offset,
    cred_t		*cr,
    caller_context_t	*ct)
{
	smb_node_t	*node;
	uint32_t	status;
	int	rc = 0;

	if (ct != &smb_ct) {
		node = (smb_node_t *)(arg->fa_fnode->fn_available);
		SMB_NODE_VALID(node);

		status = smb_oplock_break_SETINFO(node, NULL,
		    FileAllocationInformation);
		if (status == NT_STATUS_OPLOCK_BREAK_IN_PROGRESS)
			rc = smb_fem_oplock_wait(node, ct);
		else if (status != 0)
			rc = EIO;
	}
	if (rc == 0)
		rc = vnext_space(arg, cmd, bfp, flag, offset, cr, ct);
	return (rc);
}

/*
 * smb_fem_oplock_vnevent()
 *
 * To intercept NFS and local renames and removes in order to break any
 * existing oplock prior to the operation.
 *
 * Note: Currently, this monitor is traversed only when an FS is mounted
 * non-nbmand.  (When the FS is mounted nbmand, share reservation checking
 * will detect a share violation and return an error prior to the VOP layer
 * being reached.)  Thus, for nbmand NFS and local renames and removes,
 * an existing oplock is never broken prior to share checking (contrary to
 * how it is with intra-CIFS remove and rename requests).
 */

static int
smb_fem_oplock_vnevent(
    femarg_t		*arg,
    vnevent_t		vnevent,
    vnode_t		*dvp,
    char		*name,
    caller_context_t	*ct)
{
	smb_node_t	*node;
	uint32_t	status;
	int		rc = 0;

	if (ct != &smb_ct) {
		node = (smb_node_t *)(arg->fa_fnode->fn_available);
		SMB_NODE_VALID(node);

		switch (vnevent) {
		case VE_REMOVE:
		case VE_PRE_RENAME_DEST:
		case VE_RENAME_DEST:
			status = smb_oplock_break_HANDLE(node, NULL);
			break;
		case VE_PRE_RENAME_SRC:
		case VE_RENAME_SRC:
			status = smb_oplock_break_SETINFO(node, NULL,
			    FileRenameInformation);
			break;
		default:
			status = 0;
			break;
		}
		if (status == NT_STATUS_OPLOCK_BREAK_IN_PROGRESS)
			rc = smb_fem_oplock_wait(node, ct);
		else if (status != 0)
			rc = EIO;
	}
	if (rc == 0)
		rc = vnext_vnevent(arg, vnevent, dvp, name, ct);

	return (rc);
}

int smb_fem_oplock_timeout = 5000; /* mSec. */

static int
smb_fem_oplock_wait(smb_node_t *node, caller_context_t *ct)
{
	int		rc = 0;

	ASSERT(ct != &smb_ct);

	if (ct && (ct->cc_flags & CC_DONTBLOCK)) {
		ct->cc_flags |= CC_WOULDBLOCK;
		rc = EAGAIN;
	} else {
		(void) smb_oplock_wait_break(node,
		    smb_fem_oplock_timeout);
		rc = 0;
	}

	return (rc);
}
