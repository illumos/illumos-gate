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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <smbsrv/smb_incl.h>
#include <sys/sdt.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/vnode.h>
#include <sys/fem.h>

fem_t *smb_fcn_ops = NULL;

int smb_fem_fcn_create(femarg_t *, char *, vattr_t *, vcexcl_t, int,
    vnode_t **, cred_t *, int, caller_context_t *, vsecattr_t *);
int smb_fem_fcn_remove(femarg_t *, char *, cred_t *,
    caller_context_t *, int);
int smb_fem_fcn_rename(femarg_t *, char *, vnode_t *, char *,
    cred_t *, caller_context_t *, int);
int smb_fem_fcn_mkdir(femarg_t *, char *, vattr_t *, vnode_t **,
    cred_t *, caller_context_t *, int, vsecattr_t *);
int smb_fem_fcn_rmdir(femarg_t *, char *, vnode_t *, cred_t *,
    caller_context_t *, int);
int smb_fem_fcn_link(femarg_t *, vnode_t *, char *, cred_t *,
    caller_context_t *, int);
int smb_fem_fcn_symlink(femarg_t *, char *, vattr_t *,
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

int
smb_fem_init()
{
	return (fem_create("smb_fcn_ops", smb_fcn_tmpl, &smb_fcn_ops));
}

void
smb_fem_shutdown()
{
	if (smb_fcn_ops)
		fem_free(smb_fcn_ops);
}

void
smb_fem_fcn_install(smb_node_t *node)
{
	(void) fem_install(node->vp, smb_fcn_ops, (void *)node, OPARGUNIQ,
	    (fem_func_t)smb_node_ref, (fem_func_t)smb_node_release);
}

void
smb_fem_fcn_uninstall(smb_node_t *node)
{
	(void) fem_uninstall(node->vp, smb_fcn_ops, (void *)node);
}

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

int
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

	if (error == 0)
		smb_process_node_notify_change_queue(dnode);

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

int
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

	if (error == 0)
		smb_process_node_notify_change_queue(dnode);

	return (error);
}

int
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

	if (error == 0)
		smb_process_node_notify_change_queue(dnode);

	return (error);
}

int
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

	if (error == 0)
		smb_process_node_notify_change_queue(dnode);

	return (error);
}

int
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

	if (error == 0)
		smb_process_node_notify_change_queue(dnode);

	return (error);
}

int
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

	if (error == 0)
		smb_process_node_notify_change_queue(dnode);

	return (error);
}

int
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

	if (error == 0)
		smb_process_node_notify_change_queue(dnode);

	return (error);
}
