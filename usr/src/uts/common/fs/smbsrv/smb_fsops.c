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
 * Copyright 2012-2022 Tintri by DDN, Inc. All rights reserved.
 * Copyright 2022 RackTop Systems, Inc.
 */

#include <sys/sid.h>
#include <sys/nbmlock.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/smb_kproto.h>
#include <acl/acl_common.h>
#include <sys/fcntl.h>
#include <sys/filio.h>
#include <sys/flock.h>
#include <fs/fs_subr.h>

extern caller_context_t smb_ct;

static int smb_fsop_create_file_with_stream(smb_request_t *, cred_t *,
    smb_node_t *, char *, char *, int, smb_attr_t *, smb_node_t **);

static int smb_fsop_create_file(smb_request_t *, cred_t *, smb_node_t *,
    char *, int, smb_attr_t *, smb_node_t **);

#ifdef	_KERNEL
static int smb_fsop_create_with_sd(smb_request_t *, cred_t *, smb_node_t *,
    char *, smb_attr_t *, smb_node_t **, smb_fssd_t *);
static int smb_fsop_sdinherit(smb_request_t *, smb_node_t *, smb_fssd_t *);
#endif	/* _KERNEL */

/*
 * The smb_fsop_* functions have knowledge of CIFS semantics.
 *
 * The smb_vop_* functions have minimal knowledge of CIFS semantics and
 * serve as an interface to the VFS layer.
 *
 * Hence, smb_request_t and smb_node_t structures should not be passed
 * from the smb_fsop_* layer to the smb_vop_* layer.
 *
 * In general, CIFS service code should only ever call smb_fsop_*
 * functions directly, and never smb_vop_* functions directly.
 *
 * smb_fsop_* functions should call smb_vop_* functions where possible, instead
 * of their smb_fsop_* counterparts.  However, there are times when
 * this cannot be avoided.
 */

/*
 * Note: Stream names cannot be mangled.
 */

/*
 * smb_fsop_amask_to_omode
 *
 * Convert the access mask to the open mode (for use
 * with the VOP_OPEN call).
 *
 * Note that opening a file for attribute only access
 * will also translate into an FREAD or FWRITE open mode
 * (i.e., it's not just for data).
 *
 * This is needed so that opens are tracked appropriately
 * for oplock processing.
 */

int
smb_fsop_amask_to_omode(uint32_t access)
{
	int mode = 0;

	if (access & (FILE_READ_DATA | FILE_EXECUTE |
	    FILE_READ_ATTRIBUTES | FILE_READ_EA))
		mode |= FREAD;

	if (access & (FILE_WRITE_DATA | FILE_APPEND_DATA |
	    FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA))
		mode |= FWRITE;

	if (access & FILE_APPEND_DATA)
		mode |= FAPPEND;

	return (mode);
}

int
smb_fsop_open(smb_node_t *node, int mode, cred_t *cred)
{
	/*
	 * Assuming that the same vnode is returned as we had before.
	 * (I.e., with certain types of files or file systems, a
	 * different vnode might be returned by VOP_OPEN)
	 */
	return (smb_vop_open(&node->vp, mode, cred));
}

void
smb_fsop_close(smb_node_t *node, int mode, cred_t *cred)
{
	smb_vop_close(node->vp, mode, cred);
}

#ifdef	_KERNEL
static int
smb_fsop_create_with_sd(smb_request_t *sr, cred_t *cr,
    smb_node_t *dnode, char *name,
    smb_attr_t *attr, smb_node_t **ret_snode, smb_fssd_t *fs_sd)
{
	vsecattr_t *vsap;
	vsecattr_t vsecattr;
	smb_attr_t set_attr;
	acl_t *acl, *dacl, *sacl;
	vnode_t *vp;
	cred_t *kcr = zone_kcred();
	int aclbsize = 0;	/* size of acl list in bytes */
	int flags = 0;
	int rc;
	boolean_t is_dir;

	ASSERT(fs_sd);
	ASSERT(ret_snode != NULL);

	if (SMB_TREE_IS_CASEINSENSITIVE(sr))
		flags = SMB_IGNORE_CASE;
	if (SMB_TREE_SUPPORTS_CATIA(sr))
		flags |= SMB_CATIA;

	ASSERT(cr);

	is_dir = ((fs_sd->sd_flags & SMB_FSSD_FLAGS_DIR) != 0);

	if (smb_tree_has_feature(sr->tid_tree, SMB_TREE_ACLONCREATE)) {
		dacl = fs_sd->sd_zdacl;
		sacl = fs_sd->sd_zsacl;
		if (dacl != NULL || sacl != NULL) {
			if (dacl && sacl) {
				acl = smb_fsacl_merge(dacl, sacl);
			} else if (dacl) {
				acl = dacl;
			} else {
				acl = sacl;
			}

			rc = smb_fsacl_to_vsa(acl, &vsecattr, &aclbsize);

			if (dacl && sacl)
				acl_free(acl);

			if (rc != 0)
				return (rc);

			vsap = &vsecattr;
		} else {
			vsap = NULL;
		}

		/* The tree ACEs may prevent a create */
		rc = EACCES;
		if (is_dir) {
			if (SMB_TREE_HAS_ACCESS(sr, ACE_ADD_SUBDIRECTORY) != 0)
				rc = smb_vop_mkdir(dnode->vp, name, attr,
				    &vp, flags, cr, vsap);
		} else {
			if (SMB_TREE_HAS_ACCESS(sr, ACE_ADD_FILE) != 0)
				rc = smb_vop_create(dnode->vp, name, attr,
				    &vp, flags, cr, vsap);
		}

		if (vsap != NULL)
			kmem_free(vsap->vsa_aclentp, aclbsize);

		if (rc != 0)
			return (rc);

		set_attr.sa_mask = 0;

		/*
		 * Ideally we should be able to specify the owner and owning
		 * group at create time along with the ACL. Since we cannot
		 * do that right now, kcred is passed to smb_vop_setattr so it
		 * doesn't fail due to lack of permission.
		 */
		if (fs_sd->sd_secinfo & SMB_OWNER_SECINFO) {
			set_attr.sa_vattr.va_uid = fs_sd->sd_uid;
			set_attr.sa_mask |= SMB_AT_UID;
		}

		if (fs_sd->sd_secinfo & SMB_GROUP_SECINFO) {
			set_attr.sa_vattr.va_gid = fs_sd->sd_gid;
			set_attr.sa_mask |= SMB_AT_GID;
		}

		if (set_attr.sa_mask)
			rc = smb_vop_setattr(vp, NULL, &set_attr, 0, kcr);

		if (rc == 0) {
			*ret_snode = smb_node_lookup(sr, &sr->arg.open, cr, vp,
			    name, dnode, NULL);

			if (*ret_snode == NULL)
				rc = ENOMEM;

			VN_RELE(vp);
		}
	} else {
		/*
		 * For filesystems that don't support ACL-on-create, try
		 * to set the specified SD after create, which could actually
		 * fail because of conflicts between inherited security
		 * attributes upon creation and the specified SD.
		 *
		 * Passing kcred to smb_fsop_sdwrite() to overcome this issue.
		 */

		if (is_dir) {
			rc = smb_vop_mkdir(dnode->vp, name, attr, &vp,
			    flags, cr, NULL);
		} else {
			rc = smb_vop_create(dnode->vp, name, attr, &vp,
			    flags, cr, NULL);
		}

		if (rc != 0)
			return (rc);

		*ret_snode = smb_node_lookup(sr, &sr->arg.open, cr, vp,
		    name, dnode, NULL);

		if (*ret_snode != NULL) {
			if (!smb_tree_has_feature(sr->tid_tree,
			    SMB_TREE_NFS_MOUNTED))
				rc = smb_fsop_sdwrite(sr, kcr, *ret_snode,
				    fs_sd, 1);
		} else {
			rc = ENOMEM;
		}

		VN_RELE(vp);
	}

	if (rc != 0) {
		if (is_dir)
			(void) smb_vop_rmdir(dnode->vp, name, flags, cr);
		else
			(void) smb_vop_remove(dnode->vp, name, flags, cr);
	}

	return (rc);
}
#endif	/* _KERNEL */

/*
 * smb_fsop_create
 *
 * All SMB functions should use this wrapper to ensure that
 * all the smb_vop_creates are performed with the appropriate credentials.
 * Please document any direct calls to explain the reason for avoiding
 * this wrapper.
 *
 * *ret_snode is returned with a reference upon success.  No reference is
 * taken if an error is returned.
 */
int
smb_fsop_create(smb_request_t *sr, cred_t *cr, smb_node_t *dnode,
    char *name, smb_attr_t *attr, smb_node_t **ret_snode)
{
	int	rc = 0;
	int	flags = 0;
	char	*fname, *sname;
	char	*longname = NULL;

	ASSERT(cr);
	ASSERT(dnode);
	ASSERT(dnode->n_magic == SMB_NODE_MAGIC);
	ASSERT(dnode->n_state != SMB_NODE_STATE_DESTROYING);

	ASSERT(ret_snode);
	*ret_snode = 0;

	ASSERT(name);
	if (*name == 0)
		return (EINVAL);

	ASSERT(sr);
	ASSERT(sr->tid_tree);

	if (SMB_TREE_CONTAINS_NODE(sr, dnode) == 0)
		return (EACCES);

	if (SMB_TREE_IS_READONLY(sr))
		return (EROFS);

	if (SMB_TREE_IS_CASEINSENSITIVE(sr))
		flags = SMB_IGNORE_CASE;
	if (SMB_TREE_SUPPORTS_CATIA(sr))
		flags |= SMB_CATIA;
	if (SMB_TREE_SUPPORTS_ABE(sr))
		flags |= SMB_ABE;

	if (smb_is_stream_name(name)) {
		fname = kmem_alloc(MAXNAMELEN, KM_SLEEP);
		sname = kmem_alloc(MAXNAMELEN, KM_SLEEP);
		smb_stream_parse_name(name, fname, sname);

		rc = smb_fsop_create_file_with_stream(sr, cr, dnode,
		    fname, sname, flags, attr, ret_snode);

		kmem_free(fname, MAXNAMELEN);
		kmem_free(sname, MAXNAMELEN);
		return (rc);
	}

	/* Not a named stream */

	if (SMB_TREE_SUPPORTS_SHORTNAMES(sr) && smb_maybe_mangled(name)) {
		longname = kmem_alloc(MAXNAMELEN, KM_SLEEP);
		rc = smb_unmangle(dnode, name, longname, MAXNAMELEN, flags);
		kmem_free(longname, MAXNAMELEN);

		if (rc == 0)
			rc = EEXIST;
		if (rc != ENOENT)
			return (rc);
	}

	rc = smb_fsop_create_file(sr, cr, dnode, name, flags,
	    attr, ret_snode);
	return (rc);

}


/*
 * smb_fsop_create_file_with_stream
 *
 * Create named stream (sname) on file (fname), creating the file if it
 * doesn't exist.
 * If we created the file and then creation of the named stream fails,
 * we delete the file.
 * Since we use the real file name for the smb_vop_remove we
 * clear the SMB_IGNORE_CASE flag to ensure a case sensitive
 * match.
 *
 * Note that some stream "types" are "restricted" and only
 * internal callers (cr == kcred) can create those.
 */
static int
smb_fsop_create_file_with_stream(smb_request_t *sr, cred_t *cr,
    smb_node_t *dnode, char *fname, char *sname, int flags,
    smb_attr_t *attr, smb_node_t **ret_snode)
{
	smb_node_t	*fnode;
	cred_t		*kcr = zone_kcred();
	int		rc = 0;
	boolean_t	fcreate = B_FALSE;

	ASSERT(ret_snode != NULL);

	if (cr != kcr && smb_strname_restricted(sname))
		return (EACCES);

	/* Look up / create the unnamed stream, fname */
	rc = smb_fsop_lookup(sr, cr, flags | SMB_FOLLOW_LINKS,
	    sr->tid_tree->t_snode, dnode, fname, &fnode);
	if (rc == 0) {
		if (smb_fsop_access(sr, sr->user_cr, fnode,
		    sr->sr_open.desired_access) != 0) {
			smb_node_release(fnode);
			rc = EACCES;
		}
	} else if (rc == ENOENT) {
		fcreate = B_TRUE;
		rc = smb_fsop_create_file(sr, cr, dnode, fname, flags,
		    attr, &fnode);
	}
	if (rc != 0)
		return (rc);

	rc = smb_fsop_create_stream(sr, cr, dnode, fnode, sname, flags, attr,
	    ret_snode);

	if (rc != 0) {
		if (fcreate) {
			flags &= ~SMB_IGNORE_CASE;
			(void) smb_vop_remove(dnode->vp,
			    fnode->od_name, flags, cr);
		}
	}

	smb_node_release(fnode);
	return (rc);
}

/*
 * smb_fsop_create_stream
 *
 * Create named stream (sname) on existing file (fnode).
 *
 * The second parameter of smb_vop_setattr() is set to
 * NULL, even though an unnamed stream exists.  This is
 * because we want to set the UID and GID on the named
 * stream in this case for consistency with the (unnamed
 * stream) file (see comments for smb_vop_setattr()).
 *
 * Note that some stream "types" are "restricted" and only
 * internal callers (cr == kcred) can create those.
 */
int
smb_fsop_create_stream(smb_request_t *sr, cred_t *cr,
    smb_node_t *dnode, smb_node_t *fnode, char *sname, int flags,
    smb_attr_t *attr, smb_node_t **ret_snode)
{
	smb_attr_t	fattr;
	vnode_t		*xattrdvp;
	vnode_t		*vp;
	cred_t		*kcr = zone_kcred();
	int		rc = 0;

	ASSERT(ret_snode != NULL);

	if (cr != kcr && smb_strname_restricted(sname))
		return (EACCES);

	bzero(&fattr, sizeof (fattr));
	fattr.sa_mask = SMB_AT_UID | SMB_AT_GID;
	rc = smb_vop_getattr(fnode->vp, NULL, &fattr, 0, kcr);

	if (rc == 0) {
		/* create the named stream, sname */
		rc = smb_vop_stream_create(fnode->vp, sname,
		    attr, &vp, &xattrdvp, flags, cr);
	}
	if (rc != 0)
		return (rc);

	attr->sa_vattr.va_uid = fattr.sa_vattr.va_uid;
	attr->sa_vattr.va_gid = fattr.sa_vattr.va_gid;
	attr->sa_mask = SMB_AT_UID | SMB_AT_GID;

	rc = smb_vop_setattr(vp, NULL, attr, 0, kcr);
	if (rc != 0) {
		VN_RELE(xattrdvp);
		VN_RELE(vp);
		return (rc);
	}

	*ret_snode = smb_stream_node_lookup(sr, cr, fnode, xattrdvp,
	    vp, sname);

	VN_RELE(xattrdvp);
	VN_RELE(vp);

	if (*ret_snode == NULL)
		rc = ENOMEM;

	/* notify change to the unnamed stream */
	if (rc == 0)
		smb_node_notify_change(dnode,
		    FILE_ACTION_ADDED_STREAM, fnode->od_name);

	return (rc);
}

/*
 * smb_fsop_create_file
 */
static int
smb_fsop_create_file(smb_request_t *sr, cred_t *cr,
    smb_node_t *dnode, char *name, int flags,
    smb_attr_t *attr, smb_node_t **ret_snode)
{
	smb_arg_open_t	*op = &sr->sr_open;
	vnode_t		*vp;
	int		rc;

	ASSERT(ret_snode != NULL);

#ifdef	_KERNEL
	smb_fssd_t	fs_sd;
	uint32_t	secinfo;
	uint32_t	status;

	if (op->sd) {
		/*
		 * SD sent by client in Windows format. Needs to be
		 * converted to FS format. Inherit DACL/SACL if they're not
		 * specified.
		 */
		secinfo = smb_sd_get_secinfo(op->sd);

		if ((secinfo & SMB_SACL_SECINFO) != 0 &&
		    !smb_user_has_security_priv(sr->uid_user, cr))
			return (EPERM);

		smb_fssd_init(&fs_sd, secinfo, 0);

		status = smb_sd_tofs(op->sd, &fs_sd);
		if (status == NT_STATUS_SUCCESS) {
			rc = smb_fsop_sdinherit(sr, dnode, &fs_sd);
			if (rc == 0)
				rc = smb_fsop_create_with_sd(sr, cr, dnode,
				    name, attr, ret_snode, &fs_sd);

		} else {
			rc = EINVAL;
		}
		smb_fssd_term(&fs_sd);
	} else if (sr->tid_tree->t_acltype == ACE_T) {
		/*
		 * No incoming SD and filesystem is ZFS
		 * Server applies Windows inheritance rules,
		 * see smb_fsop_sdinherit() comments as to why.
		 */
		smb_fssd_init(&fs_sd, 0, 0);
		rc = smb_fsop_sdinherit(sr, dnode, &fs_sd);
		if (rc == 0) {
			rc = smb_fsop_create_with_sd(sr, cr, dnode,
			    name, attr, ret_snode, &fs_sd);
		}

		smb_fssd_term(&fs_sd);
	} else
#endif	/* _KERNEL */
	{
		/*
		 * No incoming SD and filesystem is not ZFS
		 * let the filesystem handles the inheritance.
		 */
		rc = smb_vop_create(dnode->vp, name, attr, &vp,
		    flags, cr, NULL);

		if (rc == 0) {
			*ret_snode = smb_node_lookup(sr, op, cr, vp,
			    name, dnode, NULL);

			if (*ret_snode == NULL)
				rc = ENOMEM;

			VN_RELE(vp);
		}

	}

	if (rc == 0)
		smb_node_notify_change(dnode, FILE_ACTION_ADDED, name);

	return (rc);
}

/*
 * smb_fsop_mkdir
 *
 * All SMB functions should use this wrapper to ensure that
 * the the calls are performed with the appropriate credentials.
 * Please document any direct call to explain the reason
 * for avoiding this wrapper.
 *
 * It is assumed that a reference exists on snode coming into this routine.
 *
 * *ret_snode is returned with a reference upon success.  No reference is
 * taken if an error is returned.
 */
int
smb_fsop_mkdir(
    smb_request_t *sr,
    cred_t *cr,
    smb_node_t *dnode,
    char *name,
    smb_attr_t *attr,
    smb_node_t **ret_snode)
{
	struct open_param *op = &sr->arg.open;
	char *longname;
	vnode_t *vp;
	int flags = 0;
	int rc;

#ifdef	_KERNEL
	smb_fssd_t fs_sd;
	uint32_t secinfo;
	uint32_t status;
#endif	/* _KERNEL */

	ASSERT(cr);
	ASSERT(dnode);
	ASSERT(dnode->n_magic == SMB_NODE_MAGIC);
	ASSERT(dnode->n_state != SMB_NODE_STATE_DESTROYING);

	ASSERT(ret_snode);
	*ret_snode = 0;

	ASSERT(name);
	if (*name == 0)
		return (EINVAL);

	ASSERT(sr);
	ASSERT(sr->tid_tree);

	if (SMB_TREE_CONTAINS_NODE(sr, dnode) == 0)
		return (EACCES);

	if (SMB_TREE_IS_READONLY(sr))
		return (EROFS);
	if (SMB_TREE_SUPPORTS_CATIA(sr))
		flags |= SMB_CATIA;
	if (SMB_TREE_SUPPORTS_ABE(sr))
		flags |= SMB_ABE;

	if (SMB_TREE_SUPPORTS_SHORTNAMES(sr) && smb_maybe_mangled(name)) {
		longname = kmem_alloc(MAXNAMELEN, KM_SLEEP);
		rc = smb_unmangle(dnode, name, longname, MAXNAMELEN, flags);
		kmem_free(longname, MAXNAMELEN);

		/*
		 * If the name passed in by the client has an unmangled
		 * equivalent that is found in the specified directory,
		 * then the mkdir cannot succeed.  Return EEXIST.
		 *
		 * Only if ENOENT is returned will a mkdir be attempted.
		 */

		if (rc == 0)
			rc = EEXIST;

		if (rc != ENOENT)
			return (rc);
	}

	if (SMB_TREE_IS_CASEINSENSITIVE(sr))
		flags = SMB_IGNORE_CASE;

#ifdef	_KERNEL
	if (op->sd) {
		/*
		 * SD sent by client in Windows format. Needs to be
		 * converted to FS format. Inherit DACL/SACL if they're not
		 * specified.
		 */
		secinfo = smb_sd_get_secinfo(op->sd);

		if ((secinfo & SMB_SACL_SECINFO) != 0 &&
		    !smb_user_has_security_priv(sr->uid_user, cr))
			return (EPERM);

		smb_fssd_init(&fs_sd, secinfo, SMB_FSSD_FLAGS_DIR);

		status = smb_sd_tofs(op->sd, &fs_sd);
		if (status == NT_STATUS_SUCCESS) {
			rc = smb_fsop_sdinherit(sr, dnode, &fs_sd);
			if (rc == 0)
				rc = smb_fsop_create_with_sd(sr, cr, dnode,
				    name, attr, ret_snode, &fs_sd);
		}
		else
			rc = EINVAL;
		smb_fssd_term(&fs_sd);
	} else if (sr->tid_tree->t_acltype == ACE_T) {
		/*
		 * No incoming SD and filesystem is ZFS
		 * Server applies Windows inheritance rules,
		 * see smb_fsop_sdinherit() comments as to why.
		 */
		smb_fssd_init(&fs_sd, 0, SMB_FSSD_FLAGS_DIR);
		rc = smb_fsop_sdinherit(sr, dnode, &fs_sd);
		if (rc == 0) {
			rc = smb_fsop_create_with_sd(sr, cr, dnode,
			    name, attr, ret_snode, &fs_sd);
		}

		smb_fssd_term(&fs_sd);

	} else
#endif	/* _KERNEL */
	{
		rc = smb_vop_mkdir(dnode->vp, name, attr, &vp, flags, cr,
		    NULL);

		if (rc == 0) {
			*ret_snode = smb_node_lookup(sr, op, cr, vp, name,
			    dnode, NULL);

			if (*ret_snode == NULL)
				rc = ENOMEM;

			VN_RELE(vp);
		}
	}

	if (rc == 0)
		smb_node_notify_change(dnode, FILE_ACTION_ADDED, name);

	return (rc);
}

/*
 * smb_fsop_remove
 *
 * All SMB functions should use this wrapper to ensure that
 * the the calls are performed with the appropriate credentials.
 * Please document any direct call to explain the reason
 * for avoiding this wrapper.
 *
 * It is assumed that a reference exists on snode coming into this routine.
 *
 * A null smb_request might be passed to this function.
 *
 * Note that some stream "types" are "restricted" and only
 * internal callers (cr == kcred) can remove those.
 */
int
smb_fsop_remove(
    smb_request_t	*sr,
    cred_t		*cr,
    smb_node_t		*dnode,
    char		*name,
    uint32_t		flags)
{
	smb_node_t	*fnode;
	char		*longname;
	char		*fname;
	char		*sname;
	int		rc;

	ASSERT(cr);
	/*
	 * The state of the node could be SMB_NODE_STATE_DESTROYING if this
	 * function is called during the deletion of the node (because of
	 * DELETE_ON_CLOSE).
	 */
	ASSERT(dnode);
	ASSERT(dnode->n_magic == SMB_NODE_MAGIC);

	if (SMB_TREE_CONTAINS_NODE(sr, dnode) == 0 ||
	    SMB_TREE_HAS_ACCESS(sr, ACE_DELETE) == 0)
		return (EACCES);

	if (SMB_TREE_IS_READONLY(sr))
		return (EROFS);

	fname = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	sname = kmem_alloc(MAXNAMELEN, KM_SLEEP);

	if (dnode->flags & NODE_XATTR_DIR) {
		if (cr != zone_kcred() && smb_strname_restricted(name)) {
			rc = EACCES;
			goto out;
		}

		fnode = dnode->n_dnode;
		rc = smb_vop_stream_remove(fnode->vp, name, flags, cr);

		/* notify change to the unnamed stream */
		if ((rc == 0) && fnode->n_dnode) {
			smb_node_notify_change(fnode->n_dnode,
			    FILE_ACTION_REMOVED_STREAM, fnode->od_name);
		}
	} else if (smb_is_stream_name(name)) {
		smb_stream_parse_name(name, fname, sname);

		if (cr != zone_kcred() && smb_strname_restricted(sname)) {
			rc = EACCES;
			goto out;
		}

		/*
		 * Look up the unnamed stream (i.e. fname).
		 * Unmangle processing will be done on fname
		 * as well as any link target.
		 */

		rc = smb_fsop_lookup(sr, cr, flags | SMB_FOLLOW_LINKS,
		    sr->tid_tree->t_snode, dnode, fname, &fnode);

		if (rc != 0) {
			goto out;
		}

		/*
		 * XXX
		 * Need to find out what permission is required by NTFS
		 * to remove a stream.
		 */
		rc = smb_vop_stream_remove(fnode->vp, sname, flags, cr);

		smb_node_release(fnode);

		/* notify change to the unnamed stream */
		if (rc == 0) {
			smb_node_notify_change(dnode,
			    FILE_ACTION_REMOVED_STREAM, fname);
		}
	} else {
		rc = smb_vop_remove(dnode->vp, name, flags, cr);

		if (rc == ENOENT) {
			if (!SMB_TREE_SUPPORTS_SHORTNAMES(sr) ||
			    !smb_maybe_mangled(name)) {
				goto out;
			}
			longname = kmem_alloc(MAXNAMELEN, KM_SLEEP);

			if (SMB_TREE_SUPPORTS_ABE(sr))
				flags |= SMB_ABE;

			rc = smb_unmangle(dnode, name, longname, MAXNAMELEN,
			    flags);

			if (rc == 0) {
				/*
				 * longname is the real (case-sensitive)
				 * on-disk name.
				 * We make sure we do a remove on this exact
				 * name, as the name was mangled and denotes
				 * a unique file.
				 */
				flags &= ~SMB_IGNORE_CASE;
				rc = smb_vop_remove(dnode->vp, longname,
				    flags, cr);
			}
			kmem_free(longname, MAXNAMELEN);
		}
		if (rc == 0) {
			smb_node_notify_change(dnode,
			    FILE_ACTION_REMOVED, name);
		}
	}

out:
	kmem_free(fname, MAXNAMELEN);
	kmem_free(sname, MAXNAMELEN);

	return (rc);
}

/*
 * smb_fsop_remove_streams
 *
 * This function removes a file's streams without removing the
 * file itself.
 *
 * It is assumed that fnode is not a link.
 */
uint32_t
smb_fsop_remove_streams(smb_request_t *sr, cred_t *cr, smb_node_t *fnode)
{
	int rc, flags = 0;
	smb_odir_t *od;
	smb_odirent_t *odirent;
	uint32_t status;
	boolean_t eos;

	ASSERT(sr);
	ASSERT(cr);
	ASSERT(fnode);
	ASSERT(fnode->n_magic == SMB_NODE_MAGIC);
	ASSERT(fnode->n_state != SMB_NODE_STATE_DESTROYING);

	if (SMB_TREE_CONTAINS_NODE(sr, fnode) == 0)
		return (NT_STATUS_ACCESS_DENIED);

	if (SMB_TREE_IS_READONLY(sr))
		return (NT_STATUS_ACCESS_DENIED);

	if (SMB_TREE_IS_CASEINSENSITIVE(sr))
		flags = SMB_IGNORE_CASE;

	if (SMB_TREE_SUPPORTS_CATIA(sr))
		flags |= SMB_CATIA;

	/*
	 * NB: There aren't currently any restricted streams that could be
	 * removed by this function. If there ever are, be careful to exclude
	 * any restricted streams that we DON'T want to remove.
	 */
	status = smb_odir_openat(sr, fnode, &od, B_FALSE);
	switch (status) {
	case 0:
		break;
	case NT_STATUS_OBJECT_NAME_NOT_FOUND:
	case NT_STATUS_NO_SUCH_FILE:
	case NT_STATUS_NOT_SUPPORTED:
		/* No streams to remove. */
		return (0);
	default:
		return (status);
	}

	odirent = kmem_alloc(sizeof (smb_odirent_t), KM_SLEEP);
	for (;;) {
		rc = smb_odir_read(sr, od, odirent, &eos);
		if ((rc != 0) || (eos))
			break;
		(void) smb_vop_remove(od->d_dnode->vp, odirent->od_name,
		    flags, cr);
	}
	kmem_free(odirent, sizeof (smb_odirent_t));
	if (eos && rc == ENOENT)
		rc = 0;

	smb_odir_close(od);
	smb_odir_release(od);
	if (rc)
		status = smb_errno2status(rc);
	return (status);
}

/*
 * smb_fsop_rmdir
 *
 * All SMB functions should use this wrapper to ensure that
 * the the calls are performed with the appropriate credentials.
 * Please document any direct call to explain the reason
 * for avoiding this wrapper.
 *
 * It is assumed that a reference exists on snode coming into this routine.
 */
int
smb_fsop_rmdir(
    smb_request_t	*sr,
    cred_t		*cr,
    smb_node_t		*dnode,
    char		*name,
    uint32_t		flags)
{
	int		rc;
	char		*longname;

	ASSERT(cr);
	/*
	 * The state of the node could be SMB_NODE_STATE_DESTROYING if this
	 * function is called during the deletion of the node (because of
	 * DELETE_ON_CLOSE).
	 */
	ASSERT(dnode);
	ASSERT(dnode->n_magic == SMB_NODE_MAGIC);

	if (SMB_TREE_CONTAINS_NODE(sr, dnode) == 0 ||
	    SMB_TREE_HAS_ACCESS(sr, ACE_DELETE_CHILD) == 0)
		return (EACCES);

	if (SMB_TREE_IS_READONLY(sr))
		return (EROFS);

	rc = smb_vop_rmdir(dnode->vp, name, flags, cr);

	if (rc == ENOENT) {
		if (!SMB_TREE_SUPPORTS_SHORTNAMES(sr) ||
		    !smb_maybe_mangled(name)) {
			return (rc);
		}

		longname = kmem_alloc(MAXNAMELEN, KM_SLEEP);

		if (SMB_TREE_SUPPORTS_ABE(sr))
			flags |= SMB_ABE;
		rc = smb_unmangle(dnode, name, longname, MAXNAMELEN, flags);

		if (rc == 0) {
			/*
			 * longname is the real (case-sensitive)
			 * on-disk name.
			 * We make sure we do a rmdir on this exact
			 * name, as the name was mangled and denotes
			 * a unique directory.
			 */
			flags &= ~SMB_IGNORE_CASE;
			rc = smb_vop_rmdir(dnode->vp, longname, flags, cr);
		}

		kmem_free(longname, MAXNAMELEN);
	}

	if (rc == 0)
		smb_node_notify_change(dnode, FILE_ACTION_REMOVED, name);

	return (rc);
}

/*
 * smb_fsop_getattr
 *
 * All SMB functions should use this wrapper to ensure that
 * the the calls are performed with the appropriate credentials.
 * Please document any direct call to explain the reason
 * for avoiding this wrapper.
 *
 * It is assumed that a reference exists on snode coming into this routine.
 */
int
smb_fsop_getattr(smb_request_t *sr, cred_t *cr, smb_node_t *snode,
    smb_attr_t *attr)
{
	smb_node_t *unnamed_node;
	vnode_t *unnamed_vp = NULL;
	uint32_t status;
	uint32_t access = 0;
	int flags = 0;
	int rc;

	ASSERT(cr);
	ASSERT(snode);
	ASSERT(snode->n_magic == SMB_NODE_MAGIC);
	ASSERT(snode->n_state != SMB_NODE_STATE_DESTROYING);

	if (SMB_TREE_CONTAINS_NODE(sr, snode) == 0 ||
	    SMB_TREE_HAS_ACCESS(sr, ACE_READ_ATTRIBUTES) == 0)
		return (EACCES);

	/* sr could be NULL in some cases */
	if (sr && sr->fid_ofile) {
		/* if uid and/or gid is requested */
		if (attr->sa_mask & (SMB_AT_UID|SMB_AT_GID))
			access |= READ_CONTROL;

		/* if anything else is also requested */
		if (attr->sa_mask & ~(SMB_AT_UID|SMB_AT_GID))
			access |= FILE_READ_ATTRIBUTES;

		status = smb_ofile_access(sr->fid_ofile, cr, access);
		if (status != NT_STATUS_SUCCESS)
			return (EACCES);

		if (smb_tree_has_feature(sr->tid_tree,
		    SMB_TREE_ACEMASKONACCESS))
			flags = ATTR_NOACLCHECK;
	}

	unnamed_node = SMB_IS_STREAM(snode);

	if (unnamed_node) {
		ASSERT(unnamed_node->n_magic == SMB_NODE_MAGIC);
		ASSERT(unnamed_node->n_state != SMB_NODE_STATE_DESTROYING);
		unnamed_vp = unnamed_node->vp;
	}

	rc = smb_vop_getattr(snode->vp, unnamed_vp, attr, flags, cr);

	if ((rc == 0) && smb_node_is_dfslink(snode)) {
		/* a DFS link should be treated as a directory */
		attr->sa_dosattr |= FILE_ATTRIBUTE_DIRECTORY;
	}

	return (rc);
}

/*
 * smb_fsop_link
 *
 * All SMB functions should use this smb_vop_link wrapper to ensure that
 * the smb_vop_link is performed with the appropriate credentials.
 * Please document any direct call to smb_vop_link to explain the reason
 * for avoiding this wrapper.
 *
 * It is assumed that references exist on from_dnode and to_dnode coming
 * into this routine.
 */
int
smb_fsop_link(smb_request_t *sr, cred_t *cr, smb_node_t *from_fnode,
    smb_node_t *to_dnode, char *to_name)
{
	char	*longname = NULL;
	int	flags = 0;
	int	rc;

	ASSERT(sr);
	ASSERT(sr->tid_tree);
	ASSERT(cr);
	ASSERT(to_dnode);
	ASSERT(to_dnode->n_magic == SMB_NODE_MAGIC);
	ASSERT(to_dnode->n_state != SMB_NODE_STATE_DESTROYING);
	ASSERT(from_fnode);
	ASSERT(from_fnode->n_magic == SMB_NODE_MAGIC);
	ASSERT(from_fnode->n_state != SMB_NODE_STATE_DESTROYING);

	if (SMB_TREE_CONTAINS_NODE(sr, from_fnode) == 0)
		return (EACCES);

	if (SMB_TREE_CONTAINS_NODE(sr, to_dnode) == 0)
		return (EACCES);

	if (SMB_TREE_IS_READONLY(sr))
		return (EROFS);

	if (SMB_TREE_IS_CASEINSENSITIVE(sr))
		flags = SMB_IGNORE_CASE;
	if (SMB_TREE_SUPPORTS_CATIA(sr))
		flags |= SMB_CATIA;
	if (SMB_TREE_SUPPORTS_ABE(sr))
		flags |= SMB_ABE;

	if (SMB_TREE_SUPPORTS_SHORTNAMES(sr) && smb_maybe_mangled(to_name)) {
		longname = kmem_alloc(MAXNAMELEN, KM_SLEEP);
		rc = smb_unmangle(to_dnode, to_name, longname,
		    MAXNAMELEN, flags);
		kmem_free(longname, MAXNAMELEN);

		if (rc == 0)
			rc = EEXIST;
		if (rc != ENOENT)
			return (rc);
	}

	rc = smb_vop_link(to_dnode->vp, from_fnode->vp, to_name, flags, cr);

	if (rc == 0)
		smb_node_notify_change(to_dnode, FILE_ACTION_ADDED, to_name);

	return (rc);
}

/*
 * smb_fsop_rename
 *
 * All SMB functions should use this smb_vop_rename wrapper to ensure that
 * the smb_vop_rename is performed with the appropriate credentials.
 * Please document any direct call to smb_vop_rename to explain the reason
 * for avoiding this wrapper.
 *
 * It is assumed that references exist on from_dnode and to_dnode coming
 * into this routine.
 */
int
smb_fsop_rename(
    smb_request_t *sr,
    cred_t *cr,
    smb_node_t *from_dnode,
    char *from_name,
    smb_node_t *to_dnode,
    char *to_name)
{
	smb_node_t *from_snode;
	smb_attr_t from_attr;
	vnode_t *from_vp;
	int flags = 0, ret_flags;
	int rc;
	boolean_t isdir;

	ASSERT(cr);
	ASSERT(from_dnode);
	ASSERT(from_dnode->n_magic == SMB_NODE_MAGIC);
	ASSERT(from_dnode->n_state != SMB_NODE_STATE_DESTROYING);

	ASSERT(to_dnode);
	ASSERT(to_dnode->n_magic == SMB_NODE_MAGIC);
	ASSERT(to_dnode->n_state != SMB_NODE_STATE_DESTROYING);

	if (SMB_TREE_CONTAINS_NODE(sr, from_dnode) == 0)
		return (EACCES);

	if (SMB_TREE_CONTAINS_NODE(sr, to_dnode) == 0)
		return (EACCES);

	ASSERT(sr);
	ASSERT(sr->tid_tree);
	if (SMB_TREE_IS_READONLY(sr))
		return (EROFS);

	/*
	 * Note: There is no need to check SMB_TREE_IS_CASEINSENSITIVE
	 * here.
	 *
	 * A case-sensitive rename is always done in this routine
	 * because we are using the on-disk name from an earlier lookup.
	 * If a mangled name was passed in by the caller (denoting a
	 * deterministic lookup), then the exact file must be renamed
	 * (i.e. SMB_IGNORE_CASE must not be passed to VOP_RENAME, or
	 * else the underlying file system might return a "first-match"
	 * on this on-disk name, possibly resulting in the wrong file).
	 */

	if (SMB_TREE_SUPPORTS_CATIA(sr))
		flags |= SMB_CATIA;

	/*
	 * XXX: Lock required through smb_node_release() below?
	 */

	rc = smb_vop_lookup(from_dnode->vp, from_name, &from_vp, NULL,
	    flags, &ret_flags, NULL, &from_attr, cr);

	if (rc != 0)
		return (rc);

	/*
	 * Make sure "from" vp is not a mount point.
	 */
	if (from_vp->v_type == VDIR && vn_ismntpt(from_vp)) {
		VN_RELE(from_vp);
		return (EACCES);
	}

	if (from_attr.sa_dosattr & FILE_ATTRIBUTE_REPARSE_POINT) {
		VN_RELE(from_vp);
		return (EACCES);
	}

	isdir = ((from_attr.sa_dosattr & FILE_ATTRIBUTE_DIRECTORY) != 0);

	if ((isdir && SMB_TREE_HAS_ACCESS(sr,
	    ACE_DELETE_CHILD | ACE_ADD_SUBDIRECTORY) !=
	    (ACE_DELETE_CHILD | ACE_ADD_SUBDIRECTORY)) ||
	    (!isdir && SMB_TREE_HAS_ACCESS(sr, ACE_DELETE | ACE_ADD_FILE) !=
	    (ACE_DELETE | ACE_ADD_FILE))) {
		VN_RELE(from_vp);
		return (EACCES);
	}

	/*
	 * SMB checks access on open and retains an access granted
	 * mask for use while the file is open.  ACL changes should
	 * not affect access to an open file.
	 *
	 * If the rename is being performed on an ofile:
	 * - Check the ofile's access granted mask to see if the
	 *   rename is permitted - requires DELETE access.
	 * - If the file system does access checking, set the
	 *   ATTR_NOACLCHECK flag to ensure that the file system
	 *   does not check permissions on subsequent calls.
	 */
	if (sr && sr->fid_ofile) {
		rc = smb_ofile_access(sr->fid_ofile, cr, DELETE);
		if (rc != NT_STATUS_SUCCESS) {
			VN_RELE(from_vp);
			return (EACCES);
		}

		/*
		 * TODO: avoid ACL check for source file.
		 * smb_vop_rename() passes its own flags to VOP_RENAME,
		 * and ZFS doesn't pass it on to zfs_zaccess_rename().
		 */
	}

	rc = smb_vop_rename(from_dnode->vp, from_name, to_dnode->vp,
	    to_name, flags, cr);

	if (rc == 0) {
		from_snode = smb_node_lookup(sr, NULL, cr, from_vp, from_name,
		    from_dnode, NULL);

		if (from_snode == NULL) {
			rc = ENOMEM;
		} else {
			smb_node_rename(from_dnode, from_snode,
			    to_dnode, to_name);
			smb_node_release(from_snode);
		}
	}
	VN_RELE(from_vp);

	if (rc == 0) {
		if (from_dnode == to_dnode) {
			smb_node_notify_change(from_dnode,
			    FILE_ACTION_RENAMED_OLD_NAME, from_name);
			smb_node_notify_change(to_dnode,
			    FILE_ACTION_RENAMED_NEW_NAME, to_name);
		} else {
			smb_node_notify_change(from_dnode,
			    FILE_ACTION_REMOVED, from_name);
			smb_node_notify_change(to_dnode,
			    FILE_ACTION_ADDED, to_name);
		}
	}

	/* XXX: unlock */

	return (rc);
}

/*
 * smb_fsop_setattr
 *
 * All SMB functions should use this wrapper to ensure that
 * the the calls are performed with the appropriate credentials.
 * Please document any direct call to explain the reason
 * for avoiding this wrapper.
 *
 * It is assumed that a reference exists on snode coming into
 * this function.
 * A null smb_request might be passed to this function.
 */
int
smb_fsop_setattr(
    smb_request_t	*sr,
    cred_t		*cr,
    smb_node_t		*snode,
    smb_attr_t		*set_attr)
{
	smb_node_t *unnamed_node;
	vnode_t *unnamed_vp = NULL;
	uint32_t status;
	uint32_t access;
	int rc = 0;
	int flags = 0;
	uint_t sa_mask;

	ASSERT(cr);
	ASSERT(snode);
	ASSERT(snode->n_magic == SMB_NODE_MAGIC);
	ASSERT(snode->n_state != SMB_NODE_STATE_DESTROYING);

	if (SMB_TREE_CONTAINS_NODE(sr, snode) == 0)
		return (EACCES);

	if (SMB_TREE_IS_READONLY(sr))
		return (EROFS);

	if (SMB_TREE_HAS_ACCESS(sr,
	    ACE_WRITE_ATTRIBUTES | ACE_WRITE_NAMED_ATTRS) == 0)
		return (EACCES);

	/*
	 * SMB checks access on open and retains an access granted
	 * mask for use while the file is open.  ACL changes should
	 * not affect access to an open file.
	 *
	 * If the setattr is being performed on an ofile:
	 * - Check the ofile's access granted mask to see if the
	 *   setattr is permitted.
	 *   UID, GID - require WRITE_OWNER
	 *   SIZE, ALLOCSZ - require FILE_WRITE_DATA
	 *   all other attributes require FILE_WRITE_ATTRIBUTES
	 *
	 * - If the file system does access checking, set the
	 *   ATTR_NOACLCHECK flag to ensure that the file system
	 *   does not check permissions on subsequent calls.
	 */
	if (sr && sr->fid_ofile) {
		sa_mask = set_attr->sa_mask;
		access = 0;

		if (sa_mask & (SMB_AT_SIZE | SMB_AT_ALLOCSZ)) {
			access |= FILE_WRITE_DATA;
			sa_mask &= ~(SMB_AT_SIZE | SMB_AT_ALLOCSZ);
		}

		if (sa_mask & (SMB_AT_UID|SMB_AT_GID)) {
			access |= WRITE_OWNER;
			sa_mask &= ~(SMB_AT_UID|SMB_AT_GID);
		}

		if (sa_mask)
			access |= FILE_WRITE_ATTRIBUTES;

		status = smb_ofile_access(sr->fid_ofile, cr, access);
		if (status != NT_STATUS_SUCCESS)
			return (EACCES);

		if (smb_tree_has_feature(sr->tid_tree,
		    SMB_TREE_ACEMASKONACCESS))
			flags = ATTR_NOACLCHECK;
	}

	unnamed_node = SMB_IS_STREAM(snode);

	if (unnamed_node) {
		ASSERT(unnamed_node->n_magic == SMB_NODE_MAGIC);
		ASSERT(unnamed_node->n_state != SMB_NODE_STATE_DESTROYING);
		unnamed_vp = unnamed_node->vp;
	}

	rc = smb_vop_setattr(snode->vp, unnamed_vp, set_attr, flags, cr);
	return (rc);
}

/*
 * Support for SMB2 setinfo FileValidDataLengthInformation.
 * Free (zero out) data in the range off, off+len
 */
int
smb_fsop_freesp(
    smb_request_t	*sr,
    cred_t		*cr,
    smb_ofile_t		*ofile,
    off64_t		off,
    off64_t		len)
{
	flock64_t flk;
	smb_node_t *node = ofile->f_node;
	uint32_t status;
	uint32_t access = FILE_WRITE_DATA;
	int rc;

	ASSERT(cr);
	ASSERT(node);
	ASSERT(node->n_magic == SMB_NODE_MAGIC);
	ASSERT(node->n_state != SMB_NODE_STATE_DESTROYING);

	if (SMB_TREE_CONTAINS_NODE(sr, node) == 0)
		return (EACCES);

	if (SMB_TREE_IS_READONLY(sr))
		return (EROFS);

	if (SMB_TREE_HAS_ACCESS(sr, access) == 0)
		return (EACCES);

	/*
	 * SMB checks access on open and retains an access granted
	 * mask for use while the file is open.  ACL changes should
	 * not affect access to an open file.
	 *
	 * If the setattr is being performed on an ofile:
	 * - Check the ofile's access granted mask to see if this
	 *   modification should be permitted (FILE_WRITE_DATA)
	 */
	status = smb_ofile_access(sr->fid_ofile, cr, access);
	if (status != NT_STATUS_SUCCESS)
		return (EACCES);

	bzero(&flk, sizeof (flk));
	flk.l_start = off;
	flk.l_len = len;

	rc = smb_vop_space(node->vp, F_FREESP, &flk, FWRITE, 0LL, cr);
	return (rc);
}

/*
 * smb_fsop_read
 *
 * All SMB functions should use this wrapper to ensure that
 * the the calls are performed with the appropriate credentials.
 * Please document any direct call to explain the reason
 * for avoiding this wrapper.
 *
 * It is assumed that a reference exists on snode coming into this routine.
 * Note that ofile may be different from sr->fid_ofile, or may be NULL.
 */
int
smb_fsop_read(smb_request_t *sr, cred_t *cr, smb_node_t *snode,
    smb_ofile_t *ofile, uio_t *uio, int ioflag)
{
	caller_context_t ct;
	cred_t *kcr = zone_kcred();
	uint32_t amask;
	int svmand;
	int rc;

	ASSERT(cr);
	ASSERT(snode);
	ASSERT(snode->n_magic == SMB_NODE_MAGIC);
	ASSERT(snode->n_state != SMB_NODE_STATE_DESTROYING);

	ASSERT(sr);

	if (ofile != NULL) {
		/*
		 * Check tree access.  Not SMB_TREE_HAS_ACCESS
		 * because we need to use ofile->f_tree
		 */
		if ((ofile->f_tree->t_access & ACE_READ_DATA) == 0)
			return (EACCES);

		/*
		 * Check ofile access.  Use in-line smb_ofile_access
		 * so we can check both amask bits at the same time.
		 * If any bit in amask is granted, allow this read.
		 */
		amask = FILE_READ_DATA;
		if (sr->smb_flg2 & SMB_FLAGS2_READ_IF_EXECUTE)
			amask |= FILE_EXECUTE;
		if (cr != kcr && (ofile->f_granted_access & amask) == 0)
			return (EACCES);
	}

	/*
	 * Streams permission are checked against the unnamed stream,
	 * but in FS level they have their own permissions. To avoid
	 * rejection by FS due to lack of permission on the actual
	 * extended attr kcred is passed for streams.
	 */
	if (SMB_IS_STREAM(snode))
		cr = kcr;

	smb_node_start_crit(snode, RW_READER);
	rc = nbl_svmand(snode->vp, kcr, &svmand);
	if (rc) {
		smb_node_end_crit(snode);
		return (rc);
	}

	/*
	 * Note: SMB allows a zero-byte read, which should not
	 * conflict with any locks.  However nbl_lock_conflict
	 * takes a zero-byte length as lock to EOF, so we must
	 * special case that here.
	 */
	if (uio->uio_resid > 0) {
		ct = smb_ct;
		if (ofile != NULL)
			ct.cc_pid = ofile->f_uniqid;
		rc = nbl_lock_conflict(snode->vp, NBL_READ, uio->uio_loffset,
		    uio->uio_resid, svmand, &ct);
		if (rc != 0) {
			smb_node_end_crit(snode);
			return (ERANGE);
		}
	}

	rc = smb_vop_read(snode->vp, uio, ioflag, cr);
	smb_node_end_crit(snode);

	return (rc);
}

/*
 * smb_fsop_write
 *
 * It is assumed that a reference exists on snode coming into this routine.
 * Note that ofile may be different from sr->fid_ofile, or may be NULL.
 */
int
smb_fsop_write(
    smb_request_t *sr,
    cred_t *cr,
    smb_node_t *snode,
    smb_ofile_t *ofile,
    uio_t *uio,
    uint32_t *lcount,
    int ioflag)
{
	caller_context_t ct;
	smb_attr_t attr;
	cred_t *kcr = zone_kcred();
	smb_node_t *u_node;
	vnode_t *u_vp = NULL;
	vnode_t *vp;
	uint32_t amask;
	int svmand;
	int rc;

	ASSERT(cr);
	ASSERT(snode);
	ASSERT(snode->n_magic == SMB_NODE_MAGIC);
	ASSERT(snode->n_state != SMB_NODE_STATE_DESTROYING);

	ASSERT(sr);
	vp = snode->vp;

	if (ofile != NULL) {
		amask = FILE_WRITE_DATA | FILE_APPEND_DATA;

		/* Check tree access. */
		if ((ofile->f_tree->t_access & amask) == 0)
			return (EROFS);

		/*
		 * Check ofile access.  Use in-line smb_ofile_access
		 * so we can check both amask bits at the same time.
		 * If any bit in amask is granted, allow this write.
		 */
		if (cr != kcr && (ofile->f_granted_access & amask) == 0)
			return (EACCES);
	}

	/*
	 * Streams permission are checked against the unnamed stream,
	 * but in FS level they have their own permissions. To avoid
	 * rejection by FS due to lack of permission on the actual
	 * extended attr kcred is passed for streams.
	 */
	u_node = SMB_IS_STREAM(snode);
	if (u_node != NULL) {
		ASSERT(u_node->n_magic == SMB_NODE_MAGIC);
		ASSERT(u_node->n_state != SMB_NODE_STATE_DESTROYING);
		u_vp = u_node->vp;
		cr = kcr;
	}

	smb_node_start_crit(snode, RW_READER);
	rc = nbl_svmand(vp, kcr, &svmand);
	if (rc) {
		smb_node_end_crit(snode);
		return (rc);
	}

	/*
	 * Note: SMB allows a zero-byte write, which should not
	 * conflict with any locks.  However nbl_lock_conflict
	 * takes a zero-byte length as lock to EOF, so we must
	 * special case that here.
	 */
	if (uio->uio_resid > 0) {
		ct = smb_ct;
		if (ofile != NULL)
			ct.cc_pid = ofile->f_uniqid;
		rc = nbl_lock_conflict(vp, NBL_WRITE, uio->uio_loffset,
		    uio->uio_resid, svmand, &ct);
		if (rc != 0) {
			smb_node_end_crit(snode);
			return (ERANGE);
		}
	}

	rc = smb_vop_write(vp, uio, ioflag, lcount, cr);

	/*
	 * Once the mtime has been set via this ofile, the
	 * automatic mtime changes from writes via this ofile
	 * should cease, preserving the mtime that was set.
	 * See: [MS-FSA] 2.1.5.14 and smb_node_setattr.
	 *
	 * The VFS interface does not offer a way to ask it to
	 * skip the mtime updates, so we simulate the desired
	 * behavior by re-setting the mtime after writes on a
	 * handle where the mtime has been set.
	 */
	if (ofile != NULL &&
	    (ofile->f_pending_attr.sa_mask & SMB_AT_MTIME) != 0) {
		bcopy(&ofile->f_pending_attr, &attr, sizeof (attr));
		attr.sa_mask = SMB_AT_MTIME;
		(void) smb_vop_setattr(vp, u_vp, &attr, 0, kcr);
	}

	smb_node_end_crit(snode);

	return (rc);
}


/*
 * Support for zero-copy read/write
 * Request buffers and return them.
 *
 * Unlike other fsop functions, these two do NOT include the SR
 * because the lifetime of the loaned buffers could eventually
 * extend beyond the life of the smb_request_t that used them.
 */
int
smb_fsop_reqzcbuf(smb_node_t *node, xuio_t *xuio, int ioflag, cred_t *cr)
{
	return (smb_vop_reqzcbuf(node->vp, ioflag, xuio, cr));
}

int
smb_fsop_retzcbuf(smb_node_t *node, xuio_t *xuio, cred_t *cr)
{
	return (smb_vop_retzcbuf(node->vp, xuio, cr));
}

/*
 * Find the next allocated range starting at or after
 * the offset (*datap), returning the start/end of
 * that range in (*datap, *holep)
 */
int
smb_fsop_next_alloc_range(
    cred_t *cr,
    smb_node_t *node,
    off64_t *datap,
    off64_t *holep)
{
	int err;

	err = smb_vop_ioctl(node->vp, _FIO_SEEK_DATA, datap, cr);
	if (err != 0)
		return (err);

	*holep = *datap;
	err = smb_vop_ioctl(node->vp, _FIO_SEEK_HOLE, holep, cr);

	return (err);
}

/*
 * smb_fsop_statfs
 *
 * This is a wrapper function used for stat operations.
 */
int
smb_fsop_statfs(
    cred_t *cr,
    smb_node_t *snode,
    struct statvfs64 *statp)
{
	ASSERT(cr);
	ASSERT(snode);
	ASSERT(snode->n_magic == SMB_NODE_MAGIC);
	ASSERT(snode->n_state != SMB_NODE_STATE_DESTROYING);

	return (smb_vop_statfs(snode->vp, statp, cr));
}

/*
 * smb_fsop_access
 *
 * Named streams do not have separate permissions from the associated
 * unnamed stream.  Thus, if node is a named stream, the permissions
 * check will be performed on the associated unnamed stream.
 *
 * However, our named streams do have their own quarantine attribute,
 * separate from that on the unnamed stream. If READ or EXECUTE
 * access has been requested on a named stream, an additional access
 * check is performed on the named stream in case it has been
 * quarantined.  kcred is used to avoid issues with the permissions
 * set on the extended attribute file representing the named stream.
 *
 * Note that some stream "types" are "restricted" and only
 * internal callers (cr == kcred) can access those.
 */
int
smb_fsop_access(smb_request_t *sr, cred_t *cr, smb_node_t *snode,
    uint32_t faccess)
{
	int access = 0;
	int error;
	vnode_t *dir_vp;
	boolean_t acl_check = B_TRUE;
	smb_node_t *unnamed_node;

	ASSERT(sr);
	ASSERT(cr);
	ASSERT(snode);
	ASSERT(snode->n_magic == SMB_NODE_MAGIC);
	ASSERT(snode->n_state != SMB_NODE_STATE_DESTROYING);

	if (SMB_TREE_IS_READONLY(sr)) {
		if (faccess & (FILE_WRITE_DATA|FILE_APPEND_DATA|
		    FILE_WRITE_EA|FILE_DELETE_CHILD|FILE_WRITE_ATTRIBUTES|
		    DELETE|WRITE_DAC|WRITE_OWNER)) {
			return (NT_STATUS_ACCESS_DENIED);
		}
	}

	if (smb_node_is_reparse(snode) && (faccess & DELETE))
		return (NT_STATUS_ACCESS_DENIED);

	unnamed_node = SMB_IS_STREAM(snode);
	if (unnamed_node) {
		cred_t *kcr = zone_kcred();

		ASSERT(unnamed_node->n_magic == SMB_NODE_MAGIC);
		ASSERT(unnamed_node->n_state != SMB_NODE_STATE_DESTROYING);

		if (cr != kcr && smb_strname_restricted(snode->od_name))
			return (NT_STATUS_ACCESS_DENIED);

		/*
		 * Perform VREAD access check on the named stream in case it
		 * is quarantined. kcred is passed to smb_vop_access so it
		 * doesn't fail due to lack of permission.
		 */
		if (faccess & (FILE_READ_DATA | FILE_EXECUTE)) {
			error = smb_vop_access(snode->vp, VREAD,
			    0, NULL, kcr);
			if (error)
				return (NT_STATUS_ACCESS_DENIED);
		}

		/*
		 * Streams authorization should be performed against the
		 * unnamed stream.
		 */
		snode = unnamed_node;
	}

	if (faccess & ACCESS_SYSTEM_SECURITY) {
		/*
		 * This permission is required for reading/writing SACL and
		 * it's not part of DACL. It's only granted via proper
		 * privileges.
		 */
		if (!smb_user_has_security_priv(sr->uid_user, cr))
			return (NT_STATUS_PRIVILEGE_NOT_HELD);

		faccess &= ~ACCESS_SYSTEM_SECURITY;
	}

	/* Links don't have ACL */
	if ((!smb_tree_has_feature(sr->tid_tree, SMB_TREE_ACEMASKONACCESS)) ||
	    smb_node_is_symlink(snode))
		acl_check = B_FALSE;

	/* Deny access based on the share access mask */

	if ((faccess & ~sr->tid_tree->t_access) != 0)
		return (NT_STATUS_ACCESS_DENIED);

	if (acl_check) {
		dir_vp = (snode->n_dnode) ? snode->n_dnode->vp : NULL;
		error = smb_vop_access(snode->vp, faccess, V_ACE_MASK, dir_vp,
		    cr);
	} else {
		/*
		 * FS doesn't understand 32-bit mask, need to map
		 */
		if (faccess & (FILE_WRITE_DATA | FILE_APPEND_DATA))
			access |= VWRITE;

		if (faccess & FILE_READ_DATA)
			access |= VREAD;

		if (faccess & FILE_EXECUTE)
			access |= VEXEC;

		error = smb_vop_access(snode->vp, access, 0, NULL, cr);
	}

	return ((error) ? NT_STATUS_ACCESS_DENIED : NT_STATUS_SUCCESS);
}

/*
 * smb_fsop_lookup_name()
 *
 * Lookup both the file and stream specified in 'name'.
 * If name indicates that the file is a stream file, perform
 * stream specific lookup, otherwise call smb_fsop_lookup.
 *
 * On success, returns the found node in *ret_snode. This will be either a named
 * or unnamed stream node, depending on the name specified.
 *
 * Return an error if the looked-up file is in outside the tree.
 * (Required when invoked from open path.)
 *
 * Case sensitivity flags (SMB_IGNORE_CASE, SMB_CASE_SENSITIVE):
 * if SMB_CASE_SENSITIVE is set, the SMB_IGNORE_CASE flag will NOT be set
 * based on the tree's case sensitivity. However, if the SMB_IGNORE_CASE
 * flag is set in the flags value passed as a parameter, a case insensitive
 * lookup WILL be done (regardless of whether SMB_CASE_SENSITIVE is set
 * or not).
 */

int
smb_fsop_lookup_name(
    smb_request_t *sr,
    cred_t	*cr,
    int		flags,
    smb_node_t	*root_node,
    smb_node_t	*dnode,
    char	*name,
    smb_node_t	**ret_snode)
{
	char *sname = NULL;
	int rc;
	smb_node_t *tmp_node;

	ASSERT(ret_snode != NULL);

	rc = smb_fsop_lookup_file(sr, cr, flags, root_node, dnode, name,
	    &sname, ret_snode);

	if (rc != 0 || sname == NULL)
		return (rc);

	tmp_node = *ret_snode;
	rc = smb_fsop_lookup_stream(sr, cr, flags, root_node, tmp_node, sname,
	    ret_snode);
	kmem_free(sname, MAXNAMELEN);
	smb_node_release(tmp_node);

	return (rc);
}

/*
 * smb_fsop_lookup_file()
 *
 * Look up of the file portion of 'name'. If a Stream is specified,
 * return the stream name in 'sname', which this allocates.
 * The caller must free 'sname'.
 *
 * Return an error if the looked-up file is outside the tree.
 * (Required when invoked from open path.)
 *
 * Case sensitivity flags (SMB_IGNORE_CASE, SMB_CASE_SENSITIVE):
 * if SMB_CASE_SENSITIVE is set, the SMB_IGNORE_CASE flag will NOT be set
 * based on the tree's case sensitivity. However, if the SMB_IGNORE_CASE
 * flag is set in the flags value passed as a parameter, a case insensitive
 * lookup WILL be done (regardless of whether SMB_CASE_SENSITIVE is set
 * or not).
 */

int
smb_fsop_lookup_file(
    smb_request_t *sr,
    cred_t	*cr,
    int		flags,
    smb_node_t	*root_node,
    smb_node_t	*dnode,
    char	*name,
    char	**sname,
    smb_node_t	**ret_snode)
{
	char		*fname;
	int		rc;

	ASSERT(cr);
	ASSERT(dnode);
	ASSERT(dnode->n_magic == SMB_NODE_MAGIC);
	ASSERT(dnode->n_state != SMB_NODE_STATE_DESTROYING);
	ASSERT(ret_snode != NULL);

	/*
	 * The following check is required for streams processing, below
	 */

	if (!(flags & SMB_CASE_SENSITIVE)) {
		if (SMB_TREE_IS_CASEINSENSITIVE(sr))
			flags |= SMB_IGNORE_CASE;
	}

	*sname = NULL;
	if (smb_is_stream_name(name)) {
		*sname = kmem_alloc(MAXNAMELEN, KM_SLEEP);
		fname = kmem_alloc(MAXNAMELEN, KM_SLEEP);
		smb_stream_parse_name(name, fname, *sname);

		/*
		 * Look up the unnamed stream (i.e. fname).
		 * Unmangle processing will be done on fname
		 * as well as any link target.
		 */
		rc = smb_fsop_lookup(sr, cr, flags, root_node, dnode,
		    fname, ret_snode);
		kmem_free(fname, MAXNAMELEN);
	} else {
		rc = smb_fsop_lookup(sr, cr, flags, root_node, dnode, name,
		    ret_snode);
	}

	if (rc == 0) {
		ASSERT(ret_snode);
		if (SMB_TREE_CONTAINS_NODE(sr, *ret_snode) == 0) {
			smb_node_release(*ret_snode);
			*ret_snode = NULL;
			rc = EACCES;
		}
	}

	if (rc != 0 && *sname != NULL) {
		kmem_free(*sname, MAXNAMELEN);
		*sname = NULL;
	}
	return (rc);
}

/*
 * smb_fsop_lookup_stream
 *
 * The file exists, see if the stream exists.
 */
int
smb_fsop_lookup_stream(
    smb_request_t *sr,
    cred_t *cr,
    int flags,
    smb_node_t *root_node,
    smb_node_t *fnode,
    char *sname,
    smb_node_t **ret_snode)
{
	char		*od_name;
	vnode_t		*xattrdirvp;
	vnode_t		*vp;
	int rc;

	/*
	 * The following check is required for streams processing, below
	 */

	if (!(flags & SMB_CASE_SENSITIVE)) {
		if (SMB_TREE_IS_CASEINSENSITIVE(sr))
			flags |= SMB_IGNORE_CASE;
	}

	od_name = kmem_alloc(MAXNAMELEN, KM_SLEEP);

	/*
	 * od_name is the on-disk name of the stream, except
	 * without the prepended stream prefix (SMB_STREAM_PREFIX)
	 */

	rc = smb_vop_stream_lookup(fnode->vp, sname, &vp, od_name,
	    &xattrdirvp, flags, root_node->vp, cr);

	if (rc != 0) {
		kmem_free(od_name, MAXNAMELEN);
		return (rc);
	}

	*ret_snode = smb_stream_node_lookup(sr, cr, fnode, xattrdirvp,
	    vp, od_name);

	kmem_free(od_name, MAXNAMELEN);
	VN_RELE(xattrdirvp);
	VN_RELE(vp);

	if (*ret_snode == NULL)
		return (ENOMEM);

	return (rc);
}

/*
 * smb_fsop_lookup
 *
 * All SMB functions should use this smb_vop_lookup wrapper to ensure that
 * the smb_vop_lookup is performed with the appropriate credentials and using
 * case insensitive compares. Please document any direct call to smb_vop_lookup
 * to explain the reason for avoiding this wrapper.
 *
 * It is assumed that a reference exists on dnode coming into this routine
 * (and that it is safe from deallocation).
 *
 * Same with the root_node.
 *
 * *ret_snode is returned with a reference upon success.  No reference is
 * taken if an error is returned.
 *
 * Note: The returned ret_snode may be in a child mount.  This is ok for
 * readdir.
 *
 * Other smb_fsop_* routines will call SMB_TREE_CONTAINS_NODE() to prevent
 * operations on files not in the parent mount.
 *
 * Case sensitivity flags (SMB_IGNORE_CASE, SMB_CASE_SENSITIVE):
 * if SMB_CASE_SENSITIVE is set, the SMB_IGNORE_CASE flag will NOT be set
 * based on the tree's case sensitivity. However, if the SMB_IGNORE_CASE
 * flag is set in the flags value passed as a parameter, a case insensitive
 * lookup WILL be done (regardless of whether SMB_CASE_SENSITIVE is set
 * or not).
 */
int
smb_fsop_lookup(
    smb_request_t *sr,
    cred_t	*cr,
    int		flags,
    smb_node_t	*root_node,
    smb_node_t	*dnode,
    char	*name,
    smb_node_t	**ret_snode)
{
	smb_node_t *lnk_target_node;
	smb_node_t *lnk_dnode;
	char *longname;
	char *od_name;
	vnode_t *vp;
	int rc;
	int ret_flags;
	smb_attr_t attr;

	ASSERT(cr);
	ASSERT(dnode);
	ASSERT(dnode->n_magic == SMB_NODE_MAGIC);
	ASSERT(dnode->n_state != SMB_NODE_STATE_DESTROYING);

	if (name == NULL)
		return (EINVAL);

	if (SMB_TREE_CONTAINS_NODE(sr, dnode) == 0)
		return (EACCES);

	if (!(flags & SMB_CASE_SENSITIVE)) {
		if (SMB_TREE_IS_CASEINSENSITIVE(sr))
			flags |= SMB_IGNORE_CASE;
	}
	if (SMB_TREE_SUPPORTS_CATIA(sr))
		flags |= SMB_CATIA;
	if (SMB_TREE_SUPPORTS_ABE(sr))
		flags |= SMB_ABE;

	/*
	 * Can have "" or "." when opening named streams on a directory.
	 */
	if (name[0] == '\0' || (name[0] == '.' && name[1] == '\0')) {
		smb_node_ref(dnode);
		*ret_snode = dnode;
		return (0);
	}

	od_name = kmem_alloc(MAXNAMELEN, KM_SLEEP);

	rc = smb_vop_lookup(dnode->vp, name, &vp, od_name, flags,
	    &ret_flags, root_node ? root_node->vp : NULL, &attr, cr);

	if (rc != 0) {
		if (!SMB_TREE_SUPPORTS_SHORTNAMES(sr) ||
		    !smb_maybe_mangled(name)) {
			kmem_free(od_name, MAXNAMELEN);
			return (rc);
		}

		longname = kmem_alloc(MAXNAMELEN, KM_SLEEP);
		rc = smb_unmangle(dnode, name, longname, MAXNAMELEN, flags);
		if (rc != 0) {
			kmem_free(od_name, MAXNAMELEN);
			kmem_free(longname, MAXNAMELEN);
			return (rc);
		}

		/*
		 * longname is the real (case-sensitive)
		 * on-disk name.
		 * We make sure we do a lookup on this exact
		 * name, as the name was mangled and denotes
		 * a unique file.
		 */

		if (flags & SMB_IGNORE_CASE)
			flags &= ~SMB_IGNORE_CASE;

		rc = smb_vop_lookup(dnode->vp, longname, &vp, od_name,
		    flags, &ret_flags, root_node ? root_node->vp : NULL, &attr,
		    cr);

		kmem_free(longname, MAXNAMELEN);

		if (rc != 0) {
			kmem_free(od_name, MAXNAMELEN);
			return (rc);
		}
	}

	if ((flags & SMB_FOLLOW_LINKS) && (vp->v_type == VLNK) &&
	    ((attr.sa_dosattr & FILE_ATTRIBUTE_REPARSE_POINT) == 0)) {
		rc = smb_pathname(sr, od_name, FOLLOW, root_node, dnode,
		    &lnk_dnode, &lnk_target_node, cr, NULL);

		if (rc != 0) {
			/*
			 * The link is assumed to be for the last component
			 * of a path.  Hence any ENOTDIR error will be returned
			 * as ENOENT.
			 */
			if (rc == ENOTDIR)
				rc = ENOENT;

			VN_RELE(vp);
			kmem_free(od_name, MAXNAMELEN);
			return (rc);
		}

		/*
		 * Release the original VLNK vnode
		 */

		VN_RELE(vp);
		vp = lnk_target_node->vp;

		rc = smb_vop_traverse_check(&vp);

		if (rc != 0) {
			smb_node_release(lnk_dnode);
			smb_node_release(lnk_target_node);
			kmem_free(od_name, MAXNAMELEN);
			return (rc);
		}

		/*
		 * smb_vop_traverse_check() may have returned a different vnode
		 */

		if (lnk_target_node->vp == vp) {
			*ret_snode = lnk_target_node;
		} else {
			*ret_snode = smb_node_lookup(sr, NULL, cr, vp,
			    lnk_target_node->od_name, lnk_dnode, NULL);
			VN_RELE(vp);

			if (*ret_snode == NULL)
				rc = ENOMEM;
			smb_node_release(lnk_target_node);
		}

		smb_node_release(lnk_dnode);

	} else {

		rc = smb_vop_traverse_check(&vp);
		if (rc) {
			VN_RELE(vp);
			kmem_free(od_name, MAXNAMELEN);
			return (rc);
		}

		*ret_snode = smb_node_lookup(sr, NULL, cr, vp, od_name,
		    dnode, NULL);
		VN_RELE(vp);

		if (*ret_snode == NULL)
			rc = ENOMEM;
	}

	kmem_free(od_name, MAXNAMELEN);
	return (rc);
}

int /*ARGSUSED*/
smb_fsop_commit(smb_request_t *sr, cred_t *cr, smb_node_t *snode)
{
	ASSERT(cr);
	ASSERT(snode);
	ASSERT(snode->n_magic == SMB_NODE_MAGIC);
	ASSERT(snode->n_state != SMB_NODE_STATE_DESTROYING);

	ASSERT(sr);
	ASSERT(sr->tid_tree);
	if (SMB_TREE_IS_READONLY(sr))
		return (EROFS);

	return (smb_vop_commit(snode->vp, cr));
}

/*
 * smb_fsop_aclread
 *
 * Retrieve filesystem ACL. Depends on requested ACLs in
 * fs_sd->sd_secinfo, it'll set DACL and SACL pointers in
 * fs_sd. Note that requesting a DACL/SACL doesn't mean that
 * the corresponding field in fs_sd should be non-NULL upon
 * return, since the target ACL might not contain that type of
 * entries.
 *
 * Returned ACL is always in ACE_T (aka ZFS) format.
 * If successful the allocated memory for the ACL should be freed
 * using smb_fsacl_free() or smb_fssd_term()
 */
int
smb_fsop_aclread(smb_request_t *sr, cred_t *cr, smb_node_t *snode,
    smb_fssd_t *fs_sd)
{
	int error = 0;
	int flags = 0;
	int access = 0;
	acl_t *acl;

	ASSERT(cr);

	/* Can't query security on named streams */
	if (SMB_IS_STREAM(snode) != NULL)
		return (EINVAL);

	if (SMB_TREE_HAS_ACCESS(sr, ACE_READ_ACL) == 0)
		return (EACCES);

	if (sr->fid_ofile) {
		if (fs_sd->sd_secinfo & SMB_DACL_SECINFO)
			access = READ_CONTROL;

		if (fs_sd->sd_secinfo & SMB_SACL_SECINFO)
			access |= ACCESS_SYSTEM_SECURITY;

		error = smb_ofile_access(sr->fid_ofile, cr, access);
		if (error != NT_STATUS_SUCCESS) {
			return (EACCES);
		}
	}


	if (smb_tree_has_feature(sr->tid_tree, SMB_TREE_ACEMASKONACCESS))
		flags = ATTR_NOACLCHECK;

	error = smb_vop_acl_read(snode->vp, &acl, flags,
	    sr->tid_tree->t_acltype, cr);
	if (error != 0) {
		return (error);
	}

	error = acl_translate(acl, _ACL_ACE_ENABLED,
	    smb_node_is_dir(snode), fs_sd->sd_uid, fs_sd->sd_gid);

	if (error == 0) {
		smb_fsacl_split(acl, &fs_sd->sd_zdacl, &fs_sd->sd_zsacl,
		    fs_sd->sd_secinfo);
	}

	acl_free(acl);
	return (error);
}

/*
 * smb_fsop_aclwrite
 *
 * Stores the filesystem ACL provided in fs_sd->sd_acl.
 */
int
smb_fsop_aclwrite(smb_request_t *sr, cred_t *cr, smb_node_t *snode,
    smb_fssd_t *fs_sd)
{
	int target_flavor;
	int error = 0;
	int flags = 0;
	int access = 0;
	acl_t *acl, *dacl, *sacl;

	ASSERT(cr);

	ASSERT(sr);
	ASSERT(sr->tid_tree);
	if (SMB_TREE_IS_READONLY(sr))
		return (EROFS);

	/* Can't set security on named streams */
	if (SMB_IS_STREAM(snode) != NULL)
		return (EINVAL);

	if (SMB_TREE_HAS_ACCESS(sr, ACE_WRITE_ACL) == 0)
		return (EACCES);

	if (sr->fid_ofile) {
		if (fs_sd->sd_secinfo & SMB_DACL_SECINFO)
			access = WRITE_DAC;

		if (fs_sd->sd_secinfo & SMB_SACL_SECINFO)
			access |= ACCESS_SYSTEM_SECURITY;

		error = smb_ofile_access(sr->fid_ofile, cr, access);
		if (error != NT_STATUS_SUCCESS)
			return (EACCES);
	}

	switch (sr->tid_tree->t_acltype) {
	case ACLENT_T:
		target_flavor = _ACL_ACLENT_ENABLED;
		break;

	case ACE_T:
		target_flavor = _ACL_ACE_ENABLED;
		break;
	default:
		return (EINVAL);
	}

	dacl = fs_sd->sd_zdacl;
	sacl = fs_sd->sd_zsacl;

	ASSERT(dacl || sacl);
	if ((dacl == NULL) && (sacl == NULL))
		return (EINVAL);

	if (dacl && sacl)
		acl = smb_fsacl_merge(dacl, sacl);
	else if (dacl)
		acl = dacl;
	else
		acl = sacl;

	error = acl_translate(acl, target_flavor, smb_node_is_dir(snode),
	    fs_sd->sd_uid, fs_sd->sd_gid);
	if (error == 0) {
		if (smb_tree_has_feature(sr->tid_tree,
		    SMB_TREE_ACEMASKONACCESS))
			flags = ATTR_NOACLCHECK;

		error = smb_vop_acl_write(snode->vp, acl, flags, cr);
		if (error == 0 && snode->n_dnode != NULL) {
			// FILE_NOTIFY_CHANGE_SECURITY
			smb_node_notify_change(snode->n_dnode,
			    FILE_ACTION_MODIFIED, snode->od_name);
		}
	}

	if (dacl && sacl)
		acl_free(acl);

	return (error);
}

acl_type_t
smb_fsop_acltype(smb_node_t *snode)
{
	return (smb_vop_acl_type(snode->vp));
}

/*
 * smb_fsop_sdread
 *
 * Read the requested security descriptor items from filesystem.
 * The items are specified in fs_sd->sd_secinfo.
 */
int
smb_fsop_sdread(smb_request_t *sr, cred_t *cr, smb_node_t *snode,
    smb_fssd_t *fs_sd)
{
	int error = 0;
	int getowner = 0;
	cred_t *ga_cred;
	smb_attr_t attr;

	ASSERT(cr);
	ASSERT(fs_sd);

	/* Can't query security on named streams */
	if (SMB_IS_STREAM(snode) != NULL)
		return (EINVAL);

	/*
	 * File's uid/gid is fetched in two cases:
	 *
	 * 1. it's explicitly requested
	 *
	 * 2. target ACL is ACE_T (ZFS ACL). They're needed for
	 *    owner@/group@ entries. In this case kcred should be used
	 *    because uid/gid are fetched on behalf of smb server.
	 */
	if (fs_sd->sd_secinfo & (SMB_OWNER_SECINFO | SMB_GROUP_SECINFO)) {
		getowner = 1;
		ga_cred = cr;
	} else if (sr->tid_tree->t_acltype == ACE_T) {
		getowner = 1;
		ga_cred = zone_kcred();
	}

	if (getowner) {
		/*
		 * Windows require READ_CONTROL to read owner/group SID since
		 * they're part of Security Descriptor.
		 * ZFS only requires read_attribute. Need to have a explicit
		 * access check here.
		 */
		if (sr->fid_ofile == NULL) {
			error = smb_fsop_access(sr, ga_cred, snode,
			    READ_CONTROL);
			if (error)
				return (EACCES);
		}

		attr.sa_mask = SMB_AT_UID | SMB_AT_GID;
		error = smb_fsop_getattr(sr, ga_cred, snode, &attr);
		if (error == 0) {
			fs_sd->sd_uid = attr.sa_vattr.va_uid;
			fs_sd->sd_gid = attr.sa_vattr.va_gid;
		} else {
			return (error);
		}
	}

	if (fs_sd->sd_secinfo & SMB_ACL_SECINFO) {
		error = smb_fsop_aclread(sr, cr, snode, fs_sd);
	}

	return (error);
}

/*
 * smb_fsop_sdmerge
 *
 * From SMB point of view DACL and SACL are two separate list
 * which can be manipulated independently without one affecting
 * the other, but entries for both DACL and SACL will end up
 * in the same ACL if target filesystem supports ACE_T ACLs.
 *
 * So, if either DACL or SACL is present in the client set request
 * the entries corresponding to the non-present ACL shouldn't
 * be touched in the FS ACL.
 *
 * fs_sd parameter contains DACL and SACL specified by SMB
 * client to be set on a file/directory. The client could
 * specify both or one of these ACLs (if none is specified
 * we don't get this far). When both DACL and SACL are given
 * by client the existing ACL should be overwritten. If only
 * one of them is specified the entries corresponding to the other
 * ACL should not be touched. For example, if only DACL
 * is specified in input fs_sd, the function reads audit entries
 * of the existing ACL of the file and point fs_sd->sd_zsdacl
 * pointer to the fetched SACL, this way when smb_fsop_sdwrite()
 * function is called the passed fs_sd would point to the specified
 * DACL by client and fetched SACL from filesystem, so the file
 * will end up with correct ACL.
 */
static int
smb_fsop_sdmerge(smb_request_t *sr, smb_node_t *snode, smb_fssd_t *fs_sd)
{
	smb_fssd_t cur_sd;
	cred_t *kcr = zone_kcred();
	int error = 0;

	if (sr->tid_tree->t_acltype != ACE_T)
		/* Don't bother if target FS doesn't support ACE_T */
		return (0);

	if ((fs_sd->sd_secinfo & SMB_ACL_SECINFO) != SMB_ACL_SECINFO) {
		if (fs_sd->sd_secinfo & SMB_DACL_SECINFO) {
			/*
			 * Don't overwrite existing audit entries
			 */
			smb_fssd_init(&cur_sd, SMB_SACL_SECINFO,
			    fs_sd->sd_flags);

			error = smb_fsop_sdread(sr, kcr, snode, &cur_sd);
			if (error == 0) {
				ASSERT(fs_sd->sd_zsacl == NULL);
				fs_sd->sd_zsacl = cur_sd.sd_zsacl;
				if (fs_sd->sd_zsacl && fs_sd->sd_zdacl)
					fs_sd->sd_zsacl->acl_flags =
					    fs_sd->sd_zdacl->acl_flags;
			}
		} else {
			/*
			 * Don't overwrite existing access entries
			 */
			smb_fssd_init(&cur_sd, SMB_DACL_SECINFO,
			    fs_sd->sd_flags);

			error = smb_fsop_sdread(sr, kcr, snode, &cur_sd);
			if (error == 0) {
				ASSERT(fs_sd->sd_zdacl == NULL);
				fs_sd->sd_zdacl = cur_sd.sd_zdacl;
				if (fs_sd->sd_zdacl && fs_sd->sd_zsacl)
					fs_sd->sd_zdacl->acl_flags =
					    fs_sd->sd_zsacl->acl_flags;
			}
		}

		if (error)
			smb_fssd_term(&cur_sd);
	}

	return (error);
}

/*
 * smb_fsop_sdwrite
 *
 * Stores the given uid, gid and acl in filesystem.
 * Provided items in fs_sd are specified by fs_sd->sd_secinfo.
 *
 * A SMB security descriptor could contain owner, primary group,
 * DACL and SACL. Setting an SD should be atomic but here it has to
 * be done via two separate FS operations: VOP_SETATTR and
 * VOP_SETSECATTR. Therefore, this function has to simulate the
 * atomicity as well as it can.
 *
 * Get the current uid, gid before setting the new uid/gid
 * so if smb_fsop_aclwrite fails they can be restored. root cred is
 * used to get currend uid/gid since this operation is performed on
 * behalf of the server not the user.
 *
 * If setting uid/gid fails with EPERM it means that and invalid
 * owner has been specified. Callers should translate this to
 * STATUS_INVALID_OWNER which is not the normal mapping for EPERM
 * in upper layers, so EPERM is mapped to EBADE.
 *
 * If 'overwrite' is non-zero, then the existing ACL is ignored.
 */
int
smb_fsop_sdwrite(smb_request_t *sr, cred_t *cr, smb_node_t *snode,
    smb_fssd_t *fs_sd, int overwrite)
{
	smb_attr_t set_attr;
	smb_attr_t orig_attr;
	cred_t *kcr = zone_kcred();
	int error = 0;
	int access = 0;

	ASSERT(cr);
	ASSERT(fs_sd);

	ASSERT(sr);
	ASSERT(sr->tid_tree);
	if (SMB_TREE_IS_READONLY(sr))
		return (EROFS);

	/* Can't set security on named streams */
	if (SMB_IS_STREAM(snode) != NULL)
		return (EINVAL);

	bzero(&set_attr, sizeof (smb_attr_t));

	if (fs_sd->sd_secinfo & SMB_OWNER_SECINFO) {
		set_attr.sa_vattr.va_uid = fs_sd->sd_uid;
		set_attr.sa_mask |= SMB_AT_UID;
		access |= WRITE_OWNER;
	}

	if (fs_sd->sd_secinfo & SMB_GROUP_SECINFO) {
		set_attr.sa_vattr.va_gid = fs_sd->sd_gid;
		set_attr.sa_mask |= SMB_AT_GID;
		access |= WRITE_OWNER;
	}

	if (fs_sd->sd_secinfo & SMB_DACL_SECINFO)
		access |= WRITE_DAC;

	if (fs_sd->sd_secinfo & SMB_SACL_SECINFO)
		access |= ACCESS_SYSTEM_SECURITY;

	if (sr->fid_ofile)
		error = smb_ofile_access(sr->fid_ofile, cr, access);
	else
		error = smb_fsop_access(sr, cr, snode, access);

	if (error)
		return (EACCES);

	if (set_attr.sa_mask) {
		orig_attr.sa_mask = SMB_AT_UID | SMB_AT_GID;
		error = smb_fsop_getattr(sr, kcr, snode, &orig_attr);
		if (error == 0) {
			error = smb_fsop_setattr(sr, cr, snode, &set_attr);
			if (error == EPERM)
				error = EBADE;
		}

		if (error)
			return (error);
	}

	if (fs_sd->sd_secinfo & SMB_ACL_SECINFO) {
		if (overwrite == 0)
			error = smb_fsop_sdmerge(sr, snode, fs_sd);

		if (error == 0)
			error = smb_fsop_aclwrite(sr, cr, snode, fs_sd);

		if (error != 0) {
			/*
			 * Revert uid/gid changes if required.
			 */
			if (set_attr.sa_mask) {
				orig_attr.sa_mask = set_attr.sa_mask;
				(void) smb_fsop_setattr(sr, kcr, snode,
				    &orig_attr);
			}
		}
	}

	return (error);
}

#ifdef	_KERNEL
/*
 * smb_fsop_sdinherit
 *
 * Inherit the security descriptor from the parent container.
 * This function is called after FS has created the file/folder
 * so if this doesn't do anything it means FS inheritance is
 * in place.
 *
 * Do inheritance for ZFS internally.
 *
 * If we want to let ZFS does the inheritance the
 * following setting should be true:
 *
 *  - aclinherit = passthrough
 *  - aclmode = passthrough
 *  - smbd umask = 0777
 *
 * This will result in right effective permissions but
 * ZFS will always add 6 ACEs for owner, owning group
 * and others to be POSIX compliant. This is not what
 * Windows clients/users expect, so we decided that CIFS
 * implements Windows rules and overwrite whatever ZFS
 * comes up with. This way we also don't have to care
 * about ZFS aclinherit and aclmode settings.
 */
static int
smb_fsop_sdinherit(smb_request_t *sr, smb_node_t *dnode, smb_fssd_t *fs_sd)
{
	acl_t *dacl = NULL;
	acl_t *sacl = NULL;
	int is_dir;
	int error;
	uint32_t secinfo;
	smb_fssd_t pfs_sd;

	ASSERT(fs_sd);

	secinfo = fs_sd->sd_secinfo;

	/* Anything to do? */
	if ((secinfo & SMB_ACL_SECINFO) == SMB_ACL_SECINFO)
		return (0);

	/*
	 * No forced inheritance for non-ZFS filesystems.
	 */
	if (sr->tid_tree->t_acltype != ACE_T)
		return (0);

	smb_fssd_init(&pfs_sd, SMB_ACL_SECINFO, fs_sd->sd_flags);

	/* Fetch parent directory's ACL */
	error = smb_fsop_sdread(sr, zone_kcred(), dnode, &pfs_sd);
	if (error) {
		return (error);
	}

	is_dir = (fs_sd->sd_flags & SMB_FSSD_FLAGS_DIR);
	if ((secinfo & SMB_DACL_SECINFO) == 0) {
		dacl = smb_fsacl_inherit(pfs_sd.sd_zdacl, is_dir,
		    SMB_DACL_SECINFO, sr->user_cr);
		fs_sd->sd_zdacl = dacl;
	}

	if ((secinfo & SMB_SACL_SECINFO) == 0) {
		sacl = smb_fsacl_inherit(pfs_sd.sd_zsacl, is_dir,
		    SMB_SACL_SECINFO, sr->user_cr);
		fs_sd->sd_zsacl = sacl;
	}

	smb_fsacl_free(pfs_sd.sd_zdacl);
	smb_fsacl_free(pfs_sd.sd_zsacl);
	return (0);
}
#endif	/* _KERNEL */

/*
 * smb_fsop_eaccess
 *
 * Returns the effective permission of the given credential for the
 * specified object.
 *
 * This is just a workaround. We need VFS/FS support for this.
 */
void
smb_fsop_eaccess(smb_request_t *sr, cred_t *cr, smb_node_t *snode,
    uint32_t *eaccess)
{
	int access = 0;
	vnode_t *dir_vp;
	smb_node_t *unnamed_node;

	ASSERT(cr);
	ASSERT(snode);
	ASSERT(snode->n_magic == SMB_NODE_MAGIC);
	ASSERT(snode->n_state != SMB_NODE_STATE_DESTROYING);

	unnamed_node = SMB_IS_STREAM(snode);
	if (unnamed_node) {
		ASSERT(unnamed_node->n_magic == SMB_NODE_MAGIC);
		ASSERT(unnamed_node->n_state != SMB_NODE_STATE_DESTROYING);
		/*
		 * Streams authorization should be performed against the
		 * unnamed stream.
		 */
		snode = unnamed_node;
	}

	if (smb_tree_has_feature(sr->tid_tree, SMB_TREE_ACEMASKONACCESS)) {
		dir_vp = (snode->n_dnode) ? snode->n_dnode->vp : NULL;
		smb_vop_eaccess(snode->vp, (int *)eaccess, V_ACE_MASK, dir_vp,
		    cr);
		return;
	}

	/*
	 * FS doesn't understand 32-bit mask
	 */
	smb_vop_eaccess(snode->vp, &access, 0, NULL, cr);
	access &= sr->tid_tree->t_access;

	*eaccess = READ_CONTROL | FILE_READ_EA | FILE_READ_ATTRIBUTES;

	if (access & VREAD)
		*eaccess |= FILE_READ_DATA;

	if (access & VEXEC)
		*eaccess |= FILE_EXECUTE;

	if (access & VWRITE)
		*eaccess |= FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES |
		    FILE_WRITE_EA | FILE_APPEND_DATA | FILE_DELETE_CHILD;

	if (access & (VREAD | VWRITE))
		*eaccess |= SYNCHRONIZE;

#ifdef	_FAKE_KERNEL
	/* Should be: if (we are the owner)... */
	if (access & VWRITE)
		*eaccess |= DELETE | WRITE_DAC | WRITE_OWNER;
#endif
}

/*
 * smb_fsop_shrlock
 *
 * For the current open request, check file sharing rules
 * against existing opens.
 *
 * Returns NT_STATUS_SHARING_VIOLATION if there is any
 * sharing conflict.  Returns NT_STATUS_SUCCESS otherwise.
 *
 * Full system-wide share reservation synchronization is available
 * when the nbmand (non-blocking mandatory) mount option is set
 * (i.e. nbl_need_crit() is true) and nbmand critical regions are used.
 * This provides synchronization with NFS and local processes.  The
 * critical regions are entered in VOP_SHRLOCK()/fs_shrlock() (called
 * from smb_open_subr()/smb_fsop_shrlock()/smb_vop_shrlock()) as well
 * as the CIFS rename and delete paths.
 *
 * The CIFS server will also enter the nbl critical region in the open,
 * rename, and delete paths when nbmand is not set.  There is limited
 * coordination with local and VFS share reservations in this case.
 * Note that when the nbmand mount option is not set, the VFS layer
 * only processes advisory reservations and the delete mode is not checked.
 *
 * Whether or not the nbmand mount option is set, intra-CIFS share
 * checking is done in the open, delete, and rename paths using a CIFS
 * critical region (node->n_share_lock).
 */
uint32_t
smb_fsop_shrlock(cred_t *cr, smb_node_t *node, uint32_t uniq_fid,
    uint32_t desired_access, uint32_t share_access)
{
	int rc;

	/* Allow access if the request is just for meta data */
	if ((desired_access & FILE_DATA_ALL) == 0)
		return (NT_STATUS_SUCCESS);

	rc = smb_node_open_check(node, desired_access, share_access);
	if (rc)
		return (NT_STATUS_SHARING_VIOLATION);

	rc = smb_vop_shrlock(node->vp, uniq_fid, desired_access, share_access,
	    cr);
	if (rc)
		return (NT_STATUS_SHARING_VIOLATION);

	return (NT_STATUS_SUCCESS);
}

void
smb_fsop_unshrlock(cred_t *cr, smb_node_t *node, uint32_t uniq_fid)
{
	(void) smb_vop_unshrlock(node->vp, uniq_fid, cr);
}

int
smb_fsop_frlock(smb_node_t *node, smb_lock_t *lock, boolean_t unlock,
    cred_t *cr)
{
	flock64_t bf;
	int flag = F_REMOTELOCK;

	/*
	 * VOP_FRLOCK() will not be called if:
	 *
	 * 1) The lock has a range of zero bytes. The semantics of Windows and
	 *    POSIX are different. In the case of POSIX it asks for the locking
	 *    of all the bytes from the offset provided until the end of the
	 *    file. In the case of Windows a range of zero locks nothing and
	 *    doesn't conflict with any other lock.
	 *
	 * 2) The lock rolls over (start + lenght < start). Solaris will assert
	 *    if such a request is submitted. This will not create
	 *    incompatibilities between POSIX and Windows. In the Windows world,
	 *    if a client submits such a lock, the server will not lock any
	 *    bytes. Interestingly if the same lock (same offset and length) is
	 *    resubmitted Windows will consider that there is an overlap and
	 *    the granting rules will then apply.
	 *
	 * 3) The SMB-level process IDs (smb_pid) are not passed down to the
	 *    POSIX level in l_pid because (a) the rules about lock PIDs are
	 *    different in SMB, and (b) we're putting our ofile f_uniqid in
	 *    the POSIX l_pid field to segregate locks per SMB ofile.
	 *    (We're also using a "remote" system ID in l_sysid.)
	 *    All SMB locking PIDs are handled at the SMB level and
	 *    not exposed in POSIX locking.
	 */
	if ((lock->l_length == 0) ||
	    ((lock->l_start + lock->l_length - 1) < lock->l_start))
		return (0);

	bzero(&bf, sizeof (bf));

	if (unlock) {
		bf.l_type = F_UNLCK;
	} else if (lock->l_type == SMB_LOCK_TYPE_READONLY) {
		bf.l_type = F_RDLCK;
		flag |= FREAD;
	} else if (lock->l_type == SMB_LOCK_TYPE_READWRITE) {
		bf.l_type = F_WRLCK;
		flag |= FWRITE;
	}

	bf.l_start = lock->l_start;
	bf.l_len = lock->l_length;
	bf.l_pid = lock->l_file->f_uniqid;
	bf.l_sysid = smb_ct.cc_sysid;

	return (smb_vop_frlock(node->vp, cr, flag, &bf));
}
