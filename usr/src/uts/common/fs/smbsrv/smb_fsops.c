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

#include <sys/sid.h>
#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_fsops.h>
#include <acl/acl_common.h>

u_longlong_t smb_caller_id;

static int smb_fsop_amask_to_omode(uint32_t granted_access);

extern uint32_t smb_sd_tofs(smb_sdbuf_t *sr_sd, smb_fssd_t *fs_sd);

extern uint32_t smb_sd_write(smb_request_t *sr, smb_sdbuf_t *sr_sd,
    uint32_t secinfo);

extern int smb_vop_acl_to_vsa(acl_t *acl_info, vsecattr_t *vsecattr,
    int *aclbsize);

static int smb_fsop_sdinherit(smb_request_t *sr, smb_node_t *dnode,
    smb_fssd_t *fs_sd);

static void smb_fsop_aclsplit(acl_t *zacl, acl_t **dacl, acl_t **sacl,
    int which_acl);
static acl_t *smb_fsop_aclmerge(acl_t *dacl, acl_t *sacl);

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

int
smb_fsop_start()
{
	int error;

	smb_caller_id = fs_new_caller_id();
	error = smb_node_root_init();

	if (error == 0)
		error = smb_fem_init();

	return (error);
}

void
smb_fsop_stop()
{
	smb_fem_shutdown();
	smb_vfs_rele_all();
	smb_node_root_fini();
}

int
smb_fsop_open(smb_ofile_t *of)
{
	caller_context_t ct;
	int mode;

	mode = smb_fsop_amask_to_omode(of->f_granted_access);

	smb_get_caller_context(NULL, &ct);

	/*
	 * Assuming that same vnode is returned as we had before
	 * (i.e. no special vnodes)
	 */

	return (smb_vop_open(&of->f_node->vp, mode, of->f_cr, &ct));
}

int
smb_fsop_close(smb_ofile_t *of)
{
	caller_context_t ct;
	int mode;

	mode = smb_fsop_amask_to_omode(of->f_granted_access);

	smb_get_caller_context(NULL, &ct);

	return (smb_vop_close(of->f_node->vp, mode, of->f_cr, &ct));
}

static int
smb_fsop_amask_to_omode(uint32_t granted_access)
{
	int mode = 0;

	if (granted_access & (ACE_READ_DATA | ACE_EXECUTE))
		mode |= FREAD;

	if (granted_access & (ACE_WRITE_DATA | ACE_APPEND_DATA))
		mode |= FWRITE;

	if (granted_access & ACE_APPEND_DATA)
		mode |= FAPPEND;

	return (mode);
}

static int
smb_fsop_create_with_sd(
	struct smb_request *sr,
	cred_t *cr,
	smb_node_t *snode,
	char *name,
	smb_attr_t *attr,
	smb_node_t **ret_snode,
	smb_attr_t *ret_attr,
	smb_fssd_t *fs_sd)
{
	caller_context_t ct;
	vsecattr_t *vsap;
	vsecattr_t vsecattr;
	acl_t *acl, *dacl, *sacl;
	smb_attr_t set_attr;
	vnode_t *vp;
	int aclbsize = 0;	/* size of acl list in bytes */
	int flags = 0;
	int is_dir;
	int rc;

	ASSERT(fs_sd);

	if (SMB_TREE_CASE_INSENSITIVE(sr))
		flags = SMB_IGNORE_CASE;

	ASSERT(cr);
	smb_get_caller_context(sr, &ct);

	is_dir = ((fs_sd->sd_flags & SMB_FSSD_FLAGS_DIR) != 0);

	if (sr->tid_tree->t_flags & SMB_TREE_FLAG_ACLONCREATE) {
		if (fs_sd->sd_secinfo & SMB_ACL_SECINFO) {
			dacl = fs_sd->sd_zdacl;
			sacl = fs_sd->sd_zsacl;
			ASSERT(dacl || sacl);
			if (dacl && sacl) {
				acl = smb_fsop_aclmerge(dacl, sacl);
			} else if (dacl) {
				acl = dacl;
			} else {
				acl = sacl;
			}

			rc = smb_vop_acl_to_vsa(acl, &vsecattr, &aclbsize);

			if (dacl && sacl)
				acl_free(acl);

			if (rc)
				return (rc);

			vsap = &vsecattr;
		}
		else
			vsap = NULL;

		if (is_dir) {
			rc = smb_vop_mkdir(snode->vp, name, attr, &vp, flags,
			    cr, &ct, vsap);
		} else {
			rc = smb_vop_create(snode->vp, name, attr, &vp, flags,
			    cr, &ct, vsap);
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

		if (set_attr.sa_mask) {
			rc = smb_vop_setattr(snode->vp, NULL, &set_attr,
			    0, kcred, &ct);
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
			rc = smb_vop_mkdir(snode->vp, name, attr, &vp, flags,
			    cr, &ct, NULL);
		} else {
			rc = smb_vop_create(snode->vp, name, attr, &vp, flags,
			    cr, &ct, NULL);
		}

		if (rc == 0)
			rc = smb_fsop_sdwrite(sr, kcred, snode, fs_sd, 1);
	}

	if (rc == 0) {
		*ret_snode = smb_node_lookup(sr, &sr->arg.open, cr, vp, name,
		    snode, NULL, ret_attr);

		if (*ret_snode == NULL) {
			VN_RELE(vp);
			rc = ENOMEM;
		}
	}

	return (rc);
}


/*
 * smb_fsop_create
 *
 * All SMB functions should use this wrapper to ensure that
 * all the smb_vop_creates are performed with the appropriate credentials.
 * Please document any direct calls to explain the reason
 * for avoiding this wrapper.
 *
 * It is assumed that a reference exists on snode coming into this routine.
 *
 * *ret_snode is returned with a reference upon success.  No reference is
 * taken if an error is returned.
 */

int
smb_fsop_create(
    struct smb_request *sr,
    cred_t *cr,
    smb_node_t *dir_snode,
    char *name,
    smb_attr_t *attr,
    smb_node_t **ret_snode,
    smb_attr_t *ret_attr)
{
	struct open_param *op = &sr->arg.open;
	smb_node_t *fnode;
	smb_attr_t file_attr;
	caller_context_t ct;
	vnode_t *xattrdirvp;
	vnode_t *vp;
	char *longname = NULL;
	char *namep;
	char *fname;
	char *sname;
	int is_stream;
	int flags = 0;
	int rc = 0;
	smb_fssd_t fs_sd;
	uint32_t secinfo;
	uint32_t status;

	ASSERT(cr);
	ASSERT(dir_snode);
	ASSERT(dir_snode->n_magic == SMB_NODE_MAGIC);
	ASSERT(dir_snode->n_state != SMB_NODE_STATE_DESTROYING);

	ASSERT(ret_snode);
	*ret_snode = 0;

	ASSERT(name);
	if (*name == 0)
		return (EINVAL);

	if (SMB_TREE_ROOT_FS(sr, dir_snode) == 0)
		return (EACCES);

	ASSERT(sr);
	ASSERT(sr->tid_tree);
	if (SMB_TREE_IS_READ_ONLY(sr))
		return (EROFS);

	if (SMB_TREE_CASE_INSENSITIVE(sr))
		flags = SMB_IGNORE_CASE;

	fname = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	sname = kmem_alloc(MAXNAMELEN, KM_SLEEP);

	is_stream = smb_stream_parse_name(name, fname, sname);

	if (is_stream)
		namep = fname;
	else
		namep = name;

	if (smb_maybe_mangled_name(namep)) {
		longname = kmem_alloc(MAXNAMELEN, KM_SLEEP);

		rc = smb_unmangle_name(sr, cr, dir_snode, namep, longname,
		    MAXNAMELEN, NULL, NULL, 1);

		if ((is_stream == 0) && (rc == 0))
			rc = EEXIST;

		if ((is_stream && rc) ||
		    ((is_stream == 0) && (rc != ENOENT))) {
			kmem_free(longname, MAXNAMELEN);
			kmem_free(fname, MAXNAMELEN);
			kmem_free(sname, MAXNAMELEN);
			return (rc);
		}

		if (is_stream)
			namep = longname;
		else
			kmem_free(longname, MAXNAMELEN);
	}

	if (is_stream) {
		/*
		 * Look up the unnamed stream.
		 *
		 * Mangle processing in smb_fsop_lookup() for the unnamed
		 * stream won't be needed (as it was done above), but
		 * it may be needed on any link target (which
		 * smb_fsop_lookup() will provide).
		 */
		rc = smb_fsop_lookup(sr, cr, flags | SMB_FOLLOW_LINKS,
		    sr->tid_tree->t_snode, dir_snode, namep, &fnode, &file_attr,
		    0, 0);

		if (longname) {
			kmem_free(longname, MAXNAMELEN);
			namep = NULL;
		}

		if (rc != 0) {
			kmem_free(fname, MAXNAMELEN);
			kmem_free(sname, MAXNAMELEN);
			return (rc);
		}

		smb_get_caller_context(sr, &ct);

		rc = smb_vop_stream_create(fnode->vp, sname, attr, &vp,
		    &xattrdirvp, flags, cr, &ct);

		if (rc != 0) {
			smb_node_release(fnode);
			kmem_free(fname, MAXNAMELEN);
			kmem_free(sname, MAXNAMELEN);
			return (rc);
		}

		*ret_snode = smb_stream_node_lookup(sr, cr, fnode, xattrdirvp,
		    vp, sname, ret_attr);

		smb_node_release(fnode);

		if (*ret_snode == NULL) {
			VN_RELE(xattrdirvp);
			VN_RELE(vp);
			kmem_free(fname, MAXNAMELEN);
			kmem_free(sname, MAXNAMELEN);
			return (ENOMEM);
		}
	} else {
		if (op->sd_buf) {
			/*
			 * SD sent by client in Windows format. Needs to be
			 * converted to FS format. No inheritance.
			 */
			secinfo = smb_sd_get_secinfo((smb_sdbuf_t *)op->sd_buf);
			smb_fsop_sdinit(&fs_sd, secinfo, 0);

			status = smb_sd_tofs(op->sd_buf, &fs_sd);
			if (status == NT_STATUS_SUCCESS) {
				rc = smb_fsop_create_with_sd(sr, cr, dir_snode,
				    name, attr, ret_snode, ret_attr, &fs_sd);
			}
			else
				rc = EINVAL;
			smb_fsop_sdterm(&fs_sd);
		} else if (sr->tid_tree->t_acltype == ACE_T) {
			/*
			 * No incoming SD and filesystem is ZFS
			 * Server applies Windows inheritance rules,
			 * see smb_fsop_sdinherit() comments as to why.
			 */
			smb_fsop_sdinit(&fs_sd, SMB_ACL_SECINFO, 0);
			rc = smb_fsop_sdinherit(sr, dir_snode, &fs_sd);
			if (rc == 0) {
				rc = smb_fsop_create_with_sd(sr, cr, dir_snode,
				    name, attr, ret_snode, ret_attr, &fs_sd);
			}

			smb_fsop_sdterm(&fs_sd);
		} else {
			/*
			 * No incoming SD and filesystem is not ZFS
			 * let the filesystem handles the inheritance.
			 */
			smb_get_caller_context(sr, &ct);
			rc = smb_vop_create(dir_snode->vp, name, attr, &vp,
			    flags, cr, &ct, NULL);

			if (rc == 0) {
				*ret_snode = smb_node_lookup(sr, op, cr, vp,
				    name, dir_snode, NULL, ret_attr);

				if (*ret_snode == NULL) {
					VN_RELE(vp);
					rc = ENOMEM;
				}
			}

		}
	}

	kmem_free(fname, MAXNAMELEN);
	kmem_free(sname, MAXNAMELEN);
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
    struct smb_request *sr,
    cred_t *cr,
    smb_node_t *dir_snode,
    char *name,
    smb_attr_t *attr,
    smb_node_t **ret_snode,
    smb_attr_t *ret_attr)
{
	struct open_param *op = &sr->arg.open;
	caller_context_t ct;
	char *longname;
	vnode_t *vp;
	int flags = 0;
	smb_fssd_t fs_sd;
	uint32_t secinfo;
	uint32_t status;
	int rc;

	ASSERT(cr);
	ASSERT(dir_snode);
	ASSERT(dir_snode->n_magic == SMB_NODE_MAGIC);
	ASSERT(dir_snode->n_state != SMB_NODE_STATE_DESTROYING);

	ASSERT(ret_snode);
	*ret_snode = 0;

	ASSERT(name);
	if (*name == 0)
		return (EINVAL);

	if (SMB_TREE_ROOT_FS(sr, dir_snode) == 0)
		return (EACCES);

	ASSERT(sr);
	ASSERT(sr->tid_tree);
	if (SMB_TREE_IS_READ_ONLY(sr))
		return (EROFS);

	if (smb_maybe_mangled_name(name)) {
		longname = kmem_alloc(MAXNAMELEN, KM_SLEEP);
		rc = smb_unmangle_name(sr, cr, dir_snode, name, longname,
		    MAXNAMELEN, NULL, NULL, 1);

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

	if (SMB_TREE_CASE_INSENSITIVE(sr))
		flags = SMB_IGNORE_CASE;

	smb_get_caller_context(sr, &ct);

	if (op->sd_buf) {
		/*
		 * SD sent by client in Windows format. Needs to be
		 * converted to FS format. No inheritance.
		 */
		secinfo = smb_sd_get_secinfo((smb_sdbuf_t *)op->sd_buf);
		smb_fsop_sdinit(&fs_sd, secinfo, SMB_FSSD_FLAGS_DIR);

		status = smb_sd_tofs(op->sd_buf, &fs_sd);
		if (status == NT_STATUS_SUCCESS) {
			rc = smb_fsop_create_with_sd(sr, cr, dir_snode,
			    name, attr, ret_snode, ret_attr, &fs_sd);
		}
		else
			rc = EINVAL;
		smb_fsop_sdterm(&fs_sd);
	} else if (sr->tid_tree->t_acltype == ACE_T) {
		/*
		 * No incoming SD and filesystem is ZFS
		 * Server applies Windows inheritance rules,
		 * see smb_fsop_sdinherit() comments as to why.
		 */
		smb_fsop_sdinit(&fs_sd, SMB_ACL_SECINFO, SMB_FSSD_FLAGS_DIR);
		rc = smb_fsop_sdinherit(sr, dir_snode, &fs_sd);
		if (rc == 0) {
			rc = smb_fsop_create_with_sd(sr, cr, dir_snode,
			    name, attr, ret_snode, ret_attr, &fs_sd);
		}

		smb_fsop_sdterm(&fs_sd);

	} else {
		rc = smb_vop_mkdir(dir_snode->vp, name, attr, &vp, flags, cr,
		    &ct, NULL);

		if (rc == 0) {
			*ret_snode = smb_node_lookup(sr, op, cr, vp, name,
			    dir_snode, NULL, ret_attr);

			if (*ret_snode == NULL) {
				VN_RELE(vp);
				rc = ENOMEM;
			}
		}
	}

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
 * od: This means that the name passed in is an on-disk name.
 * A null smb_request might be passed to this function.
 */

int
smb_fsop_remove(
    struct smb_request *sr,
    cred_t *cr,
    smb_node_t *dir_snode,
    char *name,
    int od)
{
	smb_node_t *fnode;
	smb_attr_t file_attr;
	caller_context_t ct;
	char *longname;
	char *fname;
	char *sname;
	int flags = 0;
	int rc;

	ASSERT(cr);
	/*
	 * The state of the node could be SMB_NODE_STATE_DESTROYING if this
	 * function is called during the deletion of the node (because of
	 * DELETE_ON_CLOSE).
	 */
	ASSERT(dir_snode);
	ASSERT(dir_snode->n_magic == SMB_NODE_MAGIC);

	if (SMB_TREE_ROOT_FS(sr, dir_snode) == 0)
		return (EACCES);

	if (SMB_TREE_IS_READ_ONLY(sr))
		return (EROFS);

	smb_get_caller_context(sr, &ct);

	fname = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	sname = kmem_alloc(MAXNAMELEN, KM_SLEEP);

	if (smb_stream_parse_name(name, fname, sname)) {

		ASSERT(od == 0);

		if (SMB_TREE_CASE_INSENSITIVE(sr))
			flags = SMB_IGNORE_CASE;

		/*
		 * Look up the unnamed stream (i.e. fname).
		 * Unmangle processing will be done on fname
		 * as well as any link target.
		 */

		rc = smb_fsop_lookup(sr, cr, flags | SMB_FOLLOW_LINKS,
		    sr->tid_tree->t_snode, dir_snode, fname, &fnode, &file_attr,
		    0, 0);

		if (rc != 0) {
			kmem_free(fname, MAXNAMELEN);
			kmem_free(sname, MAXNAMELEN);
			return (rc);
		}

		/*
		 * XXX
		 * Need to find out what permission is required by NTFS
		 * to remove a stream.
		 */
		rc = smb_vop_stream_remove(fnode->vp, sname, flags, cr, &ct);

		smb_node_release(fnode);
	} else {
		/*
		 * If the passed-in name is an on-disk name,
		 * then we need to do a case-sensitive remove.
		 * This is important if the on-disk name
		 * corresponds to a mangled name passed in by
		 * the client.  We want to make sure to remove
		 * the exact file specified by the client,
		 * instead of letting the underlying file system
		 * do a remove on the "first match."
		 */

		if ((od == 0) && SMB_TREE_CASE_INSENSITIVE(sr))
			flags = SMB_IGNORE_CASE;

		rc = smb_vop_remove(dir_snode->vp, name, flags, cr, &ct);

		if (rc == ENOENT) {
			if (smb_maybe_mangled_name(name) == 0) {
				kmem_free(fname, MAXNAMELEN);
				kmem_free(sname, MAXNAMELEN);
				return (rc);
			}
			longname = kmem_alloc(MAXNAMELEN, KM_SLEEP);

			rc = smb_unmangle_name(sr, cr, dir_snode, name,
			    longname, MAXNAMELEN, NULL, NULL, 1);

			if (rc == 0) {
				/*
				 * We passed "1" as the "od" parameter
				 * to smb_unmangle_name(), such that longname
				 * is the real (case-sensitive) on-disk name.
				 * We make sure we do a remove on this exact
				 * name, as the name was mangled and denotes
				 * a unique file.
				 */
				flags &= ~SMB_IGNORE_CASE;
				rc = smb_vop_remove(dir_snode->vp, longname,
				    flags, cr, &ct);
			}

			kmem_free(longname, MAXNAMELEN);
		}
	}

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
 * It is assumed that snode is not a link.
 */
int
smb_fsop_remove_streams(struct smb_request *sr, cred_t *cr,
    smb_node_t *fnode)
{
	struct fs_stream_info stream_info;
	caller_context_t ct;
	uint32_t cookie = 0;
	int flags = 0;
	int rc;

	ASSERT(cr);
	ASSERT(fnode);
	ASSERT(fnode->n_magic == SMB_NODE_MAGIC);
	ASSERT(fnode->n_state != SMB_NODE_STATE_DESTROYING);

	if (SMB_TREE_ROOT_FS(sr, fnode) == 0)
		return (EACCES);

	if (SMB_TREE_IS_READ_ONLY(sr))
		return (EROFS);

	if (SMB_TREE_CASE_INSENSITIVE(sr))
		flags = SMB_IGNORE_CASE;

	smb_get_caller_context(sr, &ct);

	for (;;) {
		rc = smb_vop_stream_readdir(fnode->vp, &cookie, &stream_info,
		    NULL, NULL, flags, cr, &ct);

		if ((rc != 0) || (cookie == SMB_EOF))
			break;

		(void) smb_vop_stream_remove(fnode->vp, stream_info.name, flags,
		    cr, &ct);
	}
	return (rc);
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
 *
 * od: This means that the name passed in is an on-disk name.
 */

int
smb_fsop_rmdir(
    struct smb_request *sr,
    cred_t *cr,
    smb_node_t *dir_snode,
    char *name,
    int od)
{
	caller_context_t ct;
	int rc;
	int flags = 0;
	char *longname;

	ASSERT(cr);
	/*
	 * The state of the node could be SMB_NODE_STATE_DESTROYING if this
	 * function is called during the deletion of the node (because of
	 * DELETE_ON_CLOSE).
	 */
	ASSERT(dir_snode);
	ASSERT(dir_snode->n_magic == SMB_NODE_MAGIC);

	if (SMB_TREE_ROOT_FS(sr, dir_snode) == 0)
		return (EACCES);

	if (SMB_TREE_IS_READ_ONLY(sr))
		return (EROFS);

	/*
	 * If the passed-in name is an on-disk name,
	 * then we need to do a case-sensitive rmdir.
	 * This is important if the on-disk name
	 * corresponds to a mangled name passed in by
	 * the client.  We want to make sure to remove
	 * the exact directory specified by the client,
	 * instead of letting the underlying file system
	 * do a rmdir on the "first match."
	 */

	if ((od == 0) && SMB_TREE_CASE_INSENSITIVE(sr))
		flags = SMB_IGNORE_CASE;

	smb_get_caller_context(sr, &ct);

	rc = smb_vop_rmdir(dir_snode->vp, name, flags, cr, &ct);

	if (rc == ENOENT) {
		if (smb_maybe_mangled_name(name) == 0)
			return (rc);

		longname = kmem_alloc(MAXNAMELEN, KM_SLEEP);

		rc = smb_unmangle_name(sr, cr, dir_snode,
		    name, longname, MAXNAMELEN, NULL,
		    NULL, 1);

		if (rc == 0) {
			/*
			 * We passed "1" as the "od" parameter
			 * to smb_unmangle_name(), such that longname
			 * is the real (case-sensitive) on-disk name.
			 * We make sure we do a rmdir on this exact
			 * name, as the name was mangled and denotes
			 * a unique directory.
			 */
			flags &= ~SMB_IGNORE_CASE;
			rc = smb_vop_rmdir(dir_snode->vp, longname, flags, cr,
			    &ct);
		}

		kmem_free(longname, MAXNAMELEN);
	}

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
smb_fsop_getattr(struct smb_request *sr, cred_t *cr, smb_node_t *snode,
    smb_attr_t *attr)
{
	smb_node_t *unnamed_node;
	vnode_t *unnamed_vp = NULL;
	caller_context_t ct;
	uint32_t status;
	uint32_t access = 0;
	int flags = 0;

	ASSERT(cr);
	ASSERT(snode);
	ASSERT(snode->n_magic == SMB_NODE_MAGIC);
	ASSERT(snode->n_state != SMB_NODE_STATE_DESTROYING);

	if (SMB_TREE_ROOT_FS(sr, snode) == 0)
		return (EACCES);

	if (sr->fid_ofile) {
		/* if uid and/or gid is requested */
		if (attr->sa_mask & (SMB_AT_UID|SMB_AT_GID))
			access |= READ_CONTROL;

		/* if anything else is also requested */
		if (attr->sa_mask & ~(SMB_AT_UID|SMB_AT_GID))
			access |= FILE_READ_ATTRIBUTES;

		status = smb_ofile_access(sr->fid_ofile, cr, access);
		if (status != NT_STATUS_SUCCESS)
			return (EACCES);

		if (sr->tid_tree->t_flags & SMB_TREE_FLAG_ACEMASKONACCESS)
			flags = ATTR_NOACLCHECK;
	}

	smb_get_caller_context(sr, &ct);

	unnamed_node = SMB_IS_STREAM(snode);

	if (unnamed_node) {
		ASSERT(unnamed_node->n_magic == SMB_NODE_MAGIC);
		ASSERT(unnamed_node->n_state != SMB_NODE_STATE_DESTROYING);
		unnamed_vp = unnamed_node->vp;
	}

	return (smb_vop_getattr(snode->vp, unnamed_vp, attr, flags, cr, &ct));
}

/*
 * smb_fsop_readdir
 *
 * All SMB functions should use this smb_fsop_readdir wrapper to ensure that
 * the smb_vop_readdir is performed with the appropriate credentials.
 * Please document any direct call to smb_vop_readdir to explain the reason
 * for avoiding this wrapper.
 *
 * It is assumed that a reference exists on snode coming into this routine.
 */
int
smb_fsop_readdir(
    struct smb_request *sr,
    cred_t *cr,
    smb_node_t *dir_snode,
    uint32_t *cookie,
    char *name,
    int *namelen,
    ino64_t *fileid,
    struct fs_stream_info *stream_info,
    smb_node_t **ret_snode,
    smb_attr_t *ret_attr)
{
	caller_context_t ct;
	smb_node_t *ret_snodep;
	smb_node_t *fnode;
	smb_attr_t tmp_attr;
	vnode_t *xattrdirvp;
	vnode_t *fvp;
	vnode_t *vp = NULL;
	char *od_name;
	int rc;
	int flags = 0;

	ASSERT(cr);
	ASSERT(dir_snode);
	ASSERT(dir_snode->n_magic == SMB_NODE_MAGIC);
	ASSERT(dir_snode->n_state != SMB_NODE_STATE_DESTROYING);

	if (SMB_TREE_ROOT_FS(sr, dir_snode) == 0)
		return (EACCES);

	if (*cookie == SMB_EOF) {
		*namelen = 0;
		return (0);
	}

	if (SMB_TREE_CASE_INSENSITIVE(sr))
		flags = SMB_IGNORE_CASE;

	smb_get_caller_context(sr, &ct);

	od_name = kmem_alloc(MAXNAMELEN, KM_SLEEP);

	if (stream_info) {
		rc = smb_vop_lookup(dir_snode->vp, name, &fvp, od_name,
		    SMB_FOLLOW_LINKS, sr->tid_tree->t_snode->vp, cr, &ct);

		if (rc != 0) {
			kmem_free(od_name, MAXNAMELEN);
			return (rc);
		}

		fnode = smb_node_lookup(sr, NULL, cr, fvp, od_name, dir_snode,
		    NULL, ret_attr);

		kmem_free(od_name, MAXNAMELEN);

		if (fnode == NULL) {
			VN_RELE(fvp);
			return (ENOMEM);
		}

		/*
		 * XXX
		 * Need to find out what permission(s) NTFS requires for getting
		 * a file's streams list.
		 *
		 * Might have to use kcred.
		 */
		rc = smb_vop_stream_readdir(fvp, cookie, stream_info, &vp,
		    &xattrdirvp, flags, cr, &ct);

		if ((rc != 0) || (*cookie == SMB_EOF)) {
			smb_node_release(fnode);
			return (rc);
		}

		ret_snodep = smb_stream_node_lookup(sr, cr, fnode, xattrdirvp,
		    vp, stream_info->name, &tmp_attr);

		smb_node_release(fnode);

		if (ret_snodep == NULL) {
			VN_RELE(xattrdirvp);
			VN_RELE(vp);
			return (ENOMEM);
		}

		stream_info->size = tmp_attr.sa_vattr.va_size;

		if (ret_attr)
			*ret_attr = tmp_attr;

		if (ret_snode)
			*ret_snode = ret_snodep;
		else
			smb_node_release(ret_snodep);

	} else {
		rc = smb_vop_readdir(dir_snode->vp, cookie, name, namelen,
		    fileid, &vp, od_name, flags, cr, &ct);

		if (rc != 0) {
			kmem_free(od_name, MAXNAMELEN);
			return (rc);
		}

		if (*namelen) {
			ASSERT(vp);
			if (ret_attr || ret_snode) {
				ret_snodep = smb_node_lookup(sr, NULL, cr, vp,
				    od_name, dir_snode, NULL, &tmp_attr);

				if (ret_snodep == NULL) {
					kmem_free(od_name, MAXNAMELEN);
					VN_RELE(vp);
					return (ENOMEM);
				}

				if (ret_attr)
					*ret_attr = tmp_attr;

				if (ret_snode)
					*ret_snode = ret_snodep;
				else
					smb_node_release(ret_snodep);
			}
		}

		kmem_free(od_name, MAXNAMELEN);
	}

	return (rc);
}

/*
 * smb_fsop_getdents
 *
 * All SMB functions should use this smb_vop_getdents wrapper to ensure that
 * the smb_vop_getdents is performed with the appropriate credentials.
 * Please document any direct call to smb_vop_getdents to explain the reason
 * for avoiding this wrapper.
 *
 * It is assumed that a reference exists on snode coming into this routine.
 */
/*ARGSUSED*/
int
smb_fsop_getdents(
    struct smb_request *sr,
    cred_t *cr,
    smb_node_t *dir_snode,
    uint32_t *cookie,
    uint64_t *verifierp,
    int32_t	*maxcnt,
    char *args,
    char *pattern)
{
	caller_context_t ct;
	int flags = 0;

	ASSERT(cr);
	ASSERT(dir_snode);
	ASSERT(dir_snode->n_magic == SMB_NODE_MAGIC);
	ASSERT(dir_snode->n_state != SMB_NODE_STATE_DESTROYING);

	if (SMB_TREE_ROOT_FS(sr, dir_snode) == 0)
		return (EACCES);

	if (SMB_TREE_CASE_INSENSITIVE(sr))
		flags = SMB_IGNORE_CASE;

	smb_get_caller_context(sr, &ct);

	return (smb_vop_getdents(dir_snode, cookie, 0, maxcnt, args, pattern,
	    flags, sr, cr, &ct));
}

/*
 * smb_fsop_rename
 *
 * All SMB functions should use this smb_vop_rename wrapper to ensure that
 * the smb_vop_rename is performed with the appropriate credentials.
 * Please document any direct call to smb_vop_rename to explain the reason
 * for avoiding this wrapper.
 *
 * It is assumed that references exist on from_dir_snode and to_dir_snode coming
 * into this routine.
 */
int
smb_fsop_rename(
    struct smb_request *sr,
    cred_t *cr,
    smb_node_t *from_dir_snode,
    char *from_name,
    smb_node_t *to_dir_snode,
    char *to_name)
{
	smb_node_t *from_snode;
	caller_context_t ct;
	smb_attr_t tmp_attr;
	vnode_t *from_vp;
	int flags = 0;
	int rc;

	ASSERT(cr);
	ASSERT(from_dir_snode);
	ASSERT(from_dir_snode->n_magic == SMB_NODE_MAGIC);
	ASSERT(from_dir_snode->n_state != SMB_NODE_STATE_DESTROYING);

	ASSERT(to_dir_snode);
	ASSERT(to_dir_snode->n_magic == SMB_NODE_MAGIC);
	ASSERT(to_dir_snode->n_state != SMB_NODE_STATE_DESTROYING);

	if (SMB_TREE_ROOT_FS(sr, from_dir_snode) == 0)
		return (EACCES);

	if (SMB_TREE_ROOT_FS(sr, to_dir_snode) == 0)
		return (EACCES);

	ASSERT(sr);
	ASSERT(sr->tid_tree);
	if (SMB_TREE_IS_READ_ONLY(sr))
		return (EROFS);

	/*
	 * Note: There is no need to check SMB_TREE_CASE_INSENSITIVE(sr)
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

	/*
	 * XXX: Lock required through smb_node_release() below?
	 */

	smb_get_caller_context(sr, &ct);

	rc = smb_vop_lookup(from_dir_snode->vp, from_name, &from_vp, NULL, 0,
	    NULL, cr, &ct);

	if (rc != 0)
		return (rc);

	rc = smb_vop_rename(from_dir_snode->vp, from_name, to_dir_snode->vp,
	    to_name, flags, cr, &ct);

	if (rc == 0) {
		from_snode = smb_node_lookup(sr, NULL, cr, from_vp, from_name,
		    from_dir_snode, NULL, &tmp_attr);

		if (from_snode == NULL) {
			VN_RELE(from_vp);
			return (ENOMEM);
		}

		(void) smb_node_rename(from_dir_snode, from_snode, to_dir_snode,
		    to_name);

		smb_node_release(from_snode);
	} else {
		VN_RELE(from_vp);
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
 * It is assumed that a reference exists on snode coming into this routine.
 * A null smb_request might be passed to this function.
 */
int
smb_fsop_setattr(
    smb_request_t *sr,
    cred_t *cr,
    smb_node_t *snode,
    smb_attr_t *set_attr,
    smb_attr_t *ret_attr)
{
	smb_node_t *unnamed_node;
	vnode_t *unnamed_vp = NULL;
	caller_context_t ct;
	uint32_t status;
	uint32_t access = 0;
	int rc = 0;
	int flags = 0;

	ASSERT(cr);
	ASSERT(snode);
	ASSERT(snode->n_magic == SMB_NODE_MAGIC);
	ASSERT(snode->n_state != SMB_NODE_STATE_DESTROYING);

	if (SMB_TREE_ROOT_FS(sr, snode) == 0)
		return (EACCES);

	if (SMB_TREE_IS_READ_ONLY(sr))
		return (EROFS);

	/* sr could be NULL in some cases */
	if (sr && sr->fid_ofile) {
		/* if uid and/or gid is requested */
		if (set_attr->sa_mask & (SMB_AT_UID|SMB_AT_GID))
			access |= WRITE_OWNER;

		/* if anything else is also requested */
		if (set_attr->sa_mask & ~(SMB_AT_UID|SMB_AT_GID))
			access |= FILE_WRITE_ATTRIBUTES;

		status = smb_ofile_access(sr->fid_ofile, cr, access);
		if (status != NT_STATUS_SUCCESS)
			return (EACCES);

		if (sr->tid_tree->t_flags & SMB_TREE_FLAG_ACEMASKONACCESS)
			flags = ATTR_NOACLCHECK;
	}

	smb_get_caller_context(sr, &ct);

	unnamed_node = SMB_IS_STREAM(snode);

	if (unnamed_node) {
		ASSERT(unnamed_node->n_magic == SMB_NODE_MAGIC);
		ASSERT(unnamed_node->n_state != SMB_NODE_STATE_DESTROYING);
		unnamed_vp = unnamed_node->vp;
	}

	rc = smb_vop_setattr(snode->vp, unnamed_vp, set_attr, flags, cr, &ct);

	if ((rc == 0) && ret_attr) {
		/*
		 * This is an operation on behalf of CIFS service (to update
		 * smb node's attr) not on behalf of the user so it's done
		 * using kcred and the return value is intentionally ignored.
		 */
		ret_attr->sa_mask = SMB_AT_ALL;
		(void) smb_vop_getattr(snode->vp, unnamed_vp, ret_attr, 0,
		    kcred, &ct);
	}

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
 */
int
smb_fsop_read(
    struct smb_request *sr,
    cred_t *cr,
    smb_node_t *snode,
    uio_t *uio,
    smb_attr_t *ret_attr)
{
	smb_node_t *unnamed_node;
	vnode_t *unnamed_vp = NULL;
	caller_context_t ct;
	int rc;

	ASSERT(cr);
	ASSERT(snode);
	ASSERT(snode->n_magic == SMB_NODE_MAGIC);
	ASSERT(snode->n_state != SMB_NODE_STATE_DESTROYING);

	ASSERT(sr);
	ASSERT(sr->fid_ofile);

	rc = smb_ofile_access(sr->fid_ofile, cr, FILE_READ_DATA);
	if (rc != NT_STATUS_SUCCESS) {
		rc = smb_ofile_access(sr->fid_ofile, cr, FILE_EXECUTE);
		if (rc != NT_STATUS_SUCCESS)
			return (EACCES);
	}

	unnamed_node = SMB_IS_STREAM(snode);
	if (unnamed_node) {
		ASSERT(unnamed_node->n_magic == SMB_NODE_MAGIC);
		ASSERT(unnamed_node->n_state != SMB_NODE_STATE_DESTROYING);
		unnamed_vp = unnamed_node->vp;
		/*
		 * Streams permission are checked against the unnamed stream,
		 * but in FS level they have their own permissions. To avoid
		 * rejection by FS due to lack of permission on the actual
		 * extended attr kcred is passed for streams.
		 */
		cr = kcred;
	}

	smb_get_caller_context(sr, &ct);
	rc = smb_vop_read(snode->vp, uio, cr, &ct);

	if (rc == 0) {
		/*
		 * This is an operation on behalf of CIFS service (to update
		 * smb node's attr) not on behalf of the user so it's done
		 * using kcred and the return value is intentionally ignored.
		 */
		ret_attr->sa_mask = SMB_AT_ALL;
		(void) smb_vop_getattr(snode->vp, unnamed_vp, ret_attr, 0,
		    kcred, &ct);
	}

	return (rc);
}

/*
 * smb_fsop_write
 *
 * This is a wrapper function used for smb_write and smb_write_raw operations.
 *
 * It is assumed that a reference exists on snode coming into this routine.
 */
int
smb_fsop_write(
    struct smb_request *sr,
    cred_t *cr,
    smb_node_t *snode,
    uio_t *uio,
    uint32_t *lcount,
    smb_attr_t *ret_attr,
    uint32_t *flag)
{
	smb_node_t *unnamed_node;
	vnode_t *unnamed_vp = NULL;
	caller_context_t ct;
	int rc;

	ASSERT(cr);
	ASSERT(snode);
	ASSERT(snode->n_magic == SMB_NODE_MAGIC);
	ASSERT(snode->n_state != SMB_NODE_STATE_DESTROYING);

	ASSERT(sr);
	ASSERT(sr->tid_tree);
	ASSERT(sr->fid_ofile);

	if (SMB_TREE_IS_READ_ONLY(sr))
		return (EROFS);
	/*
	 * XXX what if the file has been opened only with
	 * FILE_APPEND_DATA?
	 */
	rc = smb_ofile_access(sr->fid_ofile, cr, FILE_WRITE_DATA);
	if (rc != NT_STATUS_SUCCESS)
		return (EACCES);

	smb_get_caller_context(sr, &ct);

	unnamed_node = SMB_IS_STREAM(snode);

	if (unnamed_node) {
		ASSERT(unnamed_node->n_magic == SMB_NODE_MAGIC);
		ASSERT(unnamed_node->n_state != SMB_NODE_STATE_DESTROYING);
		unnamed_vp = unnamed_node->vp;
		/*
		 * Streams permission are checked against the unnamed stream,
		 * but in FS level they have their own permissions. To avoid
		 * rejection by FS due to lack of permission on the actual
		 * extended attr kcred is passed for streams.
		 */
		cr = kcred;
	}

	rc = smb_vop_write(snode->vp, uio, flag, lcount, cr, &ct);

	if (rc == 0) {
		/*
		 * This is an operation on behalf of CIFS service (to update
		 * smb node's attr) not on behalf of the user so it's done
		 * using kcred and the return value is intentionally ignored.
		 */
		ret_attr->sa_mask = SMB_AT_ALL;
		(void) smb_vop_getattr(snode->vp, unnamed_vp, ret_attr, 0,
		    kcred, &ct);
	}

	return (rc);
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

	ASSERT(cr);
	ASSERT(snode);
	ASSERT(snode->n_magic == SMB_NODE_MAGIC);
	ASSERT(snode->n_state != SMB_NODE_STATE_DESTROYING);

	if (faccess == 0)
		return (NT_STATUS_SUCCESS);

	if (SMB_TREE_IS_READ_ONLY(sr)) {
		if (faccess & (FILE_WRITE_DATA|FILE_APPEND_DATA|
		    FILE_WRITE_EA|FILE_DELETE_CHILD|FILE_WRITE_ATTRIBUTES|
		    DELETE|WRITE_DAC|WRITE_OWNER)) {
			return (NT_STATUS_ACCESS_DENIED);
		}
	}

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

	if (faccess & ACCESS_SYSTEM_SECURITY) {
		/*
		 * This permission is required for reading/writing SACL and
		 * it's not part of DACL. It's only granted via proper
		 * privileges.
		 */
		if ((sr->uid_user->u_privileges &
		    (SMB_USER_PRIV_BACKUP |
		    SMB_USER_PRIV_RESTORE |
		    SMB_USER_PRIV_SECURITY)) == 0)
			return (NT_STATUS_PRIVILEGE_NOT_HELD);

		faccess &= ~ACCESS_SYSTEM_SECURITY;
	}

	/* Links don't have ACL */
	if (((sr->tid_tree->t_flags & SMB_TREE_FLAG_ACEMASKONACCESS) == 0) ||
	    (snode->attr.sa_vattr.va_type == VLNK))
		acl_check = B_FALSE;

	if (acl_check) {
		dir_vp = (snode->dir_snode) ? snode->dir_snode->vp : NULL;
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
 * Sanity checks on dir_snode done in smb_fsop_lookup().
 *
 * Note: This function is called only from the open path.
 * It will check if the file is a stream.
 * It will also return an error if the looked-up file is in
 * a child mount.
 */

int
smb_fsop_lookup_name(
    struct smb_request *sr,
    cred_t	*cr,
    int		flags,
    smb_node_t	*root_node,
    smb_node_t	*dir_snode,
    char	*name,
    smb_node_t	**ret_snode,
    smb_attr_t	*ret_attr)
{
	smb_node_t *fnode;
	smb_attr_t file_attr;
	caller_context_t ct;
	vnode_t *xattrdirvp;
	vnode_t *vp;
	char *od_name;
	char *fname;
	char *sname;
	int rc;

	ASSERT(cr);
	ASSERT(dir_snode);
	ASSERT(dir_snode->n_magic == SMB_NODE_MAGIC);
	ASSERT(dir_snode->n_state != SMB_NODE_STATE_DESTROYING);

	/*
	 * The following check is required for streams processing, below
	 */

	if (SMB_TREE_CASE_INSENSITIVE(sr))
		flags |= SMB_IGNORE_CASE;

	fname = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	sname = kmem_alloc(MAXNAMELEN, KM_SLEEP);

	if (smb_stream_parse_name(name, fname, sname)) {
		/*
		 * Look up the unnamed stream (i.e. fname).
		 * Unmangle processing will be done on fname
		 * as well as any link target.
		 */
		rc = smb_fsop_lookup(sr, cr, flags, root_node, dir_snode, fname,
		    &fnode, &file_attr, NULL, NULL);

		if (rc != 0) {
			kmem_free(fname, MAXNAMELEN);
			kmem_free(sname, MAXNAMELEN);
			return (rc);
		}

		od_name = kmem_alloc(MAXNAMELEN, KM_SLEEP);

		/*
		 * od_name is the on-disk name of the stream, except
		 * without the prepended stream prefix (SMB_STREAM_PREFIX)
		 */

		/*
		 * XXX
		 * What permissions NTFS requires for stream lookup if any?
		 */
		rc = smb_vop_stream_lookup(fnode->vp, sname, &vp, od_name,
		    &xattrdirvp, flags, root_node->vp, cr, &ct);

		if (rc != 0) {
			smb_node_release(fnode);
			kmem_free(fname, MAXNAMELEN);
			kmem_free(sname, MAXNAMELEN);
			kmem_free(od_name, MAXNAMELEN);
			return (rc);
		}

		*ret_snode = smb_stream_node_lookup(sr, cr, fnode, xattrdirvp,
		    vp, od_name, ret_attr);

		kmem_free(od_name, MAXNAMELEN);
		smb_node_release(fnode);

		if (*ret_snode == NULL) {
			VN_RELE(xattrdirvp);
			VN_RELE(vp);
			kmem_free(fname, MAXNAMELEN);
			kmem_free(sname, MAXNAMELEN);
			return (ENOMEM);
		}
	} else {
		rc = smb_fsop_lookup(sr, cr, flags, root_node, dir_snode, name,
		    ret_snode, ret_attr, NULL, NULL);
	}

	if (rc == 0) {
		ASSERT(ret_snode);
		if (SMB_TREE_ROOT_FS(sr, *ret_snode) == 0) {
			smb_node_release(*ret_snode);
			*ret_snode = NULL;
			rc = EACCES;
		}
	}

	kmem_free(fname, MAXNAMELEN);
	kmem_free(sname, MAXNAMELEN);

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
 * It is assumed that a reference exists on dir_snode coming into this routine
 * (and that it is safe from deallocation).
 *
 * Same with the root_node.
 *
 * *ret_snode is returned with a reference upon success.  No reference is
 * taken if an error is returned.
 *
 * Note: The returned ret_snode may be in a child mount.  This is ok for
 * readdir and getdents.
 *
 * Other smb_fsop_* routines will call SMB_TREE_ROOT_FS() to prevent
 * operations on files not in the parent mount.
 */
int
smb_fsop_lookup(
    struct smb_request *sr,
    cred_t	*cr,
    int		flags,
    smb_node_t	*root_node,
    smb_node_t	*dir_snode,
    char	*name,
    smb_node_t	**ret_snode,
    smb_attr_t	*ret_attr,
    char	*ret_shortname, /* Must be at least MANGLE_NAMELEN chars */
    char	*ret_name83)    /* Must be at least MANGLE_NAMELEN chars */
{
	smb_node_t *lnk_target_node;
	smb_node_t *lnk_dnode;
	caller_context_t ct;
	char *longname;
	char *od_name;
	vnode_t *vp;
	int rc;

	ASSERT(cr);
	ASSERT(dir_snode);
	ASSERT(dir_snode->n_magic == SMB_NODE_MAGIC);
	ASSERT(dir_snode->n_state != SMB_NODE_STATE_DESTROYING);

	if (name == NULL)
		return (EINVAL);

	if (SMB_TREE_ROOT_FS(sr, dir_snode) == 0)
		return (EACCES);

	if (SMB_TREE_CASE_INSENSITIVE(sr))
		flags |= SMB_IGNORE_CASE;

	smb_get_caller_context(sr, &ct);

	od_name = kmem_alloc(MAXNAMELEN, KM_SLEEP);

	rc = smb_vop_lookup(dir_snode->vp, name, &vp, od_name, flags,
	    root_node ? root_node->vp : NULL, cr, &ct);

	if (rc != 0) {
		if (smb_maybe_mangled_name(name) == 0) {
			kmem_free(od_name, MAXNAMELEN);
			return (rc);
		}

		longname = kmem_alloc(MAXNAMELEN, KM_SLEEP);

		rc = smb_unmangle_name(sr, cr, dir_snode, name, longname,
		    MAXNAMELEN, ret_shortname, ret_name83, 1);

		if (rc != 0) {
			kmem_free(od_name, MAXNAMELEN);
			kmem_free(longname, MAXNAMELEN);
			return (rc);
		}

		/*
		 * We passed "1" as the "od" parameter
		 * to smb_unmangle_name(), such that longname
		 * is the real (case-sensitive) on-disk name.
		 * We make sure we do a lookup on this exact
		 * name, as the name was mangled and denotes
		 * a unique file.
		 */

		if (flags & SMB_IGNORE_CASE)
			flags &= ~SMB_IGNORE_CASE;

		rc = smb_vop_lookup(dir_snode->vp, longname, &vp, od_name,
		    flags, root_node ? root_node->vp : NULL, cr, &ct);

		kmem_free(longname, MAXNAMELEN);

		if (rc != 0) {
			kmem_free(od_name, MAXNAMELEN);
			return (rc);
		}
	}

	if ((flags & SMB_FOLLOW_LINKS) && (vp->v_type == VLNK)) {

		rc = smb_pathname(sr, od_name, FOLLOW, root_node, dir_snode,
		    &lnk_dnode, &lnk_target_node, cr);

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
			*ret_attr = (*ret_snode)->attr;
		} else {
			*ret_snode = smb_node_lookup(sr, NULL, cr, vp,
			    lnk_target_node->od_name, lnk_dnode, NULL,
			    ret_attr);

			if (*ret_snode == NULL) {
				VN_RELE(vp);
				rc = ENOMEM;
			}
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
		    dir_snode, NULL, ret_attr);

		if (*ret_snode == NULL) {
			VN_RELE(vp);
			rc = ENOMEM;
		}
	}

	kmem_free(od_name, MAXNAMELEN);
	return (rc);
}

/*
 * smb_fsop_stream_readdir()
 *
 * ret_snode and ret_attr are optional parameters (i.e. NULL may be passed in)
 *
 * This routine will return only NTFS streams.  If an NTFS stream is not
 * found at the offset specified, the directory will be read until an NTFS
 * stream is found or until EOF.
 *
 * Note: Sanity checks done in caller
 * (smb_fsop_readdir(), smb_fsop_remove_streams())
 */

int
smb_fsop_stream_readdir(struct smb_request *sr, cred_t *cr, smb_node_t *fnode,
    uint32_t *cookiep, struct fs_stream_info *stream_info,
    smb_node_t **ret_snode, smb_attr_t *ret_attr)
{
	smb_node_t *ret_snodep = NULL;
	caller_context_t ct;
	smb_attr_t tmp_attr;
	vnode_t *xattrdirvp;
	vnode_t *vp;
	int rc = 0;
	int flags = 0;

	/*
	 * XXX NTFS permission requirements if any?
	 */
	ASSERT(cr);
	ASSERT(fnode);
	ASSERT(fnode->n_magic == SMB_NODE_MAGIC);
	ASSERT(fnode->n_state != SMB_NODE_STATE_DESTROYING);

	if (SMB_TREE_CASE_INSENSITIVE(sr))
		flags = SMB_IGNORE_CASE;

	smb_get_caller_context(sr, &ct);

	rc = smb_vop_stream_readdir(fnode->vp, cookiep, stream_info, &vp,
	    &xattrdirvp, flags, cr, &ct);

	if ((rc != 0) || *cookiep == SMB_EOF)
		return (rc);

	ret_snodep = smb_stream_node_lookup(sr, cr, fnode, xattrdirvp, vp,
	    stream_info->name, &tmp_attr);

	if (ret_snodep == NULL) {
		VN_RELE(xattrdirvp);
		VN_RELE(vp);
		return (ENOMEM);
	}

	stream_info->size = tmp_attr.sa_vattr.va_size;

	if (ret_attr)
		*ret_attr = tmp_attr;

	if (ret_snode)
		*ret_snode = ret_snodep;
	else
		smb_node_release(ret_snodep);

	return (rc);
}

int /*ARGSUSED*/
smb_fsop_commit(smb_request_t *sr, cred_t *cr, smb_node_t *snode)
{
	caller_context_t ct;

	ASSERT(cr);
	ASSERT(snode);
	ASSERT(snode->n_magic == SMB_NODE_MAGIC);
	ASSERT(snode->n_state != SMB_NODE_STATE_DESTROYING);

	ASSERT(sr);
	ASSERT(sr->tid_tree);
	if (SMB_TREE_IS_READ_ONLY(sr))
		return (EROFS);

	smb_get_caller_context(sr, &ct);

	return (smb_vop_commit(snode->vp, cr, &ct));
}

/*
 * smb_fsop_sdinit
 *
 * Initializes the given FS SD structure.
 */
void
smb_fsop_sdinit(smb_fssd_t *fs_sd, uint32_t secinfo, uint32_t flags)
{
	bzero(fs_sd, sizeof (smb_fssd_t));
	fs_sd->sd_secinfo = secinfo;
	fs_sd->sd_flags = flags;
}

/*
 * smb_fsop_sdterm
 *
 * Frees allocated memory for acl fields.
 */
void
smb_fsop_sdterm(smb_fssd_t *fs_sd)
{
	ASSERT(fs_sd);

	smb_fsop_aclfree(fs_sd->sd_zdacl);
	smb_fsop_aclfree(fs_sd->sd_zsacl);
	bzero(fs_sd, sizeof (smb_fssd_t));
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
 * using smb_fsop_aclfree() or smb_fsop_sdterm()
 */
int
smb_fsop_aclread(smb_request_t *sr, cred_t *cr, smb_node_t *snode,
    smb_fssd_t *fs_sd)
{
	int error = 0;
	int flags = 0;
	int access = 0;
	acl_t *acl;
	caller_context_t ct;
	smb_node_t *unnamed_node;

	ASSERT(cr);

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

	unnamed_node = SMB_IS_STREAM(snode);
	if (unnamed_node) {
		ASSERT(unnamed_node->n_magic == SMB_NODE_MAGIC);
		ASSERT(unnamed_node->n_state != SMB_NODE_STATE_DESTROYING);
		/*
		 * Streams don't have ACL, any read ACL attempt on a stream
		 * should be performed on the unnamed stream.
		 */
		snode = unnamed_node;
	}

	if (sr->tid_tree->t_flags & SMB_TREE_FLAG_ACEMASKONACCESS)
		flags = ATTR_NOACLCHECK;

	smb_get_caller_context(sr, &ct);
	error = smb_vop_acl_read(snode->vp, &acl, flags,
	    sr->tid_tree->t_acltype, cr, &ct);
	if (error != 0) {
		return (error);
	}

	error = acl_translate(acl, _ACL_ACE_ENABLED,
	    (snode->vp->v_type == VDIR), fs_sd->sd_uid, fs_sd->sd_gid);

	if (error == 0) {
		smb_fsop_aclsplit(acl, &fs_sd->sd_zdacl, &fs_sd->sd_zsacl,
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
	caller_context_t ct;
	acl_t *acl, *dacl, *sacl;
	smb_node_t *unnamed_node;

	ASSERT(cr);

	ASSERT(sr);
	ASSERT(sr->tid_tree);
	if (SMB_TREE_IS_READ_ONLY(sr))
		return (EROFS);

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

	unnamed_node = SMB_IS_STREAM(snode);
	if (unnamed_node) {
		ASSERT(unnamed_node->n_magic == SMB_NODE_MAGIC);
		ASSERT(unnamed_node->n_state != SMB_NODE_STATE_DESTROYING);
		/*
		 * Streams don't have ACL, any write ACL attempt on a stream
		 * should be performed on the unnamed stream.
		 */
		snode = unnamed_node;
	}

	dacl = fs_sd->sd_zdacl;
	sacl = fs_sd->sd_zsacl;

	ASSERT(dacl || sacl);
	if ((dacl == NULL) && (sacl == NULL))
		return (EINVAL);

	if (dacl && sacl)
		acl = smb_fsop_aclmerge(dacl, sacl);
	else if (dacl)
		acl = dacl;
	else
		acl = sacl;

	error = acl_translate(acl, target_flavor, (snode->vp->v_type == VDIR),
	    fs_sd->sd_uid, fs_sd->sd_gid);
	if (error == 0) {
		smb_get_caller_context(sr, &ct);
		if (sr->tid_tree->t_flags & SMB_TREE_FLAG_ACEMASKONACCESS)
			flags = ATTR_NOACLCHECK;

		error = smb_vop_acl_write(snode->vp, acl, flags, cr, &ct);
	}

	if (dacl && sacl)
		acl_free(acl);

	return (error);
}

acl_t *
smb_fsop_aclalloc(int acenum, int flags)
{
	acl_t *acl;

	acl = acl_alloc(ACE_T);
	acl->acl_cnt = acenum;
	acl->acl_aclp = kmem_zalloc(acl->acl_entry_size * acenum, KM_SLEEP);
	acl->acl_flags = flags;
	return (acl);
}

void
smb_fsop_aclfree(acl_t *acl)
{
	if (acl)
		acl_free(acl);
}

/*
 * smb_fsop_aclmerge
 *
 * smb_fsop_aclread/write routines which interact with filesystem
 * work with single ACL. This routine merges given DACL and SACL
 * which might have been created during CIFS to FS conversion into
 * one single ACL.
 */
static acl_t *
smb_fsop_aclmerge(acl_t *dacl, acl_t *sacl)
{
	acl_t *acl;
	int dacl_size;

	ASSERT(dacl);
	ASSERT(sacl);

	acl = smb_fsop_aclalloc(dacl->acl_cnt + sacl->acl_cnt, dacl->acl_flags);
	dacl_size = dacl->acl_cnt * dacl->acl_entry_size;
	bcopy(dacl->acl_aclp, acl->acl_aclp, dacl_size);
	bcopy(sacl->acl_aclp, (char *)acl->acl_aclp + dacl_size,
	    sacl->acl_cnt * sacl->acl_entry_size);

	return (acl);
}

/*
 * smb_fsop_aclsplit
 *
 * splits the given ACE_T ACL (zacl) to one or two ACLs (DACL/SACL) based on
 * the 'which_acl' parameter. Note that output dacl/sacl parameters could be
 * NULL even if they're specified in 'which_acl', which means the target
 * doesn't have any access and/or audit ACEs.
 */
static void
smb_fsop_aclsplit(acl_t *zacl, acl_t **dacl, acl_t **sacl, int which_acl)
{
	ace_t *zace;
	ace_t *access_ace;
	ace_t *audit_ace;
	int naccess, naudit;
	int get_dacl, get_sacl;
	int i;

	*dacl = *sacl = NULL;
	naccess = naudit = 0;
	get_dacl = (which_acl & SMB_DACL_SECINFO);
	get_sacl = (which_acl & SMB_SACL_SECINFO);

	for (i = 0, zace = zacl->acl_aclp; i < zacl->acl_cnt; zace++, i++) {
		if (get_dacl && smb_ace_is_access(zace->a_type))
			naccess++;
		else if (get_sacl && smb_ace_is_audit(zace->a_type))
			naudit++;
	}

	if (naccess) {
		*dacl = smb_fsop_aclalloc(naccess, zacl->acl_flags);
		access_ace = (*dacl)->acl_aclp;
	}

	if (naudit) {
		*sacl = smb_fsop_aclalloc(naudit, zacl->acl_flags);
		audit_ace = (*sacl)->acl_aclp;
	}

	for (i = 0, zace = zacl->acl_aclp; i < zacl->acl_cnt; zace++, i++) {
		if (get_dacl && smb_ace_is_access(zace->a_type)) {
			*access_ace = *zace;
			access_ace++;
		} else if (get_sacl && smb_ace_is_audit(zace->a_type)) {
			*audit_ace = *zace;
			audit_ace++;
		}
	}
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
		ga_cred = kcred;
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
				return (error);
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
	int error = 0;

	if (sr->tid_tree->t_acltype != ACE_T)
		/* Don't bother if target FS doesn't support ACE_T */
		return (0);

	if ((fs_sd->sd_secinfo & SMB_ACL_SECINFO) != SMB_ACL_SECINFO) {
		if (fs_sd->sd_secinfo & SMB_DACL_SECINFO) {
			/*
			 * Don't overwrite existing audit entries
			 */
			smb_fsop_sdinit(&cur_sd, SMB_SACL_SECINFO,
			    fs_sd->sd_flags);

			error = smb_fsop_sdread(sr, kcred, snode, &cur_sd);
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
			smb_fsop_sdinit(&cur_sd, SMB_DACL_SECINFO,
			    fs_sd->sd_flags);

			error = smb_fsop_sdread(sr, kcred, snode, &cur_sd);
			if (error == 0) {
				ASSERT(fs_sd->sd_zdacl == NULL);
				fs_sd->sd_zdacl = cur_sd.sd_zdacl;
				if (fs_sd->sd_zdacl && fs_sd->sd_zsacl)
					fs_sd->sd_zdacl->acl_flags =
					    fs_sd->sd_zsacl->acl_flags;
			}
		}

		if (error)
			smb_fsop_sdterm(&cur_sd);
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
 */
int
smb_fsop_sdwrite(smb_request_t *sr, cred_t *cr, smb_node_t *snode,
    smb_fssd_t *fs_sd, int overwrite)
{
	int error = 0;
	int access = 0;
	smb_attr_t set_attr;
	smb_attr_t orig_attr;

	ASSERT(cr);
	ASSERT(fs_sd);

	ASSERT(sr);
	ASSERT(sr->tid_tree);
	if (SMB_TREE_IS_READ_ONLY(sr))
		return (EROFS);

	bzero(&set_attr, sizeof (smb_attr_t));

	if (fs_sd->sd_secinfo & SMB_OWNER_SECINFO) {
		set_attr.sa_vattr.va_uid = fs_sd->sd_uid;
		set_attr.sa_mask |= SMB_AT_UID;
	}

	if (fs_sd->sd_secinfo & SMB_GROUP_SECINFO) {
		set_attr.sa_vattr.va_gid = fs_sd->sd_gid;
		set_attr.sa_mask |= SMB_AT_GID;
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
		/*
		 * Get the current uid, gid so if smb_fsop_aclwrite fails
		 * we can revert uid, gid changes.
		 *
		 * We use root cred here so the operation doesn't fail
		 * due to lack of permission for the user to read the attrs
		 */

		orig_attr.sa_mask = SMB_AT_UID | SMB_AT_GID;
		error = smb_fsop_getattr(sr, kcred, snode, &orig_attr);
		if (error == 0)
			error = smb_fsop_setattr(sr, cr, snode, &set_attr,
			    NULL);

		if (error)
			return (error);
	}

	if (fs_sd->sd_secinfo & SMB_ACL_SECINFO) {
		if (overwrite == 0) {
			error = smb_fsop_sdmerge(sr, snode, fs_sd);
			if (error)
				return (error);
		}

		error = smb_fsop_aclwrite(sr, cr, snode, fs_sd);
		if (error) {
			/*
			 * Revert uid/gid changes if required.
			 */
			if (set_attr.sa_mask) {
				orig_attr.sa_mask = set_attr.sa_mask;
				(void) smb_fsop_setattr(sr, kcred, snode,
				    &orig_attr, NULL);
			}
		}
	}

	return (error);
}

/*ARGSUSED*/
void
smb_get_caller_context(smb_request_t *sr, caller_context_t *ct)
{
	ct->cc_caller_id = smb_caller_id;
	ct->cc_pid = 0;			/* TBD */
	ct->cc_sysid = 0;		/* TBD */
}

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
	int is_dir;
	acl_t *dacl;
	acl_t *sacl;
	ksid_t *owner_sid;
	int error;

	ASSERT(fs_sd);

	if (sr->tid_tree->t_acltype != ACE_T) {
		/*
		 * No forced inheritance for non-ZFS filesystems.
		 */
		fs_sd->sd_secinfo = 0;
		return (0);
	}


	/* Fetch parent directory's ACL */
	error = smb_fsop_sdread(sr, kcred, dnode, fs_sd);
	if (error) {
		return (error);
	}

	is_dir = (fs_sd->sd_flags & SMB_FSSD_FLAGS_DIR);
	owner_sid = crgetsid(sr->user_cr, KSID_OWNER);
	ASSERT(owner_sid);
	dacl = smb_acl_inherit(fs_sd->sd_zdacl, is_dir, SMB_DACL_SECINFO,
	    owner_sid->ks_id);
	sacl = smb_acl_inherit(fs_sd->sd_zsacl, is_dir, SMB_SACL_SECINFO,
	    (uid_t)-1);

	smb_fsop_aclfree(fs_sd->sd_zdacl);
	smb_fsop_aclfree(fs_sd->sd_zsacl);

	fs_sd->sd_zdacl = dacl;
	fs_sd->sd_zsacl = sacl;

	return (0);
}

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

	if (sr->tid_tree->t_flags & SMB_TREE_FLAG_ACEMASKONACCESS) {
		dir_vp = (snode->dir_snode) ? snode->dir_snode->vp : NULL;
		smb_vop_eaccess(snode->vp, (int *)eaccess, V_ACE_MASK, dir_vp,
		    cr);
		return;
	}

	/*
	 * FS doesn't understand 32-bit mask
	 */
	smb_vop_eaccess(snode->vp, &access, 0, NULL, cr);

	*eaccess = READ_CONTROL | FILE_READ_EA | FILE_READ_ATTRIBUTES;

	if (access & VREAD)
		*eaccess |= FILE_READ_DATA;

	if (access & VEXEC)
		*eaccess |= FILE_EXECUTE;

	if (access & VWRITE)
		*eaccess |= FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES |
		    FILE_WRITE_EA | FILE_APPEND_DATA | FILE_DELETE_CHILD;
}
