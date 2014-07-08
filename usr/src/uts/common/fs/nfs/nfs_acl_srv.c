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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/buf.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/pathname.h>
#include <sys/uio.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <sys/siginfo.h>
#include <sys/tiuser.h>
#include <sys/statvfs.h>
#include <sys/t_kuser.h>
#include <sys/kmem.h>
#include <sys/kstat.h>
#include <sys/acl.h>
#include <sys/dirent.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/unistd.h>
#include <sys/vtrace.h>
#include <sys/mode.h>

#include <rpc/types.h>
#include <rpc/auth.h>
#include <rpc/svc.h>
#include <rpc/xdr.h>

#include <nfs/nfs.h>
#include <nfs/export.h>
#include <nfs/nfssys.h>
#include <nfs/nfs_clnt.h>
#include <nfs/nfs_acl.h>

#include <fs/fs_subr.h>

/*
 * These are the interface routines for the server side of the
 * NFS ACL server.  See the NFS ACL protocol specification
 * for a description of this interface.
 */

/* ARGSUSED */
void
acl2_getacl(GETACL2args *args, GETACL2res *resp, struct exportinfo *exi,
    struct svc_req *req, cred_t *cr, bool_t ro)
{
	int error;
	vnode_t *vp;
	vattr_t va;

	vp = nfs_fhtovp(&args->fh, exi);
	if (vp == NULL) {
		resp->status = NFSERR_STALE;
		return;
	}

	bzero((caddr_t)&resp->resok.acl, sizeof (resp->resok.acl));

	resp->resok.acl.vsa_mask = args->mask;

	error = VOP_GETSECATTR(vp, &resp->resok.acl, 0, cr, NULL);

	if ((error == ENOSYS) && !(exi->exi_export.ex_flags & EX_NOACLFAB)) {
		/*
		 * If the underlying file system doesn't support
		 * aclent_t type acls, fabricate an acl.  This is
		 * required in order to to support existing clients
		 * that require the call to VOP_GETSECATTR to
		 * succeed while making the assumption that all
		 * file systems support aclent_t type acls.  This
		 * causes problems for servers exporting ZFS file
		 * systems because ZFS supports ace_t type acls,
		 * and fails (with ENOSYS) when asked for aclent_t
		 * type acls.
		 *
		 * Note: if the fs_fab_acl() fails, we have other problems.
		 * This error should be returned to the caller.
		 */
		error = fs_fab_acl(vp, &resp->resok.acl, 0, cr, NULL);
	}

	if (error) {
		VN_RELE(vp);
		resp->status = puterrno(error);
		return;
	}

	va.va_mask = AT_ALL;
	error = rfs4_delegated_getattr(vp, &va, 0, cr);

	VN_RELE(vp);

	/* check for overflowed values */
	if (!error) {
		error = vattr_to_nattr(&va, &resp->resok.attr);
	}
	if (error) {
		resp->status = puterrno(error);
		if (resp->resok.acl.vsa_aclcnt > 0 &&
		    resp->resok.acl.vsa_aclentp != NULL) {
			kmem_free((caddr_t)resp->resok.acl.vsa_aclentp,
			    resp->resok.acl.vsa_aclcnt * sizeof (aclent_t));
		}
		if (resp->resok.acl.vsa_dfaclcnt > 0 &&
		    resp->resok.acl.vsa_dfaclentp != NULL) {
			kmem_free((caddr_t)resp->resok.acl.vsa_dfaclentp,
			    resp->resok.acl.vsa_dfaclcnt * sizeof (aclent_t));
		}
		return;
	}

	resp->status = NFS_OK;
	if (!(args->mask & NA_ACL)) {
		if (resp->resok.acl.vsa_aclcnt > 0 &&
		    resp->resok.acl.vsa_aclentp != NULL) {
			kmem_free((caddr_t)resp->resok.acl.vsa_aclentp,
			    resp->resok.acl.vsa_aclcnt * sizeof (aclent_t));
		}
		resp->resok.acl.vsa_aclentp = NULL;
	}
	if (!(args->mask & NA_DFACL)) {
		if (resp->resok.acl.vsa_dfaclcnt > 0 &&
		    resp->resok.acl.vsa_dfaclentp != NULL) {
			kmem_free((caddr_t)resp->resok.acl.vsa_dfaclentp,
			    resp->resok.acl.vsa_dfaclcnt * sizeof (aclent_t));
		}
		resp->resok.acl.vsa_dfaclentp = NULL;
	}
}

void *
acl2_getacl_getfh(GETACL2args *args)
{

	return (&args->fh);
}

void
acl2_getacl_free(GETACL2res *resp)
{

	if (resp->status == NFS_OK) {
		if (resp->resok.acl.vsa_aclcnt > 0 &&
		    resp->resok.acl.vsa_aclentp != NULL) {
			kmem_free((caddr_t)resp->resok.acl.vsa_aclentp,
			    resp->resok.acl.vsa_aclcnt * sizeof (aclent_t));
		}
		if (resp->resok.acl.vsa_dfaclcnt > 0 &&
		    resp->resok.acl.vsa_dfaclentp != NULL) {
			kmem_free((caddr_t)resp->resok.acl.vsa_dfaclentp,
			    resp->resok.acl.vsa_dfaclcnt * sizeof (aclent_t));
		}
	}
}

/* ARGSUSED */
void
acl2_setacl(SETACL2args *args, SETACL2res *resp, struct exportinfo *exi,
	struct svc_req *req, cred_t *cr, bool_t ro)
{
	int error;
	vnode_t *vp;
	vattr_t va;

	vp = nfs_fhtovp(&args->fh, exi);
	if (vp == NULL) {
		resp->status = NFSERR_STALE;
		return;
	}

	if (rdonly(ro, vp)) {
		VN_RELE(vp);
		resp->status = NFSERR_ROFS;
		return;
	}

	(void) VOP_RWLOCK(vp, V_WRITELOCK_TRUE, NULL);
	error = VOP_SETSECATTR(vp, &args->acl, 0, cr, NULL);
	if (error) {
		VOP_RWUNLOCK(vp, V_WRITELOCK_TRUE, NULL);
		VN_RELE(vp);
		resp->status = puterrno(error);
		return;
	}

	va.va_mask = AT_ALL;
	error = rfs4_delegated_getattr(vp, &va, 0, cr);

	VOP_RWUNLOCK(vp, V_WRITELOCK_TRUE, NULL);
	VN_RELE(vp);

	/* check for overflowed values */
	if (!error) {
		error = vattr_to_nattr(&va, &resp->resok.attr);
	}
	if (error) {
		resp->status = puterrno(error);
		return;
	}

	resp->status = NFS_OK;
}

void *
acl2_setacl_getfh(SETACL2args *args)
{

	return (&args->fh);
}

/* ARGSUSED */
void
acl2_getattr(GETATTR2args *args, GETATTR2res *resp, struct exportinfo *exi,
    struct svc_req *req, cred_t *cr, bool_t ro)
{
	int error;
	vnode_t *vp;
	vattr_t va;

	vp = nfs_fhtovp(&args->fh, exi);
	if (vp == NULL) {
		resp->status = NFSERR_STALE;
		return;
	}

	va.va_mask = AT_ALL;
	error = rfs4_delegated_getattr(vp, &va, 0, cr);

	VN_RELE(vp);

	/* check for overflowed values */
	if (!error) {
		error = vattr_to_nattr(&va, &resp->resok.attr);
	}
	if (error) {
		resp->status = puterrno(error);
		return;
	}

	resp->status = NFS_OK;
}

void *
acl2_getattr_getfh(GETATTR2args *args)
{

	return (&args->fh);
}

/* ARGSUSED */
void
acl2_access(ACCESS2args *args, ACCESS2res *resp, struct exportinfo *exi,
    struct svc_req *req, cred_t *cr, bool_t ro)
{
	int error;
	vnode_t *vp;
	vattr_t va;
	int checkwriteperm;

	vp = nfs_fhtovp(&args->fh, exi);
	if (vp == NULL) {
		resp->status = NFSERR_STALE;
		return;
	}

	/*
	 * If the file system is exported read only, it is not appropriate
	 * to check write permissions for regular files and directories.
	 * Special files are interpreted by the client, so the underlying
	 * permissions are sent back to the client for interpretation.
	 */
	if (rdonly(ro, vp) && (vp->v_type == VREG || vp->v_type == VDIR))
		checkwriteperm = 0;
	else
		checkwriteperm = 1;

	/*
	 * We need the mode so that we can correctly determine access
	 * permissions relative to a mandatory lock file.  Access to
	 * mandatory lock files is denied on the server, so it might
	 * as well be reflected to the server during the open.
	 */
	va.va_mask = AT_MODE;
	error = VOP_GETATTR(vp, &va, 0, cr, NULL);
	if (error) {
		VN_RELE(vp);
		resp->status = puterrno(error);
		return;
	}

	resp->resok.access = 0;

	if (args->access & ACCESS2_READ) {
		error = VOP_ACCESS(vp, VREAD, 0, cr, NULL);
		if (!error && !MANDLOCK(vp, va.va_mode))
			resp->resok.access |= ACCESS2_READ;
	}
	if ((args->access & ACCESS2_LOOKUP) && vp->v_type == VDIR) {
		error = VOP_ACCESS(vp, VEXEC, 0, cr, NULL);
		if (!error)
			resp->resok.access |= ACCESS2_LOOKUP;
	}
	if (checkwriteperm &&
	    (args->access & (ACCESS2_MODIFY|ACCESS2_EXTEND))) {
		error = VOP_ACCESS(vp, VWRITE, 0, cr, NULL);
		if (!error && !MANDLOCK(vp, va.va_mode))
			resp->resok.access |=
			    (args->access & (ACCESS2_MODIFY|ACCESS2_EXTEND));
	}
	if (checkwriteperm &&
	    (args->access & ACCESS2_DELETE) && (vp->v_type == VDIR)) {
		error = VOP_ACCESS(vp, VWRITE, 0, cr, NULL);
		if (!error)
			resp->resok.access |= ACCESS2_DELETE;
	}
	if (args->access & ACCESS2_EXECUTE) {
		error = VOP_ACCESS(vp, VEXEC, 0, cr, NULL);
		if (!error && !MANDLOCK(vp, va.va_mode))
			resp->resok.access |= ACCESS2_EXECUTE;
	}

	va.va_mask = AT_ALL;
	error = rfs4_delegated_getattr(vp, &va, 0, cr);

	VN_RELE(vp);

	/* check for overflowed values */
	if (!error) {
		error = vattr_to_nattr(&va, &resp->resok.attr);
	}
	if (error) {
		resp->status = puterrno(error);
		return;
	}

	resp->status = NFS_OK;
}

void *
acl2_access_getfh(ACCESS2args *args)
{

	return (&args->fh);
}

/* ARGSUSED */
void
acl2_getxattrdir(GETXATTRDIR2args *args, GETXATTRDIR2res *resp,
    struct exportinfo *exi, struct svc_req *req, cred_t *cr, bool_t ro)
{
	int error;
	int flags;
	vnode_t *vp, *avp;

	vp = nfs_fhtovp(&args->fh, exi);
	if (vp == NULL) {
		resp->status = NFSERR_STALE;
		return;
	}

	flags = LOOKUP_XATTR;
	if (args->create)
		flags |= CREATE_XATTR_DIR;
	else {
		ulong_t val = 0;
		error = VOP_PATHCONF(vp, _PC_SATTR_EXISTS, &val, cr, NULL);
		if (!error && val == 0) {
			error = VOP_PATHCONF(vp, _PC_XATTR_EXISTS,
			    &val, cr, NULL);
			if (!error && val == 0) {
				VN_RELE(vp);
				resp->status = NFSERR_NOENT;
				return;
			}
		}
	}

	error = VOP_LOOKUP(vp, "", &avp, NULL, flags, NULL, cr,
	    NULL, NULL, NULL);
	if (!error && avp == vp) {	/* lookup of "" on old FS? */
		error = EINVAL;
		VN_RELE(avp);
	}
	if (!error) {
		struct vattr va;
		va.va_mask = AT_ALL;
		error = rfs4_delegated_getattr(avp, &va, 0, cr);
		if (!error) {
			error = vattr_to_nattr(&va, &resp->resok.attr);
			if (!error)
				error = makefh(&resp->resok.fh, avp, exi);
		}
		VN_RELE(avp);
	}

	VN_RELE(vp);

	if (error) {
		resp->status = puterrno(error);
		return;
	}
	resp->status = NFS_OK;
}

void *
acl2_getxattrdir_getfh(GETXATTRDIR2args *args)
{
	return (&args->fh);
}

/* ARGSUSED */
void
acl3_getacl(GETACL3args *args, GETACL3res *resp, struct exportinfo *exi,
    struct svc_req *req, cred_t *cr, bool_t ro)
{
	int error;
	vnode_t *vp;
	vattr_t *vap;
	vattr_t va;

	vap = NULL;

	vp = nfs3_fhtovp(&args->fh, exi);
	if (vp == NULL) {
		error = ESTALE;
		goto out;
	}

	va.va_mask = AT_ALL;
	vap = rfs4_delegated_getattr(vp, &va, 0, cr) ? NULL : &va;

	bzero((caddr_t)&resp->resok.acl, sizeof (resp->resok.acl));

	resp->resok.acl.vsa_mask = args->mask;

	error = VOP_GETSECATTR(vp, &resp->resok.acl, 0, cr, NULL);

	if ((error == ENOSYS) && !(exi->exi_export.ex_flags & EX_NOACLFAB)) {
		/*
		 * If the underlying file system doesn't support
		 * aclent_t type acls, fabricate an acl.  This is
		 * required in order to to support existing clients
		 * that require the call to VOP_GETSECATTR to
		 * succeed while making the assumption that all
		 * file systems support aclent_t type acls.  This
		 * causes problems for servers exporting ZFS file
		 * systems because ZFS supports ace_t type acls,
		 * and fails (with ENOSYS) when asked for aclent_t
		 * type acls.
		 *
		 * Note: if the fs_fab_acl() fails, we have other problems.
		 * This error should be returned to the caller.
		 */
		error = fs_fab_acl(vp, &resp->resok.acl, 0, cr, NULL);
	}

	if (error)
		goto out;

	va.va_mask = AT_ALL;
	vap = rfs4_delegated_getattr(vp, &va, 0, cr) ? NULL : &va;

	VN_RELE(vp);

	resp->status = NFS3_OK;
	vattr_to_post_op_attr(vap, &resp->resok.attr);
	if (!(args->mask & NA_ACL)) {
		if (resp->resok.acl.vsa_aclcnt > 0 &&
		    resp->resok.acl.vsa_aclentp != NULL) {
			kmem_free((caddr_t)resp->resok.acl.vsa_aclentp,
			    resp->resok.acl.vsa_aclcnt * sizeof (aclent_t));
		}
		resp->resok.acl.vsa_aclentp = NULL;
	}
	if (!(args->mask & NA_DFACL)) {
		if (resp->resok.acl.vsa_dfaclcnt > 0 &&
		    resp->resok.acl.vsa_dfaclentp != NULL) {
			kmem_free((caddr_t)resp->resok.acl.vsa_dfaclentp,
			    resp->resok.acl.vsa_dfaclcnt * sizeof (aclent_t));
		}
		resp->resok.acl.vsa_dfaclentp = NULL;
	}
	return;

out:
	if (curthread->t_flag & T_WOULDBLOCK) {
		curthread->t_flag &= ~T_WOULDBLOCK;
		resp->status = NFS3ERR_JUKEBOX;
	} else
		resp->status = puterrno3(error);
out1:
	if (vp != NULL)
		VN_RELE(vp);
	vattr_to_post_op_attr(vap, &resp->resfail.attr);
}

void *
acl3_getacl_getfh(GETACL3args *args)
{

	return (&args->fh);
}

void
acl3_getacl_free(GETACL3res *resp)
{

	if (resp->status == NFS3_OK) {
		if (resp->resok.acl.vsa_aclcnt > 0 &&
		    resp->resok.acl.vsa_aclentp != NULL) {
			kmem_free((caddr_t)resp->resok.acl.vsa_aclentp,
			    resp->resok.acl.vsa_aclcnt * sizeof (aclent_t));
		}
		if (resp->resok.acl.vsa_dfaclcnt > 0 &&
		    resp->resok.acl.vsa_dfaclentp != NULL) {
			kmem_free((caddr_t)resp->resok.acl.vsa_dfaclentp,
			    resp->resok.acl.vsa_dfaclcnt * sizeof (aclent_t));
		}
	}
}

/* ARGSUSED */
void
acl3_setacl(SETACL3args *args, SETACL3res *resp, struct exportinfo *exi,
    struct svc_req *req, cred_t *cr, bool_t ro)
{
	int error;
	vnode_t *vp;
	vattr_t *vap;
	vattr_t va;

	vap = NULL;

	vp = nfs3_fhtovp(&args->fh, exi);
	if (vp == NULL) {
		error = ESTALE;
		goto out1;
	}

	(void) VOP_RWLOCK(vp, V_WRITELOCK_TRUE, NULL);

	va.va_mask = AT_ALL;
	vap = rfs4_delegated_getattr(vp, &va, 0, cr) ? NULL : &va;

	if (rdonly(ro, vp)) {
		resp->status = NFS3ERR_ROFS;
		goto out1;
	}

	error = VOP_SETSECATTR(vp, &args->acl, 0, cr, NULL);

	va.va_mask = AT_ALL;
	vap = rfs4_delegated_getattr(vp, &va, 0, cr) ? NULL : &va;

	if (error)
		goto out;

	VOP_RWUNLOCK(vp, V_WRITELOCK_TRUE, NULL);
	VN_RELE(vp);

	resp->status = NFS3_OK;
	vattr_to_post_op_attr(vap, &resp->resok.attr);
	return;

out:
	if (curthread->t_flag & T_WOULDBLOCK) {
		curthread->t_flag &= ~T_WOULDBLOCK;
		resp->status = NFS3ERR_JUKEBOX;
	} else
		resp->status = puterrno3(error);
out1:
	if (vp != NULL) {
		VOP_RWUNLOCK(vp, V_WRITELOCK_TRUE, NULL);
		VN_RELE(vp);
	}
	vattr_to_post_op_attr(vap, &resp->resfail.attr);
}

void *
acl3_setacl_getfh(SETACL3args *args)
{

	return (&args->fh);
}

/* ARGSUSED */
void
acl3_getxattrdir(GETXATTRDIR3args *args, GETXATTRDIR3res *resp,
    struct exportinfo *exi, struct svc_req *req, cred_t *cr, bool_t ro)
{
	int error;
	int flags;
	vnode_t *vp, *avp;

	vp = nfs3_fhtovp(&args->fh, exi);
	if (vp == NULL) {
		resp->status = NFS3ERR_STALE;
		return;
	}

	flags = LOOKUP_XATTR;
	if (args->create)
		flags |= CREATE_XATTR_DIR;
	else {
		ulong_t val = 0;

		error = VOP_PATHCONF(vp, _PC_SATTR_EXISTS, &val, cr, NULL);
		if (!error && val == 0) {
			error = VOP_PATHCONF(vp, _PC_XATTR_EXISTS,
			    &val, cr, NULL);
			if (!error && val == 0) {
				VN_RELE(vp);
				resp->status = NFS3ERR_NOENT;
				return;
			}
		}
	}

	error = VOP_LOOKUP(vp, "", &avp, NULL, flags, NULL, cr,
	    NULL, NULL, NULL);
	if (!error && avp == vp) {	/* lookup of "" on old FS? */
		error = EINVAL;
		VN_RELE(avp);
	}
	if (!error) {
		struct vattr va;
		va.va_mask = AT_ALL;
		error = rfs4_delegated_getattr(avp, &va, 0, cr);
		if (!error) {
			vattr_to_post_op_attr(&va, &resp->resok.attr);
			error = makefh3(&resp->resok.fh, avp, exi);
		}
		VN_RELE(avp);
	}

	VN_RELE(vp);

	if (error) {
		resp->status = puterrno3(error);
		return;
	}
	resp->status = NFS3_OK;
}

void *
acl3_getxattrdir_getfh(GETXATTRDIR3args *args)
{
	return (&args->fh);
}
