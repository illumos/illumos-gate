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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/statvfs.h>
#include <sys/vnode.h>
#include <sys/thread.h>
#include <sys/pathname.h>
#include <sys/cred.h>
#include <sys/extdirent.h>
#include <sys/nbmlock.h>
#include <sys/share.h>
#include <sys/fcntl.h>
#include <nfs/lm.h>

#include <smbsrv/smb_vops.h>
#include <smbsrv/string.h>

#include <smbsrv/smbtrans.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_incl.h>

void
smb_vop_setup_xvattr(smb_attr_t *smb_attr, xvattr_t *xvattr);

static int
smb_vop_readdir_readpage(vnode_t *, void *, uint32_t, int *, cred_t *);

static int
smb_vop_readdir_entry(vnode_t *, uint32_t *, char *, int *,
    ino64_t *, vnode_t **, char *, int, cred_t *, char *, int);

static int
smb_vop_getdents_entries(smb_node_t *, uint32_t *, int32_t *, char *, uint32_t,
    smb_request_t *, cred_t *, char *, int *, int, char *);

extern int
smb_gather_dents_info(char *args, ino_t fileid, int namelen,
    char *name, uint32_t cookie, int32_t *countp,
    smb_attr_t *attr, struct smb_node *snode,
    char *shortname, char *name83);

static void
smb_sa_to_va_mask(uint_t sa_mask, uint_t *va_maskp);

static
callb_cpr_t *smb_lock_frlock_callback(flk_cb_when_t, void *);

extern sysid_t lm_alloc_sysidt();

#define	SMB_AT_MAX	16
static uint_t smb_attrmap[SMB_AT_MAX] = {
	0,
	AT_TYPE,
	AT_MODE,
	AT_UID,
	AT_GID,
	AT_FSID,
	AT_NODEID,
	AT_NLINK,
	AT_SIZE,
	AT_ATIME,
	AT_MTIME,
	AT_CTIME,
	AT_RDEV,
	AT_BLKSIZE,
	AT_NBLOCKS,
	AT_SEQ
};

static boolean_t	smb_vop_initialized = B_FALSE;
caller_context_t	smb_ct;

/*
 * smb_vop_init
 *
 * This function is not multi-thread safe. The caller must make sure only one
 * thread makes the call.
 */
int
smb_vop_init(void)
{
	if (smb_vop_initialized)
		return (0);
	/*
	 * The caller_context will be used primarily for range locking.
	 * Since the CIFS server is mapping its locks to POSIX locks,
	 * only one pid is used for operations originating from the
	 * CIFS server (to represent CIFS in the VOP_FRLOCK routines).
	 */
	smb_ct.cc_sysid = lm_alloc_sysidt();
	if (smb_ct.cc_sysid == LM_NOSYSID)
		return (ENOMEM);

	smb_ct.cc_caller_id = fs_new_caller_id();
	smb_ct.cc_pid = IGN_PID;
	smb_ct.cc_flags = 0;

	smb_vop_initialized = B_TRUE;
	return (0);
}

/*
 * smb_vop_fini
 *
 * This function is not multi-thread safe. The caller must make sure only one
 * thread makes the call.
 */
void
smb_vop_fini(void)
{
	if (!smb_vop_initialized)
		return;

	lm_free_sysidt(smb_ct.cc_sysid);
	smb_ct.cc_pid = IGN_PID;
	smb_ct.cc_sysid = LM_NOSYSID;
	smb_vop_initialized = B_FALSE;
}

/*
 * The smb_ct will be used primarily for range locking.
 * Since the CIFS server is mapping its locks to POSIX locks,
 * only one pid is used for operations originating from the
 * CIFS server (to represent CIFS in the VOP_FRLOCK routines).
 */

int
smb_vop_open(vnode_t **vpp, int mode, cred_t *cred)
{
	return (VOP_OPEN(vpp, mode, cred, &smb_ct));
}

void
smb_vop_close(vnode_t *vp, int mode, cred_t *cred)
{
	(void) VOP_CLOSE(vp, mode, 1, (offset_t)0, cred, &smb_ct);
}

int
smb_vop_other_opens(vnode_t *vp, int mode)
{
	return (((mode & FWRITE) && vn_has_other_opens(vp, V_WRITE)) ||
	    (((mode & FWRITE) == 0) && vn_is_opened(vp, V_WRITE)) ||
	    ((mode & FREAD) && vn_has_other_opens(vp, V_READ)) ||
	    (((mode & FREAD) == 0) && vn_is_opened(vp, V_READ)) ||
	    vn_is_mapped(vp, V_RDORWR));
}

/*
 * The smb_vop_* functions have minimal knowledge of CIFS semantics and
 * serve as an interface to the VFS layer.
 *
 * Only smb_fsop_* layer functions should call smb_vop_* layer functions.
 * (Higher-level CIFS service code should never skip the smb_fsop_* layer
 * to call smb_vop_* layer functions directly.)
 */

/*
 * XXX - Extended attributes support in the file system assumed.
 * This is needed for full NT Streams functionality.
 */

int
smb_vop_read(vnode_t *vp, uio_t *uiop, cred_t *cr)
{
	int error;

	(void) VOP_RWLOCK(vp, V_WRITELOCK_FALSE, &smb_ct);
	error = VOP_READ(vp, uiop, 0, cr, &smb_ct);
	VOP_RWUNLOCK(vp, V_WRITELOCK_FALSE, &smb_ct);
	return (error);
}

int
smb_vop_write(vnode_t *vp, uio_t *uiop, int ioflag, uint32_t *lcount,
    cred_t *cr)
{
	int error;

	*lcount = uiop->uio_resid;

	uiop->uio_llimit = MAXOFFSET_T;

	(void) VOP_RWLOCK(vp, V_WRITELOCK_TRUE, &smb_ct);
	error = VOP_WRITE(vp, uiop, ioflag, cr, &smb_ct);
	VOP_RWUNLOCK(vp, V_WRITELOCK_TRUE, &smb_ct);

	*lcount -= uiop->uio_resid;

	return (error);
}

/*
 * smb_vop_getattr()
 *
 * smb_fsop_getattr()/smb_vop_getattr() should always be called from the CIFS
 * service (instead of calling VOP_GETATTR directly) to retrieve attributes
 * due to special processing needed for streams files.
 *
 * All attributes are retrieved.
 *
 * A named stream's attributes (as far as CIFS is concerned) are those of the
 * unnamed (i.e. data) stream (minus the size attribute), and the size of the
 * named stream.  Though the file system may store attributes other than size
 * with the named stream, these should not be used by CIFS for any purpose.
 *
 * When vp denotes a named stream, then unnamed_vp should be passed in (denoting
 * the corresponding unnamed stream).
 */

int
smb_vop_getattr(vnode_t *vp, vnode_t *unnamed_vp, smb_attr_t *ret_attr,
    int flags, cred_t *cr)
{
	int error;
	vnode_t *use_vp;
	smb_attr_t tmp_attr;
	xvattr_t tmp_xvattr;
	xoptattr_t *xoap = NULL;

	if (unnamed_vp)
		use_vp = unnamed_vp;
	else
		use_vp = vp;

	if (vfs_has_feature(use_vp->v_vfsp, VFSFT_XVATTR)) {
		xva_init(&tmp_xvattr);
		xoap = xva_getxoptattr(&tmp_xvattr);

		ASSERT(xoap);

		smb_sa_to_va_mask(ret_attr->sa_mask,
		    &tmp_xvattr.xva_vattr.va_mask);

		XVA_SET_REQ(&tmp_xvattr, XAT_READONLY);
		XVA_SET_REQ(&tmp_xvattr, XAT_HIDDEN);
		XVA_SET_REQ(&tmp_xvattr, XAT_SYSTEM);
		XVA_SET_REQ(&tmp_xvattr, XAT_ARCHIVE);
		XVA_SET_REQ(&tmp_xvattr, XAT_CREATETIME);

		if ((error = VOP_GETATTR(use_vp, &tmp_xvattr.xva_vattr, flags,
		    cr, &smb_ct)) != 0)
			return (error);

		ret_attr->sa_vattr = tmp_xvattr.xva_vattr;

		/*
		 * Copy special attributes to ret_attr parameter
		 */

		ret_attr->sa_dosattr = 0;

		ASSERT(tmp_xvattr.xva_vattr.va_mask & AT_XVATTR);

		xoap = xva_getxoptattr(&tmp_xvattr);
		ASSERT(xoap);

		if (XVA_ISSET_RTN(&tmp_xvattr, XAT_READONLY)) {
			if (xoap->xoa_readonly)
				ret_attr->sa_dosattr |= FILE_ATTRIBUTE_READONLY;
		}

		if (XVA_ISSET_RTN(&tmp_xvattr, XAT_HIDDEN)) {
			if (xoap->xoa_hidden)
				ret_attr->sa_dosattr |= FILE_ATTRIBUTE_HIDDEN;
		}

		if (XVA_ISSET_RTN(&tmp_xvattr, XAT_SYSTEM)) {
			if (xoap->xoa_system)
				ret_attr->sa_dosattr |= FILE_ATTRIBUTE_SYSTEM;
		}

		if (XVA_ISSET_RTN(&tmp_xvattr, XAT_ARCHIVE)) {
			if (xoap->xoa_archive)
				ret_attr->sa_dosattr |= FILE_ATTRIBUTE_ARCHIVE;
		}

		ret_attr->sa_crtime = xoap->xoa_createtime;

		if (unnamed_vp && (ret_attr->sa_mask & SMB_AT_SIZE)) {
			/*
			 * Retrieve stream size attribute into temporary
			 * structure, in case the underlying file system
			 * returns attributes other than the size (we do not
			 * want to have ret_attr's other fields get
			 * overwritten).
			 *
			 * Note that vp is used here, and not use_vp.
			 * Also, only AT_SIZE is needed.
			 */

			tmp_xvattr.xva_vattr.va_mask = AT_SIZE;

			if ((error = VOP_GETATTR(vp, &tmp_xvattr.xva_vattr,
			    flags, cr, &smb_ct)) != 0)
				return (error);

			ret_attr->sa_vattr.va_size =
			    tmp_xvattr.xva_vattr.va_size;

		}

		if (ret_attr->sa_vattr.va_type == VDIR) {
			ret_attr->sa_dosattr |= FILE_ATTRIBUTE_DIRECTORY;
		}

		return (error);
	}

	/*
	 * Support for file systems without VFSFT_XVATTR
	 */

	smb_sa_to_va_mask(ret_attr->sa_mask,
	    &ret_attr->sa_vattr.va_mask);

	error = VOP_GETATTR(use_vp, &ret_attr->sa_vattr, flags, cr, &smb_ct);

	if (error != 0)
		return (error);

	/*
	 * "Fake" DOS attributes and create time, filesystem doesn't support
	 * them.
	 */

	ret_attr->sa_dosattr = 0;
	ret_attr->sa_crtime = ret_attr->sa_vattr.va_mtime;

	if (unnamed_vp && (ret_attr->sa_mask & SMB_AT_SIZE)) {
		/*
		 * Retrieve stream size attribute into temporary structure,
		 * in case the underlying file system returns attributes
		 * other than the size (we do not want to have ret_attr's
		 * other fields get overwritten).
		 *
		 * Note that vp is used here, and not use_vp.
		 * Also, only AT_SIZE is needed.
		 */

		tmp_attr.sa_vattr.va_mask = AT_SIZE;
		error = VOP_GETATTR(vp, &tmp_attr.sa_vattr, flags, cr, &smb_ct);

		if (error != 0)
			return (error);


		ret_attr->sa_vattr.va_size = tmp_attr.sa_vattr.va_size;
	}

	if (ret_attr->sa_vattr.va_type == VDIR) {
		ret_attr->sa_dosattr |= FILE_ATTRIBUTE_DIRECTORY;
	}

	return (error);
}

/*
 * smb_vop_setattr()
 *
 * smb_fsop_setattr()/smb_vop_setattr() should always be used instead of
 * VOP_SETATTR() when calling from the CIFS service, due to special processing
 * for streams files.
 *
 * Streams have a size but otherwise do not have separate attributes from
 * the (unnamed stream) file, i.e., the security and ownership of the file
 * applies to the stream.  In contrast, extended attribute files, which are
 * used to implement streams, are independent objects with their own
 * attributes.
 *
 * For compatibility with streams, we set the size on the extended attribute
 * file and apply other attributes to the (unnamed stream) file.  The one
 * exception is that the UID and GID can be set on the stream by passing a
 * NULL unnamed_vp, which allows callers to synchronize stream ownership
 * with the (unnamed stream) file.
 */

int
smb_vop_setattr(vnode_t *vp, vnode_t *unnamed_vp, smb_attr_t *set_attr,
    int flags, cred_t *cr, boolean_t no_xvattr)
{
	int error = 0;
	int at_size = 0;
	vnode_t *use_vp;
	xvattr_t xvattr;
	vattr_t *vap;

	if (unnamed_vp) {
		use_vp = unnamed_vp;
		if (set_attr->sa_mask & SMB_AT_SIZE) {
			at_size = 1;
			set_attr->sa_mask &= ~SMB_AT_SIZE;
		}
	} else {
		use_vp = vp;
	}

	/*
	 * The caller should not be setting sa_vattr.va_mask,
	 * but rather sa_mask.
	 */

	set_attr->sa_vattr.va_mask = 0;

	if ((no_xvattr == B_FALSE) &&
	    vfs_has_feature(use_vp->v_vfsp, VFSFT_XVATTR)) {
		smb_vop_setup_xvattr(set_attr, &xvattr);
		vap = &xvattr.xva_vattr;
	} else {
		smb_sa_to_va_mask(set_attr->sa_mask,
		    &set_attr->sa_vattr.va_mask);
		vap = &set_attr->sa_vattr;
	}

	if ((error = VOP_SETATTR(use_vp, vap, flags, cr, &smb_ct)) != 0)
		return (error);

	/*
	 * If the size of the stream needs to be set, set it on
	 * the stream file directly.  (All other indicated attributes
	 * are set on the stream's unnamed stream, except under the
	 * exception described in the function header.)
	 */

	if (at_size) {
		/*
		 * set_attr->sa_vattr.va_size already contains the
		 * size as set by the caller
		 *
		 * Note that vp is used here, and not use_vp.
		 * Also, only AT_SIZE is needed.
		 */

		set_attr->sa_vattr.va_mask = AT_SIZE;
		error = VOP_SETATTR(vp, &set_attr->sa_vattr, flags, cr,
		    &smb_ct);
	}

	return (error);
}

/*
 * smb_vop_access
 *
 * This is a wrapper round VOP_ACCESS. VOP_ACCESS checks the given mode
 * against file's ACL or Unix permissions. CIFS on the other hand needs to
 * know if the requested operation can succeed for the given object, this
 * requires more checks in case of DELETE bit since permissions on the parent
 * directory are important as well. Based on Windows rules if parent's ACL
 * grant FILE_DELETE_CHILD a file can be delete regardless of the file's
 * permissions.
 */
int
smb_vop_access(vnode_t *vp, int mode, int flags, vnode_t *dir_vp, cred_t *cr)
{
	int error = 0;

	if (mode == 0)
		return (0);

	if ((flags == V_ACE_MASK) && (mode & ACE_DELETE)) {
		if (dir_vp) {
			error = VOP_ACCESS(dir_vp, ACE_DELETE_CHILD, flags,
			    cr, NULL);

			if (error == 0)
				mode &= ~ACE_DELETE;
		}
	}

	if (mode) {
		error = VOP_ACCESS(vp, mode, flags, cr, NULL);
	}

	return (error);
}

/*
 * smb_vop_lookup
 *
 * dvp:		directory vnode (in)
 * name:	name of file to be looked up (in)
 * vpp:		looked-up vnode (out)
 * od_name:	on-disk name of file (out).
 *		This parameter is optional.  If a pointer is passed in, it
 * 		must be allocated with MAXNAMELEN bytes
 * rootvp:	vnode of the tree root (in)
 *		This parameter is always passed in non-NULL except at the time
 *		of share set up.
 */

int
smb_vop_lookup(
    vnode_t		*dvp,
    char		*name,
    vnode_t		**vpp,
    char		*od_name,
    int			flags,
    vnode_t		*rootvp,
    cred_t		*cr)
{
	int error = 0;
	int option_flags = 0;
	pathname_t rpn;

	if (*name == '\0')
		return (EINVAL);

	ASSERT(vpp);
	*vpp = NULL;

	if ((name[0] == '.') && (name[1] == '.') && (name[2] == 0)) {
		if (rootvp && (dvp == rootvp)) {
			VN_HOLD(dvp);
			*vpp = dvp;
			return (0);
		}

		if (dvp->v_flag & VROOT) {
			vfs_t *vfsp;
			vnode_t *cvp = dvp;

			/*
			 * Set dvp and check for races with forced unmount
			 * (see lookuppnvp())
			 */

			vfsp = cvp->v_vfsp;
			vfs_rlock_wait(vfsp);
			if (((dvp = cvp->v_vfsp->vfs_vnodecovered) == NULL) ||
			    (cvp->v_vfsp->vfs_flag & VFS_UNMOUNTED)) {
				vfs_unlock(vfsp);
				return (EIO);
			}
			vfs_unlock(vfsp);
		}
	}



	if (flags & SMB_IGNORE_CASE)
		option_flags = FIGNORECASE;

	pn_alloc(&rpn);

	error = VOP_LOOKUP(dvp, name, vpp, NULL, option_flags, NULL, cr,
	    &smb_ct, NULL, &rpn);

	if ((error == 0) && od_name) {
		bzero(od_name, MAXNAMELEN);
		if (option_flags == FIGNORECASE)
			(void) strlcpy(od_name, rpn.pn_buf, MAXNAMELEN);
		else
			(void) strlcpy(od_name, name, MAXNAMELEN);
	}

	pn_free(&rpn);
	return (error);
}

int
smb_vop_create(vnode_t *dvp, char *name, smb_attr_t *attr, vnode_t **vpp,
    int flags, cred_t *cr, vsecattr_t *vsap)
{
	int error;
	int option_flags = 0;
	xvattr_t xvattr;
	vattr_t *vap;

	if (flags & SMB_IGNORE_CASE)
		option_flags = FIGNORECASE;

	attr->sa_vattr.va_mask = 0;

	if (vfs_has_feature(dvp->v_vfsp, VFSFT_XVATTR)) {
		smb_vop_setup_xvattr(attr, &xvattr);
		vap = &xvattr.xva_vattr;
	} else {
		smb_sa_to_va_mask(attr->sa_mask, &attr->sa_vattr.va_mask);
		vap = &attr->sa_vattr;
	}

	error = VOP_CREATE(dvp, name, vap, EXCL, attr->sa_vattr.va_mode,
	    vpp, cr, option_flags, &smb_ct, vsap);

	return (error);
}

int
smb_vop_remove(vnode_t *dvp, char *name, int flags, cred_t *cr)
{
	int error;
	int option_flags = 0;

	if (flags & SMB_IGNORE_CASE)
		option_flags = FIGNORECASE;

	error = VOP_REMOVE(dvp, name, cr, &smb_ct, option_flags);

	return (error);
}

/*
 * smb_vop_rename()
 *
 * The rename is for files in the same tree (identical TID) only.
 */

int
smb_vop_rename(vnode_t *from_dvp, char *from_name, vnode_t *to_dvp,
    char *to_name, int flags, cred_t *cr)
{
	int error;
	int option_flags = 0;


	if (flags & SMB_IGNORE_CASE)
		option_flags = FIGNORECASE;

	error = VOP_RENAME(from_dvp, from_name, to_dvp, to_name, cr,
	    &smb_ct, option_flags);

	return (error);
}

int
smb_vop_mkdir(vnode_t *dvp, char *name, smb_attr_t *attr, vnode_t **vpp,
    int flags, cred_t *cr, vsecattr_t *vsap)
{
	int error;
	int option_flags = 0;
	xvattr_t xvattr;
	vattr_t *vap;

	if (flags & SMB_IGNORE_CASE)
		option_flags = FIGNORECASE;

	attr->sa_vattr.va_mask = 0;

	if (vfs_has_feature(dvp->v_vfsp, VFSFT_XVATTR)) {
		smb_vop_setup_xvattr(attr, &xvattr);
		vap = &xvattr.xva_vattr;
	} else {
		smb_sa_to_va_mask(attr->sa_mask, &attr->sa_vattr.va_mask);
		vap = &attr->sa_vattr;
	}

	error = VOP_MKDIR(dvp, name, vap, vpp, cr, &smb_ct,
	    option_flags, vsap);

	return (error);
}

/*
 * smb_vop_rmdir()
 *
 * Only simple rmdir supported, consistent with NT semantics
 * (can only remove an empty directory).
 *
 */

int
smb_vop_rmdir(vnode_t *dvp, char *name, int flags, cred_t *cr)
{
	int error;
	int option_flags = 0;

	if (flags & SMB_IGNORE_CASE)
		option_flags = FIGNORECASE;

	/*
	 * Comments adapted from rfs_rmdir().
	 *
	 * VOP_RMDIR now takes a new third argument (the current
	 * directory of the process).  That's because rmdir
	 * wants to return EINVAL if one tries to remove ".".
	 * Of course, SMB servers do not know what their
	 * clients' current directories are.  We fake it by
	 * supplying a vnode known to exist and illegal to
	 * remove.
	 */

	error = VOP_RMDIR(dvp, name, rootdir, cr, &smb_ct, option_flags);
	return (error);
}

int
smb_vop_commit(vnode_t *vp, cred_t *cr)
{
	return (VOP_FSYNC(vp, 1, cr, &smb_ct));
}

void
smb_vop_setup_xvattr(smb_attr_t *smb_attr, xvattr_t *xvattr)
{
	xoptattr_t *xoap = NULL;
	uint_t xva_mask;

	/*
	 * Initialize xvattr, including bzero
	 */
	xva_init(xvattr);
	xoap = xva_getxoptattr(xvattr);

	ASSERT(xoap);

	/*
	 * Copy caller-specified classic attributes to xvattr.
	 * First save xvattr's mask (set in xva_init()), which
	 * contains AT_XVATTR.  This is |'d in later if needed.
	 */

	xva_mask = xvattr->xva_vattr.va_mask;
	xvattr->xva_vattr = smb_attr->sa_vattr;

	smb_sa_to_va_mask(smb_attr->sa_mask, &xvattr->xva_vattr.va_mask);

	/*
	 * Do not set ctime (only the file system can do it)
	 */

	xvattr->xva_vattr.va_mask &= ~AT_CTIME;

	if (smb_attr->sa_mask & SMB_AT_DOSATTR) {

		/*
		 * "|" in the original xva_mask, which contains
		 * AT_XVATTR
		 */

		xvattr->xva_vattr.va_mask |= xva_mask;

		XVA_SET_REQ(xvattr, XAT_ARCHIVE);
		XVA_SET_REQ(xvattr, XAT_SYSTEM);
		XVA_SET_REQ(xvattr, XAT_READONLY);
		XVA_SET_REQ(xvattr, XAT_HIDDEN);

		/*
		 * smb_attr->sa_dosattr: If a given bit is not set,
		 * that indicates that the corresponding field needs
		 * to be updated with a "0" value.  This is done
		 * implicitly as the xoap->xoa_* fields were bzero'd.
		 */

		if (smb_attr->sa_dosattr & FILE_ATTRIBUTE_ARCHIVE)
			xoap->xoa_archive = 1;

		if (smb_attr->sa_dosattr & FILE_ATTRIBUTE_SYSTEM)
			xoap->xoa_system = 1;

		if (smb_attr->sa_dosattr & FILE_ATTRIBUTE_READONLY)
			xoap->xoa_readonly = 1;

		if (smb_attr->sa_dosattr & FILE_ATTRIBUTE_HIDDEN)
			xoap->xoa_hidden = 1;
	}

	if (smb_attr->sa_mask & SMB_AT_CRTIME) {
		/*
		 * "|" in the original xva_mask, which contains
		 * AT_XVATTR
		 */

		xvattr->xva_vattr.va_mask |= xva_mask;
		XVA_SET_REQ(xvattr, XAT_CREATETIME);
		xoap->xoa_createtime = smb_attr->sa_crtime;
	}
}


/*
 * smb_vop_readdir()
 *
 * Upon return, the "name" field will contain either the on-disk name or, if
 * it needs mangling or has a case-insensitive collision, the mangled
 * "shortname."
 *
 * vpp is an optional parameter.  If non-NULL, it will contain a pointer to
 * the vnode for the name that is looked up (the vnode will be returned held).
 *
 * od_name is an optional parameter (NULL can be passed if the on-disk name
 * is not needed by the caller).
 */

int
smb_vop_readdir(vnode_t *dvp, uint32_t *cookiep, char *name, int *namelen,
    ino64_t *inop, vnode_t **vpp, char *od_name, int flags, cred_t *cr)
{
	int num_bytes;
	int error = 0;
	char *dirbuf = NULL;

	ASSERT(dvp);
	ASSERT(cookiep);
	ASSERT(name);
	ASSERT(namelen);
	ASSERT(inop);
	ASSERT(cr);

	if (dvp->v_type != VDIR) {
		*namelen = 0;
		return (ENOTDIR);
	}

	if (vpp)
		*vpp = NULL;

	dirbuf = kmem_zalloc(SMB_MINLEN_RDDIR_BUF, KM_SLEEP);
	num_bytes = SMB_MINLEN_RDDIR_BUF;

	/*
	 * The goal is to retrieve the first valid entry from *cookiep
	 * forward.  smb_vop_readdir_readpage() collects an
	 * SMB_MINLEN_RDDIR_BUF-size "page" of directory entry information.
	 * smb_vop_readdir_entry() attempts to find the first valid entry
	 * in that page.
	 */

	while ((error = smb_vop_readdir_readpage(dvp, dirbuf, *cookiep,
	    &num_bytes, cr)) == 0) {

		if (num_bytes <= 0)
			break;

		name[0] = '\0';

		error = smb_vop_readdir_entry(dvp, cookiep, name, namelen,
		    inop, vpp, od_name, flags, cr, dirbuf, num_bytes);

		if (error)
			break;

		if (*name)
			break;

		bzero(dirbuf, SMB_MINLEN_RDDIR_BUF);
		num_bytes = SMB_MINLEN_RDDIR_BUF;
	}


	if (error) {
		kmem_free(dirbuf, SMB_MINLEN_RDDIR_BUF);
		*namelen = 0;
		return (error);
	}

	if (num_bytes == 0) { /* EOF */
		kmem_free(dirbuf, SMB_MINLEN_RDDIR_BUF);
		*cookiep = SMB_EOF;
		*namelen = 0;
		return (0);
	}

	kmem_free(dirbuf, SMB_MINLEN_RDDIR_BUF);
	return (0);
}

/*
 * smb_vop_readdir_readpage()
 *
 * Collects an SMB_MINLEN_RDDIR_BUF "page" of directory entries.  (The
 * directory entries are returned in an fs-independent format by the
 * underlying file system.  That is, the "page" of information returned is
 * not literally stored on-disk in the format returned.)
 *
 * Much of the following is borrowed from getdents64()
 *
 * MAXGETDENTS_SIZE is defined in getdents.c
 */

#define	MAXGETDENTS_SIZE	(64 * 1024)

static int
smb_vop_readdir_readpage(vnode_t *vp, void *buf, uint32_t offset, int *count,
    cred_t *cr)
{
	int error = 0;
	int rdirent_flags = 0;
	int sink;
	struct uio auio;
	struct iovec aiov;

	if (vp->v_type != VDIR)
		return (ENOTDIR);

	if (vfs_has_feature(vp->v_vfsp, VFSFT_DIRENTFLAGS)) {
		/*
		 * Setting V_RDDIR_ENTFLAGS will cause the buffer to
		 * be filled with edirent_t structures (instead of
		 * dirent64_t structures).
		 */
		rdirent_flags = V_RDDIR_ENTFLAGS;

		if (*count < sizeof (edirent_t))
			return (EINVAL);
	} else {
		if (*count < sizeof (dirent64_t))
			return (EINVAL);
	}

	if (*count > MAXGETDENTS_SIZE)
		*count = MAXGETDENTS_SIZE;

	aiov.iov_base = buf;
	aiov.iov_len = *count;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_loffset = (uint64_t)offset;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_resid = *count;
	auio.uio_fmode = 0;

	(void) VOP_RWLOCK(vp, V_WRITELOCK_FALSE, &smb_ct);
	error = VOP_READDIR(vp, &auio, cr, &sink, &smb_ct, rdirent_flags);
	VOP_RWUNLOCK(vp, V_WRITELOCK_FALSE, &smb_ct);

	if (error) {
		if (error == ENOENT) {
			/* Fake EOF if offset is bad due to dropping of lock */
			*count = 0;
			return (0);
		} else {
			return (error);
		}
	}

	/*
	 * Windows cannot handle an offset > SMB_EOF.
	 * Pretend we are at EOF.
	 */

	if (auio.uio_loffset > SMB_EOF) {
		*count = 0;
		return (0);
	}

	*count = *count - auio.uio_resid;
	return (0);
}

/*
 * smb_vop_readdir_entry()
 *
 * This function retrieves the first valid entry from the
 * SMB_MINLEN_RDDIR_BUF-sized buffer returned by smb_vop_readdir_readpage()
 * to smb_vop_readdir().
 *
 * Both dirent64_t and edirent_t structures need to be handled.  The former is
 * needed for file systems that do not support VFSFT_DIRENTFLAGS.  The latter
 * is required for proper handling of case collisions on file systems that
 * support case-insensitivity.  edirent_t structures are also used for
 * case-sensitive file systems if VFSFT_DIRENTFLAGS is supported.
 */

static int
smb_vop_readdir_entry(
    vnode_t		*dvp,
    uint32_t		*cookiep,
    char		*name,
    int			*namelen,
    ino64_t		*inop,
    vnode_t		**vpp,
    char		*od_name,
    int			flags,
    cred_t		*cr,
    char		*dirbuf,
    int			 num_bytes)
{
	uint32_t next_cookie;
	int ebufsize;
	int error = 0;
	int len;
	int rc;
	char shortname[SMB_SHORTNAMELEN];
	char name83[SMB_SHORTNAMELEN];
	char *ebuf = NULL;
	edirent_t *edp;
	dirent64_t *dp = NULL;
	vnode_t *vp = NULL;

	ASSERT(dirbuf);

	/*
	 * Use edirent_t structure for both
	 */
	if (vfs_has_feature(dvp->v_vfsp, VFSFT_DIRENTFLAGS)) {
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		edp = (edirent_t *)dirbuf;
	} else {
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		dp = (dirent64_t *)dirbuf;
		ebufsize = EDIRENT_RECLEN(MAXNAMELEN);
		ebuf = kmem_zalloc(ebufsize, KM_SLEEP);
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		edp = (edirent_t *)ebuf;
	}

	while (edp) {
		if (dp)
			DP_TO_EDP(dp, edp);

		next_cookie = (uint32_t)edp->ed_off;
		if (edp->ed_ino == 0) {
			*cookiep = next_cookie;

			if (dp) {
				/*LINTED E_BAD_PTR_CAST_ALIGN*/
				DP_ADVANCE(dp, dirbuf, num_bytes);
				if (dp == NULL)
					edp = NULL;
			} else {
				/*LINTED E_BAD_PTR_CAST_ALIGN*/
				EDP_ADVANCE(edp, dirbuf, num_bytes);
			}
			continue;
		}

		len = strlen(edp->ed_name);

		if (*namelen < len) {
			*namelen = 0;

			if (ebuf)
				kmem_free(ebuf, ebufsize);

			return (EOVERFLOW);
		}

		/*
		 * Do not pass SMB_IGNORE_CASE to smb_vop_lookup
		 */

		error = smb_vop_lookup(dvp, edp->ed_name, vpp ? vpp : &vp,
		    od_name, 0, NULL, cr);

		if (error) {
			if (error == ENOENT) {
				*cookiep = (uint32_t)next_cookie;

				if (dp) {
					/*LINTED E_BAD_PTR_CAST_ALIGN*/
					DP_ADVANCE(dp, dirbuf, num_bytes);
					if (dp == NULL)
						edp = NULL;
				} else {
					/*LINTED E_BAD_PTR_CAST_ALIGN*/
					EDP_ADVANCE(edp, dirbuf, num_bytes);
				}
				continue;
			}


			*namelen = 0;

			if (ebuf)
				kmem_free(ebuf, ebufsize);

			return (error);
		}

		if ((flags & SMB_IGNORE_CASE) && ED_CASE_CONFLICTS(edp)) {
			rc = smb_mangle_name(edp->ed_ino, edp->ed_name,
			    shortname, name83, 1);

			if (rc == 1) { /* success */
				(void) strlcpy(name, shortname, *namelen + 1);
				*namelen = strlen(shortname);
			} else {
				(void) strlcpy(name, edp->ed_name,
				    *namelen + 1);
				name[*namelen] = '\0';
			}

		} else {
			(void) strlcpy(name, edp->ed_name, *namelen + 1);
				*namelen = len;
		}

		if (vpp == NULL)
			VN_RELE(vp);

		if (inop)
			*inop = edp->ed_ino;

		*cookiep = (uint32_t)next_cookie;
		break;
	}

	if (ebuf)
		kmem_free(ebuf, ebufsize);

	return (error);
}

/*
 * smb_sa_to_va_mask
 *
 * Set va_mask by running through the SMB_AT_* #define's and
 * setting those bits that correspond to the SMB_AT_* bits
 * set in sa_mask.
 */

void
smb_sa_to_va_mask(uint_t sa_mask, uint_t *va_maskp)
{
	int i;
	uint_t smask;

	smask = (sa_mask);
	for (i = SMB_AT_TYPE; (i < SMB_AT_MAX) && (smask != 0); ++i) {
		if (smask & 1)
			*(va_maskp) |= smb_attrmap[i];

		smask >>= 1;
	}
}

/*
 * smb_vop_getdents()
 *
 * Upon success, the smb_node corresponding to each entry returned will
 * have a reference taken on it.  These will be released in
 * smb_trans2_find_get_dents().
 *
 * If an error is returned from this routine, a list of already processed
 * entries will be returned.  The smb_nodes corresponding to these entries
 * will be referenced, and will be released in smb_trans2_find_get_dents().
 *
 * The returned dp->d_name field will contain either the on-disk name or, if
 * it needs mangling or has a case-insensitive collision, the mangled
 * "shortname."  In this case, the on-disk name can be retrieved from the
 * smb_node's od_name (the smb_node is passed to smb_gather_dents_info()).
 */

int /*ARGSUSED*/
smb_vop_getdents(
    smb_node_t		*dir_snode,
    uint32_t		*cookiep,
    uint64_t		*verifierp,
    int32_t		*dircountp,
    char		*arg,
    char		*pattern,
    uint32_t		flags,
    smb_request_t	*sr,
    cred_t		*cr)
{
	int		error = 0;
	int		maxentries;
	int		num_bytes;
	int		resid;
	char		*dirbuf = NULL;
	vnode_t		*dvp;
	/*LINTED E_BAD_PTR_CAST_ALIGN*/
	smb_dent_info_hdr_t *ihdr = (smb_dent_info_hdr_t *)arg;

	dvp = dir_snode->vp;

	resid = ihdr->uio.uio_resid;
	maxentries = resid / SMB_MAX_DENT_INFO_SIZE;

	bzero(ihdr->iov->iov_base, resid);

	dirbuf = kmem_alloc(SMB_MINLEN_RDDIR_BUF, KM_SLEEP);

	while (maxentries) {

		bzero(dirbuf, SMB_MINLEN_RDDIR_BUF);

		num_bytes = SMB_MINLEN_RDDIR_BUF;
		error = smb_vop_readdir_readpage(dvp, dirbuf, *cookiep,
		    &num_bytes, cr);

		if (error || (num_bytes <= 0))
			break;

		error = smb_vop_getdents_entries(dir_snode, cookiep, dircountp,
		    arg, flags, sr, cr, dirbuf, &maxentries, num_bytes,
		    pattern);

		if (error)
			goto out;
	}

	if (num_bytes < 0) {
		error = -1;
	} else if (num_bytes == 0) {
		*cookiep = SMB_EOF;
		error = 0;
	} else {
		error = 0;
	}

out:
	if (dirbuf)
		kmem_free(dirbuf, SMB_MINLEN_RDDIR_BUF);

	return (error);
}

/*
 * smb_vop_getdents_entries()
 *
 * This function retrieves names from the SMB_MINLEN_RDDIR_BUF-sized buffer
 * returned by smb_vop_readdir_readpage() to smb_vop_getdents().
 *
 * Both dirent64_t and edirent_t structures need to be handled.  The former is
 * needed for file systems that do not support VFSFT_DIRENTFLAGS.  The latter
 * is required for properly handling case collisions on file systems that
 * support case-insensitivity.  edirent_t is also used on case-sensitive
 * file systems where VFSFT_DIRENTFLAGS is available.
 */

static int
smb_vop_getdents_entries(
    smb_node_t		*dir_snode,
    uint32_t		*cookiep,
    int32_t		*dircountp,
    char		*arg,
    uint32_t		flags,
    smb_request_t	*sr,
    cred_t		*cr,
    char		*dirbuf,
    int			*maxentries,
    int			num_bytes,
    char		*pattern)
{
	uint32_t	next_cookie;
	int		ebufsize;
	char		*tmp_name;
	int		error;
	int		rc;
	char		shortname[SMB_SHORTNAMELEN];
	char		name83[SMB_SHORTNAMELEN];
	char		*ebuf = NULL;
	dirent64_t	*dp = NULL;
	edirent_t	*edp;
	smb_node_t	*ret_snode;
	smb_attr_t	ret_attr;
	vnode_t		*dvp;
	vnode_t		*fvp;

	ASSERT(dirbuf);

	dvp = dir_snode->vp;

	if (vfs_has_feature(dvp->v_vfsp, VFSFT_DIRENTFLAGS)) {
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		edp = (edirent_t *)dirbuf;
	} else {
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		dp = (dirent64_t *)dirbuf;
		ebufsize = EDIRENT_RECLEN(MAXNAMELEN);
		ebuf = kmem_zalloc(ebufsize, KM_SLEEP);
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		edp = (edirent_t *)ebuf;
	}

	while (edp) {
		if (dp)
			DP_TO_EDP(dp, edp);

		if (*maxentries == 0)
			break;

		next_cookie = (uint32_t)edp->ed_off;

		if (edp->ed_ino == 0) {
			*cookiep = next_cookie;
			if (dp) {
				/*LINTED E_BAD_PTR_CAST_ALIGN*/
				DP_ADVANCE(dp, dirbuf, num_bytes);
				if (dp == NULL)
					edp = NULL;
			} else {
				/*LINTED E_BAD_PTR_CAST_ALIGN*/
				EDP_ADVANCE(edp, dirbuf, num_bytes);
			}
			continue;
		}

		error = smb_vop_lookup(dvp, edp->ed_name, &fvp,
		    NULL, 0, NULL, cr);

		if (error) {
			if (error == ENOENT) {
				*cookiep = next_cookie;
				if (dp) {
					/*LINTED E_BAD_PTR_CAST_ALIGN*/
					DP_ADVANCE(dp, dirbuf,
					    num_bytes);
					if (dp == NULL)
						edp = NULL;
				} else {
					/*LINTED E_BAD_PTR_CAST_ALIGN*/
					EDP_ADVANCE(edp, dirbuf,
					    num_bytes);
				}
				continue;
			}
			if (ebuf)
				kmem_free(ebuf, ebufsize);

			return (error);
		}

		ret_snode = smb_node_lookup(sr, NULL, cr, fvp,
		    edp->ed_name, dir_snode, NULL, &ret_attr);

		if (ret_snode == NULL) {
			VN_RELE(fvp);

			if (ebuf)
				kmem_free(ebuf, ebufsize);

			return (ENOMEM);
		}

		if (smb_match_name(edp->ed_ino, edp->ed_name, shortname,
		    name83, pattern, (flags & SMB_IGNORE_CASE))) {

			tmp_name = edp->ed_name;

			if ((flags & SMB_IGNORE_CASE) &&
			    ED_CASE_CONFLICTS(edp)) {
				rc = smb_mangle_name(edp->ed_ino, edp->ed_name,
				    shortname, name83, 1);
				if (rc == 1)
					tmp_name = shortname;
			} else {
				rc = smb_mangle_name(edp->ed_ino, edp->ed_name,
				    shortname, name83, 0);
			}

			if (rc != 1) {
				(void) strlcpy(shortname, edp->ed_name,
				    SMB_SHORTNAMELEN);
				(void) strlcpy(name83, edp->ed_name,
				    SMB_SHORTNAMELEN);
				shortname[SMB_SHORTNAMELEN - 1] = '\0';
				name83[SMB_SHORTNAMELEN - 1] = '\0';
			}

			error = smb_gather_dents_info(arg, edp->ed_ino,
			    strlen(tmp_name), tmp_name, next_cookie, dircountp,
			    &ret_attr, ret_snode, shortname, name83);

			if (error > 0) {
				if (ebuf)
					kmem_free(ebuf, ebufsize);
				return (error);
			}

			/*
			 * Treat errors from smb_gather_dents_info() that are
			 * < 0 the same as EOF.
			 */
			if (error < 0) {
				if (ebuf)
					kmem_free(ebuf, ebufsize);
				*maxentries = 0;
				return (0);
			}
			(*maxentries)--;
		} else {
			smb_node_release(ret_snode);
		}

		*cookiep = next_cookie;

		if (dp) {
			/*LINTED E_BAD_PTR_CAST_ALIGN*/
			DP_ADVANCE(dp, dirbuf, num_bytes);
			if (dp == NULL)
				edp = NULL;
		} else {
			/*LINTED E_BAD_PTR_CAST_ALIGN*/
			EDP_ADVANCE(edp, dirbuf, num_bytes);
		}
	}

	if (ebuf)
		kmem_free(ebuf, ebufsize);

	return (0);
}

/*
 * smb_vop_stream_lookup()
 *
 * The name returned in od_name is the on-disk name of the stream with the
 * SMB_STREAM_PREFIX stripped off.  od_name should be allocated to MAXNAMELEN
 * by the caller.
 */

int
smb_vop_stream_lookup(
    vnode_t		*fvp,
    char		*stream_name,
    vnode_t		**vpp,
    char		*od_name,
    vnode_t		**xattrdirvpp,
    int			flags,
    vnode_t		*rootvp,
    cred_t		*cr)
{
	char *solaris_stream_name;
	char *name;
	int error;

	if ((error = smb_vop_lookup_xattrdir(fvp, xattrdirvpp,
	    LOOKUP_XATTR | CREATE_XATTR_DIR, cr)) != 0)
		return (error);

	/*
	 * Prepend SMB_STREAM_PREFIX to stream name
	 */

	solaris_stream_name = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	(void) sprintf(solaris_stream_name, "%s%s", SMB_STREAM_PREFIX,
	    stream_name);

	/*
	 * "name" will hold the on-disk name returned from smb_vop_lookup
	 * for the stream, including the SMB_STREAM_PREFIX.
	 */

	name = kmem_zalloc(MAXNAMELEN, KM_SLEEP);

	if ((error = smb_vop_lookup(*xattrdirvpp, solaris_stream_name, vpp,
	    name, flags, rootvp, cr)) != 0) {
		VN_RELE(*xattrdirvpp);
	} else {
		(void) strlcpy(od_name, &(name[SMB_STREAM_PREFIX_LEN]),
		    MAXNAMELEN);
	}

	kmem_free(solaris_stream_name, MAXNAMELEN);
	kmem_free(name, MAXNAMELEN);

	return (error);
}

int
smb_vop_stream_create(vnode_t *fvp, char *stream_name, smb_attr_t *attr,
    vnode_t **vpp, vnode_t **xattrdirvpp, int flags, cred_t *cr)
{
	char *solaris_stream_name;
	int error;

	if ((error = smb_vop_lookup_xattrdir(fvp, xattrdirvpp,
	    LOOKUP_XATTR | CREATE_XATTR_DIR, cr)) != 0)
		return (error);

	/*
	 * Prepend SMB_STREAM_PREFIX to stream name
	 */

	solaris_stream_name = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	(void) sprintf(solaris_stream_name, "%s%s", SMB_STREAM_PREFIX,
	    stream_name);

	if ((error = smb_vop_create(*xattrdirvpp, solaris_stream_name, attr,
	    vpp, flags, cr, NULL)) != 0)
		VN_RELE(*xattrdirvpp);

	kmem_free(solaris_stream_name, MAXNAMELEN);

	return (error);
}

int
smb_vop_stream_remove(vnode_t *vp, char *stream_name, int flags, cred_t *cr)
{
	char *solaris_stream_name;
	vnode_t *xattrdirvp;
	int error;

	error = smb_vop_lookup_xattrdir(vp, &xattrdirvp, LOOKUP_XATTR, cr);
	if (error != 0)
		return (error);

	/*
	 * Prepend SMB_STREAM_PREFIX to stream name
	 */

	solaris_stream_name = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	(void) sprintf(solaris_stream_name, "%s%s", SMB_STREAM_PREFIX,
	    stream_name);

	/* XXX might have to use kcred */
	error = smb_vop_remove(xattrdirvp, solaris_stream_name, flags, cr);

	kmem_free(solaris_stream_name, MAXNAMELEN);

	return (error);
}

/*
 * smb_vop_stream_readdir()
 *
 * Note: stream_info.size is not filled in in this routine.
 * It needs to be filled in by the caller due to the parameters for getattr.
 *
 * stream_info.name is set to the on-disk stream name with the SMB_STREAM_PREFIX
 * removed.
 */

int
smb_vop_stream_readdir(vnode_t *fvp, uint32_t *cookiep,
    struct fs_stream_info *stream_info, vnode_t **vpp, vnode_t **xattrdirvpp,
    int flags, cred_t *cr)
{
	int nsize;
	int error = 0;
	ino64_t ino;
	char *tmp_name;
	vnode_t *xattrdirvp;
	vnode_t *vp;

	if ((error = smb_vop_lookup_xattrdir(fvp, &xattrdirvp, LOOKUP_XATTR,
	    cr)) != 0)
		return (error);

	bzero(stream_info->name, sizeof (stream_info->name));
	stream_info->size = 0;

	tmp_name = kmem_zalloc(MAXNAMELEN, KM_SLEEP);

	for (;;) {
		nsize = MAXNAMELEN-1;
		error = smb_vop_readdir(xattrdirvp, cookiep, tmp_name, &nsize,
		    &ino, &vp, NULL, flags, cr);

		if (error || (*cookiep == SMB_EOF))
			break;

		if (strncmp(tmp_name, SMB_STREAM_PREFIX,
		    SMB_STREAM_PREFIX_LEN)) {
			VN_RELE(vp);
			continue;
		}

		tmp_name[nsize] = '\0';
		(void) strlcpy(stream_info->name,
		    &(tmp_name[SMB_STREAM_PREFIX_LEN]),
		    sizeof (stream_info->name));

		nsize -= SMB_STREAM_PREFIX_LEN;
		break;
	}

	if ((error == 0) && nsize) {
		if (vpp)
			*vpp = vp;
		else
			VN_RELE(vp);

		if (xattrdirvpp)
			*xattrdirvpp = xattrdirvp;
		else
			VN_RELE(xattrdirvp);

	} else {
		VN_RELE(xattrdirvp);
	}

	kmem_free(tmp_name, MAXNAMELEN);

	return (error);
}

int
smb_vop_lookup_xattrdir(vnode_t *fvp, vnode_t **xattrdirvpp, int flags,
    cred_t *cr)
{
	int error;

	error = VOP_LOOKUP(fvp, "", xattrdirvpp, NULL, flags, NULL, cr,
	    &smb_ct, NULL, NULL);
	return (error);
}

/*
 * smb_vop_traverse_check()
 *
 * This function checks to see if the passed-in vnode has a file system
 * mounted on it.  If it does, the mount point is "traversed" and the
 * vnode for the root of the file system is returned.
 */

int
smb_vop_traverse_check(vnode_t **vpp)
{
	int error;

	if (vn_mountedvfs(*vpp) == 0)
		return (0);

	/*
	 * traverse() may return a different held vnode, even in the error case.
	 * If it returns a different vnode, it will have released the original.
	 */

	error = traverse(vpp);

	return (error);
}

int /*ARGSUSED*/
smb_vop_statfs(vnode_t *vp, struct statvfs64 *statp, cred_t *cr)
{
	int error;

	error = VFS_STATVFS(vp->v_vfsp, statp);

	return (error);
}

/*
 * smb_vop_acl_read
 *
 * Reads the ACL of the specified file into 'aclp'.
 * acl_type is the type of ACL which the filesystem supports.
 *
 * Caller has to free the allocated memory for aclp by calling
 * acl_free().
 */
int
smb_vop_acl_read(vnode_t *vp, acl_t **aclp, int flags, acl_type_t acl_type,
    cred_t *cr)
{
	int error;
	vsecattr_t vsecattr;

	ASSERT(vp);
	ASSERT(aclp);

	*aclp = NULL;
	bzero(&vsecattr, sizeof (vsecattr_t));

	switch (acl_type) {
	case ACLENT_T:
		vsecattr.vsa_mask = VSA_ACL | VSA_ACLCNT | VSA_DFACL |
		    VSA_DFACLCNT;
		break;

	case ACE_T:
		vsecattr.vsa_mask = VSA_ACE | VSA_ACECNT | VSA_ACE_ACLFLAGS;
		break;

	default:
		return (EINVAL);
	}

	if (error = VOP_GETSECATTR(vp, &vsecattr, flags, cr, &smb_ct))
		return (error);

	*aclp = smb_fsacl_from_vsa(&vsecattr, acl_type);
	if (vp->v_type == VDIR)
		(*aclp)->acl_flags |= ACL_IS_DIR;

	return (0);
}

/*
 * smb_vop_acl_write
 *
 * Writes the given ACL in aclp for the specified file.
 */
int
smb_vop_acl_write(vnode_t *vp, acl_t *aclp, int flags, cred_t *cr)
{
	int error;
	vsecattr_t vsecattr;
	int aclbsize;

	ASSERT(vp);
	ASSERT(aclp);

	error = smb_fsacl_to_vsa(aclp, &vsecattr, &aclbsize);

	if (error == 0) {
		(void) VOP_RWLOCK(vp, V_WRITELOCK_TRUE, &smb_ct);
		error = VOP_SETSECATTR(vp, &vsecattr, flags, cr, &smb_ct);
		VOP_RWUNLOCK(vp, V_WRITELOCK_TRUE, &smb_ct);
	}

	if (aclbsize && vsecattr.vsa_aclentp)
		kmem_free(vsecattr.vsa_aclentp, aclbsize);

	return (error);
}

/*
 * smb_vop_acl_type
 *
 * Determines the ACL type for the given vnode.
 * ACLENT_T is a Posix ACL and ACE_T is a ZFS ACL.
 */
acl_type_t
smb_vop_acl_type(vnode_t *vp)
{
	int error;
	ulong_t whichacl;

	error = VOP_PATHCONF(vp, _PC_ACL_ENABLED, &whichacl, kcred, NULL);
	if (error != 0) {
		/*
		 * If we got an error, then the filesystem
		 * likely does not understand the _PC_ACL_ENABLED
		 * pathconf.  In this case, we fall back to trying
		 * POSIX-draft (aka UFS-style) ACLs.
		 */
		whichacl = _ACL_ACLENT_ENABLED;
	}

	if (!(whichacl & (_ACL_ACE_ENABLED | _ACL_ACLENT_ENABLED))) {
		/*
		 * If the file system supports neither ACE nor
		 * ACLENT ACLs we will fall back to UFS-style ACLs
		 * like we did above if there was an error upon
		 * calling VOP_PATHCONF.
		 *
		 * ACE and ACLENT type ACLs are the only interfaces
		 * supported thus far.  If any other bits are set on
		 * 'whichacl' upon return from VOP_PATHCONF, we will
		 * ignore them.
		 */
		whichacl = _ACL_ACLENT_ENABLED;
	}

	if (whichacl == _ACL_ACLENT_ENABLED)
		return (ACLENT_T);

	return (ACE_T);
}

static int zfs_perms[] = {
	ACE_READ_DATA, ACE_WRITE_DATA, ACE_APPEND_DATA, ACE_READ_NAMED_ATTRS,
	ACE_WRITE_NAMED_ATTRS, ACE_EXECUTE, ACE_DELETE_CHILD,
	ACE_READ_ATTRIBUTES, ACE_WRITE_ATTRIBUTES, ACE_DELETE, ACE_READ_ACL,
	ACE_WRITE_ACL, ACE_WRITE_OWNER, ACE_SYNCHRONIZE
};

static int unix_perms[] = { VREAD, VWRITE, VEXEC };
/*
 * smb_vop_eaccess
 *
 * Returns the effective permission of the given credential for the
 * specified object.
 *
 * This is just a workaround. We need VFS/FS support for this.
 */
void
smb_vop_eaccess(vnode_t *vp, int *mode, int flags, vnode_t *dir_vp, cred_t *cr)
{
	int error, i;
	int pnum;

	*mode = 0;

	if (flags == V_ACE_MASK) {
		pnum = sizeof (zfs_perms) / sizeof (int);

		for (i = 0; i < pnum; i++) {
			error = smb_vop_access(vp, zfs_perms[i], flags,
			    dir_vp, cr);
			if (error == 0)
				*mode |= zfs_perms[i];
		}
	} else {
		pnum = sizeof (unix_perms) / sizeof (int);

		for (i = 0; i < pnum; i++) {
			error = smb_vop_access(vp, unix_perms[i], flags,
			    dir_vp, cr);
			if (error == 0)
				*mode |= unix_perms[i];
		}
	}
}

/*
 * smb_vop_shrlock()
 *
 * See comments for smb_fsop_shrlock()
 */

int
smb_vop_shrlock(vnode_t *vp, uint32_t uniq_fid, uint32_t desired_access,
    uint32_t share_access, cred_t *cr)
{
	struct shrlock shr;
	struct shr_locowner shr_own;
	short new_access = 0;
	short deny = 0;
	int flag = 0;
	int cmd;

	cmd = (nbl_need_check(vp)) ? F_SHARE_NBMAND : F_SHARE;

	/*
	 * Check if this is a metadata access
	 */

	if ((desired_access & FILE_DATA_ALL) == 0) {
		new_access |= F_MDACC;
	} else {
		if (desired_access & (ACE_READ_DATA | ACE_EXECUTE)) {
			new_access |= F_RDACC;
			flag |= FREAD;
		}

		if (desired_access & (ACE_WRITE_DATA | ACE_APPEND_DATA |
		    ACE_ADD_FILE)) {
			new_access |= F_WRACC;
			flag |= FWRITE;
		}

		if (SMB_DENY_READ(share_access)) {
			deny |= F_RDDNY;
		}

		if (SMB_DENY_WRITE(share_access)) {
			deny |= F_WRDNY;
		}

		if (cmd == F_SHARE_NBMAND) {
			if (desired_access & ACE_DELETE)
				new_access |= F_RMACC;

			if (SMB_DENY_DELETE(share_access)) {
				deny |= F_RMDNY;
			}
		}
	}

	shr.s_access = new_access;
	shr.s_deny = deny;
	shr.s_sysid = smb_ct.cc_sysid;
	shr.s_pid = uniq_fid;
	shr.s_own_len = sizeof (shr_own);
	shr.s_owner = (caddr_t)&shr_own;
	shr_own.sl_id = shr.s_sysid;
	shr_own.sl_pid = shr.s_pid;

	return (VOP_SHRLOCK(vp, cmd, &shr, flag, cr, NULL));
}

int
smb_vop_unshrlock(vnode_t *vp, uint32_t uniq_fid, cred_t *cr)
{
	struct shrlock shr;
	struct shr_locowner shr_own;

	/*
	 * For s_access and s_deny, we do not need to pass in the original
	 * values.
	 */

	shr.s_access = 0;
	shr.s_deny = 0;
	shr.s_sysid = smb_ct.cc_sysid;
	shr.s_pid = uniq_fid;
	shr.s_own_len = sizeof (shr_own);
	shr.s_owner = (caddr_t)&shr_own;
	shr_own.sl_id = shr.s_sysid;
	shr_own.sl_pid = shr.s_pid;

	return (VOP_SHRLOCK(vp, F_UNSHARE, &shr, 0, cr, NULL));
}

int
smb_vop_frlock(vnode_t *vp, cred_t *cr, int flag, flock64_t *bf)
{
	int cmd = nbl_need_check(vp) ? F_SETLK_NBMAND : F_SETLK;
	flk_callback_t flk_cb;

	flk_init_callback(&flk_cb, smb_lock_frlock_callback, NULL);

	return (VOP_FRLOCK(vp, cmd, bf, flag, 0, &flk_cb, cr, &smb_ct));
}

static callb_cpr_t *
/* ARGSUSED */
smb_lock_frlock_callback(flk_cb_when_t when, void *error)
{
	return (0);
}
