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
 * Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Big Theory Statement for Extended Attribute (XATTR) directories
 *
 * The Solaris VFS layer presents extended file attributes using a special
 * "XATTR" directory under files or directories that have extended file
 * attributes.  See fsattr(5) for background.
 *
 * This design avoids the need for a separate set of VFS or vnode functions
 * for operating on XATTR objects.  File system implementations that support
 * XATTR instantiate a special XATTR directory using this module.
 * Applications get to the XATTR directory by passing the LOOKUP_XATTR flag
 * to fop_lookup.  Once the XATTR directory is obtained, all other file
 * system operations on extended attributes happen via the normal vnode
 * functions, applied to the XATTR directory or its contents.
 *
 * The XATTR directories returned by fop_lookup (with LOOKUP_XATTR) are
 * implemented differntly, depending on whether the file system supports
 * "extended attributes" (XATTR), "system attributes" (SYSATTR), or both.
 *
 * When SYSATTR=true, XATTR=true:
 *	The XATTR directory is a "generic file system" (GFS) object
 *	that adds the special system attribute names (SUNWattr*) to
 *	the list of XATTR files presented by the underling FS.
 *	In this case, many operations are "passed through" to the
 *	lower-level FS.
 *
 * When SYSATTR=true, XATTR=false:
 *	The XATTR directory is a "generic file system" (GFS) object,
 *	presenting only the system attribute names (SUNWattr*)
 *	In this case there's no lower-level FS, only the GFS object.
 *
 * When SYSATTR=false, XATTR=true:
 *	The XATTR directory is implemented by the file system code,
 *	and this module is not involved after xattr_dir_lookup()
 *	returns the XATTR dir from the underlying file system.
 *
 * When SYSATTR=false, XATTR=false:
 *	xattr_dir_lookup just returns EINVAL
 *
 * In the first two cases (where we have system attributes) this module
 * implements what can be thought of as a "translucent" directory containing
 * both the system attribute names (SUNWattr*) and whatever XATTR names may
 * exist in the XATTR directory of the underlying file system, if any.
 *
 * This affects operations on the (GFS) XATTR directory as follows:
 *
 * readdir:	Merges the SUNWattr* names with any contents from the
 *		underlying XATTR directory.
 *
 * rename:	If "to" or "from" is a SUNWattr name, special handling,
 *		else pass through to the lower FS.
 *
 * link:	If "from" is a SUNWattr name, disallow.
 *
 * create:	If a SUNWattr name, disallow, else pass to lower FS.
 * remove:	(same)
 *
 * open,close:	Just pass through to the XATTR dir in the lower FS.
 *
 * lookup:	Lookup an XATTR file in either the (GFS) XATTR directory
 *		or the "real" XATTR directory of the underlying FS.
 *		Note for file systems the support SYSATTR but not XATTR,
 *		only the GFS XATTR directory will exist.  When both exist,
 *		gfs_vop_lookup uses the xattr_lookup_cb callback function
 *		which passes the lookup call through to the "real" FS.
 *
 * Operations on the XATTR _files_ are simpler:
 *
 * If the file vnode came from lookup at the GFS level, the file is one of
 * the special SUNWattr* vnodes, and it's vnode operations (xattr_file_tops)
 * allow only what's appropriate on these "files".
 *
 * If the file vnode came from the underlying FS, all operations on that
 * object are handled through the vnode operations set by that FS.
 */

#include <sys/param.h>
#include <sys/isa_defs.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/cred.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/pathname.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/acl.h>
#include <sys/file.h>
#include <sys/sunddi.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/vnode.h>
#include <sys/mode.h>
#include <sys/nvpair.h>
#include <sys/attr.h>
#include <sys/gfs.h>
#include <sys/mutex.h>
#include <fs/fs_subr.h>
#include <sys/kidmap.h>

typedef struct {
	gfs_file_t	xattr_gfs_private;
	xattr_view_t	xattr_view;
} xattr_file_t;

typedef struct {
	gfs_dir_t	xattr_gfs_private;
	vnode_t		*xattr_realvp;
} xattr_dir_t;

/* ARGSUSED */
static int
xattr_file_open(vnode_t **vpp, int flags, cred_t *cr, caller_context_t *ct)
{
	xattr_file_t *np = (*vpp)->v_data;

	if ((np->xattr_view == XATTR_VIEW_READONLY) && (flags & FWRITE))
		return (EACCES);

	return (0);
}

/* ARGSUSED */
static int
xattr_file_access(vnode_t *vp, int mode, int flags, cred_t *cr,
    caller_context_t *ct)
{
	xattr_file_t *np = vp->v_data;

	if ((np->xattr_view == XATTR_VIEW_READONLY) && (mode & VWRITE))
		return (EACCES);

	return (0);
}

/* ARGSUSED */
static int
xattr_file_close(vnode_t *vp, int flags, int count, offset_t off,
    cred_t *cr, caller_context_t *ct)
{
	cleanlocks(vp, ddi_get_pid(), 0);
	cleanshares(vp, ddi_get_pid());
	return (0);
}

static int
xattr_common_fid(vnode_t *vp, fid_t *fidp, caller_context_t *ct)
{
	xattr_fid_t	*xfidp;
	vnode_t		*pvp, *savevp;
	int		error;
	uint16_t	orig_len;

	if (fidp->fid_len < XATTR_FIDSZ) {
		fidp->fid_len = XATTR_FIDSZ;
		return (ENOSPC);
	}

	savevp = pvp = gfs_file_parent(vp);
	mutex_enter(&savevp->v_lock);
	if (pvp->v_flag & V_XATTRDIR) {
		pvp = gfs_file_parent(pvp);
	}
	mutex_exit(&savevp->v_lock);

	xfidp = (xattr_fid_t *)fidp;
	orig_len = fidp->fid_len;
	fidp->fid_len = sizeof (xfidp->parent_fid);

	error = VOP_FID(pvp, fidp, ct);
	if (error) {
		fidp->fid_len = orig_len;
		return (error);
	}

	xfidp->parent_len = fidp->fid_len;
	fidp->fid_len = XATTR_FIDSZ;
	xfidp->dir_offset = gfs_file_inode(vp);

	return (0);
}

/* ARGSUSED */
static int
xattr_fill_nvlist(vnode_t *vp, xattr_view_t xattr_view, nvlist_t *nvlp,
    cred_t *cr, caller_context_t *ct)
{
	int error;
	f_attr_t attr;
	uint64_t fsid;
	xvattr_t xvattr;
	xoptattr_t *xoap;	/* Pointer to optional attributes */
	vnode_t *ppvp;
	const char *domain;
	uint32_t rid;

	xva_init(&xvattr);

	if ((xoap = xva_getxoptattr(&xvattr)) == NULL)
		return (EINVAL);

	/*
	 * For detecting ephemeral uid/gid
	 */
	xvattr.xva_vattr.va_mask |= (AT_UID|AT_GID);

	/*
	 * We need to access the real fs object.
	 * vp points to a GFS file; ppvp points to the real object.
	 */
	ppvp = gfs_file_parent(gfs_file_parent(vp));

	/*
	 * Iterate through the attrs associated with this view
	 */

	for (attr = 0; attr < F_ATTR_ALL; attr++) {
		if (xattr_view != attr_to_xattr_view(attr)) {
			continue;
		}

		switch (attr) {
		case F_SYSTEM:
			XVA_SET_REQ(&xvattr, XAT_SYSTEM);
			break;
		case F_READONLY:
			XVA_SET_REQ(&xvattr, XAT_READONLY);
			break;
		case F_HIDDEN:
			XVA_SET_REQ(&xvattr, XAT_HIDDEN);
			break;
		case F_ARCHIVE:
			XVA_SET_REQ(&xvattr, XAT_ARCHIVE);
			break;
		case F_IMMUTABLE:
			XVA_SET_REQ(&xvattr, XAT_IMMUTABLE);
			break;
		case F_APPENDONLY:
			XVA_SET_REQ(&xvattr, XAT_APPENDONLY);
			break;
		case F_NOUNLINK:
			XVA_SET_REQ(&xvattr, XAT_NOUNLINK);
			break;
		case F_OPAQUE:
			XVA_SET_REQ(&xvattr, XAT_OPAQUE);
			break;
		case F_NODUMP:
			XVA_SET_REQ(&xvattr, XAT_NODUMP);
			break;
		case F_AV_QUARANTINED:
			XVA_SET_REQ(&xvattr, XAT_AV_QUARANTINED);
			break;
		case F_AV_MODIFIED:
			XVA_SET_REQ(&xvattr, XAT_AV_MODIFIED);
			break;
		case F_AV_SCANSTAMP:
			if (ppvp->v_type == VREG)
				XVA_SET_REQ(&xvattr, XAT_AV_SCANSTAMP);
			break;
		case F_CRTIME:
			XVA_SET_REQ(&xvattr, XAT_CREATETIME);
			break;
		case F_FSID:
			fsid = (((uint64_t)vp->v_vfsp->vfs_fsid.val[0] << 32) |
			    (uint64_t)(vp->v_vfsp->vfs_fsid.val[1] &
			    0xffffffff));
			VERIFY(nvlist_add_uint64(nvlp, attr_to_name(attr),
			    fsid) == 0);
			break;
		case F_REPARSE:
			XVA_SET_REQ(&xvattr, XAT_REPARSE);
			break;
		case F_GEN:
			XVA_SET_REQ(&xvattr, XAT_GEN);
			break;
		case F_OFFLINE:
			XVA_SET_REQ(&xvattr, XAT_OFFLINE);
			break;
		case F_SPARSE:
			XVA_SET_REQ(&xvattr, XAT_SPARSE);
			break;
		default:
			break;
		}
	}

	error = VOP_GETATTR(ppvp, &xvattr.xva_vattr, 0, cr, ct);
	if (error)
		return (error);

	/*
	 * Process all the optional attributes together here.  Notice that
	 * xoap was set when the optional attribute bits were set above.
	 */
	if ((xvattr.xva_vattr.va_mask & AT_XVATTR) && xoap) {
		if (XVA_ISSET_RTN(&xvattr, XAT_READONLY)) {
			VERIFY(nvlist_add_boolean_value(nvlp,
			    attr_to_name(F_READONLY),
			    xoap->xoa_readonly) == 0);
		}
		if (XVA_ISSET_RTN(&xvattr, XAT_HIDDEN)) {
			VERIFY(nvlist_add_boolean_value(nvlp,
			    attr_to_name(F_HIDDEN),
			    xoap->xoa_hidden) == 0);
		}
		if (XVA_ISSET_RTN(&xvattr, XAT_SYSTEM)) {
			VERIFY(nvlist_add_boolean_value(nvlp,
			    attr_to_name(F_SYSTEM),
			    xoap->xoa_system) == 0);
		}
		if (XVA_ISSET_RTN(&xvattr, XAT_ARCHIVE)) {
			VERIFY(nvlist_add_boolean_value(nvlp,
			    attr_to_name(F_ARCHIVE),
			    xoap->xoa_archive) == 0);
		}
		if (XVA_ISSET_RTN(&xvattr, XAT_IMMUTABLE)) {
			VERIFY(nvlist_add_boolean_value(nvlp,
			    attr_to_name(F_IMMUTABLE),
			    xoap->xoa_immutable) == 0);
		}
		if (XVA_ISSET_RTN(&xvattr, XAT_NOUNLINK)) {
			VERIFY(nvlist_add_boolean_value(nvlp,
			    attr_to_name(F_NOUNLINK),
			    xoap->xoa_nounlink) == 0);
		}
		if (XVA_ISSET_RTN(&xvattr, XAT_APPENDONLY)) {
			VERIFY(nvlist_add_boolean_value(nvlp,
			    attr_to_name(F_APPENDONLY),
			    xoap->xoa_appendonly) == 0);
		}
		if (XVA_ISSET_RTN(&xvattr, XAT_NODUMP)) {
			VERIFY(nvlist_add_boolean_value(nvlp,
			    attr_to_name(F_NODUMP),
			    xoap->xoa_nodump) == 0);
		}
		if (XVA_ISSET_RTN(&xvattr, XAT_OPAQUE)) {
			VERIFY(nvlist_add_boolean_value(nvlp,
			    attr_to_name(F_OPAQUE),
			    xoap->xoa_opaque) == 0);
		}
		if (XVA_ISSET_RTN(&xvattr, XAT_AV_QUARANTINED)) {
			VERIFY(nvlist_add_boolean_value(nvlp,
			    attr_to_name(F_AV_QUARANTINED),
			    xoap->xoa_av_quarantined) == 0);
		}
		if (XVA_ISSET_RTN(&xvattr, XAT_AV_MODIFIED)) {
			VERIFY(nvlist_add_boolean_value(nvlp,
			    attr_to_name(F_AV_MODIFIED),
			    xoap->xoa_av_modified) == 0);
		}
		if (XVA_ISSET_RTN(&xvattr, XAT_AV_SCANSTAMP)) {
			VERIFY(nvlist_add_uint8_array(nvlp,
			    attr_to_name(F_AV_SCANSTAMP),
			    xoap->xoa_av_scanstamp,
			    sizeof (xoap->xoa_av_scanstamp)) == 0);
		}
		if (XVA_ISSET_RTN(&xvattr, XAT_CREATETIME)) {
			VERIFY(nvlist_add_uint64_array(nvlp,
			    attr_to_name(F_CRTIME),
			    (uint64_t *)&(xoap->xoa_createtime),
			    sizeof (xoap->xoa_createtime) /
			    sizeof (uint64_t)) == 0);
		}
		if (XVA_ISSET_RTN(&xvattr, XAT_REPARSE)) {
			VERIFY(nvlist_add_boolean_value(nvlp,
			    attr_to_name(F_REPARSE),
			    xoap->xoa_reparse) == 0);
		}
		if (XVA_ISSET_RTN(&xvattr, XAT_GEN)) {
			VERIFY(nvlist_add_uint64(nvlp,
			    attr_to_name(F_GEN),
			    xoap->xoa_generation) == 0);
		}
		if (XVA_ISSET_RTN(&xvattr, XAT_OFFLINE)) {
			VERIFY(nvlist_add_boolean_value(nvlp,
			    attr_to_name(F_OFFLINE),
			    xoap->xoa_offline) == 0);
		}
		if (XVA_ISSET_RTN(&xvattr, XAT_SPARSE)) {
			VERIFY(nvlist_add_boolean_value(nvlp,
			    attr_to_name(F_SPARSE),
			    xoap->xoa_sparse) == 0);
		}
	}
	/*
	 * Check for optional ownersid/groupsid
	 */

	if (xvattr.xva_vattr.va_uid > MAXUID) {
		nvlist_t *nvl_sid;

		if (nvlist_alloc(&nvl_sid, NV_UNIQUE_NAME, KM_SLEEP))
			return (ENOMEM);

		if (kidmap_getsidbyuid(crgetzone(cr), xvattr.xva_vattr.va_uid,
		    &domain, &rid) == 0) {
			VERIFY(nvlist_add_string(nvl_sid,
			    SID_DOMAIN, domain) == 0);
			VERIFY(nvlist_add_uint32(nvl_sid, SID_RID, rid) == 0);
			VERIFY(nvlist_add_nvlist(nvlp, attr_to_name(F_OWNERSID),
			    nvl_sid) == 0);
		}
		nvlist_free(nvl_sid);
	}
	if (xvattr.xva_vattr.va_gid > MAXUID) {
		nvlist_t *nvl_sid;

		if (nvlist_alloc(&nvl_sid, NV_UNIQUE_NAME, KM_SLEEP))
			return (ENOMEM);

		if (kidmap_getsidbygid(crgetzone(cr), xvattr.xva_vattr.va_gid,
		    &domain, &rid) == 0) {
			VERIFY(nvlist_add_string(nvl_sid,
			    SID_DOMAIN, domain) == 0);
			VERIFY(nvlist_add_uint32(nvl_sid, SID_RID, rid) == 0);
			VERIFY(nvlist_add_nvlist(nvlp, attr_to_name(F_GROUPSID),
			    nvl_sid) == 0);
		}
		nvlist_free(nvl_sid);
	}

	return (0);
}

/*
 * The size of a sysattr file is the size of the nvlist that will be
 * returned by xattr_file_read().  A call to xattr_file_write() could
 * change the size of that nvlist.  That size is not stored persistently
 * so xattr_fill_nvlist() calls VOP_GETATTR so that it can be calculated.
 */
static int
xattr_file_size(vnode_t *vp, xattr_view_t xattr_view, size_t *size,
    cred_t *cr, caller_context_t *ct)
{
	nvlist_t *nvl;

	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, KM_SLEEP)) {
		return (ENOMEM);
	}

	if (xattr_fill_nvlist(vp, xattr_view, nvl, cr, ct)) {
		nvlist_free(nvl);
		return (EFAULT);
	}

	VERIFY(nvlist_size(nvl, size, NV_ENCODE_XDR) == 0);
	nvlist_free(nvl);
	return (0);
}

/* ARGSUSED */
static int
xattr_file_getattr(vnode_t *vp, vattr_t *vap, int flags, cred_t *cr,
    caller_context_t *ct)
{
	xattr_file_t *np = vp->v_data;
	timestruc_t now;
	size_t size;
	int error;
	vnode_t *pvp;
	vattr_t pvattr;

	vap->va_type = VREG;
	vap->va_mode = MAKEIMODE(vap->va_type,
	    (np->xattr_view == XATTR_VIEW_READONLY ? 0444 : 0644));
	vap->va_nodeid = gfs_file_inode(vp);
	vap->va_nlink = 1;
	pvp = gfs_file_parent(vp);
	(void) memset(&pvattr, 0, sizeof (pvattr));
	pvattr.va_mask = AT_CTIME|AT_MTIME;
	error = VOP_GETATTR(pvp, &pvattr, flags, cr, ct);
	if (error) {
		return (error);
	}
	vap->va_ctime = pvattr.va_ctime;
	vap->va_mtime = pvattr.va_mtime;
	gethrestime(&now);
	vap->va_atime = now;
	vap->va_uid = 0;
	vap->va_gid = 0;
	vap->va_rdev = 0;
	vap->va_blksize = DEV_BSIZE;
	vap->va_seq = 0;
	vap->va_fsid = vp->v_vfsp->vfs_dev;
	error = xattr_file_size(vp, np->xattr_view, &size, cr, ct);
	vap->va_size = size;
	vap->va_nblocks = howmany(vap->va_size, vap->va_blksize);
	return (error);
}

/* ARGSUSED */
static int
xattr_file_read(vnode_t *vp, uio_t *uiop, int ioflag, cred_t *cr,
    caller_context_t *ct)
{
	xattr_file_t *np = vp->v_data;
	xattr_view_t xattr_view = np->xattr_view;
	char *buf;
	size_t filesize;
	nvlist_t *nvl;
	int error;

	/*
	 * Validate file offset and fasttrack empty reads
	 */
	if (uiop->uio_loffset < (offset_t)0)
		return (EINVAL);

	if (uiop->uio_resid == 0)
		return (0);

	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, KM_SLEEP))
		return (ENOMEM);

	if (xattr_fill_nvlist(vp, xattr_view, nvl, cr, ct)) {
		nvlist_free(nvl);
		return (EFAULT);
	}

	VERIFY(nvlist_size(nvl, &filesize, NV_ENCODE_XDR) == 0);

	if (uiop->uio_loffset >= filesize) {
		nvlist_free(nvl);
		return (0);
	}

	buf = kmem_alloc(filesize, KM_SLEEP);
	VERIFY(nvlist_pack(nvl, &buf, &filesize, NV_ENCODE_XDR,
	    KM_SLEEP) == 0);

	error = uiomove((caddr_t)buf, filesize, UIO_READ, uiop);
	kmem_free(buf, filesize);
	nvlist_free(nvl);
	return (error);
}

/* ARGSUSED */
static int
xattr_file_write(vnode_t *vp, uio_t *uiop, int ioflag, cred_t *cr,
    caller_context_t *ct)
{
	int error = 0;
	char *buf;
	char *domain;
	uint32_t rid;
	ssize_t size = uiop->uio_resid;
	nvlist_t *nvp;
	nvpair_t *pair = NULL;
	vnode_t *ppvp;
	xvattr_t xvattr;
	xoptattr_t *xoap = NULL;	/* Pointer to optional attributes */

	if (vfs_has_feature(vp->v_vfsp, VFSFT_XVATTR) == 0)
		return (EINVAL);

	/*
	 * Validate file offset and size.
	 */
	if (uiop->uio_loffset < (offset_t)0)
		return (EINVAL);

	if (size == 0)
		return (EINVAL);

	xva_init(&xvattr);

	if ((xoap = xva_getxoptattr(&xvattr)) == NULL) {
		return (EINVAL);
	}

	/*
	 * Copy and unpack the nvlist
	 */
	buf = kmem_alloc(size, KM_SLEEP);
	if (uiomove((caddr_t)buf, size, UIO_WRITE, uiop)) {
		return (EFAULT);
	}

	if (nvlist_unpack(buf, size, &nvp, KM_SLEEP) != 0) {
		kmem_free(buf, size);
		uiop->uio_resid = size;
		return (EINVAL);
	}
	kmem_free(buf, size);

	/*
	 * Fasttrack empty writes (nvlist with no nvpairs)
	 */
	if (nvlist_next_nvpair(nvp, NULL) == 0)
		return (0);

	ppvp = gfs_file_parent(gfs_file_parent(vp));

	while (pair = nvlist_next_nvpair(nvp, pair)) {
		data_type_t type;
		f_attr_t attr;
		boolean_t value;
		uint64_t *time, *times;
		uint_t elem, nelems;
		nvlist_t *nvp_sid;
		uint8_t *scanstamp;

		/*
		 * Validate the name and type of each attribute.
		 * Log any unknown names and continue.  This will
		 * help if additional attributes are added later.
		 */
		type = nvpair_type(pair);
		if ((attr = name_to_attr(nvpair_name(pair))) == F_ATTR_INVAL) {
			cmn_err(CE_WARN, "Unknown attribute %s",
			    nvpair_name(pair));
			continue;
		}

		/*
		 * Verify nvlist type matches required type and view is OK
		 */

		if (type != attr_to_data_type(attr) ||
		    (attr_to_xattr_view(attr) == XATTR_VIEW_READONLY)) {
			nvlist_free(nvp);
			return (EINVAL);
		}

		/*
		 * For OWNERSID/GROUPSID make sure the target
		 * file system support ephemeral ID's
		 */
		if ((attr == F_OWNERSID || attr == F_GROUPSID) &&
		    (!(vp->v_vfsp->vfs_flag & VFS_XID))) {
			nvlist_free(nvp);
			return (EINVAL);
		}

		/*
		 * Retrieve data from nvpair
		 */
		switch (type) {
		case DATA_TYPE_BOOLEAN_VALUE:
			if (nvpair_value_boolean_value(pair, &value)) {
				nvlist_free(nvp);
				return (EINVAL);
			}
			break;
		case DATA_TYPE_UINT64_ARRAY:
			if (nvpair_value_uint64_array(pair, &times, &nelems)) {
				nvlist_free(nvp);
				return (EINVAL);
			}
			break;
		case DATA_TYPE_NVLIST:
			if (nvpair_value_nvlist(pair, &nvp_sid)) {
				nvlist_free(nvp);
				return (EINVAL);
			}
			break;
		case DATA_TYPE_UINT8_ARRAY:
			if (nvpair_value_uint8_array(pair,
			    &scanstamp, &nelems)) {
				nvlist_free(nvp);
				return (EINVAL);
			}
			break;
		default:
			nvlist_free(nvp);
			return (EINVAL);
		}

		switch (attr) {
		/*
		 * If we have several similar optional attributes to
		 * process then we should do it all together here so that
		 * xoap and the requested bitmap can be set in one place.
		 */
		case F_READONLY:
			XVA_SET_REQ(&xvattr, XAT_READONLY);
			xoap->xoa_readonly = value;
			break;
		case F_HIDDEN:
			XVA_SET_REQ(&xvattr, XAT_HIDDEN);
			xoap->xoa_hidden = value;
			break;
		case F_SYSTEM:
			XVA_SET_REQ(&xvattr, XAT_SYSTEM);
			xoap->xoa_system = value;
			break;
		case F_ARCHIVE:
			XVA_SET_REQ(&xvattr, XAT_ARCHIVE);
			xoap->xoa_archive = value;
			break;
		case F_IMMUTABLE:
			XVA_SET_REQ(&xvattr, XAT_IMMUTABLE);
			xoap->xoa_immutable = value;
			break;
		case F_NOUNLINK:
			XVA_SET_REQ(&xvattr, XAT_NOUNLINK);
			xoap->xoa_nounlink = value;
			break;
		case F_APPENDONLY:
			XVA_SET_REQ(&xvattr, XAT_APPENDONLY);
			xoap->xoa_appendonly = value;
			break;
		case F_NODUMP:
			XVA_SET_REQ(&xvattr, XAT_NODUMP);
			xoap->xoa_nodump = value;
			break;
		case F_AV_QUARANTINED:
			XVA_SET_REQ(&xvattr, XAT_AV_QUARANTINED);
			xoap->xoa_av_quarantined = value;
			break;
		case F_AV_MODIFIED:
			XVA_SET_REQ(&xvattr, XAT_AV_MODIFIED);
			xoap->xoa_av_modified = value;
			break;
		case F_CRTIME:
			XVA_SET_REQ(&xvattr, XAT_CREATETIME);
			time = (uint64_t *)&(xoap->xoa_createtime);
			for (elem = 0; elem < nelems; elem++)
				*time++ = times[elem];
			break;
		case F_OWNERSID:
		case F_GROUPSID:
			if (nvlist_lookup_string(nvp_sid, SID_DOMAIN,
			    &domain) || nvlist_lookup_uint32(nvp_sid, SID_RID,
			    &rid)) {
				nvlist_free(nvp);
				return (EINVAL);
			}

			/*
			 * Now map domain+rid to ephemeral id's
			 *
			 * If mapping fails, then the uid/gid will
			 * be set to UID_NOBODY by Winchester.
			 */

			if (attr == F_OWNERSID) {
				(void) kidmap_getuidbysid(crgetzone(cr), domain,
				    rid, &xvattr.xva_vattr.va_uid);
				xvattr.xva_vattr.va_mask |= AT_UID;
			} else {
				(void) kidmap_getgidbysid(crgetzone(cr), domain,
				    rid, &xvattr.xva_vattr.va_gid);
				xvattr.xva_vattr.va_mask |= AT_GID;
			}
			break;
		case F_AV_SCANSTAMP:
			if (ppvp->v_type == VREG) {
				XVA_SET_REQ(&xvattr, XAT_AV_SCANSTAMP);
				(void) memcpy(xoap->xoa_av_scanstamp,
				    scanstamp, nelems);
			} else {
				nvlist_free(nvp);
				return (EINVAL);
			}
			break;
		case F_REPARSE:
			XVA_SET_REQ(&xvattr, XAT_REPARSE);
			xoap->xoa_reparse = value;
			break;
		case F_OFFLINE:
			XVA_SET_REQ(&xvattr, XAT_OFFLINE);
			xoap->xoa_offline = value;
			break;
		case F_SPARSE:
			XVA_SET_REQ(&xvattr, XAT_SPARSE);
			xoap->xoa_sparse = value;
			break;
		default:
			break;
		}
	}

	ppvp = gfs_file_parent(gfs_file_parent(vp));
	error = VOP_SETATTR(ppvp, &xvattr.xva_vattr, 0, cr, ct);
	if (error)
		uiop->uio_resid = size;

	nvlist_free(nvp);
	return (error);
}

static int
xattr_file_pathconf(vnode_t *vp, int cmd, ulong_t *valp, cred_t *cr,
    caller_context_t *ct)
{
	switch (cmd) {
	case _PC_XATTR_EXISTS:
	case _PC_SATTR_ENABLED:
	case _PC_SATTR_EXISTS:
		*valp = 0;
		return (0);
	default:
		return (fs_pathconf(vp, cmd, valp, cr, ct));
	}
}

vnodeops_t *xattr_file_ops;

static const fs_operation_def_t xattr_file_tops[] = {
	{ VOPNAME_OPEN,		{ .vop_open = xattr_file_open }		},
	{ VOPNAME_CLOSE,	{ .vop_close = xattr_file_close }	},
	{ VOPNAME_READ,		{ .vop_read = xattr_file_read }		},
	{ VOPNAME_WRITE,	{ .vop_write = xattr_file_write }	},
	{ VOPNAME_IOCTL,	{ .error = fs_ioctl }			},
	{ VOPNAME_GETATTR,	{ .vop_getattr = xattr_file_getattr }	},
	{ VOPNAME_ACCESS,	{ .vop_access = xattr_file_access }	},
	{ VOPNAME_READDIR,	{ .error = fs_notdir }			},
	{ VOPNAME_SEEK,		{ .vop_seek = fs_seek }			},
	{ VOPNAME_INACTIVE,	{ .vop_inactive = gfs_vop_inactive }	},
	{ VOPNAME_FID,		{ .vop_fid = xattr_common_fid }		},
	{ VOPNAME_PATHCONF,	{ .vop_pathconf = xattr_file_pathconf }	},
	{ VOPNAME_PUTPAGE,	{ .error = fs_putpage }			},
	{ VOPNAME_FSYNC,	{ .error = fs_fsync }			},
	{ NULL }
};

vnode_t *
xattr_mkfile(vnode_t *pvp, xattr_view_t xattr_view)
{
	vnode_t *vp;
	xattr_file_t *np;

	vp = gfs_file_create(sizeof (xattr_file_t), pvp, xattr_file_ops);
	np = vp->v_data;
	np->xattr_view = xattr_view;
	vp->v_flag |= V_SYSATTR;
	return (vp);
}

vnode_t *
xattr_mkfile_ro(vnode_t *pvp)
{
	return (xattr_mkfile(pvp, XATTR_VIEW_READONLY));
}

vnode_t *
xattr_mkfile_rw(vnode_t *pvp)
{
	return (xattr_mkfile(pvp, XATTR_VIEW_READWRITE));
}

vnodeops_t *xattr_dir_ops;

static gfs_dirent_t xattr_dirents[] = {
	{ VIEW_READONLY, xattr_mkfile_ro, GFS_CACHE_VNODE, },
	{ VIEW_READWRITE, xattr_mkfile_rw, GFS_CACHE_VNODE, },
	{ NULL },
};

#define	XATTRDIR_NENTS	((sizeof (xattr_dirents) / sizeof (gfs_dirent_t)) - 1)

static int
is_sattr_name(char *s)
{
	int i;

	for (i = 0; i < XATTRDIR_NENTS; ++i) {
		if (strcmp(s, xattr_dirents[i].gfse_name) == 0) {
			return (1);
		}
	}
	return (0);
}

/*
 * Given the name of an extended attribute file, determine if there is a
 * normalization conflict with a sysattr view name.
 */
int
xattr_sysattr_casechk(char *s)
{
	int i;

	for (i = 0; i < XATTRDIR_NENTS; ++i) {
		if (strcasecmp(s, xattr_dirents[i].gfse_name) == 0)
			return (1);
	}
	return (0);
}

static int
xattr_copy(vnode_t *sdvp, char *snm, vnode_t *tdvp, char *tnm,
    cred_t *cr, caller_context_t *ct)
{
	xvattr_t xvattr;
	vnode_t *pdvp;
	int error;

	/*
	 * Only copy system attrs if the views are the same
	 */
	if (strcmp(snm, tnm) != 0)
		return (EINVAL);

	xva_init(&xvattr);

	XVA_SET_REQ(&xvattr, XAT_SYSTEM);
	XVA_SET_REQ(&xvattr, XAT_READONLY);
	XVA_SET_REQ(&xvattr, XAT_HIDDEN);
	XVA_SET_REQ(&xvattr, XAT_ARCHIVE);
	XVA_SET_REQ(&xvattr, XAT_APPENDONLY);
	XVA_SET_REQ(&xvattr, XAT_NOUNLINK);
	XVA_SET_REQ(&xvattr, XAT_IMMUTABLE);
	XVA_SET_REQ(&xvattr, XAT_NODUMP);
	XVA_SET_REQ(&xvattr, XAT_AV_MODIFIED);
	XVA_SET_REQ(&xvattr, XAT_AV_QUARANTINED);
	XVA_SET_REQ(&xvattr, XAT_CREATETIME);
	XVA_SET_REQ(&xvattr, XAT_REPARSE);
	XVA_SET_REQ(&xvattr, XAT_OFFLINE);
	XVA_SET_REQ(&xvattr, XAT_SPARSE);

	pdvp = gfs_file_parent(sdvp);
	error = VOP_GETATTR(pdvp, &xvattr.xva_vattr, 0, cr, ct);
	if (error)
		return (error);

	pdvp = gfs_file_parent(tdvp);
	error = VOP_SETATTR(pdvp, &xvattr.xva_vattr, 0, cr, ct);
	return (error);
}

/*
 * Get the "real" XATTR directory associtated with the GFS XATTR directory.
 * Note: This does NOT take any additional hold on the returned real_vp,
 * because when this lookup succeeds we save the result in xattr_realvp
 * and keep that hold until the GFS XATTR directory goes inactive.
 */
static int
xattr_dir_realdir(vnode_t *gfs_dvp, vnode_t **ret_vpp, int flags,
    cred_t *cr, caller_context_t *ct)
{
	struct pathname pn;
	char *nm = "";
	xattr_dir_t *xattr_dir;
	vnode_t *realvp;
	int error;

	*ret_vpp = NULL;

	/*
	 * Usually, we've already found the underlying XATTR directory
	 * during some previous lookup and stored it in xattr_realvp.
	 */
	mutex_enter(&gfs_dvp->v_lock);
	xattr_dir = gfs_dvp->v_data;
	realvp = xattr_dir->xattr_realvp;
	mutex_exit(&gfs_dvp->v_lock);
	if (realvp != NULL) {
		*ret_vpp = realvp;
		return (0);
	}

	/*
	 * Lookup the XATTR dir in the underlying FS, relative to our
	 * "parent", which is the real object for which this GFS XATTR
	 * directory was created.  Set the LOOKUP_HAVE_SYSATTR_DIR flag
	 * so that we don't get into an infinite loop with fop_lookup
	 * calling back to xattr_dir_lookup.
	 */
	error = pn_get(nm, UIO_SYSSPACE, &pn);
	if (error != 0)
		return (error);
	error = VOP_LOOKUP(gfs_file_parent(gfs_dvp), nm, &realvp, &pn,
	    flags | LOOKUP_HAVE_SYSATTR_DIR, rootvp, cr, ct, NULL, NULL);
	pn_free(&pn);
	if (error != 0)
		return (error);

	/*
	 * Have the real XATTR directory.  Save it -- but first
	 * check whether we lost a race doing the lookup.
	 */
	mutex_enter(&gfs_dvp->v_lock);
	xattr_dir = gfs_dvp->v_data;
	if (xattr_dir->xattr_realvp == NULL) {
		/*
		 * Note that the hold taken by the VOP_LOOKUP above is
		 * retained from here until xattr_dir_inactive.
		 */
		xattr_dir->xattr_realvp = realvp;
	} else {
		/* We lost the race. */
		VN_RELE(realvp);
		realvp = xattr_dir->xattr_realvp;
	}
	mutex_exit(&gfs_dvp->v_lock);

	*ret_vpp = realvp;
	return (0);
}

/* ARGSUSED */
static int
xattr_dir_open(vnode_t **vpp, int flags, cred_t *cr, caller_context_t *ct)
{
	vnode_t *realvp;
	int error;

	if (flags & FWRITE) {
		return (EACCES);
	}

	/*
	 * If there is a real extended attribute directory,
	 * let the underlying FS see the VOP_OPEN call;
	 * otherwise just return zero.
	 */
	error = xattr_dir_realdir(*vpp, &realvp, LOOKUP_XATTR, cr, ct);
	if (error == 0) {
		error = VOP_OPEN(&realvp, flags, cr, ct);
	} else {
		error = 0;
	}

	return (error);
}

/* ARGSUSED */
static int
xattr_dir_close(vnode_t *vp, int flags, int count, offset_t off, cred_t *cr,
    caller_context_t *ct)
{
	vnode_t *realvp;
	int error;

	/*
	 * If there is a real extended attribute directory,
	 * let the underlying FS see the VOP_CLOSE call;
	 * otherwise just return zero.
	 */
	error = xattr_dir_realdir(vp, &realvp, LOOKUP_XATTR, cr, ct);
	if (error == 0) {
		error = VOP_CLOSE(realvp, flags, count, off, cr, ct);
	} else {
		error = 0;
	}

	return (error);
}

/*
 * Retrieve the attributes on an xattr directory.  If there is a "real"
 * xattr directory, use that.  Otherwise, get the attributes (represented
 * by PARENT_ATTRMASK) from the "parent" node and fill in the rest.  Note
 * that VOP_GETATTR() could turn off bits in the va_mask.
 */

#define	PARENT_ATTRMASK	(AT_UID|AT_GID|AT_RDEV|AT_CTIME|AT_MTIME)

/* ARGSUSED */
static int
xattr_dir_getattr(vnode_t *vp, vattr_t *vap, int flags, cred_t *cr,
    caller_context_t *ct)
{
	timestruc_t now;
	vnode_t *pvp;
	int error;

	error = xattr_dir_realdir(vp, &pvp, LOOKUP_XATTR, cr, ct);
	if (error == 0) {
		error = VOP_GETATTR(pvp, vap, 0, cr, ct);
		if (error) {
			return (error);
		}
		vap->va_nlink += XATTRDIR_NENTS;
		vap->va_size += XATTRDIR_NENTS;
		return (0);
	}

	/*
	 * There is no real xattr directory.  Cobble together
	 * an entry using info from the parent object (if needed)
	 * plus information common to all xattrs.
	 */
	if (vap->va_mask & PARENT_ATTRMASK) {
		vattr_t pvattr;
		uint_t  off_bits;

		pvp = gfs_file_parent(vp);
		(void) memset(&pvattr, 0, sizeof (pvattr));
		pvattr.va_mask = PARENT_ATTRMASK;
		error = VOP_GETATTR(pvp, &pvattr, 0, cr, ct);
		if (error) {
			return (error);
		}

		/*
		 * VOP_GETATTR() might have turned off some bits in
		 * pvattr.va_mask.  This means that the underlying
		 * file system couldn't process those attributes.
		 * We need to make sure those bits get turned off
		 * in the vattr_t structure that gets passed back
		 * to the caller.  Figure out which bits were turned
		 * off (if any) then set pvattr.va_mask before it
		 * gets copied to the vattr_t that the caller sees.
		 */
		off_bits = (pvattr.va_mask ^ PARENT_ATTRMASK) & PARENT_ATTRMASK;
		pvattr.va_mask = vap->va_mask & ~off_bits;
		*vap = pvattr;
	}

	vap->va_type = VDIR;
	vap->va_mode = MAKEIMODE(vap->va_type, S_ISVTX | 0777);
	vap->va_fsid = vp->v_vfsp->vfs_dev;
	vap->va_nodeid = gfs_file_inode(vp);
	vap->va_nlink = XATTRDIR_NENTS+2;
	vap->va_size = vap->va_nlink;
	gethrestime(&now);
	vap->va_atime = now;
	vap->va_blksize = 0;
	vap->va_nblocks = 0;
	vap->va_seq = 0;
	return (0);
}

static int
xattr_dir_setattr(vnode_t *vp, vattr_t *vap, int flags, cred_t *cr,
    caller_context_t *ct)
{
	vnode_t *realvp;
	int error;

	/*
	 * If there is a real xattr directory, do the setattr there.
	 * Otherwise, just return success.  The GFS directory is transient,
	 * and any setattr changes can disappear anyway.
	 */
	error = xattr_dir_realdir(vp, &realvp, LOOKUP_XATTR, cr, ct);
	if (error == 0) {
		error = VOP_SETATTR(realvp, vap, flags, cr, ct);
	}
	if (error == ENOENT) {
		error = 0;
	}
	return (error);
}

/* ARGSUSED */
static int
xattr_dir_access(vnode_t *vp, int mode, int flags, cred_t *cr,
    caller_context_t *ct)
{
	int error;
	vnode_t *realvp = NULL;

	if (mode & VWRITE) {
		return (EACCES);
	}

	error = xattr_dir_realdir(vp, &realvp, LOOKUP_XATTR, cr, ct);
	if ((error == ENOENT || error == EINVAL)) {
		/*
		 * These errors mean there's no "real" xattr dir.
		 * The GFS xattr dir always allows access.
		 */
		return (0);
	}
	if (error != 0) {
		/*
		 * The "real" xattr dir was not accessible.
		 */
		return (error);
	}
	/*
	 * We got the "real" xattr dir.
	 * Pass through the access call.
	 */
	error = VOP_ACCESS(realvp, mode, flags, cr, ct);

	return (error);
}

static int
xattr_dir_create(vnode_t *dvp, char *name, vattr_t *vap, vcexcl_t excl,
    int mode, vnode_t **vpp, cred_t *cr, int flag, caller_context_t *ct,
    vsecattr_t *vsecp)
{
	vnode_t *pvp;
	int error;

	*vpp = NULL;

	/*
	 * Don't allow creation of extended attributes with sysattr names.
	 */
	if (is_sattr_name(name)) {
		return (gfs_dir_lookup(dvp, name, vpp, cr, 0, NULL, NULL));
	}

	error = xattr_dir_realdir(dvp, &pvp, LOOKUP_XATTR|CREATE_XATTR_DIR,
	    cr, ct);
	if (error == 0) {
		error = VOP_CREATE(pvp, name, vap, excl, mode, vpp, cr, flag,
		    ct, vsecp);
	}
	return (error);
}

static int
xattr_dir_remove(vnode_t *dvp, char *name, cred_t *cr, caller_context_t *ct,
    int flags)
{
	vnode_t *pvp;
	int error;

	if (is_sattr_name(name)) {
		return (EACCES);
	}

	error = xattr_dir_realdir(dvp, &pvp, LOOKUP_XATTR, cr, ct);
	if (error == 0) {
		error = VOP_REMOVE(pvp, name, cr, ct, flags);
	}
	return (error);
}

static int
xattr_dir_link(vnode_t *tdvp, vnode_t *svp, char *name, cred_t *cr,
    caller_context_t *ct, int flags)
{
	vnode_t *pvp;
	int error;

	if (svp->v_flag & V_SYSATTR) {
		return (EINVAL);
	}

	error = xattr_dir_realdir(tdvp, &pvp, LOOKUP_XATTR, cr, ct);
	if (error == 0) {
		error = VOP_LINK(pvp, svp, name, cr, ct, flags);
	}
	return (error);
}

static int
xattr_dir_rename(vnode_t *sdvp, char *snm, vnode_t *tdvp, char *tnm,
    cred_t *cr, caller_context_t *ct, int flags)
{
	vnode_t *spvp, *tpvp;
	int error;

	if (is_sattr_name(snm) || is_sattr_name(tnm))
		return (xattr_copy(sdvp, snm, tdvp, tnm, cr, ct));
	/*
	 * We know that sdvp is a GFS dir, or we wouldn't be here.
	 * Get the real unnamed directory.
	 */
	error = xattr_dir_realdir(sdvp, &spvp, LOOKUP_XATTR, cr, ct);
	if (error) {
		return (error);
	}

	if (sdvp == tdvp) {
		/*
		 * If the source and target are the same GFS directory, the
		 * underlying unnamed source and target dir will be the same.
		 */
		tpvp = spvp;
	} else if (tdvp->v_flag & V_SYSATTR) {
		/*
		 * If the target dir is a different GFS directory,
		 * find its underlying unnamed dir.
		 */
		error = xattr_dir_realdir(tdvp, &tpvp, LOOKUP_XATTR, cr, ct);
		if (error) {
			return (error);
		}
	} else {
		/*
		 * Target dir is outside of GFS, pass it on through.
		 */
		tpvp = tdvp;
	}

	error = VOP_RENAME(spvp, snm, tpvp, tnm, cr, ct, flags);

	return (error);
}

/*
 * readdir_xattr_casecmp: given a system attribute name, see if there
 * is a real xattr with the same normalized name.
 */
static int
readdir_xattr_casecmp(vnode_t *dvp, char *nm, cred_t *cr, caller_context_t *ct,
    int *eflags)
{
	int error;
	vnode_t *vp;
	struct pathname pn;

	*eflags = 0;

	error = pn_get(nm, UIO_SYSSPACE, &pn);
	if (error == 0) {
		error = VOP_LOOKUP(dvp, nm, &vp, &pn,
		    FIGNORECASE, rootvp, cr, ct, NULL, NULL);
		if (error == 0) {
			*eflags = ED_CASE_CONFLICT;
			VN_RELE(vp);
		} else if (error == ENOENT) {
			error = 0;
		}
		pn_free(&pn);
	}

	return (error);
}

static int
xattr_dir_readdir(vnode_t *dvp, uio_t *uiop, cred_t *cr, int *eofp,
    caller_context_t *ct, int flags)
{
	vnode_t *pvp;
	int error;
	int local_eof;
	int reset_off = 0;
	int has_xattrs = 0;

	if (eofp == NULL) {
		eofp = &local_eof;
	}
	*eofp = 0;

	/*
	 * See if there is a real extended attribute directory.
	 */
	error = xattr_dir_realdir(dvp, &pvp, LOOKUP_XATTR, cr, ct);
	if (error == 0) {
		has_xattrs = 1;
	}

	/*
	 * Start by reading up the static entries.
	 */
	if (uiop->uio_loffset == 0) {
		ino64_t pino, ino;
		offset_t off;
		gfs_dir_t *dp = dvp->v_data;
		gfs_readdir_state_t gstate;

		if (has_xattrs) {
			/*
			 * If there is a real xattr dir, skip . and ..
			 * in the GFS dir.  We'll pick them up below
			 * when we call into the underlying fs.
			 */
			uiop->uio_loffset = GFS_STATIC_ENTRY_OFFSET;
		}
		error = gfs_get_parent_ino(dvp, cr, ct, &pino, &ino);
		if (error == 0) {
			error = gfs_readdir_init(&gstate, dp->gfsd_maxlen, 1,
			    uiop, pino, ino, flags);
		}
		if (error) {
			return (error);
		}

		while ((error = gfs_readdir_pred(&gstate, uiop, &off)) == 0 &&
		    !*eofp) {
			if (off >= 0 && off < dp->gfsd_nstatic) {
				int eflags;

				/*
				 * Check to see if this sysattr set name has a
				 * case-insensitive conflict with a real xattr
				 * name.
				 */
				eflags = 0;
				if ((flags & V_RDDIR_ENTFLAGS) && has_xattrs) {
					error = readdir_xattr_casecmp(pvp,
					    dp->gfsd_static[off].gfse_name,
					    cr, ct, &eflags);
					if (error)
						break;
				}
				ino = dp->gfsd_inode(dvp, off);

				error = gfs_readdir_emit(&gstate, uiop, off,
				    ino, dp->gfsd_static[off].gfse_name,
				    eflags);
				if (error)
					break;
			} else {
				*eofp = 1;
			}
		}

		error = gfs_readdir_fini(&gstate, error, eofp, *eofp);
		if (error) {
			return (error);
		}

		/*
		 * We must read all of the static entries in the first
		 * call.  Otherwise we won't know if uio_loffset in a
		 * subsequent call refers to the static entries or to those
		 * in an underlying fs.
		 */
		if (*eofp == 0)
			return (EINVAL);
		reset_off = 1;
	}

	if (!has_xattrs) {
		*eofp = 1;
		return (0);
	}

	*eofp = 0;
	if (reset_off) {
		uiop->uio_loffset = 0;
	}
	(void) VOP_RWLOCK(pvp, V_WRITELOCK_FALSE, NULL);
	error = VOP_READDIR(pvp, uiop, cr, eofp, ct, flags);
	VOP_RWUNLOCK(pvp, V_WRITELOCK_FALSE, NULL);

	return (error);
}

/*
 * Last reference on a (GFS) XATTR directory.
 *
 * If there's a real XATTR directory in the underlying FS, we will have
 * taken a hold on that directory in xattr_dir_realdir.  Now that the
 * last hold on the GFS directory is gone, it's time to release that
 * hold on the underlying XATTR directory.
 */
/* ARGSUSED */
static void
xattr_dir_inactive(vnode_t *vp, cred_t *cr, caller_context_t *ct)
{
	xattr_dir_t *dp;

	dp = gfs_dir_inactive(vp);	/* will track v_count */
	if (dp != NULL) {
		/* vp was freed */
		if (dp->xattr_realvp != NULL)
			VN_RELE(dp->xattr_realvp);

		kmem_free(dp, ((gfs_file_t *)dp)->gfs_size);
	}
}

static int
xattr_dir_pathconf(vnode_t *vp, int cmd, ulong_t *valp, cred_t *cr,
    caller_context_t *ct)
{
	switch (cmd) {
	case _PC_XATTR_EXISTS:
	case _PC_SATTR_ENABLED:
	case _PC_SATTR_EXISTS:
		*valp = 0;
		return (0);
	default:
		return (fs_pathconf(vp, cmd, valp, cr, ct));
	}
}

/* ARGSUSED */
static int
xattr_dir_realvp(vnode_t *vp, vnode_t **realvp, caller_context_t *ct)
{
	int error;

	error = xattr_dir_realdir(vp, realvp, LOOKUP_XATTR, kcred, NULL);
	return (error);

}

static const fs_operation_def_t xattr_dir_tops[] = {
	{ VOPNAME_OPEN,		{ .vop_open = xattr_dir_open }		},
	{ VOPNAME_CLOSE,	{ .vop_close = xattr_dir_close }	},
	{ VOPNAME_IOCTL,	{ .error = fs_inval }			},
	{ VOPNAME_GETATTR,	{ .vop_getattr = xattr_dir_getattr }	},
	{ VOPNAME_SETATTR,	{ .vop_setattr = xattr_dir_setattr }	},
	{ VOPNAME_ACCESS,	{ .vop_access = xattr_dir_access }	},
	{ VOPNAME_READDIR,	{ .vop_readdir = xattr_dir_readdir }	},
	{ VOPNAME_LOOKUP,	{ .vop_lookup = gfs_vop_lookup }	},
	{ VOPNAME_CREATE,	{ .vop_create = xattr_dir_create }	},
	{ VOPNAME_REMOVE,	{ .vop_remove = xattr_dir_remove }	},
	{ VOPNAME_LINK,		{ .vop_link = xattr_dir_link }		},
	{ VOPNAME_RENAME,	{ .vop_rename = xattr_dir_rename }	},
	{ VOPNAME_MKDIR,	{ .error = fs_inval }			},
	{ VOPNAME_SEEK,		{ .vop_seek = fs_seek }			},
	{ VOPNAME_INACTIVE,	{ .vop_inactive = xattr_dir_inactive }	},
	{ VOPNAME_FID,		{ .vop_fid = xattr_common_fid }		},
	{ VOPNAME_PATHCONF,	{ .vop_pathconf = xattr_dir_pathconf }	},
	{ VOPNAME_REALVP,	{ .vop_realvp = xattr_dir_realvp } },
	{ NULL, NULL }
};

static gfs_opsvec_t xattr_opsvec[] = {
	{ "xattr dir", xattr_dir_tops, &xattr_dir_ops },
	{ "system attributes", xattr_file_tops, &xattr_file_ops },
	{ NULL, NULL, NULL }
};

/*
 * Callback supporting lookup in a GFS XATTR directory.
 */
static int
xattr_lookup_cb(vnode_t *vp, const char *nm, vnode_t **vpp, ino64_t *inop,
    cred_t *cr, int flags, int *deflags, pathname_t *rpnp)
{
	vnode_t *pvp;
	struct pathname pn;
	int error;

	*vpp = NULL;
	*inop = 0;

	error = xattr_dir_realdir(vp, &pvp, LOOKUP_XATTR, cr, NULL);

	/*
	 * Return ENOENT for EACCES requests during lookup.  Once an
	 * attribute create is attempted EACCES will be returned.
	 */
	if (error) {
		if (error == EACCES)
			return (ENOENT);
		return (error);
	}

	error = pn_get((char *)nm, UIO_SYSSPACE, &pn);
	if (error == 0) {
		error = VOP_LOOKUP(pvp, (char *)nm, vpp, &pn, flags, rootvp,
		    cr, NULL, deflags, rpnp);
		pn_free(&pn);
	}

	return (error);
}

/* ARGSUSED */
static ino64_t
xattrdir_do_ino(vnode_t *vp, int index)
{
	/*
	 * We use index 0 for the directory fid.  Start
	 * the file numbering at 1.
	 */
	return ((ino64_t)index+1);
}

void
xattr_init(void)
{
	VERIFY(gfs_make_opsvec(xattr_opsvec) == 0);
}

/*
 * Get the XATTR dir for some file or directory.
 * See vnode.c: fop_lookup()
 *
 * Note this only gets the GFS XATTR directory.  We'll get the
 * real XATTR directory later, in xattr_dir_realdir.
 */
int
xattr_dir_lookup(vnode_t *dvp, vnode_t **vpp, int flags, cred_t *cr)
{
	int error = 0;

	*vpp = NULL;

	if (dvp->v_type != VDIR && dvp->v_type != VREG)
		return (EINVAL);

	mutex_enter(&dvp->v_lock);

	/*
	 * If we're already in sysattr space, don't allow creation
	 * of another level of sysattrs.
	 */
	if (dvp->v_flag & V_SYSATTR) {
		mutex_exit(&dvp->v_lock);
		return (EINVAL);
	}

	if (dvp->v_xattrdir != NULL) {
		*vpp = dvp->v_xattrdir;
		VN_HOLD(*vpp);
	} else {
		ulong_t val;
		int xattrs_allowed = dvp->v_vfsp->vfs_flag & VFS_XATTR;
		int sysattrs_allowed = 1;

		/*
		 * We have to drop the lock on dvp.  gfs_dir_create will
		 * grab it for a VN_HOLD.
		 */
		mutex_exit(&dvp->v_lock);

		/*
		 * If dvp allows xattr creation, but not sysattr
		 * creation, return the real xattr dir vp. We can't
		 * use the vfs feature mask here because _PC_SATTR_ENABLED
		 * has vnode-level granularity (e.g. .zfs).
		 */
		error = VOP_PATHCONF(dvp, _PC_SATTR_ENABLED, &val, cr, NULL);
		if (error != 0 || val == 0)
			sysattrs_allowed = 0;

		if (!xattrs_allowed && !sysattrs_allowed)
			return (EINVAL);

		if (!sysattrs_allowed) {
			struct pathname pn;
			char *nm = "";

			error = pn_get(nm, UIO_SYSSPACE, &pn);
			if (error)
				return (error);
			error = VOP_LOOKUP(dvp, nm, vpp, &pn,
			    flags|LOOKUP_HAVE_SYSATTR_DIR, rootvp, cr, NULL,
			    NULL, NULL);
			pn_free(&pn);
			return (error);
		}

		/*
		 * Note that we act as if we were given CREATE_XATTR_DIR,
		 * but only for creation of the GFS directory.
		 */
		*vpp = gfs_dir_create(
		    sizeof (xattr_dir_t), dvp, xattr_dir_ops, xattr_dirents,
		    xattrdir_do_ino, MAXNAMELEN, NULL, xattr_lookup_cb);
		mutex_enter(&dvp->v_lock);
		if (dvp->v_xattrdir != NULL) {
			/*
			 * We lost the race to create the xattr dir.
			 * Destroy this one, use the winner.  We can't
			 * just call VN_RELE(*vpp), because the vnode
			 * is only partially initialized.
			 */
			gfs_dir_t *dp = (*vpp)->v_data;

			ASSERT((*vpp)->v_count == 1);
			vn_free(*vpp);

			mutex_destroy(&dp->gfsd_lock);
			kmem_free(dp->gfsd_static,
			    dp->gfsd_nstatic * sizeof (gfs_dirent_t));
			kmem_free(dp, dp->gfsd_file.gfs_size);

			/*
			 * There is an implied VN_HOLD(dvp) here.  We should
			 * be doing a VN_RELE(dvp) to clean up the reference
			 * from *vpp, and then a VN_HOLD(dvp) for the new
			 * reference.  Instead, we just leave the count alone.
			 */

			*vpp = dvp->v_xattrdir;
			VN_HOLD(*vpp);
		} else {
			(*vpp)->v_flag |= (V_XATTRDIR|V_SYSATTR);
			dvp->v_xattrdir = *vpp;
		}
	}
	mutex_exit(&dvp->v_lock);

	return (error);
}

int
xattr_dir_vget(vfs_t *vfsp, vnode_t **vpp, fid_t *fidp)
{
	int error;
	vnode_t *pvp, *dvp;
	xattr_fid_t *xfidp;
	struct pathname pn;
	char *nm;
	uint16_t orig_len;

	*vpp = NULL;

	if (fidp->fid_len < XATTR_FIDSZ)
		return (EINVAL);

	xfidp = (xattr_fid_t *)fidp;
	orig_len = fidp->fid_len;
	fidp->fid_len = xfidp->parent_len;

	error = VFS_VGET(vfsp, &pvp, fidp);
	fidp->fid_len = orig_len;
	if (error)
		return (error);

	/*
	 * Start by getting the GFS sysattr directory.	We might need
	 * to recreate it during the VOP_LOOKUP.
	 */
	nm = "";
	error = pn_get(nm, UIO_SYSSPACE, &pn);
	if (error) {
		VN_RELE(pvp);
		return (EINVAL);
	}

	error = VOP_LOOKUP(pvp, nm, &dvp, &pn, LOOKUP_XATTR|CREATE_XATTR_DIR,
	    rootvp, CRED(), NULL, NULL, NULL);
	pn_free(&pn);
	VN_RELE(pvp);
	if (error)
		return (error);

	if (xfidp->dir_offset == 0) {
		/*
		 * If we were looking for the directory, we're done.
		 */
		*vpp = dvp;
		return (0);
	}

	if (xfidp->dir_offset > XATTRDIR_NENTS) {
		VN_RELE(dvp);
		return (EINVAL);
	}

	nm = xattr_dirents[xfidp->dir_offset - 1].gfse_name;

	error = pn_get(nm, UIO_SYSSPACE, &pn);
	if (error) {
		VN_RELE(dvp);
		return (EINVAL);
	}

	error = VOP_LOOKUP(dvp, nm, vpp, &pn, 0, rootvp, CRED(), NULL,
	    NULL, NULL);

	pn_free(&pn);
	VN_RELE(dvp);

	return (error);
}
