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
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
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

#include <smbsrv/smb_kproto.h>
#include <smbsrv/string.h>
#include <smbsrv/smb_vops.h>
#include <smbsrv/smb_fsops.h>

/*
 * CATIA support
 *
 * CATIA V4 is a UNIX product and uses characters in filenames that
 * are considered invalid by Windows. CATIA V5 is available on both
 * UNIX and Windows.  Thus, as CATIA customers migrate from V4 to V5,
 * some V4 files could become inaccessible to windows clients if the
 * filename contains the characters that are considered illegal in
 * Windows.  In order to address this issue an optional character
 * translation is applied to filenames at the smb_vop interface.
 *
 * Character Translation Table
 * ----------------------------------
 * Unix-char (v4) | Windows-char (v5)
 * ----------------------------------
 *        *       |  0x00a4  Currency Sign
 *        |       |  0x00a6  Broken Bar
 *        "       |  0x00a8  Diaeresis
 *        <       |  0x00ab  Left-Pointing Double Angle Quotation Mark
 *        >       |  0x00bb  Right-Pointing Double Angle Quotation Mark
 *        ?       |  0x00bf  Inverted Question mark
 *        :       |  0x00f7  Division Sign
 *        /       |  0x00f8  Latin Small Letter o with stroke
 *        \       |  0x00ff  Latin Small Letter Y with Diaeresis
 *
 *
 * Two lookup tables are used to perform the character translation:
 *
 * smb_catia_v5_lookup - provides the mapping between UNIX ASCII (v4)
 * characters and equivalent or translated wide characters.
 * It is indexed by the decimal value of the ASCII character (0-127).
 *
 * smb_catia_v4_lookup - provides the mapping between wide characters
 * in the range from 0x00A4 to 0x00FF and their UNIX (v4) equivalent
 * (in wide character format).  It is indexed by the decimal value of
 * the wide character (164-255) with an offset of -164.
 * If this translation produces a filename containing a '/' create, mkdir
 * or rename (to the '/' name)  operations will not be permitted. It is
 * not valid to create a filename with a '/' in it. However, if such a
 * file already exists other operations (e.g, lookup, delete, rename)
 * are permitted on it.
 */

/* number of characters mapped */
#define	SMB_CATIA_NUM_MAPS		9

/* Windows Characters used in special character mapping */
#define	SMB_CATIA_WIN_CURRENCY		0x00a4
#define	SMB_CATIA_WIN_BROKEN_BAR	0x00a6
#define	SMB_CATIA_WIN_DIAERESIS		0x00a8
#define	SMB_CATIA_WIN_LEFT_ANGLE	0x00ab
#define	SMB_CATIA_WIN_RIGHT_ANGLE	0x00bb
#define	SMB_CATIA_WIN_INVERTED_QUESTION	0x00bf
#define	SMB_CATIA_WIN_DIVISION		0x00f7
#define	SMB_CATIA_WIN_LATIN_O		0x00f8
#define	SMB_CATIA_WIN_LATIN_Y		0x00ff

#define	SMB_CATIA_V4_LOOKUP_LOW		SMB_CATIA_WIN_CURRENCY
#define	SMB_CATIA_V4_LOOKUP_UPPER	SMB_CATIA_WIN_LATIN_Y
#define	SMB_CATIA_V4_LOOKUP_MAX		\
	(SMB_CATIA_V4_LOOKUP_UPPER - SMB_CATIA_V4_LOOKUP_LOW + 1)
#define	SMB_CATIA_V5_LOOKUP_MAX		0x0080

typedef struct smb_catia_map
{
	unsigned char unixchar;	/* v4 */
	smb_wchar_t winchar;	/* v5 */
} smb_catia_map_t;

smb_catia_map_t const catia_maps[SMB_CATIA_NUM_MAPS] =
{
	{'"',  SMB_CATIA_WIN_DIAERESIS},
	{'*',  SMB_CATIA_WIN_CURRENCY},
	{':',  SMB_CATIA_WIN_DIVISION},
	{'<',  SMB_CATIA_WIN_LEFT_ANGLE},
	{'>',  SMB_CATIA_WIN_RIGHT_ANGLE},
	{'?',  SMB_CATIA_WIN_INVERTED_QUESTION},
	{'\\', SMB_CATIA_WIN_LATIN_Y},
	{'/',  SMB_CATIA_WIN_LATIN_O},
	{'|',  SMB_CATIA_WIN_BROKEN_BAR}
};

static smb_wchar_t smb_catia_v5_lookup[SMB_CATIA_V5_LOOKUP_MAX];
static smb_wchar_t smb_catia_v4_lookup[SMB_CATIA_V4_LOOKUP_MAX];

static void smb_vop_setup_xvattr(smb_attr_t *smb_attr, xvattr_t *xvattr);
static void smb_sa_to_va_mask(uint_t sa_mask, uint_t *va_maskp);
static callb_cpr_t *smb_lock_frlock_callback(flk_cb_when_t, void *);
static void smb_vop_catia_init();

extern sysid_t lm_alloc_sysidt();

#define	SMB_AT_MAX	16
static const uint_t smb_attrmap[SMB_AT_MAX] = {
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
	 *
	 * XXX: Should smb_ct be per-zone?
	 */
	smb_ct.cc_sysid = lm_alloc_sysidt();
	if (smb_ct.cc_sysid == LM_NOSYSID)
		return (ENOMEM);

	smb_ct.cc_caller_id = fs_new_caller_id();
	smb_ct.cc_pid = IGN_PID;
	smb_ct.cc_flags = 0;
	smb_vop_catia_init();

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
 * When vp denotes a named stream, then unnamed_vp should be passed in (denoting
 * the corresponding unnamed stream).
 * A named stream's attributes (as far as CIFS is concerned) are those of the
 * unnamed stream (minus the size attribute, and the type), plus  the size of
 * the named stream, and a type value of VREG.
 * Although the file system may store other attributes with the named stream,
 * these should not be used by CIFS for any purpose.
 *
 * File systems without VFSFT_XVATTR do not support DOS attributes or create
 * time (crtime). In this case the mtime is used as the crtime.
 * Likewise if VOP_GETATTR doesn't return any system attributes the dosattr
 * is 0 and the mtime is used as the crtime.
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
		XVA_SET_REQ(&tmp_xvattr, XAT_REPARSE);
		XVA_SET_REQ(&tmp_xvattr, XAT_OFFLINE);
		XVA_SET_REQ(&tmp_xvattr, XAT_SPARSE);

		error = VOP_GETATTR(use_vp, &tmp_xvattr.xva_vattr, flags,
		    cr, &smb_ct);
		if (error != 0)
			return (error);

		ret_attr->sa_vattr = tmp_xvattr.xva_vattr;
		ret_attr->sa_dosattr = 0;

		if (tmp_xvattr.xva_vattr.va_mask & AT_XVATTR) {
			xoap = xva_getxoptattr(&tmp_xvattr);
			ASSERT(xoap);

			if ((XVA_ISSET_RTN(&tmp_xvattr, XAT_READONLY)) &&
			    (xoap->xoa_readonly)) {
				ret_attr->sa_dosattr |= FILE_ATTRIBUTE_READONLY;
			}

			if ((XVA_ISSET_RTN(&tmp_xvattr, XAT_HIDDEN)) &&
			    (xoap->xoa_hidden)) {
				ret_attr->sa_dosattr |= FILE_ATTRIBUTE_HIDDEN;
			}

			if ((XVA_ISSET_RTN(&tmp_xvattr, XAT_SYSTEM)) &&
			    (xoap->xoa_system)) {
				ret_attr->sa_dosattr |= FILE_ATTRIBUTE_SYSTEM;
			}

			if ((XVA_ISSET_RTN(&tmp_xvattr, XAT_ARCHIVE)) &&
			    (xoap->xoa_archive)) {
				ret_attr->sa_dosattr |= FILE_ATTRIBUTE_ARCHIVE;
			}

			if ((XVA_ISSET_RTN(&tmp_xvattr, XAT_REPARSE)) &&
			    (xoap->xoa_reparse)) {
				ret_attr->sa_dosattr |=
				    FILE_ATTRIBUTE_REPARSE_POINT;
			}

			if ((XVA_ISSET_RTN(&tmp_xvattr, XAT_OFFLINE)) &&
			    (xoap->xoa_offline)) {
				ret_attr->sa_dosattr |= FILE_ATTRIBUTE_OFFLINE;
			}

			if ((XVA_ISSET_RTN(&tmp_xvattr, XAT_SPARSE)) &&
			    (xoap->xoa_sparse)) {
				ret_attr->sa_dosattr |=
				    FILE_ATTRIBUTE_SPARSE_FILE;
			}

			ret_attr->sa_crtime = xoap->xoa_createtime;
		} else {
			ret_attr->sa_crtime = ret_attr->sa_vattr.va_mtime;
		}
	} else {
		/*
		 * Support for file systems without VFSFT_XVATTR
		 */
		smb_sa_to_va_mask(ret_attr->sa_mask,
		    &ret_attr->sa_vattr.va_mask);

		error = VOP_GETATTR(use_vp, &ret_attr->sa_vattr,
		    flags, cr, &smb_ct);
		if (error != 0)
			return (error);

		ret_attr->sa_dosattr = 0;
		ret_attr->sa_crtime = ret_attr->sa_vattr.va_mtime;
	}

	if (unnamed_vp) {
		ret_attr->sa_vattr.va_type = VREG;

		if (ret_attr->sa_mask & (SMB_AT_SIZE | SMB_AT_NBLOCKS)) {
			tmp_attr.sa_vattr.va_mask = AT_SIZE | AT_NBLOCKS;

			error = VOP_GETATTR(vp, &tmp_attr.sa_vattr,
			    flags, cr, &smb_ct);
			if (error != 0)
				return (error);

			ret_attr->sa_vattr.va_size = tmp_attr.sa_vattr.va_size;
			ret_attr->sa_vattr.va_nblocks =
			    tmp_attr.sa_vattr.va_nblocks;
		}
	}

	if (ret_attr->sa_vattr.va_type == VDIR)
		ret_attr->sa_dosattr |= FILE_ATTRIBUTE_DIRECTORY;

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
smb_vop_setattr(vnode_t *vp, vnode_t *unnamed_vp, smb_attr_t *attr,
    int flags, cred_t *cr)
{
	int error = 0;
	int at_size = 0;
	vnode_t *use_vp;
	xvattr_t xvattr;
	vattr_t *vap;

	if (attr->sa_mask & SMB_AT_DOSATTR) {
		attr->sa_dosattr &=
		    (FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_READONLY |
		    FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM |
		    FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_SPARSE_FILE);
	}

	if (unnamed_vp) {
		use_vp = unnamed_vp;
		if (attr->sa_mask & SMB_AT_SIZE) {
			at_size = 1;
			attr->sa_mask &= ~SMB_AT_SIZE;
		}
	} else {
		use_vp = vp;
	}

	/*
	 * The caller should not be setting sa_vattr.va_mask,
	 * but rather sa_mask.
	 */

	attr->sa_vattr.va_mask = 0;

	if (vfs_has_feature(use_vp->v_vfsp, VFSFT_XVATTR)) {
		smb_vop_setup_xvattr(attr, &xvattr);
		vap = &xvattr.xva_vattr;
	} else {
		smb_sa_to_va_mask(attr->sa_mask,
		    &attr->sa_vattr.va_mask);
		vap = &attr->sa_vattr;
	}

	if ((error = VOP_SETATTR(use_vp, vap, flags, cr, &smb_ct)) != 0)
		return (error);

	if (at_size) {
		attr->sa_vattr.va_mask = AT_SIZE;
		error = VOP_SETATTR(vp, &attr->sa_vattr, flags,
		    zone_kcred(), &smb_ct);
	}

	return (error);
}

int
smb_vop_space(vnode_t *vp, int cmd, flock64_t *bfp, int flags,
	offset_t offset, cred_t *cr)
{
	int error;

	error = VOP_SPACE(vp, cmd, bfp, flags, offset, cr, &smb_ct);

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
 * direntflags:	dirent flags returned from VOP_LOOKUP
 */
int
smb_vop_lookup(
    vnode_t		*dvp,
    char		*name,
    vnode_t		**vpp,
    char		*od_name,
    int			flags,
    int			*direntflags,
    vnode_t		*rootvp,
    smb_attr_t		*attr,
    cred_t		*cr)
{
	int error = 0;
	int option_flags = 0;
	pathname_t rpn;
	char *np = name;
	char namebuf[MAXNAMELEN];

	if (*name == '\0')
		return (EINVAL);

	ASSERT(vpp);
	*vpp = NULL;
	*direntflags = 0;

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

	if (flags & SMB_CATIA)
		np = smb_vop_catia_v5tov4(name, namebuf, sizeof (namebuf));

	pn_alloc(&rpn);

	error = VOP_LOOKUP(dvp, np, vpp, NULL, option_flags, NULL, cr,
	    &smb_ct, direntflags, &rpn);

	if (error == 0) {
		if (od_name) {
			bzero(od_name, MAXNAMELEN);
			np = (option_flags == FIGNORECASE) ? rpn.pn_buf : name;

			if (flags & SMB_CATIA)
				smb_vop_catia_v4tov5(np, od_name, MAXNAMELEN);
			else
				(void) strlcpy(od_name, np, MAXNAMELEN);
		}

		if (attr != NULL) {
			attr->sa_mask = SMB_AT_ALL;
			(void) smb_vop_getattr(*vpp, NULL, attr, 0,
			    zone_kcred());
		}
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
	char *np = name;
	char namebuf[MAXNAMELEN];

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

	if (flags & SMB_CATIA) {
		np = smb_vop_catia_v5tov4(name, namebuf, sizeof (namebuf));
		if (strchr(np, '/') != NULL)
			return (EILSEQ);
	}

	error = VOP_CREATE(dvp, np, vap, EXCL, attr->sa_vattr.va_mode,
	    vpp, cr, option_flags, &smb_ct, vsap);

	return (error);
}

int
smb_vop_remove(vnode_t *dvp, char *name, int flags, cred_t *cr)
{
	int error;
	int option_flags = 0;
	char *np = name;
	char namebuf[MAXNAMELEN];

	if (flags & SMB_IGNORE_CASE)
		option_flags = FIGNORECASE;

	if (flags & SMB_CATIA)
		np = smb_vop_catia_v5tov4(name, namebuf, sizeof (namebuf));

	error = VOP_REMOVE(dvp, np, cr, &smb_ct, option_flags);

	return (error);
}

/*
 * smb_vop_link(target-dir-vp, source-file-vp, target-name)
 *
 * Create a link - same tree (identical TID) only.
 */
int
smb_vop_link(vnode_t *to_dvp, vnode_t *from_vp, char *to_name,
    int flags, cred_t *cr)
{
	int option_flags = 0;
	char *np, *buf;
	int rc;

	if (flags & SMB_IGNORE_CASE)
		option_flags = FIGNORECASE;

	if (flags & SMB_CATIA) {
		buf = kmem_zalloc(MAXNAMELEN, KM_SLEEP);
		np = smb_vop_catia_v5tov4(to_name, buf, MAXNAMELEN);
		if (strchr(np, '/') != NULL) {
			kmem_free(buf, MAXNAMELEN);
			return (EILSEQ);
		}

		rc = VOP_LINK(to_dvp, from_vp, np, cr, &smb_ct, option_flags);
		kmem_free(buf, MAXNAMELEN);
		return (rc);
	}

	rc = VOP_LINK(to_dvp, from_vp, to_name, cr, &smb_ct, option_flags);
	return (rc);
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
	char *from, *to, *fbuf, *tbuf;

	if (flags & SMB_IGNORE_CASE)
		option_flags = FIGNORECASE;

	if (flags & SMB_CATIA) {
		tbuf = kmem_zalloc(MAXNAMELEN, KM_SLEEP);
		to = smb_vop_catia_v5tov4(to_name, tbuf, MAXNAMELEN);
		if (strchr(to, '/') != NULL) {
			kmem_free(tbuf, MAXNAMELEN);
			return (EILSEQ);
		}

		fbuf = kmem_zalloc(MAXNAMELEN, KM_SLEEP);
		from = smb_vop_catia_v5tov4(from_name, fbuf, MAXNAMELEN);

		error = VOP_RENAME(from_dvp, from, to_dvp, to, cr,
		    &smb_ct, option_flags);

		kmem_free(tbuf, MAXNAMELEN);
		kmem_free(fbuf, MAXNAMELEN);
		return (error);
	}

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
	char *np = name;
	char namebuf[MAXNAMELEN];

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

	if (flags & SMB_CATIA) {
		np = smb_vop_catia_v5tov4(name, namebuf, sizeof (namebuf));
		if (strchr(np, '/') != NULL)
			return (EILSEQ);
	}

	error = VOP_MKDIR(dvp, np, vap, vpp, cr, &smb_ct, option_flags, vsap);

	return (error);
}

/*
 * smb_vop_rmdir()
 *
 * Only simple rmdir supported, consistent with NT semantics
 * (can only remove an empty directory).
 *
 * The third argument to VOP_RMDIR  is the current directory of
 * the process.  It allows rmdir wants to EINVAL if one tries to
 * remove ".".  Since SMB servers do not know what their clients'
 * current directories are, we fake it by supplying a vnode known
 * to exist and illegal to remove (rootdir).
 */
int
smb_vop_rmdir(vnode_t *dvp, char *name, int flags, cred_t *cr)
{
	int error;
	int option_flags = 0;
	char *np = name;
	char namebuf[MAXNAMELEN];

	if (flags & SMB_IGNORE_CASE)
		option_flags = FIGNORECASE;

	if (flags & SMB_CATIA)
		np = smb_vop_catia_v5tov4(name, namebuf, sizeof (namebuf));

	error = VOP_RMDIR(dvp, np, rootdir, cr, &smb_ct, option_flags);
	return (error);
}

int
smb_vop_commit(vnode_t *vp, cred_t *cr)
{
	return (VOP_FSYNC(vp, 1, cr, &smb_ct));
}

/*
 * Some code in smb_node.c needs to know which DOS attributes
 * we can actually store.  Let's define a mask here of all the
 * DOS attribute flags supported by the following function.
 */
const uint32_t
smb_vop_dosattr_settable =
	FILE_ATTRIBUTE_ARCHIVE |
	FILE_ATTRIBUTE_SYSTEM |
	FILE_ATTRIBUTE_HIDDEN |
	FILE_ATTRIBUTE_READONLY |
	FILE_ATTRIBUTE_OFFLINE |
	FILE_ATTRIBUTE_SPARSE_FILE;

static void
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
		XVA_SET_REQ(xvattr, XAT_OFFLINE);
		XVA_SET_REQ(xvattr, XAT_SPARSE);

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

		if (smb_attr->sa_dosattr & FILE_ATTRIBUTE_OFFLINE)
			xoap->xoa_offline = 1;

		if (smb_attr->sa_dosattr & FILE_ATTRIBUTE_SPARSE_FILE)
			xoap->xoa_sparse = 1;
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
 * Collects an SMB_MINLEN_RDDIR_BUF "page" of directory entries.
 * The directory entries are returned in an fs-independent format by the
 * underlying file system.  That is, the "page" of information returned is
 * not literally stored on-disk in the format returned.
 * If the file system supports extended directory entries (has features
 * VFSFT_DIRENTFLAGS), set V_RDDIR_ENTFLAGS to cause the buffer to be
 * filled with edirent_t structures, instead of dirent64_t structures.
 * If the file system supports access based enumeration (abe), set
 * V_RDDIR_ACCFILTER to filter directory entries based on user cred.
 */
int
smb_vop_readdir(vnode_t *vp, uint32_t offset,
    void *buf, int *count, int *eof, uint32_t rddir_flag, cred_t *cr)
{
	int error = 0;
	int flags = 0;
	int rdirent_size;
	struct uio auio;
	struct iovec aiov;

	if (vp->v_type != VDIR)
		return (ENOTDIR);

	if (vfs_has_feature(vp->v_vfsp, VFSFT_DIRENTFLAGS)) {
		flags |= V_RDDIR_ENTFLAGS;
		rdirent_size = sizeof (edirent_t);
	} else {
		rdirent_size = sizeof (dirent64_t);
	}

	if (*count < rdirent_size)
		return (EINVAL);

	if (rddir_flag & SMB_ABE)
		flags |= V_RDDIR_ACCFILTER;

	aiov.iov_base = buf;
	aiov.iov_len = *count;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_loffset = (uint64_t)offset;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_extflg = UIO_COPY_DEFAULT;
	auio.uio_resid = *count;
	auio.uio_fmode = 0;

	(void) VOP_RWLOCK(vp, V_WRITELOCK_FALSE, &smb_ct);
	error = VOP_READDIR(vp, &auio, cr, eof, &smb_ct, flags);
	VOP_RWUNLOCK(vp, V_WRITELOCK_FALSE, &smb_ct);

	if (error == 0)
		*count = *count - auio.uio_resid;

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
	int error, tmpflgs;

	if ((error = smb_vop_lookup_xattrdir(fvp, xattrdirvpp,
	    LOOKUP_XATTR | CREATE_XATTR_DIR, cr)) != 0)
		return (error);

	/*
	 * Prepend SMB_STREAM_PREFIX to stream name
	 */

	solaris_stream_name = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	(void) snprintf(solaris_stream_name, MAXNAMELEN,
	    "%s%s", SMB_STREAM_PREFIX, stream_name);

	/*
	 * "name" will hold the on-disk name returned from smb_vop_lookup
	 * for the stream, including the SMB_STREAM_PREFIX.
	 */

	name = kmem_zalloc(MAXNAMELEN, KM_SLEEP);

	if ((error = smb_vop_lookup(*xattrdirvpp, solaris_stream_name, vpp,
	    name, flags, &tmpflgs, rootvp, NULL, cr)) != 0) {
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
	(void) snprintf(solaris_stream_name, MAXNAMELEN,
	    "%s%s", SMB_STREAM_PREFIX, stream_name);

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
	(void) snprintf(solaris_stream_name, MAXNAMELEN,
	    "%s%s", SMB_STREAM_PREFIX, stream_name);

	/* XXX might have to use kcred */
	error = smb_vop_remove(xattrdirvp, solaris_stream_name, flags, cr);

	kmem_free(solaris_stream_name, MAXNAMELEN);
	VN_RELE(xattrdirvp);

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

	error = VOP_PATHCONF(vp, _PC_ACL_ENABLED, &whichacl,
	    zone_kcred(), NULL);
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

static const int zfs_perms[] = {
	ACE_READ_DATA, ACE_WRITE_DATA, ACE_APPEND_DATA, ACE_READ_NAMED_ATTRS,
	ACE_WRITE_NAMED_ATTRS, ACE_EXECUTE, ACE_DELETE_CHILD,
	ACE_READ_ATTRIBUTES, ACE_WRITE_ATTRIBUTES, ACE_DELETE, ACE_READ_ACL,
	ACE_WRITE_ACL, ACE_WRITE_OWNER, ACE_SYNCHRONIZE
};

static const int unix_perms[] = { VREAD, VWRITE, VEXEC };
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

	/*
	 * share locking is not supported for non-regular
	 * objects in NBMAND mode.
	 */
	if (nbl_need_check(vp)) {
		if (vp->v_type != VREG)
			return (0);

		cmd = F_SHARE_NBMAND;
	} else {
		cmd = F_SHARE;
	}

	if ((desired_access & FILE_DATA_ALL) == 0) {
		/* metadata access only */
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
	 * share locking is not supported for non-regular
	 * objects in NBMAND mode.
	 */
	if (nbl_need_check(vp) && (vp->v_type != VREG))
		return (0);

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

/*
 * smb_vop_catia_init_v4_lookup
 * Initialize  mapping between wide characters in the range from
 * 0x00A4 to 0x00FF and their UNIX (v4) equivalent (wide character).
 * Indexed by the decimal value of the wide character (164-255)
 * with an offset of -164.
 */
static void
smb_vop_catia_init_v4_lookup()
{
	int i, idx, offset = SMB_CATIA_V4_LOOKUP_LOW;

	for (i = 0; i < SMB_CATIA_V4_LOOKUP_MAX; i++)
		smb_catia_v4_lookup[i] = (smb_wchar_t)(i + offset);

	for (i = 0; i < SMB_CATIA_NUM_MAPS; i++) {
		idx = (int)catia_maps[i].winchar - offset;
		smb_catia_v4_lookup[idx] = (smb_wchar_t)catia_maps[i].unixchar;
	}
}

/*
 * smb_vop_catia_init_v5_lookup
 * Initialize mapping between UNIX ASCII (v4) characters and equivalent
 * or translated wide characters.
 * Indexed by the decimal value of the ASCII character (0-127).
 */
static void
smb_vop_catia_init_v5_lookup()
{
	int i, idx;

	for (i = 0; i < SMB_CATIA_V5_LOOKUP_MAX; i++)
		smb_catia_v5_lookup[i] = (smb_wchar_t)i;

	for (i = 0; i < SMB_CATIA_NUM_MAPS; i++) {
		idx = (int)catia_maps[i].unixchar;
		smb_catia_v5_lookup[idx] = catia_maps[i].winchar;
	}
}

static void
smb_vop_catia_init()
{
	smb_vop_catia_init_v4_lookup();
	smb_vop_catia_init_v5_lookup();
}

/*
 * smb_vop_catia_v5tov4
 * (windows (v5) to unix (v4))
 *
 * Traverse each character in the given source filename and convert the
 * multibyte that is equivalent to any special Windows character listed
 * in the catia_maps table to the Unix ASCII character if any is
 * encountered in the filename. The translated name is returned in buf.
 *
 * If an error occurs the conversion terminates and name is returned,
 * otherwise buf is returned.
 */
char *
smb_vop_catia_v5tov4(char *name, char *buf, int buflen)
{
	int v4_idx, numbytes, inc;
	int space_left = buflen - 1; /* one byte reserved for null */
	smb_wchar_t wc;
	char mbstring[MTS_MB_CHAR_MAX];
	char *p, *src = name, *dst = buf;

	ASSERT(name);
	ASSERT(buf);

	if (!buf || !name)
		return (name);

	bzero(buf, buflen);

	while (*src) {
		if ((numbytes = smb_mbtowc(&wc, src, MTS_MB_CHAR_MAX)) < 0)
			return (name);

		if (wc < SMB_CATIA_V4_LOOKUP_LOW ||
		    wc > SMB_CATIA_V4_LOOKUP_UPPER) {
			inc = numbytes;
			p = src;
		} else {
			/* Lookup required. */
			v4_idx = (int)wc - SMB_CATIA_V4_LOOKUP_LOW;
			inc = smb_wctomb(mbstring, smb_catia_v4_lookup[v4_idx]);
			p = mbstring;
		}

		if (space_left < inc)
			return (name);

		(void) strncpy(dst, p, inc);
		dst += inc;
		space_left -= inc;
		src += numbytes;
	}

	return (buf);
}

/*
 * smb_vop_catia_v4tov5
 * (unix (v4) to windows (v5))
 *
 * Traverse each character in the given filename 'srcbuf' and convert
 * the special Unix character that is listed in the catia_maps table to
 * the UTF-8 encoding of the corresponding Windows character if any is
 * encountered in the filename.
 *
 * The translated name is returned in buf.
 * If an error occurs the conversion terminates and the original name
 * is returned in buf.
 */
void
smb_vop_catia_v4tov5(char *name, char *buf, int buflen)
{
	int v5_idx, numbytes;
	int space_left = buflen - 1; /* one byte reserved for null */
	smb_wchar_t wc;
	char mbstring[MTS_MB_CHAR_MAX];
	char *src = name, *dst = buf;

	ASSERT(name);
	ASSERT(buf);

	if (!buf || !name)
		return;

	(void) bzero(buf, buflen);
	while (*src) {
		if (smb_isascii(*src)) {
			/* Lookup required */
			v5_idx = (int)*src++;
			numbytes = smb_wctomb(mbstring,
			    smb_catia_v5_lookup[v5_idx]);
			if (space_left < numbytes)
				break;
			(void) strncpy(dst, mbstring, numbytes);
		} else {
			if ((numbytes = smb_mbtowc(&wc, src,
			    MTS_MB_CHAR_MAX)) < 0)
				break;
			if (space_left < numbytes)
				break;
			(void) strncpy(dst, src, numbytes);
			src += numbytes;
		}

		dst += numbytes;
		space_left -= numbytes;
	}

	if (*src)
		(void) strlcpy(buf, name, buflen);
}
