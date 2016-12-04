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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2012 Nexenta Systems, Inc. All rights reserved.
 */

#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <nfs/nfs.h>
#include <nfs/export.h>
#include <nfs/nfs4.h>
#include <sys/ddi.h>
#include <sys/door.h>
#include <sys/sdt.h>
#include <nfs/nfssys.h>

void	rfs4_init_compound_state(struct compound_state *);

bitmap4 rfs4_supported_attrs;
int MSG_PRT_DEBUG = FALSE;

/* If building with DEBUG enabled, enable mandattr tunable by default */
#ifdef DEBUG
#ifndef RFS4_SUPPORT_MANDATTR_ONLY
#define	RFS4_SUPPORT_MANDATTR_ONLY
#endif
#endif

/*
 * If building with mandattr only code, disable it by default.
 * To enable, set rfs4_mandattr_only in /etc/system and reboot.
 * When building without mandattr ifdef, the compiler should
 * optimize away the the comparisons because RFS4_MANDATTR_ONLY
 * is defined to be 0.
 */
#ifdef RFS4_SUPPORT_MANDATTR_ONLY
#define	NFS4_LAST_MANDATTR FATTR4_RDATTR_ERROR
#define	RFS4_MANDATTR_ONLY rfs4_mandattr_only
int rfs4_mandattr_only = 0;
#else
#define	RFS4_MANDATTR_ONLY 0
#endif


static void rfs4_ntov_init(void);
static int rfs4_fattr4_supported_attrs();
static int rfs4_fattr4_type();
static int rfs4_fattr4_fh_expire_type();
static int rfs4_fattr4_change();
static int rfs4_fattr4_size();
static int rfs4_fattr4_link_support();
static int rfs4_fattr4_symlink_support();
static int rfs4_fattr4_named_attr();
static int rfs4_fattr4_fsid();
static int rfs4_fattr4_unique_handles();
static int rfs4_fattr4_lease_time();
static int rfs4_fattr4_rdattr_error();
static int rfs4_fattr4_acl();
static int rfs4_fattr4_aclsupport();
static int rfs4_fattr4_archive();
static int rfs4_fattr4_cansettime();
static int rfs4_fattr4_case_insensitive();
static int rfs4_fattr4_case_preserving();
static int rfs4_fattr4_chown_restricted();
static int rfs4_fattr4_filehandle();
static int rfs4_fattr4_fileid();
static int rfs4_fattr4_files_avail();
static int rfs4_fattr4_files_free();
static int rfs4_fattr4_files_total();
static int rfs4_fattr4_fs_locations();
static int rfs4_fattr4_hidden();
static int rfs4_fattr4_homogeneous();
static int rfs4_fattr4_maxfilesize();
static int rfs4_fattr4_maxlink();
static int rfs4_fattr4_maxname();
static int rfs4_fattr4_maxread();
static int rfs4_fattr4_maxwrite();
static int rfs4_fattr4_mimetype();
static int rfs4_fattr4_mode();
static int rfs4_fattr4_no_trunc();
static int rfs4_fattr4_numlinks();
static int rfs4_fattr4_owner();
static int rfs4_fattr4_owner_group();
static int rfs4_fattr4_quota_avail_hard();
static int rfs4_fattr4_quota_avail_soft();
static int rfs4_fattr4_quota_used();
static int rfs4_fattr4_rawdev();
static int rfs4_fattr4_space_avail();
static int rfs4_fattr4_space_free();
static int rfs4_fattr4_space_total();
static int rfs4_fattr4_space_used();
static int rfs4_fattr4_system();
static int rfs4_fattr4_time_access();
static int rfs4_fattr4_time_access_set();
static int rfs4_fattr4_time_backup();
static int rfs4_fattr4_time_create();
static int rfs4_fattr4_time_delta();
static int rfs4_fattr4_time_metadata();
static int rfs4_fattr4_time_modify();
static int rfs4_fattr4_time_modify_set();

/*
 * Initialize the supported attributes
 */
void
rfs4_attr_init()
{
	int i;
	struct nfs4_svgetit_arg sarg;
	struct compound_state cs;
	struct statvfs64 sb;

	rfs4_init_compound_state(&cs);
	cs.vp = rootvp;
	cs.fh.nfs_fh4_val = NULL;
	cs.cr = kcred;

	/*
	 * Get all the supported attributes
	 */
	sarg.op = NFS4ATTR_SUPPORTED;
	sarg.cs = &cs;
	sarg.vap->va_mask = AT_ALL;
	sarg.sbp = &sb;
	sarg.flag = 0;
	sarg.rdattr_error = NFS4_OK;
	sarg.rdattr_error_req = FALSE;
	sarg.is_referral = B_FALSE;

	rfs4_ntov_init();

	rfs4_supported_attrs = 0;
	for (i = 0; i < NFS4_MAXNUM_ATTRS; i++) {
#ifdef RFS4_SUPPORT_MANDATTR_ONLY
		if (rfs4_mandattr_only == TRUE && i > NFS4_LAST_MANDATTR)
			continue;
#endif
		if ((*nfs4_ntov_map[i].sv_getit)(NFS4ATTR_SUPPORTED,
		    &sarg, NULL) == 0) {
			rfs4_supported_attrs |= nfs4_ntov_map[i].fbit;
		}
	}
}

/*
 * The following rfs4_fattr4_* functions convert between the fattr4
 * arguments/attributes and the system (e.g. vattr) values. The following
 * commands are currently in use:
 *
 * NFS4ATTR_SUPPORTED: checks if the attribute in question is supported:
 *	sarg.op = SUPPORTED - all supported attrs
 *	sarg.op = GETIT - only supported readable attrs
 *	sarg.op = SETIT - only supported writable attrs
 *
 * NFS4ATTR_GETIT: getattr type conversion - convert system values
 * (e.g. vattr struct) to fattr4 type values to be returned to the
 * user - usually in response to nfsv4 getattr request.
 *
 * NFS4ATTR_SETIT: convert fattr4 type values to system values to use by
 * setattr. Allows only read/write and write attributes,
 * even if not supported by the filesystem. Note that ufs only allows setattr
 * of owner/group, mode, size, atime/mtime.
 *
 * NFS4ATTR_VERIT: convert fattr4 type values to system values to use by
 * verify/nverify. Implemented to allow
 * almost everything that can be returned by getattr into known structs
 * (like vfsstat64 or vattr_t), that is, both read only and read/write attrs.
 * The function will return -1 if it found that the arguments don't match.
 * This applies to system-wide values that don't require a VOP_GETATTR
 * or other further checks to verify. It will return no error if they
 * either match or were retrieved successfully for later checking.
 *
 * NFS4ATTR_FREEIT: free up any space allocated by either of the above.
 * The sargp->op should be either NFS4ATTR_GETIT or NFS4ATTR_SETIT
 * to indicate which op was used to allocate the space.
 *
 * XXX Note: these functions are currently used by the server only. A
 * XXX different method of conversion is used on the client side.
 * XXX Eventually combining the two (possibly by adding NFS4ATTR_CLNT_GETIT
 * XXX and SETIT) may be a cleaner approach.
 */

/*
 * Mandatory attributes
 */

/* ARGSUSED */
static int
rfs4_fattr4_supported_attrs(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int	error = 0;

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		na->supported_attrs = rfs4_supported_attrs;
		break;
	case NFS4ATTR_SETIT:
		/*
		 * read-only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		/*
		 * Compare the input bitmap to the server's bitmap
		 */
		if (na->supported_attrs != rfs4_supported_attrs) {
			error = -1;	/* no match */
		}
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/*
 * Translate vnode vtype to nfsv4_ftype.
 */
static nfs_ftype4 vt_to_nf4[] = {
	0, NF4REG, NF4DIR, NF4BLK, NF4CHR, NF4LNK, NF4FIFO, 0, 0, NF4SOCK, 0
};

/* ARGSUSED */
static int
rfs4_fattr4_type(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int		error = 0;

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		if (sarg->rdattr_error && !(sarg->vap->va_mask & AT_TYPE)) {
			error = -1;	/* may be okay if rdattr_error */
			break;
		}
		ASSERT(sarg->vap->va_mask & AT_TYPE);

		/*
		 * if xattr flag not set, use v4_to_nf4 mapping;
		 * otherwise verify xattr flag is in sync with va_type
		 * and set xattr types.
		 */
		if (! (sarg->xattr & (FH4_NAMEDATTR | FH4_ATTRDIR)))
			na->type = vt_to_nf4[sarg->vap->va_type];
		else {
			/*
			 * FH4 flag was set.  Dir type maps to attrdir,
			 * and all other types map to namedattr.
			 */
			if (sarg->vap->va_type == VDIR)
				na->type = NF4ATTRDIR;
			else
				na->type = NF4NAMEDATTR;
		}
		break;
	case NFS4ATTR_SETIT:
		/*
		 * read-only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		/*
		 * Compare the input type to the object type on server
		 */
		ASSERT(sarg->vap->va_mask & AT_TYPE);
		if (sarg->vap->va_type != nf4_to_vt[na->type])
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/* ARGSUSED */
static int
fattr4_get_fh_expire_type(struct exportinfo *exi, uint32_t *fh_expire_typep)
{
#ifdef	VOLATILE_FH_TEST
	int	ex_flags;

	if (exi == NULL)
		return (ESTALE);
	ex_flags = exi->exi_export.ex_flags;
	if ((ex_flags & (EX_VOLFH | EX_VOLRNM | EX_VOLMIG | EX_NOEXPOPEN))
	    == 0) {
		*fh_expire_typep = FH4_PERSISTENT;
		return (0);
	}
	*fh_expire_typep = 0;

	if (ex_flags & EX_NOEXPOPEN) {
		/* file handles should not expire with open - not used */
		*fh_expire_typep = FH4_NOEXPIRE_WITH_OPEN;
	}
	if (ex_flags & EX_VOLFH) {
		/*
		 * file handles may expire any time - on share here.
		 * If volatile any, no need to check other flags.
		 */
		*fh_expire_typep |= FH4_VOLATILE_ANY;
		return (0);
	}
	if (ex_flags & EX_VOLRNM) {
		/* file handles may expire on rename */
		*fh_expire_typep |= FH4_VOL_RENAME;
	}
	if (ex_flags & EX_VOLMIG) {
		/* file handles may expire on migration - not used */
		*fh_expire_typep |= FH4_VOL_MIGRATION;
	}
#else	/* not VOLATILE_FH_TEST */
	*fh_expire_typep = FH4_PERSISTENT;
#endif	/* VOLATILE_FH_TEST */

	return (0);
}

/*
 * At this point the only volatile filehandles we allow (for test purposes
 * only) are either fh's that expire when the filesystem is shared (reshared),
 * fh's that expire on a rename and persistent ones.
 */
/* ARGSUSED */
static int
rfs4_fattr4_fh_expire_type(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	uint32_t fh_expire_type;
	int error = 0;

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		error = fattr4_get_fh_expire_type(sarg->cs->exi,
		    &na->fh_expire_type);
		break;
	case NFS4ATTR_SETIT:
		/*
		 * read-only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		error = fattr4_get_fh_expire_type(sarg->cs->exi,
		    &fh_expire_type);
		if (!error && (na->fh_expire_type != fh_expire_type))
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

static int
fattr4_get_change(struct nfs4_svgetit_arg *sarg, fattr4_change *changep)
{
	vattr_t vap2[1], *vap = sarg->vap;
	struct compound_state *cs = sarg->cs;
	vnode_t *vp = cs->vp;
	nfsstat4 status;
	timespec_t vis_change;

	if ((vap->va_mask & AT_CTIME) == 0) {
		if (sarg->rdattr_error && (vp == NULL)) {
			return (-1);	/* may be okay if rdattr_error */
		}
		ASSERT(vp != NULL);
		vap = vap2;
		vap->va_mask = AT_CTIME;
		status = rfs4_vop_getattr(vp, vap, 0, cs->cr);
		if (status != NFS4_OK)
			return (geterrno4(status));
	}
	NFS4_SET_FATTR4_CHANGE(*changep, vap->va_ctime);

	if (nfs_visible_change(cs->exi, vp, &vis_change)) {
		fattr4_change visch;
		NFS4_SET_FATTR4_CHANGE(visch, vis_change);
		if (visch > *changep)
			*changep = visch;
	}

	return (0);
}

/* ARGSUSED */
static int
rfs4_fattr4_change(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int error = 0;
	fattr4_change change;
	uint_t mask;
	vattr_t *vap = sarg->vap;

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		error = fattr4_get_change(sarg, &na->change);
		break;
	case NFS4ATTR_SETIT:
		/*
		 * read-only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		mask = vap->va_mask;
		vap->va_mask &= ~AT_CTIME;	/* force a VOP_GETATTR */
		error = fattr4_get_change(sarg, &change);
		vap->va_mask = mask;
		if (!error && (na->change != change))
			error = -1;
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/* ARGSUSED */
static int
rfs4_fattr4_size(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int	error = 0;

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		if (sarg->rdattr_error && !(sarg->vap->va_mask & AT_SIZE)) {
			error = -1;	/* may be okay if rdattr_error */
			break;
		}
		ASSERT(sarg->vap->va_mask & AT_SIZE);
		na->size = sarg->vap->va_size;
		break;
	case NFS4ATTR_SETIT:
		ASSERT(sarg->vap->va_mask & AT_SIZE);
		sarg->vap->va_size = na->size;
		break;
	case NFS4ATTR_VERIT:
		ASSERT(sarg->vap->va_mask & AT_SIZE);
		if (sarg->vap->va_size != na->size)
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/*
 * XXX - need VOP extension to ask file system (e.g. pcfs) if it supports
 * hard links.
 */
/* ARGSUSED */
static int
rfs4_fattr4_link_support(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int error = 0;

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		na->link_support = TRUE;
		break;
	case NFS4ATTR_SETIT:
		/*
		 * read-only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		if (!na->link_support)
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/*
 * XXX - need VOP extension to ask file system (e.g. pcfs) if it supports
 * sym links.
 */
/* ARGSUSED */
static int
rfs4_fattr4_symlink_support(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int error = 0;

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		na->symlink_support = TRUE;
		break;
	case NFS4ATTR_SETIT:
		/*
		 * read-only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		if (!na->symlink_support)
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/* ARGSUSED */
static int
rfs4_fattr4_named_attr(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int error = 0;
	ulong_t val;

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		if (sarg->rdattr_error && (sarg->cs->vp == NULL)) {
			error = -1;	/* may be okay if rdattr_error */
			break;
		}
		ASSERT(sarg->cs->vp != NULL);

		/*
		 * Solaris xattr model requires that VFS_XATTR is set
		 * in file systems enabled for generic xattr.  If VFS_XATTR
		 * not set, no need to call pathconf for _PC_XATTR_EXISTS..
		 *
		 * However the VFS_XATTR flag doesn't indicate sysattr support
		 * so always check for sysattrs and then only do the
		 * _PC_XATTR_EXISTS pathconf if needed.
		 */

		val = 0;
		error = VOP_PATHCONF(sarg->cs->vp, _PC_SATTR_EXISTS,
		    &val, sarg->cs->cr, NULL);
		if ((error || val == 0) &&
		    sarg->cs->vp->v_vfsp->vfs_flag & VFS_XATTR) {
			error = VOP_PATHCONF(sarg->cs->vp,
			    _PC_XATTR_EXISTS, &val, sarg->cs->cr, NULL);
			if (error)
				break;
		}
		na->named_attr = (val ? TRUE : FALSE);
		break;
	case NFS4ATTR_SETIT:
		/*
		 * read-only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		ASSERT(sarg->cs->vp != NULL);
		if (sarg->cs->vp->v_vfsp->vfs_flag & VFS_XATTR) {
			error = VOP_PATHCONF(sarg->cs->vp, _PC_SATTR_EXISTS,
			    &val, sarg->cs->cr, NULL);
			if (error || val == 0)
				error = VOP_PATHCONF(sarg->cs->vp,
				    _PC_XATTR_EXISTS, &val,
				    sarg->cs->cr, NULL);
			if (error)
				break;
		} else
			val = 0;
		if (na->named_attr != (val ? TRUE : FALSE))
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/* ARGSUSED */
static int
rfs4_fattr4_fsid(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int error = 0;
	int *pmaj = (int *)&na->fsid.major;

	/*
	 * fsid_t is 64bits so it fits completely in fattr4_fsid.major.
	 * fattr4_fsid.minor is always set to 0 since it isn't needed (yet).
	 */
	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		if (sarg->is_referral) {
			na->fsid.major = 1;
			na->fsid.minor = 0;
		} else if (sarg->cs->exi->exi_volatile_dev) {
			pmaj[0] = sarg->cs->exi->exi_fsid.val[0];
			pmaj[1] = sarg->cs->exi->exi_fsid.val[1];
			na->fsid.minor = 0;
		} else {
			na->fsid.major = getmajor(sarg->vap->va_fsid);
			na->fsid.minor = getminor(sarg->vap->va_fsid);
		}
		break;
	case NFS4ATTR_SETIT:
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		if (sarg->is_referral) {
			if (na->fsid.major != 1 ||
			    na->fsid.minor != 0)
				error = -1;
		} else if (sarg->cs->exi->exi_volatile_dev) {
			if (pmaj[0] != sarg->cs->exi->exi_fsid.val[0] ||
			    pmaj[1] != sarg->cs->exi->exi_fsid.val[1] ||
			    na->fsid.minor != 0)
				error = -1;
		} else {
			if (na->fsid.major != getmajor(sarg->vap->va_fsid) ||
			    na->fsid.minor != getminor(sarg->vap->va_fsid))
				error = -1;
		}
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/* ARGSUSED */
static int
rfs4_fattr4_unique_handles(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	/*
	 * XXX
	 * For now, we can't support this. Problem of /export, beinging
	 * a file system, /export/a and /export/b shared separately,
	 * and /export/a/l and /export/b/l are ahrd links of each other.
	 */
	int error = 0;

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		na->unique_handles = FALSE;
		break;
	case NFS4ATTR_SETIT:
		/*
		 * read-only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		if (na->unique_handles)
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/* ARGSUSED */
static int
rfs4_fattr4_lease_time(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int error = 0;

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		na->lease_time = rfs4_lease_time;
		break;
	case NFS4ATTR_SETIT:
		/*
		 * read-only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		if (na->lease_time != rfs4_lease_time)
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/* ARGSUSED */
static int
rfs4_fattr4_rdattr_error(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int error = 0;

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if ((sarg->op == NFS4ATTR_SETIT) ||
		    (sarg->op == NFS4ATTR_VERIT))
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		ASSERT(sarg->rdattr_error_req);
		na->rdattr_error = sarg->rdattr_error;
		break;
	case NFS4ATTR_SETIT:
	case NFS4ATTR_VERIT:
		/*
		 * read-only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/*
 * Server side compare of a filehandle from the wire to a native
 * server filehandle.
 */
static int
rfs4fhcmp(nfs_fh4 *wirefh, nfs_fh4 *srvfh)
{
	nfs_fh4_fmt_t fh;

	ASSERT(IS_P2ALIGNED(wirefh->nfs_fh4_val, sizeof (uint32_t)));

	bzero(&fh, sizeof (nfs_fh4_fmt_t));
	if (!xdr_inline_decode_nfs_fh4((uint32_t *)wirefh->nfs_fh4_val, &fh,
	    wirefh->nfs_fh4_len))
		return (1);

	return (bcmp(srvfh->nfs_fh4_val, &fh, srvfh->nfs_fh4_len));
}

/* ARGSUSED */
static int
rfs4_fattr4_filehandle(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	nfs_fh4 *fh;

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			return (EINVAL);
		return (0);	/* this attr is supported */
	case NFS4ATTR_GETIT:
		/*
		 * If sarg->cs->fh is all zeros then should makefh a new
		 * one, otherwise, copy that one over.
		 */
		fh = &sarg->cs->fh;
		if (sarg->cs->fh.nfs_fh4_len == 0) {
			if (sarg->rdattr_error && (sarg->cs->vp == NULL))
				return (-1);	/* okay if rdattr_error */
			ASSERT(sarg->cs->vp != NULL);
			na->filehandle.nfs_fh4_val =
			    kmem_alloc(NFS_FH4_LEN, KM_SLEEP);
			return (makefh4(&na->filehandle, sarg->cs->vp,
			    sarg->cs->exi));
		}
		na->filehandle.nfs_fh4_val =
		    kmem_alloc(fh->nfs_fh4_len, KM_SLEEP);
		nfs_fh4_copy(fh, &na->filehandle);
		return (0);
	case NFS4ATTR_SETIT:
		/*
		 * read-only attr
		 */
		return (EINVAL);
	case NFS4ATTR_VERIT:
		/*
		 * A verify of a filehandle will have the client sending
		 * the raw format which needs to be compared to the
		 * native format.
		 */
		if (rfs4fhcmp(&na->filehandle, &sarg->cs->fh) == 1)
			return (-1);	/* no match */
		return (0);
	case NFS4ATTR_FREEIT:
		if (sarg->op != NFS4ATTR_GETIT)
			return (0);
		if (na->filehandle.nfs_fh4_val == NULL)
			return (0);
		kmem_free(na->filehandle.nfs_fh4_val,
		    na->filehandle.nfs_fh4_len);
		na->filehandle.nfs_fh4_val = NULL;
		na->filehandle.nfs_fh4_len = 0;
		return (0);
	}
	return (0);
}

/*
 * Recommended attributes
 */

/* ARGSUSED */
static int
rfs4_fattr4_acl(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int error = 0;
	vsecattr_t vs_native, vs_ace4;
	ulong_t whichacl;
	nfsstat4 status;
	vattr_t va, *vap = sarg->vap;
	vnode_t *vp = sarg->cs->vp;

	if (RFS4_MANDATTR_ONLY)
		return (ENOTSUP);

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		break;

	case NFS4ATTR_VERIT:
	case NFS4ATTR_GETIT:
		if (sarg->rdattr_error && (vp == NULL)) {
			return (-1);
		}
		ASSERT(vp != NULL);
		bzero(&vs_native, sizeof (vs_native));

		/* see which ACLs fs supports */
		error = VOP_PATHCONF(vp, _PC_ACL_ENABLED, &whichacl,
		    sarg->cs->cr, NULL);
		if (error != 0) {
			/*
			 * If we got an error, then the filesystem
			 * likely does not understand the _PC_ACL_ENABLED
			 * pathconf.  In this case, we fall back to trying
			 * POSIX-draft (aka UFS-style) ACLs, since that's
			 * the behavior used by earlier version of NFS.
			 */
			error = 0;
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

		if (whichacl & _ACL_ACE_ENABLED)
			vs_native.vsa_mask = VSA_ACE | VSA_ACECNT;
		else if (whichacl & _ACL_ACLENT_ENABLED)
			vs_native.vsa_mask = VSA_ACL | VSA_ACLCNT |
			    VSA_DFACL | VSA_DFACLCNT;

		if (error != 0)
			break;

		/* get the ACL, and translate it into nfsace4 style */
		error = VOP_GETSECATTR(vp, &vs_native,
		    0, sarg->cs->cr, NULL);
		if (error != 0)
			break;
		if (whichacl & _ACL_ACE_ENABLED) {
			error = vs_acet_to_ace4(&vs_native, &vs_ace4, TRUE);
			vs_acet_destroy(&vs_native);
		} else {
			error = vs_aent_to_ace4(&vs_native, &vs_ace4,
			    vp->v_type == VDIR, TRUE);
			vs_aent_destroy(&vs_native);
		}
		if (error != 0)
			break;

		if (cmd == NFS4ATTR_GETIT) {
			na->acl.fattr4_acl_len = vs_ace4.vsa_aclcnt;
			/* see case NFS4ATTR_FREEIT for this being freed */
			na->acl.fattr4_acl_val = vs_ace4.vsa_aclentp;
		} else {
			if (na->acl.fattr4_acl_len != vs_ace4.vsa_aclcnt)
				error = -1; /* no match */
			else if (ln_ace4_cmp(na->acl.fattr4_acl_val,
			    vs_ace4.vsa_aclentp,
			    vs_ace4.vsa_aclcnt) != 0)
				error = -1; /* no match */
		}

		break;

	case NFS4ATTR_SETIT:
		if (sarg->rdattr_error && (vp == NULL)) {
			return (-1);
		}
		ASSERT(vp != NULL);

		/* prepare vs_ace4 from fattr4 data */
		bzero(&vs_ace4, sizeof (vs_ace4));
		vs_ace4.vsa_mask = VSA_ACE | VSA_ACECNT;
		vs_ace4.vsa_aclcnt = na->acl.fattr4_acl_len;
		vs_ace4.vsa_aclentp = na->acl.fattr4_acl_val;
		vs_ace4.vsa_aclentsz = vs_ace4.vsa_aclcnt * sizeof (ace_t);
		/* make sure we have correct owner/group */
		if ((vap->va_mask & (AT_UID | AT_GID)) !=
		    (AT_UID | AT_GID)) {
			vap = &va;
			vap->va_mask = AT_UID | AT_GID;
			status = rfs4_vop_getattr(vp,
			    vap, 0, sarg->cs->cr);
			if (status != NFS4_OK)
				return (geterrno4(status));
		}

		/* see which ACLs the fs supports */
		error = VOP_PATHCONF(vp, _PC_ACL_ENABLED, &whichacl,
		    sarg->cs->cr, NULL);
		if (error != 0) {
			/*
			 * If we got an error, then the filesystem
			 * likely does not understand the _PC_ACL_ENABLED
			 * pathconf.  In this case, we fall back to trying
			 * POSIX-draft (aka UFS-style) ACLs, since that's
			 * the behavior used by earlier version of NFS.
			 */
			error = 0;
			whichacl = _ACL_ACLENT_ENABLED;
		}

		if (!(whichacl & (_ACL_ACLENT_ENABLED | _ACL_ACE_ENABLED))) {
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

		if (whichacl & _ACL_ACE_ENABLED) {
			error = vs_ace4_to_acet(&vs_ace4, &vs_native,
			    vap->va_uid, vap->va_gid, TRUE);
			if (error != 0)
				break;
			(void) VOP_RWLOCK(vp, V_WRITELOCK_TRUE, NULL);
			error = VOP_SETSECATTR(vp, &vs_native,
			    0, sarg->cs->cr, NULL);
			VOP_RWUNLOCK(vp, V_WRITELOCK_TRUE, NULL);
			vs_acet_destroy(&vs_native);
		} else if (whichacl & _ACL_ACLENT_ENABLED) {
			error = vs_ace4_to_aent(&vs_ace4, &vs_native,
			    vap->va_uid, vap->va_gid, vp->v_type == VDIR, TRUE);
			if (error != 0)
				break;
			(void) VOP_RWLOCK(vp, V_WRITELOCK_TRUE, NULL);
			error = VOP_SETSECATTR(vp, &vs_native,
			    0, sarg->cs->cr, NULL);
			VOP_RWUNLOCK(vp, V_WRITELOCK_TRUE, NULL);
			vs_aent_destroy(&vs_native);
		}
		break;

	case NFS4ATTR_FREEIT:
		if (sarg->op == NFS4ATTR_GETIT) {
			vs_ace4.vsa_mask = VSA_ACE | VSA_ACECNT;
			vs_ace4.vsa_aclcnt = na->acl.fattr4_acl_len;
			vs_ace4.vsa_aclentp = na->acl.fattr4_acl_val;
			vs_ace4_destroy(&vs_ace4);
		}
		break;
	}

	return (error);
}

/* ARGSUSED */
static int
rfs4_fattr4_aclsupport(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int error = 0;

	if (RFS4_MANDATTR_ONLY)
		return (ENOTSUP);

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;	/* supported */
	case NFS4ATTR_GETIT:
		na->aclsupport = ACL4_SUPPORT_ALLOW_ACL |
		    ACL4_SUPPORT_DENY_ACL;
		break;
	case NFS4ATTR_SETIT:
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		if (na->aclsupport != (ACL4_SUPPORT_ALLOW_ACL |
		    ACL4_SUPPORT_DENY_ACL))
			error = -1;	/* no match */
		break;
	}

	return (error);
}

/* ARGSUSED */
static int
rfs4_fattr4_archive(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	return (ENOTSUP);
}

/* ARGSUSED */
static int
rfs4_fattr4_cansettime(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int error = 0;

	if (RFS4_MANDATTR_ONLY)
		return (ENOTSUP);

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		na->cansettime = TRUE;
		break;
	case NFS4ATTR_SETIT:
		/*
		 * read-only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		if (!na->cansettime)
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/*
 * XXX - need VOP extension to ask file system (e.g. pcfs) if it supports
 * case insensitive.
 */
/* ARGSUSED */
static int
rfs4_fattr4_case_insensitive(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int error = 0;

	if (RFS4_MANDATTR_ONLY)
		return (ENOTSUP);

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		na->case_insensitive = FALSE;
		break;
	case NFS4ATTR_SETIT:
		/*
		 * read-only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		if (!na->case_insensitive)
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/* ARGSUSED */
static int
rfs4_fattr4_case_preserving(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int error = 0;

	if (RFS4_MANDATTR_ONLY)
		return (ENOTSUP);

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		na->case_preserving = TRUE;
		break;
	case NFS4ATTR_SETIT:
		/*
		 * read-only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		if (!na->case_preserving)
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/* fattr4_chown_restricted should reall be fattr4_chown_allowed */
/* ARGSUSED */
static int
rfs4_fattr4_chown_restricted(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int error = 0;
	ulong_t val;

	if (RFS4_MANDATTR_ONLY)
		return (ENOTSUP);

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		if (sarg->rdattr_error && (sarg->cs->vp == NULL)) {
			error = -1;	/* may be okay if rdattr_error */
			break;
		}
		ASSERT(sarg->cs->vp != NULL);
		error = VOP_PATHCONF(sarg->cs->vp,
		    _PC_CHOWN_RESTRICTED, &val, sarg->cs->cr, NULL);
		if (error)
			break;

		na->chown_restricted = (val == 1);
		break;
	case NFS4ATTR_SETIT:
		/*
		 * read-only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		ASSERT(sarg->cs->vp != NULL);
		error = VOP_PATHCONF(sarg->cs->vp,
		    _PC_CHOWN_RESTRICTED, &val, sarg->cs->cr, NULL);
		if (error)
			break;
		if (na->chown_restricted != (val == 1))
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/* ARGSUSED */
static int
rfs4_fattr4_fileid(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int	error = 0;

	if (RFS4_MANDATTR_ONLY)
		return (ENOTSUP);

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		if (sarg->rdattr_error && !(sarg->vap->va_mask & AT_NODEID)) {
			error = -1;	/* may be okay if rdattr_error */
			break;
		}
		ASSERT(sarg->vap->va_mask & AT_NODEID);
		na->fileid = sarg->vap->va_nodeid;
		break;
	case NFS4ATTR_SETIT:
		/*
		 * read-only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		ASSERT(sarg->vap->va_mask & AT_NODEID);
		if (sarg->vap->va_nodeid != na->fileid)
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/* ARGSUSED */
static int
rfs4_get_mntdfileid(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg)
{
	int error = 0;
	vattr_t	*vap, va;
	vnode_t *stubvp = NULL, *vp;

	vp = sarg->cs->vp;
	sarg->mntdfid_set = FALSE;

	/* VROOT object, must untraverse */
	if (vp->v_flag & VROOT) {

		/* extra hold for vp since untraverse might rele */
		VN_HOLD(vp);
		stubvp = untraverse(vp);

		/*
		 * If vp/stubvp are same, we must be at system
		 * root because untraverse returned same vp
		 * for a VROOT object.  sarg->vap was setup
		 * before we got here, so there's no need to do
		 * another getattr -- just use the one in sarg.
		 */
		if (VN_CMP(vp, stubvp)) {
			ASSERT(VN_CMP(vp, rootdir));
			vap = sarg->vap;
		} else {
			va.va_mask = AT_NODEID;
			vap = &va;
			error = rfs4_vop_getattr(stubvp, vap, 0, sarg->cs->cr);
		}

		/*
		 * Done with stub, time to rele.  If vp and stubvp
		 * were the same, then we need to rele either vp or
		 * stubvp.  If they weren't the same, then untraverse()
		 * already took case of the extra hold on vp, and only
		 * the stub needs to be rele'd.  Both cases are handled
		 * by unconditionally rele'ing the stub.
		 */
		VN_RELE(stubvp);
	} else
		vap = sarg->vap;

	/*
	 * At this point, vap should contain "correct" AT_NODEID --
	 * (for V_ROOT case, nodeid of stub, for non-VROOT case,
	 * nodeid of vp).  If error or AT_NODEID not available, then
	 * make the obligatory (yet mysterious) rdattr_error
	 * check that is so common in the attr code.
	 */
	if (!error && (vap->va_mask & AT_NODEID)) {
		sarg->mounted_on_fileid = vap->va_nodeid;
		sarg->mntdfid_set = TRUE;
	} else if (sarg->rdattr_error)
		error = -1;

	/*
	 * error describes these cases:
	 *	0 : success
	 *	-1: failure due to previous attr processing error (rddir only).
	 *	* : new attr failure  (if rddir, caller will set rdattr_error)
	 */
	return (error);
}

/* ARGSUSED */
static int
rfs4_fattr4_mounted_on_fileid(nfs4_attr_cmd_t cmd,
    struct nfs4_svgetit_arg *sarg, union nfs4_attr_u *na)
{
	int	error = 0;

	if (RFS4_MANDATTR_ONLY)
		return (ENOTSUP);

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
	case NFS4ATTR_VERIT:
		if (! sarg->mntdfid_set)
			error = rfs4_get_mntdfileid(cmd, sarg);

		if (! error && sarg->mntdfid_set) {
			if (cmd == NFS4ATTR_GETIT)
				na->mounted_on_fileid = sarg->mounted_on_fileid;
			else
				if (na->mounted_on_fileid !=
				    sarg->mounted_on_fileid)
					error = -1;
		}
		break;
	case NFS4ATTR_SETIT:
		/* read-only attr */
		error = EINVAL;
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/* ARGSUSED */
static int
rfs4_fattr4_files_avail(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int	error = 0;

	if (RFS4_MANDATTR_ONLY)
		return (ENOTSUP);

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		if (sarg->rdattr_error && (sarg->sbp == NULL)) {
			error = -1;	/* may be okay if rdattr_error */
			break;
		}
		ASSERT(sarg->sbp != NULL);
		na->files_avail = sarg->sbp->f_favail;
		break;
	case NFS4ATTR_SETIT:
		/*
		 * read-only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		ASSERT(sarg->sbp != NULL);
		if (sarg->sbp->f_favail != na->files_avail)
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/* ARGSUSED */
static int
rfs4_fattr4_files_free(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int	error = 0;

	if (RFS4_MANDATTR_ONLY)
		return (ENOTSUP);

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		if (sarg->rdattr_error && (sarg->sbp == NULL)) {
			error = -1;	/* may be okay if rdattr_error */
			break;
		}
		ASSERT(sarg->sbp != NULL);
		na->files_free = sarg->sbp->f_ffree;
		break;
	case NFS4ATTR_SETIT:
		/*
		 * read-only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		ASSERT(sarg->sbp != NULL);
		if (sarg->sbp->f_ffree != na->files_free)
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/* ARGSUSED */
static int
rfs4_fattr4_files_total(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int	error = 0;

	if (RFS4_MANDATTR_ONLY)
		return (ENOTSUP);

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		if (sarg->rdattr_error && (sarg->sbp == NULL)) {
			error = -1;	/* may be okay if rdattr_error */
			break;
		}
		ASSERT(sarg->sbp != NULL);
		na->files_total = sarg->sbp->f_files;
		break;
	case NFS4ATTR_SETIT:
		/*
		 * read-only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		ASSERT(sarg->sbp != NULL);
		if (sarg->sbp->f_files != na->files_total)
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

static void
rfs4_free_pathname4(pathname4 *pn4)
{
	int i, len;
	utf8string *utf8s;

	if (pn4 == NULL || (len = pn4->pathname4_len) == 0 ||
	    (utf8s = pn4->pathname4_val) == NULL)
		return;

	for (i = 0; i < len; i++, utf8s++) {
		if (utf8s->utf8string_val == NULL ||
		    utf8s->utf8string_len == 0)
			continue;

		kmem_free(utf8s->utf8string_val, utf8s->utf8string_len);
		utf8s->utf8string_val = NULL;
	}

	kmem_free(pn4->pathname4_val,
	    sizeof (utf8string) * pn4->pathname4_len);
	pn4->pathname4_val = 0;
}

static void
rfs4_free_fs_location4(fs_location4 *fsl4)
{
	if (fsl4 == NULL)
		return;

	rfs4_free_pathname4((pathname4 *)&fsl4->server_len);
	rfs4_free_pathname4(&fsl4->rootpath);
}

void
rfs4_free_fs_locations4(fs_locations4 *fsls4)
{
	int i, len;
	fs_location4 *fsl4;

	if (fsls4 == NULL)
		return;

	/* free fs_root */
	rfs4_free_pathname4(&fsls4->fs_root);

	if ((len = fsls4->locations_len) == 0 ||
	    (fsl4 = fsls4->locations_val) == NULL)
		return;

	/* free fs_location4 */
	for (i = 0; i < len; i++) {
		rfs4_free_fs_location4(fsl4);
		fsl4++;
	}

	kmem_free(fsls4->locations_val, sizeof (fs_location4) * len);
	fsls4->locations_val = NULL;
}

/* ARGSUSED */
static int
rfs4_fattr4_fs_locations(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int error = 0;
	fs_locations4 *fsl;

	if (RFS4_MANDATTR_ONLY)
		return (ENOTSUP);

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT || sarg->op == NFS4ATTR_VERIT)
			error = EINVAL;
		break;  /* this attr is supported */

	case NFS4ATTR_GETIT:
		fsl = fetch_referral(sarg->cs->vp, sarg->cs->cr);
		if (fsl == NULL)
			(void) memset(&(na->fs_locations), 0,
			    sizeof (fs_locations4));
		else {
			na->fs_locations = *fsl;
			kmem_free(fsl, sizeof (fs_locations4));
		}
		global_svstat_ptr[4][NFS_REFERRALS].value.ui64++;
		break;

	case NFS4ATTR_FREEIT:
		if (sarg->op == NFS4ATTR_SETIT || sarg->op == NFS4ATTR_VERIT)
			error = EINVAL;
		rfs4_free_fs_locations4(&na->fs_locations);
		break;

	case NFS4ATTR_SETIT:
	case NFS4ATTR_VERIT:
		/*
		 * read-only attr
		 */
		error = EINVAL;
		break;
	}
	return (error);
}

/* ARGSUSED */
static int
rfs4_fattr4_hidden(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	return (ENOTSUP);
}

/* ARGSUSED */
static int
rfs4_fattr4_homogeneous(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int error = 0;

	if (RFS4_MANDATTR_ONLY)
		return (ENOTSUP);

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		na->homogeneous = TRUE; /* XXX - need a VOP extension */
		break;
	case NFS4ATTR_SETIT:
		/*
		 * read-only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		if (!na->homogeneous)
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/* ARGSUSED */
static int
rfs4_fattr4_maxfilesize(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int error = 0;
	ulong_t val;
	fattr4_maxfilesize maxfilesize;

	if (RFS4_MANDATTR_ONLY)
		return (ENOTSUP);

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		if (sarg->rdattr_error && (sarg->cs->vp == NULL)) {
			error = -1;	/* may be okay if rdattr_error */
			break;
		}
		ASSERT(sarg->cs->vp != NULL);
		error = VOP_PATHCONF(sarg->cs->vp, _PC_FILESIZEBITS, &val,
		    sarg->cs->cr, NULL);
		if (error)
			break;

		/*
		 * If the underlying file system does not support
		 * _PC_FILESIZEBITS, return a reasonable default. Note that
		 * error code on VOP_PATHCONF will be 0, even if the underlying
		 * file system does not support _PC_FILESIZEBITS.
		 */
		if (val == (ulong_t)-1) {
			na->maxfilesize = MAXOFF32_T;
		} else {
			if (val >= (sizeof (uint64_t) * 8))
				na->maxfilesize = INT64_MAX;
			else
				na->maxfilesize = ((1LL << (val - 1)) - 1);
		}
		break;
	case NFS4ATTR_SETIT:
		/*
		 * read-only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		ASSERT(sarg->cs->vp != NULL);
		error = VOP_PATHCONF(sarg->cs->vp, _PC_FILESIZEBITS, &val,
		    sarg->cs->cr, NULL);
		if (error)
			break;
		/*
		 * If the underlying file system does not support
		 * _PC_FILESIZEBITS, return a reasonable default. Note that
		 * error code on VOP_PATHCONF will be 0, even if the underlying
		 * file system does not support _PC_FILESIZEBITS.
		 */
		if (val == (ulong_t)-1) {
			maxfilesize = MAXOFF32_T;
		} else {
			if (val >= (sizeof (uint64_t) * 8))
				maxfilesize = INT64_MAX;
			else
				maxfilesize = ((1LL << (val - 1)) - 1);
		}
		if (na->maxfilesize != maxfilesize)
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/* ARGSUSED */
static int
rfs4_fattr4_maxlink(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int error = 0;
	ulong_t val;

	if (RFS4_MANDATTR_ONLY)
		return (ENOTSUP);

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		if (sarg->rdattr_error && (sarg->cs->vp == NULL)) {
			error = -1;	/* may be okay if rdattr_error */
			break;
		}
		ASSERT(sarg->cs->vp != NULL);
		error = VOP_PATHCONF(sarg->cs->vp, _PC_LINK_MAX, &val,
		    sarg->cs->cr, NULL);
		if (error == 0) {
			na->maxlink = val;
		}
		break;
	case NFS4ATTR_SETIT:
		/*
		 * read-only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		ASSERT(sarg->cs->vp != NULL);
		error = VOP_PATHCONF(sarg->cs->vp, _PC_LINK_MAX, &val,
		    sarg->cs->cr, NULL);
		if (!error && (na->maxlink != (uint32_t)val))
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/* ARGSUSED */
static int
rfs4_fattr4_maxname(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int error = 0;
	ulong_t val;

	if (RFS4_MANDATTR_ONLY)
		return (ENOTSUP);

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		if (sarg->rdattr_error && (sarg->cs->vp == NULL)) {
			error = -1;	/* may be okay if rdattr_error */
			break;
		}
		ASSERT(sarg->cs->vp != NULL);
		error = VOP_PATHCONF(sarg->cs->vp, _PC_NAME_MAX, &val,
		    sarg->cs->cr, NULL);
		if (error == 0) {
			na->maxname = val;
		}
		break;
	case NFS4ATTR_SETIT:
		/*
		 * read-only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		ASSERT(sarg->cs->vp != NULL);
		error = VOP_PATHCONF(sarg->cs->vp, _PC_NAME_MAX, &val,
		    sarg->cs->cr, NULL);
		if (!error && (na->maxname != val))
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/* ARGSUSED */
static int
rfs4_fattr4_maxread(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int error = 0;

	if (RFS4_MANDATTR_ONLY)
		return (ENOTSUP);

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		na->maxread = rfs4_tsize(sarg->cs->req);
		break;
	case NFS4ATTR_SETIT:
		/*
		 * read-only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		if (na->maxread != rfs4_tsize(sarg->cs->req))
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/* ARGSUSED */
static int
rfs4_fattr4_maxwrite(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int error = 0;

	if (RFS4_MANDATTR_ONLY)
		return (ENOTSUP);

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		na->maxwrite = rfs4_tsize(sarg->cs->req);
		break;
	case NFS4ATTR_SETIT:
		/*
		 * read-only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		if (na->maxwrite != rfs4_tsize(sarg->cs->req))
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/* ARGSUSED */
static int
rfs4_fattr4_mimetype(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	return (ENOTSUP);
}

/* ARGSUSED */
static int
rfs4_fattr4_mode(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int	error = 0;

	if (RFS4_MANDATTR_ONLY)
		return (ENOTSUP);

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		if (sarg->rdattr_error && !(sarg->vap->va_mask & AT_MODE)) {
			error = -1;	/* may be okay if rdattr_error */
			break;
		}
		ASSERT(sarg->vap->va_mask & AT_MODE);
		na->mode = sarg->vap->va_mode;
		break;
	case NFS4ATTR_SETIT:
		ASSERT(sarg->vap->va_mask & AT_MODE);
		sarg->vap->va_mode = na->mode;
		/*
		 * If the filesystem is exported with nosuid, then mask off
		 * the setuid and setgid bits.
		 */
		if (sarg->cs->vp->v_type == VREG &&
		    (sarg->cs->exi->exi_export.ex_flags & EX_NOSUID))
			sarg->vap->va_mode &= ~(VSUID | VSGID);
		break;
	case NFS4ATTR_VERIT:
		ASSERT(sarg->vap->va_mask & AT_MODE);
		if (sarg->vap->va_mode != na->mode)
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/* ARGSUSED */
static int
rfs4_fattr4_no_trunc(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int error = 0;

	if (RFS4_MANDATTR_ONLY)
		return (ENOTSUP);

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		na->no_trunc = TRUE;
		break;
	case NFS4ATTR_SETIT:
		/*
		 * read-only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		if (!na->no_trunc)
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/* ARGSUSED */
static int
rfs4_fattr4_numlinks(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int	error = 0;

	if (RFS4_MANDATTR_ONLY)
		return (ENOTSUP);

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		if (sarg->rdattr_error && !(sarg->vap->va_mask & AT_NLINK)) {
			error = -1;	/* may be okay if rdattr_error */
			break;
		}
		ASSERT(sarg->vap->va_mask & AT_NLINK);
		na->numlinks = sarg->vap->va_nlink;
		break;
	case NFS4ATTR_SETIT:
		/*
		 * read-only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		ASSERT(sarg->vap->va_mask & AT_NLINK);
		if (sarg->vap->va_nlink != na->numlinks)
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/* ARGSUSED */
static int
rfs4_fattr4_owner(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int	error = 0;
	uid_t	uid;

	if (RFS4_MANDATTR_ONLY)
		return (ENOTSUP);

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		if (sarg->rdattr_error && !(sarg->vap->va_mask & AT_UID)) {
			error = -1;	/* may be okay if rdattr_error */
			break;
		}
		ASSERT(sarg->vap->va_mask & AT_UID);

		/*
		 * There are well defined polices for what happens on server-
		 * side GETATTR when uid to attribute string conversion cannot
		 * occur. Please refer to nfs4_idmap.c for details.
		 */
		error = nfs_idmap_uid_str(sarg->vap->va_uid, &na->owner, TRUE);
		switch (error) {
		case ECONNREFUSED:
			error = NFS4ERR_DELAY;
			break;
		default:
			break;
		}
		break;

	case NFS4ATTR_SETIT:
		ASSERT(sarg->vap->va_mask & AT_UID);

		/*
		 * There are well defined policies for what happens on server-
		 * side SETATTR of 'owner' when a "user@domain" mapping cannot
		 * occur. Please refer to nfs4_idmap.c for details.
		 *
		 * Any other errors, such as the mapping not being found by
		 * nfsmapid(1m), and interrupted clnt_call, etc, will result
		 * in NFS4ERR_BADOWNER.
		 *
		 * XXX need to return consistent errors, perhaps all
		 * server side attribute routines should return NFS4ERR*.
		 */
		error = nfs_idmap_str_uid(&na->owner, &sarg->vap->va_uid, TRUE);
		switch (error) {
		case NFS4_OK:
		case ENOTSUP:
			/*
			 * Ignore warning that we are the
			 * nfsmapid (can't happen on srv)
			 */
			error = 0;
			MSG_PRT_DEBUG = FALSE;
			break;

		case ECOMM:
		case ECONNREFUSED:
			if (!MSG_PRT_DEBUG) {
				/*
				 * printed just once per daemon death,
				 * inform the user and then stay silent
				 */
				cmn_err(CE_WARN, "!Unable to contact "
				    "nfsmapid");
				MSG_PRT_DEBUG = TRUE;
			}
			error = NFS4ERR_DELAY;
			break;

		case EINVAL:
			error = NFS4ERR_INVAL;
			break;

		default:
			error = NFS4ERR_BADOWNER;
			break;
		}
		break;

	case NFS4ATTR_VERIT:
		ASSERT(sarg->vap->va_mask & AT_UID);
		error = nfs_idmap_str_uid(&na->owner, &uid, TRUE);
		/*
		 * Ignore warning that we are the nfsmapid (can't happen on srv)
		 */
		if (error == ENOTSUP)
			error = 0;
		if (error)
			error = -1;	/* no match */
		else if (sarg->vap->va_uid != uid)
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		if (sarg->op == NFS4ATTR_GETIT) {
			if (na->owner.utf8string_val) {
				UTF8STRING_FREE(na->owner)
				bzero(&na->owner, sizeof (na->owner));
			}
		}
		break;
	}
	return (error);
}

/* ARGSUSED */
static int
rfs4_fattr4_owner_group(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int	error = 0;
	gid_t	gid;

	if (RFS4_MANDATTR_ONLY)
		return (ENOTSUP);

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		if (sarg->rdattr_error && !(sarg->vap->va_mask & AT_GID)) {
			error = -1;	/* may be okay if rdattr_error */
			break;
		}
		ASSERT(sarg->vap->va_mask & AT_GID);

		/*
		 * There are well defined polices for what happens on server-
		 * side GETATTR when gid to attribute string conversion cannot
		 * occur. Please refer to nfs4_idmap.c for details.
		 */
		error = nfs_idmap_gid_str(sarg->vap->va_gid, &na->owner_group,
		    TRUE);
		switch (error) {
		case ECONNREFUSED:
			error = NFS4ERR_DELAY;
			break;
		default:
			break;
		}
		break;

	case NFS4ATTR_SETIT:
		ASSERT(sarg->vap->va_mask & AT_GID);

		/*
		 * There are well defined policies for what happens on server-
		 * side SETATTR of 'owner_group' when a "group@domain" mapping
		 * cannot occur. Please refer to nfs4_idmap.c for details.
		 *
		 * Any other errors, such as the mapping not being found by
		 * nfsmapid(1m), and interrupted clnt_call, etc, will result
		 * in NFS4ERR_BADOWNER.
		 *
		 * XXX need to return consistent errors, perhaps all
		 * server side attribute routines should return NFS4ERR*.
		 */
		error = nfs_idmap_str_gid(&na->owner_group, &sarg->vap->va_gid,
		    TRUE);
		switch (error) {
		case NFS4_OK:
		case ENOTSUP:
			/*
			 * Ignore warning that we are the
			 * nfsmapid (can't happen on srv)
			 */
			error = 0;
			MSG_PRT_DEBUG = FALSE;
			break;

		case ECOMM:
		case ECONNREFUSED:
			if (!MSG_PRT_DEBUG) {
				/*
				 * printed just once per daemon death,
				 * inform the user and then stay silent
				 */
				cmn_err(CE_WARN, "!Unable to contact "
				    "nfsmapid");
				MSG_PRT_DEBUG = TRUE;
			}
			error = NFS4ERR_DELAY;
			break;

		case EINVAL:
			error = NFS4ERR_INVAL;
			break;

		default:
			error = NFS4ERR_BADOWNER;
			break;
		}
		break;

	case NFS4ATTR_VERIT:
		ASSERT(sarg->vap->va_mask & AT_GID);
		error = nfs_idmap_str_gid(&na->owner_group, &gid, TRUE);
		/*
		 * Ignore warning that we are the nfsmapid (can't happen on srv)
		 */
		if (error == ENOTSUP)
			error = 0;
		if (error)
			error = -1;	/* no match */
		else if (sarg->vap->va_gid != gid)
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		if (sarg->op == NFS4ATTR_GETIT) {
			if (na->owner_group.utf8string_val) {
				UTF8STRING_FREE(na->owner_group)
				bzero(&na->owner_group,
				    sizeof (na->owner_group));
			}
		}
		break;
	}
	return (error);
}

/* XXX - quota attributes should be supportable on Solaris 2 */
/* ARGSUSED */
static int
rfs4_fattr4_quota_avail_hard(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	return (ENOTSUP);
}

/* ARGSUSED */
static int
rfs4_fattr4_quota_avail_soft(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	return (ENOTSUP);
}

/* ARGSUSED */
static int
rfs4_fattr4_quota_used(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	return (ENOTSUP);
}

/* ARGSUSED */
static int
rfs4_fattr4_rawdev(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int	error = 0;

	if (RFS4_MANDATTR_ONLY)
		return (ENOTSUP);

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		if (sarg->rdattr_error && !(sarg->vap->va_mask & AT_RDEV)) {
			error = -1;	/* may be okay if rdattr_error */
			break;
		}
		ASSERT(sarg->vap->va_mask & AT_RDEV);
		na->rawdev.specdata1 =  (uint32)getmajor(sarg->vap->va_rdev);
		na->rawdev.specdata2 =  (uint32)getminor(sarg->vap->va_rdev);
		break;
	case NFS4ATTR_SETIT:
		/*
		 * read-only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		ASSERT(sarg->vap->va_mask & AT_RDEV);
		if ((na->rawdev.specdata1 !=
		    (uint32)getmajor(sarg->vap->va_rdev)) ||
		    (na->rawdev.specdata2 !=
		    (uint32)getminor(sarg->vap->va_rdev)))
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/* ARGSUSED */
static int
rfs4_fattr4_space_avail(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int	error = 0;

	if (RFS4_MANDATTR_ONLY)
		return (ENOTSUP);

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		if (sarg->rdattr_error && (sarg->sbp == NULL)) {
			error = -1;	/* may be okay if rdattr_error */
			break;
		}
		ASSERT(sarg->sbp != NULL);
		if (sarg->sbp->f_bavail != (fsblkcnt64_t)-1) {
			na->space_avail =
			    (fattr4_space_avail) sarg->sbp->f_frsize *
			    (fattr4_space_avail) sarg->sbp->f_bavail;
		} else {
			na->space_avail =
			    (fattr4_space_avail) sarg->sbp->f_bavail;
		}
		break;
	case NFS4ATTR_SETIT:
		/*
		 * read-only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		ASSERT(sarg->sbp != NULL);
		if (sarg->sbp->f_bavail != na->space_avail)
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/* ARGSUSED */
static int
rfs4_fattr4_space_free(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int	error = 0;

	if (RFS4_MANDATTR_ONLY)
		return (ENOTSUP);

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		if (sarg->rdattr_error && (sarg->sbp == NULL)) {
			error = -1;	/* may be okay if rdattr_error */
			break;
		}
		ASSERT(sarg->sbp != NULL);
		if (sarg->sbp->f_bfree != (fsblkcnt64_t)-1) {
			na->space_free =
			    (fattr4_space_free) sarg->sbp->f_frsize *
			    (fattr4_space_free) sarg->sbp->f_bfree;
		} else {
			na->space_free =
			    (fattr4_space_free) sarg->sbp->f_bfree;
		}
		break;
	case NFS4ATTR_SETIT:
		/*
		 * read-only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		ASSERT(sarg->sbp != NULL);
		if (sarg->sbp->f_bfree != na->space_free)
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/* ARGSUSED */
static int
rfs4_fattr4_space_total(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int	error = 0;

	if (RFS4_MANDATTR_ONLY)
		return (ENOTSUP);

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		if (sarg->rdattr_error_req && (sarg->sbp == NULL)) {
			error = -1;	/* may be okay if rdattr_error */
			break;
		}
		ASSERT(sarg->sbp != NULL);
		if (sarg->sbp->f_blocks != (fsblkcnt64_t)-1) {
			na->space_total =
			    (fattr4_space_total) sarg->sbp->f_frsize *
			    (fattr4_space_total) sarg->sbp->f_blocks;
		} else {
			na->space_total =
			    (fattr4_space_total) sarg->sbp->f_blocks;
		}
		break;
	case NFS4ATTR_SETIT:
		/*
		 * read-only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		ASSERT(sarg->sbp != NULL);
		if (sarg->sbp->f_blocks != na->space_total)
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/* ARGSUSED */
static int
rfs4_fattr4_space_used(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int	error = 0;

	if (RFS4_MANDATTR_ONLY)
		return (ENOTSUP);

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		if (sarg->rdattr_error && !(sarg->vap->va_mask & AT_NBLOCKS)) {
			error = -1;	/* may be okay if rdattr_error */
			break;
		}
		ASSERT(sarg->vap->va_mask & AT_NBLOCKS);
		na->space_used =  (fattr4_space_used) DEV_BSIZE *
		    (fattr4_space_used) sarg->vap->va_nblocks;
		break;
	case NFS4ATTR_SETIT:
		/*
		 * read-only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		ASSERT(sarg->vap->va_mask & AT_NBLOCKS);
		if (sarg->vap->va_nblocks != na->space_used)
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/* ARGSUSED */
static int
rfs4_fattr4_system(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	return (ENOTSUP);
}

/* ARGSUSED */
static int
rfs4_fattr4_time_access(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int	error = 0;
	timestruc_t atime;

	if (RFS4_MANDATTR_ONLY)
		return (ENOTSUP);

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		if (sarg->rdattr_error && !(sarg->vap->va_mask & AT_ATIME)) {
			error = -1;	/* may be okay if rdattr_error */
			break;
		}
		ASSERT(sarg->vap->va_mask & AT_ATIME);
		error = nfs4_time_vton(&sarg->vap->va_atime, &na->time_access);
		break;
	case NFS4ATTR_SETIT:
		/*
		 * read-only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		ASSERT(sarg->vap->va_mask & AT_ATIME);
		error = nfs4_time_ntov(&na->time_access, &atime);
		if (error)
			break;
		if (bcmp(&atime, &sarg->vap->va_atime, sizeof (atime)))
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/*
 * XXX - need to support the setting of access time
 */
/* ARGSUSED */
static int
rfs4_fattr4_time_access_set(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int	error = 0;
	settime4 *ta;

	if (RFS4_MANDATTR_ONLY)
		return (ENOTSUP);

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if ((sarg->op == NFS4ATTR_GETIT) ||
		    (sarg->op == NFS4ATTR_VERIT))
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
	case NFS4ATTR_VERIT:
		/*
		 * write only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_SETIT:
		ASSERT(sarg->vap->va_mask & AT_ATIME);
		/*
		 * Set access time (by server or by client)
		 */
		ta = &na->time_access_set;
		if (ta->set_it == SET_TO_CLIENT_TIME4) {
			error = nfs4_time_ntov(&ta->time, &sarg->vap->va_atime);
		} else if (ta->set_it == SET_TO_SERVER_TIME4) {
			gethrestime(&sarg->vap->va_atime);
		} else {
			error = EINVAL;
		}
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/* ARGSUSED */
static int
rfs4_fattr4_time_backup(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	return (ENOTSUP);
}

/* ARGSUSED */
static int
rfs4_fattr4_time_create(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	return (ENOTSUP);
}

/* ARGSUSED */
static int
rfs4_fattr4_time_delta(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int error = 0;

	if (RFS4_MANDATTR_ONLY)
		return (ENOTSUP);

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		na->time_delta.seconds = 0;
		na->time_delta.nseconds = 1000;
		break;
	case NFS4ATTR_SETIT:
		/*
		 * write only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		if ((na->time_delta.seconds != 0) ||
		    (na->time_delta.nseconds != 1000))
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/* ARGSUSED */
static int
rfs4_fattr4_time_metadata(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int	error = 0;
	timestruc_t ctime;

	if (RFS4_MANDATTR_ONLY)
		return (ENOTSUP);

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		if (sarg->rdattr_error && !(sarg->vap->va_mask & AT_CTIME)) {
			error = -1;	/* may be okay if rdattr_error */
			break;
		}
		ASSERT(sarg->vap->va_mask & AT_CTIME);
		error = nfs4_time_vton(&sarg->vap->va_ctime,
		    &na->time_metadata);
		break;
	case NFS4ATTR_SETIT:
		/*
		 * read-only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		ASSERT(sarg->vap->va_mask & AT_CTIME);
		error = nfs4_time_ntov(&na->time_metadata, &ctime);
		if (error)
			break;
		if (bcmp(&ctime, &sarg->vap->va_ctime, sizeof (ctime)))
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/* ARGSUSED */
static int
rfs4_fattr4_time_modify(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int	error = 0;
	timestruc_t mtime;

	if (RFS4_MANDATTR_ONLY)
		return (ENOTSUP);

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if (sarg->op == NFS4ATTR_SETIT)
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
		if (sarg->rdattr_error && !(sarg->vap->va_mask & AT_MTIME)) {
			error = -1;	/* may be okay if rdattr_error */
			break;
		}
		ASSERT(sarg->vap->va_mask & AT_MTIME);
		error = nfs4_time_vton(&sarg->vap->va_mtime, &na->time_modify);
		break;
	case NFS4ATTR_SETIT:
		/*
		 * read-only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_VERIT:
		ASSERT(sarg->vap->va_mask & AT_MTIME);
		error = nfs4_time_ntov(&na->time_modify, &mtime);
		if (error)
			break;
		if (bcmp(&mtime, &sarg->vap->va_mtime, sizeof (mtime)))
			error = -1;	/* no match */
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}

/*
 * XXX - need to add support for setting modify time
 */
/* ARGSUSED */
static int
rfs4_fattr4_time_modify_set(nfs4_attr_cmd_t cmd, struct nfs4_svgetit_arg *sarg,
    union nfs4_attr_u *na)
{
	int	error = 0;
	settime4 *tm;

	if (RFS4_MANDATTR_ONLY)
		return (ENOTSUP);

	switch (cmd) {
	case NFS4ATTR_SUPPORTED:
		if ((sarg->op == NFS4ATTR_GETIT) ||
		    (sarg->op == NFS4ATTR_VERIT))
			error = EINVAL;
		break;		/* this attr is supported */
	case NFS4ATTR_GETIT:
	case NFS4ATTR_VERIT:
		/*
		 * write only attr
		 */
		error = EINVAL;
		break;
	case NFS4ATTR_SETIT:
		ASSERT(sarg->vap->va_mask & AT_MTIME);
		/*
		 * Set modify time (by server or by client)
		 */
		tm = &na->time_modify_set;
		if (tm->set_it == SET_TO_CLIENT_TIME4) {
			error = nfs4_time_ntov(&tm->time, &sarg->vap->va_mtime);
			sarg->flag = ATTR_UTIME;
		} else if (tm->set_it == SET_TO_SERVER_TIME4) {
			gethrestime(&sarg->vap->va_mtime);
		} else {
			error = EINVAL;
		}
		break;
	case NFS4ATTR_FREEIT:
		break;
	}
	return (error);
}


static void
rfs4_ntov_init(void)
{
	/* index must be same as corresponding FATTR4_* define */
	nfs4_ntov_map[0].sv_getit = rfs4_fattr4_supported_attrs;
	nfs4_ntov_map[1].sv_getit = rfs4_fattr4_type;
	nfs4_ntov_map[2].sv_getit = rfs4_fattr4_fh_expire_type;
	nfs4_ntov_map[3].sv_getit = rfs4_fattr4_change;
	nfs4_ntov_map[4].sv_getit = rfs4_fattr4_size;
	nfs4_ntov_map[5].sv_getit = rfs4_fattr4_link_support;
	nfs4_ntov_map[6].sv_getit = rfs4_fattr4_symlink_support;
	nfs4_ntov_map[7].sv_getit = rfs4_fattr4_named_attr;
	nfs4_ntov_map[8].sv_getit = rfs4_fattr4_fsid;
	nfs4_ntov_map[9].sv_getit = rfs4_fattr4_unique_handles;
	nfs4_ntov_map[10].sv_getit = rfs4_fattr4_lease_time;
	nfs4_ntov_map[11].sv_getit = rfs4_fattr4_rdattr_error;
	nfs4_ntov_map[12].sv_getit = rfs4_fattr4_acl;
	nfs4_ntov_map[13].sv_getit = rfs4_fattr4_aclsupport;
	nfs4_ntov_map[14].sv_getit = rfs4_fattr4_archive;
	nfs4_ntov_map[15].sv_getit = rfs4_fattr4_cansettime;
	nfs4_ntov_map[16].sv_getit = rfs4_fattr4_case_insensitive;
	nfs4_ntov_map[17].sv_getit = rfs4_fattr4_case_preserving;
	nfs4_ntov_map[18].sv_getit = rfs4_fattr4_chown_restricted;
	nfs4_ntov_map[19].sv_getit = rfs4_fattr4_filehandle;
	nfs4_ntov_map[20].sv_getit = rfs4_fattr4_fileid;
	nfs4_ntov_map[21].sv_getit = rfs4_fattr4_files_avail;
	nfs4_ntov_map[22].sv_getit = rfs4_fattr4_files_free;
	nfs4_ntov_map[23].sv_getit = rfs4_fattr4_files_total;
	nfs4_ntov_map[24].sv_getit = rfs4_fattr4_fs_locations;
	nfs4_ntov_map[25].sv_getit = rfs4_fattr4_hidden;
	nfs4_ntov_map[26].sv_getit = rfs4_fattr4_homogeneous;
	nfs4_ntov_map[27].sv_getit = rfs4_fattr4_maxfilesize;
	nfs4_ntov_map[28].sv_getit = rfs4_fattr4_maxlink;
	nfs4_ntov_map[29].sv_getit = rfs4_fattr4_maxname;
	nfs4_ntov_map[30].sv_getit = rfs4_fattr4_maxread;
	nfs4_ntov_map[31].sv_getit = rfs4_fattr4_maxwrite;
	nfs4_ntov_map[32].sv_getit = rfs4_fattr4_mimetype;
	nfs4_ntov_map[33].sv_getit = rfs4_fattr4_mode;
	nfs4_ntov_map[34].sv_getit = rfs4_fattr4_no_trunc;
	nfs4_ntov_map[35].sv_getit = rfs4_fattr4_numlinks;
	nfs4_ntov_map[36].sv_getit = rfs4_fattr4_owner;
	nfs4_ntov_map[37].sv_getit = rfs4_fattr4_owner_group;
	nfs4_ntov_map[38].sv_getit = rfs4_fattr4_quota_avail_hard;
	nfs4_ntov_map[39].sv_getit = rfs4_fattr4_quota_avail_soft;
	nfs4_ntov_map[40].sv_getit = rfs4_fattr4_quota_used;
	nfs4_ntov_map[41].sv_getit = rfs4_fattr4_rawdev;
	nfs4_ntov_map[42].sv_getit = rfs4_fattr4_space_avail;
	nfs4_ntov_map[43].sv_getit = rfs4_fattr4_space_free;
	nfs4_ntov_map[44].sv_getit = rfs4_fattr4_space_total;
	nfs4_ntov_map[45].sv_getit = rfs4_fattr4_space_used;
	nfs4_ntov_map[46].sv_getit = rfs4_fattr4_system;
	nfs4_ntov_map[47].sv_getit = rfs4_fattr4_time_access;
	nfs4_ntov_map[48].sv_getit = rfs4_fattr4_time_access_set;
	nfs4_ntov_map[49].sv_getit = rfs4_fattr4_time_backup;
	nfs4_ntov_map[50].sv_getit = rfs4_fattr4_time_create;
	nfs4_ntov_map[51].sv_getit = rfs4_fattr4_time_delta;
	nfs4_ntov_map[52].sv_getit = rfs4_fattr4_time_metadata;
	nfs4_ntov_map[53].sv_getit = rfs4_fattr4_time_modify;
	nfs4_ntov_map[54].sv_getit = rfs4_fattr4_time_modify_set;
	nfs4_ntov_map[55].sv_getit = rfs4_fattr4_mounted_on_fileid;
}
