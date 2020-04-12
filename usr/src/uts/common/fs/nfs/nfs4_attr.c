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
 */

#include <sys/time.h>
#include <sys/systm.h>

#include <nfs/nfs.h>
#include <nfs/nfs4.h>
#include <nfs/rnode4.h>
#include <nfs/nfs4_clnt.h>
#include <sys/cmn_err.h>

static int
timestruc_to_settime4(timestruc_t *tt, settime4 *tt4, int flags)
{
	int	error = 0;

	if (flags & ATTR_UTIME) {
		tt4->set_it = SET_TO_CLIENT_TIME4;
		error = nfs4_time_vton(tt, &tt4->time);
	} else {
		tt4->set_it = SET_TO_SERVER_TIME4;
	}
	return (error);
}


/*
 * nfs4_ver_fattr4_attr translates a vattr attribute into a fattr4 attribute
 * for use by nfsv4 verify.  For setting atime or mtime use the entry for
 * time_XX (XX == access or modify).
 * Return TRUE if arg was set (even if there was an error) and FALSE
 * otherwise. Also set error code. The caller should not continue
 * if error was set, whether or not the return is TRUE or FALSE. Returning
 * FALSE does not mean there was an error, only that the attr was not set.
 *
 * Note: For now we only have the options used by setattr. In the future
 * the switch statement below should cover all vattr attrs and possibly
 * sys attrs as well.
 */
/* ARGSUSED */
static bool_t
nfs4_ver_fattr4_attr(vattr_t *vap, struct nfs4_ntov_map *ntovp,
    union nfs4_attr_u *nap, int flags, int *errorp)
{
	bool_t	retval = TRUE;

	/*
	 * Special case for time set: if setting the
	 * time, ignore entry for time access/modify set (setattr)
	 * and instead use that of time access/modify.
	 */
	*errorp = 0;
	/*
	 * Bit matches the mask
	 */
	switch (ntovp->vbit & vap->va_mask) {
	case AT_SIZE:
		nap->size = vap->va_size;
		break;
	case AT_MODE:
		nap->mode = vap->va_mode;
		break;
	case AT_UID:
		/*
		 * if no mapping, uid could be mapped to a numeric string,
		 * e.g. 12345->"12345"
		 */
		if (*errorp = nfs_idmap_uid_str(vap->va_uid, &nap->owner,
		    FALSE))
			retval = FALSE;
		break;
	case AT_GID:
		/*
		 * if no mapping, gid will be mapped to a number string,
		 * e.g. "12345"
		 */
		if (*errorp = nfs_idmap_gid_str(vap->va_gid, &nap->owner_group,
		    FALSE))
			retval = FALSE;
		break;
	case AT_ATIME:
		if ((ntovp->nval != FATTR4_TIME_ACCESS) ||
		    (*errorp = nfs4_time_vton(&vap->va_ctime,
		    &nap->time_access))) {
			/*
			 * either asked for FATTR4_TIME_ACCESS_SET -
			 *	not used for setattr
			 * or system time invalid for otw transfers
			 */
			retval = FALSE;
		}
		break;
	case AT_MTIME:
		if ((ntovp->nval != FATTR4_TIME_MODIFY) ||
		    (*errorp = nfs4_time_vton(&vap->va_mtime,
		    &nap->time_modify))) {
			/*
			 * either asked for FATTR4_TIME_MODIFY_SET -
			 *	not used for setattr
			 * or system time invalid for otw transfers
			 */
			retval = FALSE;
		}
		break;
	case AT_CTIME:
		if (*errorp = nfs4_time_vton(&vap->va_ctime,
		    &nap->time_metadata)) {
			/*
			 * system time invalid for otw transfers
			 */
			retval = FALSE;
		}
		break;
	default:
		retval = FALSE;
	}
	return (retval);
}

/*
 * nfs4_set_fattr4_attr translates a vattr attribute into a fattr4 attribute
 * for use by nfs4_setattr.  For setting atime or mtime use the entry for
 * time_XX_set rather than time_XX (XX == access or modify).
 * Return TRUE if arg was set (even if there was an error) and FALSE
 * otherwise. Also set error code. The caller should not continue
 * if error was set, whether or not the return is TRUE or FALSE. Returning
 * FALSE does not mean there was an error, only that the attr was not set.
 */
static bool_t
nfs4_set_fattr4_attr(vattr_t *vap, vsecattr_t *vsap,
    struct nfs4_ntov_map *ntovp, union nfs4_attr_u *nap, int flags,
    int *errorp)
{
	bool_t	retval = TRUE;

	/*
	 * Special case for time set: if setting the
	 * time, ignore entry for time access/modify
	 * and instead use that of time access/modify set.
	 */
	*errorp = 0;
	/*
	 * Bit matches the mask
	 */
	switch (ntovp->vbit & vap->va_mask) {
	case AT_SIZE:
		nap->size = vap->va_size;
		break;
	case AT_MODE:
		nap->mode = vap->va_mode;
		break;
	case AT_UID:
		/*
		 * if no mapping, uid will be mapped to a number string,
		 * e.g. "12345"
		 */
		if (*errorp = nfs_idmap_uid_str(vap->va_uid, &nap->owner,
		    FALSE))
			retval = FALSE;
		break;
	case AT_GID:
		/*
		 * if no mapping, gid will be mapped to a number string,
		 * e.g. "12345"
		 */
		if (*errorp = nfs_idmap_gid_str(vap->va_gid, &nap->owner_group,
		    FALSE))
			retval = FALSE;
		break;
	case AT_ATIME:
		if ((ntovp->nval != FATTR4_TIME_ACCESS_SET) ||
		    (*errorp = timestruc_to_settime4(&vap->va_atime,
		    &nap->time_access_set, flags))) {
			/* FATTR4_TIME_ACCESS - not used for verify */
			retval = FALSE;
		}
		break;
	case AT_MTIME:
		if ((ntovp->nval != FATTR4_TIME_MODIFY_SET) ||
		    (*errorp = timestruc_to_settime4(&vap->va_mtime,
		    &nap->time_modify_set, flags))) {
			/* FATTR4_TIME_MODIFY - not used for verify */
			retval = FALSE;
		}
		break;
	default:
		/*
		 * If the ntovp->vbit == 0 this is most likely the ACL.
		 */
		if (ntovp->vbit == 0 && ntovp->fbit == FATTR4_ACL_MASK) {
			ASSERT(vsap->vsa_mask == (VSA_ACE | VSA_ACECNT));
			nap->acl.fattr4_acl_len = vsap->vsa_aclcnt;
			nap->acl.fattr4_acl_val = vsap->vsa_aclentp;
		} else
			retval = FALSE;
	}

	return (retval);
}

/*
 * XXX - This is a shorter version of vattr_to_fattr4 which only takes care
 * of setattr args - size, mode, uid/gid, times. Eventually we should generalize
 * by using nfs4_ntov_map and the same functions used by the server.
 * Here we just hardcoded the setattr attributes. Note that the order is
 * important - it should follow the order of the bits in the mask.
 */
int
vattr_to_fattr4(vattr_t *vap, vsecattr_t *vsap, fattr4 *fattrp, int flags,
    enum nfs_opnum4 op, bitmap4 supp)
{
	int i, j;
	union nfs4_attr_u *na = NULL;
	int attrcnt;
	int uid_attr = -1;
	int gid_attr = -1;
	int acl_attr = -1;
	XDR xdr;
	ulong_t xdr_size;
	char *xdr_attrs;
	int error = 0;
	uint8_t amap[NFS4_MAXNUM_ATTRS];
	uint_t va_mask = vap->va_mask;
	bool_t (*attrfunc)();

#ifndef lint
	/*
	 * Make sure that maximum attribute number can be expressed as an
	 * 8 bit quantity.
	 */
	ASSERT(NFS4_MAXNUM_ATTRS <= (UINT8_MAX + 1));
#endif
	fattrp->attrmask = 0;
	fattrp->attrlist4_len = 0;
	fattrp->attrlist4 = NULL;
	na = kmem_zalloc(sizeof (union nfs4_attr_u) * nfs4_ntov_map_size,
	    KM_SLEEP);

	if (op == OP_SETATTR || op == OP_CREATE || op == OP_OPEN) {
		/*
		 * Note we need to set the attrmask for set operations.
		 * In particular mtime and atime will be set to the
		 * servers time.
		 */
		nfs4_vmask_to_nmask_set(va_mask, &fattrp->attrmask);
		if (vsap != NULL)
			fattrp->attrmask |= FATTR4_ACL_MASK;
		attrfunc = nfs4_set_fattr4_attr;
	} else {	/* verify/nverify */
		/*
		 * Verfy/nverify use the "normal vmask_to_nmask
		 * this routine knows how to handle all vmask bits
		 */
		nfs4_vmask_to_nmask(va_mask, &fattrp->attrmask);
		/*
		 * XXX verify/nverify only works for a subset of attrs that
		 * directly map to vattr_t attrs.  So, verify/nverify is
		 * broken for servers that only support mandatory attrs.
		 * Mask out change attr for now and fix verify op to
		 * work with mandonly servers later.  nfs4_vmask_to_nmask
		 * sets change whenever it sees request for ctime/mtime,
		 * so we must turn off change because nfs4_ver_fattr4_attr
		 * will not generate args for change.  This is a bug
		 * that will be fixed later.
		 * XXX
		 */
		fattrp->attrmask &= ~FATTR4_CHANGE_MASK;
		attrfunc = nfs4_ver_fattr4_attr;
	}

	/* Mask out any rec attrs unsupported by server */
	fattrp->attrmask &= supp;

	attrcnt = 0;
	xdr_size = 0;
	for (i = 0; i < nfs4_ntov_map_size; i++) {
		/*
		 * In the case of FATTR4_ACL_MASK, the vbit will be 0 (zero)
		 * so we must also check if the fbit is FATTR4_ACL_MASK before
		 * skipping over this attribute.
		 */
		if (!(nfs4_ntov_map[i].vbit & vap->va_mask)) {
			if (nfs4_ntov_map[i].fbit != FATTR4_ACL_MASK)
				continue;
			if (vsap == NULL)
				continue;
		}

		if (attrfunc == nfs4_set_fattr4_attr) {
			if (!(*attrfunc)(vap, vsap, &nfs4_ntov_map[i],
			    &na[attrcnt], flags, &error))
				continue;
		} else if (attrfunc == nfs4_ver_fattr4_attr) {
			if (!(*attrfunc)(vap, &nfs4_ntov_map[i], &na[attrcnt],
			    flags, &error))
				continue;
		}

		if (error)
			goto done;	/* Exit! */

		/*
		 * Calculate XDR size
		 */
		if (nfs4_ntov_map[i].xdr_size != 0) {
			/*
			 * If we are setting attributes (attrfunc is
			 * nfs4_set_fattr4_attr) and are setting the
			 * mtime or atime, adjust the xdr size down by
			 * 3 words, since we are using the server's
			 * time as the current time.  Exception: if
			 * ATTR_UTIME is set, the client sends the
			 * time, so leave the xdr size alone.
			 */
			xdr_size += nfs4_ntov_map[i].xdr_size;
			if ((nfs4_ntov_map[i].nval == FATTR4_TIME_ACCESS_SET ||
			    nfs4_ntov_map[i].nval == FATTR4_TIME_MODIFY_SET) &&
			    attrfunc == nfs4_set_fattr4_attr &&
			    !(flags & ATTR_UTIME)) {
				xdr_size -= 3 * BYTES_PER_XDR_UNIT;
			}
		} else {
			/*
			 * The only zero xdr_sizes we should see
			 * are AT_UID, AT_GID and FATTR4_ACL_MASK
			 */
			ASSERT(nfs4_ntov_map[i].vbit == AT_UID ||
			    nfs4_ntov_map[i].vbit == AT_GID ||
			    nfs4_ntov_map[i].fbit == FATTR4_ACL_MASK);
			if (nfs4_ntov_map[i].vbit == AT_UID) {
				uid_attr = attrcnt;
				xdr_size += BYTES_PER_XDR_UNIT;	/* length */
				xdr_size +=
				    RNDUP(na[attrcnt].owner.utf8string_len);
			} else if (nfs4_ntov_map[i].vbit == AT_GID) {
				gid_attr = attrcnt;
				xdr_size += BYTES_PER_XDR_UNIT;	/* length */
				xdr_size +=
				    RNDUP(
				    na[attrcnt].owner_group.utf8string_len);
			} else if (nfs4_ntov_map[i].fbit == FATTR4_ACL_MASK) {
				nfsace4 *tmpacl = (nfsace4 *)vsap->vsa_aclentp;

				acl_attr = attrcnt;
				/* fattr4_acl_len */
				xdr_size += BYTES_PER_XDR_UNIT;
				/* fattr4_acl_val */
				xdr_size += RNDUP((vsap->vsa_aclcnt *
				    (sizeof (acetype4) + sizeof (aceflag4)
				    + sizeof (acemask4))));

				for (j = 0; j < vsap->vsa_aclcnt; j++) {
					/* who - utf8string_len */
					xdr_size += BYTES_PER_XDR_UNIT;
					/* who - utf8string_val */
					xdr_size +=
					    RNDUP(tmpacl[j].who.utf8string_len);
				}
			}
		}

		/*
		 * This attr is going otw
		 */
		amap[attrcnt] = (uint8_t)nfs4_ntov_map[i].nval;
		attrcnt++;

		/*
		 * Clear this bit from test mask so we stop
		 * as soon as all requested attrs are done.
		 */
		va_mask &= ~nfs4_ntov_map[i].vbit;
		if (va_mask == 0 &&
		    (vsap == NULL || (vsap != NULL && acl_attr != -1)))
			break;
	}

	if (attrcnt == 0) {
		goto done;
	}

	fattrp->attrlist4 = xdr_attrs = kmem_alloc(xdr_size, KM_SLEEP);
	fattrp->attrlist4_len = xdr_size;
	xdrmem_create(&xdr, xdr_attrs, xdr_size, XDR_ENCODE);
	for (i = 0; i < attrcnt; i++) {
		if ((*nfs4_ntov_map[amap[i]].xfunc)(&xdr, &na[i]) == FALSE) {
			cmn_err(CE_WARN, "vattr_to_fattr4: xdr encode of "
			    "attribute failed\n");
			error = EINVAL;
			break;
		}
	}
done:
	/*
	 * Free any malloc'd attrs, can only be uid or gid
	 */
	if (uid_attr != -1 && na[uid_attr].owner.utf8string_val != NULL) {
		kmem_free(na[uid_attr].owner.utf8string_val,
		    na[uid_attr].owner.utf8string_len);
	}
	if (gid_attr != -1 && na[gid_attr].owner_group.utf8string_val != NULL) {
		kmem_free(na[gid_attr].owner_group.utf8string_val,
		    na[gid_attr].owner_group.utf8string_len);
	}

	/* xdrmem_destroy(&xdrs); */	/* NO-OP */
	kmem_free(na, sizeof (union nfs4_attr_u) * nfs4_ntov_map_size);
	if (error)
		nfs4_fattr4_free(fattrp);
	return (error);
}

void
nfs4_fattr4_free(fattr4 *attrp)
{
	/*
	 * set attrlist4val/len to 0 because...
	 *
	 * op_readdir resfree function could call us again
	 * for last entry4 if it was able to encode the name
	 * and cookie but couldn't encode the attrs because
	 * of maxcount violation (from rddir args).  In that
	 * case, the last/partial entry4's fattr4 has already
	 * been free'd, but the entry4 remains on the end of
	 * the list.
	 */
	attrp->attrmask = 0;

	if (attrp->attrlist4) {
		kmem_free(attrp->attrlist4, attrp->attrlist4_len);
		attrp->attrlist4 = NULL;
		attrp->attrlist4_len = 0;
	}
}

/*
 * Translate a vattr_t mask to a fattr4 type bitmap, caller is
 * responsible for zeroing bitsval if needed.
 */
void
nfs4_vmask_to_nmask(uint_t vmask, bitmap4 *bitsval)
{
	if (vmask == AT_ALL || vmask == NFS4_VTON_ATTR_MASK) {
		*bitsval |= NFS4_NTOV_ATTR_MASK;
		return;
	}

	vmask &= NFS4_VTON_ATTR_MASK;
	if (vmask == 0) {
		return;
	}

	if (vmask & AT_TYPE)
		*bitsval |= FATTR4_TYPE_MASK;
	if (vmask & AT_MODE)
		*bitsval |= FATTR4_MODE_MASK;
	if (vmask & AT_UID)
		*bitsval |= FATTR4_OWNER_MASK;
	if (vmask & AT_GID)
		*bitsval |= FATTR4_OWNER_GROUP_MASK;
	if (vmask & AT_FSID)
		*bitsval |= FATTR4_FSID_MASK;
	/* set mounted_on_fileid when AT_NODEID requested */
	if (vmask & AT_NODEID)
		*bitsval |= FATTR4_FILEID_MASK | FATTR4_MOUNTED_ON_FILEID_MASK;
	if (vmask & AT_NLINK)
		*bitsval |= FATTR4_NUMLINKS_MASK;
	if (vmask & AT_SIZE)
		*bitsval |= FATTR4_SIZE_MASK;
	if (vmask & AT_ATIME)
		*bitsval |= FATTR4_TIME_ACCESS_MASK;
	if (vmask & AT_MTIME)
		*bitsval |= FATTR4_TIME_MODIFY_MASK;
	/* also set CHANGE whenever AT_CTIME requested */
	if (vmask & AT_CTIME)
		*bitsval |= FATTR4_TIME_METADATA_MASK | FATTR4_CHANGE_MASK;
	if (vmask & AT_NBLOCKS)
		*bitsval |= FATTR4_SPACE_USED_MASK;
	if (vmask & AT_RDEV)
		*bitsval |= FATTR4_RAWDEV_MASK;
}

/*
 * nfs4_vmask_to_nmask_set is used for setattr. A separate function needed
 * because of special treatment to timeset.
 */
void
nfs4_vmask_to_nmask_set(uint_t vmask, bitmap4 *bitsval)
{
	vmask &= NFS4_VTON_ATTR_MASK_SET;

	if (vmask == 0) {
		return;
	}

	if (vmask & AT_MODE)
		*bitsval |= FATTR4_MODE_MASK;
	if (vmask & AT_UID)
		*bitsval |= FATTR4_OWNER_MASK;
	if (vmask & AT_GID)
		*bitsval |= FATTR4_OWNER_GROUP_MASK;
	if (vmask & AT_SIZE)
		*bitsval |= FATTR4_SIZE_MASK;
	if (vmask & AT_ATIME)
		*bitsval |= FATTR4_TIME_ACCESS_SET_MASK;
	if (vmask & AT_MTIME)
		*bitsval |= FATTR4_TIME_MODIFY_SET_MASK;
}

/*
 * Convert NFS Version 4 over the network attributes to the local
 * virtual attributes.
 */
vtype_t nf4_to_vt[] = {
	VBAD, VREG, VDIR, VBLK, VCHR, VLNK, VSOCK, VFIFO, VDIR, VREG
};


/*
 *	{ fbit, vbit, vfsstat, mandatory,
 *		nval, xdr_size, xfunc,
 *		sv_getit, prtstr },
 */
struct nfs4_ntov_map nfs4_ntov_map[] = {
	{ FATTR4_SUPPORTED_ATTRS_MASK, 0, FALSE, TRUE,
		FATTR4_SUPPORTED_ATTRS, 2 * BYTES_PER_XDR_UNIT, xdr_bitmap4,
		NULL, "fattr4_supported_attrs" },

	{ FATTR4_TYPE_MASK, AT_TYPE, FALSE, TRUE,
		FATTR4_TYPE, BYTES_PER_XDR_UNIT, xdr_int,
		NULL, "fattr4_type" },

	{ FATTR4_FH_EXPIRE_TYPE_MASK, 0, FALSE, TRUE,
		FATTR4_FH_EXPIRE_TYPE, BYTES_PER_XDR_UNIT, xdr_u_int,
		NULL, "fattr4_fh_expire_type" },

	{ FATTR4_CHANGE_MASK, 0, FALSE, TRUE,
		FATTR4_CHANGE, 2 * BYTES_PER_XDR_UNIT, xdr_u_longlong_t,
		NULL, "fattr4_change" },

	{ FATTR4_SIZE_MASK, AT_SIZE, FALSE, TRUE,
		FATTR4_SIZE,  2 * BYTES_PER_XDR_UNIT, xdr_u_longlong_t,
		NULL, "fattr4_size" },

	{ FATTR4_LINK_SUPPORT_MASK, 0, FALSE, TRUE,
		FATTR4_LINK_SUPPORT, BYTES_PER_XDR_UNIT, xdr_bool,
		NULL, "fattr4_link_support" },

	{ FATTR4_SYMLINK_SUPPORT_MASK, 0, FALSE, TRUE,
		FATTR4_SYMLINK_SUPPORT, BYTES_PER_XDR_UNIT, xdr_bool,
		NULL, "fattr4_symlink_support" },

	{ FATTR4_NAMED_ATTR_MASK, 0, FALSE, TRUE,
		FATTR4_NAMED_ATTR, BYTES_PER_XDR_UNIT, xdr_bool,
		NULL, "fattr4_named_attr" },

	{ FATTR4_FSID_MASK, AT_FSID, FALSE, TRUE,
		FATTR4_FSID, 4 * BYTES_PER_XDR_UNIT, xdr_fattr4_fsid,
		NULL, "fattr4_fsid" },

	{ FATTR4_UNIQUE_HANDLES_MASK, 0, FALSE, TRUE,
		FATTR4_UNIQUE_HANDLES, BYTES_PER_XDR_UNIT, xdr_bool,
		NULL, "fattr4_unique_handles" },

	{ FATTR4_LEASE_TIME_MASK, 0, FALSE, TRUE,
		FATTR4_LEASE_TIME, BYTES_PER_XDR_UNIT, xdr_u_int,
		NULL, "fattr4_lease_time" },

	{ FATTR4_RDATTR_ERROR_MASK, 0, FALSE, TRUE,
		FATTR4_RDATTR_ERROR, BYTES_PER_XDR_UNIT, xdr_int,
		NULL, "fattr4_rdattr_error" },

	{ FATTR4_ACL_MASK, 0, FALSE, FALSE,
		FATTR4_ACL, 0, xdr_fattr4_acl,
		NULL, "fattr4_acl" },

	{ FATTR4_ACLSUPPORT_MASK, 0, FALSE, FALSE,
		FATTR4_ACLSUPPORT, BYTES_PER_XDR_UNIT, xdr_u_int,
		NULL, "fattr4_aclsupport" },

	{ FATTR4_ARCHIVE_MASK, 0, FALSE, FALSE,
		FATTR4_ARCHIVE, BYTES_PER_XDR_UNIT, xdr_bool,
		NULL, "fattr4_archive" },

	{ FATTR4_CANSETTIME_MASK, 0, FALSE, FALSE,
		FATTR4_CANSETTIME, BYTES_PER_XDR_UNIT, xdr_bool,
		NULL, "fattr4_cansettime" },

	{ FATTR4_CASE_INSENSITIVE_MASK, 0, FALSE, FALSE,
		FATTR4_CASE_INSENSITIVE, BYTES_PER_XDR_UNIT, xdr_bool,
		NULL, "fattr4_case_insensitive" },

	{ FATTR4_CASE_PRESERVING_MASK, 0, FALSE, FALSE,
		FATTR4_CASE_PRESERVING, BYTES_PER_XDR_UNIT, xdr_bool,
		NULL, "fattr4_case_preserving" },

	{ FATTR4_CHOWN_RESTRICTED_MASK, 0, FALSE, FALSE,
		FATTR4_CHOWN_RESTRICTED, BYTES_PER_XDR_UNIT, xdr_bool,
		NULL, "fattr4_chown_restricted" },

	{ FATTR4_FILEHANDLE_MASK, 0, FALSE, TRUE,
		FATTR4_FILEHANDLE, 0, xdr_nfs_fh4,
		NULL, "fattr4_filehandle" },

	{ FATTR4_FILEID_MASK, AT_NODEID, FALSE, FALSE,
		FATTR4_FILEID, 2 * BYTES_PER_XDR_UNIT, xdr_u_longlong_t,
		NULL, "fattr4_fileid" },

	{ FATTR4_FILES_AVAIL_MASK, 0, TRUE, FALSE,
		FATTR4_FILES_AVAIL, 2 * BYTES_PER_XDR_UNIT, xdr_u_longlong_t,
		NULL, "fattr4_files_avail" },

	{ FATTR4_FILES_FREE_MASK, 0, TRUE, FALSE,
		FATTR4_FILES_FREE, 2 * BYTES_PER_XDR_UNIT, xdr_u_longlong_t,
		NULL, "fattr4_files_free" },

	{ FATTR4_FILES_TOTAL_MASK, 0, TRUE, FALSE,
		FATTR4_FILES_TOTAL, 2 * BYTES_PER_XDR_UNIT, xdr_u_longlong_t,
		NULL, "fattr4_files_total" },

	{ FATTR4_FS_LOCATIONS_MASK, 0, FALSE, FALSE,
		FATTR4_FS_LOCATIONS, 0, xdr_fattr4_fs_locations,
		NULL, "fattr4_fs_locations" },

	{ FATTR4_HIDDEN_MASK, 0, FALSE, FALSE,
		FATTR4_HIDDEN, BYTES_PER_XDR_UNIT, xdr_bool,
		NULL, "fattr4_hidden" },

	{ FATTR4_HOMOGENEOUS_MASK, 0, FALSE, FALSE,
		FATTR4_HOMOGENEOUS, BYTES_PER_XDR_UNIT, xdr_bool,
		NULL, "fattr4_homogeneous" },

	{ FATTR4_MAXFILESIZE_MASK, 0, FALSE, FALSE,
		FATTR4_MAXFILESIZE, 2 * BYTES_PER_XDR_UNIT, xdr_u_longlong_t,
		NULL, "fattr4_maxfilesize" },

	{ FATTR4_MAXLINK_MASK, 0, FALSE, FALSE,
		FATTR4_MAXLINK, BYTES_PER_XDR_UNIT, xdr_u_int,
		NULL, "fattr4_maxlink" },

	{ FATTR4_MAXNAME_MASK, 0, FALSE, FALSE,
		FATTR4_MAXNAME, BYTES_PER_XDR_UNIT, xdr_u_int,
		NULL, "fattr4_maxname" },

	{ FATTR4_MAXREAD_MASK, 0, FALSE, FALSE,
		FATTR4_MAXREAD, 2 * BYTES_PER_XDR_UNIT, xdr_u_longlong_t,
		NULL, "fattr4_maxread" },

	{ FATTR4_MAXWRITE_MASK, 0, FALSE, FALSE,
		FATTR4_MAXWRITE, 2 * BYTES_PER_XDR_UNIT, xdr_u_longlong_t,
		NULL, "fattr4_maxwrite" },

	{ FATTR4_MIMETYPE_MASK, 0, FALSE, FALSE,
		FATTR4_MIMETYPE, 0, xdr_utf8string,
		NULL, "fattr4_mimetype" },

	{ FATTR4_MODE_MASK, AT_MODE, FALSE, FALSE,
		FATTR4_MODE, BYTES_PER_XDR_UNIT, xdr_u_int,
		NULL, "fattr4_mode" },

	{ FATTR4_NO_TRUNC_MASK, 0, FALSE, FALSE,
		FATTR4_NO_TRUNC, BYTES_PER_XDR_UNIT, xdr_bool,
		NULL, "fattr4_no_trunc" },

	{ FATTR4_NUMLINKS_MASK, AT_NLINK, FALSE, FALSE,
		FATTR4_NUMLINKS, BYTES_PER_XDR_UNIT, xdr_u_int,
		NULL, "fattr4_numlinks" },

	{ FATTR4_OWNER_MASK, AT_UID, FALSE, FALSE,
		FATTR4_OWNER, 0, xdr_utf8string,
		NULL, "fattr4_owner" },

	{ FATTR4_OWNER_GROUP_MASK, AT_GID, FALSE, FALSE,
		FATTR4_OWNER_GROUP, 0, xdr_utf8string,
		NULL, "fattr4_owner_group" },

	{ FATTR4_QUOTA_AVAIL_HARD_MASK, 0, FALSE, FALSE,
		FATTR4_QUOTA_AVAIL_HARD, 2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t,
		NULL, "fattr4_quota_avail_hard" },

	{ FATTR4_QUOTA_AVAIL_SOFT_MASK, 0, FALSE, FALSE,
		FATTR4_QUOTA_AVAIL_SOFT, 2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t,
		NULL, "fattr4_quota_avail_soft" },

	{ FATTR4_QUOTA_USED_MASK, 0, FALSE, FALSE,
		FATTR4_QUOTA_USED, 2 * BYTES_PER_XDR_UNIT, xdr_u_longlong_t,
		NULL, "fattr4_quota_used" },

	{ FATTR4_RAWDEV_MASK, AT_RDEV, FALSE, FALSE,
		FATTR4_RAWDEV, 2 * BYTES_PER_XDR_UNIT, xdr_fattr4_rawdev,
		NULL, "fattr4_rawdev" },

	{ FATTR4_SPACE_AVAIL_MASK, 0, TRUE, FALSE,
		FATTR4_SPACE_AVAIL, 2 * BYTES_PER_XDR_UNIT, xdr_u_longlong_t,
		NULL, "fattr4_space_avail" },

	{ FATTR4_SPACE_FREE_MASK, 0, TRUE, FALSE,
		FATTR4_SPACE_FREE, 2 * BYTES_PER_XDR_UNIT, xdr_u_longlong_t,
		NULL, "fattr4_space_free" },

	{ FATTR4_SPACE_TOTAL_MASK, 0, TRUE, FALSE,
		FATTR4_SPACE_TOTAL, 2 * BYTES_PER_XDR_UNIT, xdr_u_longlong_t,
		NULL, "fattr4_space_total" },

	{ FATTR4_SPACE_USED_MASK, AT_NBLOCKS, FALSE, FALSE,
		FATTR4_SPACE_USED, 2 * BYTES_PER_XDR_UNIT, xdr_u_longlong_t,
		NULL, "fattr4_space_used" },

	{ FATTR4_SYSTEM_MASK, 0, FALSE, FALSE,
		FATTR4_SYSTEM, BYTES_PER_XDR_UNIT, xdr_bool,
		NULL, "fattr4_system" },

	{ FATTR4_TIME_ACCESS_MASK, AT_ATIME, FALSE, FALSE,
		FATTR4_TIME_ACCESS, 3 * BYTES_PER_XDR_UNIT, xdr_nfstime4,
		NULL, "fattr4_time_access" },

	{ FATTR4_TIME_ACCESS_SET_MASK, AT_ATIME, FALSE, FALSE,
		FATTR4_TIME_ACCESS_SET, 4 * BYTES_PER_XDR_UNIT, xdr_settime4,
		NULL, "fattr4_time_access_set" },

	{ FATTR4_TIME_BACKUP_MASK, 0, FALSE, FALSE,
		FATTR4_TIME_BACKUP, 3 * BYTES_PER_XDR_UNIT, xdr_nfstime4,
		NULL, "fattr4_time_backup" },

	{ FATTR4_TIME_CREATE_MASK, 0, FALSE, FALSE,
		FATTR4_TIME_CREATE, 3 * BYTES_PER_XDR_UNIT, xdr_nfstime4,
		NULL, "fattr4_time_create" },

	{ FATTR4_TIME_DELTA_MASK, 0, FALSE, FALSE,
		FATTR4_TIME_DELTA, 3 * BYTES_PER_XDR_UNIT, xdr_nfstime4,
		NULL, "fattr4_time_delta" },

	{ FATTR4_TIME_METADATA_MASK, AT_CTIME, FALSE, FALSE,
		FATTR4_TIME_METADATA, 3 * BYTES_PER_XDR_UNIT, xdr_nfstime4,
		NULL, "fattr4_time_metadata" },

	{ FATTR4_TIME_MODIFY_MASK, AT_MTIME, FALSE, FALSE,
		FATTR4_TIME_MODIFY, 3 * BYTES_PER_XDR_UNIT, xdr_nfstime4,
		NULL, "fattr4_time_modify" },

	{ FATTR4_TIME_MODIFY_SET_MASK, AT_MTIME, FALSE, FALSE,
		FATTR4_TIME_MODIFY_SET, 4 * BYTES_PER_XDR_UNIT, xdr_settime4,
		NULL, "fattr4_time_modify_set" },

	{ FATTR4_MOUNTED_ON_FILEID_MASK, AT_NODEID, FALSE, FALSE,
		FATTR4_MOUNTED_ON_FILEID, 2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t,
		NULL, "fattr4_mounted_on_fileid" },

	{ FATTR4_SUPPATTR_EXCLCREAT_MASK_LOCAL, 0, FALSE, FALSE,
		FATTR4_MOUNTED_ON_FILEID + 1, 0, xdr_bitmap4,
		NULL, "fattr4_suppattr_exclcreat" },
};

uint_t nfs4_ntov_map_size = sizeof (nfs4_ntov_map) /
	sizeof (struct nfs4_ntov_map);
