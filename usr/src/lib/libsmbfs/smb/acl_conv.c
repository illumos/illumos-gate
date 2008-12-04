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

/*
 * ACL support for smbfs
 *
 * May want to move some of this to usr/src/common
 * and compile with the smbfs kmod too, once we
 * implement VOP_GETSECATTR, VOP_SETSECATTR.
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/sunddi.h>
#include <sys/acl.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/byteorder.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <umem.h>
#include <idmap.h>

#include <sys/fs/smbfs_ioctl.h>

#include <netsmb/smb_lib.h>
#include <netsmb/smbfs_acl.h>
#include <netsmb/smbfs_isec.h>
#include <netsmb/mchain.h>
#include "private.h"

#ifdef _KERNEL
#define	MALLOC(size) kmem_alloc(size, KM_SLEEP)
#define	FREESZ(p, sz) kmem_free(p, sz)
#else	/* _KERNEL */
#define	MALLOC(size) malloc(size)
#ifndef lint
#define	FREESZ(p, sz) free(p)
#else	/* lint */
/* ARGSUSED */
static void
FREESZ(void *p, size_t sz)
{
	free(p);
}
#endif	/* lint */
#endif	/* _KERNEL */


#define	ERRCHK(expr)	if ((error = expr) != 0) goto errout

/*
 * Security IDentifier (SID)
 */
static void
ifree_sid(i_ntsid_t *sid)
{
	size_t sz;

	if (sid == NULL)
		return;

	sz = I_SID_SIZE(sid->sid_subauthcount);
	FREESZ(sid, sz);
}

static int
mb_get_sid(mbdata_t *mbp, i_ntsid_t **sidp)
{
	i_ntsid_t *sid = NULL;
	uint8_t revision, subauthcount;
	uint32_t *subauthp;
	size_t sidsz;
	int error, i;

	if ((error = mb_get_uint8(mbp, &revision)) != 0)
		return (error);
	if ((error = mb_get_uint8(mbp, &subauthcount)) != 0)
		return (error);

	sidsz = I_SID_SIZE(subauthcount);

	if ((sid = MALLOC(sidsz)) == NULL)
		return (ENOMEM);

	bzero(sid, sidsz);
	sid->sid_revision = revision;
	sid->sid_subauthcount = subauthcount;
	ERRCHK(mb_get_mem(mbp, (char *)sid->sid_authority, 6));

	subauthp = &sid->sid_subauthvec[0];
	for (i = 0; i < subauthcount; i++) {
		ERRCHK(mb_get_uint32le(mbp, subauthp));
		subauthp++;
	}

	/* Success! */
	*sidp = sid;
	return (0);

errout:
	ifree_sid(sid);
	return (error);
}

static int
mb_put_sid(mbdata_t *mbp, i_ntsid_t *sid)
{
	uint32_t *subauthp;
	int error, i;

	if (sid == NULL)
		return (EINVAL);

	ERRCHK(mb_put_uint8(mbp, sid->sid_revision));
	ERRCHK(mb_put_uint8(mbp, sid->sid_subauthcount));
	ERRCHK(mb_put_mem(mbp, (char *)sid->sid_authority, 6));

	subauthp = &sid->sid_subauthvec[0];
	for (i = 0; i < sid->sid_subauthcount; i++) {
		ERRCHK(mb_put_uint32le(mbp, *subauthp));
		subauthp++;
	}

	/* Success! */
	return (0);

errout:
	return (error);
}


/*
 * Access Control Entry (ACE)
 */
static void
ifree_ace(i_ntace_t *ace)
{
	size_t sz;

	if (ace == NULL)
		return;

	ifree_sid(ace->ace_sid);
	FREESZ(ace, sizeof (*ace));
}

static int
mb_get_ace(mbdata_t *mbp, i_ntace_t **acep)
{
	mbdata_t tmp_mb;
	i_ntace_t *ace = NULL;
	uint16_t ace_len;
	int error;

	if ((ace = MALLOC(sizeof (*ace))) == NULL)
		return (ENOMEM);
	bzero(ace, sizeof (*ace));

	/*
	 * The ACE is realy variable length,
	 * with format determined by the type.
	 * XXX: This only decodes types 0-7
	 *
	 * There may also be padding after it, so
	 * decode the using a copy of the mbdata,
	 * and then consume the specified length.
	 */
	tmp_mb = *mbp;

	/* Fixed-size header */
	ERRCHK(mb_get_uint8(&tmp_mb, &ace->ace_type));
	ERRCHK(mb_get_uint8(&tmp_mb, &ace->ace_flags));
	ERRCHK(mb_get_uint16le(&tmp_mb, &ace_len));

	/* Variable-size body */
	ERRCHK(mb_get_uint32le(&tmp_mb, &ace->ace_rights));
	ERRCHK(mb_get_sid(&tmp_mb, &ace->ace_sid));

	/* Now actually consume ace_len */
	ERRCHK(mb_get_mem(mbp, NULL, ace_len));

	/* Success! */
	*acep = ace;
	return (0);

errout:
	ifree_ace(ace);
	return (error);
}

static int
mb_put_ace(mbdata_t *mbp, i_ntace_t *ace)
{
	int cnt0, error;
	uint16_t ace_len, *ace_len_p;

	if (ace == NULL)
		return (EINVAL);

	cnt0 = mbp->mb_count;

	ERRCHK(mb_put_uint8(mbp, ace->ace_type));
	ERRCHK(mb_put_uint8(mbp, ace->ace_flags));
	ERRCHK(mb_fit(mbp, 2, (char **)&ace_len_p));
	ERRCHK(mb_put_uint32le(mbp, ace->ace_rights));

	ERRCHK(mb_put_sid(mbp, ace->ace_sid));

	ace_len = mbp->mb_count - cnt0;
	*ace_len_p = htoles(ace_len);

	/* Success! */
	return (0);

errout:
	return (error);
}


/*
 * Access Control List (ACL)
 */

/* Not an OTW structure, so size can be at our convenience. */
#define	I_ACL_SIZE(cnt)	(sizeof (i_ntacl_t) + (cnt) * sizeof (void *))

static void
ifree_acl(i_ntacl_t *acl)
{
	i_ntace_t **acep;
	size_t sz;
	int i;

	if (acl == NULL)
		return;

	acep = &acl->acl_acevec[0];
	for (i = 0; i < acl->acl_acecount; i++) {
		ifree_ace(*acep);
		acep++;
	}
	sz = I_ACL_SIZE(acl->acl_acecount);
	FREESZ(acl, sz);
}

static int
mb_get_acl(mbdata_t *mbp, i_ntacl_t **aclp)
{
	i_ntacl_t *acl = NULL;
	i_ntace_t **acep;
	uint8_t revision;
	uint16_t acl_len, acecount;
	uint32_t *subauthp;
	size_t aclsz;
	int i, error;

	if ((error = mb_get_uint8(mbp, &revision)) != 0)
		return (error);
	if ((error = mb_get_uint8(mbp, NULL)) != 0)
		return (error);
	if ((error = mb_get_uint16le(mbp, &acl_len)) != 0)
		return (error);
	if ((error = mb_get_uint16le(mbp, &acecount)) != 0)
		return (error);
	if ((error = mb_get_uint16(mbp, NULL)) != 0)
		return (error);

	aclsz = I_ACL_SIZE(acecount);
	if ((acl = MALLOC(aclsz)) == NULL)
		return (ENOMEM);
	bzero(acl, aclsz);
	acl->acl_revision = revision;
	acl->acl_acecount = acecount;

	acep = &acl->acl_acevec[0];
	for (i = 0; i < acl->acl_acecount; i++) {
		ERRCHK(mb_get_ace(mbp, acep));
		acep++;
	}
	/*
	 * There may be more data here, but
	 * the caller takes care of that.
	 */

	/* Success! */
	*aclp = acl;
	return (0);

errout:
	ifree_acl(acl);
	return (error);
}

static int
mb_put_acl(mbdata_t *mbp, i_ntacl_t *acl)
{
	i_ntace_t **acep;
	uint8_t revision;
	uint16_t acl_len, *acl_len_p;
	uint32_t *subauthp;
	size_t aclsz;
	int i, cnt0, error;

	cnt0 = mbp->mb_count;

	ERRCHK(mb_put_uint8(mbp, acl->acl_revision));
	ERRCHK(mb_put_uint8(mbp, 0)); /* pad1 */
	ERRCHK(mb_fit(mbp, 2, (char **)&acl_len_p));
	ERRCHK(mb_put_uint16le(mbp, acl->acl_acecount));
	ERRCHK(mb_put_uint16le(mbp, 0)); /* pad2 */

	acep = &acl->acl_acevec[0];
	for (i = 0; i < acl->acl_acecount; i++) {
		ERRCHK(mb_put_ace(mbp, *acep));
		acep++;
	}

	/* Fill in acl_len_p */
	acl_len = mbp->mb_count - cnt0;
	*acl_len_p = htoles(acl_len);

	/* Success! */
	return (0);

errout:
	return (error);
}


/*
 * Security Descriptor
 */
void
smbfs_acl_free_sd(i_ntsd_t *sd)
{

	if (sd == NULL)
		return;

	ifree_sid(sd->sd_owner);
	ifree_sid(sd->sd_group);
	ifree_acl(sd->sd_sacl);
	ifree_acl(sd->sd_dacl);

	FREESZ(sd, sizeof (*sd));
}

/*
 * Import a raw SD (mb chain) into "internal" form.
 * (like "absolute" form per. NT docs)
 * Returns allocated data in sdp
 *
 * Note: does NOT consume all the mbp data, so the
 * caller has to take care of that if necessary.
 */
int
mb_get_ntsd(mbdata_t *mbp, i_ntsd_t **sdp)
{
	i_ntsd_t *sd = NULL;
	mbdata_t top_mb, tmp_mb;
	uint32_t owneroff, groupoff, sacloff, dacloff;
	int error;

	if ((sd = MALLOC(sizeof (*sd))) == NULL)
		return (ENOMEM);
	bzero(sd, sizeof (*sd));

	/*
	 * Offsets below are relative to this point,
	 * so save the mbp state for use below.
	 */
	top_mb = *mbp;

	ERRCHK(mb_get_uint8(mbp, &sd->sd_revision));
	ERRCHK(mb_get_uint8(mbp, NULL));
	ERRCHK(mb_get_uint16le(mbp, &sd->sd_flags));
	ERRCHK(mb_get_uint32le(mbp, &owneroff));
	ERRCHK(mb_get_uint32le(mbp, &groupoff));
	ERRCHK(mb_get_uint32le(mbp, &sacloff));
	ERRCHK(mb_get_uint32le(mbp, &dacloff));

	/*
	 * For each section make a temporary copy of the
	 * top_mb state, advance to the given offset, and
	 * pass that to the lower mb_get_xxx functions.
	 * These could be marshalled in any order, but
	 * are normally found in the order shown here.
	 */
	if (sacloff) {
		tmp_mb = top_mb;
		mb_get_mem(&tmp_mb, NULL, sacloff);
		ERRCHK(mb_get_acl(&tmp_mb, &sd->sd_sacl));
	}
	if (dacloff) {
		tmp_mb = top_mb;
		mb_get_mem(&tmp_mb, NULL, dacloff);
		ERRCHK(mb_get_acl(&tmp_mb, &sd->sd_dacl));
	}
	if (owneroff) {
		tmp_mb = top_mb;
		mb_get_mem(&tmp_mb, NULL, owneroff);
		ERRCHK(mb_get_sid(&tmp_mb, &sd->sd_owner));
	}
	if (groupoff) {
		tmp_mb = top_mb;
		mb_get_mem(&tmp_mb, NULL, groupoff);
		ERRCHK(mb_get_sid(&tmp_mb, &sd->sd_group));
	}

	/* Success! */
	*sdp = sd;
	return (0);

errout:
	smbfs_acl_free_sd(sd);
	return (error);
}

/*
 * Export an "internal" SD into an raw SD (mb chain).
 * (a.k.a "self-relative" form per. NT docs)
 * Returns allocated mbchain in mbp.
 */
int
mb_put_ntsd(mbdata_t *mbp, i_ntsd_t *sd)
{
	uint32_t *owneroffp, *groupoffp, *sacloffp, *dacloffp;
	uint32_t owneroff, groupoff, sacloff, dacloff;
	int cnt0, error;

	cnt0 = mbp->mb_count;
	owneroff = groupoff = sacloff = dacloff = 0;

	ERRCHK(mb_put_uint8(mbp, sd->sd_revision));
	ERRCHK(mb_put_uint8(mbp, 0)); /* pad1 */
	ERRCHK(mb_put_uint16le(mbp, sd->sd_flags));
	ERRCHK(mb_fit(mbp, 4, (char **)&owneroffp));
	ERRCHK(mb_fit(mbp, 4, (char **)&groupoffp));
	ERRCHK(mb_fit(mbp, 4, (char **)&sacloffp));
	ERRCHK(mb_fit(mbp, 4, (char **)&dacloffp));

	/*
	 * These could be marshalled in any order, but
	 * are normally found in the order shown here.
	 */
	if (sd->sd_sacl) {
		sacloff = mbp->mb_count - cnt0;
		ERRCHK(mb_put_acl(mbp, sd->sd_sacl));
	}
	if (sd->sd_dacl) {
		dacloff = mbp->mb_count - cnt0;
		ERRCHK(mb_put_acl(mbp, sd->sd_dacl));
	}
	if (sd->sd_owner) {
		owneroff = mbp->mb_count - cnt0;
		ERRCHK(mb_put_sid(mbp, sd->sd_owner));
	}
	if (sd->sd_group) {
		groupoff = mbp->mb_count - cnt0;
		ERRCHK(mb_put_sid(mbp, sd->sd_group));
	}

	/* Fill in the offsets */
	*owneroffp = htolel(owneroff);
	*groupoffp = htolel(groupoff);
	*sacloffp  = htolel(sacloff);
	*dacloffp  = htolel(dacloff);

	/* Success! */
	return (0);

errout:
	return (error);
}


/*
 * Helper functions for conversion between ZFS-style ACLs
 * and Windows Security Descriptors.
 */


/*
 * Convert an NT SID to a string. Optionally return the
 * last sub-authority (or "relative ID" -- RID) in *ridp
 * and truncate the output string after the domain part.
 * If ridp==NULL, the output string is the whole SID,
 * including both the domain and RID.
 *
 * Return length written, or -1 on error.
 */
int
smbfs_sid2str(i_ntsid_t *sid,
	char *obuf, size_t osz, uint32_t *ridp)
{
	char *s = obuf;
	uint64_t auth = 0;
	uint_t i, n;
	uint32_t subs, *ip;

	n = snprintf(s, osz, "S-%u", sid->sid_revision);
	if (n > osz)
		return (-1);
	s += n; osz -= n;

	for (i = 0; i < 6; i++)
		auth = (auth << 8) | sid->sid_authority[i];
	n = snprintf(s, osz, "-%llu", auth);
	if (n > osz)
		return (-1);
	s += n; osz -= n;

	subs = sid->sid_subauthcount;
	if (subs < 1 || subs > 15)
		return (-1);
	if (ridp)
		subs--;

	ip = &sid->sid_subauthvec[0];
	for (; subs; subs--, ip++) {
		n = snprintf(s, osz, "-%u", *ip);
		if (n > osz)
			return (-1);
		s += n; osz -= n;
	}
	if (ridp)
		*ridp = *ip;

	return (s - obuf);
}

/*
 * Our interface to the idmap service.
 */

#ifdef	_KERNEL
#define	I_GetPidBySid kidmap_batch_getpidbysid
#define	I_GetMappings kidmap_get_mappings
#else /* _KERNEL */
#define	I_GetPidBySid idmap_get_pidbysid
#define	I_GetMappings idmap_get_mappings
#endif /* _KERNEL */

struct mapinfo {
	uid_t	mi_uid; /* or gid */
	int	mi_isuser;
	idmap_stat mi_status;
};

/*
 * A special value for mi_isuser (above) to indicate
 * that the SID is the well-known "Everyone" (S-1-1-0).
 * The idmap library only uses -1, 0, 1, so this value
 * is arbitrary but must not overlap w/ idmap values.
 * XXX: Could use a way for idmap to tell us when
 * it recognizes this well-known SID.
 */
#define	IS_WKSID_EVERYONE 11

/*
 * Build an idmap request.  Cleanup is
 * handled by the caller (error or not)
 */
static int
mkrq_idmap_sid2ux(
	idmap_get_handle_t *idmap_gh,
	i_ntsid_t *sid,
	struct mapinfo *mip)
{
	char sid_prefix[256];
	uint32_t	rid;
	idmap_stat	idms;

	if (smbfs_sid2str(sid, sid_prefix, sizeof (sid_prefix), &rid) < 0)
		return (EINVAL);

	/*
	 * Give the "Everyone" group special treatment.
	 */
	if (strcmp(sid_prefix, "S-1-1") == 0 && rid == 0) {
		/* This is "Everyone" */
		mip->mi_uid = (uid_t)-1;
		mip->mi_isuser = IS_WKSID_EVERYONE;
		mip->mi_status = 0;
		return (0);
	}

	idms = I_GetPidBySid(idmap_gh, sid_prefix, rid, 0,
	    &mip->mi_uid, &mip->mi_isuser, &mip->mi_status);
	if (idms != IDMAP_SUCCESS)
		return (EINVAL);

	return (0);
}

static void
ntace2zace(ace_t *zacep, i_ntace_t *ntace, struct mapinfo *mip)
{
	uint32_t zamask;
	uint16_t zflags, ntflags;
	uint8_t zatype = ntace->ace_type;

	/*
	 * Translate NT ACE flags to ZFS ACE flags.
	 * The low four bits are the same, but not
	 * others: INHERITED_ACE_FLAG, etc.
	 */
	ntflags = ntace->ace_flags;
	zflags = 0;

	if (ntflags & OBJECT_INHERIT_ACE_FLAG)
		zflags |= ACE_FILE_INHERIT_ACE;
	if (ntflags & CONTAINER_INHERIT_ACE_FLAG)
		zflags |= ACE_DIRECTORY_INHERIT_ACE;
	if (ntflags & NO_PROPAGATE_INHERIT_ACE_FLAG)
		zflags |= ACE_NO_PROPAGATE_INHERIT_ACE;
	if (ntflags & INHERIT_ONLY_ACE_FLAG)
		zflags |= ACE_INHERIT_ONLY_ACE;
	if (ntflags & INHERITED_ACE_FLAG)
		zflags |= ACE_INHERITED_ACE;

	if (ntflags & SUCCESSFUL_ACCESS_ACE_FLAG)
		zflags |= ACE_SUCCESSFUL_ACCESS_ACE_FLAG;
	if (ntflags & FAILED_ACCESS_ACE_FLAG)
		zflags |= ACE_FAILED_ACCESS_ACE_FLAG;

	/*
	 * Add the "ID type" flags to the ZFS ace flags.
	 * Would be nice if the idmap header defined some
	 * manifest constants for these "isuser" values.
	 */
	switch (mip->mi_isuser) {
	case IS_WKSID_EVERYONE:
		zflags |= ACE_EVERYONE;
		break;
	case 0: /* it's a GID */
		zflags |= ACE_IDENTIFIER_GROUP;
		break;
	default:
	case 1: /* it's a UID */
		break;
	}

	/*
	 * The access mask bits are the same, but
	 * mask off any bits we don't expect.
	 * Should not see any GENERIC_xxx flags,
	 * as those are only valid in requested
	 * access masks, not ACLs.  But if we do,
	 * get those, silently clear them here.
	 */
	zamask = ntace->ace_rights & ACE_ALL_PERMS;

	/*
	 * Verify that it's a known ACE type.
	 * Only handle the types that appear in
	 * V2, V3, V4 ACLs for now.  Avoid failing
	 * the whole conversion if we get unknown
	 * ace types, but convert them to something
	 * that will have no effect on access.
	 */
	if (zatype > SYSTEM_ALARM_OBJECT_ACE_TYPE) {
		zatype = ACCESS_ALLOWED_ACE_TYPE;
		zamask = 0; /* harmless */
	}

	/*
	 * Fill in the ZFS-style ACE
	 */
	zacep->a_who = mip->mi_uid; /* from ace_sid */
	zacep->a_access_mask = zamask;
	zacep->a_flags = zflags;
	zacep->a_type = zatype;
}

/*
 * Convert an internal SD to a ZFS-style ACL.
 * Note optional args: vsa/acl, uidp, gidp.
 */
int
smbfs_acl_sd2zfs(
	i_ntsd_t *sd,
#ifdef	_KERNEL
	vsecattr_t *acl_info,
#else /* _KERNEL */
	acl_t *acl_info,
#endif /* _KERNEL */
	uid_t *uidp, gid_t *gidp)
{
	struct mapinfo *mip, *mapinfo = NULL;
	int error, i, mapcnt, zacecnt, zacl_size;
	ace_t *zacep;
	i_ntacl_t *ntacl;
	i_ntace_t **ntacep;
#ifndef	_KERNEL
	idmap_handle_t *idmap_h = NULL;
#endif /* _KERNEL */
	idmap_get_handle_t *idmap_gh = NULL;
	idmap_stat	idms;

	/*
	 * sanity checks
	 */
#ifndef	_KERNEL
	if (acl_info) {
		if (acl_info->acl_type != ACE_T ||
		    acl_info->acl_aclp != NULL ||
		    acl_info->acl_entry_size != sizeof (ace_t))
			return (EINVAL);
	}
#endif /* _KERNEL */

	/*
	 * First, get all the SID mappings.
	 * How many?
	 */
	mapcnt = 0;
	if (sd->sd_owner)
		mapcnt++;
	if (sd->sd_group)
		mapcnt++;
	if (sd->sd_sacl)
		mapcnt += sd->sd_sacl->acl_acecount;
	if (sd->sd_dacl)
		mapcnt += sd->sd_dacl->acl_acecount;
	if (mapcnt == 0)
		return (EINVAL);

	mapinfo = MALLOC(mapcnt * sizeof (*mapinfo));
	if (mapinfo == NULL) {
		error = ENOMEM;
		goto errout;
	}
	bzero(mapinfo, mapcnt * sizeof (*mapinfo));


	/*
	 * Build our request to the idmap deamon.
	 */
#ifdef	_KERNEL
	idmap_gh = kidmap_get_create(curproc->p_zone);
#else /* _KERNEL */
	idms = idmap_init(&idmap_h);
	if (idms != IDMAP_SUCCESS) {
		error = ENOTACTIVE;
		goto errout;
	}
	idms = idmap_get_create(idmap_h, &idmap_gh);
	if (idms != IDMAP_SUCCESS) {
		error = ENOTACTIVE;
		goto errout;
	}
#endif /* _KERNEL */

	mip = mapinfo;
	if (sd->sd_owner) {
		error = mkrq_idmap_sid2ux(
		    idmap_gh, sd->sd_owner, mip);
		if (error)
			goto errout;
		mip++;
	}
	if (sd->sd_group) {
		error = mkrq_idmap_sid2ux(
		    idmap_gh, sd->sd_group, mip);
		if (error)
			goto errout;
		mip++;
	}
	if (sd->sd_sacl) {
		ntacl = sd->sd_sacl;
		ntacep = &ntacl->acl_acevec[0];
		for (i = 0; i < ntacl->acl_acecount; i++) {
			error = mkrq_idmap_sid2ux(
			    idmap_gh, (*ntacep)->ace_sid, mip);
			if (error)
				goto errout;
			ntacep++;
			mip++;
		}
	}
	if (sd->sd_dacl) {
		ntacl = sd->sd_dacl;
		ntacep = &ntacl->acl_acevec[0];
		for (i = 0; i < ntacl->acl_acecount; i++) {
			error = mkrq_idmap_sid2ux(
			    idmap_gh, (*ntacep)->ace_sid, mip);
			if (error)
				goto errout;
			ntacep++;
			mip++;
		}
	}

	idms = I_GetMappings(idmap_gh);
	if (idms != IDMAP_SUCCESS) {
#ifdef	DEBUG
		printf("idmap_get_mappings: rc=%d\n", idms);
#endif
		/* creative error choice */
		error = EIDRM;
		goto errout;
	}

	/*
	 * With any luck, we now have Unix user/group IDs
	 * for every Windows SID in the security descriptor.
	 * The remaining work is just format conversion.
	 */
	mip = mapinfo;
	if (sd->sd_owner) {
		if (uidp) {
			if (mip->mi_isuser == 1)
				*uidp = mip->mi_uid;
			else
				*uidp = (uid_t)-1;
		}
		mip++;
	} else {
		if (uidp)
			*uidp = (uid_t)-1;
	}
	if (sd->sd_group) {
		if (gidp) {
			if (mip->mi_isuser == 0)
				*gidp = (gid_t)mip->mi_uid;
			else
				*gidp = (gid_t)-1;
		}
		mip++;
	} else {
		if (gidp)
			*gidp = (gid_t)-1;
	}

	if (acl_info == NULL) {
		/* Caller only wanted uid/gid */
		goto ok_out;
	}

	/*
	 * Build the ZFS-style ACL
	 */
	zacecnt = 0;
	if (sd->sd_sacl)
		zacecnt += sd->sd_sacl->acl_acecount;
	if (sd->sd_dacl)
		zacecnt += sd->sd_dacl->acl_acecount;
	zacl_size = zacecnt * sizeof (ace_t);
	zacep = MALLOC(zacl_size);
#ifdef _KERNEL
	acl_info->vsa_aclentp = zacep;
	acl_info->vsa_aclentsz = zacl_size;
#else	/* _KERNEL */
	if (zacep == NULL) {
		error = ENOMEM;
		goto errout;
	}
	acl_info->acl_cnt = zacecnt;
	acl_info->acl_aclp = zacep;
#endif	/* _KERNEL */

	if (sd->sd_sacl) {
		ntacl = sd->sd_sacl;
		ntacep = &ntacl->acl_acevec[0];
		for (i = 0; i < ntacl->acl_acecount; i++) {
			ntace2zace(zacep, *ntacep, mip);
			zacep++;
			ntacep++;
			mip++;
		}
	}
	if (sd->sd_dacl) {
		ntacl = sd->sd_dacl;
		ntacep = &ntacl->acl_acevec[0];
		for (i = 0; i < ntacl->acl_acecount; i++) {
			ntace2zace(zacep, *ntacep, mip);
			zacep++;
			ntacep++;
			mip++;
		}
	}

ok_out:
	error = 0;

errout:
	if (mapinfo)
		FREESZ(mapinfo, mapcnt * sizeof (*mapinfo));

	return (error);
}


/*
 * Convert an internal SD to a ZFS-style ACL.
 * Include owner/group too if uid/gid != -1.
 * Note optional arg: vsa/acl
 */
int smbfs_acl_zfs2sd(
#ifdef	_KERNEL
	vsecattr_t *vsa,
#else /* _KERNEL */
	acl_t *acl,
#endif /* _KERNEL */
	uid_t uid, gid_t gid,
	i_ntsd_t **sdp)
{
	/* XXX - todo */
	return (ENOSYS);
}
