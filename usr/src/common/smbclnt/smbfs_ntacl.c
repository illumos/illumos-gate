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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * ACL conversion support for smbfs
 * (To/from NT/ZFS-style ACLs.)
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/acl.h>
#include <sys/byteorder.h>

#ifdef _KERNEL

#include <sys/cred.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/sunddi.h>
#include <sys/vnode.h>
#include <sys/vfs.h>

#include <sys/kidmap.h>

#else	/* _KERNEL */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#include <idmap.h>

#endif	/* _KERNEL */

#include <netsmb/mchain.h>
#include <netsmb/smb.h>
#include "smbfs_ntacl.h"

#define	NT_SD_REVISION	1
#define	NT_ACL_REVISION	2

#ifdef _KERNEL
#define	MALLOC(size) kmem_alloc(size, KM_SLEEP)
#define	FREESZ(p, sz) kmem_free(p, sz)
#else	/* _KERNEL */
#define	MALLOC(size) malloc(size)
/*
 * Define FREESZ() as inline function so the compiler will not
 * trigger variable set but not used warning for sz in calling function.
 */
/* ARGSUSED */
static inline void
FREESZ(void *p, size_t sz __unused)
{
	free(p);
}
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
md_get_sid(mdchain_t *mdp, i_ntsid_t **sidp)
{
	i_ntsid_t *sid = NULL;
	uint8_t revision, subauthcount;
	uint32_t *subauthp;
	size_t sidsz;
	int error, i;

	if ((error = md_get_uint8(mdp, &revision)) != 0)
		return (error);
	if ((error = md_get_uint8(mdp, &subauthcount)) != 0)
		return (error);

	sidsz = I_SID_SIZE(subauthcount);

	if ((sid = MALLOC(sidsz)) == NULL)
		return (ENOMEM);

	bzero(sid, sidsz);
	sid->sid_revision = revision;
	sid->sid_subauthcount = subauthcount;
	ERRCHK(md_get_mem(mdp, sid->sid_authority, 6, MB_MSYSTEM));

	subauthp = &sid->sid_subauthvec[0];
	for (i = 0; i < subauthcount; i++) {
		ERRCHK(md_get_uint32le(mdp, subauthp));
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
mb_put_sid(mbchain_t *mbp, i_ntsid_t *sid)
{
	uint32_t *subauthp;
	int error, i;

	if (sid == NULL)
		return (EINVAL);

	ERRCHK(mb_put_uint8(mbp, sid->sid_revision));
	ERRCHK(mb_put_uint8(mbp, sid->sid_subauthcount));
	ERRCHK(mb_put_mem(mbp, sid->sid_authority, 6, MB_MSYSTEM));

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

	if (ace == NULL)
		return;

	switch (ace->ace_hdr.ace_type) {
	case ACCESS_ALLOWED_ACE_TYPE:
	case ACCESS_DENIED_ACE_TYPE:
	case SYSTEM_AUDIT_ACE_TYPE:
	case SYSTEM_ALARM_ACE_TYPE:
		ifree_sid(ace->ace_v2.ace_sid);
		FREESZ(ace, sizeof (i_ntace_v2_t));
		break;
	/* other types todo */
	default:
		break;
	}
}

static int
md_get_ace(mdchain_t *mdp, i_ntace_t **acep)
{
	mdchain_t tmp_md;
	i_ntace_hdr_t ace_hdr;
	i_ntace_t *ace = NULL;
	uint16_t alloc_size;
	int error;

	/*
	 * The ACE is realy variable length,
	 * with format determined by the type.
	 *
	 * There may also be padding after it, so
	 * decode it using a copy of the mdchain,
	 * and then consume the specified length.
	 */
	tmp_md = *mdp;

	/* Fixed-size ACE header */
	ERRCHK(md_get_uint8(&tmp_md, &ace_hdr.ace_type));
	ERRCHK(md_get_uint8(&tmp_md, &ace_hdr.ace_flags));
	ERRCHK(md_get_uint16le(&tmp_md, &ace_hdr.ace_size));

	switch (ace_hdr.ace_type) {
	case ACCESS_ALLOWED_ACE_TYPE:
	case ACCESS_DENIED_ACE_TYPE:
	case SYSTEM_AUDIT_ACE_TYPE:
	case SYSTEM_ALARM_ACE_TYPE:
		alloc_size = sizeof (i_ntace_v2_t);
		if ((ace = MALLOC(alloc_size)) == NULL)
			return (ENOMEM);
		bzero(ace, alloc_size);
		/* ACE header */
		ace->ace_hdr.ace_type = ace_hdr.ace_type;
		ace->ace_hdr.ace_flags = ace_hdr.ace_flags;
		ace->ace_hdr.ace_size = alloc_size;
		/* Type-specific data. */
		ERRCHK(md_get_uint32le(&tmp_md, &ace->ace_v2.ace_rights));
		ERRCHK(md_get_sid(&tmp_md, &ace->ace_v2.ace_sid));
		break;

	/* other types todo */
	default:
		error = EIO;
		goto errout;
	}

	/* Now actually consume ace_hdr.ace_size */
	ERRCHK(md_get_mem(mdp, NULL, ace_hdr.ace_size, MB_MSYSTEM));

	/* Success! */
	*acep = ace;
	return (0);

errout:
	ifree_ace(ace);
	return (error);
}

static int
mb_put_ace(mbchain_t *mbp, i_ntace_t *ace)
{
	int cnt0, error;
	uint16_t ace_len, *ace_len_p;

	if (ace == NULL)
		return (EINVAL);

	cnt0 = mbp->mb_count;

	/*
	 * Put the (fixed-size) ACE header
	 * Will fill in the length later.
	 */
	ERRCHK(mb_put_uint8(mbp, ace->ace_hdr.ace_type));
	ERRCHK(mb_put_uint8(mbp, ace->ace_hdr.ace_flags));
	ace_len_p = mb_reserve(mbp, sizeof (*ace_len_p));
	if (ace_len_p == NULL) {
		error = ENOMEM;
		goto errout;
	}

	switch (ace->ace_hdr.ace_type) {
	case ACCESS_ALLOWED_ACE_TYPE:
	case ACCESS_DENIED_ACE_TYPE:
	case SYSTEM_AUDIT_ACE_TYPE:
	case SYSTEM_ALARM_ACE_TYPE:
		/* Put type-specific data. */
		ERRCHK(mb_put_uint32le(mbp, ace->ace_v2.ace_rights));
		ERRCHK(mb_put_sid(mbp, ace->ace_v2.ace_sid));
		break;

	/* other types todo */
	default:
		error = EIO;
		goto errout;
	}

	/* Fill in the (OtW) ACE length. */
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
md_get_acl(mdchain_t *mdp, i_ntacl_t **aclp)
{
	i_ntacl_t *acl = NULL;
	i_ntace_t **acep;
	uint8_t revision;
	uint16_t acl_len, acecount;
	size_t aclsz;
	int i, error;

	if ((error = md_get_uint8(mdp, &revision)) != 0)
		return (error);
	if ((error = md_get_uint8(mdp, NULL)) != 0) /* pad1 */
		return (error);
	if ((error = md_get_uint16le(mdp, &acl_len)) != 0)
		return (error);
	if ((error = md_get_uint16le(mdp, &acecount)) != 0)
		return (error);
	if ((error = md_get_uint16le(mdp, NULL)) != 0) /* pad2 */
		return (error);

	aclsz = I_ACL_SIZE(acecount);
	if ((acl = MALLOC(aclsz)) == NULL)
		return (ENOMEM);
	bzero(acl, aclsz);
	acl->acl_revision = revision;
	acl->acl_acecount = acecount;

	acep = &acl->acl_acevec[0];
	for (i = 0; i < acl->acl_acecount; i++) {
		ERRCHK(md_get_ace(mdp, acep));
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
mb_put_acl(mbchain_t *mbp, i_ntacl_t *acl)
{
	i_ntace_t **acep;
	uint16_t acl_len, *acl_len_p;
	int i, cnt0, error;

	cnt0 = mbp->mb_count;

	ERRCHK(mb_put_uint8(mbp, acl->acl_revision));
	ERRCHK(mb_put_uint8(mbp, 0)); /* pad1 */
	acl_len_p = mb_reserve(mbp, sizeof (*acl_len_p));
	if (acl_len_p == NULL) {
		error = ENOMEM;
		goto errout;
	}
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
 * Note: does NOT consume all the mdp data, so the
 * caller has to take care of that if necessary.
 */
int
md_get_ntsd(mdchain_t *mdp, i_ntsd_t **sdp)
{
	i_ntsd_t *sd = NULL;
	mdchain_t top_md, tmp_md;
	uint32_t owneroff, groupoff, sacloff, dacloff;
	int error;

	if ((sd = MALLOC(sizeof (*sd))) == NULL)
		return (ENOMEM);
	bzero(sd, sizeof (*sd));

	/*
	 * Offsets below are relative to this point,
	 * so save the mdp state for use below.
	 */
	top_md = *mdp;

	ERRCHK(md_get_uint8(mdp, &sd->sd_revision));
	ERRCHK(md_get_uint8(mdp, &sd->sd_rmctl));
	ERRCHK(md_get_uint16le(mdp, &sd->sd_flags));
	ERRCHK(md_get_uint32le(mdp, &owneroff));
	ERRCHK(md_get_uint32le(mdp, &groupoff));
	ERRCHK(md_get_uint32le(mdp, &sacloff));
	ERRCHK(md_get_uint32le(mdp, &dacloff));

	/*
	 * The SD is "self-relative" on the wire,
	 * but not after this decodes it.
	 */
	sd->sd_flags &= ~SD_SELF_RELATIVE;

	/*
	 * For each section make a temporary copy of the
	 * top_md state, advance to the given offset, and
	 * pass that to the lower md_get_xxx functions.
	 * These could be marshalled in any order, but
	 * are normally found in the order shown here.
	 */
	if (sacloff) {
		tmp_md = top_md;
		md_get_mem(&tmp_md, NULL, sacloff, MB_MSYSTEM);
		ERRCHK(md_get_acl(&tmp_md, &sd->sd_sacl));
	}
	if (dacloff) {
		tmp_md = top_md;
		md_get_mem(&tmp_md, NULL, dacloff, MB_MSYSTEM);
		ERRCHK(md_get_acl(&tmp_md, &sd->sd_dacl));
	}
	if (owneroff) {
		tmp_md = top_md;
		md_get_mem(&tmp_md, NULL, owneroff, MB_MSYSTEM);
		ERRCHK(md_get_sid(&tmp_md, &sd->sd_owner));
	}
	if (groupoff) {
		tmp_md = top_md;
		md_get_mem(&tmp_md, NULL, groupoff, MB_MSYSTEM);
		ERRCHK(md_get_sid(&tmp_md, &sd->sd_group));
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
mb_put_ntsd(mbchain_t *mbp, i_ntsd_t *sd)
{
	uint32_t *owneroffp, *groupoffp, *sacloffp, *dacloffp;
	uint32_t owneroff, groupoff, sacloff, dacloff;
	uint16_t flags;
	int cnt0, error;

	cnt0 = mbp->mb_count;
	owneroff = groupoff = sacloff = dacloff = 0;

	/* The SD is "self-relative" on the wire. */
	flags = sd->sd_flags | SD_SELF_RELATIVE;

	ERRCHK(mb_put_uint8(mbp, sd->sd_revision));
	ERRCHK(mb_put_uint8(mbp, sd->sd_rmctl));
	ERRCHK(mb_put_uint16le(mbp, flags));

	owneroffp = mb_reserve(mbp, sizeof (*owneroffp));
	groupoffp = mb_reserve(mbp, sizeof (*groupoffp));
	sacloffp  = mb_reserve(mbp, sizeof (*sacloffp));
	dacloffp  = mb_reserve(mbp, sizeof (*dacloffp));
	if (owneroffp == NULL || groupoffp == NULL ||
	    sacloffp == NULL || dacloffp == NULL) {
		error = ENOMEM;
		goto errout;
	}

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
 * ================================================================
 * Support for ACL fetch, including conversions
 * from Windows ACLs to NFSv4-style ACLs.
 * ================================================================
 */

#define	GENERIC_RIGHTS_MASK \
	(GENERIC_RIGHT_READ_ACCESS | GENERIC_RIGHT_WRITE_ACCESS |\
	GENERIC_RIGHT_EXECUTE_ACCESS | GENERIC_RIGHT_ALL_ACCESS)

/*
 * Table for converting NT GENERIC_RIGHT_... to specific rights
 * appropriate for objects of type file.
 */
struct gen2fsr {
	uint32_t	gf_generic;
	uint32_t	gf_specific;
};
static const struct gen2fsr
smbfs_gen2fsr[] = {
	{
		GENERIC_RIGHT_READ_ACCESS,
		STD_RIGHT_SYNCHRONIZE_ACCESS |
		STD_RIGHT_READ_CONTROL_ACCESS |
		SA_RIGHT_FILE_READ_ATTRIBUTES |
		SA_RIGHT_FILE_READ_EA |
		SA_RIGHT_FILE_READ_DATA },
	{
		GENERIC_RIGHT_WRITE_ACCESS,
		STD_RIGHT_SYNCHRONIZE_ACCESS |
		STD_RIGHT_READ_CONTROL_ACCESS |
		SA_RIGHT_FILE_WRITE_ATTRIBUTES |
		SA_RIGHT_FILE_WRITE_EA |
		SA_RIGHT_FILE_APPEND_DATA |
		SA_RIGHT_FILE_WRITE_DATA },
	{
		GENERIC_RIGHT_EXECUTE_ACCESS,
		STD_RIGHT_SYNCHRONIZE_ACCESS |
		STD_RIGHT_READ_CONTROL_ACCESS |
		SA_RIGHT_FILE_READ_ATTRIBUTES |
		SA_RIGHT_FILE_EXECUTE },
	{
		GENERIC_RIGHT_ALL_ACCESS,
		STD_RIGHT_SYNCHRONIZE_ACCESS |
		STD_RIGHT_WRITE_OWNER_ACCESS |
		STD_RIGHT_WRITE_DAC_ACCESS |
		STD_RIGHT_READ_CONTROL_ACCESS |
		STD_RIGHT_DELETE_ACCESS |
		SA_RIGHT_FILE_ALL_ACCESS },
	{ 0, 0 }
};

/*
 * Table for translating ZFS ACE flags to NT ACE flags.
 * The low four bits are the same, but not others.
 */
struct zaf2naf {
	uint16_t	za_flag;
	uint8_t		na_flag;
};
static const struct zaf2naf
smbfs_zaf2naf[] = {
	{ ACE_FILE_INHERIT_ACE,		OBJECT_INHERIT_ACE_FLAG },
	{ ACE_DIRECTORY_INHERIT_ACE,	CONTAINER_INHERIT_ACE_FLAG },
	{ ACE_NO_PROPAGATE_INHERIT_ACE,	NO_PROPAGATE_INHERIT_ACE_FLAG },
	{ ACE_INHERIT_ONLY_ACE,		INHERIT_ONLY_ACE_FLAG },
	{ ACE_INHERITED_ACE,		INHERITED_ACE_FLAG },
	{ ACE_SUCCESSFUL_ACCESS_ACE_FLAG, SUCCESSFUL_ACCESS_ACE_FLAG },
	{ ACE_FAILED_ACCESS_ACE_FLAG,	FAILED_ACCESS_ACE_FLAG },
	{ 0, 0 }
};

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
	n = snprintf(s, osz, "-%llu", (u_longlong_t)auth);
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

	/* LINTED E_PTRDIFF_OVERFLOW */
	return (s - obuf);
}

/*
 * Our interface to the idmap service.
 *
 * The idmap API is _almost_ the same between
 * kernel and user-level.  But not quite...
 * Hope this improves readability below.
 */
#ifdef	_KERNEL

#define	I_getuidbysid(GH, SPP, RID, UIDP, SP) \
	kidmap_batch_getuidbysid(GH, SPP, RID, UIDP, SP)

#define	I_getgidbysid(GH, SPP, RID, GIDP, SP) \
	kidmap_batch_getgidbysid(GH, SPP, RID, GIDP, SP)

#define	I_getpidbysid(GH, SPP, RID, PIDP, ISUP, SP) \
	kidmap_batch_getpidbysid(GH, SPP, RID, PIDP, ISUP, SP)

#define	I_getmappings kidmap_get_mappings

#else /* _KERNEL */

#define	I_getuidbysid(GH, SPP, RID, UIDP, SP) \
	idmap_get_uidbysid(GH, SPP, RID, 0, UIDP, SP)

#define	I_getgidbysid(GH, SPP, RID, GIDP, SP) \
	idmap_get_gidbysid(GH, SPP, RID, 0, GIDP, SP)

#define	I_getpidbysid(GH, SPP, RID, PIDP, ISUP, SP) \
	idmap_get_pidbysid(GH, SPP, RID, 0, PIDP, ISUP, SP)

#define	I_getmappings idmap_get_mappings

#endif /* _KERNEL */


/*
 * The idmap request types, chosen so they also
 * match the values returned in mi_isuser.
 */
#define	IDM_TYPE_ANY	-1
#define	IDM_TYPE_GROUP	0
#define	IDM_TYPE_USER	1

/*
 * A sentinel value for mi_isuser (below) to indicate
 * that the SID is the well-known "Everyone" (S-1-1-0).
 * The idmap library only uses -1, 0, 1, so this value
 * is arbitrary but must not overlap w/ idmap values.
 * XXX: Could use a way for idmap to tell us when
 * it recognizes this well-known SID.
 */
#define	IDM_EVERYONE	11

struct mapinfo2uid {
	uid_t	mi_uid; /* or gid, or pid */
	int	mi_isuser; /* IDM_TYPE */
	idmap_stat mi_status;
};

/*
 * Build an idmap request.  Cleanup is
 * handled by the caller (error or not)
 */
static int
mkrq_idmap_sid2ux(
	idmap_get_handle_t *idmap_gh,
	struct mapinfo2uid *mip,
	i_ntsid_t *sid,
	int req_type)
{
	char strbuf[256];
	char *sid_prefix;
	uint32_t	rid;
	idmap_stat	idms;

	if (smbfs_sid2str(sid, strbuf, sizeof (strbuf), &rid) < 0)
		return (EINVAL);
	sid_prefix = strbuf;

	/*
	 * Give the "Everyone" group special treatment.
	 */
	if (strcmp(sid_prefix, "S-1-1") == 0 && rid == 0) {
		/* This is "Everyone" */
		mip->mi_uid = (uid_t)-1;
		mip->mi_isuser = IDM_EVERYONE;
		mip->mi_status = 0;
		return (0);
	}

	switch (req_type) {

	case IDM_TYPE_USER:
		mip->mi_isuser = req_type;
		idms = I_getuidbysid(idmap_gh, sid_prefix, rid,
		    &mip->mi_uid, &mip->mi_status);
		break;

	case IDM_TYPE_GROUP:
		mip->mi_isuser = req_type;
		idms = I_getgidbysid(idmap_gh, sid_prefix, rid,
		    &mip->mi_uid, &mip->mi_status);
		break;

	case IDM_TYPE_ANY:
		idms = I_getpidbysid(idmap_gh, sid_prefix, rid,
		    &mip->mi_uid, &mip->mi_isuser, &mip->mi_status);
		break;

	default:
		idms = IDMAP_ERR_OTHER;
		break;
	}

	if (idms != IDMAP_SUCCESS)
		return (EINVAL);

	return (0);
}

/*
 * Convert an NT ACE to a ZFS ACE.
 * ACE type was already validated.
 */
static void
ntace2zace(ace_t *zacep, i_ntace_t *ntace, struct mapinfo2uid *mip)
{
	const struct zaf2naf *znaf;
	uid_t zwho;
	uint32_t zamask;
	uint16_t zflags;

	/*
	 * Set the "ID type" flags in the ZFS ace flags.
	 */
	zflags = 0;
	switch (mip->mi_isuser) {
	case IDM_EVERYONE:
		zflags = ACE_EVERYONE;
		zwho = (uid_t)-1;
		break;

	case IDM_TYPE_GROUP: /* it's a GID */
		zflags = ACE_IDENTIFIER_GROUP;
		zwho = mip->mi_uid;
		break;

	default:
	case IDM_TYPE_USER: /* it's a UID */
		zflags = 0;
		zwho = mip->mi_uid;
		break;
	}

	/*
	 * Translate NT ACE flags to ZFS ACE flags.
	 */
	for (znaf = smbfs_zaf2naf; znaf->za_flag; znaf++)
		if (ntace->ace_hdr.ace_flags & znaf->na_flag)
			zflags |= znaf->za_flag;

	/*
	 * The "normal" access mask bits are the same, but
	 * if the ACE has any GENERIC_RIGHT_... convert those
	 * to specific rights.  GENERIC bits are rarely seen,
	 * but reportedly can happen with inherit-only ACEs.
	 */
	zamask = ntace->ace_v2.ace_rights & ACE_ALL_PERMS;
	if (ntace->ace_v2.ace_rights & GENERIC_RIGHTS_MASK) {
		const struct gen2fsr *gf;
		for (gf = smbfs_gen2fsr; gf->gf_generic; gf++)
			if (ntace->ace_v2.ace_rights & gf->gf_generic)
				zamask |= gf->gf_specific;
	}

	/*
	 * Fill in the ZFS-style ACE
	 */
	zacep->a_who = zwho;
	zacep->a_access_mask = zamask;
	zacep->a_flags = zflags;
	zacep->a_type = ntace->ace_hdr.ace_type;
}

/*
 * Convert an internal SD to a ZFS-style ACL.
 * Note optional args: vsa/acl, uidp, gidp.
 *
 * This makes two passes over the SD, the first building a
 * "batch" request for idmap with results in mapinfo, the
 * second building a ZFS-style ACL using the idmap results.
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
	struct mapinfo2uid *mip, *mapinfo = NULL;
	int error, i, mapcnt, zacecnt, zacl_size;
	ace_t *zacep0, *zacep;
	uid_t own_uid = (uid_t)-1;
	gid_t own_gid = (gid_t)-1;
	i_ntacl_t *ntacl;
	i_ntace_t **ntacep;
	idmap_get_handle_t *idmap_gh = NULL;
	idmap_stat	idms;

	/*
	 * sanity checks
	 */
	if (acl_info) {
#ifndef	_KERNEL
		if (acl_info->acl_type != ACE_T ||
		    acl_info->acl_aclp != NULL ||
		    acl_info->acl_entry_size != sizeof (ace_t))
			return (EINVAL);
#endif /* _KERNEL */
		if ((sd->sd_flags & SD_DACL_PRESENT) == 0)
			return (EINVAL);
	}

	/*
	 * How many SID mappings will we need?
	 */
	mapcnt = 0;
	if (sd->sd_owner)
		mapcnt++;
	if (sd->sd_group)
		mapcnt++;
	if ((sd->sd_flags & SD_SACL_PRESENT) &&
	    (sd->sd_sacl != NULL))
		mapcnt += sd->sd_sacl->acl_acecount;
	if ((sd->sd_flags & SD_DACL_PRESENT) &&
	    (sd->sd_dacl != NULL))
		mapcnt += sd->sd_dacl->acl_acecount;
	if (mapcnt == 0) {
		/*
		 * We have a NULL DACL, SACL, and don't
		 * have an owner or group, so there's no
		 * idmap work to do.  This is very rare,
		 * so rather than complicate things below,
		 * pretend we need one mapping slot.
		 */
		mapcnt = 1;
	}

	mapinfo = MALLOC(mapcnt * sizeof (*mapinfo));
	if (mapinfo == NULL) {
		error = ENOMEM;
		goto errout;
	}
	bzero(mapinfo, mapcnt * sizeof (*mapinfo));


	/*
	 * Get an imap "batch" request handle.
	 */
#ifdef	_KERNEL
	idmap_gh = kidmap_get_create(curproc->p_zone);
#else /* _KERNEL */
	idms = idmap_get_create(&idmap_gh);
	if (idms != IDMAP_SUCCESS) {
		error = ENOTACTIVE;
		goto errout;
	}
#endif /* _KERNEL */

	/*
	 * Build our request to the idmap deamon,
	 * getting Unix IDs for every SID.
	 */
	mip = mapinfo;
	if (sd->sd_owner) {
		error = mkrq_idmap_sid2ux(idmap_gh, mip,
		    sd->sd_owner, IDM_TYPE_USER);
		if (error)
			goto errout;
		mip++;
	}
	if (sd->sd_group) {
		error = mkrq_idmap_sid2ux(idmap_gh, mip,
		    sd->sd_group, IDM_TYPE_GROUP);
		if (error)
			goto errout;
		mip++;
	}
	if ((sd->sd_flags & SD_SACL_PRESENT) &&
	    (sd->sd_sacl != NULL)) {
		ntacl = sd->sd_sacl;
		ntacep = &ntacl->acl_acevec[0];
		for (i = 0; i < ntacl->acl_acecount; i++) {
			error = mkrq_idmap_sid2ux(idmap_gh, mip,
			    (*ntacep)->ace_v2.ace_sid, IDM_TYPE_ANY);
			if (error)
				goto errout;
			ntacep++;
			mip++;
		}
	}
	if ((sd->sd_flags & SD_DACL_PRESENT) &&
	    (sd->sd_dacl != NULL)) {
		ntacl = sd->sd_dacl;
		ntacep = &ntacl->acl_acevec[0];
		for (i = 0; i < ntacl->acl_acecount; i++) {
			error = mkrq_idmap_sid2ux(idmap_gh, mip,
			    (*ntacep)->ace_v2.ace_sid, IDM_TYPE_ANY);
			if (error)
				goto errout;
			ntacep++;
			mip++;
		}
	}

	if (mip != mapinfo) {
		idms = I_getmappings(idmap_gh);
		if (idms != IDMAP_SUCCESS) {
			/* creative error choice */
			error = EIDRM;
			goto errout;
		}
	}

	/*
	 * With any luck, we now have Unix user/group IDs
	 * for every Windows SID in the security descriptor.
	 * The remaining work is just format conversion.
	 */
	mip = mapinfo;
	if (sd->sd_owner) {
		own_uid = mip->mi_uid;
		mip++;
	}
	if (sd->sd_group) {
		own_gid = mip->mi_uid;
		mip++;
	}

	if (uidp)
		*uidp = own_uid;
	if (gidp)
		*gidp = own_gid;

	if (acl_info == NULL) {
		/* Caller only wanted uid/gid */
		goto done;
	}

	/*
	 * Build the ZFS-style ACL
	 * First, allocate the most ZFS ACEs we'll need.
	 */
	zacecnt = 0;
	if ((sd->sd_flags & SD_SACL_PRESENT) &&
	    (sd->sd_sacl != NULL))
		zacecnt += sd->sd_sacl->acl_acecount;

	/* NB, have: (sd->sd_flags & SD_DACL_PRESENT) */
	if ((sd->sd_dacl != NULL) &&
	    (sd->sd_dacl->acl_acecount > 0)) {
		zacecnt += sd->sd_dacl->acl_acecount;
	} else {
		/*
		 * DACL is NULL or empty. Either way,
		 * we'll need to add a ZFS ACE below.
		 */
		zacecnt++;
	}
	zacl_size = zacecnt * sizeof (ace_t);
	zacep0 = MALLOC(zacl_size);
	if (zacep0 == NULL) {
		error = ENOMEM;
		goto errout;
	}
	zacep = zacep0;

	if ((sd->sd_flags & SD_SACL_PRESENT) &&
	    (sd->sd_sacl != NULL)) {
		ntacl = sd->sd_sacl;
		ntacep = &ntacl->acl_acevec[0];
		for (i = 0; i < ntacl->acl_acecount; i++) {
			ntace2zace(zacep, *ntacep, mip);
			zacep++;
			ntacep++;
			mip++;
		}
	}

	/* NB, have: (sd->sd_flags & SD_DACL_PRESENT) */
	if (sd->sd_dacl != NULL) {
		ntacl = sd->sd_dacl;
		ntacep = &ntacl->acl_acevec[0];
		for (i = 0; i < ntacl->acl_acecount; i++) {
			ntace2zace(zacep, *ntacep, mip);
			zacep++;
			ntacep++;
			mip++;
		}
	}
	if (sd->sd_dacl == NULL) {
		/*
		 * The SD has a NULL DACL.  That means
		 * everyone@, full-control
		 */
		zacep->a_who = (uid_t)-1;
		zacep->a_access_mask = ACE_ALL_PERMS;
		zacep->a_flags = ACE_EVERYONE;
		zacep->a_type = ACCESS_ALLOWED_ACE_TYPE;
	} else if (sd->sd_dacl->acl_acecount == 0) {
		/*
		 * The SD has an Empty DACL.  We need
		 * at least one ACE, so add one giving
		 * the owner the usual implied access.
		 */
		zacep->a_who = (uid_t)-1;
		zacep->a_access_mask = ACE_READ_ATTRIBUTES | \
		    ACE_READ_ACL | ACE_WRITE_ACL;
		zacep->a_flags = ACE_OWNER;
		zacep->a_type = ACCESS_ALLOWED_ACE_TYPE;
	}

#ifdef _KERNEL
	acl_info->vsa_aclcnt = zacecnt;
	acl_info->vsa_aclentp = zacep0;
	acl_info->vsa_aclentsz = zacl_size;
#else	/* _KERNEL */
	acl_info->acl_cnt = zacecnt;
	acl_info->acl_aclp = zacep0;
#endif	/* _KERNEL */

done:
	error = 0;

errout:
	if (mapinfo != NULL)
		FREESZ(mapinfo, mapcnt * sizeof (*mapinfo));
#ifdef	_KERNEL
	if (idmap_gh != NULL)
		kidmap_get_destroy(idmap_gh);
#else /* _KERNEL */
	if (idmap_gh != NULL)
		idmap_get_destroy(idmap_gh);
#endif /* _KERNEL */

	return (error);
}


/*
 * ================================================================
 * Support for ACL store, including conversions
 * from NFSv4-style ACLs to Windows ACLs.
 * ================================================================
 */

/*
 * Convert a "sid-prefix" string plus RID into an NT SID.
 *
 * If successful, sets *osid and returns zero,
 * otherwise returns an errno value.
 */
int
smbfs_str2sid(const char *sid_prefix, uint32_t *ridp, i_ntsid_t **osidp)
{
	i_ntsid_t *sid = NULL;
	u_longlong_t auth = 0;
	ulong_t sa;
	uint8_t sacnt;
	const char *p;
	char *np;
	size_t size;
	int i;
	int err;

	if (sid_prefix == NULL)
		return (EINVAL);

	p = sid_prefix;
	if (strncmp(p, "S-1-", 4) != 0)
		return (EINVAL);
	p += 4;

	/* Parse the "authority" */
#ifdef	_KERNEL
	err = ddi_strtoull(p, &np, 10, &auth);
	if (err != 0)
		return (err);
#else	/* _KERNEL */
	auth = strtoull(p, &np, 10);
	if (p == np)
		return (EINVAL);
#endif	/* _KERNEL */

	/*
	 * Count the sub-authorities.  Here, np points to
	 * the "-" before the first sub-authority.
	 */
	sacnt = 0;
	for (p = np; *p; p++) {
		if (*p == '-')
			sacnt++;
	}
	if (ridp != NULL)
		sacnt++;

	/* Allocate the internal SID. */
	size = I_SID_SIZE(sacnt);
	sid = MALLOC(size);
	if (sid == NULL)
		return (ENOMEM);
	bzero(sid, size);

	/* Fill it in. */
	sid->sid_revision = 1;
	sid->sid_subauthcount = sacnt;
	for (i = 5; i >= 0; i--) {
		sid->sid_authority[i] = auth & 0xFF;
		auth = auth >> 8;
	}

	err = EINVAL;
	if (ridp != NULL)
		sacnt--; /* Last SA not from string */
	p = np;
	for (i = 0; i < sacnt; i++) {
		if (*p != '-') {
			err = EINVAL;
			goto out;
		}
		p++;
#ifdef	_KERNEL
		err = ddi_strtoul(p, &np, 10, &sa);
		if (err != 0)
			goto out;
#else	/* _KERNEL */
		sa = strtoul(p, &np, 10);
		if (p == np) {
			err = EINVAL;
			goto out;
		}
#endif	/* _KERNEL */
		sid->sid_subauthvec[i] = (uint32_t)sa;
		p = np;
	}
	if (*p != '\0')
		goto out;
	if (ridp != NULL)
		sid->sid_subauthvec[i] = *ridp;
	err = 0;

out:
	if (err)
		FREESZ(sid, size);
	else
		*osidp = sid;

	return (err);
}

/*
 * The idmap API is _almost_ the same between
 * kernel and user-level.  But not quite...
 * Hope this improves readability below.
 */
#ifdef	_KERNEL

#define	I_getsidbyuid(GH, UID, SPP, RP, ST) \
	kidmap_batch_getsidbyuid(GH, UID, SPP, RP, ST)

#define	I_getsidbygid(GH, GID, SPP, RP, ST) \
	kidmap_batch_getsidbygid(GH, GID, SPP, RP, ST)

#else /* _KERNEL */

#define	I_getsidbyuid(GH, UID, SPP, RP, ST) \
	idmap_get_sidbyuid(GH, UID, 0, SPP, RP, ST)

#define	I_getsidbygid(GH, GID, SPP, RP, ST) \
	idmap_get_sidbygid(GH, GID, 0, SPP, RP, ST)

#endif /* _KERNEL */

struct mapinfo2sid {
	/* Yet another kernel vs. user difference. */
#ifdef	_KERNEL
	const char *mi_dsid;	/* domain SID */
#else /* _KERNEL */
	char *mi_dsid;
#endif /* _KERNEL */
	uint32_t mi_rid;	/* relative ID */
	idmap_stat mi_status;
};

/*
 * Build an idmap request.  Cleanup is
 * handled by the caller (error or not)
 */
static int
mkrq_idmap_ux2sid(
	idmap_get_handle_t *idmap_gh,
	struct mapinfo2sid *mip,
	uid_t	uid, /* or gid */
	int req_type)
{
	idmap_stat	idms;

	switch (req_type) {

	case IDM_TYPE_USER:
		if (uid == (uid_t)-1)
			return (EINVAL);
		idms = I_getsidbyuid(idmap_gh, uid,
		    &mip->mi_dsid, &mip->mi_rid, &mip->mi_status);
		break;

	case IDM_TYPE_GROUP:
		if (uid == (uid_t)-1)
			return (EINVAL);
		idms = I_getsidbygid(idmap_gh, uid,
		    &mip->mi_dsid, &mip->mi_rid, &mip->mi_status);
		break;

	case IDM_EVERYONE:
		mip->mi_dsid = "S-1-1";
		mip->mi_rid = 0;
		mip->mi_status = 0;
		idms = IDMAP_SUCCESS;
		break;

	default:
		idms = IDMAP_ERR_OTHER;
		break;
	}

	if (idms != IDMAP_SUCCESS)
		return (EINVAL);

	return (0);
}

/*
 * Convert a ZFS ACE to an NT ACE.
 * ACE type was already validated.
 */
static int
zace2ntace(i_ntace_t **ntacep, ace_t *zacep, struct mapinfo2sid *mip)
{
	const struct zaf2naf *znaf;
	uint8_t aflags;
	uint16_t alloc_size;
	uint32_t rights;
	i_ntace_t *ntace = NULL;
	i_ntsid_t *sid = NULL;
	int error;

	if (mip->mi_dsid == NULL || mip->mi_status != 0) {
		return (EINVAL);
	}

	/*
	 * Translate ZFS ACE flags to NT ACE flags.
	 */
	aflags = 0;
	for (znaf = smbfs_zaf2naf; znaf->za_flag; znaf++)
		if (zacep->a_flags & znaf->za_flag)
			aflags |= znaf->na_flag;

	/*
	 * The access rights bits are OK as-is.
	 */
	rights = zacep->a_access_mask;

	/*
	 * Make sure we can get the SID.
	 * Note: allocates sid.
	 */
	error = smbfs_str2sid(mip->mi_dsid, &mip->mi_rid, &sid);
	if (error)
		return (error);

	/*
	 * Allocate the NT ACE and fill it in.
	 */
	alloc_size = sizeof (i_ntace_v2_t);
	if ((ntace = MALLOC(alloc_size)) == NULL) {
		ifree_sid(sid);
		return (ENOMEM);
	}
	bzero(ntace, alloc_size);

	ntace->ace_hdr.ace_type = zacep->a_type;
	ntace->ace_hdr.ace_flags = aflags;
	ntace->ace_hdr.ace_size = alloc_size;
	ntace->ace_v2.ace_rights = rights;
	ntace->ace_v2.ace_sid = sid;

	*ntacep = ntace;
	return (0);
}

/*
 * Convert a ZFS-style ACL to an internal SD.
 * Set owner/group too if selector indicates.
 * Always need to pass uid+gid, either the new
 * (when setting them) or existing, so that any
 * owner@ or group@ ACEs can be translated.
 *
 * This makes two passes over the ZFS ACL.  The first builds a
 * "batch" request for idmap with results in mapinfo, and the
 * second builds the NT SD using the idmap SID results.
 */
int
smbfs_acl_zfs2sd(
#ifdef	_KERNEL
	vsecattr_t *acl_info,
#else /* _KERNEL */
	acl_t *acl_info,
#endif /* _KERNEL */
	uid_t own_uid,
	gid_t own_gid,
	uint32_t selector,
	i_ntsd_t **sdp)
{
	struct mapinfo2sid *mip, *mip_acl, *mapinfo = NULL;
	int aclsz, error, i, mapcnt;
	int dacl_acecnt = 0;
	int sacl_acecnt = 0;
	int zacecnt = 0;
	ace_t *zacevec = NULL;
	ace_t *zacep;
	i_ntsd_t *sd = NULL;
	i_ntacl_t *acl = NULL;
	i_ntace_t **acep = NULL;
	idmap_get_handle_t *idmap_gh = NULL;
	idmap_stat	idms;

	/*
	 * First, get all the UID+GID to SID mappings.
	 * How many?  Also sanity checks.
	 */
	mapcnt = 0;
	if (selector & OWNER_SECURITY_INFORMATION) {
		if (own_uid == (uid_t)-1)
			return (EINVAL);
		mapcnt++;
	}
	if (selector & GROUP_SECURITY_INFORMATION) {
		if (own_gid == (gid_t)-1)
			return (EINVAL);
		mapcnt++;
	}
	if (selector & (DACL_SECURITY_INFORMATION |
	    SACL_SECURITY_INFORMATION)) {
		if (acl_info == NULL)
			return (EINVAL);
		if (own_uid == (uid_t)-1)
			return (EINVAL);
		if (own_gid == (gid_t)-1)
			return (EINVAL);
#ifdef	_KERNEL
		if ((acl_info->vsa_mask & VSA_ACE) == 0)
			return (EINVAL);
		zacecnt = acl_info->vsa_aclcnt;
		zacevec = acl_info->vsa_aclentp;
#else	/* _KERNEL */
		if (acl_info->acl_type != ACE_T ||
		    acl_info->acl_entry_size != sizeof (ace_t))
			return (EINVAL);
		zacecnt = acl_info->acl_cnt;
		zacevec = acl_info->acl_aclp;
#endif	/* _KERNEL */
		if (zacecnt == 0 || zacevec == NULL)
			return (EINVAL);
		mapcnt += zacecnt;
	}
	if (mapcnt == 0)
		return (EINVAL);
	mapinfo = MALLOC(mapcnt * sizeof (*mapinfo));
	if (mapinfo == NULL)
		return (ENOMEM);
	bzero(mapinfo, mapcnt * sizeof (*mapinfo));
	/* no more returns until errout */

	/*
	 * Get an imap "batch" request handle.
	 */
#ifdef	_KERNEL
	idmap_gh = kidmap_get_create(curproc->p_zone);
#else /* _KERNEL */
	idms = idmap_get_create(&idmap_gh);
	if (idms != IDMAP_SUCCESS) {
		error = ENOTACTIVE;
		goto errout;
	}
#endif /* _KERNEL */

	/*
	 * Build our request to the idmap deamon,
	 * getting SIDs for every Unix UID/GID.
	 * Also count DACL and SACL ACEs here.
	 */
	mip = mapinfo;
	if (selector & OWNER_SECURITY_INFORMATION) {
		error = mkrq_idmap_ux2sid(idmap_gh, mip,
		    own_uid, IDM_TYPE_USER);
		if (error)
			goto errout;
		mip++;
	}
	if (selector & GROUP_SECURITY_INFORMATION) {
		error = mkrq_idmap_ux2sid(idmap_gh, mip,
		    own_gid, IDM_TYPE_GROUP);
		if (error)
			goto errout;
		mip++;
	}
	if (selector & (DACL_SECURITY_INFORMATION |
	    SACL_SECURITY_INFORMATION)) {
		int rqtype;
		uid_t uid;

		zacep = zacevec;
		for (i = 0; i < zacecnt; i++) {

			switch (zacep->a_type) {
			case ACE_ACCESS_ALLOWED_ACE_TYPE:
			case ACE_ACCESS_DENIED_ACE_TYPE:
				dacl_acecnt++;
				break;
			case ACE_SYSTEM_AUDIT_ACE_TYPE:
			case ACE_SYSTEM_ALARM_ACE_TYPE:
				sacl_acecnt++;
				break;
			/* other types todo */
			}

			if (zacep->a_flags & ACE_EVERYONE) {
				rqtype = IDM_EVERYONE;
				uid = (uid_t)-1;
			} else if (zacep->a_flags & ACE_GROUP) {
				/* owning group (a_who = -1) */
				rqtype = IDM_TYPE_GROUP;
				uid = (uid_t)own_gid;
			} else if (zacep->a_flags & ACE_OWNER) {
				/* owning user (a_who = -1) */
				rqtype = IDM_TYPE_USER;
				uid = (uid_t)own_uid;
			} else if (zacep->a_flags & ACE_IDENTIFIER_GROUP) {
				/* regular group */
				rqtype = IDM_TYPE_GROUP;
				uid = zacep->a_who;
			} else {
				rqtype = IDM_TYPE_USER;
				uid = zacep->a_who;
			}

			error = mkrq_idmap_ux2sid(idmap_gh, mip, uid, rqtype);
			if (error)
				goto errout;
			zacep++;
			mip++;
		}
	}

	idms = I_getmappings(idmap_gh);
	if (idms != IDMAP_SUCCESS) {
		/* creative error choice */
		error = EIDRM;
		goto errout;
	}

	/*
	 * With any luck, we now have a Windows SID for
	 * every Unix UID or GID in the NFS/ZFS ACL.
	 * The remaining work is just format conversion,
	 * memory allocation, etc.
	 */
	if ((sd = MALLOC(sizeof (*sd))) == NULL) {
		error = ENOMEM;
		goto errout;
	}
	bzero(sd, sizeof (*sd));
	sd->sd_revision = NT_SD_REVISION;

	mip = mapinfo;
	if (selector & OWNER_SECURITY_INFORMATION) {
		error = smbfs_str2sid(mip->mi_dsid, &mip->mi_rid,
		    &sd->sd_owner);
		mip++;
	}
	if (selector & GROUP_SECURITY_INFORMATION) {
		error = smbfs_str2sid(mip->mi_dsid, &mip->mi_rid,
		    &sd->sd_group);
		mip++;
	}

	/*
	 * If setting both DACL and SACL, we will
	 * make two passes starting here in mapinfo.
	 */
	mip_acl = mip;

	if (selector & DACL_SECURITY_INFORMATION) {
		/*
		 * Caller wants to set the DACL.
		 */
		aclsz = I_ACL_SIZE(dacl_acecnt);
		if ((acl = MALLOC(aclsz)) == NULL) {
			error = ENOMEM;
			goto errout;
		}
		bzero(acl, aclsz);

		acl->acl_revision = NT_ACL_REVISION;
		acl->acl_acecount = (uint16_t)dacl_acecnt;
		acep = &acl->acl_acevec[0];

		/* 1st pass - scan for DACL ACE types. */
		mip = mip_acl;
		zacep = zacevec;
		for (i = 0; i < zacecnt; i++) {

			switch (zacep->a_type) {
			case ACE_ACCESS_ALLOWED_ACE_TYPE:
			case ACE_ACCESS_DENIED_ACE_TYPE:
				error = zace2ntace(acep, zacep, mip);
				if (error != 0)
					goto errout;
				acep++;
				break;

			case ACE_SYSTEM_AUDIT_ACE_TYPE:
			case ACE_SYSTEM_ALARM_ACE_TYPE:
				break;
			/* other types todo */
			}
			zacep++;
			mip++;
		}
		sd->sd_dacl = acl;
		acl = NULL;
		sd->sd_flags |= SD_DACL_PRESENT;
	}

	if (selector & SACL_SECURITY_INFORMATION) {
		/*
		 * Caller wants to set the SACL.
		 */
		aclsz = I_ACL_SIZE(sacl_acecnt);
		if ((acl = MALLOC(aclsz)) == NULL) {
			error = ENOMEM;
			goto errout;
		}
		bzero(acl, aclsz);

		acl->acl_revision = NT_ACL_REVISION;
		acl->acl_acecount = (uint16_t)sacl_acecnt;
		acep = &acl->acl_acevec[0];

		/* 2nd pass - scan for SACL ACE types. */
		mip = mip_acl;
		zacep = zacevec;
		for (i = 0; i < zacecnt; i++) {

			switch (zacep->a_type) {
			case ACE_ACCESS_ALLOWED_ACE_TYPE:
			case ACE_ACCESS_DENIED_ACE_TYPE:
				break;

			case ACE_SYSTEM_AUDIT_ACE_TYPE:
			case ACE_SYSTEM_ALARM_ACE_TYPE:
				error = zace2ntace(acep, zacep, mip);
				if (error != 0)
					goto errout;
				acep++;
				break;
			/* other types todo */
			}
			zacep++;
			mip++;
		}
		sd->sd_sacl = acl;
		acl = NULL;
		sd->sd_flags |= SD_SACL_PRESENT;
	}

	*sdp = sd;
	error = 0;

errout:
	if (error != 0) {
		if (acl != NULL)
			ifree_acl(acl);
		if (sd != NULL)
			smbfs_acl_free_sd(sd);
	}
	if (mapinfo != NULL)
		FREESZ(mapinfo, mapcnt * sizeof (*mapinfo));
#ifdef	_KERNEL
	if (idmap_gh != NULL)
		kidmap_get_destroy(idmap_gh);
#else /* _KERNEL */
	if (idmap_gh != NULL)
		idmap_get_destroy(idmap_gh);
#endif /* _KERNEL */

	return (error);
}
