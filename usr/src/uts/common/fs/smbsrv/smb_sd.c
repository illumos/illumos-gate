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

/*
 * This module provides Security Descriptor handling functions.
 */

#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/smb_idmap.h>

#define	AS_DWORD(X)		(*(uint32_t *)&(X))
#define	SELF_REL(P, M, T)	(T *)(((char *)(P)) + AS_DWORD((P)->M))

void smb_fmt_sid(char *buf, nt_sid_t *sid);

void
smb_sd_init(smb_sd_t *sd, uint8_t revision)
{
	bzero(sd, sizeof (smb_sd_t));
	sd->sd_hdr.sd_revision = revision;
}

/*
 * smb_sd_term
 *
 * Free non-NULL members of 'sd' which has to be in
 * absolute (pointer) form.
 */
void
smb_sd_term(smb_sd_t *sd)
{
	ASSERT(sd);
	ASSERT((sd->sd_hdr.sd_control & SE_SELF_RELATIVE) == 0);

	if (sd->sd_owner)
		MEM_FREE("libnt", sd->sd_owner);

	if (sd->sd_group)
		MEM_FREE("libnt", sd->sd_group);

	if (sd->sd_dacl)
		kmem_free(sd->sd_dacl, sd->sd_dacl->sl_size);

	if (sd->sd_sacl)
		kmem_free(sd->sd_sacl, sd->sd_sacl->sl_size);

	bzero(sd, sizeof (smb_sd_t));
}

/*
 * Hmmm. For all of these smb_sd_set_xxx() functions,
 * what do we do if the affected member is already set?
 * Should we free() it? For now, punt and risk a memory leak.
 */

void
smb_sd_set_owner(smb_sd_t *sd, nt_sid_t *owner, int defaulted)
{
	ASSERT((sd->sd_hdr.sd_control & SE_SELF_RELATIVE) == 0);

	sd->sd_owner = owner;
	if (defaulted)
		sd->sd_hdr.sd_control |= SE_OWNER_DEFAULTED;
	else
		sd->sd_hdr.sd_control &= ~SE_OWNER_DEFAULTED;
}

void
smb_sd_set_group(smb_sd_t *sd, nt_sid_t *group, int defaulted)
{
	ASSERT((sd->sd_hdr.sd_control & SE_SELF_RELATIVE) == 0);

	sd->sd_group = group;
	if (defaulted)
		sd->sd_hdr.sd_control |= SE_GROUP_DEFAULTED;
	else
		sd->sd_hdr.sd_control &= ~SE_GROUP_DEFAULTED;
}

void
smb_sd_set_dacl(smb_sd_t *sd, int present, smb_acl_t *acl, int flags)
{
	ASSERT((sd->sd_hdr.sd_control & SE_SELF_RELATIVE) == 0);

	sd->sd_dacl = acl;

	if (flags & ACL_DEFAULTED)
		sd->sd_hdr.sd_control |= SE_DACL_DEFAULTED;
	if (flags & ACL_AUTO_INHERIT)
		sd->sd_hdr.sd_control |= SE_DACL_AUTO_INHERITED;
	if (flags & ACL_PROTECTED)
		sd->sd_hdr.sd_control |= SE_DACL_PROTECTED;

	if (present)
		sd->sd_hdr.sd_control |= SE_DACL_PRESENT;
}

void
smb_sd_set_sacl(smb_sd_t *sd, int present, smb_acl_t *acl, int flags)
{
	ASSERT((sd->sd_hdr.sd_control & SE_SELF_RELATIVE) == 0);

	sd->sd_sacl = acl;

	if (flags & ACL_DEFAULTED)
		sd->sd_hdr.sd_control |= SE_SACL_DEFAULTED;
	if (flags & ACL_AUTO_INHERIT)
		sd->sd_hdr.sd_control |= SE_SACL_AUTO_INHERITED;
	if (flags & ACL_PROTECTED)
		sd->sd_hdr.sd_control |= SE_SACL_PROTECTED;

	if (present)
		sd->sd_hdr.sd_control |= SE_SACL_PRESENT;
}

nt_sid_t *
smb_sd_get_owner(void *sd, int *defaulted)
{
	smb_sdbuf_t *sr_sd;
	smb_sd_hdr_t *sd_hdr;
	nt_sid_t *sid;

	sd_hdr = (smb_sd_hdr_t *)sd;
	if (defaulted != NULL)
		*defaulted = (sd_hdr->sd_control & SE_OWNER_DEFAULTED) ? 1 : 0;

	if (sd_hdr->sd_control & SE_SELF_RELATIVE) {
		sr_sd = ((smb_sdbuf_t *)sd);
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		sid = SELF_REL(sr_sd, sd_owner_offs, nt_sid_t);
	}
	else
		sid = ((smb_sd_t *)sd)->sd_owner;

	return (sid);
}

nt_sid_t *
smb_sd_get_group(void *sd, int *defaulted)
{
	smb_sdbuf_t *sr_sd;
	smb_sd_hdr_t *sd_hdr;
	nt_sid_t *sid;

	sd_hdr = (smb_sd_hdr_t *)sd;
	if (defaulted != NULL)
		*defaulted = (sd_hdr->sd_control & SE_GROUP_DEFAULTED) ? 1 : 0;

	if (sd_hdr->sd_control & SE_SELF_RELATIVE) {
		sr_sd = ((smb_sdbuf_t *)sd);
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		sid = SELF_REL(sr_sd, sd_group_offs, nt_sid_t);
	}
	else
		sid = ((smb_sd_t *)sd)->sd_group;

	return (sid);
}

smb_acl_t *
smb_sd_get_dacl(void *sd, int *present, int *defaulted)
{
	smb_sdbuf_t *sr_sd;
	smb_sd_hdr_t *sd_hdr;
	smb_acl_t *acl = NULL;

	sd_hdr = (smb_sd_hdr_t *)sd;
	if (present != NULL)
		*present = (sd_hdr->sd_control & SE_DACL_PRESENT) ? 1 : 0;

	if (defaulted != NULL)
		*defaulted = (sd_hdr->sd_control & SE_DACL_DEFAULTED) ? 1 : 0;

	if (sd_hdr->sd_control & SE_SELF_RELATIVE) {
		sr_sd = ((smb_sdbuf_t *)sd);
		if (sr_sd->sd_dacl_offs) {
			/*LINTED E_BAD_PTR_CAST_ALIGN*/
			acl = SELF_REL(sr_sd, sd_dacl_offs, smb_acl_t);
		}
	}
	else
		acl = ((smb_sd_t *)sd)->sd_dacl;

	return (acl);
}

smb_acl_t *
smb_sd_get_sacl(void *sd, int *present, int *defaulted)
{
	smb_sdbuf_t *sr_sd;
	smb_sd_hdr_t *sd_hdr;
	smb_acl_t *acl = NULL;

	sd_hdr = (smb_sd_hdr_t *)sd;
	if (present != NULL)
		*present = (sd_hdr->sd_control & SE_SACL_PRESENT) ? 1 : 0;

	if (defaulted != NULL)
		*defaulted = (sd_hdr->sd_control & SE_SACL_DEFAULTED) ? 1 : 0;

	if (sd_hdr->sd_control & SE_SELF_RELATIVE) {
		sr_sd = ((smb_sdbuf_t *)sd);
		if (sr_sd->sd_sacl_offs) {
			/*LINTED E_BAD_PTR_CAST_ALIGN*/
			acl = SELF_REL(sr_sd, sd_sacl_offs, smb_acl_t);
		}
	}
	else
		acl = ((smb_sd_t *)sd)->sd_sacl;

	return (acl);
}

uint32_t
smb_sd_len(void *sd, uint32_t secinfo)
{
	uint32_t length = 0;
	nt_sid_t *sid;
	smb_acl_t *acl;
	int present;

	/* SD Header */
	length += sizeof (smb_sdbuf_t);

	/* Owner */
	if (secinfo & SMB_OWNER_SECINFO) {
		sid = smb_sd_get_owner(sd, NULL);
		if (sid)
			length += nt_sid_length(sid);
	}


	/* Group */
	if (secinfo & SMB_GROUP_SECINFO) {
		sid = smb_sd_get_group(sd, NULL);
		if (sid)
			length += nt_sid_length(sid);
	}


	/* DACL */
	if (secinfo & SMB_DACL_SECINFO) {
		acl = smb_sd_get_dacl(sd, &present, NULL);
		if (present && acl)
			length += smb_acl_len(acl);
	}

	/* SACL */
	if (secinfo & SMB_SACL_SECINFO) {
		acl = smb_sd_get_sacl(sd, &present, NULL);
		if (present && acl)
			length += smb_acl_len(acl);
	}

	return (length);
}

/*
 * smb_sd_get_secinfo
 *
 * Return the security information mask for the specified security
 * descriptor.
 */
uint32_t
smb_sd_get_secinfo(void *sd)
{
	uint32_t sec_info = 0;
	smb_acl_t *acl;
	int present;

	if (sd == 0)
		return (0);

	if (smb_sd_get_owner(sd, NULL) != 0)
		sec_info |= SMB_OWNER_SECINFO;

	if (smb_sd_get_group(sd, NULL) != 0)
		sec_info |= SMB_GROUP_SECINFO;

	acl = smb_sd_get_dacl(sd, &present, NULL);
	if (acl && present)
		sec_info |= SMB_DACL_SECINFO;

	acl = smb_sd_get_sacl(sd, &present, NULL);
	if (acl && present)
		sec_info |= SMB_SACL_SECINFO;

	return (sec_info);
}

/*
 * smb_sd_abs2selfrel
 *
 * This function takes an absolute SD (sd) and make a self relative
 * SD which will be returned in srel_sd.
 *
 * srel_sdsz contains the size of buffer which srel_sd points to.
 *
 * Do not add new error codes here without checking the impact on
 * all callers of this function.
 *
 * Returns NT status codes:
 *		NT_STATUS_SUCCESS
 *		NT_STATUS_BUFFER_TOO_SMALL
 *		NT_STATUS_INVALID_SECURITY_DESCR
 */
static uint32_t
smb_sd_abs2selfrel(
    smb_sd_t *sd,
    uint32_t secinfo,
    smb_sdbuf_t *srel_sd,
    uint32_t srel_sdsz)
{
	uint32_t avail_len = srel_sdsz;
	uint32_t length = 0;
	unsigned char *scan_beg = (unsigned char *) srel_sd;
	unsigned char *scan = scan_beg;
	unsigned char *scan_end;
	nt_sid_t *sid;
	smb_acl_t *acl;
	int present, defaulted;

	length = smb_sd_len(sd, secinfo);

	if (length == 0)
		return (NT_STATUS_INVALID_SECURITY_DESCR);

	if (avail_len < length)
		return (NT_STATUS_BUFFER_TOO_SMALL);

	bzero(srel_sd, length);
	scan_end = scan_beg + length;

	/* SD Header */
	length = sizeof (smb_sdbuf_t);
	srel_sd->sd_hdr.sd_revision = sd->sd_hdr.sd_revision;
	srel_sd->sd_hdr.sd_control  = SE_SELF_RELATIVE;
	scan += length;

	if (secinfo & SMB_OWNER_SECINFO) {
		/* Owner */
		sid = smb_sd_get_owner(sd, &defaulted);

		if (defaulted)
			srel_sd->sd_hdr.sd_control |= SE_OWNER_DEFAULTED;

		if (sid) {
			/*LINTED E_PTRDIFF_OVERFLOW*/
			length = nt_sid_copy((void*)scan, sid, scan_end - scan);
			if (length == 0)
				goto fail;
			/*LINTED E_PTRDIFF_OVERFLOW*/
			srel_sd->sd_owner_offs = scan - scan_beg;
			scan += length;
		}
	}

	if (secinfo & SMB_GROUP_SECINFO) {
		/* Group */
		sid = smb_sd_get_group(sd, &defaulted);

		if (defaulted)
			srel_sd->sd_hdr.sd_control |= SE_GROUP_DEFAULTED;

		if (sid) {
			/*LINTED E_PTRDIFF_OVERFLOW*/
			length = nt_sid_copy((void*)scan, sid, scan_end - scan);
			if (length == 0)
				goto fail;
			/*LINTED E_PTRDIFF_OVERFLOW*/
			srel_sd->sd_group_offs = scan - scan_beg;
			scan += length;
		}
	}


	if (secinfo & SMB_DACL_SECINFO) {
		/* Dacl */
		acl = smb_sd_get_dacl(sd, &present, &defaulted);

		srel_sd->sd_hdr.sd_control |=
		    (sd->sd_hdr.sd_control & SE_DACL_INHERITANCE_MASK);

		if (defaulted)
			srel_sd->sd_hdr.sd_control |= SE_DACL_DEFAULTED;

		if (present)
			srel_sd->sd_hdr.sd_control |= SE_DACL_PRESENT;

		if (present && acl) {
			/*LINTED E_PTRDIFF_OVERFLOW*/
			length = smb_acl_copy(scan_end - scan,
			    (void*) scan, acl);
			if (length == 0)
				goto fail;
			/*LINTED E_PTRDIFF_OVERFLOW*/
			srel_sd->sd_dacl_offs = scan - scan_beg;
			/*LINTED E_PTRDIFF_OVERFLOW*/
			acl = (smb_acl_t *)scan;
			acl->sl_size = (WORD)length;	/* set the size */
			scan += length;
		}
	}

	if (secinfo & SMB_SACL_SECINFO) {
		/* Sacl */
		acl = smb_sd_get_sacl(sd, &present, &defaulted);

		srel_sd->sd_hdr.sd_control |=
		    (sd->sd_hdr.sd_control & SE_SACL_INHERITANCE_MASK);

		if (defaulted)
			srel_sd->sd_hdr.sd_control |= SE_SACL_DEFAULTED;

		if (present)
			srel_sd->sd_hdr.sd_control |= SE_SACL_PRESENT;

		if (present && acl) {
			/*LINTED E_PTRDIFF_OVERFLOW*/
			length = smb_acl_copy(scan_end - scan,
			    (void*) scan, acl);
			if (length == 0)
				goto fail;
			/*LINTED E_PTRDIFF_OVERFLOW*/
			srel_sd->sd_sacl_offs = scan - scan_beg;
			/*LINTED E_PTRDIFF_OVERFLOW*/
			acl = (smb_acl_t *)scan;
			acl->sl_size = (WORD)length;	/* set the size */
			scan += length;
		}
	}

	return (NT_STATUS_SUCCESS);

fail:
	return (NT_STATUS_INVALID_SECURITY_DESCR);
}

/*
 * smb_sd_fromfs
 *
 * Makes an Windows style security descriptor in absolute form
 * based on the given filesystem security information.
 *
 * Should call smb_sd_term() for the returned sd to free allocated
 * members.
 */
static uint32_t
smb_sd_fromfs(smb_fssd_t *fs_sd, smb_sd_t *sd)
{
	uint32_t status = NT_STATUS_SUCCESS;
	smb_acl_t *acl = NULL;
	smb_acl_t *sorted_acl;
	nt_sid_t *sid;
	idmap_stat idm_stat;

	ASSERT(fs_sd);
	ASSERT(sd);

	smb_sd_init(sd, SECURITY_DESCRIPTOR_REVISION);

	/* Owner */
	if (fs_sd->sd_secinfo & SMB_OWNER_SECINFO) {
		idm_stat = smb_idmap_getsid(fs_sd->sd_uid,
		    SMB_IDMAP_USER, &sid);

		if (idm_stat != IDMAP_SUCCESS) {
			return (NT_STATUS_NONE_MAPPED);
		}

		smb_sd_set_owner(sd, sid, 0);
	}

	/* Group */
	if (fs_sd->sd_secinfo & SMB_GROUP_SECINFO) {
		idm_stat = smb_idmap_getsid(fs_sd->sd_gid,
		    SMB_IDMAP_GROUP, &sid);

		if (idm_stat != IDMAP_SUCCESS) {
			smb_sd_term(sd);
			return (NT_STATUS_NONE_MAPPED);
		}

		smb_sd_set_group(sd, sid, 0);
	}

	/* DACL */
	if (fs_sd->sd_secinfo & SMB_DACL_SECINFO) {
		if (fs_sd->sd_zdacl != NULL) {
			acl = smb_acl_from_zfs(fs_sd->sd_zdacl, fs_sd->sd_uid,
			    fs_sd->sd_gid);
			if (acl == NULL) {
				smb_sd_term(sd);
				return (NT_STATUS_INTERNAL_ERROR);
			}

			/*
			 * Need to sort the ACL before send it to Windows
			 * clients. Winodws GUI is sensitive about the order
			 * of ACEs.
			 */
			sorted_acl = smb_acl_sort(acl);
			if (sorted_acl && (sorted_acl != acl)) {
				kmem_free(acl, acl->sl_size);
				acl = sorted_acl;
			}
			smb_sd_set_dacl(sd, 1, acl, fs_sd->sd_zdacl->acl_flags);
		} else {
			smb_sd_set_dacl(sd, 0, NULL, 0);
		}
	}

	/* SACL */
	if (fs_sd->sd_secinfo & SMB_SACL_SECINFO) {
		if (fs_sd->sd_zsacl != NULL) {
			acl = smb_acl_from_zfs(fs_sd->sd_zsacl, fs_sd->sd_uid,
			    fs_sd->sd_gid);
			if (acl == NULL) {
				smb_sd_term(sd);
				return (NT_STATUS_INTERNAL_ERROR);
			}

			smb_sd_set_sacl(sd, 1, acl, fs_sd->sd_zsacl->acl_flags);
		} else {
			smb_sd_set_sacl(sd, 0, NULL, 0);
		}
	}

	return (status);
}

/*
 * smb_sd_tofs
 *
 * Creates a filesystem security structure based on the given
 * Windows security descriptor.
 */
uint32_t
smb_sd_tofs(smb_sdbuf_t *sr_sd, smb_fssd_t *fs_sd)
{
	nt_sid_t *sid;
	smb_acl_t *acl;
	uint32_t status = NT_STATUS_SUCCESS;
	uint16_t sd_control;
	idmap_stat idm_stat;
	int present;
	int idtype;
	int flags = 0;

	sd_control = sr_sd->sd_hdr.sd_control;

	/*
	 * ZFS only has one set of flags so for now only
	 * Windows DACL flags are taken into account.
	 */
	if (sd_control & SE_DACL_DEFAULTED)
		flags |= ACL_DEFAULTED;
	if (sd_control & SE_DACL_AUTO_INHERITED)
		flags |= ACL_AUTO_INHERIT;
	if (sd_control & SE_DACL_PROTECTED)
		flags |= ACL_PROTECTED;

	if (fs_sd->sd_flags & SMB_FSSD_FLAGS_DIR)
		flags |= ACL_IS_DIR;

	/* Owner */
	if (fs_sd->sd_secinfo & SMB_OWNER_SECINFO) {
		sid = smb_sd_get_owner(sr_sd, NULL);
		if (nt_sid_is_valid(sid) == 0) {
			return (NT_STATUS_INVALID_SID);
		}

		idtype = SMB_IDMAP_UNKNOWN;
		idm_stat = smb_idmap_getid(sid, &fs_sd->sd_uid, &idtype);
		if (idm_stat != IDMAP_SUCCESS) {
			return (NT_STATUS_NONE_MAPPED);
		}
	}

	/* Group */
	if (fs_sd->sd_secinfo & SMB_GROUP_SECINFO) {
		sid = smb_sd_get_group(sr_sd, NULL);
		if (nt_sid_is_valid(sid) == 0) {
			return (NT_STATUS_INVALID_SID);
		}

		idtype = SMB_IDMAP_UNKNOWN;
		idm_stat = smb_idmap_getid(sid, &fs_sd->sd_gid, &idtype);
		if (idm_stat != IDMAP_SUCCESS) {
			return (NT_STATUS_NONE_MAPPED);
		}
	}

	/* DACL */
	if (fs_sd->sd_secinfo & SMB_DACL_SECINFO) {
		acl = smb_sd_get_dacl(sr_sd, &present, NULL);
		if (present) {
			status = smb_acl_to_zfs(acl, flags,
			    SMB_DACL_SECINFO, &fs_sd->sd_zdacl);
			if (status != NT_STATUS_SUCCESS)
				return (status);
		}
		else
			return (NT_STATUS_INVALID_ACL);
	}

	/* SACL */
	if (fs_sd->sd_secinfo & SMB_SACL_SECINFO) {
		acl = smb_sd_get_sacl(sr_sd, &present, NULL);
		if (present) {
			status = smb_acl_to_zfs(acl, flags,
			    SMB_SACL_SECINFO, &fs_sd->sd_zsacl);
			if (status != NT_STATUS_SUCCESS) {
				return (status);
			}
		} else {
			return (NT_STATUS_INVALID_ACL);
		}
	}

	return (status);
}

/*
 * smb_sd_read
 *
 * Read uid, gid and ACL from filesystem. The returned ACL from read
 * routine is always in ZFS format. Convert the ZFS acl to a Win acl
 * and return the Win SD in relative form.
 *
 * NOTE: upon successful return caller MUST free the memory allocated
 * for the returned SD by calling kmem_free(). The length of the allocated
 * buffer is returned in 'buflen'.
 */
uint32_t
smb_sd_read(smb_request_t *sr, smb_sdbuf_t **sr_sd,
    uint32_t secinfo, uint32_t *buflen)
{
	smb_sd_t sd;
	smb_fssd_t fs_sd;
	smb_error_t smb_err;
	smb_sdbuf_t *sdbuf;
	smb_node_t *node;
	uint32_t sdlen;
	uint32_t status = NT_STATUS_SUCCESS;
	uint32_t sd_flags;
	int error;

	*sr_sd = NULL;

	node = sr->fid_ofile->f_node;
	sd_flags = (node->vp->v_type == VDIR) ? SMB_FSSD_FLAGS_DIR : 0;
	smb_fsop_sdinit(&fs_sd, secinfo, sd_flags);

	error = smb_fsop_sdread(sr, sr->user_cr, node, &fs_sd);
	if (error) {
		smb_errmap_unix2smb(error, &smb_err);
		return (smb_err.status);
	}

	status = smb_sd_fromfs(&fs_sd, &sd);
	smb_fsop_sdterm(&fs_sd);

	if (status != NT_STATUS_SUCCESS)
		return (status);

	sdlen = smb_sd_len(&sd, secinfo);

	if (*buflen < sdlen) {
		/* return the required size */
		*buflen = sdlen;
		smb_sd_term(&sd);
		return (NT_STATUS_BUFFER_TOO_SMALL);
	}

	sdbuf = kmem_alloc(sdlen, KM_SLEEP);
	status = smb_sd_abs2selfrel(&sd, secinfo, sdbuf, sdlen);
	smb_sd_term(&sd);

	if (status == NT_STATUS_SUCCESS) {
		*sr_sd = sdbuf;
		*buflen = sdlen;
	}
	else
		kmem_free(sdbuf, sdlen);

	return (status);
}

/*
 * smb_sd_write
 *
 * Takes a Win SD in self-relative form, convert it to
 * ZFS format and write it to filesystem. The write routine
 * converts ZFS acl to Posix acl if required.
 */
uint32_t
smb_sd_write(smb_request_t *sr, smb_sdbuf_t *sr_sd, uint32_t secinfo)
{
	smb_node_t *node;
	smb_fssd_t fs_sd;
	smb_error_t smb_err;
	uint32_t status;
	uint32_t sd_flags;
	int error;

	node = sr->fid_ofile->f_node;
	sd_flags = (node->vp->v_type == VDIR) ? SMB_FSSD_FLAGS_DIR : 0;
	smb_fsop_sdinit(&fs_sd, secinfo, sd_flags);

	status = smb_sd_tofs(sr_sd, &fs_sd);
	if (status != NT_STATUS_SUCCESS) {
		smb_fsop_sdterm(&fs_sd);
		return (status);
	}

	error = smb_fsop_sdwrite(sr, sr->user_cr, node, &fs_sd, 0);
	smb_fsop_sdterm(&fs_sd);

	if (error) {
		smb_errmap_unix2smb(error, &smb_err);
		return (smb_err.status);
	}

	return (NT_STATUS_SUCCESS);
}

/*
 * smb_fmt_sid
 *
 * Make an string SID and copy the result into the specified buffer.
 */
void
smb_fmt_sid(char *buf, nt_sid_t *sid)
{
	char *sid_str;

	sid_str = nt_sid_format(sid);
	if (sid_str) {
		(void) strcpy(buf, sid_str);
		MEM_FREE("smb", sid_str);
	} else {
		(void) strcpy(buf, "<invalid SID>");
	}
}

/*
 * smb_sd_log
 *
 * log the given Windows style security descriptor information
 * in system log. This is for debugging purposes.
 */
void
smb_sd_log(void *sd)
{
	smb_acl_t *acl;
	smb_ace_t *ace;
	nt_sid_t *sid;
	int present, defaulted;
	char entry[128];
	char *inherit;
	char *type;
	int ix_dacl;

	sid = smb_sd_get_owner(sd, &defaulted);
	if (sid)
		smb_fmt_sid(entry, sid);
	else
		(void) strcpy(entry, "NULL");

	cmn_err(CE_NOTE, "  Owner: %s", entry);

	sid = smb_sd_get_group(sd, &defaulted);
	if (sid)
		smb_fmt_sid(entry, sid);
	else
		(void) strcpy(entry, "NULL");

	cmn_err(CE_NOTE, "  Primary Group: %s", entry);

	acl = smb_sd_get_dacl(sd, &present, &defaulted);

	if (!present || !acl) {
		cmn_err(CE_NOTE, "  No DACL");
		return;
	}

	for (ix_dacl = 0;
	    ace = smb_ace_get(acl, ix_dacl);
	    ix_dacl++) {
		/*
		 * Make sure the ACE type is something we grok.
		 * All ACE, now and in the future, have a valid
		 * header. Can't access fields passed the Header
		 * until we're sure it's right.
		 */
		switch (ace->se_header.se_type) {
		case ACCESS_ALLOWED_ACE_TYPE:
			type = "(Allow)";
			break;
		case ACCESS_DENIED_ACE_TYPE:
			type = "(Deny)";
			break;

		case SYSTEM_AUDIT_ACE_TYPE:
		default:
			/* Ignore unrecognized/misplaced ACE */
			continue;
		}

		smb_fmt_sid(entry, &ace->se_sid);

		switch (ace->se_header.se_flags & INHERIT_MASK_ACE) {
		case OBJECT_INHERIT_ACE:
			inherit = "(OI)";
			break;
		case CONTAINER_INHERIT_ACE:
			inherit = "(CI)";
			break;
		case INHERIT_ONLY_ACE:
			inherit = "(IO)";
			break;
		case NO_PROPOGATE_INHERIT_ACE:
			inherit = "(NP)";
			break;
		default:
			inherit = "";
		}

		(void) snprintf(entry + strlen(entry), sizeof (entry),
		    ":%s 0x%X %s", inherit, ace->se_mask, type);

		cmn_err(CE_NOTE, "  %s", entry);
	}

	cmn_err(CE_NOTE, "  %d ACE(s)", ix_dacl);
}
