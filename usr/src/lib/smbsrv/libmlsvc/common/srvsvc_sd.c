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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * This is a helper file to get/set Windows SD. This is used by
 * SRVSVC service.
 */
#include <strings.h>
#include <libzfs.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/ndl/srvsvc.ndl>

/* Size of offset members in mslm_security_descriptor structure */
#define	SRVSVC_SD_OFFSET_SZ	16

#define	SRVSVC_ACE_OFFSET	8
#define	SRVSVC_SID_OFFSET	8

uint32_t srvsvc_sd_set_relative(smb_sd_t *, uint8_t *);

static uint32_t srvsvc_sd_get_autohome(const smb_share_t *, smb_sd_t *);
static uint32_t srvsvc_sd_status_to_error(uint32_t);
static uint32_t srvsvc_sd_set_absolute(uint8_t *, smb_sd_t *);

/*
 * This method computes ACL on share path from a share name.
 * Return 0 upon success, -1 upon failure.
 */
static int
srvsvc_shareacl_getpath(smb_share_t *si, char *shr_acl_path)
{
	char dataset[MAXPATHLEN];
	char mp[ZFS_MAXPROPLEN];
	libzfs_handle_t *libhd;
	zfs_handle_t *zfshd;
	int ret = 0;

	if ((libhd = libzfs_init()) == NULL)
		return (-1);

	ret = smb_getdataset(libhd, si->shr_path, dataset, MAXPATHLEN);
	if (ret != 0) {
		libzfs_fini(libhd);
		return (ret);
	}


	if ((zfshd = zfs_open(libhd, dataset, ZFS_TYPE_DATASET)) == NULL) {
		libzfs_fini(libhd);
		return (-1);
	}

	if (zfs_prop_get(zfshd, ZFS_PROP_MOUNTPOINT, mp, sizeof (mp), NULL,
	    NULL, 0, B_FALSE) != 0) {
		zfs_close(zfshd);
		libzfs_fini(libhd);
		return (-1);
	}

	zfs_close(zfshd);
	libzfs_fini(libhd);

	(void) snprintf(shr_acl_path, MAXPATHLEN, "%s/.zfs/shares/%s",
	    mp, si->shr_name);

	return (ret);
}

/*
 * This method sets Security Descriptor on a share path.
 *
 * Returns:
 *	ERROR_SUCCESS
 *	ERROR_NOT_ENOUGH_MEMORY
 *	ERROR_INVALID_ACL
 *	ERROR_INVALID_SID
 *	ERROR_INVALID_SECURITY_DESCR
 *	ERROR_NONE_MAPPED
 *	ERROR_INTERNAL_ERROR
 *	ERROR_PATH_NOT_FOUND
 */
uint32_t
srvsvc_sd_set(smb_share_t *si, uint8_t *sdbuf)
{
	smb_sd_t sd;
	uint32_t status = ERROR_SUCCESS;
	char path[MAXPATHLEN];
	int ret = 0;

	ret = srvsvc_shareacl_getpath(si, path);
	if (ret != 0)
		return (ERROR_PATH_NOT_FOUND);

	smb_sd_init(&sd, 0);
	status = srvsvc_sd_set_absolute(sdbuf, &sd);
	if (status != ERROR_SUCCESS) {
		smb_sd_term(&sd);
		return (status);
	}

	status = smb_sd_write(path, &sd, SMB_DACL_SECINFO);
	status = srvsvc_sd_status_to_error(status);
	smb_sd_term(&sd);

	return (status);
}

/*
 * This method returns a Security Descriptor of a share path in self relative
 * format. Call to this function with NULL buffer, returns the size of the
 * security descriptor, which can be used to allocate buffer.
 *
 * Returns:
 *	ERROR_SUCCESS
 *	ERROR_NOT_ENOUGH_MEMORY
 *	ERROR_INVALID_ACL
 *	ERROR_INVALID_SID
 *	ERROR_INVALID_SECURITY_DESCR
 *	ERROR_INVALID_PARAMETER
 *	ERROR_NONE_MAPPED
 *	ERROR_INTERNAL_ERROR
 *	ERROR_PATH_NOT_FOUND
 */
uint32_t
srvsvc_sd_get(smb_share_t *si, uint8_t *sdbuf, uint32_t *size)
{
	smb_sd_t sd;
	uint32_t status = ERROR_SUCCESS;
	char path[MAXPATHLEN];
	int ret = 0;

	if (sdbuf == NULL && size == NULL)
		return (ERROR_INVALID_PARAMETER);

	bzero(&sd, sizeof (smb_sd_t));

	if (si->shr_flags & SMB_SHRF_AUTOHOME) {
		status = srvsvc_sd_get_autohome(si, &sd);
	} else {
		ret = srvsvc_shareacl_getpath(si, path);
		if (ret != 0)
			return (ERROR_PATH_NOT_FOUND);

		status = smb_sd_read(path, &sd, SMB_ALL_SECINFO);
		status = srvsvc_sd_status_to_error(status);
	}

	if (status != ERROR_SUCCESS) {
		smb_sd_term(&sd);
		return (status);
	}

	if (sdbuf == NULL) {
		*size = smb_sd_len(&sd, SMB_ALL_SECINFO);
		smb_sd_term(&sd);
		return (status);
	}

	status = srvsvc_sd_set_relative(&sd, sdbuf);

	smb_sd_term(&sd);
	return (status);
}

static uint32_t
srvsvc_sd_get_autohome(const smb_share_t *si, smb_sd_t *sd)
{
	smb_fssd_t	fs_sd;
	acl_t		*acl;
	uint32_t	status;

	if (acl_fromtext("owner@:rwxpdDaARWcCos::allow", &acl) != 0)
		return (ERROR_NOT_ENOUGH_MEMORY);

	smb_fssd_init(&fs_sd, SMB_ALL_SECINFO, SMB_FSSD_FLAGS_DIR);
	fs_sd.sd_uid = si->shr_uid;
	fs_sd.sd_gid = si->shr_gid;
	fs_sd.sd_zdacl = acl;
	fs_sd.sd_zsacl = NULL;

	status = smb_sd_fromfs(&fs_sd, sd);
	status = srvsvc_sd_status_to_error(status);
	smb_fssd_term(&fs_sd);
	return (status);
}

/*
 * This method converts an ACE from absolute (pointer) to
 * self relative (flat buffer) format.
 *
 * Returns Win32 error codes.
 */
static uint32_t
srvsvc_ace_set_relative(mslm_ace_t *m_ace, struct mslm_sid *m_sid,
    smb_ace_t *ace)
{
	if ((m_ace == NULL) || (ace == NULL))
		return (ERROR_INVALID_PARAMETER);

	bcopy(&ace->se_hdr, &m_ace->header, sizeof (mslm_ace_hdr_t));
	m_ace->mask = ace->se_mask;

	if ((ace->se_sid == NULL) || (m_sid == NULL))
		return (ERROR_INVALID_PARAMETER);
	bcopy(ace->se_sid, m_sid, smb_sid_len(ace->se_sid));

	return (ERROR_SUCCESS);
}

/*
 * This method converts an ACL from absolute (pointer) to
 * self relative (flat buffer) format.
 *
 * Returns an initialized mslm_acl structure on success.
 * Returns NULL on failure.
 */
static struct mslm_acl *
srvsvc_acl_set_relative(uint8_t *sdbuf, smb_acl_t *acl)
{
	struct mslm_acl *m_acl;

	if (sdbuf == NULL)
		return (NULL);

	/*LINTED E_BAD_PTR_CAST_ALIGN*/
	m_acl = (struct mslm_acl *)sdbuf;
	m_acl->revision = acl->sl_revision;
	m_acl->sbz1 = 0;
	m_acl->size = acl->sl_bsize;
	m_acl->sbz2 = 0;
	m_acl->ace_count = acl->sl_acecnt;

	return (m_acl);
}

/*
 * This method converts Security Descriptor from absolute (pointer) to
 * self relative (flat buffer) format.
 *
 * Returns Win32 error codes.
 */
uint32_t
srvsvc_sd_set_relative(smb_sd_t *sd, uint8_t *sdbuf)
{
	mslm_security_descriptor_t *msd;
	int offset, len, i;
	smb_ace_t *ace;
	mslm_ace_t *m_ace;
	struct mslm_sid *m_sid;
	uint16_t ace_cnt;
	uint32_t status = ERROR_SUCCESS;

	/*LINTED E_BAD_PTR_CAST_ALIGN*/
	msd = (mslm_security_descriptor_t *)sdbuf;
	if (msd == NULL)
		return (ERROR_INVALID_SECURITY_DESCR);

	msd->revision = sd->sd_revision;
	msd->sbz1 = 0;
	msd->control = sd->sd_control | SE_SELF_RELATIVE;

	offset = sizeof (mslm_security_descriptor_t) - SRVSVC_SD_OFFSET_SZ;
	msd->offset_owner = msd->offset_group = 0;
	msd->offset_sacl = msd->offset_dacl = 0;

	if (sd->sd_owner != NULL) {
		msd->offset_owner = offset;

		if (sd->sd_owner == NULL)
			return (ERROR_NOT_ENOUGH_MEMORY);

		len = smb_sid_len(sd->sd_owner);
		bcopy(sd->sd_owner, &sdbuf[offset], len);
		offset += len;
	}

	if (sd->sd_group != NULL) {
		msd->offset_group = offset;

		if (sd->sd_group == NULL)
			return (ERROR_NOT_ENOUGH_MEMORY);

		len = smb_sid_len(sd->sd_group);
		bcopy(sd->sd_group, &sdbuf[offset], len);
		offset += len;
	}

	if (sd->sd_sacl != NULL) {
		msd->offset_sacl = offset;
		msd->sacl = srvsvc_acl_set_relative(&sdbuf[offset],
		    sd->sd_sacl);
		if (msd->sacl == NULL)
			return (ERROR_INVALID_PARAMETER);

		ace = sd->sd_sacl->sl_aces;
		ace_cnt = msd->sacl->ace_count;
		offset += SRVSVC_ACE_OFFSET;

		for (i = 0; i < ace_cnt; i++, ace++) {
			/*LINTED E_BAD_PTR_CAST_ALIGN*/
			m_ace = (mslm_ace_t *)&sdbuf[offset];
			offset += SRVSVC_SID_OFFSET;
			/*LINTED E_BAD_PTR_CAST_ALIGN*/
			m_sid = (struct mslm_sid *)&sdbuf[offset];

			status = srvsvc_ace_set_relative(m_ace, m_sid, ace);
			if (status != ERROR_SUCCESS)
				return (status);
			offset += smb_sid_len(ace->se_sid);
		}
	}

	if (sd->sd_dacl != NULL) {
		msd->offset_dacl = offset;
		msd->dacl = srvsvc_acl_set_relative(&sdbuf[offset],
		    sd->sd_dacl);
		if (msd->dacl == NULL)
			return (ERROR_INVALID_PARAMETER);

		ace = sd->sd_dacl->sl_aces;
		ace_cnt = msd->dacl->ace_count;
		offset += SRVSVC_ACE_OFFSET;

		for (i = 0; i < ace_cnt; i++, ace++) {
			/*LINTED E_BAD_PTR_CAST_ALIGN*/
			m_ace = (mslm_ace_t *)&sdbuf[offset];
			offset += SRVSVC_SID_OFFSET;
			/*LINTED E_BAD_PTR_CAST_ALIGN*/
			m_sid = (struct mslm_sid *)&sdbuf[offset];

			status = srvsvc_ace_set_relative(m_ace, m_sid, ace);
			if (status != ERROR_SUCCESS)
				return (status);
			offset += smb_sid_len(ace->se_sid);
		}
	}

	return (status);
}

/*
 * This method converts an ACE from self relative (flat buffer) to
 * absolute (pointer) format.
 *
 * Returns Win32 error codes.
 */
static uint32_t
srvsvc_ace_set_absolute(mslm_ace_t *m_ace, struct mslm_sid *m_sid,
    smb_ace_t *ace)
{
	int sid_size = 0;
	if ((m_ace == NULL) || (ace == NULL) || (m_sid == NULL))
		return (ERROR_INVALID_PARAMETER);

	bzero(ace, sizeof (smb_ace_t));
	bcopy(&m_ace->header, &ace->se_hdr, sizeof (mslm_ace_hdr_t));
	ace->se_mask = m_ace->mask;

	sid_size = smb_sid_len((smb_sid_t *)m_sid);
	if ((ace->se_sid = malloc(sid_size)) == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);
	bcopy(m_sid, ace->se_sid, sid_size);

	return (ERROR_SUCCESS);
}

/*
 * This method converts an ACL from self relative (flat buffer) to
 * absolute (pointer) format.
 *
 * Returns an initialized smb_acl_t structure on success.
 * Returns NULL on failure.
 */
static smb_acl_t *
srvsvc_acl_set_absolute(uint8_t *sdbuf, int *offset)
{
	uint8_t rev;
	uint16_t sz, ace_cnt;
	smb_acl_t *acl;

	bcopy(&sdbuf[*offset], &rev, sizeof (uint8_t));
	*offset += 2; /* Pad for Sbz1 */
	bcopy(&sdbuf[*offset], &sz, sizeof (uint16_t));
	*offset += 2;
	bcopy(&sdbuf[*offset], &ace_cnt, sizeof (uint16_t));
	*offset += 4; /* Pad for Sbz2 */

	acl = smb_acl_alloc(rev, sz, ace_cnt);

	return (acl);
}

/*
 * This method converts Security Descriptor from self relative (flat buffer) to
 * absolute (pointer) format.
 *
 * Returns Win32 error codes.
 */
static uint32_t
srvsvc_sd_set_absolute(uint8_t *sdbuf, smb_sd_t *sd)
{
	mslm_security_descriptor_t *msd;
	mslm_ace_t *m_ace;
	struct mslm_sid *m_sid;
	smb_ace_t *ace;
	uint16_t ace_cnt;
	int offset, i, sid_size;
	uint32_t status = ERROR_SUCCESS;

	if (sdbuf == NULL)
		return (ERROR_INVALID_SECURITY_DESCR);

	/*LINTED E_BAD_PTR_CAST_ALIGN*/
	msd = (mslm_security_descriptor_t *)sdbuf;

	sd->sd_revision = msd->revision;
	sd->sd_control = msd->control & (~SE_SELF_RELATIVE);

	if (msd->offset_owner != 0) {
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		m_sid = (struct mslm_sid *)&sdbuf[msd->offset_owner];
		sid_size = smb_sid_len((smb_sid_t *)m_sid);

		if ((sd->sd_owner = malloc(sid_size)) == NULL)
			return (ERROR_NOT_ENOUGH_MEMORY);
		bcopy(m_sid, sd->sd_owner, sid_size);
	}

	if (msd->offset_group != 0) {
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		m_sid = (struct mslm_sid *)&sdbuf[msd->offset_group];
		sid_size = smb_sid_len((smb_sid_t *)m_sid);

		if ((sd->sd_group = malloc(sid_size)) == NULL)
			return (ERROR_NOT_ENOUGH_MEMORY);
		bcopy(m_sid, sd->sd_group, sid_size);
	}

	if (msd->offset_sacl != 0) {
		offset = msd->offset_sacl;
		sd->sd_sacl = srvsvc_acl_set_absolute(sdbuf, &offset);
		if (sd->sd_sacl == NULL)
			return (ERROR_NOT_ENOUGH_MEMORY);

		ace = sd->sd_sacl->sl_aces;
		ace_cnt = sd->sd_sacl->sl_acecnt;

		for (i = 0; i < ace_cnt; i++, ace++) {
			/*LINTED E_BAD_PTR_CAST_ALIGN*/
			m_ace = (mslm_ace_t *)&sdbuf[offset];
			offset += SRVSVC_SID_OFFSET;
			/*LINTED E_BAD_PTR_CAST_ALIGN*/
			m_sid = (struct mslm_sid *)&sdbuf[offset];

			status = srvsvc_ace_set_absolute(m_ace, m_sid, ace);
			if (status != ERROR_SUCCESS)
				return (status);
			offset += smb_sid_len(ace->se_sid);
		}
	}

	if (msd->offset_dacl != 0) {
		offset = msd->offset_dacl;
		sd->sd_dacl = srvsvc_acl_set_absolute(sdbuf, &offset);
		if (sd->sd_dacl == NULL)
			return (ERROR_NOT_ENOUGH_MEMORY);

		ace = sd->sd_dacl->sl_aces;
		ace_cnt = sd->sd_dacl->sl_acecnt;

		for (i = 0; i < ace_cnt; i++, ace++) {
			/*LINTED E_BAD_PTR_CAST_ALIGN*/
			m_ace = (mslm_ace_t *)&sdbuf[offset];
			offset += SRVSVC_SID_OFFSET;
			/*LINTED E_BAD_PTR_CAST_ALIGN*/
			m_sid = (struct mslm_sid *)&sdbuf[offset];

			status = srvsvc_ace_set_absolute(m_ace, m_sid, ace);
			if (status != ERROR_SUCCESS)
				return (status);
			offset += smb_sid_len(ace->se_sid);
		}
	}

	return (status);
}

/*
 * This method maps NT status codes into Win 32 error codes.
 * This method operates on status codes that are related
 * to processing of Security Descriptor.
 */
static uint32_t
srvsvc_sd_status_to_error(uint32_t status)
{
	int i;
	static struct {
		uint32_t	nt_status;
		uint32_t	err_code;
	} errmap[] = {
		{ NT_STATUS_SUCCESS,		ERROR_SUCCESS },
		{ NT_STATUS_INVALID_ACL,	ERROR_INVALID_ACL },
		{ NT_STATUS_INVALID_SID,	ERROR_INVALID_SID },
		{ NT_STATUS_NONE_MAPPED,	ERROR_NONE_MAPPED }
	};

	for (i = 0; i < (sizeof (errmap) / sizeof (errmap[0])); ++i) {
		if (status == errmap[i].nt_status)
			return (errmap[i].err_code);
	}

	return (ERROR_INTERNAL_ERROR);
}
