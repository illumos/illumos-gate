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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioccom.h>
#include <sys/param.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <smbsrv/smb_xdr.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/smb_ioctl.h>
#include <smbsrv/smb_ioctl.h>
#include <smbsrv/libsmb.h>

#define	SMBDRV_DEVICE_PATH		"/devices/pseudo/smbsrv@0:smbsrv"
#define	SMB_IOC_DATA_SIZE		(256 * 1024)

static int smb_kmod_ioctl(int, smb_ioc_header_t *, uint32_t);


int	smbdrv_fd = -1;

int
smb_kmod_bind(void)
{
	if (smbdrv_fd != -1)
		(void) close(smbdrv_fd);

	if ((smbdrv_fd = open(SMBDRV_DEVICE_PATH, 0)) < 0) {
		smbdrv_fd = -1;
		return (errno);
	}

	return (0);
}

int
smb_kmod_setcfg(smb_kmod_cfg_t *cfg)
{
	smb_ioc_cfg_t ioc;

	ioc.maxworkers = cfg->skc_maxworkers;
	ioc.maxconnections = cfg->skc_maxconnections;
	ioc.keepalive = cfg->skc_keepalive;
	ioc.restrict_anon = cfg->skc_restrict_anon;
	ioc.signing_enable = cfg->skc_signing_enable;
	ioc.signing_required = cfg->skc_signing_required;
	ioc.oplock_enable = cfg->skc_oplock_enable;
	ioc.sync_enable = cfg->skc_sync_enable;
	ioc.secmode = cfg->skc_secmode;
	ioc.ipv6_enable = cfg->skc_ipv6_enable;

	(void) strlcpy(ioc.nbdomain, cfg->skc_nbdomain, sizeof (ioc.nbdomain));
	(void) strlcpy(ioc.fqdn, cfg->skc_fqdn, sizeof (ioc.fqdn));
	(void) strlcpy(ioc.hostname, cfg->skc_hostname, sizeof (ioc.hostname));
	(void) strlcpy(ioc.system_comment, cfg->skc_system_comment,
	    sizeof (ioc.system_comment));

	return (smb_kmod_ioctl(SMB_IOC_CONFIG, &ioc.hdr, sizeof (ioc)));
}

int
smb_kmod_setgmtoff(int32_t gmtoff)
{
	smb_ioc_gmt_t ioc;

	ioc.offset = gmtoff;
	return (smb_kmod_ioctl(SMB_IOC_GMTOFF, &ioc.hdr,
	    sizeof (ioc)));
}

int
smb_kmod_start(int opipe, int lmshr, int udoor)
{
	smb_ioc_start_t ioc;

	ioc.opipe = opipe;
	ioc.lmshrd = lmshr;
	ioc.udoor = udoor;
	return (smb_kmod_ioctl(SMB_IOC_START, &ioc.hdr, sizeof (ioc)));
}

int
smb_kmod_tcplisten(int error)
{
	smb_ioc_listen_t ioc;

	ioc.error = error;
	return (smb_kmod_ioctl(SMB_IOC_TCP_LISTEN, &ioc.hdr, sizeof (ioc)));
}

int
smb_kmod_nbtlisten(int error)
{
	smb_ioc_listen_t ioc;

	ioc.error = error;
	return (smb_kmod_ioctl(SMB_IOC_NBT_LISTEN, &ioc.hdr, sizeof (ioc)));
}

int
smb_kmod_tcpreceive(void)
{
	smb_ioc_header_t ioc;

	return (smb_kmod_ioctl(SMB_IOC_TCP_RECEIVE, &ioc, sizeof (ioc)));
}

int
smb_kmod_nbtreceive(void)
{
	smb_ioc_header_t ioc;

	return (smb_kmod_ioctl(SMB_IOC_NBT_RECEIVE, &ioc, sizeof (ioc)));
}

int
smb_kmod_share(char *path, char *name)
{
	smb_ioc_share_t *ioc;
	int rc = ENOMEM;

	ioc = malloc(sizeof (smb_ioc_share_t));

	if (ioc != NULL) {
		(void) strlcpy(ioc->path, path, sizeof (ioc->path));
		(void) strlcpy(ioc->name, name, sizeof (ioc->name));
		rc = smb_kmod_ioctl(SMB_IOC_SHARE, &ioc->hdr,
		    sizeof (smb_ioc_share_t));
		free(ioc);
	}
	return (rc);
}

int
smb_kmod_unshare(char *path, char *name)
{
	smb_ioc_share_t *ioc;
	int rc = ENOMEM;

	ioc = malloc(sizeof (smb_ioc_share_t));

	if (ioc != NULL) {
		(void) strlcpy(ioc->path, path, sizeof (ioc->path));
		(void) strlcpy(ioc->name, name, sizeof (ioc->name));
		rc = smb_kmod_ioctl(SMB_IOC_UNSHARE, &ioc->hdr,
		    sizeof (smb_ioc_share_t));
		free(ioc);
	}
	return (rc);
}

int
smb_kmod_get_usernum(uint32_t *punum)
{
	smb_ioc_usernum_t ioc;
	int rc;

	ioc.num = 0;
	rc = smb_kmod_ioctl(SMB_IOC_USER_NUMBER, &ioc.hdr, sizeof (ioc));
	if (rc == 0)
		*punum = ioc.num;

	return (rc);
}

int
smb_kmod_get_userlist(smb_ulist_t *ulist)
{
	smb_opipe_context_t	*ctx;
	smb_ioc_ulist_t		*ioc;
	uint32_t		ioc_len;
	uint8_t			*data;
	uint32_t		data_len;
	uint32_t		unum;
	int			rc;

	smb_ulist_cleanup(ulist);

	rc = smb_kmod_get_usernum(&unum);
	if ((rc != 0) || (unum == 0))
		return (rc);

	ioc_len = sizeof (smb_ioc_ulist_t) + SMB_IOC_DATA_SIZE;
	ioc = malloc(ioc_len);
	if (ioc == NULL)
		return (ENOMEM);

	ctx = malloc(sizeof (smb_opipe_context_t) * unum);
	if (ctx == NULL) {
		free(ioc);
		return (ENOMEM);
	}
	ulist->ul_users = ctx;

	while (ulist->ul_cnt < unum) {
		ioc->cookie = ulist->ul_cnt;
		ioc->data_len = SMB_IOC_DATA_SIZE;
		rc = smb_kmod_ioctl(SMB_IOC_USER_LIST, &ioc->hdr,
		    ioc_len);
		if (rc != 0)
			break;

		if ((ulist->ul_cnt + ioc->num) > unum)
			ioc->num = unum - ulist->ul_cnt;

		if (ioc->num == 0)
			break;

		data = ioc->data;
		data_len = ioc->data_len;
		while (ioc->num > 0) {
			uint_t	bd = 0;

			rc = smb_opipe_context_decode(ctx, data, data_len, &bd);
			if (rc != 0)
				break;

			ctx++;
			ioc->num--;
			ulist->ul_cnt++;
			data += bd;
			data_len -= bd;
		}
	}

	if (rc != 0)
		smb_ulist_cleanup(ulist);

	free(ioc);
	return (rc);
}

void
smb_kmod_unbind(void)
{
	if (smbdrv_fd != -1) {
		(void) close(smbdrv_fd);
		smbdrv_fd = -1;
	}
}

static int
smb_kmod_ioctl(int cmd, smb_ioc_header_t *ioc, uint32_t len)
{
	int rc = EINVAL;

	ioc->version = SMB_IOC_VERSION;
	ioc->cmd = cmd;
	ioc->len = len;
	ioc->crc = 0;
	ioc->crc = smb_crc_gen((uint8_t *)ioc, sizeof (smb_ioc_header_t));

	if (smbdrv_fd != -1) {
		if (ioctl(smbdrv_fd, cmd, ioc) < 0)
			rc = errno;
		else
			rc = 0;
	}
	return (rc);
}
