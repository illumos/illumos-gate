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

void
smb_kmod_stop(void)
{
	smb_ioc_header_t ioc;

	(void) smb_kmod_ioctl(SMB_IOC_STOP, &ioc, sizeof (ioc));
}

int
smb_kmod_event_notify(uint32_t txid)
{
	smb_ioc_event_t ioc;

	ioc.txid = txid;
	return (smb_kmod_ioctl(SMB_IOC_EVENT, &ioc.hdr, sizeof (ioc)));
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
smb_kmod_get_open_num(smb_opennum_t *opennum)
{
	smb_ioc_opennum_t ioc;
	int rc;

	bzero(&ioc, sizeof (ioc));
	ioc.qualtype = opennum->qualtype;
	(void) strlcpy(ioc.qualifier, opennum->qualifier, MAXNAMELEN);

	rc = smb_kmod_ioctl(SMB_IOC_NUMOPEN, &ioc.hdr, sizeof (ioc));
	if (rc == 0) {
		opennum->open_users = ioc.open_users;
		opennum->open_trees = ioc.open_trees;
		opennum->open_files = ioc.open_files;
	}

	return (rc);
}

/*
 * Initialization for an smb_kmod_enum request.  If this call succeeds,
 * smb_kmod_enum_fini() must be called later to deallocate resources.
 */
smb_netsvc_t *
smb_kmod_enum_init(smb_svcenum_t *request)
{
	smb_netsvc_t		*ns;
	smb_svcenum_t		*svcenum;
	smb_ioc_svcenum_t	*ioc;
	uint32_t		ioclen;

	if ((ns = calloc(1, sizeof (smb_netsvc_t))) == NULL)
		return (NULL);

	ioclen = sizeof (smb_ioc_svcenum_t) + SMB_IOC_DATA_SIZE;
	if ((ioc = malloc(ioclen)) == NULL) {
		free(ns);
		return (NULL);
	}

	bzero(ioc, ioclen);
	svcenum = &ioc->svcenum;
	svcenum->se_type   = request->se_type;
	svcenum->se_level  = request->se_level;
	svcenum->se_bavail = SMB_IOC_DATA_SIZE;
	svcenum->se_nlimit = request->se_nlimit;
	svcenum->se_nskip = request->se_nskip;
	svcenum->se_buflen = SMB_IOC_DATA_SIZE;

	list_create(&ns->ns_list, sizeof (smb_netsvcitem_t),
	    offsetof(smb_netsvcitem_t, nsi_lnd));

	ns->ns_ioc = ioc;
	ns->ns_ioclen = ioclen;
	return (ns);
}

/*
 * Cleanup resources allocated via smb_kmod_enum_init and smb_kmod_enum.
 */
void
smb_kmod_enum_fini(smb_netsvc_t *ns)
{
	list_t			*lst;
	smb_netsvcitem_t	*item;
	smb_netuserinfo_t	*user;
	smb_netconnectinfo_t	*tree;
	smb_netfileinfo_t	*ofile;
	uint32_t		se_type;

	if (ns == NULL)
		return;

	lst = &ns->ns_list;
	se_type = ns->ns_ioc->svcenum.se_type;

	while ((item = list_head(lst)) != NULL) {
		list_remove(lst, item);

		switch (se_type) {
		case SMB_SVCENUM_TYPE_USER:
			user = &item->nsi_un.nsi_user;
			free(user->ui_domain);
			free(user->ui_account);
			free(user->ui_workstation);
			break;
		case SMB_SVCENUM_TYPE_TREE:
			tree = &item->nsi_un.nsi_tree;
			free(tree->ci_username);
			free(tree->ci_share);
			break;
		case SMB_SVCENUM_TYPE_FILE:
			ofile = &item->nsi_un.nsi_ofile;
			free(ofile->fi_path);
			free(ofile->fi_username);
			break;
		default:
			break;
		}
	}

	list_destroy(&ns->ns_list);
	free(ns->ns_items);
	free(ns->ns_ioc);
	free(ns);
}

/*
 * Enumerate users, connections or files.
 */
int
smb_kmod_enum(smb_netsvc_t *ns)
{
	smb_ioc_svcenum_t	*ioc;
	uint32_t		ioclen;
	smb_svcenum_t		*svcenum;
	smb_netsvcitem_t	*items;
	smb_netuserinfo_t	*user;
	smb_netconnectinfo_t	*tree;
	smb_netfileinfo_t	*ofile;
	uint8_t			*data;
	uint32_t		len;
	uint32_t		se_type;
	uint_t			nbytes;
	int			i;
	int			rc;

	ioc = ns->ns_ioc;
	ioclen = ns->ns_ioclen;
	rc = smb_kmod_ioctl(SMB_IOC_SVCENUM, &ioc->hdr, ioclen);
	if (rc != 0)
		return (rc);

	svcenum = &ioc->svcenum;
	items = calloc(svcenum->se_nitems, sizeof (smb_netsvcitem_t));
	if (items == NULL)
		return (ENOMEM);

	ns->ns_items = items;
	se_type = ns->ns_ioc->svcenum.se_type;
	data = svcenum->se_buf;
	len = svcenum->se_bused;

	for (i = 0; i < svcenum->se_nitems; ++i) {
		switch (se_type) {
		case SMB_SVCENUM_TYPE_USER:
			user = &items->nsi_un.nsi_user;
			rc = smb_netuserinfo_decode(user, data, len, &nbytes);
			break;
		case SMB_SVCENUM_TYPE_TREE:
			tree = &items->nsi_un.nsi_tree;
			rc = smb_netconnectinfo_decode(tree, data, len,
			    &nbytes);
			break;
		case SMB_SVCENUM_TYPE_FILE:
			ofile = &items->nsi_un.nsi_ofile;
			rc = smb_netfileinfo_decode(ofile, data, len, &nbytes);
			break;
		default:
			rc = -1;
			break;
		}

		if (rc != 0)
			return (EINVAL);

		list_insert_tail(&ns->ns_list, items);

		++items;
		data += nbytes;
		len -= nbytes;
	}

	return (0);
}

/*
 * A NULL pointer is a wildcard indicator, which we pass on
 * as an empty string (by virtue of the bzero).
 */
int
smb_kmod_session_close(const char *client, const char *username)
{
	smb_ioc_session_t ioc;
	int rc;

	bzero(&ioc, sizeof (ioc));

	if (client != NULL)
		(void) strlcpy(ioc.client, client, MAXNAMELEN);
	if (username != NULL)
		(void) strlcpy(ioc.username, username, MAXNAMELEN);

	rc = smb_kmod_ioctl(SMB_IOC_SESSION_CLOSE, &ioc.hdr, sizeof (ioc));
	return (rc);
}

int
smb_kmod_file_close(uint32_t uniqid)
{
	smb_ioc_fileid_t ioc;
	int rc;

	bzero(&ioc, sizeof (ioc));
	ioc.uniqid = uniqid;

	rc = smb_kmod_ioctl(SMB_IOC_FILE_CLOSE, &ioc.hdr, sizeof (ioc));
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
