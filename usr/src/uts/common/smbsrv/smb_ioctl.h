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

#ifndef _SMB_IOCTL_H_
#define	_SMB_IOCTL_H_

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <smbsrv/smbinfo.h>

#define	SMB_IOC_VERSION		0x534D4201	/* SMB1 */

#define	SMB_IOC_BASE		(('S' << 16) | ('B' << 8))

#define	SMB_IOC_CONFIG		_IOW(SMB_IOC_BASE, 1, int)
#define	SMB_IOC_START		_IOW(SMB_IOC_BASE, 2, int)
#define	SMB_IOC_NBT_LISTEN	_IOW(SMB_IOC_BASE, 3, int)
#define	SMB_IOC_TCP_LISTEN	_IOW(SMB_IOC_BASE, 4, int)
#define	SMB_IOC_NBT_RECEIVE	_IOW(SMB_IOC_BASE, 5, int)
#define	SMB_IOC_TCP_RECEIVE	_IOW(SMB_IOC_BASE, 6, int)
#define	SMB_IOC_GMTOFF		_IOW(SMB_IOC_BASE, 7, int)
#define	SMB_IOC_SHARE		_IOW(SMB_IOC_BASE, 8, int)
#define	SMB_IOC_UNSHARE		_IOW(SMB_IOC_BASE, 9, int)
#define	SMB_IOC_USER_NUMBER	_IOW(SMB_IOC_BASE, 10, int)
#define	SMB_IOC_USER_LIST	_IOW(SMB_IOC_BASE, 11, int)

typedef struct smb_ioc_header {
	uint32_t	version;
	uint32_t	crc;
	uint32_t	len;
	int		cmd;
} smb_ioc_header_t;

typedef	struct {
	smb_ioc_header_t hdr;
	int32_t 	offset;
} smb_ioc_gmt_t;

typedef struct smb_ioc_share {
	smb_ioc_header_t hdr;
	char		path[MAXPATHLEN];
	char		name[MAXNAMELEN];
} smb_ioc_share_t;

typedef	struct smb_ioc_listen {
	smb_ioc_header_t hdr;
	int		error;
} smb_ioc_listen_t;

typedef	struct smb_ioc_start {
	smb_ioc_header_t hdr;
	int		opipe;
	int		lmshrd;
	int		udoor;
} smb_ioc_start_t;

typedef	struct smb_ioc_usernum {
	smb_ioc_header_t hdr;
	uint32_t	num;
} smb_ioc_usernum_t;

typedef	struct smb_ioc_ulist {
	smb_ioc_header_t hdr;
	uint32_t	cookie;
	uint32_t	num;
	uint32_t	data_len;
	uint8_t		data[1];
} smb_ioc_ulist_t;

typedef struct smb_ioc_cfg {
	smb_ioc_header_t hdr;
	uint32_t	maxworkers;
	uint32_t	maxconnections;
	uint32_t	keepalive;
	int32_t		restrict_anon;
	int32_t		signing_enable;
	int32_t		signing_required;
	int32_t		oplock_enable;
	int32_t		sync_enable;
	int32_t		secmode;
	int32_t		ipv6_enable;
	char		nbdomain[NETBIOS_NAME_SZ];
	char		fqdn[SMB_PI_MAX_DOMAIN];
	char		hostname[SMB_PI_MAX_HOST];
	char		system_comment[SMB_PI_MAX_COMMENT];
} smb_ioc_cfg_t;

typedef union smb_ioc {
	smb_ioc_header_t	ioc_hdr;
	smb_ioc_gmt_t		ioc_gmt;
	smb_ioc_cfg_t		ioc_cfg;
	smb_ioc_start_t		ioc_start;
	smb_ioc_listen_t	ioc_listen;
	smb_ioc_usernum_t	ioc_unum;
	smb_ioc_ulist_t		ioc_ulist;
	smb_ioc_share_t		ioc_share;
} smb_ioc_t;

uint32_t smb_crc_gen(uint8_t *, size_t);

#ifdef __cplusplus
}
#endif

#endif /* _SMB_IOCTL_H_ */
