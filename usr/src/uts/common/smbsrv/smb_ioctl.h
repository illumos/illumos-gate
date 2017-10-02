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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2017 Joyent, Inc.
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
#define	SMB_IOC_GMTOFF		_IOW(SMB_IOC_BASE, 3, int)
#define	SMB_IOC_SHARE		_IOW(SMB_IOC_BASE, 4, int)
#define	SMB_IOC_UNSHARE		_IOW(SMB_IOC_BASE, 5, int)
#define	SMB_IOC_NUMOPEN		_IOW(SMB_IOC_BASE, 6, int)
#define	SMB_IOC_SVCENUM		_IOW(SMB_IOC_BASE, 7, int)
#define	SMB_IOC_FILE_CLOSE	_IOW(SMB_IOC_BASE, 8, int)
#define	SMB_IOC_SESSION_CLOSE	_IOW(SMB_IOC_BASE, 9, int)
#define	SMB_IOC_STOP		_IOW(SMB_IOC_BASE, 10, int)
#define	SMB_IOC_EVENT		_IOW(SMB_IOC_BASE, 11, int)
#define	SMB_IOC_SHAREINFO	_IOW(SMB_IOC_BASE, 12, int)
#define	SMB_IOC_SPOOLDOC	_IOW(SMB_IOC_BASE, 13, int)

typedef struct smb_ioc_header {
	uint32_t	version;
	uint32_t	crc;
	uint32_t	len;
	int		cmd;
} smb_ioc_header_t;

typedef	struct smb_ioc_spooldoc {
	smb_ioc_header_t hdr;
	smb_inaddr_t	ipaddr;
	uint32_t	spool_num;
	char		username[MAXNAMELEN];
	char		path[MAXPATHLEN];
} smb_ioc_spooldoc_t;

typedef	struct {
	smb_ioc_header_t hdr;
	int32_t 	offset;
} smb_ioc_gmt_t;

typedef struct smb_ioc_share {
	smb_ioc_header_t hdr;
	uint32_t	shrlen;
	char		shr[1];
} smb_ioc_share_t;

typedef struct smb_ioc_shareinfo {
	smb_ioc_header_t hdr;
	char		shrname[MAXNAMELEN];
	uint32_t	shortnames;
} smb_ioc_shareinfo_t;

typedef	struct smb_ioc_start {
	smb_ioc_header_t hdr;
	int		opipe;
	int		lmshrd;
	int		udoor;
	/* These are used only by libfksmbsrv */
	void		*opipe_func;
	void		*lmshr_func;
	void		*udoor_func;
} smb_ioc_start_t;

typedef	struct smb_ioc_event {
	smb_ioc_header_t hdr;
	uint32_t	txid;
} smb_ioc_event_t;

typedef	struct smb_ioc_opennum {
	smb_ioc_header_t hdr;
	uint32_t	open_users;
	uint32_t	open_trees;
	uint32_t	open_files;
	uint32_t	qualtype;
	char		qualifier[MAXNAMELEN];
} smb_ioc_opennum_t;

/*
 * For enumeration, user and session are synonymous, as are
 * connection and tree.
 */
#define	SMB_SVCENUM_TYPE_USER	0x55534552	/* 'USER' */
#define	SMB_SVCENUM_TYPE_TREE	0x54524545	/* 'TREE' */
#define	SMB_SVCENUM_TYPE_FILE	0x46494C45	/* 'FILE' */
#define	SMB_SVCENUM_TYPE_SHARE	0x53484152	/* 'SHAR' */

/* Maximum size of payload data an smbsrv ioctl may use. */
#define	SMB_IOC_DATA_SIZE		(256 * 1024)

typedef struct smb_svcenum {
	uint32_t	se_type;	/* object type to enumerate */
	uint32_t	se_level;	/* level of detail being requested */
	uint32_t	se_prefmaxlen;	/* client max size buffer preference */
	uint32_t	se_resume;	/* client resume handle */
	uint32_t	se_bavail;	/* remaining buffer space in bytes */
	uint32_t	se_bused;	/* consumed buffer space in bytes */
	uint32_t	se_ntotal;	/* total number of objects */
	uint32_t	se_nlimit;	/* max number of objects to return */
	uint32_t	se_nitems;	/* number of objects in buf */
	uint32_t	se_nskip;	/* number of objects to skip */
	uint32_t	se_status;	/* enumeration status */
	uint32_t	se_buflen;	/* length of the buffer in bytes */
	uint8_t		se_buf[1];	/* buffer to hold enumeration data */
} smb_svcenum_t;

typedef	struct smb_ioc_svcenum {
	smb_ioc_header_t hdr;
	smb_svcenum_t	svcenum;
} smb_ioc_svcenum_t;

typedef struct smb_ioc_session {
	smb_ioc_header_t hdr;
	char		client[MAXNAMELEN];
	char		username[MAXNAMELEN];
} smb_ioc_session_t;

typedef	struct smb_ioc_fileid {
	smb_ioc_header_t hdr;
	uint32_t	uniqid;
} smb_ioc_fileid_t;

/* See also: smb_kmod_cfg_t */
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
	int32_t		netbios_enable;
	int32_t		ipv6_enable;
	int32_t		print_enable;
	int32_t		traverse_mounts;
	uint32_t	max_protocol;
	uint32_t	exec_flags;
	uint32_t	negtok_len;
	smb_version_t	version;
	uint16_t	initial_credits;
	uint16_t	maximum_credits;
	/* SMB negotiate protocol response. */
	uuid_t		machine_uuid;
	uchar_t		negtok[SMB_PI_MAX_NEGTOK];
	char		native_os[SMB_PI_MAX_NATIVE_OS];
	char		native_lm[SMB_PI_MAX_LANMAN];
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
	smb_ioc_event_t		ioc_event;
	smb_ioc_opennum_t	ioc_opennum;
	smb_ioc_svcenum_t	ioc_svcenum;
	smb_ioc_session_t	ioc_session;
	smb_ioc_fileid_t	ioc_fileid;
	smb_ioc_share_t		ioc_share;
	smb_ioc_shareinfo_t	ioc_shareinfo;
	smb_ioc_spooldoc_t	ioc_spooldoc;
} smb_ioc_t;

uint32_t smb_crc_gen(uint8_t *, size_t);

/* fksmbd (init,open,close,ioctl) calls into libfksmbsrv */
int fksmbsrv_drv_open(void);
int fksmbsrv_drv_close(void);
int fksmbsrv_drv_ioctl(int cmd, void *arg);
void fksmbsrv_drv_load(void);

#ifdef __cplusplus
}
#endif

#endif /* _SMB_IOCTL_H_ */
