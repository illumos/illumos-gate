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

#ifndef _SMBSRV_SVRAPI_H
#define	_SMBSRV_SVRAPI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file provides definitions for the SMB Net interface. On Windows
 * this would be NetAccess, NetConnection, NetFile, NetServer,
 * NetSession, NetShare and NetSecurity but here things are a limited.
 * This stuff should be described in Windows 9x LanMan documentation.
 *
 * Notes:
 * Lengths of ASCIIZ strings are given as the maximum strlen() value.
 * This does not include space for the terminating 0-byte. When
 * allocating space for such an item, use the form:
 *
 *              char username[LM20_UNLEN+1];
 *
 * An exception to this is PATHLEN, which does include space for the
 * terminating 0-byte.
 *
 * User names, computer names and share names should be upper-cased
 * by the caller and drawn from the ANSI character set.
 */

#ifdef __cplusplus
extern "C" {
#endif


/*
 * Server Class (NetServerGetInfo, NetServerEnum2)
 */

struct server_info_0 {
    char sv0_name[CNLEN + 1]; 	/* Server name */
};	 /* server_info_0 */


struct server_info_1 {
    char		sv1_name[CNLEN + 1];	/* Server name */
    unsigned char	sv1_version_major;	/* Major version # of net */
    unsigned char	sv1_version_minor;	/* Minor version # of net */
    uint32_t		sv1_type;		/* Server type */
    char		*sv1_comment; 		/* Exported server comment */
};	 /* server_info_1 */


/* NOTE struct prefix must equal server_info_1 format */

struct server_info_50 {
    char		sv50_name[CNLEN + 1];
    unsigned char	sv50_version_major;	/* Major version # of net */
    unsigned char	sv50_version_minor;	/* Minor version # of net */
    uint32_t		sv50_type;		/* Server type */
    char		*sv50_comment;		/* Exported server comment */
    unsigned short	sv50_security;		/* SV_SECURITY_* (see below) */
    unsigned short	sv50_auditing;	/* 0 = no auditing; !0 = auditing */
    char		*sv50_container;	/* Security server/domain */
    char		*sv50_ab_server;	/* Address book server */
    char		*sv50_ab_dll;		/* Address book provider DLL */
};	/* server_info_50 */


struct server_info_2 {
    char	sv2_name[CNLEN + 1];
    unsigned char sv2_version_major;
    unsigned char sv2_version_minor;
    uint32_t	sv2_type;
    char	*sv2_comment;
    uint32_t	sv2_ulist_mtime; /* User list, last modification time */
    uint32_t	sv2_glist_mtime; /* Group list, last modification time */
    uint32_t	sv2_alist_mtime; /* Access list, last modification time */
    uint16_t	sv2_users;	/* max number of users allowed */
    uint16_t	sv2_disc;	/* auto-disconnect timeout(in minutes) */
    char	*sv2_alerts;	/* alert names (semicolon separated) */
    uint16_t	sv2_security;	/* SV_USERSECURITY or SV_SHARESECURITY */
    uint16_t	sv2_auditing;	/* 0 = no auditing; nonzero = auditing */

    uint16_t	sv2_numadmin;	/* max number of administrators allowed */
    uint16_t	sv2_lanmask;	/* bit mask representing the srv'd nets */
    uint16_t	sv2_hidden;	/* 0 = visible; nonzero = hidden */
    uint16_t	sv2_announce;	/* visible server announce rate (sec) */
    uint16_t	sv2_anndelta;	/* announce randomize interval (sec) */
				/* name of guest account */
    char	sv2_guestacct[LM20_UNLEN + 1];
    unsigned char sv2_pad1;	/* Word alignment pad byte */
    char	*sv2_userpath;	/* ASCIIZ path to user directories */
    uint16_t	sv2_chdevs;	/* max # shared character devices */
    uint16_t	sv2_chdevq;	/* max # character device queues */
    uint16_t	sv2_chdevjobs;	/* max # character device jobs */
    uint16_t	sv2_connections; /* max # of connections */
    uint16_t	sv2_shares;	/* max # of shares */
    uint16_t	sv2_openfiles;	/* max # of open files */
    uint16_t	sv2_sessopens;	/* max # of open files per session */
    uint16_t	sv2_sessvcs;	/* max # of virtual circuits per client */
    uint16_t	sv2_sessreqs;	/* max # of simul. reqs. from a client */
    uint16_t	sv2_opensearch;	/* max # of open searches */
    uint16_t	sv2_activelocks; /* max # of active file locks */
    uint16_t	sv2_numreqbuf;	/* number of server (standard) buffers */
    uint16_t	sv2_sizreqbuf;	/* size of svr (standard) bufs (bytes) */
    uint16_t	sv2_numbigbuf;	/* number of big (64K) buffers */
    uint16_t	sv2_numfiletasks; /* number of file worker processes */
    uint16_t	sv2_alertsched;	/* alert counting interval (minutes) */
    uint16_t	sv2_erroralert;	/* error log alerting threshold */
    uint16_t	sv2_logonalert;	/* logon violation alerting threshold */
    uint16_t	sv2_accessalert; /* access violation alerting threshold */
    uint16_t	sv2_diskalert;	/* low disk space alert threshold (KB) */
    uint16_t	sv2_netioalert;	/* net I/O error ratio alert threshold */
				/* (tenths of a percent) */
    uint16_t	sv2_maxauditsz;	/* Maximum audit file size (KB) */
    char	*sv2_srvheuristics; /* performance related server switches */
};	/* server_info_2 */


struct server_info_3 {
    char	sv3_name[CNLEN + 1];
    unsigned char sv3_version_major;
    unsigned char sv3_version_minor;
    uint32_t	sv3_type;
    char	*sv3_comment;
    uint32_t	sv3_ulist_mtime; /* User list, last modification time */
    uint32_t	sv3_glist_mtime; /* Group list, last modification time */
    uint32_t	sv3_alist_mtime; /* Access list, last modification time */
    uint16_t	sv3_users;	/* max number of users allowed */
    uint16_t	sv3_disc;	/* auto-disconnect timeout(in minutes) */
    char	*sv3_alerts;	/* alert names (semicolon separated) */
    uint16_t	sv3_security;	/* SV_USERSECURITY or SV_SHARESECURITY */
    uint16_t	sv3_auditing;	/* 0 = no auditing; nonzero = auditing */

    uint16_t	sv3_numadmin;	/* max number of administrators allowed */
    uint16_t	sv3_lanmask;	/* bit mask representing the srv'd nets */
    uint16_t	sv3_hidden;	/* 0 = visible; nonzero = hidden */
    uint16_t	sv3_announce;	/* visible server announce rate (sec) */
    uint16_t	sv3_anndelta;	/* announce randomize interval (sec) */
				/* name of guest account */
    char	sv3_guestacct[LM20_UNLEN + 1];
    unsigned char sv3_pad1;	/* Word alignment pad byte */
    char	*sv3_userpath;	/* ASCIIZ path to user directories */
    uint16_t	sv3_chdevs;	/* max # shared character devices */
    uint16_t	sv3_chdevq;	/* max # character device queues */
    uint16_t	sv3_chdevjobs;	/* max # character device jobs */
    uint16_t	sv3_connections; /* max # of connections */
    uint16_t	sv3_shares;	/* max # of shares */
    uint16_t	sv3_openfiles;	/* max # of open files */
    uint16_t	sv3_sessopens;	/* max # of open files per session */
    uint16_t	sv3_sessvcs;	/* max # of virtual circuits per client */
    uint16_t	sv3_sessreqs;	/* max # of simul. reqs. from a client */
    uint16_t	sv3_opensearch;	/* max # of open searches */
    uint16_t	sv3_activelocks; /* max # of active file locks */
    uint16_t	sv3_numreqbuf;	/* number of server (standard) buffers */
    uint16_t	sv3_sizreqbuf;	/* size of svr (standard) bufs (bytes) */
    uint16_t	sv3_numbigbuf;	/* number of big (64K) buffers */
    uint16_t	sv3_numfiletasks; /* number of file worker processes */
    uint16_t	sv3_alertsched;	/* alert counting interval (minutes) */
    uint16_t	sv3_erroralert;	/* error log alerting threshold	*/
    uint16_t	sv3_logonalert;	/* logon violation alerting threshold */
    uint16_t	sv3_accessalert; /* access violation alerting threshold */
    uint16_t	sv3_diskalert;	/* low disk space alert threshold (KB) */
    uint16_t	sv3_netioalert;	/* net I/O error ratio alert threshold */
				/* (tenths of a percent) */
    uint16_t	sv3_maxauditsz;	/* Maximum audit file size (KB)	*/
    char	*sv3_srvheuristics; /* performance related server switches */
    uint32_t 	sv3_auditedevents; /* Audit event control mask */
    uint16_t	sv3_autoprofile; /* (0,1,2,3) = (NONE,LOAD,SAVE,or BOTH) */
    char	*sv3_autopath;	/* file pathname (where to load & save) */
};	/* server_info_3 */


/*
 *	Mask to be applied to svX_version_major in order to obtain
 *	the major version number.
 */
#define	MAJOR_VERSION_MASK	0x0F


/*
 * Bit-mapped values for svX_type fields. X = 1, 2, 3 etc.
 *
 * SV_TYPE_WORKSTATION        0x00000001 All workstations
 * SV_TYPE_SERVER             0x00000002 All servers
 * SV_TYPE_SQLSERVER          0x00000004 Any server running with SQL
 *                                       server
 * SV_TYPE_DOMAIN_CTRL        0x00000008 Primary domain controller
 * SV_TYPE_DOMAIN_BAKCTRL     0x00000010 Backup domain controller
 * SV_TYPE_TIME_SOURCE        0x00000020 Server running the timesource
 *                                       service
 * SV_TYPE_AFP                0x00000040 Apple File Protocol servers
 * SV_TYPE_NOVELL             0x00000080 Novell servers
 * SV_TYPE_DOMAIN_MEMBER      0x00000100 Domain Member
 * SV_TYPE_PRINTQ_SERVER      0x00000200 Server sharing print queue
 * SV_TYPE_DIALIN_SERVER      0x00000400 Server running dialin service.
 * SV_TYPE_XENIX_SERVER       0x00000800 Xenix server
 * SV_TYPE_NT                 0x00001000 NT server
 * SV_TYPE_WFW                0x00002000 Server running Windows for
 *                                       Workgroups
 * SV_TYPE_SERVER_NT          0x00008000 Windows NT non DC server
 * SV_TYPE_POTENTIAL_BROWSER  0x00010000 Server that can run the browser
 *                                       service
 * SV_TYPE_BACKUP_BROWSER     0x00020000 Backup browser server
 * SV_TYPE_MASTER_BROWSER     0x00040000 Master browser server
 * SV_TYPE_DOMAIN_MASTER      0x00080000 Domain Master Browser server
 * SV_TYPE_LOCAL_LIST_ONLY    0x40000000 Enumerate only entries marked
 *                                       "local"
 * SV_TYPE_DOMAIN_ENUM        0x80000000 Enumerate Domains. The pszDomain
 *                                       parameter must be NULL.
 */
#define	SV_TYPE_WORKSTATION		0x00000001
#define	SV_TYPE_SERVER			0x00000002
#define	SV_TYPE_SQLSERVER		0x00000004
#define	SV_TYPE_DOMAIN_CTRL		0x00000008
#define	SV_TYPE_DOMAIN_BAKCTRL		0x00000010
#define	SV_TYPE_TIME_SOURCE		0x00000020
#define	SV_TYPE_AFP			0x00000040
/* Also set by Win95 NWSERVER */
#define	SV_TYPE_NOVELL			0x00000080
#define	SV_TYPE_DOMAIN_MEMBER		0x00000100
#define	SV_TYPE_PRINTQ_SERVER		0x00000200
#define	SV_TYPE_DIALIN_SERVER		0x00000400
#define	SV_TYPE_XENIX_SERVER		0x00000800
#define	SV_TYPE_NT			0x00001000
#define	SV_TYPE_WFW			0x00002000
#define	SV_TYPE_SERVER_NT		0x00008000
#define	SV_TYPE_POTENTIAL_BROWSER	0x00010000
#define	SV_TYPE_BACKUP_BROWSER		0x00020000
#define	SV_TYPE_MASTER_BROWSER		0x00040000
#define	SV_TYPE_DOMAIN_MASTER		0x00080000
#define	SV_TYPE_LOCAL_LIST_ONLY		0x40000000
#define	SV_TYPE_DOMAIN_ENUM		0x80000000
/* Handy for NetServerEnum2 */
#define	SV_TYPE_ALL			0xFFFFFFFF


#ifdef __cplusplus
}
#endif

#endif /* _SMBSRV_SVRAPI_H */
