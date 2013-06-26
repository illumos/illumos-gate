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
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Kstat definitions for the SMB server module.
 */
#ifndef _SMBSRV_SMB_KSTAT_H
#define	_SMBSRV_SMB_KSTAT_H

#include	<smbsrv/smb.h>
#include	<smbsrv/smb2.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	SMBSRV_KSTAT_PROCESS		"smbd"
#define	SMBSRV_KSTAT_MODULE		"smbsrv"
#define	SMBSRV_KSTAT_CLASS		"net"
#define	SMBSRV_KSTAT_NAME		"smbsrv"
#define	SMBSRV_KSTAT_NAME_CMDS		"smbsrv_commands"
#define	SMBSRV_KSTAT_TXRCACHE		"smb_txreq"
#define	SMBSRV_KSTAT_REQUEST_CACHE	"smb_request_cache"
#define	SMBSRV_KSTAT_SESSION_CACHE	"smb_session_cache"
#define	SMBSRV_KSTAT_USER_CACHE		"smb_user_cache"
#define	SMBSRV_KSTAT_TREE_CACHE		"smb_tree_cache"
#define	SMBSRV_KSTAT_OFILE_CACHE	"smb_ofile_cache"
#define	SMBSRV_KSTAT_ODIR_CACHE		"smb_odir_cache"
#define	SMBSRV_KSTAT_NODE_CACHE		"smb_node_cache"
#define	SMBSRV_KSTAT_MBC_CACHE		"smb_mbc_cache"
#define	SMBSRV_KSTAT_STATISTICS		"smbsrv_statistics"
#define	SMBSRV_KSTAT_UNSUPPORTED	"Unsupported"
#define	SMBSRV_KSTAT_WORKERS		"smb_workers"

#pragma pack(1)

typedef struct smb_kstat_utilization {
	hrtime_t	ku_wtime;
	hrtime_t	ku_wlentime;
	hrtime_t	ku_rtime;
	hrtime_t	ku_rlentime;
} smb_kstat_utilization_t;

typedef struct smb_kstat_req {
	char		kr_name[KSTAT_STRLEN];
	char		kr_pad[(~(KSTAT_STRLEN & 0x07) + 1) & 0x07];
	uint64_t	kr_sum;
	uint64_t	kr_txb;
	uint64_t	kr_rxb;
	uint64_t	kr_nreq;
	uint64_t	kr_a_mean;
	uint64_t	kr_a_stddev;
	uint64_t	kr_d_mean;
	uint64_t	kr_d_stddev;
} smb_kstat_req_t;

typedef struct smbsrv_kstats {
	hrtime_t		ks_start_time;
	uint64_t		ks_txb;		/* Bytes transmitted */
	uint64_t		ks_rxb;		/* Bytes received */
	uint64_t		ks_nreq;	/* Requests treated */
	smb_kstat_utilization_t	ks_utilization;
	smb_kstat_req_t		ks_reqs1[SMB_COM_NUM];
	smb_kstat_req_t		ks_reqs2[SMB2__NCMDS];
	uint32_t		ks_nbt_sess;	/* NBT sessions */
	uint32_t		ks_tcp_sess;	/* TCP sessions */
	uint32_t		ks_users;	/* Users logged in */
	uint32_t		ks_trees;	/* Trees connected */
	uint32_t		ks_files;	/* Open files */
	uint32_t		ks_pipes;	/* Open pipes */
	uint32_t		ks_maxreqs;	/* Max number of reqs */
	uint32_t		ks_padding;
} smbsrv_kstats_t;

#pragma pack()

#ifdef	__cplusplus
}
#endif

#endif /* _SMBSRV_SMB_KSTAT_H */
