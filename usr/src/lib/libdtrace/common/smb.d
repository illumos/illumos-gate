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
 *
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

#pragma	D depends_on library ip.d
#pragma	D depends_on library net.d
#pragma	D depends_on module genunix
#pragma	D depends_on module smbsrv

#pragma D binding "1.5" translator
translator conninfo_t < struct smb_request *P > {
	ci_protocol =
	    P->session->ipaddr.a_family == AF_INET6 ? "tcp6" :
	    P->session->ipaddr.a_family == AF_INET ? "tcp" :
	    "<unknown>";
	ci_local = "<any>"; /* not interesting */
	ci_remote = P->session->ip_addr_str;
};

/*
 * The smbopinfo_t structure describes the internal form of a
 * single SMB request (SMB v1).
 */
typedef struct smbopinfo {
	cred_t   *soi_cred;		/* credentials for operation */
	string   soi_share;		/* share name */
	string   soi_curpath;		/* file handle path (if any) */
	uint64_t soi_sid;		/* session id */
	uint32_t soi_pid;		/* process id */
	uint32_t soi_status;		/* status */
	uint16_t soi_tid;		/* tree id */
	uint16_t soi_uid;		/* user id */
	uint16_t soi_mid;		/* request id */
	uint16_t soi_fid;		/* file id */
	uint16_t soi_flags2;		/* flags2 */
	uint8_t  soi_flags;		/* flags */
} smbopinfo_t;

#pragma D binding "1.5" translator
translator smbopinfo_t < struct smb_request *P > {
	soi_cred	= (cred_t *)P->user_cr;
	soi_sid		= P->session->s_kid;
	soi_pid		= P->smb_pid;
	soi_status	= P->smb_error.status;
	soi_tid		= P->smb_tid;
	soi_uid		= P->smb_uid;
	soi_mid		= P->smb_mid;
	soi_fid		= P->smb_fid;
	soi_flags2	= P->smb_flg2;
	soi_flags	= P->smb_flg;

	soi_share = (P->tid_tree == NULL) ? "<NULL>" :
	    P->tid_tree->t_sharename;

	soi_curpath = (P->fid_ofile == NULL ||
	    P->fid_ofile->f_node == NULL ||
	    P->fid_ofile->f_node->vp == NULL ||
	    P->fid_ofile->f_node->vp->v_path == NULL) ? "<NULL>" :
	    P->fid_ofile->f_node->vp->v_path;
};

typedef struct smb_rw_args {
	off_t	soa_offset;
	uint_t	soa_count;
} smb_rw_args_t;

#pragma D binding "1.5" translator
translator smb_rw_args_t < smb_request_t *P > {
	soa_offset = P->arg.rw->rw_offset;
	soa_count  = P->arg.rw->rw_count;
};

typedef struct smb_name_args {
	string	soa_name;
} smb_name_args_t;

#pragma D binding "1.5" translator
translator smb_name_args_t < smb_request_t *P > {
	soa_name = (P->arg.dirop.fqi.fq_path.pn_path == NULL) ? "<NULL>" :
	    P->arg.dirop.fqi.fq_path.pn_path;
};

typedef struct smb_open_args {
	string		soa_name;
	uint32_t	soa_desired_access;
	uint32_t	soa_share_access;
	uint32_t	soa_create_options;
	uint32_t	soa_create_disposition;
} smb_open_args_t;

#pragma D binding "1.5" translator
translator smb_open_args_t < smb_request_t *P > {
	soa_name = (P->arg.open.fqi.fq_path.pn_path == NULL) ? "<NULL>" :
	    P->arg.open.fqi.fq_path.pn_path;
	soa_desired_access = P->arg.open.desired_access;
	soa_share_access   = P->arg.open.share_access;
	soa_create_options = P->arg.open.create_options;
	soa_create_disposition = P->arg.open.create_disposition;
};

/*
 * The smb2opinfo_t structure describes the internal form of a
 * single SMB2 request (SMB v2 and later).
 */
typedef struct smb2opinfo {
	cred_t   *soi_cred;		/* credentials for operation */
	string   soi_share;		/* share name */
	string   soi_curpath;		/* file handle path (if any) */
	uint64_t soi_sid;		/* (internal) session ID */
	uint64_t soi_mid;		/* Message ID */
	uint64_t soi_asyncid;		/* Message ID (when async) */
	uint64_t soi_uid;		/* user ID (SMB2 Session ID) */
	uint32_t soi_tid;		/* tree ID */
	uint32_t soi_status;
	uint32_t soi_flags;
} smb2opinfo_t;

#pragma D binding "1.5" translator
translator smb2opinfo_t < struct smb_request *P > {
	soi_cred	= (cred_t *)P->user_cr;
	soi_sid		= P->session->s_kid;
	soi_mid		= P->smb2_messageid;
	soi_asyncid	= P->smb2_async_id;
	soi_uid		= P->smb2_ssnid;
	soi_tid		= P->smb_tid;
	soi_status	= P->smb2_status;
	soi_flags	= P->smb2_hdr_flags;

	soi_share = (P->tid_tree == NULL) ? "<NULL>" :
	    P->tid_tree->t_sharename;

	soi_curpath = (P->fid_ofile == NULL ||
	    P->fid_ofile->f_node == NULL ||
	    P->fid_ofile->f_node->vp == NULL ||
	    P->fid_ofile->f_node->vp->v_path == NULL) ? "<NULL>" :
	    P->fid_ofile->f_node->vp->v_path;
};
