%/*
% * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
% * Use is subject to license terms.
% *
% * CDDL HEADER START
% *
% * The contents of this file are subject to the terms of the
% * Common Development and Distribution License, Version 1.0 only
% * (the "License").  You may not use this file except in compliance
% * with the License.
% *
% * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
% * or http://www.opensolaris.org/os/licensing.
% * See the License for the specific language governing permissions
% * and limitations under the License.
% *
% * When distributing Covered Code, include this CDDL HEADER in each
% * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
% * If applicable, add the following below this CDDL HEADER, with the
% * fields enclosed by brackets "[]" replaced with your own identifying
% * information: Portions Copyright [yyyy] [name of copyright owner]
% *
% * CDDL HEADER END
% */
%
%#pragma ident	"%Z%%M%	%I%	%E% SMI"
%
%/*
% * MH shadow structure for struct mhioctkown (sys/mhd.h)
% */
struct mhd_mhioctkown_t {
	int		reinstate_resv_delay;
	int		min_ownership_delay;
	int		max_ownership_delay;
};

%
%/*
% * MH timeout values
% */
struct mhd_mhiargs_t {
        int			mh_ff;
        mhd_mhioctkown_t	mh_tk;
};

%
%/*
% * controller info
% */
#ifdef RPC_HDR
%
%#define	METACTLRMAP	"/etc/lvm/md.ctlrmap"
%#define	META_SSA200_PID	"SSA200"
#endif	/* RPC_HDR */
enum mhd_ctlrtype_t {
	MHD_CTLR_GENERIC = 0,
	MHD_CTLR_SSA100,
	MHD_CTLR_SSA200
};

struct mhd_cinfo_t {
	mhd_ctlrtype_t	mhc_ctype;	/* controller type */
	u_int		mhc_tray;	/* SSA100 tray */
	u_int		mhc_bus;	/* SSA100 bus */
	u_longlong_t	mhc_wwn;	/* SSA100 World Wide Name */
};

%
%/*
% * unique drive identifier
% */
typedef	u_int	mhd_did_flags_t;
#ifdef RPC_HDR
%
%#define	MHD_DID_TIME		0x0001
%#define	MHD_DID_SERIAL		0x0002
%#define	MHD_DID_CINFO		0x0004
%#define	MHD_DID_DUPLICATE	0x0008
#endif	/* RPC_HDR */
typedef	char	mhd_serial_t[40];		/* SCSI VID+PID+REV+SERIAL */
struct mhd_drive_id_t {
	mhd_did_flags_t	did_flags;
	long		did_time;		/* vtoc timestamp (time_t) */
	mhd_serial_t	did_serial;		/* SCSI serial number */
	mhd_cinfo_t	did_cinfo;		/* controller info */
};

%
%/*
% * drive identifier list
% */
struct mhd_drive_info_t {
	string		dif_name<>;
	mhd_drive_id_t	dif_id;
};
typedef	mhd_drive_info_t	mhd_drive_info_list_t<>;
