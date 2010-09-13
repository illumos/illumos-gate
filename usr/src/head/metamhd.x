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

/* pick up multihost ioctl definitions */
%#include <mhdx.h>

#ifdef	RPC_SVC
%
%#include <signal.h>
#endif	/* RPC_SVC */

#ifdef	RPC_HDR
%
%/*
% * error info
% */
%#define	MHD_E_MAJORITY	-1	/* couldn't get majority reservation */
%#define	MHD_E_RESERVED	-2	/* drive is reserved */
#endif	/* RPC_HDR */
struct mhd_error_t {
	int		errnum;		/* errno or negative error code */
	string		name<>;		/* associated name */
};

#ifdef	RPC_HDR
%
%/*
% * null error constant
% */
%#define	MHD_NULL_ERROR	{ 0, NULL }
#endif	/* RPC_HDR */

#ifdef	RPC_XDR
%
%/*
% * Constant null error struct.
% */
%const		mhd_error_t		mhd_null_error = MHD_NULL_ERROR;
#endif	/* RPC_XDR */

#ifdef	RPC_HDR
%
%/*
% * External reference to constant null error struct. (decl. in metamhd_xdr.c)
% */
%extern	const	mhd_error_t		mhd_null_error;
#endif	/* RPC_HDR */


%
%/*
% * drivename type
% */
typedef	string	mhd_drivename_t<>;

%
%/*
% * set definition
% */
struct mhd_set_t {
	string		setname<>;	/* set name */
	mhd_drivename_t	drives<>;	/* drive names */
};

%
%/*
% * common options
% */
typedef	u_int	mhd_opts_t;
#ifdef	RPC_HDR
%
%#define	MHD_PARTIAL_SET	0x01	/* partial set definition */
%#define	MHD_SERIAL	0x02	/* process disks serially */
#endif	/* RPC_HDR */

%
%/*
% * take ownership
% */
enum mhd_ff_mode_t {
	MHD_FF_NONE,			/* no failfast */
	MHD_FF_DRIVER,			/* set failfast on each drive */
	MHD_FF_DEBUG,			/* use /dev/ff debug mode */
	MHD_FF_HALT,			/* use /dev/ff halt mode */
	MHD_FF_PANIC			/* use /dev/ff panic mode */
};
struct mhd_tkown_args_t {
	mhd_set_t	set;		/* set definition */
	mhd_mhiargs_t	timeouts;	/* timeout values */
	mhd_ff_mode_t	ff_mode;	/* failfast mode */
	mhd_opts_t	options;	/* options */
};

%
%/*
% * release ownership
% */
struct mhd_relown_args_t {
	mhd_set_t	set;		/* set definition */
	mhd_opts_t	options;	/* options */
};

%
%/*
% * inquire status
% */
struct mhd_status_args_t {
	mhd_set_t	set;		/* set definition */
	mhd_opts_t	options;	/* options */
};
struct mhd_drive_status_t {
	mhd_drivename_t	drive;		/* drive name */
	int		errnum;		/* drive status */
};
struct mhd_status_res_t {
	mhd_error_t		status;		/* status of command */
	mhd_drive_status_t	results<>;	/* drive status */
};

%/*
% * get local drives
% */
struct mhd_list_args_t {
	string		path<>;		/* where to look (or NULL) */
	mhd_did_flags_t	flags;		/* what to get */
};
struct mhd_list_res_t {
	mhd_error_t		status;		/* status of command */
	mhd_drive_info_list_t	results;	/* drive info list */
};

%
%/*
% * authorization info
% */
const	METAMHD_GID = 14;		/* magic sysadmin group */

%
%/*
% * services available
% */
program METAMHD {
	version METAMHD_VERSION {

		mhd_error_t
		mhd_tkown(mhd_tkown_args_t)		= 1;

		mhd_error_t
		mhd_relown(mhd_relown_args_t)		= 2;

		mhd_status_res_t
		mhd_status(mhd_status_args_t)		= 3;

		mhd_list_res_t
		mhd_list(mhd_list_args_t)		= 4;

	} = 1;
} = 100230;
