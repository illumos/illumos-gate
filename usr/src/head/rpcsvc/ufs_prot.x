/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 *	Copyright 1994 by Sun Microsystems, Inc.
 *	  All Rights Reserved
 */

%#pragma ident	"%Z%%M%	%I%	%E% SMI"

%#include <sys/fs/ufs_fs.h>
%#include <sys/types.h>
%#include <sys/errno.h>

enum ufsdrc_t {
	UFSDRC_OK	= 0,
	UFSDRC_NOENT	= ENOENT,	/* can't find fsck */
	UFSDRC_PERM	= EPERM,	/* no permissions */
	UFSDRC_INVAL	= EINVAL,	/* poorly formed args */
	UFSDRC_NOEXEC	= ENOEXEC,	/* can't exec fsck */
	UFSDRC_NODEV	= ENODEV,	/* invalid file system id */
	UFSDRC_NXIO	= ENXIO,	/* bad special device */
	UFSDRC_BUSY	= EBUSY,	/* another fsck in progress */
	UFSDRC_OPNOTSUP	= EOPNOTSUPP,	/* daemons mode makes this unfeasible */
	UFSDRC_EXECERR	= 254,		/* fsck/child ran but had an error */
	UFSDRC_ERR	= 255		/* generic error */
};

struct fs_identity_t {
	dev_t		fs_dev;
	string		fs_name<MAXMNTLEN>;
};

struct ufsd_repairfs_args_t {
	fs_identity_t	ua_fsid;
	unsigned int	ua_attempts;
};

struct ufsd_repairfs_list_t {
	int			 ual_listlen;
	ufsd_repairfs_args_t	*ual_list;
};

enum ufsd_event_t {
	UFSDEV_NONE = 0,
	UFSDEV_REBOOT,
	UFSDEV_FSCK,
	UFSDEV_LOG_OP
};

enum ufsd_boot_type_t {
	UFSDB_NONE = 0,
	UFSDB_CLEAN,
	UFSDB_POSTPANIC
};

enum ufsd_log_op_t {
	UFSDLO_NONE = 0,
	UFSDLO_COMMIT,
	UFSDLO_GET,
	UFSDLO_PUT,
	UFSDLO_RESET
};

enum ufsd_fsck_state_t {
	UFSDFS_NONE = 0,
	UFSDFS_DISPATCH,
	UFSDFS_ERREXIT,
	UFSDFS_SUCCESS
};

const UFSD_VARMSGMAX		= 1024;
const UFSD_SPAREMSGBYTES	= 4;
struct ufsd_log_data_t {
	int		umld_eob;
	int		umld_seq;
	char		umld_buf<UFSD_VARMSGMAX>;

};

union ufsd_log_msg_t switch (ufsd_log_op_t um_lop) {
case UFSDLO_COMMIT:
	void;
case UFSDLO_GET:
	void;
case UFSDLO_PUT:
	ufsd_log_data_t	um_logdata;
case UFSDLO_RESET:
	void;
default:
	void;
};

union ufsd_msg_vardata_t switch (ufsd_event_t umv_ev) {
case UFSDEV_NONE:
	void;
case UFSDEV_REBOOT:
	ufsd_boot_type_t	umv_b;
case UFSDEV_FSCK:
	ufsd_fsck_state_t	umv_fs;
case UFSDEV_LOG_OP:
	ufsd_log_msg_t		umv_lm;
default:
	void;
};

struct ufsd_msg_t {
	time_t			um_time;
	unsigned int		um_from;
	char			um_spare<UFSD_SPAREMSGBYTES>;
	ufsd_msg_vardata_t	um_var;
};

%#define	UFSD_SERVNAME	"ufsd"
%#define	xdr_dev_t	xdr_u_int
%#define	xdr_time_t	xdr_int

%/*
% * Set UFSD_THISVERS to the newest version of the protocol
% * This allows the preprocessor to force an error if the
% * protocol changes, since the kernel xdr routines may need to be
% * recoded.  Note that we can't explicitly set the version to a
% * symbol as rpcgen will then create erroneous routine names.
% */
%#define	UFSD_V1			1
%#define	UFSD_ORIGVERS		UFSD_V1
%#define	UFSD_THISVERS		1

program UFSD_PROG {
	version UFSD_VERS {
		ufsdrc_t UFSD_NULL(void)				= 0;
		ufsdrc_t UFSD_REPAIRFS(ufsd_repairfs_args_t)		= 1;
		ufsdrc_t UFSD_REPAIRFSLIST(ufsd_repairfs_list_t)	= 2;
		ufsdrc_t UFSD_SEND(ufsd_msg_t)				= 3;
		ufsdrc_t UFSD_RECV(ufsd_msg_t)				= 4;
		ufsdrc_t UFSD_EXIT(void)				= 5;
	} = 1;
} = 100233;
