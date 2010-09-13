%/*
% * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
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

%#include <mdiox.h>
%#include <meta_basic.h>
%#include <sys/lvm/mdmn_commd.h>

#ifdef RPC_SVC
%
%int md_in_daemon = 1;
%#include <signal.h>
#endif /* RPC_SVC */

#ifdef RPC_CLNT
%int _md_in_daemon = 0;
%#pragma weak md_in_daemon = _md_in_daemon
#endif /* RPC_CLNT */

#ifdef RPC_HDR
%
%extern	int	md_in_daemon;
%/*
% * There are too many external factors that affect the timing of the
% * operations, so we set the timeout to a very large value, in this
% * case 1 day, which should handle HW timeouts, large configurations,
% * and other potential delays.
% */
%#define	CL_LONG_TMO	86400L
#endif /* RPC_HDR */

#ifdef	RPC_XDR
%
%/* Start - Avoid duplicate definitions, but get the xdr calls right */
%#if 0
#include "../uts/common/sys/lvm/meta_arr.x"
%#endif	/* 0 */
%/* End   - Avoid duplicate definitions, but get the xdr calls right */
%
#endif	/* RPC_XDR */

%
%/*
% * Structure Revisions
% */
enum mdrpc_metad_args_rev {
	MD_METAD_ARGS_REV_1 = 1			/* Revision 1 */
};

%
%/*
% *	device id
% */
struct mdrpc_devid_res {
	string		enc_devid<>;		/* encoded device id */
	md_error_t	status;			/* status of RPC call */
};

%
%/*
% * svm rpc version 2 device id arguments
% * (member union in mdrpc_devid_2_args)
% */
struct mdrpc_devid_args {
	md_setkey_t	*cl_sk;
	mdsetname_t	*sp;
	mddrivename_t	*drivenamep;
};

%
%/*
% * svm rpc version 2 device id arguments
% * (union of all version 2 revisions)
% */
union mdrpc_devid_2_args switch (mdrpc_metad_args_rev rev) {
	case MD_METAD_ARGS_REV_1:
	    mdrpc_devid_args	rev1;
	default:
	    void;
};

%
%/*
% * For getting the devinfo based upon devid
% */
struct mdrpc_devidstr_args {
	mdsetname_t	*sp;
	string		enc_devid<>;		/* encoded device id */
	md_error_t	status;			/* status of RPC call */
};

%
%/*
% * For getting the devinfo based upon devid/devname
% */
struct mdrpc_devid_name_args {
	mdsetname_t	*sp;
	string		orig_devname<>;		/* devname on orig node */
	string		enc_devid<>;		/* encoded device id */
};

%
%/*
% * svm rpc version 2 devinfo based upon devid/devname
% * (union of all version 2 revisions)
% */
union mdrpc_devid_name_2_args switch (mdrpc_metad_args_rev rev) {
	case MD_METAD_ARGS_REV_1:
	    mdrpc_devid_name_args	rev1;
	default:
	    void;
};

%
%/*
% * version 1 device info
% */
struct mdrpc_devinfo_res {
	dev_t		dev;			/* major.minor */
	int		vtime;			/* vtoc timestamp */
	md_error_t	status;			/* status of RPC call */
};

%
%/*
% * version 2 device info. dev_t is always 64-bit
% */
struct mdrpc_devinfo_2_res {
	md_dev64_t	dev;			/* major.minor */
	int		vtime;			/* vtoc timestamp */
	string		enc_devid<>;		/* encoded device id */
	string		devname<>;		/* name of the device */
	string		drivername<>;		/* name of the driver */
	md_error_t	status;			/* status of RPC call */
};

%
%/*
% * svm rpc version 1 device info arguments
% */
struct mdrpc_devinfo_args {
	md_setkey_t	*cl_sk;
	mdsetname_t	*sp;
	o_mddrivename_t	*drivenamep;
};

%
%/*
% * svm rpc version 2 (revision 1) device info arguments
% * (member of union in mdrpc_devinfo_2_args)
% */
struct mdrpc_devinfo_2_args_r1 {
	md_setkey_t	*cl_sk;
	mdsetname_t	*sp;
	mddrivename_t	*drivenamep;
	string		enc_devid<>;	/* encoded device id */
};

%
%/*
% * svm rpc version 2 device info arguments
% * (union of all version 2 revisions)
% */
union mdrpc_devinfo_2_args switch (mdrpc_metad_args_rev rev) {
    case MD_METAD_ARGS_REV_1:
	mdrpc_devinfo_2_args_r1	rev1;
    default:
	void;
};

struct mdrpc_hostname_res {
	string		hostname<>;
	md_error_t	status;
};

%
%/*
% * svm rpc version 1 and version 2 (revision 1) getset arguments
% */
struct mdrpc_getset_args {
	string		setname<>;
	set_t		setno;
};

%
%/*
% * svm rpc version 2 getset arguments
% * (union of all version 2 revisions)
% */
union mdrpc_getset_2_args switch (mdrpc_metad_args_rev rev) {
    case MD_METAD_ARGS_REV_1:
	mdrpc_getset_args	rev1;
    default:
	void;
};

%
%/* NOTE: if you add to this struct, then fix the clnt_getset() */
%/*	  to prevent memory leaks */
struct mdrpc_getset_res {
	md_set_record	*sr;
	md_error_t	status;
};

%
%/* NOTE: if you add to this struct, then fix the clnt_mngetset() */
%/*	  to prevent memory leaks */
struct mdrpc_mngetset_res {
	md_mnset_record	*mnsr;
	md_error_t	status;
};

%
%/* NOTE: if you add to this struct, then fix the clnt_getdrivedesc() */
%/*	  to prevent memory leaks */
struct mdrpc_getdrivedesc_res {
	md_drive_desc	*dd;
	md_error_t	status;
};

#ifdef RPC_HDR
%#ifndef STRINGARRAY
#endif
typedef string stringarray<>;
#ifdef RPC_HDR
%#define STRINGARRAY
%#endif
#endif

%
%/*
% * svm rpc version 1 and version 2 (revision 1) createset arguments
% */
struct mdrpc_createset_args {
	md_setkey_t		*cl_sk;
	mdsetname_t		*sp;
	md_node_nm_arr_t	nodes;
	md_timeval32_t		timestamp;
	u_long			genid;
};

%
%/*
% * svm rpc version 2 createset arguments
% * (union of all version 2 revisions)
% */
union mdrpc_createset_2_args switch (mdrpc_metad_args_rev rev) {
    case MD_METAD_ARGS_REV_1:
	mdrpc_createset_args	rev1;
    default:
	void;
};

struct mdrpc_mncreateset_args {
	md_setkey_t		*cl_sk;
	mdsetname_t		*sp;
	md_mnnode_desc		*nodelist;
	md_timeval32_t		timestamp;
	u_long			genid;
	md_node_nm_t		master_nodenm;
	int			master_nodeid;
};

%
%/*
% * svm rpc version 2 mncreateset arguments
% * (union of all version 2 revisions)
% */
union mdrpc_mncreateset_2_args switch (mdrpc_metad_args_rev rev) {
    case MD_METAD_ARGS_REV_1:
	mdrpc_mncreateset_args  rev1;
    default:
	void;
};


struct mdrpc_bool_res {
	int		value;
	md_error_t	status;
};

%
%/*
% * svm rpc version 1 drive arguments
% */
struct mdrpc_drives_args {
	md_setkey_t	*cl_sk;
	mdsetname_t	*sp;
	o_md_drive_desc	*drivedescs;
	md_timeval32_t	timestamp;
	u_long		genid;
};

%
%/*
% * svm rpc version 2 (revision 1) drive arguments
% * (member of union in mrpc_drives_2_args)
% */
struct mdrpc_drives_2_args_r1 {
	md_setkey_t	*cl_sk;
	mdsetname_t	*sp;
	md_drive_desc	*drivedescs;
	md_timeval32_t	timestamp;
	u_long		genid;
};

%
%/*
% * svm rpc version 2 drive arguments
% * (union of all version 2 revisions)
% */
union mdrpc_drives_2_args switch (mdrpc_metad_args_rev rev) {
    case MD_METAD_ARGS_REV_1:
	mdrpc_drives_2_args_r1	rev1;
    default:
	void;
};

%
%/*
% * svm rpc version 1 sidename arguments
% */
struct mdrpc_drv_sidenm_args {
	md_setkey_t	*cl_sk;
	string		hostname<>;
	mdsetname_t	*sp;
	o_md_set_desc	*sd;
	stringarray	node_v<>;
};

%
%/*
% * svm rpc version 2 (revision 1) sidename arguments
% * (member of union in mdrpc_drv_sidenm_2_args)
% */
struct mdrpc_drv_sidenm_2_args_r1 {
	md_setkey_t	*cl_sk;
	string		hostname<>;
	mdsetname_t	*sp;
	md_set_desc	*sd;
	stringarray	node_v<>;
};

%
%/*
% * svm rpc version 2 sidename arguments
% * (union of all version 2 revisions)
% */
union mdrpc_drv_sidenm_2_args switch (mdrpc_metad_args_rev rev) {
    case MD_METAD_ARGS_REV_1:
	mdrpc_drv_sidenm_2_args_r1	rev1;
    default:
	void;
};

%
%/*
% * svm rpc version 1 drvused arguments
% */
struct mdrpc_drvused_args {
	md_setkey_t	*cl_sk;
	mdsetname_t	*sp;
	o_mddrivename_t	*drivenamep;
};

%
%/*
% * svm rpc version 2 (revision 1) drvused arguments
% * (member of union in mdrpc_drvused_2_args)
% */
struct mdrpc_drvused_2_args_r1 {
	md_setkey_t	*cl_sk;
	mdsetname_t	*sp;
	mddrivename_t	*drivenamep;
};

%
%/*
% * svm rpc version 2 drvused arguments
% * (union of all version 2 revisions)
% */
union mdrpc_drvused_2_args switch (mdrpc_metad_args_rev rev) {
    case MD_METAD_ARGS_REV_1:
	mdrpc_drvused_2_args_r1	rev1;
    default:
	void;
};

%
%/*
% * svm rpc version 1 and version 2 (revision 1) host arguments
% */
struct mdrpc_host_args {
	md_setkey_t	*cl_sk;
	mdsetname_t	*sp;
	stringarray	hosts<>;
};

%
%/*
% * svm rpc version 2 host arguments
% * (union of all version 2 revisions)
% */
union mdrpc_host_2_args switch (mdrpc_metad_args_rev rev) {
    case MD_METAD_ARGS_REV_1:
	mdrpc_host_args	rev1;
    default:
	void;
};

struct mdrpc_gtimeout_res {
	md_error_t	status;
	mhd_mhiargs_t	*mhiargsp;
};

%
%/*
% * svm rpc version 1 and version 2 (revision 1) set timeout arguments
% */
struct mdrpc_stimeout_args {
	md_setkey_t	*cl_sk;
	mdsetname_t	*sp;
	mhd_mhiargs_t	*mhiargsp;
};

%
%/*
% * svm rpc version 2 set timeout arguments
% * (union of all version 2 revisions)
% */
union mdrpc_stimeout_2_args switch (mdrpc_metad_args_rev rev) {
    case MD_METAD_ARGS_REV_1:
	mdrpc_stimeout_args	rev1;
    default:
	void;
};

%
%/*
% * svm rpc version 1 arguments
% */
struct mdrpc_upd_dr_flags_args {
	md_setkey_t	*cl_sk;
	mdsetname_t	*sp;
	o_md_drive_desc	*drivedescs;
	u_int		new_flags;
};

%
%/*
% * svm rpc version 2 (revision 1) arguments
% * (member of union in mdrpc_upd_dr_flags_2_args)
% */
struct mdrpc_upd_dr_flags_2_args_r1 {
	md_setkey_t	*cl_sk;
	mdsetname_t	*sp;
	md_drive_desc	*drivedescs;
	u_int		new_flags;
};

%
%/*
% * svm rpc version 2 arguments
% * (union of all version 2 revisions)
% */
union mdrpc_upd_dr_flags_2_args switch (mdrpc_metad_args_rev rev) {
    case MD_METAD_ARGS_REV_1:
	mdrpc_upd_dr_flags_2_args_r1	rev1;
    default:
	void;
};

%
%/*
% * svm rpc version 1 and version 2 (revision 1) arguments
% */
struct mdrpc_upd_sr_flags_args {
	md_setkey_t	*cl_sk;
	mdsetname_t	*sp;
	u_int		new_flags;
};

%
%/*
% * svm rpc version 2 arguments
% * (union of all version 2 revisions)
% */
union mdrpc_upd_sr_flags_2_args switch (mdrpc_metad_args_rev rev) {
    case MD_METAD_ARGS_REV_1:
	mdrpc_upd_sr_flags_args	rev1;
    default:
	void;
};

%
%/*
% * svm rpc version 2 (revision 1) arguments
% */
struct mdrpc_upd_nr_flags_args {
	md_setkey_t	*cl_sk;
	mdsetname_t	*sp;
	md_mnnode_desc	*nodedescs;
	u_int		flag_action;
	u_int		flags;
};

%
%/*
% * svm rpc version 2 arguments
% * (union of all version 2 revisions)
% */
union mdrpc_upd_nr_flags_2_args switch (mdrpc_metad_args_rev rev) {
    case MD_METAD_ARGS_REV_1:
	mdrpc_upd_nr_flags_args	rev1;
    default:
	void;
};


struct mdrpc_setlock_res {
	md_setkey_t	*cl_sk;
	md_error_t	status;
};

struct mdrpc_generic_res {
	md_error_t	status;
};

%
%/*
% * svm rpc version 1 and version 2 (revision 1) set arguments
% */
struct mdrpc_setno_args {
	md_setkey_t	*cl_sk;
	set_t		setno;
};

%
%/*
% * svm rpc version 2 set arguments
% * (union of all version 2 revisions)
% */
union mdrpc_setno_2_args switch (mdrpc_metad_args_rev rev) {
    case MD_METAD_ARGS_REV_1:
	mdrpc_setno_args	rev1;
    default:
	void;
};

struct mdrpc_null_args {
	md_setkey_t	*cl_sk;
};

%
%/*
% * svm rpc version 1 and version 2 (revision 1) arguments
% */
struct mdrpc_sp_args {
	md_setkey_t	*cl_sk;
	mdsetname_t	*sp;
};

%
%/*
% * svm rpc version 2 arguments
% * (union of all version 2 revisions)
% */
union mdrpc_sp_2_args switch (mdrpc_metad_args_rev rev) {
    case MD_METAD_ARGS_REV_1:
	mdrpc_sp_args	rev1;
    default:
	void;
};

%
%/*
% * svm rpc version 2 (revision 1) arguments
% */
struct mdrpc_sp_flags_args {
	md_setkey_t	*cl_sk;
	mdsetname_t	*sp;
	int		flags;
};

%
%/*
% * svm rpc version 2 arguments
% * (union of all version 2 revisions)
% */
union mdrpc_sp_flags_2_args switch (mdrpc_metad_args_rev rev) {
    case MD_METAD_ARGS_REV_1:
	mdrpc_sp_flags_args	rev1;
    default:
	void;
};

%
%/*
% * svm rpc version 1 and version 2 (revision 1) arguments
% */
struct mdrpc_updmeds_args {
	md_setkey_t		*cl_sk;
	mdsetname_t		*sp;
	md_h_arr_t		meds;
};

%
%/*
% * svm rpc version 2 arguments
% * (union of all version 2 revisions)
% */
union mdrpc_updmeds_2_args switch (mdrpc_metad_args_rev rev) {
    case MD_METAD_ARGS_REV_1:
	mdrpc_updmeds_args	rev1;
    default:
	void;
};

struct mdrpc_mnsetmaster_args {
	md_setkey_t	*cl_sk;
	mdsetname_t	*sp;
	md_node_nm_t	master_nodenm;
	int		master_nodeid;
};

%
%/*
% * svm rpc version 2 arguments
% * (union of all version 2 revisions)
% */
union mdrpc_mnsetmaster_2_args switch (mdrpc_metad_args_rev rev) {
    case MD_METAD_ARGS_REV_1:
	mdrpc_mnsetmaster_args  rev1;
    default:
	void;
};

/*
 * Defines and structures to support rpc.mdcommd.
 * RPC routines in rpc.metad will be used to suspend, resume
 * and reinitialize the rpc.mdcommd running on that node.
 * These actions are needed when the nodelist is changing.
 */
%#define	COMMDCTL_SUSPEND	1
%#define	COMMDCTL_RESUME		2
%#define	COMMDCTL_REINIT		3

struct mdrpc_mdcommdctl_args {
	int			flag_action;
	set_t			setno;
	md_mn_msgclass_t	class;
	int			flags;
};

%
%
%/*
% * svm rpc version 2 arguments
% * (union of all version 2 revisions)
% */
union mdrpc_mdcommdctl_2_args switch (mdrpc_metad_args_rev rev) {
    case MD_METAD_ARGS_REV_1:
	mdrpc_mdcommdctl_args  rev1;
    default:
	void;
};

%
%/*
% * svm rpc version 2 (revision 1) nodeid arguments
% */
struct mdrpc_nodeid_args {
	md_setkey_t	*cl_sk;
	mdsetname_t	*sp;
	int		nodeid<>;
};

%
%/*
% * svm rpc version 2 nodeid arguments
% * (union of all version 2 revisions)
% */
union mdrpc_nodeid_2_args switch (mdrpc_metad_args_rev rev) {
    case MD_METAD_ARGS_REV_1:
	mdrpc_nodeid_args 	rev1;
    default:
	void;
};

%
%/*
% * Defines and structures to support suspend and resume I/O
% * driven by a remote node.
% */
%#define	MN_SUSP_IO	1
%#define	MN_RES_IO	2
%
%/*
% * svm rpc version 2 (revision 1) mn_susp_res_io arguments
% * setno of 0 represents all disksets.
% */
struct mdrpc_mn_susp_res_io_args {
	md_setkey_t	*susp_res_l_sk;
	set_t		susp_res_setno;
	int		susp_res_cmd;
};

%
%/*
% * svm rpc version 2 nodeid arguments
% * (union of all version 2 revisions)
% */
union mdrpc_mn_susp_res_io_2_args switch (mdrpc_metad_args_rev rev) {
    case MD_METAD_ARGS_REV_1:
	mdrpc_mn_susp_res_io_args 	rev1;
    default:
	void;
};

#ifdef	RPC_HDR
%
%/*
% *	authorization info
% */
const	METAD_GID = 14;				/* magic sysadmin group */
#endif	/* RPC_HDR */

%
%/*
% *	services available
% */
program METAD {
	version METAD_VERSION {
		md_error_t
		mdrpc_nullproc(void)				= 0;

		mdrpc_hostname_res
		mdrpc_hostname(mdrpc_null_args)			= 1;

		mdrpc_generic_res
		mdrpc_addhosts(mdrpc_host_args)			= 2;

		mdrpc_generic_res
		mdrpc_delhosts(mdrpc_host_args)			= 3;

		mdrpc_generic_res
		mdrpc_createset(mdrpc_createset_args)		= 4;

		mdrpc_generic_res
		mdrpc_delset(mdrpc_sp_args)			= 5;

		mdrpc_getset_res
		mdrpc_getset(mdrpc_getset_args)			= 6;

		mdrpc_bool_res
		mdrpc_setnumbusy(mdrpc_setno_args)		= 7;

		mdrpc_bool_res
		mdrpc_setnameok(mdrpc_sp_args)			= 8;

		mdrpc_bool_res
		mdrpc_ownset(mdrpc_sp_args)			= 9;

		mdrpc_generic_res
		mdrpc_adddrvs(mdrpc_drives_args)		= 10;

		mdrpc_generic_res
		mdrpc_deldrvs(mdrpc_drives_args)		= 11;

		mdrpc_generic_res
		mdrpc_upd_dr_dbinfo(mdrpc_drives_args)		= 12;

		mdrpc_devinfo_res
		mdrpc_devinfo(mdrpc_devinfo_args)		= 13;

		mdrpc_generic_res
		mdrpc_drvused(mdrpc_drvused_args)		= 14;

		mdrpc_generic_res
		mdrpc_add_drv_sidenms(mdrpc_drv_sidenm_args)	= 15;

		mdrpc_generic_res
		mdrpc_del_drv_sidenms(mdrpc_sp_args)		= 16;

		mdrpc_gtimeout_res
		mdrpc_gtimeout(mdrpc_sp_args)			= 17;

		mdrpc_generic_res
		mdrpc_stimeout(mdrpc_stimeout_args)		= 18;

		mdrpc_generic_res
		mdrpc_upd_dr_flags(mdrpc_upd_dr_flags_args)	= 19;

		mdrpc_generic_res
		mdrpc_upd_sr_flags(mdrpc_upd_sr_flags_args)	= 20;

		mdrpc_setlock_res
		mdrpc_unlock_set(mdrpc_null_args)		= 21;

		mdrpc_setlock_res
		mdrpc_lock_set(mdrpc_null_args)			= 22;

		mdrpc_generic_res
		mdrpc_updmeds(mdrpc_updmeds_args)		= 23;

		mdrpc_generic_res
		mdrpc_flush_internal(mdrpc_null_args)		= 24;

	} = 1;

	version METAD_VERSION_DEVID {
		md_error_t
		mdrpc_nullproc(void)				= 0;

		mdrpc_hostname_res
		mdrpc_hostname(mdrpc_null_args)			= 1;

		mdrpc_generic_res
		mdrpc_addhosts(mdrpc_host_2_args)		= 2;

		mdrpc_generic_res
		mdrpc_delhosts(mdrpc_host_2_args)		= 3;

		mdrpc_generic_res
		mdrpc_createset(mdrpc_createset_2_args)		= 4;

		mdrpc_generic_res
		mdrpc_delset(mdrpc_sp_2_args)			= 5;

		mdrpc_getset_res
		mdrpc_getset(mdrpc_getset_2_args)		= 6;

		mdrpc_bool_res
		mdrpc_setnumbusy(mdrpc_setno_2_args)		= 7;

		mdrpc_bool_res
		mdrpc_setnameok(mdrpc_sp_2_args)		= 8;

		mdrpc_bool_res
		mdrpc_ownset(mdrpc_sp_2_args)			= 9;

		mdrpc_generic_res
		mdrpc_adddrvs(mdrpc_drives_2_args)		= 10;

		mdrpc_generic_res
		mdrpc_deldrvs(mdrpc_drives_2_args)		= 11;

		mdrpc_generic_res
		mdrpc_upd_dr_dbinfo(mdrpc_drives_2_args)	= 12;

		mdrpc_devinfo_2_res
		mdrpc_devinfo(mdrpc_devinfo_2_args)		= 13;

		mdrpc_generic_res
		mdrpc_drvused(mdrpc_drvused_2_args)		= 14;

		mdrpc_generic_res
		mdrpc_add_drv_sidenms(mdrpc_drv_sidenm_2_args)	= 15;

		mdrpc_generic_res
		mdrpc_del_drv_sidenms(mdrpc_sp_2_args)		= 16;

		mdrpc_gtimeout_res
		mdrpc_gtimeout(mdrpc_sp_2_args)			= 17;

		mdrpc_generic_res
		mdrpc_stimeout(mdrpc_stimeout_2_args)		= 18;

		mdrpc_generic_res
		mdrpc_upd_dr_flags(mdrpc_upd_dr_flags_2_args)	= 19;

		mdrpc_generic_res
		mdrpc_upd_sr_flags(mdrpc_upd_sr_flags_2_args)	= 20;

		mdrpc_setlock_res
		mdrpc_unlock_set(mdrpc_null_args)		= 21;

		mdrpc_setlock_res
		mdrpc_lock_set(mdrpc_null_args)			= 22;

		mdrpc_generic_res
		mdrpc_updmeds(mdrpc_updmeds_2_args)		= 23;

		mdrpc_generic_res
		mdrpc_flush_internal(mdrpc_null_args)		= 24;

		mdrpc_devid_res
		mdrpc_devid(mdrpc_devid_2_args)			= 25;

		mdrpc_devinfo_2_res
		mdrpc_devinfo_by_devid(mdrpc_devidstr_args)	= 26;

		mdrpc_generic_res
		mdrpc_resnarf_set(mdrpc_setno_2_args)		= 27;

		mdrpc_generic_res
		mdrpc_mncreateset(mdrpc_mncreateset_2_args)	= 28;

		mdrpc_mngetset_res
		mdrpc_mngetset(mdrpc_getset_2_args)		= 29;

		mdrpc_generic_res
		mdrpc_mnsetmaster(mdrpc_mnsetmaster_2_args)	= 30;

		mdrpc_generic_res
		mdrpc_joinset(mdrpc_sp_flags_2_args)		= 31;

		mdrpc_generic_res
		mdrpc_withdrawset(mdrpc_sp_2_args)		= 32;

		mdrpc_generic_res
		mdrpc_upd_nr_flags(mdrpc_upd_nr_flags_2_args)	= 33;

		mdrpc_bool_res
		mdrpc_mn_is_stale(mdrpc_setno_2_args)		= 34;

		mdrpc_generic_res
		mdrpc_mdcommdctl(mdrpc_mdcommdctl_2_args)	= 35;

		mdrpc_generic_res
		mdrpc_clr_mnsetlock(mdrpc_null_args)		= 36;

		mdrpc_getdrivedesc_res
		mdrpc_getdrivedesc(mdrpc_sp_2_args)		= 37;

		mdrpc_generic_res
		mdrpc_upd_dr_reconfig(mdrpc_upd_dr_flags_2_args) = 38;

		mdrpc_generic_res
		mdrpc_reset_mirror_owner(mdrpc_nodeid_2_args)	 = 39;

		mdrpc_generic_res
		mdrpc_mn_susp_res_io(mdrpc_mn_susp_res_io_2_args) = 40;

		mdrpc_generic_res
		mdrpc_mn_mirror_resync_all(mdrpc_setno_2_args) = 41;

		mdrpc_devinfo_2_res
		mdrpc_devinfo_by_devid_name(mdrpc_devid_name_2_args) = 42;

		mdrpc_generic_res
		mdrpc_mn_sp_update_abr(mdrpc_setno_2_args) = 43;

		mdrpc_generic_res
		mdrpc_imp_adddrvs(mdrpc_drives_2_args) = 44;

	} = 2;
} = 100229;

#ifdef RPC_HDR
%
%extern	void	short_circuit_getset(mdrpc_getset_args *args,
%		    mdrpc_getset_res *res);
%extern	void	short_circuit_mngetset(mdrpc_getset_args *args,
%		    mdrpc_mngetset_res *res);
#endif	/* RPC_HDR */
