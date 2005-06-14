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
%#include <sys/types.h>
%#include <sys/errno.h>
%#include <sys/utsname.h>
#ifndef _KERNEL
%#include <netdb.h>
#endif
%
%#include <sys/lvm/md_basic.h>

#ifdef	RPC_SVC
%
%#include <signal.h>
#endif	/* RPC_SVC */

%
%/*
% * mediator (med) errors, definition of MDE_MED_HOSTNOMED must be changed
% * when new errors are added, since MDE_MED_NOERROR has to come out to
% * be zero!
% */
enum md_med_errno_t {
	MDE_MED_HOSTNOMED = -16,
	MDE_MED_DBNOTINIT,
	MDE_MED_DBSZBAD,
	MDE_MED_DBKEYADDFAIL,
	MDE_MED_DBKEYDELFAIL,
	MDE_MED_DBHDRSZBAD,
	MDE_MED_DBHDRMAGBAD,
	MDE_MED_DBHDRREVBAD,
	MDE_MED_DBHDRCKSBAD,
	MDE_MED_DBRECSZBAD,
	MDE_MED_DBRECMAGBAD,
	MDE_MED_DBRECREVBAD,
	MDE_MED_DBRECCKSBAD,
	MDE_MED_DBRECOFFBAD,
	MDE_MED_DBRECNOENT,
	MDE_MED_DBARGSMISMATCH,
	MDE_MED_NOERROR
};

struct med_err_t {
	int			med_errno; /* errno or negative error code */
	string			med_node<>;	/* associated node */
	string			med_misc<>;	/* misc text */
};

#ifdef	RPC_HDR
%
%/*
% * Null error structure initializer.
% */
%#define	MED_NULL_ERR	{ 0, NULL, NULL }
%#define	MD_MED_DEF_TO	{2, 0}		/* 2 seconds */
%#define	MD_MED_PMAP_TO	{5, 0}		/* 5 seconds */
%
%/*
% * Mediator Magic Number and Data Revision String
% */
%#define	MED_DATA_MAGIC	0x6d656461
%#define	MED_DATA_REV	0x10000000
%
%#define	MED_REC_MAGIC	0x6d657265
%#define	MED_REC_REV	0x10000000
%
%#define	MED_DB_MAGIC	0x6d656462
%#define	MED_DB_REV	0x10000000
%
%#define	METAETCDIR	"/etc/lvm/"
%#define	MED_DB_FILE	METAETCDIR "meddb"
%
%extern	char	*med_errnum_to_str(int errnum);
#endif	/* RPC_HDR */

%/* Mediator records in MN diskset have all callers set to multiowner */
%#define	MED_MN_CALLER	"multiowner"
%

#ifdef	RPC_XDR
%
%/* Start - Avoid duplicate definitions, but get the xdr calls right */
%#if 0
#include "meta_arr.x"
%#endif	/* 0 */
%/* End   - Avoid duplicate definitions, but get the xdr calls right */
%
#endif	/* RPC_XDR */

#ifdef	RPC_HDR
struct	med_db_hdr_t	{
	u_int			med_dbh_mag;
	u_int			med_dbh_rev;
	u_int			med_dbh_cks;
	u_int			med_dbh_nm;
};

%
%/*
% * Flags for the mediator data
% */
%
%#define	MED_DFL_GOLDEN		0x0001
%#define	MED_DFL_ERROR		0x0002
%
#endif	/* RPC_HDR */

%
struct	med_data_t	{
	u_int			med_dat_mag;
	u_int			med_dat_rev;
	u_int			med_dat_cks;
	u_int			med_dat_fl;
	u_int			med_dat_cc;
	set_t			med_dat_sn;
	struct	timeval		med_dat_id;
	int			med_dat_spare;
};

#ifdef	RPC_HDR
%
%/*
% * List of mediator data
% */
%
struct med_data_lst_t	{
	med_data_lst_t		*mdl_nx;
	med_data_t		*mdl_med;
};

%
%/*
% * Flags for the mediator record
% */
%
%#define	MED_RFL_DEL		0x0001
%
#endif	/* RPC_HDR */

%
#ifndef _KERNEL
struct	med_rec_t	{
	u_int			med_rec_mag;
	u_int			med_rec_rev;
	u_int			med_rec_cks;
	u_int			med_rec_fl;
	set_t			med_rec_sn;
	md_set_nm_t		med_rec_snm;
	md_node_nm_arr_t	med_rec_nodes;
	md_h_arr_t		med_rec_meds;
	med_data_t		med_rec_data;
	off_t			med_rec_foff;
};
#endif /* !_KERNEL */

struct	med_med_t	{
	set_t			med_setno;
	string			med_setname<>;
	string			med_caller<>;
};

struct	med_args_t	{
	med_med_t		med;
};

struct	med_res_t	{
	med_err_t		med_status;
	med_med_t		med;
};

struct	med_get_data_res_t	{
	med_err_t		med_status;
	med_data_t		med_data;
};

struct	med_upd_data_args_t	{
	med_med_t		med;
	med_data_t		med_data;
};

#ifndef _KERNEL
struct	med_get_rec_res_t	{
	med_err_t		med_status;
	med_med_t		med;
	med_rec_t		med_rec;
};

struct	med_upd_rec_args_t	{
	u_int			med_flags;
	med_med_t		med;
	med_rec_t		med_rec;
};
#endif /* !_KERNEL */

struct med_hnm_res_t {
	med_err_t		med_status;
	string			med_hnm<>;
};

#ifdef	RPC_XDR
%
%/*
% * Constant null error struct.
% */
%const		med_err_t		med_null_err = MED_NULL_ERR;
%const	struct	timeval			md_med_def_timeout = MD_MED_DEF_TO;
%const	struct	timeval			md_med_pmap_timeout = MD_MED_PMAP_TO;
#endif	/* RPC_XDR */

#ifdef	RPC_HDR
%
%/*
% * External reference to constant null error struct. (declared in med_xdr.c)
% */
%extern	const	med_err_t		med_null_err;
%extern	const	struct	timeval		md_med_def_timeout;
%extern	const	struct	timeval		md_med_pmap_timeout;
%
%/*
% * Some useful defines
% */
%#define	MED_SERVNAME	"rpc.metamedd"
%#define	MED_SVC		"metamed"
%
%/*
% * authorization info
% */
const	MED_GID = 14;		/* mag sysadmin group */
#endif	/* RPC_HDR */

program MED_PROG {
	version MED_VERS {
		med_err_t MED_NULL(void)				= 0;
		med_err_t MED_UPD_DATA(med_upd_data_args_t)		= 1;
		med_get_data_res_t MED_GET_DATA(med_args_t)		= 2;
#ifndef _KERNEL
		med_err_t MED_UPD_REC(med_upd_rec_args_t)		= 3;
		med_get_rec_res_t MED_GET_REC(med_args_t)		= 4;
#endif
		med_hnm_res_t MED_HOSTNAME(void)			= 5;
	} = 1;
} = 100242;

#ifdef  RPC_HDR
#ifdef	_KERNEL
%
%extern	int		upd_med_hosts(md_hi_arr_t *mp, char *setname,
%			    med_data_t *meddp, char *caller);
%extern	med_data_lst_t 	*get_med_host_data(md_hi_arr_t *mp, char *setname, 
%			    set_t setno);
#endif	/* ! _KERNEL */
#endif  /* RPC_HDR */
