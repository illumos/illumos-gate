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
% * This file has the shared fixed array RPC definitions for use in a couple
% * places.
% */
%

%
%/*
% * Node Name type
% */
typedef	char			md_node_nm_t[MD_MAX_NODENAME_PLUS_1];
typedef	char			md_mnnode_nm_t[MD_MAX_MNNODENAME_PLUS_1];

%
%/*
% * Set Name Type
% */
typedef	char			md_set_nm_t[MD_MAX_SETNAME_PLUS_1];

%
%/*
% * Mediator Basic Data Types
% */
typedef	md_node_nm_t		md_alias_nm_t[MAX_HOST_ADDRS];
typedef	u_int			md_alias_ip_t[MAX_HOST_ADDRS];

#ifdef	RPC_HDR
%
%/*
% * Values for the a_flg structure member of md_alias_nm_ip_t structure
% */
%#define	NMIP_F_LOCAL	0x0001
%
#endif	/* RPC_HDR */

struct	md_hi_t {
	u_int			a_flg;
	int			a_cnt;
	md_alias_nm_t		a_nm;
	md_alias_ip_t		a_ip;
};

struct	md_hi_arr_t {
	int			n_cnt;
	md_hi_t			n_lst[MED_MAX_HOSTS];
};

struct	md_h_t {
	int			a_cnt;
	md_alias_nm_t		a_nm;
};

struct	md_h_arr_t {
	int			n_cnt;
	md_h_t			n_lst[MED_MAX_HOSTS];
};

%
%/*
% * Node Name type
% */
typedef	md_node_nm_t		md_node_nm_arr_t[MD_MAXSIDES];
%
#if 0
%
%/*
% * Node Name type with added aliases
% */
struct	md_node_nm_arr_t {
	int			n_cnt;
	md_h_t			n_lst[MD_MAXSIDES];
};
#endif	/* 0 */
