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
%/*
% * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
% * Use is subject to license terms.
% */

%/* from bootparam_prot.x */

#ifdef RPC_HDR
%
%#pragma ident	"%Z%%M%	%I%	%E% SMI"
%
#endif

/*
 * RPC for bootparms service.
 * There are two procedures:
 *   WHOAMI takes a net address and returns a client name and also a
 *	likely net address for routing
 *   GETFILE takes a client name and file identifier and returns the
 *	server name, server net address and pathname for the file.
 *   file identifiers typically include root, swap, pub and dump
 */
const MAX_MACHINE_NAME  = 255;
const MAX_PATH_LEN	= 1024;
const MAX_FILEID	= 32;
const IP_ADDR_TYPE	= 1;

typedef	string	bp_machine_name_t<MAX_MACHINE_NAME>;
typedef	string	bp_path_t<MAX_PATH_LEN>;
typedef	string	bp_fileid_t<MAX_FILEID>;

struct	ip_addr_t {
	char	net;
	char	host;
	char	lh;
	char	impno;
};

union bp_address switch (int address_type) {
	case IP_ADDR_TYPE:
		ip_addr_t	ip_addr;
};

struct bp_whoami_arg {
	bp_address		client_address;
};

struct bp_whoami_res {
	bp_machine_name_t	client_name;
	bp_machine_name_t	domain_name;
	bp_address		router_address;
};

struct bp_getfile_arg {
	bp_machine_name_t	client_name;
	bp_fileid_t		file_id;
};
	
struct bp_getfile_res {
	bp_machine_name_t	server_name;
	bp_address		server_address;
	bp_path_t		server_path;
};

program BOOTPARAMPROG {
	version BOOTPARAMVERS {
		bp_whoami_res	BOOTPARAMPROC_WHOAMI(bp_whoami_arg) = 1;
		bp_getfile_res	BOOTPARAMPROC_GETFILE(bp_getfile_arg) = 2;
	} = 1;
} = 100026;
