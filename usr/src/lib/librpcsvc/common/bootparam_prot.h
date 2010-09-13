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
 *
 * Copyright 1984 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	

#include <rpc/types.h>

#include <rpc/types.h>
#include <sys/time.h>
#include <sys/errno.h>
#include <nfs/nfs.h>
#define	MAX_MACHINE_NAME 255
#define	MAX_PATH_LEN 1024
#define	MAX_FILEID 32
#define	IP_ADDR_TYPE 1

typedef char *bp_machine_name_t;
bool_t xdr_bp_machine_name_t();

typedef char *bp_path_t;
bool_t xdr_bp_path_t();

typedef char *bp_fileid_t;
bool_t xdr_bp_fileid_t();

struct ip_addr_t {
	char net;
	char host;
	char lh;
	char impno;
};
typedef struct ip_addr_t ip_addr_t;
bool_t xdr_ip_addr_t();

struct bp_address {
	int address_type;
	union {
		ip_addr_t ip_addr;
	} bp_address_u;
};
typedef struct bp_address bp_address;
bool_t xdr_bp_address();

struct bp_whoami_arg {
	bp_address client_address;
};
typedef struct bp_whoami_arg bp_whoami_arg;
bool_t xdr_bp_whoami_arg();

struct bp_whoami_res {
	bp_machine_name_t client_name;
	bp_machine_name_t domain_name;
	bp_address router_address;
};
typedef struct bp_whoami_res bp_whoami_res;
bool_t xdr_bp_whoami_res();

struct bp_getfile_arg {
	bp_machine_name_t client_name;
	bp_fileid_t file_id;
};
typedef struct bp_getfile_arg bp_getfile_arg;
bool_t xdr_bp_getfile_arg();

struct bp_getfile_res {
	bp_machine_name_t server_name;
	bp_address server_address;
	bp_path_t server_path;
};
typedef struct bp_getfile_res bp_getfile_res;
bool_t xdr_bp_getfile_res();

#define	BOOTPARAMPROG ((rpcprog_t)100026)
#define	BOOTPARAMVERS ((rpcvers_t)1)
#define	BOOTPARAMPROC_WHOAMI ((rpcproc_t)1)
extern bp_whoami_res *bootparamproc_whoami_1();
#define	BOOTPARAMPROC_GETFILE ((rpcproc_t)2)
extern bp_getfile_res *bootparamproc_getfile_1();
