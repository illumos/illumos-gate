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
 */
#ifndef _INET_ILB_H
#define	_INET_ILB_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This file contains the private interface to IP to configure ILB in
 * the system.  Note that this is not a supported interface, and is
 * subject to be changed without notice.  User level apps should instead
 * use the libilb library to interface with ILB.
 */

/* ioctl cmds to IP to configure ILB */
typedef enum {
	ILB_CREATE_RULE,
	ILB_DESTROY_RULE,
	ILB_ENABLE_RULE,
	ILB_DISABLE_RULE,
	ILB_NUM_RULES,
	ILB_NUM_SERVERS,
	ILB_RULE_NAMES,
	ILB_LIST_RULE,
	ILB_LIST_SERVERS,
	ILB_ADD_SERVERS,
	ILB_DEL_SERVERS,
	ILB_ENABLE_SERVERS,
	ILB_DISABLE_SERVERS,
	ILB_LIST_NAT_TABLE,
	ILB_LIST_STICKY_TABLE
} ilb_cmd_t;

/* Supported load balancing algorithm type */
typedef enum {
	ILB_ALG_IMPL_ROUNDROBIN = 1,
	ILB_ALG_IMPL_HASH_IP,
	ILB_ALG_IMPL_HASH_IP_SPORT,
	ILB_ALG_IMPL_HASH_IP_VIP
} ilb_algo_impl_t;

/* Supported load balancing method */
typedef enum {
	ILB_TOPO_IMPL_DSR = 1,
	ILB_TOPO_IMPL_NAT,
	ILB_TOPO_IMPL_HALF_NAT
} ilb_topo_impl_t;

/* Max ILB rule name length */
#define	ILB_RULE_NAMESZ	20

/* Max kstat server name length */
#define	ILB_SERVER_NAMESZ 20

/* Rule destroy/enable/disable command struct */
typedef struct {
	ilb_cmd_t	cmd;
	char		name[ILB_RULE_NAMESZ];
	uint32_t	flags;
} ilb_name_cmd_t;

/* Flags for rule creation command */
/* these are echoed in lib/libilb/common/libilb.h - please keep in sync */
#define	ILB_RULE_ENABLED	0x1
#define	ILB_RULE_STICKY		0x2
#define	ILB_RULE_ALLRULES	0x4
#define	ILB_RULE_BUSY		0x8

/* Rule creation/retrieval command struct */
typedef struct {
	ilb_cmd_t	cmd;
	char		name[ILB_RULE_NAMESZ];
	uint32_t	ip_ver;
	in6_addr_t	vip;
	char		vip_itf[LIFNAMSIZ];
	uint32_t	proto;
	in_port_t	min_port;	/* In network byte order */
	in_port_t	max_port;
	ilb_algo_impl_t	algo;
	ilb_topo_impl_t	topo;
	char		servers_itf[LIFNAMSIZ];
	in6_addr_t	nat_src_start;
	in6_addr_t	nat_src_end;
	uint32_t	flags;
	in6_addr_t	sticky_mask;
	uint32_t	conn_drain_timeout;	/* Time value is in seconds */
	uint32_t	nat_expiry;
	uint32_t	sticky_expiry;
} ilb_rule_cmd_t;

/* Get number of servers command struct */
typedef struct {
	ilb_cmd_t	cmd;
	char		name[ILB_RULE_NAMESZ];
	uint32_t	num;
} ilb_num_servers_cmd_t;

/* Get number of rules command struct */
typedef struct {
	ilb_cmd_t	cmd;
	uint32_t	num;
} ilb_num_rules_cmd_t;

/* Get all rule names command struct */
typedef struct {
	ilb_cmd_t	cmd;
	uint32_t	num_names;
	/* buf size is (num_names * ILB_RULE_NAMESZ) */
	char		buf[ILB_RULE_NAMESZ];
} ilb_rule_names_cmd_t;

/* Flags for ilb_server_info_t */
#define	ILB_SERVER_ENABLED	0x1

/* Struct to represent a backend server for add/list command */
typedef struct {
	char		name[ILB_SERVER_NAMESZ];
	in6_addr_t	addr;
	in_port_t	min_port;	/* In network byte order */
	in_port_t	max_port;
	uint32_t	flags;
	int		err;	/* In return, non zero value indicates error */
} ilb_server_info_t;

/* Add/list servers command struct */
typedef struct {
	ilb_cmd_t		cmd;
	char			name[ILB_RULE_NAMESZ];
	uint32_t		num_servers;
	ilb_server_info_t	servers[1];
} ilb_servers_info_cmd_t;

/*
 * Struct to represent a backend server for delete/enable/disable
 * command
 */
typedef struct {
	in6_addr_t	addr;
	int		err;	/* In return, non zero value indicates error */
} ilb_server_arg_t;

/* Delete/enable/disable a server command struct */
typedef struct {
	ilb_cmd_t		cmd;
	char			name[ILB_RULE_NAMESZ];
	uint32_t		num_servers;
	ilb_server_arg_t	servers[1];
} ilb_servers_cmd_t;

/*
 * Flags for listing NAT/persistence table entries
 *
 * ILB_LIST_BEGIN: start from the beginning of the table
 * ILB_LIST_CONT: start from the last reply
 * ILB_LIST_END: on return, this flag indicates the end of the table
 */
#define	ILB_LIST_BEGIN	0x1
#define	ILB_LIST_CONT	0x2
#define	ILB_LIST_END	0x4

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif

typedef struct {
	uint32_t	proto;

	in6_addr_t	in_local;
	in6_addr_t	in_global;
	in6_addr_t	out_local;
	in6_addr_t	out_global;

	in_port_t	in_local_port;
	in_port_t	in_global_port;
	in_port_t	out_local_port;
	in_port_t	out_global_port;

	int64_t		create_time;
	int64_t		last_access_time;
	uint64_t	pkt_cnt;
} ilb_nat_entry_t;

/* List NAT table entries command struct */
typedef struct {
	ilb_cmd_t	cmd;
	uint32_t	flags;
	uint32_t	num_nat;
	ilb_nat_entry_t	entries[1];
} ilb_list_nat_cmd_t;

typedef struct {
	char		rule_name[ILB_RULE_NAMESZ];
	in6_addr_t	req_addr;
	in6_addr_t	srv_addr;
	int64_t		expiry_time;
} ilb_sticky_entry_t;

/* List sticky table entries command struct */
typedef struct {
	ilb_cmd_t		cmd;
	uint32_t		flags;
	uint32_t		num_sticky;
	ilb_sticky_entry_t	entries[1];
} ilb_list_sticky_cmd_t;

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

#ifdef __cplusplus
}
#endif

#endif /* _INET_ILB_H */
