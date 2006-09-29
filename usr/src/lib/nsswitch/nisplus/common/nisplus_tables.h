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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *	nisplus_tables.h
 */

#ifndef	_NISPLUS_TABLES_H
#define	_NISPLUS_TABLES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	PW_TBLNAME		"passwd"
#define	PW_TYP			"passwd_tbl"
#define	PW_NDX_NAME		0
#define	PW_TAG_NAME		"name"
#define	PW_NDX_PASSWD		1
#define	PW_TAG_PASSWD		"passwd"
#define	PW_NDX_UID		2
#define	PW_TAG_UID		"uid"
#define	PW_NDX_GID		3
#define	PW_TAG_GID		"gid"
#define	PW_NDX_GCOS		4
#define	PW_TAG_GCOS		"gcos"
#define	PW_NDX_HOME		5
#define	PW_TAG_HOME		"home"
#define	PW_NDX_SHELL		6
#define	PW_TAG_SHELL		"shell"
#define	PW_NDX_SHADOW		7
#define	PW_TAG_SHADOW		"shadow"
#define	PW_COL			8

#define	GR_TBLNAME		"group"
#define	GR_TYP			"group_tbl"
#define	GR_NDX_NAME		0
#define	GR_TAG_NAME		"name"
#define	GR_NDX_PASSWD		1
#define	GR_TAG_PASSWD		"passwd"
#define	GR_NDX_GID		2
#define	GR_TAG_GID		"gid"
#define	GR_NDX_MEM		3
#define	GR_TAG_MEM		"members"
#define	GR_COL			4

#define	HOST_TBLNAME		"hosts"
#define	IPNODES_TBLNAME		"ipnodes"
#define	HOST_TYP		"hosts_tbl"
#define	HOST_NDX_CNAME		0
#define	HOST_TAG_CNAME		"cname"
#define	HOST_NDX_NAME		1
#define	HOST_TAG_NAME		"name"
#define	HOST_NDX_ADDR		2
#define	HOST_TAG_ADDR		"addr"
#define	HOST_NDX_COMMENT	3
#define	HOST_TAG_COMMENT	"comment"
#define	HOST_COL		4

#define	NET_TBLNAME		"networks"
#define	NET_TYP			"networks_tbl"
#define	NET_NDX_CNAME		0
#define	NET_TAG_CNAME		"cname"
#define	NET_NDX_NAME		1
#define	NET_TAG_NAME		"name"
#define	NET_NDX_ADDR		2
#define	NET_TAG_ADDR		"addr"
#define	NET_NDX_COMMENT		3
#define	NET_TAG_COMMENT		"comment"
#define	NET_COL			4

#define	PROTO_TBLNAME		"protocols"
#define	PROTO_TYP		"protocols_tbl"
#define	PROTO_NDX_CNAME		0
#define	PROTO_TAG_CNAME		"cname"
#define	PROTO_NDX_NAME		1
#define	PROTO_TAG_NAME		"name"
#define	PROTO_NDX_NUMBER	2
#define	PROTO_TAG_NUMBER	"number"
#define	PROTO_NDX_COMMENT	3
#define	PROTO_TAG_COMMENT	"comment"
#define	PROTO_COL		4

#define	RPC_TBLNAME		"rpc"
#define	RPC_TYP			"rpc_tbl"
#define	RPC_NDX_CNAME		0
#define	RPC_TAG_CNAME		"cname"
#define	RPC_NDX_NAME		1
#define	RPC_TAG_NAME		"name"
#define	RPC_NDX_NUMBER		2
#define	RPC_TAG_NUMBER		"number"
#define	RPC_NDX_COMMENT		3
#define	RPC_TAG_COMMENT		"comment"
#define	RPC_COL			4

#define	SERV_TBLNAME		"services"
#define	SERV_TYP		"services_tbl"
#define	SERV_NDX_CNAME		0
#define	SERV_TAG_CNAME		"cname"
#define	SERV_NDX_NAME		1
#define	SERV_TAG_NAME		"name"
#define	SERV_NDX_PROTO		2
#define	SERV_TAG_PROTO		"proto"
#define	SERV_NDX_PORT		3
#define	SERV_TAG_PORT		"port"
#define	SERV_NDX_COMMENT	4
#define	SERV_TAG_COMMENT	"comment"
#define	SERV_COL		5

/* common for hosts, networks, services, protocols, rpc */
#define	NETDB_COL		4
#define	NETDB_NDX_CNAME		0
#define	NETDB_NDX_NAME		1

#define	ETHER_TBLNAME		"ethers"
#define	ETHER_TYP		"ethers_tbl"
#define	ETHER_NDX_ADDR		0
#define	ETHER_TAG_ADDR		"addr"
#define	ETHER_NDX_NAME		1
#define	ETHER_TAG_NAME		"name"
#define	ETHER_NDX_COMMENT	2
#define	ETHER_TAG_COMMENT	"comment"
#define	ETHER_COL		3

/*
 * One way to implement netgroups.  This has the same contents as the YP
 *   'netgroup' map, but we represent each netgroup member as a separate
 *   entry.  Netgroup members may be either (host, user, domain) triples or
 *   recursive references to other netgroups;  we use separate (and
 *   mutually exclusive) columns to represent the two sorts of members.
 */
#define	NETGR_TBLNAME		"netgroup"
#define	NETGR_TYP		"netgroup_tbl"
#define	NETGR_NDX_NAME		0
#define	NETGR_TAG_NAME		"name"
#define	NETGR_NDX_GROUP		1
#define	NETGR_TAG_GROUP		"group"
#define	NETGR_NDX_HOST		2
#define	NETGR_TAG_HOST		"host"
#define	NETGR_NDX_USER		3
#define	NETGR_TAG_USER		"user"
#define	NETGR_NDX_DOMAIN	4
#define	NETGR_TAG_DOMAIN	"domain"
#define	NETGR_NDX_COMMENT	5
#define	NETGR_TAG_COMMENT	"comment"
#define	NETGR_COL		6

#define	BOOTPARAM_TBLNAME	"bootparams"
#define	BOOTPARAM_TYP		"bootparams_tbl"
#define	BOOTPARAM_NDX_KEY	0
#define	BOOTPARAM_TAG_KEY	"key"
#define	BOOTPARAM_NDX_DATUM	1
#define	BOOTPARAM_TAG_DATUM	"datum"
#define	BOOTPARAM_COL		2


#define	PRINTERS_TBLNAME	"printers"
#define	PRINTERS_TYP		"printers_tbl"
#define	PRINTERS_NDX_KEY	0
#define	PRINTERS_TAG_KEY	"key"
#define	PRINTERS_NDX_DATUM	1
#define	PRINTERS_TAG_DATUM	"datum"
#define	PRINTERS_COL		2

/* According to Mukesh: */

/*
 * netmasks stuff implemented in /usr/src/cmd/cmd-inet/usr.sbin/ifconfig using
 * statically linked backends because diskless booting requirements do not
 * permit using dlopen() stuff
 */
#define	NETMASK_TBLNAME		"netmasks"
#define	NETMASK_TYP		"netmasks_tbl"
#define	NETMASK_NDX_ADDR	0
#define	NETMASK_TAG_ADDR	"addr"
#define	NETMASK_NDX_MASK	1
#define	NETMASK_TAG_MASK	"mask"
#define	NETMASK_NDX_COMMENT	2
#define	NETMASK_TAG_COMMENT	"comment"
#define	NETMASK_COL		3

/*
 * The cred table holds different types of data depending on the value
 * of the auth_type field, hence the overlapping NDX values.
 */
#define	CRED_TBLNAME		"cred"
#define	CRED_TYPE		"cred_tbl"
#define	CRED_NDX_CNAME		0
#define	CRED_TAG_CNAME		"cname"
#define	CRED_NDX_AUTHTYPE	1
#define	CRED_TAG_AUTHTYPE	"auth_type"
#define	CRED_NDX_AUTHNAME	2
#define	CRED_TAG_AUTHNAME	"auth_name"
/* DES Credentials or other creds with public/private pair */
#define	CRED_NDX_PUBLICDATA	3
#define	CRED_TAG_PUBLICDATA	"public_data"
#define	CRED_NDX_PRIVATEDATA	4
#define	CRED_TAG_PRIVATEDATA	"private_data"
/* LOCAL cred - aka netid */
#define	CRED_NDX_GROUPLIST	3
#define	CRED_TAG_GROUPLIST	"public_data"

#define	AUDITUSER_TBLNAME		"audit_user"
#define	AUDITUSER_TYPE			"audit_user_tbl"
#define	AUDITUSER_NDX_NAME		0
#define	AUDITUSER_TAG_NAME		"name"
#define	AUDITUSER_NDX_ALWAYS		1
#define	AUDITUSER_TAG_ALWAYS		"always"
#define	AUDITUSER_NDX_NEVER		2
#define	AUDITUSER_TAG_NEVER		"never"
#define	AUDITUSER_COL			3

#define	AUTHATTR_TBLNAME		"auth_attr"
#define	AUTHATTR_TYPE			"auth_attr_tbl"
#define	AUTHATTR_NDX_NAME		0
#define	AUTHATTR_TAG_NAME		"name"
#define	AUTHATTR_NDX_RES1		1
#define	AUTHATTR_TAG_RES1		"res1"
#define	AUTHATTR_NDX_RES2		2
#define	AUTHATTR_TAG_RES2		"res2"
#define	AUTHATTR_NDX_SHORTDESC		3
#define	AUTHATTR_TAG_SHORTDESC		"short_desc"
#define	AUTHATTR_NDX_LONGDESC		4
#define	AUTHATTR_TAG_LONGDESC		"long_desc"
#define	AUTHATTR_NDX_ATTR		5
#define	AUTHATTR_TAG_ATTR		"attr"
#define	AUTHATTR_COL			6

#define	EXECATTR_TBLNAME		"exec_attr"
#define	EXECATTR_TYPE			"exec_attr_tbl"
#define	EXECATTR_NDX_NAME		0
#define	EXECATTR_TAG_NAME		"name"
#define	EXECATTR_NDX_POLICY		1
#define	EXECATTR_TAG_POLICY		"policy"
#define	EXECATTR_NDX_TYPE		2
#define	EXECATTR_TAG_TYPE		"type"
#define	EXECATTR_NDX_RES1		3
#define	EXECATTR_TAG_RES1		"res1"
#define	EXECATTR_NDX_RES2		4
#define	EXECATTR_TAG_RES2		"res2"
#define	EXECATTR_NDX_ID			5
#define	EXECATTR_TAG_ID			"id"
#define	EXECATTR_NDX_ATTR		6
#define	EXECATTR_TAG_ATTR		"attr"
#define	EXECATTR_COL			7

#define	PROFATTR_TBLNAME		"prof_attr"
#define	PROFATTR_TYPE			"prof_attr_tbl"
#define	PROFATTR_NDX_NAME		0
#define	PROFATTR_TAG_NAME		"name"
#define	PROFATTR_NDX_RES1		1
#define	PROFATTR_TAG_RES1		"res1"
#define	PROFATTR_NDX_RES2		2
#define	PROFATTR_TAG_RES2		"res2"
#define	PROFATTR_NDX_DESC		3
#define	PROFATTR_TAG_DESC		"desc"
#define	PROFATTR_NDX_ATTR		4
#define	PROFATTR_TAG_ATTR		"attr"
#define	PROFATTR_COL			5

#define	USERATTR_TBLNAME		"user_attr"
#define	USERATTR_TYPE			"user_attr_tbl"
#define	USERATTR_NDX_NAME		0
#define	USERATTR_TAG_NAME		"name"
#define	USERATTR_NDX_QUALIFIER		1
#define	USERATTR_TAG_QUALIFIER		"qualifier"
#define	USERATTR_NDX_RES1		2
#define	USERATTR_TAG_RES1		"res1"
#define	USERATTR_NDX_RES2		3
#define	USERATTR_TAG_RES2		"res2"
#define	USERATTR_NDX_ATTR		4
#define	USERATTR_TAG_ATTR		"attr"
#define	USERATTR_COL			5


/* macros to get values out of NIS+ entry objects */
#define	EC_LEN(ecp, ndx)		((ecp)[ndx].ec_value.ec_value_len)
#define	EC_VAL(ecp, ndx)		((ecp)[ndx].ec_value.ec_value_val)
#define	EC_SET(ecp, ndx, l, v) \
		((l) = EC_LEN(ecp, ndx), (v) = EC_VAL(ecp, ndx))

#define	__NISPLUS_GETCOL_OR_EMPTY(ecp, ndx, l, v) \
	EC_SET(ecp, ndx, l, v);\
	if (l < 2) {\
		(v) = "";\
		(l) = 1;\
	} else {\
		l--;\
	}

#define	__NISPLUS_GETCOL_OR_RETURN(ecp, ndx, l, v) \
	EC_SET(ecp, ndx, l, v);\
	if (l < 2) {\
		return (NSS_STR_PARSE_PARSE);\
	} else {\
		l--;\
	}

#define	__NISPLUS_GETCOL_OR_CONTINUE(ecp, ndx, l, v) \
	EC_SET(ecp, ndx, l, v);\
	if (l < 2) {\
		continue;\
	} else {\
		l--;\
	}
#ifdef	__cplusplus
}
#endif

#endif	/* _NISPLUS_TABLES_H */
