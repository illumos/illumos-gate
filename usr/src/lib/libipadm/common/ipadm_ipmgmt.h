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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2016, Chris Fraire <cfraire@me.com>.
 */

#ifndef _IPADM_IPMGMT_H
#define	_IPADM_IPMGMT_H

#ifdef	__cplusplus
extern "C" {
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <door.h>
#include <libipadm.h>
#include <inet/tunables.h>

/*
 * Function declarations and data structures shared by libipadm.so and
 * the IP management daemon.
 */

/* Authorization required to configure network interfaces */
#define	NETWORK_INTERFACE_CONFIG_AUTH	"solaris.network.interface.config"

/*
 * Data store read/write utilities related declarations.
 */
/*
 * For more information on these definitions please refer to the top of
 * ipadm_persist.c. These are the name of the nvpairs which hold the
 * respective values. All nvpairs private to ipadm have names that begin
 * with "_". Note below that 'prefixlen' and 'reqhost' are address
 * properties and therefore not a private nvpair name.
 */
#define	IPADM_NVP_PROTONAME	"_protocol"	/* protocol name */
#define	IPADM_NVP_IFNAME	"_ifname"	/* interface name */
#define	IPADM_NVP_AOBJNAME	"_aobjname"	/* addrobj name */
#define	IPADM_NVP_FAMILY	"_family"	/* address family */
#define	IPADM_NVP_IPV4ADDR	"_ipv4addr"	/* name of IPv4 addr nvlist */
#define	IPADM_NVP_IPNUMADDR	"_addr"		/* local address */
#define	IPADM_NVP_IPADDRHNAME	"_aname"	/* local hostname */
#define	IPADM_NVP_IPDADDRHNAME	"_dname"	/* remote hostname */
#define	IPADM_NVP_PREFIXLEN	"prefixlen"	/* prefixlen */
#define	IPADM_NVP_REQHOST	"reqhost"	/* requested hostname */
#define	IPADM_NVP_IPV6ADDR	"_ipv6addr"	/* name of IPv6 addr nvlist */
#define	IPADM_NVP_DHCP		"_dhcp"		/* name of DHCP nvlist */
#define	IPADM_NVP_WAIT		"_wait"		/* DHCP timeout value */
#define	IPADM_NVP_PRIMARY	"_primary"	/* DHCP primary interface */
#define	IPADM_NVP_LIFNUM	"_lifnum"	/* logical interface number */
#define	IPADM_NVP_INTFID	"_intfid"	/* name of IPv6 intfid nvlist */
#define	IPADM_NVP_STATELESS	"_stateless"	/* IPv6 autoconf stateless */
#define	IPADM_NVP_STATEFUL	"_stateful"	/* IPv6 autoconf dhcpv6 */

#define	IPADM_PRIV_NVP(s) ((s)[0] == '_' && (s)[1] != '_')

/*
 * All protocol properties that are private to ipadm are stored in the
 * ipadm datastore with "__" as prefix. This is to ensure there
 * is no collision of namespace between ipadm private nvpair names and
 * the private protocol property names.
 */
#define	IPADM_PERSIST_PRIVPROP_PREFIX	"__"

/* data-store operations */
typedef enum {
	IPADM_DB_WRITE = 0,	/* Writes to DB */
	IPADM_DB_DELETE,	/* Deletes an entry from DB */
	IPADM_DB_READ		/* Read from DB */
} ipadm_db_op_t;

/*
 * callback arg used by db_wfunc_t that writes to DB. The contents to be
 * written to DB are captured in `dbw_nvl'.
 */
typedef	struct	ipadm_dbwrite_cbarg_s {
	nvlist_t	*dbw_nvl;
	uint_t		dbw_flags;
} ipadm_dbwrite_cbarg_t;

/*
 * door related function declarations and data structures.
 */

/* The door file for the ipmgmt (ip-interface management) daemon */
#define	IPMGMT_DOOR		"/etc/svc/volatile/ipadm/ipmgmt_door"
#define	MAXPROTONAMELEN		32

/* door call command type */
typedef enum {
	IPMGMT_CMD_SETPROP = 1,		/* persist property */
	IPMGMT_CMD_SETIF,		/* persist interface */
	IPMGMT_CMD_SETADDR,		/* persist address */
	IPMGMT_CMD_GETPROP,		/* retrieve persisted property value */
	IPMGMT_CMD_GETIF,		/* retrieve persisted interface conf. */
	IPMGMT_CMD_GETADDR,		/* retrieve persisted addresses */
	IPMGMT_CMD_RESETIF,		/* purge interface configuration */
	IPMGMT_CMD_RESETADDR,		/* purge address configuration */
	IPMGMT_CMD_RESETPROP,		/* purge property configuration */
	IPMGMT_CMD_INITIF,		/* retrieve interfaces to initialize */
	IPMGMT_CMD_ADDROBJ_LOOKUPADD,	/* addr. object lookup & add */
	IPMGMT_CMD_ADDROBJ_SETLIFNUM,	/* set lifnum on the addrobj */
	IPMGMT_CMD_ADDROBJ_ADD,		/* add addr. object to addrobj map */
	IPMGMT_CMD_LIF2ADDROBJ,		/* lifname to addrobj mapping */
	IPMGMT_CMD_AOBJNAME2ADDROBJ	/* aobjname to addrobj mapping */
} ipmgmt_door_cmd_type_t;

/*
 * Note: We need to keep the size of the structure the same on amd64 and i386
 * for all door_call arguments and door_return structures.
 */
/* door_call argument */
typedef struct ipmgmt_arg {
	ipmgmt_door_cmd_type_t	ia_cmd;
} ipmgmt_arg_t;

/* IPMGMT_CMD_{SETPROP|GETPROP|RESETPROP} door_call argument */
typedef struct ipmgmt_prop_arg_s {
	ipmgmt_door_cmd_type_t	ia_cmd;
	uint32_t		ia_flags;
	char			ia_ifname[LIFNAMSIZ];
	char			ia_aobjname[IPADM_AOBJSIZ];
	char			ia_module[MAXPROTONAMELEN];
	char			ia_pname[MAXPROPNAMELEN];
	char			ia_pval[MAXPROPVALLEN];
} ipmgmt_prop_arg_t;
/*
 * ia_flags used in ipmgmt_prop_arg_t.
 *	- APPEND updates the multi-valued property entry with a new value
 *	- REDUCE updates the multi-valued property entry by removing a value
 */
#define	IPMGMT_APPEND	0x00000001
#define	IPMGMT_REMOVE	0x00000002

/*
 * ipadm_addr_type_t-specific values that are cached in ipmgmtd and can
 * make a round-trip back to client programs
 */
typedef union {
	struct {
		boolean_t		ipmgmt_linklocal;
		struct sockaddr_in6		ipmgmt_ifid;
	} ipmgmt_ipv6_cache_s;
	struct {
		char			ipmgmt_reqhost[MAXNAMELEN];
	} ipmgmt_dhcp_cache_s;
} ipmgmt_addr_type_cache_u;

/* IPMGMT_CMD_GETIF door_call argument structure */
typedef struct ipmgmt_getif_arg_s {
	ipmgmt_door_cmd_type_t	ia_cmd;
	uint32_t	ia_flags;
	char		ia_ifname[LIFNAMSIZ];
} ipmgmt_getif_arg_t;

/* IPMGMT_CMD_RESETIF, IPMGMT_CMD_SETIF door_call argument structure */
typedef struct ipmgmt_if_arg_s {
	ipmgmt_door_cmd_type_t	ia_cmd;
	uint32_t		ia_flags;
	char			ia_ifname[LIFNAMSIZ];
	sa_family_t		ia_family;
} ipmgmt_if_arg_t;

/* IPMGMT_CMD_INITIF door_call argument structure */
typedef struct ipmgmt_initif_arg_s {
	ipmgmt_door_cmd_type_t	ia_cmd;
	uint32_t	ia_flags;
	sa_family_t	ia_family;
	size_t		ia_nvlsize;
	/* packed nvl follows */
} ipmgmt_initif_arg_t;

/* IPMGMT_CMD_SETADDR door_call argument */
typedef struct ipmgmt_setaddr_arg_s {
	ipmgmt_door_cmd_type_t	ia_cmd;
	uint32_t		ia_flags;
	size_t			ia_nvlsize;
	/* packed nvl follows */
} ipmgmt_setaddr_arg_t;

/* IPMGMT_CMD_GETADDR door_call argument */
typedef struct ipmgmt_getaddr_arg_s {
	ipmgmt_door_cmd_type_t	ia_cmd;
	uint32_t	ia_flags;
	char		ia_ifname[LIFNAMSIZ];
	sa_family_t	ia_family;
	char		ia_aobjname[IPADM_AOBJSIZ];
} ipmgmt_getaddr_arg_t;

/* IPMGMT_CMD_RESETADDR door_call argument */
typedef struct ipmgmt_addr_arg_s {
	ipmgmt_door_cmd_type_t	ia_cmd;
	uint32_t	ia_flags;
	char		ia_aobjname[IPADM_AOBJSIZ];
	int32_t		ia_lnum;
} ipmgmt_addr_arg_t;

/*
 * IPMGMT_CMD_{ADDROBJ_ADD|ADDROBJ_LOOKUPADD|LIFNUM2ADDROBJ|
 * ADDROBJ2LIFNUM} door_call argument.
 */
typedef struct ipmgmt_aobjop_arg_s {
	ipmgmt_door_cmd_type_t	ia_cmd;
	uint32_t		ia_flags;
	char			ia_aobjname[IPADM_AOBJSIZ];
	char			ia_ifname[LIFNAMSIZ];
	int32_t			ia_lnum;
	sa_family_t		ia_family;
	ipadm_addr_type_t	ia_atype;
} ipmgmt_aobjop_arg_t;

/*
 * ia_flags used inside the arguments for interface/address commands
 *	- ACTIVE updates the running configuration
 *	- PERSIST updates the permanent data store
 *	- INIT	indicates that operation being performed is under init
 *		    context
 *	- PROPS_ONLY indicates the update changes the running configuration of
 *		    "props" data on the interface/address object. The props are
 *		    cached there on the parent, so a PROPS_ONLY change does not
 *		    affect the ACTIVE/PERSIST state of the parent.
 */
#define	IPMGMT_ACTIVE		0x00000001
#define	IPMGMT_PERSIST		0x00000002
#define	IPMGMT_INIT		0x00000004
#define	IPMGMT_PROPS_ONLY		0x00000008

/* door call return value */
typedef struct ipmgmt_retval_s {
	int32_t	ir_err;
} ipmgmt_retval_t;

/* IPMGMT_CMD_GETADDR door_return value */
typedef struct ipmgmt_get_rval_s {
	int32_t		ir_err;
	size_t		ir_nvlsize;
	/* packed nvl follows */
} ipmgmt_get_rval_t;

/* IPMGMT_CMD_GETPROP door_return value */
typedef struct ipmgmt_getprop_rval_s {
	int32_t		ir_err;
	char		ir_pval[MAXPROPVALLEN];
} ipmgmt_getprop_rval_t;

/* IPMGMT_CMD_GETIF door_return value */
typedef struct ipmgmt_getif_rval_s {
	int32_t		ir_err;
	uint32_t	ir_ifcnt;
	ipadm_if_info_t	ir_ifinfo[1];
} ipmgmt_getif_rval_t;

/* IPMGMT_CMD_{LOOKUPADD|LIFNUM2ADDROBJ|ADDROBJ2LIFNUM} door_return value */
typedef struct ipmgmt_aobjop_rval_s {
	int32_t			ir_err;
	char			ir_aobjname[IPADM_AOBJSIZ];
	char			ir_ifname[LIFNAMSIZ];
	int32_t			ir_lnum;
	sa_family_t		ir_family;
	uint32_t		ir_flags;
	ipadm_addr_type_t	ir_atype;
	ipmgmt_addr_type_cache_u	ir_atype_cache;
} ipmgmt_aobjop_rval_t;

#define	ipmgmt_ir_intfid	ir_atype_cache. \
	ipmgmt_ipv6_cache_s.ipmgmt_ifid
#define	ipmgmt_ir_reqhost	ir_atype_cache. \
	ipmgmt_dhcp_cache_s.ipmgmt_reqhost

/* DB walk callback functions */
typedef boolean_t	db_wfunc_t(void *, nvlist_t *, char *, size_t, int *);
extern int		ipadm_rw_db(db_wfunc_t *, void *, const char *, mode_t,
			    ipadm_db_op_t);

/* zone related functions */
/*
 *  callback function to persist an interface in ipmgmtd data store
 */
typedef void (*persist_cb_t)(char *, boolean_t, boolean_t);
/*
 * ipmgmtd/libipadm network initialization interface.
 */
extern ipadm_status_t	ipadm_init_net_from_gz(ipadm_handle_t, char *,
			    persist_cb_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _IPADM_IPMGMT_H */
