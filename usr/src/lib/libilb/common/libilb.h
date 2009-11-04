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

#ifndef	_LIBILB_H
#define	_LIBILB_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <netinet/in.h>
#include <net/if.h>

/* make sure these values stay in sync with definitions in ilb.h! */
#define	ILB_FLAGS_RULE_ENABLED	0x01
#define	ILB_FLAGS_RULE_STICKY	0x02
#define	ILB_FLAGS_RULE_ALLRULES	0x04
#define	ILB_FLAGS_RESERVED	0x08	/* in use by kernel, don't overlay */

/*
 * information whether we're interested in names or numerical information
 */
#define	ILB_FLAGS_SRV_HOSTNAME	0x01	/* a servers hostname was given */
#define	ILB_FLAGS_SRV_PORTNAME	0x02	/* a port was spec'd by name */

/*
 * server status information
 */
#define	ILB_FLAGS_SRV_ENABLED	0x10

/*
 * macros to determine, and for some cases, set status of server
 */
#define	ILB_IS_SRV_ENABLED(f)		\
	((f & ILB_FLAGS_SRV_ENABLED) == ILB_FLAGS_SRV_ENABLED)
#define	ILB_IS_SRV_DISABLED(f)	((f & ILB_FLAGS_SRV_ENABLED) == 0)

#define	ILB_SET_ENABLED(f)	(f |= ILB_FLAGS_SRV_ENABLED)
#define	ILB_SET_DISABLED(f)	(f &= ~ILB_FLAGS_SRV_ENABLED)

#define	MAX_IP_SPREAD	0xff	/* largest ip addr. range */

#define	ILB_HC_STR_UDP	"udp"
#define	ILB_HC_STR_TCP	"tcp"
#define	ILB_HC_STR_PING	"ping"

#define	ILB_NAMESZ	20	/* keep in sync with kernel definition */
#define	ILB_SGNAME_SZ	(ILB_NAMESZ - 5) /* 3 numeric digits, "." and "_" */

#define	ILB_SRVID_PREFIX  '_'	/* a valid serverID starts with this */

/* producers of these statuses are libilb and ilbd functions */
typedef enum {
	ILB_STATUS_OK = 0,
	ILB_STATUS_INTERNAL,	/* an error internal to the library */
	ILB_STATUS_EINVAL,	/* invalid argument(s) */
	ILB_STATUS_ENOMEM,	/* not enough memory for operation */
	ILB_STATUS_ENOENT,	/* no such/no more element(s) */
	ILB_STATUS_SOCKET,	/* socket related failure */
	ILB_STATUS_READ,	/* read related failure */
	ILB_STATUS_WRITE,	/* write related failure */
	ILB_STATUS_TIMER,	/* healthcheck timer error */
	ILB_STATUS_INUSE,	/* item in use, cannot delete */
	ILB_STATUS_EEXIST,	/* scf item exist */
	ILB_STATUS_PERMIT,	/* no scf permit */
	ILB_STATUS_CALLBACK,	/* scf callback error */
	ILB_STATUS_EWOULDBLOCK,	/* operation is blocked - no error string */
	ILB_STATUS_INPROGRESS,	/* operation already in progress */
	ILB_STATUS_SEND,	/* send related failure */
	ILB_STATUS_GENERIC,	/* generic failure  - no error string */
	ILB_STATUS_ENOHCINFO,   /* missing healthcheck info */
	ILB_STATUS_INVAL_HCTESTTYPE,	/* invalid  health check */
	ILB_STATUS_INVAL_CMD, 	/* unknown command */
	ILB_STATUS_DUP_RULE,	/* rule name exists */
	ILB_STATUS_ENORULE,	/* rule does not exist */
	ILB_STATUS_MISMATCHSG,	/* addr family mismatch with sgroup */
	ILB_STATUS_MISMATCHH,	/* addr family mismatch with hosts/rule */
	ILB_STATUS_SGUNAVAIL,	/* cannot find sgroup in sggroup list */
	ILB_STATUS_SGINUSE,	/* server is un use, cannot remove */
	ILB_STATUS_SGEXISTS,	/* server exists */
	ILB_STATUS_SGFULL,   	/* cannot add any more servers */
	ILB_STATUS_SGEMPTY,  	/* sgroup is empty */
	ILB_STATUS_NAMETOOLONG,	/* a name is longer than allowed */
	ILB_STATUS_CFGAUTH,	/* config authoriz denied -no error string */
	ILB_STATUS_CFGUPDATE,	/* failed to update config! */
	ILB_STATUS_BADSG,	/* rules port range size does not match */
				/* that of the servers  */
	ILB_STATUS_INVAL_SRVR,   /* server port is incompatible with */
				/* rule port */
	ILB_STATUS_INVAL_ENBSRVR,   /* server  cannot be enabled since it's */
				    /* not being used by a rule */
	ILB_STATUS_BADPORT,	/* rules port value does not match */
				/* server's */
	ILB_STATUS_SRVUNAVAIL,	/* cannot find specified server */
	ILB_STATUS_RULE_NO_HC,	/* rule does not have hc info */
	ILB_STATUS_RULE_HC_MISMATCH,	/* rule and hc object mismatch */
	ILB_STATUS_HANDLE_CLOSING	/* library handle is being closed */
} ilb_status_t;

typedef struct {
	int32_t		ia_af;		/* AF_INET or AF_INET6 */
	union {
		struct in_addr	v4;	/* network byte order */
		struct in6_addr	v6;	/* network byte order */
	} _au;
#define	ia_v4	_au.v4
#define	ia_v6	_au.v6
} ilb_ip_addr_t;

/* Supported load balancing algorithm type */
typedef enum {
	ILB_ALG_ROUNDROBIN = 1,
	ILB_ALG_HASH_IP,
	ILB_ALG_HASH_IP_SPORT,
	ILB_ALG_HASH_IP_VIP
} ilb_algo_t;

/* Supported load balancing method */
typedef enum {
	ILB_TOPO_DSR = 1,
	ILB_TOPO_NAT,
	ILB_TOPO_HALF_NAT
} ilb_topo_t;

#define	ILB_INVALID_HANDLE ((void *) NULL)

/*
 * note: pointer to a non-existant struct
 */
typedef struct ilb_handle *ilb_handle_t;

/*
 * Health check related information
 */

/* HC state of a server */
typedef enum {
	ILB_HCS_UNINIT = -1,	/* Uninitialized */
	ILB_HCS_UNREACH = 0,	/* Unreachable, ping fails */
	ILB_HCS_ALIVE,		/* Probe succeeds */
	ILB_HCS_DEAD,		/* Probe fails */
	ILB_HCS_DISABLED	/* Server is disabled */
} ilb_hc_srv_status_t;

/*
 * Struct representing a server in a hc object
 *
 * hcs_rule_name: rule using this server
 * hcs_ID: server ID
 * hcs_hc_name: hc object this server is associated with
 * hcs_IP: IP address of the server
 * hcs_fail_cnt: number of fail hc probe
 * hcs_status: hc status of the server
 * hcs_rtt: (in microsec) smoothed average RTT to the server
 * hcs_lasttime: last time hc test was done (as returned by time(2))
 * hcs_nexttime: next time hc test will be done (as returned by (time(2))
 */
typedef struct {
	char		hcs_rule_name[ILB_NAMESZ];
	char		hcs_ID[ILB_NAMESZ];
	char		hcs_hc_name[ILB_NAMESZ];
	struct in6_addr hcs_IP;
	uint32_t	hcs_fail_cnt;
	ilb_hc_srv_status_t	hcs_status;
	uint32_t	hcs_rtt;
	time_t		hcs_lasttime;
	time_t		hcs_nexttime;
} ilb_hc_srv_t;

/* Probe flags to be used in r_hcpflag in struct rule data. */
typedef enum {
	ILB_HCI_PROBE_ANY = 0,	/* Probe any port in the server port range */
	ILB_HCI_PROBE_FIX	/* Probe a fixed port */
} ilb_hcp_flags_t;

/*
 * Struct representing a hc object
 *
 * hci_name: name of the hc object
 * hci_test: hc test to be done, TCP, UDP, or user supplied path name
 * hci_timeout: (in sec) test time out
 * hci_interval: (in sec) test execution interval
 * hci_def_ping: true if default ping is done; false otherwise
 */
typedef struct {
	char		hci_name[ILB_NAMESZ];
	char		hci_test[MAXPATHLEN];
	int32_t		hci_timeout;
	int32_t		hci_count;
	int32_t		hci_interval;
	boolean_t	hci_def_ping;
} ilb_hc_info_t;

typedef struct rule_data {
	char		r_name[ILB_NAMESZ]; 	/* name of this rule */
	int32_t		r_flags;	/* opt: ILB_FLAGS_RULE_ENABLED etc. */
	ilb_ip_addr_t	r_vip;		/* vip, required for rule creation */
	uint16_t	r_proto;	/* protocol (tcp, udp) */
	in_port_t	r_minport;	/* port this rule refers to */
	in_port_t	r_maxport;	/* if != 0, defines port range */
	ilb_algo_t	r_algo;		/* round-robin, hash-ip, etc. */
	ilb_topo_t	r_topo;		/* dsr, NAT, etc */
	ilb_ip_addr_t	r_nat_src_start; /* required for NAT */
	ilb_ip_addr_t	r_nat_src_end;	/* required for NAT */
	ilb_ip_addr_t	r_stickymask;	/* netmask for persistence */
	uint32_t	r_conndrain;	/* opt: time for conn. draining (s) */
	uint32_t	r_nat_timeout;	/* opt: timeout for nat connections */
	uint32_t	r_sticky_timeout; /* opt: timeout for persistence */
	ilb_hcp_flags_t	r_hcpflag;	/* HC port flag */
	in_port_t	r_hcport;	/* opt with HC */
	char		r_sgname[ILB_SGNAME_SZ]; /* this rule's server grp. */
	char		r_hcname[ILB_NAMESZ];	/* HC name: optional */
} ilb_rule_data_t;

/* not all fields are valid in all calls where this is used */
typedef struct server_data {
	ilb_ip_addr_t	sd_addr;	/* a server's ip address */
	in_port_t	sd_minport;	/* port information */
	in_port_t	sd_maxport;	/* ... if != 0, defines a port range */
	uint32_t	sd_flags;	/* enabled, dis- */
	char 		sd_srvID[ILB_NAMESZ];	/* "name" for server */
					/* assigned by system, not user */
} ilb_server_data_t;

/*
 * Struct to represent a server group.
 *
 * sgd_name: server group name
 * sgd_flags: flags
 * sgd_srvcount: number of servers in the group (not used in sever group
 *               creation); filled in when used by call back function for
 *               ilb_walk_servergroups().
 */
typedef struct sg_data {
	char		sgd_name[ILB_SGNAME_SZ];
	int32_t		sgd_flags;
	int32_t		sgd_srvcount;
} ilb_sg_data_t;

/*
 * Struct to represent a NAT entry in kernel.
 *
 * nat_proto: transport protocol used in this NAT entry
 *
 * nat_out_global: IP address of client's request
 * nat_out_global_port: port number of client's request
 * nat_in_global: VIP of a rule for the NAT entry
 * nat_in_global_port: port of a rule for the NAT entry
 *
 * nat_out_local: half NAT: IP address of client's request
 *                full NAT: NAT'ed IP addres of client' request
 * nat_out_local_port: half NAT: port number of client's request
 *                     full NAT: NAT'ed port number of client's request
 * nat_in_local: IP address of back end server handling this request
 * nat_in_local_port: port number in back end server handling thi request
 *
 * (*) IPv4 address is represented as IPv4 mapped IPv6 address.
 */
typedef struct {
	uint32_t	nat_proto;

	in6_addr_t	nat_in_local;
	in6_addr_t	nat_in_global;
	in6_addr_t	nat_out_local;
	in6_addr_t	nat_out_global;

	in_port_t	nat_in_local_port;
	in_port_t	nat_in_global_port;
	in_port_t	nat_out_local_port;
	in_port_t	nat_out_global_port;
} ilb_nat_info_t;

/*
 * Struct to represet a persistent entry in kernel.
 *
 * rule_name: the name of rule for a persistent entry
 * req_addr: the client's IP address (*)
 * srv_addr: the server's IP address (*) handling the client's request
 *
 * (*) IPv4 address is represented as IPv4 mapped IPv6 address.
 */
typedef struct {
	char		persist_rule_name[ILB_NAMESZ];
	in6_addr_t	persist_req_addr;
	in6_addr_t	persist_srv_addr;
} ilb_persist_info_t;

/*
 * Function prototype of the call back function of those walker functions.
 *
 * Note: the storage of the data item parameter (ilb_sg_data_t/
 * ilb_server_data_/ilb_rule_data_t/ilb_hc_info_t/ilb_hc_srv_t) will be
 * freed after calling the call back function.  If the call back function
 * needs to keep a copy of the data, it must copy the data content.
 */
typedef ilb_status_t	(* sg_walkerfunc_t)(ilb_handle_t, ilb_sg_data_t *,
    void *);
typedef ilb_status_t	(* srv_walkerfunc_t)(ilb_handle_t, ilb_server_data_t *,
    const char *, void *);
typedef ilb_status_t	(* rule_walkerfunc_t)(ilb_handle_t, ilb_rule_data_t *,
    void *);
typedef ilb_status_t	(* hc_walkerfunc_t)(ilb_handle_t, ilb_hc_info_t *,
    void *);
typedef ilb_status_t	(* hc_srvwalkerfunc_t)(ilb_handle_t, ilb_hc_srv_t *,
    void *);

/*
 * ilb_open creates a session handle that every caller into
 * libilb needs to use
 */
ilb_status_t	ilb_open(ilb_handle_t *);

/*
 * relinquish the session handle
 */
ilb_status_t	ilb_close(ilb_handle_t);

/* support and general functions */
ilb_status_t	ilb_reset_config(ilb_handle_t);
const char	*ilb_errstr(ilb_status_t);

/* rule-related functions */
ilb_status_t	ilb_create_rule(ilb_handle_t, const ilb_rule_data_t *);
ilb_status_t	ilb_destroy_rule(ilb_handle_t, const char *);
ilb_status_t	ilb_disable_rule(ilb_handle_t, const char *);
ilb_status_t	ilb_enable_rule(ilb_handle_t, const char *);
ilb_status_t	ilb_walk_rules(ilb_handle_t, rule_walkerfunc_t, const char *,
    void *);

/* servergroup functionality */
ilb_status_t	ilb_create_servergroup(ilb_handle_t, const char *);
ilb_status_t	ilb_destroy_servergroup(ilb_handle_t, const char *);
ilb_status_t	ilb_add_server_to_group(ilb_handle_t, const char *,
    ilb_server_data_t *);
ilb_status_t	ilb_rem_server_from_group(ilb_handle_t, const char *,
    ilb_server_data_t *);
ilb_status_t	ilb_walk_servergroups(ilb_handle_t, sg_walkerfunc_t,
    const char *, void *);
ilb_status_t	ilb_walk_servers(ilb_handle_t, srv_walkerfunc_t,
    const char *, void *);

/* functions for individual servers */
ilb_status_t	ilb_enable_server(ilb_handle_t, ilb_server_data_t *, void *);
ilb_status_t	ilb_disable_server(ilb_handle_t, ilb_server_data_t *, void *);
ilb_status_t	ilb_srvID_to_address(ilb_handle_t, ilb_server_data_t *,
    const char *);
ilb_status_t	ilb_address_to_srvID(ilb_handle_t, ilb_server_data_t *,
    const char *);

/* health check-related functions */
ilb_status_t	ilb_create_hc(ilb_handle_t, const ilb_hc_info_t *);
ilb_status_t	ilb_destroy_hc(ilb_handle_t, const char *);
ilb_status_t	ilb_get_hc_info(ilb_handle_t, const char *, ilb_hc_info_t *);
ilb_status_t	ilb_walk_hc(ilb_handle_t, hc_walkerfunc_t, void *);
ilb_status_t	ilb_walk_hc_srvs(ilb_handle_t, hc_srvwalkerfunc_t,
    const char *, void *);

/* To show NAT table entries of ILB */
ilb_status_t	ilb_show_nat(ilb_handle_t, ilb_nat_info_t[], size_t *,
    boolean_t *);

/* To show persistent table entries of ILB */
ilb_status_t	ilb_show_persist(ilb_handle_t, ilb_persist_info_t[], size_t *,
    boolean_t *);

/* PRIVATE */
int ilb_cmp_ipaddr(ilb_ip_addr_t *, ilb_ip_addr_t *, int64_t *);
int ilb_cmp_in6_addr(struct in6_addr *, struct in6_addr *, int64_t *);

#ifdef __cplusplus
}
#endif

#endif /* _LIBILB_H */
