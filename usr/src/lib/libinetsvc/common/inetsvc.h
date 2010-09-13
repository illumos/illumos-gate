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

#ifndef _INETSVC_H
#define	_INETSVC_H

#include <libscf.h>
#include <sys/socket.h>
#include <libuutil.h>
#include <rpc/rpc.h>

/*
 * Interfaces shared by usr.lib/inetd and its administrative commands.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#define	PROTO_DELIMITERS		" ,"

#define	INETD_UDS_PATH			"/var/run/.inetd.uds"
#define	INETD_INSTANCE_FMRI		"svc:/network/inetd:default"

#define	PG_NAME_SERVICE_CONFIG		"inetd"
#define	PG_NAME_SERVICE_DEFAULTS	"defaults"
#define	PG_NAME_INETCONV		"inetconv"

#define	PR_SVC_NAME_NAME		"name"
#define	PR_SOCK_TYPE_NAME		"endpoint_type"
#define	PR_PROTO_NAME			"proto"
#define	PR_ISRPC_NAME			"isrpc"
#define	PR_RPC_LW_VER_NAME		"rpc_low_version"
#define	PR_RPC_HI_VER_NAME		"rpc_high_version"
#define	PR_ISWAIT_NAME			"wait"
#define	PR_CON_RATE_MAX_NAME		"max_con_rate"
#define	PR_CON_RATE_OFFLINE_NAME	"con_rate_offline"
#define	PR_BIND_ADDR_NAME		"bind_addr"
#define	PR_BIND_FAIL_MAX_NAME		"bind_fail_max"
#define	PR_BIND_FAIL_INTVL_NAME		"bind_fail_interval"
#define	PR_MAX_COPIES_NAME		"max_copies"
#define	PR_MAX_FAIL_RATE_CNT_NAME	"failrate_cnt"
#define	PR_MAX_FAIL_RATE_INTVL_NAME	"failrate_interval"
#define	PR_INHERIT_ENV_NAME		"inherit_env"
#define	PR_DO_TCP_WRAPPERS_NAME		"tcp_wrappers"
#define	PR_DO_TCP_TRACE_NAME		"tcp_trace"
#define	PR_DO_TCP_KEEPALIVE_NAME	"tcp_keepalive"
#define	PR_AUTO_CONVERTED_NAME		"converted"
#define	PR_VERSION_NAME			"version"
#define	PR_SOURCE_LINE_NAME		"source_line"
#define	PR_CONNECTION_BACKLOG_NAME	"connection_backlog"

/*
 * Provide index values for inetd property locations in the property table, for
 * convenience.  If the array is modified, these values MUST be updated.
 */
#define	PT_SVC_NAME_INDEX		0
#define	PT_SOCK_TYPE_INDEX		1
#define	PT_PROTO_INDEX			2
#define	PT_ISRPC_INDEX			3
#define	PT_RPC_LW_VER_INDEX		4
#define	PT_RPC_HI_VER_INDEX		5
#define	PT_ISWAIT_INDEX			6
#define	PT_EXEC_INDEX			7
#define	PT_ARG0_INDEX			8
#define	PT_USER_INDEX			9
#define	PT_BIND_ADDR_INDEX		10
#define	PT_BIND_FAIL_MAX_INDEX		11
#define	PT_BIND_FAIL_INTVL_INDEX	12
#define	PT_CON_RATE_MAX_INDEX		13
#define	PT_MAX_COPIES_INDEX		14
#define	PT_CON_RATE_OFFLINE_INDEX	15
#define	PT_MAX_FAIL_RATE_CNT_INDEX	16
#define	PT_MAX_FAIL_RATE_INTVL_INDEX	17
#define	PT_INHERIT_ENV_INDEX		18
#define	PT_DO_TCP_TRACE_INDEX		19
#define	PT_DO_TCP_WRAPPERS_INDEX	20
#define	PT_CONNECTION_BACKLOG_INDEX	21
#define	PT_DO_TCP_KEEPALIVE_INDEX	22

/*
 * Names of method properties.
 */
#define	PR_EXEC_NAME			"exec"
#define	PR_ARG0_NAME			"arg0"
#define	PR_USER_NAME			"user"

/*
 * Method property group names.
 */
#define	START_METHOD_NAME		"inetd_start"
#define	OFFLINE_METHOD_NAME		"inetd_offline"
#define	ONLINE_METHOD_NAME		"inetd_online"
#define	DISABLE_METHOD_NAME		"inetd_disable"
#define	REFRESH_METHOD_NAME		"inetd_refresh"

/*
 * Valid socket type values.
 */
#define	SOCKTYPE_STREAM_STR	"stream"
#define	SOCKTYPE_DGRAM_STR	"dgram"
#define	SOCKTYPE_RAW_STR	"raw"
#define	SOCKTYPE_SEQPKT_STR	"seqpacket"
#define	SOCKTYPE_TLI_STR	"tli"
#define	SOCKTYPE_XTI_STR	"xti"

/*
 * Valid socket based service protocols.
 */
#define	SOCKET_PROTO_SCTP6	"sctp6"
#define	SOCKET_PROTO_SCTP6_ONLY	"sctp6only"
#define	SOCKET_PROTO_SCTP	"sctp"
#define	SOCKET_PROTO_TCP6	"tcp6"
#define	SOCKET_PROTO_TCP6_ONLY	"tcp6only"
#define	SOCKET_PROTO_TCP	"tcp"
#define	SOCKET_PROTO_UDP6	"udp6"
#define	SOCKET_PROTO_UDP6_ONLY	"udp6only"
#define	SOCKET_PROTO_UDP	"udp"

/*
 * Return codes for the methods of inetd managed services.
 */
#define	IMRET_SUCCESS	0
/*
 * Set this value above the range used by unix commands so theres minimal chance
 * of a non-GL cognizant command accidentally returning this code.
 */
#define	IMRET_FAILURE	100

/*
 * Macros for differentiating between sockaddr_in & sockaddr_in6 when
 * dealing with the contents of a sockaddr_storage structure.
 * These differentiate based on the contents of ss_family (either AF_INET
 * or AF_INET6).
 */
#define	SS_ADDRLEN(s)	((s).ss_family == AF_INET ? \
	sizeof (struct sockaddr_in) : sizeof (struct sockaddr_in6))
#define	SS_PORT(s)	((s).ss_family == AF_INET ? \
	((struct sockaddr_in *)&(s))->sin_port : \
	((struct sockaddr_in6 *)&(s))->sin6_port)
#define	SS_SETPORT(s, port)	((s).ss_family == AF_INET ? \
	(((struct sockaddr_in *)&(s))->sin_port = port) : \
	(((struct sockaddr_in6 *)&(s))->sin6_port = port))
#define	SS_SINADDR(s)	((s).ss_family == AF_INET ? \
	((void *) &(((struct sockaddr_in *)&(s))->sin_addr)) : \
	((void *) &(((struct sockaddr_in6 *)&(s))->sin6_addr)))

/* Collection of information pertaining to rpc based services. */
typedef struct {
	struct netbuf	netbuf;
	int		prognum;
	int		lowver;
	int		highver;
	char		*netid;
	boolean_t	is_loopback;
} rpc_info_t;

/*
 * Structure containing the common elements of both the socket_info_t and the
 * tlx_info_t structures.
 */
typedef struct {
	/* proto string causing this entry */
	char		*proto;

	/* network fd we're listening on; -1 if not listening */
	int		listen_fd;

	/* associate RPC info structure, if any (NULL if none). */
	rpc_info_t	*ri;

	uu_list_node_t	link;

	/* should this fd have the v6 socket option set? */
	boolean_t	v6only;
} proto_info_t;


/* TLI/XTI connection indication list construct. */
typedef struct {
	struct t_call	*call;
	uu_list_node_t	link;
} tlx_conn_ind_t;

/* Collection of information pertaining to tli/xti based services. */
typedef struct {
	/* protocol information common to tlx and socket based services */
	proto_info_t	pr_info;

	/* address we're bound to */
	struct netbuf	local_addr;

	/* device name supplied to t_open() */
	char		*dev_name;

	/* queue of pending connection indications */
	uu_list_t	*conn_ind_queue;
} tlx_info_t;

/* Collection of information pertaining to socket based services. */
typedef struct {
	/* protocol information common to tlx and socket based services */
	proto_info_t		pr_info;

	/* address we're bound to */
	struct sockaddr_storage local_addr;

	/* SOCK_STREAM/SOCK_DGRAM/SOCK_RAW/SOCK_SEQPACKET */
	int			type;

	int			protocol;
} socket_info_t;

/* Basic configuration properties for an instance. */
typedef struct {
	/* getservbyname() recognized service name */
	char		*svc_name;

	/* TLI/XTI type service ? */
	boolean_t	istlx;

	/* list of protocols and associated info */
	uu_list_t	*proto_list;

	/* wait type service ? */
	boolean_t	iswait;

	/*
	 * Properties from here onwards all have default values in the inetd
	 * service instance.
	 */

	boolean_t	do_tcp_wrappers;
	boolean_t	do_tcp_trace;
	boolean_t	do_tcp_keepalive;

	/* inherit inetd's environment, or take an empty one */
	boolean_t	inherit_env;

	/* failure rate configuration */
	int64_t		wait_fail_cnt;
	int		wait_fail_interval;

	/* maximum concurrent copies limit */
	int64_t		max_copies;

	/* connection rate configuration */
	int		conn_rate_offline;
	int64_t		conn_rate_max;

	/* bind failure retries configuration */
	int		bind_fail_interval;
	int64_t		bind_fail_max;

	/* specific address to bind instance to */
	char		*bind_addr;

	/* connection backlog queue size */
	int64_t		conn_backlog;
} basic_cfg_t;

typedef enum uds_request {
	UR_REFRESH_INETD,
	UR_STOP_INETD
} uds_request_t;

typedef union {
	int64_t		iv_int;
	uint64_t	iv_cnt;
	boolean_t	iv_boolean;
	char		*iv_string;
	char		**iv_string_list;
} inetd_value_t;

typedef enum {
	IVE_VALID,
	IVE_UNSET,
	IVE_INVALID
} iv_error_t;

/*
 * Operations on these types (like valid_default_prop()) need to be modified
 * when this list is changed.
 */
typedef enum {
	INET_TYPE_INVALID = 0,

	INET_TYPE_BOOLEAN,
	INET_TYPE_COUNT,
	INET_TYPE_INTEGER,
	INET_TYPE_STRING,
	INET_TYPE_STRING_LIST
} inet_type_t;

typedef struct {
	const char	*ip_name;
	const char	*ip_pg;
	inet_type_t	ip_type;
	boolean_t	ip_default;
	iv_error_t	ip_error;
	inetd_value_t	ip_value;
	boolean_t	from_inetd;
} inetd_prop_t;

inetd_prop_t *get_prop_table(size_t *);
inetd_prop_t *find_prop(const inetd_prop_t *, const char *, inet_type_t);
int64_t get_prop_value_int(const inetd_prop_t *, const char *);
uint64_t get_prop_value_count(const inetd_prop_t *, const char *);
boolean_t get_prop_value_boolean(const inetd_prop_t *, const char *);
const char *get_prop_value_string(const inetd_prop_t *, const char *);
const char **get_prop_value_string_list(const inetd_prop_t *, const char *);
void put_prop_value_int(inetd_prop_t *, const char *, int64_t);
void put_prop_value_count(inetd_prop_t *, const char *, uint64_t);
void put_prop_value_boolean(inetd_prop_t *, const char *, boolean_t);
boolean_t put_prop_value_string(inetd_prop_t *, const char *, const char *);
void put_prop_value_string_list(inetd_prop_t *, const char *, char **);
boolean_t valid_props(inetd_prop_t *, const char *fmri, basic_cfg_t **,
    uu_list_pool_t *, uu_list_pool_t *);
void destroy_basic_cfg(basic_cfg_t *);
void destroy_proto_list(basic_cfg_t *);
boolean_t valid_default_prop(const char *, const void *);
scf_error_t read_prop(scf_handle_t *, inetd_prop_t *, int, const char *,
    const char *);
inetd_prop_t *read_instance_props(scf_handle_t *, const char *, size_t *,
    scf_error_t *);
inetd_prop_t *read_default_props(scf_handle_t *, size_t *, scf_error_t *);
void free_instance_props(inetd_prop_t *);
int connect_to_inetd(void);
int refresh_inetd(void);
int get_sock_type_id(const char *);
int get_rpc_prognum(const char *);
int calculate_hash(const char *, char **);
scf_error_t retrieve_inetd_hash(char **);
scf_error_t store_inetd_hash(const char *);
const char *inet_ntop_native(int, const void *, char *, size_t);
void setproctitle(const char *, int, char **);
void dg_template(
    void (*)(int, const struct sockaddr *, int, const void *, size_t), int,
    void *, size_t);
int safe_write(int, const void *, size_t);
int safe_sendto(int, const void *, size_t, int, const struct sockaddr *, int);
char **get_protos(const char *);
char **get_netids(char *);
void destroy_strings(char **);

#ifdef	__cplusplus
}
#endif

#endif /* _INETSVC_H */
