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

#ifndef _LIBILB_IMPL_H
#define	_LIBILB_IMPL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/note.h>
#include <netinet/in.h>
#include <netdb.h>
#include <net/if.h>
#include <inet/ilb.h>
#include <libilb.h>
#include <thread.h>
#include <synch.h>

#if !defined max
#define	max(a, b)	((a) > (b) ? (a) : (b))
#endif

/* The UNIX domain socket path to talk to ilbd. */
#define	SOCKET_PATH	"/var/run/daemon/ilb_sock"

/* The max message size for communicating with ilbd */
#define	ILBD_MSG_SIZE	102400

/*
 * moral equivalent of ntohl for IPv6 addresses, MSB and LSB (64 bit each),
 * assign to uint64_t variables
 */
#define	INV6_N2H_MSB64(addr)				\
	(((uint64_t)ntohl((addr)->_S6_un._S6_u32[0]) << 32) + 	\
	    (ntohl((addr)->_S6_un._S6_u32[1])))

#define	INV6_N2H_LSB64(addr)				\
	(((uint64_t)ntohl((addr)->_S6_un._S6_u32[2]) << 32) + 	\
	    (ntohl((addr)->_S6_un._S6_u32[3])))

/*
 * moral equiv. of htonl of MSB and LSB 64-bit portions to an IPv6 address
 */
#define	INV6_H2N_MSB64(addr, msb)				\
	(addr)->_S6_un._S6_u32[0] = htonl((msb) >> 32);		\
	(addr)->_S6_un._S6_u32[1] = htonl((msb) & 0xffffffff)

#define	INV6_H2N_LSB64(addr, lsb)				\
	(addr)->_S6_un._S6_u32[2] = htonl((lsb) >> 32);		\
	(addr)->_S6_un._S6_u32[3] = htonl((lsb) & 0xffffffff)

#define	IP_COPY_CLI_2_IMPL(_e, _i)				\
	bzero(_i, sizeof (*(_i)));				\
	if ((_e)->ia_af == AF_INET6)  				\
		(void) memcpy((_i), &(_e)->ia_v6, sizeof (*(_i)));	\
	else							\
		IN6_INADDR_TO_V4MAPPED(&(_e)->ia_v4, (_i))

#define	IP_COPY_IMPL_2_CLI(_i, _e)				\
	do {							\
		bzero(_e, sizeof (*(_e)));			\
		if (IN6_IS_ADDR_V4MAPPED(_i)) {			\
			(_e)->ia_af = AF_INET;			\
			IN6_V4MAPPED_TO_INADDR((_i), &(_e)->ia_v4); \
		} else {					\
			(_e)->ia_af = AF_INET6;			\
			(void) memcpy(&(_e)->ia_v6, (_i), 	\
			    sizeof ((_e)->ia_v6));		\
		}						\
		_NOTE(CONSTCOND)				\
	} while (0)

#define	GET_AF(_a) IN6_IS_ADDR_V4MAPPED(_a)?AF_INET:AF_INET6
#define	IS_AF_VALID(_af) (_af == AF_INET || _af == AF_INET6)

typedef enum {
	ILBD_BAD_CMD = 0,
				/* servergroup commands */
	ILBD_CREATE_SERVERGROUP,
	ILBD_ADD_SERVER_TO_GROUP,
	ILBD_REM_SERVER_FROM_GROUP,
	ILBD_ENABLE_SERVER,
	ILBD_DISABLE_SERVER,
	ILBD_DESTROY_SERVERGROUP,
	ILBD_RETRIEVE_SG_NAMES,		/* names of all SGs registered */
	ILBD_RETRIEVE_SG_HOSTS,		/* all hosts for a given SG (hndl) */
	ILBD_SRV_ADDR2ID,	/* fill in serverID for given address */
	ILBD_SRV_ID2ADDR,	/* fill in address from given serverID */
				/* rule commands */
	ILBD_CREATE_RULE,
	ILBD_DESTROY_RULE,
	ILBD_ENABLE_RULE,
	ILBD_DISABLE_RULE,
	ILBD_RETRIEVE_RULE_NAMES,
	ILBD_RETRIEVE_RULE,

	ILBD_CREATE_HC,
	ILBD_DESTROY_HC,
	ILBD_GET_HC_INFO,
	ILBD_GET_HC_SRVS,
	ILBD_GET_HC_RULES,
	ILBD_RETRIEVE_HC_NAMES,

	ILBD_SHOW_NAT,		/* list the NAT table */
	ILBD_SHOW_PERSIST,	/* list the sticky table */

	ILBD_CMD_OK,		/* Requested operation succeeds. */
	ILBD_CMD_ERROR		/* Rquested operation fails. */
} ilbd_cmd_t;

typedef struct sg_srv {
	int32_t		sgs_flags;	/* enabled, dis- */
	struct in6_addr	sgs_addr;
	int32_t		sgs_minport;
	int32_t		sgs_maxport;
	int32_t		sgs_id;		/* numerical part of srvID */
	char		sgs_srvID[ILB_NAMESZ];	/* "name" given to server */
} ilb_sg_srv_t;

typedef struct sg_info {
	int32_t		sg_flags;
	char		sg_name[ILB_SGNAME_SZ];
	int32_t		sg_srvcount;
	ilb_sg_srv_t	sg_servers[];
} ilb_sg_info_t;

typedef char	ilbd_name_t[ILB_NAMESZ];

typedef struct ilbd_namelist {
	int32_t		ilbl_flags;
	int32_t		ilbl_count;
	ilbd_name_t	ilbl_name[];
} ilbd_namelist_t;

#define	ILBL_NAME_OFFSET	(offsetof(ilbd_namelist_t, ilbl_name))

typedef struct rule_info {
	int32_t		rl_flags;
	char		rl_name[ILB_NAMESZ];
	struct in6_addr	rl_vip;
	uint16_t	rl_proto;
	uint16_t	rl_ipversion;
	int32_t		rl_minport;
	int32_t		rl_maxport;
	ilb_algo_t	rl_algo;
	ilb_topo_t	rl_topo;
	struct in6_addr	rl_nat_src_start;
	struct in6_addr	rl_nat_src_end;
	struct in6_addr	rl_stickymask;
	uint32_t	rl_conndrain;
	uint32_t	rl_nat_timeout;
	uint32_t	rl_sticky_timeout;
	in_port_t	rl_hcport;
	ilb_hcp_flags_t	rl_hcpflag;
	char		rl_sgname[ILB_SGNAME_SZ];
	char		rl_hcname[ILB_NAMESZ];
} ilb_rule_info_t;

/*
 * Struct to represent show NAT request and reply.
 *
 * sn_num: (request) indicates the number of entries wanted;
 *         (reply) the number of entries returned;
 * sn_data: NAT/persist able entries (is uint32_t aligned).
 */
typedef struct {
	uint32_t	sn_num;
	uint32_t	sn_data[];
} ilb_show_info_t;

/*
 * Struct to represent the set of servers associated with a hc object.
 *
 * rs_num_srvs: number of servers in this struct.
 * rs_srvs: array of servers.
 */
typedef struct {
	uint32_t	rs_num_srvs;
	ilb_hc_srv_t	rs_srvs[];
} ilb_hc_rule_srv_t;

typedef struct ilb_handle_impl {
	mutex_t		h_lock;
	cond_t		h_cv;
	boolean_t	h_busy;
	boolean_t	h_valid;
	boolean_t	h_closing;
	uint32_t	h_waiter;
	int		h_socket;
	ilb_status_t	h_error;	/* ... that caused invalidation */
} ilb_handle_impl_t;

/*
 * Communication flags used in ilb_comm_t.
 *
 * ILB_COMM_END: end of communication
 */
#define	ILB_COMM_END	0x1

/*
 * The message structure used to communicate with ilbd.
 *
 * ic_cmd: the message type.
 * ic_flags: communication flags
 * ic_data: message data (is uint32_t aligned).
 */
typedef struct {
	ilbd_cmd_t	ic_cmd;
	int32_t		ic_flags;
	uint32_t	ic_data[];
} ilb_comm_t;

ilb_status_t	i_check_ip_range(ilb_ip_addr_t *, ilb_ip_addr_t *);
ilb_status_t	i_ilb_do_comm(ilb_handle_t, ilb_comm_t *, size_t, ilb_comm_t *,
		    size_t *);
void		i_ilb_close_comm(ilb_handle_t);
struct in6_addr	i_next_ip_addr(struct in6_addr *, int);

ilb_status_t	i_ilb_retrieve_rule_names(ilb_handle_t, ilb_comm_t **,
		    size_t *);
ilb_comm_t 	*i_ilb_alloc_req(ilbd_cmd_t, size_t *);

#ifdef __cplusplus
}
#endif

#endif /* _LIBILB_IMPL_H */
