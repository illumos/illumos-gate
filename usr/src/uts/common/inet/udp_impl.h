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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_UDP_IMPL_H
#define	_UDP_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * UDP implementation private declarations.  These interfaces are
 * used to build the IP module and are not meant to be accessed
 * by any modules except IP itself.  They are undocumented and are
 * subject to change without notice.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

#include <sys/int_types.h>
#include <sys/netstack.h>

#include <netinet/in.h>
#include <netinet/ip6.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/optcom.h>

#define	UDP_MOD_ID		5607

typedef struct udp_bits_s {

	uint32_t

	udpb_debug : 1,		/* SO_DEBUG "socket" option. */
	udpb_dontroute : 1,	/* SO_DONTROUTE "socket" option. */
	udpb_broadcast : 1,	/* SO_BROADCAST "socket" option. */
	udpb_useloopback : 1,	/* SO_USELOOPBACK "socket" option */

	udpb_reuseaddr : 1,	/* SO_REUSEADDR "socket" option. */
	udpb_dgram_errind : 1,	/* SO_DGRAM_ERRIND option */
	udpb_recvdstaddr : 1,	/* IP_RECVDSTADDR option */
	udpb_recvopts : 1,	/* IP_RECVOPTS option */

	udpb_unspec_source : 1,	/* IP*_UNSPEC_SRC option */
	udpb_ip_recvpktinfo : 1,	/* IPV6_RECVPKTINFO option  */
	udpb_ipv6_recvhoplimit : 1,	/* IPV6_RECVHOPLIMIT option */
	udpb_ipv6_recvhopopts : 1,	/* IPV6_RECVHOPOPTS option */

	udpb_ipv6_recvdstopts : 1,	/* IPV6_RECVDSTOPTS option */
	udpb_ipv6_recvrthdr : 1,	/* IPV6_RECVRTHDR option */
	udpb_ipv6_recvtclass : 1,	/* IPV6_RECVTCLASS */
	udpb_ipv6_recvpathmtu : 1,	/* IPV6_RECVPATHMTU */

	udpb_anon_priv_bind : 1,
	udpb_exclbind : 1,		/* ``exclusive'' binding */
	udpb_recvif : 1,		/* IP_RECVIF option */
	udpb_recvslla : 1,		/* IP_RECVSLLA option */

	udpb_recvttl : 1,		/* IP_RECVTTL option */
	udpb_recvucred : 1,		/* IP_RECVUCRED option */
	udpb_old_ipv6_recvdstopts : 1,	/* old form of IPV6_DSTOPTS */
	udpb_ipv6_recvrthdrdstopts : 1,	/* IPV6_RECVRTHDRDSTOPTS */

	udpb_rcvhdr : 1,		/* UDP_RCVHDR option */
	udpb_issocket : 1,		/* socket mode */
	udpb_direct_sockfs : 1,		/* direct calls to/from sockfs */
	udpb_timestamp : 1,		/* SO_TIMESTAMP "socket" option */

	udpb_nat_t_endpoint : 1,	/* UDP_NAT_T_ENDPOINT option */
	udpb_pad_to_bit_31 : 3;
} udp_bits_t;

#define	udp_debug	udp_bits.udpb_debug
#define	udp_dontroute	udp_bits.udpb_dontroute
#define	udp_broadcast	udp_bits.udpb_broadcast
#define	udp_useloopback	udp_bits.udpb_useloopback

#define	udp_reuseaddr		udp_bits.udpb_reuseaddr
#define	udp_dgram_errind	udp_bits.udpb_dgram_errind
#define	udp_recvdstaddr		udp_bits.udpb_recvdstaddr
#define	udp_recvopts		udp_bits.udpb_recvopts

#define	udp_unspec_source	udp_bits.udpb_unspec_source
#define	udp_ip_recvpktinfo	udp_bits.udpb_ip_recvpktinfo
#define	udp_ipv6_recvhoplimit	udp_bits.udpb_ipv6_recvhoplimit
#define	udp_ipv6_recvhopopts	udp_bits.udpb_ipv6_recvhopopts

#define	udp_ipv6_recvdstopts	udp_bits.udpb_ipv6_recvdstopts
#define	udp_ipv6_recvrthdr	udp_bits.udpb_ipv6_recvrthdr
#define	udp_ipv6_recvtclass	udp_bits.udpb_ipv6_recvtclass
#define	udp_ipv6_recvpathmtu	udp_bits.udpb_ipv6_recvpathmtu

#define	udp_anon_priv_bind	udp_bits.udpb_anon_priv_bind
#define	udp_exclbind		udp_bits.udpb_exclbind
#define	udp_recvif		udp_bits.udpb_recvif
#define	udp_recvslla		udp_bits.udpb_recvslla

#define	udp_recvttl		udp_bits.udpb_recvttl
#define	udp_recvucred		udp_bits.udpb_recvucred
#define	udp_old_ipv6_recvdstopts	udp_bits.udpb_old_ipv6_recvdstopts
#define	udp_ipv6_recvrthdrdstopts	udp_bits.udpb_ipv6_recvrthdrdstopts

#define	udp_rcvhdr		udp_bits.udpb_rcvhdr
#define	udp_issocket		udp_bits.udpb_issocket
#define	udp_direct_sockfs	udp_bits.udpb_direct_sockfs
#define	udp_timestamp		udp_bits.udpb_timestamp

#define	udp_nat_t_endpoint	udp_bits.udpb_nat_t_endpoint

/*
 * Bind hash list size and hash function.  It has to be a power of 2 for
 * hashing.
 */
#define	UDP_BIND_FANOUT_SIZE	512
#define	UDP_BIND_HASH(lport, size) \
	((ntohs((uint16_t)lport)) & (size - 1))

/* UDP bind fanout hash structure. */
typedef struct udp_fanout_s {
	struct udp_s *uf_udp;
	kmutex_t uf_lock;
#if defined(_LP64) || defined(_I32LPx)
	char	uf_pad[48];
#else
	char	uf_pad[56];
#endif
} udp_fanout_t;

/*
 * dev_q is the write side queue of the entity below IP.
 * If there is a module below IP, we can't optimize by looking
 * at q_first of the queue below IP. If the driver is directly
 * below IP and if the q_first is NULL, we optimize by not doing
 * the canput check
 */
#define	DEV_Q_IS_FLOW_CTLED(dev_q)					\
	(((dev_q)->q_next != NULL || (dev_q)->q_first != NULL) &&	\
	!canput(dev_q))

/* Kstats */
typedef struct udp_stat {			/* Class "net" kstats */
	kstat_named_t	udp_ip_send;
	kstat_named_t	udp_ip_ire_send;
	kstat_named_t	udp_ire_null;
	kstat_named_t	udp_drain;
	kstat_named_t	udp_sock_fallback;
	kstat_named_t	udp_rrw_busy;
	kstat_named_t	udp_rrw_msgcnt;
	kstat_named_t	udp_out_sw_cksum;
	kstat_named_t	udp_out_sw_cksum_bytes;
	kstat_named_t	udp_out_opt;
	kstat_named_t	udp_out_err_notconn;
	kstat_named_t	udp_out_err_output;
	kstat_named_t	udp_out_err_tudr;
	kstat_named_t	udp_in_pktinfo;
	kstat_named_t	udp_in_recvdstaddr;
	kstat_named_t	udp_in_recvopts;
	kstat_named_t	udp_in_recvif;
	kstat_named_t	udp_in_recvslla;
	kstat_named_t	udp_in_recvucred;
	kstat_named_t	udp_in_recvttl;
	kstat_named_t	udp_in_recvhopopts;
	kstat_named_t	udp_in_recvhoplimit;
	kstat_named_t	udp_in_recvdstopts;
	kstat_named_t	udp_in_recvrtdstopts;
	kstat_named_t	udp_in_recvrthdr;
	kstat_named_t	udp_in_recvpktinfo;
	kstat_named_t	udp_in_recvtclass;
	kstat_named_t	udp_in_timestamp;
	kstat_named_t	udp_ip_rcvpktinfo;
	kstat_named_t	udp_direct_send;
	kstat_named_t	udp_bwsq_send;
	kstat_named_t	udp_connected_direct_send;
	kstat_named_t	udp_connected_bwsq_send;
#ifdef DEBUG
	kstat_named_t	udp_data_conn;
	kstat_named_t	udp_data_notconn;
#endif

} udp_stat_t;

/* Named Dispatch Parameter Management Structure */
typedef struct udpparam_s {
	uint32_t udp_param_min;
	uint32_t udp_param_max;
	uint32_t udp_param_value;
	char	*udp_param_name;
} udpparam_t;

#define	UDP_NUM_EPRIV_PORTS	64

/*
 * UDP stack instances
 */
struct udp_stack {
	netstack_t	*us_netstack;	/* Common netstack */

	uint_t		us_bind_fanout_size;
	udp_fanout_t	*us_bind_fanout;

	int		us_num_epriv_ports;
	in_port_t	us_epriv_ports[UDP_NUM_EPRIV_PORTS];

	/* Hint not protected by any lock */
	in_port_t	us_next_port_to_try;

	IDP		us_nd;	/* Points to table of UDP ND variables. */
	udpparam_t	*us_param_arr; 	/* ndd variable table */

	kstat_t		*us_mibkp;	/* kstats exporting mib data */
	kstat_t		*us_kstat;
	udp_stat_t	us_statistics;

	mib2_udp_t	us_udp_mib;	/* SNMP fixed size info */

/*
 * This controls the rate some ndd info report functions can be used
 * by non-priviledged users.  It stores the last time such info is
 * requested.  When those report functions are called again, this
 * is checked with the current time and compare with the ndd param
 * udp_ndd_get_info_interval.
 */
	clock_t		us_last_ndd_get_info_time;

/*
 * The smallest anonymous port in the priviledged port range which UDP
 * looks for free port.  Use in the option UDP_ANONPRIVBIND.
 */
	in_port_t	us_min_anonpriv_port;

};
typedef struct udp_stack udp_stack_t;

/* Internal udp control structure, one per open stream */
typedef	struct udp_s {
	krwlock_t	udp_rwlock;	/* Protects most of udp_t */
	t_scalar_t	udp_pending_op;	/* The current TPI operation */
	/*
	 * Following fields up to udp_ipversion protected by conn_lock,
	 * and the fanout lock i.e.uf_lock. Need both locks to change the
	 * field, either lock is sufficient for reading the field.
	 */
	uint32_t	udp_state;	/* TPI state */
	in_port_t	udp_port;	/* Port bound to this stream */
	in_port_t	udp_dstport;	/* Connected port */
	in6_addr_t	udp_v6src;	/* Source address of this stream */
	in6_addr_t	udp_bound_v6src; /* Explicitly bound address */
	in6_addr_t	udp_v6dst;	/* Connected destination */
	/*
	 * IP format that packets transmitted from this struct should use.
	 * Value can be IP4_VERSION or IPV6_VERSION.
	 */
	ushort_t	udp_ipversion;

	/* Written to only once at the time of opening the endpoint */
	sa_family_t	udp_family;	/* Family from socket() call */

	/* Following protected by udp_rwlock */
	uint32_t	udp_flowinfo;	/* Connected flow id and tclass */
	uint32_t	udp_max_hdr_len; /* For write offset in stream head */
	uint32_t	udp_ip_snd_options_len; /* Len of IPv4 options */
	uchar_t		*udp_ip_snd_options;    /* Ptr to IPv4 options */
	uint32_t	udp_ip_rcv_options_len; /* Len of IPv4 options recvd */
	uchar_t		*udp_ip_rcv_options;    /* Ptr to IPv4 options recvd */
	uchar_t		udp_multicast_ttl;	/* IP*_MULTICAST_TTL/HOPS */
	ipaddr_t	udp_multicast_if_addr;  /* IP_MULTICAST_IF option */
	uint_t		udp_multicast_if_index;	/* IPV6_MULTICAST_IF option */
	int		udp_bound_if;		/* IP*_BOUND_IF option */

	/* Written to only once at the time of opening the endpoint */
	conn_t		*udp_connp;

	/* Following protected by udp_rwlock */
	udp_bits_t	udp_bits;		/* Bit fields defined above */
	uint8_t		udp_type_of_service;	/* IP_TOS option */
	uint8_t		udp_ttl;		/* TTL or hoplimit */
	ip6_pkt_t	udp_sticky_ipp;		/* Sticky options */
	uint8_t		*udp_sticky_hdrs;	/* Prebuilt IPv6 hdrs */
	uint_t		udp_sticky_hdrs_len;	/* Incl. ip6h and any ip6i */

	/* Following 2 fields protected by the uf_lock */
	struct udp_s	*udp_bind_hash; /* Bind hash chain */
	struct udp_s	**udp_ptpbhn; /* Pointer to previous bind hash next. */

	kmutex_t	udp_drain_lock;		/* lock for udp_rcv_list */
	/* Protected by udp_drain_lock */
	boolean_t	udp_drain_qfull;	/* drain queue is full */

	/* Following protected by udp_rwlock */
	mblk_t		*udp_rcv_list_head;	/* b_next chain of mblks */
	mblk_t		*udp_rcv_list_tail;	/* last mblk in chain */
	uint_t		udp_rcv_cnt;		/* total data in rcv_list */
	uint_t		udp_rcv_msgcnt;		/* total msgs in rcv_list */
	size_t		udp_rcv_hiwat;		/* receive high watermark */
	uint_t		udp_label_len;		/* length of security label */
	uint_t		udp_label_len_v6;	/* len of v6 security label */
	in6_addr_t 	udp_v6lastdst;		/* most recent destination */

	uint64_t	udp_open_time;	/* time when this was opened */
	pid_t		udp_open_pid;	/* process id when this was opened */
	udp_stack_t	*udp_us;		/* Stack instance for zone */
} udp_t;

/* UDP Protocol header */
/* UDP Protocol header aligned */
typedef	struct udpahdr_s {
	in_port_t	uha_src_port;		/* Source port */
	in_port_t	uha_dst_port;		/* Destination port */
	uint16_t	uha_length;		/* UDP length */
	uint16_t	uha_checksum;		/* UDP checksum */
} udpha_t;

#define	us_wroff_extra			us_param_arr[0].udp_param_value
#define	us_ipv4_ttl			us_param_arr[1].udp_param_value
#define	us_ipv6_hoplimit		us_param_arr[2].udp_param_value
#define	us_smallest_nonpriv_port	us_param_arr[3].udp_param_value
#define	us_do_checksum			us_param_arr[4].udp_param_value
#define	us_smallest_anon_port		us_param_arr[5].udp_param_value
#define	us_largest_anon_port		us_param_arr[6].udp_param_value
#define	us_xmit_hiwat			us_param_arr[7].udp_param_value
#define	us_xmit_lowat			us_param_arr[8].udp_param_value
#define	us_recv_hiwat			us_param_arr[9].udp_param_value
#define	us_max_buf			us_param_arr[10].udp_param_value
#define	us_ndd_get_info_interval	us_param_arr[11].udp_param_value


#define	UDP_STAT(us, x)		((us)->us_statistics.x.value.ui64++)
#define	UDP_STAT_UPDATE(us, x, n)	\
			((us)->us_statistics.x.value.ui64 += (n))

#ifdef DEBUG
#define	UDP_DBGSTAT(us, x)	UDP_STAT(us, x)
#else
#define	UDP_DBGSTAT(us, x)
#endif /* DEBUG */

extern int	udp_opt_default(queue_t *, t_scalar_t, t_scalar_t, uchar_t *);
extern int	udp_opt_get(queue_t *, t_scalar_t, t_scalar_t, uchar_t *);
extern int	udp_opt_set(queue_t *, uint_t, int, int, uint_t, uchar_t *,
		    uint_t *, uchar_t *, void *, cred_t *, mblk_t *);
extern mblk_t	*udp_snmp_get(queue_t *, mblk_t *);
extern int	udp_snmp_set(queue_t *, t_scalar_t, t_scalar_t, uchar_t *, int);
extern void	udp_close_free(conn_t *);
extern void	udp_quiesce_conn(conn_t *);
extern void	udp_ddi_init(void);
extern void	udp_ddi_destroy(void);
extern void	udp_resume_bind(conn_t *, mblk_t *);
extern void	udp_output(conn_t *connp, mblk_t *mp, struct sockaddr *addr,
		    socklen_t addrlen);
extern void	udp_wput(queue_t *, mblk_t *);

extern int	udp_opt_default(queue_t *q, t_scalar_t level, t_scalar_t name,
    uchar_t *ptr);
extern int	udp_opt_get(queue_t *q, t_scalar_t level, t_scalar_t name,
    uchar_t *ptr);
extern int	udp_opt_set(queue_t *q, uint_t optset_context,
    int level, int name, uint_t inlen, uchar_t *invalp, uint_t *outlenp,
    uchar_t *outvalp, void *thisdg_attrs, cred_t *cr, mblk_t *mblk);

/*
 * Object to represent database of options to search passed to
 * {sock,tpi}optcom_req() interface routine to take care of option
 * management and associated methods.
 */
extern optdb_obj_t	udp_opt_obj;
extern uint_t		udp_max_optsize;

#endif	/*  _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _UDP_IMPL_H */
