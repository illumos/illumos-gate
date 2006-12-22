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

#include <netinet/in.h>
#include <netinet/ip6.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/optcom.h>

#define	UDP_MOD_ID		5607

/* udp_mode. UDP_MT_HOT and UDP_SQUEUE are stable modes. Rest are transient */
typedef enum {
	UDP_MT_HOT = 0,			/* UDP endpoint is MT HOT */
	UDP_MT_QUEUED = 1,		/* Messages enqueued in udp_mphead */
	UDP_QUEUED_SQUEUE = 2,		/* Messages enqueued in conn_sqp */
	UDP_SQUEUE = 3			/* Single threaded using squeues */
} udp_mode_t;

/* Internal udp control structure, one per open stream */
typedef	struct udp_s {
	uint32_t	udp_state;	/* TPI state */
	in_port_t	udp_port;	/* Port bound to this stream */
	in_port_t	udp_dstport;	/* Connected port */
	in6_addr_t	udp_v6src;	/* Source address of this stream */
	in6_addr_t	udp_bound_v6src; /* Explicitly bound address */
	in6_addr_t	udp_v6dst;	/* Connected destination */
	uint32_t	udp_flowinfo;	/* Connected flow id and tclass */
	uint32_t	udp_max_hdr_len; /* For write offset in stream head */
	sa_family_t	udp_family;	/* Family from socket() call */
	/*
	 * IP format that packets transmitted from this struct should use.
	 * Value can be IP4_VERSION or IPV6_VERSION.
	 */
	ushort_t	udp_ipversion;
	uint32_t	udp_ip_snd_options_len; /* Len of IPv4 options */
	uchar_t		*udp_ip_snd_options;    /* Ptr to IPv4 options */
	uint32_t	udp_ip_rcv_options_len; /* Len of IPv4 options recvd */
	uchar_t		*udp_ip_rcv_options;    /* Ptr to IPv4 options recvd */
	uchar_t		udp_multicast_ttl;	/* IP*_MULTICAST_TTL/HOPS */
	ipaddr_t	udp_multicast_if_addr;  /* IP_MULTICAST_IF option */
	uint_t		udp_multicast_if_index;	/* IPV6_MULTICAST_IF option */
	int		udp_bound_if;		/* IP*_BOUND_IF option */
	int		udp_xmit_if;		/* IP_XMIT_IF option */
	conn_t		*udp_connp;
	uint32_t
		udp_debug : 1,		/* SO_DEBUG "socket" option. */
		udp_dontroute : 1,	/* SO_DONTROUTE "socket" option. */
		udp_broadcast : 1,	/* SO_BROADCAST "socket" option. */
		udp_useloopback : 1,	/* SO_USELOOPBACK "socket" option */

		udp_reuseaddr : 1,	/* SO_REUSEADDR "socket" option. */
		udp_dgram_errind : 1,	/* SO_DGRAM_ERRIND option */
		udp_recvdstaddr : 1,	/* IP_RECVDSTADDR option */
		udp_recvopts : 1,	/* IP_RECVOPTS option */

		udp_discon_pending : 1,	/* T_DISCON_REQ in progress */
		udp_unspec_source : 1,	/* IP*_UNSPEC_SRC option */
		udp_ip_recvpktinfo : 1,	/* IPV[4,6]_RECVPKTINFO option  */
		udp_ipv6_recvhoplimit : 1,	/* IPV6_RECVHOPLIMIT option */

		udp_ipv6_recvhopopts : 1,	/* IPV6_RECVHOPOPTS option */
		udp_ipv6_recvdstopts : 1,	/* IPV6_RECVDSTOPTS option */
		udp_ipv6_recvrthdr : 1,		/* IPV6_RECVRTHDR option */
		udp_ipv6_recvtclass : 1,	/* IPV6_RECVTCLASS */

		udp_ipv6_recvpathmtu : 1,	/* IPV6_RECVPATHMTU */
		udp_anon_priv_bind : 1,
		udp_exclbind : 1,	/* ``exclusive'' binding */
		udp_recvif : 1,		/* IP_RECVIF option */

		udp_recvslla : 1,	/* IP_RECVSLLA option */
		udp_recvttl : 1,	/* IP_RECVTTL option */
		udp_recvucred : 1,	/* IP_RECVUCRED option */
		udp_old_ipv6_recvdstopts : 1,	/* old form of IPV6_DSTOPTS */

		udp_ipv6_recvrthdrdstopts : 1,	/* IPV6_RECVRTHDRDSTOPTS */
		udp_rcvhdr : 1,		/* UDP_RCVHDR option */
		udp_issocket : 1,	/* socket mode */
		udp_direct_sockfs : 1,	/* direct calls to/from sockfs */

		udp_timestamp : 1,	/* SO_TIMESTAMP "socket" option */
		udp_anon_mlp : 1,		/* SO_ANON_MLP */
		udp_mac_exempt : 1,		/* SO_MAC_EXEMPT */
		udp_pad_to_bit_31 : 1;

	uint8_t		udp_type_of_service;	/* IP_TOS option */
	uint8_t		udp_ttl;		/* TTL or hoplimit */

	ip6_pkt_t	udp_sticky_ipp;		/* Sticky options */
	uint8_t		*udp_sticky_hdrs;	/* Prebuilt IPv6 hdrs */
	uint_t		udp_sticky_hdrs_len;	/* Incl. ip6h and any ip6i */
	struct udp_s	*udp_bind_hash; /* Bind hash chain */
	struct udp_s	**udp_ptpbhn; /* Pointer to previous bind hash next. */
	udp_mode_t	udp_mode;	/* Current mode of operation */
	mblk_t		*udp_mphead;	/* Head of the queued operations */
	mblk_t		*udp_mptail;	/* Tail of the queued operations */
	uint_t		udp_mpcount;	/* Number of messages in the queue */
	uint_t		udp_reader_count; /* Number of reader threads */
	uint_t		udp_squeue_count; /* Number of messages in conn_sqp */

	kmutex_t	udp_drain_lock;		/* lock for udp_rcv_list */
	boolean_t	udp_drain_qfull;	/* drain queue is full */
	mblk_t		*udp_rcv_list_head;	/* b_next chain of mblks */
	mblk_t		*udp_rcv_list_tail;	/* last mblk in chain */
	uint_t		udp_rcv_cnt;		/* total data in rcv_list */
	uint_t		udp_rcv_msgcnt;		/* total messages in rcv_list */
	size_t		udp_rcv_hiwat;		/* receive high watermark */
	uint_t		udp_label_len;		/* length of security label */
	uint_t		udp_label_len_v6;	/* len of v6 security label */
	in6_addr_t 	udp_v6lastdst;		/* most recent destination */

	uint64_t	udp_open_time;	/* time when this was opened */
	pid_t		udp_open_pid;	/* process id when this was opened */
} udp_t;

/* UDP Protocol header */
/* UDP Protocol header aligned */
typedef	struct udpahdr_s {
	in_port_t	uha_src_port;		/* Source port */
	in_port_t	uha_dst_port;		/* Destination port */
	uint16_t	uha_length;		/* UDP length */
	uint16_t	uha_checksum;		/* UDP checksum */
} udpha_t;

/* Named Dispatch Parameter Management Structure */
typedef struct udpparam_s {
	uint32_t udp_param_min;
	uint32_t udp_param_max;
	uint32_t udp_param_value;
	char	*udp_param_name;
} udpparam_t;

extern udpparam_t udp_param_arr[];

#define	udp_wroff_extra			udp_param_arr[0].udp_param_value
#define	udp_ipv4_ttl			udp_param_arr[1].udp_param_value
#define	udp_ipv6_hoplimit		udp_param_arr[2].udp_param_value
#define	udp_smallest_nonpriv_port	udp_param_arr[3].udp_param_value
#define	udp_do_checksum			udp_param_arr[4].udp_param_value
#define	udp_smallest_anon_port		udp_param_arr[5].udp_param_value
#define	udp_largest_anon_port		udp_param_arr[6].udp_param_value
#define	udp_xmit_hiwat			udp_param_arr[7].udp_param_value
#define	udp_xmit_lowat			udp_param_arr[8].udp_param_value
#define	udp_recv_hiwat			udp_param_arr[9].udp_param_value
#define	udp_max_buf			udp_param_arr[10].udp_param_value
#define	udp_ndd_get_info_interval	udp_param_arr[11].udp_param_value

/* Kstats */
typedef struct {				/* Class "net" kstats */
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
	kstat_named_t	udp_ip_recvpktinfo;
#ifdef DEBUG
	kstat_named_t	udp_data_conn;
	kstat_named_t	udp_data_notconn;
#endif
} udp_stat_t;

extern udp_stat_t	udp_statistics;

#define	UDP_STAT(x)		(udp_statistics.x.value.ui64++)
#define	UDP_STAT_UPDATE(x, n)	(udp_statistics.x.value.ui64 += (n))
#ifdef DEBUG
#define	UDP_DBGSTAT(x)		UDP_STAT(x)
#else
#define	UDP_DBGSTAT(x)
#endif /* DEBUG */

extern major_t	UDP6_MAJ;

extern int	udp_opt_default(queue_t *, t_scalar_t, t_scalar_t, uchar_t *);
extern int	udp_opt_get(queue_t *, t_scalar_t, t_scalar_t, uchar_t *);
extern int	udp_opt_set(queue_t *, uint_t, int, int, uint_t, uchar_t *,
		    uint_t *, uchar_t *, void *, cred_t *, mblk_t *);
extern int	udp_snmp_get(queue_t *, mblk_t *);
extern int	udp_snmp_set(queue_t *, t_scalar_t, t_scalar_t, uchar_t *, int);
extern void	udp_close_free(conn_t *);
extern void	udp_quiesce_conn(conn_t *);
extern void	udp_ddi_init(void);
extern void	udp_ddi_destroy(void);
extern void	udp_resume_bind(conn_t *, mblk_t *);
extern void	udp_conn_recv(conn_t *, mblk_t *);
extern boolean_t udp_compute_checksum(void);
extern void	udp_wput_data(queue_t *, mblk_t *, struct sockaddr *,
		    socklen_t);

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
