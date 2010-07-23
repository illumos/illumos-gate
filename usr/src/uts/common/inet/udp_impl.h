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
 * Copyright (c) 2000, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_UDP_IMPL_H
#define	_UDP_IMPL_H

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
#include <inet/tunables.h>

#define	UDP_MOD_ID		5607

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

/* Kstats */
typedef struct udp_stat {			/* Class "net" kstats */
	kstat_named_t	udp_sock_fallback;
	kstat_named_t	udp_out_opt;
	kstat_named_t	udp_out_err_notconn;
	kstat_named_t	udp_out_err_output;
	kstat_named_t	udp_out_err_tudr;
#ifdef DEBUG
	kstat_named_t	udp_data_conn;
	kstat_named_t	udp_data_notconn;
	kstat_named_t	udp_out_lastdst;
	kstat_named_t	udp_out_diffdst;
	kstat_named_t	udp_out_ipv6;
	kstat_named_t	udp_out_mapped;
	kstat_named_t	udp_out_ipv4;
#endif
} udp_stat_t;

/*
 * This struct contains only the counter part of udp_stat_t.  It is used
 * in udp_stats_cpu_t instead of udp_stat_t to save memory space.
 */
typedef struct {
	uint64_t	udp_sock_fallback;
	uint64_t	udp_out_opt;
	uint64_t	udp_out_err_notconn;
	uint64_t	udp_out_err_output;
	uint64_t	udp_out_err_tudr;
#ifdef DEBUG
	uint64_t	udp_data_conn;
	uint64_t	udp_data_notconn;
	uint64_t	udp_out_lastdst;
	uint64_t	udp_out_diffdst;
	uint64_t	udp_out_ipv6;
	uint64_t	udp_out_mapped;
	uint64_t	udp_out_ipv4;
#endif
} udp_stat_counter_t;

/* Per CPU stats: UDP MIB2 and UDP kstat. */
typedef struct {
	mib2_udp_t		udp_sc_mib;
	udp_stat_counter_t	udp_sc_stats;
} udp_stats_cpu_t;

#define	UDP_NUM_EPRIV_PORTS	64

/* Default buffer size and flow control wake up threshold. */
#define	UDP_RECV_HIWATER	(56 * 1024)
#define	UDP_RECV_LOWATER	128
#define	UDP_XMIT_HIWATER	(56 * 1024)
#define	UDP_XMIT_LOWATER	1024

/*
 * UDP stack instances
 */
struct udp_stack {
	netstack_t	*us_netstack;	/* Common netstack */

	uint_t		us_bind_fanout_size;
	udp_fanout_t	*us_bind_fanout;

	int		us_num_epriv_ports;
	in_port_t	us_epriv_ports[UDP_NUM_EPRIV_PORTS];
	kmutex_t	us_epriv_port_lock;

	/* Hint not protected by any lock */
	in_port_t	us_next_port_to_try;

	/* UDP tunables table */
	struct mod_prop_info_s	*us_propinfo_tbl;

	kstat_t		*us_mibkp;	/* kstats exporting mib data */
	kstat_t		*us_kstat;

/*
 * The smallest anonymous port in the priviledged port range which UDP
 * looks for free port.  Use in the option UDP_ANONPRIVBIND.
 */
	in_port_t	us_min_anonpriv_port;

	ldi_ident_t	us_ldi_ident;

	udp_stats_cpu_t	**us_sc;
	int		us_sc_cnt;
};

typedef struct udp_stack udp_stack_t;

/* Internal udp control structure, one per open stream */
typedef	struct udp_s {
	/*
	 * The addresses and ports in the conn_t and udp_state are protected by
	 * conn_lock and the fanout lock i.e. uf_lock. Need both locks to change
	 * the fields, either lock is sufficient for reading the field.
	 * conn_lock also protects the content of udp_t.
	 */
	uint32_t	udp_state;	/* TPI state */

	ip_pkt_t	udp_recv_ipp;	/* Used for IPv4 options received */

	/* Written to only once at the time of opening the endpoint */
	conn_t		*udp_connp;

	uint32_t
		udp_issocket : 1,	/* socket mode; sockfs is on top */
		udp_nat_t_endpoint : 1,	/* UDP_NAT_T_ENDPOINT option */
		udp_rcvhdr : 1,		/* UDP_RCVHDR option */

		udp_pad_to_bit_31 : 29;

	/* Following 2 fields protected by the uf_lock */
	struct udp_s	*udp_bind_hash; /* Bind hash chain */
	struct udp_s	**udp_ptpbhn; /* Pointer to previous bind hash next. */

	kmutex_t	udp_recv_lock;		/* recv lock */
	size_t		udp_rcv_disply_hiwat;	/* user's view of rcvbuf */
	size_t		udp_rcv_hiwat;		/* receive high watermark */

	/* Set at open time and never changed */
	udp_stack_t	*udp_us;		/* Stack instance for zone */

	int		udp_delayed_error;
	mblk_t		*udp_fallback_queue_head;
	mblk_t		*udp_fallback_queue_tail;
	struct sockaddr_storage	udp_delayed_addr;
} udp_t;

/* UDP Protocol header aligned */
typedef	struct udpahdr_s {
	in_port_t	uha_src_port;		/* Source port */
	in_port_t	uha_dst_port;		/* Destination port */
	uint16_t	uha_length;		/* UDP length */
	uint16_t	uha_checksum;		/* UDP checksum */
} udpha_t;

#define	us_wroff_extra			us_propinfo_tbl[0].prop_cur_uval
#define	us_ipv4_ttl			us_propinfo_tbl[1].prop_cur_uval
#define	us_ipv6_hoplimit		us_propinfo_tbl[2].prop_cur_uval
#define	us_smallest_nonpriv_port	us_propinfo_tbl[3].prop_cur_uval
#define	us_do_checksum			us_propinfo_tbl[4].prop_cur_bval
#define	us_smallest_anon_port		us_propinfo_tbl[5].prop_cur_uval
#define	us_largest_anon_port		us_propinfo_tbl[6].prop_cur_uval
#define	us_xmit_hiwat			us_propinfo_tbl[7].prop_cur_uval
#define	us_xmit_lowat			us_propinfo_tbl[8].prop_cur_uval
#define	us_recv_hiwat			us_propinfo_tbl[9].prop_cur_uval
#define	us_max_buf			us_propinfo_tbl[10].prop_cur_uval
#define	us_pmtu_discovery		us_propinfo_tbl[11].prop_cur_bval
#define	us_sendto_ignerr		us_propinfo_tbl[12].prop_cur_bval

#define	UDPS_BUMP_MIB(us, x)	\
	BUMP_MIB(&(us)->us_sc[CPU->cpu_seqid]->udp_sc_mib, x)

#define	UDP_STAT(us, x)		((us)->us_sc[CPU->cpu_seqid]->udp_sc_stats.x++)
#define	UDP_STAT_UPDATE(us, x, n)	\
	((us)->us->sc[CPU->cpu_seqid]->udp_sc_stats.x.value.ui64 += (n))
#ifdef DEBUG
#define	UDP_DBGSTAT(us, x)	UDP_STAT(us, x)
#else
#define	UDP_DBGSTAT(us, x)
#endif /* DEBUG */

extern int	udp_opt_default(queue_t *, t_scalar_t, t_scalar_t, uchar_t *);
extern int	udp_tpi_opt_get(queue_t *, t_scalar_t, t_scalar_t, uchar_t *);
extern int	udp_tpi_opt_set(queue_t *, uint_t, int, int, uint_t, uchar_t *,
		    uint_t *, uchar_t *, void *, cred_t *);
extern mblk_t	*udp_snmp_get(queue_t *, mblk_t *, boolean_t);
extern int	udp_snmp_set(queue_t *, t_scalar_t, t_scalar_t, uchar_t *, int);
extern void	udp_ddi_g_init(void);
extern void	udp_ddi_g_destroy(void);
extern void	udp_output(conn_t *connp, mblk_t *mp, struct sockaddr *addr,
		    socklen_t addrlen);
extern void	udp_wput(queue_t *, mblk_t *);

extern void	*udp_kstat_init(netstackid_t stackid);
extern void	udp_kstat_fini(netstackid_t stackid, kstat_t *ksp);
extern void	*udp_kstat2_init(netstackid_t stackid);
extern void	udp_kstat2_fini(netstackid_t, kstat_t *);

extern void	udp_stack_cpu_add(udp_stack_t *, processorid_t);

/*
 * Object to represent database of options to search passed to
 * {sock,tpi}optcom_req() interface routine to take care of option
 * management and associated methods.
 */
extern optdb_obj_t	udp_opt_obj;
extern uint_t		udp_max_optsize;

extern sock_lower_handle_t udp_create(int, int, int, sock_downcalls_t **,
    uint_t *, int *, int, cred_t *);
extern int udp_fallback(sock_lower_handle_t, queue_t *, boolean_t,
    so_proto_quiesced_cb_t, sock_quiesce_arg_t *);

extern sock_downcalls_t sock_udp_downcalls;

#endif	/*  _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _UDP_IMPL_H */
