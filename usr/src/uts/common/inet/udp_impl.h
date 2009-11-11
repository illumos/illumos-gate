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
 * The smallest anonymous port in the priviledged port range which UDP
 * looks for free port.  Use in the option UDP_ANONPRIVBIND.
 */
	in_port_t	us_min_anonpriv_port;

	ldi_ident_t	us_ldi_ident;
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
#define	us_pmtu_discovery		us_param_arr[11].udp_param_value
#define	us_sendto_ignerr		us_param_arr[12].udp_param_value


#define	UDP_STAT(us, x)		((us)->us_statistics.x.value.ui64++)
#define	UDP_STAT_UPDATE(us, x, n)	\
			((us)->us_statistics.x.value.ui64 += (n))
#ifdef DEBUG
#define	UDP_DBGSTAT(us, x)	UDP_STAT(us, x)
#else
#define	UDP_DBGSTAT(us, x)
#endif /* DEBUG */

extern int	udp_opt_default(queue_t *, t_scalar_t, t_scalar_t, uchar_t *);
extern int	udp_tpi_opt_get(queue_t *, t_scalar_t, t_scalar_t, uchar_t *);
extern int	udp_tpi_opt_set(queue_t *, uint_t, int, int, uint_t, uchar_t *,
		    uint_t *, uchar_t *, void *, cred_t *);
extern mblk_t	*udp_snmp_get(queue_t *, mblk_t *);
extern int	udp_snmp_set(queue_t *, t_scalar_t, t_scalar_t, uchar_t *, int);
extern void	udp_ddi_g_init(void);
extern void	udp_ddi_g_destroy(void);
extern void	udp_output(conn_t *connp, mblk_t *mp, struct sockaddr *addr,
		    socklen_t addrlen);
extern void	udp_wput(queue_t *, mblk_t *);

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
    so_proto_quiesced_cb_t);

extern sock_downcalls_t sock_udp_downcalls;

#endif	/*  _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _UDP_IMPL_H */
