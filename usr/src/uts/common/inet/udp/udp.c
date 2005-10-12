/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/* Copyright (c) 1990 Mentat Inc. */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

const char udp_version[] = "%Z%%M%	%I%	%E% SMI";

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strlog.h>
#include <sys/strsun.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/timod.h>
#include <sys/tiuser.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/strsubr.h>
#include <sys/suntpi.h>
#include <sys/xti_inet.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/policy.h>
#include <sys/ucred.h>
#include <sys/zone.h>

#include <sys/socket.h>
#include <sys/vtrace.h>
#include <sys/debug.h>
#include <sys/isa_defs.h>
#include <sys/random.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>
#include <net/if.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/ip_ire.h>
#include <inet/mi.h>
#include <inet/mib2.h>
#include <inet/nd.h>
#include <inet/optcom.h>
#include <inet/snmpcom.h>
#include <inet/kstatcom.h>
#include <inet/udp_impl.h>

/*
 * The ipsec_info.h header file is here since it has the defination for the
 * M_CTL message types used by IP to convey information to the ULP. The
 * ipsec_info.h needs the pfkeyv2.h, hence the latters presence.
 */
#include <net/pfkeyv2.h>
#include <inet/ipsec_info.h>

/*
 * Object to represent database of options to search passed to
 * {sock,tpi}optcom_req() interface routine to take care of option
 * management and associated methods.
 * XXX. These and other externs should really move to a udp header file.
 */
extern optdb_obj_t	udp_opt_obj;
extern uint_t		udp_max_optsize;


/*
 * Synchronization notes:
 *
 * UDP uses a combination of the queue-pair STREAMS perimeter, a global
 * lock and a set of bind hash locks to protect its data structures.
 *
 * The queue-pair perimeter is not acquired exclusively in the put
 * procedures thus when udp_rput or udp_wput needs exclusive access to
 * the udp_t instance structure it will use qwriter(..., PERIM_INNER) to
 * asynchronously acquire exclusive access to the udp_t instance.
 *
 * When UDP global data needs to be modified the udp_g_lock mutex is acquired.
 * Currently, udp_g_head and udp_g_epriv_ports[] are protected by it.
 *
 * When an UDP endpoint is bound to a local port, it is inserted into
 * a bind hash list.  The list consists of an array of udp_fanout_t buckets.
 * The size of the array is controlled by the udp_bind_fanout_size variable.
 * This variable can be changed in /etc/system if the default value is
 * not large enough.  Each bind hash bucket is protected by a per bucket lock.
 * It protects the udp_bind_hash and udp_ptpbhn fields in the udp_t
 * structure.  An UDP endpoint is removed from the bind hash list only
 * when it is being unbound or being closed.  The per bucket lock also
 * protects an UDP endpoint's state changes.
 */

/*
 * Bind hash list size and hash function.  It has to be a power of 2 for
 * hashing.
 */
#define	UDP_BIND_FANOUT_SIZE	512
#define	UDP_BIND_HASH(lport) \
	((ntohs((uint16_t)lport)) & (udp_bind_fanout_size - 1))

/* UDP bind fanout hash structure. */
typedef struct udp_fanout_s {
	udp_t *uf_udp;
	kmutex_t uf_lock;
#if defined(_LP64) || defined(_I32LPx)
	char	uf_pad[48];
#else
	char	uf_pad[56];
#endif
} udp_fanout_t;

uint_t udp_bind_fanout_size = UDP_BIND_FANOUT_SIZE;
/* udp_fanout_t *udp_bind_fanout. */
static udp_fanout_t *udp_bind_fanout;

/*
 * This controls the rate some ndd info report functions can be used
 * by non-priviledged users.  It stores the last time such info is
 * requested.  When those report functions are called again, this
 * is checked with the current time and compare with the ndd param
 * udp_ndd_get_info_interval.
 */
static clock_t udp_last_ndd_get_info_time;
#define	NDD_TOO_QUICK_MSG \
	"ndd get info rate too high for non-priviledged users, try again " \
	"later.\n"
#define	NDD_OUT_OF_BUF_MSG	"<< Out of buffer >>\n"

/* Named Dispatch Parameter Management Structure */
typedef struct udpparam_s {
	uint32_t udp_param_min;
	uint32_t udp_param_max;
	uint32_t udp_param_value;
	char	*udp_param_name;
} udpparam_t;

static void	udp_addr_req(queue_t *q, mblk_t *mp);
static void	udp_bind(queue_t *q, mblk_t *mp);
static void	udp_bind_hash_insert(udp_fanout_t *uf, udp_t *udp);
static void	udp_bind_hash_remove(udp_t *udp, boolean_t caller_holds_lock);
static int	udp_build_hdrs(queue_t *q, udp_t *udp);
static void	udp_capability_req(queue_t *q, mblk_t *mp);
static int	udp_close(queue_t *q);
static void	udp_connect(queue_t *q, mblk_t *mp);
static void	udp_disconnect(queue_t *q, mblk_t *mp);
static void	udp_err_ack(queue_t *q, mblk_t *mp, t_scalar_t t_error,
		    int sys_error);
static void	udp_err_ack_prim(queue_t *q, mblk_t *mp, int primitive,
		    t_scalar_t tlierr, int unixerr);
static int	udp_extra_priv_ports_get(queue_t *q, mblk_t *mp, caddr_t cp,
		    cred_t *cr);
static int	udp_extra_priv_ports_add(queue_t *q, mblk_t *mp,
		    char *value, caddr_t cp, cred_t *cr);
static int	udp_extra_priv_ports_del(queue_t *q, mblk_t *mp,
		    char *value, caddr_t cp, cred_t *cr);
static void	udp_icmp_error(queue_t *q, mblk_t *mp);
static void	udp_icmp_error_ipv6(queue_t *q, mblk_t *mp);
static void	udp_info_req(queue_t *q, mblk_t *mp);
static mblk_t	*udp_ip_bind_mp(udp_t *udp, t_scalar_t bind_prim,
		    t_scalar_t addr_length);
static int	udp_open(queue_t *q, dev_t *devp, int flag, int sflag,
		    cred_t *credp);
static  int	udp_unitdata_opt_process(queue_t *q, mblk_t *mp,
		    int *errorp, void *thisdg_attrs);
static boolean_t udp_opt_allow_udr_set(t_scalar_t level, t_scalar_t name);
int		udp_opt_default(queue_t *q, t_scalar_t level, t_scalar_t name,
		    uchar_t *ptr);
int		udp_opt_get(queue_t *q, t_scalar_t level, t_scalar_t name,
		    uchar_t *ptr);
int		udp_opt_set(queue_t *q, uint_t optset_context,
		    int level, int name,
		    uint_t inlen, uchar_t *invalp,
		    uint_t *outlenp, uchar_t *outvalp,
		    void *thisdg_attrs, cred_t *cr, mblk_t *mblk);
static int	udp_param_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *cr);
static boolean_t udp_param_register(udpparam_t *udppa, int cnt);
static int	udp_param_set(queue_t *q, mblk_t *mp, char *value, caddr_t cp,
		    cred_t *cr);
static int	udp_pkt_set(uchar_t *invalp, uint_t inlen, boolean_t sticky,
		    uchar_t **optbufp, uint_t *optlenp);
static void	udp_report_item(mblk_t *mp, udp_t *udp);
static void	udp_rput(queue_t *q, mblk_t *mp);
static	void	udp_rput_bind_ack(queue_t *q, mblk_t *mp);
static void	udp_rput_other(queue_t *q, mblk_t *mp);
static int	udp_snmp_get(queue_t *q, mblk_t *mpctl);
static int	udp_snmp_set(queue_t *q, t_scalar_t level, t_scalar_t name,
		    uchar_t *ptr, int len);
static int	udp_status_report(queue_t *q, mblk_t *mp, caddr_t cp,
		    cred_t *cr);
static void	udp_ud_err(queue_t *q, mblk_t *mp, t_scalar_t err);
static void	udp_unbind(queue_t *q, mblk_t *mp);
static in_port_t udp_update_next_port(in_port_t port, boolean_t random);
static void	udp_wput(queue_t *q, mblk_t *mp);
static void	udp_wput_ipv6(queue_t *q, mblk_t *mp, sin6_t *sin6,
		    t_scalar_t tudr_optlen);
static void	udp_wput_other(queue_t *q, mblk_t *mp);
static void	udp_wput_iocdata(queue_t *q, mblk_t *mp);

static void	udp_kstat_init(void);
static void	udp_kstat_fini(void);
static int	udp_kstat_update(kstat_t *kp, int rw);

major_t UDP6_MAJ;
#define		UDP6		"udp6"

#define		UDP_MAXPACKET_IPV4	\
	(IP_MAXPACKET - UDPH_SIZE - IP_SIMPLE_HDR_LENGTH)
#define		UDP_MAXPACKET_IPV6	\
	(IP_MAXPACKET - UDPH_SIZE - IPV6_HDR_LEN)

static struct module_info info =  {
	5607, "udp", 1, INFPSZ, 512, 128
};

static struct qinit rinit = {
	(pfi_t)udp_rput, NULL, udp_open, udp_close, NULL, &info
};

static struct qinit winit = {
	(pfi_t)udp_wput, NULL, NULL, NULL, NULL, &info
};

struct streamtab udpinfo = {
	&rinit, &winit
};

static	sin_t	sin_null;	/* Zero address for quick clears */
static	sin6_t	sin6_null;	/* Zero address for quick clears */

/* Protected by udp_g_lock */
static void	*udp_g_head;	/* Head for list of open udp streams. */
kmutex_t	udp_g_lock;	/* Protects the above variable */

/* Hint not protected by any lock */
static in_port_t	udp_g_next_port_to_try;

/*
 * Extra privileged ports. In host byte order. Protected by udp_g_lock.
 */
#define	UDP_NUM_EPRIV_PORTS	64
static int	udp_g_num_epriv_ports = UDP_NUM_EPRIV_PORTS;
static in_port_t udp_g_epriv_ports[UDP_NUM_EPRIV_PORTS] = { 2049, 4045 };

/* Only modified during _init and _fini thus no locking is needed. */
static IDP	udp_g_nd;	/* Points to table of UDP ND variables. */

/* MIB-2 stuff for SNMP */
static mib2_udp_t	udp_mib;	/* SNMP fixed size info */
static kstat_t		*udp_mibkp;	/* kstat exporting udp_mib data */


/* Default structure copied into T_INFO_ACK messages */
static struct T_info_ack udp_g_t_info_ack_ipv4 = {
	T_INFO_ACK,
	UDP_MAXPACKET_IPV4,	/* TSDU_size. Excl. headers */
	T_INVALID,	/* ETSU_size.  udp does not support expedited data. */
	T_INVALID,	/* CDATA_size. udp does not support connect data. */
	T_INVALID,	/* DDATA_size. udp does not support disconnect data. */
	sizeof (sin_t),	/* ADDR_size. */
	0,		/* OPT_size - not initialized here */
	UDP_MAXPACKET_IPV4,	/* TIDU_size.  Excl. headers */
	T_CLTS,		/* SERV_type.  udp supports connection-less. */
	TS_UNBND,	/* CURRENT_state.  This is set from udp_state. */
	(XPG4_1|SENDZERO) /* PROVIDER_flag */
};

static	struct T_info_ack udp_g_t_info_ack_ipv6 = {
	T_INFO_ACK,
	UDP_MAXPACKET_IPV6,	/* TSDU_size.  Excl. headers */
	T_INVALID,	/* ETSU_size.  udp does not support expedited data. */
	T_INVALID,	/* CDATA_size. udp does not support connect data. */
	T_INVALID,	/* DDATA_size. udp does not support disconnect data. */
	sizeof (sin6_t), /* ADDR_size. */
	0,		/* OPT_size - not initialized here */
	UDP_MAXPACKET_IPV6,	/* TIDU_size. Excl. headers */
	T_CLTS,		/* SERV_type.  udp supports connection-less. */
	TS_UNBND,	/* CURRENT_state.  This is set from udp_state. */
	(XPG4_1|SENDZERO) /* PROVIDER_flag */
};

/* largest UDP port number */
#define	UDP_MAX_PORT	65535

/*
 * Table of ND variables supported by udp.  These are loaded into udp_g_nd
 * in udp_open.
 * All of these are alterable, within the min/max values given, at run time.
 */
static udpparam_t	udp_param_arr[] = {
	/* min	max		value		name */
	{ 0L,	256,		32,		"udp_wroff_extra" },
	{ 1L,	255,		255,		"udp_ipv4_ttl" },
	{ 0, IPV6_MAX_HOPS, IPV6_DEFAULT_HOPS,	"udp_ipv6_hoplimit"},
	{ 1024,	(32 * 1024),	1024,		"udp_smallest_nonpriv_port" },
	{ 0,	1,		1,		"udp_do_checksum" },
	{ 1024,	UDP_MAX_PORT,	(32 * 1024),	"udp_smallest_anon_port" },
	{ 1024,	UDP_MAX_PORT,	UDP_MAX_PORT,	"udp_largest_anon_port" },
	{ 4096,	1024*1024,	56*1024,	"udp_xmit_hiwat"},
	{ 0,	1024*1024,	1024,		"udp_xmit_lowat"},
	{ 4096,	1024*1024,	56*1024,	"udp_recv_hiwat"},
	{ 65536, 1024*1024*1024, 2*1024*1024,	"udp_max_buf"},
	{ 100,	60000,		1000,		"udp_ndd_get_info_interval"},
};
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

/*
 * The smallest anonymous port in the priviledged port range which UDP
 * looks for free port.  Use in the option UDP_ANONPRIVBIND.
 */
static in_port_t udp_min_anonpriv_port = 512;

/* If set to 0, pick ephemeral port sequentially; otherwise randomly. */
uint32_t udp_random_anon_port = 1;

/*
 * Hook functions to enable cluster networking.
 * On non-clustered systems these vectors must always be NULL
 */

void (*cl_inet_bind)(uchar_t protocol, sa_family_t addr_family,
			uint8_t *laddrp, in_port_t lport) = NULL;
void (*cl_inet_unbind)(uint8_t protocol, sa_family_t addr_family,
			uint8_t *laddrp, in_port_t lport) = NULL;

/*
 * Return the next anonymous port in the priviledged port range for
 * bind checking.
 */
static in_port_t
udp_get_next_priv_port(void)
{
	static in_port_t next_priv_port = IPPORT_RESERVED - 1;

	if (next_priv_port < udp_min_anonpriv_port) {
		next_priv_port = IPPORT_RESERVED - 1;
	}
	return (next_priv_port--);
}

/* UDP bind hash report triggered via the Named Dispatch mechanism. */
/* ARGSUSED */
static int
udp_bind_hash_report(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	udp_fanout_t	*udpf;
	udp_t		*udp;
	int		i;
	zoneid_t	zoneid;

	/* Refer to comments in udp_status_report(). */
	if (cr == NULL || secpolicy_net_config(cr, B_TRUE) != 0) {
		if (ddi_get_lbolt() - udp_last_ndd_get_info_time <
		    drv_usectohz(udp_ndd_get_info_interval * 1000)) {
			(void) mi_mpprintf(mp, NDD_TOO_QUICK_MSG);
			return (0);
		}
	}
	if ((mp->b_cont = allocb(ND_MAX_BUF_LEN, BPRI_HI)) == NULL) {
		/* The following may work even if we cannot get a large buf. */
		(void) mi_mpprintf(mp, NDD_OUT_OF_BUF_MSG);
		return (0);
	}

	(void) mi_mpprintf(mp,
	    "UDP     " MI_COL_HDRPAD_STR
	/*   12345678[89ABCDEF] */
	    " zone lport src addr        dest addr       port  state");
	/*    1234 12345 xxx.xxx.xxx.xxx xxx.xxx.xxx.xxx 12345 UNBOUND */

	udp = (udp_t *)q->q_ptr;
	zoneid = udp->udp_zoneid;

	for (i = 0; i < udp_bind_fanout_size; i++) {
		udpf = &udp_bind_fanout[i];
		mutex_enter(&udpf->uf_lock);

		/* Print the hash index. */
		udp = udpf->uf_udp;
		if (zoneid != GLOBAL_ZONEID) {
			/* skip to first entry in this zone; might be none */
			while (udp != NULL &&
			    udp->udp_zoneid != zoneid)
				udp = udp->udp_bind_hash;
		}
		if (udp != NULL) {
			uint_t print_len, buf_len;

			buf_len = mp->b_cont->b_datap->db_lim -
			    mp->b_cont->b_wptr;
			print_len = snprintf((char *)mp->b_cont->b_wptr,
			    buf_len, "%d\n", i);
			if (print_len < buf_len) {
				mp->b_cont->b_wptr += print_len;
			} else {
				mp->b_cont->b_wptr += buf_len;
			}
			for (; udp != NULL; udp = udp->udp_bind_hash) {
				if (zoneid == GLOBAL_ZONEID ||
				    zoneid == udp->udp_zoneid)
					udp_report_item(mp->b_cont, udp);
			}
		}
		mutex_exit(&udpf->uf_lock);
	}
	udp_last_ndd_get_info_time = ddi_get_lbolt();
	return (0);
}

/*
 * Hash list removal routine for udp_t structures.
 */
static void
udp_bind_hash_remove(udp_t *udp, boolean_t caller_holds_lock)
{
	udp_t	*udpnext;
	kmutex_t *lockp;

	if (udp->udp_ptpbhn == NULL)
		return;

	/*
	 * Extract the lock pointer in case there are concurrent
	 * hash_remove's for this instance.
	 */
	ASSERT(udp->udp_port != 0);
	if (!caller_holds_lock) {
		lockp = &udp_bind_fanout[UDP_BIND_HASH(udp->udp_port)].uf_lock;
		ASSERT(lockp != NULL);
		mutex_enter(lockp);
	}
	if (udp->udp_ptpbhn != NULL) {
		udpnext = udp->udp_bind_hash;
		if (udpnext != NULL) {
			udpnext->udp_ptpbhn = udp->udp_ptpbhn;
			udp->udp_bind_hash = NULL;
		}
		*udp->udp_ptpbhn = udpnext;
		udp->udp_ptpbhn = NULL;
	}
	if (!caller_holds_lock) {
		mutex_exit(lockp);
	}
}

static void
udp_bind_hash_insert(udp_fanout_t *uf, udp_t *udp)
{
	udp_t	**udpp;
	udp_t	*udpnext;

	ASSERT(MUTEX_HELD(&uf->uf_lock));
	if (udp->udp_ptpbhn != NULL) {
		udp_bind_hash_remove(udp, B_TRUE);
	}
	udpp = &uf->uf_udp;
	udpnext = udpp[0];
	if (udpnext != NULL) {
		/*
		 * If the new udp bound to the INADDR_ANY address
		 * and the first one in the list is not bound to
		 * INADDR_ANY we skip all entries until we find the
		 * first one bound to INADDR_ANY.
		 * This makes sure that applications binding to a
		 * specific address get preference over those binding to
		 * INADDR_ANY.
		 */
		if (V6_OR_V4_INADDR_ANY(udp->udp_bound_v6src) &&
		    !V6_OR_V4_INADDR_ANY(udpnext->udp_bound_v6src)) {
			while ((udpnext = udpp[0]) != NULL &&
			    !V6_OR_V4_INADDR_ANY(
			    udpnext->udp_bound_v6src)) {
				udpp = &(udpnext->udp_bind_hash);
			}
			if (udpnext != NULL)
				udpnext->udp_ptpbhn = &udp->udp_bind_hash;
		} else {
			udpnext->udp_ptpbhn = &udp->udp_bind_hash;
		}
	}
	udp->udp_bind_hash = udpnext;
	udp->udp_ptpbhn = udpp;
	udpp[0] = udp;
}

/*
 * This routine is called to handle each O_T_BIND_REQ/T_BIND_REQ message
 * passed to udp_wput.
 * It associates a port number and local address with the stream.
 * The O_T_BIND_REQ/T_BIND_REQ is passed downstream to ip with the UDP
 * protocol type (IPPROTO_UDP) placed in the message following the address.
 * A T_BIND_ACK message is passed upstream when ip acknowledges the request.
 * (Called as writer.)
 *
 * Note that UDP over IPv4 and IPv6 sockets can use the same port number
 * without setting SO_REUSEADDR. This is needed so that they
 * can be viewed as two independent transport protocols.
 * However, anonymouns ports are allocated from the same range to avoid
 * duplicating the udp_g_next_port_to_try.
 */
static void
udp_bind(queue_t *q, mblk_t *mp)
{
	sin_t		*sin;
	sin6_t		*sin6;
	mblk_t		*mp1;
	in_port_t	port;		/* Host byte order */
	in_port_t	requested_port;	/* Host byte order */
	struct T_bind_req *tbr;
	udp_t		*udp;
	int		count;
	in6_addr_t	v6src;
	boolean_t	bind_to_req_port_only;
	int		loopmax;
	udp_fanout_t	*udpf;
	in_port_t	lport;		/* Network byte order */
	zoneid_t	zoneid;

	udp = (udp_t *)q->q_ptr;
	if ((mp->b_wptr - mp->b_rptr) < sizeof (*tbr)) {
		(void) mi_strlog(q, 1, SL_ERROR|SL_TRACE,
		    "udp_bind: bad req, len %u",
		    (uint_t)(mp->b_wptr - mp->b_rptr));
		udp_err_ack(q, mp, TPROTO, 0);
		return;
	}
	if (udp->udp_state != TS_UNBND) {
		(void) mi_strlog(q, 1, SL_ERROR|SL_TRACE,
		    "udp_bind: bad state, %u", udp->udp_state);
		udp_err_ack(q, mp, TOUTSTATE, 0);
		return;
	}
	/*
	 * Reallocate the message to make sure we have enough room for an
	 * address and the protocol type.
	 */
	mp1 = reallocb(mp, sizeof (struct T_bind_ack) + sizeof (sin6_t) + 1, 1);
	if (!mp1) {
		udp_err_ack(q, mp, TSYSERR, ENOMEM);
		return;
	}

	mp = mp1;
	tbr = (struct T_bind_req *)mp->b_rptr;
	switch (tbr->ADDR_length) {
	case 0:			/* Request for a generic port */
		tbr->ADDR_offset = sizeof (struct T_bind_req);
		if (udp->udp_family == AF_INET) {
			tbr->ADDR_length = sizeof (sin_t);
			sin = (sin_t *)&tbr[1];
			*sin = sin_null;
			sin->sin_family = AF_INET;
			mp->b_wptr = (uchar_t *)&sin[1];
		} else {
			ASSERT(udp->udp_family == AF_INET6);
			tbr->ADDR_length = sizeof (sin6_t);
			sin6 = (sin6_t *)&tbr[1];
			*sin6 = sin6_null;
			sin6->sin6_family = AF_INET6;
			mp->b_wptr = (uchar_t *)&sin6[1];
		}
		port = 0;
		break;

	case sizeof (sin_t):	/* Complete IPv4 address */
		sin = (sin_t *)mi_offset_param(mp, tbr->ADDR_offset,
		    sizeof (sin_t));
		if (sin == NULL || !OK_32PTR((char *)sin)) {
			udp_err_ack(q, mp, TSYSERR, EINVAL);
			return;
		}
		if (udp->udp_family != AF_INET ||
		    sin->sin_family != AF_INET) {
			udp_err_ack(q, mp, TSYSERR, EAFNOSUPPORT);
			return;
		}
		port = ntohs(sin->sin_port);
		break;

	case sizeof (sin6_t):	/* complete IPv6 address */
		sin6 = (sin6_t *)mi_offset_param(mp, tbr->ADDR_offset,
		    sizeof (sin6_t));
		if (sin6 == NULL || !OK_32PTR((char *)sin6)) {
			udp_err_ack(q, mp, TSYSERR, EINVAL);
			return;
		}
		if (udp->udp_family != AF_INET6 ||
		    sin6->sin6_family != AF_INET6) {
			udp_err_ack(q, mp, TSYSERR, EAFNOSUPPORT);
			return;
		}
		port = ntohs(sin6->sin6_port);
		break;

	default:		/* Invalid request */
		(void) mi_strlog(q, 1, SL_ERROR|SL_TRACE,
		    "udp_bind: bad ADDR_length length %u", tbr->ADDR_length);
		udp_err_ack(q, mp, TBADADDR, 0);
		return;
	}

	requested_port = port;

	if (requested_port == 0 || tbr->PRIM_type == O_T_BIND_REQ)
		bind_to_req_port_only = B_FALSE;
	else			/* T_BIND_REQ and requested_port != 0 */
		bind_to_req_port_only = B_TRUE;

	if (requested_port == 0) {
		/*
		 * If the application passed in zero for the port number, it
		 * doesn't care which port number we bind to. Get one in the
		 * valid range.
		 */
		if (udp->udp_anon_priv_bind) {
			port = udp_get_next_priv_port();
		} else {
			port = udp_update_next_port(udp_g_next_port_to_try,
			    B_TRUE);
		}
	} else {
		/*
		 * If the port is in the well-known privileged range,
		 * make sure the caller was privileged.
		 */
		int i;
		boolean_t priv = B_FALSE;

		if (port < udp_smallest_nonpriv_port) {
			priv = B_TRUE;
		} else {
			for (i = 0; i < udp_g_num_epriv_ports; i++) {
				if (port == udp_g_epriv_ports[i]) {
					priv = B_TRUE;
					break;
				}
			}
		}

		if (priv) {
			cred_t *cr = DB_CREDDEF(mp, udp->udp_credp);

			if (secpolicy_net_privaddr(cr, port) != 0) {
				udp_err_ack(q, mp, TACCES, 0);
				return;
			}
		}
	}

	/*
	 * Copy the source address into our udp structure. This address
	 * may still be zero; if so, IP will fill in the correct address
	 * each time an outbound packet is passed to it.
	 */
	if (udp->udp_family == AF_INET) {
		ASSERT(sin != NULL);
		ASSERT(udp->udp_ipversion == IPV4_VERSION);
		udp->udp_max_hdr_len = IP_SIMPLE_HDR_LENGTH + UDPH_SIZE +
		    udp->udp_ip_snd_options_len;
		IN6_IPADDR_TO_V4MAPPED(sin->sin_addr.s_addr, &v6src);
	} else {
		ASSERT(sin6 != NULL);
		v6src = sin6->sin6_addr;
		if (IN6_IS_ADDR_V4MAPPED(&v6src)) {
			udp->udp_ipversion = IPV4_VERSION;
			udp->udp_max_hdr_len = IP_SIMPLE_HDR_LENGTH +
			    UDPH_SIZE + udp->udp_ip_snd_options_len;
		} else {
			udp->udp_ipversion = IPV6_VERSION;
			udp->udp_max_hdr_len = udp->udp_sticky_hdrs_len;
		}
	}

	/*
	 * If udp_reuseaddr is not set, then we have to make sure that
	 * the IP address and port number the application requested
	 * (or we selected for the application) is not being used by
	 * another stream.  If another stream is already using the
	 * requested IP address and port, the behavior depends on
	 * "bind_to_req_port_only". If set the bind fails; otherwise we
	 * search for any an unused port to bind to the the stream.
	 *
	 * As per the BSD semantics, as modified by the Deering multicast
	 * changes, if udp_reuseaddr is set, then we allow multiple binds
	 * to the same port independent of the local IP address.
	 *
	 * This is slightly different than in SunOS 4.X which did not
	 * support IP multicast. Note that the change implemented by the
	 * Deering multicast code effects all binds - not only binding
	 * to IP multicast addresses.
	 *
	 * Note that when binding to port zero we ignore SO_REUSEADDR in
	 * order to guarantee a unique port.
	 */

	count = 0;
	if (udp->udp_anon_priv_bind) {
		/* loopmax = (IPPORT_RESERVED-1) - udp_min_anonpriv_port + 1 */
		loopmax = IPPORT_RESERVED - udp_min_anonpriv_port;
	} else {
		loopmax = udp_largest_anon_port - udp_smallest_anon_port + 1;
	}

	zoneid = udp->udp_zoneid;
	for (;;) {
		udp_t		*udp1;
		boolean_t	is_inaddr_any;
		boolean_t	found_exclbind = B_FALSE;

		is_inaddr_any = V6_OR_V4_INADDR_ANY(v6src);
		/*
		 * Walk through the list of udp streams bound to
		 * requested port with the same IP address.
		 */
		lport = htons(port);
		udpf = &udp_bind_fanout[UDP_BIND_HASH(lport)];
		mutex_enter(&udpf->uf_lock);
		for (udp1 = udpf->uf_udp; udp1 != NULL;
		    udp1 = udp1->udp_bind_hash) {
			if (lport != udp1->udp_port ||
			    zoneid != udp1->udp_zoneid)
				continue;

			/*
			 * If UDP_EXCLBIND is set for either the bound or
			 * binding endpoint, the semantics of bind
			 * is changed according to the following chart.
			 *
			 * spec = specified address (v4 or v6)
			 * unspec = unspecified address (v4 or v6)
			 * A = specified addresses are different for endpoints
			 *
			 * bound	bind to		allowed?
			 * -------------------------------------
			 * unspec	unspec		no
			 * unspec	spec		no
			 * spec		unspec		no
			 * spec		spec		yes if A
			 */
			if (udp1->udp_exclbind || udp->udp_exclbind) {
				if (V6_OR_V4_INADDR_ANY(
				    udp1->udp_bound_v6src) ||
				    is_inaddr_any ||
				    IN6_ARE_ADDR_EQUAL(&udp1->udp_bound_v6src,
				    &v6src)) {
					found_exclbind = B_TRUE;
					break;
				}
				continue;
			}

			/*
			 * Check ipversion to allow IPv4 and IPv6 sockets to
			 * have disjoint port number spaces.
			 */
			if (udp->udp_ipversion != udp1->udp_ipversion)
				continue;

			/*
			 * No difference depending on SO_REUSEADDR.
			 *
			 * If existing port is bound to a
			 * non-wildcard IP address and
			 * the requesting stream is bound to
			 * a distinct different IP addresses
			 * (non-wildcard, also), keep going.
			 */
			if (!is_inaddr_any &&
			    !V6_OR_V4_INADDR_ANY(udp1->udp_bound_v6src) &&
			    !IN6_ARE_ADDR_EQUAL(&udp1->udp_bound_v6src,
			    &v6src)) {
				continue;
			}
			break;
		}

		if (!found_exclbind &&
		    (udp->udp_reuseaddr && requested_port != 0)) {
			break;
		}

		if (udp1 == NULL) {
			/*
			 * No other stream has this IP address
			 * and port number. We can use it.
			 */
			break;
		}
		mutex_exit(&udpf->uf_lock);
		if (bind_to_req_port_only) {
			/*
			 * We get here only when requested port
			 * is bound (and only first  of the for()
			 * loop iteration).
			 *
			 * The semantics of this bind request
			 * require it to fail so we return from
			 * the routine (and exit the loop).
			 *
			 */
			udp_err_ack(q, mp, TADDRBUSY, 0);
			return;
		}

		if (udp->udp_anon_priv_bind) {
			port = udp_get_next_priv_port();
		} else {
			if ((count == 0) && (requested_port != 0)) {
				/*
				 * If the application wants us to find
				 * a port, get one to start with. Set
				 * requested_port to 0, so that we will
				 * update udp_g_next_port_to_try below.
				 */
				port = udp_update_next_port(
				    udp_g_next_port_to_try, B_TRUE);
				requested_port = 0;
			} else {
				port = udp_update_next_port(port + 1, B_FALSE);
			}
		}

		if (++count >= loopmax) {
			/*
			 * We've tried every possible port number and
			 * there are none available, so send an error
			 * to the user.
			 */
			udp_err_ack(q, mp, TNOADDR, 0);
			return;
		}
	}

	/*
	 * Copy the source address into our udp structure.  This address
	 * may still be zero; if so, ip will fill in the correct address
	 * each time an outbound packet is passed to it.
	 * If we are binding to a broadcast or multicast address udp_rput
	 * will clear the source address when it receives the T_BIND_ACK.
	 */
	udp->udp_v6src = udp->udp_bound_v6src = v6src;
	udp->udp_port = lport;
	/*
	 * Now reset the the next anonymous port if the application requested
	 * an anonymous port, or we handed out the next anonymous port.
	 */
	if ((requested_port == 0) && (!udp->udp_anon_priv_bind)) {
		udp_g_next_port_to_try = port + 1;
	}

	/* Initialize the O_T_BIND_REQ/T_BIND_REQ for ip. */
	if (udp->udp_family == AF_INET) {
		sin->sin_port = udp->udp_port;
	} else {
		int error;

		sin6->sin6_port = udp->udp_port;
		/* Rebuild the header template */
		error = udp_build_hdrs(q, udp);
		if (error != 0) {
			mutex_exit(&udpf->uf_lock);
			udp_err_ack(q, mp, TSYSERR, error);
			return;
		}
	}
	udp->udp_state = TS_IDLE;
	udp_bind_hash_insert(udpf, udp);
	mutex_exit(&udpf->uf_lock);

	if (cl_inet_bind) {
		/*
		 * Running in cluster mode - register bind information
		 */
		if (udp->udp_ipversion == IPV4_VERSION) {
			(*cl_inet_bind)(IPPROTO_UDP, AF_INET,
			    (uint8_t *)(&V4_PART_OF_V6(udp->udp_v6src)),
			    (in_port_t)udp->udp_port);
		} else {
			(*cl_inet_bind)(IPPROTO_UDP, AF_INET6,
			    (uint8_t *)&(udp->udp_v6src),
			    (in_port_t)udp->udp_port);
		}

	}

	/* Pass the protocol number in the message following the address. */
	*mp->b_wptr++ = IPPROTO_UDP;
	if (!V6_OR_V4_INADDR_ANY(udp->udp_v6src)) {
		/*
		 * Append a request for an IRE if udp_v6src not
		 * zero (IPv4 - INADDR_ANY, or IPv6 - all-zeroes address).
		 */
		mp->b_cont = allocb(sizeof (ire_t), BPRI_HI);
		if (!mp->b_cont) {
			udp_err_ack(q, mp, TSYSERR, ENOMEM);
			return;
		}
		mp->b_cont->b_wptr += sizeof (ire_t);
		mp->b_cont->b_datap->db_type = IRE_DB_REQ_TYPE;
	}
	putnext(q, mp);
}

/*
 * This routine handles each T_CONN_REQ message passed to udp.  It
 * associates a default destination address with the stream.
 *
 * This routine sends down a T_BIND_REQ to IP with the following mblks:
 *	T_BIND_REQ	- specifying local and remote address/port
 *	IRE_DB_REQ_TYPE	- to get an IRE back containing ire_type and src
 *	T_OK_ACK	- for the T_CONN_REQ
 *	T_CONN_CON	- to keep the TPI user happy
 *
 * The connect completes in udp_rput.
 * When a T_BIND_ACK is received information is extracted from the IRE
 * and the two appended messages are sent to the TPI user.
 * Should udp_rput receive T_ERROR_ACK for the T_BIND_REQ it will convert
 * it to an error ack for the appropriate primitive.
 */
static void
udp_connect(queue_t *q, mblk_t *mp)
{
	sin6_t	*sin6;
	sin_t	*sin;
	struct T_conn_req	*tcr;
	udp_t	*udp, *udp1;
	in6_addr_t v6dst;
	ipaddr_t v4dst;
	uint16_t dstport;
	uint32_t flowinfo;
	mblk_t	*mp1, *mp2;
	udp_fanout_t	*udpf;

	udp = (udp_t *)q->q_ptr;
	tcr = (struct T_conn_req *)mp->b_rptr;

	/* A bit of sanity checking */
	if ((mp->b_wptr - mp->b_rptr) < sizeof (struct T_conn_req)) {
		udp_err_ack(q, mp, TPROTO, 0);
		return;
	}
	/*
	 * This UDP must have bound to a port already before doing
	 * a connect.
	 */
	if (udp->udp_state == TS_UNBND) {
		(void) mi_strlog(q, 1, SL_ERROR|SL_TRACE,
		    "udp_connect: bad state, %u", udp->udp_state);
		udp_err_ack(q, mp, TOUTSTATE, 0);
		return;
	}
	ASSERT(udp->udp_port != 0 && udp->udp_ptpbhn != NULL);

	udpf = &udp_bind_fanout[UDP_BIND_HASH(udp->udp_port)];
	if (udp->udp_state == TS_DATA_XFER) {
		/* Already connected - clear out state */
		mutex_enter(&udpf->uf_lock);
		udp->udp_v6src = udp->udp_bound_v6src;
		udp->udp_state = TS_IDLE;
		mutex_exit(&udpf->uf_lock);
	}

	if (tcr->OPT_length != 0) {
		udp_err_ack(q, mp, TBADOPT, 0);
		return;
	}

	/*
	 * Determine packet type based on type of address passed in
	 * the request should contain an IPv4 or IPv6 address.
	 * Make sure that address family matches the type of
	 * family of the the address passed down
	 */
	switch (tcr->DEST_length) {
	default:
		udp_err_ack(q, mp, TBADADDR, 0);
		return;

	case sizeof (sin_t):
		sin = (sin_t *)mi_offset_param(mp, tcr->DEST_offset,
		    sizeof (sin_t));
		if (sin == NULL || !OK_32PTR((char *)sin)) {
			udp_err_ack(q, mp, TSYSERR, EINVAL);
			return;
		}
		if (udp->udp_family != AF_INET ||
		    sin->sin_family != AF_INET) {
			udp_err_ack(q, mp, TSYSERR, EAFNOSUPPORT);
			return;
		}
		v4dst = sin->sin_addr.s_addr;
		dstport = sin->sin_port;
		IN6_IPADDR_TO_V4MAPPED(v4dst, &v6dst);
		ASSERT(udp->udp_ipversion == IPV4_VERSION);
		udp->udp_max_hdr_len = IP_SIMPLE_HDR_LENGTH + UDPH_SIZE +
		    udp->udp_ip_snd_options_len;
		break;

	case sizeof (sin6_t):
		sin6 = (sin6_t *)mi_offset_param(mp, tcr->DEST_offset,
		    sizeof (sin6_t));
		if (sin6 == NULL || !OK_32PTR((char *)sin6)) {
			udp_err_ack(q, mp, TSYSERR, EINVAL);
			return;
		}
		if (udp->udp_family != AF_INET6 ||
		    sin6->sin6_family != AF_INET6) {
			udp_err_ack(q, mp, TSYSERR, EAFNOSUPPORT);
			return;
		}
		v6dst = sin6->sin6_addr;
		if (IN6_IS_ADDR_V4MAPPED(&v6dst)) {
			IN6_V4MAPPED_TO_IPADDR(&v6dst, v4dst);
			udp->udp_ipversion = IPV4_VERSION;
			udp->udp_max_hdr_len = IP_SIMPLE_HDR_LENGTH +
			    UDPH_SIZE + udp->udp_ip_snd_options_len;
			flowinfo = 0;
		} else {
			udp->udp_ipversion = IPV6_VERSION;
			udp->udp_max_hdr_len = udp->udp_sticky_hdrs_len;
			flowinfo = sin6->sin6_flowinfo;
		}
		dstport = sin6->sin6_port;
		break;
	}
	if (dstport == 0) {
		udp_err_ack(q, mp, TBADADDR, 0);
		return;
	}

	/*
	 * Create a default IP header with no IP options.
	 */
	udp->udp_dstport = dstport;
	if (udp->udp_ipversion == IPV4_VERSION) {
		/*
		 * Interpret a zero destination to mean loopback.
		 * Update the T_CONN_REQ (sin/sin6) since it is used to
		 * generate the T_CONN_CON.
		 */
		if (v4dst == INADDR_ANY) {
			v4dst = htonl(INADDR_LOOPBACK);
			IN6_IPADDR_TO_V4MAPPED(v4dst, &v6dst);
			if (udp->udp_family == AF_INET) {
				sin->sin_addr.s_addr = v4dst;
			} else {
				sin6->sin6_addr = v6dst;
			}
		}
		udp->udp_v6dst = v6dst;
		udp->udp_flowinfo = 0;

		/*
		 * If the destination address is multicast and
		 * an outgoing multicast interface has been set,
		 * use the address of that interface as our
		 * source address if no source address has been set.
		 */
		if (V4_PART_OF_V6(udp->udp_v6src) == INADDR_ANY &&
		    CLASSD(v4dst) &&
		    udp->udp_multicast_if_addr != INADDR_ANY) {
			IN6_IPADDR_TO_V4MAPPED(udp->udp_multicast_if_addr,
			    &udp->udp_v6src);
		}
	} else {
		ASSERT(udp->udp_ipversion == IPV6_VERSION);
		/*
		 * Interpret a zero destination to mean loopback.
		 * Update the T_CONN_REQ (sin/sin6) since it is used to
		 * generate the T_CONN_CON.
		 */
		if (IN6_IS_ADDR_UNSPECIFIED(&v6dst)) {
			v6dst = ipv6_loopback;
			sin6->sin6_addr = v6dst;
		}
		udp->udp_v6dst = v6dst;
		udp->udp_flowinfo = flowinfo;
		/*
		 * If the destination address is multicast and
		 * an outgoing multicast interface has been set,
		 * then the ip bind logic will pick the correct source
		 * address (i.e. matching the outgoing multicast interface).
		 */
	}

	/*
	 * Verify that the src/port/dst/port is unique for all
	 * connections in TS_DATA_XFER
	 */
	mutex_enter(&udpf->uf_lock);
	for (udp1 = udpf->uf_udp; udp1 != NULL; udp1 = udp1->udp_bind_hash) {
		if (udp1->udp_state != TS_DATA_XFER)
			continue;
		if (udp->udp_port != udp1->udp_port ||
		    udp->udp_ipversion != udp1->udp_ipversion ||
		    dstport != udp1->udp_dstport ||
		    !IN6_ARE_ADDR_EQUAL(&udp->udp_v6src, &udp1->udp_v6src) ||
		    !IN6_ARE_ADDR_EQUAL(&v6dst, &udp1->udp_v6dst))
			continue;
		mutex_exit(&udpf->uf_lock);
		udp_err_ack(q, mp, TBADADDR, 0);
		return;
	}
	udp->udp_state = TS_DATA_XFER;
	mutex_exit(&udpf->uf_lock);

	/*
	 * Send down bind to IP to verify that there is a route
	 * and to determine the source address.
	 * This will come back as T_BIND_ACK with an IRE_DB_TYPE in rput.
	 */
	if (udp->udp_family == AF_INET)
		mp1 = udp_ip_bind_mp(udp, O_T_BIND_REQ, sizeof (ipa_conn_t));
	else
		mp1 = udp_ip_bind_mp(udp, O_T_BIND_REQ, sizeof (ipa6_conn_t));
	if (mp1 == NULL) {
		udp_err_ack(q, mp, TSYSERR, ENOMEM);
bind_failed:
		mutex_enter(&udpf->uf_lock);
		udp->udp_state = TS_IDLE;
		mutex_exit(&udpf->uf_lock);
		return;
	}

	/*
	 * We also have to send a connection confirmation to
	 * keep TLI happy. Prepare it for udp_rput.
	 */
	if (udp->udp_family == AF_INET)
		mp2 = mi_tpi_conn_con(NULL, (char *)sin,
		    sizeof (*sin), NULL, 0);
	else
		mp2 = mi_tpi_conn_con(NULL, (char *)sin6,
		    sizeof (*sin6), NULL, 0);
	if (mp2 == NULL) {
		freemsg(mp1);
		udp_err_ack(q, mp, TSYSERR, ENOMEM);
		goto bind_failed;
	}

	mp = mi_tpi_ok_ack_alloc(mp);
	if (mp == NULL) {
		/* Unable to reuse the T_CONN_REQ for the ack. */
		freemsg(mp2);
		udp_err_ack_prim(q, mp1, T_CONN_REQ, TSYSERR, ENOMEM);
		goto bind_failed;
	}

	/* Hang onto the T_OK_ACK and T_CONN_CON for later. */
	linkb(mp1, mp);
	linkb(mp1, mp2);

	putnext(q, mp1);
}

/* This is the close routine for udp.  It frees the per-stream data. */
static int
udp_close(queue_t *q)
{
	udp_t	*udp = (udp_t *)q->q_ptr;

	TRACE_1(TR_FAC_UDP, TR_UDP_CLOSE,
		"udp_close: q %p", q);

	qprocsoff(q);

	if (cl_inet_unbind != NULL && udp->udp_state == TS_IDLE) {
		/*
		 * Running in cluster mode - register unbind information
		 */
		if (udp->udp_ipversion == IPV4_VERSION) {
			(*cl_inet_unbind)(IPPROTO_UDP, AF_INET,
			    (uint8_t *)(&(V4_PART_OF_V6(udp->udp_v6src))),
			    (in_port_t)udp->udp_port);
		} else {
			(*cl_inet_unbind)(IPPROTO_UDP, AF_INET6,
			    (uint8_t *)(&(udp->udp_v6src)),
			    (in_port_t)udp->udp_port);
		}
	}

	udp_bind_hash_remove(udp, B_FALSE);
	mutex_enter(&udp_g_lock);
	/* Unlink the udp structure and release the minor device number. */
	mi_close_unlink(&udp_g_head, (IDP)udp);
	mutex_exit(&udp_g_lock);
	/* If there are any options associated with the stream, free them. */
	if (udp->udp_ip_snd_options)
		mi_free((char *)udp->udp_ip_snd_options);

	if (udp->udp_ip_rcv_options)
		mi_free((char *)udp->udp_ip_rcv_options);

	/* Free memory associated with sticky options */
	if (udp->udp_sticky_hdrs_len != 0) {
		kmem_free(udp->udp_sticky_hdrs,
		    udp->udp_sticky_hdrs_len);
		udp->udp_sticky_hdrs = NULL;
		udp->udp_sticky_hdrs_len = 0;
	}
	if (udp->udp_sticky_ipp.ipp_fields & IPPF_HOPOPTS) {
		kmem_free(udp->udp_sticky_ipp.ipp_hopopts,
		    udp->udp_sticky_ipp.ipp_hopoptslen);
	}
	if (udp->udp_sticky_ipp.ipp_fields & IPPF_RTDSTOPTS) {
		kmem_free(udp->udp_sticky_ipp.ipp_rtdstopts,
		    udp->udp_sticky_ipp.ipp_rtdstoptslen);
	}
	if (udp->udp_sticky_ipp.ipp_fields & IPPF_RTHDR) {
		kmem_free(udp->udp_sticky_ipp.ipp_rthdr,
		    udp->udp_sticky_ipp.ipp_rthdrlen);
	}
	if (udp->udp_sticky_ipp.ipp_fields & IPPF_DSTOPTS) {
		kmem_free(udp->udp_sticky_ipp.ipp_dstopts,
		    udp->udp_sticky_ipp.ipp_dstoptslen);
	}
	udp->udp_sticky_ipp.ipp_fields &=
	    ~(IPPF_HOPOPTS|IPPF_RTDSTOPTS|IPPF_RTHDR|IPPF_DSTOPTS);

	crfree(udp->udp_credp);
	/* Free the data structure */
	mi_close_free((IDP)udp);
	q->q_ptr = WR(q)->q_ptr = NULL;
	return (0);
}

/*
 * This routine handles each T_DISCON_REQ message passed to udp
 * as an indicating that UDP is no longer connected. This results
 * in sending a T_BIND_REQ to IP to restore the binding to just
 * the local address/port.
 *
 * This routine sends down a T_BIND_REQ to IP with the following mblks:
 *	T_BIND_REQ	- specifying just the local address/port
 *	T_OK_ACK	- for the T_DISCON_REQ
 *
 * The disconnect completes in udp_rput.
 * When a T_BIND_ACK is received the appended T_OK_ACK is sent to the TPI user.
 * Should udp_rput receive T_ERROR_ACK for the T_BIND_REQ it will convert
 * it to an error ack for the appropriate primitive.
 */
static void
udp_disconnect(queue_t *q, mblk_t *mp)
{
	udp_t	*udp;
	mblk_t	*mp1;
	udp_fanout_t *udpf;

	udp = (udp_t *)q->q_ptr;

	if (udp->udp_state != TS_DATA_XFER) {
		(void) mi_strlog(q, 1, SL_ERROR|SL_TRACE,
		    "udp_disconnect: bad state, %u", udp->udp_state);
		udp_err_ack(q, mp, TOUTSTATE, 0);
		return;
	}
	udpf = &udp_bind_fanout[UDP_BIND_HASH(udp->udp_port)];
	mutex_enter(&udpf->uf_lock);
	udp->udp_v6src = udp->udp_bound_v6src;
	udp->udp_state = TS_IDLE;
	mutex_exit(&udpf->uf_lock);

	/*
	 * Send down bind to IP to remove the full binding and revert
	 * to the local address binding.
	 */
	if (udp->udp_family == AF_INET)
		mp1 = udp_ip_bind_mp(udp, O_T_BIND_REQ, sizeof (sin_t));
	else
		mp1 = udp_ip_bind_mp(udp, O_T_BIND_REQ, sizeof (sin6_t));
	if (mp1 == NULL) {
		udp_err_ack(q, mp, TSYSERR, ENOMEM);
		return;
	}
	mp = mi_tpi_ok_ack_alloc(mp);
	if (mp == NULL) {
		/* Unable to reuse the T_DISCON_REQ for the ack. */
		udp_err_ack_prim(q, mp1, T_DISCON_REQ, TSYSERR, ENOMEM);
		return;
	}

	if (udp->udp_family == AF_INET6) {
		int error;

		/* Rebuild the header template */
		error = udp_build_hdrs(q, udp);
		if (error != 0) {
			udp_err_ack_prim(q, mp, T_DISCON_REQ, TSYSERR, error);
			freemsg(mp1);
			return;
		}
	}
	mutex_enter(&udpf->uf_lock);
	udp->udp_discon_pending = 1;
	mutex_exit(&udpf->uf_lock);

	/* Append the T_OK_ACK to the T_BIND_REQ for udp_rput */
	linkb(mp1, mp);
	putnext(q, mp1);
}

/* This routine creates a T_ERROR_ACK message and passes it upstream. */
static void
udp_err_ack(queue_t *q, mblk_t *mp, t_scalar_t t_error, int sys_error)
{
	if ((mp = mi_tpi_err_ack_alloc(mp, t_error, sys_error)) != NULL)
		qreply(q, mp);
}

/* Shorthand to generate and send TPI error acks to our client */
static void
udp_err_ack_prim(queue_t *q, mblk_t *mp, int primitive, t_scalar_t t_error,
    int sys_error)
{
	struct T_error_ack	*teackp;

	if ((mp = tpi_ack_alloc(mp, sizeof (struct T_error_ack),
	    M_PCPROTO, T_ERROR_ACK)) != NULL) {
		teackp = (struct T_error_ack *)mp->b_rptr;
		teackp->ERROR_prim = primitive;
		teackp->TLI_error = t_error;
		teackp->UNIX_error = sys_error;
		qreply(q, mp);
	}
}

/*ARGSUSED*/
static int
udp_extra_priv_ports_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	int i;

	for (i = 0; i < udp_g_num_epriv_ports; i++) {
		if (udp_g_epriv_ports[i] != 0)
			(void) mi_mpprintf(mp, "%d ", udp_g_epriv_ports[i]);
	}
	return (0);
}

/*
 * Hold udp_g_lock to prevent multiple threads from changing udp_g_epriv_ports
 * at the same time.
 */
/* ARGSUSED */
static int
udp_extra_priv_ports_add(queue_t *q, mblk_t *mp, char *value, caddr_t cp,
    cred_t *cr)
{
	long	new_value;
	int	i;

	/*
	 * Fail the request if the new value does not lie within the
	 * port number limits.
	 */
	if (ddi_strtol(value, NULL, 10, &new_value) != 0 ||
	    new_value <= 0 || new_value >= 65536) {
		return (EINVAL);
	}

	mutex_enter(&udp_g_lock);
	/* Check if the value is already in the list */
	for (i = 0; i < udp_g_num_epriv_ports; i++) {
		if (new_value == udp_g_epriv_ports[i]) {
			mutex_exit(&udp_g_lock);
			return (EEXIST);
		}
	}
	/* Find an empty slot */
	for (i = 0; i < udp_g_num_epriv_ports; i++) {
		if (udp_g_epriv_ports[i] == 0)
			break;
	}
	if (i == udp_g_num_epriv_ports) {
		mutex_exit(&udp_g_lock);
		return (EOVERFLOW);
	}

	/* Set the new value */
	udp_g_epriv_ports[i] = (in_port_t)new_value;
	mutex_exit(&udp_g_lock);
	return (0);
}

/*
 * Hold udp_g_lock to prevent multiple threads from changing udp_g_epriv_ports
 * at the same time.
 */
/* ARGSUSED */
static int
udp_extra_priv_ports_del(queue_t *q, mblk_t *mp, char *value, caddr_t cp,
    cred_t *cr)
{
	long	new_value;
	int	i;

	/*
	 * Fail the request if the new value does not lie within the
	 * port number limits.
	 */
	if (ddi_strtol(value, NULL, 10, &new_value) != 0 ||
	    new_value <= 0 || new_value >= 65536) {
		return (EINVAL);
	}

	mutex_enter(&udp_g_lock);
	/* Check that the value is already in the list */
	for (i = 0; i < udp_g_num_epriv_ports; i++) {
		if (udp_g_epriv_ports[i] == new_value)
			break;
	}
	if (i == udp_g_num_epriv_ports) {
		mutex_exit(&udp_g_lock);
		return (ESRCH);
	}

	/* Clear the value */
	udp_g_epriv_ports[i] = 0;
	mutex_exit(&udp_g_lock);
	return (0);
}

/* At minimum we need 4 bytes of UDP header */
#define	ICMP_MIN_UDP_HDR	4

/*
 * udp_icmp_error is called by udp_rput to process ICMP msgs. passed up by IP.
 * Generates the appropriate T_UDERROR_IND for permanent (non-transient) errors.
 * Assumes that IP has pulled up everything up to and including the ICMP header.
 * An M_CTL could potentially come here from some other module (i.e. if UDP
 * is pushed on some module other than IP). Thus, if we find that the M_CTL
 * does not have enough ICMP information , following STREAMS conventions,
 * we send it upstream assuming it is an M_CTL we don't understand.
 */
static void
udp_icmp_error(queue_t *q, mblk_t *mp)
{
	icmph_t *icmph;
	ipha_t	*ipha;
	int	iph_hdr_length;
	udpha_t	*udpha;
	sin_t	sin;
	sin6_t	sin6;
	mblk_t	*mp1;
	int	error = 0;
	udp_t	*udp = (udp_t *)q->q_ptr;
	size_t	mp_size = MBLKL(mp);

	/*
	 * Assume IP provides aligned packets - otherwise toss
	 */
	if (!OK_32PTR(mp->b_rptr)) {
		freemsg(mp);
		return;
	}

	/*
	 * Verify that we have a complete IP header and the application has
	 * asked for errors. If not, send it upstream.
	 */
	if (!udp->udp_dgram_errind || mp_size < sizeof (ipha_t)) {
noticmpv4:
		putnext(q, mp);
		return;
	}

	ipha = (ipha_t *)mp->b_rptr;
	/*
	 * Verify IP version. Anything other than IPv4 or IPv6 packet is sent
	 * upstream. ICMPv6  is handled in udp_icmp_error_ipv6.
	 */
	switch (IPH_HDR_VERSION(ipha)) {
	case IPV6_VERSION:
		udp_icmp_error_ipv6(q, mp);
		return;
	case IPV4_VERSION:
		break;
	default:
		goto noticmpv4;
	}

	/* Skip past the outer IP and ICMP headers */
	iph_hdr_length = IPH_HDR_LENGTH(ipha);
	icmph = (icmph_t *)&mp->b_rptr[iph_hdr_length];
	/*
	 * If we don't have the correct outer IP header length or if the ULP
	 * is not IPPROTO_ICMP or if we don't have a complete inner IP header
	 * send the packet upstream.
	 */
	if (iph_hdr_length < sizeof (ipha_t) ||
	    ipha->ipha_protocol != IPPROTO_ICMP ||
	    (ipha_t *)&icmph[1] + 1 > (ipha_t *)mp->b_wptr) {
		goto noticmpv4;
	}
	ipha = (ipha_t *)&icmph[1];

	/* Skip past the inner IP and find the ULP header */
	iph_hdr_length = IPH_HDR_LENGTH(ipha);
	udpha = (udpha_t *)((char *)ipha + iph_hdr_length);
	/*
	 * If we don't have the correct inner IP header length or if the ULP
	 * is not IPPROTO_UDP or if we don't have at least ICMP_MIN_UDP_HDR
	 * bytes of UDP header, send it upstream.
	 */
	if (iph_hdr_length < sizeof (ipha_t) ||
	    ipha->ipha_protocol != IPPROTO_UDP ||
	    (uchar_t *)udpha + ICMP_MIN_UDP_HDR > mp->b_wptr) {
		goto noticmpv4;
	}

	switch (icmph->icmph_type) {
	case ICMP_DEST_UNREACHABLE:
		switch (icmph->icmph_code) {
		case ICMP_FRAGMENTATION_NEEDED:
			/*
			 * IP has already adjusted the path MTU.
			 * XXX Somehow pass MTU indication to application?
			 */
			break;
		case ICMP_PORT_UNREACHABLE:
		case ICMP_PROTOCOL_UNREACHABLE:
			error = ECONNREFUSED;
			break;
		default:
			/* Transient errors */
			break;
		}
		break;
	default:
		/* Transient errors */
		break;
	}
	if (error == 0) {
		freemsg(mp);
		return;
	}

	switch (udp->udp_family) {
	case AF_INET:
		sin = sin_null;
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = ipha->ipha_dst;
		sin.sin_port = udpha->uha_dst_port;
		mp1 = mi_tpi_uderror_ind((char *)&sin, sizeof (sin_t), NULL, 0,
		    error);
		break;
	case AF_INET6:
		sin6 = sin6_null;
		sin6.sin6_family = AF_INET6;
		IN6_IPADDR_TO_V4MAPPED(ipha->ipha_dst, &sin6.sin6_addr);
		sin6.sin6_port = udpha->uha_dst_port;

		mp1 = mi_tpi_uderror_ind((char *)&sin6, sizeof (sin6_t),
		    NULL, 0, error);
		break;
	}
	if (mp1)
		putnext(q, mp1);
	freemsg(mp);
}

/*
 * udp_icmp_error_ipv6 is called by udp_icmp_error to process ICMP for IPv6.
 * Generates the appropriate T_UDERROR_IND for permanent (non-transient) errors.
 * Assumes that IP has pulled up all the extension headers as well as the
 * ICMPv6 header.
 * An M_CTL could potentially come here from some other module (i.e. if UDP
 * is pushed on some module other than IP). Thus, if we find that the M_CTL
 * does not have enough ICMP information , following STREAMS conventions,
 * we send it upstream assuming it is an M_CTL we don't understand. The reason
 * it might get here is if the non-ICMP M_CTL accidently has 6 in the version
 * field (when cast to ipha_t in udp_icmp_error).
 */
static void
udp_icmp_error_ipv6(queue_t *q, mblk_t *mp)
{
	udp_t		*udp = (udp_t *)q->q_ptr;
	icmp6_t		*icmp6;
	ip6_t		*ip6h, *outer_ip6h;
	uint16_t	hdr_length;
	uint8_t		*nexthdrp;
	udpha_t		*udpha;
	sin6_t		sin6;
	mblk_t		*mp1;
	int		error = 0;
	size_t		mp_size = MBLKL(mp);

	/*
	 * Verify that we have a complete IP header. If not, send it upstream.
	 */
	if (mp_size < sizeof (ip6_t)) {
noticmpv6:
		putnext(q, mp);
		return;
	}

	outer_ip6h = (ip6_t *)mp->b_rptr;
	/*
	 * Verify this is an ICMPV6 packet, else send it upstream
	 */
	if (outer_ip6h->ip6_nxt == IPPROTO_ICMPV6) {
		hdr_length = IPV6_HDR_LEN;
	} else if (!ip_hdr_length_nexthdr_v6(mp, outer_ip6h, &hdr_length,
	    &nexthdrp) ||
	    *nexthdrp != IPPROTO_ICMPV6) {
		goto noticmpv6;
	}
	icmp6 = (icmp6_t *)&mp->b_rptr[hdr_length];
	ip6h = (ip6_t *)&icmp6[1];
	/*
	 * Verify we have a complete ICMP and inner IP header.
	 */
	if ((uchar_t *)&ip6h[1] > mp->b_wptr)
		goto noticmpv6;

	if (!ip_hdr_length_nexthdr_v6(mp, ip6h, &hdr_length, &nexthdrp))
		goto noticmpv6;
	udpha = (udpha_t *)((char *)ip6h + hdr_length);
	/*
	 * Validate inner header. If the ULP is not IPPROTO_UDP or if we don't
	 * have at least ICMP_MIN_UDP_HDR bytes of  UDP header send the
	 * packet upstream.
	 */
	if ((*nexthdrp != IPPROTO_UDP) ||
	    ((uchar_t *)udpha + ICMP_MIN_UDP_HDR) > mp->b_wptr) {
		goto noticmpv6;
	}

	switch (icmp6->icmp6_type) {
	case ICMP6_DST_UNREACH:
		switch (icmp6->icmp6_code) {
		case ICMP6_DST_UNREACH_NOPORT:
			error = ECONNREFUSED;
			break;
		case ICMP6_DST_UNREACH_ADMIN:
		case ICMP6_DST_UNREACH_NOROUTE:
		case ICMP6_DST_UNREACH_BEYONDSCOPE:
		case ICMP6_DST_UNREACH_ADDR:
			/* Transient errors */
			break;
		default:
			break;
		}
		break;
	case ICMP6_PACKET_TOO_BIG: {
		struct T_unitdata_ind	*tudi;
		struct T_opthdr		*toh;
		size_t			udi_size;
		mblk_t			*newmp;
		t_scalar_t		opt_length = sizeof (struct T_opthdr) +
		    sizeof (struct ip6_mtuinfo);
		sin6_t			*sin6;
		struct ip6_mtuinfo	*mtuinfo;

		/*
		 * If the application has requested to receive path mtu
		 * information, send up an empty message containing an
		 * IPV6_PATHMTU ancillary data item.
		 */
		if (!udp->udp_ipv6_recvpathmtu)
			break;

		udi_size = sizeof (struct T_unitdata_ind) + sizeof (sin6_t) +
		    opt_length;
		if ((newmp = allocb(udi_size, BPRI_MED)) == NULL) {
			BUMP_MIB(&udp_mib, udpInErrors);
			break;
		}

		/*
		 * newmp->b_cont is left to NULL on purpose.  This is an
		 * empty message containing only ancillary data.
		 */
		newmp->b_datap->db_type = M_PROTO;
		tudi = (struct T_unitdata_ind *)newmp->b_rptr;
		newmp->b_wptr = (uchar_t *)tudi + udi_size;
		tudi->PRIM_type = T_UNITDATA_IND;
		tudi->SRC_length = sizeof (sin6_t);
		tudi->SRC_offset = sizeof (struct T_unitdata_ind);
		tudi->OPT_offset = tudi->SRC_offset + sizeof (sin6_t);
		tudi->OPT_length = opt_length;

		sin6 = (sin6_t *)&tudi[1];
		bzero(sin6, sizeof (sin6_t));
		sin6->sin6_family = AF_INET6;
		sin6->sin6_addr = udp->udp_v6dst;

		toh = (struct T_opthdr *)&sin6[1];
		toh->level = IPPROTO_IPV6;
		toh->name = IPV6_PATHMTU;
		toh->len = opt_length;
		toh->status = 0;

		mtuinfo = (struct ip6_mtuinfo *)&toh[1];
		bzero(mtuinfo, sizeof (struct ip6_mtuinfo));
		mtuinfo->ip6m_addr.sin6_family = AF_INET6;
		mtuinfo->ip6m_addr.sin6_addr = ip6h->ip6_dst;
		mtuinfo->ip6m_mtu = icmp6->icmp6_mtu;
		/*
		 * We've consumed everything we need from the original
		 * message.  Free it, then send our empty message.
		 */
		freemsg(mp);
		putnext(q, newmp);
		return;
	}
	case ICMP6_TIME_EXCEEDED:
		/* Transient errors */
		break;
	case ICMP6_PARAM_PROB:
		/* If this corresponds to an ICMP_PROTOCOL_UNREACHABLE */
		if (icmp6->icmp6_code == ICMP6_PARAMPROB_NEXTHEADER &&
		    (uchar_t *)ip6h + icmp6->icmp6_pptr ==
		    (uchar_t *)nexthdrp) {
			error = ECONNREFUSED;
			break;
		}
		break;
	}
	if (error == 0) {
		freemsg(mp);
		return;
	}

	sin6 = sin6_null;
	sin6.sin6_family = AF_INET6;
	sin6.sin6_addr = ip6h->ip6_dst;
	sin6.sin6_port = udpha->uha_dst_port;
	sin6.sin6_flowinfo = ip6h->ip6_vcf & ~IPV6_VERS_AND_FLOW_MASK;

	mp1 = mi_tpi_uderror_ind((char *)&sin6, sizeof (sin6_t), NULL, 0,
	    error);
	if (mp1)
		putnext(q, mp1);
	freemsg(mp);
}

/*
 * This routine responds to T_ADDR_REQ messages.  It is called by udp_wput.
 * The local address is filled in if endpoint is bound. The remote address
 * is filled in if remote address has been precified ("connected endpoint")
 * (The concept of connected CLTS sockets is alien to published TPI
 *  but we support it anyway).
 */
static void
udp_addr_req(queue_t *q, mblk_t *mp)
{
	udp_t	*udp = (udp_t *)q->q_ptr;
	sin_t	*sin;
	sin6_t	*sin6;
	mblk_t	*ackmp;
	struct T_addr_ack *taa;

	/* Make it large enough for worst case */
	ackmp = reallocb(mp, sizeof (struct T_addr_ack) +
	    2 * sizeof (sin6_t), 1);
	if (ackmp == NULL) {
		udp_err_ack(q, mp, TSYSERR, ENOMEM);
		return;
	}
	taa = (struct T_addr_ack *)ackmp->b_rptr;

	bzero(taa, sizeof (struct T_addr_ack));
	ackmp->b_wptr = (uchar_t *)&taa[1];

	taa->PRIM_type = T_ADDR_ACK;
	ackmp->b_datap->db_type = M_PCPROTO;
	/*
	 * Note: Following code assumes 32 bit alignment of basic
	 * data structures like sin_t and struct T_addr_ack.
	 */
	if (udp->udp_state != TS_UNBND) {
		/*
		 * Fill in local address first
		 */
		taa->LOCADDR_offset = sizeof (*taa);
		if (udp->udp_family == AF_INET) {
			taa->LOCADDR_length = sizeof (sin_t);
			sin = (sin_t *)&taa[1];
			/* Fill zeroes and then initialize non-zero fields */
			*sin = sin_null;
			sin->sin_family = AF_INET;
			if (!IN6_IS_ADDR_V4MAPPED_ANY(&udp->udp_v6src) &&
			    !IN6_IS_ADDR_UNSPECIFIED(&udp->udp_v6src)) {
				IN6_V4MAPPED_TO_IPADDR(&udp->udp_v6src,
				    sin->sin_addr.s_addr);
			} else {
				/*
				 * INADDR_ANY
				 * udp_v6src is not set, we might be bound to
				 * broadcast/multicast. Use udp_bound_v6src as
				 * local address instead (that could
				 * also still be INADDR_ANY)
				 */
				IN6_V4MAPPED_TO_IPADDR(&udp->udp_bound_v6src,
				    sin->sin_addr.s_addr);
			}
			sin->sin_port = udp->udp_port;
			ackmp->b_wptr = (uchar_t *)&sin[1];
			if (udp->udp_state == TS_DATA_XFER) {
				/*
				 * connected, fill remote address too
				 */
				taa->REMADDR_length = sizeof (sin_t);
				/* assumed 32-bit alignment */
				taa->REMADDR_offset = taa->LOCADDR_offset +
				    taa->LOCADDR_length;

				sin = (sin_t *)(ackmp->b_rptr +
				    taa->REMADDR_offset);
				/* initialize */
				*sin = sin_null;
				sin->sin_family = AF_INET;
				sin->sin_addr.s_addr =
				    V4_PART_OF_V6(udp->udp_v6dst);
				sin->sin_port = udp->udp_dstport;
				ackmp->b_wptr = (uchar_t *)&sin[1];
			}
		} else {
			taa->LOCADDR_length = sizeof (sin6_t);
			sin6 = (sin6_t *)&taa[1];
			/* Fill zeroes and then initialize non-zero fields */
			*sin6 = sin6_null;
			sin6->sin6_family = AF_INET6;
			if (!IN6_IS_ADDR_UNSPECIFIED(&udp->udp_v6src)) {
				sin6->sin6_addr = udp->udp_v6src;
			} else {
				/*
				 * UNSPECIFIED
				 * udp_v6src is not set, we might be bound to
				 * broadcast/multicast. Use udp_bound_v6src as
				 * local address instead (that could
				 * also still be UNSPECIFIED)
				 */
				sin6->sin6_addr =
				    udp->udp_bound_v6src;
			}
			sin6->sin6_port = udp->udp_port;
			ackmp->b_wptr = (uchar_t *)&sin6[1];
			if (udp->udp_state == TS_DATA_XFER) {
				/*
				 * connected, fill remote address too
				 */
				taa->REMADDR_length = sizeof (sin6_t);
				/* assumed 32-bit alignment */
				taa->REMADDR_offset = taa->LOCADDR_offset +
				    taa->LOCADDR_length;

				sin6 = (sin6_t *)(ackmp->b_rptr +
				    taa->REMADDR_offset);
				/* initialize */
				*sin6 = sin6_null;
				sin6->sin6_family = AF_INET6;
				sin6->sin6_addr = udp->udp_v6dst;
				sin6->sin6_port =  udp->udp_dstport;
				ackmp->b_wptr = (uchar_t *)&sin6[1];
			}
			ackmp->b_wptr = (uchar_t *)&sin6[1];
		}
	}
	ASSERT(ackmp->b_wptr <= ackmp->b_datap->db_lim);
	qreply(q, ackmp);
}

static void
udp_copy_info(struct T_info_ack *tap, udp_t *udp)
{
	if (udp->udp_family == AF_INET) {
		*tap = udp_g_t_info_ack_ipv4;
	} else {
		*tap = udp_g_t_info_ack_ipv6;
	}
	tap->CURRENT_state = udp->udp_state;
	tap->OPT_size = udp_max_optsize;
}

/*
 * This routine responds to T_CAPABILITY_REQ messages.  It is called by
 * udp_wput.  Much of the T_CAPABILITY_ACK information is copied from
 * udp_g_t_info_ack.  The current state of the stream is copied from
 * udp_state.
 */
static void
udp_capability_req(queue_t *q, mblk_t *mp)
{
	udp_t			*udp = (udp_t *)q->q_ptr;
	t_uscalar_t		cap_bits1;
	struct T_capability_ack	*tcap;

	cap_bits1 = ((struct T_capability_req *)mp->b_rptr)->CAP_bits1;

	mp = tpi_ack_alloc(mp, sizeof (struct T_capability_ack),
	    mp->b_datap->db_type, T_CAPABILITY_ACK);
	if (!mp)
		return;

	tcap = (struct T_capability_ack *)mp->b_rptr;
	tcap->CAP_bits1 = 0;

	if (cap_bits1 & TC1_INFO) {
		udp_copy_info(&tcap->INFO_ack, udp);
		tcap->CAP_bits1 |= TC1_INFO;
	}

	qreply(q, mp);
}

/*
 * This routine responds to T_INFO_REQ messages.  It is called by udp_wput.
 * Most of the T_INFO_ACK information is copied from udp_g_t_info_ack.
 * The current state of the stream is copied from udp_state.
 */
static void
udp_info_req(queue_t *q, mblk_t *mp)
{
	udp_t	*udp = (udp_t *)q->q_ptr;

	/* Create a T_INFO_ACK message. */
	mp = tpi_ack_alloc(mp, sizeof (struct T_info_ack), M_PCPROTO,
	    T_INFO_ACK);
	if (!mp)
		return;
	udp_copy_info((struct T_info_ack *)mp->b_rptr, udp);
	qreply(q, mp);
}

/*
 * IP recognizes seven kinds of bind requests:
 *
 * - A zero-length address binds only to the protocol number.
 *
 * - A 4-byte address is treated as a request to
 * validate that the address is a valid local IPv4
 * address, appropriate for an application to bind to.
 * IP does the verification, but does not make any note
 * of the address at this time.
 *
 * - A 16-byte address contains is treated as a request
 * to validate a local IPv6 address, as the 4-byte
 * address case above.
 *
 * - A 16-byte sockaddr_in to validate the local IPv4 address and also
 * use it for the inbound fanout of packets.
 *
 * - A 24-byte sockaddr_in6 to validate the local IPv6 address and also
 * use it for the inbound fanout of packets.
 *
 * - A 12-byte address (ipa_conn_t) containing complete IPv4 fanout
 * information consisting of local and remote addresses
 * and ports.  In this case, the addresses are both
 * validated as appropriate for this operation, and, if
 * so, the information is retained for use in the
 * inbound fanout.
 *
 * - A 36-byte address address (ipa6_conn_t) containing complete IPv6
 * fanout information, like the 12-byte case above.
 *
 * IP will also fill in the IRE request mblk with information
 * regarding our peer.  In all cases, we notify IP of our protocol
 * type by appending a single protocol byte to the bind request.
 */
static mblk_t *
udp_ip_bind_mp(udp_t *udp, t_scalar_t bind_prim, t_scalar_t addr_length)
{
	char	*cp;
	mblk_t	*mp;
	struct T_bind_req *tbr;
	ipa_conn_t	*ac;
	ipa6_conn_t	*ac6;
	sin_t		*sin;
	sin6_t		*sin6;

	ASSERT(bind_prim == O_T_BIND_REQ || bind_prim == T_BIND_REQ);

	mp = allocb(sizeof (*tbr) + addr_length + 1, BPRI_HI);
	if (!mp)
		return (mp);
	mp->b_datap->db_type = M_PROTO;
	tbr = (struct T_bind_req *)mp->b_rptr;
	tbr->PRIM_type = bind_prim;
	tbr->ADDR_offset = sizeof (*tbr);
	tbr->CONIND_number = 0;
	tbr->ADDR_length = addr_length;
	cp = (char *)&tbr[1];
	switch (addr_length) {
	case sizeof (ipa_conn_t):
		ASSERT(udp->udp_family == AF_INET);
		/* Append a request for an IRE */
		mp->b_cont = allocb(sizeof (ire_t), BPRI_HI);
		if (!mp->b_cont) {
			freemsg(mp);
			return (NULL);
		}
		mp->b_cont->b_wptr += sizeof (ire_t);
		mp->b_cont->b_datap->db_type = IRE_DB_REQ_TYPE;

		/* cp known to be 32 bit aligned */
		ac = (ipa_conn_t *)cp;
		ac->ac_laddr = V4_PART_OF_V6(udp->udp_v6src);
		ac->ac_faddr = V4_PART_OF_V6(udp->udp_v6dst);
		ac->ac_fport = udp->udp_dstport;
		ac->ac_lport = udp->udp_port;
		break;

	case sizeof (ipa6_conn_t):
		ASSERT(udp->udp_family == AF_INET6);
		/* Append a request for an IRE */
		mp->b_cont = allocb(sizeof (ire_t), BPRI_HI);
		if (!mp->b_cont) {
			freemsg(mp);
			return (NULL);
		}
		mp->b_cont->b_wptr += sizeof (ire_t);
		mp->b_cont->b_datap->db_type = IRE_DB_REQ_TYPE;

		/* cp known to be 32 bit aligned */
		ac6 = (ipa6_conn_t *)cp;
		ac6->ac6_laddr = udp->udp_v6src;
		ac6->ac6_faddr = udp->udp_v6dst;
		ac6->ac6_fport = udp->udp_dstport;
		ac6->ac6_lport = udp->udp_port;
		break;

	case sizeof (sin_t):
		ASSERT(udp->udp_family == AF_INET);
		/* Append a request for an IRE */
		mp->b_cont = allocb(sizeof (ire_t), BPRI_HI);
		if (!mp->b_cont) {
			freemsg(mp);
			return (NULL);
		}
		mp->b_cont->b_wptr += sizeof (ire_t);
		mp->b_cont->b_datap->db_type = IRE_DB_REQ_TYPE;

		sin = (sin_t *)cp;
		*sin = sin_null;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = V4_PART_OF_V6(udp->udp_bound_v6src);
		sin->sin_port = udp->udp_port;
		break;

	case sizeof (sin6_t):
		ASSERT(udp->udp_family == AF_INET6);
		/* Append a request for an IRE */
		mp->b_cont = allocb(sizeof (ire_t), BPRI_HI);
		if (!mp->b_cont) {
			freemsg(mp);
			return (NULL);
		}
		mp->b_cont->b_wptr += sizeof (ire_t);
		mp->b_cont->b_datap->db_type = IRE_DB_REQ_TYPE;

		sin6 = (sin6_t *)cp;
		*sin6 = sin6_null;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_addr = udp->udp_bound_v6src;
		sin6->sin6_port = udp->udp_port;
		break;
	}
	/* Add protocol number to end */
	cp[addr_length] = (char)IPPROTO_UDP;
	mp->b_wptr = (uchar_t *)&cp[addr_length + 1];
	return (mp);
}

/*
 * This is the open routine for udp.  It allocates a udp_t structure for
 * the stream and, on the first open of the module, creates an ND table.
 */
static int
udp_open(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	int	err;
	udp_t	*udp;

	TRACE_1(TR_FAC_UDP, TR_UDP_OPEN, "udp_open: q %p", q);

	/*
	 * Defer the qprocson until everything is initialized since
	 * we are D_MTPERQ and after qprocson the rput routine can
	 * run.
	 */

	/* If the stream is already open, return immediately. */
	if (q->q_ptr != NULL)
		return (0);

	/* If this is not a push of udp as a module, fail. */
	if (sflag != MODOPEN)
		return (EINVAL);

	/*
	 * Create and initialize a udp_t structure for this stream.
	 */
	udp = (udp_t *)mi_open_alloc_sleep(sizeof (udp_t));

	/* Set the initial state of the stream and the privilege status. */
	q->q_ptr = WR(q)->q_ptr = udp;
	udp->udp_state = TS_UNBND;
	if (getmajor(*devp) == (major_t)UDP6_MAJ) {
		udp->udp_family = AF_INET6;
		udp->udp_ipversion = IPV6_VERSION;
		udp->udp_max_hdr_len = IPV6_HDR_LEN + UDPH_SIZE;
		udp->udp_ttl = udp_ipv6_hoplimit;
	} else {
		udp->udp_family = AF_INET;
		udp->udp_ipversion = IPV4_VERSION;
		udp->udp_max_hdr_len = IP_SIMPLE_HDR_LENGTH + UDPH_SIZE;
		udp->udp_ttl = udp_ipv4_ttl;
	}

	/*
	 * The receive hiwat is only looked at on the stream head queue.
	 * Store in q_hiwat in order to return on SO_RCVBUF getsockopts.
	 */
	q->q_hiwat = udp_recv_hiwat;

	udp->udp_multicast_ttl = IP_DEFAULT_MULTICAST_TTL;
	udp->udp_multicast_loop = IP_DEFAULT_MULTICAST_LOOP;
	udp->udp_credp = credp;
	crhold(credp);

	udp->udp_zoneid = getzoneid();

	/*
	 * Acquire the lock and link it into the list of open streams.
	 */
	mutex_enter(&udp_g_lock);
	err = mi_open_link(&udp_g_head, (IDP)udp, devp, flag, sflag, credp);
	mutex_exit(&udp_g_lock);
	if (err != 0)
		goto error;

	qprocson(q);

	/*
	 * The transmit hiwat/lowat is only looked at on IP's queue.
	 * Store in q_hiwat in order to return on SO_SNDBUF
	 * getsockopts.
	 */
	WR(q)->q_hiwat = udp_xmit_hiwat;
	WR(q)->q_next->q_hiwat = WR(q)->q_hiwat;
	WR(q)->q_lowat = udp_xmit_lowat;
	WR(q)->q_next->q_lowat = WR(q)->q_lowat;

	if (udp->udp_family == AF_INET6) {
		/* Build initial header template for transmit */
		if ((err = udp_build_hdrs(q, udp)) != 0) {
			qprocsoff(q);
			/*
			 * Unlink the udp structure and release
			 * the minor device number.
			 */
			mutex_enter(&udp_g_lock);
			mi_close_unlink(&udp_g_head, (IDP)udp);
			mutex_exit(&udp_g_lock);
			goto error;
		}
	}

	/* Set the Stream head write offset. */
	(void) mi_set_sth_wroff(q, udp->udp_max_hdr_len + udp_wroff_extra);
	(void) mi_set_sth_hiwat(q, q->q_hiwat);
	return (0);

error:
	q->q_ptr = WR(q)->q_ptr = NULL;
	crfree(credp);
	mi_close_free((IDP)udp);
	return (err);
}

/*
 * Which UDP options OK to set through T_UNITDATA_REQ...
 */
/* ARGSUSED */
static boolean_t
udp_opt_allow_udr_set(t_scalar_t level, t_scalar_t name)
{

	return (B_TRUE);
}

/*
 * This routine gets default values of certain options whose default
 * values are maintained by protcol specific code
 */
/* ARGSUSED */
int
udp_opt_default(queue_t	*q, t_scalar_t level, t_scalar_t name, uchar_t *ptr)
{
	int *i1 = (int *)ptr;

	switch (level) {
	case IPPROTO_IP:
		switch (name) {
		case IP_MULTICAST_TTL:
			*ptr = (uchar_t)IP_DEFAULT_MULTICAST_TTL;
			return (sizeof (uchar_t));
		case IP_MULTICAST_LOOP:
			*ptr = (uchar_t)IP_DEFAULT_MULTICAST_LOOP;
			return (sizeof (uchar_t));
		}
		break;
	case IPPROTO_IPV6:
		switch (name) {
		case IPV6_MULTICAST_HOPS:
			*i1 = IP_DEFAULT_MULTICAST_TTL;
			return (sizeof (int));
		case IPV6_MULTICAST_LOOP:
			*i1 = IP_DEFAULT_MULTICAST_LOOP;
			return (sizeof (int));
		case IPV6_UNICAST_HOPS:
			*i1 = udp_ipv6_hoplimit;
			return (sizeof (int));
		}
		break;
	}
	return (-1);
}

/*
 * This routine retrieves the current status of socket options.
 * It returns the size of the option retrieved.
 */
int
udp_opt_get(queue_t *q, t_scalar_t level, t_scalar_t name, uchar_t *ptr)
{
	int	*i1 = (int *)ptr;
	udp_t	*udp = (udp_t *)q->q_ptr;
	ip6_pkt_t	*ipp = &udp->udp_sticky_ipp;

	switch (level) {
	case SOL_SOCKET:
		switch (name) {
		case SO_DEBUG:
			*i1 = udp->udp_debug;
			break;	/* goto sizeof (int) option return */
		case SO_REUSEADDR:
			*i1 = udp->udp_reuseaddr;
			break;	/* goto sizeof (int) option return */
		case SO_TYPE:
			*i1 = SOCK_DGRAM;
			break;	/* goto sizeof (int) option return */

		/*
		 * The following three items are available here,
		 * but are only meaningful to IP.
		 */
		case SO_DONTROUTE:
			*i1 = udp->udp_dontroute;
			break;	/* goto sizeof (int) option return */
		case SO_USELOOPBACK:
			*i1 = udp->udp_useloopback;
			break;	/* goto sizeof (int) option return */
		case SO_BROADCAST:
			*i1 = udp->udp_broadcast;
			break;	/* goto sizeof (int) option return */

		case SO_SNDBUF:
			*i1 = q->q_hiwat;
			break;	/* goto sizeof (int) option return */
		case SO_RCVBUF:
			*i1 = RD(q)->q_hiwat;
			break;	/* goto sizeof (int) option return */
		case SO_DGRAM_ERRIND:
			*i1 = udp->udp_dgram_errind;
			break;	/* goto sizeof (int) option return */
		case SO_RECVUCRED:
			*i1 = udp->udp_recvucred;
			break;	/* goto sizeof (int) option return */
		default:
			return (-1);
		}
		break;
	case IPPROTO_IP:
		if (udp->udp_family != AF_INET)
			return (-1);
		switch (name) {
		case IP_OPTIONS:
		case T_IP_OPTIONS:
			if (udp->udp_ip_rcv_options_len)
				bcopy(udp->udp_ip_rcv_options, ptr,
				    udp->udp_ip_rcv_options_len);
			return (udp->udp_ip_rcv_options_len);
		case IP_TOS:
		case T_IP_TOS:
			*i1 = (int)udp->udp_type_of_service;
			break;	/* goto sizeof (int) option return */
		case IP_TTL:
			*i1 = (int)udp->udp_ttl;
			break;	/* goto sizeof (int) option return */
		case IP_MULTICAST_IF:
			/* 0 address if not set */
			*(ipaddr_t *)ptr = udp->udp_multicast_if_addr;
			return (sizeof (ipaddr_t));
		case IP_MULTICAST_TTL:
			*(uchar_t *)ptr = udp->udp_multicast_ttl;
			return (sizeof (uchar_t));
		case IP_MULTICAST_LOOP:
			*ptr = udp->udp_multicast_loop;
			return (sizeof (uint8_t));
		case IP_RECVOPTS:
			*i1 = udp->udp_recvopts;
			break;	/* goto sizeof (int) option return */
		case IP_RECVDSTADDR:
			*i1 = udp->udp_recvdstaddr;
			break;	/* goto sizeof (int) option return */
		case IP_RECVIF:
			*i1 = udp->udp_recvif;
			break;	/* goto sizeof (int) option return */
		case IP_RECVSLLA:
			*i1 = udp->udp_recvslla;
			break;	/* goto sizeof (int) option return */
		case IP_RECVTTL:
			*i1 = udp->udp_recvttl;
			break;	/* goto sizeof (int) option return */
		case IP_ADD_MEMBERSHIP:
		case IP_DROP_MEMBERSHIP:
		case IP_BLOCK_SOURCE:
		case IP_UNBLOCK_SOURCE:
		case IP_ADD_SOURCE_MEMBERSHIP:
		case IP_DROP_SOURCE_MEMBERSHIP:
		case MCAST_JOIN_GROUP:
		case MCAST_LEAVE_GROUP:
		case MCAST_BLOCK_SOURCE:
		case MCAST_UNBLOCK_SOURCE:
		case MCAST_JOIN_SOURCE_GROUP:
		case MCAST_LEAVE_SOURCE_GROUP:
		case IP_DONTFAILOVER_IF:
			/* cannot "get" the value for these */
			return (-1);
		case IP_BOUND_IF:
			/* Zero if not set */
			*i1 = udp->udp_bound_if;
			break;	/* goto sizeof (int) option return */
		case IP_UNSPEC_SRC:
			*i1 = udp->udp_unspec_source;
			break;	/* goto sizeof (int) option return */
		case IP_XMIT_IF:
			*i1 = udp->udp_xmit_if;
			break; /* goto sizeof (int) option return */
		default:
			return (-1);
		}
		break;
	case IPPROTO_IPV6:
		if (udp->udp_family != AF_INET6)
			return (-1);
		switch (name) {
		case IPV6_UNICAST_HOPS:
			*i1 = (unsigned int)udp->udp_ttl;
			break;	/* goto sizeof (int) option return */
		case IPV6_MULTICAST_IF:
			/* 0 index if not set */
			*i1 = udp->udp_multicast_if_index;
			break;	/* goto sizeof (int) option return */
		case IPV6_MULTICAST_HOPS:
			*i1 = udp->udp_multicast_ttl;
			break;	/* goto sizeof (int) option return */
		case IPV6_MULTICAST_LOOP:
			*i1 = udp->udp_multicast_loop;
			break;	/* goto sizeof (int) option return */
		case IPV6_JOIN_GROUP:
		case IPV6_LEAVE_GROUP:
		case MCAST_JOIN_GROUP:
		case MCAST_LEAVE_GROUP:
		case MCAST_BLOCK_SOURCE:
		case MCAST_UNBLOCK_SOURCE:
		case MCAST_JOIN_SOURCE_GROUP:
		case MCAST_LEAVE_SOURCE_GROUP:
			/* cannot "get" the value for these */
			return (-1);
		case IPV6_BOUND_IF:
			/* Zero if not set */
			*i1 = udp->udp_bound_if;
			break;	/* goto sizeof (int) option return */
		case IPV6_UNSPEC_SRC:
			*i1 = udp->udp_unspec_source;
			break;	/* goto sizeof (int) option return */
		case IPV6_RECVPKTINFO:
			*i1 = udp->udp_ipv6_recvpktinfo;
			break;	/* goto sizeof (int) option return */
		case IPV6_RECVTCLASS:
			*i1 = udp->udp_ipv6_recvtclass;
			break;	/* goto sizeof (int) option return */
		case IPV6_RECVPATHMTU:
			*i1 = udp->udp_ipv6_recvpathmtu;
			break;	/* goto sizeof (int) option return */
		case IPV6_RECVHOPLIMIT:
			*i1 = udp->udp_ipv6_recvhoplimit;
			break;	/* goto sizeof (int) option return */
		case IPV6_RECVHOPOPTS:
			*i1 = udp->udp_ipv6_recvhopopts;
			break;	/* goto sizeof (int) option return */
		case IPV6_RECVDSTOPTS:
			*i1 = udp->udp_ipv6_recvdstopts;
			break;	/* goto sizeof (int) option return */
		case _OLD_IPV6_RECVDSTOPTS:
			*i1 = udp->udp_old_ipv6_recvdstopts;
			break;	/* goto sizeof (int) option return */
		case IPV6_RECVRTHDRDSTOPTS:
			*i1 = udp->udp_ipv6_recvrthdrdstopts;
			break;	/* goto sizeof (int) option return */
		case IPV6_RECVRTHDR:
			*i1 = udp->udp_ipv6_recvrthdr;
			break;	/* goto sizeof (int) option return */
		case IPV6_PKTINFO: {
			/* XXX assumes that caller has room for max size! */
			struct in6_pktinfo *pkti;

			pkti = (struct in6_pktinfo *)ptr;
			if (ipp->ipp_fields & IPPF_IFINDEX)
				pkti->ipi6_ifindex = ipp->ipp_ifindex;
			else
				pkti->ipi6_ifindex = 0;
			if (ipp->ipp_fields & IPPF_ADDR)
				pkti->ipi6_addr = ipp->ipp_addr;
			else
				pkti->ipi6_addr = ipv6_all_zeros;
			return (sizeof (struct in6_pktinfo));
		}
		case IPV6_TCLASS:
			if (ipp->ipp_fields & IPPF_TCLASS)
				*i1 = ipp->ipp_tclass;
			else
				*i1 = IPV6_FLOW_TCLASS(
				    IPV6_DEFAULT_VERS_AND_FLOW);
			break;	/* goto sizeof (int) option return */
		case IPV6_NEXTHOP: {
			sin6_t *sin6 = (sin6_t *)ptr;

			if (!(ipp->ipp_fields & IPPF_NEXTHOP))
				return (0);
			*sin6 = sin6_null;
			sin6->sin6_family = AF_INET6;
			sin6->sin6_addr = ipp->ipp_nexthop;
			return (sizeof (sin6_t));
		}
		case IPV6_HOPOPTS:
			if (!(ipp->ipp_fields & IPPF_HOPOPTS))
				return (0);
			bcopy(ipp->ipp_hopopts, ptr, ipp->ipp_hopoptslen);
			return (ipp->ipp_hopoptslen);
		case IPV6_RTHDRDSTOPTS:
			if (!(ipp->ipp_fields & IPPF_RTDSTOPTS))
				return (0);
			bcopy(ipp->ipp_rtdstopts, ptr, ipp->ipp_rtdstoptslen);
			return (ipp->ipp_rtdstoptslen);
		case IPV6_RTHDR:
			if (!(ipp->ipp_fields & IPPF_RTHDR))
				return (0);
			bcopy(ipp->ipp_rthdr, ptr, ipp->ipp_rthdrlen);
			return (ipp->ipp_rthdrlen);
		case IPV6_DSTOPTS:
			if (!(ipp->ipp_fields & IPPF_DSTOPTS))
				return (0);
			bcopy(ipp->ipp_dstopts, ptr, ipp->ipp_dstoptslen);
			return (ipp->ipp_dstoptslen);
		case IPV6_PATHMTU:
			return (ip_fill_mtuinfo(&udp->udp_v6dst,
				udp->udp_dstport, (struct ip6_mtuinfo *)ptr));
		default:
			return (-1);
		}
		break;
	case IPPROTO_UDP:
		switch (name) {
		case UDP_ANONPRIVBIND:
			*i1 = udp->udp_anon_priv_bind;
			break;
		case UDP_EXCLBIND:
			*i1 = udp->udp_exclbind ? UDP_EXCLBIND : 0;
			break;
		case UDP_RCVHDR:
			*i1 = udp->udp_rcvhdr ? 1 : 0;
			break;
		default:
			return (-1);
		}
		break;
	default:
		return (-1);
	}
	return (sizeof (int));
}

/* This routine sets socket options. */
/* ARGSUSED */
int
udp_opt_set(queue_t *q, uint_t optset_context, int level,
    int name, uint_t inlen, uchar_t *invalp, uint_t *outlenp,
    uchar_t *outvalp, void *thisdg_attrs, cred_t *cr, mblk_t *mblk)
{
	udp_t	*udp = (udp_t *)q->q_ptr;
	int	*i1 = (int *)invalp;
	boolean_t onoff = (*i1 == 0) ? 0 : 1;
	boolean_t checkonly;
	int	error;

	switch (optset_context) {
	case SETFN_OPTCOM_CHECKONLY:
		checkonly = B_TRUE;
		/*
		 * Note: Implies T_CHECK semantics for T_OPTCOM_REQ
		 * inlen != 0 implies value supplied and
		 * 	we have to "pretend" to set it.
		 * inlen == 0 implies that there is no
		 * 	value part in T_CHECK request and just validation
		 * done elsewhere should be enough, we just return here.
		 */
		if (inlen == 0) {
			*outlenp = 0;
			return (0);
		}
		break;
	case SETFN_OPTCOM_NEGOTIATE:
		checkonly = B_FALSE;
		break;
	case SETFN_UD_NEGOTIATE:
	case SETFN_CONN_NEGOTIATE:
		checkonly = B_FALSE;
		/*
		 * Negotiating local and "association-related" options
		 * through T_UNITDATA_REQ.
		 *
		 * Following routine can filter out ones we do not
		 * want to be "set" this way.
		 */
		if (!udp_opt_allow_udr_set(level, name)) {
			*outlenp = 0;
			return (EINVAL);
		}
		break;
	default:
		/*
		 * We should never get here
		 */
		*outlenp = 0;
		return (EINVAL);
	}

	ASSERT((optset_context != SETFN_OPTCOM_CHECKONLY) ||
	    (optset_context == SETFN_OPTCOM_CHECKONLY && inlen != 0));

	/*
	 * For fixed length options, no sanity check
	 * of passed in length is done. It is assumed *_optcom_req()
	 * routines do the right thing.
	 */

	switch (level) {
	case SOL_SOCKET:
		switch (name) {
		case SO_REUSEADDR:
			if (!checkonly)
				udp->udp_reuseaddr = onoff;
			break;
		case SO_DEBUG:
			if (!checkonly)
				udp->udp_debug = onoff;
			break;
		/*
		 * The following three items are available here,
		 * but are only meaningful to IP.
		 */
		case SO_DONTROUTE:
			if (!checkonly)
				udp->udp_dontroute = onoff;
			break;
		case SO_USELOOPBACK:
			if (!checkonly)
				udp->udp_useloopback = onoff;
			break;
		case SO_BROADCAST:
			if (!checkonly)
				udp->udp_broadcast = onoff;
			break;

		case SO_SNDBUF:
			if (*i1 > udp_max_buf) {
				*outlenp = 0;
				return (ENOBUFS);
			}
			if (!checkonly) {
				q->q_hiwat = *i1;
				q->q_next->q_hiwat = *i1;
			}
			break;
		case SO_RCVBUF:
			if (*i1 > udp_max_buf) {
				*outlenp = 0;
				return (ENOBUFS);
			}
			if (!checkonly) {
				RD(q)->q_hiwat = *i1;
				(void) mi_set_sth_hiwat(RD(q), *i1);
			}
			break;
		case SO_DGRAM_ERRIND:
			if (!checkonly)
				udp->udp_dgram_errind = onoff;
			break;
		case SO_RECVUCRED:
			if (!checkonly)
				udp->udp_recvucred = onoff;
			break;
		default:
			*outlenp = 0;
			return (EINVAL);
		}
		break;
	case IPPROTO_IP:
		if (udp->udp_family != AF_INET) {
			*outlenp = 0;
			return (ENOPROTOOPT);
		}
		switch (name) {
		case IP_OPTIONS:
		case T_IP_OPTIONS:
			/* Save options for use by IP. */
			if (inlen & 0x3) {
				*outlenp = 0;
				return (EINVAL);
			}
			if (checkonly)
				break;

			if (udp->udp_ip_snd_options) {
				mi_free((char *)udp->udp_ip_snd_options);
				udp->udp_ip_snd_options_len = 0;
				udp->udp_ip_snd_options = NULL;
			}
			if (inlen) {
				udp->udp_ip_snd_options =
					(uchar_t *)mi_alloc(inlen, BPRI_HI);
				if (udp->udp_ip_snd_options) {
					bcopy(invalp, udp->udp_ip_snd_options,
					    inlen);
					udp->udp_ip_snd_options_len = inlen;
				}
			}
			udp->udp_max_hdr_len = IP_SIMPLE_HDR_LENGTH +
			    UDPH_SIZE + udp->udp_ip_snd_options_len;
			(void) mi_set_sth_wroff(RD(q), udp->udp_max_hdr_len +
			    udp_wroff_extra);
			break;
		case IP_TTL:
			if (!checkonly) {
				udp->udp_ttl = (uchar_t)*i1;
			}
			break;
		case IP_TOS:
		case T_IP_TOS:
			if (!checkonly) {
				udp->udp_type_of_service = (uchar_t)*i1;
			}
			break;
		case IP_MULTICAST_IF: {
			/*
			 * TODO should check OPTMGMT reply and undo this if
			 * there is an error.
			 */
			struct in_addr *inap = (struct in_addr *)invalp;
			if (!checkonly) {
				udp->udp_multicast_if_addr =
				    inap->s_addr;
			}
			break;
		}
		case IP_MULTICAST_TTL:
			if (!checkonly)
				udp->udp_multicast_ttl = *invalp;
			break;
		case IP_MULTICAST_LOOP:
			if (!checkonly)
				udp->udp_multicast_loop = *invalp;
			break;
		case IP_RECVOPTS:
			if (!checkonly)
				udp->udp_recvopts = onoff;
			break;
		case IP_RECVDSTADDR:
			if (!checkonly)
				udp->udp_recvdstaddr = onoff;
			break;
		case IP_RECVIF:
			if (!checkonly)
				udp->udp_recvif = onoff;
			break;
		case IP_RECVSLLA:
			if (!checkonly)
				udp->udp_recvslla = onoff;
			break;
		case IP_RECVTTL:
			if (!checkonly)
				udp->udp_recvttl = onoff;
			break;
		case IP_ADD_MEMBERSHIP:
		case IP_DROP_MEMBERSHIP:
		case IP_BLOCK_SOURCE:
		case IP_UNBLOCK_SOURCE:
		case IP_ADD_SOURCE_MEMBERSHIP:
		case IP_DROP_SOURCE_MEMBERSHIP:
		case MCAST_JOIN_GROUP:
		case MCAST_LEAVE_GROUP:
		case MCAST_BLOCK_SOURCE:
		case MCAST_UNBLOCK_SOURCE:
		case MCAST_JOIN_SOURCE_GROUP:
		case MCAST_LEAVE_SOURCE_GROUP:
		case IP_SEC_OPT:
			/*
			 * "soft" error (negative)
			 * option not handled at this level
			 * Do not modify *outlenp.
			 */
			return (-EINVAL);
		case IP_BOUND_IF:
			if (!checkonly)
				udp->udp_bound_if = *i1;
			break;
		case IP_UNSPEC_SRC:
			if (!checkonly)
				udp->udp_unspec_source = onoff;
			break;
		case IP_XMIT_IF:
			if (!checkonly)
				udp->udp_xmit_if = *i1;
			break;
		default:
			*outlenp = 0;
			return (EINVAL);
		}
		break;
	case IPPROTO_IPV6: {
		ip6_pkt_t		*ipp;
		boolean_t		sticky;

		if (udp->udp_family != AF_INET6) {
			*outlenp = 0;
			return (ENOPROTOOPT);
		}
		/*
		 * Deal with both sticky options and ancillary data
		 */
		if (thisdg_attrs == NULL) {
			/* sticky options, or none */
			ipp = &udp->udp_sticky_ipp;
			sticky = B_TRUE;
		} else {
			/* ancillary data */
			ipp = (ip6_pkt_t *)thisdg_attrs;
			sticky = B_FALSE;
		}

		switch (name) {
		case IPV6_MULTICAST_IF:
			if (!checkonly)
				udp->udp_multicast_if_index = *i1;
			break;
		case IPV6_UNICAST_HOPS:
			/* -1 means use default */
			if (*i1 < -1 || *i1 > IPV6_MAX_HOPS) {
				*outlenp = 0;
				return (EINVAL);
			}
			if (!checkonly) {
				if (*i1 == -1) {
					udp->udp_ttl = ipp->ipp_unicast_hops =
					    udp_ipv6_hoplimit;
					ipp->ipp_fields &= ~IPPF_UNICAST_HOPS;
					/* Pass modified value to IP. */
					*i1 = udp->udp_ttl;
				} else {
					udp->udp_ttl = ipp->ipp_unicast_hops =
					    (uint8_t)*i1;
					ipp->ipp_fields |= IPPF_UNICAST_HOPS;
				}
				/* Rebuild the header template */
				error = udp_build_hdrs(q, udp);
				if (error != 0) {
					*outlenp = 0;
					return (error);
				}
			}
			break;
		case IPV6_MULTICAST_HOPS:
			/* -1 means use default */
			if (*i1 < -1 || *i1 > IPV6_MAX_HOPS) {
				*outlenp = 0;
				return (EINVAL);
			}
			if (!checkonly) {
				if (*i1 == -1) {
					udp->udp_multicast_ttl =
					    ipp->ipp_multicast_hops =
					    IP_DEFAULT_MULTICAST_TTL;
					ipp->ipp_fields &= ~IPPF_MULTICAST_HOPS;
					/* Pass modified value to IP. */
					*i1 = udp->udp_multicast_ttl;
				} else {
					udp->udp_multicast_ttl =
					    ipp->ipp_multicast_hops =
					    (uint8_t)*i1;
					ipp->ipp_fields |= IPPF_MULTICAST_HOPS;
				}
			}
			break;
		case IPV6_MULTICAST_LOOP:
			if (*i1 != 0 && *i1 != 1) {
				*outlenp = 0;
				return (EINVAL);
			}
			if (!checkonly)
				udp->udp_multicast_loop = *i1;
			break;
		case IPV6_JOIN_GROUP:
		case IPV6_LEAVE_GROUP:
		case MCAST_JOIN_GROUP:
		case MCAST_LEAVE_GROUP:
		case MCAST_BLOCK_SOURCE:
		case MCAST_UNBLOCK_SOURCE:
		case MCAST_JOIN_SOURCE_GROUP:
		case MCAST_LEAVE_SOURCE_GROUP:
			/*
			 * "soft" error (negative)
			 * option not handled at this level
			 * Note: Do not modify *outlenp
			 */
			return (-EINVAL);
		case IPV6_BOUND_IF:
			if (!checkonly)
				udp->udp_bound_if = *i1;
			break;
		case IPV6_UNSPEC_SRC:
			if (!checkonly)
				udp->udp_unspec_source = onoff;
			break;
		/*
		 * Set boolean switches for ancillary data delivery
		 */
		case IPV6_RECVPKTINFO:
			if (!checkonly)
				udp->udp_ipv6_recvpktinfo = onoff;
			break;
		case IPV6_RECVTCLASS:
			if (!checkonly) {
				udp->udp_ipv6_recvtclass = onoff;
			}
			break;
		case IPV6_RECVPATHMTU:
			if (!checkonly) {
				udp->udp_ipv6_recvpathmtu = onoff;
			}
			break;
		case IPV6_RECVHOPLIMIT:
			if (!checkonly)
				udp->udp_ipv6_recvhoplimit = onoff;
			break;
		case IPV6_RECVHOPOPTS:
			if (!checkonly)
				udp->udp_ipv6_recvhopopts = onoff;
			break;
		case IPV6_RECVDSTOPTS:
			if (!checkonly)
				udp->udp_ipv6_recvdstopts = onoff;
			break;
		case _OLD_IPV6_RECVDSTOPTS:
			if (!checkonly)
				udp->udp_old_ipv6_recvdstopts = onoff;
			break;
		case IPV6_RECVRTHDRDSTOPTS:
			if (!checkonly)
				udp->udp_ipv6_recvrthdrdstopts = onoff;
			break;
		case IPV6_RECVRTHDR:
			if (!checkonly)
				udp->udp_ipv6_recvrthdr = onoff;
			break;
		/*
		 * Set sticky options or ancillary data.
		 * If sticky options, (re)build any extension headers
		 * that might be needed as a result.
		 */
		case IPV6_PKTINFO:
			/*
			 * The source address and ifindex are verified
			 * in ip_opt_set(). For ancillary data the
			 * source address is checked in ip_wput_v6.
			 */
			if (inlen != 0 && inlen != sizeof (struct in6_pktinfo))
				return (EINVAL);
			if (checkonly)
				break;

			if (inlen == 0) {
				ipp->ipp_fields &= ~(IPPF_IFINDEX|IPPF_ADDR);
				ipp->ipp_sticky_ignored |=
				    (IPPF_IFINDEX|IPPF_ADDR);
			} else {
				struct in6_pktinfo *pkti;

				pkti = (struct in6_pktinfo *)invalp;
				ipp->ipp_ifindex = pkti->ipi6_ifindex;
				ipp->ipp_addr = pkti->ipi6_addr;
				if (ipp->ipp_ifindex != 0)
					ipp->ipp_fields |= IPPF_IFINDEX;
				else
					ipp->ipp_fields &= ~IPPF_IFINDEX;
				if (!IN6_IS_ADDR_UNSPECIFIED(
				    &ipp->ipp_addr))
					ipp->ipp_fields |= IPPF_ADDR;
				else
					ipp->ipp_fields &= ~IPPF_ADDR;
			}
			if (sticky) {
				error = udp_build_hdrs(q, udp);
				if (error != 0)
					return (error);
			}
			break;
		case IPV6_HOPLIMIT:
			if (sticky)
				return (EINVAL);
			if (inlen != 0 && inlen != sizeof (int))
				return (EINVAL);
			if (checkonly)
				break;

			if (inlen == 0) {
				ipp->ipp_fields &= ~IPPF_HOPLIMIT;
				ipp->ipp_sticky_ignored |= IPPF_HOPLIMIT;
			} else {
				if (*i1 > 255 || *i1 < -1)
					return (EINVAL);
				if (*i1 == -1)
					ipp->ipp_hoplimit = udp_ipv6_hoplimit;
				else
					ipp->ipp_hoplimit = *i1;
				ipp->ipp_fields |= IPPF_HOPLIMIT;
			}
			break;
		case IPV6_TCLASS:
			if (inlen != 0 && inlen != sizeof (int))
				return (EINVAL);
			if (checkonly)
				break;

			if (inlen == 0) {
				ipp->ipp_fields &= ~IPPF_TCLASS;
				ipp->ipp_sticky_ignored |= IPPF_TCLASS;
			} else {
				if (*i1 > 255 || *i1 < -1)
					return (EINVAL);
				if (*i1 == -1)
					ipp->ipp_tclass = 0;
				else
					ipp->ipp_tclass = *i1;
				ipp->ipp_fields |= IPPF_TCLASS;
			}
			if (sticky) {
				error = udp_build_hdrs(q, udp);
				if (error != 0)
					return (error);
			}
			break;
		case IPV6_NEXTHOP:
			/*
			 * IP will verify that the nexthop is reachable
			 * and fail for sticky options.
			 */
			if (inlen != 0 && inlen != sizeof (sin6_t))
				return (EINVAL);
			if (checkonly)
				break;

			if (inlen == 0) {
				ipp->ipp_fields &= ~IPPF_NEXTHOP;
				ipp->ipp_sticky_ignored |= IPPF_NEXTHOP;
			} else {
				sin6_t *sin6 = (sin6_t *)invalp;

				if (sin6->sin6_family != AF_INET6)
					return (EAFNOSUPPORT);
				if (IN6_IS_ADDR_V4MAPPED(
				    &sin6->sin6_addr))
					return (EADDRNOTAVAIL);
				ipp->ipp_nexthop = sin6->sin6_addr;
				if (!IN6_IS_ADDR_UNSPECIFIED(
				    &ipp->ipp_nexthop))
					ipp->ipp_fields |= IPPF_NEXTHOP;
				else
					ipp->ipp_fields &= ~IPPF_NEXTHOP;
			}
			if (sticky) {
				error = udp_build_hdrs(q, udp);
				if (error != 0)
					return (error);
			}
			break;
		case IPV6_HOPOPTS: {
			ip6_hbh_t *hopts = (ip6_hbh_t *)invalp;
			/*
			 * Sanity checks - minimum size, size a multiple of
			 * eight bytes, and matching size passed in.
			 */
			if (inlen != 0 &&
			    inlen != (8 * (hopts->ip6h_len + 1)))
				return (EINVAL);

			if (checkonly)
				break;

			if (inlen == 0) {
				if (sticky &&
				    (ipp->ipp_fields & IPPF_HOPOPTS) != 0) {
					kmem_free(ipp->ipp_hopopts,
					    ipp->ipp_hopoptslen);
					ipp->ipp_hopopts = NULL;
					ipp->ipp_hopoptslen = 0;
				}
				ipp->ipp_fields &= ~IPPF_HOPOPTS;
				ipp->ipp_sticky_ignored |= IPPF_HOPOPTS;
			} else {
				error = udp_pkt_set(invalp, inlen, sticky,
				    (uchar_t **)&ipp->ipp_hopopts,
				    &ipp->ipp_hopoptslen);
				if (error != 0)
					return (error);
				ipp->ipp_fields |= IPPF_HOPOPTS;
			}
			if (sticky) {
				error = udp_build_hdrs(q, udp);
				if (error != 0)
					return (error);
			}
			break;
		}
		case IPV6_RTHDRDSTOPTS: {
			ip6_dest_t *dopts = (ip6_dest_t *)invalp;

			/*
			 * Sanity checks - minimum size, size a multiple of
			 * eight bytes, and matching size passed in.
			 */
			if (inlen != 0 &&
			    inlen != (8 * (dopts->ip6d_len + 1)))
				return (EINVAL);

			if (checkonly)
				break;

			if (inlen == 0) {
				if (sticky &&
				    (ipp->ipp_fields & IPPF_RTDSTOPTS) != 0) {
					kmem_free(ipp->ipp_rtdstopts,
					    ipp->ipp_rtdstoptslen);
					ipp->ipp_rtdstopts = NULL;
					ipp->ipp_rtdstoptslen = 0;
				}
				ipp->ipp_fields &= ~IPPF_RTDSTOPTS;
				ipp->ipp_sticky_ignored |= IPPF_RTDSTOPTS;
			} else {
				error = udp_pkt_set(invalp, inlen, sticky,
				    (uchar_t **)&ipp->ipp_rtdstopts,
				    &ipp->ipp_rtdstoptslen);
				if (error != 0)
					return (error);
				ipp->ipp_fields |= IPPF_RTDSTOPTS;
			}
			if (sticky) {
				error = udp_build_hdrs(q, udp);
				if (error != 0)
					return (error);
			}
			break;
		}
		case IPV6_DSTOPTS: {
			ip6_dest_t *dopts = (ip6_dest_t *)invalp;

			/*
			 * Sanity checks - minimum size, size a multiple of
			 * eight bytes, and matching size passed in.
			 */
			if (inlen != 0 &&
			    inlen != (8 * (dopts->ip6d_len + 1)))
				return (EINVAL);

			if (checkonly)
				break;

			if (inlen == 0) {
				if (sticky &&
				    (ipp->ipp_fields & IPPF_DSTOPTS) != 0) {
					kmem_free(ipp->ipp_dstopts,
					    ipp->ipp_dstoptslen);
					ipp->ipp_dstopts = NULL;
					ipp->ipp_dstoptslen = 0;
				}
				ipp->ipp_fields &= ~IPPF_DSTOPTS;
				ipp->ipp_sticky_ignored |= IPPF_DSTOPTS;
			} else {
				error = udp_pkt_set(invalp, inlen, sticky,
				    (uchar_t **)&ipp->ipp_dstopts,
				    &ipp->ipp_dstoptslen);
				if (error != 0)
					return (error);
				ipp->ipp_fields |= IPPF_DSTOPTS;
			}
			if (sticky) {
				error = udp_build_hdrs(q, udp);
				if (error != 0)
					return (error);
			}
			break;
		}
		case IPV6_RTHDR: {
			ip6_rthdr_t *rt = (ip6_rthdr_t *)invalp;

			/*
			 * Sanity checks - minimum size, size a multiple of
			 * eight bytes, and matching size passed in.
			 */
			if (inlen != 0 &&
			    inlen != (8 * (rt->ip6r_len + 1)))
				return (EINVAL);

			if (checkonly)
				break;

			if (inlen == 0) {
				if (sticky &&
				    (ipp->ipp_fields & IPPF_RTHDR) != 0) {
					kmem_free(ipp->ipp_rthdr,
					    ipp->ipp_rthdrlen);
					ipp->ipp_rthdr = NULL;
					ipp->ipp_rthdrlen = 0;
				}
				ipp->ipp_fields &= ~IPPF_RTHDR;
				ipp->ipp_sticky_ignored |= IPPF_RTHDR;
			} else {
				error = udp_pkt_set(invalp, inlen, sticky,
				    (uchar_t **)&ipp->ipp_rthdr,
				    &ipp->ipp_rthdrlen);
				if (error != 0)
					return (error);
				ipp->ipp_fields |= IPPF_RTHDR;
			}
			if (sticky) {
				error = udp_build_hdrs(q, udp);
				if (error != 0)
					return (error);
			}
			break;
		}

		case IPV6_DONTFRAG:
			if (checkonly)
				break;

			if (onoff) {
				ipp->ipp_fields |= IPPF_DONTFRAG;
			} else {
				ipp->ipp_fields &= ~IPPF_DONTFRAG;
			}
			break;

		case IPV6_USE_MIN_MTU:
			if (inlen != sizeof (int))
				return (EINVAL);

			if (*i1 < -1 || *i1 > 1)
				return (EINVAL);

			if (checkonly)
				break;

			ipp->ipp_fields |= IPPF_USE_MIN_MTU;
			ipp->ipp_use_min_mtu = *i1;
			break;

		case IPV6_BOUND_PIF:
		case IPV6_SEC_OPT:
		case IPV6_DONTFAILOVER_IF:
		case IPV6_SRC_PREFERENCES:
		case IPV6_V6ONLY:
			/* Handled at the IP level */
			return (-EINVAL);
		default:
			*outlenp = 0;
			return (EINVAL);
		}
		break;
		}		/* end IPPROTO_IPV6 */
	case IPPROTO_UDP:
		switch (name) {
		case UDP_ANONPRIVBIND:
			if ((error = secpolicy_net_privaddr(cr, 0)) != 0) {
				*outlenp = 0;
				return (error);
			}
			if (!checkonly) {
				udp->udp_anon_priv_bind = onoff;
			}
			break;
		case UDP_EXCLBIND:
			if (!checkonly)
				udp->udp_exclbind = onoff;
			break;
		case UDP_RCVHDR:
			if (!checkonly)
				udp->udp_rcvhdr = onoff;
			break;
		default:
			*outlenp = 0;
			return (EINVAL);
		}
		break;
	default:
		*outlenp = 0;
		return (EINVAL);
	}
	/*
	 * Common case of OK return with outval same as inval.
	 */
	if (invalp != outvalp) {
		/* don't trust bcopy for identical src/dst */
		(void) bcopy(invalp, outvalp, inlen);
	}
	*outlenp = inlen;
	return (0);
}

/*
 * Update udp_sticky_hdrs based on udp_sticky_ipp, udp_v6src, and udp_ttl.
 * The headers include ip6i_t (if needed), ip6_t, any sticky extension
 * headers, and the udp header.
 * Returns failure if can't allocate memory.
 */
static int
udp_build_hdrs(queue_t *q, udp_t *udp)
{
	uchar_t	*hdrs;
	uint_t	hdrs_len;
	ip6_t	*ip6h;
	ip6i_t	*ip6i;
	udpha_t	*udpha;
	ip6_pkt_t *ipp = &udp->udp_sticky_ipp;

	hdrs_len = ip_total_hdrs_len_v6(ipp) + UDPH_SIZE;
	ASSERT(hdrs_len != 0);
	if (hdrs_len != udp->udp_sticky_hdrs_len) {
		/* Need to reallocate */
		hdrs = kmem_alloc(hdrs_len, KM_NOSLEEP);
		if (hdrs == NULL)
			return (ENOMEM);

		if (udp->udp_sticky_hdrs_len != 0) {
			kmem_free(udp->udp_sticky_hdrs,
			    udp->udp_sticky_hdrs_len);
		}
		udp->udp_sticky_hdrs = hdrs;
		udp->udp_sticky_hdrs_len = hdrs_len;
	}
	ip_build_hdrs_v6(udp->udp_sticky_hdrs,
	    udp->udp_sticky_hdrs_len - UDPH_SIZE, ipp, IPPROTO_UDP);

	/* Set header fields not in ipp */
	if (ipp->ipp_fields & IPPF_HAS_IP6I) {
		ip6i = (ip6i_t *)udp->udp_sticky_hdrs;
		ip6h = (ip6_t *)&ip6i[1];
	} else {
		ip6h = (ip6_t *)udp->udp_sticky_hdrs;
	}

	if (!(ipp->ipp_fields & IPPF_ADDR))
		ip6h->ip6_src = udp->udp_v6src;

	udpha = (udpha_t *)(udp->udp_sticky_hdrs + hdrs_len - UDPH_SIZE);
	udpha->uha_src_port = udp->udp_port;

	/* Try to get everything in a single mblk */
	if (hdrs_len > udp->udp_max_hdr_len) {
		udp->udp_max_hdr_len = hdrs_len;
		(void) mi_set_sth_wroff(RD(q), udp->udp_max_hdr_len +
		    udp_wroff_extra);
	}
	return (0);
}

/*
 * Set optbuf and optlen for the option.
 * If sticky is set allocate memory (if not already present).
 * Otherwise just point optbuf and optlen at invalp and inlen.
 * Returns failure if memory can not be allocated.
 */
static int
udp_pkt_set(uchar_t *invalp, uint_t inlen, boolean_t sticky,
    uchar_t **optbufp, uint_t *optlenp)
{
	uchar_t *optbuf;

	if (!sticky) {
		*optbufp = invalp;
		*optlenp = inlen;
		return (0);
	}
	if (inlen == *optlenp) {
		/* Unchanged length - no need to realocate */
		bcopy(invalp, *optbufp, inlen);
		return (0);
	}
	if (inlen != 0) {
		/* Allocate new buffer before free */
		optbuf = kmem_alloc(inlen, KM_NOSLEEP);
		if (optbuf == NULL)
			return (ENOMEM);
	} else {
		optbuf = NULL;
	}
	/* Free old buffer */
	if (*optlenp != 0)
		kmem_free(*optbufp, *optlenp);

	bcopy(invalp, optbuf, inlen);
	*optbufp = optbuf;
	*optlenp = inlen;
	return (0);
}

/*
 * This routine retrieves the value of an ND variable in a udpparam_t
 * structure.  It is called through nd_getset when a user reads the
 * variable.
 */
/* ARGSUSED */
static int
udp_param_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	udpparam_t *udppa = (udpparam_t *)cp;

	(void) mi_mpprintf(mp, "%d", udppa->udp_param_value);
	return (0);
}

/*
 * Walk through the param array specified registering each element with the
 * named dispatch (ND) handler.
 */
static boolean_t
udp_param_register(udpparam_t *udppa, int cnt)
{
	for (; cnt-- > 0; udppa++) {
		if (udppa->udp_param_name && udppa->udp_param_name[0]) {
			if (!nd_load(&udp_g_nd, udppa->udp_param_name,
			    udp_param_get, udp_param_set,
			    (caddr_t)udppa)) {
				nd_free(&udp_g_nd);
				return (B_FALSE);
			}
		}
	}
	if (!nd_load(&udp_g_nd, "udp_extra_priv_ports",
	    udp_extra_priv_ports_get, NULL, NULL)) {
		nd_free(&udp_g_nd);
		return (B_FALSE);
	}
	if (!nd_load(&udp_g_nd, "udp_extra_priv_ports_add",
	    NULL, udp_extra_priv_ports_add, NULL)) {
		nd_free(&udp_g_nd);
		return (B_FALSE);
	}
	if (!nd_load(&udp_g_nd, "udp_extra_priv_ports_del",
	    NULL, udp_extra_priv_ports_del, NULL)) {
		nd_free(&udp_g_nd);
		return (B_FALSE);
	}
	if (!nd_load(&udp_g_nd, "udp_status", udp_status_report, NULL,
	    NULL)) {
		nd_free(&udp_g_nd);
		return (B_FALSE);
	}
	if (!nd_load(&udp_g_nd, "udp_bind_hash", udp_bind_hash_report, NULL,
	    NULL)) {
		nd_free(&udp_g_nd);
		return (B_FALSE);
	}
	return (B_TRUE);
}

/* This routine sets an ND variable in a udpparam_t structure. */
/* ARGSUSED */
static int
udp_param_set(queue_t *q, mblk_t *mp, char *value, caddr_t cp, cred_t *cr)
{
	long		new_value;
	udpparam_t	*udppa = (udpparam_t *)cp;

	/*
	 * Fail the request if the new value does not lie within the
	 * required bounds.
	 */
	if (ddi_strtol(value, NULL, 10, &new_value) != 0 ||
	    new_value < udppa->udp_param_min ||
	    new_value > udppa->udp_param_max) {
		return (EINVAL);
	}

	/* Set the new value */
	udppa->udp_param_value = new_value;
	return (0);
}

static void
udp_rput(queue_t *q, mblk_t *mp)
{
	struct T_unitdata_ind	*tudi;
	uchar_t			*rptr;
	int			hdr_length;
	int			udi_size;	/* Size of T_unitdata_ind */
	udp_t			*udp;
	udpha_t			*udpha;
	int			ipversion;
	ip6_pkt_t		ipp;
	ip6_t			*ip6h;
	ip6i_t			*ip6i;
	mblk_t			*mp1;
	mblk_t			*options_mp = NULL;
	in_pktinfo_t		*pinfo = NULL;
	size_t			mp_size = MBLKL(mp);
	cred_t			*cr = NULL;
	pid_t			cpid;

	TRACE_2(TR_FAC_UDP, TR_UDP_RPUT_START,
	    "udp_rput_start: q %p mp %p", q, mp);

	udp = (udp_t *)q->q_ptr;
	rptr = mp->b_rptr;

	switch (mp->b_datap->db_type) {
	case M_DATA:
		/*
		 * M_DATA messages contain IP datagrams.  They are handled
		 * after this switch.
		 */
		break;
	case M_PROTO:
	case M_PCPROTO:
		/* M_PROTO messages contain some type of TPI message. */
		if ((mp->b_wptr - rptr) < sizeof (t_scalar_t)) {
			freemsg(mp);
			TRACE_2(TR_FAC_UDP, TR_UDP_RPUT_END,
				"udp_rput_end: q %p (%S)", q, "protoshort");
			return;
		}
		qwriter(q, mp, udp_rput_other, PERIM_INNER);
		TRACE_2(TR_FAC_UDP, TR_UDP_RPUT_END,
			"udp_rput_end: q %p (%S)", q, "proto");
		return;
	case M_FLUSH:
		if (*mp->b_rptr & FLUSHR)
			flushq(q, FLUSHDATA);
		putnext(q, mp);
		TRACE_2(TR_FAC_UDP, TR_UDP_RPUT_END,
			"udp_rput_end: q %p (%S)", q, "flush");
		return;
	case M_CTL:
		if (udp->udp_recvif || udp->udp_recvslla ||
		    udp->udp_ipv6_recvpktinfo) {
			/*
			 * IP should have prepended the options data in an M_CTL
			 * Check M_CTL "type" to make sure are not here bcos of
			 * a valid ICMP message
			 */
			if (mp_size == sizeof (in_pktinfo_t) &&
			    ((in_pktinfo_t *)mp->b_rptr)->in_pkt_ulp_type ==
			    IN_PKTINFO) {
				pinfo = (in_pktinfo_t *)mp->b_rptr;
				/*
				 * Jump to normal data processing, this is not
				 * an ICMP message
				 */
				break;
			}
		}
		/*
		 * ICMP messages.
		 */
		udp_icmp_error(q, mp);
		TRACE_2(TR_FAC_UDP, TR_UDP_RPUT_END,
			"udp_rput_end: q %p (%S)", q, "m_ctl");
		return;
	default:
		putnext(q, mp);
		TRACE_2(TR_FAC_UDP, TR_UDP_RPUT_END,
			"udp_rput_end: q %p (%S)", q, "default");
		return;
	}

	/*
	 * If we are here bcos the IP_RECVIF or IP_RECVSLLA then we need to
	 * extract the mblk and adjust the rptr
	 */
	if (pinfo != NULL) {
		ASSERT(mp->b_datap->db_type == M_CTL);
		options_mp = mp;
		mp = mp->b_cont;
		rptr = mp->b_rptr;
		mp_size = MBLKL(mp);
	}
	/*
	 * This is the inbound data path.
	 * First, we check to make sure the IP version number is correct,
	 * and then pull the IP and UDP headers into the first mblk.
	 */
	/*
	 * Assume IP provides aligned packets - otherwise toss.
	 * Also, check if we have a complete IP header.
	 */
	if (!OK_32PTR(rptr) || (mp_size < sizeof (ipha_t))) {
tossit:
		freemsg(mp);
		if (options_mp != NULL)
			freeb(options_mp);
		BUMP_MIB(&udp_mib, udpInErrors);
		return;
	}

	/* Initialize regardless if ipversion is IPv4 or IPv6 */
	ipp.ipp_fields = 0;

	ipversion = IPH_HDR_VERSION(rptr);
	switch (ipversion) {
	case IPV4_VERSION:
		hdr_length = IPH_HDR_LENGTH(rptr) + UDPH_SIZE;
		/* Verify this is a UDP packet */
		if (((ipha_t *)rptr)->ipha_protocol != IPPROTO_UDP)
			goto tossit;
		if ((hdr_length > IP_SIMPLE_HDR_LENGTH + UDPH_SIZE) ||
		    (udp->udp_ip_rcv_options_len)) {
			/*
			 * Handle IPv4 packets with options outside of the
			 * main data path. Not needed for AF_INET6 sockets
			 * since they don't support a getsockopt of IP_OPTIONS.
			 */
			if (udp->udp_family == AF_INET6)
				break;
			/*
			 * UDP length check performed for IPv4 packets with
			 * options to check whether UDP length specified in
			 * the header is the same as the physical length of
			 * the packet.
			 */
			udpha = (udpha_t *)(rptr + (hdr_length - UDPH_SIZE));
			if (msgdsize(mp) != (ntohs(udpha->uha_length) +
			    hdr_length - UDPH_SIZE)) {
				goto tossit;
			}
			/*
			 * Handle the case where the packet has IP options
			 * and the IP_RECVSLLA & IP_RECVIF are set
			 */
			if (pinfo != NULL)
				mp = options_mp;
			qwriter(q, mp, udp_rput_other, PERIM_INNER);
			TRACE_2(TR_FAC_UDP, TR_UDP_RPUT_END,
				"udp_rput_end: q %p (%S)", q, "end");
			return;
		}

		/* Handle IPV6_RECVHOPLIMIT. */
		if ((udp->udp_family == AF_INET6) && (pinfo != NULL)) {
			if (pinfo->in_pkt_flags & IPF_RECVIF) {
				ipp.ipp_fields |= IPPF_IFINDEX;
				ipp.ipp_ifindex = pinfo->in_pkt_ifindex;
			}
		}
		break;
	case IPV6_VERSION:
		/*
		 * IPv6 packets can only be received by applications
		 * that are prepared to receive IPv6 addresses.
		 * The IP fanout must ensure this.
		 */
		ASSERT(udp->udp_family == AF_INET6);

		ip6h = (ip6_t *)rptr;
		if ((uchar_t *)&ip6h[1] > mp->b_wptr)
			goto tossit;

		if (ip6h->ip6_nxt != IPPROTO_UDP) {
			uint8_t nexthdrp;
			/* Look for ifindex information */
			if (ip6h->ip6_nxt == IPPROTO_RAW) {
				ip6i = (ip6i_t *)ip6h;
				if ((uchar_t *)&ip6i[1] > mp->b_wptr)
					goto tossit;

				if (ip6i->ip6i_flags & IP6I_IFINDEX) {
					ASSERT(ip6i->ip6i_ifindex != 0);
					ipp.ipp_fields |= IPPF_IFINDEX;
					ipp.ipp_ifindex = ip6i->ip6i_ifindex;
				}
				rptr = (uchar_t *)&ip6i[1];
				mp->b_rptr = rptr;
				if (rptr == mp->b_wptr) {
					mp1 = mp->b_cont;
					freeb(mp);
					mp = mp1;
					rptr = mp->b_rptr;
				}
				if (MBLKL(mp) < (IPV6_HDR_LEN + UDPH_SIZE))
					goto tossit;
				ip6h = (ip6_t *)rptr;
			}
			/*
			 * Find any potentially interesting extension headers
			 * as well as the length of the IPv6 + extension
			 * headers.
			 */
			hdr_length = ip_find_hdr_v6(mp, ip6h, &ipp, &nexthdrp) +
			    UDPH_SIZE;
			/* Verify this is a UDP packet */
			if (nexthdrp != IPPROTO_UDP)
				goto tossit;
		} else {
			hdr_length = IPV6_HDR_LEN + UDPH_SIZE;
			ip6i = NULL;
		}
		break;
	default:
		TRACE_2(TR_FAC_UDP, TR_UDP_RPUT_END,
			"udp_rput_end: q %p (%S)", q, "Unknown IP version");
		goto tossit;
	}

	/*
	 * IP inspected the UDP header thus all of it must be in the mblk.
	 * UDP length check is performed for IPv6 packets and IPv4 packets
	 * without options to check if the size of the packet as specified
	 * by the header is the same as the physical size of the packet.
	 */
	udpha = (udpha_t *)(rptr + (hdr_length - UDPH_SIZE));
	if ((MBLKL(mp) < hdr_length) ||
	    (msgdsize(mp) != (ntohs(udpha->uha_length) +
	    hdr_length - UDPH_SIZE))) {
		goto tossit;
	}

	/* Walk past the headers. */
	if (!udp->udp_rcvhdr)
		mp->b_rptr = rptr + hdr_length;

	/*
	 * This is the inbound data path.  Packets are passed upstream as
	 * T_UNITDATA_IND messages with full IP headers still attached.
	 */
	if (udp->udp_family == AF_INET) {
		sin_t *sin;

		ASSERT(IPH_HDR_VERSION((ipha_t *)rptr) == IPV4_VERSION);

		/*
		 * Normally only send up the address.
		 * If IP_RECVDSTADDR is set we include the destination IP
		 * address as an option. With IP_RECVOPTS we include all
		 * the IP options. Only ip_rput_other() handles packets
		 * that contain IP options.
		 */
		udi_size = sizeof (struct T_unitdata_ind) + sizeof (sin_t);
		if (udp->udp_recvdstaddr) {
			udi_size += sizeof (struct T_opthdr) +
			    sizeof (struct in_addr);
		}

		/*
		 * If the IP_RECVSLLA or the IP_RECVIF is set then allocate
		 * space accordingly
		 */
		if (udp->udp_recvif && (pinfo != NULL) &&
		    (pinfo->in_pkt_flags & IPF_RECVIF)) {
			udi_size += sizeof (struct T_opthdr) +
				sizeof (uint_t);
		}

		if (udp->udp_recvslla && (pinfo != NULL) &&
		    (pinfo->in_pkt_flags & IPF_RECVSLLA)) {
			udi_size += sizeof (struct T_opthdr) +
				sizeof (struct sockaddr_dl);
		}

		if (udp->udp_recvucred && (cr = DB_CRED(mp)) != NULL) {
			udi_size += sizeof (struct T_opthdr) + ucredsize;
			cpid = DB_CPID(mp);
		}
		/*
		 * If IP_RECVTTL is set allocate the appropriate sized buffer
		 */
		if (udp->udp_recvttl) {
			udi_size += sizeof (struct T_opthdr) + sizeof (uint8_t);
		}

		ASSERT(IPH_HDR_LENGTH((ipha_t *)rptr) == IP_SIMPLE_HDR_LENGTH);

		/* Allocate a message block for the T_UNITDATA_IND structure. */
		mp1 = allocb(udi_size, BPRI_MED);
		if (mp1 == NULL) {
			freemsg(mp);
			if (options_mp != NULL)
				freeb(options_mp);
			TRACE_2(TR_FAC_UDP, TR_UDP_RPUT_END,
				"udp_rput_end: q %p (%S)", q, "allocbfail");
			BUMP_MIB(&udp_mib, udpInErrors);
			return;
		}
		mp1->b_cont = mp;
		mp = mp1;
		mp->b_datap->db_type = M_PROTO;
		tudi = (struct T_unitdata_ind *)mp->b_rptr;
		mp->b_wptr = (uchar_t *)tudi + udi_size;
		tudi->PRIM_type = T_UNITDATA_IND;
		tudi->SRC_length = sizeof (sin_t);
		tudi->SRC_offset = sizeof (struct T_unitdata_ind);
		tudi->OPT_offset = sizeof (struct T_unitdata_ind) +
		    sizeof (sin_t);
		udi_size -= (sizeof (struct T_unitdata_ind) + sizeof (sin_t));
		tudi->OPT_length = udi_size;
		sin = (sin_t *)&tudi[1];
		sin->sin_addr.s_addr = ((ipha_t *)rptr)->ipha_src;
		sin->sin_port =	udpha->uha_src_port;
		sin->sin_family = udp->udp_family;
		*(uint32_t *)&sin->sin_zero[0] = 0;
		*(uint32_t *)&sin->sin_zero[4] = 0;

		/*
		 * Add options if IP_RECVDSTADDR, IP_RECVIF, IP_RECVSLLA or
		 * IP_RECVTTL has been set.
		 */
		if (udi_size != 0) {
			/*
			 * Copy in destination address before options to avoid
			 * any padding issues.
			 */
			char *dstopt;

			dstopt = (char *)&sin[1];
			if (udp->udp_recvdstaddr) {
				struct T_opthdr *toh;
				ipaddr_t *dstptr;

				toh = (struct T_opthdr *)dstopt;
				toh->level = IPPROTO_IP;
				toh->name = IP_RECVDSTADDR;
				toh->len = sizeof (struct T_opthdr) +
				    sizeof (ipaddr_t);
				toh->status = 0;
				dstopt += sizeof (struct T_opthdr);
				dstptr = (ipaddr_t *)dstopt;
				*dstptr = ((ipha_t *)rptr)->ipha_dst;
				dstopt += sizeof (ipaddr_t);
				udi_size -= toh->len;
			}

			if (udp->udp_recvslla && (pinfo != NULL) &&
			    (pinfo->in_pkt_flags & IPF_RECVSLLA)) {

				struct T_opthdr *toh;
				struct sockaddr_dl	*dstptr;

				toh = (struct T_opthdr *)dstopt;
				toh->level = IPPROTO_IP;
				toh->name = IP_RECVSLLA;
				toh->len = sizeof (struct T_opthdr) +
					sizeof (struct sockaddr_dl);
				toh->status = 0;
				dstopt += sizeof (struct T_opthdr);
				dstptr = (struct sockaddr_dl *)dstopt;
				bcopy(&pinfo->in_pkt_slla, dstptr,
				    sizeof (struct sockaddr_dl));
				dstopt += sizeof (struct sockaddr_dl);
				udi_size -= toh->len;
			}

			if (udp->udp_recvif && (pinfo != NULL) &&
			    (pinfo->in_pkt_flags & IPF_RECVIF)) {

				struct T_opthdr *toh;
				uint_t		*dstptr;

				toh = (struct T_opthdr *)dstopt;
				toh->level = IPPROTO_IP;
				toh->name = IP_RECVIF;
				toh->len = sizeof (struct T_opthdr) +
					sizeof (uint_t);
				toh->status = 0;
				dstopt += sizeof (struct T_opthdr);
				dstptr = (uint_t *)dstopt;
				*dstptr = pinfo->in_pkt_ifindex;
				dstopt += sizeof (uint_t);
				udi_size -= toh->len;
			}

			if (cr != NULL) {
				struct T_opthdr *toh;

				toh = (struct T_opthdr *)dstopt;
				toh->level = SOL_SOCKET;
				toh->name = SCM_UCRED;
				toh->len = sizeof (struct T_opthdr) + ucredsize;
				toh->status = 0;
				(void) cred2ucred(cr, cpid, &toh[1]);
				dstopt += toh->len;
				udi_size -= toh->len;
			}

			if (udp->udp_recvttl) {
				struct	T_opthdr *toh;
				uint8_t	*dstptr;

				toh = (struct T_opthdr *)dstopt;
				toh->level = IPPROTO_IP;
				toh->name = IP_RECVTTL;
				toh->len = sizeof (struct T_opthdr) +
				    sizeof (uint8_t);
				toh->status = 0;
				dstopt += sizeof (struct T_opthdr);
				dstptr = (uint8_t *)dstopt;
				*dstptr = ((ipha_t *)rptr)->ipha_ttl;
				dstopt += sizeof (uint8_t);
				udi_size -= toh->len;
			}

			/* Consumed all of allocated space */
			ASSERT(udi_size == 0);
		}
	} else {
		sin6_t *sin6;

		/*
		 * Handle both IPv4 and IPv6 packets for IPv6 sockets.
		 *
		 * Normally we only send up the address. If receiving of any
		 * optional receive side information is enabled, we also send
		 * that up as options.
		 * [ Only udp_rput_other() handles packets that contain IP
		 * options so code to account for does not appear immediately
		 * below but elsewhere ]
		 */
		udi_size = sizeof (struct T_unitdata_ind) + sizeof (sin6_t);

		if (ipp.ipp_fields & (IPPF_HOPOPTS|IPPF_DSTOPTS|IPPF_RTDSTOPTS|
		    IPPF_RTHDR|IPPF_IFINDEX)) {
			if (udp->udp_ipv6_recvhopopts &&
			    (ipp.ipp_fields & IPPF_HOPOPTS)) {
				udi_size += sizeof (struct T_opthdr) +
				    ipp.ipp_hopoptslen;
			}
			if ((udp->udp_ipv6_recvdstopts ||
				udp->udp_old_ipv6_recvdstopts) &&
			    (ipp.ipp_fields & IPPF_DSTOPTS)) {
				udi_size += sizeof (struct T_opthdr) +
				    ipp.ipp_dstoptslen;
			}
			if (((udp->udp_ipv6_recvdstopts &&
			    udp->udp_ipv6_recvrthdr &&
			    (ipp.ipp_fields & IPPF_RTHDR)) ||
			    udp->udp_ipv6_recvrthdrdstopts) &&
			    (ipp.ipp_fields & IPPF_RTDSTOPTS)) {
				udi_size += sizeof (struct T_opthdr) +
				    ipp.ipp_rtdstoptslen;
			}
			if (udp->udp_ipv6_recvrthdr &&
			    (ipp.ipp_fields & IPPF_RTHDR)) {
				udi_size += sizeof (struct T_opthdr) +
				    ipp.ipp_rthdrlen;
			}
			if (udp->udp_ipv6_recvpktinfo &&
			    (ipp.ipp_fields & IPPF_IFINDEX)) {
				udi_size += sizeof (struct T_opthdr) +
				    sizeof (struct in6_pktinfo);
			}

		}
		if (udp->udp_recvucred && (cr = DB_CRED(mp)) != NULL) {
			udi_size += sizeof (struct T_opthdr) + ucredsize;
			cpid = DB_CPID(mp);
		}

		if (udp->udp_ipv6_recvhoplimit)
			udi_size += sizeof (struct T_opthdr) + sizeof (int);

		if (udp->udp_ipv6_recvtclass)
			udi_size += sizeof (struct T_opthdr) + sizeof (int);

		mp1 = allocb(udi_size, BPRI_MED);
		if (mp1 == NULL) {
			freemsg(mp);
			if (options_mp != NULL)
				freeb(options_mp);
			TRACE_2(TR_FAC_UDP, TR_UDP_RPUT_END,
				"udp_rput_end: q %p (%S)", q, "allocbfail");
			BUMP_MIB(&udp_mib, udpInErrors);
			return;
		}
		mp1->b_cont = mp;
		mp = mp1;
		mp->b_datap->db_type = M_PROTO;
		tudi = (struct T_unitdata_ind *)mp->b_rptr;
		mp->b_wptr = (uchar_t *)tudi + udi_size;
		tudi->PRIM_type = T_UNITDATA_IND;
		tudi->SRC_length = sizeof (sin6_t);
		tudi->SRC_offset = sizeof (struct T_unitdata_ind);
		tudi->OPT_offset = sizeof (struct T_unitdata_ind) +
		    sizeof (sin6_t);
		udi_size -= (sizeof (struct T_unitdata_ind) + sizeof (sin6_t));
		tudi->OPT_length = udi_size;
		sin6 = (sin6_t *)&tudi[1];
		if (ipversion == IPV4_VERSION) {
			in6_addr_t v6dst;

			IN6_IPADDR_TO_V4MAPPED(((ipha_t *)rptr)->ipha_src,
			    &sin6->sin6_addr);
			IN6_IPADDR_TO_V4MAPPED(((ipha_t *)rptr)->ipha_dst,
			    &v6dst);
			sin6->sin6_flowinfo = 0;
			sin6->sin6_scope_id = 0;
			sin6->__sin6_src_id = ip_srcid_find_addr(&v6dst,
			    udp->udp_zoneid);
		} else {
			sin6->sin6_addr = ip6h->ip6_src;
			/* No sin6_flowinfo per API */
			sin6->sin6_flowinfo = 0;
			/* For link-scope source pass up scope id */
			if ((ipp.ipp_fields & IPPF_IFINDEX) &&
			    IN6_IS_ADDR_LINKSCOPE(&ip6h->ip6_src))
				sin6->sin6_scope_id = ipp.ipp_ifindex;
			else
				sin6->sin6_scope_id = 0;
			sin6->__sin6_src_id =
			    ip_srcid_find_addr(&ip6h->ip6_dst, udp->udp_zoneid);
		}
		sin6->sin6_port = udpha->uha_src_port;
		sin6->sin6_family = udp->udp_family;

		if (udi_size != 0) {
			uchar_t *dstopt;

			dstopt = (uchar_t *)&sin6[1];
			if (udp->udp_ipv6_recvpktinfo &&
			    (ipp.ipp_fields & IPPF_IFINDEX)) {
				struct T_opthdr *toh;
				struct in6_pktinfo *pkti;

				toh = (struct T_opthdr *)dstopt;
				toh->level = IPPROTO_IPV6;
				toh->name = IPV6_PKTINFO;
				toh->len = sizeof (struct T_opthdr) +
				    sizeof (*pkti);
				toh->status = 0;
				dstopt += sizeof (struct T_opthdr);
				pkti = (struct in6_pktinfo *)dstopt;
				if (ipversion == IPV6_VERSION)
					pkti->ipi6_addr = ip6h->ip6_dst;
				else
					IN6_IPADDR_TO_V4MAPPED(
						((ipha_t *)rptr)->ipha_dst,
						    &pkti->ipi6_addr);
				pkti->ipi6_ifindex = ipp.ipp_ifindex;
				dstopt += sizeof (*pkti);
				udi_size -= toh->len;
			}
			if (udp->udp_ipv6_recvhoplimit) {
				struct T_opthdr *toh;

				toh = (struct T_opthdr *)dstopt;
				toh->level = IPPROTO_IPV6;
				toh->name = IPV6_HOPLIMIT;
				toh->len = sizeof (struct T_opthdr) +
				    sizeof (uint_t);
				toh->status = 0;
				dstopt += sizeof (struct T_opthdr);
				if (ipversion == IPV6_VERSION)
					*(uint_t *)dstopt = ip6h->ip6_hops;
				else
					*(uint_t *)dstopt =
					    ((ipha_t *)rptr)->ipha_ttl;
				dstopt += sizeof (uint_t);
				udi_size -= toh->len;
			}
			if (udp->udp_ipv6_recvtclass) {
				struct T_opthdr *toh;

				toh = (struct T_opthdr *)dstopt;
				toh->level = IPPROTO_IPV6;
				toh->name = IPV6_TCLASS;
				toh->len = sizeof (struct T_opthdr) +
				    sizeof (uint_t);
				toh->status = 0;
				dstopt += sizeof (struct T_opthdr);
				if (ipversion == IPV6_VERSION) {
					*(uint_t *)dstopt =
					IPV6_FLOW_TCLASS(ip6h->ip6_flow);
				} else {
					ipha_t *ipha = (ipha_t *)rptr;
					*(uint_t *)dstopt =
					    ipha->ipha_type_of_service;
				}
				dstopt += sizeof (uint_t);
				udi_size -= toh->len;
			}
			if (udp->udp_ipv6_recvhopopts &&
			    (ipp.ipp_fields & IPPF_HOPOPTS)) {
				struct T_opthdr *toh;

				toh = (struct T_opthdr *)dstopt;
				toh->level = IPPROTO_IPV6;
				toh->name = IPV6_HOPOPTS;
				toh->len = sizeof (struct T_opthdr) +
				    ipp.ipp_hopoptslen;
				toh->status = 0;
				dstopt += sizeof (struct T_opthdr);
				bcopy(ipp.ipp_hopopts, dstopt,
				    ipp.ipp_hopoptslen);
				dstopt += ipp.ipp_hopoptslen;
				udi_size -= toh->len;
			}
			if (udp->udp_ipv6_recvdstopts &&
			    udp->udp_ipv6_recvrthdr &&
			    (ipp.ipp_fields & IPPF_RTHDR) &&
			    (ipp.ipp_fields & IPPF_RTDSTOPTS)) {
				struct T_opthdr *toh;

				toh = (struct T_opthdr *)dstopt;
				toh->level = IPPROTO_IPV6;
				toh->name = IPV6_DSTOPTS;
				toh->len = sizeof (struct T_opthdr) +
				    ipp.ipp_rtdstoptslen;
				toh->status = 0;
				dstopt += sizeof (struct T_opthdr);
				bcopy(ipp.ipp_rtdstopts, dstopt,
				    ipp.ipp_rtdstoptslen);
				dstopt += ipp.ipp_rtdstoptslen;
				udi_size -= toh->len;
			}
			if (udp->udp_ipv6_recvrthdr &&
			    (ipp.ipp_fields & IPPF_RTHDR)) {
				struct T_opthdr *toh;

				toh = (struct T_opthdr *)dstopt;
				toh->level = IPPROTO_IPV6;
				toh->name = IPV6_RTHDR;
				toh->len = sizeof (struct T_opthdr) +
				    ipp.ipp_rthdrlen;
				toh->status = 0;
				dstopt += sizeof (struct T_opthdr);
				bcopy(ipp.ipp_rthdr, dstopt, ipp.ipp_rthdrlen);
				dstopt += ipp.ipp_rthdrlen;
				udi_size -= toh->len;
			}
			if (udp->udp_ipv6_recvdstopts &&
			    (ipp.ipp_fields & IPPF_DSTOPTS)) {
				struct T_opthdr *toh;

				toh = (struct T_opthdr *)dstopt;
				toh->level = IPPROTO_IPV6;
				toh->name = IPV6_DSTOPTS;
				toh->len = sizeof (struct T_opthdr) +
				    ipp.ipp_dstoptslen;
				toh->status = 0;
				dstopt += sizeof (struct T_opthdr);
				bcopy(ipp.ipp_dstopts, dstopt,
				    ipp.ipp_dstoptslen);
				dstopt += ipp.ipp_dstoptslen;
				udi_size -= toh->len;
			}

			if (cr != NULL) {
				struct T_opthdr *toh;

				toh = (struct T_opthdr *)dstopt;
				toh->level = SOL_SOCKET;
				toh->name = SCM_UCRED;
				toh->len = sizeof (struct T_opthdr) + ucredsize;
				toh->status = 0;
				(void) cred2ucred(cr, cpid, &toh[1]);
				dstopt += toh->len;
				udi_size -= toh->len;
			}
			/* Consumed all of allocated space */
			ASSERT(udi_size == 0);
		}
#undef	sin6
		/* No IP_RECVDSTADDR for IPv6. */
	}

	BUMP_MIB(&udp_mib, udpInDatagrams);
	TRACE_2(TR_FAC_UDP, TR_UDP_RPUT_END,
		"udp_rput_end: q %p (%S)", q, "end");
	if (options_mp != NULL)
		freeb(options_mp);
	putnext(q, mp);
}

/*
 * Process non-M_DATA messages as well as M_DATA messages that requires
 * modifications to udp_ip_rcv_options i.e. IPv4 packets with IP options.
 */
static void
udp_rput_other(queue_t *q, mblk_t *mp)
{
	struct T_unitdata_ind	*tudi;
	mblk_t			*mp1;
	uchar_t			*rptr;
	uchar_t			*new_rptr;
	int			hdr_length;
	int			udi_size;	/* Size of T_unitdata_ind */
	int			opt_len;	/* Length of IP options */
	sin_t			*sin;
	struct T_error_ack	*tea;
	udp_t			*udp;
	mblk_t			*options_mp = NULL;
	in_pktinfo_t		*pinfo;
	boolean_t		recv_on = B_FALSE;
	cred_t			*cr = NULL;
	pid_t			cpid;

	TRACE_2(TR_FAC_UDP, TR_UDP_RPUT_START,
	    "udp_rput_other: q %p mp %p", q, mp);

	ASSERT(OK_32PTR(mp->b_rptr));
	udp = (udp_t *)q->q_ptr;
	rptr = mp->b_rptr;

	switch (mp->b_datap->db_type) {
	case M_CTL:
		/*
		 * We are here only if IP_RECVSLLA and/or IP_RECVIF are set
		 */
		recv_on = B_TRUE;
		options_mp = mp;
		pinfo = (in_pktinfo_t *)options_mp->b_rptr;

		/*
		 * The actual data is in mp->b_cont
		 */
		mp = mp->b_cont;
		ASSERT(OK_32PTR(mp->b_rptr));
		rptr = mp->b_rptr;
		break;
	case M_DATA:
		/*
		 * M_DATA messages contain IPv4 datagrams.  They are handled
		 * after this switch.
		 */
		break;
	case M_PROTO:
	case M_PCPROTO:
		/* M_PROTO messages contain some type of TPI message. */
		ASSERT((uintptr_t)(mp->b_wptr - rptr) <= (uintptr_t)INT_MAX);
		if (mp->b_wptr - rptr < sizeof (t_scalar_t)) {
			freemsg(mp);
			TRACE_2(TR_FAC_UDP, TR_UDP_RPUT_END,
			    "udp_rput_other_end: q %p (%S)", q, "protoshort");
			return;
		}
		tea = (struct T_error_ack *)rptr;

		switch (tea->PRIM_type) {
		case T_ERROR_ACK:
			switch (tea->ERROR_prim) {
			case O_T_BIND_REQ:
			case T_BIND_REQ: {
				/*
				 * If our O_T_BIND_REQ/T_BIND_REQ fails,
				 * clear out the associated port and source
				 * address before passing the message
				 * upstream. If this was caused by a T_CONN_REQ
				 * revert back to bound state.
				 */
				udp_fanout_t	*udpf;

				udpf = &udp_bind_fanout[
				    UDP_BIND_HASH(udp->udp_port)];
				mutex_enter(&udpf->uf_lock);
				if (udp->udp_state == TS_DATA_XFER) {
					/* Connect failed */
					tea->ERROR_prim = T_CONN_REQ;
					/* Revert back to the bound source */
					udp->udp_v6src = udp->udp_bound_v6src;
					udp->udp_state = TS_IDLE;
					mutex_exit(&udpf->uf_lock);
					if (udp->udp_family == AF_INET6)
						(void) udp_build_hdrs(q, udp);
					break;
				}

				if (udp->udp_discon_pending) {
					tea->ERROR_prim = T_DISCON_REQ;
					udp->udp_discon_pending = 0;
				}
				V6_SET_ZERO(udp->udp_v6src);
				V6_SET_ZERO(udp->udp_bound_v6src);
				udp->udp_state = TS_UNBND;
				udp_bind_hash_remove(udp, B_TRUE);
				udp->udp_port = 0;
				mutex_exit(&udpf->uf_lock);
				if (udp->udp_family == AF_INET6)
					(void) udp_build_hdrs(q, udp);
				break;
			}
			default:
				break;
			}
			break;
		case T_BIND_ACK:
			udp_rput_bind_ack(q, mp);
			return;

		case T_OPTMGMT_ACK:
		case T_OK_ACK:
			break;
		default:
			freemsg(mp);
			return;
		}
		putnext(q, mp);
		return;
	}

	/*
	 * This is the inbound data path.
	 * First, we make sure the data contains both IP and UDP headers.
	 *
	 * This handle IPv4 packets for only AF_INET sockets.
	 * AF_INET6 sockets can never access udp_ip_rcv_options thus there
	 * is no need saving the options.
	 */
	ASSERT(IPH_HDR_VERSION((ipha_t *)rptr) == IPV4_VERSION);
	hdr_length = IPH_HDR_LENGTH(rptr) + UDPH_SIZE;
	if (mp->b_wptr - rptr < hdr_length) {
		if (!pullupmsg(mp, hdr_length)) {
			freemsg(mp);
			if (options_mp != NULL)
				freeb(options_mp);
			BUMP_MIB(&udp_mib, udpInErrors);
			TRACE_2(TR_FAC_UDP, TR_UDP_RPUT_END,
			    "udp_rput_other_end: q %p (%S)", q, "hdrshort");
			BUMP_MIB(&udp_mib, udpInErrors);
			return;
		}
		rptr = mp->b_rptr;
	}
	/* Walk past the headers. */
	new_rptr = rptr + hdr_length;
	if (!udp->udp_rcvhdr)
		mp->b_rptr = new_rptr;

	/* Save the options if any */
	opt_len = hdr_length - (IP_SIMPLE_HDR_LENGTH + UDPH_SIZE);
	if (opt_len > 0) {
		if (opt_len > udp->udp_ip_rcv_options_len) {
			if (udp->udp_ip_rcv_options_len)
				mi_free((char *)udp->udp_ip_rcv_options);
			udp->udp_ip_rcv_options_len = 0;
			udp->udp_ip_rcv_options =
			    (uchar_t *)mi_alloc(opt_len, BPRI_HI);
			if (udp->udp_ip_rcv_options)
				udp->udp_ip_rcv_options_len = opt_len;
		}
		if (udp->udp_ip_rcv_options_len) {
			bcopy(rptr + IP_SIMPLE_HDR_LENGTH,
			    udp->udp_ip_rcv_options, opt_len);
			/* Adjust length if we are resusing the space */
			udp->udp_ip_rcv_options_len = opt_len;
		}
	} else if (udp->udp_ip_rcv_options_len) {
		mi_free((char *)udp->udp_ip_rcv_options);
		udp->udp_ip_rcv_options = NULL;
		udp->udp_ip_rcv_options_len = 0;
	}

	/*
	 * Normally only send up the address.
	 * If IP_RECVDSTADDR is set we include the destination IP
	 * address as an option. With IP_RECVOPTS we include all
	 * the IP options.
	 */
	udi_size = sizeof (struct T_unitdata_ind) + sizeof (sin_t);
	if (udp->udp_recvdstaddr) {
		udi_size += sizeof (struct T_opthdr) + sizeof (struct in_addr);
	}
	if (udp->udp_recvopts && opt_len > 0)
		udi_size += sizeof (struct T_opthdr) + opt_len;

	/*
	 * If the IP_RECVSLLA or the IP_RECVIF is set then allocate
	 * space accordingly
	 */
	if (udp->udp_recvif && recv_on &&
	    (pinfo->in_pkt_flags & IPF_RECVIF)) {
		udi_size += sizeof (struct T_opthdr) +
		    sizeof (uint_t);
	}

	if (udp->udp_recvslla && recv_on &&
	    (pinfo->in_pkt_flags & IPF_RECVSLLA)) {
		udi_size += sizeof (struct T_opthdr) +
		    sizeof (struct sockaddr_dl);
	}

	if (udp->udp_recvucred && (cr = DB_CRED(mp)) != NULL) {
		udi_size += sizeof (struct T_opthdr) + ucredsize;
		cpid = DB_CPID(mp);
	}
	/*
	 * If IP_RECVTTL is set allocate the appropriate sized buffer
	 */
	if (udp->udp_recvttl) {
		udi_size += sizeof (struct T_opthdr) + sizeof (uint8_t);
	}

	/* Allocate a message block for the T_UNITDATA_IND structure. */
	mp1 = allocb(udi_size, BPRI_MED);
	if (mp1 == NULL) {
		freemsg(mp);
		if (options_mp != NULL)
			freeb(options_mp);
		TRACE_2(TR_FAC_UDP, TR_UDP_RPUT_END,
			"udp_rput_other_end: q %p (%S)", q, "allocbfail");
		BUMP_MIB(&udp_mib, udpInErrors);
		return;
	}
	mp1->b_cont = mp;
	mp = mp1;
	mp->b_datap->db_type = M_PROTO;
	tudi = (struct T_unitdata_ind *)mp->b_rptr;
	mp->b_wptr = (uchar_t *)tudi + udi_size;
	tudi->PRIM_type = T_UNITDATA_IND;
	tudi->SRC_length = sizeof (sin_t);
	tudi->SRC_offset = sizeof (struct T_unitdata_ind);
	tudi->OPT_offset = sizeof (struct T_unitdata_ind) + sizeof (sin_t);
	udi_size -= (sizeof (struct T_unitdata_ind) + sizeof (sin_t));
	tudi->OPT_length = udi_size;

	sin = (sin_t *)&tudi[1];
	sin->sin_addr.s_addr = ((ipha_t *)rptr)->ipha_src;
	sin->sin_port =	((in_port_t *)
	    new_rptr)[-(UDPH_SIZE/sizeof (in_port_t))];
	sin->sin_family = AF_INET;
	*(uint32_t *)&sin->sin_zero[0] = 0;
	*(uint32_t *)&sin->sin_zero[4] = 0;

	/*
	 * Add options if IP_RECVDSTADDR, IP_RECVIF, IP_RECVSLLA or
	 * IP_RECVTTL has been set.
	 */
	if (udi_size != 0) {
		/*
		 * Copy in destination address before options to avoid any
		 * padding issues.
		 */
		char *dstopt;

		dstopt = (char *)&sin[1];
		if (udp->udp_recvdstaddr) {
			struct T_opthdr *toh;
			ipaddr_t *dstptr;

			toh = (struct T_opthdr *)dstopt;
			toh->level = IPPROTO_IP;
			toh->name = IP_RECVDSTADDR;
			toh->len = sizeof (struct T_opthdr) + sizeof (ipaddr_t);
			toh->status = 0;
			dstopt += sizeof (struct T_opthdr);
			dstptr = (ipaddr_t *)dstopt;
			*dstptr = (((ipaddr_t *)rptr)[4]);
			dstopt += sizeof (ipaddr_t);
			udi_size -= toh->len;
		}
		if (udp->udp_recvopts && udi_size != 0) {
			struct T_opthdr *toh;

			toh = (struct T_opthdr *)dstopt;
			toh->level = IPPROTO_IP;
			toh->name = IP_RECVOPTS;
			toh->len = sizeof (struct T_opthdr) + opt_len;
			toh->status = 0;
			dstopt += sizeof (struct T_opthdr);
			bcopy(rptr + IP_SIMPLE_HDR_LENGTH, dstopt, opt_len);
			dstopt += opt_len;
			udi_size -= toh->len;
		}

		if (udp->udp_recvslla && recv_on &&
		    (pinfo->in_pkt_flags & IPF_RECVSLLA)) {

			struct T_opthdr *toh;
			struct sockaddr_dl	*dstptr;

			toh = (struct T_opthdr *)dstopt;
			toh->level = IPPROTO_IP;
			toh->name = IP_RECVSLLA;
			toh->len = sizeof (struct T_opthdr) +
			    sizeof (struct sockaddr_dl);
			toh->status = 0;
			dstopt += sizeof (struct T_opthdr);
			dstptr = (struct sockaddr_dl *)dstopt;
			bcopy(&pinfo->in_pkt_slla, dstptr,
			    sizeof (struct sockaddr_dl));
			dstopt += sizeof (struct sockaddr_dl);
			udi_size -= toh->len;
		}

		if (udp->udp_recvif && recv_on &&
		    (pinfo->in_pkt_flags & IPF_RECVIF)) {

			struct T_opthdr *toh;
			uint_t		*dstptr;

			toh = (struct T_opthdr *)dstopt;
			toh->level = IPPROTO_IP;
			toh->name = IP_RECVIF;
			toh->len = sizeof (struct T_opthdr) +
			    sizeof (uint_t);
			toh->status = 0;
			dstopt += sizeof (struct T_opthdr);
			dstptr = (uint_t *)dstopt;
			*dstptr = pinfo->in_pkt_ifindex;
			dstopt += sizeof (uint_t);
			udi_size -= toh->len;
		}

		if (cr != NULL) {
			struct T_opthdr *toh;

			toh = (struct T_opthdr *)dstopt;
			toh->level = SOL_SOCKET;
			toh->name = SCM_UCRED;
			toh->len = sizeof (struct T_opthdr) + ucredsize;
			toh->status = 0;
			(void) cred2ucred(cr, cpid, &toh[1]);
			dstopt += toh->len;
			udi_size -= toh->len;
		}

		if (udp->udp_recvttl) {
			struct	T_opthdr *toh;
			uint8_t	*dstptr;

			toh = (struct T_opthdr *)dstopt;
			toh->level = IPPROTO_IP;
			toh->name = IP_RECVTTL;
			toh->len = sizeof (struct T_opthdr) +
			    sizeof (uint8_t);
			toh->status = 0;
			dstopt += sizeof (struct T_opthdr);
			dstptr = (uint8_t *)dstopt;
			*dstptr = ((ipha_t *)rptr)->ipha_ttl;
			dstopt += sizeof (uint8_t);
			udi_size -= toh->len;
		}

		ASSERT(udi_size == 0);	/* "Consumed" all of allocated space */
	}
	BUMP_MIB(&udp_mib, udpInDatagrams);
	TRACE_2(TR_FAC_UDP, TR_UDP_RPUT_END,
	    "udp_rput_other_end: q %p (%S)", q, "end");
	if (options_mp != NULL)
		freeb(options_mp);
	putnext(q, mp);
}

/*
 * Process a T_BIND_ACK
 */
static void
udp_rput_bind_ack(queue_t *q, mblk_t *mp)
{
	udp_t	*udp = (udp_t *)q->q_ptr;
	mblk_t	*mp1;
	ire_t	*ire;
	struct T_bind_ack *tba;
	uchar_t *addrp;
	ipa_conn_t	*ac;
	ipa6_conn_t	*ac6;

	if (udp->udp_discon_pending)
		udp->udp_discon_pending = 0;

	/*
	 * If a broadcast/multicast address was bound set
	 * the source address to 0.
	 * This ensures no datagrams with broadcast address
	 * as source address are emitted (which would violate
	 * RFC1122 - Hosts requirements)
	 *
	 * Note that when connecting the returned IRE is
	 * for the destination address and we only perform
	 * the broadcast check for the source address (it
	 * is OK to connect to a broadcast/multicast address.)
	 */
	mp1 = mp->b_cont;
	if (mp1 != NULL && mp1->b_datap->db_type == IRE_DB_TYPE) {
		ire = (ire_t *)mp1->b_rptr;

		/*
		 * Note: we get IRE_BROADCAST for IPv6 to "mark" a multicast
		 * local address.
		 */
		if (ire->ire_type == IRE_BROADCAST &&
		    udp->udp_state != TS_DATA_XFER) {
			/* This was just a local bind to a broadcast addr */
			V6_SET_ZERO(udp->udp_v6src);
			if (udp->udp_family == AF_INET6)
				(void) udp_build_hdrs(q, udp);
		} else if (V6_OR_V4_INADDR_ANY(udp->udp_v6src)) {
			/*
			 * Local address not yet set - pick it from the
			 * T_bind_ack
			 */
			tba = (struct T_bind_ack *)mp->b_rptr;
			addrp = &mp->b_rptr[tba->ADDR_offset];
			switch (udp->udp_family) {
			case AF_INET:
				if (tba->ADDR_length == sizeof (ipa_conn_t)) {
					ac = (ipa_conn_t *)addrp;
				} else {
					ASSERT(tba->ADDR_length ==
					    sizeof (ipa_conn_x_t));
					ac = &((ipa_conn_x_t *)addrp)->acx_conn;
				}
				IN6_IPADDR_TO_V4MAPPED(ac->ac_laddr,
				    &udp->udp_v6src);
				break;
			case AF_INET6:
				if (tba->ADDR_length == sizeof (ipa6_conn_t)) {
					ac6 = (ipa6_conn_t *)addrp;
				} else {
					ASSERT(tba->ADDR_length ==
					    sizeof (ipa6_conn_x_t));
					ac6 = &((ipa6_conn_x_t *)
					    addrp)->ac6x_conn;
				}
				udp->udp_v6src = ac6->ac6_laddr;
				(void) udp_build_hdrs(q, udp);
				break;
			}
		}
		mp1 = mp1->b_cont;
	}
	/*
	 * Look for one or more appended ACK message added by
	 * udp_connect or udp_disconnect.
	 * If none found just send up the T_BIND_ACK.
	 * udp_connect has appended a T_OK_ACK and a T_CONN_CON.
	 * udp_disconnect has appended a T_OK_ACK.
	 */
	if (mp1 != NULL) {
		if (mp->b_cont == mp1)
			mp->b_cont = NULL;
		else {
			ASSERT(mp->b_cont->b_cont == mp1);
			mp->b_cont->b_cont = NULL;
		}
		freemsg(mp);
		mp = mp1;
		while (mp != NULL) {
			mp1 = mp->b_cont;
			mp->b_cont = NULL;
			putnext(q, mp);
			mp = mp1;
		}
		return;
	}
	freemsg(mp->b_cont);
	mp->b_cont = NULL;
	putnext(q, mp);
}

/*
 * return SNMP stuff in buffer in mpdata
 */
static int
udp_snmp_get(queue_t *q, mblk_t *mpctl)
{
	mblk_t			*mpdata;
	mblk_t			*mp_conn_ctl;
	mblk_t			*mp6_conn_ctl;
	mblk_t			*mp_conn_data;
	mblk_t			*mp6_conn_data;
	mblk_t			*mp_conn_tail = NULL;
	mblk_t			*mp6_conn_tail = NULL;
	struct opthdr		*optp;
	IDP			idp;
	udp_t			*udp;
	mib2_udpEntry_t		ude;
	mib2_udp6Entry_t	ude6;
	int			state;
	zoneid_t		zoneid;

	if (mpctl == NULL ||
	    (mpdata = mpctl->b_cont) == NULL ||
	    (mp_conn_ctl = copymsg(mpctl)) == NULL ||
	    (mp6_conn_ctl = copymsg(mpctl)) == NULL) {
		freemsg(mp_conn_ctl);
		return (0);
	}

	mp_conn_data = mp_conn_ctl->b_cont;
	mp6_conn_data = mp6_conn_ctl->b_cont;

	udp = (udp_t *)q->q_ptr;
	zoneid = udp->udp_zoneid;

	/* fixed length structure for IPv4 and IPv6 counters */
	SET_MIB(udp_mib.udpEntrySize, sizeof (mib2_udpEntry_t));
	SET_MIB(udp_mib.udp6EntrySize, sizeof (mib2_udp6Entry_t));
	optp = (struct opthdr *)&mpctl->b_rptr[sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_UDP;
	optp->name = 0;
	(void) snmp_append_data(mpdata, (char *)&udp_mib, sizeof (udp_mib));
	optp->len = msgdsize(mpdata);
	qreply(q, mpctl);

	mutex_enter(&udp_g_lock);
	for (idp = mi_first_ptr(&udp_g_head);
	    (udp = (udp_t *)idp) != 0;
	    idp = mi_next_ptr(&udp_g_head, idp)) {

		if (zoneid != udp->udp_zoneid)
			continue;

		/* Note that the port numbers are sent in host byte order */

		if (udp->udp_state == TS_UNBND)
			state = MIB2_UDP_unbound;
		else if (udp->udp_state == TS_IDLE)
			state = MIB2_UDP_idle;
		else if (udp->udp_state == TS_DATA_XFER)
			state = MIB2_UDP_connected;
		else
			state = MIB2_UDP_unknown;

		/*
		 * Create an IPv4 table entry for IPv4 entries and also
		 * any IPv6 entries which are bound to in6addr_any
		 * (i.e. anything a IPv4 peer could connect/send to).
		 */
		if (udp->udp_ipversion == IPV4_VERSION ||
		    (udp->udp_state <= TS_IDLE &&
		    IN6_IS_ADDR_UNSPECIFIED(&udp->udp_v6src))) {
			ude.udpEntryInfo.ue_state = state;
			/* If in6addr_any this will set it to INADDR_ANY */
			ude.udpLocalAddress = V4_PART_OF_V6(udp->udp_v6src);
			ude.udpLocalPort = ntohs(udp->udp_port);
			if (udp->udp_state == TS_DATA_XFER) {
				/*
				 * Can potentially get here for v6 socket
				 * if another process (say, ping) has just
				 * done a sendto(), changing the state
				 * from the TS_IDLE above to TS_DATA_XFER
				 * by the time we hit this part of the code.
				 */
				ude.udpEntryInfo.ue_RemoteAddress =
				    V4_PART_OF_V6(udp->udp_v6dst);
				ude.udpEntryInfo.ue_RemotePort =
				    ntohs(udp->udp_dstport);
			} else {
				ude.udpEntryInfo.ue_RemoteAddress = 0;
				ude.udpEntryInfo.ue_RemotePort = 0;
			}
			(void) snmp_append_data2(mp_conn_data, &mp_conn_tail,
			    (char *)&ude, sizeof (ude));
		}
		if (udp->udp_ipversion == IPV6_VERSION) {
			ude6.udp6EntryInfo.ue_state  = state;
			ude6.udp6LocalAddress = udp->udp_v6src;
			ude6.udp6LocalPort = ntohs(udp->udp_port);
			ude6.udp6IfIndex = udp->udp_bound_if;
			if (udp->udp_state == TS_DATA_XFER) {
				ude6.udp6EntryInfo.ue_RemoteAddress =
				    udp->udp_v6dst;
				ude6.udp6EntryInfo.ue_RemotePort =
				    ntohs(udp->udp_dstport);
			} else {
				ude6.udp6EntryInfo.ue_RemoteAddress =
				    sin6_null.sin6_addr;
				ude6.udp6EntryInfo.ue_RemotePort = 0;
			}
			(void) snmp_append_data2(mp6_conn_data, &mp6_conn_tail,
			    (char *)&ude6, sizeof (ude6));
		}
	}
	mutex_exit(&udp_g_lock);

	/* IPv4 UDP endpoints */
	optp = (struct opthdr *)&mp_conn_ctl->b_rptr[
	    sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_UDP;
	optp->name = MIB2_UDP_ENTRY;
	optp->len = msgdsize(mp_conn_data);
	qreply(q, mp_conn_ctl);

	/* IPv6 UDP endpoints */
	optp = (struct opthdr *)&mp6_conn_ctl->b_rptr[
	    sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_UDP6;
	optp->name = MIB2_UDP6_ENTRY;
	optp->len = msgdsize(mp6_conn_data);
	qreply(q, mp6_conn_ctl);

	return (1);
}

/*
 * Return 0 if invalid set request, 1 otherwise, including non-udp requests.
 * NOTE: Per MIB-II, UDP has no writable data.
 * TODO:  If this ever actually tries to set anything, it needs to be
 * to do the appropriate locking.
 */
/* ARGSUSED */
static int
udp_snmp_set(queue_t *q, t_scalar_t level, t_scalar_t name,
    uchar_t *ptr, int len)
{
	switch (level) {
	case MIB2_UDP:
		return (0);
	default:
		return (1);
	}
}

static void
udp_report_item(mblk_t *mp, udp_t *udp)
{
	char *state;
	char addrbuf1[INET6_ADDRSTRLEN];
	char addrbuf2[INET6_ADDRSTRLEN];
	uint_t print_len, buf_len;

	buf_len = mp->b_datap->db_lim - mp->b_wptr;
	ASSERT(buf_len >= 0);
	if (buf_len == 0)
		return;

	if (udp->udp_state == TS_UNBND)
		state = "UNBOUND";
	else if (udp->udp_state == TS_IDLE)
		state = "IDLE";
	else if (udp->udp_state == TS_DATA_XFER)
		state = "CONNECTED";
	else
		state = "UnkState";
	print_len = snprintf((char *)mp->b_wptr, buf_len,
	    MI_COL_PTRFMT_STR "%4d %5u %s %s %5u %s\n",
	    (void *)udp, udp->udp_zoneid, ntohs(udp->udp_port),
	    inet_ntop(AF_INET6, &udp->udp_v6src,
		addrbuf1, sizeof (addrbuf1)),
	    inet_ntop(AF_INET6, &udp->udp_v6dst,
		addrbuf2, sizeof (addrbuf2)),
	    ntohs(udp->udp_dstport), state);
	if (print_len < buf_len) {
		mp->b_wptr += print_len;
	} else {
		mp->b_wptr += buf_len;
	}
}

/* Report for ndd "udp_status" */
/* ARGSUSED */
static int
udp_status_report(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	IDP	idp;
	udp_t	*udp;
	zoneid_t zoneid;

	/*
	 * Because of the ndd constraint, at most we can have 64K buffer
	 * to put in all UDP info.  So to be more efficient, just
	 * allocate a 64K buffer here, assuming we need that large buffer.
	 * This may be a problem as any user can read udp_status.  Therefore
	 * we limit the rate of doing this using udp_ndd_get_info_interval.
	 * This should be OK as normal users should not do this too often.
	 */
	if (cr == NULL || secpolicy_net_config(cr, B_TRUE) != 0) {
		if (ddi_get_lbolt() - udp_last_ndd_get_info_time <
		    drv_usectohz(udp_ndd_get_info_interval * 1000)) {
			(void) mi_mpprintf(mp, NDD_TOO_QUICK_MSG);
			return (0);
		}
	}
	if ((mp->b_cont = allocb(ND_MAX_BUF_LEN, BPRI_HI)) == NULL) {
		/* The following may work even if we cannot get a large buf. */
		(void) mi_mpprintf(mp, NDD_OUT_OF_BUF_MSG);
		return (0);
	}
	(void) mi_mpprintf(mp,
	    "UDP     " MI_COL_HDRPAD_STR
	/*   12345678[89ABCDEF] */
	    " zone lport src addr        dest addr       port  state");
	/*    1234 12345 xxx.xxx.xxx.xxx xxx.xxx.xxx.xxx 12345 UNBOUND */

	udp = (udp_t *)q->q_ptr;
	zoneid = udp->udp_zoneid;

	mutex_enter(&udp_g_lock);
	for (idp = mi_first_ptr(&udp_g_head);
	    (udp = (udp_t *)idp) != 0;
	    idp = mi_next_ptr(&udp_g_head, idp)) {

		if (zoneid != GLOBAL_ZONEID &&
		    zoneid != udp->udp_zoneid)
			continue;

		udp_report_item(mp->b_cont, udp);
	}
	mutex_exit(&udp_g_lock);
	udp_last_ndd_get_info_time = ddi_get_lbolt();
	return (0);
}

/*
 * This routine creates a T_UDERROR_IND message and passes it upstream.
 * The address and options are copied from the T_UNITDATA_REQ message
 * passed in mp.  This message is freed.
 */
static void
udp_ud_err(queue_t *q, mblk_t *mp, t_scalar_t err)
{
	mblk_t	*mp1;
	struct T_unitdata_req	*tudr = (struct T_unitdata_req *)mp->b_rptr;
	uchar_t	*destaddr, *optaddr;

	if ((mp->b_wptr < mp->b_rptr) ||
	    (mp->b_wptr - mp->b_rptr) < sizeof (struct T_unitdata_req)) {
		goto done;
	}
	destaddr = mp->b_rptr + tudr->DEST_offset;
	if (destaddr < mp->b_rptr || destaddr >= mp->b_wptr ||
	    destaddr + tudr->DEST_length < mp->b_rptr ||
	    destaddr + tudr->DEST_length > mp->b_wptr) {
		goto done;
	}
	optaddr = mp->b_rptr + tudr->OPT_offset;
	if (optaddr < mp->b_rptr || optaddr >= mp->b_wptr ||
	    optaddr + tudr->OPT_length < mp->b_rptr ||
	    optaddr + tudr->OPT_length > mp->b_wptr) {
		goto done;
	}
	mp1 = mi_tpi_uderror_ind((char *)destaddr, tudr->DEST_length,
	    (char *)optaddr, tudr->OPT_length, err);
	if (mp1)
		qreply(q, mp1);

done:
	freemsg(mp);
}

/*
 * This routine removes a port number association from a stream.  It
 * is called by udp_wput to handle T_UNBIND_REQ messages.
 */
static void
udp_unbind(queue_t *q, mblk_t *mp)
{
	udp_t	*udp;

	udp = (udp_t *)q->q_ptr;
	/* If a bind has not been done, we can't unbind. */
	if (udp->udp_state == TS_UNBND) {
		udp_err_ack(q, mp, TOUTSTATE, 0);
		return;
	}
	if (cl_inet_unbind != NULL) {
		/*
		 * Running in cluster mode - register unbind information
		 */
		if (udp->udp_ipversion == IPV4_VERSION) {
			(*cl_inet_unbind)(IPPROTO_UDP, AF_INET,
			    (uint8_t *)(&V4_PART_OF_V6(udp->udp_v6src)),
			    (in_port_t)udp->udp_port);
		} else {
			(*cl_inet_unbind)(IPPROTO_UDP, AF_INET6,
			    (uint8_t *)&(udp->udp_v6src),
			    (in_port_t)udp->udp_port);
		}
	}

	udp_bind_hash_remove(udp, B_FALSE);
	V6_SET_ZERO(udp->udp_v6src);
	V6_SET_ZERO(udp->udp_bound_v6src);
	udp->udp_port = 0;
	udp->udp_state = TS_UNBND;

	if (udp->udp_family == AF_INET6) {
		int error;

		/* Rebuild the header template */
		error = udp_build_hdrs(q, udp);
		if (error != 0) {
			udp_err_ack(q, mp, TSYSERR, error);
			return;
		}
	}
	/* Pass the unbind to IP */
	putnext(q, mp);
}

/*
 * Don't let port fall into the privileged range.
 * Since the extra priviledged ports can be arbitrary we also
 * ensure that we exclude those from consideration.
 * udp_g_epriv_ports is not sorted thus we loop over it until
 * there are no changes.
 */
static in_port_t
udp_update_next_port(in_port_t port, boolean_t random)
{
	int i;

	if (random && udp_random_anon_port != 0) {
		(void) random_get_pseudo_bytes((uint8_t *)&port,
		    sizeof (in_port_t));
		/*
		 * Unless changed by a sys admin, the smallest anon port
		 * is 32768 and the largest anon port is 65535.  It is
		 * very likely (50%) for the random port to be smaller
		 * than the smallest anon port.  When that happens,
		 * add port % (anon port range) to the smallest anon
		 * port to get the random port.  It should fall into the
		 * valid anon port range.
		 */
		if (port < udp_smallest_anon_port) {
			port = udp_smallest_anon_port +
			    port % (udp_largest_anon_port -
			    udp_smallest_anon_port);
		}
	}

retry:
	if (port < udp_smallest_anon_port || port > udp_largest_anon_port)
		port = udp_smallest_anon_port;

	if (port < udp_smallest_nonpriv_port)
		port = udp_smallest_nonpriv_port;

	for (i = 0; i < udp_g_num_epriv_ports; i++) {
		if (port == udp_g_epriv_ports[i]) {
			port++;
			/*
			 * Make sure that the port is in the
			 * valid range.
			 */
			goto retry;
		}
	}
	return (port);
}

/*
 * This routine handles all messages passed downstream.  It either
 * consumes the message or passes it downstream; it never queues a
 * a message.
 */
static void
udp_wput(queue_t *q, mblk_t *mp)
{
	uchar_t		*rptr = mp->b_rptr;
	struct 		datab *db;
	ipha_t		*ipha;
	udpha_t		*udpha;
	mblk_t		*mp1;
	int		ip_hdr_length;
#define	tudr ((struct T_unitdata_req *)rptr)
	uint32_t	ip_len;
	udp_t		*udp;
	sin6_t		*sin6;
	sin_t		*sin;
	ipaddr_t	v4dst;
	uint16_t	port;
	uint_t		srcid;

	TRACE_2(TR_FAC_UDP, TR_UDP_WPUT_START,
		"udp_wput_start: q %p mp %p", q, mp);

	db = mp->b_datap;
	switch (db->db_type) {
	case M_PROTO:
	case M_PCPROTO:
		ASSERT((uintptr_t)(mp->b_wptr - rptr) <= (uintptr_t)INT_MAX);
		if (mp->b_wptr - rptr >= sizeof (struct T_unitdata_req)) {
			/* Detect valid T_UNITDATA_REQ here */
			if (((union T_primitives *)rptr)->type
			    == T_UNITDATA_REQ)
				break;
		}
		/* FALLTHRU */
	default:
		qwriter(q, mp, udp_wput_other, PERIM_INNER);
		return;
	}

	udp = (udp_t *)q->q_ptr;

	/* Handle UNITDATA_REQ messages here */
	if (udp->udp_state == TS_UNBND) {
		/* If a port has not been bound to the stream, fail. */
		BUMP_MIB(&udp_mib, udpOutErrors);
		udp_ud_err(q, mp, EPROTO);
		TRACE_2(TR_FAC_UDP, TR_UDP_WPUT_END,
			"udp_wput_end: q %p (%S)", q, "outstate");
		return;
	}
	mp1 = mp->b_cont;
	if (mp1 == NULL) {
		BUMP_MIB(&udp_mib, udpOutErrors);
		udp_ud_err(q, mp, EPROTO);
		TRACE_2(TR_FAC_UDP, TR_UDP_WPUT_END,
			"udp_wput_end: q %p (%S)", q, "badaddr");
		return;
	}

	if ((rptr + tudr->DEST_offset + tudr->DEST_length) > mp->b_wptr) {
		BUMP_MIB(&udp_mib, udpOutErrors);
		udp_ud_err(q, mp, EADDRNOTAVAIL);
		TRACE_2(TR_FAC_UDP, TR_UDP_WPUT_END,
			"udp_wput_end: q %p (%S)", q, "badaddr");
		return;
	}

	switch (udp->udp_family) {
	case AF_INET6:
		sin6 = (sin6_t *)&rptr[tudr->DEST_offset];
		if (!OK_32PTR((char *)sin6) ||
		    tudr->DEST_length != sizeof (sin6_t) ||
		    sin6->sin6_family != AF_INET6) {
			BUMP_MIB(&udp_mib, udpOutErrors);
			udp_ud_err(q, mp, EADDRNOTAVAIL);
			TRACE_2(TR_FAC_UDP, TR_UDP_WPUT_END,
				"udp_wput_end: q %p (%S)", q, "badaddr");
			return;
		}

		if (!IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
			/*
			 * Destination is a non-IPv4-compatible IPv6 address.
			 * Send out an IPv6 format packet.
			 */
			udp_wput_ipv6(q, mp, sin6, tudr->OPT_length);
			TRACE_2(TR_FAC_UDP, TR_UDP_WPUT_END,
				"udp_wput_end: q %p (%S)", q, "udp_wput_ipv6");
			return;
		}
		/*
		 * If the local address is not zero or a mapped address return
		 * an error.
		 * I would be possible to send an IPv4 packet but the
		 * response would never make it back to the application
		 * since it is bound to a non-mapped address.
		 */
		if (!IN6_IS_ADDR_V4MAPPED(&udp->udp_v6src) &&
		    !IN6_IS_ADDR_UNSPECIFIED(&udp->udp_v6src)) {
			BUMP_MIB(&udp_mib, udpOutErrors);
			udp_ud_err(q, mp, EADDRNOTAVAIL);
			TRACE_2(TR_FAC_UDP, TR_UDP_WPUT_END,
				"udp_wput_end: q %p (%S)", q, "badaddr");
			return;
		}
		/* Send IPv4 packet without modifying udp_ipversion */
		/* Extract port and ipaddr */
		port = sin6->sin6_port;
		IN6_V4MAPPED_TO_IPADDR(&sin6->sin6_addr, v4dst);
		srcid = sin6->__sin6_src_id;
		break;

	case AF_INET:
		sin = (sin_t *)&rptr[tudr->DEST_offset];
		if (!OK_32PTR((char *)sin) ||
		    tudr->DEST_length != sizeof (sin_t) ||
		    sin->sin_family != AF_INET) {
			BUMP_MIB(&udp_mib, udpOutErrors);
			udp_ud_err(q, mp, EADDRNOTAVAIL);
			TRACE_2(TR_FAC_UDP, TR_UDP_WPUT_END,
				"udp_wput_end: q %p (%S)", q, "badaddr");
			return;
		}
		/* Extract port and ipaddr */
		port = sin->sin_port;
		v4dst = sin->sin_addr.s_addr;
		srcid = 0;
		break;
	}


	/*
	 * If options passed in, feed it for verification and handling
	 */
	if (tudr->OPT_length != 0) {
		int error;

		if (udp_unitdata_opt_process(q, mp, &error, NULL) < 0) {
			/* failure */
			BUMP_MIB(&udp_mib, udpOutErrors);
			udp_ud_err(q, mp, error);
			TRACE_2(TR_FAC_UDP, TR_UDP_WPUT_END,
			    "udp_wput_end: q %p (%S)", q,
			    "udp_unitdata_opt_process");
			return;
		}
		ASSERT(error == 0);
		/*
		 * Note: success in processing options.
		 * mp option buffer represented by
		 * OPT_length/offset now potentially modified
		 * and contain option setting results
		 */
	}

	/* Add an IP header */
	ip_hdr_length = IP_SIMPLE_HDR_LENGTH + UDPH_SIZE +
	    udp->udp_ip_snd_options_len;
	ipha = (ipha_t *)&mp1->b_rptr[-ip_hdr_length];
	if ((mp1->b_datap->db_ref != 1) ||
	    ((uchar_t *)ipha < mp1->b_datap->db_base) ||
	    !OK_32PTR(ipha)) {
		uchar_t *wptr;

		mp1 = allocb(ip_hdr_length + udp_wroff_extra, BPRI_LO);
		if (!mp1) {
			BUMP_MIB(&udp_mib, udpOutErrors);
			udp_ud_err(q, mp, ENOMEM);
			TRACE_2(TR_FAC_UDP, TR_UDP_WPUT_END,
				"udp_wput_end: q %p (%S)", q, "allocbfail2");
			return;
		}
		mp1->b_cont = mp->b_cont;
		mp->b_cont = mp1;
		wptr = mp1->b_datap->db_lim;
		mp1->b_wptr = wptr;
		ipha = (ipha_t *)(wptr - ip_hdr_length);
	}
	mp1->b_rptr = (uchar_t *)ipha;

	ASSERT((uintptr_t)(mp1->b_wptr - (uchar_t *)ipha) <=
	    (uintptr_t)UINT_MAX);

	ip_hdr_length -= UDPH_SIZE;
#ifdef	_BIG_ENDIAN
	/* Set version, header length, and tos */
	*(uint16_t *)&ipha->ipha_version_and_hdr_length =
	    ((((IP_VERSION << 4) | (ip_hdr_length>>2)) << 8) |
		udp->udp_type_of_service);
	/* Set ttl and protocol */
	*(uint16_t *)&ipha->ipha_ttl = (udp->udp_ttl << 8) | IPPROTO_UDP;
#else
	/* Set version, header length, and tos */
	*(uint16_t *)&ipha->ipha_version_and_hdr_length =
		((udp->udp_type_of_service << 8) |
		    ((IP_VERSION << 4) | (ip_hdr_length>>2)));
	/* Set ttl and protocol */
	*(uint16_t *)&ipha->ipha_ttl = (IPPROTO_UDP << 8) | udp->udp_ttl;
#endif
	/*
	 * Copy our address into the packet.  If this is zero,
	 * first look at __sin6_src_id for a hint. If we leave the source
	 * as INADDR_ANY then ip will fill in the real source address.
	 */
	IN6_V4MAPPED_TO_IPADDR(&udp->udp_v6src, ipha->ipha_src);
	if (srcid != 0 && ipha->ipha_src == INADDR_ANY) {
		in6_addr_t v6src;

		ip_srcid_find_id(srcid, &v6src, udp->udp_zoneid);
		IN6_V4MAPPED_TO_IPADDR(&v6src, ipha->ipha_src);
	}

	ipha->ipha_fragment_offset_and_flags = 0;
	ipha->ipha_ident = 0;

	/* Determine length of packet */
	ip_len = (uint32_t)(mp1->b_wptr - (uchar_t *)ipha);
	{
		mblk_t	*mp2;
		if ((mp2 = mp1->b_cont) != NULL) {
			do {
				ASSERT((uintptr_t)(mp2->b_wptr - mp2->b_rptr)
				    <= (uintptr_t)UINT_MAX);
				ip_len += (uint32_t)(mp2->b_wptr - mp2->b_rptr);
			} while ((mp2 = mp2->b_cont) != NULL);
		}
	}
	/*
	 * If the size of the packet is greater than the maximum allowed by
	 * ip, return an error. Passing this down could cause panics because
	 * the size will have wrapped and be inconsistent with the msg size.
	 */
	if (ip_len > IP_MAXPACKET) {
		BUMP_MIB(&udp_mib, udpOutErrors);
		udp_ud_err(q, mp, EMSGSIZE);
		TRACE_2(TR_FAC_UDP, TR_UDP_WPUT_END,
		    "udp_wput_end: q %p (%S)", q, "IP length exceeded");
		return;
	}
	ipha->ipha_length = htons((uint16_t)ip_len);
	ip_len -= ip_hdr_length;
	ip_len = htons((uint16_t)ip_len);
	udpha = (udpha_t *)(((uchar_t *)ipha) + ip_hdr_length);
	/*
	 * Copy in the destination address and port from the T_UNITDATA
	 * request
	 */
	if (v4dst == INADDR_ANY)
		ipha->ipha_dst = htonl(INADDR_LOOPBACK);
	else
		ipha->ipha_dst = v4dst;

	/*
	 * Set ttl based on IP_MULTICAST_TTL to match IPv6 logic.
	 */
	if (CLASSD(v4dst))
		ipha->ipha_ttl = udp->udp_multicast_ttl;

	udpha->uha_dst_port = port;
	udpha->uha_src_port = udp->udp_port;

	if (ip_hdr_length > IP_SIMPLE_HDR_LENGTH) {
		uint32_t	cksum;

		bcopy(udp->udp_ip_snd_options, &ipha[1],
		    udp->udp_ip_snd_options_len);
		/*
		 * Massage source route putting first source route in ipha_dst.
		 * Ignore the destination in T_unitdata_req.
		 * Create a checksum adjustment for a source route, if any.
		 */
		cksum = ip_massage_options(ipha);
		cksum = (cksum & 0xFFFF) + (cksum >> 16);
		cksum -= ((ipha->ipha_dst >> 16) & 0xFFFF) +
		    (ipha->ipha_dst & 0xFFFF);
		if ((int)cksum < 0)
			cksum--;
		cksum = (cksum & 0xFFFF) + (cksum >> 16);
		/*
		 * IP does the checksum if uha_checksum is non-zero,
		 * We make it easy for IP to include our pseudo header
		 * by putting our length in uha_checksum.
		 */
		cksum += ip_len;
		cksum = (cksum & 0xFFFF) + (cksum >> 16);
		/* There might be a carry. */
		cksum = (cksum & 0xFFFF) + (cksum >> 16);
#ifdef _LITTLE_ENDIAN
		if (udp_do_checksum)
			ip_len = (cksum << 16) | ip_len;
#else
		if (udp_do_checksum)
			ip_len = (ip_len << 16) | cksum;
		else
			ip_len <<= 16;
#endif
	} else {
		/*
		 * IP does the checksum if uha_checksum is non-zero,
		 * We make it easy for IP to include our pseudo header
		 * by putting our length in uha_checksum.
		 */
		if (udp_do_checksum)
			ip_len |= (ip_len << 16);
#ifndef _LITTLE_ENDIAN
		else
			ip_len <<= 16;
#endif
	}
	/* Set UDP length and checksum */
	*((uint32_t *)&udpha->uha_length) = ip_len;

	freeb(mp);

	/* We're done.  Pass the packet to ip. */
	BUMP_MIB(&udp_mib, udpOutDatagrams);
	TRACE_2(TR_FAC_UDP, TR_UDP_WPUT_END,
		"udp_wput_end: q %p (%S)", q, "end");
	putnext(q, mp1);
#undef tudr
}

/*
 * udp_wput_ipv6():
 * Assumes that udp_wput did some sanity checking on the destination
 * address.
 */
static void
udp_wput_ipv6(queue_t *q, mblk_t *mp, sin6_t *sin6, t_scalar_t tudr_optlen)
{
	ip6_t			*ip6h;
	ip6i_t			*ip6i;	/* mp1->b_rptr even if no ip6i_t */
	mblk_t			*mp1;
	int			udp_ip_hdr_len = IPV6_HDR_LEN + UDPH_SIZE;
	size_t			ip_len;
	udpha_t			*udph;
	udp_t			*udp;
	ip6_pkt_t		ipp_s;	/* For ancillary data options */
	ip6_pkt_t		*ipp = &ipp_s;
	ip6_pkt_t		*tipp;	/* temporary ipp */
	uint32_t		csum = 0;
	uint_t			ignore = 0;
	uint_t			option_exists = 0, is_sticky = 0;
	uint8_t			*cp;
	uint8_t			*nxthdr_ptr;

	udp = (udp_t *)q->q_ptr;

	/*
	 * If the local address is a mapped address return
	 * an error.
	 * It would be possible to send an IPv6 packet but the
	 * response would never make it back to the application
	 * since it is bound to a mapped address.
	 */
	if (IN6_IS_ADDR_V4MAPPED(&udp->udp_v6src)) {
		BUMP_MIB(&udp_mib, udpOutErrors);
		udp_ud_err(q, mp, EADDRNOTAVAIL);
		return;
	}

	ipp->ipp_fields = 0;
	ipp->ipp_sticky_ignored = 0;

	/*
	 * If TPI options passed in, feed it for verification and handling
	 */
	if (tudr_optlen != 0) {
		int 		error;

		if (udp_unitdata_opt_process(q, mp, &error,
		    (void *)ipp) < 0) {
			/* failure */
			BUMP_MIB(&udp_mib, udpOutErrors);
			udp_ud_err(q, mp, error);
			return;
		}
		ignore = ipp->ipp_sticky_ignored;
		ASSERT(error == 0);
	}

	if (sin6->sin6_scope_id != 0 &&
	    IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
		/*
		 * IPPF_SCOPE_ID is special.  It's neither a sticky
		 * option nor ancillary data.  It needs to be
		 * explicitly set in options_exists.
		 */
		option_exists |= IPPF_SCOPE_ID;
	}

	if ((udp->udp_sticky_ipp.ipp_fields == 0) &&
	    (ipp->ipp_fields == 0)) {
		/* No sticky options nor ancillary data. */
		goto no_options;
	}

	/*
	 * Go through the options figuring out where each is going to
	 * come from and build two masks.  The first mask indicates if
	 * the option exists at all.  The second mask indicates if the
	 * option is sticky or ancillary.
	 */
	if (!(ignore & IPPF_HOPOPTS)) {
		if (ipp->ipp_fields & IPPF_HOPOPTS) {
			option_exists |= IPPF_HOPOPTS;
			udp_ip_hdr_len += ipp->ipp_hopoptslen;
		} else if (udp->udp_sticky_ipp.ipp_fields & IPPF_HOPOPTS) {
			option_exists |= IPPF_HOPOPTS;
			is_sticky |= IPPF_HOPOPTS;
			udp_ip_hdr_len += udp->udp_sticky_ipp.ipp_hopoptslen;
		}
	}

	if (!(ignore & IPPF_RTHDR)) {
		if (ipp->ipp_fields & IPPF_RTHDR) {
			option_exists |= IPPF_RTHDR;
			udp_ip_hdr_len += ipp->ipp_rthdrlen;
		} else if (udp->udp_sticky_ipp.ipp_fields & IPPF_RTHDR) {
			option_exists |= IPPF_RTHDR;
			is_sticky |= IPPF_RTHDR;
			udp_ip_hdr_len += udp->udp_sticky_ipp.ipp_rthdrlen;
		}
	}

	if (!(ignore & IPPF_RTDSTOPTS) && (option_exists & IPPF_RTHDR)) {
		if (ipp->ipp_fields & IPPF_RTDSTOPTS) {
			option_exists |= IPPF_RTDSTOPTS;
			udp_ip_hdr_len += ipp->ipp_rtdstoptslen;
		} else if (udp->udp_sticky_ipp.ipp_fields & IPPF_RTDSTOPTS) {
			option_exists |= IPPF_RTDSTOPTS;
			is_sticky |= IPPF_RTDSTOPTS;
			udp_ip_hdr_len += udp->udp_sticky_ipp.ipp_rtdstoptslen;
		}
	}

	if (!(ignore & IPPF_DSTOPTS)) {
		if (ipp->ipp_fields & IPPF_DSTOPTS) {
			option_exists |= IPPF_DSTOPTS;
			udp_ip_hdr_len += ipp->ipp_dstoptslen;
		} else if (udp->udp_sticky_ipp.ipp_fields & IPPF_DSTOPTS) {
			option_exists |= IPPF_DSTOPTS;
			is_sticky |= IPPF_DSTOPTS;
			udp_ip_hdr_len += udp->udp_sticky_ipp.ipp_dstoptslen;
		}
	}

	if (!(ignore & IPPF_IFINDEX)) {
		if (ipp->ipp_fields & IPPF_IFINDEX) {
			option_exists |= IPPF_IFINDEX;
		} else if (udp->udp_sticky_ipp.ipp_fields & IPPF_IFINDEX) {
			option_exists |= IPPF_IFINDEX;
			is_sticky |= IPPF_IFINDEX;
		}
	}

	if (!(ignore & IPPF_ADDR)) {
		if (ipp->ipp_fields & IPPF_ADDR) {
			option_exists |= IPPF_ADDR;
		} else if (udp->udp_sticky_ipp.ipp_fields & IPPF_ADDR) {
			option_exists |= IPPF_ADDR;
			is_sticky |= IPPF_ADDR;
		}
	}

	if (!(ignore & IPPF_DONTFRAG)) {
		if (ipp->ipp_fields & IPPF_DONTFRAG) {
			option_exists |= IPPF_DONTFRAG;
		} else if (udp->udp_sticky_ipp.ipp_fields & IPPF_DONTFRAG) {
			option_exists |= IPPF_DONTFRAG;
			is_sticky |= IPPF_DONTFRAG;
		}
	}

	if (!(ignore & IPPF_USE_MIN_MTU)) {
		if (ipp->ipp_fields & IPPF_USE_MIN_MTU) {
			option_exists |= IPPF_USE_MIN_MTU;
		} else if (udp->udp_sticky_ipp.ipp_fields & IPPF_USE_MIN_MTU) {
			option_exists |= IPPF_USE_MIN_MTU;
			is_sticky |= IPPF_USE_MIN_MTU;
		}
	}

	if (!(ignore & IPPF_HOPLIMIT) && (ipp->ipp_fields & IPPF_HOPLIMIT))
		option_exists |= IPPF_HOPLIMIT;
	/* IPV6_HOPLIMIT can never be sticky */
	ASSERT(!(udp->udp_sticky_ipp.ipp_fields & IPPF_HOPLIMIT));

	if (!(ignore & IPPF_UNICAST_HOPS) &&
	    (udp->udp_sticky_ipp.ipp_fields & IPPF_UNICAST_HOPS)) {
		option_exists |= IPPF_UNICAST_HOPS;
		is_sticky |= IPPF_UNICAST_HOPS;
	}

	if (!(ignore & IPPF_MULTICAST_HOPS) &&
	    (udp->udp_sticky_ipp.ipp_fields & IPPF_MULTICAST_HOPS)) {
		option_exists |= IPPF_MULTICAST_HOPS;
		is_sticky |= IPPF_MULTICAST_HOPS;
	}

	if (!(ignore & IPPF_TCLASS)) {
		if (ipp->ipp_fields & IPPF_TCLASS) {
			option_exists |= IPPF_TCLASS;
		} else if (udp->udp_sticky_ipp.ipp_fields & IPPF_TCLASS) {
			option_exists |= IPPF_TCLASS;
			is_sticky |= IPPF_TCLASS;
		}
	}

no_options:

	/*
	 * If any options carried in the ip6i_t were specified, we
	 * need to account for the ip6i_t in the data we'll be sending
	 * down.
	 */
	if (option_exists & IPPF_HAS_IP6I)
		udp_ip_hdr_len += sizeof (ip6i_t);

	/* check/fix buffer config, setup pointers into it */
	mp1 = mp->b_cont;
	ip6h = (ip6_t *)&mp1->b_rptr[-udp_ip_hdr_len];
	if ((mp1->b_datap->db_ref != 1) ||
	    ((unsigned char *)ip6h < mp1->b_datap->db_base) ||
	    !OK_32PTR(ip6h)) {
		/* Try to get everything in a single mblk next time */
		if (udp_ip_hdr_len > udp->udp_max_hdr_len) {
			udp->udp_max_hdr_len = udp_ip_hdr_len;
			(void) mi_set_sth_wroff(RD(q),
			    udp->udp_max_hdr_len + udp_wroff_extra);
		}
		mp1 = allocb(udp_ip_hdr_len + udp_wroff_extra, BPRI_LO);
		if (!mp1) {
			BUMP_MIB(&udp_mib, udpOutErrors);
			udp_ud_err(q, mp, ENOMEM);
			return;
		}
		mp1->b_cont = mp->b_cont;
		mp->b_cont = mp1;
		mp1->b_wptr = mp1->b_datap->db_lim;
		ip6h = (ip6_t *)(mp1->b_wptr - udp_ip_hdr_len);
	}
	mp1->b_rptr = (unsigned char *)ip6h;
	ip6i = (ip6i_t *)ip6h;

#define	ANCIL_OR_STICKY_PTR(f) ((is_sticky & f) ? &udp->udp_sticky_ipp : ipp)
	if (option_exists & IPPF_HAS_IP6I) {
		ip6h = (ip6_t *)&ip6i[1];
		ip6i->ip6i_flags = 0;
		ip6i->ip6i_vcf = IPV6_DEFAULT_VERS_AND_FLOW;

		/* sin6_scope_id takes precendence over IPPF_IFINDEX */
		if (option_exists & IPPF_SCOPE_ID) {
			ip6i->ip6i_flags |= IP6I_IFINDEX;
			ip6i->ip6i_ifindex = sin6->sin6_scope_id;
		} else if (option_exists & IPPF_IFINDEX) {
			tipp = ANCIL_OR_STICKY_PTR(IPPF_IFINDEX);
			ASSERT(tipp->ipp_ifindex != 0);
			ip6i->ip6i_flags |= IP6I_IFINDEX;
			ip6i->ip6i_ifindex = tipp->ipp_ifindex;
		}

		if (option_exists & IPPF_ADDR) {
			/*
			 * Enable per-packet source address verification if
			 * IPV6_PKTINFO specified the source address.
			 * ip6_src is set in the transport's _wput function.
			 */
			ip6i->ip6i_flags |= IP6I_VERIFY_SRC;
		}

		if (option_exists & IPPF_DONTFRAG) {
			ip6i->ip6i_flags |= IP6I_DONTFRAG;
		}

		if (option_exists & IPPF_USE_MIN_MTU) {
			ip6i->ip6i_flags = IP6I_API_USE_MIN_MTU(
			    ip6i->ip6i_flags, ipp->ipp_use_min_mtu);
		}

		if (option_exists & IPPF_NEXTHOP) {
			tipp = ANCIL_OR_STICKY_PTR(IPPF_NEXTHOP);
			ASSERT(!IN6_IS_ADDR_UNSPECIFIED(&tipp->ipp_nexthop));
			ip6i->ip6i_flags |= IP6I_NEXTHOP;
			ip6i->ip6i_nexthop = tipp->ipp_nexthop;
		}

		/*
		 * tell IP this is an ip6i_t private header
		 */
		ip6i->ip6i_nxt = IPPROTO_RAW;
	}

	/* Initialize IPv6 header */
	ip6h->ip6_vcf = IPV6_DEFAULT_VERS_AND_FLOW;
	bzero(&ip6h->ip6_src, sizeof (ip6h->ip6_src));

	/* Set the hoplimit of the outgoing packet. */
	if (option_exists & IPPF_HOPLIMIT) {
		/* IPV6_HOPLIMIT ancillary data overrides all other settings. */
		ip6h->ip6_hops = ipp->ipp_hoplimit;
		ip6i->ip6i_flags |= IP6I_HOPLIMIT;
	} else if (IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr)) {
		ip6h->ip6_hops = udp->udp_multicast_ttl;
		if (option_exists & IPPF_MULTICAST_HOPS)
			ip6i->ip6i_flags |= IP6I_HOPLIMIT;
	} else {
		ip6h->ip6_hops = udp->udp_ttl;
		if (option_exists & IPPF_UNICAST_HOPS)
			ip6i->ip6i_flags |= IP6I_HOPLIMIT;
	}

	if (option_exists & IPPF_ADDR) {
		tipp = ANCIL_OR_STICKY_PTR(IPPF_ADDR);
		ASSERT(!IN6_IS_ADDR_UNSPECIFIED(&tipp->ipp_addr));
		ip6h->ip6_src = tipp->ipp_addr;
	} else {
		/*
		 * The source address was not set using IPV6_PKTINFO.
		 * First look at the bound source.
		 * If unspecified fallback to __sin6_src_id.
		 */
		ip6h->ip6_src = udp->udp_v6src;
		if (sin6->__sin6_src_id != 0 &&
		    IN6_IS_ADDR_UNSPECIFIED(&ip6h->ip6_src)) {
			ip_srcid_find_id(sin6->__sin6_src_id,
			    &ip6h->ip6_src, udp->udp_zoneid);
		}
	}

	nxthdr_ptr = (uint8_t *)&ip6h->ip6_nxt;
	cp = (uint8_t *)&ip6h[1];

	/*
	 * Here's where we have to start stringing together
	 * any extension headers in the right order:
	 * Hop-by-hop, destination, routing, and final destination opts.
	 */
	if (option_exists & IPPF_HOPOPTS) {
		/* Hop-by-hop options */
		ip6_hbh_t *hbh = (ip6_hbh_t *)cp;
		tipp = ANCIL_OR_STICKY_PTR(IPPF_HOPOPTS);

		*nxthdr_ptr = IPPROTO_HOPOPTS;
		nxthdr_ptr = &hbh->ip6h_nxt;

		bcopy(tipp->ipp_hopopts, cp, tipp->ipp_hopoptslen);
		cp += tipp->ipp_hopoptslen;
	}
	/*
	 * En-route destination options
	 * Only do them if there's a routing header as well
	 */
	if (option_exists & IPPF_RTDSTOPTS) {
		ip6_dest_t *dst = (ip6_dest_t *)cp;
		tipp = ANCIL_OR_STICKY_PTR(IPPF_RTDSTOPTS);

		*nxthdr_ptr = IPPROTO_DSTOPTS;
		nxthdr_ptr = &dst->ip6d_nxt;

		bcopy(tipp->ipp_rtdstopts, cp, tipp->ipp_rtdstoptslen);
		cp += tipp->ipp_rtdstoptslen;
	}
	/*
	 * Routing header next
	 */
	if (option_exists & IPPF_RTHDR) {
		ip6_rthdr_t *rt = (ip6_rthdr_t *)cp;
		tipp = ANCIL_OR_STICKY_PTR(IPPF_RTHDR);

		*nxthdr_ptr = IPPROTO_ROUTING;
		nxthdr_ptr = &rt->ip6r_nxt;

		bcopy(tipp->ipp_rthdr, cp, tipp->ipp_rthdrlen);
		cp += tipp->ipp_rthdrlen;
	}
	/*
	 * Do ultimate destination options
	 */
	if (option_exists & IPPF_DSTOPTS) {
		ip6_dest_t *dest = (ip6_dest_t *)cp;
		tipp = ANCIL_OR_STICKY_PTR(IPPF_DSTOPTS);

		*nxthdr_ptr = IPPROTO_DSTOPTS;
		nxthdr_ptr = &dest->ip6d_nxt;

		bcopy(tipp->ipp_dstopts, cp, tipp->ipp_dstoptslen);
		cp += tipp->ipp_dstoptslen;
	}
	/*
	 * Now set the last header pointer to the proto passed in
	 */
	ASSERT((int)(cp - (uint8_t *)ip6i) == (udp_ip_hdr_len - UDPH_SIZE));
	*nxthdr_ptr = IPPROTO_UDP;

	/* Update UDP header */
	udph = (udpha_t *)((uchar_t *)ip6i + udp_ip_hdr_len - UDPH_SIZE);
	udph->uha_dst_port = sin6->sin6_port;
	udph->uha_src_port = udp->udp_port;

	/*
	 * Copy in the destination address
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr))
		ip6h->ip6_dst = ipv6_loopback;
	else
		ip6h->ip6_dst = sin6->sin6_addr;

	ip6h->ip6_vcf =
	    (IPV6_DEFAULT_VERS_AND_FLOW & IPV6_VERS_AND_FLOW_MASK) |
	    (sin6->sin6_flowinfo & ~IPV6_VERS_AND_FLOW_MASK);

	if (option_exists & IPPF_TCLASS) {
		tipp = ANCIL_OR_STICKY_PTR(IPPF_TCLASS);
		ip6h->ip6_vcf = IPV6_TCLASS_FLOW(ip6h->ip6_vcf,
		    tipp->ipp_tclass);
	}

	if (option_exists & IPPF_RTHDR) {
		ip6_rthdr_t	*rth;

		/*
		 * Perform any processing needed for source routing.
		 * We know that all extension headers will be in the same mblk
		 * as the IPv6 header.
		 */
		rth = ip_find_rthdr_v6(ip6h, mp1->b_wptr);
		if (rth != NULL && rth->ip6r_segleft != 0) {
			if (rth->ip6r_type != IPV6_RTHDR_TYPE_0) {
				/*
				 * Drop packet - only support Type 0 routing.
				 * Notify the application as well.
				 */
				udp_ud_err(q, mp, EPROTO);
				BUMP_MIB(&udp_mib, udpOutErrors);
				return;
			}

			/*
			 * rth->ip6r_len is twice the number of
			 * addresses in the header. Thus it must be even.
			 */
			if (rth->ip6r_len & 0x1) {
				udp_ud_err(q, mp, EPROTO);
				BUMP_MIB(&udp_mib, udpOutErrors);
				return;
			}
			/*
			 * Shuffle the routing header and ip6_dst
			 * addresses, and get the checksum difference
			 * between the first hop (in ip6_dst) and
			 * the destination (in the last routing hdr entry).
			 */
			csum = ip_massage_options_v6(ip6h, rth);
			/*
			 * Verify that the first hop isn't a mapped address.
			 * Routers along the path need to do this verification
			 * for subsequent hops.
			 */
			if (IN6_IS_ADDR_V4MAPPED(&ip6h->ip6_dst)) {
				udp_ud_err(q, mp, EADDRNOTAVAIL);
				BUMP_MIB(&udp_mib, udpOutErrors);
				return;
			}

			cp += (rth->ip6r_len + 1)*8;
		}
	}

	/* count up length of UDP packet */
	ip_len = (mp1->b_wptr - (unsigned char *)ip6h) - IPV6_HDR_LEN;
	{
		mblk_t *mp2;

		if ((mp2 = mp1->b_cont) != NULL) {
			do {
				ip_len += mp2->b_wptr - mp2->b_rptr;
			} while ((mp2 = mp2->b_cont) != NULL);
		}
	}

	/*
	 * If the size of the packet is greater than the maximum allowed by
	 * ip, return an error. Passing this down could cause panics because
	 * the size will have wrapped and be inconsistent with the msg size.
	 */
	if (ip_len > IP_MAXPACKET) {
		BUMP_MIB(&udp_mib, udpOutErrors);
		udp_ud_err(q, mp, EMSGSIZE);
		return;
	}

	/* Store the UDP length. Subtract length of extension hdrs */
	udph->uha_length = htons(ip_len + IPV6_HDR_LEN -
	    (int)((uchar_t *)udph - (uchar_t *)ip6h));

	/*
	 * We make it easy for IP to include our pseudo header
	 * by putting our length in uh_checksum, modified (if
	 * we have a routing header) by the checksum difference
	 * between the ultimate destination and first hop addresses.
	 * Note: UDP over IPv6 must always checksum the packet.
	 */
	csum += udph->uha_length;
	csum = (csum & 0xFFFF) + (csum >> 16);
	udph->uha_checksum = (uint16_t)csum;

#ifdef _LITTLE_ENDIAN
	ip_len = htons(ip_len);
#endif
	ip6h->ip6_plen = ip_len;

	freeb(mp);

	/* We're done. Pass the packet to IP */
	BUMP_MIB(&udp_mib, udpOutDatagrams);
	putnext(q, mp1);
}

static void
udp_wput_other(queue_t *q, mblk_t *mp)
{
	uchar_t	*rptr = mp->b_rptr;
	struct datab *db;
	struct iocblk *iocp;
	udp_t	*udp;
	cred_t	*cr;

	TRACE_1(TR_FAC_UDP, TR_UDP_WPUT_OTHER_START,
		"udp_wput_other_start: q %p", q);

	udp = (udp_t *)q->q_ptr;
	db = mp->b_datap;

	cr = DB_CREDDEF(mp, udp->udp_credp);

	switch (db->db_type) {
	case M_DATA:
		/* Not connected */
		BUMP_MIB(&udp_mib, udpOutErrors);
		freemsg(mp);
		TRACE_2(TR_FAC_UDP, TR_UDP_WPUT_OTHER_END,
			"udp_wput_other_end: q %p (%S)",
			q, "not-connected");
		return;
	case M_PROTO:
	case M_PCPROTO:
		if (mp->b_wptr - rptr < sizeof (t_scalar_t)) {
			freemsg(mp);
			TRACE_2(TR_FAC_UDP, TR_UDP_WPUT_OTHER_END,
				"udp_wput_other_end: q %p (%S)",
				q, "protoshort");
			return;
		}
		switch (((union T_primitives *)rptr)->type) {
		case T_ADDR_REQ:
			udp_addr_req(q, mp);
			TRACE_2(TR_FAC_UDP, TR_UDP_WPUT_OTHER_END,
				"udp_wput_other_end: q %p (%S)", q, "addrreq");
			return;
		case O_T_BIND_REQ:
		case T_BIND_REQ:
			udp_bind(q, mp);
			TRACE_2(TR_FAC_UDP, TR_UDP_WPUT_OTHER_END,
				"udp_wput_other_end: q %p (%S)", q, "bindreq");
			return;
		case T_CONN_REQ:
			udp_connect(q, mp);
			TRACE_2(TR_FAC_UDP, TR_UDP_WPUT_OTHER_END,
				"udp_wput_other_end: q %p (%S)", q, "connreq");
			return;
		case T_CAPABILITY_REQ:
			udp_capability_req(q, mp);
			TRACE_2(TR_FAC_UDP, TR_UDP_WPUT_OTHER_END,
				"udp_wput_other_end: q %p (%S)", q, "capabreq");
			return;
		case T_INFO_REQ:
			udp_info_req(q, mp);
			TRACE_2(TR_FAC_UDP, TR_UDP_WPUT_OTHER_END,
				"udp_wput_other_end: q %p (%S)", q, "inforeq");
			return;
		case T_UNITDATA_REQ:
			/*
			 * If a T_UNITDATA_REQ gets here, the address must
			 * be bad.  Valid T_UNITDATA_REQs are handled
			 * in udp_wput.
			 */
			udp_ud_err(q, mp, EADDRNOTAVAIL);
			TRACE_2(TR_FAC_UDP, TR_UDP_WPUT_OTHER_END,
				"udp_wput_other_end: q %p (%S)",
				q, "unitdatareq");
			return;
		case T_UNBIND_REQ:
			udp_unbind(q, mp);
			TRACE_2(TR_FAC_UDP, TR_UDP_WPUT_OTHER_END,
			    "udp_wput_other_end: q %p (%S)", q, "unbindreq");
			return;
		case T_SVR4_OPTMGMT_REQ:
			if (!snmpcom_req(q, mp, udp_snmp_set, udp_snmp_get, cr))
				(void) svr4_optcom_req(q, mp, cr, &udp_opt_obj);
			TRACE_2(TR_FAC_UDP, TR_UDP_WPUT_OTHER_END,
			    "udp_wput_other_end: q %p (%S)",
			    q, "optmgmtreq");
			return;

		case T_OPTMGMT_REQ:
			(void) tpi_optcom_req(q, mp, cr, &udp_opt_obj);
			TRACE_2(TR_FAC_UDP, TR_UDP_WPUT_OTHER_END,
				"udp_wput_other_end: q %p (%S)",
				q, "optmgmtreq");
			return;

		case T_DISCON_REQ:
			udp_disconnect(q, mp);
			TRACE_2(TR_FAC_UDP, TR_UDP_WPUT_OTHER_END,
				"udp_wput_other_end: q %p (%S)",
				q, "disconreq");
			return;

		/* The following TPI message is not supported by udp. */
		case O_T_CONN_RES:
		case T_CONN_RES:
			udp_err_ack(q, mp, TNOTSUPPORT, 0);
			TRACE_2(TR_FAC_UDP, TR_UDP_WPUT_OTHER_END,
				"udp_wput_other_end: q %p (%S)",
				q, "connres/disconreq");
			return;

		/* The following 3 TPI messages are illegal for udp. */
		case T_DATA_REQ:
		case T_EXDATA_REQ:
		case T_ORDREL_REQ:
			udp_err_ack(q, mp, TNOTSUPPORT, 0);
			TRACE_2(TR_FAC_UDP, TR_UDP_WPUT_OTHER_END,
				"udp_wput_other_end: q %p (%S)",
				q, "data/exdata/ordrel");
			return;
		default:
			break;
		}
		break;
	case M_FLUSH:
		if (*rptr & FLUSHW)
			flushq(q, FLUSHDATA);
		break;
	case M_IOCTL:
		iocp = (struct iocblk *)mp->b_rptr;
		switch (iocp->ioc_cmd) {
		case TI_GETPEERNAME:
			if (udp->udp_state != TS_DATA_XFER) {
				/*
				 * If a default destination address has not
				 * been associated with the stream, then we
				 * don't know the peer's name.
				 */
				iocp->ioc_error = ENOTCONN;
err_ret:;
				iocp->ioc_count = 0;
				mp->b_datap->db_type = M_IOCACK;
				qreply(q, mp);
				TRACE_2(TR_FAC_UDP, TR_UDP_WPUT_OTHER_END,
					"udp_wput_other_end: q %p (%S)",
					q, "getpeername");
				return;
			}
			/* FALLTHRU */
		case TI_GETMYNAME: {
			/*
			 * For TI_GETPEERNAME and TI_GETMYNAME, we first
			 * need to copyin the user's strbuf structure.
			 * Processing will continue in the M_IOCDATA case
			 * below.
			 */
			mi_copyin(q, mp, NULL,
			    SIZEOF_STRUCT(strbuf, iocp->ioc_flag));
			TRACE_2(TR_FAC_UDP, TR_UDP_WPUT_OTHER_END,
				"udp_wput_other_end: q %p (%S)",
				q, "getmyname");
			return;
			}
		case ND_SET:
			/* nd_getset performs the necessary checking */
		case ND_GET:
			if (nd_getset(q, udp_g_nd, mp)) {
				qreply(q, mp);
				TRACE_2(TR_FAC_UDP, TR_UDP_WPUT_OTHER_END,
					"udp_wput_other_end: q %p (%S)",
					q, "get");
				return;
			}
			break;
		default:
			break;
		}
		break;
	case M_IOCDATA:
		udp_wput_iocdata(q, mp);
		TRACE_2(TR_FAC_UDP, TR_UDP_WPUT_OTHER_END,
			"udp_wput_other_end: q %p (%S)", q, "iocdata");
		return;
	default:
		/* Unrecognized messages are passed through without change. */
		break;
	}
	TRACE_2(TR_FAC_UDP, TR_UDP_WPUT_OTHER_END,
		"udp_wput_other_end: q %p (%S)", q, "end");
	putnext(q, mp);
}

/*
 * udp_wput_iocdata is called by udp_wput_other to handle all M_IOCDATA
 * messages.
 */
static void
udp_wput_iocdata(queue_t *q, mblk_t *mp)
{
	mblk_t	*mp1;
	STRUCT_HANDLE(strbuf, sb);
	uint16_t port;
	udp_t	*udp;
	in6_addr_t	v6addr;
	ipaddr_t	v4addr;
	uint32_t	flowinfo = 0;
	int		addrlen;

	/* Make sure it is one of ours. */
	switch (((struct iocblk *)mp->b_rptr)->ioc_cmd) {
	case TI_GETMYNAME:
	case TI_GETPEERNAME:
		break;
	default:
		putnext(q, mp);
		return;
	}
	switch (mi_copy_state(q, mp, &mp1)) {
	case -1:
		return;
	case MI_COPY_CASE(MI_COPY_IN, 1):
		break;
	case MI_COPY_CASE(MI_COPY_OUT, 1):
		/*
		 * The address has been copied out, so now
		 * copyout the strbuf.
		 */
		mi_copyout(q, mp);
		return;
	case MI_COPY_CASE(MI_COPY_OUT, 2):
		/*
		 * The address and strbuf have been copied out.
		 * We're done, so just acknowledge the original
		 * M_IOCTL.
		 */
		mi_copy_done(q, mp, 0);
		return;
	default:
		/*
		 * Something strange has happened, so acknowledge
		 * the original M_IOCTL with an EPROTO error.
		 */
		mi_copy_done(q, mp, EPROTO);
		return;
	}

	/*
	 * Now we have the strbuf structure for TI_GETMYNAME
	 * and TI_GETPEERNAME.  Next we copyout the requested
	 * address and then we'll copyout the strbuf.
	 */
	STRUCT_SET_HANDLE(sb, ((struct iocblk *)mp->b_rptr)->ioc_flag,
	    (void *)mp1->b_rptr);
	udp = (udp_t *)q->q_ptr;
	if (udp->udp_family == AF_INET)
		addrlen = sizeof (sin_t);
	else
		addrlen = sizeof (sin6_t);

	if (STRUCT_FGET(sb, maxlen) < addrlen) {
		mi_copy_done(q, mp, EINVAL);
		return;
	}
	switch (((struct iocblk *)mp->b_rptr)->ioc_cmd) {
	case TI_GETMYNAME:
		if (udp->udp_family == AF_INET) {
			ASSERT(udp->udp_ipversion == IPV4_VERSION);
			if (!IN6_IS_ADDR_V4MAPPED_ANY(&udp->udp_v6src) &&
			    !IN6_IS_ADDR_UNSPECIFIED(&udp->udp_v6src)) {
				v4addr = V4_PART_OF_V6(udp->udp_v6src);
			} else {
				/*
				 * INADDR_ANY
				 * udp_v6src is not set, we might be bound to
				 * broadcast/multicast. Use udp_bound_v6src as
				 * local address instead (that could
				 * also still be INADDR_ANY)
				 */
				v4addr = V4_PART_OF_V6(udp->udp_bound_v6src);
			}
		} else {
			/* udp->udp_family == AF_INET6 */
			if (!IN6_IS_ADDR_UNSPECIFIED(&udp->udp_v6src)) {
				v6addr = udp->udp_v6src;
			} else {
				/*
				 * UNSPECIFIED
				 * udp_v6src is not set, we might be bound to
				 * broadcast/multicast. Use udp_bound_v6src as
				 * local address instead (that could
				 * also still be UNSPECIFIED)
				 */
				v6addr = udp->udp_bound_v6src;
			}
		}
		port = udp->udp_port;
		break;
	case TI_GETPEERNAME:
		if (udp->udp_family == AF_INET) {
			ASSERT(udp->udp_ipversion == IPV4_VERSION);
			v4addr = V4_PART_OF_V6(udp->udp_v6dst);
		} else {
			/* udp->udp_family == AF_INET6) */
			v6addr = udp->udp_v6dst;
			flowinfo = udp->udp_flowinfo;
		}
		port = udp->udp_dstport;
		break;
	default:
		mi_copy_done(q, mp, EPROTO);
		return;
	}
	mp1 = mi_copyout_alloc(q, mp, STRUCT_FGETP(sb, buf), addrlen, B_TRUE);
	if (!mp1)
		return;

	if (udp->udp_family == AF_INET) {
		sin_t *sin;

		STRUCT_FSET(sb, len, (int)sizeof (sin_t));
		sin = (sin_t *)mp1->b_rptr;
		mp1->b_wptr = (uchar_t *)&sin[1];
		*sin = sin_null;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = v4addr;
		sin->sin_port = port;
	} else {
		/* udp->udp_family == AF_INET6 */
		sin6_t *sin6;

		STRUCT_FSET(sb, len, (int)sizeof (sin6_t));
		sin6 = (sin6_t *)mp1->b_rptr;
		mp1->b_wptr = (uchar_t *)&sin6[1];
		*sin6 = sin6_null;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_flowinfo = flowinfo;
		sin6->sin6_addr = v6addr;
		sin6->sin6_port = port;
	}
	/* Copy out the address */
	mi_copyout(q, mp);
}


static int
udp_unitdata_opt_process(queue_t *q, mblk_t *mp, int *errorp,
    void *thisdg_attrs)
{
	udp_t	*udp;
	struct T_unitdata_req *udreqp;
	int is_absreq_failure;
	cred_t *cr;

	ASSERT(((union T_primitives *)mp->b_rptr)->type);

	udp = (udp_t *)q->q_ptr;

	cr = DB_CREDDEF(mp, udp->udp_credp);

	udreqp = (struct T_unitdata_req *)mp->b_rptr;
	*errorp = 0;

	*errorp = tpi_optcom_buf(q, mp, &udreqp->OPT_length,
	    udreqp->OPT_offset, cr, &udp_opt_obj,
	    thisdg_attrs, &is_absreq_failure);

	if (*errorp != 0) {
		/*
		 * Note: No special action needed in this
		 * module for "is_absreq_failure"
		 */
		return (-1);		/* failure */
	}
	ASSERT(is_absreq_failure == 0);
	return (0);	/* success */
}

void
udp_ddi_init(void)
{
	int i;

	UDP6_MAJ = ddi_name_to_major(UDP6);
	mutex_init(&udp_g_lock, NULL, MUTEX_DEFAULT, NULL);

	udp_max_optsize = optcom_max_optsize(udp_opt_obj.odb_opt_des_arr,
	    udp_opt_obj.odb_opt_arr_cnt);

	if (udp_bind_fanout_size & (udp_bind_fanout_size - 1)) {
		/* Not a power of two. Round up to nearest power of two */
		for (i = 0; i < 31; i++) {
			if (udp_bind_fanout_size < (1 << i))
				break;
		}
		udp_bind_fanout_size = 1 << i;
	}
	udp_bind_fanout = kmem_zalloc(udp_bind_fanout_size *
	    sizeof (udp_fanout_t), KM_SLEEP);
	for (i = 0; i < udp_bind_fanout_size; i++) {
		mutex_init(&udp_bind_fanout[i].uf_lock, NULL, MUTEX_DEFAULT,
		    NULL);
	}
	(void) udp_param_register(udp_param_arr, A_CNT(udp_param_arr));
	udp_kstat_init();
}

void
udp_ddi_destroy(void)
{
	int i;

	nd_free(&udp_g_nd);

	mutex_destroy(&udp_g_lock);
	for (i = 0; i < udp_bind_fanout_size; i++) {
		mutex_destroy(&udp_bind_fanout[i].uf_lock);
	}
	kmem_free(udp_bind_fanout, udp_bind_fanout_size *
	    sizeof (udp_fanout_t));
	udp_kstat_fini();

}

static void
udp_kstat_init(void)
{
	udp_named_kstat_t template = {
		{ "inDatagrams",	KSTAT_DATA_UINT32, 0 },
		{ "inErrors",		KSTAT_DATA_UINT32, 0 },
		{ "outDatagrams",	KSTAT_DATA_UINT32, 0 },
		{ "entrySize",		KSTAT_DATA_INT32, 0 },
		{ "entry6Size",		KSTAT_DATA_INT32, 0 },
		{ "outErrors",		KSTAT_DATA_UINT32, 0 },
	};

	udp_mibkp = kstat_create("udp", 0, "udp", "mib2", KSTAT_TYPE_NAMED,
					NUM_OF_FIELDS(udp_named_kstat_t),
					0);
	if (udp_mibkp == NULL)
		return;

	template.entrySize.value.ui32 = sizeof (mib2_udpEntry_t);
	template.entry6Size.value.ui32 = sizeof (mib2_udp6Entry_t);

	bcopy(&template, udp_mibkp->ks_data, sizeof (template));

	udp_mibkp->ks_update = udp_kstat_update;

	kstat_install(udp_mibkp);
}

static void
udp_kstat_fini(void)
{
	if (udp_mibkp) {
		kstat_delete(udp_mibkp);
		udp_mibkp = NULL;
	}
}

static int
udp_kstat_update(kstat_t *kp, int rw)
{
	udp_named_kstat_t *udpkp;

	if ((kp == NULL) || (kp->ks_data == NULL))
		return (EIO);

	if (rw == KSTAT_WRITE)
		return (EACCES);

	udpkp = (udp_named_kstat_t *)kp->ks_data;

	udpkp->inDatagrams.value.ui32 =	udp_mib.udpInDatagrams;
	udpkp->inErrors.value.ui32 =	udp_mib.udpInErrors;
	udpkp->outDatagrams.value.ui32 = udp_mib.udpOutDatagrams;
	udpkp->outErrors.value.ui32 =	udp_mib.udpOutErrors;

	return (0);
}

/*
 * Little helper for IPsec's NAT-T processing.
 */
boolean_t
udp_compute_checksum(void)
{
	return (udp_do_checksum);
}
