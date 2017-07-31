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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/priv.h>
#include <sys/cpuvar.h>
#include <sys/socket.h>
#include <sys/strsubr.h>
#include <sys/sysmacros.h>
#include <sys/sdt.h>
#include <netinet/tcp.h>
#include <inet/tcp.h>
#include <sys/socketvar.h>
#include <sys/pathname.h>
#include <sys/fs/snode.h>
#include <sys/fs/dv_node.h>
#include <sys/vnode.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/sockio.h>
#include <sys/ksocket.h>
#include <sys/filio.h>		/* FIONBIO */
#include <sys/iscsi_protocol.h>
#include <sys/idm/idm.h>
#include <sys/idm/idm_so.h>
#include <sys/idm/idm_text.h>

#define	IN_PROGRESS_DELAY	1

/*
 * in6addr_any is currently all zeroes, but use the macro in case this
 * ever changes.
 */
static const struct in6_addr in6addr_any = IN6ADDR_ANY_INIT;

static void idm_sorx_cache_pdu_cb(idm_pdu_t *pdu, idm_status_t status);
static void idm_sorx_addl_pdu_cb(idm_pdu_t *pdu, idm_status_t status);
static void idm_sotx_cache_pdu_cb(idm_pdu_t *pdu, idm_status_t status);

static idm_status_t idm_so_conn_create_common(idm_conn_t *ic, ksocket_t new_so);
static void idm_so_conn_destroy_common(idm_conn_t *ic);
static void idm_so_conn_connect_common(idm_conn_t *ic);

static void idm_set_ini_preconnect_options(idm_so_conn_t *sc,
    boolean_t boot_conn);
static void idm_set_postconnect_options(ksocket_t so);
static idm_status_t idm_i_so_tx(idm_pdu_t *pdu);

static idm_status_t idm_sorecvdata(idm_conn_t *ic, idm_pdu_t *pdu);
static void idm_so_send_rtt_data(idm_conn_t *ic, idm_task_t *idt,
    idm_buf_t *idb, uint32_t offset, uint32_t length);
static void idm_so_send_rtt_data_done(idm_task_t *idt, idm_buf_t *idb);
static idm_status_t idm_so_send_buf_region(idm_task_t *idt,
    idm_buf_t *idb, uint32_t buf_region_offset, uint32_t buf_region_length);

static uint32_t idm_fill_iov(idm_pdu_t *pdu, idm_buf_t *idb,
    uint32_t ro, uint32_t dlength);

static idm_status_t idm_so_handle_digest(idm_conn_t *it,
    nvpair_t *digest_choice, const idm_kv_xlate_t *ikvx);

static void idm_so_socket_set_nonblock(struct sonode *node);
static void idm_so_socket_set_block(struct sonode *node);

/*
 * Transport ops prototypes
 */
static void idm_so_tx(idm_conn_t *ic, idm_pdu_t *pdu);
static idm_status_t idm_so_buf_tx_to_ini(idm_task_t *idt, idm_buf_t *idb);
static idm_status_t idm_so_buf_rx_from_ini(idm_task_t *idt, idm_buf_t *idb);
static void idm_so_rx_datain(idm_conn_t *ic, idm_pdu_t *pdu);
static void idm_so_rx_rtt(idm_conn_t *ic, idm_pdu_t *pdu);
static void idm_so_rx_dataout(idm_conn_t *ic, idm_pdu_t *pdu);
static idm_status_t idm_so_free_task_rsrc(idm_task_t *idt);
static kv_status_t idm_so_negotiate_key_values(idm_conn_t *it,
    nvlist_t *request_nvl, nvlist_t *response_nvl, nvlist_t *negotiated_nvl);
static void idm_so_notice_key_values(idm_conn_t *it,
    nvlist_t *negotiated_nvl);
static kv_status_t idm_so_declare_key_values(idm_conn_t *it,
    nvlist_t *config_nvl, nvlist_t *outgoing_nvl);
static boolean_t idm_so_conn_is_capable(idm_conn_req_t *ic,
    idm_transport_caps_t *caps);
static idm_status_t idm_so_buf_alloc(idm_buf_t *idb, uint64_t buflen);
static void idm_so_buf_free(idm_buf_t *idb);
static idm_status_t idm_so_buf_setup(idm_buf_t *idb);
static void idm_so_buf_teardown(idm_buf_t *idb);
static idm_status_t idm_so_tgt_svc_create(idm_svc_req_t *sr, idm_svc_t *is);
static void idm_so_tgt_svc_destroy(idm_svc_t *is);
static idm_status_t idm_so_tgt_svc_online(idm_svc_t *is);
static void idm_so_tgt_svc_offline(idm_svc_t *is);
static void idm_so_tgt_conn_destroy(idm_conn_t *ic);
static idm_status_t idm_so_tgt_conn_connect(idm_conn_t *ic);
static void idm_so_conn_disconnect(idm_conn_t *ic);
static idm_status_t idm_so_ini_conn_create(idm_conn_req_t *cr, idm_conn_t *ic);
static void idm_so_ini_conn_destroy(idm_conn_t *ic);
static idm_status_t idm_so_ini_conn_connect(idm_conn_t *ic);

/*
 * IDM Native Sockets transport operations
 */
static
idm_transport_ops_t idm_so_transport_ops = {
	idm_so_tx,			/* it_tx_pdu */
	idm_so_buf_tx_to_ini,		/* it_buf_tx_to_ini */
	idm_so_buf_rx_from_ini,		/* it_buf_rx_from_ini */
	idm_so_rx_datain,		/* it_rx_datain */
	idm_so_rx_rtt,			/* it_rx_rtt */
	idm_so_rx_dataout,		/* it_rx_dataout */
	NULL,				/* it_alloc_conn_rsrc */
	NULL,				/* it_free_conn_rsrc */
	NULL,				/* it_tgt_enable_datamover */
	NULL,				/* it_ini_enable_datamover */
	NULL,				/* it_conn_terminate */
	idm_so_free_task_rsrc,		/* it_free_task_rsrc */
	idm_so_negotiate_key_values,	/* it_negotiate_key_values */
	idm_so_notice_key_values,	/* it_notice_key_values */
	idm_so_conn_is_capable,		/* it_conn_is_capable */
	idm_so_buf_alloc,		/* it_buf_alloc */
	idm_so_buf_free,		/* it_buf_free */
	idm_so_buf_setup,		/* it_buf_setup */
	idm_so_buf_teardown,		/* it_buf_teardown */
	idm_so_tgt_svc_create,		/* it_tgt_svc_create */
	idm_so_tgt_svc_destroy,		/* it_tgt_svc_destroy */
	idm_so_tgt_svc_online,		/* it_tgt_svc_online */
	idm_so_tgt_svc_offline,		/* it_tgt_svc_offline */
	idm_so_tgt_conn_destroy,	/* it_tgt_conn_destroy */
	idm_so_tgt_conn_connect,	/* it_tgt_conn_connect */
	idm_so_conn_disconnect,		/* it_tgt_conn_disconnect */
	idm_so_ini_conn_create,		/* it_ini_conn_create */
	idm_so_ini_conn_destroy,	/* it_ini_conn_destroy */
	idm_so_ini_conn_connect,	/* it_ini_conn_connect */
	idm_so_conn_disconnect,		/* it_ini_conn_disconnect */
	idm_so_declare_key_values	/* it_declare_key_values */
};

kmutex_t	idm_so_timed_socket_mutex;

int32_t idm_so_sndbuf = IDM_SNDBUF_SIZE;
int32_t idm_so_rcvbuf = IDM_RCVBUF_SIZE;

/*
 * idm_so_init()
 * Sockets transport initialization
 */
void
idm_so_init(idm_transport_t *it)
{
	/* Cache for IDM Data and R2T Transmit PDU's */
	idm.idm_sotx_pdu_cache = kmem_cache_create("idm_tx_pdu_cache",
	    sizeof (idm_pdu_t) + sizeof (iscsi_hdr_t), 8,
	    &idm_sotx_pdu_constructor, NULL, NULL, NULL, NULL, KM_SLEEP);

	/* Cache for IDM Receive PDU's */
	idm.idm_sorx_pdu_cache = kmem_cache_create("idm_rx_pdu_cache",
	    sizeof (idm_pdu_t) + IDM_SORX_CACHE_HDRLEN, 8,
	    &idm_sorx_pdu_constructor, NULL, NULL, NULL, NULL, KM_SLEEP);

	/* 128k buffer cache */
	idm.idm_so_128k_buf_cache = kmem_cache_create("idm_128k_buf_cache",
	    IDM_SO_BUF_CACHE_UB, 8, NULL, NULL, NULL, NULL, NULL, KM_SLEEP);

	/* Set the sockets transport ops */
	it->it_ops = &idm_so_transport_ops;

	mutex_init(&idm_so_timed_socket_mutex, NULL, MUTEX_DEFAULT, NULL);

}

/*
 * idm_so_fini()
 * Sockets transport teardown
 */
void
idm_so_fini(void)
{
	kmem_cache_destroy(idm.idm_so_128k_buf_cache);
	kmem_cache_destroy(idm.idm_sotx_pdu_cache);
	kmem_cache_destroy(idm.idm_sorx_pdu_cache);
	mutex_destroy(&idm_so_timed_socket_mutex);
}

ksocket_t
idm_socreate(int domain, int type, int protocol)
{
	ksocket_t ks;

	if (!ksocket_socket(&ks, domain, type, protocol, KSOCKET_NOSLEEP,
	    CRED())) {
		return (ks);
	} else {
		return (NULL);
	}
}

/*
 * idm_soshutdown will disconnect the socket and prevent subsequent PDU
 * reception and transmission.  The sonode still exists but its state
 * gets modified to indicate it is no longer connected.  Calls to
 * idm_sorecv/idm_iov_sorecv will return so idm_soshutdown can be used
 * regain control of a thread stuck in idm_sorecv.
 */
void
idm_soshutdown(ksocket_t so)
{
	(void) ksocket_shutdown(so, SHUT_RDWR, CRED());
}

/*
 * idm_sodestroy releases all resources associated with a socket previously
 * created with idm_socreate.  The socket must be shutdown using
 * idm_soshutdown before the socket is destroyed with idm_sodestroy,
 * otherwise undefined behavior will result.
 */
void
idm_sodestroy(ksocket_t ks)
{
	(void) ksocket_close(ks, CRED());
}

/*
 * Function to compare two addresses in sockaddr_storage format
 */

int
idm_ss_compare(const struct sockaddr_storage *cmp_ss1,
    const struct sockaddr_storage *cmp_ss2,
    boolean_t v4_mapped_as_v4,
    boolean_t compare_ports)
{
	struct sockaddr_storage			mapped_v4_ss1, mapped_v4_ss2;
	const struct sockaddr_storage		*ss1, *ss2;
	struct in_addr				*in1, *in2;
	struct in6_addr				*in61, *in62;
	int i;

	/*
	 * Normalize V4-mapped IPv6 addresses into V4 format if
	 * v4_mapped_as_v4 is B_TRUE.
	 */
	ss1 = cmp_ss1;
	ss2 = cmp_ss2;
	if (v4_mapped_as_v4 && (ss1->ss_family == AF_INET6)) {
		in61 = &((struct sockaddr_in6 *)ss1)->sin6_addr;
		if (IN6_IS_ADDR_V4MAPPED(in61)) {
			bzero(&mapped_v4_ss1, sizeof (mapped_v4_ss1));
			mapped_v4_ss1.ss_family = AF_INET;
			((struct sockaddr_in *)&mapped_v4_ss1)->sin_port =
			    ((struct sockaddr_in *)ss1)->sin_port;
			IN6_V4MAPPED_TO_INADDR(in61,
			    &((struct sockaddr_in *)&mapped_v4_ss1)->sin_addr);
			ss1 = &mapped_v4_ss1;
		}
	}
	ss2 = cmp_ss2;
	if (v4_mapped_as_v4 && (ss2->ss_family == AF_INET6)) {
		in62 = &((struct sockaddr_in6 *)ss2)->sin6_addr;
		if (IN6_IS_ADDR_V4MAPPED(in62)) {
			bzero(&mapped_v4_ss2, sizeof (mapped_v4_ss2));
			mapped_v4_ss2.ss_family = AF_INET;
			((struct sockaddr_in *)&mapped_v4_ss2)->sin_port =
			    ((struct sockaddr_in *)ss2)->sin_port;
			IN6_V4MAPPED_TO_INADDR(in62,
			    &((struct sockaddr_in *)&mapped_v4_ss2)->sin_addr);
			ss2 = &mapped_v4_ss2;
		}
	}

	/*
	 * Compare ports, then address family, then ip address
	 */
	if (compare_ports &&
	    (((struct sockaddr_in *)ss1)->sin_port !=
	    ((struct sockaddr_in *)ss2)->sin_port)) {
		if (((struct sockaddr_in *)ss1)->sin_port >
		    ((struct sockaddr_in *)ss2)->sin_port)
			return (1);
		else
			return (-1);
	}

	/*
	 * ports are the same
	 */
	if (ss1->ss_family != ss2->ss_family) {
		if (ss1->ss_family == AF_INET)
			return (1);
		else
			return (-1);
	}

	/*
	 * address families are the same
	 */
	if (ss1->ss_family == AF_INET) {
		in1 = &((struct sockaddr_in *)ss1)->sin_addr;
		in2 = &((struct sockaddr_in *)ss2)->sin_addr;

		if (in1->s_addr > in2->s_addr)
			return (1);
		else if (in1->s_addr < in2->s_addr)
			return (-1);
		else
			return (0);
	} else if (ss1->ss_family == AF_INET6) {
		in61 = &((struct sockaddr_in6 *)ss1)->sin6_addr;
		in62 = &((struct sockaddr_in6 *)ss2)->sin6_addr;

		for (i = 0; i < 4; i++) {
			if (in61->s6_addr32[i] > in62->s6_addr32[i])
				return (1);
			else if (in61->s6_addr32[i] < in62->s6_addr32[i])
				return (-1);
		}
		return (0);
	}

	return (1);
}

/*
 * IP address filter functions to flag addresses that should not
 * go out to initiators through discovery.
 */
static boolean_t
idm_v4_addr_okay(struct in_addr *in_addr)
{
	in_addr_t addr = ntohl(in_addr->s_addr);

	if ((INADDR_NONE == addr) ||
	    (IN_MULTICAST(addr)) ||
	    ((addr >> IN_CLASSA_NSHIFT) == 0) ||
	    ((addr >> IN_CLASSA_NSHIFT) == IN_LOOPBACKNET)) {
		return (B_FALSE);
	}
	return (B_TRUE);
}

static boolean_t
idm_v6_addr_okay(struct in6_addr *addr6)
{

	if ((IN6_IS_ADDR_UNSPECIFIED(addr6)) ||
	    (IN6_IS_ADDR_LOOPBACK(addr6)) ||
	    (IN6_IS_ADDR_MULTICAST(addr6)) ||
	    (IN6_IS_ADDR_V4MAPPED(addr6)) ||
	    (IN6_IS_ADDR_V4COMPAT(addr6)) ||
	    (IN6_IS_ADDR_LINKLOCAL(addr6))) {
		return (B_FALSE);
	}
	return (B_TRUE);
}

/*
 * idm_get_ipaddr will retrieve a list of IP Addresses which the host is
 * configured with by sending down a sequence of kernel ioctl to IP STREAMS.
 */
int
idm_get_ipaddr(idm_addr_list_t **ipaddr_p)
{
	ksocket_t 		so4, so6;
	struct lifnum		lifn;
	struct lifconf		lifc;
	struct lifreq		*lp;
	int			rval;
	int			numifs;
	int			bufsize;
	void			*buf;
	int			i, j, n, rc;
	struct sockaddr_storage	ss;
	struct sockaddr_in	*sin;
	struct sockaddr_in6	*sin6;
	idm_addr_t		*ip;
	idm_addr_list_t		*ipaddr = NULL;
	int			size_ipaddr;

	*ipaddr_p = NULL;
	size_ipaddr = 0;
	buf = NULL;

	/* create an ipv4 and ipv6 UDP socket */
	if ((so6 = idm_socreate(PF_INET6, SOCK_DGRAM, 0)) == NULL)
		return (0);
	if ((so4 = idm_socreate(PF_INET, SOCK_DGRAM, 0)) == NULL) {
		idm_sodestroy(so6);
		return (0);
	}


retry_count:
	/* snapshot the current number of interfaces */
	lifn.lifn_family = PF_UNSPEC;
	lifn.lifn_flags = LIFC_NOXMIT | LIFC_TEMPORARY | LIFC_ALLZONES;
	lifn.lifn_count = 0;
	/* use vp6 for ioctls with unspecified families by default */
	if (ksocket_ioctl(so6, SIOCGLIFNUM, (intptr_t)&lifn, &rval, CRED())
	    != 0) {
		goto cleanup;
	}

	numifs = lifn.lifn_count;
	if (numifs <= 0) {
		goto cleanup;
	}

	/* allocate extra room in case more interfaces appear */
	numifs += 10;

	/* get the interface names and ip addresses */
	bufsize = numifs * sizeof (struct lifreq);
	buf = kmem_alloc(bufsize, KM_SLEEP);

	lifc.lifc_family = AF_UNSPEC;
	lifc.lifc_flags = LIFC_NOXMIT | LIFC_TEMPORARY | LIFC_ALLZONES;
	lifc.lifc_len = bufsize;
	lifc.lifc_buf = buf;
	rc = ksocket_ioctl(so6, SIOCGLIFCONF, (intptr_t)&lifc, &rval, CRED());
	if (rc != 0) {
		goto cleanup;
	}
	/* if our extra room is used up, try again */
	if (bufsize <= lifc.lifc_len) {
		kmem_free(buf, bufsize);
		buf = NULL;
		goto retry_count;
	}
	/* calc actual number of ifconfs */
	n = lifc.lifc_len / sizeof (struct lifreq);

	/* get ip address */
	if (n > 0) {
		size_ipaddr = sizeof (idm_addr_list_t) +
		    (n - 1) * sizeof (idm_addr_t);
		ipaddr = kmem_zalloc(size_ipaddr, KM_SLEEP);
	} else {
		goto cleanup;
	}

	/*
	 * Examine the array of interfaces and filter uninteresting ones
	 */
	for (i = 0, j = 0, lp = lifc.lifc_req; i < n; i++, lp++) {

		/*
		 * Copy the address as the SIOCGLIFFLAGS ioctl is destructive
		 */
		ss = lp->lifr_addr;
		/*
		 * fetch the flags using the socket of the correct family
		 */
		switch (ss.ss_family) {
		case AF_INET:
			rc = ksocket_ioctl(so4, SIOCGLIFFLAGS, (intptr_t)lp,
			    &rval, CRED());
			break;
		case AF_INET6:
			rc = ksocket_ioctl(so6, SIOCGLIFFLAGS, (intptr_t)lp,
			    &rval, CRED());
			break;
		default:
			continue;
		}
		if (rc == 0) {
			/*
			 * If we got the flags, skip uninteresting
			 * interfaces based on flags
			 */
			if ((lp->lifr_flags & IFF_UP) != IFF_UP)
				continue;
			if (lp->lifr_flags &
			    (IFF_ANYCAST|IFF_NOLOCAL|IFF_DEPRECATED))
				continue;
		}

		/* save ip address */
		ip = &ipaddr->al_addrs[j];
		switch (ss.ss_family) {
		case AF_INET:
			sin = (struct sockaddr_in *)&ss;
			if (!idm_v4_addr_okay(&sin->sin_addr))
				continue;
			ip->a_addr.i_addr.in4 = sin->sin_addr;
			ip->a_addr.i_insize = sizeof (struct in_addr);
			break;
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)&ss;
			if (!idm_v6_addr_okay(&sin6->sin6_addr))
				continue;
			ip->a_addr.i_addr.in6 = sin6->sin6_addr;
			ip->a_addr.i_insize = sizeof (struct in6_addr);
			break;
		default:
			continue;
		}
		j++;
	}

	if (j == 0) {
		/* no valid ifaddr */
		kmem_free(ipaddr, size_ipaddr);
		size_ipaddr = 0;
		ipaddr = NULL;
	} else {
		ipaddr->al_out_cnt = j;
	}


cleanup:
	idm_sodestroy(so6);
	idm_sodestroy(so4);

	if (buf != NULL)
		kmem_free(buf, bufsize);

	*ipaddr_p = ipaddr;
	return (size_ipaddr);
}

int
idm_sorecv(ksocket_t so, void *msg, size_t len)
{
	iovec_t iov;

	ASSERT(so != NULL);
	ASSERT(len != 0);

	/*
	 * Fill in iovec and receive data
	 */
	iov.iov_base = msg;
	iov.iov_len = len;

	return (idm_iov_sorecv(so, &iov, 1, len));
}

/*
 * idm_sosendto - Sends a buffered data on a non-connected socket.
 *
 * This function puts the data provided on the wire by calling sosendmsg.
 * It will return only when all the data has been sent or if an error
 * occurs.
 *
 * Returns 0 for success, the socket errno value if sosendmsg fails, and
 * -1 if sosendmsg returns success but uio_resid != 0
 */
int
idm_sosendto(ksocket_t so, void *buff, size_t len,
    struct sockaddr *name, socklen_t namelen)
{
	struct msghdr		msg;
	struct iovec		iov[1];
	int			error;
	size_t			sent = 0;

	iov[0].iov_base	= buff;
	iov[0].iov_len	= len;

	/* Initialization of the message header. */
	bzero(&msg, sizeof (msg));
	msg.msg_iov	= iov;
	msg.msg_iovlen	= 1;
	msg.msg_name	= name;
	msg.msg_namelen	= namelen;

	if ((error = ksocket_sendmsg(so, &msg, 0, &sent, CRED())) == 0) {
		/* Data sent */
		if (sent == len) {
			/* All data sent.  Success. */
			return (0);
		} else {
			/* Not all data was sent.  Failure */
			return (-1);
		}
	}

	/* Send failed */
	return (error);
}

/*
 * idm_iov_sosend - Sends an iovec on a connection.
 *
 * This function puts the data provided on the wire by calling sosendmsg.
 * It will return only when all the data has been sent or if an error
 * occurs.
 *
 * Returns 0 for success, the socket errno value if sosendmsg fails, and
 * -1 if sosendmsg returns success but uio_resid != 0
 */
int
idm_iov_sosend(ksocket_t so, iovec_t *iop, int iovlen, size_t total_len)
{
	struct msghdr		msg;
	int			error;
	size_t 			sent = 0;

	ASSERT(iop != NULL);

	/* Initialization of the message header. */
	bzero(&msg, sizeof (msg));
	msg.msg_iov	= iop;
	msg.msg_iovlen	= iovlen;

	if ((error = ksocket_sendmsg(so, &msg, 0, &sent, CRED()))
	    == 0) {
		/* Data sent */
		if (sent == total_len) {
			/* All data sent.  Success. */
			return (0);
		} else {
			/* Not all data was sent.  Failure */
			return (-1);
		}
	}

	/* Send failed */
	return (error);
}

/*
 * idm_iov_sorecv - Receives an iovec from a connection
 *
 * This function gets the data asked for from the socket.  It will return
 * only when all the requested data has been retrieved or if an error
 * occurs.
 *
 * Returns 0 for success, the socket errno value if sorecvmsg fails, and
 * -1 if sorecvmsg returns success but uio_resid != 0
 */
int
idm_iov_sorecv(ksocket_t so, iovec_t *iop, int iovlen, size_t total_len)
{
	struct msghdr		msg;
	int			error;
	size_t			recv;
	int 			flags;

	ASSERT(iop != NULL);

	/* Initialization of the message header. */
	bzero(&msg, sizeof (msg));
	msg.msg_iov	= iop;
	msg.msg_iovlen	= iovlen;
	flags		= MSG_WAITALL;

	if ((error = ksocket_recvmsg(so, &msg, flags, &recv, CRED()))
	    == 0) {
		/* Received data */
		if (recv == total_len) {
			/* All requested data received.  Success */
			return (0);
		} else {
			/*
			 * Not all data was received.  The connection has
			 * probably failed.
			 */
			return (-1);
		}
	}

	/* Receive failed */
	return (error);
}

static void
idm_set_ini_preconnect_options(idm_so_conn_t *sc, boolean_t boot_conn)
{
	int	conn_abort = 10000;
	int	conn_notify = 2000;
	int	abort = 30000;

	/* Pre-connect socket options */
	(void) ksocket_setsockopt(sc->ic_so, IPPROTO_TCP,
	    TCP_CONN_NOTIFY_THRESHOLD, (char *)&conn_notify, sizeof (int),
	    CRED());
	if (boot_conn == B_FALSE) {
		(void) ksocket_setsockopt(sc->ic_so, IPPROTO_TCP,
		    TCP_CONN_ABORT_THRESHOLD, (char *)&conn_abort, sizeof (int),
		    CRED());
		(void) ksocket_setsockopt(sc->ic_so, IPPROTO_TCP,
		    TCP_ABORT_THRESHOLD,
		    (char *)&abort, sizeof (int), CRED());
	}
}

static void
idm_set_postconnect_options(ksocket_t ks)
{
	const int	on = 1;

	/* Set connect options */
	(void) ksocket_setsockopt(ks, SOL_SOCKET, SO_RCVBUF,
	    (char *)&idm_so_rcvbuf, sizeof (idm_so_rcvbuf), CRED());
	(void) ksocket_setsockopt(ks, SOL_SOCKET, SO_SNDBUF,
	    (char *)&idm_so_sndbuf, sizeof (idm_so_sndbuf), CRED());
	(void) ksocket_setsockopt(ks, IPPROTO_TCP, TCP_NODELAY,
	    (char *)&on, sizeof (on), CRED());
}

static uint32_t
n2h24(const uchar_t *ptr)
{
	return ((ptr[0] << 16) | (ptr[1] << 8) | ptr[2]);
}


static idm_status_t
idm_sorecvhdr(idm_conn_t *ic, idm_pdu_t *pdu)
{
	iscsi_hdr_t	*bhs;
	uint32_t	hdr_digest_crc;
	uint32_t	crc_calculated;
	void		*new_hdr;
	int		ahslen = 0;
	int		total_len = 0;
	int		iovlen = 0;
	struct iovec	iov[2];
	idm_so_conn_t	*so_conn;
	int		rc;

	so_conn = ic->ic_transport_private;

	/*
	 * Read BHS
	 */
	bhs = pdu->isp_hdr;
	rc = idm_sorecv(so_conn->ic_so, pdu->isp_hdr, sizeof (iscsi_hdr_t));
	if (rc != IDM_STATUS_SUCCESS) {
		return (IDM_STATUS_FAIL);
	}

	/*
	 * Check actual AHS length against the amount available in the buffer
	 */
	pdu->isp_hdrlen = sizeof (iscsi_hdr_t) +
	    (bhs->hlength * sizeof (uint32_t));
	pdu->isp_datalen = n2h24(bhs->dlength);
	if (ic->ic_conn_type == CONN_TYPE_TGT &&
	    pdu->isp_datalen > ic->ic_conn_params.max_recv_dataseglen) {
		IDM_CONN_LOG(CE_WARN,
		    "idm_sorecvhdr: exceeded the max data segment length");
		return (IDM_STATUS_FAIL);
	}
	if (bhs->hlength > IDM_SORX_CACHE_AHSLEN) {
		/* Allocate a new header segment and change the callback */
		new_hdr = kmem_alloc(pdu->isp_hdrlen, KM_SLEEP);
		bcopy(pdu->isp_hdr, new_hdr, sizeof (iscsi_hdr_t));
		pdu->isp_hdr = new_hdr;
		pdu->isp_flags |= IDM_PDU_ADDL_HDR;

		/*
		 * This callback will restore the expected values after
		 * the RX PDU has been processed.
		 */
		pdu->isp_callback = idm_sorx_addl_pdu_cb;
	}

	/*
	 * Setup receipt of additional header and header digest (if enabled).
	 */
	if (bhs->hlength > 0) {
		iov[iovlen].iov_base = (caddr_t)(pdu->isp_hdr + 1);
		ahslen = pdu->isp_hdrlen - sizeof (iscsi_hdr_t);
		iov[iovlen].iov_len = ahslen;
		total_len += iov[iovlen].iov_len;
		iovlen++;
	}

	if (ic->ic_conn_flags & IDM_CONN_HEADER_DIGEST) {
		iov[iovlen].iov_base = (caddr_t)&hdr_digest_crc;
		iov[iovlen].iov_len = sizeof (hdr_digest_crc);
		total_len += iov[iovlen].iov_len;
		iovlen++;
	}

	if ((iovlen != 0) &&
	    (idm_iov_sorecv(so_conn->ic_so, &iov[0], iovlen,
	    total_len) != 0)) {
		return (IDM_STATUS_FAIL);
	}

	/*
	 * Validate header digest if enabled
	 */
	if (ic->ic_conn_flags & IDM_CONN_HEADER_DIGEST) {
		crc_calculated = idm_crc32c(pdu->isp_hdr,
		    sizeof (iscsi_hdr_t) + ahslen);
		if (crc_calculated != hdr_digest_crc) {
			/* Invalid Header Digest */
			return (IDM_STATUS_HEADER_DIGEST);
		}
	}

	return (0);
}

/*
 * idm_so_ini_conn_create()
 * Allocate the sockets transport connection resources.
 */
static idm_status_t
idm_so_ini_conn_create(idm_conn_req_t *cr, idm_conn_t *ic)
{
	ksocket_t	so;
	idm_so_conn_t	*so_conn;
	idm_status_t	idmrc;

	so = idm_socreate(cr->cr_domain, cr->cr_type,
	    cr->cr_protocol);
	if (so == NULL) {
		return (IDM_STATUS_FAIL);
	}

	/* Bind the socket if configured to do so */
	if (cr->cr_bound) {
		if (ksocket_bind(so, &cr->cr_bound_addr.sin,
		    SIZEOF_SOCKADDR(&cr->cr_bound_addr.sin), CRED()) != 0) {
			idm_sodestroy(so);
			return (IDM_STATUS_FAIL);
		}
	}

	idmrc = idm_so_conn_create_common(ic, so);
	if (idmrc != IDM_STATUS_SUCCESS) {
		idm_soshutdown(so);
		idm_sodestroy(so);
		return (IDM_STATUS_FAIL);
	}

	so_conn = ic->ic_transport_private;
	/* Set up socket options */
	idm_set_ini_preconnect_options(so_conn, cr->cr_boot_conn);

	return (IDM_STATUS_SUCCESS);
}

/*
 * idm_so_ini_conn_destroy()
 * Tear down the sockets transport connection resources.
 */
static void
idm_so_ini_conn_destroy(idm_conn_t *ic)
{
	idm_so_conn_destroy_common(ic);
}

/*
 * idm_so_ini_conn_connect()
 * Establish the connection referred to by the handle previously allocated via
 * idm_so_ini_conn_create().
 */
static idm_status_t
idm_so_ini_conn_connect(idm_conn_t *ic)
{
	idm_so_conn_t	*so_conn;
	struct sonode	*node = NULL;
	int 		rc;
	clock_t		lbolt, conn_login_max, conn_login_interval;
	boolean_t	nonblock;

	so_conn = ic->ic_transport_private;
	nonblock = ic->ic_conn_params.nonblock_socket;
	conn_login_max = ic->ic_conn_params.conn_login_max;
	conn_login_interval = ddi_get_lbolt() +
	    SEC_TO_TICK(ic->ic_conn_params.conn_login_interval);

	if (nonblock == B_TRUE) {
		node = ((struct sonode *)(so_conn->ic_so));
		/* Set to none block socket mode */
		idm_so_socket_set_nonblock(node);
		do {
			rc = ksocket_connect(so_conn->ic_so,
			    &ic->ic_ini_dst_addr.sin,
			    (SIZEOF_SOCKADDR(&ic->ic_ini_dst_addr.sin)),
			    CRED());
			if (rc == 0 || rc == EISCONN) {
				/* socket success or already success */
				rc = IDM_STATUS_SUCCESS;
				break;
			}
			if ((rc == ETIMEDOUT) || (rc == ECONNREFUSED) ||
			    (rc == ECONNRESET)) {
				/* socket connection timeout or refuse */
				break;
			}
			lbolt = ddi_get_lbolt();
			if (lbolt > conn_login_max) {
				/*
				 * Connection retry timeout,
				 * failed connect to target.
				 */
				break;
			}
			if (lbolt < conn_login_interval) {
				if ((rc == EINPROGRESS) || (rc == EALREADY)) {
					/* TCP connect still in progress */
					delay(SEC_TO_TICK(IN_PROGRESS_DELAY));
					continue;
				} else {
					delay(conn_login_interval - lbolt);
				}
			}
			conn_login_interval = ddi_get_lbolt() +
			    SEC_TO_TICK(ic->ic_conn_params.conn_login_interval);
		} while (rc != 0);
		/* resume to nonblock mode */
		if (rc == IDM_STATUS_SUCCESS) {
			idm_so_socket_set_block(node);
		}
	} else {
		rc = ksocket_connect(so_conn->ic_so, &ic->ic_ini_dst_addr.sin,
		    (SIZEOF_SOCKADDR(&ic->ic_ini_dst_addr.sin)), CRED());
	}

	if (rc != 0) {
		idm_soshutdown(so_conn->ic_so);
		return (IDM_STATUS_FAIL);
	}

	idm_so_conn_connect_common(ic);

	idm_set_postconnect_options(so_conn->ic_so);

	return (IDM_STATUS_SUCCESS);
}

idm_status_t
idm_so_tgt_conn_create(idm_conn_t *ic, ksocket_t new_so)
{
	idm_status_t	idmrc;

	idm_set_postconnect_options(new_so);
	idmrc = idm_so_conn_create_common(ic, new_so);

	return (idmrc);
}

static void
idm_so_tgt_conn_destroy(idm_conn_t *ic)
{
	idm_so_conn_destroy_common(ic);
}

/*
 * idm_so_tgt_conn_connect()
 * Establish the connection in ic, passed from idm_tgt_conn_finish(), which
 * is invoked from the SM as a result of an inbound connection request.
 */
static idm_status_t
idm_so_tgt_conn_connect(idm_conn_t *ic)
{
	idm_so_conn_connect_common(ic);

	return (IDM_STATUS_SUCCESS);
}

static idm_status_t
idm_so_conn_create_common(idm_conn_t *ic, ksocket_t new_so)
{
	idm_so_conn_t	*so_conn;

	so_conn = kmem_zalloc(sizeof (idm_so_conn_t), KM_SLEEP);
	so_conn->ic_so = new_so;

	ic->ic_transport_private = so_conn;
	ic->ic_transport_hdrlen = 0;

	/* Set the scoreboarding flag on this connection */
	ic->ic_conn_flags |= IDM_CONN_USE_SCOREBOARD;
	ic->ic_conn_params.max_recv_dataseglen =
	    ISCSI_DEFAULT_MAX_RECV_SEG_LEN;
	ic->ic_conn_params.max_xmit_dataseglen =
	    ISCSI_DEFAULT_MAX_XMIT_SEG_LEN;

	/*
	 * Initialize tx thread mutex and list
	 */
	mutex_init(&so_conn->ic_tx_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&so_conn->ic_tx_cv, NULL, CV_DEFAULT, NULL);
	list_create(&so_conn->ic_tx_list, sizeof (idm_pdu_t),
	    offsetof(idm_pdu_t, idm_tx_link));

	return (IDM_STATUS_SUCCESS);
}

static void
idm_so_conn_destroy_common(idm_conn_t *ic)
{
	idm_so_conn_t	*so_conn = ic->ic_transport_private;

	ic->ic_transport_private = NULL;
	idm_sodestroy(so_conn->ic_so);
	list_destroy(&so_conn->ic_tx_list);
	mutex_destroy(&so_conn->ic_tx_mutex);
	cv_destroy(&so_conn->ic_tx_cv);

	kmem_free(so_conn, sizeof (idm_so_conn_t));
}

static void
idm_so_conn_connect_common(idm_conn_t *ic)
{
	idm_so_conn_t	*so_conn;
	struct sockaddr_in6	t_addr;
	socklen_t	t_addrlen = 0;

	so_conn = ic->ic_transport_private;
	bzero(&t_addr, sizeof (struct sockaddr_in6));
	t_addrlen = sizeof (struct sockaddr_in6);

	/* Set the local and remote addresses in the idm conn handle */
	(void) ksocket_getsockname(so_conn->ic_so, (struct sockaddr *)&t_addr,
	    &t_addrlen, CRED());
	bcopy(&t_addr, &ic->ic_laddr, t_addrlen);
	(void) ksocket_getpeername(so_conn->ic_so, (struct sockaddr *)&t_addr,
	    &t_addrlen, CRED());
	bcopy(&t_addr, &ic->ic_raddr, t_addrlen);

	mutex_enter(&ic->ic_mutex);
	so_conn->ic_tx_thread = thread_create(NULL, 0, idm_sotx_thread, ic, 0,
	    &p0, TS_RUN, minclsyspri);
	so_conn->ic_rx_thread = thread_create(NULL, 0, idm_sorx_thread, ic, 0,
	    &p0, TS_RUN, minclsyspri);

	while (so_conn->ic_rx_thread_did == 0 ||
	    so_conn->ic_tx_thread_did == 0)
		cv_wait(&ic->ic_cv, &ic->ic_mutex);
	mutex_exit(&ic->ic_mutex);
}

/*
 * idm_so_conn_disconnect()
 * Shutdown the socket connection and stop the thread
 */
static void
idm_so_conn_disconnect(idm_conn_t *ic)
{
	idm_so_conn_t	*so_conn;

	so_conn = ic->ic_transport_private;

	mutex_enter(&ic->ic_mutex);
	so_conn->ic_rx_thread_running = B_FALSE;
	so_conn->ic_tx_thread_running = B_FALSE;
	/* We need to wakeup the TX thread */
	mutex_enter(&so_conn->ic_tx_mutex);
	cv_signal(&so_conn->ic_tx_cv);
	mutex_exit(&so_conn->ic_tx_mutex);
	mutex_exit(&ic->ic_mutex);

	/* This should wakeup the RX thread if it is sleeping */
	idm_soshutdown(so_conn->ic_so);

	thread_join(so_conn->ic_tx_thread_did);
	thread_join(so_conn->ic_rx_thread_did);
}

/*
 * idm_so_tgt_svc_create()
 * Establish a service on an IP address and port.  idm_svc_req_t contains
 * the service parameters.
 */
/*ARGSUSED*/
static idm_status_t
idm_so_tgt_svc_create(idm_svc_req_t *sr, idm_svc_t *is)
{
	idm_so_svc_t		*so_svc;

	so_svc = kmem_zalloc(sizeof (idm_so_svc_t), KM_SLEEP);

	/* Set the new sockets service in svc handle */
	is->is_so_svc = (void *)so_svc;

	return (IDM_STATUS_SUCCESS);
}

/*
 * idm_so_tgt_svc_destroy()
 * Teardown sockets resources allocated in idm_so_tgt_svc_create()
 */
static void
idm_so_tgt_svc_destroy(idm_svc_t *is)
{
	/* the socket will have been torn down; free the service */
	kmem_free(is->is_so_svc, sizeof (idm_so_svc_t));
}

/*
 * idm_so_tgt_svc_online()
 * Launch a watch thread on the svc allocated in idm_so_tgt_svc_create()
 */

static idm_status_t
idm_so_tgt_svc_online(idm_svc_t *is)
{
	idm_so_svc_t		*so_svc;
	idm_svc_req_t		*sr = &is->is_svc_req;
	struct sockaddr_in6	sin6_ip;
	const uint32_t		on = 1;
	const uint32_t		off = 0;

	mutex_enter(&is->is_mutex);
	so_svc = (idm_so_svc_t *)is->is_so_svc;

	/*
	 * Try creating an IPv6 socket first
	 */
	if ((so_svc->is_so = idm_socreate(PF_INET6, SOCK_STREAM, 0)) == NULL) {
		mutex_exit(&is->is_mutex);
		return (IDM_STATUS_FAIL);
	} else {
		bzero(&sin6_ip, sizeof (sin6_ip));
		sin6_ip.sin6_family = AF_INET6;
		sin6_ip.sin6_port = htons(sr->sr_port);
		sin6_ip.sin6_addr = in6addr_any;

		(void) ksocket_setsockopt(so_svc->is_so, SOL_SOCKET,
		    SO_REUSEADDR, (char *)&on, sizeof (on), CRED());
		/*
		 * Turn off SO_MAC_EXEMPT so future sobinds succeed
		 */
		(void) ksocket_setsockopt(so_svc->is_so, SOL_SOCKET,
		    SO_MAC_EXEMPT, (char *)&off, sizeof (off), CRED());

		if (ksocket_bind(so_svc->is_so, (struct sockaddr *)&sin6_ip,
		    sizeof (sin6_ip), CRED()) != 0) {
			mutex_exit(&is->is_mutex);
			idm_sodestroy(so_svc->is_so);
			return (IDM_STATUS_FAIL);
		}
	}

	idm_set_postconnect_options(so_svc->is_so);

	if (ksocket_listen(so_svc->is_so, 5, CRED()) != 0) {
		mutex_exit(&is->is_mutex);
		idm_soshutdown(so_svc->is_so);
		idm_sodestroy(so_svc->is_so);
		return (IDM_STATUS_FAIL);
	}

	/* Launch a watch thread */
	so_svc->is_thread = thread_create(NULL, 0, idm_so_svc_port_watcher,
	    is, 0, &p0, TS_RUN, minclsyspri);

	if (so_svc->is_thread == NULL) {
		/* Failure to launch; teardown the socket */
		mutex_exit(&is->is_mutex);
		idm_soshutdown(so_svc->is_so);
		idm_sodestroy(so_svc->is_so);
		return (IDM_STATUS_FAIL);
	}
	ksocket_hold(so_svc->is_so);
	/* Wait for the port watcher thread to start */
	while (!so_svc->is_thread_running)
		cv_wait(&is->is_cv, &is->is_mutex);
	mutex_exit(&is->is_mutex);

	return (IDM_STATUS_SUCCESS);
}

/*
 * idm_so_tgt_svc_offline
 *
 * Stop listening on the IP address and port identified by idm_svc_t.
 */
static void
idm_so_tgt_svc_offline(idm_svc_t *is)
{
	idm_so_svc_t		*so_svc;
	mutex_enter(&is->is_mutex);
	so_svc = (idm_so_svc_t *)is->is_so_svc;
	so_svc->is_thread_running = B_FALSE;
	mutex_exit(&is->is_mutex);

	/*
	 * Teardown socket
	 */
	idm_sodestroy(so_svc->is_so);

	/*
	 * Now we expect the port watcher thread to terminate
	 */
	thread_join(so_svc->is_thread_did);
}

/*
 * Watch thread for target service connection establishment.
 */
void
idm_so_svc_port_watcher(void *arg)
{
	idm_svc_t		*svc = arg;
	ksocket_t		new_so;
	idm_conn_t		*ic;
	idm_status_t		idmrc;
	idm_so_svc_t		*so_svc;
	int			rc;
	const uint32_t		off = 0;
	struct sockaddr_in6 	t_addr;
	socklen_t		t_addrlen;

	bzero(&t_addr, sizeof (struct sockaddr_in6));
	t_addrlen = sizeof (struct sockaddr_in6);
	mutex_enter(&svc->is_mutex);

	so_svc = svc->is_so_svc;
	so_svc->is_thread_running = B_TRUE;
	so_svc->is_thread_did = so_svc->is_thread->t_did;

	cv_signal(&svc->is_cv);

	IDM_SVC_LOG(CE_NOTE, "iSCSI service (%p/%d) online", (void *)svc,
	    svc->is_svc_req.sr_port);

	while (so_svc->is_thread_running) {
		mutex_exit(&svc->is_mutex);

		if ((rc = ksocket_accept(so_svc->is_so,
		    (struct sockaddr *)&t_addr, &t_addrlen,
		    &new_so, CRED())) != 0) {
			mutex_enter(&svc->is_mutex);
			if (rc != ECONNABORTED && rc != EINTR) {
				IDM_SVC_LOG(CE_NOTE, "idm_so_svc_port_watcher:"
				    " ksocket_accept failed %d", rc);
			}
			/*
			 * Unclean shutdown of this thread is not handled
			 * wait for !is_thread_running.
			 */
			continue;
		}
		/*
		 * Turn off SO_MAC_EXEMPT so future sobinds succeed
		 */
		(void) ksocket_setsockopt(new_so, SOL_SOCKET, SO_MAC_EXEMPT,
		    (char *)&off, sizeof (off), CRED());

		idmrc = idm_svc_conn_create(svc, IDM_TRANSPORT_TYPE_SOCKETS,
		    &ic);
		if (idmrc != IDM_STATUS_SUCCESS) {
			/* Drop connection */
			idm_soshutdown(new_so);
			idm_sodestroy(new_so);
			mutex_enter(&svc->is_mutex);
			continue;
		}

		idmrc = idm_so_tgt_conn_create(ic, new_so);
		if (idmrc != IDM_STATUS_SUCCESS) {
			idm_svc_conn_destroy(ic);
			idm_soshutdown(new_so);
			idm_sodestroy(new_so);
			mutex_enter(&svc->is_mutex);
			continue;
		}

		/*
		 * Kick the state machine.  At CS_S3_XPT_UP the state machine
		 * will notify the client (target) about the new connection.
		 */
		idm_conn_event(ic, CE_CONNECT_ACCEPT, NULL);

		mutex_enter(&svc->is_mutex);
	}
	ksocket_rele(so_svc->is_so);
	so_svc->is_thread_running = B_FALSE;
	mutex_exit(&svc->is_mutex);

	IDM_SVC_LOG(CE_NOTE, "iSCSI service (%p/%d) offline", (void *)svc,
	    svc->is_svc_req.sr_port);

	thread_exit();
}

/*
 * idm_so_free_task_rsrc() stops any ongoing processing of the task and
 * frees resources associated with the task.
 *
 * It's not clear that this should return idm_status_t.  What do we do
 * if it fails?
 */
static idm_status_t
idm_so_free_task_rsrc(idm_task_t *idt)
{
	idm_buf_t	*idb, *next_idb;

	/*
	 * There is nothing to cleanup on initiator connections
	 */
	if (IDM_CONN_ISINI(idt->idt_ic))
		return (IDM_STATUS_SUCCESS);

	/*
	 * If this is a target connection, call idm_buf_rx_from_ini_done for
	 * any buffer on the "outbufv" list with idb->idb_in_transport==B_TRUE.
	 *
	 * In addition, remove any buffers associated with this task from
	 * the ic_tx_list.  We'll do this by walking the idt_inbufv list, but
	 * items don't actually get removed from that list (and completion
	 * routines called) until idm_task_cleanup.
	 */
	mutex_enter(&idt->idt_mutex);

	for (idb = list_head(&idt->idt_outbufv); idb != NULL; idb = next_idb) {
		next_idb = list_next(&idt->idt_outbufv, idb);
		if (idb->idb_in_transport) {
			/*
			 * idm_buf_rx_from_ini_done releases idt->idt_mutex
			 */
			DTRACE_ISCSI_8(xfer__done, idm_conn_t *, idt->idt_ic,
			    uintptr_t, idb->idb_buf,
			    uint32_t, idb->idb_bufoffset,
			    uint64_t, 0, uint32_t, 0, uint32_t, 0,
			    uint32_t, idb->idb_xfer_len,
			    int, XFER_BUF_RX_FROM_INI);
			idm_buf_rx_from_ini_done(idt, idb, IDM_STATUS_ABORTED);
			mutex_enter(&idt->idt_mutex);
		}
	}

	for (idb = list_head(&idt->idt_inbufv); idb != NULL; idb = next_idb) {
		next_idb = list_next(&idt->idt_inbufv, idb);
		/*
		 * We want to remove these items from the tx_list as well,
		 * but knowing it's in the idt_inbufv list is not a guarantee
		 * that it's in the tx_list.  If it's on the tx list then
		 * let idm_sotx_thread() clean it up.
		 */
		if (idb->idb_in_transport && !idb->idb_tx_thread) {
			/*
			 * idm_buf_tx_to_ini_done releases idt->idt_mutex
			 */
			DTRACE_ISCSI_8(xfer__done, idm_conn_t *, idt->idt_ic,
			    uintptr_t, idb->idb_buf,
			    uint32_t, idb->idb_bufoffset,
			    uint64_t, 0, uint32_t, 0, uint32_t, 0,
			    uint32_t, idb->idb_xfer_len,
			    int, XFER_BUF_TX_TO_INI);
			idm_buf_tx_to_ini_done(idt, idb, IDM_STATUS_ABORTED);
			mutex_enter(&idt->idt_mutex);
		}
	}

	mutex_exit(&idt->idt_mutex);

	return (IDM_STATUS_SUCCESS);
}

/*
 * idm_so_negotiate_key_values() validates the key values for this connection
 */
/* ARGSUSED */
static kv_status_t
idm_so_negotiate_key_values(idm_conn_t *it, nvlist_t *request_nvl,
    nvlist_t *response_nvl, nvlist_t *negotiated_nvl)
{
	/* All parameters are negotiated at the iscsit level */
	return (KV_HANDLED);
}

/*
 * idm_so_notice_key_values() activates the negotiated key values for
 * this connection.
 */
static void
idm_so_notice_key_values(idm_conn_t *it, nvlist_t *negotiated_nvl)
{
	char			*nvp_name;
	nvpair_t		*nvp;
	nvpair_t		*next_nvp;
	int			nvrc;
	idm_status_t		idm_status;
	const idm_kv_xlate_t	*ikvx;
	uint64_t		num_val;

	for (nvp = nvlist_next_nvpair(negotiated_nvl, NULL);
	    nvp != NULL; nvp = next_nvp) {
		next_nvp = nvlist_next_nvpair(negotiated_nvl, nvp);
		nvp_name = nvpair_name(nvp);

		ikvx = idm_lookup_kv_xlate(nvp_name, strlen(nvp_name));
		switch (ikvx->ik_key_id) {
		case KI_HEADER_DIGEST:
		case KI_DATA_DIGEST:
			idm_status = idm_so_handle_digest(it, nvp, ikvx);
			ASSERT(idm_status == 0);

			/* Remove processed item from negotiated_nvl list */
			nvrc = nvlist_remove_all(
			    negotiated_nvl, ikvx->ik_key_name);
			ASSERT(nvrc == 0);
			break;
		case KI_MAX_RECV_DATA_SEGMENT_LENGTH:
			/*
			 * Just pass the value down to idm layer.
			 * No need to remove it from negotiated_nvl list here.
			 */
			nvrc = nvpair_value_uint64(nvp, &num_val);
			ASSERT(nvrc == 0);
			it->ic_conn_params.max_xmit_dataseglen =
			    (uint32_t)num_val;
			break;
		default:
			break;
		}
	}
}

/*
 * idm_so_declare_key_values() declares the key values for this connection
 */
/* ARGSUSED */
static kv_status_t
idm_so_declare_key_values(idm_conn_t *it, nvlist_t *config_nvl,
    nvlist_t *outgoing_nvl)
{
	char			*nvp_name;
	nvpair_t		*nvp;
	nvpair_t		*next_nvp;
	kv_status_t		kvrc;
	int			nvrc = 0;
	const idm_kv_xlate_t	*ikvx;
	uint64_t		num_val;

	for (nvp = nvlist_next_nvpair(config_nvl, NULL);
	    nvp != NULL && nvrc == 0; nvp = next_nvp) {
		next_nvp = nvlist_next_nvpair(config_nvl, nvp);
		nvp_name = nvpair_name(nvp);

		ikvx = idm_lookup_kv_xlate(nvp_name, strlen(nvp_name));
		switch (ikvx->ik_key_id) {
		case KI_MAX_RECV_DATA_SEGMENT_LENGTH:
			if ((nvrc = nvpair_value_uint64(nvp, &num_val)) != 0) {
				break;
			}
			if (outgoing_nvl &&
			    (nvrc = nvlist_add_uint64(outgoing_nvl,
			    nvp_name, num_val)) != 0) {
				break;
			}
			it->ic_conn_params.max_recv_dataseglen =
			    (uint32_t)num_val;
			break;
		default:
			break;
		}
	}
	kvrc = idm_nvstat_to_kvstat(nvrc);
	return (kvrc);
}

static idm_status_t
idm_so_handle_digest(idm_conn_t *it, nvpair_t *digest_choice,
    const idm_kv_xlate_t *ikvx)
{
	int			nvrc;
	char			*digest_choice_string;

	nvrc = nvpair_value_string(digest_choice,
	    &digest_choice_string);
	ASSERT(nvrc == 0);
	if (strcasecmp(digest_choice_string, "crc32c") == 0) {
		switch (ikvx->ik_key_id) {
		case KI_HEADER_DIGEST:
			it->ic_conn_flags |= IDM_CONN_HEADER_DIGEST;
			break;
		case KI_DATA_DIGEST:
			it->ic_conn_flags |= IDM_CONN_DATA_DIGEST;
			break;
		default:
			ASSERT(0);
			break;
		}
	} else if (strcasecmp(digest_choice_string, "none") == 0) {
		switch (ikvx->ik_key_id) {
		case KI_HEADER_DIGEST:
			it->ic_conn_flags &= ~IDM_CONN_HEADER_DIGEST;
			break;
		case KI_DATA_DIGEST:
			it->ic_conn_flags &= ~IDM_CONN_DATA_DIGEST;
			break;
		default:
			ASSERT(0);
			break;
		}
	} else {
		ASSERT(0);
	}

	return (IDM_STATUS_SUCCESS);
}


/*
 * idm_so_conn_is_capable() verifies that the passed connection is provided
 * for by the sockets interface.
 */
/* ARGSUSED */
static boolean_t
idm_so_conn_is_capable(idm_conn_req_t *ic, idm_transport_caps_t *caps)
{
	return (B_TRUE);
}

/*
 * idm_so_rx_datain() validates the Data Sequence number of the PDU. The
 * idm_sorecv_scsidata() function invoked earlier actually reads the data
 * off the socket into the appropriate buffers.
 */
static void
idm_so_rx_datain(idm_conn_t *ic, idm_pdu_t *pdu)
{
	iscsi_data_hdr_t	*bhs;
	idm_task_t		*idt;
	idm_buf_t		*idb;
	uint32_t		datasn;
	size_t			offset;
	iscsi_hdr_t		*ihp = (iscsi_hdr_t *)pdu->isp_hdr;
	iscsi_data_rsp_hdr_t    *idrhp = (iscsi_data_rsp_hdr_t *)ihp;

	ASSERT(ic != NULL);
	ASSERT(pdu != NULL);

	bhs	= (iscsi_data_hdr_t *)pdu->isp_hdr;
	datasn	= ntohl(bhs->datasn);
	offset	= ntohl(bhs->offset);

	ASSERT(bhs->opcode == ISCSI_OP_SCSI_DATA_RSP);

	/*
	 * Look up the task corresponding to the initiator task tag
	 * to get the buffers affiliated with the task.
	 */
	idt = idm_task_find(ic, bhs->itt, bhs->ttt);
	if (idt == NULL) {
		IDM_CONN_LOG(CE_WARN, "idm_so_rx_datain: failed to find task");
		idm_pdu_rx_protocol_error(ic, pdu);
		return;
	}

	idb = pdu->isp_sorx_buf;
	if (idb == NULL) {
		IDM_CONN_LOG(CE_WARN,
		    "idm_so_rx_datain: failed to find buffer");
		idm_task_rele(idt);
		idm_pdu_rx_protocol_error(ic, pdu);
		return;
	}

	/*
	 * DataSN values should be sequential and should not have any gaps or
	 * repetitions. Check the DataSN with the one stored in the task.
	 */
	if (datasn == idt->idt_exp_datasn) {
		idt->idt_exp_datasn++; /* keep track of DataSN received */
	} else {
		IDM_CONN_LOG(CE_WARN, "idm_so_rx_datain: datasn out of order");
		idm_task_rele(idt);
		idm_pdu_rx_protocol_error(ic, pdu);
		return;
	}

	/*
	 * PDUs in a sequence should be in continuously increasing
	 * address offset
	 */
	if (offset != idb->idb_exp_offset) {
		IDM_CONN_LOG(CE_WARN, "idm_so_rx_datain: unexpected offset");
		idm_task_rele(idt);
		idm_pdu_rx_protocol_error(ic, pdu);
		return;
	}
	/* Expected next relative buffer offset */
	idb->idb_exp_offset += n2h24(bhs->dlength);
	idt->idt_rx_bytes += n2h24(bhs->dlength);

	idm_task_rele(idt);

	/*
	 * For now call scsi_rsp which will process the data rsp
	 * Revisit, need to provide an explicit client entry point for
	 * phase collapse completions.
	 */
	if (((ihp->opcode & ISCSI_OPCODE_MASK) == ISCSI_OP_SCSI_DATA_RSP) &&
	    (idrhp->flags & ISCSI_FLAG_DATA_STATUS)) {
		(*ic->ic_conn_ops.icb_rx_scsi_rsp)(ic, pdu);
	}

	idm_pdu_complete(pdu, IDM_STATUS_SUCCESS);
}

/*
 * The idm_so_rx_dataout() function is used by the iSCSI target to read
 * data from the Data-Out PDU sent by the iSCSI initiator.
 *
 * This function gets the Initiator Task Tag from the PDU BHS and looks up the
 * task to get the buffers associated with the PDU. A PDU might span buffers.
 * The data is then read into the respective buffer.
 */
static void
idm_so_rx_dataout(idm_conn_t *ic, idm_pdu_t *pdu)
{

	iscsi_data_hdr_t	*bhs;
	idm_task_t		*idt;
	idm_buf_t		*idb;
	size_t			offset;

	ASSERT(ic != NULL);
	ASSERT(pdu != NULL);

	bhs = (iscsi_data_hdr_t *)pdu->isp_hdr;
	offset = ntohl(bhs->offset);
	ASSERT(bhs->opcode == ISCSI_OP_SCSI_DATA);

	/*
	 * Look up the task corresponding to the initiator task tag
	 * to get the buffers affiliated with the task.
	 */
	idt = idm_task_find(ic, bhs->itt, bhs->ttt);
	if (idt == NULL) {
		IDM_CONN_LOG(CE_WARN,
		    "idm_so_rx_dataout: failed to find task");
		idm_pdu_rx_protocol_error(ic, pdu);
		return;
	}

	idb = pdu->isp_sorx_buf;
	if (idb == NULL) {
		IDM_CONN_LOG(CE_WARN,
		    "idm_so_rx_dataout: failed to find buffer");
		idm_task_rele(idt);
		idm_pdu_rx_protocol_error(ic, pdu);
		return;
	}

	/* Keep track of data transferred - check data offsets */
	if (offset != idb->idb_exp_offset) {
		IDM_CONN_LOG(CE_NOTE, "idm_so_rx_dataout: offset out of seq: "
		    "%ld, %d", offset, idb->idb_exp_offset);
		idm_task_rele(idt);
		idm_pdu_rx_protocol_error(ic, pdu);
		return;
	}
	/* Expected next relative offset */
	idb->idb_exp_offset += ntoh24(bhs->dlength);
	idt->idt_rx_bytes += n2h24(bhs->dlength);

	/*
	 * Call the buffer callback when the transfer is complete
	 *
	 * The connection state machine should only abort tasks after
	 * shutting down the connection so we are assured that there
	 * won't be a simultaneous attempt to abort this task at the
	 * same time as we are processing this PDU (due to a connection
	 * state change).
	 */
	if (bhs->flags & ISCSI_FLAG_FINAL) {
		/*
		 * We only want to call idm_buf_rx_from_ini_done once
		 * per transfer.  It's possible that this task has
		 * already been aborted in which case
		 * idm_so_free_task_rsrc will call idm_buf_rx_from_ini_done
		 * for each buffer with idb_in_transport==B_TRUE.  To
		 * close this window and ensure that this doesn't happen,
		 * we'll clear idb->idb_in_transport now while holding
		 * the task mutex.   This is only really an issue for
		 * SCSI task abort -- if tasks were being aborted because
		 * of a connection state change the state machine would
		 * have already stopped the receive thread.
		 */
		mutex_enter(&idt->idt_mutex);

		/*
		 * Release the task hold here (obtained in idm_task_find)
		 * because the task may complete synchronously during
		 * idm_buf_rx_from_ini_done.  Since we still have an active
		 * buffer we know there is at least one additional hold on idt.
		 */
		idm_task_rele(idt);

		/*
		 * idm_buf_rx_from_ini_done releases idt->idt_mutex
		 */
		DTRACE_ISCSI_8(xfer__done, idm_conn_t *, idt->idt_ic,
		    uintptr_t, idb->idb_buf, uint32_t, idb->idb_bufoffset,
		    uint64_t, 0, uint32_t, 0, uint32_t, 0,
		    uint32_t, idb->idb_xfer_len,
		    int, XFER_BUF_RX_FROM_INI);
		idm_buf_rx_from_ini_done(idt, idb, IDM_STATUS_SUCCESS);
		idm_pdu_complete(pdu, IDM_STATUS_SUCCESS);
		return;
	}

	idm_task_rele(idt);
	idm_pdu_complete(pdu, IDM_STATUS_SUCCESS);
}

/*
 * The idm_so_rx_rtt() function is used by the iSCSI initiator to handle
 * the R2T PDU sent by the iSCSI target indicating that it is ready to
 * accept data. This gets the Initiator Task Tag (itt) from the PDU BHS
 * and looks up the task in the task tree using the itt to get the output
 * buffers associated the task. The R2T PDU contains the offset of the
 * requested data and the data length. This function then constructs a
 * sequence of iSCSI PDUs and outputs the requested data. Each Data-Out
 * PDU is associated with the R2T by the Target Transfer Tag  (ttt).
 */

static void
idm_so_rx_rtt(idm_conn_t *ic, idm_pdu_t *pdu)
{
	idm_task_t		*idt;
	idm_buf_t		*idb;
	iscsi_rtt_hdr_t		*rtt_hdr;
	uint32_t		data_offset;
	uint32_t		data_length;

	ASSERT(ic != NULL);
	ASSERT(pdu != NULL);

	rtt_hdr	= (iscsi_rtt_hdr_t *)pdu->isp_hdr;
	data_offset = ntohl(rtt_hdr->data_offset);
	data_length = ntohl(rtt_hdr->data_length);
	idt	= idm_task_find(ic, rtt_hdr->itt, rtt_hdr->ttt);

	if (idt == NULL) {
		IDM_CONN_LOG(CE_WARN, "idm_so_rx_rtt: could not find task");
		idm_pdu_rx_protocol_error(ic, pdu);
		return;
	}

	/* Find the buffer bound to the task by the iSCSI initiator */
	mutex_enter(&idt->idt_mutex);
	idb = idm_buf_find(&idt->idt_outbufv, data_offset);
	if (idb == NULL) {
		mutex_exit(&idt->idt_mutex);
		idm_task_rele(idt);
		IDM_CONN_LOG(CE_WARN, "idm_so_rx_rtt: could not find buffer");
		idm_pdu_rx_protocol_error(ic, pdu);
		return;
	}

	/* return buffer contains this data */
	if (data_offset + data_length > idb->idb_buflen) {
		/* Overflow */
		mutex_exit(&idt->idt_mutex);
		idm_task_rele(idt);
		IDM_CONN_LOG(CE_WARN, "idm_so_rx_rtt: read from outside "
		    "buffer");
		idm_pdu_rx_protocol_error(ic, pdu);
		return;
	}

	idt->idt_r2t_ttt = rtt_hdr->ttt;
	idt->idt_exp_datasn = 0;

	idm_so_send_rtt_data(ic, idt, idb, data_offset,
	    ntohl(rtt_hdr->data_length));
	/*
	 * the idt_mutex is released in idm_so_send_rtt_data
	 */

	idm_pdu_complete(pdu, IDM_STATUS_SUCCESS);
	idm_task_rele(idt);

}

idm_status_t
idm_sorecvdata(idm_conn_t *ic, idm_pdu_t *pdu)
{
	uint8_t		pad[ISCSI_PAD_WORD_LEN];
	int		pad_len;
	uint32_t	data_digest_crc;
	uint32_t	crc_calculated;
	int		total_len;
	idm_so_conn_t	*so_conn;

	so_conn = ic->ic_transport_private;

	pad_len = ((ISCSI_PAD_WORD_LEN -
	    (pdu->isp_datalen & (ISCSI_PAD_WORD_LEN - 1))) &
	    (ISCSI_PAD_WORD_LEN - 1));

	ASSERT(pdu->isp_iovlen < (PDU_MAX_IOVLEN - 2)); /* pad + data digest */

	total_len = pdu->isp_datalen;

	if (pad_len) {
		pdu->isp_iov[pdu->isp_iovlen].iov_base	= (char *)&pad;
		pdu->isp_iov[pdu->isp_iovlen].iov_len	= pad_len;
		total_len		+= pad_len;
		pdu->isp_iovlen++;
	}

	/* setup data digest */
	if ((ic->ic_conn_flags & IDM_CONN_DATA_DIGEST) != 0) {
		pdu->isp_iov[pdu->isp_iovlen].iov_base =
		    (char *)&data_digest_crc;
		pdu->isp_iov[pdu->isp_iovlen].iov_len =
		    sizeof (data_digest_crc);
		total_len		+= sizeof (data_digest_crc);
		pdu->isp_iovlen++;
	}

	pdu->isp_data = (uint8_t *)(uintptr_t)pdu->isp_iov[0].iov_base;

	if (idm_iov_sorecv(so_conn->ic_so, &pdu->isp_iov[0],
	    pdu->isp_iovlen, total_len) != 0) {
		return (IDM_STATUS_IO);
	}

	if ((ic->ic_conn_flags & IDM_CONN_DATA_DIGEST) != 0) {
		crc_calculated = idm_crc32c(pdu->isp_data,
		    pdu->isp_datalen);
		if (pad_len) {
			crc_calculated = idm_crc32c_continued((char *)&pad,
			    pad_len, crc_calculated);
		}
		if (crc_calculated != data_digest_crc) {
			IDM_CONN_LOG(CE_WARN,
			    "idm_sorecvdata: "
			    "CRC error: actual 0x%x, calc 0x%x",
			    data_digest_crc, crc_calculated);

			/* Invalid Data Digest */
			return (IDM_STATUS_DATA_DIGEST);
		}
	}

	return (IDM_STATUS_SUCCESS);
}

/*
 * idm_sorecv_scsidata() is used to receive scsi data from the socket. The
 * Data-type PDU header must be read into the idm_pdu_t structure prior to
 * calling this function.
 */
idm_status_t
idm_sorecv_scsidata(idm_conn_t *ic, idm_pdu_t *pdu)
{
	iscsi_data_hdr_t	*bhs;
	idm_task_t		*task;
	uint32_t		offset;
	uint8_t			opcode;
	uint32_t		dlength;
	list_t			*buflst;
	uint32_t		xfer_bytes;
	idm_status_t		status;

	ASSERT(ic != NULL);
	ASSERT(pdu != NULL);

	bhs	= (iscsi_data_hdr_t *)pdu->isp_hdr;

	offset	= ntohl(bhs->offset);
	opcode	= bhs->opcode;
	dlength = n2h24(bhs->dlength);

	ASSERT((opcode == ISCSI_OP_SCSI_DATA_RSP) ||
	    (opcode == ISCSI_OP_SCSI_DATA));

	/*
	 * Successful lookup implicitly gets a "hold" on the task.  This
	 * hold must be released before leaving this function.  At one
	 * point we were caching this task context and retaining the hold
	 * but it turned out to be very difficult to release the hold properly.
	 * The task can be aborted and the connection shutdown between this
	 * call and the subsequent expected call to idm_so_rx_datain/
	 * idm_so_rx_dataout (in which case those functions are not called).
	 * Releasing the hold in the PDU callback doesn't work well either
	 * because the whole task may be completed by then at which point
	 * it is too late to release the hold -- for better or worse this
	 * code doesn't wait on the refcnts during normal operation.
	 * idm_task_find() is very fast and it is not a huge burden if we
	 * have to do it twice.
	 */
	task = idm_task_find(ic, bhs->itt, bhs->ttt);
	if (task == NULL) {
		IDM_CONN_LOG(CE_WARN,
		    "idm_sorecv_scsidata: could not find task");
		return (IDM_STATUS_FAIL);
	}

	mutex_enter(&task->idt_mutex);
	buflst	= (opcode == ISCSI_OP_SCSI_DATA_RSP) ?
	    &task->idt_inbufv : &task->idt_outbufv;
	pdu->isp_sorx_buf = idm_buf_find(buflst, offset);
	mutex_exit(&task->idt_mutex);

	if (pdu->isp_sorx_buf == NULL) {
		idm_task_rele(task);
		IDM_CONN_LOG(CE_WARN, "idm_sorecv_scsidata: could not find "
		    "buffer for offset %x opcode=%x",
		    offset, opcode);
		return (IDM_STATUS_FAIL);
	}

	xfer_bytes = idm_fill_iov(pdu, pdu->isp_sorx_buf, offset, dlength);
	ASSERT(xfer_bytes != 0);
	if (xfer_bytes != dlength) {
		idm_task_rele(task);
		/*
		 * Buffer overflow, connection error.  The PDU data is still
		 * sitting in the socket so we can't use the connection
		 * again until that data is drained.
		 */
		return (IDM_STATUS_FAIL);
	}

	status = idm_sorecvdata(ic, pdu);

	idm_task_rele(task);

	return (status);
}

static uint32_t
idm_fill_iov(idm_pdu_t *pdu, idm_buf_t *idb, uint32_t ro, uint32_t dlength)
{
	uint32_t	buf_ro = ro - idb->idb_bufoffset;
	uint32_t	xfer_len = min(dlength, idb->idb_buflen - buf_ro);

	ASSERT(ro >= idb->idb_bufoffset);

	pdu->isp_iov[pdu->isp_iovlen].iov_base	=
	    (caddr_t)idb->idb_buf + buf_ro;
	pdu->isp_iov[pdu->isp_iovlen].iov_len	= xfer_len;
	pdu->isp_iovlen++;

	return (xfer_len);
}

int
idm_sorecv_nonscsidata(idm_conn_t *ic, idm_pdu_t *pdu)
{
	pdu->isp_data = kmem_alloc(pdu->isp_datalen, KM_SLEEP);
	ASSERT(pdu->isp_data != NULL);

	pdu->isp_databuflen = pdu->isp_datalen;
	pdu->isp_iov[0].iov_base = (caddr_t)pdu->isp_data;
	pdu->isp_iov[0].iov_len = pdu->isp_datalen;
	pdu->isp_iovlen = 1;
	/*
	 * Since we are associating a new data buffer with this received
	 * PDU we need to set a specific callback to free the data
	 * after the PDU is processed.
	 */
	pdu->isp_flags |= IDM_PDU_ADDL_DATA;
	pdu->isp_callback = idm_sorx_addl_pdu_cb;

	return (idm_sorecvdata(ic, pdu));
}

void
idm_sorx_thread(void *arg)
{
	boolean_t	conn_failure = B_FALSE;
	idm_conn_t	*ic = (idm_conn_t *)arg;
	idm_so_conn_t	*so_conn;
	idm_pdu_t	*pdu;
	idm_status_t	rc;

	idm_conn_hold(ic);

	mutex_enter(&ic->ic_mutex);

	so_conn = ic->ic_transport_private;
	so_conn->ic_rx_thread_running = B_TRUE;
	so_conn->ic_rx_thread_did = so_conn->ic_rx_thread->t_did;
	cv_signal(&ic->ic_cv);

	while (so_conn->ic_rx_thread_running) {
		mutex_exit(&ic->ic_mutex);

		/*
		 * Get PDU with default header size (large enough for
		 * BHS plus any anticipated AHS).  PDU from
		 * the cache will have all values set correctly
		 * for sockets RX including callback.
		 */
		pdu = kmem_cache_alloc(idm.idm_sorx_pdu_cache, KM_SLEEP);
		pdu->isp_ic = ic;
		pdu->isp_flags = 0;
		pdu->isp_transport_hdrlen = 0;

		if ((rc = idm_sorecvhdr(ic, pdu)) != 0) {
			/*
			 * Call idm_pdu_complete so that we call the callback
			 * and ensure any memory allocated in idm_sorecvhdr
			 * gets freed up.
			 */
			idm_pdu_complete(pdu, IDM_STATUS_FAIL);

			/*
			 * If ic_rx_thread_running is still set then
			 * this is some kind of connection problem
			 * on the socket.  In this case we want to
			 * generate an event.  Otherwise some other
			 * thread closed the socket due to another
			 * issue in which case we don't need to
			 * generate an event.
			 */
			mutex_enter(&ic->ic_mutex);
			if (so_conn->ic_rx_thread_running) {
				conn_failure = B_TRUE;
				so_conn->ic_rx_thread_running = B_FALSE;
			}

			continue;
		}

		/*
		 * Header has been read and validated.  Now we need
		 * to read the PDU data payload (if present).  SCSI data
		 * need to be transferred from the socket directly into
		 * the associated transfer buffer for the SCSI task.
		 */
		if (pdu->isp_datalen != 0) {
			if ((IDM_PDU_OPCODE(pdu) == ISCSI_OP_SCSI_DATA) ||
			    (IDM_PDU_OPCODE(pdu) == ISCSI_OP_SCSI_DATA_RSP)) {
				rc = idm_sorecv_scsidata(ic, pdu);
				/*
				 * All SCSI errors are fatal to the
				 * connection right now since we have no
				 * place to put the data.  What we need
				 * is some kind of sink to dispose of unwanted
				 * SCSI data.  For example an invalid task tag
				 * should not kill the connection (although
				 * we may want to drop the connection).
				 */
			} else {
				/*
				 * Not data PDUs so allocate a buffer for the
				 * data segment and read the remaining data.
				 */
				rc = idm_sorecv_nonscsidata(ic, pdu);
			}
			if (rc != 0) {
				/*
				 * Call idm_pdu_complete so that we call the
				 * callback and ensure any memory allocated
				 * in idm_sorecvhdr gets freed up.
				 */
				idm_pdu_complete(pdu, IDM_STATUS_FAIL);

				/*
				 * If ic_rx_thread_running is still set then
				 * this is some kind of connection problem
				 * on the socket.  In this case we want to
				 * generate an event.  Otherwise some other
				 * thread closed the socket due to another
				 * issue in which case we don't need to
				 * generate an event.
				 */
				mutex_enter(&ic->ic_mutex);
				if (so_conn->ic_rx_thread_running) {
					conn_failure = B_TRUE;
					so_conn->ic_rx_thread_running = B_FALSE;
				}
				continue;
			}
		}

		/*
		 * Process RX PDU
		 */
		idm_pdu_rx(ic, pdu);

		mutex_enter(&ic->ic_mutex);
	}

	mutex_exit(&ic->ic_mutex);

	/*
	 * If we dropped out of the RX processing loop because of
	 * a socket problem or other connection failure (including
	 * digest errors) then we need to generate a state machine
	 * event to shut the connection down.
	 * If the state machine is already in, for example, INIT_ERROR, this
	 * event will get dropped, and the TX thread will never be notified
	 * to shut down.  To be safe, we'll just notify it here.
	 */
	if (conn_failure) {
		if (so_conn->ic_tx_thread_running) {
			so_conn->ic_tx_thread_running = B_FALSE;
			mutex_enter(&so_conn->ic_tx_mutex);
			cv_signal(&so_conn->ic_tx_cv);
			mutex_exit(&so_conn->ic_tx_mutex);
		}

		idm_conn_event(ic, CE_TRANSPORT_FAIL, rc);
	}

	idm_conn_rele(ic);

	thread_exit();
}

/*
 * idm_so_tx
 *
 * This is the implementation of idm_transport_ops_t's it_tx_pdu entry
 * point.  By definition, it is supposed to be fast.  So, simply queue
 * the entry and return.  The real work is done by idm_i_so_tx() via
 * idm_sotx_thread().
 */

static void
idm_so_tx(idm_conn_t *ic, idm_pdu_t *pdu)
{
	idm_so_conn_t *so_conn = ic->ic_transport_private;

	ASSERT(pdu->isp_ic == ic);
	mutex_enter(&so_conn->ic_tx_mutex);

	if (!so_conn->ic_tx_thread_running) {
		mutex_exit(&so_conn->ic_tx_mutex);
		idm_pdu_complete(pdu, IDM_STATUS_ABORTED);
		return;
	}

	list_insert_tail(&so_conn->ic_tx_list, (void *)pdu);
	cv_signal(&so_conn->ic_tx_cv);
	mutex_exit(&so_conn->ic_tx_mutex);
}

static idm_status_t
idm_i_so_tx(idm_pdu_t *pdu)
{
	idm_conn_t	*ic = pdu->isp_ic;
	idm_status_t	status = IDM_STATUS_SUCCESS;
	uint8_t		pad[ISCSI_PAD_WORD_LEN];
	int		pad_len;
	uint32_t	hdr_digest_crc;
	uint32_t	data_digest_crc = 0;
	int		total_len = 0;
	int		iovlen = 0;
	struct iovec	iov[6];
	idm_so_conn_t	*so_conn;

	so_conn = ic->ic_transport_private;

	/* Setup BHS */
	iov[iovlen].iov_base	= (caddr_t)pdu->isp_hdr;
	iov[iovlen].iov_len	= pdu->isp_hdrlen;
	total_len		+= iov[iovlen].iov_len;
	iovlen++;

	/* Setup header digest */
	if (((pdu->isp_flags & IDM_PDU_LOGIN_TX) == 0) &&
	    (ic->ic_conn_flags & IDM_CONN_HEADER_DIGEST)) {
		hdr_digest_crc = idm_crc32c(pdu->isp_hdr, pdu->isp_hdrlen);

		iov[iovlen].iov_base	= (caddr_t)&hdr_digest_crc;
		iov[iovlen].iov_len	= sizeof (hdr_digest_crc);
		total_len		+= iov[iovlen].iov_len;
		iovlen++;
	}

	/* Setup the data */
	if (pdu->isp_datalen) {
		idm_task_t		*idt;
		idm_buf_t		*idb;
		iscsi_data_hdr_t	*ihp;
		ihp = (iscsi_data_hdr_t *)pdu->isp_hdr;
		/* Write of immediate data */
		if (ic->ic_ffp &&
		    (ihp->opcode == ISCSI_OP_SCSI_CMD ||
		    ihp->opcode == ISCSI_OP_SCSI_DATA)) {
			idt = idm_task_find(ic, ihp->itt, ihp->ttt);
			if (idt) {
				mutex_enter(&idt->idt_mutex);
				idb = idm_buf_find(&idt->idt_outbufv, 0);
				mutex_exit(&idt->idt_mutex);
				/*
				 * If the initiator call to idm_buf_alloc
				 * failed then we can get to this point
				 * without a bound buffer.  The associated
				 * connection failure will clean things up
				 * later.  It would be nice to come up with
				 * a cleaner way to handle this.  In
				 * particular it seems absurd to look up
				 * the task and the buffer just to update
				 * this counter.
				 */
				if (idb)
					idb->idb_xfer_len += pdu->isp_datalen;
				idm_task_rele(idt);
			}
		}

		iov[iovlen].iov_base = (caddr_t)pdu->isp_data;
		iov[iovlen].iov_len  = pdu->isp_datalen;
		total_len += iov[iovlen].iov_len;
		iovlen++;
	}

	/* Setup the data pad if necessary */
	pad_len = ((ISCSI_PAD_WORD_LEN -
	    (pdu->isp_datalen & (ISCSI_PAD_WORD_LEN - 1))) &
	    (ISCSI_PAD_WORD_LEN - 1));

	if (pad_len) {
		bzero(pad, sizeof (pad));
		iov[iovlen].iov_base = (void *)&pad;
		iov[iovlen].iov_len  = pad_len;
		total_len		+= iov[iovlen].iov_len;
		iovlen++;
	}

	/*
	 * Setup the data digest if enabled.  Data-digest is not sent
	 * for login-phase PDUs.
	 */
	if ((ic->ic_conn_flags & IDM_CONN_DATA_DIGEST) &&
	    ((pdu->isp_flags & IDM_PDU_LOGIN_TX) == 0) &&
	    (pdu->isp_datalen || pad_len)) {
		/*
		 * RFC3720/10.2.3: A zero-length Data Segment also
		 * implies a zero-length data digest.
		 */
		if (pdu->isp_datalen) {
			data_digest_crc = idm_crc32c(pdu->isp_data,
			    pdu->isp_datalen);
		}
		if (pad_len) {
			data_digest_crc = idm_crc32c_continued(&pad,
			    pad_len, data_digest_crc);
		}

		iov[iovlen].iov_base	= (caddr_t)&data_digest_crc;
		iov[iovlen].iov_len	= sizeof (data_digest_crc);
		total_len		+= iov[iovlen].iov_len;
		iovlen++;
	}

	/* Transmit the PDU */
	if (idm_iov_sosend(so_conn->ic_so, &iov[0], iovlen,
	    total_len) != 0) {
		/* Set error status */
		IDM_CONN_LOG(CE_WARN,
		    "idm_so_tx: failed to transmit the PDU, so: %p ic: %p "
		    "data: %p", (void *) so_conn->ic_so, (void *) ic,
		    (void *) pdu->isp_data);
		status = IDM_STATUS_IO;
	}

	/*
	 * Success does not mean that the PDU actually reached the
	 * remote node since it could get dropped along the way.
	 */
	idm_pdu_complete(pdu, status);

	return (status);
}

/*
 * The idm_so_buf_tx_to_ini() is used by the target iSCSI layer to transmit the
 * Data-In PDUs using sockets. Based on the negotiated MaxRecvDataSegmentLength,
 * the buffer is segmented into a sequence of Data-In PDUs, ordered by DataSN.
 * A target can invoke this function multiple times for a single read command
 * (identified by the same ITT) to split the input into several sequences.
 *
 * DataSN starts with 0 for the first data PDU of an input command and advances
 * by 1 for each subsequent data PDU. Each sequence will have its own F bit,
 * which is set to 1 for the last data PDU of a sequence.
 * If the initiator supports phase collapse, the status bit must be set along
 * with the F bit to indicate that the status is shipped together with the last
 * Data-In PDU.
 *
 * The data PDUs within a sequence will be sent in order with the buffer offset
 * in increasing order. i.e. initiator and target must have negotiated the
 * "DataPDUInOrder" to "Yes". The order between sequences is not enforced.
 *
 * Caller holds idt->idt_mutex
 */
static idm_status_t
idm_so_buf_tx_to_ini(idm_task_t *idt, idm_buf_t *idb)
{
	idm_so_conn_t	*so_conn = idb->idb_ic->ic_transport_private;
	idm_pdu_t	tmppdu;

	ASSERT(mutex_owned(&idt->idt_mutex));

	/*
	 * Put the idm_buf_t on the tx queue.  It will be transmitted by
	 * idm_sotx_thread.
	 */
	mutex_enter(&so_conn->ic_tx_mutex);

	DTRACE_ISCSI_8(xfer__start, idm_conn_t *, idt->idt_ic,
	    uintptr_t, idb->idb_buf, uint32_t, idb->idb_bufoffset,
	    uint64_t, 0, uint32_t, 0, uint32_t, 0,
	    uint32_t, idb->idb_xfer_len, int, XFER_BUF_TX_TO_INI);

	if (!so_conn->ic_tx_thread_running) {
		mutex_exit(&so_conn->ic_tx_mutex);
		/*
		 * Don't release idt->idt_mutex since we're supposed to hold
		 * in when calling idm_buf_tx_to_ini_done
		 */
		DTRACE_ISCSI_8(xfer__done, idm_conn_t *, idt->idt_ic,
		    uintptr_t, idb->idb_buf, uint32_t, idb->idb_bufoffset,
		    uint64_t, 0, uint32_t, 0, uint32_t, 0,
		    uint32_t, idb->idb_xfer_len,
		    int, XFER_BUF_TX_TO_INI);
		idm_buf_tx_to_ini_done(idt, idb, IDM_STATUS_ABORTED);
		return (IDM_STATUS_FAIL);
	}

	/*
	 * Build a template for the data PDU headers we will use so that
	 * the SN values will stay consistent with other PDU's we are
	 * transmitting like R2T and SCSI status.
	 */
	bzero(&idb->idb_data_hdr_tmpl, sizeof (iscsi_hdr_t));
	tmppdu.isp_hdr = &idb->idb_data_hdr_tmpl;
	(*idt->idt_ic->ic_conn_ops.icb_build_hdr)(idt, &tmppdu,
	    ISCSI_OP_SCSI_DATA_RSP);
	idb->idb_tx_thread = B_TRUE;
	list_insert_tail(&so_conn->ic_tx_list, (void *)idb);
	cv_signal(&so_conn->ic_tx_cv);
	mutex_exit(&so_conn->ic_tx_mutex);
	mutex_exit(&idt->idt_mutex);

	/*
	 * Returning success here indicates the transfer was successfully
	 * dispatched -- it does not mean that the transfer completed
	 * successfully.
	 */
	return (IDM_STATUS_SUCCESS);
}

/*
 * The idm_so_buf_rx_from_ini() is used by the target iSCSI layer to specify the
 * data blocks it is ready to receive from the initiator in response to a WRITE
 * SCSI command. The target iSCSI layer passes the information about the desired
 * data blocks to the initiator in one R2T PDU. The receiving buffer, the buffer
 * offset and datalen are passed via the 'idb' argument.
 *
 * Scope for Prototype build:
 * R2Ts are required for any Data-Out PDU, i.e. initiator and target must have
 * negotiated the "InitialR2T" to "Yes".
 *
 * Caller holds idt->idt_mutex
 */
static idm_status_t
idm_so_buf_rx_from_ini(idm_task_t *idt, idm_buf_t *idb)
{
	idm_pdu_t		*pdu;
	iscsi_rtt_hdr_t		*rtt;

	ASSERT(mutex_owned(&idt->idt_mutex));

	DTRACE_ISCSI_8(xfer__start, idm_conn_t *, idt->idt_ic,
	    uintptr_t, idb->idb_buf, uint32_t, idb->idb_bufoffset,
	    uint64_t, 0, uint32_t, 0, uint32_t, 0,
	    uint32_t, idb->idb_xfer_len, int, XFER_BUF_RX_FROM_INI);

	pdu = kmem_cache_alloc(idm.idm_sotx_pdu_cache, KM_SLEEP);
	pdu->isp_ic = idt->idt_ic;
	pdu->isp_flags = IDM_PDU_SET_STATSN;
	bzero(pdu->isp_hdr, sizeof (iscsi_rtt_hdr_t));

	/* iSCSI layer fills the TTT, ITT, ExpCmdSN, MaxCmdSN */
	(*idt->idt_ic->ic_conn_ops.icb_build_hdr)(idt, pdu, ISCSI_OP_RTT_RSP);

	/* set the rttsn, rtt.flags, rtt.data_offset and rtt.data_length */
	rtt = (iscsi_rtt_hdr_t *)(pdu->isp_hdr);

	rtt->opcode		= ISCSI_OP_RTT_RSP;
	rtt->flags		= ISCSI_FLAG_FINAL;
	rtt->data_offset	= htonl(idb->idb_bufoffset);
	rtt->data_length	= htonl(idb->idb_xfer_len);
	rtt->rttsn		= htonl(idt->idt_exp_rttsn++);

	/* Keep track of buffer offsets */
	idb->idb_exp_offset	= idb->idb_bufoffset;
	mutex_exit(&idt->idt_mutex);

	/*
	 * Transmit the PDU.
	 */
	idm_pdu_tx(pdu);

	return (IDM_STATUS_SUCCESS);
}

static idm_status_t
idm_so_buf_alloc(idm_buf_t *idb, uint64_t buflen)
{
	if ((buflen > IDM_SO_BUF_CACHE_LB) && (buflen <= IDM_SO_BUF_CACHE_UB)) {
		idb->idb_buf = kmem_cache_alloc(idm.idm_so_128k_buf_cache,
		    KM_NOSLEEP);
		idb->idb_buf_private = idm.idm_so_128k_buf_cache;
	} else {
		idb->idb_buf = kmem_alloc(buflen, KM_NOSLEEP);
		idb->idb_buf_private = NULL;
	}

	if (idb->idb_buf == NULL) {
		IDM_CONN_LOG(CE_NOTE,
		    "idm_so_buf_alloc: failed buffer allocation");
		return (IDM_STATUS_FAIL);
	}

	return (IDM_STATUS_SUCCESS);
}

/* ARGSUSED */
static idm_status_t
idm_so_buf_setup(idm_buf_t *idb)
{
	/* Ensure bufalloc'd flag is unset */
	idb->idb_bufalloc = B_FALSE;

	return (IDM_STATUS_SUCCESS);
}

/* ARGSUSED */
static void
idm_so_buf_teardown(idm_buf_t *idb)
{
	/* nothing to do here */
}

static void
idm_so_buf_free(idm_buf_t *idb)
{
	if (idb->idb_buf_private == NULL) {
		kmem_free(idb->idb_buf, idb->idb_buflen);
	} else {
		kmem_cache_free(idb->idb_buf_private, idb->idb_buf);
	}
}

static void
idm_so_send_rtt_data(idm_conn_t *ic, idm_task_t *idt, idm_buf_t *idb,
    uint32_t offset, uint32_t length)
{
	idm_so_conn_t	*so_conn = ic->ic_transport_private;
	idm_pdu_t	tmppdu;
	idm_buf_t	*rtt_buf;

	ASSERT(mutex_owned(&idt->idt_mutex));

	/*
	 * Allocate a buffer to represent the RTT transfer.  We could further
	 * optimize this by allocating the buffers internally from an rtt
	 * specific buffer cache since this is socket-specific code but for
	 * now we will keep it simple.
	 */
	rtt_buf = idm_buf_alloc(ic, (uint8_t *)idb->idb_buf + offset, length);
	if (rtt_buf == NULL) {
		/*
		 * If we're in FFP then the failure was likely a resource
		 * allocation issue and we should close the connection by
		 * sending a CE_TRANSPORT_FAIL event.
		 *
		 * If we're not in FFP then idm_buf_alloc will always
		 * fail and the state is transitioning to "complete" anyway
		 * so we won't bother to send an event.
		 */
		mutex_enter(&ic->ic_state_mutex);
		if (ic->ic_ffp)
			idm_conn_event_locked(ic, CE_TRANSPORT_FAIL,
			    NULL, CT_NONE);
		mutex_exit(&ic->ic_state_mutex);
		mutex_exit(&idt->idt_mutex);
		return;
	}

	rtt_buf->idb_buf_cb = NULL;
	rtt_buf->idb_cb_arg = NULL;
	rtt_buf->idb_bufoffset = offset;
	rtt_buf->idb_xfer_len = length;
	rtt_buf->idb_ic = idt->idt_ic;
	rtt_buf->idb_task_binding = idt;

	/*
	 * The new buffer (if any) represents an additional
	 * reference on the task
	 */
	idm_task_hold(idt);
	mutex_exit(&idt->idt_mutex);

	/*
	 * Put the idm_buf_t on the tx queue.  It will be transmitted by
	 * idm_sotx_thread.
	 */
	mutex_enter(&so_conn->ic_tx_mutex);

	if (!so_conn->ic_tx_thread_running) {
		idm_buf_free(rtt_buf);
		mutex_exit(&so_conn->ic_tx_mutex);
		idm_task_rele(idt);
		return;
	}

	/*
	 * Build a template for the data PDU headers we will use so that
	 * the SN values will stay consistent with other PDU's we are
	 * transmitting like R2T and SCSI status.
	 */
	bzero(&rtt_buf->idb_data_hdr_tmpl, sizeof (iscsi_hdr_t));
	tmppdu.isp_hdr = &rtt_buf->idb_data_hdr_tmpl;
	(*idt->idt_ic->ic_conn_ops.icb_build_hdr)(idt, &tmppdu,
	    ISCSI_OP_SCSI_DATA);
	rtt_buf->idb_tx_thread = B_TRUE;
	rtt_buf->idb_in_transport = B_TRUE;
	list_insert_tail(&so_conn->ic_tx_list, (void *)rtt_buf);
	cv_signal(&so_conn->ic_tx_cv);
	mutex_exit(&so_conn->ic_tx_mutex);
}

static void
idm_so_send_rtt_data_done(idm_task_t *idt, idm_buf_t *idb)
{
	/*
	 * Don't worry about status -- we assume any error handling
	 * is performed by the caller (idm_sotx_thread).
	 */
	idb->idb_in_transport = B_FALSE;
	idm_task_rele(idt);
	idm_buf_free(idb);
}

static idm_status_t
idm_so_send_buf_region(idm_task_t *idt, idm_buf_t *idb,
    uint32_t buf_region_offset, uint32_t buf_region_length)
{
	idm_conn_t		*ic;
	uint32_t		max_dataseglen;
	size_t			remainder, chunk;
	uint32_t		data_offset = buf_region_offset;
	iscsi_data_hdr_t	*bhs;
	idm_pdu_t		*pdu;
	idm_status_t		tx_status;

	ASSERT(mutex_owned(&idt->idt_mutex));

	ic = idt->idt_ic;

	max_dataseglen = ic->ic_conn_params.max_xmit_dataseglen;
	remainder = buf_region_length;

	while (remainder) {
		if (idt->idt_state != TASK_ACTIVE) {
			ASSERT((idt->idt_state != TASK_IDLE) &&
			    (idt->idt_state != TASK_COMPLETE));
			return (IDM_STATUS_ABORTED);
		}

		/* check to see if we need to chunk the data */
		if (remainder > max_dataseglen) {
			chunk = max_dataseglen;
		} else {
			chunk = remainder;
		}

		/* Data PDU headers will always be sizeof (iscsi_hdr_t) */
		pdu = kmem_cache_alloc(idm.idm_sotx_pdu_cache, KM_SLEEP);
		pdu->isp_ic = ic;
		pdu->isp_flags = 0;	/* initialize isp_flags */

		/*
		 * We've already built a build a header template
		 * to use during the transfer.  Use this template so that
		 * the SN values stay consistent with any unrelated PDU's
		 * being transmitted.
		 */
		bcopy(&idb->idb_data_hdr_tmpl, pdu->isp_hdr,
		    sizeof (iscsi_hdr_t));

		/*
		 * Set DataSN, data offset, and flags in BHS
		 * For the prototype build, A = 0, S = 0, U = 0
		 */
		bhs = (iscsi_data_hdr_t *)(pdu->isp_hdr);

		bhs->datasn		= htonl(idt->idt_exp_datasn++);

		hton24(bhs->dlength, chunk);
		bhs->offset = htonl(idb->idb_bufoffset + data_offset);

		/* setup data */
		pdu->isp_data	=  (uint8_t *)idb->idb_buf + data_offset;
		pdu->isp_datalen = (uint_t)chunk;

		if (chunk == remainder) {
			bhs->flags = ISCSI_FLAG_FINAL; /* F bit set to 1 */
			/* Piggyback the status with the last data PDU */
			if (idt->idt_flags & IDM_TASK_PHASECOLLAPSE_REQ) {
				pdu->isp_flags |= IDM_PDU_SET_STATSN |
				    IDM_PDU_ADVANCE_STATSN;
				(*idt->idt_ic->ic_conn_ops.icb_update_statsn)
				    (idt, pdu);
				idt->idt_flags |=
				    IDM_TASK_PHASECOLLAPSE_SUCCESS;

			}
		}

		remainder	-= chunk;
		data_offset	+= chunk;

		/* Instrument the data-send DTrace probe. */
		if (IDM_PDU_OPCODE(pdu) == ISCSI_OP_SCSI_DATA_RSP) {
			DTRACE_ISCSI_2(data__send,
			    idm_conn_t *, idt->idt_ic,
			    iscsi_data_rsp_hdr_t *,
			    (iscsi_data_rsp_hdr_t *)pdu->isp_hdr);
		}

		/*
		 * Now that we're done working with idt_exp_datasn,
		 * idt->idt_state and idb->idb_bufoffset we can release
		 * the task lock -- don't want to hold it across the
		 * call to idm_i_so_tx since we could block.
		 */
		mutex_exit(&idt->idt_mutex);

		/*
		 * Transmit the PDU.  Call the internal routine directly
		 * as there is already implicit ordering.
		 */
		if ((tx_status = idm_i_so_tx(pdu)) != IDM_STATUS_SUCCESS) {
			mutex_enter(&idt->idt_mutex);
			return (tx_status);
		}

		mutex_enter(&idt->idt_mutex);
		idt->idt_tx_bytes += chunk;
	}

	return (IDM_STATUS_SUCCESS);
}

/*
 * TX PDU cache
 */
/* ARGSUSED */
int
idm_sotx_pdu_constructor(void *hdl, void *arg, int flags)
{
	idm_pdu_t	*pdu = hdl;

	bzero(pdu, sizeof (idm_pdu_t));
	pdu->isp_hdr = (iscsi_hdr_t *)(pdu + 1); /* Ptr arithmetic */
	pdu->isp_hdrlen = sizeof (iscsi_hdr_t);
	pdu->isp_callback = idm_sotx_cache_pdu_cb;
	pdu->isp_magic = IDM_PDU_MAGIC;
	bzero(pdu->isp_hdr, sizeof (iscsi_hdr_t));

	return (0);
}

/* ARGSUSED */
void
idm_sotx_cache_pdu_cb(idm_pdu_t *pdu, idm_status_t status)
{
	/* reset values between use */
	pdu->isp_datalen = 0;

	kmem_cache_free(idm.idm_sotx_pdu_cache, pdu);
}

/*
 * RX PDU cache
 */
/* ARGSUSED */
int
idm_sorx_pdu_constructor(void *hdl, void *arg, int flags)
{
	idm_pdu_t	*pdu = hdl;

	bzero(pdu, sizeof (idm_pdu_t));
	pdu->isp_magic = IDM_PDU_MAGIC;
	pdu->isp_hdr = (iscsi_hdr_t *)(pdu + 1); /* Ptr arithmetic */
	pdu->isp_callback = idm_sorx_cache_pdu_cb;

	return (0);
}

/* ARGSUSED */
static void
idm_sorx_cache_pdu_cb(idm_pdu_t *pdu, idm_status_t status)
{
	pdu->isp_iovlen = 0;
	pdu->isp_sorx_buf = 0;
	kmem_cache_free(idm.idm_sorx_pdu_cache, pdu);
}

static void
idm_sorx_addl_pdu_cb(idm_pdu_t *pdu, idm_status_t status)
{
	/*
	 * We had to modify our cached RX PDU with a longer header buffer
	 * and/or a longer data buffer.  Release the new buffers and fix
	 * the fields back to what we would expect for a cached RX PDU.
	 */
	if (pdu->isp_flags & IDM_PDU_ADDL_HDR) {
		kmem_free(pdu->isp_hdr, pdu->isp_hdrlen);
	}
	if (pdu->isp_flags & IDM_PDU_ADDL_DATA) {
		kmem_free(pdu->isp_data, pdu->isp_datalen);
	}
	pdu->isp_hdr = (iscsi_hdr_t *)(pdu + 1);
	pdu->isp_hdrlen = sizeof (iscsi_hdr_t);
	pdu->isp_data = NULL;
	pdu->isp_datalen = 0;
	pdu->isp_sorx_buf = 0;
	pdu->isp_callback = idm_sorx_cache_pdu_cb;
	idm_sorx_cache_pdu_cb(pdu, status);
}

/*
 * This thread is only active when I/O is queued for transmit
 * because the socket is busy.
 */
void
idm_sotx_thread(void *arg)
{
	idm_conn_t	*ic = arg;
	idm_tx_obj_t	*object, *next;
	idm_so_conn_t	*so_conn;
	idm_status_t	status = IDM_STATUS_SUCCESS;

	idm_conn_hold(ic);

	mutex_enter(&ic->ic_mutex);
	so_conn = ic->ic_transport_private;
	so_conn->ic_tx_thread_running = B_TRUE;
	so_conn->ic_tx_thread_did = so_conn->ic_tx_thread->t_did;
	cv_signal(&ic->ic_cv);
	mutex_exit(&ic->ic_mutex);

	mutex_enter(&so_conn->ic_tx_mutex);

	while (so_conn->ic_tx_thread_running) {
		while (list_is_empty(&so_conn->ic_tx_list)) {
			DTRACE_PROBE1(soconn__tx__sleep, idm_conn_t *, ic);
			cv_wait(&so_conn->ic_tx_cv, &so_conn->ic_tx_mutex);
			DTRACE_PROBE1(soconn__tx__wakeup, idm_conn_t *, ic);

			if (!so_conn->ic_tx_thread_running) {
				goto tx_bail;
			}
		}

		object = (idm_tx_obj_t *)list_head(&so_conn->ic_tx_list);
		list_remove(&so_conn->ic_tx_list, object);
		mutex_exit(&so_conn->ic_tx_mutex);

		switch (object->idm_tx_obj_magic) {
		case IDM_PDU_MAGIC: {
			idm_pdu_t *pdu = (idm_pdu_t *)object;
			DTRACE_PROBE2(soconn__tx__pdu, idm_conn_t *, ic,
			    idm_pdu_t *, (idm_pdu_t *)object);

			if (pdu->isp_flags & IDM_PDU_SET_STATSN) {
				/* No IDM task */
				(ic->ic_conn_ops.icb_update_statsn)(NULL, pdu);
			}
			status = idm_i_so_tx((idm_pdu_t *)object);
			break;
		}
		case IDM_BUF_MAGIC: {
			idm_buf_t *idb = (idm_buf_t *)object;
			idm_task_t *idt = idb->idb_task_binding;

			DTRACE_PROBE2(soconn__tx__buf, idm_conn_t *, ic,
			    idm_buf_t *, idb);

			mutex_enter(&idt->idt_mutex);
			status = idm_so_send_buf_region(idt,
			    idb, 0, idb->idb_xfer_len);

			/*
			 * TX thread owns the buffer so we expect it to
			 * be "in transport"
			 */
			ASSERT(idb->idb_in_transport);
			if (IDM_CONN_ISTGT(ic)) {
				/*
				 * idm_buf_tx_to_ini_done releases
				 * idt->idt_mutex
				 */
				DTRACE_ISCSI_8(xfer__done,
				    idm_conn_t *, idt->idt_ic,
				    uintptr_t, idb->idb_buf,
				    uint32_t, idb->idb_bufoffset,
				    uint64_t, 0, uint32_t, 0, uint32_t, 0,
				    uint32_t, idb->idb_xfer_len,
				    int, XFER_BUF_TX_TO_INI);
				idm_buf_tx_to_ini_done(idt, idb, status);
			} else {
				idm_so_send_rtt_data_done(idt, idb);
				mutex_exit(&idt->idt_mutex);
			}
			break;
		}

		default:
			IDM_CONN_LOG(CE_WARN, "idm_sotx_thread: Unknown magic "
			    "(0x%08x)", object->idm_tx_obj_magic);
			status = IDM_STATUS_FAIL;
		}

		mutex_enter(&so_conn->ic_tx_mutex);

		if (status != IDM_STATUS_SUCCESS) {
			so_conn->ic_tx_thread_running = B_FALSE;
			idm_conn_event(ic, CE_TRANSPORT_FAIL, status);
		}
	}

	/*
	 * Before we leave, we need to abort every item remaining in the
	 * TX list.
	 */

tx_bail:
	object = (idm_tx_obj_t *)list_head(&so_conn->ic_tx_list);

	while (object != NULL) {
		next = list_next(&so_conn->ic_tx_list, object);

		list_remove(&so_conn->ic_tx_list, object);
		switch (object->idm_tx_obj_magic) {
		case IDM_PDU_MAGIC:
			idm_pdu_complete((idm_pdu_t *)object,
			    IDM_STATUS_ABORTED);
			break;

		case IDM_BUF_MAGIC: {
			idm_buf_t *idb = (idm_buf_t *)object;
			idm_task_t *idt = idb->idb_task_binding;
			mutex_exit(&so_conn->ic_tx_mutex);
			mutex_enter(&idt->idt_mutex);
			/*
			 * TX thread owns the buffer so we expect it to
			 * be "in transport"
			 */
			ASSERT(idb->idb_in_transport);
			if (IDM_CONN_ISTGT(ic)) {
				/*
				 * idm_buf_tx_to_ini_done releases
				 * idt->idt_mutex
				 */
				DTRACE_ISCSI_8(xfer__done,
				    idm_conn_t *, idt->idt_ic,
				    uintptr_t, idb->idb_buf,
				    uint32_t, idb->idb_bufoffset,
				    uint64_t, 0, uint32_t, 0, uint32_t, 0,
				    uint32_t, idb->idb_xfer_len,
				    int, XFER_BUF_TX_TO_INI);
				idm_buf_tx_to_ini_done(idt, idb,
				    IDM_STATUS_ABORTED);
			} else {
				idm_so_send_rtt_data_done(idt, idb);
				mutex_exit(&idt->idt_mutex);
			}
			mutex_enter(&so_conn->ic_tx_mutex);
			break;
		}
		default:
			IDM_CONN_LOG(CE_WARN,
			    "idm_sotx_thread: Unexpected magic "
			    "(0x%08x)", object->idm_tx_obj_magic);
		}

		object = next;
	}

	mutex_exit(&so_conn->ic_tx_mutex);
	idm_conn_rele(ic);
	thread_exit();
	/*NOTREACHED*/
}

static void
idm_so_socket_set_nonblock(struct sonode *node)
{
	(void) VOP_SETFL(node->so_vnode, node->so_flag,
	    (node->so_state | FNONBLOCK), CRED(), NULL);
}

static void
idm_so_socket_set_block(struct sonode *node)
{
	(void) VOP_SETFL(node->so_vnode, node->so_flag,
	    (node->so_state & (~FNONBLOCK)), CRED(), NULL);
}


/*
 * Called by kernel sockets when the connection has been accepted or
 * rejected. In early volo, a "disconnect" callback was sent instead of
 * "connectfailed", so we check for both.
 */
/* ARGSUSED */
void
idm_so_timed_socket_connect_cb(ksocket_t ks,
    ksocket_callback_event_t ev, void *arg, uintptr_t info)
{
	idm_so_timed_socket_t	*itp = arg;
	ASSERT(itp != NULL);
	ASSERT(ev == KSOCKET_EV_CONNECTED ||
	    ev == KSOCKET_EV_CONNECTFAILED ||
	    ev == KSOCKET_EV_DISCONNECTED);

	mutex_enter(&idm_so_timed_socket_mutex);
	itp->it_callback_called = B_TRUE;
	if (ev == KSOCKET_EV_CONNECTED) {
		itp->it_socket_error_code = 0;
	} else {
		/* Make sure the error code is non-zero on error */
		if (info == 0)
			info = ECONNRESET;
		itp->it_socket_error_code = (int)info;
	}
	cv_signal(&itp->it_cv);
	mutex_exit(&idm_so_timed_socket_mutex);
}

int
idm_so_timed_socket_connect(ksocket_t ks,
    struct sockaddr_storage *sa, int sa_sz, int login_max_usec)
{
	clock_t			conn_login_max;
	int			rc, nonblocking, rval;
	idm_so_timed_socket_t	it;
	ksocket_callbacks_t	ks_cb;

	conn_login_max = ddi_get_lbolt() + drv_usectohz(login_max_usec);

	/*
	 * Set to non-block socket mode, with callback on connect
	 * Early volo used "disconnected" instead of "connectfailed",
	 * so set callback to look for both.
	 */
	bzero(&it, sizeof (it));
	ks_cb.ksock_cb_flags = KSOCKET_CB_CONNECTED |
	    KSOCKET_CB_CONNECTFAILED | KSOCKET_CB_DISCONNECTED;
	ks_cb.ksock_cb_connected = idm_so_timed_socket_connect_cb;
	ks_cb.ksock_cb_connectfailed = idm_so_timed_socket_connect_cb;
	ks_cb.ksock_cb_disconnected = idm_so_timed_socket_connect_cb;
	cv_init(&it.it_cv, NULL, CV_DEFAULT, NULL);
	rc = ksocket_setcallbacks(ks, &ks_cb, &it, CRED());
	if (rc != 0)
		return (rc);

	/* Set to non-blocking mode */
	nonblocking = 1;
	rc = ksocket_ioctl(ks, FIONBIO, (intptr_t)&nonblocking, &rval,
	    CRED());
	if (rc != 0)
		goto cleanup;

	bzero(&it, sizeof (it));
	for (;;) {
		/*
		 * Warning -- in a loopback scenario, the call to
		 * the connect_cb can occur inside the call to
		 * ksocket_connect. Do not hold the mutex around the
		 * call to ksocket_connect.
		 */
		rc = ksocket_connect(ks, (struct sockaddr *)sa, sa_sz, CRED());
		if (rc == 0 || rc == EISCONN) {
			/* socket success or already success */
			rc = 0;
			break;
		}
		if ((rc != EINPROGRESS) && (rc != EALREADY)) {
			break;
		}

		/* TCP connect still in progress. See if out of time. */
		if (ddi_get_lbolt() > conn_login_max) {
			/*
			 * Connection retry timeout,
			 * failed connect to target.
			 */
			rc = ETIMEDOUT;
			break;
		}

		/*
		 * TCP connect still in progress.  Sleep until callback.
		 * Do NOT go to sleep if the callback already occurred!
		 */
		mutex_enter(&idm_so_timed_socket_mutex);
		if (!it.it_callback_called) {
			(void) cv_timedwait(&it.it_cv,
			    &idm_so_timed_socket_mutex, conn_login_max);
		}
		if (it.it_callback_called) {
			rc = it.it_socket_error_code;
			mutex_exit(&idm_so_timed_socket_mutex);
			break;
		}
		/* If timer expires, go call ksocket_connect one last time. */
		mutex_exit(&idm_so_timed_socket_mutex);
	}

	/* resume blocking mode */
	nonblocking = 0;
	(void) ksocket_ioctl(ks, FIONBIO, (intptr_t)&nonblocking, &rval,
	    CRED());
cleanup:
	(void) ksocket_setcallbacks(ks, NULL, NULL, CRED());
	cv_destroy(&it.it_cv);
	if (rc != 0) {
		idm_soshutdown(ks);
	}
	return (rc);
}


void
idm_addr_to_sa(idm_addr_t *dportal, struct sockaddr_storage *sa)
{
	int			dp_addr_size;
	struct sockaddr_in	*sin;
	struct sockaddr_in6	*sin6;

	/* Build sockaddr_storage for this portal (idm_addr_t) */
	bzero(sa, sizeof (*sa));
	dp_addr_size = dportal->a_addr.i_insize;
	if (dp_addr_size == sizeof (struct in_addr)) {
		/* IPv4 */
		sa->ss_family = AF_INET;
		sin = (struct sockaddr_in *)sa;
		sin->sin_port = htons(dportal->a_port);
		bcopy(&dportal->a_addr.i_addr.in4,
		    &sin->sin_addr, sizeof (struct in_addr));
	} else if (dp_addr_size == sizeof (struct in6_addr)) {
		/* IPv6 */
		sa->ss_family = AF_INET6;
		sin6 = (struct sockaddr_in6 *)sa;
		sin6->sin6_port = htons(dportal->a_port);
		bcopy(&dportal->a_addr.i_addr.in6,
		    &sin6->sin6_addr, sizeof (struct in6_addr));
	} else {
		ASSERT(0);
	}
}


/*
 * return a human-readable form of a sockaddr_storage, in the form
 * [ip-address]:port.  This is used in calls to logging functions.
 * If several calls to idm_sa_ntop are made within the same invocation
 * of a logging function, then each one needs its own buf.
 */
const char *
idm_sa_ntop(const struct sockaddr_storage *sa,
    char *buf, size_t size)
{
	static const char bogus_ip[] = "[0].-1";
	char tmp[INET6_ADDRSTRLEN];

	switch (sa->ss_family) {
	case AF_INET6: {
		const struct sockaddr_in6 *in6 =
		    (const struct sockaddr_in6 *) sa;

		(void) inet_ntop(in6->sin6_family, &in6->sin6_addr, tmp,
		    sizeof (tmp));
		if (strlen(tmp) + sizeof ("[].65535") > size)
			goto err;
		/* struct sockaddr_storage gets port info from v4 loc */
		(void) snprintf(buf, size, "[%s].%u", tmp,
		    ntohs(in6->sin6_port));
		return (buf);
	}
	case AF_INET: {
		const struct sockaddr_in *in = (const struct sockaddr_in *) sa;

		(void) inet_ntop(in->sin_family, &in->sin_addr, tmp,
		    sizeof (tmp));
		if (strlen(tmp) + sizeof ("[].65535") > size)
				goto err;
		(void) snprintf(buf, size,  "[%s].%u", tmp,
		    ntohs(in->sin_port));
		return (buf);
	}
	default:
		break;
	}
err:
	(void) snprintf(buf, size, "%s", bogus_ip);
	return (buf);
}
