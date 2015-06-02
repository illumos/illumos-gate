/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015, Joyent, Inc.
 */

/*
 * This plugin implements the SDC VXLAN Protocol (SVP).
 *
 * This plugin is designed to work with a broader distributed system that
 * mainains a database of mappings and provides a means of looking up data and
 * provides a stream of updates. While it is named after VXLAN, there isn't
 * anything specific to VXLAN baked into the protocol at this time, other than
 * that it requires both an IP address and a port; however, if there's a good
 * reason to support others here, we can modify that.
 *
 * -----------
 * Terminology
 * -----------
 *
 * Throughout this module we refer to a few different kinds of addresses:
 *
 *    VL3
 *
 * 	A VL3 address, or virtual layer 3, refers to the layer three addreses
 * 	that are used by entities on an overlay network. As far as we're
 * 	concerned that means that this is the IP address of an interface on an
 * 	overlay network.
 *
 *    VL2
 *
 *    	A VL2 address, or a virtual layer 2, referes to the link-layer addresses
 *    	that are used by entities on an overlay network. As far as we're
 *    	concerned that means that this is the MAC addresses of an interface on
 *    	an overlay network.
 *
 *    UL3
 *
 *    	A UL3, or underlay layer 3, refers to the layer three (IP) address on
 *    	the underlay network.
 *
 * The svp plugin provides lookups from VL3->VL2, eg. the equivalent of an ARP
 * or NDP query, and then also provides VL2->UL3 lookups.
 *
 * -------------------
 * Protocol Operations
 * -------------------
 *
 * The svp protocol is defined in lib/varpd/svp/common/libvarpd_svp_prot.h. It
 * defines the basic TCP protocol that we use to communicate to hosts. At this
 * time, it is not quite 100% implemented in both this plug-in and our primary
 * server, sdc-portolan (see https://github.com/joyent/sdc-portolan).
 *
 * At this time, we don't quite support everything that we need to. Including
 * the SVP_R_LOG_REQ, SVP_R_BULK_REQ, and SVP_R_SHOOTDOWN.
 *
 * ---------------------------------
 * General Design and Considerations
 * ---------------------------------
 *
 * Every instance of the svp plugin requires the hostname and port of a server
 * to contact. Though, we have co-opted the port 1296 (the year of the oldest
 * extant portolan) as our default port.
 *
 * Each of the different instance of the plugins has a corresponding remote
 * backend. The remote backend represents the tuple of the [ host, port ].
 * Different instances that share the same host and port tuple will use the same
 * backend.
 *
 * The backend is actually in charge of performing lookups, resolving and
 * updating the set of remote hosts based on the DNS resolution we've been
 * provided, and taking care of things like shootdowns.
 *
 * The whole plugin itself maintains an event loop and a number of threads to
 * service that event loop. On top of that event loop, we have a simple timer
 * backend that ticks at one second intervals and performs various callbacks,
 * such as idle query timers, DNS resolution, connection backoff, etc. Each of
 * the remote hosts that we obtain is wrapped up in an svp_conn_t, which manages
 * the connection state, reconnecting, etc.
 *
 * All in all, the general way that this all looks like is:
 *
 *  +----------------------------+
 *  | Plugin Instance            |
 *  | svp_t                      |
 *  |                            |
 *  | varpd_provider_handle_t * -+-> varpd handle
 *  | uint64_t               ----+-> varpd ID
 *  | char *                 ----+-> remote host
 *  | uint16_t               ----+-> remote port
 *  | svp_remote_t *   ---+------+-> remote backend
 *  +---------------------+------+
 *                        |
 *                        v
 *   +----------------------+                   +----------------+
 *   | Remote backend       |------------------>| Remove Backend |---> ...
 *   | svp_remote_t         |                   | svp_remote_t   |
 *   |                      |                   +----------------+
 *   | svp_remote_state_t --+-> state flags
 *   | svp_degrade_state_t -+-> degraded reason
 *   | struct addrinfo *  --+-> resolved hosts
 *   | uint_t            ---+-> active hosts
 *   | uint_t            ---+-> DNS generation
 *   | uint_t            ---+-> Reference count
 *   | uint_t            ---+-> active conns
 *   | uint_t            ---+-> degraded conns
 *   | list_t        ---+---+-> connection list
 *   +------------------+---+
 *                      |
 *                      +------------------------------+-----------------+
 *                      |                              |                 |
 *                      v                              v                 v
 *   +-------------------+                       +----------------
 *   | SVP Connection    |                       | SVP connection |     ...
 *   | svp_conn_t        |                       | svp_conn_t     |
 *   |                   |                       +----------------+
 *   | svp_event_t   ----+-> event loop handle
 *   | svp_timer_t   ----+-> backoff timer
 *   | svp_timer_t   ----+-> query timer
 *   | int           ----+-> socket fd
 *   | uint_t        ----+-> generation
 *   | uint_t        ----+-> current backoff
 *   | svp_conn_flags_t -+-> connection flags
 *   | svp_conn_state_t -+-> connection state
 *   | svp_conn_error_t -+-> connection error
 *   | int            ---+-> last errrno
 *   | hrtime_t       ---+-> activity timestamp
 *   | svp_conn_out_t ---+-> outgoing data state
 *   | svp_conn_in_t  ---+-> incoming data state
 *   | list_t      ---+--+-> active queries
 *   +----------------+--+
 *                    |
 *                    +----------------------------------+-----------------+
 *                    |                                  |                 |
 *                    v                                  v                 v
 *   +--------------------+                       +-------------+
 *   | SVP Query          |                       | SVP Query   |         ...
 *   | svp_query_t        |                       | svp_query_t |
 *   |                    |                       +-------------+
 *   | svp_query_f     ---+-> callback function
 *   | void *          ---+-> callback arg
 *   | svp_query_state_t -+-> state flags
 *   | svp_req_t       ---+-> svp prot. header
 *   | svp_query_data_t --+-> read data
 *   | svp_query_data_t --+-> write data
 *   | svp_status_t    ---+-> request status
 *   +--------------------+
 *
 * The svp_t is the instance that we assoicate with varpd. The instance itself
 * maintains properties and then when it's started associates with an
 * svp_remote_t, which is the remote backend. The remote backend itself,
 * maintains the DNS state and spins up and downs connections based on the
 * results from DNS. By default, we query DNS every 30 seconds. For more on the
 * connection life cycle, see the next section.
 *
 * By default, each connection maintains its own back off timer and list of
 * queries it's servicing. Only one request is generally outstanding at a time
 * and requests are round robined across the various connections.
 *
 * The query itself represents the svp request that's going on and keep track of
 * its state and is a place for data that's read and written to as part of the
 * request.
 *
 * Connections maintain a query timer such that if we have not received data on
 * a socket for a certain amount of time, we kill that socket and begin a
 * reconnection cycle with backoff.
 *
 * ------------------------
 * Connection State Machine
 * ------------------------
 *
 * We have a connection pool that's built upon DNS records. DNS describes the
 * membership of the set of remote peers that make up our pool and we maintain
 * one connection to each of them.  In addition, we maintain an exponential
 * backoff for each peer and will attempt to reconect immediately before backing
 * off. The following are the valid states that a connection can be in:
 *
 * 	SVP_CS_ERROR		An OS error has occurred on this connection,
 * 				such as failure to create a socket or associate
 * 				the socket with an event port. We also
 * 				transition all connections to this state before
 * 				we destroy them.
 *
 *	SVP_CS_INITIAL		This is the initial state of a connection, all
 *				that should exist is an unbound socket.
 *
 *	SVP_CS_CONNECTING	A call to connect has been made and we are
 *				polling for it to complete.
 *
 *	SVP_CS_BACKOFF		A connect attempt has failed and we are
 *				currently backing off, waiting to try again.
 *
 *	SVP_CS_ACTIVE		We have successfully connected to the remote
 *				system.
 *
 *	SVP_CS_WINDDOWN		This connection is going to valhalla. In other
 *				words, a previously active connection is no
 *				longer valid in DNS, so we should curb our use
 *				of it, and reap it as soon as we have other
 *				active connections.
 *
 * The following diagram attempts to describe our state transition scheme, and
 * when we transition from one state to the next.
 *
 *                               |
 *                               * New remote IP from DNS resolution,
 *                               | not currently active in the system.
 *                               |
 *                               v                                Socket Error,
 *                       +----------------+                       still in DNS
 *  +----------------<---| SVP_CS_INITIAL |<----------------------*-----+
 *  |                    +----------------+                             |
 *  |                            System  |                              |
 *  | Connection . . . . .       success *               Successful     |
 *  | failed             .               |               connect()      |
 *  |               +----*---------+     |        +-----------*--+      |
 *  |               |              |     |        |              |      |
 *  |               V              ^     v        ^              V      ^
 *  |  +----------------+         +-------------------+     +---------------+
 *  +<-| SVP_CS_BACKOFF |         | SVP_CS_CONNECTING |     | SVP_CS_ACTIVE |
 *  |  +----------------+         +-------------------+     +---------------+
 *  |               V              ^  V                       V  V
 *  | Backoff wait  *              |  |                       |  * Removed
 *  v interval      +--------------+  +-----------------<-----+  | from DNS
 *  | finished                        |                          |
 *  |                                 V                          |
 *  |                                 |                          V
 *  |                                 |            +-----------------+
 *  +----------------+----------<-----+-------<----| SVP_CS_WINDDOWN |
 *                   |                             +-----------------+
 *                   * . . .   Fatal system, not
 *                   |         socket error or
 *                   V         quiesced after
 *           +--------------+  removal from DNS
 *           | SVP_CS_ERROR |
 *           +--------------+
 *                   |
 *                   * . . . Removed from DNS
 *                   v
 *            +------------+
 *            | Connection |
 *            | Destroyed  |
 *            +------------+
 *
 * ------------
 * Notes on DNS
 * ------------
 *
 * Unfortunately, doing host name resolution in a way that allows us to leverage
 * the system's resolvers and the system's caching, require us to make blocking
 * calls in libc via getaddrinfo(3SOCKET). If we can't reach a given server,
 * that will tie up a thread for quite some time. To work around that fact,
 * we're going to create a fixed number of threads and we'll use them to service
 * our DNS requests. While this isn't ideal, until we have a sane means of
 * integrating a DNS resolution into an event loop with say portfs, it's not
 * going to be a fun day no matter what we do.
 *
 * ------
 * Timers
 * ------
 *
 * We maintain a single timer based on CLOCK_REALTIME. It's designed to fire
 * every second. While we'd rather use CLOCK_HIGHRES just to alleviate ourselves
 * from timer drift; however, as zones may not actually have CLOCK_HIGHRES
 * access, we don't want them to end up in there. The timer itself is just a
 * simple avl tree sorted by expiration time, which is stored as a tick in the
 * future, a tick is just one second.
 */

#include <umem.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libnvpair.h>
#include <strings.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include <libvarpd_provider.h>
#include "libvarpd_svp.h"

bunyan_logger_t *svp_bunyan;
static int svp_defport = 1296;
static int svp_defuport = 1339;
static umem_cache_t *svp_lookup_cache;

typedef enum svp_lookup_type {
	SVP_L_UNKNOWN	= 0x0,
	SVP_L_VL2	= 0x1,
	SVP_L_VL3	= 0x2
} svp_lookup_type_t;

typedef struct svp_lookup {
	int svl_type;
	union {
		struct svl_lookup_vl2 {
			varpd_query_handle_t	*svl_handle;
			overlay_target_point_t	*svl_point;
		} svl_vl2;
		struct svl_lookup_vl3 {
			varpd_arp_handle_t	*svl_vah;
			uint8_t			*svl_out;
		} svl_vl3;
	} svl_u;
	svp_query_t				svl_query;
} svp_lookup_t;

static const char *varpd_svp_props[] = {
	"svp/host",
	"svp/port",
	"svp/underlay_ip",
	"svp/underlay_port"
};

int
svp_comparator(const void *l, const void *r)
{
	const svp_t *ls = l;
	const svp_t *rs = r;

	if (ls->svp_vid > rs->svp_vid)
		return (1);
	if (ls->svp_vid < rs->svp_vid)
		return (-1);
	return (0);
}

static void
svp_vl2_lookup_cb(svp_t *svp, svp_status_t status, const struct in6_addr *uip,
    const uint16_t uport, void *arg)
{
	svp_lookup_t *svl = arg;
	overlay_target_point_t *otp;

	assert(svp != NULL);
	assert(arg != NULL);

	if (status != SVP_S_OK) {
		libvarpd_plugin_query_reply(svl->svl_u.svl_vl2.svl_handle,
		    VARPD_LOOKUP_DROP);
		umem_cache_free(svp_lookup_cache, svl);
		return;
	}

	otp = svl->svl_u.svl_vl2.svl_point;
	bcopy(uip, &otp->otp_ip, sizeof (struct in6_addr));
	otp->otp_port = uport;
	libvarpd_plugin_query_reply(svl->svl_u.svl_vl2.svl_handle,
	    VARPD_LOOKUP_OK);
	umem_cache_free(svp_lookup_cache, svl);
}

static void
svp_vl3_lookup_cb(svp_t *svp, svp_status_t status, const uint8_t *vl2mac,
    const struct in6_addr *uip, const uint16_t uport, void *arg)
{
	overlay_target_point_t point;
	svp_lookup_t *svl = arg;

	assert(svp != NULL);
	assert(svl != NULL);

	if (status != SVP_S_OK) {
		libvarpd_plugin_arp_reply(svl->svl_u.svl_vl3.svl_vah,
		    VARPD_LOOKUP_DROP);
		umem_cache_free(svp_lookup_cache, svl);
		return;
	}

	/* Inject the L2 mapping before the L3 */
	bcopy(uip, &point.otp_ip, sizeof (struct in6_addr));
	point.otp_port = uport;
	libvarpd_inject_varp(svp->svp_hdl, vl2mac, &point);

	bcopy(vl2mac, svl->svl_u.svl_vl3.svl_out, ETHERADDRL);
	libvarpd_plugin_arp_reply(svl->svl_u.svl_vl3.svl_vah,
	    VARPD_LOOKUP_OK);
	umem_cache_free(svp_lookup_cache, svl);
}

static void
svp_vl2_invalidate_cb(svp_t *svp, const uint8_t *vl2mac)
{
	libvarpd_inject_varp(svp->svp_hdl, vl2mac, NULL);
}

static void
svp_vl3_inject_cb(svp_t *svp, const uint16_t vlan, const struct in6_addr *vl3ip,
    const uint8_t *vl2mac, const uint8_t *targmac)
{
	struct in_addr v4;

	if (IN6_IS_ADDR_V4MAPPED(vl3ip) == 0)
		libvarpd_panic("implement libvarpd_inject_ndp");
	IN6_V4MAPPED_TO_INADDR(vl3ip, &v4);
	libvarpd_inject_arp(svp->svp_hdl, vlan, vl2mac, &v4, targmac);
}

/* ARGSUSED */
static void
svp_shootdown_cb(svp_t *svp, const uint8_t *vl2mac, const struct in6_addr *uip,
    const uint16_t uport)
{
	/*
	 * We should probably do a conditional invlaidation here.
	 */
	libvarpd_inject_varp(svp->svp_hdl, vl2mac, NULL);
}

static svp_cb_t svp_defops = {
	svp_vl2_lookup_cb,
	svp_vl3_lookup_cb,
	svp_vl2_invalidate_cb,
	svp_vl3_inject_cb,
	svp_shootdown_cb
};

static boolean_t
varpd_svp_valid_dest(overlay_plugin_dest_t dest)
{
	if (dest != (OVERLAY_PLUGIN_D_IP | OVERLAY_PLUGIN_D_PORT))
		return (B_FALSE);

	return (B_TRUE);
}

static int
varpd_svp_create(varpd_provider_handle_t *hdl, void **outp,
    overlay_plugin_dest_t dest)
{
	int ret;
	svp_t *svp;

	if (varpd_svp_valid_dest(dest) == B_FALSE)
		return (ENOTSUP);

	svp = umem_zalloc(sizeof (svp_t), UMEM_DEFAULT);
	if (svp == NULL)
		return (ENOMEM);

	if ((ret = mutex_init(&svp->svp_lock, USYNC_THREAD | LOCK_ERRORCHECK,
	    NULL)) != 0) {
		umem_free(svp, sizeof (svp_t));
		return (ret);
	}

	svp->svp_port = svp_defport;
	svp->svp_uport = svp_defuport;
	svp->svp_cb = svp_defops;
	svp->svp_hdl = hdl;
	svp->svp_vid = libvarpd_plugin_vnetid(svp->svp_hdl);
	*outp = svp;
	return (0);
}

static int
varpd_svp_start(void *arg)
{
	int ret;
	svp_remote_t *srp;
	svp_t *svp = arg;

	mutex_enter(&svp->svp_lock);
	if (svp->svp_host == NULL || svp->svp_port == 0 ||
	    svp->svp_huip == B_FALSE || svp->svp_uport == 0) {
		mutex_exit(&svp->svp_lock);
		return (EAGAIN);
	}
	mutex_exit(&svp->svp_lock);

	if ((ret = svp_remote_find(svp->svp_host, svp->svp_port, &srp)) != 0)
		return (ret);

	if ((ret = svp_remote_attach(srp, svp)) != 0) {
		svp_remote_release(srp);
		return (ret);
	}

	return (0);
}

static void
varpd_svp_stop(void *arg)
{
	svp_t *svp = arg;

	svp_remote_detach(svp);
}

static void
varpd_svp_destroy(void *arg)
{
	svp_t *svp = arg;

	if (svp->svp_host != NULL)
		umem_free(svp->svp_host, strlen(svp->svp_host) + 1);

	if (mutex_destroy(&svp->svp_lock) != 0)
		libvarpd_panic("failed to destroy svp_t`svp_lock");

	umem_free(svp, sizeof (svp_t));
}

static void
varpd_svp_lookup(void *arg, varpd_query_handle_t *vqh,
    const overlay_targ_lookup_t *otl, overlay_target_point_t *otp)
{
	svp_lookup_t *slp;
	svp_t *svp = arg;
	static const uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	/*
	 * Check if this is something that we need to proxy, eg. arp or ndp.
	 */
	if (otl->otl_sap == ETHERTYPE_ARP) {
		libvarpd_plugin_proxy_arp(svp->svp_hdl, vqh, otl);
		return;
	}

	if (otl->otl_dstaddr[0] == 0x33 &&
	    otl->otl_dstaddr[1] == 0x33) {
		if (otl->otl_sap == ETHERTYPE_IPV6) {
			libvarpd_plugin_proxy_ndp(svp->svp_hdl, vqh, otl);
		} else {
			libvarpd_plugin_query_reply(vqh, VARPD_LOOKUP_DROP);
		}
		return;
	}

	/*
	 * Watch out for various multicast and broadcast addresses. We've
	 * already taken care of the IPv6 range above. Now we just need to
	 * handle broadcast and if the multicast bit is set, lowest bit of the
	 * first octet of the MAC, then we drop it now.
	 */
	if (bcmp(otl->otl_dstaddr, bcast, ETHERADDRL) == 0 ||
	    (otl->otl_dstaddr[0] & 0x01) == 0x01) {
		libvarpd_plugin_query_reply(vqh, VARPD_LOOKUP_DROP);
		return;
	}

	/*
	 * If we have a failure to allocate memory for this, that's not good.
	 * However, telling the kernel to just drop this packet is much better
	 * than the alternative at this moment. At least we'll try again and we
	 * may have something more available to us in a little bit.
	 */
	slp = umem_cache_alloc(svp_lookup_cache, UMEM_DEFAULT);
	if (slp == NULL) {
		libvarpd_plugin_query_reply(vqh, VARPD_LOOKUP_DROP);
		return;
	}

	slp->svl_type = SVP_L_VL2;
	slp->svl_u.svl_vl2.svl_handle = vqh;
	slp->svl_u.svl_vl2.svl_point = otp;

	svp_remote_vl2_lookup(svp, &slp->svl_query, otl->otl_dstaddr, slp);
}

/* ARGSUSED */
static int
varpd_svp_nprops(void *arg, uint_t *nprops)
{
	*nprops = sizeof (varpd_svp_props) / sizeof (char *);
	return (0);
}

/* ARGSUSED */
static int
varpd_svp_propinfo(void *arg, uint_t propid, varpd_prop_handle_t *vph)
{
	switch (propid) {
	case 0:
		/* svp/host */
		libvarpd_prop_set_name(vph, varpd_svp_props[0]);
		libvarpd_prop_set_prot(vph, OVERLAY_PROP_PERM_RRW);
		libvarpd_prop_set_type(vph, OVERLAY_PROP_T_STRING);
		libvarpd_prop_set_nodefault(vph);
		break;
	case 1:
		/* svp/port */
		libvarpd_prop_set_name(vph, varpd_svp_props[1]);
		libvarpd_prop_set_prot(vph, OVERLAY_PROP_PERM_RRW);
		libvarpd_prop_set_type(vph, OVERLAY_PROP_T_UINT);
		(void) libvarpd_prop_set_default(vph, &svp_defport,
		    sizeof (svp_defport));
		libvarpd_prop_set_range_uint32(vph, 1, UINT16_MAX);
		break;
	case 2:
		/* svp/underlay_ip */
		libvarpd_prop_set_name(vph, varpd_svp_props[2]);
		libvarpd_prop_set_prot(vph, OVERLAY_PROP_PERM_RRW);
		libvarpd_prop_set_type(vph, OVERLAY_PROP_T_IP);
		libvarpd_prop_set_nodefault(vph);
		break;
	case 3:
		/* svp/underlay_port */
		libvarpd_prop_set_name(vph, varpd_svp_props[3]);
		libvarpd_prop_set_prot(vph, OVERLAY_PROP_PERM_RRW);
		libvarpd_prop_set_type(vph, OVERLAY_PROP_T_UINT);
		(void) libvarpd_prop_set_default(vph, &svp_defuport,
		    sizeof (svp_defuport));
		libvarpd_prop_set_range_uint32(vph, 1, UINT16_MAX);
		break;
	default:
		return (EINVAL);
	}
	return (0);
}

static int
varpd_svp_getprop(void *arg, const char *pname, void *buf, uint32_t *sizep)
{
	svp_t *svp = arg;

	/* svp/host */
	if (strcmp(pname, varpd_svp_props[0]) == 0) {
		size_t len;

		mutex_enter(&svp->svp_lock);
		if (svp->svp_host == NULL) {
			*sizep = 0;
		} else {
			len = strlen(svp->svp_host) + 1;
			if (*sizep < len) {
				mutex_exit(&svp->svp_lock);
				return (EOVERFLOW);
			}
			*sizep = len;
			(void) strlcpy(buf, svp->svp_host, *sizep);
		}
		mutex_exit(&svp->svp_lock);
		return (0);
	}

	/* svp/port */
	if (strcmp(pname, varpd_svp_props[1]) == 0) {
		uint64_t val;

		if (*sizep < sizeof (uint64_t))
			return (EOVERFLOW);

		mutex_enter(&svp->svp_lock);
		if (svp->svp_port == 0) {
			*sizep = 0;
		} else {
			val = svp->svp_port;
			bcopy(&val, buf, sizeof (uint64_t));
			*sizep = sizeof (uint64_t);
		}

		mutex_exit(&svp->svp_lock);
		return (0);
	}

	/* svp/underlay_ip */
	if (strcmp(pname, varpd_svp_props[2]) == 0) {
		if (*sizep > sizeof (struct in6_addr))
			return (EOVERFLOW);
		mutex_enter(&svp->svp_lock);
		if (svp->svp_huip == B_FALSE) {
			*sizep = 0;
		} else {
			bcopy(&svp->svp_uip, buf, sizeof (struct in6_addr));
			*sizep = sizeof (struct in6_addr);
		}
		return (0);
	}

	/* svp/underlay_port */
	if (strcmp(pname, varpd_svp_props[3]) == 0) {
		uint64_t val;

		if (*sizep < sizeof (uint64_t))
			return (EOVERFLOW);

		mutex_enter(&svp->svp_lock);
		if (svp->svp_uport == 0) {
			*sizep = 0;
		} else {
			val = svp->svp_uport;
			bcopy(&val, buf, sizeof (uint64_t));
			*sizep = sizeof (uint64_t);
		}

		mutex_exit(&svp->svp_lock);
		return (0);
	}

	return (EINVAL);
}

static int
varpd_svp_setprop(void *arg, const char *pname, const void *buf,
    const uint32_t size)
{
	svp_t *svp = arg;

	/* svp/host */
	if (strcmp(pname, varpd_svp_props[0]) == 0) {
		char *dup;
		dup = umem_alloc(size, UMEM_DEFAULT);
		(void) strlcpy(dup, buf, size);
		if (dup == NULL)
			return (ENOMEM);
		mutex_enter(&svp->svp_lock);
		if (svp->svp_host != NULL)
			umem_free(svp->svp_host, strlen(svp->svp_host) + 1);
		svp->svp_host = dup;
		mutex_exit(&svp->svp_lock);
		return (0);
	}

	/* svp/port */
	if (strcmp(pname, varpd_svp_props[1]) == 0) {
		const uint64_t *valp = buf;
		if (size < sizeof (uint64_t))
			return (EOVERFLOW);

		if (*valp == 0 || *valp > UINT16_MAX)
			return (EINVAL);

		mutex_enter(&svp->svp_lock);
		svp->svp_port = (uint16_t)*valp;
		mutex_exit(&svp->svp_lock);
		return (0);
	}

	/* svp/underlay_ip */
	if (strcmp(pname, varpd_svp_props[2]) == 0) {
		const struct in6_addr *ipv6 = buf;

		if (size < sizeof (struct in6_addr))
			return (EOVERFLOW);

		if (IN6_IS_ADDR_V4COMPAT(ipv6))
			return (EINVAL);

		if (IN6_IS_ADDR_MULTICAST(ipv6))
			return (EINVAL);

		if (IN6_IS_ADDR_6TO4(ipv6))
			return (EINVAL);

		if (IN6_IS_ADDR_V4MAPPED(ipv6)) {
			ipaddr_t v4;
			IN6_V4MAPPED_TO_IPADDR(ipv6, v4);
			if (IN_MULTICAST(v4))
				return (EINVAL);
		}

		mutex_enter(&svp->svp_lock);
		bcopy(buf, &svp->svp_uip, sizeof (struct in6_addr));
		svp->svp_huip = B_TRUE;
		mutex_exit(&svp->svp_lock);
		return (0);
	}

	/* svp/underlay_port */
	if (strcmp(pname, varpd_svp_props[3]) == 0) {
		const uint64_t *valp = buf;
		if (size < sizeof (uint64_t))
			return (EOVERFLOW);

		if (*valp == 0 || *valp > UINT16_MAX)
			return (EINVAL);

		mutex_enter(&svp->svp_lock);
		svp->svp_uport = (uint16_t)*valp;
		mutex_exit(&svp->svp_lock);

		return (0);
	}

	return (EINVAL);
}

static int
varpd_svp_save(void *arg, nvlist_t *nvp)
{
	int ret;
	svp_t *svp = arg;

	mutex_enter(&svp->svp_lock);
	if (svp->svp_host != NULL) {
		if ((ret = nvlist_add_string(nvp, varpd_svp_props[0],
		    svp->svp_host)) != 0) {
			mutex_exit(&svp->svp_lock);
			return (ret);
		}
	}

	if (svp->svp_port != 0) {
		if ((ret = nvlist_add_uint16(nvp, varpd_svp_props[1],
		    svp->svp_port)) != 0) {
			mutex_exit(&svp->svp_lock);
			return (ret);
		}
	}

	if (svp->svp_huip == B_TRUE) {
		char buf[INET6_ADDRSTRLEN];

		if (inet_ntop(AF_INET6, &svp->svp_uip, buf, sizeof (buf)) ==
		    NULL)
			libvarpd_panic("unexpected inet_ntop failure: %d",
			    errno);

		if ((ret = nvlist_add_string(nvp, varpd_svp_props[2],
		    buf)) != 0) {
			mutex_exit(&svp->svp_lock);
			return (ret);
		}
	}

	if (svp->svp_uport != 0) {
		if ((ret = nvlist_add_uint16(nvp, varpd_svp_props[3],
		    svp->svp_uport)) != 0) {
			mutex_exit(&svp->svp_lock);
			return (ret);
		}
	}

	mutex_exit(&svp->svp_lock);
	return (0);
}

static int
varpd_svp_restore(nvlist_t *nvp, varpd_provider_handle_t *hdl,
    overlay_plugin_dest_t dest, void **outp)
{
	int ret;
	svp_t *svp;
	char *ipstr, *hstr;

	if (varpd_svp_valid_dest(dest) == B_FALSE)
		return (ENOTSUP);

	if ((ret = varpd_svp_create(hdl, (void **)&svp, dest)) != 0)
		return (ret);

	if ((ret = nvlist_lookup_string(nvp, varpd_svp_props[0],
	    &hstr)) != 0) {
		if (ret != ENOENT) {
			varpd_svp_destroy(svp);
			return (ret);
		}
		svp->svp_host = NULL;
	} else {
		size_t blen = strlen(hstr) + 1;
		svp->svp_host = umem_alloc(blen, UMEM_DEFAULT);
		(void) strlcpy(svp->svp_host, hstr, blen);
	}

	if ((ret = nvlist_lookup_uint16(nvp, varpd_svp_props[1],
	    &svp->svp_port)) != 0) {
		if (ret != ENOENT) {
			varpd_svp_destroy(svp);
			return (ret);
		}
		svp->svp_port = 0;
	}

	if ((ret = nvlist_lookup_string(nvp, varpd_svp_props[2],
	    &ipstr)) != 0) {
		if (ret != ENOENT) {
			varpd_svp_destroy(svp);
			return (ret);
		}
		svp->svp_huip = B_FALSE;
	} else {
		ret = inet_pton(AF_INET6, ipstr, &svp->svp_uip);
		if (ret == -1) {
			assert(errno == EAFNOSUPPORT);
			libvarpd_panic("unexpected inet_pton failure: %d",
			    errno);
		}

		if (ret == 0) {
			varpd_svp_destroy(svp);
			return (EINVAL);
		}
		svp->svp_huip = B_TRUE;
	}

	if ((ret = nvlist_lookup_uint16(nvp, varpd_svp_props[3],
	    &svp->svp_uport)) != 0) {
		if (ret != ENOENT) {
			varpd_svp_destroy(svp);
			return (ret);
		}
		svp->svp_uport = 0;
	}

	svp->svp_hdl = hdl;
	*outp = svp;
	return (0);
}

static void
varpd_svp_arp(void *arg, varpd_arp_handle_t *vah, int type,
    const struct sockaddr *sock, uint8_t *out)
{
	svp_t *svp = arg;
	svp_lookup_t *svl;

	if (type != VARPD_QTYPE_ETHERNET) {
		libvarpd_plugin_arp_reply(vah, VARPD_LOOKUP_DROP);
		return;
	}

	svl = umem_cache_alloc(svp_lookup_cache, UMEM_DEFAULT);
	if (svl == NULL) {
		libvarpd_plugin_arp_reply(vah, VARPD_LOOKUP_DROP);
		return;
	}

	svl->svl_type = SVP_L_VL3;
	svl->svl_u.svl_vl3.svl_vah = vah;
	svl->svl_u.svl_vl3.svl_out = out;
	svp_remote_vl3_lookup(svp, &svl->svl_query, sock, svl);
}

static const varpd_plugin_ops_t varpd_svp_ops = {
	0,
	varpd_svp_create,
	varpd_svp_start,
	varpd_svp_stop,
	varpd_svp_destroy,
	NULL,
	varpd_svp_lookup,
	varpd_svp_nprops,
	varpd_svp_propinfo,
	varpd_svp_getprop,
	varpd_svp_setprop,
	varpd_svp_save,
	varpd_svp_restore,
	varpd_svp_arp,
	NULL
};

static int
svp_bunyan_init(void)
{
	int ret;

	if ((ret = bunyan_init("svp", &svp_bunyan)) != 0)
		return (ret);
	ret = bunyan_stream_add(svp_bunyan, "stderr", BUNYAN_L_INFO,
	    bunyan_stream_fd, (void *)STDERR_FILENO);
	if (ret != 0)
		bunyan_fini(svp_bunyan);
	return (ret);
}

static void
svp_bunyan_fini(void)
{
	if (svp_bunyan != NULL)
		bunyan_fini(svp_bunyan);
}

#pragma init(varpd_svp_init)
static void
varpd_svp_init(void)
{
	int err;
	varpd_plugin_register_t *vpr;

	if (svp_bunyan_init() != 0)
		return;

	if ((err = svp_host_init()) != 0) {
		(void) bunyan_error(svp_bunyan, "failed to init host subsystem",
		    BUNYAN_T_INT32, "error", err,
		    BUNYAN_T_END);
		svp_bunyan_fini();
		return;
	}

	svp_lookup_cache = umem_cache_create("svp_lookup",
	    sizeof (svp_lookup_t),  0, NULL, NULL, NULL, NULL, NULL, 0);
	if (svp_lookup_cache == NULL) {
		(void) bunyan_error(svp_bunyan,
		    "failed to create svp_lookup cache",
		    BUNYAN_T_INT32, "error", errno,
		    BUNYAN_T_END);
		svp_bunyan_fini();
		return;
	}

	if ((err = svp_event_init()) != 0) {
		(void) bunyan_error(svp_bunyan,
		    "failed to init event subsystem",
		    BUNYAN_T_INT32, "error", err,
		    BUNYAN_T_END);
		svp_bunyan_fini();
		umem_cache_destroy(svp_lookup_cache);
		return;
	}

	if ((err = svp_timer_init()) != 0) {
		(void) bunyan_error(svp_bunyan,
		    "failed to init timer subsystem",
		    BUNYAN_T_INT32, "error", err,
		    BUNYAN_T_END);
		svp_event_fini();
		umem_cache_destroy(svp_lookup_cache);
		svp_bunyan_fini();
		return;
	}

	if ((err = svp_remote_init()) != 0) {
		(void) bunyan_error(svp_bunyan,
		    "failed to init remote subsystem",
		    BUNYAN_T_INT32, "error", err,
		    BUNYAN_T_END);
		svp_event_fini();
		umem_cache_destroy(svp_lookup_cache);
		svp_bunyan_fini();
		return;
	}

	vpr = libvarpd_plugin_alloc(VARPD_CURRENT_VERSION, &err);
	if (vpr == NULL) {
		(void) bunyan_error(svp_bunyan,
		    "failed to alloc varpd plugin",
		    BUNYAN_T_INT32, "error", err,
		    BUNYAN_T_END);
		svp_remote_fini();
		svp_event_fini();
		umem_cache_destroy(svp_lookup_cache);
		svp_bunyan_fini();
		return;
	}

	vpr->vpr_mode = OVERLAY_TARGET_DYNAMIC;
	vpr->vpr_name = "svp";
	vpr->vpr_ops = &varpd_svp_ops;

	if ((err = libvarpd_plugin_register(vpr)) != 0) {
		(void) bunyan_error(svp_bunyan,
		    "failed to register varpd plugin",
		    BUNYAN_T_INT32, "error", err,
		    BUNYAN_T_END);
		svp_remote_fini();
		svp_event_fini();
		umem_cache_destroy(svp_lookup_cache);
		svp_bunyan_fini();

	}
	libvarpd_plugin_free(vpr);
}
