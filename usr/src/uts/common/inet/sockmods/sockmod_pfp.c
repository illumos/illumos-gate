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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015 Joyent, Inc. All rights reserved.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/stropts.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/socket_proto.h>
#include <sys/sockio.h>
#include <sys/strsun.h>
#include <sys/kstat.h>
#include <sys/modctl.h>
#include <sys/policy.h>
#include <sys/priv_const.h>
#include <sys/tihdr.h>
#include <sys/zone.h>
#include <sys/time.h>
#include <sys/ethernet.h>
#include <sys/llc1.h>
#include <fs/sockfs/sockcommon.h>
#include <net/if.h>
#include <inet/ip_arp.h>

#include <sys/dls.h>
#include <sys/mac.h>
#include <sys/mac_client.h>
#include <sys/mac_provider.h>
#include <sys/mac_client_priv.h>

#include <netpacket/packet.h>

static void pfp_close(mac_handle_t, mac_client_handle_t);
static int pfp_dl_to_arphrd(int);
static int pfp_getpacket_sockopt(sock_lower_handle_t, int, void *,
    socklen_t *);
static int pfp_ifreq_getlinkid(intptr_t, struct ifreq *, datalink_id_t *, int);
static int pfp_lifreq_getlinkid(intptr_t, struct lifreq *, datalink_id_t *,
    int);
static int pfp_open_index(int, mac_handle_t *, mac_client_handle_t *,
    cred_t *);
static void pfp_packet(void *, mac_resource_handle_t, mblk_t *, boolean_t);
static void pfp_release_bpf(struct pfpsock *);
static int pfp_set_promisc(struct pfpsock *, mac_client_promisc_type_t);
static int pfp_setsocket_sockopt(sock_lower_handle_t, int, const void *,
    socklen_t);
static int pfp_setpacket_sockopt(sock_lower_handle_t, int, const void *,
    socklen_t);

/*
 * PFP sockfs operations
 * Most are currently no-ops because they have no meaning for a connectionless
 * socket.
 */
static void sdpfp_activate(sock_lower_handle_t, sock_upper_handle_t,
    sock_upcalls_t *, int, struct cred *);
static int sdpfp_bind(sock_lower_handle_t, struct sockaddr *, socklen_t,
    struct cred *);
static int sdpfp_close(sock_lower_handle_t, int, struct cred *);
static void sdpfp_clr_flowctrl(sock_lower_handle_t);
static int sdpfp_getsockopt(sock_lower_handle_t, int, int, void *,
    socklen_t *, struct cred *);
static int sdpfp_ioctl(sock_lower_handle_t, int, intptr_t, int, int32_t *,
    struct cred *);
static int sdpfp_senduio(sock_lower_handle_t, struct uio *, struct nmsghdr *,
    struct cred *);
static int sdpfp_setsockopt(sock_lower_handle_t, int, int, const void *,
    socklen_t, struct cred *);

static sock_lower_handle_t sockpfp_create(int, int, int, sock_downcalls_t **,
    uint_t *, int *, int, cred_t *);

static int sockpfp_init(void);
static void sockpfp_fini(void);

static kstat_t *pfp_ksp;
static pfp_kstats_t ks_stats;
static pfp_kstats_t pfp_kstats = {
	/*
	 * Each one of these kstats is a different return path in handling
	 * a packet received from the mac layer.
	 */
	{ "recvMacHeaderFail",	KSTAT_DATA_UINT64 },
	{ "recvBadProtocol",	KSTAT_DATA_UINT64 },
	{ "recvAllocbFail",	KSTAT_DATA_UINT64 },
	{ "recvOk",		KSTAT_DATA_UINT64 },
	{ "recvFail",		KSTAT_DATA_UINT64 },
	{ "recvFiltered",	KSTAT_DATA_UINT64 },
	{ "recvFlowControl",	KSTAT_DATA_UINT64 },
	/*
	 * A global set of counters is maintained to track the behaviour
	 * of the system (kernel & applications) in sending packets.
	 */
	{ "sendUnbound",	KSTAT_DATA_UINT64 },
	{ "sendFailed",		KSTAT_DATA_UINT64 },
	{ "sendTooBig",		KSTAT_DATA_UINT64 },
	{ "sendAllocFail",	KSTAT_DATA_UINT64 },
	{ "sendUiomoveFail",	KSTAT_DATA_UINT64 },
	{ "sendNoMemory",	KSTAT_DATA_UINT64 },
	{ "sendOpenFail",	KSTAT_DATA_UINT64 },
	{ "sendWrongFamily",	KSTAT_DATA_UINT64 },
	{ "sendShortMsg",	KSTAT_DATA_UINT64 },
	{ "sendOk",		KSTAT_DATA_UINT64 }
};

sock_downcalls_t pfp_downcalls = {
	sdpfp_activate,
	sock_accept_notsupp,
	sdpfp_bind,
	sock_listen_notsupp,
	sock_connect_notsupp,
	sock_getpeername_notsupp,
	sock_getsockname_notsupp,
	sdpfp_getsockopt,
	sdpfp_setsockopt,
	sock_send_notsupp,
	sdpfp_senduio,
	NULL,
	sock_poll_notsupp,
	sock_shutdown_notsupp,
	sdpfp_clr_flowctrl,
	sdpfp_ioctl,
	sdpfp_close,
};

static smod_reg_t sinfo = {
	SOCKMOD_VERSION,
	"sockpfp",
	SOCK_UC_VERSION,
	SOCK_DC_VERSION,
	sockpfp_create,
	NULL
};

static int accepted_protos[3][2] = {
	{ ETH_P_ALL,	0 },
	{ ETH_P_802_2,	LLC_SNAP_SAP },
	{ ETH_P_803_3,	0 },
};

/*
 * This sets an upper bound on the size of the receive buffer for a PF_PACKET
 * socket. More properly, this should be controlled through ipadm, ala TCP, UDP,
 * SCTP, etc. Until that's done, this provides a hard cap of 4 MB and allows an
 * opportunity for it to be changed, should it be needed.
 */
int sockmod_pfp_rcvbuf_max = 1024 * 1024 * 4;

/*
 * Module linkage information for the kernel.
 */
static struct modlsockmod modlsockmod = {
	&mod_sockmodops, "PF Packet socket module", &sinfo
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modlsockmod,
	NULL
};

int
_init(void)
{
	int error;

	error = sockpfp_init();
	if (error != 0)
		return (error);

	error = mod_install(&modlinkage);
	if (error != 0)
		sockpfp_fini();

	return (error);
}

int
_fini(void)
{
	int error;

	error = mod_remove(&modlinkage);
	if (error == 0)
		sockpfp_fini();

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * sockpfp_init: called as part of the initialisation of the module when
 * loaded into the kernel.
 *
 * Being able to create and record the kstats data in the kernel is not
 * considered to be vital to the operation of this kernel module, thus
 * its failure is tolerated.
 */
static int
sockpfp_init(void)
{
	(void) memset(&ks_stats, 0, sizeof (ks_stats));

	(void) memcpy(&ks_stats, &pfp_kstats, sizeof (pfp_kstats));

	pfp_ksp = kstat_create("pfpacket", 0, "global", "misc",
	    KSTAT_TYPE_NAMED, sizeof (pfp_kstats) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);
	if (pfp_ksp != NULL) {
		pfp_ksp->ks_data = &ks_stats;
		kstat_install(pfp_ksp);
	}

	return (0);
}

/*
 * sockpfp_fini: called when the operating system wants to unload the
 * socket module from the kernel.
 */
static void
sockpfp_fini(void)
{
	if (pfp_ksp != NULL)
		kstat_delete(pfp_ksp);
}

/*
 * Due to sockets being created read-write by default, all PF_PACKET sockets
 * therefore require the NET_RAWACCESS priviliege, even if the socket is only
 * being used for reading packets from.
 *
 * This create function enforces this module only being used with PF_PACKET
 * sockets and the policy that we support via the config file in sock2path.d:
 * PF_PACKET sockets must be either SOCK_DGRAM or SOCK_RAW.
 */
/* ARGSUSED */
static sock_lower_handle_t
sockpfp_create(int family, int type, int proto,
    sock_downcalls_t **sock_downcalls, uint_t *smodep, int *errorp,
    int sflags, cred_t *cred)
{
	struct pfpsock *ps;
	int kmflags;
	int newproto;
	int i;

	if (secpolicy_net_rawaccess(cred) != 0) {
		*errorp = EACCES;
		return (NULL);
	}

	if (family != AF_PACKET) {
		*errorp = EAFNOSUPPORT;
		return (NULL);
	}

	if ((type != SOCK_RAW) && (type != SOCK_DGRAM)) {
		*errorp = ESOCKTNOSUPPORT;
		return (NULL);
	}

	/*
	 * First check to see if the protocol number passed in via the socket
	 * creation should be mapped to a different number for internal use.
	 */
	for (i = 0, newproto = -1;
	    i < sizeof (accepted_protos)/ sizeof (accepted_protos[0]); i++) {
		if (accepted_protos[i][0] == proto) {
			newproto = accepted_protos[i][1];
			break;
		}
	}

	/*
	 * If the mapping of the protocol that was under 0x800 failed to find
	 * a local equivalent then fail the socket creation. If the protocol
	 * for the socket is over 0x800 and it was not found in the mapping
	 * table above, then use the value as is.
	 */
	if (newproto == -1) {
		if (proto < 0x800) {
			*errorp = ENOPROTOOPT;
			return (NULL);
		}
		newproto = proto;
	}
	proto = newproto;

	kmflags = (sflags & SOCKET_NOSLEEP) ? KM_NOSLEEP : KM_SLEEP;
	ps = kmem_zalloc(sizeof (*ps), kmflags);
	if (ps == NULL) {
		*errorp = ENOMEM;
		return (NULL);
	}

	ps->ps_type = type;
	ps->ps_proto = proto;
	rw_init(&ps->ps_bpflock, NULL, RW_DRIVER, NULL);
	mutex_init(&ps->ps_lock, NULL, MUTEX_DRIVER, NULL);

	*sock_downcalls = &pfp_downcalls;
	/*
	 * Setting this causes bytes from a packet that do not fit into the
	 * destination user buffer to be discarded. Thus the API is one
	 * packet per receive and callers are required to use a buffer large
	 * enough for the biggest packet that the interface can provide.
	 */
	*smodep = SM_ATOMIC;

	return ((sock_lower_handle_t)ps);
}

/* ************************************************************************* */

/*
 * pfp_packet is the callback function that is given to the mac layer for
 * PF_PACKET to receive packets with. One packet at a time is passed into
 * this function from the mac layer. Each packet is a private copy given
 * to PF_PACKET to modify or free as it wishes and does not harm the original
 * packet from which it was cloned.
 */
/* ARGSUSED */
static void
pfp_packet(void *arg, mac_resource_handle_t mrh, mblk_t *mp, boolean_t flag)
{
	struct T_unitdata_ind *tunit;
	struct sockaddr_ll *sll;
	struct sockaddr_ll *sol;
	mac_header_info_t hdr;
	struct pfpsock *ps;
	size_t tusz;
	mblk_t *mp0;
	int error;

	if (mp == NULL)
		return;

	ps = arg;
	if (ps->ps_flow_ctrld) {
		ps->ps_flow_ctrl_drops++;
		ps->ps_stats.tp_drops++;
		ks_stats.kp_recv_flow_cntrld.value.ui64++;
		freemsg(mp);
		return;
	}

	if (mac_header_info(ps->ps_mh, mp, &hdr) != 0) {
		/*
		 * Can't decode the packet header information so drop it.
		 */
		ps->ps_stats.tp_drops++;
		ks_stats.kp_recv_mac_hdr_fail.value.ui64++;
		freemsg(mp);
		return;
	}

	if (mac_type(ps->ps_mh) == DL_ETHER &&
	    hdr.mhi_bindsap == ETHERTYPE_VLAN) {
		struct ether_vlan_header *evhp;
		struct ether_vlan_header evh;

		hdr.mhi_hdrsize = sizeof (struct ether_vlan_header);
		hdr.mhi_istagged = B_TRUE;

		if (MBLKL(mp) >= sizeof (*evhp)) {
			evhp = (struct ether_vlan_header *)mp->b_rptr;
		} else {
			int sz = sizeof (*evhp);
			char *s = (char *)&evh;
			mblk_t *tmp;
			int len;

			for (tmp = mp; sz > 0 && tmp != NULL;
			    tmp = tmp->b_cont) {
				len = min(sz, MBLKL(tmp));
				bcopy(tmp->b_rptr, s, len);
				sz -= len;
			}
			evhp = &evh;
		}
		hdr.mhi_tci = ntohs(evhp->ether_tci);
		hdr.mhi_bindsap = ntohs(evhp->ether_type);
	}

	if ((ps->ps_proto != 0) && (ps->ps_proto != hdr.mhi_bindsap)) {
		/*
		 * The packet is not of interest to this socket so
		 * drop it on the floor. Here the SAP is being used
		 * as a very course filter.
		 */
		ps->ps_stats.tp_drops++;
		ks_stats.kp_recv_bad_proto.value.ui64++;
		freemsg(mp);
		return;
	}

	/*
	 * This field is not often set, even for ethernet,
	 * by mac_header_info, so compute it if it is 0.
	 */
	if (hdr.mhi_pktsize == 0)
		hdr.mhi_pktsize = msgdsize(mp);

	/*
	 * If a BPF filter is present, pass the raw packet into that.
	 * A failed match will result in zero being returned, indicating
	 * that this socket is not interested in the packet.
	 */
	if (ps->ps_bpf.bf_len != 0) {
		uchar_t *buffer;
		int buflen;

		buflen = MBLKL(mp);
		if (hdr.mhi_pktsize == buflen) {
			buffer = mp->b_rptr;
		} else {
			buflen = 0;
			buffer = (uchar_t *)mp;
		}
		rw_enter(&ps->ps_bpflock, RW_READER);
		if (bpf_filter(ps->ps_bpf.bf_insns, buffer,
		    hdr.mhi_pktsize, buflen) == 0) {
			rw_exit(&ps->ps_bpflock);
			ps->ps_stats.tp_drops++;
			ks_stats.kp_recv_filtered.value.ui64++;
			freemsg(mp);
			return;
		}
		rw_exit(&ps->ps_bpflock);
	}

	if (ps->ps_type == SOCK_DGRAM) {
		/*
		 * SOCK_DGRAM socket expect a "layer 3" packet, so advance
		 * past the link layer header.
		 */
		mp->b_rptr += hdr.mhi_hdrsize;
		hdr.mhi_pktsize -= hdr.mhi_hdrsize;
	}

	tusz = sizeof (struct T_unitdata_ind) + sizeof (struct sockaddr_ll);
	if (ps->ps_auxdata) {
		tusz += _TPI_ALIGN_TOPT(sizeof (struct tpacket_auxdata));
		tusz += _TPI_ALIGN_TOPT(sizeof (struct T_opthdr));
	}

	/*
	 * It is tempting to think that this could be optimised by having
	 * the base mblk_t allocated and hung off the pfpsock structure,
	 * except that then another one would need to be allocated for the
	 * sockaddr_ll that is included. Even creating a template to copy
	 * from is of questionable value, as read-write from one structure
	 * to the other is going to be slower than all of the initialisation.
	 */
	mp0 = allocb(tusz, BPRI_HI);
	if (mp0 == NULL) {
		ps->ps_stats.tp_drops++;
		ks_stats.kp_recv_alloc_fail.value.ui64++;
		freemsg(mp);
		return;
	}

	(void) memset(mp0->b_rptr, 0, tusz);

	mp0->b_datap->db_type = M_PROTO;
	mp0->b_wptr = mp0->b_rptr + tusz;

	tunit = (struct T_unitdata_ind *)mp0->b_rptr;
	tunit->PRIM_type = T_UNITDATA_IND;
	tunit->SRC_length = sizeof (struct sockaddr);
	tunit->SRC_offset = sizeof (*tunit);

	sol = &ps->ps_sock;
	sll = (struct sockaddr_ll *)(mp0->b_rptr + sizeof (*tunit));
	sll->sll_ifindex = sol->sll_ifindex;
	sll->sll_hatype = (uint16_t)hdr.mhi_origsap;
	sll->sll_halen = sol->sll_halen;
	if (hdr.mhi_saddr != NULL)
		(void) memcpy(sll->sll_addr, hdr.mhi_saddr, sll->sll_halen);

	switch (hdr.mhi_dsttype) {
	case MAC_ADDRTYPE_MULTICAST :
		sll->sll_pkttype = PACKET_MULTICAST;
		break;
	case MAC_ADDRTYPE_BROADCAST :
		sll->sll_pkttype = PACKET_BROADCAST;
		break;
	case MAC_ADDRTYPE_UNICAST :
		if (memcmp(sol->sll_addr, hdr.mhi_daddr, sol->sll_halen) == 0)
			sll->sll_pkttype = PACKET_HOST;
		else
			sll->sll_pkttype = PACKET_OTHERHOST;
		break;
	}

	if (ps->ps_auxdata) {
		struct tpacket_auxdata *aux;
		struct T_opthdr *topt;

		tunit->OPT_offset = _TPI_ALIGN_TOPT(tunit->SRC_offset +
		    sizeof (struct sockaddr_ll));
		tunit->OPT_length = _TPI_ALIGN_TOPT(sizeof (struct T_opthdr)) +
		    _TPI_ALIGN_TOPT(sizeof (struct tpacket_auxdata));

		topt = (struct T_opthdr *)(mp0->b_rptr + tunit->OPT_offset);
		aux = (struct tpacket_auxdata *)
		    ((char *)topt + _TPI_ALIGN_TOPT(sizeof (*topt)));

		topt->len = tunit->OPT_length;
		topt->level = SOL_PACKET;
		topt->name = PACKET_AUXDATA;
		topt->status = 0;
		/*
		 * libpcap doesn't seem to use any other field,
		 * so it isn't clear how they should be filled in.
		 */
		aux->tp_vlan_vci = hdr.mhi_tci;
	}

	linkb(mp0, mp);

	(void) gethrestime(&ps->ps_timestamp);

	ps->ps_upcalls->su_recv(ps->ps_upper, mp0, hdr.mhi_pktsize, 0,
	    &error, NULL);

	if (error == 0) {
		ps->ps_stats.tp_packets++;
		ks_stats.kp_recv_ok.value.ui64++;
	} else {
		mutex_enter(&ps->ps_lock);
		if (error == ENOSPC) {
			ps->ps_upcalls->su_recv(ps->ps_upper, NULL, 0, 0,
			    &error, NULL);
			if (error == ENOSPC)
				ps->ps_flow_ctrld = B_TRUE;
		}
		mutex_exit(&ps->ps_lock);
		ps->ps_stats.tp_drops++;
		ks_stats.kp_recv_fail.value.ui64++;
	}
}

/*
 * Bind a PF_PACKET socket to a network interface.
 *
 * The default operation of this bind() is to place the socket (and thus the
 * network interface) into promiscuous mode. It is then up to the application
 * to turn that down by issuing the relevant ioctls, if desired.
 */
static int
sdpfp_bind(sock_lower_handle_t handle, struct sockaddr *addr,
    socklen_t addrlen, struct cred *cred)
{
	struct sockaddr_ll *addr_ll, *sol;
	mac_client_handle_t mch;
	struct pfpsock *ps;
	mac_handle_t mh;
	int error;

	ps = (struct pfpsock *)handle;
	if (ps->ps_bound)
		return (EINVAL);

	if (addrlen < sizeof (struct sockaddr_ll) || addr == NULL)
		return (EINVAL);

	addr_ll = (struct sockaddr_ll *)addr;

	error = pfp_open_index(addr_ll->sll_ifindex, &mh, &mch, cred);
	if (error != 0)
		return (error);
	/*
	 * Ensure that each socket is only bound once.
	 */
	mutex_enter(&ps->ps_lock);
	if (ps->ps_mh != 0) {
		mutex_exit(&ps->ps_lock);
		pfp_close(mh, mch);
		return (EADDRINUSE);
	}
	ps->ps_mh = mh;
	ps->ps_mch = mch;
	mutex_exit(&ps->ps_lock);

	/*
	 * Cache all of the information from bind so that it's in an easy
	 * place to get at when packets are received.
	 */
	sol = &ps->ps_sock;
	sol->sll_family = AF_PACKET;
	sol->sll_ifindex = addr_ll->sll_ifindex;
	sol->sll_protocol = addr_ll->sll_protocol;
	sol->sll_halen = mac_addr_len(ps->ps_mh);
	mac_unicast_primary_get(ps->ps_mh, sol->sll_addr);
	mac_sdu_get(ps->ps_mh, NULL, &ps->ps_max_sdu);
	ps->ps_linkid = addr_ll->sll_ifindex;

	error = mac_promisc_add(ps->ps_mch, MAC_CLIENT_PROMISC_ALL,
	    pfp_packet, ps, &ps->ps_phd, MAC_PROMISC_FLAGS_VLAN_TAG_STRIP);
	if (error == 0) {
		ps->ps_promisc = MAC_CLIENT_PROMISC_ALL;
		ps->ps_bound = B_TRUE;
	}

	return (error);
}

/* ARGSUSED */
static void
sdpfp_activate(sock_lower_handle_t lower, sock_upper_handle_t upper,
    sock_upcalls_t *upcalls, int flags, cred_t *cred)
{
	struct pfpsock *ps;

	ps = (struct pfpsock *)lower;
	ps->ps_upper = upper;
	ps->ps_upcalls = upcalls;
}

/*
 * This module only implements getting socket options for the new socket
 * option level (SOL_PACKET) that it introduces. All other requests are
 * passed back to the sockfs layer.
 */
/* ARGSUSED */
static int
sdpfp_getsockopt(sock_lower_handle_t handle, int level, int option_name,
    void *optval, socklen_t *optlenp, struct cred *cred)
{
	struct pfpsock *ps;
	int error = 0;

	ps = (struct pfpsock *)handle;

	switch (level) {
	case SOL_PACKET :
		error = pfp_getpacket_sockopt(handle, option_name, optval,
		    optlenp);
		break;

	case SOL_SOCKET :
		if (option_name == SO_RCVBUF) {
			if (*optlenp < sizeof (int32_t))
				return (EINVAL);
			*((int32_t *)optval) = ps->ps_rcvbuf;
			*optlenp = sizeof (int32_t);
		} else {
			error = ENOPROTOOPT;
		}
		break;

	default :
		/*
		 * If sockfs code receives this error in return from the
		 * getsockopt downcall it handles the option locally, if
		 * it can.
		 */
		error = ENOPROTOOPT;
		break;
	}

	return (error);
}

/*
 * PF_PACKET supports setting socket options at only two levels:
 * SOL_SOCKET and SOL_PACKET.
 */
/* ARGSUSED */
static int
sdpfp_setsockopt(sock_lower_handle_t handle, int level, int option_name,
    const void *optval, socklen_t optlen, struct cred *cred)
{
	int error = 0;

	switch (level) {
	case SOL_SOCKET :
		error = pfp_setsocket_sockopt(handle, option_name, optval,
		    optlen);
		break;
	case SOL_PACKET :
		error = pfp_setpacket_sockopt(handle, option_name, optval,
		    optlen);
		break;
	default :
		error = EINVAL;
		break;
	}

	return (error);
}

/*
 * This function is incredibly inefficient for sending any packet that
 * comes with a msghdr asking to be sent to an interface to which the
 * socket has not been bound. Some possibilities here are keeping a
 * cache of all open mac's and mac_client's, for the purpose of sending,
 * and closing them after some amount of inactivity. Clearly, applications
 * should not be written to use one socket for multiple interfaces if
 * performance is desired with the code as is.
 */
/* ARGSUSED */
static int
sdpfp_senduio(sock_lower_handle_t handle, struct uio *uiop,
    struct nmsghdr *msg, struct cred *cred)
{
	struct sockaddr_ll *sol;
	mac_client_handle_t mch;
	struct pfpsock *ps;
	boolean_t new_open;
	mac_handle_t mh;
	size_t mpsize;
	uint_t maxsdu;
	mblk_t *mp0;
	mblk_t *mp;
	int error;

	mp = NULL;
	mp0 = NULL;
	new_open = B_FALSE;
	ps = (struct pfpsock *)handle;
	mh = ps->ps_mh;
	mch = ps->ps_mch;
	maxsdu = ps->ps_max_sdu;

	sol = (struct sockaddr_ll *)msg->msg_name;
	if (sol == NULL) {
		/*
		 * If no sockaddr_ll has been provided with the send call,
		 * use the one constructed when the socket was bound to an
		 * interface and fail if it hasn't been bound.
		 */
		if (!ps->ps_bound) {
			ks_stats.kp_send_unbound.value.ui64++;
			return (EPROTO);
		}
		sol = &ps->ps_sock;
	} else {
		/*
		 * Verify the sockaddr_ll message passed down before using
		 * it to send a packet out with. If it refers to an interface
		 * that has not been bound, it is necessary to open it.
		 */
		struct sockaddr_ll *sll;

		if (msg->msg_namelen < sizeof (struct sockaddr_ll)) {
			ks_stats.kp_send_short_msg.value.ui64++;
			return (EINVAL);
		}

		if (sol->sll_family != AF_PACKET) {
			ks_stats.kp_send_wrong_family.value.ui64++;
			return (EAFNOSUPPORT);
		}

		sll = &ps->ps_sock;
		if (sol->sll_ifindex != sll->sll_ifindex) {
			error = pfp_open_index(sol->sll_ifindex, &mh, &mch,
			    cred);
			if (error != 0) {
				ks_stats.kp_send_open_fail.value.ui64++;
				return (error);
			}
			mac_sdu_get(mh, NULL, &maxsdu);
			new_open = B_TRUE;
		}
	}

	mpsize = uiop->uio_resid;
	if (mpsize > maxsdu) {
		ks_stats.kp_send_too_big.value.ui64++;
		error = EMSGSIZE;
		goto done;
	}

	if ((mp = allocb(mpsize, BPRI_HI)) == NULL) {
		ks_stats.kp_send_alloc_fail.value.ui64++;
		error = ENOBUFS;
		goto done;
	}

	mp->b_wptr = mp->b_rptr + mpsize;
	error = uiomove(mp->b_rptr, mpsize, UIO_WRITE, uiop);
	if (error != 0) {
		ks_stats.kp_send_uiomove_fail.value.ui64++;
		goto done;
	}

	if (ps->ps_type == SOCK_DGRAM) {
		mp0 = mac_header(mh, sol->sll_addr, sol->sll_protocol, mp, 0);
		if (mp0 == NULL) {
			ks_stats.kp_send_no_memory.value.ui64++;
			error = ENOBUFS;
			goto done;
		}
		linkb(mp0, mp);
		mp = mp0;
	}

	/*
	 * As this is sending datagrams and no promise is made about
	 * how or if a packet will be sent/delivered, no effort is to
	 * be expended in recovering from a situation where the packet
	 * cannot be sent - it is just dropped.
	 */
	error = mac_tx(mch, mp, 0, MAC_DROP_ON_NO_DESC, NULL);
	if (error == 0) {
		mp = NULL;
		ks_stats.kp_send_ok.value.ui64++;
	} else {
		ks_stats.kp_send_failed.value.ui64++;
	}

done:

	if (new_open) {
		ASSERT(mch != ps->ps_mch);
		ASSERT(mh != ps->ps_mh);
		pfp_close(mh, mch);
	}
	if (mp != NULL)
		freemsg(mp);

	return (error);

}

/*
 * There's no use of a lock here, or at the bottom of pfp_packet() where
 * ps_flow_ctrld is set to true, because in a situation where these two
 * are racing to set the flag one way or the other, the end result is
 * going to be ultimately determined by the scheduler anyway - which of
 * the two threads gets the lock first? In such an operational environment,
 * we've got packets arriving too fast to be delt with so packets are going
 * to be dropped. Grabbing a lock just makes the drop more expensive.
 */
static void
sdpfp_clr_flowctrl(sock_lower_handle_t handle)
{
	struct pfpsock *ps;

	ps = (struct pfpsock *)handle;

	mutex_enter(&ps->ps_lock);
	ps->ps_flow_ctrld = B_FALSE;
	mutex_exit(&ps->ps_lock);
}

/*
 * The implementation of this ioctl() handler is intended to function
 * in the absence of a bind() being made before it is called. Thus the
 * function calls mac_open() itself to provide a handle
 * This function is structured like this:
 * - determine the linkid for the interface being targetted
 * - open the interface with said linkid
 * - perform ioctl
 * - copy results back to caller
 *
 * The ioctls that interact with interface flags have been implented below
 * to assume that the interface is always up and running (IFF_RUNNING) and
 * to use the state of this socket to determine whether or not the network
 * interface is in promiscuous mode. Thus an ioctl to get the interface flags
 * of an interface that has been put in promiscuous mode by another socket
 * (in the same program or different), will not report that status.
 */
/* ARGSUSED */
static int
sdpfp_ioctl(sock_lower_handle_t handle, int cmd, intptr_t arg, int mod,
    int32_t *rval, struct cred *cr)
{
	struct timeval tival;
	mac_client_promisc_type_t mtype;
	struct sockaddr_dl *sock;
	datalink_id_t linkid;
	struct lifreq lifreq;
	struct ifreq ifreq;
	struct pfpsock *ps;
	mac_handle_t mh;
	int error;

	ps = (struct pfpsock *)handle;

	switch (cmd) {
	/*
	 * ioctls that work on "struct lifreq"
	 */
	case SIOCSLIFFLAGS :
	case SIOCGLIFINDEX :
	case SIOCGLIFFLAGS :
	case SIOCGLIFMTU :
	case SIOCGLIFHWADDR :
		error = pfp_lifreq_getlinkid(arg, &lifreq, &linkid, mod);
		if (error != 0)
			return (error);
		break;

	/*
	 * ioctls that work on "struct ifreq".
	 * Not all of these have a "struct lifreq" partner, for example
	 * SIOCGIFHWADDR, for the simple reason that the logical interface
	 * does not have a hardware address.
	 */
	case SIOCSIFFLAGS :
	case SIOCGIFINDEX :
	case SIOCGIFFLAGS :
	case SIOCGIFMTU :
	case SIOCGIFHWADDR :
		error = pfp_ifreq_getlinkid(arg, &ifreq, &linkid, mod);
		if (error != 0)
			return (error);
		break;

	case SIOCGSTAMP :
		tival.tv_sec = (time_t)ps->ps_timestamp.tv_sec;
		tival.tv_usec = ps->ps_timestamp.tv_nsec / 1000;
		if (get_udatamodel() == DATAMODEL_NATIVE) {
			error = ddi_copyout(&tival, (void *)arg,
			    sizeof (tival), mod);
		}
#ifdef _SYSCALL32_IMPL
		else {
			struct timeval32 tv32;
			TIMEVAL_TO_TIMEVAL32(&tv32, &tival);
			error = ddi_copyout(&tv32, (void *)arg,
			    sizeof (tv32), mod);
		}
#endif
		return (error);
	}

	error =  mac_open_by_linkid(linkid, &mh);
	if (error != 0)
		return (error);

	switch (cmd) {
	case SIOCGLIFINDEX :
		lifreq.lifr_index = linkid;
		break;

	case SIOCGIFINDEX :
		ifreq.ifr_index = linkid;
		break;

	case SIOCGIFFLAGS :
		ifreq.ifr_flags = IFF_RUNNING;
		if (ps->ps_promisc == MAC_CLIENT_PROMISC_ALL)
			ifreq.ifr_flags |= IFF_PROMISC;
		break;

	case SIOCGLIFFLAGS :
		lifreq.lifr_flags = IFF_RUNNING;
		if (ps->ps_promisc == MAC_CLIENT_PROMISC_ALL)
			lifreq.lifr_flags |= IFF_PROMISC;
		break;

	case SIOCSIFFLAGS :
		if (linkid != ps->ps_linkid) {
			error = EINVAL;
		} else {
			if ((ifreq.ifr_flags & IFF_PROMISC) != 0)
				mtype = MAC_CLIENT_PROMISC_ALL;
			else
				mtype = MAC_CLIENT_PROMISC_FILTERED;
			error = pfp_set_promisc(ps, mtype);
		}
		break;

	case SIOCSLIFFLAGS :
		if (linkid != ps->ps_linkid) {
			error = EINVAL;
		} else {
			if ((lifreq.lifr_flags & IFF_PROMISC) != 0)
				mtype = MAC_CLIENT_PROMISC_ALL;
			else
				mtype = MAC_CLIENT_PROMISC_FILTERED;
			error = pfp_set_promisc(ps, mtype);
		}
		break;

	case SIOCGIFMTU :
		mac_sdu_get(mh, NULL, &ifreq.ifr_mtu);
		break;

	case SIOCGLIFMTU :
		mac_sdu_get(mh, NULL, &lifreq.lifr_mtu);
		break;

	case SIOCGIFHWADDR :
		if (mac_addr_len(mh) > sizeof (ifreq.ifr_addr.sa_data)) {
			error = EPFNOSUPPORT;
			break;
		}

		if (mac_addr_len(mh) == 0) {
			(void) memset(ifreq.ifr_addr.sa_data, 0,
			    sizeof (ifreq.ifr_addr.sa_data));
		} else {
			mac_unicast_primary_get(mh,
			    (uint8_t *)ifreq.ifr_addr.sa_data);
		}

		/*
		 * The behaviour here in setting sa_family is consistent
		 * with what applications such as tcpdump would expect
		 * for a Linux PF_PACKET socket.
		 */
		ifreq.ifr_addr.sa_family = pfp_dl_to_arphrd(mac_type(mh));
		break;

	case SIOCGLIFHWADDR :
		lifreq.lifr_type = 0;
		sock = (struct sockaddr_dl *)&lifreq.lifr_addr;

		if (mac_addr_len(mh) > sizeof (sock->sdl_data)) {
			error = EPFNOSUPPORT;
			break;
		}

		/*
		 * Fill in the sockaddr_dl with link layer details. Of note,
		 * the index is returned as 0 for a couple of reasons:
		 * (1) there is no public API that uses or requires it
		 * (2) the MAC index is currently 32bits and sdl_index is 16.
		 */
		sock->sdl_family = AF_LINK;
		sock->sdl_index = 0;
		sock->sdl_type = mac_type(mh);
		sock->sdl_nlen = 0;
		sock->sdl_alen = mac_addr_len(mh);
		sock->sdl_slen = 0;
		if (mac_addr_len(mh) == 0) {
			(void) memset(sock->sdl_data, 0,
			    sizeof (sock->sdl_data));
		} else {
			mac_unicast_primary_get(mh, (uint8_t *)sock->sdl_data);
		}
		break;

	default :
		break;
	}

	mac_close(mh);

	if (error == 0) {
		/*
		 * Only the "GET" ioctls need to copy data back to userace.
		 */
		switch (cmd) {
		case SIOCGLIFINDEX :
		case SIOCGLIFFLAGS :
		case SIOCGLIFMTU :
		case SIOCGLIFHWADDR :
			error = ddi_copyout(&lifreq, (void *)arg,
			    sizeof (lifreq), mod);
			break;

		case SIOCGIFINDEX :
		case SIOCGIFFLAGS :
		case SIOCGIFMTU :
		case SIOCGIFHWADDR :
			error = ddi_copyout(&ifreq, (void *)arg,
			    sizeof (ifreq), mod);
			break;
		default :
			break;
		}
	}

	return (error);
}

/*
 * Closing the socket requires that all open references to network
 * interfaces be closed.
 */
/* ARGSUSED */
static int
sdpfp_close(sock_lower_handle_t handle, int flag, struct cred *cr)
{
	struct pfpsock *ps = (struct pfpsock *)handle;

	if (ps->ps_phd != 0) {
		mac_promisc_remove(ps->ps_phd);
		ps->ps_phd = 0;
	}

	if (ps->ps_mch != 0) {
		mac_client_close(ps->ps_mch, 0);
		ps->ps_mch = 0;
	}

	if (ps->ps_mh != 0) {
		mac_close(ps->ps_mh);
		ps->ps_mh = 0;
	}

	kmem_free(ps, sizeof (*ps));

	return (0);
}

/* ************************************************************************* */

/*
 * Given a pointer (arg) to a "struct ifreq" (potentially in user space),
 * determine the linkid for the interface name stored in that structure.
 * name is used as a buffer so that we can ensure a trailing \0 is appended
 * to the name safely.
 */
static int
pfp_ifreq_getlinkid(intptr_t arg, struct ifreq *ifreqp,
    datalink_id_t *linkidp, int mode)
{
	char name[IFNAMSIZ + 1];
	int error;

	if (ddi_copyin((void *)arg, ifreqp, sizeof (*ifreqp), mode) != 0)
		return (EFAULT);

	(void) strlcpy(name, ifreqp->ifr_name, sizeof (name));

	error = dls_mgmt_get_linkid(name, linkidp);
	if (error != 0)
		error = dls_devnet_macname2linkid(name, linkidp);

	return (error);
}

/*
 * Given a pointer (arg) to a "struct lifreq" (potentially in user space),
 * determine the linkid for the interface name stored in that structure.
 * name is used as a buffer so that we can ensure a trailing \0 is appended
 * to the name safely.
 */
static int
pfp_lifreq_getlinkid(intptr_t arg, struct lifreq *lifreqp,
    datalink_id_t *linkidp, int mode)
{
	char name[LIFNAMSIZ + 1];
	int error;

	if (ddi_copyin((void *)arg, lifreqp, sizeof (*lifreqp), mode) != 0)
		return (EFAULT);

	(void) strlcpy(name, lifreqp->lifr_name, sizeof (name));

	error = dls_mgmt_get_linkid(name, linkidp);
	if (error != 0)
		error = dls_devnet_macname2linkid(name, linkidp);

	return (error);
}

/*
 * Although there are several new SOL_PACKET options that can be set and
 * are specific to this implementation of PF_PACKET, the current API does
 * not support doing a get on them to retrieve accompanying status. Thus
 * it is only currently possible to use SOL_PACKET with getsockopt to
 * retrieve statistical information. This remains consistant with the
 * Linux API at the time of writing.
 */
static int
pfp_getpacket_sockopt(sock_lower_handle_t handle, int option_name,
    void *optval, socklen_t *optlenp)
{
	struct pfpsock *ps;
	struct tpacket_stats_short tpss;
	int error = 0;

	ps = (struct pfpsock *)handle;

	switch (option_name) {
	case PACKET_STATISTICS :
		if (*optlenp < sizeof (ps->ps_stats)) {
			error = EINVAL;
			break;
		}
		*optlenp = sizeof (ps->ps_stats);
		bcopy(&ps->ps_stats, optval, sizeof (ps->ps_stats));
		break;
	case PACKET_STATISTICS_SHORT :
		if (*optlenp < sizeof (tpss)) {
			error = EINVAL;
			break;
		}
		*optlenp = sizeof (tpss);
		tpss.tp_packets = ps->ps_stats.tp_packets;
		tpss.tp_drops = ps->ps_stats.tp_drops;
		bcopy(&tpss, optval, sizeof (tpss));
		break;
	default :
		error = EINVAL;
		break;
	}

	return (error);
}

/*
 * The SOL_PACKET level for socket options supports three options,
 * PACKET_ADD_MEMBERSHIP, PACKET_DROP_MEMBERSHIP and PACKET_AUXDATA.
 * This function is responsible for mapping the two socket options
 * that manage multicast membership into the appropriate internal
 * function calls to bring the option into effect. Whilst direct
 * changes to the multicast membership (ADD/DROP) groups is handled
 * by calls directly into the mac module, changes to the promiscuos
 * mode are vectored through pfp_set_promisc() so that the logic for
 * managing the promiscuous mode is in one place.
 */
/* ARGSUSED */
static int
pfp_setpacket_sockopt(sock_lower_handle_t handle, int option_name,
    const void *optval, socklen_t optlen)
{
	struct packet_mreq mreq;
	struct pfpsock *ps;
	int error = 0;
	int opt;

	ps = (struct pfpsock *)handle;
	if (!ps->ps_bound)
		return (EPROTO);

	if ((option_name == PACKET_ADD_MEMBERSHIP) ||
	    (option_name == PACKET_DROP_MEMBERSHIP)) {
		if (!ps->ps_bound)
			return (EPROTO);
		bcopy(optval, &mreq, sizeof (mreq));
		if (ps->ps_linkid != mreq.mr_ifindex)
			return (EINVAL);
	}

	switch (option_name) {
	case PACKET_ADD_MEMBERSHIP :
		switch (mreq.mr_type) {
		case PACKET_MR_MULTICAST :
			if (mreq.mr_alen != ps->ps_sock.sll_halen)
				return (EINVAL);

			error = mac_multicast_add(ps->ps_mch, mreq.mr_address);
			break;

		case PACKET_MR_PROMISC :
			error = pfp_set_promisc(ps, MAC_CLIENT_PROMISC_ALL);
			break;

		case PACKET_MR_ALLMULTI :
			error = pfp_set_promisc(ps, MAC_CLIENT_PROMISC_MULTI);
			break;
		}
		break;

	case PACKET_DROP_MEMBERSHIP :
		switch (mreq.mr_type) {
		case PACKET_MR_MULTICAST :
			if (mreq.mr_alen != ps->ps_sock.sll_halen)
				return (EINVAL);

			mac_multicast_remove(ps->ps_mch, mreq.mr_address);
			break;

		case PACKET_MR_PROMISC :
			if (ps->ps_promisc != MAC_CLIENT_PROMISC_ALL)
				return (EINVAL);
			error = pfp_set_promisc(ps,
			    MAC_CLIENT_PROMISC_FILTERED);
			break;

		case PACKET_MR_ALLMULTI :
			if (ps->ps_promisc != MAC_CLIENT_PROMISC_MULTI)
				return (EINVAL);
			error = pfp_set_promisc(ps,
			    MAC_CLIENT_PROMISC_FILTERED);
			break;
		}
		break;

	case PACKET_AUXDATA :
		if (optlen == sizeof (int)) {
			opt = *(int *)optval;
			ps->ps_auxdata = (opt != 0);
		} else {
			error = EINVAL;
		}
		break;
	default :
		error = EINVAL;
		break;
	}

	return (error);
}

/*
 * There are only two special setsockopt's for SOL_SOCKET with PF_PACKET:
 * SO_ATTACH_FILTER and SO_DETACH_FILTER.
 *
 * Both of these setsockopt values are candidates for being handled by the
 * socket layer itself in future, however this requires understanding how
 * they would interact with all other sockets.
 */
static int
pfp_setsocket_sockopt(sock_lower_handle_t handle, int option_name,
    const void *optval, socklen_t optlen)
{
	struct bpf_program prog;
	struct bpf_insn *fcode;
	struct pfpsock *ps;
	struct sock_proto_props sopp;
	int error = 0;
	int size;

	ps = (struct pfpsock *)handle;

	switch (option_name) {
	case SO_ATTACH_FILTER :
#ifdef _LP64
		if (optlen == sizeof (struct bpf_program32)) {
			struct bpf_program32 prog32;

			bcopy(optval, &prog32, sizeof (prog32));
			prog.bf_len = prog32.bf_len;
			prog.bf_insns = (void *)(uint64_t)prog32.bf_insns;
		} else
#endif
		if (optlen == sizeof (struct bpf_program)) {
			bcopy(optval, &prog, sizeof (prog));
		} else if (optlen != sizeof (struct bpf_program)) {
			return (EINVAL);
		}
		if (prog.bf_len > BPF_MAXINSNS)
			return (EINVAL);

		size = prog.bf_len * sizeof (*prog.bf_insns);
		fcode = kmem_alloc(size, KM_SLEEP);
		if (ddi_copyin(prog.bf_insns, fcode, size, 0) != 0) {
			kmem_free(fcode, size);
			return (EFAULT);
		}

		if (bpf_validate(fcode, (int)prog.bf_len)) {
			rw_enter(&ps->ps_bpflock, RW_WRITER);
			pfp_release_bpf(ps);
			ps->ps_bpf.bf_insns = fcode;
			ps->ps_bpf.bf_len = size;
			rw_exit(&ps->ps_bpflock);

			return (0);
		}
		kmem_free(fcode, size);
		error = EINVAL;
		break;

	case SO_DETACH_FILTER :
		pfp_release_bpf(ps);
		break;

	case SO_RCVBUF :
		size = *(int32_t *)optval;
		if (size > sockmod_pfp_rcvbuf_max || size < 0)
			return (ENOBUFS);
		sopp.sopp_flags = SOCKOPT_RCVHIWAT;
		sopp.sopp_rxhiwat = size;
		ps->ps_upcalls->su_set_proto_props(ps->ps_upper, &sopp);
		ps->ps_rcvbuf = size;
		break;

	default :
		error = ENOPROTOOPT;
		break;
	}

	return (error);
}

/*
 * pfp_open_index is an internal function used to open a MAC device by
 * its index. Both a mac_handle_t and mac_client_handle_t are acquired
 * because some of the interfaces provided by the mac layer require either
 * only the mac_handle_t or both it and mac_handle_t.
 *
 * Whilst inside the kernel we can access data structures supporting any
 * zone, access to interfaces from non-global zones is restricted to those
 * interfaces (if any) that are exclusively assigned to a zone.
 */
static int
pfp_open_index(int index, mac_handle_t *mhp, mac_client_handle_t *mcip,
    cred_t *cred)
{
	mac_client_handle_t mch;
	zoneid_t ifzoneid;
	mac_handle_t mh;
	zoneid_t zoneid;
	int error;

	mh = 0;
	mch = 0;
	error = mac_open_by_linkid(index, &mh);
	if (error != 0)
		goto bad_open;

	error = mac_client_open(mh, &mch, NULL,
	    MAC_OPEN_FLAGS_USE_DATALINK_NAME);
	if (error != 0)
		goto bad_open;

	zoneid = crgetzoneid(cred);
	if (zoneid != GLOBAL_ZONEID) {
		mac_perim_handle_t perim;

		mac_perim_enter_by_mh(mh, &perim);
		error = dls_link_getzid(mac_name(mh), &ifzoneid);
		mac_perim_exit(perim);
		if (error != 0)
			goto bad_open;
		if (ifzoneid != zoneid) {
			error = EACCES;
			goto bad_open;
		}
	}

	*mcip = mch;
	*mhp = mh;

	return (0);
bad_open:
	if (mch != 0)
		mac_client_close(mch, 0);
	if (mh != 0)
		mac_close(mh);
	return (error);
}

static void
pfp_close(mac_handle_t mh, mac_client_handle_t mch)
{
	mac_client_close(mch, 0);
	mac_close(mh);
}

/*
 * The purpose of this function is to provide a single place where we free
 * the loaded BPF program and reset all pointers/counters associated with
 * it.
 */
static void
pfp_release_bpf(struct pfpsock *ps)
{
	if (ps->ps_bpf.bf_len != 0) {
		kmem_free(ps->ps_bpf.bf_insns, ps->ps_bpf.bf_len);
		ps->ps_bpf.bf_len = 0;
		ps->ps_bpf.bf_insns = NULL;
	}
}

/*
 * Set the promiscuous mode of a network interface.
 * This function only calls the mac layer when there is a change to the
 * status of a network interface's promiscous mode. Tracking of how many
 * sockets have the network interface in promiscuous mode, and thus the
 * control over the physical device's status, is left to the mac layer.
 */
static int
pfp_set_promisc(struct pfpsock *ps, mac_client_promisc_type_t turnon)
{
	int error = 0;
	int flags;

	/*
	 * There are 4 combinations of turnon/ps_promisc.
	 * This if handles 2 (both false, both true) and the if() below
	 * handles the remaining one - when change is required.
	 */
	if (turnon == ps->ps_promisc)
		return (error);

	if (ps->ps_phd != 0) {
		mac_promisc_remove(ps->ps_phd);
		ps->ps_phd = 0;

		/*
		 * ps_promisc is set here in case the call to mac_promisc_add
		 * fails: leaving it to indicate that the interface is still
		 * in some sort of promiscuous mode is false.
		 */
		if (ps->ps_promisc != MAC_CLIENT_PROMISC_FILTERED) {
			ps->ps_promisc = MAC_CLIENT_PROMISC_FILTERED;
			flags = MAC_PROMISC_FLAGS_NO_PHYS;
		} else {
			flags = 0;
		}
		flags |= MAC_PROMISC_FLAGS_VLAN_TAG_STRIP;
	}

	error = mac_promisc_add(ps->ps_mch, turnon, pfp_packet, ps,
	    &ps->ps_phd, flags);
	if (error == 0)
		ps->ps_promisc = turnon;

	return (error);
}

/*
 * This table maps the MAC types in Solaris to the ARPHRD_* values used
 * on Linux. This is used with the SIOCGIFHWADDR/SIOCGLIFHWADDR ioctl.
 *
 * The symbols in this table are *not* pulled in from <net/if_arp.h>,
 * they are pulled from <netpacket/packet.h>, thus it acts as a source
 * of supplementary information to the ARP table.
 */
static uint_t arphrd_to_dl[][2] = {
	{ ARPHRD_IEEE80211,	DL_WIFI },
	{ ARPHRD_TUNNEL,	DL_IPV4 },
	{ ARPHRD_TUNNEL,	DL_IPV6 },
	{ ARPHRD_TUNNEL,	DL_6TO4 },
	{ ARPHRD_AX25,		DL_X25 },
	{ ARPHRD_ATM,		DL_ATM },
	{ 0,			0 }
};

static int
pfp_dl_to_arphrd(int dltype)
{
	int i;

	for (i = 0; arphrd_to_dl[i][0] != 0; i++)
		if (arphrd_to_dl[i][1] == dltype)
			return (arphrd_to_dl[i][0]);
	return (arp_hw_type(dltype));
}
