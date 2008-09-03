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

#include <sys/socket.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/tsol/tndb.h>
#include <sys/tsol/tnet.h>

#include <netinet/in.h>
#include <netinet/ip6.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/ipclassifier.h>
#include <inet/ipsec_impl.h>
#include <inet/ipp_common.h>
#include <inet/sctp_ip.h>

#include "sctp_impl.h"
#include "sctp_addr.h"

/* Default association hash size.  The size must be a power of 2. */
#define	SCTP_CONN_HASH_SIZE	8192

uint_t		sctp_conn_hash_size = SCTP_CONN_HASH_SIZE; /* /etc/system */

/*
 * Cluster networking hook for traversing current assoc list.
 * This routine is used to extract the current list of live associations
 * which must continue to to be dispatched to this node.
 */
int cl_sctp_walk_list(int (*cl_callback)(cl_sctp_info_t *, void *), void *,
    boolean_t);
static int cl_sctp_walk_list_stack(int (*cl_callback)(cl_sctp_info_t *,
    void *), void *arg, boolean_t cansleep, sctp_stack_t *sctps);

void
sctp_hash_init(sctp_stack_t *sctps)
{
	int i;

	/* Start with /etc/system value */
	sctps->sctps_conn_hash_size = sctp_conn_hash_size;

	if (sctps->sctps_conn_hash_size & (sctps->sctps_conn_hash_size - 1)) {
		/* Not a power of two. Round up to nearest power of two */
		for (i = 0; i < 31; i++) {
			if (sctps->sctps_conn_hash_size < (1 << i))
				break;
		}
		sctps->sctps_conn_hash_size = 1 << i;
	}
	if (sctps->sctps_conn_hash_size < SCTP_CONN_HASH_SIZE) {
		sctps->sctps_conn_hash_size = SCTP_CONN_HASH_SIZE;
		cmn_err(CE_CONT, "using sctp_conn_hash_size = %u\n",
		    sctps->sctps_conn_hash_size);
	}
	sctps->sctps_conn_fanout =
	    (sctp_tf_t *)kmem_zalloc(sctps->sctps_conn_hash_size *
	    sizeof (sctp_tf_t),	KM_SLEEP);
	for (i = 0; i < sctps->sctps_conn_hash_size; i++) {
		mutex_init(&sctps->sctps_conn_fanout[i].tf_lock, NULL,
		    MUTEX_DEFAULT, NULL);
	}
	sctps->sctps_listen_fanout = kmem_zalloc(SCTP_LISTEN_FANOUT_SIZE *
	    sizeof (sctp_tf_t),	KM_SLEEP);
	for (i = 0; i < SCTP_LISTEN_FANOUT_SIZE; i++) {
		mutex_init(&sctps->sctps_listen_fanout[i].tf_lock, NULL,
		    MUTEX_DEFAULT, NULL);
	}
	sctps->sctps_bind_fanout = kmem_zalloc(SCTP_BIND_FANOUT_SIZE *
	    sizeof (sctp_tf_t),	KM_SLEEP);
	for (i = 0; i < SCTP_BIND_FANOUT_SIZE; i++) {
		mutex_init(&sctps->sctps_bind_fanout[i].tf_lock, NULL,
		    MUTEX_DEFAULT, NULL);
	}
}

void
sctp_hash_destroy(sctp_stack_t *sctps)
{
	int i;

	for (i = 0; i < sctps->sctps_conn_hash_size; i++) {
		mutex_destroy(&sctps->sctps_conn_fanout[i].tf_lock);
	}
	kmem_free(sctps->sctps_conn_fanout, sctps->sctps_conn_hash_size *
	    sizeof (sctp_tf_t));
	sctps->sctps_conn_fanout = NULL;

	for (i = 0; i < SCTP_LISTEN_FANOUT_SIZE; i++) {
		mutex_destroy(&sctps->sctps_listen_fanout[i].tf_lock);
	}
	kmem_free(sctps->sctps_listen_fanout, SCTP_LISTEN_FANOUT_SIZE *
	    sizeof (sctp_tf_t));
	sctps->sctps_listen_fanout = NULL;

	for (i = 0; i < SCTP_BIND_FANOUT_SIZE; i++) {
		mutex_destroy(&sctps->sctps_bind_fanout[i].tf_lock);
	}
	kmem_free(sctps->sctps_bind_fanout, SCTP_BIND_FANOUT_SIZE *
	    sizeof (sctp_tf_t));
	sctps->sctps_bind_fanout = NULL;
}

/*
 * Walk the SCTP global list and refrele the ire for this ipif
 * This is called when an address goes down, so that we release any reference
 * to the ire associated with this address. Additionally, for any SCTP if
 * this was the only/last address in its source list, we don't kill the
 * assoc., if there is no address added subsequently, or if this does not
 * come up, then the assoc. will die a natural death (i.e. timeout).
 */
void
sctp_ire_cache_flush(ipif_t *ipif)
{
	sctp_t			*sctp;
	sctp_t			*sctp_prev = NULL;
	sctp_faddr_t		*fp;
	conn_t			*connp;
	ire_t			*ire;
	sctp_stack_t		*sctps = ipif->ipif_ill->ill_ipst->
	    ips_netstack->netstack_sctp;

	sctp = sctps->sctps_gsctp;
	mutex_enter(&sctps->sctps_g_lock);
	while (sctp != NULL) {
		mutex_enter(&sctp->sctp_reflock);
		if (sctp->sctp_condemned) {
			mutex_exit(&sctp->sctp_reflock);
			sctp = list_next(&sctps->sctps_g_list, sctp);
			continue;
		}
		sctp->sctp_refcnt++;
		mutex_exit(&sctp->sctp_reflock);
		mutex_exit(&sctps->sctps_g_lock);
		if (sctp_prev != NULL)
			SCTP_REFRELE(sctp_prev);

		RUN_SCTP(sctp);
		connp = sctp->sctp_connp;
		mutex_enter(&connp->conn_lock);
		ire = connp->conn_ire_cache;
		if (ire != NULL && ire->ire_ipif == ipif) {
			connp->conn_ire_cache = NULL;
			mutex_exit(&connp->conn_lock);
			IRE_REFRELE_NOTR(ire);
		} else {
			mutex_exit(&connp->conn_lock);
		}
		/* check for ires cached in faddr */
		for (fp = sctp->sctp_faddrs; fp != NULL; fp = fp->next) {
			/*
			 * If this ipif is being used as the source address
			 * we need to update it as well, else we will end
			 * up using the dead source address.
			 */
			ire = fp->ire;
			if (ire != NULL && ire->ire_ipif == ipif) {
				fp->ire = NULL;
				IRE_REFRELE_NOTR(ire);
			}
			/*
			 * This may result in setting the fp as unreachable,
			 * i.e. if all the source addresses are down. In
			 * that case the assoc. would timeout.
			 */
			if (IN6_ARE_ADDR_EQUAL(&ipif->ipif_v6lcl_addr,
			    &fp->saddr)) {
				sctp_set_saddr(sctp, fp);
				if (fp == sctp->sctp_current &&
				    fp->state != SCTP_FADDRS_UNREACH) {
					sctp_set_faddr_current(sctp, fp);
				}
			}
		}
		WAKE_SCTP(sctp);
		sctp_prev = sctp;
		mutex_enter(&sctps->sctps_g_lock);
		sctp = list_next(&sctps->sctps_g_list, sctp);
	}
	mutex_exit(&sctps->sctps_g_lock);
	if (sctp_prev != NULL)
		SCTP_REFRELE(sctp_prev);
}

/*
 * Exported routine for extracting active SCTP associations.
 * Like TCP, we terminate the walk if the callback returns non-zero.
 *
 * Need to walk all sctp_stack_t instances since this clustering
 * interface is assumed global for all instances
 */
int
cl_sctp_walk_list(int (*cl_callback)(cl_sctp_info_t *, void *),
    void *arg, boolean_t cansleep)
{
	netstack_handle_t nh;
	netstack_t *ns;
	int ret = 0;

	netstack_next_init(&nh);
	while ((ns = netstack_next(&nh)) != NULL) {
		ret = cl_sctp_walk_list_stack(cl_callback, arg, cansleep,
		    ns->netstack_sctp);
		netstack_rele(ns);
	}
	netstack_next_fini(&nh);
	return (ret);
}

static int
cl_sctp_walk_list_stack(int (*cl_callback)(cl_sctp_info_t *, void *),
    void *arg, boolean_t cansleep, sctp_stack_t *sctps)
{
	sctp_t		*sctp;
	sctp_t		*sctp_prev;
	cl_sctp_info_t	cl_sctpi;
	uchar_t		*slist;
	uchar_t		*flist;

	sctp = sctps->sctps_gsctp;
	sctp_prev = NULL;
	mutex_enter(&sctps->sctps_g_lock);
	while (sctp != NULL) {
		size_t	ssize;
		size_t	fsize;

		mutex_enter(&sctp->sctp_reflock);
		if (sctp->sctp_condemned || sctp->sctp_state <= SCTPS_LISTEN) {
			mutex_exit(&sctp->sctp_reflock);
			sctp = list_next(&sctps->sctps_g_list, sctp);
			continue;
		}
		sctp->sctp_refcnt++;
		mutex_exit(&sctp->sctp_reflock);
		mutex_exit(&sctps->sctps_g_lock);
		if (sctp_prev != NULL)
			SCTP_REFRELE(sctp_prev);
		RUN_SCTP(sctp);
		ssize = sizeof (in6_addr_t) * sctp->sctp_nsaddrs;
		fsize = sizeof (in6_addr_t) * sctp->sctp_nfaddrs;

		slist = kmem_alloc(ssize, cansleep ? KM_SLEEP : KM_NOSLEEP);
		flist = kmem_alloc(fsize, cansleep ? KM_SLEEP : KM_NOSLEEP);
		if (slist == NULL || flist == NULL) {
			WAKE_SCTP(sctp);
			if (slist != NULL)
				kmem_free(slist, ssize);
			if (flist != NULL)
				kmem_free(flist, fsize);
			SCTP_REFRELE(sctp);
			return (1);
		}
		cl_sctpi.cl_sctpi_version = CL_SCTPI_V1;
		sctp_get_saddr_list(sctp, slist, ssize);
		sctp_get_faddr_list(sctp, flist, fsize);
		cl_sctpi.cl_sctpi_nladdr = sctp->sctp_nsaddrs;
		cl_sctpi.cl_sctpi_nfaddr = sctp->sctp_nfaddrs;
		cl_sctpi.cl_sctpi_family = sctp->sctp_family;
		cl_sctpi.cl_sctpi_ipversion = sctp->sctp_ipversion;
		cl_sctpi.cl_sctpi_state = sctp->sctp_state;
		cl_sctpi.cl_sctpi_lport = sctp->sctp_lport;
		cl_sctpi.cl_sctpi_fport = sctp->sctp_fport;
		cl_sctpi.cl_sctpi_handle = (cl_sctp_handle_t)sctp;
		WAKE_SCTP(sctp);
		cl_sctpi.cl_sctpi_laddrp = slist;
		cl_sctpi.cl_sctpi_faddrp = flist;
		if ((*cl_callback)(&cl_sctpi, arg) != 0) {
			kmem_free(slist, ssize);
			kmem_free(flist, fsize);
			SCTP_REFRELE(sctp);
			return (1);
		}
		/* list will be freed by cl_callback */
		sctp_prev = sctp;
		mutex_enter(&sctps->sctps_g_lock);
		sctp = list_next(&sctps->sctps_g_list, sctp);
	}
	mutex_exit(&sctps->sctps_g_lock);
	if (sctp_prev != NULL)
		SCTP_REFRELE(sctp_prev);
	return (0);
}

sctp_t *
sctp_conn_match(in6_addr_t *faddr, in6_addr_t *laddr, uint32_t ports,
    zoneid_t zoneid, sctp_stack_t *sctps)
{
	sctp_tf_t		*tf;
	sctp_t			*sctp;
	sctp_faddr_t		*fp;

	tf = &(sctps->sctps_conn_fanout[SCTP_CONN_HASH(sctps, ports)]);
	mutex_enter(&tf->tf_lock);

	for (sctp = tf->tf_sctp; sctp; sctp = sctp->sctp_conn_hash_next) {
		if (ports != sctp->sctp_ports ||
		    !IPCL_ZONE_MATCH(sctp->sctp_connp, zoneid)) {
			continue;
		}

		/* check for faddr match */
		for (fp = sctp->sctp_faddrs; fp; fp = fp->next) {
			if (IN6_ARE_ADDR_EQUAL(faddr, &fp->faddr)) {
				break;
			}
		}

		/* no faddr match; keep looking */
		if (fp == NULL)
			continue;

		/* check for laddr match */
		if (sctp_saddr_lookup(sctp, laddr, 0) != NULL) {
			SCTP_REFHOLD(sctp);
			goto done;
		}
		/* no match; continue to the next in the chain */
	}

done:
	mutex_exit(&tf->tf_lock);
	return (sctp);
}

static sctp_t *
listen_match(in6_addr_t *laddr, uint32_t ports, zoneid_t zoneid,
    sctp_stack_t *sctps)
{
	sctp_t			*sctp;
	sctp_tf_t		*tf;
	uint16_t		lport;

	lport = ((uint16_t *)&ports)[1];

	tf = &(sctps->sctps_listen_fanout[SCTP_LISTEN_HASH(ntohs(lport))]);
	mutex_enter(&tf->tf_lock);

	for (sctp = tf->tf_sctp; sctp; sctp = sctp->sctp_listen_hash_next) {
		if (lport != sctp->sctp_lport ||
		    !IPCL_ZONE_MATCH(sctp->sctp_connp, zoneid)) {
			continue;
		}

		if (sctp_saddr_lookup(sctp, laddr, 0) != NULL) {
			SCTP_REFHOLD(sctp);
			goto done;
		}
		/* no match; continue to the next in the chain */
	}

done:
	mutex_exit(&tf->tf_lock);
	return (sctp);
}

/* called by ipsec_sctp_pol */
conn_t *
sctp_find_conn(in6_addr_t *src, in6_addr_t *dst, uint32_t ports,
    zoneid_t zoneid, sctp_stack_t *sctps)
{
	sctp_t *sctp;

	if ((sctp = sctp_conn_match(src, dst, ports, zoneid, sctps)) == NULL) {
		/* Not in conn fanout; check listen fanout */
		if ((sctp = listen_match(dst, ports, zoneid, sctps)) == NULL)
			return (NULL);
	}
	return (sctp->sctp_connp);
}

conn_t *
sctp_fanout(in6_addr_t *src, in6_addr_t *dst, uint32_t ports,
    zoneid_t zoneid, mblk_t *mp, sctp_stack_t *sctps)

{
	sctp_t *sctp;
	boolean_t shared_addr;

	if ((sctp = sctp_conn_match(src, dst, ports, zoneid, sctps)) == NULL) {
		shared_addr = (zoneid == ALL_ZONES);
		if (shared_addr) {
			/*
			 * No need to handle exclusive-stack zones since
			 * ALL_ZONES only applies to the shared stack.
			 */
			zoneid = tsol_mlp_findzone(IPPROTO_SCTP,
			    htons(ntohl(ports) & 0xFFFF));
			/*
			 * If no shared MLP is found, tsol_mlp_findzone returns
			 * ALL_ZONES.  In that case, we assume it's SLP, and
			 * search for the zone based on the packet label.
			 * That will also return ALL_ZONES on failure.
			 */
			if (zoneid == ALL_ZONES)
				zoneid = tsol_packet_to_zoneid(mp);
			if (zoneid == ALL_ZONES)
				return (NULL);
		}
		/* Not in conn fanout; check listen fanout */
		if ((sctp = listen_match(dst, ports, zoneid, sctps)) == NULL)
			return (NULL);
		/*
		 * On systems running trusted extensions, check if dst
		 * should accept the packet. "IPV6_VERSION" indicates
		 * that dst is in 16 byte AF_INET6 format. IPv4-mapped
		 * IPv6 addresses are supported.
		 */
		if (is_system_labeled() &&
		    !tsol_receive_local(mp, dst, IPV6_VERSION,
		    shared_addr, sctp->sctp_connp)) {
			DTRACE_PROBE3(
			    tx__ip__log__info__classify__sctp,
			    char *,
			    "connp(1) could not receive mp(2)",
			    conn_t *, sctp->sctp_connp, mblk_t *, mp);
			SCTP_REFRELE(sctp);
			return (NULL);
		}
	}
	return (sctp->sctp_connp);
}

/*
 * Fanout for SCTP packets
 * The caller puts <fport, lport> in the ports parameter.
 */
/* ARGSUSED */
void
ip_fanout_sctp(mblk_t *mp, ill_t *recv_ill, ipha_t *ipha,
    uint32_t ports, uint_t flags, boolean_t mctl_present, boolean_t ip_policy,
    zoneid_t zoneid)
{
	sctp_t *sctp;
	boolean_t isv4;
	conn_t *connp;
	mblk_t *first_mp;
	ip6_t *ip6h;
	in6_addr_t map_src, map_dst;
	in6_addr_t *src, *dst;
	ip_stack_t	*ipst;
	ipsec_stack_t	*ipss;
	sctp_stack_t	*sctps;

	ASSERT(recv_ill != NULL);
	ipst = recv_ill->ill_ipst;
	sctps = ipst->ips_netstack->netstack_sctp;
	ipss = ipst->ips_netstack->netstack_ipsec;

	first_mp = mp;
	if (mctl_present) {
		mp = first_mp->b_cont;
		ASSERT(mp != NULL);
	}

	/* Assume IP provides aligned packets - otherwise toss */
	if (!OK_32PTR(mp->b_rptr)) {
		BUMP_MIB(recv_ill->ill_ip_mib, ipIfStatsInDiscards);
		freemsg(first_mp);
		return;
	}

	if (IPH_HDR_VERSION(ipha) == IPV6_VERSION) {
		ip6h = (ip6_t *)ipha;
		src = &ip6h->ip6_src;
		dst = &ip6h->ip6_dst;
		isv4 = B_FALSE;
	} else {
		ip6h = NULL;
		IN6_IPADDR_TO_V4MAPPED(ipha->ipha_src, &map_src);
		IN6_IPADDR_TO_V4MAPPED(ipha->ipha_dst, &map_dst);
		src = &map_src;
		dst = &map_dst;
		isv4 = B_TRUE;
	}
	connp = sctp_fanout(src, dst, ports, zoneid, mp, sctps);
	if (connp == NULL) {
		ip_fanout_sctp_raw(first_mp, recv_ill, ipha, isv4,
		    ports, mctl_present, flags, ip_policy, zoneid);
		return;
	}
	sctp = CONN2SCTP(connp);

	/* Found a client; up it goes */
	BUMP_MIB(recv_ill->ill_ip_mib, ipIfStatsHCInDelivers);

	/*
	 * We check some fields in conn_t without holding a lock.
	 * This should be fine.
	 */
	if (CONN_INBOUND_POLICY_PRESENT(connp, ipss) || mctl_present) {
		first_mp = ipsec_check_inbound_policy(first_mp, connp,
		    ipha, NULL, mctl_present);
		if (first_mp == NULL) {
			SCTP_REFRELE(sctp);
			return;
		}
	}

	/* Initiate IPPF processing for fastpath */
	if (IPP_ENABLED(IPP_LOCAL_IN, ipst)) {
		ip_process(IPP_LOCAL_IN, &mp,
		    recv_ill->ill_phyint->phyint_ifindex);
		if (mp == NULL) {
			SCTP_REFRELE(sctp);
			if (mctl_present)
				freeb(first_mp);
			return;
		} else if (mctl_present) {
			/*
			 * ip_process might return a new mp.
			 */
			ASSERT(first_mp != mp);
			first_mp->b_cont = mp;
		} else {
			first_mp = mp;
		}
	}

	if (connp->conn_recvif || connp->conn_recvslla ||
	    connp->conn_ip_recvpktinfo) {
		int in_flags = 0;

		if (connp->conn_recvif || connp->conn_ip_recvpktinfo) {
			in_flags = IPF_RECVIF;
		}
		if (connp->conn_recvslla) {
			in_flags |= IPF_RECVSLLA;
		}
		if (isv4) {
			mp = ip_add_info(mp, recv_ill, in_flags,
			    IPCL_ZONEID(connp), ipst);
		} else {
			mp = ip_add_info_v6(mp, recv_ill, &ip6h->ip6_dst);
		}
		if (mp == NULL) {
			SCTP_REFRELE(sctp);
			if (mctl_present)
				freeb(first_mp);
			return;
		} else if (mctl_present) {
			/*
			 * ip_add_info might return a new mp.
			 */
			ASSERT(first_mp != mp);
			first_mp->b_cont = mp;
		} else {
			first_mp = mp;
		}
	}

	mutex_enter(&sctp->sctp_lock);
	if (sctp->sctp_running) {
		if (mctl_present)
			mp->b_prev = first_mp;
		if (!sctp_add_recvq(sctp, mp, B_FALSE)) {
			BUMP_MIB(recv_ill->ill_ip_mib, ipIfStatsInDiscards);
			freemsg(first_mp);
		}
		mutex_exit(&sctp->sctp_lock);
	} else {
		sctp->sctp_running = B_TRUE;
		mutex_exit(&sctp->sctp_lock);

		mutex_enter(&sctp->sctp_recvq_lock);
		if (sctp->sctp_recvq != NULL) {
			if (mctl_present)
				mp->b_prev = first_mp;
			if (!sctp_add_recvq(sctp, mp, B_TRUE)) {
				BUMP_MIB(recv_ill->ill_ip_mib,
				    ipIfStatsInDiscards);
				freemsg(first_mp);
			}
			mutex_exit(&sctp->sctp_recvq_lock);
			WAKE_SCTP(sctp);
		} else {
			mutex_exit(&sctp->sctp_recvq_lock);
			sctp_input_data(sctp, mp, (mctl_present ? first_mp :
			    NULL));
			WAKE_SCTP(sctp);
			sctp_process_sendq(sctp);
		}
	}
	SCTP_REFRELE(sctp);
}

void
sctp_conn_hash_remove(sctp_t *sctp)
{
	sctp_tf_t *tf = sctp->sctp_conn_tfp;

	if (!tf) {
		return;
	}
	/*
	 * On a clustered note send this notification to the clustering
	 * subsystem.
	 */
	if (cl_sctp_disconnect != NULL) {
		(*cl_sctp_disconnect)(sctp->sctp_family,
		    (cl_sctp_handle_t)sctp);
	}

	mutex_enter(&tf->tf_lock);
	ASSERT(tf->tf_sctp);
	if (tf->tf_sctp == sctp) {
		tf->tf_sctp = sctp->sctp_conn_hash_next;
		if (sctp->sctp_conn_hash_next) {
			ASSERT(tf->tf_sctp->sctp_conn_hash_prev == sctp);
			tf->tf_sctp->sctp_conn_hash_prev = NULL;
		}
	} else {
		ASSERT(sctp->sctp_conn_hash_prev);
		ASSERT(sctp->sctp_conn_hash_prev->sctp_conn_hash_next == sctp);
		sctp->sctp_conn_hash_prev->sctp_conn_hash_next =
		    sctp->sctp_conn_hash_next;

		if (sctp->sctp_conn_hash_next) {
			ASSERT(sctp->sctp_conn_hash_next->sctp_conn_hash_prev
			    == sctp);
			sctp->sctp_conn_hash_next->sctp_conn_hash_prev =
			    sctp->sctp_conn_hash_prev;
		}
	}
	sctp->sctp_conn_hash_next = NULL;
	sctp->sctp_conn_hash_prev = NULL;
	sctp->sctp_conn_tfp = NULL;
	mutex_exit(&tf->tf_lock);
}

void
sctp_conn_hash_insert(sctp_tf_t *tf, sctp_t *sctp, int caller_holds_lock)
{
	if (sctp->sctp_conn_tfp) {
		sctp_conn_hash_remove(sctp);
	}

	if (!caller_holds_lock) {
		mutex_enter(&tf->tf_lock);
	} else {
		ASSERT(MUTEX_HELD(&tf->tf_lock));
	}

	sctp->sctp_conn_hash_next = tf->tf_sctp;
	if (tf->tf_sctp) {
		tf->tf_sctp->sctp_conn_hash_prev = sctp;
	}
	sctp->sctp_conn_hash_prev = NULL;
	tf->tf_sctp = sctp;
	sctp->sctp_conn_tfp = tf;
	if (!caller_holds_lock) {
		mutex_exit(&tf->tf_lock);
	}
}

void
sctp_listen_hash_remove(sctp_t *sctp)
{
	sctp_tf_t *tf = sctp->sctp_listen_tfp;

	if (!tf) {
		return;
	}
	/*
	 * On a clustered note send this notification to the clustering
	 * subsystem.
	 */
	if (cl_sctp_unlisten != NULL) {
		uchar_t	*slist;
		ssize_t	ssize;

		ssize = sizeof (in6_addr_t) * sctp->sctp_nsaddrs;
		slist = kmem_alloc(ssize, KM_SLEEP);
		sctp_get_saddr_list(sctp, slist, ssize);
		(*cl_sctp_unlisten)(sctp->sctp_family, slist,
		    sctp->sctp_nsaddrs, sctp->sctp_lport);
		/* list will be freed by the clustering module */
	}

	mutex_enter(&tf->tf_lock);
	ASSERT(tf->tf_sctp);
	if (tf->tf_sctp == sctp) {
		tf->tf_sctp = sctp->sctp_listen_hash_next;
		if (sctp->sctp_listen_hash_next != NULL) {
			ASSERT(tf->tf_sctp->sctp_listen_hash_prev == sctp);
			tf->tf_sctp->sctp_listen_hash_prev = NULL;
		}
	} else {
		ASSERT(sctp->sctp_listen_hash_prev);
		ASSERT(sctp->sctp_listen_hash_prev->sctp_listen_hash_next ==
		    sctp);
		ASSERT(sctp->sctp_listen_hash_next == NULL ||
		    sctp->sctp_listen_hash_next->sctp_listen_hash_prev == sctp);

		sctp->sctp_listen_hash_prev->sctp_listen_hash_next =
		    sctp->sctp_listen_hash_next;

		if (sctp->sctp_listen_hash_next != NULL) {
			sctp->sctp_listen_hash_next->sctp_listen_hash_prev =
			    sctp->sctp_listen_hash_prev;
		}
	}
	sctp->sctp_listen_hash_next = NULL;
	sctp->sctp_listen_hash_prev = NULL;
	sctp->sctp_listen_tfp = NULL;
	mutex_exit(&tf->tf_lock);
}

void
sctp_listen_hash_insert(sctp_tf_t *tf, sctp_t *sctp)
{
	if (sctp->sctp_listen_tfp) {
		sctp_listen_hash_remove(sctp);
	}

	mutex_enter(&tf->tf_lock);
	sctp->sctp_listen_hash_next = tf->tf_sctp;
	if (tf->tf_sctp) {
		tf->tf_sctp->sctp_listen_hash_prev = sctp;
	}
	sctp->sctp_listen_hash_prev = NULL;
	tf->tf_sctp = sctp;
	sctp->sctp_listen_tfp = tf;
	mutex_exit(&tf->tf_lock);
	/*
	 * On a clustered note send this notification to the clustering
	 * subsystem.
	 */
	if (cl_sctp_listen != NULL) {
		uchar_t	*slist;
		ssize_t	ssize;

		ssize = sizeof (in6_addr_t) * sctp->sctp_nsaddrs;
		slist = kmem_alloc(ssize, KM_SLEEP);
		sctp_get_saddr_list(sctp, slist, ssize);
		(*cl_sctp_listen)(sctp->sctp_family, slist,
		    sctp->sctp_nsaddrs, sctp->sctp_lport);
		/* list will be freed by the clustering module */
	}
}

/*
 * Hash list insertion routine for sctp_t structures.
 * Inserts entries with the ones bound to a specific IP address first
 * followed by those bound to INADDR_ANY.
 */
void
sctp_bind_hash_insert(sctp_tf_t *tbf, sctp_t *sctp, int caller_holds_lock)
{
	sctp_t	**sctpp;
	sctp_t	*sctpnext;

	if (sctp->sctp_ptpbhn != NULL) {
		ASSERT(!caller_holds_lock);
		sctp_bind_hash_remove(sctp);
	}
	sctpp = &tbf->tf_sctp;
	if (!caller_holds_lock) {
		mutex_enter(&tbf->tf_lock);
	} else {
		ASSERT(MUTEX_HELD(&tbf->tf_lock));
	}
	sctpnext = sctpp[0];
	if (sctpnext) {
		sctpnext->sctp_ptpbhn = &sctp->sctp_bind_hash;
	}
	sctp->sctp_bind_hash = sctpnext;
	sctp->sctp_ptpbhn = sctpp;
	sctpp[0] = sctp;
	/* For sctp_*_hash_remove */
	sctp->sctp_bind_lockp = &tbf->tf_lock;
	if (!caller_holds_lock)
		mutex_exit(&tbf->tf_lock);
}

/*
 * Hash list removal routine for sctp_t structures.
 */
void
sctp_bind_hash_remove(sctp_t *sctp)
{
	sctp_t	*sctpnext;
	kmutex_t *lockp;

	lockp = sctp->sctp_bind_lockp;

	if (sctp->sctp_ptpbhn == NULL)
		return;

	ASSERT(lockp != NULL);
	mutex_enter(lockp);
	if (sctp->sctp_ptpbhn) {
		sctpnext = sctp->sctp_bind_hash;
		if (sctpnext) {
			sctpnext->sctp_ptpbhn = sctp->sctp_ptpbhn;
			sctp->sctp_bind_hash = NULL;
		}
		*sctp->sctp_ptpbhn = sctpnext;
		sctp->sctp_ptpbhn = NULL;
	}
	mutex_exit(lockp);
	sctp->sctp_bind_lockp = NULL;
}

/*
 * Similar to but different from sctp_conn_match().
 *
 * Matches sets of addresses as follows: if the argument addr set is
 * a complete subset of the corresponding addr set in the sctp_t, it
 * is a match.
 *
 * Caller must hold tf->tf_lock.
 *
 * Returns with a SCTP_REFHOLD sctp structure. Caller must do a SCTP_REFRELE.
 */
sctp_t *
sctp_lookup(sctp_t *sctp1, in6_addr_t *faddr, sctp_tf_t *tf, uint32_t *ports,
    int min_state)
{
	sctp_t *sctp;
	sctp_faddr_t *fp;

	ASSERT(MUTEX_HELD(&tf->tf_lock));

	for (sctp = tf->tf_sctp; sctp != NULL;
	    sctp = sctp->sctp_conn_hash_next) {
		if (*ports != sctp->sctp_ports || sctp->sctp_state <
		    min_state) {
			continue;
		}

		/* check for faddr match */
		for (fp = sctp->sctp_faddrs; fp != NULL; fp = fp->next) {
			if (IN6_ARE_ADDR_EQUAL(faddr, &fp->faddr)) {
				break;
			}
		}

		if (fp == NULL) {
			/* no faddr match; keep looking */
			continue;
		}

		/*
		 * There is an existing association with the same peer
		 * address.  So now we need to check if our local address
		 * set overlaps with the one of the existing association.
		 * If they overlap, we should return it.
		 */
		if (sctp_compare_saddrs(sctp1, sctp) <= SCTP_ADDR_OVERLAP) {
			goto done;
		}

		/* no match; continue searching */
	}

done:
	if (sctp != NULL) {
		SCTP_REFHOLD(sctp);
	}
	return (sctp);
}

boolean_t
ip_fanout_sctp_raw_match(conn_t *connp, uint32_t ports, ipha_t *ipha)
{
	uint16_t lport;

	if (connp->conn_fully_bound) {
		return (IPCL_CONN_MATCH(connp, IPPROTO_SCTP, ipha->ipha_src,
		    ipha->ipha_dst, ports));
	} else {
		lport = htons(ntohl(ports) & 0xFFFF);
		return (IPCL_BIND_MATCH(connp, IPPROTO_SCTP, ipha->ipha_dst,
		    lport));
	}
}

boolean_t
ip_fanout_sctp_raw_match_v6(conn_t *connp, uint32_t ports, ip6_t *ip6h,
    boolean_t for_v4)
{
	uint16_t lport;
	in6_addr_t	v6dst;

	if (!for_v4 && connp->conn_fully_bound) {
		return (IPCL_CONN_MATCH_V6(connp, IPPROTO_SCTP, ip6h->ip6_src,
		    ip6h->ip6_dst, ports));
	} else {
		lport = htons(ntohl(ports) & 0xFFFF);
		if (for_v4)
			v6dst = ipv6_all_zeros;
		else
			v6dst = ip6h->ip6_dst;
		return (IPCL_BIND_MATCH_V6(connp, IPPROTO_SCTP, v6dst, lport));
	}
}
