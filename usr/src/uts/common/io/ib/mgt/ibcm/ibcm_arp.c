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

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/strsubr.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <net/if_types.h>
#include <sys/sockio.h>
#include <sys/pathname.h>

#include <sys/ib/mgt/ibcm/ibcm_arp.h>

#include <sys/kstr.h>
#include <sys/t_kuser.h>

extern char cmlog[];

extern int ibcm_resolver_pr_lookup(ibcm_arp_streams_t *ib_s,
    ibt_ip_addr_t *dst_addr, ibt_ip_addr_t *src_addr);
extern void ibcm_arp_delete_prwqn(ibcm_arp_prwqn_t *wqnp);

_NOTE(SCHEME_PROTECTS_DATA("Unshared data", ibt_ip_addr_s))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", ibcm_arp_ip_t))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", ibcm_arp_ibd_insts_t))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", ibcm_arp_prwqn_t))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", sockaddr_in))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", sockaddr_in6))

int ibcm_printip = 0;

/*
 * Function:
 *	ibcm_ip_print
 * Input:
 *	label		Arbitrary qualifying string
 *	ipa		Pointer to IP Address to print
 */
void
ibcm_ip_print(char *label, ibt_ip_addr_t *ipaddr)
{
	char    buf[INET6_ADDRSTRLEN];

	if (ipaddr->family == AF_INET) {
		IBTF_DPRINTF_L2(cmlog, "%s: %s", label,
		    inet_ntop(AF_INET, &ipaddr->un.ip4addr, buf, sizeof (buf)));
	} else if (ipaddr->family == AF_INET6) {
		IBTF_DPRINTF_L2(cmlog, "%s: %s", label, inet_ntop(AF_INET6,
		    &ipaddr->un.ip6addr, buf, sizeof (buf)));
	} else {
		IBTF_DPRINTF_L2(cmlog, "%s: IP ADDR NOT SPECIFIED ", label);
	}
}


ibt_status_t
ibcm_arp_get_ibaddr(ibt_ip_addr_t srcaddr, ibt_ip_addr_t destaddr,
    ib_gid_t *sgid, ib_gid_t *dgid)
{
	ibcm_arp_streams_t	*ib_s;
	ibcm_arp_prwqn_t	*wqnp;
	int			ret = 0;

	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_get_ibaddr(%p, %p, %p, %p)",
	    srcaddr, destaddr, sgid, dgid);

	ib_s = (ibcm_arp_streams_t *)kmem_zalloc(sizeof (ibcm_arp_streams_t),
	    KM_SLEEP);

	mutex_init(&ib_s->lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&ib_s->cv, NULL, CV_DRIVER, NULL);

	mutex_enter(&ib_s->lock);
	ib_s->done = B_FALSE;
	mutex_exit(&ib_s->lock);

	ret = ibcm_resolver_pr_lookup(ib_s, &destaddr, &srcaddr);

	IBTF_DPRINTF_L3(cmlog, "ibcm_arp_get_ibaddr: ibcm_resolver_pr_lookup "
	    "returned: %d", ret);
	if (ret == 0) {
		mutex_enter(&ib_s->lock);
		while (ib_s->done != B_TRUE)
			cv_wait(&ib_s->cv, &ib_s->lock);
		mutex_exit(&ib_s->lock);
	}

	mutex_enter(&ib_s->lock);
	wqnp = ib_s->wqnp;
	if (ib_s->status == 0) {
		if (sgid)
			*sgid = ib_s->wqnp->sgid;
		if (dgid)
			*dgid = ib_s->wqnp->dgid;

		IBTF_DPRINTF_L4(cmlog, "ibcm_arp_get_ibaddr: SGID: %llX:%llX"
		    " DGID: %llX:%llX",
		    ib_s->wqnp->sgid.gid_prefix, ib_s->wqnp->sgid.gid_guid,
		    ib_s->wqnp->dgid.gid_prefix, ib_s->wqnp->dgid.gid_guid);

		ibcm_arp_delete_prwqn(wqnp);
	} else if (ret == 0) {
		/*
		 * We come here only when lookup has returned empty (failed)
		 * via callback routine.
		 * i.e. ib_s->status is non-zero, while ret is zero.
		 */
		if (wqnp)
			kmem_free(wqnp, sizeof (ibcm_arp_prwqn_t));
	}
	ret = ib_s->status;
	mutex_exit(&ib_s->lock);

arp_ibaddr_error:

	mutex_destroy(&ib_s->lock);
	cv_destroy(&ib_s->cv);
	kmem_free(ib_s, sizeof (ibcm_arp_streams_t));

	if (ret)
		return (IBT_FAILURE);
	else
		return (IBT_SUCCESS);
}


/*
 * Routine to get list of "local" IP-ADDR to GID/P_KEY mapping information.
 * Optionally, if "gid" and/or "p_key" info are specified, then retrieve the
 * IP-ADDR info for that attribute only.
 */

static ibcm_arp_ip_t *
ibcm_arp_ibd_gid2mac(ib_gid_t *gid, ib_pkey_t pkey, ibcm_arp_ibd_insts_t *ibdp)
{
	ibcm_arp_ip_t		*ipp;
	int			i;

	for (i = 0, ipp = ibdp->ibcm_arp_ip; i < ibdp->ibcm_arp_ibd_cnt;
	    i++, ipp++) {
		if ((ipp->ip_port_gid.gid_prefix == gid->gid_prefix) &&
		    (ipp->ip_port_gid.gid_guid == gid->gid_guid)) {
			if (pkey) {
				if (ipp->ip_pkey == pkey)
					return (ipp);
				else
					continue;
			}
			return (ipp);
		}
	}
	return (NULL);
}

static ibt_status_t
ibcm_arp_ibd_mac2gid(ibcm_arp_ibd_insts_t *ibdp, ibt_ip_addr_t *srcip,
    ib_gid_t *sgid)
{
	ibcm_arp_ip_t		*ipp;
	int			i;
	boolean_t		found = B_FALSE;

	for (i = 0, ipp = ibdp->ibcm_arp_ip; i < ibdp->ibcm_arp_ibd_cnt;
	    i++, ipp++) {

		IBTF_DPRINTF_L4(cmlog, "ibcm_arp_ibd_mac2gid: GID %llX:%llX",
		    ipp->ip_port_gid.gid_prefix, ipp->ip_port_gid.gid_guid);

		if (srcip->family == ipp->ip_inet_family) {
			if ((srcip->family == AF_INET) &&
			    (bcmp(&srcip->un.ip4addr, &ipp->ip_cm_sin.sin_addr,
			    sizeof (in_addr_t)) == 0)) {
				found = B_TRUE;
			} else if ((srcip->family == AF_INET6) &&
			    IN6_ARE_ADDR_EQUAL(&srcip->un.ip6addr,
			    &ipp->ip_cm_sin6.sin6_addr)) {
				found = B_TRUE;
			}
			if (found) {
				*sgid = ipp->ip_port_gid;

				IBTF_DPRINTF_L4(cmlog, "ibcm_arp_ibd_mac2gid: "
				    "Found GID %llX:%llX", sgid->gid_prefix,
				    sgid->gid_guid);
				return (IBT_SUCCESS);
			}
		} else {
			IBTF_DPRINTF_L3(cmlog, "ibcm_arp_ibd_mac2gid: Different"
			    " family keep searching...");
		}
	}
	IBTF_DPRINTF_L3(cmlog, "ibcm_arp_ibd_mac2gid: Matching SRC info "
	    "NOT Found");
	return (IBT_SRC_IP_NOT_FOUND);
}

static int
ibcm_arp_get_ibd_insts_cb(dev_info_t *dip, void *arg)
{
	ibcm_arp_ibd_insts_t *ibds = (ibcm_arp_ibd_insts_t *)arg;
	ibcm_arp_ip_t	*ipp;
	ib_pkey_t	pkey;
	uint8_t		port;
	ib_guid_t	hca_guid;
	ib_gid_t	port_gid;

	if (i_ddi_devi_attached(dip) &&
	    (strcmp(ddi_node_name(dip), "ibport") == 0) &&
	    (strstr(ddi_get_name_addr(dip), "ipib") != NULL)) {

		if (ibds->ibcm_arp_ibd_cnt >= ibds->ibcm_arp_ibd_alloc) {
			ibcm_arp_ip_t	*tmp = NULL;
			uint8_t		new_count;

			new_count = ibds->ibcm_arp_ibd_alloc +
			    IBCM_ARP_IBD_INSTANCES;

			tmp = (ibcm_arp_ip_t *)kmem_zalloc(
			    new_count * sizeof (ibcm_arp_ip_t), KM_SLEEP);
			bcopy(ibds->ibcm_arp_ip, tmp,
			    ibds->ibcm_arp_ibd_alloc * sizeof (ibcm_arp_ip_t));
			kmem_free(ibds->ibcm_arp_ip,
			    ibds->ibcm_arp_ibd_alloc * sizeof (ibcm_arp_ip_t));
			ibds->ibcm_arp_ibd_alloc = new_count;
			ibds->ibcm_arp_ip = tmp;
		}

		if (((hca_guid = ddi_prop_get_int64(DDI_DEV_T_ANY, dip, 0,
		    "hca-guid", 0)) == 0) ||
		    ((port = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
		    "port-number", 0)) == 0) ||
		    (ibt_get_port_state_byguid(hca_guid, port, &port_gid,
		    NULL) != IBT_SUCCESS) ||
		    ((pkey = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
		    "port-pkey", IB_PKEY_INVALID_LIMITED)) <=
		    IB_PKEY_INVALID_FULL)) {
			return (DDI_WALK_CONTINUE);
		}

		ipp = &ibds->ibcm_arp_ip[ibds->ibcm_arp_ibd_cnt];
		ipp->ip_inst = ddi_get_instance(dip);
		ipp->ip_pkey = pkey;
		ipp->ip_hca_guid = hca_guid;
		ipp->ip_port_gid = port_gid;
		ibds->ibcm_arp_ibd_cnt++;
	}
	return (DDI_WALK_CONTINUE);
}

static void
ibcm_arp_get_ibd_insts(ibcm_arp_ibd_insts_t *ibds)
{
	ddi_walk_devs(ddi_root_node(), ibcm_arp_get_ibd_insts_cb, ibds);
}

/*
 * Issue an ioctl down to IP.  There are several similar versions of this
 * function (e.g., rpcib_do_ip_ioctl()); clearly a utility routine is needed.
 */
static int
ibcm_do_ip_ioctl(int cmd, int len, void *arg)
{
	vnode_t *kvp;
	TIUSER  *tiptr;
	struct  strioctl iocb;
	int	err = 0;

	if (lookupname("/dev/udp", UIO_SYSSPACE, FOLLOW, NULLVPP, &kvp) != 0)
		return (EPROTO);

	if (t_kopen(NULL, kvp->v_rdev, FREAD|FWRITE, &tiptr, CRED()) != 0) {
		VN_RELE(kvp);
		return (EPROTO);
	}

	iocb.ic_cmd = cmd;
	iocb.ic_timout = 0;
	iocb.ic_len = len;
	iocb.ic_dp = (caddr_t)arg;
	err = kstr_ioctl(tiptr->fp->f_vnode, I_STR, (intptr_t)&iocb);
	(void) t_kclose(tiptr, 0);
	VN_RELE(kvp);
	return (err);
}

/*
 * Issue an SIOCGLIFCONF down to IP and return the result in `lifcp'.
 * lifcp->lifc_buf is dynamically allocated to be *bufsizep bytes.
 */
static int
ibcm_do_lifconf(struct lifconf *lifcp, uint_t *bufsizep, sa_family_t family_loc)
{
	int err;
	struct lifnum lifn;

	bzero(&lifn, sizeof (struct lifnum));
	lifn.lifn_family = family_loc;

	err = ibcm_do_ip_ioctl(SIOCGLIFNUM, sizeof (struct lifnum), &lifn);
	if (err != 0)
		return (err);

	IBTF_DPRINTF_L4(cmlog, "ibcm_do_lifconf: Family %d, lifn_count %d",
	    family_loc, lifn.lifn_count);
	/*
	 * Pad the interface count to account for additional interfaces that
	 * may have been configured between the SIOCGLIFNUM and SIOCGLIFCONF.
	 */
	lifn.lifn_count += 4;

	bzero(lifcp, sizeof (struct lifconf));
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*lifcp))
	lifcp->lifc_family = family_loc;
	lifcp->lifc_len = *bufsizep = lifn.lifn_count * sizeof (struct lifreq);
	lifcp->lifc_buf = kmem_zalloc(*bufsizep, KM_SLEEP);

	err = ibcm_do_ip_ioctl(SIOCGLIFCONF, sizeof (struct lifconf), lifcp);
	if (err != 0) {
		kmem_free(lifcp->lifc_buf, *bufsizep);
		return (err);
	}
	return (0);
}

/*
 * Fill in `ibds' with IP addresses tied to IFT_IB IP interfaces.  Returns
 * B_TRUE if at least one address was filled in.
 */
static boolean_t
ibcm_arp_get_ibd_ipaddr(ibcm_arp_ibd_insts_t *ibds, sa_family_t family_loc)
{
	int i, nifs, naddr = 0;
	uint_t bufsize;
	struct lifconf lifc;
	struct lifreq *lifrp;
	ibcm_arp_ip_t *ipp;

	if (ibcm_do_lifconf(&lifc, &bufsize, family_loc) != 0)
		return (B_FALSE);

	nifs = lifc.lifc_len / sizeof (struct lifreq);

	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_get_ibd_ipaddr: Family %d, nifs %d",
	    family_loc, nifs);

	for (lifrp = lifc.lifc_req, i = 0;
	    i < nifs && naddr < ibds->ibcm_arp_ibd_cnt; i++, lifrp++) {
		if (lifrp->lifr_type != IFT_IB)
			continue;

		ipp = &ibds->ibcm_arp_ip[naddr];
		switch (lifrp->lifr_addr.ss_family) {
		case AF_INET:
			ipp->ip_inet_family = AF_INET;
			bcopy(&lifrp->lifr_addr, &ipp->ip_cm_sin,
			    sizeof (struct sockaddr_in));
			naddr++;
			break;
		case AF_INET6:
			ipp->ip_inet_family = AF_INET6;
			bcopy(&lifrp->lifr_addr, &ipp->ip_cm_sin6,
			    sizeof (struct sockaddr_in6));
			naddr++;
			break;
		}
	}

	kmem_free(lifc.lifc_buf, bufsize);
	return (naddr > 0);
}

ibt_status_t
ibcm_arp_get_ibds(ibcm_arp_ibd_insts_t *ibdp, sa_family_t family_loc)
{
#ifdef DEBUG
	int i;
#endif

	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_get_ibds(%p)", ibdp);

	ibcm_arp_get_ibd_insts(ibdp);

	IBTF_DPRINTF_L3(cmlog, "ibcm_arp_get_ibds: Found %d ibd instances",
	    ibdp->ibcm_arp_ibd_cnt);

	if (ibdp->ibcm_arp_ibd_cnt == 0)
		return (IBT_SRC_IP_NOT_FOUND);

	/* Get the IP addresses of active ports. */
	if (!ibcm_arp_get_ibd_ipaddr(ibdp, family_loc)) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_arp_get_ibds: failed to get "
		    "ibd instance: IBT_SRC_IP_NOT_FOUND");
		return (IBT_SRC_IP_NOT_FOUND);
	}

#ifdef DEBUG
	for (i = 0; i < ibdp->ibcm_arp_ibd_cnt; i++) {
		char    my_buf[INET6_ADDRSTRLEN];
		ibcm_arp_ip_t	*aip = &ibdp->ibcm_arp_ip[i];

		IBTF_DPRINTF_L4(cmlog, "ibcm_arp_get_ibds: ibd[%d]: Family %d "
		    "Instance %d PKey 0x%lX \n HCAGUID 0x%llX SGID %llX:%llX",
		    i, aip->ip_inet_family, aip->ip_inst, aip->ip_pkey,
		    aip->ip_hca_guid, aip->ip_port_gid.gid_prefix,
		    aip->ip_port_gid.gid_guid);
		if (aip->ip_inet_family == AF_INET) {
			IBTF_DPRINTF_L4(cmlog, "ibcm_arp_get_ibds: IPV4: %s",
			    inet_ntop(AF_INET, &aip->ip_cm_sin.sin_addr, my_buf,
			    sizeof (my_buf)));
		} else if (aip->ip_inet_family == AF_INET6) {
			IBTF_DPRINTF_L4(cmlog, "ibcm_arp_get_ibds: IPV6: %s",
			    inet_ntop(AF_INET6, &aip->ip_cm_sin6.sin6_addr,
			    my_buf, sizeof (my_buf)));
		} else {
			IBTF_DPRINTF_L2(cmlog, "ibcm_arp_get_ibds: Unknown "
			    "Family %d", aip->ip_inet_family);
		}
	}
#endif

	return (IBT_SUCCESS);
}

_NOTE(SCHEME_PROTECTS_DATA("Unshared data", ibtl_cm_port_list_t))

ibt_status_t
ibcm_arp_get_srcip_plist(ibt_ip_path_attr_t *ipattr, ibt_path_flags_t flags,
    ibtl_cm_port_list_t **port_list_p)
{
	ibt_path_attr_t		attr;
	ibt_status_t		ret;
	ibcm_arp_ibd_insts_t	ibds;
	ibcm_arp_ip_t		*ipp;
	ibtl_cm_port_list_t	*plistp;
	ib_gid_t		sgid;
	sa_family_t		family_interested = AF_UNSPEC;

	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_get_srcip_plist(%p, %llX)",
	    ipattr, flags);

	if (ipattr->ipa_src_ip.family != AF_UNSPEC)
		family_interested = ipattr->ipa_src_ip.family;
	else
		family_interested = ipattr->ipa_dst_ip[0].family;

	sgid.gid_prefix = sgid.gid_guid = 0;
	bzero(&ibds, sizeof (ibcm_arp_ibd_insts_t));
	ibds.ibcm_arp_ibd_alloc = IBCM_ARP_IBD_INSTANCES;
	ibds.ibcm_arp_ibd_cnt = 0;
	ibds.ibcm_arp_ip = (ibcm_arp_ip_t *)kmem_zalloc(
	    ibds.ibcm_arp_ibd_alloc * sizeof (ibcm_arp_ip_t), KM_SLEEP);

	ret = ibcm_arp_get_ibds(&ibds, family_interested);
	if (ret != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_arp_get_srcip_plist: "
		    "ibcm_arp_get_ibds failed : 0x%x", ret);
		goto srcip_plist_end;
	}

	if (ipattr->ipa_src_ip.family != AF_UNSPEC) {
		ret = ibcm_arp_ibd_mac2gid(&ibds, &ipattr->ipa_src_ip, &sgid);
		if (ret != IBT_SUCCESS) {
			IBTF_DPRINTF_L2(cmlog, "ibcm_arp_get_srcip_plist: "
			    "SGID for the specified SRCIP Not found %X", ret);
			goto srcip_plist_end;
		}
		IBTF_DPRINTF_L4(cmlog, "ibcm_arp_get_srcip_plist: SGID "
		    "%llX:%llX", sgid.gid_prefix, sgid.gid_guid);
	}

	bzero(&attr, sizeof (ibt_path_attr_t));
	attr.pa_hca_guid = ipattr->ipa_hca_guid;
	attr.pa_hca_port_num = ipattr->ipa_hca_port_num;
	attr.pa_sgid = sgid;
	bcopy(&ipattr->ipa_mtu,  &attr.pa_mtu, sizeof (ibt_mtu_req_t));
	bcopy(&ipattr->ipa_srate,  &attr.pa_srate, sizeof (ibt_srate_req_t));
	bcopy(&ipattr->ipa_pkt_lt,  &attr.pa_pkt_lt, sizeof (ibt_pkt_lt_req_t));

	ret = ibtl_cm_get_active_plist(&attr, flags, port_list_p);
	if (ret == IBT_SUCCESS) {
		int		i;
		uint8_t		cnt;
		boolean_t	no_srcip_configured = B_FALSE;
		uint8_t		no_srcip_cnt = 0;

		plistp = port_list_p[0];
		cnt = plistp->p_count;
		for (i = 0; i < cnt; i++, plistp++) {
			ipp = ibcm_arp_ibd_gid2mac(&plistp->p_sgid, 0, &ibds);
			if ((ipp == NULL) ||
			    (ipp->ip_inet_family == AF_UNSPEC)) {
				plistp->p_src_ip.family = AF_UNSPEC;
				no_srcip_configured = B_TRUE;
				no_srcip_cnt++;
				IBTF_DPRINTF_L3(cmlog,
				    "ibcm_arp_get_srcip_plist: SrcIP NOT "
				    "Configured for GID %llX:%llX",
				    plistp->p_sgid.gid_prefix,
				    plistp->p_sgid.gid_guid);
			} else {
				IBTF_DPRINTF_L4(cmlog,
				    "ibcm_arp_get_srcip_plist: GID %llX:%llX",
				    plistp->p_sgid.gid_prefix,
				    plistp->p_sgid.gid_guid);
				if (ipp->ip_inet_family == AF_INET) {
					plistp->p_src_ip.family = AF_INET;
					bcopy(&ipp->ip_cm_sin.sin_addr,
					    &plistp->p_src_ip.un.ip4addr,
					    sizeof (in_addr_t));

				} else if (ipp->ip_inet_family == AF_INET6) {
					plistp->p_src_ip.family = AF_INET6;
					bcopy(&ipp->ip_cm_sin6.sin6_addr,
					    &plistp->p_src_ip.un.ip6addr,
					    sizeof (in6_addr_t));
				}
				IBCM_PRINT_IP("ibcm_arp_get_srcip_plist: "
				    "IP Addr is:", &plistp->p_src_ip);
			}
		}
		if (no_srcip_configured) {
			ibtl_cm_port_list_t	*n_plistp, *tmp_n_plistp;
			uint8_t			new_cnt;

			new_cnt = cnt - no_srcip_cnt;

			/*
			 * Looks like some of the SRC GID we found have no
			 * IP ADDR configured, so remove these entries from
			 * our list.
			 */
			plistp = port_list_p[0];
			IBTF_DPRINTF_L4(cmlog, "ibcm_arp_get_srcip_plist: "
			    "Only %d SGID (%d/%d) have SrcIP Configured",
			    new_cnt, no_srcip_cnt, cnt);
			if (new_cnt) {
				/* Allocate Memory to hold Src Point info. */
				n_plistp = kmem_zalloc(new_cnt *
				    sizeof (ibtl_cm_port_list_t), KM_SLEEP);

				tmp_n_plistp = n_plistp;
				for (i = 0; i < cnt; i++, plistp++) {
					if (plistp->p_src_ip.family ==
					    AF_UNSPEC)
						continue;

					bcopy(plistp, n_plistp,
					    sizeof (ibtl_cm_port_list_t));
					n_plistp->p_count = new_cnt;
					n_plistp++;
				}
				plistp = port_list_p[0];
				*port_list_p = tmp_n_plistp;
			} else {
				/*
				 * All entries we have, do not have IP-Addr
				 * configured so return empty hand.
				 */
				IBTF_DPRINTF_L2(cmlog,
				    "ibcm_arp_get_srcip_plist: None of SGID "
				    "found have SrcIP Configured");
				*port_list_p = NULL;
				ret = IBT_SRC_IP_NOT_FOUND;
			}
			IBTF_DPRINTF_L4(cmlog, "FREE OLD list %p, NEW list is "
			    "%p - %p", plistp, port_list_p, *port_list_p);
			kmem_free(plistp, cnt * sizeof (ibtl_cm_port_list_t));
		}
	}

srcip_plist_end:
	if (ibds.ibcm_arp_ip)
		kmem_free(ibds.ibcm_arp_ip, ibds.ibcm_arp_ibd_alloc *
		    sizeof (ibcm_arp_ip_t));

	return (ret);
}
