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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
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

#include <sys/dls.h>

extern char cmlog[];

extern int ibcm_resolver_pr_lookup(ibcm_arp_streams_t *ib_s,
    ibt_ip_addr_t *dst_addr, ibt_ip_addr_t *src_addr, zoneid_t myzoneid);
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
ibcm_arp_get_ibaddr(zoneid_t myzoneid, ibt_ip_addr_t srcaddr,
    ibt_ip_addr_t destaddr, ib_gid_t *sgid, ib_gid_t *dgid,
    ibt_ip_addr_t *saddrp)
{
	ibcm_arp_streams_t	*ib_s;
	ibcm_arp_prwqn_t	*wqnp;
	int			ret = 0;
	int			len;

	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_get_ibaddr(%d, %p, %p, %p, %p, %p)",
	    myzoneid, srcaddr, destaddr, sgid, dgid, saddrp);

	ib_s = (ibcm_arp_streams_t *)kmem_zalloc(sizeof (ibcm_arp_streams_t),
	    KM_SLEEP);

	mutex_init(&ib_s->lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&ib_s->cv, NULL, CV_DRIVER, NULL);

	mutex_enter(&ib_s->lock);
	ib_s->done = B_FALSE;
	mutex_exit(&ib_s->lock);

	ret = ibcm_resolver_pr_lookup(ib_s, &destaddr, &srcaddr, myzoneid);

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
			*sgid = wqnp->sgid;
		if (dgid)
			*dgid = wqnp->dgid;
		/*
		 * If the user supplied a address, then verify we got
		 * for the same address.
		 */
		if (wqnp->usrc_addr.family && sgid) {
			len = (wqnp->usrc_addr.family == AF_INET) ?
			    IP_ADDR_LEN : sizeof (in6_addr_t);
			if (bcmp(&wqnp->usrc_addr.un,
			    &wqnp->src_addr.un, len)) {
				IBTF_DPRINTF_L3(cmlog, "ibcm_arp_get_ibaddr: "
				    "srcaddr mismatch");

				/* Clean-up old data, and reset the done flag */
				ibcm_arp_delete_prwqn(wqnp);
				ib_s->done = B_FALSE;
				mutex_exit(&ib_s->lock);

				ret = ibcm_resolver_pr_lookup(ib_s, &srcaddr,
				    &srcaddr, myzoneid);
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
						*sgid = wqnp->dgid;

					if (saddrp)
						bcopy(&wqnp->src_addr, saddrp,
						    sizeof (ibt_ip_addr_t));

					IBTF_DPRINTF_L4(cmlog,
					    "ibcm_arp_get_ibaddr: "
					    "SGID: %llX:%llX DGID: %llX:%llX",
					    sgid->gid_prefix, sgid->gid_guid,
					    dgid->gid_prefix, dgid->gid_guid);

					ibcm_arp_delete_prwqn(wqnp);
				} else if (ret == 0) {
					if (wqnp)
						kmem_free(wqnp,
						    sizeof (ibcm_arp_prwqn_t));
				}
				goto arp_ibaddr_done;
			}
		}

		if (saddrp)
			bcopy(&wqnp->src_addr, saddrp, sizeof (ibt_ip_addr_t));

		IBTF_DPRINTF_L4(cmlog, "ibcm_arp_get_ibaddr: SGID: %llX:%llX"
		    " DGID: %llX:%llX", sgid->gid_prefix, sgid->gid_guid,
		    dgid->gid_prefix, dgid->gid_guid);

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
arp_ibaddr_done:
	ret = ib_s->status;
	mutex_exit(&ib_s->lock);

	mutex_destroy(&ib_s->lock);
	cv_destroy(&ib_s->cv);
	kmem_free(ib_s, sizeof (ibcm_arp_streams_t));

	if (ret)
		return (IBT_FAILURE);
	else
		return (IBT_SUCCESS);
}

void
ibcm_arp_free_ibds(ibcm_arp_ibd_insts_t *ibds)
{
	if (ibds->ibcm_arp_ip) {
		kmem_free(ibds->ibcm_arp_ip, ibds->ibcm_arp_ibd_alloc *
		    sizeof (ibcm_arp_ip_t));
		ibds->ibcm_arp_ibd_alloc = 0;
		ibds->ibcm_arp_ibd_cnt = 0;
		ibds->ibcm_arp_ip = NULL;
	}
}

static void
ibcm_arp_get_ibd_insts(ibcm_arp_ibd_insts_t *ibds)
{
	ibcm_arp_ip_t	*ipp;
	ib_gid_t	port_gid;
	ibt_part_attr_t	*attr_list, *attr;
	int		nparts;

	if ((ibt_get_all_part_attr(&attr_list, &nparts) != IBT_SUCCESS) ||
	    (nparts == 0)) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_arp_get_ibd_insts: Failed to "
		    "IB Part List - %d", nparts);
		ibds->ibcm_arp_ibd_alloc = 0;
		ibds->ibcm_arp_ibd_cnt = 0;
		ibds->ibcm_arp_ip = NULL;
		return;
	}
	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_get_ibd_insts: Found %d IB Part List",
	    nparts);

	ibds->ibcm_arp_ibd_alloc = nparts;
	ibds->ibcm_arp_ibd_cnt = 0;
	ibds->ibcm_arp_ip = (ibcm_arp_ip_t *)kmem_zalloc(
	    nparts * sizeof (ibcm_arp_ip_t), KM_SLEEP);

	attr = attr_list;
	while (nparts--) {
		if (ibt_get_port_state_byguid(attr->pa_hca_guid,
		    attr->pa_port, &port_gid, NULL) == IBT_SUCCESS) {

			ipp = &ibds->ibcm_arp_ip[ibds->ibcm_arp_ibd_cnt];
			ipp->ip_linkid = attr->pa_plinkid;
			ipp->ip_pkey = attr->pa_pkey;
			ipp->ip_hca_guid = attr->pa_hca_guid;
			ipp->ip_port_gid = port_gid;
			ibds->ibcm_arp_ibd_cnt++;

			IBTF_DPRINTF_L4(cmlog, "PartAttr: p-linkid %lX, "
			    "d-linkid %lX, pkey 0x%lX", ipp->ip_linkid,
			    attr->pa_dlinkid, ipp->ip_pkey);
			IBTF_DPRINTF_L4(cmlog, "hca_guid 0x%llX, "
			    "port_gid %llX \n attr-port_guid %llX",
			    ipp->ip_hca_guid, ipp->ip_port_gid.gid_guid,
			    attr->pa_port_guid);
		}
		attr++;
	}

	(void) ibt_free_part_attr(attr_list, ibds->ibcm_arp_ibd_alloc);
}

/*
 * Issue an ioctl down to IP.  There are several similar versions of this
 * function (e.g., rpcib_do_ip_ioctl()); clearly a utility routine is needed.
 */
static int
ibcm_do_ip_ioctl(int cmd, int len, void *arg)
{
	vnode_t *kkvp;
	TIUSER  *tiptr;
	struct  strioctl iocb;
	int	err = 0;

	if (lookupname("/dev/udp", UIO_SYSSPACE, FOLLOW, NULLVPP, &kkvp) != 0)
		return (EPROTO);

	if (t_kopen(NULL, kkvp->v_rdev, FREAD|FWRITE, &tiptr, CRED()) != 0) {
		VN_RELE(kkvp);
		return (EPROTO);
	}

	iocb.ic_cmd = cmd;
	iocb.ic_timout = 0;
	iocb.ic_len = len;
	iocb.ic_dp = (caddr_t)arg;
	err = kstr_ioctl(tiptr->fp->f_vnode, I_STR, (intptr_t)&iocb);
	(void) t_kclose(tiptr, 0);
	VN_RELE(kkvp);
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
	lifn.lifn_flags = LIFC_NOXMIT | LIFC_TEMPORARY | LIFC_ALLZONES;

	err = ibcm_do_ip_ioctl(SIOCGLIFNUM, sizeof (struct lifnum), &lifn);
	if (err != 0)
		return (err);

	IBTF_DPRINTF_L3(cmlog, "ibcm_do_lifconf: Family %d, lifn_count %d",
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
	lifcp->lifc_flags = LIFC_NOXMIT | LIFC_TEMPORARY | LIFC_ALLZONES;

	err = ibcm_do_ip_ioctl(SIOCGLIFCONF, sizeof (struct lifconf), lifcp);
	if (err != 0) {
		kmem_free(lifcp->lifc_buf, *bufsizep);
		return (err);
	}
	return (0);
}

static ibcm_arp_ip_t *
ibcm_arp_lookup(ibcm_arp_ibd_insts_t *ibds, char *linkname)
{
	datalink_id_t	linkid;
	int		i;

	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_lookup: linkname =  %s", linkname);

	/*
	 * If at first we don't succeed, try again, just in case it is in
	 * hiding. The first call requires the datalink management daemon
	 * (the authorative source of information about name to id mapping)
	 * to be present and answering upcalls, the second does not.
	 */
	if (dls_mgmt_get_linkid(linkname, &linkid) != 0) {
		if (dls_devnet_macname2linkid(linkname, &linkid) != 0) {
			IBTF_DPRINTF_L2(cmlog, "ibcm_arp_lookup: could not "
			    "get linkid from linkname (%s)", linkname);
			return (NULL);
		}
	}

	for (i = 0; i < ibds->ibcm_arp_ibd_cnt; i++) {
		if (ibds->ibcm_arp_ip[i].ip_linkid == linkid)
			return (&ibds->ibcm_arp_ip[i]);
	}

	IBTF_DPRINTF_L2(cmlog, "ibcm_arp_lookup: returning NULL for "
	    "linkname (%s)", linkname);
	return (NULL);
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
	struct lifreq *lifrp, lifr_copy;
	ibcm_arp_ip_t *ipp;
	lifgroupinfo_t	lifgr;
	int err;
	char    ifname[LIFNAMSIZ + 1];
	uint64_t	ifflags = 0;
	zoneid_t	ifzoneid;

	if (ibcm_do_lifconf(&lifc, &bufsize, family_loc) != 0)
		return (B_FALSE);

	nifs = lifc.lifc_len / sizeof (struct lifreq);

	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_get_ibd_ipaddr: Family %d, nifs %d",
	    family_loc, nifs);

	for (lifrp = lifc.lifc_req, i = 0; i < nifs; i++, lifrp++) {

		if (lifrp->lifr_type != IFT_IB)
			continue;

		IBTF_DPRINTF_L4(cmlog, "\nInterface# : %d", i);
		IBTF_DPRINTF_L4(cmlog, "lifr_name : %s, lifr_family :%X, "
		    "lifr_type : 0x%lX", lifrp->lifr_name,
		    lifrp->lifr_addr.ss_family, lifrp->lifr_type);

		(void) strlcpy(ifname, lifrp->lifr_name, LIFNAMSIZ);

		/* Get ZoneId. */
		lifr_copy = *lifrp;
		ifzoneid = 0;
		err = ibcm_do_ip_ioctl(SIOCGLIFZONE, sizeof (struct lifreq),
		    &lifr_copy);
		if (err != 0) {
			IBTF_DPRINTF_L2(cmlog, "IFZONE ioctl Failed: err = %d",
			    err);
		} else  {
			IBTF_DPRINTF_L4(cmlog, "lifr_zoneid     : 0x%X",
			    lifr_copy.lifr_zoneid);
			ifzoneid = lifr_copy.lifr_zoneid;
		}

		/* Get IfIndex. */
		lifr_copy = *lifrp;
		err = ibcm_do_ip_ioctl(SIOCGLIFINDEX, sizeof (struct lifreq),
		    &lifr_copy);
		if (err != 0) {
			IBTF_DPRINTF_L2(cmlog, "IFINDEX ioctl Failed: err = %d",
			    err);
		} else
			IBTF_DPRINTF_L4(cmlog, "lifr_index      : 0x%X",
			    lifr_copy.lifr_index);

		/* Get Interface flags. */
		lifr_copy = *lifrp;
		err = ibcm_do_ip_ioctl(SIOCGLIFFLAGS, sizeof (struct lifreq),
		    &lifr_copy);
		if (err != 0) {
			IBTF_DPRINTF_L2(cmlog, "IFFLAGS ioctl Failed: err = %d",
			    err);
		} else  {
			ifflags = lifr_copy.lifr_flags;
			IBTF_DPRINTF_L4(cmlog, "lifr_flags      : 0x%llX",
			    ifflags);
		}

		lifr_copy = *lifrp;
		err = ibcm_do_ip_ioctl(SIOCGLIFGROUPNAME,
		    sizeof (struct lifreq), &lifr_copy);
		if (err != 0) {
			IBTF_DPRINTF_L3(cmlog, "IFGroupName ioctl Failed: "
			    "err = %d", err);
		}

		if (lifr_copy.lifr_groupname[0] != '\0') {
			IBTF_DPRINTF_L4(cmlog, "lifr_groupname  : %s",
			    lifr_copy.lifr_groupname);
			(void) strlcpy(lifgr.gi_grname,
			    lifr_copy.lifr_groupname, LIFGRNAMSIZ);
			err = ibcm_do_ip_ioctl(SIOCGLIFGROUPINFO,
			    sizeof (struct lifgroupinfo), &lifgr);
			if (err != 0) {
				IBTF_DPRINTF_L2(cmlog, "IFGroupINFO ioctl "
				    "Failed: err = %d", err);
			} else {
				IBTF_DPRINTF_L4(cmlog, "lifgroupinfo details");
				IBTF_DPRINTF_L4(cmlog, "grname : %s, grifname :"
				    " %s, m4ifname : %s, m6ifname : %s",
				    lifgr.gi_grname, lifgr.gi_grifname,
				    lifgr.gi_m4ifname, lifgr.gi_m6ifname);
				IBTF_DPRINTF_L4(cmlog, "gi_bcifname  : %s",
				    lifgr.gi_bcifname);
				IBTF_DPRINTF_L4(cmlog, "gi_v4 %d, gi_v6 %d, "
				    "gi_nv4 %d, gi_nv6 %d, gi_mactype %d",
				    lifgr.gi_v4, lifgr.gi_v6, lifgr.gi_nv4,
				    lifgr.gi_nv6, lifgr.gi_mactype);

				(void) strlcpy(ifname, lifgr.gi_bcifname,
				    LIFNAMSIZ);
			}
		}

		if ((ipp = ibcm_arp_lookup(ibds, ifname)) == NULL)
			continue;

		ipp->ip_zoneid = ifzoneid;	/* Copy back the zoneid info */
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
		ibcm_arp_free_ibds(ibdp);
		return (IBT_SRC_IP_NOT_FOUND);
	}

#ifdef DEBUG
	for (i = 0; i < ibdp->ibcm_arp_ibd_cnt; i++) {
		char    my_buf[INET6_ADDRSTRLEN];
		ibcm_arp_ip_t	*aip = &ibdp->ibcm_arp_ip[i];

		IBTF_DPRINTF_L4(cmlog, "ibcm_arp_get_ibds: Linkid %d Family %d "
		    "PKey 0x%lX \n HCAGUID 0x%llX SGID %llX:%llX",
		    aip->ip_linkid, aip->ip_inet_family, aip->ip_pkey,
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
