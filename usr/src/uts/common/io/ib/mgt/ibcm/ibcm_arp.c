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
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <net/if_arp.h>
#include <net/if_types.h>
#include <sys/file.h>
#include <sys/sockio.h>
#include <sys/pathname.h>
#include <inet/arp.h>
#include <sys/modctl.h>

#include <sys/ib/mgt/ibcm/ibcm_arp.h>

#include <sys/kstr.h>
#include <sys/tiuser.h>
#include <sys/t_kuser.h>

extern char cmlog[];

extern int ibcm_arp_pr_lookup(ibcm_arp_streams_t *ib_s, ibt_ip_addr_t *dst_addr,
    ibt_ip_addr_t *src_addr, uint8_t localroute, uint32_t bound_dev_if,
    ibcm_arp_pr_comp_func_t func);
extern void ibcm_arp_pr_arp_ack(mblk_t *mp);
extern void ibcm_arp_prwqn_delete(ibcm_arp_prwqn_t *wqnp);

_NOTE(SCHEME_PROTECTS_DATA("Unshared data", datab))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", ibt_ip_addr_s))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", ibcm_arp_ip_t))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", ibcm_arp_ibd_insts_t))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", ibcm_arp_prwqn_t))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", iocblk))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", msgb))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", queue))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", sockaddr_in))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", sockaddr_in6))

/*
 * ibcm_arp_get_ibaddr_cb
 */
static int
ibcm_arp_get_ibaddr_cb(void *arg, int status)
{
	ibcm_arp_prwqn_t	*wqnp = (ibcm_arp_prwqn_t *)arg;
	ibcm_arp_streams_t	*ib_s = (ibcm_arp_streams_t *)wqnp->arg;

	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_get_ibaddr_cb(ib_s: %p wqnp: %p)",
	    ib_s, wqnp);

	mutex_enter(&ib_s->lock);
	ib_s->status = status;
	ib_s->done = B_TRUE;

	IBTF_DPRINTF_L3(cmlog, "ibcm_arp_get_ibaddr_cb: SGID %llX:%llX "
	    "DGID: %llX:%llX", wqnp->sgid.gid_prefix, wqnp->sgid.gid_guid,
	    wqnp->dgid.gid_prefix, wqnp->dgid.gid_guid);

	/* lock is held by the caller. */
	cv_signal(&ib_s->cv);
	mutex_exit(&ib_s->lock);
	return (0);
}

/*
 * Lower read service procedure (messages coming back from arp/ip).
 * Process messages based on queue type.
 */
static int
ibcm_arp_lrsrv(queue_t *q)
{
	mblk_t *mp;
	ibcm_arp_streams_t *ib_s = q->q_ptr;

	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_lrsrv(%p, ibd_s: 0x%p)", q, ib_s);

	if (WR(q) == ib_s->arpqueue) {
		while (mp = getq(q)) {
			ibcm_arp_pr_arp_ack(mp);
		}
	}

	return (0);
}

/*
 * Lower write service procedure.
 * Used when lower streams are flow controlled.
 */
static int
ibcm_arp_lwsrv(queue_t *q)
{
	mblk_t *mp;

	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_lwsrv(%p)", q);

	while (mp = getq(q)) {
		if (canputnext(q)) {
			putnext(q, mp);
		} else {
			(void) putbq(q, mp);
			qenable(q);
			break;
		}
	}

	return (0);
}

/*
 * Lower read put procedure. Arp/ip messages come here.
 */
static int
ibcm_arp_lrput(queue_t *q, mblk_t *mp)
{
	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_lrput(0x%p, db_type: %d)",
	    q, DB_TYPE(mp));

	switch (DB_TYPE(mp)) {
		case M_FLUSH:
			/*
			 * Turn around
			 */
			if (*mp->b_rptr & FLUSHW) {
				*mp->b_rptr &= ~FLUSHR;
				qreply(q, mp);
				return (0);
			}
			freemsg(mp);
			break;
		case M_IOCACK:
		case M_IOCNAK:
		case M_DATA:
			/*
			 * This could be in interrupt context.
			 * Some of the ibt calls cannot be called in
			 * interrupt context, so
			 * put it in the queue and the message will be
			 * processed by service proccedure
			 */
			(void) putq(q, mp);
			qenable(q);
			break;
		default:
			IBTF_DPRINTF_L2(cmlog, "ibcm_arp_lrput: "
			    "got unknown msg <0x%x>\n", mp->b_datap->db_type);
			ASSERT(0);
			break;
	}

	return (0);
}

/*
 * Streams write queue module info
 */
static struct module_info ibcm_arp_winfo = {
	0,		/* module ID number */
	"ibcm",		/* module name */
	0,		/* min packet size */
	INFPSZ,
	49152,		/* STREAM queue high water mark -- 49152 */
	12		/* STREAM queue low water mark -- 12 */
};

/*
 * Streams lower write queue, for ibcm/ip requests.
 */
static struct qinit ibcm_arp_lwinit = {
	NULL,		/* qi_putp */
	ibcm_arp_lwsrv,	/* qi_srvp */
	NULL,		/* qi_qopen */
	NULL,		/* qi_qclose */
	NULL,		/* qi_qadmin */
	&ibcm_arp_winfo,	/* module info */
	NULL,		/* module statistics struct */
	NULL,
	NULL,
	STRUIOT_NONE	/* stream uio type is standard uiomove() */
};

/*
 * Streams lower read queue: read reply messages from ibcm/ip.
 */
static struct qinit ibcm_arp_lrinit = {
	ibcm_arp_lrput,	/* qi_putp */
	ibcm_arp_lrsrv,	/* qi_srvp */
	NULL,		/* qi_qopen */
	NULL,		/* qi_qclose */
	NULL,		/* qi_qadmin */
	&ibcm_arp_winfo,	/* module info */
	NULL,		/* module statistics struct */
	NULL,
	NULL,
	STRUIOT_NONE /* stream uio type is standard uiomove() */
};


static int
ibcm_arp_link_driver(ibcm_arp_streams_t *ib_s, char *path, queue_t **q,
    vnode_t **dev_vp)
{
	struct stdata *dev_stp;
	vnode_t *vp;
	int error;
	queue_t *rq;

	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_link_driver: Enter: %s", path);

	/* open the driver from inside the kernel */
	error = vn_open(path, UIO_SYSSPACE, FREAD|FWRITE, 0, &vp,
	    0, NULL);
	if (error) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_arp_link_driver: "
		    "vn_open('%s') failed\n", path);
		return (error);
	}
	*dev_vp = vp;

	dev_stp = vp->v_stream;
	*q = dev_stp->sd_wrq;

	VN_HOLD(vp);

	rq = RD(dev_stp->sd_wrq);
	RD(rq)->q_ptr = WR(rq)->q_ptr = ib_s;
	setq(rq, &ibcm_arp_lrinit, &ibcm_arp_lwinit, NULL, QMTSAFE,
	    SQ_CI|SQ_CO, B_FALSE);

	return (0);
}

extern struct qinit strdata;
extern struct qinit stwdata;

/*
 * Unlink ip, ibcm, icmp6 drivers
 */
/* ARGSUSED */
static int
ibcm_arp_unlink_driver(queue_t **q, vnode_t **dev_vp)
{
	vnode_t *vp = *dev_vp;
	struct stdata *dev_stp = vp->v_stream;
	queue_t *wrq, *rq;
	int	rc;

	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_unlink_driver: Enter: 0x%p", q);

	wrq = dev_stp->sd_wrq;
	rq = RD(wrq);

	disable_svc(rq);
	wait_svc(rq);
	flushq(rq, FLUSHALL);
	flushq(WR(rq), FLUSHALL);

	rq->q_ptr = wrq->q_ptr = dev_stp;

	setq(rq, &strdata, &stwdata, NULL, QMTSAFE, SQ_CI|SQ_CO, B_TRUE);

	if ((rc = VOP_CLOSE(vp, FREAD, 1, (offset_t)0, CRED(), NULL)) != 0) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_arp_unlink_driver: VOP_CLOSE "
		    "failed %d\n", rc);
	}
	VN_RELE(vp);

	return (0);
}

static int
ibcm_arp_unlink_drivers(ibcm_arp_streams_t *ib_s)
{
	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_unlink_drivers(%p)", ib_s);

	if (ib_s->arpqueue) {
		(void) ibcm_arp_unlink_driver(&ib_s->arpqueue, &ib_s->arp_vp);
	}

	return (0);
}

/*
 * Link ip, ibtl drivers below ibtl
 */
static int
ibcm_arp_link_drivers(ibcm_arp_streams_t *ib_s)
{
	int	rc;

	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_link_drivers(%p)", ib_s);

	if ((rc = ibcm_arp_link_driver(ib_s, "/dev/arp", &ib_s->arpqueue,
	    &ib_s->arp_vp)) != 0) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_arp_link_drivers: "
		    "ibcm_arp_link_driver failed: %d\n", rc);
		return (rc);
	}

	return (0);
}

ibt_status_t
ibcm_arp_get_ibaddr(ipaddr_t srcip, ipaddr_t destip, ib_gid_t *sgid,
    ib_gid_t *dgid)
{
	ibcm_arp_streams_t	*ib_s;
	ibt_ip_addr_t		srcaddr, destaddr;
	int			ret = 0;

	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_get_ibaddr(%lX, %lX, %p, %p)",
	    htonl(srcip), htonl(destip), sgid, dgid);

	ib_s = (ibcm_arp_streams_t *)kmem_zalloc(sizeof (ibcm_arp_streams_t),
	    KM_SLEEP);

	mutex_init(&ib_s->lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&ib_s->cv, NULL, CV_DRIVER, NULL);

	ret = ibcm_arp_link_drivers(ib_s);
	if (ret != 0) {
		IBTF_DPRINTF_L3(cmlog, "ibcm_arp_get_ibaddr: "
		    "ibcm_arp_link_drivers failed %d", ret);
		goto arp_ibaddr_error;
	}

	bzero(&destaddr, sizeof (ibt_ip_addr_t));
	bzero(&srcaddr, sizeof (ibt_ip_addr_t));

	mutex_enter(&ib_s->lock);
	ib_s->done = B_FALSE;
	mutex_exit(&ib_s->lock);

	destaddr.family = AF_INET_OFFLOAD;
	destaddr.un.ip4addr = destip;
	srcaddr.family = AF_INET_OFFLOAD;
	srcaddr.un.ip4addr = srcip;

	IBTF_DPRINTF_L3(cmlog, "ibcm_arp_get_ibaddr: SrcIP %lX, DstIP %lX",
	    srcaddr.un.ip4addr, destaddr.un.ip4addr);
	ret = ibcm_arp_pr_lookup(ib_s, &destaddr, &srcaddr, 0, NULL,
	    ibcm_arp_get_ibaddr_cb);

	IBTF_DPRINTF_L3(cmlog, "ibcm_arp_get_ibaddr: ibcm_arp_pr_lookup "
	    "returned: %d", ret);
	if (ret == 0) {
		mutex_enter(&ib_s->lock);
		while (ib_s->done != B_TRUE)
			cv_wait(&ib_s->cv, &ib_s->lock);
		mutex_exit(&ib_s->lock);
	}

	(void) ibcm_arp_unlink_drivers(ib_s);
	mutex_enter(&ib_s->lock);
	ret = ib_s->status;
	if (ret == 0) {
		ibcm_arp_prwqn_t *wqnp = ib_s->wqnp;
		if (sgid)
			*sgid = ib_s->wqnp->sgid;
		if (dgid)
			*dgid = ib_s->wqnp->dgid;

		IBTF_DPRINTF_L4(cmlog, "ibcm_arp_get_ibaddr: SGID: %llX:%llX"
		    " DGID: %llX:%llX",
		    ib_s->wqnp->sgid.gid_prefix, ib_s->wqnp->sgid.gid_guid,
		    ib_s->wqnp->dgid.gid_prefix, ib_s->wqnp->dgid.gid_guid);

		mutex_exit(&ib_s->lock);
		ibcm_arp_prwqn_delete(wqnp);
		mutex_enter(&ib_s->lock);
	}
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
ibcm_arp_ibd_mac2gid(ibcm_arp_ibd_insts_t *ibdp, ipaddr_t srcip,
    ib_gid_t *sgid)
{
	ibcm_arp_ip_t		*ipp;
	int			i;

	for (i = 0, ipp = ibdp->ibcm_arp_ip; i < ibdp->ibcm_arp_ibd_cnt;
	    i++, ipp++) {

		IBTF_DPRINTF_L4(cmlog, "ibcm_arp_ibd_mac2gid: Is %lX == %lX "
		    "GID %llX:%llX", srcip, ipp->ip_cm_sin.sin_addr,
		    ipp->ip_port_gid.gid_prefix, ipp->ip_port_gid.gid_guid);

		if (bcmp(&srcip, &ipp->ip_cm_sin.sin_addr, sizeof (in_addr_t))
		    == 0) {
			*sgid = ipp->ip_port_gid;

			IBTF_DPRINTF_L4(cmlog, "ibcm_arp_ibd_mac2gid: Found "
			    "GID %llX:%llX", sgid->gid_prefix, sgid->gid_guid);
			return (IBT_SUCCESS);
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
ibcm_do_lifconf(struct lifconf *lifcp, uint_t *bufsizep)
{
	int err;
	struct lifnum lifn;

	bzero(&lifn, sizeof (struct lifnum));
	lifn.lifn_family = AF_UNSPEC;

	err = ibcm_do_ip_ioctl(SIOCGLIFNUM, sizeof (struct lifnum), &lifn);
	if (err != 0)
		return (err);

	/*
	 * Pad the interface count to account for additional interfaces that
	 * may have been configured between the SIOCGLIFNUM and SIOCGLIFCONF.
	 */
	lifn.lifn_count += 4;

	bzero(lifcp, sizeof (struct lifconf));
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*lifcp))
	lifcp->lifc_family = AF_UNSPEC;
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
ibcm_arp_get_ibd_ipaddr(ibcm_arp_ibd_insts_t *ibds)
{
	int i, nifs, naddr = 0;
	uint_t bufsize;
	struct lifconf lifc;
	struct lifreq *lifrp;
	ibcm_arp_ip_t *ipp;

	if (ibcm_do_lifconf(&lifc, &bufsize) != 0)
		return (B_FALSE);

	nifs = lifc.lifc_len / sizeof (struct lifreq);
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
ibcm_arp_get_ibds(ibcm_arp_ibd_insts_t *ibdp)
{
	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_get_ibds(%p)", ibdp);

	ibcm_arp_get_ibd_insts(ibdp);

	IBTF_DPRINTF_L3(cmlog, "ibcm_arp_get_ibds: Found %d ibd instances",
	    ibdp->ibcm_arp_ibd_cnt);

	if (ibdp->ibcm_arp_ibd_cnt == 0)
		return (IBT_SRC_IP_NOT_FOUND);

	/* Get the IP addresses of active ports. */
	if (!ibcm_arp_get_ibd_ipaddr(ibdp)) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_arp_get_ibds: failed to get "
		    "ibd instance: IBT_SRC_IP_NOT_FOUND");
		return (IBT_SRC_IP_NOT_FOUND);
	}

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

	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_get_srcip_plist(%p, %llX)",
	    ipattr, flags);

	sgid.gid_prefix = sgid.gid_guid = 0;
	bzero(&ibds, sizeof (ibcm_arp_ibd_insts_t));
	ibds.ibcm_arp_ibd_alloc = IBCM_ARP_IBD_INSTANCES;
	ibds.ibcm_arp_ibd_cnt = 0;
	ibds.ibcm_arp_ip = (ibcm_arp_ip_t *)kmem_zalloc(
	    ibds.ibcm_arp_ibd_alloc * sizeof (ibcm_arp_ip_t), KM_SLEEP);

	ret = ibcm_arp_get_ibds(&ibds);
	if (ret != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_arp_get_srcip_plist: "
		    "ibcm_arp_get_ibds failed : 0x%x", ret);
		goto srcip_plist_end;
	}

	if (ipattr->ipa_src_ip.family != AF_UNSPEC) {
		ret = ibcm_arp_ibd_mac2gid(&ibds,
		    htonl(ipattr->ipa_src_ip.un.ip4addr), &sgid);
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

					IBTF_DPRINTF_L4(cmlog,
					    "ibcm_arp_get_srcip_plist: SrcIP: "
					    "%lX", plistp->p_src_ip.un.ip4addr);
				} else if (ipp->ip_inet_family == AF_INET6) {
					plistp->p_src_ip.family = AF_INET6;
					bcopy(&ipp->ip_cm_sin6.sin6_addr,
					    &plistp->p_src_ip.un.ip6addr,
					    sizeof (in6_addr_t));
				}
			}
		}
		if (no_srcip_configured == B_TRUE) {
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
/* Routines for warlock */

/* ARGSUSED */
static int
ibcm_arp_dummy_ibaddr_hdl(void *arg, int status)
{
	ibcm_arp_prwqn_t		dummy_wqn1;
	ibcm_arp_prwqn_t		dummy_wqn2;

	dummy_wqn1.func = ibcm_arp_get_ibaddr_cb;
	dummy_wqn2.func = ibcm_arp_dummy_ibaddr_hdl;

	IBTF_DPRINTF_L5(cmlog, "ibcm_arp_dummy_ibaddr_hdl: "
	    "dummy_wqn1.func %p %p", dummy_wqn1.func, dummy_wqn2.func);

	return (0);
}
