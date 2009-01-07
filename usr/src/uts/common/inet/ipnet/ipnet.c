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

/*
 * The ipnet device defined here provides access to packets at the IP layer. To
 * provide access to packets at this layer it registers a callback function in
 * the ip module and when there are open instances of the device ip will pass
 * packets into the device. Packets from ip are passed on the input, output and
 * loopback paths. Internally the module returns to ip as soon as possible by
 * deferring processing using a taskq.
 *
 * Management of the devices in /dev/ipnet/ is handled by the devname
 * filesystem and use of the neti interfaces.  This module registers for NIC
 * events using the neti framework so that when IP interfaces are bought up,
 * taken down etc. the ipnet module is notified and its view of the interfaces
 * configured on the system adjusted.  On attach, the module gets an initial
 * view of the system again using the neti framework but as it has already
 * registered for IP interface events, it is still up-to-date with any changes.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/cred.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/dlpi.h>
#include <sys/strsun.h>
#include <sys/id_space.h>
#include <sys/kmem.h>
#include <sys/mkdev.h>
#include <sys/neti.h>
#include <net/if.h>
#include <sys/errno.h>
#include <sys/list.h>
#include <sys/ksynch.h>
#include <sys/hook_event.h>
#include <sys/stropts.h>
#include <sys/sysmacros.h>
#include <inet/ip.h>
#include <inet/ip_multi.h>
#include <inet/ip6.h>
#include <inet/ipnet.h>

static struct module_info ipnet_minfo = {
	1,		/* mi_idnum */
	"ipnet",	/* mi_idname */
	0,		/* mi_minpsz */
	INFPSZ,		/* mi_maxpsz */
	2048,		/* mi_hiwat */
	0		/* mi_lowat */
};

/*
 * List to hold static view of ipnetif_t's on the system. This is needed to
 * avoid holding the lock protecting the avl tree of ipnetif's over the
 * callback into the dev filesystem.
 */
typedef struct ipnetif_cbdata {
	char		ic_ifname[LIFNAMSIZ];
	dev_t		ic_dev;
	list_node_t	ic_next;
} ipnetif_cbdata_t;

/*
 * Convenience enumerated type for ipnet_accept().  It describes the
 * properties of a given ipnet_addrp_t relative to a single ipnet_t
 * client stream.  The values represent whether the address is ...
 */
typedef enum {
	IPNETADDR_MYADDR,	/* an address on my ipnetif_t. */
	IPNETADDR_MBCAST,	/* a multicast or broadcast address. */
	IPNETADDR_UNKNOWN	/* none of the above. */
} ipnet_addrtype_t;

/* Argument used for the ipnet_nicevent_taskq callback. */
typedef struct ipnet_nicevent_s {
	nic_event_t		ipne_event;
	net_handle_t		ipne_protocol;
	netstackid_t		ipne_stackid;
	uint64_t		ipne_ifindex;
	uint64_t		ipne_lifindex;
	char			ipne_ifname[LIFNAMSIZ];
} ipnet_nicevent_t;

static dev_info_t	*ipnet_dip;
static major_t		ipnet_major;
static ddi_taskq_t	*ipnet_taskq;		/* taskq for packets */
static ddi_taskq_t	*ipnet_nicevent_taskq;	/* taskq for NIC events */
static id_space_t	*ipnet_minor_space;
static const int	IPNET_MINOR_LO = 1; 	/* minor number for /dev/lo0 */
static const int 	IPNET_MINOR_MIN = 2; 	/* start of dynamic minors */
static dl_info_ack_t	ipnet_infoack = IPNET_INFO_ACK_INIT;
static ipnet_acceptfn_t	ipnet_accept, ipnet_loaccept;

static void	ipnet_input(mblk_t *);
static int	ipnet_wput(queue_t *, mblk_t *);
static int	ipnet_rsrv(queue_t *);
static int	ipnet_open(queue_t *, dev_t *, int, int, cred_t *);
static int	ipnet_close(queue_t *);
static void	ipnet_ioctl(queue_t *, mblk_t *);
static void	ipnet_iocdata(queue_t *, mblk_t *);
static void 	ipnet_wputnondata(queue_t *, mblk_t *);
static int	ipnet_attach(dev_info_t *, ddi_attach_cmd_t);
static int	ipnet_detach(dev_info_t *, ddi_detach_cmd_t);
static int	ipnet_devinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static void	ipnet_inforeq(queue_t *q, mblk_t *mp);
static void	ipnet_bindreq(queue_t *q, mblk_t *mp);
static void	ipnet_unbindreq(queue_t *q, mblk_t *mp);
static void	ipnet_dlpromisconreq(queue_t *q, mblk_t *mp);
static void	ipnet_dlpromiscoffreq(queue_t *q, mblk_t *mp);
static int	ipnet_join_allmulti(ipnetif_t *, ipnet_stack_t *);
static void	ipnet_leave_allmulti(ipnetif_t *, ipnet_stack_t *);
static int	ipnet_nicevent_cb(hook_event_token_t, hook_data_t, void *);
static void	ipnet_nicevent_task(void *);
static ipnetif_t *ipnet_create_if(const char *, uint64_t, ipnet_stack_t *);
static void	ipnet_remove_if(ipnetif_t *, ipnet_stack_t *);
static ipnetif_addr_t *ipnet_match_lif(ipnetif_t *, lif_if_t, boolean_t);
static ipnetif_t *ipnet_if_getby_index(uint64_t, ipnet_stack_t *);
static ipnetif_t *ipnet_if_getby_dev(dev_t, ipnet_stack_t *);
static boolean_t ipnet_if_in_zone(ipnetif_t *, zoneid_t, ipnet_stack_t *);
static void	ipnet_if_zonecheck(ipnetif_t *, ipnet_stack_t *);
static int	ipnet_populate_if(net_handle_t, ipnet_stack_t *, boolean_t);
static int 	ipnet_if_compare_name(const void *, const void *);
static int 	ipnet_if_compare_index(const void *, const void *);
static void	ipnet_add_ifaddr(uint64_t, ipnetif_t *, net_handle_t);
static void	ipnet_delete_ifaddr(ipnetif_addr_t *, ipnetif_t *, boolean_t);
static void	ipnetif_refhold(ipnetif_t *);
static void	ipnetif_refrele(ipnetif_t *);
static void	ipnet_walkers_inc(ipnet_stack_t *);
static void	ipnet_walkers_dec(ipnet_stack_t *);
static void	ipnet_register_netihook(ipnet_stack_t *);
static void	*ipnet_stack_init(netstackid_t, netstack_t *);
static void	ipnet_stack_fini(netstackid_t, void *);

static struct qinit ipnet_rinit = {
	NULL,		/* qi_putp */
	ipnet_rsrv,	/* qi_srvp */
	ipnet_open,	/* qi_qopen */
	ipnet_close,	/* qi_qclose */
	NULL,		/* qi_qadmin */
	&ipnet_minfo,	/* qi_minfo */
};

static struct qinit ipnet_winit = {
	ipnet_wput,	/* qi_putp */
	NULL,		/* qi_srvp */
	NULL,		/* qi_qopen */
	NULL,		/* qi_qclose */
	NULL,		/* qi_qadmin */
	&ipnet_minfo,	/* qi_minfo */
};

static struct streamtab ipnet_info = {
	&ipnet_rinit, &ipnet_winit
};

DDI_DEFINE_STREAM_OPS(ipnet_ops, nulldev, nulldev, ipnet_attach,
    ipnet_detach, nodev, ipnet_devinfo, D_MP | D_MTPERMOD, &ipnet_info,
    ddi_quiesce_not_supported);

static struct modldrv modldrv = {
	&mod_driverops,
	"STREAMS ipnet driver",
	&ipnet_ops
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

/*
 * Walk the list of physical interfaces on the machine, for each
 * interface create a new ipnetif_t and add any addresses to it. We
 * need to do the walk twice, once for IPv4 and once for IPv6.
 *
 * The interfaces are destroyed as part of ipnet_stack_fini() for each
 * stack.  Note that we cannot do this initialization in
 * ipnet_stack_init(), since ipnet_stack_init() cannot fail.
 */
static int
ipnet_if_init(void)
{
	netstack_handle_t	nh;
	netstack_t		*ns;
	ipnet_stack_t		*ips;
	int			ret = 0;

	netstack_next_init(&nh);
	while ((ns = netstack_next(&nh)) != NULL) {
		ips = ns->netstack_ipnet;
		if ((ret = ipnet_populate_if(ips->ips_ndv4, ips, B_FALSE)) == 0)
			ret = ipnet_populate_if(ips->ips_ndv6, ips, B_TRUE);
		netstack_rele(ns);
		if (ret != 0)
			break;
	}
	netstack_next_fini(&nh);
	return (ret);
}

/*
 * Standard module entry points.
 */
int
_init(void)
{
	int ret;
	boolean_t netstack_registered = B_FALSE;

	if ((ipnet_major = ddi_name_to_major("ipnet")) == (major_t)-1)
		return (ENODEV);
	ipnet_minor_space = id_space_create("ipnet_minor_space",
	    IPNET_MINOR_MIN, MAXMIN32);

	/*
	 * We call ddi_taskq_create() with nthread == 1 to ensure in-order
	 * delivery of packets to clients.  Note that we need to create the
	 * taskqs before calling netstack_register() since ipnet_stack_init()
	 * registers callbacks that use 'em.
	 */
	ipnet_taskq = ddi_taskq_create(NULL, "ipnet", 1, TASKQ_DEFAULTPRI, 0);
	ipnet_nicevent_taskq = ddi_taskq_create(NULL, "ipnet_nic_event_queue",
	    1, TASKQ_DEFAULTPRI, 0);
	if (ipnet_taskq == NULL || ipnet_nicevent_taskq == NULL) {
		ret = ENOMEM;
		goto done;
	}

	netstack_register(NS_IPNET, ipnet_stack_init, NULL, ipnet_stack_fini);
	netstack_registered = B_TRUE;

	if ((ret = ipnet_if_init()) == 0)
		ret = mod_install(&modlinkage);
done:
	if (ret != 0) {
		if (ipnet_taskq != NULL)
			ddi_taskq_destroy(ipnet_taskq);
		if (ipnet_nicevent_taskq != NULL)
			ddi_taskq_destroy(ipnet_nicevent_taskq);
		if (netstack_registered)
			netstack_unregister(NS_IPNET);
		id_space_destroy(ipnet_minor_space);
	}
	return (ret);
}

int
_fini(void)
{
	int err;

	if ((err = mod_remove(&modlinkage)) != 0)
		return (err);

	netstack_unregister(NS_IPNET);
	ddi_taskq_destroy(ipnet_nicevent_taskq);
	ddi_taskq_destroy(ipnet_taskq);
	id_space_destroy(ipnet_minor_space);
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static void
ipnet_register_netihook(ipnet_stack_t *ips)
{
	int		ret;
	zoneid_t	zoneid;
	netid_t		netid;

	HOOK_INIT(ips->ips_nicevents, ipnet_nicevent_cb, "ipnet_nicevents",
	    ips);

	/*
	 * It is possible for an exclusive stack to be in the process of
	 * shutting down here, and the netid and protocol lookups could fail
	 * in that case.
	 */
	zoneid = netstackid_to_zoneid(ips->ips_netstack->netstack_stackid);
	if ((netid = net_zoneidtonetid(zoneid)) == -1)
		return;

	if ((ips->ips_ndv4 = net_protocol_lookup(netid, NHF_INET)) != NULL) {
		if ((ret = net_hook_register(ips->ips_ndv4, NH_NIC_EVENTS,
		    ips->ips_nicevents)) != 0) {
			VERIFY(net_protocol_release(ips->ips_ndv4) == 0);
			ips->ips_ndv4 = NULL;
			cmn_err(CE_WARN, "unable to register IPv4 netinfo hooks"
			    " in zone %d: %d", zoneid, ret);
		}
	}
	if ((ips->ips_ndv6 = net_protocol_lookup(netid, NHF_INET6)) != NULL) {
		if ((ret = net_hook_register(ips->ips_ndv6, NH_NIC_EVENTS,
		    ips->ips_nicevents)) != 0) {
			VERIFY(net_protocol_release(ips->ips_ndv6) == 0);
			ips->ips_ndv6 = NULL;
			cmn_err(CE_WARN, "unable to register IPv6 netinfo hooks"
			    " in zone %d: %d", zoneid, ret);
		}
	}
}

/*
 * This function is called on attach to build an initial view of the
 * interfaces on the system. It will be called once for IPv4 and once
 * for IPv6, although there is only one ipnet interface for both IPv4
 * and IPv6 there are separate address lists.
 */
static int
ipnet_populate_if(net_handle_t nd, ipnet_stack_t *ips, boolean_t isv6)
{
	phy_if_t		phyif;
	lif_if_t		lif;
	ipnetif_t		*ipnetif;
	char			name[LIFNAMSIZ];
	boolean_t		new_if = B_FALSE;
	uint64_t		ifflags;
	int			ret = 0;

	/*
	 * If ipnet_register_netihook() was unable to initialize this
	 * stack's net_handle_t, then we cannot populate any interface
	 * information.  This usually happens when we attempted to
	 * grab a net_handle_t as a stack was shutting down.  We don't
	 * want to fail the entire _init() operation because of a
	 * stack shutdown (other stacks will continue to work just
	 * fine), so we silently return success here.
	 */
	if (nd == NULL)
		return (0);

	/*
	 * Make sure we're not processing NIC events during the
	 * population of our interfaces and address lists.
	 */
	mutex_enter(&ips->ips_event_lock);

	for (phyif = net_phygetnext(nd, 0); phyif != 0;
	    phyif = net_phygetnext(nd, phyif)) {
		if (net_getifname(nd, phyif, name, LIFNAMSIZ) != 0)
			continue;
		if ((ipnetif = ipnet_if_getby_index(phyif, ips)) == NULL) {
			ipnetif = ipnet_create_if(name, phyif, ips);
			if (ipnetif == NULL) {
				ret = ENOMEM;
				goto done;
			}
			new_if = B_TRUE;
		}
		ipnetif->if_flags |=
		    isv6 ? IPNETIF_IPV6PLUMBED : IPNETIF_IPV4PLUMBED;

		for (lif = net_lifgetnext(nd, phyif, 0); lif != 0;
		    lif = net_lifgetnext(nd, phyif, lif)) {
			/*
			 * Skip addresses that aren't up.  We'll add
			 * them when we receive an NE_LIF_UP event.
			 */
			if (net_getlifflags(nd, phyif, lif, &ifflags) != 0 ||
			    !(ifflags & IFF_UP))
				continue;
			/* Don't add it if we already have it. */
			if (ipnet_match_lif(ipnetif, lif, isv6) != NULL)
				continue;
			ipnet_add_ifaddr(lif, ipnetif, nd);
		}
		if (!new_if)
			ipnetif_refrele(ipnetif);
	}

done:
	mutex_exit(&ips->ips_event_lock);
	return (ret);
}

static int
ipnet_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (ddi_create_minor_node(dip, "lo0", S_IFCHR, IPNET_MINOR_LO,
	    DDI_PSEUDO, 0) == DDI_FAILURE)
		return (DDI_FAILURE);

	ipnet_dip = dip;
	return (DDI_SUCCESS);
}

static int
ipnet_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	ASSERT(dip == ipnet_dip);
	ddi_remove_minor_node(ipnet_dip, NULL);
	ipnet_dip = NULL;
	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
ipnet_devinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int error = DDI_FAILURE;

	switch (infocmd) {
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2DEVINFO:
		if (ipnet_dip != NULL) {
			*result = ipnet_dip;
			error = DDI_SUCCESS;
		}
		break;
	}
	return (error);
}

/* ARGSUSED */
static int
ipnet_open(queue_t *rq, dev_t *dev, int oflag, int sflag, cred_t *crp)
{
	ipnet_t		*ipnet;
	netstack_t	*ns = NULL;
	ipnet_stack_t	*ips;
	int		err = 0;
	zoneid_t	zoneid = crgetzoneid(crp);

	/*
	 * If the system is labeled, only the global zone is allowed to open
	 * IP observability nodes.
	 */
	if (is_system_labeled() && zoneid != GLOBAL_ZONEID)
		return (EACCES);

	/* We don't support open as a module */
	if (sflag & MODOPEN)
		return (ENOTSUP);

	/* This driver is self-cloning, we don't support re-open. */
	if (rq->q_ptr != NULL)
		return (EBUSY);

	if ((ipnet = kmem_zalloc(sizeof (*ipnet), KM_NOSLEEP)) == NULL)
		return (ENOMEM);

	VERIFY((ns = netstack_find_by_cred(crp)) != NULL);
	ips = ns->netstack_ipnet;

	rq->q_ptr = WR(rq)->q_ptr = ipnet;
	ipnet->ipnet_rq = rq;
	ipnet->ipnet_minor = (minor_t)id_alloc(ipnet_minor_space);
	ipnet->ipnet_zoneid = zoneid;
	ipnet->ipnet_dlstate = DL_UNBOUND;
	ipnet->ipnet_sap = 0;
	ipnet->ipnet_ns = ns;

	/*
	 * We need to hold ips_event_lock here as any NE_LIF_DOWN events need
	 * to be processed after ipnet_if is set and the ipnet_t has been
	 * inserted in the ips_str_list.
	 */
	mutex_enter(&ips->ips_event_lock);
	if (getminor(*dev) == IPNET_MINOR_LO) {
		ipnet->ipnet_flags |= IPNET_LOMODE;
		ipnet->ipnet_acceptfn = ipnet_loaccept;
	} else {
		ipnet->ipnet_acceptfn = ipnet_accept;
		ipnet->ipnet_if = ipnet_if_getby_dev(*dev, ips);
		if (ipnet->ipnet_if == NULL ||
		    !ipnet_if_in_zone(ipnet->ipnet_if, zoneid, ips)) {
			err = ENODEV;
			goto done;
		}
	}

	mutex_enter(&ips->ips_walkers_lock);
	while (ips->ips_walkers_cnt != 0)
		cv_wait(&ips->ips_walkers_cv, &ips->ips_walkers_lock);
	list_insert_head(&ips->ips_str_list, ipnet);
	*dev = makedevice(getmajor(*dev), ipnet->ipnet_minor);
	qprocson(rq);

	/*
	 * Only register our callback if we're the first open client; we call
	 * unregister in close() for the last open client.
	 */
	if (list_head(&ips->ips_str_list) == list_tail(&ips->ips_str_list))
		ipobs_register_hook(ns, ipnet_input);
	mutex_exit(&ips->ips_walkers_lock);

done:
	mutex_exit(&ips->ips_event_lock);
	if (err != 0) {
		netstack_rele(ns);
		id_free(ipnet_minor_space, ipnet->ipnet_minor);
		if (ipnet->ipnet_if != NULL)
			ipnetif_refrele(ipnet->ipnet_if);
		kmem_free(ipnet, sizeof (*ipnet));
	}
	return (err);
}

static int
ipnet_close(queue_t *rq)
{
	ipnet_t		*ipnet = rq->q_ptr;
	ipnet_stack_t	*ips = ipnet->ipnet_ns->netstack_ipnet;

	if (ipnet->ipnet_flags & IPNET_PROMISC_PHYS)
		ipnet_leave_allmulti(ipnet->ipnet_if, ips);
	if (ipnet->ipnet_flags & IPNET_PROMISC_MULTI)
		ipnet_leave_allmulti(ipnet->ipnet_if, ips);

	mutex_enter(&ips->ips_walkers_lock);
	while (ips->ips_walkers_cnt != 0)
		cv_wait(&ips->ips_walkers_cv, &ips->ips_walkers_lock);

	qprocsoff(rq);

	list_remove(&ips->ips_str_list, ipnet);
	if (ipnet->ipnet_if != NULL)
		ipnetif_refrele(ipnet->ipnet_if);
	id_free(ipnet_minor_space, ipnet->ipnet_minor);
	kmem_free(ipnet, sizeof (*ipnet));

	if (list_is_empty(&ips->ips_str_list))
		ipobs_unregister_hook(ips->ips_netstack, ipnet_input);

	mutex_exit(&ips->ips_walkers_lock);
	netstack_rele(ips->ips_netstack);
	return (0);
}

static int
ipnet_wput(queue_t *q, mblk_t *mp)
{
	switch (mp->b_datap->db_type) {
	case M_FLUSH:
		if (*mp->b_rptr & FLUSHW) {
			flushq(q, FLUSHDATA);
			*mp->b_rptr &= ~FLUSHW;
		}
		if (*mp->b_rptr & FLUSHR)
			qreply(q, mp);
		else
			freemsg(mp);
		break;
	case M_PROTO:
	case M_PCPROTO:
		ipnet_wputnondata(q, mp);
		break;
	case M_IOCTL:
		ipnet_ioctl(q, mp);
		break;
	case M_IOCDATA:
		ipnet_iocdata(q, mp);
		break;
	default:
		freemsg(mp);
		break;
	}
	return (0);
}

static int
ipnet_rsrv(queue_t *q)
{
	mblk_t *mp;

	while ((mp = getq(q)) != NULL) {
		ASSERT(DB_TYPE(mp) == M_DATA);
		if (canputnext(q)) {
			putnext(q, mp);
		} else {
			(void) putbq(q, mp);
			break;
		}
	}
	return (0);
}

static void
ipnet_ioctl(queue_t *q, mblk_t *mp)
{
	struct iocblk *iocp = (struct iocblk *)mp->b_rptr;

	switch (iocp->ioc_cmd) {
	case DLIOCRAW:
		miocack(q, mp, 0, 0);
		break;
	case DLIOCIPNETINFO:
		if (iocp->ioc_count == TRANSPARENT) {
			mcopyin(mp, NULL, sizeof (uint_t), NULL);
			qreply(q, mp);
			break;
		}
		/* Fallthrough, we don't support I_STR with DLIOCIPNETINFO. */
	default:
		miocnak(q, mp, 0, EINVAL);
		break;
	}
}

static void
ipnet_iocdata(queue_t *q, mblk_t *mp)
{
	struct iocblk	*iocp = (struct iocblk *)mp->b_rptr;
	ipnet_t		*ipnet = q->q_ptr;

	switch (iocp->ioc_cmd) {
	case DLIOCIPNETINFO:
		if (*(int *)mp->b_cont->b_rptr == 1)
			ipnet->ipnet_flags |= IPNET_INFO;
		else if (*(int *)mp->b_cont->b_rptr == 0)
			ipnet->ipnet_flags &= ~IPNET_INFO;
		else
			goto iocnak;
		miocack(q, mp, 0, DL_IPNETINFO_VERSION);
		break;
	default:
	iocnak:
		miocnak(q, mp, 0, EINVAL);
		break;
	}
}

static void
ipnet_wputnondata(queue_t *q, mblk_t *mp)
{
	union DL_primitives	*dlp = (union DL_primitives *)mp->b_rptr;
	t_uscalar_t		prim = dlp->dl_primitive;

	switch (prim) {
	case DL_INFO_REQ:
		ipnet_inforeq(q, mp);
		break;
	case DL_UNBIND_REQ:
		ipnet_unbindreq(q, mp);
		break;
	case DL_BIND_REQ:
		ipnet_bindreq(q, mp);
		break;
	case DL_PROMISCON_REQ:
		ipnet_dlpromisconreq(q, mp);
		break;
	case DL_PROMISCOFF_REQ:
		ipnet_dlpromiscoffreq(q, mp);
		break;
	case DL_UNITDATA_REQ:
	case DL_DETACH_REQ:
	case DL_PHYS_ADDR_REQ:
	case DL_SET_PHYS_ADDR_REQ:
	case DL_ENABMULTI_REQ:
	case DL_DISABMULTI_REQ:
	case DL_ATTACH_REQ:
		dlerrorack(q, mp, prim, DL_UNSUPPORTED, 0);
		break;
	default:
		dlerrorack(q, mp, prim, DL_BADPRIM, 0);
		break;
	}
}

static void
ipnet_inforeq(queue_t *q, mblk_t *mp)
{
	dl_info_ack_t	*dlip;
	size_t		size = sizeof (dl_info_ack_t) + sizeof (ushort_t);

	if (MBLKL(mp) < DL_INFO_REQ_SIZE) {
		dlerrorack(q, mp, DL_INFO_REQ, DL_BADPRIM, 0);
		return;
	}

	if ((mp = mexchange(q, mp, size, M_PCPROTO, DL_INFO_ACK)) == NULL)
		return;

	dlip = (dl_info_ack_t *)mp->b_rptr;
	*dlip = ipnet_infoack;
	qreply(q, mp);
}

static void
ipnet_bindreq(queue_t *q, mblk_t *mp)
{
	union   DL_primitives *dlp = (union DL_primitives *)mp->b_rptr;
	int32_t sap;
	ipnet_t	*ipnet = q->q_ptr;

	if (MBLKL(mp) < DL_BIND_REQ_SIZE) {
		dlerrorack(q, mp, DL_BIND_REQ, DL_BADPRIM, 0);
		return;
	}

	sap = dlp->bind_req.dl_sap;
	if (sap != IPV4_VERSION && sap != IPV6_VERSION && sap != 0) {
		dlerrorack(q, mp, DL_BIND_REQ, DL_BADSAP, 0);
	} else {
		ipnet->ipnet_sap = sap;
		ipnet->ipnet_dlstate = DL_IDLE;
		dlbindack(q, mp, sap, 0, 0, 0, 0);
	}
}

static void
ipnet_unbindreq(queue_t *q, mblk_t *mp)
{
	ipnet_t	*ipnet = q->q_ptr;

	if (MBLKL(mp) < DL_UNBIND_REQ_SIZE) {
		dlerrorack(q, mp, DL_UNBIND_REQ, DL_BADPRIM, 0);
		return;
	}

	if (ipnet->ipnet_dlstate != DL_IDLE) {
		dlerrorack(q, mp, DL_UNBIND_REQ, DL_OUTSTATE, 0);
	} else {
		ipnet->ipnet_dlstate = DL_UNBOUND;
		ipnet->ipnet_sap = 0;
		dlokack(q, mp, DL_UNBIND_REQ);
	}
}

static void
ipnet_dlpromisconreq(queue_t *q, mblk_t *mp)
{
	ipnet_t		*ipnet = q->q_ptr;
	t_uscalar_t	level;
	int		err;

	if (MBLKL(mp) < DL_PROMISCON_REQ_SIZE) {
		dlerrorack(q, mp, DL_PROMISCON_REQ, DL_BADPRIM, 0);
		return;
	}

	if (ipnet->ipnet_flags & IPNET_LOMODE) {
		dlokack(q, mp, DL_PROMISCON_REQ);
		return;
	}

	level = ((dl_promiscon_req_t *)mp->b_rptr)->dl_level;
	if (level == DL_PROMISC_PHYS || level == DL_PROMISC_MULTI) {
		if ((err = ipnet_join_allmulti(ipnet->ipnet_if,
		    ipnet->ipnet_ns->netstack_ipnet)) != 0) {
			dlerrorack(q, mp, DL_PROMISCON_REQ, DL_SYSERR, err);
			return;
		}
	}

	switch (level) {
	case DL_PROMISC_PHYS:
		ipnet->ipnet_flags |= IPNET_PROMISC_PHYS;
		break;
	case DL_PROMISC_SAP:
		ipnet->ipnet_flags |= IPNET_PROMISC_SAP;
		break;
	case DL_PROMISC_MULTI:
		ipnet->ipnet_flags |= IPNET_PROMISC_MULTI;
		break;
	default:
		dlerrorack(q, mp, DL_PROMISCON_REQ, DL_BADPRIM, 0);
		return;
	}

	dlokack(q, mp, DL_PROMISCON_REQ);
}

static void
ipnet_dlpromiscoffreq(queue_t *q, mblk_t *mp)
{
	ipnet_t		*ipnet = q->q_ptr;
	t_uscalar_t	level;
	uint16_t	orig_ipnet_flags = ipnet->ipnet_flags;

	if (MBLKL(mp) < DL_PROMISCOFF_REQ_SIZE) {
		dlerrorack(q, mp, DL_PROMISCOFF_REQ, DL_BADPRIM, 0);
		return;
	}

	if (ipnet->ipnet_flags & IPNET_LOMODE) {
		dlokack(q, mp, DL_PROMISCOFF_REQ);
		return;
	}

	level = ((dl_promiscon_req_t *)mp->b_rptr)->dl_level;
	switch (level) {
	case DL_PROMISC_PHYS:
		if (ipnet->ipnet_flags & IPNET_PROMISC_PHYS)
			ipnet->ipnet_flags &= ~IPNET_PROMISC_PHYS;
		break;
	case DL_PROMISC_SAP:
		if (ipnet->ipnet_flags & IPNET_PROMISC_SAP)
			ipnet->ipnet_flags &= ~IPNET_PROMISC_SAP;
		break;
	case DL_PROMISC_MULTI:
		if (ipnet->ipnet_flags & IPNET_PROMISC_MULTI)
			ipnet->ipnet_flags &= ~IPNET_PROMISC_MULTI;
		break;
	default:
		dlerrorack(q, mp, DL_PROMISCOFF_REQ, DL_BADPRIM, 0);
		return;
	}

	if (orig_ipnet_flags == ipnet->ipnet_flags) {
		dlerrorack(q, mp, DL_PROMISCOFF_REQ, DL_NOTENAB, 0);
		return;
	}

	if (level == DL_PROMISC_PHYS || level == DL_PROMISC_MULTI) {
		ipnet_leave_allmulti(ipnet->ipnet_if,
		    ipnet->ipnet_ns->netstack_ipnet);
	}

	dlokack(q, mp, DL_PROMISCOFF_REQ);
}

static int
ipnet_join_allmulti(ipnetif_t *ipnetif, ipnet_stack_t *ips)
{
	int		err = 0;
	ip_stack_t	*ipst = ips->ips_netstack->netstack_ip;
	uint64_t	index = ipnetif->if_index;

	mutex_enter(&ips->ips_event_lock);
	if (ipnetif->if_multicnt == 0) {
		ASSERT((ipnetif->if_flags &
		    (IPNETIF_IPV4ALLMULTI | IPNETIF_IPV6ALLMULTI)) == 0);
		if (ipnetif->if_flags & IPNETIF_IPV4PLUMBED) {
			err = ip_join_allmulti(index, B_FALSE, ipst);
			if (err != 0)
				goto done;
			ipnetif->if_flags |= IPNETIF_IPV4ALLMULTI;
		}
		if (ipnetif->if_flags & IPNETIF_IPV6PLUMBED) {
			err = ip_join_allmulti(index, B_TRUE, ipst);
			if (err != 0 &&
			    (ipnetif->if_flags & IPNETIF_IPV4ALLMULTI)) {
				(void) ip_leave_allmulti(index, B_FALSE, ipst);
				ipnetif->if_flags &= ~IPNETIF_IPV4ALLMULTI;
				goto done;
			}
			ipnetif->if_flags |= IPNETIF_IPV6ALLMULTI;
		}
	}
	ipnetif->if_multicnt++;

done:
	mutex_exit(&ips->ips_event_lock);
	return (err);
}

static void
ipnet_leave_allmulti(ipnetif_t *ipnetif, ipnet_stack_t *ips)
{
	int		err;
	ip_stack_t	*ipst = ips->ips_netstack->netstack_ip;
	uint64_t	index = ipnetif->if_index;

	mutex_enter(&ips->ips_event_lock);
	ASSERT(ipnetif->if_multicnt != 0);
	if (--ipnetif->if_multicnt == 0) {
		if (ipnetif->if_flags & IPNETIF_IPV4ALLMULTI) {
			err = ip_leave_allmulti(index, B_FALSE, ipst);
			ASSERT(err == 0 || err == ENODEV);
			ipnetif->if_flags &= ~IPNETIF_IPV4ALLMULTI;
		}
		if (ipnetif->if_flags & IPNETIF_IPV6ALLMULTI) {
			err = ip_leave_allmulti(index, B_TRUE, ipst);
			ASSERT(err == 0 || err == ENODEV);
			ipnetif->if_flags &= ~IPNETIF_IPV6ALLMULTI;
		}
	}
	mutex_exit(&ips->ips_event_lock);
}

static mblk_t *
ipnet_addheader(ipobs_hook_data_t *ihd, mblk_t *mp)
{
	mblk_t		*dlhdr;
	dl_ipnetinfo_t	*dl;

	if ((dlhdr = allocb(sizeof (dl_ipnetinfo_t), BPRI_HI)) == NULL) {
		freemsg(mp);
		return (NULL);
	}
	dl = (dl_ipnetinfo_t *)dlhdr->b_rptr;
	dl->dli_version = DL_IPNETINFO_VERSION;
	dl->dli_len = htons(sizeof (*dl));
	dl->dli_ipver = ihd->ihd_ipver;
	dl->dli_srczone = BE_64((uint64_t)ihd->ihd_zsrc);
	dl->dli_dstzone = BE_64((uint64_t)ihd->ihd_zdst);
	dlhdr->b_wptr += sizeof (*dl);
	dlhdr->b_cont = mp;

	return (dlhdr);
}

static ipnet_addrtype_t
ipnet_get_addrtype(ipnet_t *ipnet, ipnet_addrp_t *addr)
{
	list_t			*list;
	ipnetif_t		*ipnetif = ipnet->ipnet_if;
	ipnetif_addr_t		*ifaddr;
	ipnet_addrtype_t	addrtype = IPNETADDR_UNKNOWN;

	/* First check if the address is multicast or limited broadcast. */
	switch (addr->iap_family) {
	case AF_INET:
		if (CLASSD(*(addr->iap_addr4)) ||
		    *(addr->iap_addr4) == INADDR_BROADCAST)
			return (IPNETADDR_MBCAST);
		break;
	case AF_INET6:
		if (IN6_IS_ADDR_MULTICAST(addr->iap_addr6))
			return (IPNETADDR_MBCAST);
		break;
	}

	/*
	 * Walk the address list to see if the address belongs to our
	 * interface or is one of our subnet broadcast addresses.
	 */
	mutex_enter(&ipnetif->if_addr_lock);
	list = (addr->iap_family == AF_INET) ?
	    &ipnetif->if_ip4addr_list : &ipnetif->if_ip6addr_list;
	for (ifaddr = list_head(list);
	    ifaddr != NULL && addrtype == IPNETADDR_UNKNOWN;
	    ifaddr = list_next(list, ifaddr)) {
		/*
		 * If we're not in the global zone, then only look at
		 * addresses in our zone.
		 */
		if (ipnet->ipnet_zoneid != GLOBAL_ZONEID &&
		    ipnet->ipnet_zoneid != ifaddr->ifa_zone)
			continue;
		switch (addr->iap_family) {
		case AF_INET:
			if (ifaddr->ifa_ip4addr != INADDR_ANY &&
			    *(addr->iap_addr4) == ifaddr->ifa_ip4addr)
				addrtype = IPNETADDR_MYADDR;
			else if (ifaddr->ifa_brdaddr != INADDR_ANY &&
			    *(addr->iap_addr4) == ifaddr->ifa_brdaddr)
				addrtype = IPNETADDR_MBCAST;
			break;
		case AF_INET6:
			if (IN6_ARE_ADDR_EQUAL(addr->iap_addr6,
			    &ifaddr->ifa_ip6addr))
				addrtype = IPNETADDR_MYADDR;
			break;
		}
	}
	mutex_exit(&ipnetif->if_addr_lock);

	return (addrtype);
}

/*
 * Verify if the packet contained in ihd should be passed up to the
 * ipnet client stream.
 */
static boolean_t
ipnet_accept(ipnet_t *ipnet, ipobs_hook_data_t *ihd, ipnet_addrp_t *src,
    ipnet_addrp_t *dst)
{
	boolean_t		obsif;
	uint64_t		ifindex = ipnet->ipnet_if->if_index;
	ipnet_addrtype_t	srctype, dsttype;

	srctype = ipnet_get_addrtype(ipnet, src);
	dsttype = ipnet_get_addrtype(ipnet, dst);

	/*
	 * If the packet's ifindex matches ours, or the packet's group ifindex
	 * matches ours, it's on the interface we're observing.  (Thus,
	 * observing on the group ifindex matches all ifindexes in the group.)
	 */
	obsif = (ihd->ihd_ifindex == ifindex || ihd->ihd_grifindex == ifindex);

	/*
	 * Do not allow an ipnet stream to see packets that are not from or to
	 * its zone.  The exception is when zones are using the shared stack
	 * model.  In this case, streams in the global zone have visibility
	 * into other shared-stack zones, and broadcast and multicast traffic
	 * is visible by all zones in the stack.
	 */
	if (ipnet->ipnet_zoneid != GLOBAL_ZONEID &&
	    dsttype != IPNETADDR_MBCAST) {
		if (ipnet->ipnet_zoneid != ihd->ihd_zsrc &&
		    ipnet->ipnet_zoneid != ihd->ihd_zdst)
			return (B_FALSE);
	}

	/*
	 * If DL_PROMISC_SAP isn't enabled, then the bound SAP must match the
	 * packet's IP version.
	 */
	if (!(ipnet->ipnet_flags & IPNET_PROMISC_SAP) &&
	    ipnet->ipnet_sap != ihd->ihd_ipver)
		return (B_FALSE);

	/* If the destination address is ours, then accept the packet. */
	if (dsttype == IPNETADDR_MYADDR)
		return (B_TRUE);

	/*
	 * If DL_PROMISC_PHYS is enabled, then we can see all packets that are
	 * sent or received on the interface we're observing, or packets that
	 * have our source address (this allows us to see packets we send).
	 */
	if (ipnet->ipnet_flags & IPNET_PROMISC_PHYS) {
		if (srctype == IPNETADDR_MYADDR || obsif)
			return (B_TRUE);
	}

	/*
	 * We accept multicast and broadcast packets transmitted or received
	 * on the interface we're observing.
	 */
	if (dsttype == IPNETADDR_MBCAST && obsif)
		return (B_TRUE);

	return (B_FALSE);
}

/*
 * Verify if the packet contained in ihd should be passed up to the ipnet
 * client stream that's in IPNET_LOMODE.
 */
/* ARGSUSED */
static boolean_t
ipnet_loaccept(ipnet_t *ipnet, ipobs_hook_data_t *ihd, ipnet_addrp_t *src,
    ipnet_addrp_t *dst)
{
	if (ihd->ihd_htype != IPOBS_HOOK_LOCAL)
		return (B_FALSE);

	/*
	 * An ipnet stream must not see packets that are not from/to its zone.
	 */
	if (ipnet->ipnet_zoneid != GLOBAL_ZONEID) {
		if (ipnet->ipnet_zoneid != ihd->ihd_zsrc &&
		    ipnet->ipnet_zoneid != ihd->ihd_zdst)
			return (B_FALSE);
	}

	return (ipnet->ipnet_sap == 0 || ipnet->ipnet_sap == ihd->ihd_ipver);
}

static void
ipnet_dispatch(void *arg)
{
	mblk_t			*mp = arg;
	ipobs_hook_data_t	*ihd = (ipobs_hook_data_t *)mp->b_rptr;
	ipnet_t			*ipnet;
	mblk_t			*netmp;
	list_t			*list;
	ipnet_stack_t		*ips = ihd->ihd_stack->netstack_ipnet;
	ipnet_addrp_t		src, dst;

	if (ihd->ihd_ipver == IPV4_VERSION) {
		src.iap_family = dst.iap_family = AF_INET;
		src.iap_addr4 = &((ipha_t *)(ihd->ihd_mp->b_rptr))->ipha_src;
		dst.iap_addr4 = &((ipha_t *)(ihd->ihd_mp->b_rptr))->ipha_dst;
	} else {
		src.iap_family = dst.iap_family = AF_INET6;
		src.iap_addr6 = &((ip6_t *)(ihd->ihd_mp->b_rptr))->ip6_src;
		dst.iap_addr6 = &((ip6_t *)(ihd->ihd_mp->b_rptr))->ip6_dst;
	}

	ipnet_walkers_inc(ips);

	list = &ips->ips_str_list;
	for (ipnet = list_head(list); ipnet != NULL;
	    ipnet = list_next(list, ipnet)) {
		if (!(*ipnet->ipnet_acceptfn)(ipnet, ihd, &src, &dst))
			continue;

		if (list_next(list, ipnet) == NULL) {
			netmp = ihd->ihd_mp;
			ihd->ihd_mp = NULL;
		} else {
			if ((netmp = dupmsg(ihd->ihd_mp)) == NULL &&
			    (netmp = copymsg(ihd->ihd_mp)) == NULL) {
				atomic_inc_64(&ips->ips_drops);
				continue;
			}
		}

		if (ipnet->ipnet_flags & IPNET_INFO) {
			if ((netmp = ipnet_addheader(ihd, netmp)) == NULL) {
				atomic_inc_64(&ips->ips_drops);
				continue;
			}
		}

		if (ipnet->ipnet_rq->q_first == NULL &&
		    canputnext(ipnet->ipnet_rq)) {
			putnext(ipnet->ipnet_rq, netmp);
		} else if (canput(ipnet->ipnet_rq)) {
			(void) putq(ipnet->ipnet_rq, netmp);
		} else {
			freemsg(netmp);
			atomic_inc_64(&ips->ips_drops);
		}
	}

	ipnet_walkers_dec(ips);

	freemsg(ihd->ihd_mp);
	freemsg(mp);
}

static void
ipnet_input(mblk_t *mp)
{
	ipobs_hook_data_t  *ihd = (ipobs_hook_data_t *)mp->b_rptr;

	if (ddi_taskq_dispatch(ipnet_taskq, ipnet_dispatch, mp, DDI_NOSLEEP) !=
	    DDI_SUCCESS) {
		atomic_inc_64(&ihd->ihd_stack->netstack_ipnet->ips_drops);
		freemsg(ihd->ihd_mp);
		freemsg(mp);
	}
}

/*
 * Create a new ipnetif_t and new minor node for it.  If creation is
 * successful the new ipnetif_t is inserted into an avl_tree
 * containing ipnetif's for this stack instance.
 */
static ipnetif_t *
ipnet_create_if(const char *name, uint64_t index, ipnet_stack_t *ips)
{
	ipnetif_t	*ipnetif;
	avl_index_t	where = 0;
	minor_t		ifminor;

	/*
	 * Because ipnet_create_if() can be called from a NIC event
	 * callback, it should not block.
	 */
	ifminor = (minor_t)id_alloc_nosleep(ipnet_minor_space);
	if (ifminor == (minor_t)-1)
		return (NULL);
	if ((ipnetif = kmem_zalloc(sizeof (*ipnetif), KM_NOSLEEP)) == NULL) {
		id_free(ipnet_minor_space, ifminor);
		return (NULL);
	}

	(void) strlcpy(ipnetif->if_name, name, LIFNAMSIZ);
	ipnetif->if_index = index;

	mutex_init(&ipnetif->if_addr_lock, NULL, MUTEX_DEFAULT, 0);
	list_create(&ipnetif->if_ip4addr_list, sizeof (ipnetif_addr_t),
	    offsetof(ipnetif_addr_t, ifa_link));
	list_create(&ipnetif->if_ip6addr_list, sizeof (ipnetif_addr_t),
	    offsetof(ipnetif_addr_t, ifa_link));
	ipnetif->if_dev = makedevice(ipnet_major, ifminor);
	mutex_init(&ipnetif->if_reflock, NULL, MUTEX_DEFAULT, 0);
	ipnetif->if_refcnt = 1;

	mutex_enter(&ips->ips_avl_lock);
	VERIFY(avl_find(&ips->ips_avl_by_index, &index, &where) == NULL);
	avl_insert(&ips->ips_avl_by_index, ipnetif, where);
	VERIFY(avl_find(&ips->ips_avl_by_name, (void *)name, &where) == NULL);
	avl_insert(&ips->ips_avl_by_name, ipnetif, where);
	mutex_exit(&ips->ips_avl_lock);

	return (ipnetif);
}

static void
ipnet_remove_if(ipnetif_t *ipnetif, ipnet_stack_t *ips)
{
	ipnet_t	*ipnet;

	ipnet_walkers_inc(ips);
	/* Send a SIGHUP to all open streams associated with this ipnetif. */
	for (ipnet = list_head(&ips->ips_str_list); ipnet != NULL;
	    ipnet = list_next(&ips->ips_str_list, ipnet)) {
		if (ipnet->ipnet_if == ipnetif)
			(void) putnextctl(ipnet->ipnet_rq, M_HANGUP);
	}
	ipnet_walkers_dec(ips);
	mutex_enter(&ips->ips_avl_lock);
	avl_remove(&ips->ips_avl_by_index, ipnetif);
	avl_remove(&ips->ips_avl_by_name, ipnetif);
	mutex_exit(&ips->ips_avl_lock);
	/* Release the reference we implicitly held in ipnet_create_if(). */
	ipnetif_refrele(ipnetif);
}

static void
ipnet_purge_addrlist(list_t *addrlist)
{
	ipnetif_addr_t *ifa;

	while ((ifa = list_head(addrlist)) != NULL) {
		list_remove(addrlist, ifa);
		kmem_free(ifa, sizeof (*ifa));
	}
}

static void
ipnet_free_if(ipnetif_t *ipnetif)
{
	ASSERT(ipnetif->if_refcnt == 0);

	/* Remove IPv4/v6 address lists from the ipnetif */
	ipnet_purge_addrlist(&ipnetif->if_ip4addr_list);
	list_destroy(&ipnetif->if_ip4addr_list);
	ipnet_purge_addrlist(&ipnetif->if_ip6addr_list);
	list_destroy(&ipnetif->if_ip6addr_list);
	mutex_destroy(&ipnetif->if_addr_lock);
	mutex_destroy(&ipnetif->if_reflock);
	id_free(ipnet_minor_space, getminor(ipnetif->if_dev));
	kmem_free(ipnetif, sizeof (*ipnetif));
}

/*
 * Create an ipnetif_addr_t with the given logical interface id (lif)
 * and add it to the supplied ipnetif.  The lif is the netinfo
 * representation of logical interface id, and we use this id to match
 * incoming netinfo events against our lists of addresses.
 */
static void
ipnet_add_ifaddr(uint64_t lif, ipnetif_t *ipnetif, net_handle_t nd)
{
	ipnetif_addr_t		*ifaddr;
	zoneid_t		zoneid;
	struct sockaddr_in	bcast;
	struct sockaddr_storage	addr;
	net_ifaddr_t		type = NA_ADDRESS;
	uint64_t		phyif = ipnetif->if_index;

	if (net_getlifaddr(nd, phyif, lif, 1, &type, &addr) != 0 ||
	    net_getlifzone(nd, phyif, lif, &zoneid) != 0)
		return;
	if ((ifaddr = kmem_alloc(sizeof (*ifaddr), KM_NOSLEEP)) == NULL)
		return;

	ifaddr->ifa_zone = zoneid;
	ifaddr->ifa_id = lif;

	switch (addr.ss_family) {
	case AF_INET:
		ifaddr->ifa_ip4addr =
		    ((struct sockaddr_in *)&addr)->sin_addr.s_addr;
		/*
		 * Try and get the broadcast address.  Note that it's okay for
		 * an interface to not have a broadcast address, so we don't
		 * fail the entire operation if net_getlifaddr() fails here.
		 */
		type = NA_BROADCAST;
		if (net_getlifaddr(nd, phyif, lif, 1, &type, &bcast) == 0)
			ifaddr->ifa_brdaddr = bcast.sin_addr.s_addr;
		break;
	case AF_INET6:
		ifaddr->ifa_ip6addr = ((struct sockaddr_in6 *)&addr)->sin6_addr;
		break;
	}

	mutex_enter(&ipnetif->if_addr_lock);
	list_insert_tail(addr.ss_family == AF_INET ?
	    &ipnetif->if_ip4addr_list : &ipnetif->if_ip6addr_list, ifaddr);
	mutex_exit(&ipnetif->if_addr_lock);
}

static void
ipnet_delete_ifaddr(ipnetif_addr_t *ifaddr, ipnetif_t *ipnetif, boolean_t isv6)
{
	mutex_enter(&ipnetif->if_addr_lock);
	list_remove(isv6 ?
	    &ipnetif->if_ip6addr_list : &ipnetif->if_ip4addr_list, ifaddr);
	mutex_exit(&ipnetif->if_addr_lock);
	kmem_free(ifaddr, sizeof (*ifaddr));
}

static void
ipnet_plumb_ev(uint64_t ifindex, const char *ifname, ipnet_stack_t *ips,
    boolean_t isv6)
{
	ipnetif_t	*ipnetif;
	boolean_t	refrele_needed = B_TRUE;

	if ((ipnetif = ipnet_if_getby_index(ifindex, ips)) == NULL) {
		ipnetif = ipnet_create_if(ifname, ifindex, ips);
		refrele_needed = B_FALSE;
	}
	if (ipnetif != NULL) {
		ipnetif->if_flags |=
		    isv6 ? IPNETIF_IPV6PLUMBED : IPNETIF_IPV4PLUMBED;
	}

	if (ipnetif->if_multicnt != 0) {
		if (ip_join_allmulti(ifindex, isv6,
		    ips->ips_netstack->netstack_ip) == 0) {
			ipnetif->if_flags |=
			    isv6 ? IPNETIF_IPV6ALLMULTI : IPNETIF_IPV4ALLMULTI;
		}
	}

	if (refrele_needed)
		ipnetif_refrele(ipnetif);
}

static void
ipnet_unplumb_ev(uint64_t ifindex, ipnet_stack_t *ips, boolean_t isv6)
{
	ipnetif_t	*ipnetif;

	if ((ipnetif = ipnet_if_getby_index(ifindex, ips)) == NULL)
		return;

	mutex_enter(&ipnetif->if_addr_lock);
	ipnet_purge_addrlist(isv6 ?
	    &ipnetif->if_ip6addr_list : &ipnetif->if_ip4addr_list);
	mutex_exit(&ipnetif->if_addr_lock);

	/*
	 * Note that we have one ipnetif for both IPv4 and IPv6, but we receive
	 * separate NE_UNPLUMB events for IPv4 and IPv6.  We remove the ipnetif
	 * if both IPv4 and IPv6 interfaces have been unplumbed.
	 */
	ipnetif->if_flags &= isv6 ? ~IPNETIF_IPV6PLUMBED : ~IPNETIF_IPV4PLUMBED;
	if (!(ipnetif->if_flags & (IPNETIF_IPV4PLUMBED | IPNETIF_IPV6PLUMBED)))
		ipnet_remove_if(ipnetif, ips);
	ipnetif_refrele(ipnetif);
}

static void
ipnet_lifup_ev(uint64_t ifindex, uint64_t lifindex, net_handle_t nd,
    ipnet_stack_t *ips, boolean_t isv6)
{
	ipnetif_t	*ipnetif;
	ipnetif_addr_t	*ifaddr;

	if ((ipnetif = ipnet_if_getby_index(ifindex, ips)) == NULL)
		return;
	if ((ifaddr = ipnet_match_lif(ipnetif, lifindex, isv6)) != NULL) {
		/*
		 * We must have missed a NE_LIF_DOWN event.  Delete this
		 * ifaddr and re-create it.
		 */
		ipnet_delete_ifaddr(ifaddr, ipnetif, isv6);
	}

	ipnet_add_ifaddr(lifindex, ipnetif, nd);
	ipnetif_refrele(ipnetif);
}

static void
ipnet_lifdown_ev(uint64_t ifindex, uint64_t lifindex, ipnet_stack_t *ips,
    boolean_t isv6)
{
	ipnetif_t	*ipnetif;
	ipnetif_addr_t	*ifaddr;

	if ((ipnetif = ipnet_if_getby_index(ifindex, ips)) == NULL)
		return;
	if ((ifaddr = ipnet_match_lif(ipnetif, lifindex, isv6)) != NULL)
		ipnet_delete_ifaddr(ifaddr, ipnetif, isv6);
	ipnetif_refrele(ipnetif);
	/*
	 * Make sure that open streams on this ipnetif are still allowed to
	 * have it open.
	 */
	ipnet_if_zonecheck(ipnetif, ips);
}

/*
 * This callback from the NIC event framework dispatches a taskq as the event
 * handlers may block.
 */
/* ARGSUSED */
static int
ipnet_nicevent_cb(hook_event_token_t token, hook_data_t info, void *arg)
{
	ipnet_stack_t		*ips = arg;
	hook_nic_event_t	*hn = (hook_nic_event_t *)info;
	ipnet_nicevent_t	*ipne;

	if ((ipne = kmem_alloc(sizeof (ipnet_nicevent_t), KM_NOSLEEP)) == NULL)
		return (0);
	ipne->ipne_event = hn->hne_event;
	ipne->ipne_protocol = hn->hne_protocol;
	ipne->ipne_stackid = ips->ips_netstack->netstack_stackid;
	ipne->ipne_ifindex = hn->hne_nic;
	ipne->ipne_lifindex = hn->hne_lif;
	if (hn->hne_datalen != 0) {
		(void) strlcpy(ipne->ipne_ifname, hn->hne_data,
		    sizeof (ipne->ipne_ifname));
	}
	(void) ddi_taskq_dispatch(ipnet_nicevent_taskq, ipnet_nicevent_task,
	    ipne, DDI_NOSLEEP);
	return (0);
}

static void
ipnet_nicevent_task(void *arg)
{
	ipnet_nicevent_t	*ipne = arg;
	netstack_t		*ns;
	ipnet_stack_t		*ips;
	boolean_t		isv6;

	if ((ns = netstack_find_by_stackid(ipne->ipne_stackid)) == NULL)
		goto done;
	ips = ns->netstack_ipnet;
	isv6 = (ipne->ipne_protocol == ips->ips_ndv6);

	mutex_enter(&ips->ips_event_lock);
	switch (ipne->ipne_event) {
	case NE_PLUMB:
		ipnet_plumb_ev(ipne->ipne_ifindex, ipne->ipne_ifname, ips,
		    isv6);
		break;
	case NE_UNPLUMB:
		ipnet_unplumb_ev(ipne->ipne_ifindex, ips, isv6);
		break;
	case NE_LIF_UP:
		ipnet_lifup_ev(ipne->ipne_ifindex, ipne->ipne_lifindex,
		    ipne->ipne_protocol, ips, isv6);
		break;
	case NE_LIF_DOWN:
		ipnet_lifdown_ev(ipne->ipne_ifindex, ipne->ipne_lifindex, ips,
		    isv6);
		break;
	default:
		break;
	}
	mutex_exit(&ips->ips_event_lock);
done:
	if (ns != NULL)
		netstack_rele(ns);
	kmem_free(ipne, sizeof (ipnet_nicevent_t));
}

dev_t
ipnet_if_getdev(char *name, zoneid_t zoneid)
{
	netstack_t	*ns;
	ipnet_stack_t	*ips;
	ipnetif_t	*ipnetif;
	dev_t		dev = (dev_t)-1;

	if (is_system_labeled() && zoneid != GLOBAL_ZONEID)
		return (dev);
	if ((ns = netstack_find_by_zoneid(zoneid)) == NULL)
		return (dev);

	ips = ns->netstack_ipnet;
	mutex_enter(&ips->ips_avl_lock);
	if ((ipnetif = avl_find(&ips->ips_avl_by_name, name, NULL)) != NULL) {
		if (ipnet_if_in_zone(ipnetif, zoneid, ips))
			dev = ipnetif->if_dev;
	}
	mutex_exit(&ips->ips_avl_lock);
	netstack_rele(ns);

	return (dev);
}

static ipnetif_t *
ipnet_if_getby_index(uint64_t id, ipnet_stack_t *ips)
{
	ipnetif_t	*ipnetif;

	mutex_enter(&ips->ips_avl_lock);
	if ((ipnetif = avl_find(&ips->ips_avl_by_index, &id, NULL)) != NULL)
		ipnetif_refhold(ipnetif);
	mutex_exit(&ips->ips_avl_lock);
	return (ipnetif);
}

static ipnetif_t *
ipnet_if_getby_dev(dev_t dev, ipnet_stack_t *ips)
{
	ipnetif_t	*ipnetif;
	avl_tree_t	*tree;

	mutex_enter(&ips->ips_avl_lock);
	tree = &ips->ips_avl_by_index;
	for (ipnetif = avl_first(tree); ipnetif != NULL;
	    ipnetif = avl_walk(tree, ipnetif, AVL_AFTER)) {
		if (ipnetif->if_dev == dev) {
			ipnetif_refhold(ipnetif);
			break;
		}
	}
	mutex_exit(&ips->ips_avl_lock);
	return (ipnetif);
}

static ipnetif_addr_t *
ipnet_match_lif(ipnetif_t *ipnetif, lif_if_t lid, boolean_t isv6)
{
	ipnetif_addr_t	*ifaddr;
	list_t		*list;

	mutex_enter(&ipnetif->if_addr_lock);
	list = isv6 ? &ipnetif->if_ip6addr_list : &ipnetif->if_ip4addr_list;
	for (ifaddr = list_head(list); ifaddr != NULL;
	    ifaddr = list_next(list, ifaddr)) {
		if (lid == ifaddr->ifa_id)
			break;
	}
	mutex_exit(&ipnetif->if_addr_lock);
	return (ifaddr);
}

/* ARGSUSED */
static void *
ipnet_stack_init(netstackid_t stackid, netstack_t *ns)
{
	ipnet_stack_t	*ips;

	ips = kmem_zalloc(sizeof (*ips), KM_SLEEP);
	ips->ips_netstack = ns;
	mutex_init(&ips->ips_avl_lock, NULL, MUTEX_DEFAULT, 0);
	avl_create(&ips->ips_avl_by_index, ipnet_if_compare_index,
	    sizeof (ipnetif_t), offsetof(ipnetif_t, if_avl_by_index));
	avl_create(&ips->ips_avl_by_name, ipnet_if_compare_name,
	    sizeof (ipnetif_t), offsetof(ipnetif_t, if_avl_by_name));
	mutex_init(&ips->ips_walkers_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&ips->ips_walkers_cv, NULL, CV_DRIVER, NULL);
	list_create(&ips->ips_str_list, sizeof (ipnet_t),
	    offsetof(ipnet_t, ipnet_next));
	ipnet_register_netihook(ips);
	return (ips);
}

/* ARGSUSED */
static void
ipnet_stack_fini(netstackid_t stackid, void *arg)
{
	ipnet_stack_t	*ips = arg;
	ipnetif_t	*ipnetif, *nipnetif;

	if (ips->ips_ndv4 != NULL) {
		VERIFY(net_hook_unregister(ips->ips_ndv4, NH_NIC_EVENTS,
		    ips->ips_nicevents) == 0);
		VERIFY(net_protocol_release(ips->ips_ndv4) == 0);
	}
	if (ips->ips_ndv6 != NULL) {
		VERIFY(net_hook_unregister(ips->ips_ndv6, NH_NIC_EVENTS,
		    ips->ips_nicevents) == 0);
		VERIFY(net_protocol_release(ips->ips_ndv6) == 0);
	}
	hook_free(ips->ips_nicevents);

	for (ipnetif = avl_first(&ips->ips_avl_by_index); ipnetif != NULL;
	    ipnetif = nipnetif) {
		nipnetif = AVL_NEXT(&ips->ips_avl_by_index, ipnetif);
		ipnet_remove_if(ipnetif, ips);
	}
	avl_destroy(&ips->ips_avl_by_index);
	avl_destroy(&ips->ips_avl_by_name);
	mutex_destroy(&ips->ips_avl_lock);
	mutex_destroy(&ips->ips_walkers_lock);
	cv_destroy(&ips->ips_walkers_cv);
	list_destroy(&ips->ips_str_list);
	kmem_free(ips, sizeof (*ips));
}

/* Do any of the addresses in addrlist belong the supplied zoneid? */
static boolean_t
ipnet_addrs_in_zone(list_t *addrlist, zoneid_t zoneid)
{
	ipnetif_addr_t *ifa;

	for (ifa = list_head(addrlist); ifa != NULL;
	    ifa = list_next(addrlist, ifa)) {
		if (ifa->ifa_zone == zoneid)
			return (B_TRUE);
	}
	return (B_FALSE);
}

/* Should the supplied ipnetif be visible from the supplied zoneid? */
static boolean_t
ipnet_if_in_zone(ipnetif_t *ipnetif, zoneid_t zoneid, ipnet_stack_t *ips)
{
	int ret;

	/*
	 * The global zone has visibility into all interfaces in the global
	 * stack, and exclusive stack zones have visibility into all
	 * interfaces in their stack.
	 */
	if (zoneid == GLOBAL_ZONEID ||
	    ips->ips_netstack->netstack_stackid != GLOBAL_NETSTACKID)
		return (B_TRUE);

	/*
	 * Shared-stack zones only have visibility for interfaces that have
	 * addresses in their zone.
	 */
	mutex_enter(&ipnetif->if_addr_lock);
	ret = ipnet_addrs_in_zone(&ipnetif->if_ip4addr_list, zoneid) ||
	    ipnet_addrs_in_zone(&ipnetif->if_ip6addr_list, zoneid);
	mutex_exit(&ipnetif->if_addr_lock);
	return (ret);
}

/*
 * Verify that any ipnet_t that has a reference to the supplied ipnetif should
 * still be allowed to have it open.  A given ipnet_t may no longer be allowed
 * to have an ipnetif open if there are no longer any addresses that belong to
 * the ipnetif in the ipnet_t's non-global shared-stack zoneid.  If that's the
 * case, send the ipnet_t an M_HANGUP.
 */
static void
ipnet_if_zonecheck(ipnetif_t *ipnetif, ipnet_stack_t *ips)
{
	list_t	*strlist = &ips->ips_str_list;
	ipnet_t	*ipnet;

	ipnet_walkers_inc(ips);
	for (ipnet = list_head(strlist); ipnet != NULL;
	    ipnet = list_next(strlist, ipnet)) {
		if (ipnet->ipnet_if != ipnetif)
			continue;
		if (!ipnet_if_in_zone(ipnetif, ipnet->ipnet_zoneid, ips))
			(void) putnextctl(ipnet->ipnet_rq, M_HANGUP);
	}
	ipnet_walkers_dec(ips);
}

void
ipnet_walk_if(ipnet_walkfunc_t *cb, void *arg, zoneid_t zoneid)
{
	ipnetif_t 		*ipnetif;
	list_t			cbdata;
	ipnetif_cbdata_t	*cbnode;
	netstack_t		*ns;
	ipnet_stack_t		*ips;

	/*
	 * On labeled systems, non-global zones shouldn't see anything
	 * in /dev/ipnet.
	 */
	if (is_system_labeled() && zoneid != GLOBAL_ZONEID)
		return;

	if ((ns = netstack_find_by_zoneid(zoneid)) == NULL)
		return;

	ips = ns->netstack_ipnet;
	list_create(&cbdata, sizeof (ipnetif_cbdata_t),
	    offsetof(ipnetif_cbdata_t, ic_next));

	mutex_enter(&ips->ips_avl_lock);
	for (ipnetif = avl_first(&ips->ips_avl_by_index); ipnetif != NULL;
	    ipnetif = avl_walk(&ips->ips_avl_by_index, ipnetif, AVL_AFTER)) {
		if (!ipnet_if_in_zone(ipnetif, zoneid, ips))
			continue;
		cbnode = kmem_zalloc(sizeof (ipnetif_cbdata_t), KM_SLEEP);
		(void) strlcpy(cbnode->ic_ifname, ipnetif->if_name, LIFNAMSIZ);
		cbnode->ic_dev = ipnetif->if_dev;
		list_insert_head(&cbdata, cbnode);
	}
	mutex_exit(&ips->ips_avl_lock);

	while ((cbnode = list_head(&cbdata)) != NULL) {
		cb(cbnode->ic_ifname, arg, cbnode->ic_dev);
		list_remove(&cbdata, cbnode);
		kmem_free(cbnode, sizeof (ipnetif_cbdata_t));
	}
	list_destroy(&cbdata);
	netstack_rele(ns);
}

static int
ipnet_if_compare_index(const void *index_ptr, const void *ipnetifp)
{
	int64_t index1 = *((int64_t *)index_ptr);
	int64_t index2 = (int64_t)((ipnetif_t *)ipnetifp)->if_index;

	return (SIGNOF(index2 - index1));
}

static int
ipnet_if_compare_name(const void *name_ptr, const void *ipnetifp)
{
	int res;

	res = strcmp(((ipnetif_t *)ipnetifp)->if_name, name_ptr);
	return (SIGNOF(res));
}

static void
ipnetif_refhold(ipnetif_t *ipnetif)
{
	mutex_enter(&ipnetif->if_reflock);
	ipnetif->if_refcnt++;
	mutex_exit(&ipnetif->if_reflock);
}

static void
ipnetif_refrele(ipnetif_t *ipnetif)
{
	mutex_enter(&ipnetif->if_reflock);
	ASSERT(ipnetif->if_refcnt != 0);
	if (--ipnetif->if_refcnt == 0)
		ipnet_free_if(ipnetif);
	else
		mutex_exit(&ipnetif->if_reflock);
}

static void
ipnet_walkers_inc(ipnet_stack_t *ips)
{
	mutex_enter(&ips->ips_walkers_lock);
	ips->ips_walkers_cnt++;
	mutex_exit(&ips->ips_walkers_lock);
}

static void
ipnet_walkers_dec(ipnet_stack_t *ips)
{
	mutex_enter(&ips->ips_walkers_lock);
	ASSERT(ips->ips_walkers_cnt != 0);
	if (--ips->ips_walkers_cnt == 0)
		cv_broadcast(&ips->ips_walkers_cv);
	mutex_exit(&ips->ips_walkers_lock);
}
