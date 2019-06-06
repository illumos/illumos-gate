/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/hook.h>
#include <sys/hook_event.h>

#include "viona_impl.h"


/*
 * Global linked list of viona_neti_ts.  Access is protected by viona_neti_lock
 */
static list_t		viona_neti_list;
static kmutex_t		viona_neti_lock;

/*
 * viona_neti is allocated and initialized during attach, and read-only
 * until detach (where it's also freed)
 */
static net_instance_t	*viona_neti;


/*
 * Generate a hook event for the packet in *mpp headed in the direction
 * indicated by 'out'.  If the packet is accepted, 0 is returned.  If the
 * packet is rejected, an error is returned.  The hook function may or may not
 * alter or even free *mpp.  The caller is expected to deal with either
 * situation.
 */
int
viona_hook(viona_link_t *link, viona_vring_t *ring, mblk_t **mpp, boolean_t out)
{
	viona_neti_t *nip = link->l_neti;
	viona_nethook_t *vnh = &nip->vni_nethook;
	hook_pkt_event_t info;
	hook_event_t he;
	hook_event_token_t het;
	int ret;

	he = out ? vnh->vnh_event_out : vnh->vnh_event_in;
	het = out ? vnh->vnh_token_out : vnh->vnh_token_in;

	if (!he.he_interested)
		return (0);

	info.hpe_protocol = vnh->vnh_neti;
	info.hpe_ifp = (phy_if_t)link;
	info.hpe_ofp = (phy_if_t)link;
	info.hpe_mp = mpp;
	info.hpe_flags = 0;

	ret = hook_run(vnh->vnh_neti->netd_hooks, het, (hook_data_t)&info);
	if (ret == 0)
		return (0);

	if (out) {
		VIONA_PROBE3(tx_hook_drop, viona_vring_t *, ring,
		    mblk_t *, *mpp, int, ret);
		VIONA_RING_STAT_INCR(ring, tx_hookdrop);
	} else {
		VIONA_PROBE3(rx_hook_drop, viona_vring_t *, ring,
		    mblk_t *, *mpp, int, ret);
		VIONA_RING_STAT_INCR(ring, rx_hookdrop);
	}
	return (ret);
}

/*
 * netinfo stubs - required by the nethook framework, but otherwise unused
 *
 * Currently, all ipf rules are applied against all interfaces in a given
 * netstack (e.g. all interfaces in a zone).  In the future if we want to
 * support being able to apply different rules to different interfaces, I
 * believe we would need to implement some of these stubs to map an interface
 * name in a rule (e.g. 'net0', back to an index or viona_link_t);
 */
static int
viona_neti_getifname(net_handle_t neti __unused, phy_if_t phy __unused,
    char *buf __unused, const size_t len __unused)
{
	return (-1);
}

static int
viona_neti_getmtu(net_handle_t neti __unused, phy_if_t phy __unused,
    lif_if_t ifdata __unused)
{
	return (-1);
}

static int
viona_neti_getptmue(net_handle_t neti __unused)
{
	return (-1);
}

static int
viona_neti_getlifaddr(net_handle_t neti __unused, phy_if_t phy __unused,
    lif_if_t ifdata __unused, size_t nelem __unused,
    net_ifaddr_t type[] __unused, void *storage __unused)
{
	return (-1);
}

static int
viona_neti_getlifzone(net_handle_t neti __unused, phy_if_t phy __unused,
    lif_if_t ifdata __unused, zoneid_t *zid __unused)
{
	return (-1);
}

static int
viona_neti_getlifflags(net_handle_t neti __unused, phy_if_t phy __unused,
    lif_if_t ifdata __unused, uint64_t *flags __unused)
{
	return (-1);
}

static phy_if_t
viona_neti_phygetnext(net_handle_t neti __unused, phy_if_t phy __unused)
{
	return ((phy_if_t)-1);
}

static phy_if_t
viona_neti_phylookup(net_handle_t neti __unused, const char *name __unused)
{
	return ((phy_if_t)-1);
}

static lif_if_t
viona_neti_lifgetnext(net_handle_t neti __unused, phy_if_t phy __unused,
    lif_if_t ifdata __unused)
{
	return (-1);
}

static int
viona_neti_inject(net_handle_t neti __unused, inject_t style __unused,
    net_inject_t *packet __unused)
{
	return (-1);
}

static phy_if_t
viona_neti_route(net_handle_t neti __unused, struct sockaddr *address __unused,
    struct sockaddr *next __unused)
{
	return ((phy_if_t)-1);
}

static int
viona_neti_ispchksum(net_handle_t neti __unused, mblk_t *mp __unused)
{
	return (-1);
}

static int
viona_neti_isvchksum(net_handle_t neti __unused, mblk_t *mp __unused)
{
	return (-1);
}

static net_protocol_t viona_netinfo = {
	NETINFO_VERSION,
	NHF_VIONA,
	viona_neti_getifname,
	viona_neti_getmtu,
	viona_neti_getptmue,
	viona_neti_getlifaddr,
	viona_neti_getlifzone,
	viona_neti_getlifflags,
	viona_neti_phygetnext,
	viona_neti_phylookup,
	viona_neti_lifgetnext,
	viona_neti_inject,
	viona_neti_route,
	viona_neti_ispchksum,
	viona_neti_isvchksum
};

/*
 * Create/register our nethooks
 */
static int
viona_nethook_init(netid_t nid, viona_nethook_t *vnh, char *nh_name,
    net_protocol_t *netip)
{
	int ret;

	if ((vnh->vnh_neti = net_protocol_register(nid, netip)) == NULL) {
		cmn_err(CE_NOTE, "%s: net_protocol_register failed "
		    "(netid=%d name=%s)", __func__, nid, nh_name);
		goto fail_init_proto;
	}

	HOOK_FAMILY_INIT(&vnh->vnh_family, nh_name);
	if ((ret = net_family_register(vnh->vnh_neti, &vnh->vnh_family)) != 0) {
		cmn_err(CE_NOTE, "%s: net_family_register failed "
		    "(netid=%d name=%s err=%d)", __func__,
		    nid, nh_name, ret);
		goto fail_init_family;
	}

	HOOK_EVENT_INIT(&vnh->vnh_event_in, NH_PHYSICAL_IN);
	if ((vnh->vnh_token_in = net_event_register(vnh->vnh_neti,
	    &vnh->vnh_event_in)) == NULL) {
		cmn_err(CE_NOTE, "%s: net_event_register %s failed "
		    "(netid=%d name=%s)", __func__, NH_PHYSICAL_IN, nid,
		    nh_name);
		goto fail_init_event_in;
	}

	HOOK_EVENT_INIT(&vnh->vnh_event_out, NH_PHYSICAL_OUT);
	if ((vnh->vnh_token_out = net_event_register(vnh->vnh_neti,
	    &vnh->vnh_event_out)) == NULL) {
		cmn_err(CE_NOTE, "%s: net_event_register %s failed "
		    "(netid=%d name=%s)", __func__, NH_PHYSICAL_OUT, nid,
		    nh_name);
		goto fail_init_event_out;
	}
	return (0);

	/*
	 * On failure, we undo all the steps that succeeded in the
	 * reverse order of initialization, starting at the last
	 * successful step (the labels denoting the failing step).
	 */
fail_init_event_out:
	VERIFY0(net_event_shutdown(vnh->vnh_neti, &vnh->vnh_event_in));
	VERIFY0(net_event_unregister(vnh->vnh_neti, &vnh->vnh_event_in));
	vnh->vnh_token_in = NULL;

fail_init_event_in:
	VERIFY0(net_family_shutdown(vnh->vnh_neti, &vnh->vnh_family));
	VERIFY0(net_family_unregister(vnh->vnh_neti, &vnh->vnh_family));

fail_init_family:
	VERIFY0(net_protocol_unregister(vnh->vnh_neti));
	vnh->vnh_neti = NULL;

fail_init_proto:
	return (1);
}

/*
 * Shutdown the nethooks for a protocol family.  This triggers notification
 * callbacks to anything that has registered interest to allow hook consumers
 * to unhook prior to the removal of the hooks as well as makes them unavailable
 * to any future consumers as the first step of removal.
 */
static void
viona_nethook_shutdown(viona_nethook_t *vnh)
{
	VERIFY0(net_event_shutdown(vnh->vnh_neti, &vnh->vnh_event_out));
	VERIFY0(net_event_shutdown(vnh->vnh_neti, &vnh->vnh_event_in));
	VERIFY0(net_family_shutdown(vnh->vnh_neti, &vnh->vnh_family));
}

/*
 * Remove the nethooks for a protocol family.
 */
static void
viona_nethook_fini(viona_nethook_t *vnh)
{
	VERIFY0(net_event_unregister(vnh->vnh_neti, &vnh->vnh_event_out));
	VERIFY0(net_event_unregister(vnh->vnh_neti, &vnh->vnh_event_in));
	VERIFY0(net_family_unregister(vnh->vnh_neti, &vnh->vnh_family));
	VERIFY0(net_protocol_unregister(vnh->vnh_neti));
	vnh->vnh_neti = NULL;
}

/*
 * Callback invoked by the neti module.  This creates/registers our hooks
 * {IPv4,IPv6}{in,out} with the nethook framework so they are available to
 * interested consumers (e.g. ipf).
 *
 * During attach, viona_neti_create is called once for every netstack
 * present on the system at the time of attach.  Thereafter, it is called
 * during the creation of additional netstack instances (i.e. zone boot).  As a
 * result, the viona_neti_t that is created during this call always occurs
 * prior to any viona instances that will use it to send hook events.
 *
 * It should never return NULL.  If we cannot register our hooks, we do not
 * set vnh_hooked of the respective protocol family, which will prevent the
 * creation of any viona instances on this netstack (see viona_ioc_create).
 * This can only occur if after a shutdown event (which means destruction is
 * imminent) we are trying to create a new instance.
 */
static void *
viona_neti_create(const netid_t netid)
{
	viona_neti_t *nip;

	VERIFY(netid != -1);

	nip = kmem_zalloc(sizeof (*nip), KM_SLEEP);
	nip->vni_netid = netid;
	nip->vni_zid = net_getzoneidbynetid(netid);
	mutex_init(&nip->vni_lock, NULL, MUTEX_DRIVER, NULL);
	list_create(&nip->vni_dev_list, sizeof (viona_soft_state_t),
	    offsetof(viona_soft_state_t, ss_node));

	if (viona_nethook_init(netid, &nip->vni_nethook, Hn_VIONA,
	    &viona_netinfo) == 0)
		nip->vni_nethook.vnh_hooked = B_TRUE;

	mutex_enter(&viona_neti_lock);
	list_insert_tail(&viona_neti_list, nip);
	mutex_exit(&viona_neti_lock);

	return (nip);
}

/*
 * Called during netstack teardown by the neti module.  During teardown, all
 * the shutdown callbacks are invoked, allowing consumers to release any holds
 * and otherwise quiesce themselves prior to destruction, followed by the
 * actual destruction callbacks.
 */
static void
viona_neti_shutdown(netid_t nid, void *arg)
{
	viona_neti_t *nip = arg;

	ASSERT(nip != NULL);
	VERIFY(nid == nip->vni_netid);

	mutex_enter(&viona_neti_lock);
	list_remove(&viona_neti_list, nip);
	mutex_exit(&viona_neti_lock);

	if (nip->vni_nethook.vnh_hooked)
		viona_nethook_shutdown(&nip->vni_nethook);
}

/*
 * Called during netstack teardown by the neti module.  Destroys the viona
 * netinst data.  This is invoked after all the netstack and neti shutdown
 * callbacks have been invoked.
 */
static void
viona_neti_destroy(netid_t nid, void *arg)
{
	viona_neti_t *nip = arg;

	ASSERT(nip != NULL);
	VERIFY(nid == nip->vni_netid);

	mutex_enter(&nip->vni_lock);
	while (nip->vni_ref != 0)
		cv_wait(&nip->vni_ref_change, &nip->vni_lock);
	mutex_exit(&nip->vni_lock);

	VERIFY(!list_link_active(&nip->vni_node));

	if (nip->vni_nethook.vnh_hooked)
		viona_nethook_fini(&nip->vni_nethook);

	mutex_destroy(&nip->vni_lock);
	list_destroy(&nip->vni_dev_list);
	kmem_free(nip, sizeof (*nip));
}

/*
 * Find the viona netinst data by zone id.  This is only used during
 * viona instance creation (and thus is only called by a zone that is running).
 */
viona_neti_t *
viona_neti_lookup_by_zid(zoneid_t zid)
{
	viona_neti_t *nip;

	mutex_enter(&viona_neti_lock);
	for (nip = list_head(&viona_neti_list); nip != NULL;
	    nip = list_next(&viona_neti_list, nip)) {
		if (nip->vni_zid == zid) {
			mutex_enter(&nip->vni_lock);
			nip->vni_ref++;
			mutex_exit(&nip->vni_lock);
			mutex_exit(&viona_neti_lock);
			return (nip);
		}
	}
	mutex_exit(&viona_neti_lock);
	return (NULL);
}

void
viona_neti_rele(viona_neti_t *nip)
{
	mutex_enter(&nip->vni_lock);
	VERIFY3S(nip->vni_ref, >, 0);
	nip->vni_ref--;
	mutex_exit(&nip->vni_lock);
	cv_broadcast(&nip->vni_ref_change);
}

void
viona_neti_attach(void)
{
	mutex_init(&viona_neti_lock, NULL, MUTEX_DRIVER, NULL);
	list_create(&viona_neti_list, sizeof (viona_neti_t),
	    offsetof(viona_neti_t, vni_node));

	/* This can only fail if NETINFO_VERSION is wrong */
	viona_neti = net_instance_alloc(NETINFO_VERSION);
	VERIFY(viona_neti != NULL);

	viona_neti->nin_name = "viona";
	viona_neti->nin_create = viona_neti_create;
	viona_neti->nin_shutdown = viona_neti_shutdown;
	viona_neti->nin_destroy = viona_neti_destroy;
	/* This can only fail if we've registered ourselves multiple times */
	VERIFY3S(net_instance_register(viona_neti), ==, DDI_SUCCESS);
}

void
viona_neti_detach(void)
{
	/* This can only fail if we've not registered previously */
	VERIFY3S(net_instance_unregister(viona_neti), ==, DDI_SUCCESS);
	net_instance_free(viona_neti);
	viona_neti = NULL;

	list_destroy(&viona_neti_list);
	mutex_destroy(&viona_neti_lock);
}
