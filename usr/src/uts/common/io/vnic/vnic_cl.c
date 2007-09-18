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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/vnic.h>
#include <sys/vnic_impl.h>

/*
 * Virtual Network Interface Card (VNIC) classification.
 *
 * The VNIC implements a software classifier which is used to steer
 * traffic (locally and externally generated) to the appropriate VNIC
 * based on MAC addresses.
 */

static kmem_cache_t *vnic_flow_cache;
static kmem_cache_t *vnic_flow_tab_cache;

static void vnic_classifier_rx(void *, mac_resource_handle_t, mblk_t *);

/* ARGSUSED */
static int
vnic_classifier_flow_tab_ctor(void *buf, void *arg, int km_flag)
{
	vnic_flow_tab_t *flow_tab = buf;

	bzero(flow_tab, sizeof (vnic_flow_tab_t));
	rw_init(&flow_tab->vt_lock, NULL, RW_DRIVER, NULL);
	return (0);
}

/* ARGSUSED */
static void
vnic_classifier_flow_tab_dtor(void *buf, void *arg)
{
	vnic_flow_tab_t *flow_tab = buf;

	rw_destroy(&flow_tab->vt_lock);
}

/* ARGSUSED */
static int
vnic_classifier_flow_ctor(void *buf, void *arg, int km_flag)
{
	vnic_flow_t *flow = buf;

	bzero(flow, sizeof (vnic_flow_t));
	mutex_init(&flow->vf_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&flow->vf_cv, NULL, CV_DRIVER, NULL);
	return (0);
}

/* ARGSUSED */
static void
vnic_classifier_flow_dtor(void *buf, void *arg)
{
	vnic_flow_t *flow = buf;

	ASSERT(flow->vf_refs == 0);
	mutex_destroy(&flow->vf_lock);
	cv_destroy(&flow->vf_cv);
}

void
vnic_classifier_init(void)
{
	vnic_flow_cache = kmem_cache_create("vnic_flow_cache",
	    sizeof (vnic_flow_t), 0, vnic_classifier_flow_ctor,
	    vnic_classifier_flow_dtor, NULL, NULL, NULL, 0);
	vnic_flow_tab_cache = kmem_cache_create("vnic_flow_tab_cache",
	    sizeof (vnic_flow_tab_t), 0, vnic_classifier_flow_tab_ctor,
	    vnic_classifier_flow_tab_dtor, NULL, NULL, NULL, 0);
}

void
vnic_classifier_fini(void)
{
	kmem_cache_destroy(vnic_flow_cache);
	kmem_cache_destroy(vnic_flow_tab_cache);
}

int
vnic_classifier_flow_tab_init(vnic_mac_t *vnic_mac, uint_t mac_len,
    int km_flag)
{
	vnic_mac->va_flow_tab = kmem_cache_alloc(vnic_flow_tab_cache, km_flag);
	if (vnic_mac->va_flow_tab == NULL)
		return (ENOMEM);
	vnic_mac->va_rx_hdl = mac_rx_add(vnic_mac->va_mh, vnic_classifier_rx,
	    vnic_mac);
	vnic_mac->va_flow_tab->vt_addr_len = mac_len;
	return (0);
}

void
vnic_classifier_flow_tab_fini(vnic_mac_t *vnic_mac)
{
	vnic_flow_tab_t *flow_tab = vnic_mac->va_flow_tab;

	ASSERT(flow_tab->vt_flow_list == NULL);
	mac_rx_remove(vnic_mac->va_mh, vnic_mac->va_rx_hdl, B_TRUE);
	kmem_cache_free(vnic_flow_tab_cache, flow_tab);
	vnic_mac->va_flow_tab = NULL;
}

vnic_flow_t *
vnic_classifier_flow_create(uint_t mac_len, uchar_t *mac_addr,
    void *flow_cookie, boolean_t is_active, int km_flag)
{
	vnic_flow_t *flow;

	ASSERT(mac_len <= MAXMACADDRLEN);

	if ((flow = kmem_cache_alloc(vnic_flow_cache, km_flag)) == NULL)
		return (NULL);

	flow->vf_addr_len = mac_len;
	flow->vf_cookie = flow_cookie;
	flow->vf_clearing = B_FALSE;
	flow->vf_is_active = is_active;
	bcopy(mac_addr, flow->vf_addr, mac_len);
	return (flow);
}

void
vnic_classifier_flow_destroy(vnic_flow_t *flow)
{
	kmem_cache_free(vnic_flow_cache, flow);
}

void
vnic_classifier_flow_add(vnic_mac_t *vnic_mac, vnic_flow_t *flow,
    vnic_rx_fn_t rx_fn, void *rx_arg1, void *rx_arg2)
{
	vnic_flow_tab_t *flow_tab = vnic_mac->va_flow_tab;
	vnic_flow_t **cur_flow;

	ASSERT(flow->vf_addr_len == flow_tab->vt_addr_len);

	/* initialize the flow structure */
	flow->vf_fn_info.ff_fn = rx_fn;
	flow->vf_fn_info.ff_arg1 = rx_arg1;
	flow->vf_fn_info.ff_arg2 = rx_arg2;

	/* add to the flow table */
	rw_enter(&flow_tab->vt_lock, RW_WRITER);
	for (cur_flow = &flow_tab->vt_flow_list;
	    *cur_flow != NULL;
	    cur_flow = &(*cur_flow)->vf_next)
		;
	*cur_flow = flow;
	flow->vf_next = NULL;
	rw_exit(&flow_tab->vt_lock);
}

void
vnic_classifier_flow_remove(vnic_mac_t *vnic_mac, vnic_flow_t *flow)
{
	vnic_flow_tab_t *flow_tab = vnic_mac->va_flow_tab;
	vnic_flow_t **prev, *cur;

	/* unlink from list */
	rw_enter(&flow_tab->vt_lock, RW_WRITER);
	prev = &flow_tab->vt_flow_list;
	for (cur = *prev; cur != NULL && cur != flow;
	    prev = &cur->vf_next, cur = cur->vf_next)
		;
	*prev = cur->vf_next;
	rw_exit(&flow_tab->vt_lock);

	/* wait for all references to the flow to go away */
	mutex_enter(&flow->vf_lock);
	flow->vf_clearing = B_TRUE;
	while (flow->vf_refs > 0)
		cv_wait(&flow->vf_cv, &flow->vf_lock);
	mutex_exit(&flow->vf_lock);
}

void
vnic_classifier_flow_update_addr(vnic_flow_t *flow, uchar_t *mac_addr)
{
	bcopy(mac_addr, flow->vf_addr, flow->vf_addr_len);
}

void
vnic_classifier_flow_update_fn(vnic_flow_t *flow, vnic_rx_fn_t fn,
    void *arg1, void *arg2)
{
	flow->vf_fn_info.ff_fn = fn;
	flow->vf_fn_info.ff_arg1 = arg1;
	flow->vf_fn_info.ff_arg2 = arg2;
}

vnic_flow_t *
vnic_classifier_get_flow(vnic_mac_t *vnic_mac, mblk_t *mp)
{
	vnic_flow_tab_t *flow_tab = vnic_mac->va_flow_tab;
	vnic_flow_t *flow;
	mac_header_info_t hdr_info;

	if (mac_header_info(vnic_mac->va_mh, mp, &hdr_info) != 0)
		return (NULL);

	rw_enter(&flow_tab->vt_lock, RW_READER);
	for (flow = flow_tab->vt_flow_list; flow != NULL;
	    flow = flow->vf_next) {
		if (bcmp(hdr_info.mhi_daddr, flow->vf_addr,
		    flow_tab->vt_addr_len) == 0) {
			VNIC_FLOW_REFHOLD(flow);
			break;
		}
	}
	rw_exit(&flow_tab->vt_lock);
	return (flow);
}

void *
vnic_classifier_get_client_cookie(vnic_flow_t *flow)
{
	return (flow->vf_cookie);
}

vnic_flow_fn_info_t *
vnic_classifier_get_fn_info(vnic_flow_t *flow)
{
	return (&flow->vf_fn_info);
}

boolean_t
vnic_classifier_is_active(vnic_flow_t *flow)
{
	return (flow->vf_is_active);
}

/*
 * Receive function registered with the MAC layer. Classifies
 * the packets, i.e. finds the flows matching the packets passed
 * as argument, and invokes the callback functions associated with
 * these flows.
 */
/*ARGSUSED*/
static void
vnic_classifier_rx(void *arg, mac_resource_handle_t mrh, mblk_t *mp)
{
	vnic_mac_t *vnic_mac = arg;
	vnic_flow_t *flow;
	mblk_t *next_mp;
	const vnic_flow_fn_info_t *fn_info;

	while (mp != NULL) {
		next_mp = mp->b_next;
		mp->b_next = NULL;

		vnic_promisc_rx(vnic_mac, NULL, mp);

		flow = vnic_classifier_get_flow(vnic_mac, mp);
		if (flow == NULL) {
			freemsg(mp);
		} else {
			if (flow->vf_is_active) {
				/*
				 * Inbound packets are delivered to the
				 * active MAC through mac_rx() of the
				 * the NIC.
				 */
				freemsg(mp);
			} else {
				vnic_t *vnic;

				fn_info = vnic_classifier_get_fn_info(flow);

				/*
				 * If the vnic to which we would
				 * deliver this packet is in
				 * promiscuous mode then it already
				 * received the packet via
				 * vnic_promisc_rx().
				 *
				 * XXX assumes that ff_arg2 is a
				 * vnic_t pointer if it is non-NULL
				 * (currently always true).
				 */
				vnic = (vnic_t *)fn_info->ff_arg2;
				if ((vnic != NULL) && vnic->vn_promisc) {
					freemsg(mp);
				} else {
					(fn_info->ff_fn)(fn_info->ff_arg1,
					    fn_info->ff_arg2, mp);
				}
			}
			VNIC_FLOW_REFRELE(flow);
		}
		mp = next_mp;
	}
}
