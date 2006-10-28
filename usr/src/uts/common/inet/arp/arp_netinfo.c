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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/stream.h>
#include <sys/sunddi.h>
#include <sys/hook.h>
#include <sys/hook_impl.h>
#include <net/if.h>

#include <sys/neti.h>
#include <sys/hook_event.h>
#include <inet/arp_impl.h>

/*
 * ARP netinfo entry point declarations.
 */
static int 	arp_getifname(phy_if_t, char *, const size_t);
static int 	arp_getmtu(phy_if_t, lif_if_t);
static int 	arp_getpmtuenabled(void);
static int 	arp_getlifaddr(phy_if_t, lif_if_t, size_t,
		    net_ifaddr_t [], void *);
static phy_if_t arp_phygetnext(phy_if_t);
static phy_if_t arp_phylookup(const char *);
static lif_if_t arp_lifgetnext(phy_if_t, lif_if_t);
static int 	arp_inject(inject_t, net_inject_t *);
static phy_if_t arp_routeto(struct sockaddr *);
static int 	arp_ispartialchecksum(mblk_t *);
static int 	arp_isvalidchecksum(mblk_t *);

static net_info_t arp_netinfo = {
	NETINFO_VERSION,
	NHF_ARP,
	arp_getifname,
	arp_getmtu,
	arp_getpmtuenabled,
	arp_getlifaddr,
	arp_phygetnext,
	arp_phylookup,
	arp_lifgetnext,
	arp_inject,
	arp_routeto,
	arp_ispartialchecksum,
	arp_isvalidchecksum
};

static hook_family_t	arproot;

/*
 * Hooks for ARP
 */

hook_event_t		arp_physical_in_event;
hook_event_t		arp_physical_out_event;
hook_event_t		arp_nic_events;

hook_event_token_t	arp_physical_in;
hook_event_token_t	arp_physical_out;
hook_event_token_t	arpnicevents;

net_data_t		arp = NULL;

/*
 * Register ARP netinfo functions.
 */
void
arp_net_init()
{
	arp = net_register(&arp_netinfo);
	ASSERT(arp != NULL);
}

/*
 * Unregister ARP netinfo functions.
 */
void
arp_net_destroy()
{
	(void) net_unregister(arp);
}

/*
 * Initialize ARP hook family and events
 */
void
arp_hook_init()
{
	HOOK_FAMILY_INIT(&arproot, Hn_ARP);
	if (net_register_family(arp, &arproot) != 0) {
		cmn_err(CE_NOTE, "arp_hook_init: "
		    "net_register_family failed for arp");
	}

	HOOK_EVENT_INIT(&arp_physical_in_event, NH_PHYSICAL_IN);
	arp_physical_in = net_register_event(arp, &arp_physical_in_event);
	if (arp_physical_in == NULL) {
		cmn_err(CE_NOTE, "arp_hook_init: "
		    "net_register_event failed for arp/physical_in");
	}

	HOOK_EVENT_INIT(&arp_physical_out_event, NH_PHYSICAL_OUT);
	arp_physical_out = net_register_event(arp, &arp_physical_out_event);
	if (arp_physical_out == NULL) {
		cmn_err(CE_NOTE, "arp_hook_init: "
		    "net_register_event failed for arp/physical_out");
	}

	HOOK_EVENT_INIT(&arp_nic_events, NH_NIC_EVENTS);
	arpnicevents = net_register_event(arp, &arp_nic_events);
	if (arpnicevents == NULL) {
		cmn_err(CE_NOTE, "arp_hook_init: "
		    "net_register_event failed for arp/nic_events");
	}
}

void
arp_hook_destroy()
{
	if (arpnicevents != NULL) {
		if (net_unregister_event(arp, &arp_nic_events) == 0)
			arpnicevents = NULL;
	}

	if (arp_physical_out != NULL) {
		if (net_unregister_event(arp, &arp_physical_out_event) == 0)
			arp_physical_out = NULL;
	}

	if (arp_physical_in != NULL) {
		if (net_unregister_event(arp, &arp_physical_in_event) == 0)
			arp_physical_in = NULL;
	}

	(void) net_unregister_family(arp, &arproot);
}

/*
 * Determine the name of the lower level interface
 */
int
arp_getifname(phy_if_t phy_ifdata, char *buffer, const size_t buflen)
{
	arl_t	*arl;

	ASSERT(buffer != NULL);

	rw_enter(&arl_g_lock, RW_READER);
	for (arl = arl_g_head; arl != NULL; arl = arl->arl_next) {
		if (arl->arl_index == phy_ifdata) {
			(void) strlcpy(buffer, arl->arl_name, buflen);
			rw_exit(&arl_g_lock);
			return (0);
		}
	}
	rw_exit(&arl_g_lock);

	return (1);
}

/*
 * Unsupported with ARP.
 */
/*ARGSUSED*/
int
arp_getmtu(phy_if_t phy_ifdata, lif_if_t ifdata)
{
	return (-1);
}

/*
 * Unsupported with ARP.
 */
/*ARGSUSED*/
int
arp_getpmtuenabled(void)
{
	return (-1);
}

/*
 * Unsupported with ARP.
 */
/*ARGSUSED*/
int
arp_getlifaddr(phy_if_t phy_ifdata, lif_if_t ifdata, size_t nelem,
	net_ifaddr_t type[], void *storage)
{
	return (-1);
}

/*
 * Determine the instance number of the next lower level interface
 */
phy_if_t
arp_phygetnext(phy_if_t phy_ifdata)
{
	arl_t *arl;
	int index;

	rw_enter(&arl_g_lock, RW_READER);
	if (phy_ifdata == 0) {
		arl = arl_g_head;
	} else {
		for (arl = arl_g_head; arl != NULL; arl = arl->arl_next) {
			if (arl->arl_index == phy_ifdata) {
				arl = arl->arl_next;
				break;
			}
		}
	}

	index = (arl != NULL) ? arl->arl_index : 0;

	rw_exit(&arl_g_lock);

	return (index);
}

/*
 * Given a network interface name, find its ARP layer instance number.
 */
phy_if_t
arp_phylookup(const char *name)
{
	arl_t *arl;
	int index;

	ASSERT(name != NULL);

	index = 0;

	rw_enter(&arl_g_lock, RW_READER);
	for (arl = arl_g_head; arl != NULL; arl = arl->arl_next) {
		if (strcmp(name, arl->arl_name) == 0) {
			index = arl->arl_index;
			break;
		}
	}
	rw_exit(&arl_g_lock);

	return (index);

}

/*
 * Unsupported with ARP.
 */
/*ARGSUSED*/
lif_if_t
arp_lifgetnext(phy_if_t ifp, lif_if_t lif)
{
	return ((lif_if_t)-1);
}

/*
 * Unsupported with ARP.
 */
/*ARGSUSED*/
int
arp_inject(inject_t injection, net_inject_t *neti)
{
	return (-1);
}

/*
 * Unsupported with ARP.
 */
/*ARGSUSED*/
phy_if_t
arp_routeto(struct sockaddr *addr)
{
	return ((phy_if_t)-1);
}

/*
 * Unsupported with ARP.
 */
/*ARGSUSED*/
int
arp_ispartialchecksum(mblk_t *mb)
{
	return (-1);
}

/*
 * Unsupported with ARP.
 */
/*ARGSUSED*/
int
arp_isvalidchecksum(mblk_t *mb)
{
	return (-1);
}
