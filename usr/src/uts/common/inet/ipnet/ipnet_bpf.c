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
#include <sys/stream.h>
#include <net/bpf.h>
#include <net/bpfdesc.h>
#include <inet/ipnet.h>

/*
 * This file implements the function calls for ipnet that translate the
 * calls from BPF into the correct arguments and functions inside of the
 * ipnet device.
 */
static const char *ipnet_bpf_name(uintptr_t);
static void ipnet_bpf_client_close(uintptr_t);
static const char *ipnet_bpf_client_name(uintptr_t);
static int ipnet_bpf_client_open(uintptr_t, uintptr_t *);
static void ipnet_bpf_close(uintptr_t);
static int ipnet_bpf_getdlt(uintptr_t, uint_t *);
static int ipnet_bpf_getlinkid(const char *, datalink_id_t *, zoneid_t);
static int ipnet_bpf_getzone(uintptr_t, zoneid_t *);
static int ipnet_bpf_open(const char *, uintptr_t *, zoneid_t);
static uintptr_t ipnet_bpf_promisc_add(uintptr_t, int, void *,
    uintptr_t *, int);
static void ipnet_bpf_promisc_remove(uintptr_t);
static void ipnet_bpf_sdu_get(uintptr_t, uint_t *);
static int ipnet_bpf_tx(uintptr_t, mblk_t *);
static int ipnet_bpf_type(uintptr_t);

bpf_provider_t bpf_ipnet = {
	BPR_IPNET,
	ipnet_bpf_open,
	ipnet_bpf_close,
	ipnet_bpf_name,
	ipnet_bpf_type,
	ipnet_bpf_sdu_get,
	ipnet_bpf_tx,
	ipnet_bpf_promisc_add,
	ipnet_bpf_promisc_remove,
	ipnet_bpf_getlinkid,
	ipnet_bpf_client_close,
	ipnet_bpf_client_name,
	ipnet_bpf_client_open,
	ipnet_bpf_getzone,
	ipnet_bpf_getdlt,
};

/*ARGSUSED*/
static int
ipnet_bpf_open(const char *name, uintptr_t *mhandlep, zoneid_t zoneid)
{
	if (zoneid == ALL_ZONES)
		zoneid = GLOBAL_ZONEID;
	return (ipnet_open_byname(name, (ipnetif_t **)mhandlep, zoneid));
}

/*ARGSUSED*/
static void
ipnet_bpf_close(uintptr_t mhandle)
{
	ipnet_close_byhandle((ipnetif_t *)mhandle);
}

static const char *
ipnet_bpf_name(uintptr_t mhandle)
{
	return (ipnet_name((ipnetif_t *)mhandle));
}

/*ARGSUSED*/
static int
ipnet_bpf_type(uintptr_t mhandle)
{
	return (DL_IPNET);
}

/*ARGSUSED*/
static void
ipnet_bpf_sdu_get(uintptr_t mhandle, uint_t *mtup)
{
	/*
	 * The choice of 65535 is arbitrary, it could be any smaller number
	 * but it does matche the current default choice of libpcap as the
	 * packet snap size.
	 */
	*mtup = 65535;
}

/*ARGSUSED*/
static int
ipnet_bpf_tx(uintptr_t chandle, mblk_t *pkt)
{
	/*
	 * It is not clear what it would mean to send an ipnet packet,
	 * especially since the ipnet device has been implemented to be
	 * an observation (read-only) instrument. Thus a call to send a
	 * packet using ipnet results in the packet being free'd and an
	 * error returned.
	 */
	freemsg(pkt);

	return (EBADF);
}

/*
 * BPF does not provide the means to select which SAP is being sniffed,
 * so for the purpose of ipnet, all BPF clients are in SAP promiscuous
 * mode.
 */
static uintptr_t
ipnet_bpf_promisc_add(uintptr_t chandle, int how, void *arg,
    uintptr_t *promisc, int flags)
{
	int	newhow;

	/*
	 * Map the mac values into ipnet values.
	 */
	switch (how) {
	case MAC_CLIENT_PROMISC_ALL :
		newhow = DL_PROMISC_PHYS;
		flags = IPNET_PROMISC_PHYS|IPNET_PROMISC_SAP;
		break;
	case MAC_CLIENT_PROMISC_MULTI :
		newhow = DL_PROMISC_MULTI;
		flags = IPNET_PROMISC_MULTI|IPNET_PROMISC_SAP;
		break;
	default :
		newhow = 0;
		break;
	}

	return (ipnet_promisc_add((void *)chandle, newhow,
	    arg, promisc, flags));
}

static void
ipnet_bpf_promisc_remove(uintptr_t phandle)
{
	ipnet_promisc_remove((void *)phandle);
}

static int
ipnet_bpf_client_open(uintptr_t mhandle, uintptr_t *chandlep)
{

	return (ipnet_client_open((ipnetif_t *)mhandle,
	    (ipnetif_t **)chandlep));
}

/*ARGSUSED*/
static void
ipnet_bpf_client_close(uintptr_t chandle)
{
	ipnet_client_close((ipnetif_t *)chandle);
}

static const char *
ipnet_bpf_client_name(uintptr_t chandle)
{
	return (ipnet_bpf_name(chandle));
}

static int
ipnet_bpf_getlinkid(const char *name, datalink_id_t *idp, zoneid_t zoneid)
{
	uint_t		index;
	int		error;
	ipnet_stack_t	*ips;

	VERIFY((ips = ipnet_find_by_zoneid(zoneid)) != NULL);

	index = 0;
	mutex_enter(&ips->ips_event_lock);
	error = ipnet_get_linkid_byname(name, &index, zoneid);
	mutex_exit(&ips->ips_event_lock);
	if (error == 0)
		*idp = (datalink_id_t)index;
	ipnet_rele(ips);
	return (error);
}

static int
ipnet_bpf_getzone(uintptr_t handle, zoneid_t *zip)
{
	ipnetif_t *ipnetif;

	ipnetif = (ipnetif_t *)handle;
	*zip = ipnetif->if_zoneid;
	return (0);
}

/*ARGSUSED*/
static int
ipnet_bpf_getdlt(uintptr_t handle, uint_t *dlp)
{
	*dlp = DL_IPNET;
	return (0);
}
