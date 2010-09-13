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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/stream.h>
#include <net/bpf.h>
#include <net/bpfdesc.h>

/*
 * This file provides the link to the functions required from the mac
 * module. It is currently in bpf, rather than mac (like ipnet_bpf)
 * because of the mac/dls split. The bpf driver needs to know when
 * interfaces appear and disappear and the best place for that is in
 * dls. Unfortunately all of the other functions used here are found
 * in the mac module, making it seem ill suited to being at home in
 * dls. Similarly it has even less purpose being in mac as it is
 * today.
 */
static int	mac_bpf_open(const char *, uintptr_t *, zoneid_t);
static void	mac_bpf_close(uintptr_t);
static const char *mac_bpf_name(uintptr_t);
static int	mac_bpf_type(uintptr_t);
static void	mac_bpf_sdu_get(uintptr_t, uint_t *);
static int	mac_bpf_tx(uintptr_t, mblk_t *);
static uintptr_t mac_bpf_promisc_add(uintptr_t, int, void *, uintptr_t *, int);
static void	mac_bpf_promisc_remove(uintptr_t);
static int	mac_bpf_client_open(uintptr_t, uintptr_t *);
static void	mac_bpf_client_close(uintptr_t);
static const char *mac_bpf_client_name(uintptr_t);
static int	mac_bpf_getdlt(uintptr_t, uint_t *);
static int	mac_bpf_getlinkid(const char *, datalink_id_t *, zoneid_t);
static int	mac_bpf_getzone(uintptr_t, zoneid_t *);

bpf_provider_t bpf_mac = {
	BPR_MAC,
	mac_bpf_open,
	mac_bpf_close,
	mac_bpf_name,
	mac_bpf_type,
	mac_bpf_sdu_get,
	mac_bpf_tx,
	mac_bpf_promisc_add,
	mac_bpf_promisc_remove,
	mac_bpf_getlinkid,
	mac_bpf_client_close,
	mac_bpf_client_name,
	mac_bpf_client_open,
	mac_bpf_getzone,
	mac_bpf_getdlt
};

/*ARGSUSED*/
static int
mac_bpf_open(const char *name, uintptr_t *mhandlep, zoneid_t zoneid)
{
	return (mac_open_by_linkname(name, (mac_handle_t *)mhandlep));
}

static void
mac_bpf_close(uintptr_t mhandle)
{
	mac_close((mac_handle_t)mhandle);
}

static const char *
mac_bpf_name(uintptr_t mhandle)
{
	return (mac_name((mac_handle_t)mhandle));
}

static int
mac_bpf_type(uintptr_t mhandle)
{
	return (mac_nativetype((mac_handle_t)mhandle));
}

static void
mac_bpf_sdu_get(uintptr_t mhandle, uint_t *mtup)
{
	mac_sdu_get((mac_handle_t)mhandle, NULL, mtup);
}

static int
mac_bpf_tx(uintptr_t chandle, mblk_t *pkt)
{
	/*
	 * If the mac layer cannot deliver a packet as requested by BPF then
	 * simply have the mac layer drop it. BPF isn't interested in doing
	 * any amount of retry - that's left to the application.
	 */
	return (mac_tx((mac_client_handle_t)chandle, pkt, 0,
	    MAC_DROP_ON_NO_DESC, NULL));
}

static uintptr_t
mac_bpf_promisc_add(uintptr_t chandle, int how, void *arg, uintptr_t *promisc,
    int flags)
{
	return (mac_promisc_add((mac_client_handle_t)chandle, how, bpf_mtap,
	    arg, (mac_promisc_handle_t *)promisc, flags));
}

static void
mac_bpf_promisc_remove(uintptr_t phandle)
{
	mac_promisc_remove((mac_promisc_handle_t)phandle);
}

static int
mac_bpf_client_open(uintptr_t mhandle, uintptr_t *chandlep)
{
	return (mac_client_open((mac_handle_t)mhandle,
	    (mac_client_handle_t *)chandlep,  NULL,
	    MAC_OPEN_FLAGS_USE_DATALINK_NAME));
}

static void
mac_bpf_client_close(uintptr_t chandle)
{
	mac_client_close((mac_client_handle_t)chandle, 0);
}

static const char *
mac_bpf_client_name(uintptr_t chandle)
{
	return (mac_client_name((mac_client_handle_t)chandle));
}

/*ARGSUSED*/
static int
mac_bpf_getlinkid(const char *name, datalink_id_t *idp, zoneid_t zoneid)
{
	int error;

	/*
	 * If at first we don't succeed, try again, just in case it is in
	 * hiding. The first call requires the datalink management daemon
	 * (the authorative source of information about name to id mapping)
	 * to be present and answering upcalls, the seond does not.
	 */
	error = dls_mgmt_get_linkid(name, idp);
	if (error != 0)
		error = dls_devnet_macname2linkid(name, idp);

	return (error);
}

static int
mac_bpf_getzone(uintptr_t handle, zoneid_t *zip)
{
	mac_perim_handle_t mph;
	int error;

	mac_perim_enter_by_mh((mac_handle_t)handle, &mph);
	error = dls_link_getzid(mac_name((mac_handle_t)handle), zip);
	mac_perim_exit(mph);
	return (error);
}

static int
mac_bpf_getdlt(uintptr_t handle, uint_t *dltp)
{
	*dltp = mac_nativetype((mac_handle_t)handle);

	return (0);
}
