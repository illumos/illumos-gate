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
 *
 * Copyright 2019 Joyent, Inc.
 */

/*
 * Simulated network device (simnet) driver: simulates a pseudo GLDv3 network
 * device. Can simulate an Ethernet or WiFi network device. In addition, another
 * simnet instance can be attached as a peer to create a point-to-point link on
 * the same system.
 */

#include <sys/policy.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/priv_names.h>
#include <sys/dlpi.h>
#include <net/simnet.h>
#include <sys/ethernet.h>
#include <sys/mac.h>
#include <sys/dls.h>
#include <sys/mac_ether.h>
#include <sys/mac_provider.h>
#include <sys/mac_client_priv.h>
#include <sys/vlan.h>
#include <sys/random.h>
#include <sys/sysmacros.h>
#include <sys/list.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/atomic.h>
#include <sys/mac_wifi.h>
#include <sys/mac_impl.h>
#include <sys/pattr.h>
#include <inet/wifi_ioctl.h>
#include <sys/thread.h>
#include <sys/synch.h>
#include <sys/sunddi.h>

#include "simnet_impl.h"

#define	SIMNETINFO		"Simulated Network Driver"

static dev_info_t *simnet_dip;
static ddi_taskq_t *simnet_rxq;

static int simnet_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int simnet_attach(dev_info_t *, ddi_attach_cmd_t);
static int simnet_detach(dev_info_t *, ddi_detach_cmd_t);
static int simnet_ioc_create(void *, intptr_t, int, cred_t *, int *);
static int simnet_ioc_delete(void *, intptr_t, int, cred_t *, int *);
static int simnet_ioc_info(void *, intptr_t, int, cred_t *, int *);
static int simnet_ioc_modify(void *, intptr_t, int, cred_t *, int *);
static uint8_t *mcastaddr_lookup(simnet_dev_t *, const uint8_t *);

static dld_ioc_info_t simnet_ioc_list[] = {
	{SIMNET_IOC_CREATE, DLDCOPYINOUT, sizeof (simnet_ioc_create_t),
	    simnet_ioc_create, secpolicy_dl_config},
	{SIMNET_IOC_DELETE, DLDCOPYIN, sizeof (simnet_ioc_delete_t),
	    simnet_ioc_delete, secpolicy_dl_config},
	{SIMNET_IOC_INFO, DLDCOPYINOUT, sizeof (simnet_ioc_info_t),
	    simnet_ioc_info, NULL},
	{SIMNET_IOC_MODIFY, DLDCOPYIN, sizeof (simnet_ioc_modify_t),
	    simnet_ioc_modify, secpolicy_dl_config}
};

DDI_DEFINE_STREAM_OPS(simnet_dev_ops, nulldev, nulldev, simnet_attach,
    simnet_detach, nodev, simnet_getinfo, D_MP, NULL,
    ddi_quiesce_not_supported);

static struct modldrv simnet_modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	SIMNETINFO,		/* short description */
	&simnet_dev_ops		/* driver specific ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, &simnet_modldrv, NULL
};

/* MAC callback function declarations */
static int simnet_m_start(void *);
static void simnet_m_stop(void *);
static int simnet_m_promisc(void *, boolean_t);
static int simnet_m_multicst(void *, boolean_t, const uint8_t *);
static int simnet_m_unicst(void *, const uint8_t *);
static int simnet_m_stat(void *, uint_t, uint64_t *);
static void simnet_m_ioctl(void *, queue_t *, mblk_t *);
static mblk_t *simnet_m_tx(void *, mblk_t *);
static int simnet_m_setprop(void *, const char *, mac_prop_id_t,
    const uint_t, const void *);
static int simnet_m_getprop(void *, const char *, mac_prop_id_t,
    uint_t, void *);
static void simnet_m_propinfo(void *, const char *, mac_prop_id_t,
    mac_prop_info_handle_t);
static boolean_t simnet_m_getcapab(void *, mac_capab_t, void *);

static mac_callbacks_t simnet_m_callbacks = {
	(MC_IOCTL | MC_GETCAPAB | MC_SETPROP | MC_GETPROP | MC_PROPINFO),
	simnet_m_stat,
	simnet_m_start,
	simnet_m_stop,
	simnet_m_promisc,
	simnet_m_multicst,
	simnet_m_unicst,
	simnet_m_tx,
	NULL,
	simnet_m_ioctl,
	simnet_m_getcapab,
	NULL,
	NULL,
	simnet_m_setprop,
	simnet_m_getprop,
	simnet_m_propinfo
};

/*
 * simnet_dev_lock protects the simnet device list.
 * sd_instlock in each simnet_dev_t protects access to
 * a single simnet_dev_t.
 */
static krwlock_t	simnet_dev_lock;
static list_t		simnet_dev_list;
static int		simnet_count; /* Num of simnet instances */

int
_init(void)
{
	int	status;

	mac_init_ops(&simnet_dev_ops, "simnet");
	status = mod_install(&modlinkage);
	if (status != DDI_SUCCESS)
		mac_fini_ops(&simnet_dev_ops);

	return (status);
}

int
_fini(void)
{
	int	status;

	status = mod_remove(&modlinkage);
	if (status == DDI_SUCCESS)
		mac_fini_ops(&simnet_dev_ops);

	return (status);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static boolean_t
simnet_init(void)
{
	if ((simnet_rxq = ddi_taskq_create(simnet_dip, "simnet", 1,
	    TASKQ_DEFAULTPRI, 0)) == NULL)
		return (B_FALSE);
	rw_init(&simnet_dev_lock, NULL, RW_DEFAULT, NULL);
	list_create(&simnet_dev_list, sizeof (simnet_dev_t),
	    offsetof(simnet_dev_t, sd_listnode));
	return (B_TRUE);
}

static void
simnet_fini(void)
{
	ASSERT(simnet_count == 0);
	rw_destroy(&simnet_dev_lock);
	list_destroy(&simnet_dev_list);
	ddi_taskq_destroy(simnet_rxq);
}

/*ARGSUSED*/
static int
simnet_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result)
{
	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = simnet_dip;
		return (DDI_SUCCESS);
	case DDI_INFO_DEVT2INSTANCE:
		*result = NULL;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

static int
simnet_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		if (ddi_get_instance(dip) != 0) {
			/* we only allow instance 0 to attach */
			return (DDI_FAILURE);
		}

		if (dld_ioc_register(SIMNET_IOC, simnet_ioc_list,
		    DLDIOCCNT(simnet_ioc_list)) != 0)
			return (DDI_FAILURE);

		simnet_dip = dip;
		if (!simnet_init())
			return (DDI_FAILURE);
		return (DDI_SUCCESS);

	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

/*ARGSUSED*/
static int
simnet_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		/*
		 * Allow the simnet instance to be detached only if there
		 * are no simnets configured.
		 */
		if (simnet_count > 0)
			return (DDI_FAILURE);

		dld_ioc_unregister(SIMNET_IOC);
		simnet_fini();
		simnet_dip = NULL;
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

/* Caller must hold simnet_dev_lock */
static simnet_dev_t *
simnet_dev_lookup(datalink_id_t link_id)
{
	simnet_dev_t *sdev;

	ASSERT(RW_LOCK_HELD(&simnet_dev_lock));
	for (sdev = list_head(&simnet_dev_list); sdev != NULL;
	    sdev = list_next(&simnet_dev_list, sdev)) {
		if (!(sdev->sd_flags & SDF_SHUTDOWN) &&
		    (sdev->sd_link_id == link_id)) {
			atomic_inc_32(&sdev->sd_refcount);
			return (sdev);
		}
	}

	return (NULL);
}

static void
simnet_wifidev_free(simnet_dev_t *sdev)
{
	simnet_wifidev_t *wdev = sdev->sd_wifidev;
	int i;

	for (i = 0; i < wdev->swd_esslist_num; i++) {
		kmem_free(wdev->swd_esslist[i],
		    sizeof (wl_ess_conf_t));
	}
	kmem_free(wdev, sizeof (simnet_wifidev_t));
}

static void
simnet_dev_unref(simnet_dev_t *sdev)
{

	ASSERT(sdev->sd_refcount > 0);
	if (atomic_dec_32_nv(&sdev->sd_refcount) != 0)
		return;

	if (sdev->sd_mh != NULL)
		(void) mac_unregister(sdev->sd_mh);

	if (sdev->sd_wifidev != NULL) {
		ASSERT(sdev->sd_type == DL_WIFI);
		simnet_wifidev_free(sdev);
	}

	mutex_destroy(&sdev->sd_instlock);
	cv_destroy(&sdev->sd_threadwait);
	kmem_free(sdev->sd_mcastaddrs, ETHERADDRL * sdev->sd_mcastaddr_count);
	kmem_free(sdev, sizeof (*sdev));
	simnet_count--;
}

static int
simnet_init_wifi(simnet_dev_t *sdev, mac_register_t *mac)
{
	wifi_data_t		wd = { 0 };
	int err;

	sdev->sd_wifidev = kmem_zalloc(sizeof (simnet_wifidev_t), KM_NOSLEEP);
	if (sdev->sd_wifidev == NULL)
		return (ENOMEM);

	sdev->sd_wifidev->swd_sdev = sdev;
	sdev->sd_wifidev->swd_linkstatus = WL_NOTCONNECTED;
	wd.wd_secalloc = WIFI_SEC_NONE;
	wd.wd_opmode = IEEE80211_M_STA;
	mac->m_type_ident = MAC_PLUGIN_IDENT_WIFI;
	mac->m_max_sdu = IEEE80211_MTU;
	mac->m_pdata = &wd;
	mac->m_pdata_size = sizeof (wd);
	err = mac_register(mac, &sdev->sd_mh);
	return (err);
}

static int
simnet_init_ether(simnet_dev_t *sdev, mac_register_t *mac)
{
	int err;

	mac->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	mac->m_max_sdu = SIMNET_MAX_MTU;
	mac->m_margin = VLAN_TAGSZ;
	err = mac_register(mac, &sdev->sd_mh);
	return (err);
}

static int
simnet_init_mac(simnet_dev_t *sdev)
{
	mac_register_t *mac;
	int err;

	if ((mac = mac_alloc(MAC_VERSION)) == NULL)
		return (ENOMEM);

	mac->m_driver = sdev;
	mac->m_dip = simnet_dip;
	mac->m_instance = (uint_t)-1;
	mac->m_src_addr = sdev->sd_mac_addr;
	mac->m_callbacks = &simnet_m_callbacks;
	mac->m_min_sdu = 0;

	if (sdev->sd_type == DL_ETHER)
		err = simnet_init_ether(sdev, mac);
	else if (sdev->sd_type == DL_WIFI)
		err = simnet_init_wifi(sdev, mac);
	else
		err = EINVAL;

	mac_free(mac);
	return (err);
}

/* ARGSUSED */
static int
simnet_ioc_create(void *karg, intptr_t arg, int mode, cred_t *cred, int *rvalp)
{
	simnet_ioc_create_t *create_arg = karg;
	simnet_dev_t *sdev;
	simnet_dev_t *sdev_tmp;
	int err = 0;

	sdev = kmem_zalloc(sizeof (*sdev), KM_NOSLEEP);
	if (sdev == NULL)
		return (ENOMEM);

	rw_enter(&simnet_dev_lock, RW_WRITER);
	if ((sdev_tmp = simnet_dev_lookup(create_arg->sic_link_id)) != NULL) {
		simnet_dev_unref(sdev_tmp);
		rw_exit(&simnet_dev_lock);
		kmem_free(sdev, sizeof (*sdev));
		return (EEXIST);
	}

	sdev->sd_type = create_arg->sic_type;
	sdev->sd_link_id = create_arg->sic_link_id;
	sdev->sd_zoneid = crgetzoneid(cred);
	sdev->sd_refcount++;
	mutex_init(&sdev->sd_instlock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&sdev->sd_threadwait, NULL, CV_DRIVER, NULL);
	simnet_count++;

	/* Simnets created from configuration on boot pass saved MAC address */
	if (create_arg->sic_mac_len == 0) {
		/* Generate random MAC address */
		(void) random_get_pseudo_bytes(sdev->sd_mac_addr, ETHERADDRL);
		/* Ensure MAC address is not multicast and is local */
		sdev->sd_mac_addr[0] = (sdev->sd_mac_addr[0] & ~1) | 2;
		sdev->sd_mac_len = ETHERADDRL;
	} else {
		(void) memcpy(sdev->sd_mac_addr, create_arg->sic_mac_addr,
		    create_arg->sic_mac_len);
		sdev->sd_mac_len = create_arg->sic_mac_len;
	}

	if ((err = simnet_init_mac(sdev)) != 0) {
		simnet_dev_unref(sdev);
		goto exit;
	}

	if ((err = dls_devnet_create(sdev->sd_mh, sdev->sd_link_id,
	    crgetzoneid(cred))) != 0) {
		simnet_dev_unref(sdev);
		goto exit;
	}

	mac_link_update(sdev->sd_mh, LINK_STATE_UP);
	mac_tx_update(sdev->sd_mh);
	list_insert_tail(&simnet_dev_list, sdev);

	/* Always return MAC address back to caller */
	(void) memcpy(create_arg->sic_mac_addr, sdev->sd_mac_addr,
	    sdev->sd_mac_len);
	create_arg->sic_mac_len = sdev->sd_mac_len;
exit:
	rw_exit(&simnet_dev_lock);
	return (err);
}

/* Caller must hold writer simnet_dev_lock */
static datalink_id_t
simnet_remove_peer(simnet_dev_t *sdev)
{
	simnet_dev_t *sdev_peer;
	datalink_id_t peer_link_id = DATALINK_INVALID_LINKID;

	ASSERT(RW_WRITE_HELD(&simnet_dev_lock));
	if ((sdev_peer = sdev->sd_peer_dev) != NULL) {
		ASSERT(sdev == sdev_peer->sd_peer_dev);
		sdev_peer->sd_peer_dev = NULL;
		sdev->sd_peer_dev = NULL;
		peer_link_id = sdev_peer->sd_link_id;
		/* Release previous references held on both simnets */
		simnet_dev_unref(sdev_peer);
		simnet_dev_unref(sdev);
	}

	return (peer_link_id);
}

/* ARGSUSED */
static int
simnet_ioc_modify(void *karg, intptr_t arg, int mode, cred_t *cred, int *rvalp)
{
	simnet_ioc_modify_t *modify_arg = karg;
	simnet_dev_t *sdev;
	simnet_dev_t *sdev_peer = NULL;

	rw_enter(&simnet_dev_lock, RW_WRITER);
	if ((sdev = simnet_dev_lookup(modify_arg->sim_link_id)) == NULL) {
		rw_exit(&simnet_dev_lock);
		return (ENOENT);
	}

	if (sdev->sd_zoneid != crgetzoneid(cred)) {
		rw_exit(&simnet_dev_lock);
		simnet_dev_unref(sdev);
		return (ENOENT);
	}

	if (sdev->sd_link_id == modify_arg->sim_peer_link_id) {
		/* Cannot peer with self */
		rw_exit(&simnet_dev_lock);
		simnet_dev_unref(sdev);
		return (EINVAL);
	}

	if (sdev->sd_peer_dev != NULL && sdev->sd_peer_dev->sd_link_id ==
	    modify_arg->sim_peer_link_id) {
		/* Nothing to modify */
		rw_exit(&simnet_dev_lock);
		simnet_dev_unref(sdev);
		return (0);
	}

	if (modify_arg->sim_peer_link_id != DATALINK_INVALID_LINKID) {
		sdev_peer = simnet_dev_lookup(modify_arg->sim_peer_link_id);
		if (sdev_peer == NULL) {
			/* Peer simnet device not available */
			rw_exit(&simnet_dev_lock);
			simnet_dev_unref(sdev);
			return (ENOENT);
		}
		if (sdev_peer->sd_zoneid != sdev->sd_zoneid) {
			/* The two peers must be in the same zone (for now). */
			rw_exit(&simnet_dev_lock);
			simnet_dev_unref(sdev);
			simnet_dev_unref(sdev_peer);
			return (EACCES);
		}
	}

	/* First remove any previous peer */
	(void) simnet_remove_peer(sdev);

	if (sdev_peer != NULL) {
		/* Remove any previous peer of sdev_peer */
		(void) simnet_remove_peer(sdev_peer);
		/* Update both devices with the new peer */
		sdev_peer->sd_peer_dev = sdev;
		sdev->sd_peer_dev = sdev_peer;
		/* Hold references on both devices */
	} else {
		/* Release sdev lookup reference */
		simnet_dev_unref(sdev);
	}

	rw_exit(&simnet_dev_lock);
	return (0);
}

/* ARGSUSED */
static int
simnet_ioc_delete(void *karg, intptr_t arg, int mode, cred_t *cred, int *rvalp)
{
	int err;
	simnet_dev_t *sdev;
	simnet_dev_t *sdev_peer;
	simnet_ioc_delete_t *delete_arg = karg;
	datalink_id_t tmpid;
	datalink_id_t peerid;

	rw_enter(&simnet_dev_lock, RW_WRITER);
	if ((sdev = simnet_dev_lookup(delete_arg->sid_link_id)) == NULL) {
		rw_exit(&simnet_dev_lock);
		return (ENOENT);
	}

	if (sdev->sd_zoneid != crgetzoneid(cred)) {
		rw_exit(&simnet_dev_lock);
		simnet_dev_unref(sdev);
		return (ENOENT);
	}

	if ((err = dls_devnet_destroy(sdev->sd_mh, &tmpid, B_TRUE)) != 0) {
		rw_exit(&simnet_dev_lock);
		simnet_dev_unref(sdev);
		return (err);
	}

	ASSERT(sdev->sd_link_id == tmpid);
	/* Remove any attached peer link */
	peerid = simnet_remove_peer(sdev);

	/* Prevent new threads from using the instance */
	mutex_enter(&sdev->sd_instlock);
	sdev->sd_flags |= SDF_SHUTDOWN;
	/* Wait until all active threads using the instance exit */
	while (sdev->sd_threadcount > 0) {
		if (cv_wait_sig(&sdev->sd_threadwait,
		    &sdev->sd_instlock) == 0)  {
			/* Signaled */
			mutex_exit(&sdev->sd_instlock);
			err = EINTR;
			goto fail;
		}
	}
	mutex_exit(&sdev->sd_instlock);

	/* Try disabling the MAC */
	if ((err = mac_disable(sdev->sd_mh)) != 0)
		goto fail;

	list_remove(&simnet_dev_list, sdev);
	rw_exit(&simnet_dev_lock);
	simnet_dev_unref(sdev); /* Release lookup ref */
	/* Releasing the last ref performs sdev/mem free */
	simnet_dev_unref(sdev);
	return (err);
fail:
	/* Re-create simnet instance and add any previous peer */
	(void) dls_devnet_create(sdev->sd_mh, sdev->sd_link_id,
	    crgetzoneid(cred));
	sdev->sd_flags &= ~SDF_SHUTDOWN;

	ASSERT(sdev->sd_peer_dev == NULL);
	if (peerid != DATALINK_INVALID_LINKID &&
	    ((sdev_peer = simnet_dev_lookup(peerid)) != NULL)) {
		/* Attach peer device back */
		ASSERT(sdev_peer->sd_peer_dev == NULL);
		sdev_peer->sd_peer_dev = sdev;
		sdev->sd_peer_dev = sdev_peer;
		/* Hold reference on both devices */
	} else {
		/*
		 * No previous peer or previous peer no longer
		 * available so release lookup reference.
		 */
		simnet_dev_unref(sdev);
	}

	rw_exit(&simnet_dev_lock);
	return (err);
}

/* ARGSUSED */
static int
simnet_ioc_info(void *karg, intptr_t arg, int mode, cred_t *cred, int *rvalp)
{
	simnet_ioc_info_t *info_arg = karg;
	simnet_dev_t *sdev;

	/* Make sure that the simnet link is visible from the caller's zone. */
	if (!dls_devnet_islinkvisible(info_arg->sii_link_id, crgetzoneid(cred)))
		return (ENOENT);

	rw_enter(&simnet_dev_lock, RW_READER);
	if ((sdev = simnet_dev_lookup(info_arg->sii_link_id)) == NULL) {
		rw_exit(&simnet_dev_lock);
		return (ENOENT);
	}

	(void) memcpy(info_arg->sii_mac_addr, sdev->sd_mac_addr,
	    sdev->sd_mac_len);
	info_arg->sii_mac_len = sdev->sd_mac_len;
	info_arg->sii_type = sdev->sd_type;
	if (sdev->sd_peer_dev != NULL)
		info_arg->sii_peer_link_id = sdev->sd_peer_dev->sd_link_id;
	rw_exit(&simnet_dev_lock);
	simnet_dev_unref(sdev);
	return (0);
}

static boolean_t
simnet_thread_ref(simnet_dev_t *sdev)
{
	mutex_enter(&sdev->sd_instlock);
	if (sdev->sd_flags & SDF_SHUTDOWN ||
	    !(sdev->sd_flags & SDF_STARTED)) {
		mutex_exit(&sdev->sd_instlock);
		return (B_FALSE);
	}
	sdev->sd_threadcount++;
	mutex_exit(&sdev->sd_instlock);
	return (B_TRUE);
}

static void
simnet_thread_unref(simnet_dev_t *sdev)
{
	mutex_enter(&sdev->sd_instlock);
	if (--sdev->sd_threadcount == 0)
		cv_broadcast(&sdev->sd_threadwait);
	mutex_exit(&sdev->sd_instlock);
}

/*
 * TODO: Add properties to set Rx checksum flag behavior.
 *
 * o HCK_IPV4_HDRCKSUM_OK.
 * o HCK_PARTIALCKSUM.
 * o HCK_FULLCKSUM_OK.
 */
static void
simnet_rx(void *arg)
{
	mblk_t *mp = arg;
	mac_header_info_t hdr_info;
	simnet_dev_t *sdev;

	sdev = (simnet_dev_t *)mp->b_next;
	mp->b_next = NULL;

	/* Check for valid packet header */
	if (mac_header_info(sdev->sd_mh, mp, &hdr_info) != 0) {
		mac_drop_pkt(mp, "invalid L2 header");
		sdev->sd_stats.recv_errors++;
		goto rx_done;
	}

	/*
	 * When we are NOT in promiscuous mode we only receive
	 * unicast packets addressed to us and multicast packets that
	 * MAC clients have requested.
	 */
	if (!sdev->sd_promisc &&
	    hdr_info.mhi_dsttype != MAC_ADDRTYPE_BROADCAST) {
		if (hdr_info.mhi_dsttype == MAC_ADDRTYPE_UNICAST &&
		    bcmp(hdr_info.mhi_daddr, sdev->sd_mac_addr,
		    ETHERADDRL) != 0) {
			freemsg(mp);
			goto rx_done;
		} else if (hdr_info.mhi_dsttype == MAC_ADDRTYPE_MULTICAST) {
			mutex_enter(&sdev->sd_instlock);
			if (mcastaddr_lookup(sdev, hdr_info.mhi_daddr) ==
			    NULL) {
				mutex_exit(&sdev->sd_instlock);
				freemsg(mp);
				goto rx_done;
			}
			mutex_exit(&sdev->sd_instlock);
		}
	}

	sdev->sd_stats.recv_count++;
	sdev->sd_stats.rbytes += msgdsize(mp);
	mac_rx(sdev->sd_mh, NULL, mp);
rx_done:
	simnet_thread_unref(sdev);
}

static mblk_t *
simnet_m_tx(void *arg, mblk_t *mp_chain)
{
	simnet_dev_t *sdev = arg;
	simnet_dev_t *sdev_rx;
	mblk_t *mpnext = mp_chain;
	mblk_t *mp, *nmp;

	rw_enter(&simnet_dev_lock, RW_READER);
	if ((sdev_rx = sdev->sd_peer_dev) == NULL) {
		/* Discard packets when no peer exists */
		rw_exit(&simnet_dev_lock);
		mac_drop_chain(mp_chain, "no peer");
		return (NULL);
	}

	/*
	 * Discard packets when either device is shutting down or not ready.
	 * Though MAC layer ensures a reference is held on the MAC while we
	 * process the packet chain, there is no guarantee the peer MAC will
	 * remain enabled. So we increment per-instance threadcount to ensure
	 * either MAC instance is not disabled while we handle the chain of
	 * packets. It is okay if the peer device is disconnected while we are
	 * here since we lookup the peer device while holding simnet_dev_lock
	 * (reader lock) and increment the threadcount of the peer, the peer
	 * MAC cannot be disabled in simnet_ioc_delete.
	 */
	if (!simnet_thread_ref(sdev_rx)) {
		rw_exit(&simnet_dev_lock);
		mac_drop_chain(mp_chain, "simnet peer dev not ready");
		return (NULL);
	}
	rw_exit(&simnet_dev_lock);

	if (!simnet_thread_ref(sdev)) {
		simnet_thread_unref(sdev_rx);
		mac_drop_chain(mp_chain, "simnet dev not ready");
		return (NULL);
	}

	while ((mp = mpnext) != NULL) {
		size_t len;
		size_t size;
		mblk_t *mp_new;
		mblk_t *mp_tmp;

		mpnext = mp->b_next;
		mp->b_next = NULL;
		len = msgdsize(mp);

		/* Pad packet to minimum Ethernet frame size */
		if (len < ETHERMIN) {
			size = ETHERMIN - len;
			mp_new = allocb(size, BPRI_HI);
			if (mp_new == NULL) {
				sdev->sd_stats.xmit_errors++;
				mac_drop_pkt(mp, "allocb failed");
				continue;
			}
			bzero(mp_new->b_wptr, size);
			mp_new->b_wptr += size;

			mp_tmp = mp;
			while (mp_tmp->b_cont != NULL)
				mp_tmp = mp_tmp->b_cont;
			mp_tmp->b_cont = mp_new;
			len += size;
		}

		/* Pullup packet into a single mblk */
		if ((nmp = msgpullup(mp, -1)) == NULL) {
			sdev->sd_stats.xmit_errors++;
			mac_drop_pkt(mp, "msgpullup failed");
			continue;
		} else {
			mac_hcksum_clone(mp, nmp);
			freemsg(mp);
			mp = nmp;
		}

		/* Hold reference for taskq receive processing per-pkt */
		if (!simnet_thread_ref(sdev_rx)) {
			mac_drop_pkt(mp, "failed to get thread ref");
			mac_drop_chain(mpnext, "failed to get thread ref");
			break;
		}

		mac_hw_emul(&mp, NULL, NULL,
		    MAC_IPCKSUM_EMUL | MAC_HWCKSUM_EMUL | MAC_LSO_EMUL);
		if (mp == NULL) {
			sdev->sd_stats.xmit_errors++;
			continue;
		}

		/*
		 * Remember, we are emulating a real NIC here; the
		 * checksum flags can't make the trip across the link.
		 */
		DB_CKSUMFLAGS(mp) = 0;

		/* Use taskq for pkt receive to avoid kernel stack explosion */
		mp->b_next = (mblk_t *)sdev_rx;
		if (ddi_taskq_dispatch(simnet_rxq, simnet_rx, mp,
		    DDI_NOSLEEP) == DDI_SUCCESS) {
			sdev->sd_stats.xmit_count++;
			sdev->sd_stats.obytes += len;
		} else {
			simnet_thread_unref(sdev_rx);
			mp->b_next = NULL;
			freemsg(mp);
			sdev_rx->sd_stats.recv_errors++;
		}
	}

	simnet_thread_unref(sdev);
	simnet_thread_unref(sdev_rx);
	return (NULL);
}

static int
simnet_wifi_ioctl(simnet_dev_t *sdev, mblk_t *mp)
{
	int rc = WL_SUCCESS;
	simnet_wifidev_t *wdev = sdev->sd_wifidev;

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	switch (((wldp_t *)mp->b_rptr)->wldp_id) {
	case WL_DISASSOCIATE:
		wdev->swd_linkstatus = WL_NOTCONNECTED;
		break;
	default:
		break;
	}
	return (rc);
}

static void
simnet_m_ioctl(void *arg, queue_t *q, mblk_t *mp)
{
	simnet_dev_t *sdev = arg;
	struct	iocblk	*iocp;
	mblk_t	*mp1;
	uint32_t cmd;
	int rc;

	if (sdev->sd_type != DL_WIFI) {
		miocnak(q, mp, 0, ENOTSUP);
		return;
	}

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	iocp = (struct iocblk *)mp->b_rptr;
	if (iocp->ioc_count == 0) {
		miocnak(q, mp, 0, EINVAL);
		return;
	}

	/* We only claim support for WiFi operation commands */
	cmd = iocp->ioc_cmd;
	switch (cmd) {
	default:
		miocnak(q, mp, 0, EINVAL);
		return;
	case WLAN_GET_PARAM:
	case WLAN_SET_PARAM:
	case WLAN_COMMAND:
		break;
	}

	mp1 = mp->b_cont;
	freemsg(mp1->b_cont);
	mp1->b_cont = NULL;
	/* overwrite everything */
	mp1->b_wptr = mp1->b_rptr;
	rc = simnet_wifi_ioctl(sdev, mp1);
	miocack(q, mp, msgdsize(mp1), rc);
}

static boolean_t
simnet_m_getcapab(void *arg, mac_capab_t cap, void *cap_data)
{
	simnet_dev_t *sdev = arg;
	const uint_t tcp_cksums = HCKSUM_INET_FULL_V4 | HCKSUM_INET_PARTIAL;

	switch (cap) {
	case MAC_CAPAB_HCKSUM: {
		uint32_t *tx_cksum_flags = cap_data;
		*tx_cksum_flags = sdev->sd_tx_cksum;
		break;
	}
	case MAC_CAPAB_LSO: {
		mac_capab_lso_t *cap_lso = cap_data;

		if (sdev->sd_lso &&
		    (sdev->sd_tx_cksum & HCKSUM_IPHDRCKSUM) != 0 &&
		    (sdev->sd_tx_cksum & tcp_cksums) != 0) {
			/*
			 * The LSO configuration is hardwried for now,
			 * but there's no reason we couldn't also make
			 * this configurable in the future.
			 */
			cap_lso->lso_flags = LSO_TX_BASIC_TCP_IPV4;
			cap_lso->lso_basic_tcp_ipv4.lso_max = SD_LSO_MAXLEN;
			break;
		} else {
			return (B_FALSE);
		}
	}
	default:
		return (B_FALSE);
	}

	return (B_TRUE);
}

static int
simnet_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	int rval = 0;
	simnet_dev_t *sdev = arg;

	ASSERT(sdev->sd_mh != NULL);

	switch (stat) {
	case MAC_STAT_IFSPEED:
		*val = 100 * 1000000ull; /* 100 Mbps */
		break;
	case MAC_STAT_LINK_STATE:
		*val = LINK_DUPLEX_FULL;
		break;
	case MAC_STAT_LINK_UP:
		if (sdev->sd_flags & SDF_STARTED)
			*val = LINK_STATE_UP;
		else
			*val = LINK_STATE_DOWN;
		break;
	case MAC_STAT_PROMISC:
	case MAC_STAT_MULTIRCV:
	case MAC_STAT_MULTIXMT:
	case MAC_STAT_BRDCSTRCV:
	case MAC_STAT_BRDCSTXMT:
		rval = ENOTSUP;
		break;
	case MAC_STAT_OPACKETS:
		*val = sdev->sd_stats.xmit_count;
		break;
	case MAC_STAT_OBYTES:
		*val = sdev->sd_stats.obytes;
		break;
	case MAC_STAT_IERRORS:
		*val = sdev->sd_stats.recv_errors;
		break;
	case MAC_STAT_OERRORS:
		*val = sdev->sd_stats.xmit_errors;
		break;
	case MAC_STAT_RBYTES:
		*val = sdev->sd_stats.rbytes;
		break;
	case MAC_STAT_IPACKETS:
		*val = sdev->sd_stats.recv_count;
		break;
	case WIFI_STAT_FCS_ERRORS:
	case WIFI_STAT_WEP_ERRORS:
	case WIFI_STAT_TX_FRAGS:
	case WIFI_STAT_MCAST_TX:
	case WIFI_STAT_RTS_SUCCESS:
	case WIFI_STAT_RTS_FAILURE:
	case WIFI_STAT_ACK_FAILURE:
	case WIFI_STAT_RX_FRAGS:
	case WIFI_STAT_MCAST_RX:
	case WIFI_STAT_RX_DUPS:
		rval = ENOTSUP;
		break;
	default:
		rval = ENOTSUP;
		break;
	}

	return (rval);
}

static int
simnet_m_start(void *arg)
{
	simnet_dev_t *sdev = arg;

	sdev->sd_flags |= SDF_STARTED;
	return (0);
}

static void
simnet_m_stop(void *arg)
{
	simnet_dev_t *sdev = arg;

	sdev->sd_flags &= ~SDF_STARTED;
}

static int
simnet_m_promisc(void *arg, boolean_t on)
{
	simnet_dev_t *sdev = arg;

	sdev->sd_promisc = on;
	return (0);
}

/*
 * Returns matching multicast address enabled on the simnet instance.
 * Assumes simnet instance mutex lock is held.
 */
static uint8_t *
mcastaddr_lookup(simnet_dev_t *sdev, const uint8_t *addrp)
{
	int idx;
	uint8_t *maddrptr;

	ASSERT(MUTEX_HELD(&sdev->sd_instlock));
	maddrptr = sdev->sd_mcastaddrs;
	for (idx = 0; idx < sdev->sd_mcastaddr_count; idx++) {
		if (bcmp(maddrptr, addrp, ETHERADDRL) == 0)
			return (maddrptr);
		maddrptr += ETHERADDRL;
	}

	return (NULL);
}

/* Add or remove Multicast addresses on simnet instance */
static int
simnet_m_multicst(void *arg, boolean_t add, const uint8_t *addrp)
{
	simnet_dev_t *sdev = arg;
	uint8_t *maddrptr;
	uint8_t *newbuf;
	size_t prevsize;
	size_t newsize;
	ptrdiff_t len;
	ptrdiff_t len2;

alloc_retry:
	prevsize = sdev->sd_mcastaddr_count * ETHERADDRL;
	newsize = prevsize + (add ? ETHERADDRL:-ETHERADDRL);
	newbuf = kmem_alloc(newsize, KM_SLEEP);

	mutex_enter(&sdev->sd_instlock);
	if (prevsize != (sdev->sd_mcastaddr_count * ETHERADDRL)) {
		mutex_exit(&sdev->sd_instlock);
		kmem_free(newbuf, newsize);
		goto alloc_retry;
	}

	maddrptr = mcastaddr_lookup(sdev, addrp);
	if (!add && maddrptr != NULL) {
		/* Removing a Multicast address */
		if (newbuf != NULL) {
			/* LINTED: E_PTRDIFF_OVERFLOW */
			len = maddrptr - sdev->sd_mcastaddrs;
			(void) memcpy(newbuf, sdev->sd_mcastaddrs, len);
			len2 = prevsize - len - ETHERADDRL;
			(void) memcpy(newbuf + len,
			    maddrptr + ETHERADDRL, len2);
		}
		sdev->sd_mcastaddr_count--;
	} else if (add && maddrptr == NULL) {
		/* Adding a new Multicast address */
		(void) memcpy(newbuf, sdev->sd_mcastaddrs, prevsize);
		(void) memcpy(newbuf + prevsize, addrp, ETHERADDRL);
		sdev->sd_mcastaddr_count++;
	} else {
		/* Error: removing a non-existing Multicast address */
		mutex_exit(&sdev->sd_instlock);
		kmem_free(newbuf, newsize);
		cmn_err(CE_WARN, "simnet: MAC call to remove a "
		    "Multicast address failed");
		return (EINVAL);
	}

	kmem_free(sdev->sd_mcastaddrs, prevsize);
	sdev->sd_mcastaddrs = newbuf;
	mutex_exit(&sdev->sd_instlock);
	return (0);
}

static int
simnet_m_unicst(void *arg, const uint8_t *macaddr)
{
	simnet_dev_t *sdev = arg;

	(void) memcpy(sdev->sd_mac_addr, macaddr, ETHERADDRL);
	return (0);
}

/* Parse WiFi scan list entry arguments and return the arg count */
static int
parse_esslist_args(const void *pr_val, uint_t pr_valsize,
    char args[][MAX_ESSLIST_ARGLEN])
{
	char *sep;
	ptrdiff_t len = pr_valsize;
	const char *piece = pr_val;
	const char *end = (const char *)pr_val + pr_valsize - 1;
	int arg = 0;

	while (piece < end && (arg < MAX_ESSLIST_ARGS)) {
		sep = strchr(piece, ',');
		if (sep == NULL)
			sep = (char *)end;
		/* LINTED E_PTRDIFF_OVERFLOW */
		len = sep - piece;
		/* If first arg is zero then return none to delete all */
		if (arg == 0 && strnlen(piece, len) == 1 && piece[0] == '0')
			return (0);
		if (len > MAX_ESSLIST_ARGLEN)
			len = MAX_ESSLIST_ARGLEN - 1;
		(void) memcpy(&args[arg][0], piece, len);
		args[arg][len] = '\0';
		piece = sep + 1;
		arg++;
	}

	return (arg);
}

/* Set WiFi scan list entry from private property _wl_esslist */
static int
set_wl_esslist_priv_prop(simnet_wifidev_t *wdev, uint_t pr_valsize,
    const void *pr_val)
{
	char essargs[MAX_ESSLIST_ARGS][MAX_ESSLIST_ARGLEN];
	wl_ess_conf_t *wls;
	long result;
	int i;

	bzero(essargs, sizeof (essargs));
	if (parse_esslist_args(pr_val, pr_valsize, essargs) == 0) {
		for (i = 0; i < wdev->swd_esslist_num; i++) {
			kmem_free(wdev->swd_esslist[i], sizeof (wl_ess_conf_t));
			wdev->swd_esslist[i] = NULL;
		}
		wdev->swd_esslist_num = 0;
		return (0);
	}

	for (i = 0; i < wdev->swd_esslist_num; i++) {
		wls = wdev->swd_esslist[i];
		if (strcasecmp(wls->wl_ess_conf_essid.wl_essid_essid,
		    essargs[0]) == 0)
			return (EEXIST);
	}

	if (wdev->swd_esslist_num >= MAX_SIMNET_ESSCONF)
		return (EINVAL);

	wls = kmem_zalloc(sizeof (wl_ess_conf_t), KM_SLEEP);
	(void) strlcpy(wls->wl_ess_conf_essid.wl_essid_essid,
	    essargs[0], sizeof (wls->wl_ess_conf_essid.wl_essid_essid));
	wls->wl_ess_conf_essid.wl_essid_length =
	    strlen(wls->wl_ess_conf_essid.wl_essid_essid);
	(void) random_get_pseudo_bytes((uint8_t *)
	    &wls->wl_ess_conf_bssid, sizeof (wl_bssid_t));
	(void) ddi_strtol(essargs[1], (char **)NULL, 0, &result);
	wls->wl_ess_conf_sl = (wl_rssi_t)
	    ((result > MAX_RSSI || result < 0) ? 0:result);
	wdev->swd_esslist[wdev->swd_esslist_num] = wls;
	wdev->swd_esslist_num++;

	return (0);
}

static int
simnet_set_priv_prop_wifi(simnet_dev_t *sdev, const char *name,
    const uint_t len, const void *val)
{
	simnet_wifidev_t *wdev = sdev->sd_wifidev;
	long result;

	if (strcmp(name, "_wl_esslist") == 0) {
		if (val == NULL)
			return (EINVAL);
		return (set_wl_esslist_priv_prop(wdev, len, val));
	} else if (strcmp(name, "_wl_connected") == 0) {
		if (val == NULL)
			return (EINVAL);
		(void) ddi_strtol(val, (char **)NULL, 0, &result);
		wdev->swd_linkstatus = ((result == 1) ?
		    WL_CONNECTED:WL_NOTCONNECTED);
		return (0);
	}

	return (EINVAL);
}

/* ARGSUSED */
static int
simnet_set_priv_prop_ether(simnet_dev_t *sdev, const char *name,
    const uint_t len, const void *val)
{
	if (strcmp(name, SD_PROP_TX_ULP_CKSUM) == 0) {
		if (val == NULL)
			return (EINVAL);

		/*
		 * Remember, full and partial checksum are mutually
		 * exclusive.
		 */
		if (strcmp(val, "none") == 0) {
			sdev->sd_tx_cksum &= ~HCKSUM_INET_FULL_V4;
		} else if (strcmp(val, "fullv4") == 0) {
			sdev->sd_tx_cksum &= ~HCKSUM_INET_PARTIAL;
			sdev->sd_tx_cksum |= HCKSUM_INET_FULL_V4;
		} else if (strcmp(val, "partial") == 0) {
			sdev->sd_tx_cksum &= HCKSUM_INET_FULL_V4;
			sdev->sd_tx_cksum |= HCKSUM_INET_PARTIAL;
		} else {
			return (EINVAL);
		}

		return (0);
	} else if (strcmp(name, SD_PROP_TX_IP_CKSUM) == 0) {
		if (val == NULL)
			return (EINVAL);

		if (strcmp(val, "off") == 0) {
			sdev->sd_tx_cksum &= ~HCKSUM_IPHDRCKSUM;
		} else if (strcmp(val, "on") == 0) {
			sdev->sd_tx_cksum |= HCKSUM_IPHDRCKSUM;
		} else {
			return (EINVAL);
		}

		return (0);
	} else if (strcmp(name, SD_PROP_LSO) == 0) {
		if (val == NULL)
			return (EINVAL);

		if (strcmp(val, "off") == 0) {
			sdev->sd_lso = B_FALSE;
		} else if (strcmp(val, "on") == 0) {
			sdev->sd_lso = B_TRUE;
		} else {
			return (EINVAL);
		}

		return (0);
	}

	return (ENOTSUP);
}

static int
simnet_setprop_wifi(simnet_dev_t *sdev, const char *name,
    const mac_prop_id_t num, const uint_t len, const void *val)
{
	int err = 0;
	simnet_wifidev_t *wdev = sdev->sd_wifidev;

	switch (num) {
	case MAC_PROP_WL_ESSID: {
		int i;
		wl_ess_conf_t *wls;

		(void) memcpy(&wdev->swd_essid, val, sizeof (wl_essid_t));
		wdev->swd_linkstatus = WL_CONNECTED;

		/* Lookup the signal strength of the connected ESSID */
		for (i = 0; i < wdev->swd_esslist_num; i++) {
			wls = wdev->swd_esslist[i];
			if (strcasecmp(wls->wl_ess_conf_essid.wl_essid_essid,
			    wdev->swd_essid.wl_essid_essid) == 0) {
				wdev->swd_rssi = wls->wl_ess_conf_sl;
				break;
			}
		}
		break;
	}
	case MAC_PROP_WL_BSSID: {
		(void) memcpy(&wdev->swd_bssid, val, sizeof (wl_bssid_t));
		break;
	}
	case MAC_PROP_WL_PHY_CONFIG:
	case MAC_PROP_WL_KEY_TAB:
	case MAC_PROP_WL_AUTH_MODE:
	case MAC_PROP_WL_ENCRYPTION:
	case MAC_PROP_WL_BSSTYPE:
	case MAC_PROP_WL_DESIRED_RATES:
		break;
	case MAC_PROP_PRIVATE:
		err = simnet_set_priv_prop_wifi(sdev, name, len, val);
		break;
	default:
		err = EINVAL;
		break;
	}

	return (err);
}

static int
simnet_setprop_ether(simnet_dev_t *sdev, const char *name,
    const mac_prop_id_t num, const uint_t len, const void *val)
{
	int err = 0;

	switch (num) {
	case MAC_PROP_PRIVATE:
		err = simnet_set_priv_prop_ether(sdev, name, len, val);
		break;
	default:
		err = EINVAL;
		break;
	}

	return (err);
}

static int
simnet_m_setprop(void *arg, const char *name, mac_prop_id_t num,
    const uint_t len, const void *val)
{
	simnet_dev_t *sdev = arg;
	int err = 0;
	uint32_t mtu;

	switch (num) {
	case MAC_PROP_MTU:
		(void) memcpy(&mtu, val, sizeof (mtu));
		if (mtu > ETHERMIN && mtu < SIMNET_MAX_MTU)
			return (mac_maxsdu_update(sdev->sd_mh, mtu));
		else
			return (EINVAL);
	default:
		break;
	}

	switch (sdev->sd_type) {
	case DL_ETHER:
		err = simnet_setprop_ether(sdev, name, num, len, val);
		break;
	case DL_WIFI:
		err = simnet_setprop_wifi(sdev, name, num, len, val);
		break;
	default:
		err = EINVAL;
		break;
	}

	return (err);
}

static int
simnet_get_priv_prop_wifi(const simnet_dev_t *sdev, const char *name,
    const uint_t len, void *val)
{
	simnet_wifidev_t *wdev = sdev->sd_wifidev;
	int ret, value;

	if (strcmp(name, "_wl_esslist") == 0) {
		/* Returns num of _wl_ess_conf_t that have been set */
		value = wdev->swd_esslist_num;
	} else if (strcmp(name, "_wl_connected") == 0) {
		value = ((wdev->swd_linkstatus == WL_CONNECTED) ? 1:0);
	} else {
		return (ENOTSUP);
	}

	ret = snprintf(val, len, "%d", value);

	if (ret < 0 || ret >= len)
		return (EOVERFLOW);

	return (0);
}

static int
simnet_get_priv_prop_ether(const simnet_dev_t *sdev, const char *name,
    const uint_t len, void *val)
{
	int ret;
	char *value;

	if (strcmp(name, SD_PROP_TX_ULP_CKSUM) == 0) {
		if ((sdev->sd_tx_cksum & HCKSUM_INET_FULL_V4) != 0) {
			value = "fullv4";
		} else if ((sdev->sd_tx_cksum & HCKSUM_INET_PARTIAL) != 0) {
			value = "partial";
		} else {
			value = "none";
		}
	} else if (strcmp(name, SD_PROP_TX_IP_CKSUM) == 0) {
		if ((sdev->sd_tx_cksum & HCKSUM_IPHDRCKSUM) != 0) {
			value = "on";
		} else {
			value = "off";
		}
	} else if (strcmp(name, SD_PROP_LSO) == 0) {
		value = sdev->sd_lso ? "on" : "off";
	} else {
		return (ENOTSUP);
	}

	ret = snprintf(val, len, "%s", value);

	if (ret < 0 || ret >= len) {
		return (EOVERFLOW);
	}

	return (0);
}

static int
simnet_getprop_wifi(const simnet_dev_t *sdev, const char *name,
    const mac_prop_id_t num, const uint_t len, void *val)
{
	const simnet_wifidev_t *wdev = sdev->sd_wifidev;
	int err = 0;

	switch (num) {
	case MAC_PROP_WL_ESSID:
		(void) memcpy(val, &wdev->swd_essid, sizeof (wl_essid_t));
		break;
	case MAC_PROP_WL_BSSID:
		(void) memcpy(val, &wdev->swd_bssid, sizeof (wl_bssid_t));
		break;
	case MAC_PROP_WL_PHY_CONFIG:
	case MAC_PROP_WL_AUTH_MODE:
	case MAC_PROP_WL_ENCRYPTION:
		break;
	case MAC_PROP_WL_LINKSTATUS:
		(void) memcpy(val, &wdev->swd_linkstatus,
		    sizeof (wdev->swd_linkstatus));
		break;
	case MAC_PROP_WL_ESS_LIST: {
		wl_ess_conf_t *w_ess_conf;

		((wl_ess_list_t *)val)->wl_ess_list_num = wdev->swd_esslist_num;
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		w_ess_conf = (wl_ess_conf_t *)((char *)val +
		    offsetof(wl_ess_list_t, wl_ess_list_ess));
		for (uint_t i = 0; i < wdev->swd_esslist_num; i++) {
			(void) memcpy(w_ess_conf, wdev->swd_esslist[i],
			    sizeof (wl_ess_conf_t));
			w_ess_conf++;
		}
		break;
	}
	case MAC_PROP_WL_RSSI:
		*(wl_rssi_t *)val = wdev->swd_rssi;
		break;
	case MAC_PROP_WL_RADIO:
		*(wl_radio_t *)val = B_TRUE;
		break;
	case MAC_PROP_WL_POWER_MODE:
		break;
	case MAC_PROP_WL_DESIRED_RATES:
		break;
	case MAC_PROP_PRIVATE:
		err = simnet_get_priv_prop_wifi(sdev, name, len, val);
		break;
	default:
		err = ENOTSUP;
		break;
	}

	return (err);
}

static int
simnet_getprop_ether(const simnet_dev_t *sdev, const char *name,
    const mac_prop_id_t num, const uint_t len, void *val)
{
	int err = 0;

	switch (num) {
	case MAC_PROP_PRIVATE:
		err = simnet_get_priv_prop_ether(sdev, name, len, val);
		break;
	default:
		err = ENOTSUP;
		break;
	}

	return (err);
}

static int
simnet_m_getprop(void *arg, const char *name, const mac_prop_id_t num,
    const uint_t len, void *val)
{
	const simnet_dev_t *sdev = arg;
	int err = 0;

	switch (sdev->sd_type) {
	case DL_ETHER:
		err = simnet_getprop_ether(sdev, name, num, len, val);
		break;
	case DL_WIFI:
		err = simnet_getprop_wifi(sdev, name, num, len, val);
		break;
	default:
		err = EINVAL;
		break;
	}

	return (err);
}

static void
simnet_priv_propinfo_wifi(const char *name, mac_prop_info_handle_t prh)
{
	char valstr[MAXNAMELEN];

	bzero(valstr, sizeof (valstr));

	if (strcmp(name, "_wl_esslist") == 0) {
		(void) snprintf(valstr, sizeof (valstr), "%d", 0);
	}

	if (strlen(valstr) > 0)
		mac_prop_info_set_default_str(prh, valstr);
}

static void
simnet_propinfo_wifi(const char *name, const mac_prop_id_t num,
    mac_prop_info_handle_t prh)
{
	switch (num) {
	case MAC_PROP_WL_BSSTYPE:
	case MAC_PROP_WL_ESS_LIST:
	case MAC_PROP_WL_SUPPORTED_RATES:
	case MAC_PROP_WL_RSSI:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		break;
	case MAC_PROP_PRIVATE:
		simnet_priv_propinfo_wifi(name, prh);
		break;
	}
}

static void
simnet_priv_propinfo_ether(const char *name, mac_prop_info_handle_t prh)
{
	if (strcmp(name, SD_PROP_TX_ULP_CKSUM) == 0 ||
	    strcmp(name, SD_PROP_TX_IP_CKSUM) == 0 ||
	    strcmp(name, SD_PROP_LSO) == 0) {
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_RW);
	}

	if (strcmp(name, SD_PROP_TX_ULP_CKSUM) == 0) {
		mac_prop_info_set_default_str(prh, "none");
	}

	if (strcmp(name, SD_PROP_TX_IP_CKSUM) == 0 ||
	    strcmp(name, SD_PROP_LSO) == 0) {
		mac_prop_info_set_default_str(prh, "off");
	}
}

static void
simnet_propinfo_ether(const char *name, const mac_prop_id_t num,
    mac_prop_info_handle_t prh)
{
	switch (num) {
	case MAC_PROP_PRIVATE:
		simnet_priv_propinfo_ether(name, prh);
		break;
	}
}

static void
simnet_m_propinfo(void *arg, const char *name, const mac_prop_id_t num,
    const mac_prop_info_handle_t prh)
{
	simnet_dev_t *sdev = arg;

	switch (sdev->sd_type) {
	case DL_ETHER:
		simnet_propinfo_ether(name, num, prh);
		break;
	case DL_WIFI:
		simnet_propinfo_wifi(name, num, prh);
		break;
	}
}
