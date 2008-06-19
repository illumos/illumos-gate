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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * The softmac driver is used to "unify" non-GLDv3 drivers to the GLDv3
 * framework.  It also creates the kernel datalink structure for each
 * physical network device.
 *
 * Specifically, a softmac will be created for each physical network device
 * (dip) during the device's post-attach process.  When this softmac is
 * created, the following will also be done:
 *   - create the device's <link name, linkid> mapping;
 *   - register the mac if this is a non-GLDv3 device and the media type is
 *     supported by the GLDv3 framework;
 *   - create the kernel data-link structure for this physical device;
 *
 * This softmac will be destroyed during the device's pre-detach process,
 * and all the above will be undone.
 */

#include <sys/types.h>
#include <sys/file.h>
#include <sys/cred.h>
#include <sys/dlpi.h>
#include <sys/sunndi.h>
#include <sys/modhash.h>
#include <sys/stropts.h>
#include <sys/sysmacros.h>
#include <sys/vlan.h>
#include <sys/softmac_impl.h>
#include <sys/softmac.h>
#include <sys/dls.h>

/*
 * Softmac hash table including softmacs for both style-2 and style-1 devices.
 */
static krwlock_t	softmac_hash_lock;
static mod_hash_t	*softmac_hash;

#define	SOFTMAC_HASHSZ		64

static void softmac_mac_register(void *);
static int softmac_create_datalink(softmac_t *);
static int softmac_m_start(void *);
static void softmac_m_stop(void *);
static int softmac_m_open(void *);
static void softmac_m_close(void *);
static boolean_t softmac_m_getcapab(void *, mac_capab_t, void *);

#define	SOFTMAC_M_CALLBACK_FLAGS	\
	(MC_RESOURCES | MC_IOCTL | MC_GETCAPAB | MC_OPEN | MC_CLOSE)

static mac_callbacks_t softmac_m_callbacks = {
	SOFTMAC_M_CALLBACK_FLAGS,
	softmac_m_stat,
	softmac_m_start,
	softmac_m_stop,
	softmac_m_promisc,
	softmac_m_multicst,
	softmac_m_unicst,
	softmac_m_tx,
	softmac_m_resources,
	softmac_m_ioctl,
	softmac_m_getcapab,
	softmac_m_open,
	softmac_m_close
};

void
softmac_init()
{
	softmac_hash = mod_hash_create_extended("softmac_hash",
	    SOFTMAC_HASHSZ, mod_hash_null_keydtor, mod_hash_null_valdtor,
	    mod_hash_bystr, NULL, mod_hash_strkey_cmp, KM_SLEEP);

	rw_init(&softmac_hash_lock, NULL, RW_DEFAULT, NULL);
}

void
softmac_fini()
{
	rw_destroy(&softmac_hash_lock);
	mod_hash_destroy_hash(softmac_hash);
}

/* ARGSUSED */
static uint_t
softmac_exist(mod_hash_key_t key, mod_hash_val_t *val, void *arg)
{
	boolean_t *pexist = arg;

	*pexist = B_TRUE;
	return (MH_WALK_TERMINATE);
}

boolean_t
softmac_busy()
{
	boolean_t exist = B_FALSE;

	rw_enter(&softmac_hash_lock, RW_READER);
	mod_hash_walk(softmac_hash, softmac_exist, &exist);
	rw_exit(&softmac_hash_lock);
	return (exist);
}

/*
 * This function is called for each minor node during the post-attach of
 * each DDI_NT_NET device instance.  Note that it is possible that a device
 * instance has two minor nodes (DLPI style-1 and style-2), so that for that
 * specific device, softmac_create() could be called twice.
 *
 * A softmac_t is used to track each DDI_NT_NET device, and a softmac_dev_t
 * is created to track each minor node.
 *
 * For each minor node of a legacy device, a taskq is started to finish
 * softmac_mac_register(), which will finish the rest of work (see comments
 * above softmac_mac_register()).
 */
int
softmac_create(dev_info_t *dip, dev_t dev)
{
	char		devname[MAXNAMELEN];
	softmac_t	*softmac;
	softmac_dev_t	*softmac_dev = NULL;
	datalink_id_t	linkid;
	int		index;
	int		ppa, err = 0;
	mac_handle_t	mh;

	/*
	 * Force the softmac driver to be attached.
	 */
	if (i_ddi_attach_pseudo_node(SOFTMAC_DEV_NAME) == NULL) {
		cmn_err(CE_WARN, "softmac_create:softmac attach fails");
		return (ENXIO);
	}

	ppa = ddi_get_instance(dip);
	(void) snprintf(devname, MAXNAMELEN, "%s%d", ddi_driver_name(dip), ppa);

	/*
	 * We expect legacy devices have at most two minor nodes - one style-1
	 * and one style-2.
	 */
	if (!GLDV3_DRV(ddi_driver_major(dip)) &&
	    i_ddi_minor_node_count(dip, DDI_NT_NET) > 2) {
		cmn_err(CE_WARN, "%s has more than 2 minor nodes; unsupported",
		    devname);
		return (ENOTSUP);
	}

	/*
	 * Check whether the softmac for the specified device already exists
	 */
	rw_enter(&softmac_hash_lock, RW_WRITER);
	if ((err = mod_hash_find(softmac_hash, (mod_hash_key_t)devname,
	    (mod_hash_val_t *)&softmac)) != 0) {

		softmac = kmem_zalloc(sizeof (softmac_t), KM_SLEEP);
		mutex_init(&softmac->smac_mutex, NULL, MUTEX_DRIVER, NULL);
		cv_init(&softmac->smac_cv, NULL, CV_DRIVER, NULL);
		rw_init(&softmac->smac_lock, NULL, RW_DRIVER, NULL);
		(void) strlcpy(softmac->smac_devname, devname, MAXNAMELEN);

		/*
		 * Insert the softmac into the hash table.
		 */
		err = mod_hash_insert(softmac_hash,
		    (mod_hash_key_t)softmac->smac_devname,
		    (mod_hash_val_t)softmac);
		ASSERT(err == 0);
	}

	mutex_enter(&softmac->smac_mutex);
	if (softmac->smac_attachok_cnt == 0) {
		/*
		 * Initialize the softmac if this is the post-attach of the
		 * first minor node.
		 */
		softmac->smac_flags = 0;
		softmac->smac_umajor = ddi_driver_major(dip);
		softmac->smac_uppa = ppa;

		/*
		 * Note that for GLDv3 devices, we create devfs minor nodes
		 * for VLANs as well. Assume a GLDv3 driver on which only
		 * a VLAN is created. During the detachment of this device
		 * instance, the following would happen:
		 * a. the pre-detach callback softmac_destroy() succeeds.
		 *    Because the physical link itself is not in use,
		 *    softmac_destroy() succeeds and destroys softmac_t;
		 * b. the device detach fails in mac_unregister() because
		 *    this MAC is still used by a VLAN.
		 * c. the post-attach callback is then called which leads
		 *    us here. Note that ddi_minor_node_count() returns 3
		 *    (including the minior node of the VLAN). In that case,
		 *    we must correct the minor node count to 2 as that is
		 *    the count of minor nodes that go through post-attach.
		 */
		if (GLDV3_DRV(ddi_driver_major(dip))) {
			softmac->smac_flags |= SOFTMAC_GLDV3;
			softmac->smac_cnt = 2;
		} else {
			softmac->smac_cnt =
			    i_ddi_minor_node_count(dip, DDI_NT_NET);
		}
	}

	index = (getmajor(dev) == ddi_name_to_major("clone"));
	if (softmac->smac_softmac[index] != NULL) {
		/*
		 * This is possible if the post_attach() is called:
		 *
		 * a. after pre_detach() fails.
		 *
		 * b. for a new round of reattachment. Note that DACF will not
		 * call pre_detach() for successfully post_attached minor
		 * nodes even when the post-attach failed after all.
		 *
		 * Both seem to be defects in the DACF framework. To work
		 * around it and only clear the SOFTMAC_ATTACH_DONE flag for
		 * the b case, a smac_attached_left field is used to tell
		 * the two cases apart.
		 */
		ASSERT(softmac->smac_attachok_cnt != 0);

		if (softmac->smac_attached_left != 0)
			/* case a */
			softmac->smac_attached_left--;
		else if (softmac->smac_attachok_cnt != softmac->smac_cnt) {
			/* case b */
			softmac->smac_flags &= ~SOFTMAC_ATTACH_DONE;
		}
		mutex_exit(&softmac->smac_mutex);
		rw_exit(&softmac_hash_lock);
		return (0);
	}
	mutex_exit(&softmac->smac_mutex);
	rw_exit(&softmac_hash_lock);

	/*
	 * Inform dlmgmtd of this link so that softmac_hold_device() is able
	 * to know the existence of this link.  This could fail if dlmgmtd
	 * is not yet started.
	 */
	(void) dls_mgmt_create(devname, makedevice(ddi_driver_major(dip),
	    ppa + 1), DATALINK_CLASS_PHYS, DL_OTHER, B_TRUE, &linkid);

	/*
	 * No lock is needed for access this softmac pointer, as pre-detach and
	 * post-attach won't happen at the same time.
	 */
	mutex_enter(&softmac->smac_mutex);

	softmac_dev = kmem_zalloc(sizeof (softmac_dev_t), KM_SLEEP);
	softmac_dev->sd_dev = dev;
	softmac->smac_softmac[index] = softmac_dev;

	/*
	 * Continue to register the mac and create the datalink only when all
	 * the minor nodes are attached.
	 */
	if (++softmac->smac_attachok_cnt != softmac->smac_cnt) {
		mutex_exit(&softmac->smac_mutex);
		return (0);
	}

	if (!GLDV3_DRV(ddi_driver_major(dip))) {

		/*
		 * Note that this function could be called as a result of
		 * a open() system call, and spec_open() already locked the
		 * snode (SLOCKED is set).  Therefore, we must start a
		 * taskq to finish the rest of work to sidestep the risk
		 * that our ldi_open_by_dev() call would again try to hold
		 * the same lock.
		 *
		 * If all the minor nodes have been attached, start the taskq
		 * to finish the rest of the work.
		 */
		ASSERT(softmac->smac_taskq == NULL);
		softmac->smac_taskq = taskq_dispatch(system_taskq,
		    softmac_mac_register, softmac, TQ_SLEEP);
		mutex_exit(&softmac->smac_mutex);
		return (0);
	}

	if ((err = mac_open(softmac->smac_devname, &mh)) != 0)
		goto done;

	softmac->smac_media = (mac_info(mh))->mi_nativemedia;
	softmac->smac_mh = mh;

	/*
	 * We can safely release the reference on the mac because
	 * this mac will only be unregistered and destroyed when
	 * the device detaches, and the softmac will be destroyed
	 * before then (in the pre-detach routine of the device).
	 */
	mac_close(mh);

	/*
	 * Create the GLDv3 datalink for this mac.
	 */
	err = softmac_create_datalink(softmac);

done:
	if (err != 0) {
		softmac->smac_mh = NULL;
		kmem_free(softmac_dev, sizeof (softmac_dev_t));
		softmac->smac_softmac[index] = NULL;
		--softmac->smac_attachok_cnt;
	}
	ASSERT(!(softmac->smac_flags & SOFTMAC_ATTACH_DONE));
	softmac->smac_flags |= SOFTMAC_ATTACH_DONE;
	softmac->smac_attacherr = err;
	cv_broadcast(&softmac->smac_cv);
	mutex_exit(&softmac->smac_mutex);
	return (err);
}

static boolean_t
softmac_m_getcapab(void *arg, mac_capab_t cap, void *cap_data)
{
	softmac_t *softmac = arg;

	if (!(softmac->smac_capab_flags & cap))
		return (B_FALSE);

	switch (cap) {
	case MAC_CAPAB_HCKSUM: {
		uint32_t *txflags = cap_data;

		*txflags = softmac->smac_hcksum_txflags;
		break;
	}
	case MAC_CAPAB_LEGACY: {
		mac_capab_legacy_t *legacy = cap_data;

		legacy->ml_unsup_note = ~softmac->smac_notifications &
		    (DL_NOTE_LINK_UP | DL_NOTE_LINK_DOWN | DL_NOTE_SPEED);
		legacy->ml_dev = makedevice(softmac->smac_umajor,
		    softmac->smac_uppa + 1);
		break;
	}

	/*
	 * For the capabilities below, there's nothing for us to fill in;
	 * simply return B_TRUE if we support it.
	 */
	case MAC_CAPAB_NO_ZCOPY:
	case MAC_CAPAB_POLL:
	case MAC_CAPAB_NO_NATIVEVLAN:
	default:
		break;
	}
	return (B_TRUE);
}

static int
softmac_update_info(softmac_t *softmac, datalink_id_t *linkidp)
{
	datalink_id_t	linkid = DATALINK_INVALID_LINKID;
	uint32_t	media;
	int		err;

	if ((err = dls_mgmt_update(softmac->smac_devname, softmac->smac_media,
	    softmac->smac_flags & SOFTMAC_NOSUPP, &media, &linkid)) == 0) {
		*linkidp = linkid;
	}

	if (err == EEXIST) {
		/*
		 * There is a link name conflict.  Either:
		 *
		 * - An existing link with the same device name with a
		 *   different media type from of the given type.
		 *   Mark this link back to persistent only; or
		 *
		 * - We cannot assign the "suggested" name because
		 *   GLDv3 and therefore vanity naming is not supported
		 *   for this link type. Delete this link's <link name,
		 *   linkid> mapping.
		 */
		if (media != softmac->smac_media) {
			cmn_err(CE_WARN, "%s device %s conflicts with "
			    "existing %s device %s.",
			    dl_mactypestr(softmac->smac_media),
			    softmac->smac_devname, dl_mactypestr(media),
			    softmac->smac_devname);
			(void) dls_mgmt_destroy(linkid, B_FALSE);
		} else {
			cmn_err(CE_WARN, "link name %s is already in-use.",
			    softmac->smac_devname);
			(void) dls_mgmt_destroy(linkid, B_TRUE);
		}

		cmn_err(CE_WARN, "%s device might not be available "
		    "for use.", softmac->smac_devname);
		cmn_err(CE_WARN, "See dladm(1M) for more information.");
	}

	return (err);
}

/*
 * This function:
 * 1. provides the link's media type to dlmgmtd.
 * 2. creates the GLDv3 datalink if the media type is supported by GLDv3.
 */
static int
softmac_create_datalink(softmac_t *softmac)
{
	datalink_id_t	linkid = DATALINK_INVALID_LINKID;
	int		err;

	ASSERT(MUTEX_HELD(&softmac->smac_mutex));

	/*
	 * First provide the media type of the physical link to dlmgmtd.
	 *
	 * If the new <linkname, linkid> mapping operation failed with EBADF
	 * or ENOENT, it might because the dlmgmtd was not started in time
	 * (e.g., diskless boot); ignore the failure and continue.  The
	 * mapping will be recreated once the daemon has started.
	 */
	if (((err = softmac_update_info(softmac, &linkid)) != 0) &&
	    (err != EBADF) && (err != ENOENT)) {
		return (err);
	}

	/*
	 * Create the GLDv3 datalink.
	 */
	if ((!(softmac->smac_flags & SOFTMAC_NOSUPP)) &&
	    ((err = dls_devnet_create(softmac->smac_mh, linkid)) != 0)) {
		cmn_err(CE_WARN, "dls_devnet_create failed for %s",
		    softmac->smac_devname);
		return (err);
	}

	if (linkid == DATALINK_INVALID_LINKID)
		softmac->smac_flags |= SOFTMAC_NEED_RECREATE;

	return (0);
}

/*
 * This function is only called for legacy devices. It:
 * 1. registers the MAC for the legacy devices whose media type is supported
 *    by the GLDv3 framework.
 * 2. creates the GLDv3 datalink if the media type is supported by GLDv3.
 */
static void
softmac_mac_register(void *arg)
{
	softmac_t	*softmac = arg;
	softmac_dev_t	*softmac_dev;
	dev_t		dev;
	ldi_handle_t	lh = NULL;
	ldi_ident_t	li = NULL;
	int		index;
	boolean_t	native_vlan = B_FALSE;
	int		err;

	/*
	 * Note that we do not need any locks to access this softmac pointer,
	 * as softmac_destroy() will wait until this function is called.
	 */
	ASSERT(softmac != NULL);

	if ((err = ldi_ident_from_dip(softmac_dip, &li)) != 0) {
		mutex_enter(&softmac->smac_mutex);
		goto done;
	}

	/*
	 * Determine whether this legacy device support VLANs by opening
	 * the style-2 device node (if it exists) and attaching to a VLAN
	 * PPA (1000 + ppa).
	 */
	dev = makedevice(ddi_name_to_major("clone"), softmac->smac_umajor);
	err = ldi_open_by_dev(&dev, OTYP_CHR, FREAD|FWRITE, kcred, &lh, li);
	if (err == 0) {
		if (dl_attach(lh, softmac->smac_uppa + 1 * 1000, NULL) == 0)
			native_vlan = B_TRUE;
		(void) ldi_close(lh, FREAD|FWRITE, kcred);
	}

	err = EINVAL;
	for (index = 0; index < 2; index++) {
		dl_info_ack_t	dlia;
		dl_error_ack_t	dlea;
		uint32_t	notes;
		struct strioctl	iocb;
		uint32_t	margin;
		int		rval;

		if ((softmac_dev = softmac->smac_softmac[index]) == NULL)
			continue;

		softmac->smac_dev = dev = softmac_dev->sd_dev;
		if (ldi_open_by_dev(&dev, OTYP_CHR, FREAD|FWRITE, kcred, &lh,
		    li) != 0) {
			continue;
		}

		/*
		 * Pop all the intermediate modules in order to negotiate
		 * capabilities correctly.
		 */
		while (ldi_ioctl(lh, I_POP, 0, FKIOCTL, kcred, &rval) == 0)
			;

		/* DLPI style-1 or DLPI style-2? */
		if ((rval = dl_info(lh, &dlia, NULL, NULL, &dlea)) != 0) {
			if (rval == ENOTSUP) {
				cmn_err(CE_NOTE, "softmac: received "
				    "DL_ERROR_ACK to DL_INFO_ACK; "
				    "DLPI errno 0x%x, UNIX errno %d",
				    dlea.dl_errno, dlea.dl_unix_errno);
			}
			(void) ldi_close(lh, FREAD|FWRITE, kcred);
			continue;
		}

		/*
		 * Currently only DL_ETHER has GLDv3 mac plugin support.
		 * For media types that GLDv3 does not support, create a
		 * link id for it.
		 */
		if ((softmac->smac_media = dlia.dl_mac_type) != DL_ETHER) {
			(void) ldi_close(lh, FREAD|FWRITE, kcred);
			err = 0;
			break;
		}

		if ((dlia.dl_provider_style == DL_STYLE2) &&
		    (dl_attach(lh, softmac->smac_uppa, NULL) != 0)) {
			(void) ldi_close(lh, FREAD|FWRITE, kcred);
			continue;
		}

		if ((rval = dl_bind(lh, 0, NULL)) != 0) {
			if (rval == ENOTSUP) {
				cmn_err(CE_NOTE, "softmac: received "
				    "DL_ERROR_ACK to DL_BIND_ACK; "
				    "DLPI errno 0x%x, UNIX errno %d",
				    dlea.dl_errno, dlea.dl_unix_errno);
			}
			(void) ldi_close(lh, FREAD|FWRITE, kcred);
			continue;
		}

		/*
		 * Call dl_info() after dl_bind() because some drivers only
		 * provide correct information (e.g. MAC address) once bound.
		 */
		softmac->smac_addrlen = sizeof (softmac->smac_unicst_addr);
		if ((rval = dl_info(lh, &dlia, softmac->smac_unicst_addr,
		    &softmac->smac_addrlen, &dlea)) != 0) {
			if (rval == ENOTSUP) {
				cmn_err(CE_NOTE, "softmac: received "
				    "DL_ERROR_ACK to DL_INFO_ACK; "
				    "DLPI errno 0x%x, UNIX errno %d",
				    dlea.dl_errno, dlea.dl_unix_errno);
			}
			(void) ldi_close(lh, FREAD|FWRITE, kcred);
			continue;
		}

		softmac->smac_style = dlia.dl_provider_style;
		softmac->smac_saplen = ABS(dlia.dl_sap_length);
		softmac->smac_min_sdu = dlia.dl_min_sdu;
		softmac->smac_max_sdu = dlia.dl_max_sdu;

		if ((softmac->smac_saplen != sizeof (uint16_t)) ||
		    (softmac->smac_addrlen != ETHERADDRL) ||
		    (dlia.dl_brdcst_addr_length != ETHERADDRL) ||
		    (dlia.dl_brdcst_addr_offset == 0)) {
			(void) ldi_close(lh, FREAD|FWRITE, kcred);
			continue;
		}

		/*
		 * Check other DLPI capabilities. Note that this must be after
		 * dl_bind() because some drivers return DL_ERROR_ACK if the
		 * stream is not bound. It is also before mac_register(), so
		 * we don't need any lock protection here.
		 *
		 * Softmac always supports POLL.
		 */
		softmac->smac_capab_flags =
		    (MAC_CAPAB_POLL | MAC_CAPAB_NO_ZCOPY | MAC_CAPAB_LEGACY);

		softmac->smac_no_capability_req = B_FALSE;
		if (softmac_fill_capab(lh, softmac) != 0)
			softmac->smac_no_capability_req = B_TRUE;

		/*
		 * Check the margin of the underlying driver.
		 */
		margin = 0;
		iocb.ic_cmd = DLIOCMARGININFO;
		iocb.ic_timout = INFTIM;
		iocb.ic_len = sizeof (margin);
		iocb.ic_dp = (char *)&margin;
		softmac->smac_margin = 0;

		if (ldi_ioctl(lh, I_STR, (intptr_t)&iocb, FKIOCTL, kcred,
		    &rval) == 0) {
			softmac->smac_margin = margin;
		}

		/*
		 * If the legacy driver doesn't support DLIOCMARGININFO, but
		 * it can support native VLAN, correct its margin value to 4.
		 */
		if (native_vlan) {
			if (softmac->smac_margin == 0)
				softmac->smac_margin = VLAN_TAGSZ;
		} else {
			softmac->smac_capab_flags |= MAC_CAPAB_NO_NATIVEVLAN;
		}

		/*
		 * Not all drivers support DL_NOTIFY_REQ, so ignore ENOTSUP.
		 */
		softmac->smac_notifications = 0;
		notes = DL_NOTE_PHYS_ADDR | DL_NOTE_LINK_UP | DL_NOTE_LINK_DOWN;
		switch (dl_notify(lh, &notes, NULL)) {
		case 0:
			softmac->smac_notifications = notes;
			break;
		case ENOTSUP:
			break;
		default:
			(void) ldi_close(lh, FREAD|FWRITE, kcred);
			continue;
		}

		(void) ldi_close(lh, FREAD|FWRITE, kcred);
		err = 0;
		break;
	}
	ldi_ident_release(li);

	mutex_enter(&softmac->smac_mutex);

	if (err != 0)
		goto done;

	if (softmac->smac_media != DL_ETHER)
		softmac->smac_flags |= SOFTMAC_NOSUPP;

	/*
	 * Finally, we're ready to register ourselves with the MAC layer
	 * interface; if this succeeds, we're all ready to start()
	 */
	if (!(softmac->smac_flags & SOFTMAC_NOSUPP)) {
		mac_register_t	*macp;

		if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
			err = ENOMEM;
			goto done;
		}

		macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
		macp->m_driver = softmac;
		macp->m_dip = softmac_dip;

		macp->m_margin = softmac->smac_margin;
		macp->m_src_addr = softmac->smac_unicst_addr;
		macp->m_min_sdu = softmac->smac_min_sdu;
		macp->m_max_sdu = softmac->smac_max_sdu;
		macp->m_callbacks = &softmac_m_callbacks;
		macp->m_instance = (uint_t)-1;

		err = mac_register(macp, &softmac->smac_mh);
		mac_free(macp);
		if (err != 0) {
			cmn_err(CE_WARN, "mac_register failed for %s",
			    softmac->smac_devname);
			goto done;
		}
	}

	/*
	 * Try to create the datalink for this softmac.
	 */
	if ((err = softmac_create_datalink(softmac)) != 0) {
		if (!(softmac->smac_flags & SOFTMAC_NOSUPP)) {
			(void) mac_unregister(softmac->smac_mh);
			softmac->smac_mh = NULL;
		}
	}

done:
	ASSERT(!(softmac->smac_flags & SOFTMAC_ATTACH_DONE));
	softmac->smac_flags |= SOFTMAC_ATTACH_DONE;
	softmac->smac_attacherr = err;
	softmac->smac_taskq = NULL;
	cv_broadcast(&softmac->smac_cv);
	mutex_exit(&softmac->smac_mutex);
}

int
softmac_destroy(dev_info_t *dip, dev_t dev)
{
	char			devname[MAXNAMELEN];
	softmac_t		*softmac;
	softmac_dev_t		*softmac_dev;
	int			index;
	int			ppa, err;
	datalink_id_t		linkid;

	ppa = ddi_get_instance(dip);
	(void) snprintf(devname, MAXNAMELEN, "%s%d", ddi_driver_name(dip), ppa);

	rw_enter(&softmac_hash_lock, RW_WRITER);
	err = mod_hash_find(softmac_hash, (mod_hash_key_t)devname,
	    (mod_hash_val_t *)&softmac);
	ASSERT(err == 0);

	mutex_enter(&softmac->smac_mutex);

	/*
	 * Fail the predetach routine if this softmac is in-use.
	 */
	if (softmac->smac_hold_cnt != 0) {
		softmac->smac_attached_left = softmac->smac_attachok_cnt;
		mutex_exit(&softmac->smac_mutex);
		rw_exit(&softmac_hash_lock);
		return (EBUSY);
	}

	/*
	 * Even if the predetach of one minor node has already failed
	 * (smac_attached_left is not 0), the DACF framework will continue
	 * to call the predetach routines of the other minor nodes,
	 * so we fail these calls here.
	 */
	if (softmac->smac_attached_left != 0) {
		mutex_exit(&softmac->smac_mutex);
		rw_exit(&softmac_hash_lock);
		return (EBUSY);
	}

	if (softmac->smac_attachok_cnt != softmac->smac_cnt)
		goto done;

	/*
	 * This is the detach for the first minor node.  Wait until all the
	 * minor nodes are attached.
	 */
	while (!(softmac->smac_flags & SOFTMAC_ATTACH_DONE))
		cv_wait(&softmac->smac_cv, &softmac->smac_mutex);

	if (softmac->smac_mh != NULL) {
		if (!(softmac->smac_flags & SOFTMAC_NOSUPP)) {
			if ((err = dls_devnet_destroy(softmac->smac_mh,
			    &linkid)) != 0) {
				goto done;
			}
		}
		/*
		 * If softmac_mac_register() succeeds in registering the mac
		 * of the legacy device, unregister it.
		 */
		if (!(softmac->smac_flags & (SOFTMAC_GLDV3 | SOFTMAC_NOSUPP))) {
			if ((err = mac_unregister(softmac->smac_mh)) != 0) {
				(void) dls_devnet_create(softmac->smac_mh,
				    linkid);
				goto done;
			}
		}
		softmac->smac_mh = NULL;
	}
	softmac->smac_flags &= ~SOFTMAC_ATTACH_DONE;

done:
	if (err == 0) {
		/*
		 * Free softmac_dev
		 */
		index = (getmajor(dev) == ddi_name_to_major("clone"));
		softmac_dev = softmac->smac_softmac[index];
		ASSERT(softmac_dev != NULL);
		softmac->smac_softmac[index] = NULL;
		kmem_free(softmac_dev, sizeof (softmac_dev_t));

		if (--softmac->smac_attachok_cnt == 0) {
			mod_hash_val_t	hashval;

			err = mod_hash_remove(softmac_hash,
			    (mod_hash_key_t)devname,
			    (mod_hash_val_t *)&hashval);
			ASSERT(err == 0);

			mutex_exit(&softmac->smac_mutex);
			rw_exit(&softmac_hash_lock);

			ASSERT(softmac->smac_taskq == NULL);
			ASSERT(!(softmac->smac_flags & SOFTMAC_ATTACH_DONE));
			mutex_destroy(&softmac->smac_mutex);
			cv_destroy(&softmac->smac_cv);
			rw_destroy(&softmac->smac_lock);
			kmem_free(softmac, sizeof (softmac_t));
			return (0);
		}
	} else {
		softmac->smac_attached_left = softmac->smac_attachok_cnt;
	}

	mutex_exit(&softmac->smac_mutex);
	rw_exit(&softmac_hash_lock);
	return (err);
}

/*
 * This function is called as the result of a newly started dlmgmtd daemon.
 *
 * We walk through every softmac that was created but failed to notify
 * dlmgmtd about it (whose SOFTMAC_NEED_RECREATE flag is set).  This occurs
 * when softmacs are created before dlmgmtd is ready.  For example, during
 * diskless boot, a network device is used (and therefore attached) before
 * the datalink-management service starts dlmgmtd.
 */
/* ARGSUSED */
static uint_t
softmac_mac_recreate(mod_hash_key_t key, mod_hash_val_t *val, void *arg)
{
	softmac_t	*softmac = (softmac_t *)val;
	datalink_id_t	linkid;
	int		err;

	ASSERT(RW_READ_HELD(&softmac_hash_lock));

	/*
	 * Wait for softmac_create() and softmac_mac_register() to exit.
	 */
	mutex_enter(&softmac->smac_mutex);
	while (!(softmac->smac_flags & SOFTMAC_ATTACH_DONE))
		cv_wait(&softmac->smac_cv, &softmac->smac_mutex);

	if ((softmac->smac_attacherr != 0) ||
	    !(softmac->smac_flags & SOFTMAC_NEED_RECREATE)) {
		mutex_exit(&softmac->smac_mutex);
		return (MH_WALK_CONTINUE);
	}

	if (dls_mgmt_create(softmac->smac_devname,
	    makedevice(softmac->smac_umajor, softmac->smac_uppa + 1),
	    DATALINK_CLASS_PHYS, softmac->smac_media, B_TRUE, &linkid) != 0) {
		mutex_exit(&softmac->smac_mutex);
		return (MH_WALK_CONTINUE);
	}

	if ((err = softmac_update_info(softmac, &linkid)) != 0) {
		cmn_err(CE_WARN, "softmac: softmac_update_info() for %s "
		    "failed (%d)", softmac->smac_devname, err);
		mutex_exit(&softmac->smac_mutex);
		return (MH_WALK_CONTINUE);
	}

	/*
	 * Create a link for this MAC. The link name will be the same
	 * as the MAC name.
	 */
	if (!(softmac->smac_flags & SOFTMAC_NOSUPP)) {
		err = dls_devnet_recreate(softmac->smac_mh, linkid);
		if (err != 0) {
			cmn_err(CE_WARN, "softmac: dls_devnet_recreate() for "
			    "%s (linkid %d) failed (%d)",
			    softmac->smac_devname, linkid, err);
		}
	}

	softmac->smac_flags &= ~SOFTMAC_NEED_RECREATE;
	mutex_exit(&softmac->smac_mutex);

	return (MH_WALK_CONTINUE);
}

/*
 * See comments above softmac_mac_recreate().
 */
void
softmac_recreate()
{
	/*
	 * Walk through the softmac_hash table. Request to create the
	 * [link name, linkid] mapping if we failed to do so.
	 */
	rw_enter(&softmac_hash_lock, RW_READER);
	mod_hash_walk(softmac_hash, softmac_mac_recreate, NULL);
	rw_exit(&softmac_hash_lock);
}

/* ARGSUSED */
static int
softmac_m_start(void *arg)
{
	return (0);
}

/* ARGSUSED */
static void
softmac_m_stop(void *arg)
{
}

/*
 * Set up the lower stream above the legacy device which is shared by
 * GLDv3 MAC clients. Put the lower stream into DLIOCRAW mode to send
 * and receive the raw data. Further, put the lower stream into
 * DL_PROMISC_SAP mode to receive all packets of interest.
 */
static int
softmac_lower_setup(softmac_t *softmac, softmac_lower_t **slpp)
{
	ldi_ident_t		li;
	dev_t			dev;
	ldi_handle_t		lh = NULL;
	softmac_lower_t		*slp = NULL;
	smac_ioc_start_t	start_arg;
	struct strioctl		strioc;
	uint32_t		notifications;
	int			err, rval;

	if ((err = ldi_ident_from_dip(softmac_dip, &li)) != 0)
		return (err);

	dev = softmac->smac_dev;
	err = ldi_open_by_dev(&dev, OTYP_CHR, FREAD|FWRITE, kcred, &lh, li);
	ldi_ident_release(li);
	if (err != 0)
		goto done;

	/*
	 * Pop all the intermediate modules. The autopushed modules will
	 * be pushed when the softmac node is opened.
	 */
	while (ldi_ioctl(lh, I_POP, 0, FKIOCTL, kcred, &rval) == 0)
		;

	if ((softmac->smac_style == DL_STYLE2) &&
	    ((err = dl_attach(lh, softmac->smac_uppa, NULL)) != 0)) {
		goto done;
	}

	/*
	 * Put the lower stream into DLIOCRAW mode to send/receive raw data.
	 */
	if ((err = ldi_ioctl(lh, DLIOCRAW, 0, FKIOCTL, kcred, &rval)) != 0)
		goto done;

	/*
	 * Then push the softmac shim layer atop the lower stream.
	 */
	if ((err = ldi_ioctl(lh, I_PUSH, (intptr_t)SOFTMAC_DEV_NAME, FKIOCTL,
	    kcred, &rval)) != 0) {
		goto done;
	}

	/*
	 * Send the ioctl to get the slp pointer.
	 */
	strioc.ic_cmd = SMAC_IOC_START;
	strioc.ic_timout = INFTIM;
	strioc.ic_len = sizeof (start_arg);
	strioc.ic_dp = (char *)&start_arg;

	if ((err = ldi_ioctl(lh, I_STR, (intptr_t)&strioc, FKIOCTL,
	    kcred, &rval)) != 0) {
		goto done;
	}
	slp = start_arg.si_slp;
	slp->sl_lh = lh;
	slp->sl_softmac = softmac;
	*slpp = slp;

	/*
	 * Bind to SAP 2 on token ring, 0 on other interface types.
	 * (SAP 0 has special significance on token ring).
	 * Note that the receive-side packets could come anytime after bind.
	 */
	if (softmac->smac_media == DL_TPR)
		err = softmac_send_bind_req(slp, 2);
	else
		err = softmac_send_bind_req(slp, 0);
	if (err != 0)
		goto done;

	/*
	 * Put the lower stream into DL_PROMISC_SAP mode to receive all
	 * packets of interest.
	 *
	 * Some drivers (e.g. the old legacy eri driver) incorrectly pass up
	 * packets to DL_PROMISC_SAP stream when the lower stream is not bound,
	 * so we send DL_PROMISON_REQ after DL_BIND_REQ.
	 */
	if ((err = softmac_send_promisc_req(slp, DL_PROMISC_SAP, B_TRUE)) != 0)
		goto done;

	/*
	 * Enable the capabilities the underlying driver claims to support.
	 * Some drivers require this to be called after the stream is bound.
	 */
	if ((err = softmac_capab_enable(slp)) != 0)
		goto done;

	/*
	 * Send the DL_NOTIFY_REQ to enable certain DL_NOTIFY_IND.
	 * We don't have to wait for the ack.
	 */
	notifications = DL_NOTE_PHYS_ADDR | DL_NOTE_LINK_UP |
	    DL_NOTE_LINK_DOWN | DL_NOTE_PROMISC_ON_PHYS |
	    DL_NOTE_PROMISC_OFF_PHYS;

	(void) softmac_send_notify_req(slp,
	    (notifications & softmac->smac_notifications));

done:
	if (err != 0)
		(void) ldi_close(lh, FREAD|FWRITE, kcred);
	return (err);
}

static int
softmac_m_open(void *arg)
{
	softmac_t	*softmac = arg;
	softmac_lower_t	*slp;
	int		err;

	rw_enter(&softmac->smac_lock, RW_READER);
	if (softmac->smac_state == SOFTMAC_READY)
		goto done;
	rw_exit(&softmac->smac_lock);

	if ((err = softmac_lower_setup(softmac, &slp)) != 0)
		return (err);

	rw_enter(&softmac->smac_lock, RW_WRITER);
	ASSERT(softmac->smac_state == SOFTMAC_INITIALIZED);
	softmac->smac_lower = slp;
	softmac->smac_state = SOFTMAC_READY;
done:
	rw_exit(&softmac->smac_lock);
	return (0);
}

static void
softmac_m_close(void *arg)
{
	softmac_t	*softmac = arg;
	softmac_lower_t	*slp;

	rw_enter(&softmac->smac_lock, RW_WRITER);
	slp = softmac->smac_lower;
	ASSERT(slp != NULL);

	/*
	 * Note that slp is destroyed when lh is closed.
	 */
	(void) ldi_close(slp->sl_lh, FREAD|FWRITE, kcred);
	softmac->smac_state = SOFTMAC_INITIALIZED;
	softmac->smac_lower = NULL;
	rw_exit(&softmac->smac_lock);
}

int
softmac_hold_device(dev_t dev, dls_dev_handle_t *ddhp)
{
	dev_info_t	*dip;
	const char	*drvname;
	char		devname[MAXNAMELEN];
	softmac_t	*softmac;
	int		ppa, err;

	if ((ppa = getminor(dev) - 1) > 1000)
		return (ENOENT);

	/*
	 * First try to hold this device instance to force the MAC
	 * to be registered.
	 */
	if ((dip = ddi_hold_devi_by_instance(getmajor(dev), ppa, 0)) == NULL)
		return (ENOENT);

	drvname = ddi_driver_name(dip);

	/*
	 * Exclude non-physical network device instances, for example, aggr0.
	 */
	if ((ddi_driver_major(dip) != getmajor(dev)) ||
	    !NETWORK_DRV(getmajor(dev)) || (strcmp(drvname, "aggr") == 0) ||
	    (strcmp(drvname, "vnic") == 0)) {
		ddi_release_devi(dip);
		return (ENOENT);
	}

	/*
	 * This is a network device; wait for its softmac to be registered.
	 */
	(void) snprintf(devname, MAXNAMELEN, "%s%d", drvname, ppa);
again:
	rw_enter(&softmac_hash_lock, RW_READER);

	if (mod_hash_find(softmac_hash, (mod_hash_key_t)devname,
	    (mod_hash_val_t *)&softmac) != 0) {
		/*
		 * This is rare but possible. It could happen when pre-detach
		 * routine of the device succeeds. But the softmac will then
		 * be recreated when device fails to detach (as this device
		 * is held).
		 */
		rw_exit(&softmac_hash_lock);
		goto again;
	}

	/*
	 * Bump smac_hold_cnt to prevent device detach.
	 */
	mutex_enter(&softmac->smac_mutex);
	softmac->smac_hold_cnt++;
	mutex_exit(&softmac->smac_mutex);

	rw_exit(&softmac_hash_lock);

	/*
	 * Wait till the device is fully attached.
	 */
	mutex_enter(&softmac->smac_mutex);
	while (!(softmac->smac_flags & SOFTMAC_ATTACH_DONE))
		cv_wait(&softmac->smac_cv, &softmac->smac_mutex);

	if ((err = softmac->smac_attacherr) != 0)
		softmac->smac_hold_cnt--;
	else
		*ddhp = (dls_dev_handle_t)softmac;
	mutex_exit(&softmac->smac_mutex);

	ddi_release_devi(dip);
	return (err);
}

void
softmac_rele_device(dls_dev_handle_t ddh)
{
	softmac_t	*softmac;

	if (ddh == NULL)
		return;

	softmac = (softmac_t *)ddh;
	mutex_enter(&softmac->smac_mutex);
	softmac->smac_hold_cnt--;
	mutex_exit(&softmac->smac_mutex);
}
