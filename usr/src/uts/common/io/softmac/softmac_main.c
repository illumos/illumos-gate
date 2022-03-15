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
#include <sys/mac_provider.h>
#include <sys/disp.h>
#include <sys/sunndi.h>
#include <sys/modhash.h>
#include <sys/stropts.h>
#include <sys/sysmacros.h>
#include <sys/vlan.h>
#include <sys/softmac_impl.h>
#include <sys/softmac.h>
#include <sys/dls.h>

/* Used as a parameter to the mod hash walk of softmac structures */
typedef struct {
	softmac_t	*smw_softmac;
	boolean_t	smw_retry;
} softmac_walk_t;

/*
 * Softmac hash table including softmacs for both style-2 and style-1 devices.
 */
static krwlock_t	softmac_hash_lock;
static mod_hash_t	*softmac_hash;
static kmutex_t		smac_global_lock;
static kcondvar_t	smac_global_cv;

static kmem_cache_t	*softmac_cachep;

#define	SOFTMAC_HASHSZ		64

static void softmac_create_task(void *);
static void softmac_mac_register(softmac_t *);
static int softmac_create_datalink(softmac_t *);
static int softmac_m_start(void *);
static void softmac_m_stop(void *);
static int softmac_m_open(void *);
static void softmac_m_close(void *);
static boolean_t softmac_m_getcapab(void *, mac_capab_t, void *);
static int softmac_m_setprop(void *, const char *, mac_prop_id_t,
    uint_t, const void *);
static int softmac_m_getprop(void *, const char *, mac_prop_id_t,
    uint_t, void *);
static void softmac_m_propinfo(void *, const char *, mac_prop_id_t,
    mac_prop_info_handle_t);

#define	SOFTMAC_M_CALLBACK_FLAGS	\
	(MC_IOCTL | MC_GETCAPAB | MC_OPEN | MC_CLOSE | MC_SETPROP | \
	MC_GETPROP | MC_PROPINFO)

static mac_callbacks_t softmac_m_callbacks = {
	SOFTMAC_M_CALLBACK_FLAGS,
	softmac_m_stat,
	softmac_m_start,
	softmac_m_stop,
	softmac_m_promisc,
	softmac_m_multicst,
	softmac_m_unicst,
	softmac_m_tx,
	NULL,
	softmac_m_ioctl,
	softmac_m_getcapab,
	softmac_m_open,
	softmac_m_close,
	softmac_m_setprop,
	softmac_m_getprop,
	softmac_m_propinfo
};

/*ARGSUSED*/
static int
softmac_constructor(void *buf, void *arg, int kmflag)
{
	softmac_t	*softmac = buf;

	bzero(buf, sizeof (softmac_t));
	mutex_init(&softmac->smac_mutex, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&softmac->smac_active_mutex, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&softmac->smac_fp_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&softmac->smac_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&softmac->smac_fp_cv, NULL, CV_DEFAULT, NULL);
	list_create(&softmac->smac_sup_list, sizeof (softmac_upper_t),
	    offsetof(softmac_upper_t, su_list_node));
	return (0);
}

/*ARGSUSED*/
static void
softmac_destructor(void *buf, void *arg)
{
	softmac_t	*softmac = buf;

	ASSERT(softmac->smac_fp_disable_clients == 0);
	ASSERT(!softmac->smac_fastpath_admin_disabled);

	ASSERT(!(softmac->smac_flags & SOFTMAC_ATTACH_DONE));
	ASSERT(softmac->smac_hold_cnt == 0);
	ASSERT(softmac->smac_attachok_cnt == 0);
	ASSERT(softmac->smac_mh == NULL);
	ASSERT(softmac->smac_softmac[0] == NULL &&
	    softmac->smac_softmac[1] == NULL);
	ASSERT(softmac->smac_lower == NULL);
	ASSERT(softmac->smac_active == B_FALSE);
	ASSERT(softmac->smac_nactive == 0);
	ASSERT(list_is_empty(&softmac->smac_sup_list));

	list_destroy(&softmac->smac_sup_list);
	mutex_destroy(&softmac->smac_mutex);
	mutex_destroy(&softmac->smac_active_mutex);
	mutex_destroy(&softmac->smac_fp_mutex);
	cv_destroy(&softmac->smac_cv);
	cv_destroy(&softmac->smac_fp_cv);
}

void
softmac_init()
{
	softmac_hash = mod_hash_create_extended("softmac_hash",
	    SOFTMAC_HASHSZ, mod_hash_null_keydtor, mod_hash_null_valdtor,
	    mod_hash_bystr, NULL, mod_hash_strkey_cmp, KM_SLEEP);

	rw_init(&softmac_hash_lock, NULL, RW_DEFAULT, NULL);
	mutex_init(&smac_global_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&smac_global_cv, NULL, CV_DRIVER, NULL);

	softmac_cachep = kmem_cache_create("softmac_cache",
	    sizeof (softmac_t), 0, softmac_constructor,
	    softmac_destructor, NULL, NULL, NULL, 0);
	ASSERT(softmac_cachep != NULL);
	softmac_fp_init();
}

void
softmac_fini()
{
	softmac_fp_fini();
	kmem_cache_destroy(softmac_cachep);
	rw_destroy(&softmac_hash_lock);
	mod_hash_destroy_hash(softmac_hash);
	mutex_destroy(&smac_global_lock);
	cv_destroy(&smac_global_cv);
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
 *
 * softmac_create() is called for each minor node during the post-attach of
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
 *
 *			softmac state machine
 * --------------------------------------------------------------------------
 * OLD STATE		EVENT					NEW STATE
 * --------------------------------------------------------------------------
 * UNINIT		attach of 1st minor node 		ATTACH_INPROG
 * okcnt = 0		net_postattach -> softmac_create	okcnt = 1
 *
 * ATTACH_INPROG	attach of 2nd minor node (GLDv3)	ATTACH_DONE
 * okcnt = 1		net_postattach -> softmac_create	okcnt = 2
 *
 * ATTACH_INPROG	attach of 2nd minor node (legacy)	ATTACH_INPROG
 * okcnt = 1		net_postattach -> softmac_create	okcnt = 2
 *			schedule softmac_mac_register
 *
 * ATTACH_INPROG	legacy device node			ATTACH_DONE
 * okcnt = 2		softmac_mac_register			okcnt = 2
 *
 * ATTACH_DONE		detach of 1st minor node		DETACH_INPROG
 * okcnt = 2		(success)				okcnt = 1
 *
 * DETACH_INPROG	detach of 2nd minor node		UNINIT (or free)
 * okcnt = 1		(success)				okcnt = 0
 *
 * ATTACH_DONE		detach failure				state unchanged
 * DETACH_INPROG						left = okcnt
 *
 * DETACH_INPROG	reattach				ATTACH_INPROG
 * okcnt = 0,1		net_postattach -> softmac_create
 *
 * ATTACH_DONE		reattach				ATTACH_DONE
 * left != 0		net_postattach -> softmac_create	left = 0
 *
 * Abbreviation notes:
 * states have SOFTMAC_ prefix,
 * okcnt - softmac_attach_okcnt,
 * left - softmac_attached_left
 */

#ifdef DEBUG
void
softmac_state_verify(softmac_t *softmac)
{
	ASSERT(MUTEX_HELD(&softmac->smac_mutex));

	/*
	 * There are at most 2 minor nodes, one per DLPI style
	 */
	ASSERT(softmac->smac_cnt <= 2 && softmac->smac_attachok_cnt <= 2);

	/*
	 * The smac_attachok_cnt represents the number of attaches i.e. the
	 * number of times net_postattach -> softmac_create() has been called
	 * for a device instance.
	 */
	ASSERT(softmac->smac_attachok_cnt == SMAC_NONZERO_NODECNT(softmac));

	/*
	 * softmac_create (or softmac_mac_register) ->  softmac_create_datalink
	 * happens only after all minor nodes have been attached
	 */
	ASSERT(softmac->smac_state != SOFTMAC_ATTACH_DONE ||
	    softmac->smac_attachok_cnt == softmac->smac_cnt);

	if (softmac->smac_attachok_cnt == 0) {
		ASSERT(softmac->smac_state == SOFTMAC_UNINIT);
		ASSERT(softmac->smac_mh == NULL);
	} else if (softmac->smac_attachok_cnt < softmac->smac_cnt) {
		ASSERT(softmac->smac_state == SOFTMAC_ATTACH_INPROG ||
		    softmac->smac_state == SOFTMAC_DETACH_INPROG);
		ASSERT(softmac->smac_mh == NULL);
	} else {
		/*
		 * In the stable condition the state whould be
		 * SOFTMAC_ATTACH_DONE. But there is a small transient window
		 * in softmac_destroy where we change the state to
		 * SOFTMAC_DETACH_INPROG and drop the lock before doing
		 * the link destroy
		 */
		ASSERT(softmac->smac_attachok_cnt == softmac->smac_cnt);
		ASSERT(softmac->smac_state != SOFTMAC_UNINIT);
	}
	if (softmac->smac_mh != NULL)
		ASSERT(softmac->smac_attachok_cnt == softmac->smac_cnt);
}
#endif

#ifdef DEBUG
#define	SOFTMAC_STATE_VERIFY(softmac)	softmac_state_verify(softmac)
#else
#define	SOFTMAC_STATE_VERIFY(softmac)
#endif

int
softmac_create(dev_info_t *dip, dev_t dev)
{
	char		devname[MAXNAMELEN];
	softmac_t	*softmac;
	softmac_dev_t	*softmac_dev = NULL;
	int		index;
	int		ppa, err = 0;

	/*
	 * Force the softmac driver to be attached.
	 */
	if (i_ddi_attach_pseudo_node(SOFTMAC_DEV_NAME) == NULL) {
		cmn_err(CE_WARN, "softmac_create:softmac attach fails");
		return (ENXIO);
	}

	if (GLDV3_DRV(ddi_driver_major(dip))) {
		minor_t minor = getminor(dev);
		/*
		 * For GLDv3, we don't care about the DLPI style 2
		 * compatibility node.  (We know that all such devices
		 * have style 1 nodes.)
		 */
		if ((strcmp(ddi_driver_name(dip), "clone") == 0) ||
		    (getmajor(dev) == ddi_name_to_major("clone")) ||
		    (minor == 0)) {
			return (0);
		}

		/*
		 * Likewise, we know that the minor number for DLPI style 1
		 * nodes is constrained to a maximum value.
		 */
		if (minor >= DLS_MAX_MINOR) {
			return (ENOTSUP);
		}
		/*
		 * Otherwise we can decode the instance from the minor number,
		 * which allows for situations with multiple mac instances
		 * for a single dev_info_t.
		 */
		ppa = DLS_MINOR2INST(minor);
	} else {
		/*
		 * For legacy drivers, we just have to limit them to
		 * two minor nodes, one style 1 and one style 2, and
		 * we assume the ddi_get_instance() is the PPA.
		 * Drivers that need more flexibility should be ported
		 * to GLDv3.
		 */
		ppa = ddi_get_instance(dip);
		if (i_ddi_minor_node_count(dip, DDI_NT_NET) > 2) {
			cmn_err(CE_WARN, "%s has more than 2 minor nodes; "
			    "unsupported", devname);
			return (ENOTSUP);
		}
	}

	(void) snprintf(devname, MAXNAMELEN, "%s%d", ddi_driver_name(dip), ppa);

	/*
	 * Check whether the softmac for the specified device already exists
	 */
	rw_enter(&softmac_hash_lock, RW_WRITER);
	if ((mod_hash_find(softmac_hash, (mod_hash_key_t)devname,
	    (mod_hash_val_t *)&softmac)) != 0) {

		softmac = kmem_cache_alloc(softmac_cachep, KM_SLEEP);
		(void) strlcpy(softmac->smac_devname, devname, MAXNAMELEN);

		err = mod_hash_insert(softmac_hash,
		    (mod_hash_key_t)softmac->smac_devname,
		    (mod_hash_val_t)softmac);
		ASSERT(err == 0);
		mutex_enter(&smac_global_lock);
		cv_broadcast(&smac_global_cv);
		mutex_exit(&smac_global_lock);
	}

	mutex_enter(&softmac->smac_mutex);
	SOFTMAC_STATE_VERIFY(softmac);
	if (softmac->smac_state != SOFTMAC_ATTACH_DONE)
		softmac->smac_state = SOFTMAC_ATTACH_INPROG;
	if (softmac->smac_attachok_cnt == 0) {
		/*
		 * Initialize the softmac if this is the post-attach of the
		 * first minor node.
		 */
		softmac->smac_flags = 0;
		softmac->smac_umajor = ddi_driver_major(dip);
		softmac->smac_uppa = ppa;

		/*
		 * For GLDv3, we ignore the style 2 node (see the logic
		 * above on that), and we should have exactly one attach
		 * per MAC instance (possibly more than one per dev_info_t).
		 */
		if (GLDV3_DRV(ddi_driver_major(dip))) {
			softmac->smac_flags |= SOFTMAC_GLDV3;
			softmac->smac_cnt = 1;
		} else {
			softmac->smac_cnt =
			    i_ddi_minor_node_count(dip, DDI_NT_NET);
		}
	}

	index = (getmajor(dev) == ddi_name_to_major("clone"));
	if (softmac->smac_softmac[index] != NULL) {
		/*
		 * This is possible if the post_attach() is called after
		 * pre_detach() fails. This seems to be a defect of the DACF
		 * framework. We work around it by using a smac_attached_left
		 * field that tracks this
		 */
		ASSERT(softmac->smac_attached_left != 0);
		softmac->smac_attached_left--;
		mutex_exit(&softmac->smac_mutex);
		rw_exit(&softmac_hash_lock);
		return (0);

	}
	mutex_exit(&softmac->smac_mutex);
	rw_exit(&softmac_hash_lock);

	softmac_dev = kmem_zalloc(sizeof (softmac_dev_t), KM_SLEEP);
	softmac_dev->sd_dev = dev;

	mutex_enter(&softmac->smac_mutex);
	softmac->smac_softmac[index] = softmac_dev;
	/*
	 * Continue to register the mac and create the datalink only when all
	 * the minor nodes are attached.
	 */
	if (++softmac->smac_attachok_cnt != softmac->smac_cnt) {
		mutex_exit(&softmac->smac_mutex);
		return (0);
	}

	/*
	 * All of the minor nodes have been attached; start a taskq
	 * to do the rest of the work.  We use a taskq instead of
	 * doing the work here because:
	 *
	 * We could be called as a result of a open() system call
	 * where spec_open() already SLOCKED the snode. Using a taskq
	 * sidesteps the risk that our ldi_open_by_dev() call would
	 * deadlock trying to set SLOCKED on the snode again.
	 *
	 * The devfs design requires that the downcalls don't use any
	 * interruptible cv_wait which happens when we do door upcalls.
	 * Otherwise the downcalls which may be holding devfs resources
	 * may cause a deadlock if the thread is stopped. Also we need to make
	 * sure these downcalls into softmac_create or softmac_destroy
	 * don't cv_wait on any devfs related condition. Thus softmac_destroy
	 * returns EBUSY if the asynchronous threads started in softmac_create
	 * haven't finished.
	 */
	(void) taskq_dispatch(system_taskq, softmac_create_task,
	    softmac, TQ_SLEEP);
	mutex_exit(&softmac->smac_mutex);
	return (0);
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

		/*
		 * The caller is not interested in the details.
		 */
		if (legacy == NULL)
			break;

		legacy->ml_unsup_note = ~softmac->smac_notifications &
		    (DL_NOTE_LINK_UP | DL_NOTE_LINK_DOWN | DL_NOTE_SPEED);
		legacy->ml_active_set = softmac_active_set;
		legacy->ml_active_clear = softmac_active_clear;
		legacy->ml_fastpath_disable = softmac_fastpath_disable;
		legacy->ml_fastpath_enable = softmac_fastpath_enable;
		legacy->ml_dev = makedevice(softmac->smac_umajor,
		    softmac->smac_uppa + 1);
		break;
	}

	/*
	 * For the capabilities below, there's nothing for us to fill in;
	 * simply return B_TRUE if we support it.
	 */
	case MAC_CAPAB_NO_ZCOPY:
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
		cmn_err(CE_WARN, "See dladm(8) for more information.");
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

	/*
	 * Inform dlmgmtd of this link so that softmac_hold_device() is able
	 * to know the existence of this link. If this failed with EBADF,
	 * it might be because dlmgmtd was not started in time (e.g.,
	 * diskless boot); ignore the failure and continue to create
	 * the GLDv3 datalink if needed.
	 */
	err = dls_mgmt_create(softmac->smac_devname,
	    makedevice(softmac->smac_umajor, softmac->smac_uppa + 1),
	    DATALINK_CLASS_PHYS, DL_OTHER, B_TRUE, &linkid);
	if (err != 0 && err != EBADF)
		return (err);

	/*
	 * Provide the media type of the physical link to dlmgmtd.
	 */
	if ((err != EBADF) &&
	    ((err = softmac_update_info(softmac, &linkid)) != 0)) {
		return (err);
	}

	/*
	 * Create the GLDv3 datalink.
	 */
	if (!(softmac->smac_flags & SOFTMAC_NOSUPP)) {
		err = dls_devnet_create(softmac->smac_mh, linkid,
		    crgetzoneid(CRED()));
		if (err != 0) {
			cmn_err(CE_WARN, "dls_devnet_create failed for %s",
			    softmac->smac_devname);
			return (err);
		}
	}

	if (linkid == DATALINK_INVALID_LINKID) {
		mutex_enter(&softmac->smac_mutex);
		softmac->smac_flags |= SOFTMAC_NEED_RECREATE;
		mutex_exit(&softmac->smac_mutex);
	}

	return (0);
}

static void
softmac_create_task(void *arg)
{
	softmac_t	*softmac = arg;
	mac_handle_t	mh;
	int		err;

	if (!GLDV3_DRV(softmac->smac_umajor)) {
		softmac_mac_register(softmac);
		return;
	}

	if ((err = mac_open(softmac->smac_devname, &mh)) != 0)
		goto done;

	mutex_enter(&softmac->smac_mutex);
	softmac->smac_media = (mac_info(mh))->mi_nativemedia;
	softmac->smac_mh = mh;
	mutex_exit(&softmac->smac_mutex);

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
	mutex_enter(&softmac->smac_mutex);
	if (err != 0)
		softmac->smac_mh = NULL;
	softmac->smac_attacherr = err;
	softmac->smac_state = SOFTMAC_ATTACH_DONE;
	cv_broadcast(&softmac->smac_cv);
	mutex_exit(&softmac->smac_mutex);
}

/*
 * This function is only called for legacy devices. It:
 * 1. registers the MAC for the legacy devices whose media type is supported
 *    by the GLDv3 framework.
 * 2. creates the GLDv3 datalink if the media type is supported by GLDv3.
 */
static void
softmac_mac_register(softmac_t *softmac)
{
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
	ASSERT(softmac->smac_state == SOFTMAC_ATTACH_INPROG &&
	    softmac->smac_attachok_cnt == softmac->smac_cnt);

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
		 */
		softmac->smac_capab_flags =
		    (MAC_CAPAB_NO_ZCOPY | MAC_CAPAB_LEGACY);

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
	mutex_exit(&softmac->smac_mutex);

	/*
	 * Try to create the datalink for this softmac.
	 */
	if ((err = softmac_create_datalink(softmac)) != 0) {
		if (!(softmac->smac_flags & SOFTMAC_NOSUPP))
			(void) mac_unregister(softmac->smac_mh);
		mutex_enter(&softmac->smac_mutex);
		softmac->smac_mh = NULL;
		goto done;
	}
	/*
	 * If succeed, create the thread which handles the DL_NOTIFY_IND from
	 * the lower stream.
	 */
	mutex_enter(&softmac->smac_mutex);
	if (softmac->smac_mh != NULL) {
		softmac->smac_notify_thread = thread_create(NULL, 0,
		    softmac_notify_thread, softmac, 0, &p0,
		    TS_RUN, minclsyspri);
	}

done:
	ASSERT(softmac->smac_state == SOFTMAC_ATTACH_INPROG &&
	    softmac->smac_attachok_cnt == softmac->smac_cnt);
	softmac->smac_state = SOFTMAC_ATTACH_DONE;
	softmac->smac_attacherr = err;
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
	mac_handle_t		smac_mh;
	uint32_t		smac_flags;

	if (GLDV3_DRV(ddi_driver_major(dip))) {
		minor_t minor = getminor(dev);
		/*
		 * For an explanation of this logic, see the
		 * equivalent code in softmac_create.
		 */
		if ((strcmp(ddi_driver_name(dip), "clone") == 0) ||
		    (getmajor(dev) == ddi_name_to_major("clone")) ||
		    (minor == 0)) {
			return (0);
		}
		if (minor >= DLS_MAX_MINOR) {
			return (ENOTSUP);
		}
		ppa = DLS_MINOR2INST(minor);
	} else {
		ppa = ddi_get_instance(dip);
	}

	(void) snprintf(devname, MAXNAMELEN, "%s%d", ddi_driver_name(dip), ppa);

	/*
	 * We are called only from the predetach entry point. The DACF
	 * framework ensures there can't be a concurrent postattach call
	 * for the same softmac. The softmac found out from the modhash
	 * below can't vanish beneath us since this is the only place where
	 * it is deleted.
	 */
	err = mod_hash_find(softmac_hash, (mod_hash_key_t)devname,
	    (mod_hash_val_t *)&softmac);
	ASSERT(err == 0);

	mutex_enter(&softmac->smac_mutex);
	SOFTMAC_STATE_VERIFY(softmac);

	/*
	 * Fail the predetach routine if this softmac is in-use.
	 * Make sure these downcalls into softmac_create or softmac_destroy
	 * don't cv_wait on any devfs related condition. Thus softmac_destroy
	 * returns EBUSY if the asynchronous thread started in softmac_create
	 * hasn't finished
	 */
	if ((softmac->smac_hold_cnt != 0) ||
	    (softmac->smac_state == SOFTMAC_ATTACH_INPROG)) {
		softmac->smac_attached_left = softmac->smac_attachok_cnt;
		mutex_exit(&softmac->smac_mutex);
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
		return (EBUSY);
	}

	smac_mh = softmac->smac_mh;
	smac_flags = softmac->smac_flags;
	softmac->smac_state = SOFTMAC_DETACH_INPROG;
	mutex_exit(&softmac->smac_mutex);

	if (smac_mh != NULL) {
		/*
		 * This is the first minor node that is being detached for this
		 * softmac.
		 */
		ASSERT(softmac->smac_attachok_cnt == softmac->smac_cnt);
		if (!(smac_flags & SOFTMAC_NOSUPP)) {
			if ((err = dls_devnet_destroy(smac_mh, &linkid,
			    B_FALSE)) != 0) {
				goto error;
			}
		}
		/*
		 * If softmac_mac_register() succeeds in registering the mac
		 * of the legacy device, unregister it.
		 */
		if (!(smac_flags & (SOFTMAC_GLDV3 | SOFTMAC_NOSUPP))) {
			if ((err = mac_disable_nowait(smac_mh)) != 0) {
				(void) dls_devnet_create(smac_mh, linkid,
				    crgetzoneid(CRED()));
				goto error;
			}
			/*
			 * Ask softmac_notify_thread to quit, and wait for
			 * that to be done.
			 */
			mutex_enter(&softmac->smac_mutex);
			softmac->smac_flags |= SOFTMAC_NOTIFY_QUIT;
			cv_broadcast(&softmac->smac_cv);
			while (softmac->smac_notify_thread != NULL) {
				cv_wait(&softmac->smac_cv,
				    &softmac->smac_mutex);
			}
			mutex_exit(&softmac->smac_mutex);
			VERIFY(mac_unregister(smac_mh) == 0);
		}
		softmac->smac_mh = NULL;
	}

	/*
	 * Free softmac_dev
	 */
	rw_enter(&softmac_hash_lock, RW_WRITER);
	mutex_enter(&softmac->smac_mutex);

	ASSERT(softmac->smac_state == SOFTMAC_DETACH_INPROG &&
	    softmac->smac_attachok_cnt != 0);
	softmac->smac_mh = NULL;
	index = (getmajor(dev) == ddi_name_to_major("clone"));
	softmac_dev = softmac->smac_softmac[index];
	ASSERT(softmac_dev != NULL);
	softmac->smac_softmac[index] = NULL;
	kmem_free(softmac_dev, sizeof (softmac_dev_t));

	if (--softmac->smac_attachok_cnt == 0) {
		mod_hash_val_t	hashval;

		softmac->smac_state = SOFTMAC_UNINIT;
		if (softmac->smac_hold_cnt != 0) {
			/*
			 * Someone did a softmac_hold_device while we dropped
			 * the locks. Leave the softmac itself intact which
			 * will be reused by the reattach
			 */
			mutex_exit(&softmac->smac_mutex);
			rw_exit(&softmac_hash_lock);
			return (0);
		}
		err = mod_hash_remove(softmac_hash,
		    (mod_hash_key_t)devname,
		    (mod_hash_val_t *)&hashval);
		ASSERT(err == 0);

		mutex_exit(&softmac->smac_mutex);
		rw_exit(&softmac_hash_lock);
		ASSERT(softmac->smac_fp_disable_clients == 0);
		softmac->smac_fastpath_admin_disabled = B_FALSE;
		kmem_cache_free(softmac_cachep, softmac);
		return (0);
	}
	mutex_exit(&softmac->smac_mutex);
	rw_exit(&softmac_hash_lock);
	return (0);

error:
	mutex_enter(&softmac->smac_mutex);
	softmac->smac_attached_left = softmac->smac_attachok_cnt;
	softmac->smac_state = SOFTMAC_ATTACH_DONE;
	cv_broadcast(&softmac->smac_cv);
	mutex_exit(&softmac->smac_mutex);
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
	softmac_walk_t	*smwp = arg;

	/*
	 * The framework itself must not hold any locks across calls to the
	 * mac perimeter. Thus this function does not call any framework
	 * function that needs to grab the mac perimeter.
	 */
	ASSERT(RW_READ_HELD(&softmac_hash_lock));

	smwp->smw_retry = B_FALSE;
	mutex_enter(&softmac->smac_mutex);
	SOFTMAC_STATE_VERIFY(softmac);
	if (softmac->smac_state == SOFTMAC_ATTACH_INPROG) {
		/*
		 * Wait till softmac_create or softmac_mac_register finishes
		 * Hold the softmac to ensure it stays around. The wait itself
		 * is done in the caller, since we need to drop all locks
		 * including the mod hash's internal lock before calling
		 * cv_wait.
		 */
		smwp->smw_retry = B_TRUE;
		smwp->smw_softmac = softmac;
		softmac->smac_hold_cnt++;
		return (MH_WALK_TERMINATE);
	}

	if ((softmac->smac_state != SOFTMAC_ATTACH_DONE) ||
	    !(softmac->smac_flags & SOFTMAC_NEED_RECREATE)) {
		mutex_exit(&softmac->smac_mutex);
		return (MH_WALK_CONTINUE);
	}

	/*
	 * Bumping up the smac_hold_cnt allows us to drop the lock. It also
	 * makes softmac_destroy() return failure on an attempted device detach.
	 * We don't want to hold the lock across calls to other subsystems
	 * like kstats, which will happen in the call to dls_devnet_recreate
	 */
	softmac->smac_hold_cnt++;
	mutex_exit(&softmac->smac_mutex);

	if (dls_mgmt_create(softmac->smac_devname,
	    makedevice(softmac->smac_umajor, softmac->smac_uppa + 1),
	    DATALINK_CLASS_PHYS, softmac->smac_media, B_TRUE, &linkid) != 0) {
		softmac_rele_device((dls_dev_handle_t)softmac);
		return (MH_WALK_CONTINUE);
	}

	if ((err = softmac_update_info(softmac, &linkid)) != 0) {
		cmn_err(CE_WARN, "softmac: softmac_update_info() for %s "
		    "failed (%d)", softmac->smac_devname, err);
		softmac_rele_device((dls_dev_handle_t)softmac);
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

	mutex_enter(&softmac->smac_mutex);
	softmac->smac_flags &= ~SOFTMAC_NEED_RECREATE;
	ASSERT(softmac->smac_hold_cnt != 0);
	softmac->smac_hold_cnt--;
	mutex_exit(&softmac->smac_mutex);

	return (MH_WALK_CONTINUE);
}

/*
 * See comments above softmac_mac_recreate().
 */
void
softmac_recreate()
{
	softmac_walk_t	smw;
	softmac_t	*softmac;

	/*
	 * Walk through the softmac_hash table. Request to create the
	 * [link name, linkid] mapping if we failed to do so.
	 */
	do {
		smw.smw_retry = B_FALSE;
		rw_enter(&softmac_hash_lock, RW_READER);
		mod_hash_walk(softmac_hash, softmac_mac_recreate, &smw);
		rw_exit(&softmac_hash_lock);
		if (smw.smw_retry) {
			/*
			 * softmac_create or softmac_mac_register hasn't yet
			 * finished and the softmac is not yet in the
			 * SOFTMAC_ATTACH_DONE state.
			 */
			softmac = smw.smw_softmac;
			cv_wait(&softmac->smac_cv, &softmac->smac_mutex);
			softmac->smac_hold_cnt--;
			mutex_exit(&softmac->smac_mutex);
		}
	} while (smw.smw_retry);
}

static int
softmac_m_start(void *arg)
{
	softmac_t	*softmac = arg;
	softmac_lower_t	*slp = softmac->smac_lower;
	int		err;

	ASSERT(MAC_PERIM_HELD(softmac->smac_mh));
	/*
	 * Bind to SAP 2 on token ring, 0 on other interface types.
	 * (SAP 0 has special significance on token ring).
	 * Note that the receive-side packets could come anytime after bind.
	 */
	err = softmac_send_bind_req(slp, softmac->smac_media == DL_TPR ? 2 : 0);
	if (err != 0)
		return (err);

	/*
	 * Put the lower stream to the DL_PROMISC_SAP mode in order to receive
	 * all packets of interest.
	 *
	 * some driver (e.g. the old legacy eri driver) incorrectly passes up
	 * packets to DL_PROMISC_SAP stream when the lower stream is not bound,
	 * so that we send DL_PROMISON_REQ after DL_BIND_REQ.
	 */
	err = softmac_send_promisc_req(slp, DL_PROMISC_SAP, B_TRUE);
	if (err != 0) {
		(void) softmac_send_unbind_req(slp);
		return (err);
	}

	/*
	 * Enable capabilities the underlying driver claims to support.
	 * Some driver requires this being called after the stream is bound.
	 */
	if ((err = softmac_capab_enable(slp)) != 0) {
		(void) softmac_send_promisc_req(slp, DL_PROMISC_SAP, B_FALSE);
		(void) softmac_send_unbind_req(slp);
	}

	return (err);
}

/* ARGSUSED */
static void
softmac_m_stop(void *arg)
{
	softmac_t	*softmac = arg;
	softmac_lower_t	*slp = softmac->smac_lower;

	ASSERT(MAC_PERIM_HELD(softmac->smac_mh));

	/*
	 * It is not needed to reset zerocopy, MDT or HCKSUM capabilities.
	 */
	(void) softmac_send_promisc_req(slp, DL_PROMISC_SAP, B_FALSE);
	(void) softmac_send_unbind_req(slp);
}

/*
 * Set up the lower stream above the legacy device. There are two different
 * type of lower streams:
 *
 * - Shared lower-stream
 *
 * Shared by all GLDv3 MAC clients. Put the lower stream to the DLIOCRAW
 * mode to send and receive the raw data. Further, put the lower stream into
 * DL_PROMISC_SAP mode to receive all packets of interest.
 *
 * - Dedicated lower-stream
 *
 * The lower-stream which is dedicated to upper IP/ARP stream. This is used
 * as fast-path for IP. In this case, the second argument is the pointer to
 * the softmac upper-stream.
 */
int
softmac_lower_setup(softmac_t *softmac, softmac_upper_t *sup,
    softmac_lower_t **slpp)
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

	/*
	 * The GLDv3 framework makes sure that mac_unregister(), mac_open(),
	 * and mac_close() cannot be called at the same time. So we don't
	 * need any protection to access softmac here.
	 */
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
	 * If this is the shared-lower-stream, put the lower stream to
	 * the DLIOCRAW mode to send/receive raw data.
	 */
	if ((sup == NULL) && (err = ldi_ioctl(lh, DLIOCRAW, 0, FKIOCTL,
	    kcred, &rval)) != 0) {
		goto done;
	}

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
	slp->sl_sup = sup;
	slp->sl_lh = lh;
	slp->sl_softmac = softmac;
	*slpp = slp;

	if (sup != NULL) {
		slp->sl_rxinfo = &sup->su_rxinfo;
	} else {
		/*
		 * Send DL_NOTIFY_REQ to enable certain DL_NOTIFY_IND.
		 * We don't have to wait for the ack.
		 */
		notifications = DL_NOTE_PHYS_ADDR | DL_NOTE_LINK_UP |
		    DL_NOTE_LINK_DOWN | DL_NOTE_PROMISC_ON_PHYS |
		    DL_NOTE_PROMISC_OFF_PHYS;

		(void) softmac_send_notify_req(slp,
		    (notifications & softmac->smac_notifications));
	}

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

	ASSERT(MAC_PERIM_HELD(softmac->smac_mh));

	if ((err = softmac_lower_setup(softmac, NULL, &slp)) != 0)
		return (err);

	softmac->smac_lower = slp;
	return (0);
}

static void
softmac_m_close(void *arg)
{
	softmac_t	*softmac = arg;
	softmac_lower_t	*slp;

	ASSERT(MAC_PERIM_HELD(softmac->smac_mh));
	slp = softmac->smac_lower;
	ASSERT(slp != NULL);

	/*
	 * Note that slp is destroyed when lh is closed.
	 */
	(void) ldi_close(slp->sl_lh, FREAD|FWRITE, kcred);
	softmac->smac_lower = NULL;
}

/*
 * Softmac supports two priviate link properteis:
 *
 * - "_fastpath"
 *
 *    This is a read-only link property which points out the current data-path
 *    model of the given legacy link. The possible values are "disabled" and
 *    "enabled".
 *
 * - "_disable_fastpath"
 *
 *    This is a read-write link property which can be used to disable or enable
 *    the fast-path of the given legacy link. The possible values are "true"
 *    and "false". Note that even when "_disable_fastpath" is set to be
 *    "false", the fast-path may still not be enabled since there may be
 *    other mac cleints that request the fast-path to be disabled.
 */
/* ARGSUSED */
static int
softmac_m_setprop(void *arg, const char *name, mac_prop_id_t id,
    uint_t valsize, const void *val)
{
	softmac_t	*softmac = arg;

	if (id != MAC_PROP_PRIVATE || strcmp(name, "_disable_fastpath") != 0)
		return (ENOTSUP);

	if (strcmp(val, "true") == 0)
		return (softmac_datapath_switch(softmac, B_TRUE, B_TRUE));
	else if (strcmp(val, "false") == 0)
		return (softmac_datapath_switch(softmac, B_FALSE, B_TRUE));
	else
		return (EINVAL);
}

static int
softmac_m_getprop(void *arg, const char *name, mac_prop_id_t id,
    uint_t valsize, void *val)
{
	softmac_t	*softmac = arg;
	char		*fpstr;

	if (id != MAC_PROP_PRIVATE)
		return (ENOTSUP);

	if (strcmp(name, "_fastpath") == 0) {
		mutex_enter(&softmac->smac_fp_mutex);
		fpstr = (DATAPATH_MODE(softmac) == SOFTMAC_SLOWPATH) ?
		    "disabled" : "enabled";
		mutex_exit(&softmac->smac_fp_mutex);
	} else if (strcmp(name, "_disable_fastpath") == 0) {
		fpstr = softmac->smac_fastpath_admin_disabled ?
		    "true" : "false";
	} else if (strcmp(name, "_softmac") == 0) {
		fpstr = "true";
	} else {
		return (ENOTSUP);
	}

	return (strlcpy(val, fpstr, valsize) >= valsize ? EINVAL : 0);
}

static void
softmac_m_propinfo(void *arg, const char *name, mac_prop_id_t id,
    mac_prop_info_handle_t prh)
{
        _NOTE(ARGUNUSED(arg));

	if (id != MAC_PROP_PRIVATE)
		return;

	if (strcmp(name, "_fastpath") == 0) {
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
	} else if (strcmp(name, "_disable_fastpath") == 0) {
		mac_prop_info_set_default_str(prh, "false");
	}

}

int
softmac_hold_device(dev_t dev, dls_dev_handle_t *ddhp)
{
	dev_info_t	*dip;
	char		devname[MAXNAMELEN];
	softmac_t	*softmac;
	major_t		major;
	int		ppa, err = 0, inst;

	major = getmajor(dev);
	ppa = getminor(dev) - 1;

	/*
	 * For GLDv3 devices, look up the device instance using getinfo(9e).
	 * Otherwise, fall back to the old assumption that inst == ppa.  The
	 * GLDV3_DRV() macro depends on the driver module being loaded, hence
	 * the call to ddi_hold_driver().
	 */
	if (ddi_hold_driver(major) == NULL)
		return (ENXIO);
	if (GLDV3_DRV(major)) {
		if ((inst = dev_to_instance(dev)) < 0)
			err = ENOENT;
	} else {
		inst = ppa;
	}
	ddi_rele_driver(major);
	if (err != 0)
		return (err);

	/*
	 * First try to hold this device instance to force device to attach
	 * and ensure that the softmac entry gets created in net_postattach().
	 */
	if ((dip = ddi_hold_devi_by_instance(major, inst, 0)) == NULL)
		return (ENOENT);

	/*
	 * Exclude non-physical network device instances, for example, aggr0.
	 * Note: this check *must* occur after the dip is held, or else
	 * NETWORK_PHYSDRV might return false incorrectly.  The
	 * DN_NETWORK_PHYSDRIVER flag used by NETWORK_PHYSDRV() gets set if
	 * ddi_create_minor_node() is called during the device's attach
	 * phase.
	 */
	if (!NETWORK_PHYSDRV(major)) {
		ddi_release_devi(dip);
		return (ENOENT);
	}

	/* Now wait for its softmac to be created. */
	(void) snprintf(devname, MAXNAMELEN, "%s%d", ddi_major_to_name(major),
	    ppa);
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
		mutex_enter(&smac_global_lock);
		rw_exit(&softmac_hash_lock);
		cv_wait(&smac_global_cv, &smac_global_lock);
		mutex_exit(&smac_global_lock);
		goto again;
	}

	/*
	 * Bump smac_hold_cnt to prevent device detach.
	 */
	mutex_enter(&softmac->smac_mutex);
	softmac->smac_hold_cnt++;
	rw_exit(&softmac_hash_lock);

	/*
	 * Wait till the device is fully attached.
	 */
	while (softmac->smac_state != SOFTMAC_ATTACH_DONE)
		cv_wait(&softmac->smac_cv, &softmac->smac_mutex);

	SOFTMAC_STATE_VERIFY(softmac);

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
	if (ddh != NULL)
		softmac_rele((softmac_t *)ddh);
}

int
softmac_hold(dev_t dev, softmac_t **softmacp)
{
	softmac_t	*softmac;
	char		*drv;
	mac_handle_t	mh;
	char		mac[MAXNAMELEN];
	int		err;

	if ((drv = ddi_major_to_name(getmajor(dev))) == NULL)
		return (EINVAL);

	(void) snprintf(mac, MAXNAMELEN, "%s%d", drv, getminor(dev) - 1);
	if ((err = mac_open(mac, &mh)) != 0)
		return (err);

	softmac = (softmac_t *)mac_driver(mh);

	mutex_enter(&softmac->smac_mutex);
	softmac->smac_hold_cnt++;
	mutex_exit(&softmac->smac_mutex);
	mac_close(mh);
	*softmacp = softmac;
	return (0);
}

void
softmac_rele(softmac_t *softmac)
{
	mutex_enter(&softmac->smac_mutex);
	softmac->smac_hold_cnt--;
	mutex_exit(&softmac->smac_mutex);
}
