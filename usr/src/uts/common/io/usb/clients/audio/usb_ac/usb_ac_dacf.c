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
 * This is a dacf module for usb audio plumbing/unplumbing based
 * upon the Extensions to Device Autoconfiguration project.  See
 * PSARC/1998/212 for more details.
 *
 * This module provides the dacf functions to be called after a
 * driver has attached and before it detaches.
 * Particularly, the usb_ac_mux_plumbing() is called after
 * usb_ac_attach() is called and usb_ac_mux_unplumbing() is called
 * before usb_ac_detach() is going to be called. This facilitates
 * the configuration of usb_as and hid under usb_ac and also
 * provides * usb_ac and usb_as hotplugging.
 *
 * This dacf module only supports usb_as and hid plumbing under
 * usb_ac.
 *
 * Note: This module shares some common data structures with usb_ac
 * module. So it would require dependency on usb_ac for the module
 * loading. But the side effect for usb_ac_dacf to depend on usb_ac
 * is a deadlock situation created when doing "modunload -i
 * <usb_ac_dacf_mod_id>" before "modunload -i <usb_ac_mod_id".
 * To avoid the dependency, space_store() and space_fetch() are
 * used to share the usb_ac data structure with usb_ac_dacf.
 */
#include <sys/usb/usba/usbai_version.h>
#include <sys/usb/usba.h>
#include <sys/sunndi.h>
#include <sys/audio.h>
#include <sys/audiovar.h>
#include <sys/audio/audio_support.h>
#include <sys/audio/audio_src.h>
#include <sys/mixer.h>
#include <sys/audio/audio_mixer.h>
#include <sys/audio/am_src2.h>

#include <sys/usb/clients/audio/usb_audio.h>
#include <sys/usb/clients/audio/usb_mixer.h>
#include <sys/usb/clients/audio/usb_ac/usb_ac.h>

#include <sys/stropts.h>
#include <sys/dacf.h>

/* for getting the minor node info from hid */
#include <sys/usb/clients/hid/hidminor.h>
#include <sys/usb/clients/audio/usb_as/usb_as.h>

/*
 * Dacf entry points
 */
static int	usb_ac_mux_plumbing(dacf_infohdl_t, dacf_arghdl_t, int);
static int	usb_ac_mux_unplumbing(dacf_infohdl_t, dacf_arghdl_t, int);

/*
 * External functions
 */
extern	uint_t		nproc;
#define	INIT_PROCESS_CNT 3

extern uintptr_t space_fetch(char *);

/*
 * Internal functions
 */
static int	usb_ac_mux_walk_siblings(usb_ac_state_t *, ldi_handle_t);
static void	usb_ac_print_reg_data(usb_ac_state_t *,
				usb_as_registration_t *);
static int	usb_ac_get_reg_data(usb_ac_state_t *, ldi_handle_t, int);
static int	usb_ac_setup_plumbed(usb_ac_state_t *, int, int, int);
static int	usb_ac_mixer_registration(usb_ac_state_t *,
				usb_ac_state_space_t *);
static void	usb_ac_hold_siblings(usb_ac_state_t *);
static int	usb_ac_online_siblings(usb_ac_state_t *);
static void	usb_ac_rele_siblings(usb_ac_state_t *);

static am_ad_entry_t *usb_ac_entry;
_NOTE(SCHEME_PROTECTS_DATA("stable data", usb_ac_entry))


/* just generic, USB Audio, 1.0 spec-compliant */
static audio_device_t usb_dev_info =
	{ {"USB Audio"}, {"1.0"}, {"external"} };

static dacf_op_t usb_ac_plumb_op[] = {
	{ DACF_OPID_POSTATTACH,	usb_ac_mux_plumbing },
	{ DACF_OPID_PREDETACH,	usb_ac_mux_unplumbing },
	{ DACF_OPID_END,	NULL },
};

static dacf_opset_t opsets[] = {
	{ "usb_audio_config", usb_ac_plumb_op },
	{ NULL,		NULL }
};

struct dacfsw usb_audio_dacfsw = {
	DACF_MODREV_1,
	opsets,
};

struct modldacf usb_audio_dacf = {
	&mod_dacfops,	/* Type of module */
	"USB_AC_DACF %I%",
	&usb_audio_dacfsw
};

struct modlinkage usb_audio_modlinkage = {
	MODREV_1, (void *)&usb_audio_dacf, NULL
};


int
_init(void)
{
	return (mod_install(&usb_audio_modlinkage));
}


int
_fini()
{
	return (mod_remove(&usb_audio_modlinkage));
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&usb_audio_modlinkage, modinfop));
}


/*
 * This routine is called at post attach time for the usb_ac module
 * by the DACF framework.
 */
/*ARGSUSED*/
static int
usb_ac_mux_plumbing(dacf_infohdl_t info_hdl, dacf_arghdl_t arg_hdl, int flags)
{
	major_t			major;
	minor_t			minor;
	int			instance;
	usb_ac_state_t		*uacp;
	usb_ac_state_space_t	*ssp;
	dev_info_t		*dip;
	int			error;
	ldi_handle_t		mux_lh;
	dev_t			mux_devt;
	ldi_ident_t		li;

	/* get the usb_ac dip */
	dip = dacf_devinfo_node(info_hdl);
	instance = ddi_get_instance(dip);

	/* Retrieve the soft state information */
	if ((ssp = (usb_ac_state_space_t *)space_fetch("usb_ac")) ==
	    NULL) {

		return (DACF_FAILURE);
	}

	if ((uacp = (usb_ac_state_t *)ddi_get_soft_state(ssp->sp,
	    instance)) == NULL) {

		return (DACF_FAILURE);
	}
	ASSERT(dip == uacp->usb_ac_dip);

	usb_ac_entry = ssp->ac_entryp;

	/* Access to the global variables is synchronized */
	mutex_enter(&uacp->usb_ac_mutex);

	USB_DPRINTF_L3(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_mux_plumbing callback, state=%d",
	    uacp->usb_ac_plumbing_state);

	/*
	 * by design, dacf will try to plumb again if an unplumb failed.
	 * therefore, just return success
	 */
	if (uacp->usb_ac_plumbing_state >= USB_AC_STATE_PLUMBED) {
		mutex_exit(&uacp->usb_ac_mutex);
		USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "audio streams driver already plumbed");

		return (DACF_SUCCESS);
	}

	/* usb_as and hid should be attached but double check */
	if (usb_ac_online_siblings(uacp) != USB_SUCCESS) {
		mutex_exit(&uacp->usb_ac_mutex);
		USB_DPRINTF_L2(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "no audio streams driver plumbed");

		return (DACF_FAILURE);
	}

	major = ddi_driver_major(dip);
	ASSERT(major != (major_t)-1);

	minor = dacf_minor_number(info_hdl);
	ASSERT(minor == uacp->usb_ac_mux_minor);

	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "major 0x%x, minor %d  usb_ac_mux_plumbing: driver name "
	    "%s\n", major, minor, (char *)dacf_driver_name(info_hdl));

	mutex_exit(&uacp->usb_ac_mutex);

	/* bring the device to full power */
	(ssp->pm_busy_component)(uacp);
	(void) pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);

	/* avoid dips disappearing while we are plumbing */
	usb_ac_hold_siblings(uacp);

	/* opening usb_ac for plumbing underneath */
	mux_devt = makedevice(major, minor);
	error = ldi_ident_from_mod(&usb_audio_modlinkage, &li);
	if (error == 0) {
		error = ldi_open_by_dev(&mux_devt, OTYP_CHR,
		    FREAD|FWRITE|FNOCTTY|FNONBLOCK, kcred, &mux_lh, li);
		ldi_ident_release(li);
	}
	if (error) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "open failed, error=%d", error);
		usb_ac_rele_siblings(uacp);

		(ssp->pm_idle_component)(uacp);

		return (DACF_FAILURE);
	}

	mutex_enter(&uacp->usb_ac_mutex);

	uacp->usb_ac_mux_lh = mux_lh;
	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "mux_lh=0x%p", (void *)mux_lh);

	/*
	 * walk all siblings and create the usb_ac<->usb_as and
	 * usb_ac<->hid streams. return of 0 indicates no or
	 * partial/failed plumbing
	 */
	if (usb_ac_mux_walk_siblings(uacp, mux_lh) == 0) {
		/* pretend that we are plumbed so we can unplumb */
		uacp->usb_ac_plumbing_state = USB_AC_STATE_PLUMBED;

		mutex_exit(&uacp->usb_ac_mutex);

		(void) usb_ac_mux_unplumbing(info_hdl, arg_hdl, flags);

		USB_DPRINTF_L2(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "no audio streams driver plumbed");

		usb_ac_rele_siblings(uacp);

		(ssp->pm_idle_component)(uacp);

		return (DACF_FAILURE);
	}
	uacp->usb_ac_plumbing_state = USB_AC_STATE_PLUMBED;

	/* restore state if we have already registered with the mixer */
	if (uacp->usb_ac_registered_with_mixer) {

		(void) (ssp->restore_func)(uacp, USB_FLAGS_SLEEP);

	} else if (usb_ac_mixer_registration(uacp, ssp) != USB_SUCCESS) {
		mutex_exit(&uacp->usb_ac_mutex);

		(void) usb_ac_mux_unplumbing(info_hdl, arg_hdl, flags);

		USB_DPRINTF_L1(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "mixer registration failed");

		usb_ac_rele_siblings(uacp);

		(ssp->pm_idle_component)(uacp);

		return (DACF_FAILURE);
	}

	mutex_exit(&uacp->usb_ac_mutex);
	usb_ac_rele_siblings(uacp);

	(ssp->pm_idle_component)(uacp);

	return (DACF_SUCCESS);
}


/*
 * This is the pre-detach routine invoked for usb_ac module by DACF framework
 */
/*ARGSUSED*/
static int
usb_ac_mux_unplumbing(dacf_infohdl_t info_hdl, dacf_arghdl_t arg_hdl, int flags)
{
	usb_ac_state_t		*uacp;
	usb_ac_state_space_t	*ssp;
	dev_info_t		*dip;
	ldi_handle_t		mux_lh;
	dev_info_t		*child_dip;
	int			i, error;
	int			maxlinked = 0;

	/* this is the usb_ac dip */
	dip = dacf_devinfo_node(info_hdl);

	/* Retrieve the soft state information */
	if ((ssp = (usb_ac_state_space_t *)space_fetch("usb_ac")) ==
	    NULL) {

		return (DACF_FAILURE);
	}

	if ((uacp = (usb_ac_state_t *)ddi_get_soft_state(ssp->sp,
	    ddi_get_instance(dip))) == NULL) {

		return (DACF_FAILURE);
	}

	mutex_enter(&uacp->usb_ac_mutex);

	USB_DPRINTF_L3(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_mux_unplumbing callback, state=%d",
	    uacp->usb_ac_plumbing_state);

	ASSERT(uacp->usb_ac_plumbing_state != USB_AC_STATE_UNPLUMBED);

	if (uacp->usb_ac_plumbing_state == USB_AC_STATE_UNPLUMBED) {
		USB_DPRINTF_L4(PRINT_MASK_ALL,
		    uacp->usb_ac_log_handle,
		    "already unplumbed!");
		mutex_exit(&uacp->usb_ac_mutex);

		return (DACF_SUCCESS);
	}

	ASSERT(dip == uacp->usb_ac_dip);

	mux_lh = uacp->usb_ac_mux_lh;

	/* usb_ac might not have anything plumbed yet */
	if (uacp->usb_ac_current_plumbed_index == -1) {
		USB_DPRINTF_L4(PRINT_MASK_ALL,
		    uacp->usb_ac_log_handle,
		    "nothing plumbed!");
		uacp->usb_ac_plumbing_state = USB_AC_STATE_UNPLUMBED;

		goto close_mux;
	}

	/* do not allow detach if still busy */
	if (uacp->usb_ac_busy_count) {
		USB_DPRINTF_L2(PRINT_MASK_ALL,
		    uacp->usb_ac_log_handle,
		    "mux still open (%d %d)", uacp->usb_ac_busy_count,
		    e_ddi_devi_holdcnt(dip));
		mutex_exit(&uacp->usb_ac_mutex);

		return (DACF_FAILURE);
	}

	uacp->usb_ac_plumbing_state = USB_AC_STATE_UNPLUMBED;

	/* wait till tasks have drained using save state */
	mutex_exit(&uacp->usb_ac_mutex);
	(void) audio_sup_save_state(uacp->usb_ac_audiohdl,
	    AUDIO_ALL_DEVICES, AUDIO_BOTH);
	mutex_enter(&uacp->usb_ac_mutex);

	mux_lh = uacp->usb_ac_mux_lh;
	ASSERT(mux_lh != NULL);

	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_mux_unplumbing mux_lh 0x%p", (void *)mux_lh);

	/* unlink and close ac-as and ac-hid streams */
	maxlinked = uacp->usb_ac_current_plumbed_index + 1;
	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_mux_unplumbing maxlinked %d", maxlinked);

	for (i = 0; i < maxlinked; i++) {
		int linkid = uacp->usb_ac_plumbed[i].acp_linkid;

		child_dip = uacp->usb_ac_plumbed[i].acp_dip;
		uacp->usb_ac_current_plumbed_index = i;

		USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "usb_ac_mux_unplumbing linkid %d ", linkid);

		if (child_dip) {
			int rval;

			mutex_exit(&uacp->usb_ac_mutex);

			error = ldi_ioctl(mux_lh, I_PUNLINK, (intptr_t)linkid,
			    FKIOCTL, kcred, &rval);

			USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
			    "%s%d: unplink, error=%d",
			    ddi_driver_name(child_dip),
			    ddi_get_instance(child_dip), error);

			mutex_enter(&uacp->usb_ac_mutex);
		}

	}

close_mux:
	if (mux_lh) {
		mutex_exit(&uacp->usb_ac_mutex);
		(void) ldi_close(mux_lh, FREAD|FWRITE, kcred);
		mutex_enter(&uacp->usb_ac_mutex);
		USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "closed mux");
		uacp->usb_ac_mux_lh = NULL;
	}

	uacp->usb_ac_current_plumbed_index = -1;
	mutex_exit(&uacp->usb_ac_mutex);

	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_mux_unplumbing: done");

	return (DACF_SUCCESS);
}


/*
 * walk all siblings and create the ac<->as and ac<->hid streams
 */
static int
usb_ac_mux_walk_siblings(usb_ac_state_t *uacp, ldi_handle_t mux_lh)
{
	dev_info_t	*pdip;
	dev_info_t	*child_dip;
	major_t		drv_major;
	minor_t		drv_minor;
	int		drv_instance;
	dev_t		drv_devt;
	ldi_handle_t	drv_lh;
	ldi_ident_t	li;
	int		linkid;
	int		error;
	int		count = 0;

	ASSERT(mutex_owned(&uacp->usb_ac_mutex));

	mutex_exit(&uacp->usb_ac_mutex);
	pdip = ddi_get_parent(uacp->usb_ac_dip);
	mutex_enter(&uacp->usb_ac_mutex);

	child_dip = ddi_get_child(pdip);

	while ((child_dip != NULL) && (count < USB_AC_MAX_PLUMBED)) {
		drv_instance = ddi_get_instance(child_dip);
		USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "plumbing %s%d", ddi_driver_name(child_dip), drv_instance);

		/* ignore own dip */
		if (child_dip == uacp->usb_ac_dip) {
			child_dip = ddi_get_next_sibling(child_dip);
			continue;
		}
		drv_instance = ddi_get_instance(child_dip);

		/* ignore other dip other than usb_as and hid */
		if (strcmp(ddi_driver_name(child_dip), "usb_as") == 0) {
			uacp->usb_ac_plumbed[count].acp_driver = USB_AS_PLUMBED;
			drv_minor = USB_AS_CONSTRUCT_MINOR(drv_instance);
		} else if (strcmp(ddi_driver_name(child_dip), "hid") == 0) {
			uacp->usb_ac_plumbed[count].acp_driver = USB_AH_PLUMBED;
			drv_minor = HID_CONSTRUCT_EXTERNAL_MINOR(drv_instance);
		} else {
			drv_minor = drv_instance;
			uacp->usb_ac_plumbed[count].acp_driver =
			    UNKNOWN_PLUMBED;
			child_dip = ddi_get_next_sibling(child_dip);

			continue;
		}

		if (!i_ddi_devi_attached(child_dip)) {
			child_dip = ddi_get_next_sibling(child_dip);

			continue;
		}

		if (DEVI_IS_DEVICE_REMOVED(child_dip)) {
			child_dip = ddi_get_next_sibling(child_dip);

			continue;
		}


		USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "opening %s%d", ddi_driver_name(child_dip), drv_instance);

		drv_major = ddi_driver_major(child_dip);

		uacp->usb_ac_current_plumbed_index = count;

		mutex_exit(&uacp->usb_ac_mutex);

		drv_devt = makedevice(drv_major, drv_minor);

		error = ldi_ident_from_mod(&usb_audio_modlinkage, &li);
		if (error == 0) {
			error = ldi_open_by_dev(&drv_devt, OTYP_CHR,
			    FREAD|FWRITE, kcred, &drv_lh, li);
			ldi_ident_release(li);
		}

		mutex_enter(&uacp->usb_ac_mutex);
		if (error) {
			USB_DPRINTF_L2(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
			    "ldi_open_by_dev failed on major = %d minor = %d, "
			    "name = %s error=%d", drv_major, drv_instance,
			    ddi_driver_name(child_dip), error);
			mutex_exit(&uacp->usb_ac_mutex);
			mutex_enter(&uacp->usb_ac_mutex);

			return (0);
		}

		uacp->usb_ac_plumbed[count].acp_dip = child_dip;
		uacp->usb_ac_plumbed[count].acp_ifno =
		    usb_get_if_number(child_dip);

		if (uacp->usb_ac_plumbed[count].acp_driver == USB_AS_PLUMBED) {
			/* get registration data */
			if (usb_ac_get_reg_data(uacp, drv_lh, count) !=
			    USB_SUCCESS) {

				USB_DPRINTF_L2(PRINT_MASK_ALL,
				    uacp->usb_ac_log_handle,
				    "get_reg_data failed on major = %d "
				    "minor = %d, name = %s", drv_major,
				    drv_instance,
				    ddi_driver_name(child_dip));

				mutex_exit(&uacp->usb_ac_mutex);
				(void) ldi_close(drv_lh, FREAD|FWRITE, kcred);
				mutex_enter(&uacp->usb_ac_mutex);
				uacp->usb_ac_plumbed[count].acp_dip = NULL;

				return (0);
			}
		} else if (uacp->usb_ac_plumbed[count].acp_driver ==
		    USB_AH_PLUMBED) {
			int rval;

			mutex_exit(&uacp->usb_ac_mutex);

			/* push usb_ah module on top of hid */
			error = ldi_ioctl(drv_lh, I_PUSH, (intptr_t)"usb_ah",
			    FKIOCTL, kcred, &rval);
			mutex_enter(&uacp->usb_ac_mutex);

			if (error) {
				USB_DPRINTF_L2(PRINT_MASK_ALL,
				    uacp->usb_ac_log_handle,
				    "ldi_ioctl failed for usb_ah, "
				    "major:%d minor:%d name:%s",
				    drv_major, drv_instance,
				    ddi_driver_name(child_dip));

				mutex_exit(&uacp->usb_ac_mutex);
				(void) ldi_close(drv_lh, FREAD|FWRITE, kcred);
				mutex_enter(&uacp->usb_ac_mutex);
				uacp->usb_ac_plumbed[count].acp_dip = NULL;

				/* skip plumbing the hid driver */
				child_dip = ddi_get_next_sibling(child_dip);
				continue;
			}
		} else {
			/* should not be here */
			USB_DPRINTF_L2(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
			    "usb_ac_mux_plumbing: unknown module");
			count --;

			mutex_exit(&uacp->usb_ac_mutex);
			(void) ldi_close(drv_lh, FREAD|FWRITE, kcred);
			mutex_enter(&uacp->usb_ac_mutex);

			uacp->usb_ac_plumbed[count].acp_dip = NULL;

			/* skip plumbing an unknown module */
			child_dip = ddi_get_next_sibling(child_dip);
			continue;
		}

		USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "linking %s%d", ddi_driver_name(child_dip), drv_instance);

		/* usb_ac_plumb_ioctl sets lwq, this entry should be free */
		ASSERT(uacp->usb_ac_plumbed[count].acp_lwq == NULL);

		mutex_exit(&uacp->usb_ac_mutex);

		/* plumbing one at a time */
		error = ldi_ioctl(mux_lh, I_PLINK, (intptr_t)drv_lh,
		    FREAD|FWRITE|FNOCTTY|FKIOCTL, kcred, &linkid);

		(void) ldi_close(drv_lh, FREAD|FWRITE, kcred);

		mutex_enter(&uacp->usb_ac_mutex);

		if (error) {
			USB_DPRINTF_L2(PRINT_MASK_ALL,
			    uacp->usb_ac_log_handle,
			    "plink failed for major:%d minor:%d"
			    "name:%s", drv_major, drv_instance,
			    ddi_driver_name(child_dip));

			return (0);
		}

		USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "link id %s%d 0x%x", ddi_driver_name(child_dip),
		    ddi_get_instance(child_dip), linkid);

		/* lwq should be set by usb_ac_plumb_ioctl by now */
		ASSERT(uacp->usb_ac_plumbed[count].acp_lwq != NULL);

		uacp->usb_ac_plumbed[count++].acp_linkid = linkid;

		child_dip = ddi_get_next_sibling(child_dip);
	}

	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "%d drivers plumbed under usb_ac mux", count);

	return (count);
}


/*
 * usb_ac_find_default_port:
 */
static int
usb_ac_find_default_port(uint_t port)
{
	int i;

	for (i = 0; i < 32; i++) {
		if (port & (1 << i)) {

			return (1 << i);
		}
	}

	return (0);
}


/*
 * Register with mixer only after first plumbing.
 * Also do not register if earlier reg data
 * couldn't be received from at least one
 * streaming interface
 */
_NOTE(SCHEME_PROTECTS_DATA("private", am_ad_info))

static int
usb_ac_mixer_registration(usb_ac_state_t *uacp, usb_ac_state_space_t *ssp)
{
	am_ad_info_t	*info	= &uacp->usb_ac_am_ad_info;
	audio_info_t	*dflts	= &uacp->usb_ac_am_ad_defaults;
	usb_as_registration_t *asreg;
	int		n, nplay, nrec;

	ASSERT(uacp != NULL);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, uacp->usb_ac_log_handle,
	    "usb_ac_mixer_registration: infp=0x%p, dflts=0x%p",
	    (void *)info, (void *)dflts);

	ASSERT(dflts != NULL);
	ASSERT(info != NULL);

	if (uacp->usb_ac_registered_with_mixer) {

		return (USB_SUCCESS);
	}

	for (n = 0; n < USB_AC_MAX_AS_PLUMBED; n++) {
		if (uacp->usb_ac_streams[n].acs_rcvd_reg_data) {
			break;
		}
	}

	/* Haven't found a streaming interface; fail mixer registration */
	if (n > USB_AC_MAX_AS_PLUMBED) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, uacp->usb_ac_log_handle,
		    "no streaming interface");

		return (USB_FAILURE);
	}

	USB_DPRINTF_L4(PRINT_MASK_ATTA, uacp->usb_ac_log_handle,
	    "usb_ac_mixer_registration: mixer enabled =%d",
	    uacp->usb_ac_mixer_mode_enable);

	info->ad_int_vers	= AM_VERSION;
	info->ad_mode		= (uacp->usb_ac_mixer_mode_enable ?
	    AM_MIXER_MODE : AM_COMPAT_MODE);

	info->ad_add_mode	= 0;
	info->ad_codec_type	= AM_TRAD_CODEC;
	info->ad_defaults	= dflts;

	dflts->monitor_gain	= 0;
	dflts->output_muted	= B_FALSE;
	dflts->hw_features	= 0;
	dflts->sw_features	= AUDIO_SWFEATURE_MIXER;

	/*
	 * Fill out streaming interface specific stuff
	 * Note that we handle only one playing and one recording
	 * streaming interface at the most
	 */
	nplay = nrec = 0;
	for (n = 0; n < USB_AC_MAX_AS_PLUMBED; n++) {
		int ch, chs, default_gain, id;

		if (uacp->usb_ac_streams[n].acs_rcvd_reg_data == 0) {
			continue;
		}

		asreg = uacp->usb_ac_streams[n].acs_streams_reg;
		if (asreg->reg_valid == 0) {
			continue;
		}

		mutex_exit(&uacp->usb_ac_mutex);

		/* set first format so get_featureID can be succeed */
		(void) ssp->ac_entryp->ad_set_format(uacp->usb_ac_audiohdl, 0,
		    asreg->reg_mode,
		    asreg->reg_compat_srs.ad_srs[0],
		    asreg->reg_formats[0].fmt_chns,
		    asreg->reg_formats[0].fmt_precision,
		    asreg->reg_formats[0].fmt_encoding);

		mutex_enter(&uacp->usb_ac_mutex);

		chs = asreg->reg_formats[0].fmt_chns;

		/* check if any channel supports vol. control for this fmt */
		for (ch = 0; ch <= chs; ch++) {
			if ((id = ssp->get_featureID_func(uacp,
			    asreg->reg_mode, ch,
			    USB_AUDIO_VOLUME_CONTROL)) != -1) {
				USB_DPRINTF_L3(PRINT_MASK_ATTA,
				    uacp->usb_ac_log_handle,
				    "dir=%d featureID=%d",
				    asreg->reg_mode, id);

				break;
			}
		}
		default_gain = (id == USB_AC_ID_NONE) ?
		    AUDIO_MAX_GAIN : (AUDIO_MAX_GAIN/2);

		USB_DPRINTF_L3(PRINT_MASK_ATTA, uacp->usb_ac_log_handle,
		    "mode=%d chs=%d default_gain=%d id=%d",
		    asreg->reg_mode, chs, default_gain, id);

		if (asreg->reg_mode == AUDIO_PLAY) {
			nplay++;
			ASSERT(nplay == 1);

			dflts->play.sample_rate =
			    asreg->reg_compat_srs.ad_srs[0];
			dflts->play.channels	=
			    asreg->reg_formats[0].fmt_chns;
			dflts->play.precision	=
			    asreg->reg_formats[0].fmt_precision;
			dflts->play.encoding	=
			    asreg->reg_formats[0].fmt_encoding;
			dflts->play.gain	= default_gain;
			dflts->play.port	= usb_ac_find_default_port(
			    uacp->usb_ac_output_ports);
			dflts->play.avail_ports = uacp->usb_ac_output_ports;
			dflts->play.mod_ports	= 0;
						/* no support for mixer unit */
			dflts->play.buffer_size = 8*1024;
			dflts->play.balance	= AUDIO_MID_BALANCE;
			dflts->hw_features	|= AUDIO_HWFEATURE_PLAY;

			info->ad_play.ad_mixer_srs	= asreg->reg_mixer_srs;
			info->ad_play.ad_compat_srs	= asreg->reg_compat_srs;
			info->ad_play.ad_conv		= &am_src2;
			info->ad_play.ad_sr_info	= NULL;
			info->ad_play.ad_chs		= asreg->reg_channels;
			info->ad_play.ad_int_rate	= 1000; /* every 1 ms */
			info->ad_play.ad_max_chs	= 200;
			info->ad_play.ad_bsize		= 8 * 1024;
			info->ad_play_comb	= asreg->reg_combinations;
		} else {
			nrec++;
			ASSERT(nrec == 1);

			dflts->record.sample_rate =
			    asreg->reg_compat_srs.ad_srs[0];
			dflts->record.channels	=
			    asreg->reg_formats[0].fmt_chns;
			dflts->record.precision =
			    asreg->reg_formats[0].fmt_precision;
			dflts->record.encoding	=
			    asreg->reg_formats[0].fmt_encoding;
			dflts->record.gain	= default_gain;
			dflts->record.port	= usb_ac_find_default_port(
			    uacp->usb_ac_input_ports);
			dflts->record.avail_ports = uacp->usb_ac_input_ports;
			dflts->record.mod_ports = uacp->usb_ac_input_ports;
			dflts->record.buffer_size = 8*1024;
			dflts->record.balance	= AUDIO_MID_BALANCE;
			dflts->hw_features	|= AUDIO_HWFEATURE_RECORD;

			info->ad_record.ad_mixer_srs	= asreg->reg_mixer_srs;
			info->ad_record.ad_compat_srs	= asreg->reg_compat_srs;
			info->ad_record.ad_conv 	= &am_src2;
			info->ad_record.ad_sr_info	= NULL;
			info->ad_record.ad_chs		= asreg->reg_channels;
			info->ad_record.ad_int_rate	= 1000; /* every 1 ms */
			info->ad_record.ad_max_chs	= 200;
			info->ad_record.ad_bsize	= 8 * 1024;
			info->ad_num_mics		= 1;
			info->ad_rec_comb	= asreg->reg_combinations;
		}
	}

	if (nplay && nrec) {
		/*
		 * we pretend to always support AUDIO_HWFEATURE_IN2OUT
		 * since there is no simple way to find out at this
		 * point
		 */
		dflts->hw_features	|= AUDIO_HWFEATURE_DUPLEX |
		    AUDIO_HWFEATURE_IN2OUT;
	}

	/* the rest */
	info->ad_entry		= usb_ac_entry;
	info->ad_dev_info	= &usb_dev_info;
	info->ad_diag_flags	= 0;
	info->ad_diff_flags = AM_DIFF_SR|AM_DIFF_CH|AM_DIFF_PREC|AM_DIFF_ENC;
	info->ad_assist_flags	= 0;
	info->ad_misc_flags	= AM_MISC_RP_EXCL;
	info->ad_translate_flags = 0;

	mutex_exit(&uacp->usb_ac_mutex);

	if (am_attach(uacp->usb_ac_audiohdl, DDI_ATTACH, info) ==
	    AUDIO_FAILURE) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, uacp->usb_ac_log_handle,
		    "am_attach: failed");

		mutex_enter(&uacp->usb_ac_mutex);

		return (USB_FAILURE);
	}

	mutex_enter(&uacp->usb_ac_mutex);

	uacp->usb_ac_registered_with_mixer = 1;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, uacp->usb_ac_log_handle,
	    "am_attach succeeded");

	return (USB_SUCCESS);
}


/*
 * get registration data from usb_as driver unless we already
 * have 2 registrations
 */
static int
usb_ac_get_reg_data(usb_ac_state_t *uacp, ldi_handle_t drv_lh, int index)
{
	int n, error, rval;
	usb_as_registration_t *streams_reg;

	/* if already registered, just setup data structures again */
	if (uacp->usb_ac_registered_with_mixer) {

		return (usb_ac_setup_plumbed(uacp, index, -1, -1));
	}

	for (n = 0; n < USB_AC_MAX_AS_PLUMBED; n ++) {
		/*
		 * We haven't received registration data
		 * from n-th streaming interface in the array
		 */
		if (!uacp->usb_ac_streams[n].acs_rcvd_reg_data) {
			break;
		}
	}

	if (n >= USB_AC_MAX_AS_PLUMBED) {
		USB_DPRINTF_L1(PRINT_MASK_ALL,
		    uacp->usb_ac_log_handle,
		    "More than 2 streaming interfaces (play "
		    "and/or record) currently not supported");

		return (USB_FAILURE);
	}

	/* take the stream reg struct with the same index */
	streams_reg = &uacp->usb_ac_streams_reg[n];

	USB_DPRINTF_L4(PRINT_MASK_ALL,
	    uacp->usb_ac_log_handle,
	    "regdata from usb_as: streams_reg=0x%p, n=%d",
	    (void *)streams_reg, n);

	mutex_exit(&uacp->usb_ac_mutex);

	if ((error = ldi_ioctl(drv_lh, USB_AUDIO_MIXER_REGISTRATION,
	    (intptr_t)streams_reg, FKIOCTL, kcred, &rval)) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ALL,
		    uacp->usb_ac_log_handle,
		    "ldi_ioctl fails for mixer registration, error=%d", error);
		mutex_enter(&uacp->usb_ac_mutex);

		return (USB_FAILURE);
	} else {
		mutex_enter(&uacp->usb_ac_mutex);

		rval = usb_ac_setup_plumbed(uacp, index, n, n);

		USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "usb_ac_streams: index=%d, received_reg_data=%d type=%s",
		    index, uacp->usb_ac_streams[n].acs_rcvd_reg_data,
		    ((streams_reg->reg_mode == AUDIO_PLAY) ?
		    "play" : "record"));

		usb_ac_print_reg_data(uacp, streams_reg);

		return (rval);
	}
}


/*
 * setup plumbed and stream info structure, either initially or
 * after replumbing
 * On replumbing, str_idx and reg_idx are -1
 */
static int
usb_ac_setup_plumbed(usb_ac_state_t *uacp, int plb_idx, int str_idx,
    int reg_idx)
{
	int i;

	if (str_idx == -1) {
		/* find a free streams info structure */
		for (i = 0; i < USB_AC_MAX_AS_PLUMBED; i++) {
			if (uacp->usb_ac_streams[i].acs_plumbed == NULL) {
				break;
			}
		}
		ASSERT(i < USB_AC_MAX_AS_PLUMBED);
		str_idx = i;
	}

	uacp->usb_ac_plumbed[plb_idx].acp_data =
	    &uacp->usb_ac_streams[str_idx];
	uacp->usb_ac_streams[str_idx].acs_plumbed =
	    &uacp->usb_ac_plumbed[plb_idx];
	uacp->usb_ac_streams[str_idx].acs_rcvd_reg_data = 1;
	cv_init(&(uacp->usb_ac_streams[str_idx].
	    acs_ac_to_as_req.acr_cv), NULL, CV_DRIVER, NULL);

	if (reg_idx == -1) {
		/*
		 * find the corresponding registration structure, match
		 * on interface number and not on dip since dip may have
		 * changed
		 */
		for (i = 0; i < USB_AC_MAX_AS_PLUMBED; i++) {
			if (uacp->usb_ac_streams_reg[i].reg_ifno ==
			    uacp->usb_ac_plumbed[plb_idx].acp_ifno) {
				break;
			}
		}
		if (i == USB_AC_MAX_AS_PLUMBED) {
			USB_DPRINTF_L2(PRINT_MASK_ALL,
			    uacp->usb_ac_log_handle,
			    "no corresponding registration structure");

			return (USB_FAILURE);
		}
		reg_idx = i;
	}
	uacp-> usb_ac_streams[str_idx].acs_streams_reg =
	    &uacp->usb_ac_streams_reg[reg_idx];

	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_setup_plumbed: plb_idx=%d str_idx=%d reg_idx=%d",
	    plb_idx, str_idx, reg_idx);

	return (USB_SUCCESS);
}


/*
 * function to dump registration data
 */
static void
usb_ac_print_reg_data(usb_ac_state_t *uacp,
    usb_as_registration_t *reg)
{
	int n;

	USB_DPRINTF_L3(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_print_reg_data: Begin valid=%d, play=%d, "
	    "n_formats=%d, mixer srs ptr=0x%p, compat srs ptr=0x%p",
	    reg->reg_valid, reg->reg_mode, reg->reg_n_formats,
	    (void *)&reg->reg_mixer_srs, (void *)&reg->reg_compat_srs);

	for (n = 0; n < reg->reg_n_formats; n++) {
		USB_DPRINTF_L3(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "format%d: alt=%d chns=%d prec=%d enc=%d", n,
		    reg->reg_formats[n].fmt_alt,
		    reg->reg_formats[n].fmt_chns,
		    reg->reg_formats[n].fmt_precision,
		    reg->reg_formats[n].fmt_encoding);
	}

	USB_DPRINTF_L3(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "combinations: %d %d %d %d %d %d %d %d",
	    reg->reg_combinations[0].ad_prec, reg->reg_combinations[0].ad_enc,
	    reg->reg_combinations[1].ad_prec, reg->reg_combinations[1].ad_enc,
	    reg->reg_combinations[2].ad_prec, reg->reg_combinations[2].ad_enc,
	    reg->reg_combinations[3].ad_prec, reg->reg_combinations[3].ad_enc);


	for (n = 0; n < USB_AS_N_FORMATS; n++) {
		USB_DPRINTF_L3(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "reg_formats[%d] ptr=0x%p", n,
		    (void *)&reg->reg_formats[n]);
	}

	for (n = 0; n < USB_AS_N_CHANNELS; n++) {
		USB_DPRINTF_L3(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "reg_channels[%d]=%d", n, reg->reg_channels[n]);
	}

	for (n = 0; n < USB_AS_N_COMBINATIONS; n++) {
		USB_DPRINTF_L3(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "reg_combinations[%d] ptr=0x%p", n,
		    (void *)&reg->reg_combinations[n]);
	}

	USB_DPRINTF_L3(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_print_reg_data: End");
}


static int
usb_ac_online_siblings(usb_ac_state_t *uacp)
{
	dev_info_t	*pdip, *child_dip;
	int		rval = USB_SUCCESS;

	ASSERT(mutex_owned(&uacp->usb_ac_mutex));
	USB_DPRINTF_L4(PRINT_MASK_PM, uacp->usb_ac_log_handle,
	    "usb_ac_onlining siblings");

	pdip = ddi_get_parent(uacp->usb_ac_dip);

	child_dip = ddi_get_child(pdip);
	while (child_dip != NULL) {
		USB_DPRINTF_L3(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "onlining %s%d ref=%d", ddi_driver_name(child_dip),
		    ddi_get_instance(child_dip),
		    DEVI(child_dip)->devi_ref);

		/* Online the child_dip of usb_as and hid,  if not already */
		if ((strcmp(ddi_driver_name(child_dip), "usb_as") == 0) ||
		    (strcmp(ddi_driver_name(child_dip), "hid") == 0)) {
			mutex_exit(&uacp->usb_ac_mutex);
			if (ndi_devi_online(child_dip, NDI_ONLINE_ATTACH) !=
			    NDI_SUCCESS) {
				USB_DPRINTF_L2(PRINT_MASK_ALL,
				    uacp->usb_ac_log_handle,
				    "failure to online driver %s%d",
				    ddi_driver_name(child_dip),
				    ddi_get_instance(child_dip));

				/* only onlining usb_as is fatal */
				if (strcmp(ddi_driver_name(child_dip),
				    "usb_as") == 0) {
					mutex_enter(&uacp->usb_ac_mutex);
					rval = USB_FAILURE;
					break;
				}
			}
			mutex_enter(&uacp->usb_ac_mutex);
		}
		child_dip = ddi_get_next_sibling(child_dip);
	}

	return (rval);
}


/*
 * hold all audio children before or after plumbing
 * online usb_as and hid, if not already
 */
static void
usb_ac_hold_siblings(usb_ac_state_t *uacp)
{
	int		circ;
	dev_info_t	*pdip, *child_dip;

	USB_DPRINTF_L4(PRINT_MASK_PM, uacp->usb_ac_log_handle,
	    "usb_ac_hold_siblings:");

	/* hold all siblings and ourselves */
	pdip = ddi_get_parent(uacp->usb_ac_dip);

	/* hold the children */
	ndi_devi_enter(pdip, &circ);
	child_dip = ddi_get_child(pdip);
	while (child_dip != NULL) {

		ndi_hold_devi(child_dip);

		USB_DPRINTF_L3(PRINT_MASK_PM, uacp->usb_ac_log_handle,
		    "usb_ac_hold_siblings: %s%d ref=%d",
		    ddi_driver_name(child_dip), ddi_get_instance(child_dip),
		    DEVI(child_dip)->devi_ref);

		child_dip = ddi_get_next_sibling(child_dip);
	}
	ndi_devi_exit(pdip, circ);
}


/*
 * release all audio children before or after plumbing
 */
static void
usb_ac_rele_siblings(usb_ac_state_t *uacp)
{
	int		circ;
	dev_info_t	*pdip, *child_dip;

	USB_DPRINTF_L4(PRINT_MASK_PM, uacp->usb_ac_log_handle,
	    "usb_ac_rele_siblings:");

	/* release all siblings and ourselves */
	pdip = ddi_get_parent(uacp->usb_ac_dip);
	ndi_devi_enter(pdip, &circ);
	child_dip = ddi_get_child(pdip);
	while (child_dip != NULL) {
		ndi_rele_devi(child_dip);
		USB_DPRINTF_L3(PRINT_MASK_PM, uacp->usb_ac_log_handle,
		    "usb_ac_rele_siblings: %s%d ref=%d",
		    ddi_driver_name(child_dip), ddi_get_instance(child_dip),
		    DEVI(child_dip)->devi_ref);
		child_dip = ddi_get_next_sibling(child_dip);
	}
	ndi_devi_exit(pdip, circ);
}
