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

/*
 *  Copyright (c) 2002-2005 Neterion, Inc.
 *  All right Reserved.
 *
 *  FileName :    xge.c
 *
 *  Description:  Xge main Solaris specific initialization & routines
 *		  for upper layer driver
 *
 */
#include "xgell.h"

static int xge_attach(dev_info_t *dev_info, ddi_attach_cmd_t cmd);
static int xge_detach(dev_info_t *dev_info, ddi_detach_cmd_t cmd);

DDI_DEFINE_STREAM_OPS(xge_ops, nulldev, nulldev, xge_attach, xge_detach,
    nodev, NULL, D_MP, NULL);

/* Standard Module linkage initialization for a Streams driver */
extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	XGELL_DESC,		/* short description */
	&xge_ops		/* driver specific ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, {(void *)&modldrv, NULL}
};

/* Xge device attributes */
ddi_device_acc_attr_t xge_dev_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};
ddi_device_acc_attr_t *p_xge_dev_attr = &xge_dev_attr;

/*
 * xge_event
 *
 * This function called by HAL to notify upper layer that some any
 * event been produced.
 */
void
xge_event(xge_queue_item_t *item)
{
	xgelldev_t *lldev = item->context;

	switch (item->event_type) {
	case XGELL_EVENT_RESCHED_NEEDED:
		if (lldev->is_initialized) {
			if (xge_hal_channel_dtr_count(lldev->fifo_channel)
			    >= XGELL_TX_LEVEL_HIGH) {
				mac_tx_update(lldev->mh);
				xge_debug_osdep(XGE_TRACE,
				    "mac_tx_update happened!");
			}
		}
		break;
	default:
		break;
	}
}

/*
 * xgell_callback_crit_err
 *
 * This function called by HAL on Serious Error event. XGE_HAL_EVENT_SERR.
 * Upper layer must analyze it based on %type.
 */
static void
xge_callback_crit_err(void *userdata, xge_hal_event_e type, u64 serr_data)
{
	(void) xgell_onerr_reset(userdata);
}

/*
 * xge_queue_produce context
 */
static void
xge_callback_event_queued(xge_hal_device_h devh, int event_type)
{
	if (event_type == XGELL_EVENT_RESCHED_NEEDED) {
		(void) taskq_dispatch(system_taskq, xge_device_poll_now, devh,
		    TQ_NOSLEEP);
	}
}

/*
 * xge_driver_init_hal
 *
 * To initialize HAL portion of driver.
 */
static xge_hal_status_e
xge_driver_init_hal(void)
{
	static xge_hal_driver_config_t driver_config;
	xge_hal_uld_cbs_t uld_callbacks;

	driver_config.queue_size_initial = 1;
	driver_config.queue_size_max = 4;

	uld_callbacks.link_up = xgell_callback_link_up;
	uld_callbacks.link_down = xgell_callback_link_down;
	uld_callbacks.crit_err = xge_callback_crit_err;
	uld_callbacks.event = xge_event;
	uld_callbacks.event_queued = xge_callback_event_queued;
	uld_callbacks.before_device_poll = NULL;
	uld_callbacks.after_device_poll = NULL;
	uld_callbacks.sched_timer = NULL;

	return (xge_hal_driver_initialize(&driver_config, &uld_callbacks));

}

/*
 * _init
 *
 * Solaris standard _init function for a device driver
 */
int
_init(void)
{
	int ret = 0;
	xge_hal_status_e status;

	status = xge_driver_init_hal();
	if (status != XGE_HAL_OK) {
		xge_debug_osdep(XGE_ERR, "can't initialize the driver (%d)",
		    status);
		return (EINVAL);
	}

	xge_hal_driver_debug_module_mask_set(0xffffffff);
	xge_hal_driver_debug_level_set(XGE_TRACE);

	mac_init_ops(&xge_ops, "xge");
	if ((ret = mod_install(&modlinkage)) != 0) {
		xge_hal_driver_terminate();
		mac_fini_ops(&xge_ops);
		xge_debug_osdep(XGE_ERR, "%s",
		    "Unable to install the driver");
		return (ret);
	}

	return (0);
}

/*
 * _fini
 *
 * Solaris standard _fini function for device driver
 */
int
_fini(void)
{
	int ret;

	ret = mod_remove(&modlinkage);
	if (ret == 0) {
		xge_hal_driver_terminate();
		mac_fini_ops(&xge_ops);
	}

	return (ret);
}

/*
 * _info
 *
 * Solaris standard _info function for device driver
 */
int
_info(struct modinfo *pModinfo)
{
	return (mod_info(&modlinkage, pModinfo));
}

/*
 * xge_isr
 * @arg: pointer to device private strucutre(hldev)
 *
 * This is the ISR scheduled by the OS to indicate to the
 * driver that the receive/transmit operation is completed.
 */
static uint_t
xge_isr(caddr_t arg)
{
	xge_hal_status_e status;
	xge_hal_device_t *hldev = (xge_hal_device_t *)arg;
	xgelldev_t *lldev = xge_hal_device_private(hldev);

	if (!lldev->is_initialized) {
		return (DDI_INTR_CLAIMED);
	}

	status = xge_hal_device_handle_irq(hldev);

	return ((status == XGE_HAL_ERR_WRONG_IRQ) ?
	    DDI_INTR_UNCLAIMED : DDI_INTR_CLAIMED);
}

/*
 * xge_configuration_init
 * @device_config: pointer to xge_hal_device_config_t
 *
 * This function will lookup properties from .conf file to init
 * the configuration data structure. If a property is not in .conf
 * file, the default value should be set.
 */
static void
xge_configuration_init(dev_info_t *dev_info,
    xge_hal_device_config_t *device_config, xgell_config_t *ll_config)
{
	/*
	 * Initialize common properties
	 */
	device_config->mtu = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, "default_mtu",
	    XGE_HAL_DEFAULT_INITIAL_MTU);
	device_config->isr_polling_cnt = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, "isr_polling_cnt",
	    XGE_HAL_DEFAULT_ISR_POLLING_CNT);
	device_config->latency_timer = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, "latency_timer",
	    XGE_HAL_DEFAULT_LATENCY_TIMER);
	device_config->max_splits_trans = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, "max_splits_trans",
	    XGE_HAL_DEFAULT_SPLIT_TRANSACTION);
	device_config->mmrb_count = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, "mmrb_count",
	    XGE_HAL_DEFAULT_MMRB_COUNT);
	device_config->shared_splits = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, "shared_splits",
	    XGE_HAL_DEFAULT_SHARED_SPLITS);
	device_config->stats_refresh_time_sec = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, "stats_refresh_time",
	    XGE_HAL_DEFAULT_STATS_REFRESH_TIME);
	device_config->device_poll_millis = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, "device_poll_millis",
	    XGE_HAL_DEFAULT_DEVICE_POLL_MILLIS);
	device_config->pci_freq_mherz = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, "pci_freq_mherz",
	    XGE_HAL_DEFAULT_USE_HARDCODE);

	/*
	 * Initialize ring properties
	 */
	device_config->ring.memblock_size = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, "ring_memblock_size",
	    XGE_HAL_DEFAULT_RING_MEMBLOCK_SIZE);
	device_config->ring.strip_vlan_tag = XGE_HAL_RING_DONOT_STRIP_VLAN_TAG;

#if defined(__sparc)
	device_config->ring.queue[XGELL_RING_MAIN_QID].no_snoop_bits = 1;
#endif
	device_config->ring.queue[XGELL_RING_MAIN_QID].max =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
		dev_info, DDI_PROP_DONTPASS, "ring_main_max",
		XGE_HAL_DEFAULT_USE_HARDCODE);
	device_config->ring.queue[XGELL_RING_MAIN_QID].initial =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
		dev_info, DDI_PROP_DONTPASS, "ring_main_initial",
		XGE_HAL_DEFAULT_USE_HARDCODE);
	if (device_config->ring.queue[XGELL_RING_MAIN_QID].initial ==
	    XGE_HAL_DEFAULT_USE_HARDCODE) {
		if (device_config->mtu > XGE_HAL_DEFAULT_MTU) {
			device_config->ring.queue[XGELL_RING_MAIN_QID].initial =
			    device_config->ring.queue[XGELL_RING_MAIN_QID].max =
			    XGE_HAL_DEFAULT_RING_QUEUE_BLOCKS_J;
		} else {
			device_config->ring.queue[XGELL_RING_MAIN_QID].initial =
			    device_config->ring.queue[XGELL_RING_MAIN_QID].max =
			    XGE_HAL_DEFAULT_RING_QUEUE_BLOCKS_N;
		}
	}
	device_config->ring.queue[XGELL_RING_MAIN_QID].buffer_mode =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
		dev_info, DDI_PROP_DONTPASS, "ring_main_buffer_mode",
		XGE_HAL_RING_QUEUE_BUFFER_MODE_DEFAULT);
	device_config->ring.queue[XGELL_RING_MAIN_QID].dram_size_mb =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
		dev_info, DDI_PROP_DONTPASS, "ring_main_dram_size_mb",
		XGE_HAL_DEFAULT_USE_HARDCODE);
	device_config->ring.queue[XGELL_RING_MAIN_QID].backoff_interval_us =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
		dev_info, DDI_PROP_DONTPASS, "ring_main_backoff_interval_us",
		XGE_HAL_DEFAULT_BACKOFF_INTERVAL_US);
	device_config->ring.queue[XGELL_RING_MAIN_QID].max_frm_len =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
		dev_info, DDI_PROP_DONTPASS, "ring_main_max_frm_len",
		XGE_HAL_RING_USE_MTU);
	device_config->ring.queue[XGELL_RING_MAIN_QID].priority =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
		dev_info, DDI_PROP_DONTPASS, "ring_main_priority",
		XGE_HAL_DEFAULT_RING_PRIORITY);
	device_config->ring.queue[XGELL_RING_MAIN_QID].configured =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
		dev_info, DDI_PROP_DONTPASS, "ring_main_configured",
		1);
	device_config->ring.queue[XGELL_RING_MAIN_QID].rti.urange_a =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
		dev_info, DDI_PROP_DONTPASS, "ring_main_urange_a",
		XGE_HAL_DEFAULT_RX_URANGE_A);
	device_config->ring.queue[XGELL_RING_MAIN_QID].rti.ufc_a =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
		dev_info, DDI_PROP_DONTPASS, "ring_main_ufc_a",
		XGE_HAL_DEFAULT_RX_UFC_A);
	device_config->ring.queue[XGELL_RING_MAIN_QID].rti.urange_b =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
		dev_info, DDI_PROP_DONTPASS, "ring_main_urange_b",
		XGE_HAL_DEFAULT_RX_URANGE_B);
	device_config->ring.queue[XGELL_RING_MAIN_QID].rti.ufc_b =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
		dev_info, DDI_PROP_DONTPASS, "ring_main_ufc_b",
		device_config->mtu > XGE_HAL_DEFAULT_MTU ?
			XGE_HAL_DEFAULT_RX_UFC_B_J :
			XGE_HAL_DEFAULT_RX_UFC_B_N);
	device_config->ring.queue[XGELL_RING_MAIN_QID].rti.urange_c =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
		dev_info, DDI_PROP_DONTPASS, "ring_main_urange_c",
		XGE_HAL_DEFAULT_RX_URANGE_C);
	device_config->ring.queue[XGELL_RING_MAIN_QID].rti.ufc_c =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
		dev_info, DDI_PROP_DONTPASS, "ring_main_ufc_c",
		device_config->mtu > XGE_HAL_DEFAULT_MTU ?
			XGE_HAL_DEFAULT_RX_UFC_C_J :
			XGE_HAL_DEFAULT_RX_UFC_C_N);
	device_config->ring.queue[XGELL_RING_MAIN_QID].rti.ufc_d =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
		dev_info, DDI_PROP_DONTPASS, "ring_main_ufc_d",
		XGE_HAL_DEFAULT_RX_UFC_D);
	device_config->ring.queue[XGELL_RING_MAIN_QID].rti.timer_val_us =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
		dev_info, DDI_PROP_DONTPASS, "ring_main_timer_val",
		XGE_HAL_DEFAULT_RX_TIMER_VAL);
	device_config->ring.queue[XGELL_RING_MAIN_QID].rti.timer_ac_en =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
		dev_info, DDI_PROP_DONTPASS, "ring_main_timer_ac_en",
		XGE_HAL_DEFAULT_RX_TIMER_AC_EN);
	device_config->ring.queue[XGELL_RING_MAIN_QID].indicate_max_pkts =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
		dev_info, DDI_PROP_DONTPASS, "ring_main_indicate_max_pkts",
		(device_config->bimodal_interrupts ?
			XGE_HAL_DEFAULT_INDICATE_MAX_PKTS_B :
			XGE_HAL_DEFAULT_INDICATE_MAX_PKTS_N));

	/*
	 * Initialize mac properties
	 */
	device_config->mac.tmac_util_period = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, "mac_tmac_util_period",
	    XGE_HAL_DEFAULT_TMAC_UTIL_PERIOD);
	device_config->mac.rmac_util_period = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, "mac_rmac_util_period",
	    XGE_HAL_DEFAULT_RMAC_UTIL_PERIOD);
	device_config->mac.rmac_bcast_en = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, "mac_rmac_bcast_en",
	    1); /* HAL never provide a good named macro */
	device_config->mac.rmac_pause_gen_en = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, "rmac_pause_gen_en",
	    XGE_HAL_DEFAULT_RMAC_PAUSE_GEN_DIS);
	device_config->mac.rmac_pause_rcv_en = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, "rmac_pause_rcv_en",
	    XGE_HAL_DEFAULT_RMAC_PAUSE_RCV_DIS);
	device_config->mac.rmac_pause_time = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, "mac_rmac_pause_time",
	    XGE_HAL_DEFAULT_RMAC_HIGH_PTIME);
	device_config->mac.mc_pause_threshold_q0q3 =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
		dev_info, DDI_PROP_DONTPASS, "mac_mc_pause_threshold_q0q3",
		XGE_HAL_DEFAULT_MC_PAUSE_THRESHOLD_Q0Q3);
	device_config->mac.mc_pause_threshold_q4q7 =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
		dev_info, DDI_PROP_DONTPASS, "mac_mc_pause_threshold_q4q7",
		XGE_HAL_DEFAULT_MC_PAUSE_THRESHOLD_Q4Q7);

	/*
	 * Initialize fifo properties
	 */
	device_config->fifo.max_frags = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, "fifo_max_frags",
	    XGE_HAL_DEFAULT_FIFO_FRAGS);
	if (device_config->fifo.max_frags == XGE_HAL_DEFAULT_USE_HARDCODE)
	    device_config->fifo.max_frags = XGE_HAL_DEFAULT_FIFO_FRAGS;
	device_config->fifo.reserve_threshold = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, "fifo_reserve_threshold",
	    XGE_HAL_DEFAULT_FIFO_RESERVE_THRESHOLD);
	device_config->fifo.memblock_size = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, "fifo_memblock_size",
	    XGE_HAL_DEFAULT_FIFO_MEMBLOCK_SIZE);
#ifdef XGE_HAL_ALIGN_XMIT
	device_config->fifo.alignment_size = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, "fifo_copied_frag_size",
	    XGE_HAL_DEFAULT_FIFO_ALIGNMENT_SIZE);
	device_config->fifo.max_aligned_frags = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, "fifo_copied_max_frags",
	    XGE_HAL_DEFAULT_FIFO_MAX_ALIGNED_FRAGS);
#endif
#if defined(__sparc)
	device_config->fifo.queue[0].no_snoop_bits = 1;
#endif
	device_config->fifo.queue[0].max = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, "fifo0_max",
	    XGE_HAL_DEFAULT_USE_HARDCODE);
	device_config->fifo.queue[0].initial = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, "fifo0_initial",
	    XGE_HAL_DEFAULT_USE_HARDCODE);
	if (device_config->fifo.queue[0].initial ==
	    XGE_HAL_DEFAULT_USE_HARDCODE) {
		if (device_config->mtu > XGE_HAL_DEFAULT_MTU) {
			device_config->fifo.queue[0].initial =
			    device_config->fifo.queue[0].max =
			    XGE_HAL_DEFAULT_FIFO_QUEUE_LENGTH_J;
		} else {
			device_config->fifo.queue[0].initial =
			    device_config->fifo.queue[0].max =
			    XGE_HAL_DEFAULT_FIFO_QUEUE_LENGTH_N;
		}
	}
	device_config->fifo.queue[0].intr = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, "fifo0_intr",
	    XGE_HAL_DEFAULT_FIFO_QUEUE_INTR);
	device_config->fifo.queue[0].configured =
	    ddi_prop_get_int(DDI_DEV_T_ANY, dev_info, DDI_PROP_DONTPASS,
		"fifo0_configured", 1);

	/*
	 * Bimodal Interrupts - TTI 56 configuration
	 */
	device_config->bimodal_interrupts = ddi_prop_get_int(
	    DDI_DEV_T_ANY, dev_info, DDI_PROP_DONTPASS, "bimodal_interrupts",
	    XGE_HAL_DEFAULT_BIMODAL_INTERRUPTS);
	device_config->bimodal_timer_lo_us = ddi_prop_get_int(
	    DDI_DEV_T_ANY, dev_info, DDI_PROP_DONTPASS, "bimodal_timer_lo_us",
	    XGE_HAL_DEFAULT_BIMODAL_TIMER_LO_US);
	device_config->bimodal_timer_hi_us = ddi_prop_get_int(
	    DDI_DEV_T_ANY, dev_info, DDI_PROP_DONTPASS, "bimodal_timer_hi_us",
	    XGE_HAL_DEFAULT_BIMODAL_TIMER_HI_US);

	/*
	 * TTI 0 configuration
	 */
	device_config->fifo.queue[0].tti[0].enabled = ddi_prop_get_int(
	    DDI_DEV_T_ANY, dev_info, DDI_PROP_DONTPASS, "tti_enable", 1);
	device_config->fifo.queue[0].tti[0].urange_a = ddi_prop_get_int(
	    DDI_DEV_T_ANY, dev_info, DDI_PROP_DONTPASS, "tti_urange_a",
	    XGE_HAL_DEFAULT_TX_URANGE_A);
	device_config->fifo.queue[0].tti[0].ufc_a = ddi_prop_get_int(
	    DDI_DEV_T_ANY, dev_info, DDI_PROP_DONTPASS, "tti_ufc_a",
	    XGE_HAL_DEFAULT_TX_UFC_A);
	device_config->fifo.queue[0].tti[0].urange_b = ddi_prop_get_int(
	    DDI_DEV_T_ANY, dev_info, DDI_PROP_DONTPASS, "tti_urange_b",
	    XGE_HAL_DEFAULT_TX_URANGE_B);
	device_config->fifo.queue[0].tti[0].ufc_b = ddi_prop_get_int(
	    DDI_DEV_T_ANY, dev_info, DDI_PROP_DONTPASS, "tti_ufc_b",
	    XGE_HAL_DEFAULT_TX_UFC_B);
	device_config->fifo.queue[0].tti[0].urange_c = ddi_prop_get_int(
	    DDI_DEV_T_ANY, dev_info, DDI_PROP_DONTPASS, "tti_urange_c",
	    XGE_HAL_DEFAULT_TX_URANGE_C);
	device_config->fifo.queue[0].tti[0].ufc_c = ddi_prop_get_int(
	    DDI_DEV_T_ANY, dev_info, DDI_PROP_DONTPASS, "tti_ufc_c",
	    XGE_HAL_DEFAULT_TX_UFC_C);
	device_config->fifo.queue[0].tti[0].ufc_d = ddi_prop_get_int(
	    DDI_DEV_T_ANY, dev_info, DDI_PROP_DONTPASS, "tti_ufc_d",
	    XGE_HAL_DEFAULT_TX_UFC_D);
	device_config->fifo.queue[0].tti[0].timer_ac_en = ddi_prop_get_int(
	    DDI_DEV_T_ANY, dev_info, DDI_PROP_DONTPASS, "tti_timer_ac_en",
	    XGE_HAL_DEFAULT_TX_TIMER_AC_EN);
	device_config->fifo.queue[0].tti[0].timer_val_us = ddi_prop_get_int(
	    DDI_DEV_T_ANY, dev_info, DDI_PROP_DONTPASS, "tti_timer_val",
	    XGE_HAL_DEFAULT_TX_TIMER_VAL);
	device_config->fifo.queue[0].tti[0].timer_ci_en = ddi_prop_get_int(
	    DDI_DEV_T_ANY, dev_info, DDI_PROP_DONTPASS, "tti_timer_ci_en",
	    XGE_HAL_DEFAULT_TX_TIMER_CI_EN);

	/*
	 * Initialize errors dumping
	 */
	device_config->dump_on_serr = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, "dump_on_serr",
	    0);
	device_config->dump_on_serr = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, "dump_on_eccerr",
	    0);
	device_config->dump_on_serr = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, "dump_on_parityerr",
	    0);

	/*
	 * LRO tunables
	 */
	device_config->lro_sg_size = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, "lro_sg_size",
	    XGE_HAL_DEFAULT_LRO_SG_SIZE);
	device_config->lro_frm_len = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, "lro_frm_len",
	    XGE_HAL_DEFAULT_LRO_FRM_LEN);

	/*
	 * Initialize link layer configuration
	 */
	ll_config->rx_buffer_total = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, "rx_buffer_total",
	    device_config->ring.queue[XGELL_RING_MAIN_QID].initial *
					XGELL_RX_BUFFER_TOTAL);
	ll_config->rx_buffer_post_hiwat = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, "rx_buffer_post_hiwat",
	    device_config->ring.queue[XGELL_RING_MAIN_QID].initial *
					XGELL_RX_BUFFER_POST_HIWAT);
	ll_config->rx_pkt_burst = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, "rx_pkt_burst",
	    XGELL_RX_PKT_BURST);
	ll_config->rx_dma_lowat = ddi_prop_get_int(DDI_DEV_T_ANY, dev_info,
	    DDI_PROP_DONTPASS, "rx_dma_lowat", XGELL_RX_DMA_LOWAT);
	ll_config->tx_dma_lowat = ddi_prop_get_int(DDI_DEV_T_ANY, dev_info,
	    DDI_PROP_DONTPASS, "tx_dma_lowat", XGELL_TX_DMA_LOWAT);
	ll_config->msi_enable = ddi_prop_get_int(DDI_DEV_T_ANY, dev_info,
	    DDI_PROP_DONTPASS, "msi_enable", XGELL_CONF_ENABLE_BY_DEFAULT);
	ll_config->lso_enable = ddi_prop_get_int(DDI_DEV_T_ANY, dev_info,
	    DDI_PROP_DONTPASS, "lso_enable", XGELL_CONF_ENABLE_BY_DEFAULT);
}

/*
 * xge_attach
 * @dev_info: pointer to dev_info_t structure
 * @cmd: attach command to process
 *
 * This is a solaris standard attach function.  This
 * function initializes the Xframe  identified
 * by the dev_info_t structure and setup the driver
 * data structures corresponding to the Xframe Card.
 * This function also registers the XFRAME device
 * instance with the MAC Layer.
 * If this function returns success then the OS
 * will attach the HBA controller to this
 * driver.
 */
static int
xge_attach(dev_info_t *dev_info, ddi_attach_cmd_t cmd)
{
	xgelldev_t *ll;
	xge_hal_device_config_t device_config;
	xge_hal_device_t *hldev;
	xge_hal_device_attr_t attr;
	xge_hal_status_e status;
	xgell_config_t ll_config;
	int ret;

	xge_debug_osdep(XGE_TRACE, "XGE_ATTACH cmd %d", cmd);

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
	case DDI_PM_RESUME:
		xge_debug_osdep(XGE_ERR, "%s", "resume unsupported yet");
		ret = DDI_FAILURE;
		goto _exit0;

	default:
		xge_debug_osdep(XGE_ERR, "cmd 0x%x unrecognized", cmd);
		ret = DDI_FAILURE;
		goto _exit0;
	}

	xge_os_memzero(&device_config, sizeof (xge_hal_device_config_t));

	/* Init device_config by lookup up properties from .conf file */
	xge_configuration_init(dev_info, &device_config, &ll_config);

	/* map BAR0 */
	ret = ddi_regs_map_setup(dev_info, 1, (caddr_t *)&attr.bar0,
	    (offset_t)0, (offset_t)0, &xge_dev_attr, &attr.regh0);
	if (ret != DDI_SUCCESS) {
		xge_debug_osdep(XGE_ERR, "unable to map bar0: [%d]", ret);
		goto _exit0;
	}

	/* map BAR1 */
	ret = ddi_regs_map_setup(dev_info, 2, (caddr_t *)&attr.bar1,
	    (offset_t)0, (offset_t)0, &xge_dev_attr, &attr.regh1);
	if (ret != DDI_SUCCESS) {
		xge_debug_osdep(XGE_ERR, "unable to map bar1: [%d]", ret);
		goto _exit1;
	}

	/* preallocate memory for new HAL device and private LL part */
	hldev = kmem_zalloc(sizeof (xge_hal_device_t), KM_SLEEP);
	if (hldev == NULL) {
		xge_debug_osdep(XGE_ERR, "%s", "can not allocate memory");
		ret = DDI_ENOMEM;
		goto _exit2;
	}

	/* get the interrupt block cookie associated with the interrupt */
	ret = ddi_get_iblock_cookie(dev_info, 0, &attr.irqh);
	if (ret != DDI_SUCCESS) {
		xge_debug_osdep(XGE_ERR, "%s", "can not get interrupt cookie");
		goto _exit2a;
	}

	/* Get the PCI Configuartion space handle */
	ret = pci_config_setup(dev_info, &attr.cfgh);
	if (ret != DDI_SUCCESS) {
		xge_debug_osdep(XGE_ERR, "%s", "can not setup config space");
		goto _exit2a;
	}

	attr.pdev = dev_info;

	ret = xgell_device_alloc(hldev, dev_info, &ll);
	if (ret != DDI_SUCCESS) {
		xge_debug_osdep(XGE_ERR,
		    "%s",
		    "unable to allocate new LL device");
		goto _exit3;
	}

	/* attach an interrupt handler for handling Xge device interrupts */
	ret = ddi_add_intr(dev_info, 0, &attr.irqh, NULL, xge_isr,
	    (caddr_t)hldev);
	if (ret != DDI_SUCCESS) {
		xge_debug_osdep(XGE_ERR, "%s", "unable to register ISR");
		goto _exit3a;
	}

	/* initialize HW */
	status = xge_hal_device_initialize(hldev, &attr, &device_config);
	if (status != XGE_HAL_OK) {
		switch (status) {
		case XGE_HAL_ERR_DRIVER_NOT_INITIALIZED:
			xge_debug_osdep(XGE_ERR, "%s",
			    "driver is not initialized");
			ret = DDI_FAILURE;
			goto _exit3b;
		case XGE_HAL_ERR_DEVICE_IS_NOT_QUIESCENT:
			xge_debug_osdep(XGE_ERR, "%s",
			    "device is not quiescent");
			ret = DDI_EBUSY;
			goto _exit3b;
		case XGE_HAL_ERR_OUT_OF_MEMORY:
			xge_debug_osdep(XGE_ERR, "%s",
			    "unable to allocate memory");
			ret = DDI_ENOMEM;
			goto _exit3b;
		default:
			xge_debug_osdep(XGE_ERR,
			    "can't initialize the device: %d", status);
			ret = DDI_FAILURE;
			goto _exit3b;
		}
	}

	/* allocate and register Link Layer */
	ret = xgell_device_register(ll, &ll_config);
	if (ret != DDI_SUCCESS) {
		goto _exit4;
	}

	/* store ll as a HAL private part */
	xge_hal_device_private_set(hldev, ll);

	return (DDI_SUCCESS);

_exit4:
	xge_hal_device_terminate(hldev);
_exit3b:
	ddi_remove_intr(attr.pdev, 0, hldev->irqh);
_exit3a:
	xgell_device_free(ll);
_exit3:
	pci_config_teardown(&attr.cfgh);
_exit2a:
	kmem_free(hldev, sizeof (xge_hal_device_t));
_exit2:
	ddi_regs_map_free(&attr.regh1);
_exit1:
	ddi_regs_map_free(&attr.regh0);
_exit0:
	return (ret);
}

/*
 * xge_detach
 * @dev_info: pointer to dev_info_t structure
 * @cmd: attach command to process
 *
 * This function is called by OS when the system is about
 * to shutdown or when the super user tries to unload
 * the driver. This function frees all the memory allocated
 * during xge_attch() and also unregisters the Xframe
 * device instance from the GLD framework.
 */
static int
xge_detach(dev_info_t *dev_info, ddi_detach_cmd_t cmd)
{
	xge_hal_device_t *hldev;
	xge_hal_device_attr_t *attr;
	xgelldev_t *lldev;

	xge_debug_osdep(XGE_TRACE, "XGE_DETACH cmd %d", cmd);

	hldev = (xge_hal_device_t *)ddi_get_driver_private(dev_info);
	attr = xge_hal_device_attr(hldev);
	lldev = xge_hal_device_private(hldev);

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_PM_SUSPEND:
		xge_debug_osdep(XGE_ERR, "%s", "suspend unsupported yet");
		return (DDI_FAILURE);

	default:
		xge_debug_osdep(XGE_ERR, "cmd 0x%x unrecognized", cmd);
		return (DDI_FAILURE);
	}

	if (lldev->is_initialized) {
		xge_debug_osdep(XGE_ERR, "%s",
		    "can not detach: device is not unplumbed");
		return (DDI_FAILURE);
	}

	xge_hal_device_terminating(hldev);
	if (xgell_device_unregister(lldev) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	xge_hal_device_terminate(hldev);

	ddi_remove_intr(attr->pdev, 0, attr->irqh);
	xgell_device_free(lldev);
	pci_config_teardown(&attr->cfgh);
	ddi_regs_map_free(&attr->regh1);
	ddi_regs_map_free(&attr->regh0);
	kmem_free(hldev, sizeof (xge_hal_device_t));

	return (DDI_SUCCESS);
}
