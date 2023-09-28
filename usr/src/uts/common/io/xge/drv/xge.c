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
static int xge_quiesce(dev_info_t *dev_info);

DDI_DEFINE_STREAM_OPS(xge_ops, nulldev, nulldev, xge_attach, xge_detach,
    nodev, NULL, D_MP, NULL, xge_quiesce);

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
 * xge_xpak_alarm_log
 * This function called by HAL on XPAK alarms. Upper layer must log the msg
 * based on the xpak alarm type
 */
static void
xge_xpak_alarm_log(void *userdata, xge_hal_xpak_alarm_type_e type)
{
	switch (type) {
	case XGE_HAL_XPAK_ALARM_EXCESS_TEMP:
		xge_debug_osdep(XGE_ERR, "%s", "Take Xframe NIC out of "
		    "service. Excessive temperatures may result in "
		    "premature transceiver failure \n");

		break;
	case XGE_HAL_XPAK_ALARM_EXCESS_BIAS_CURRENT:
		xge_debug_osdep(XGE_ERR, "%s", "Take Xframe NIC out of "
		    "service Excessive bias currents may indicate "
		    "imminent laser diode failure \n");

		break;
	case XGE_HAL_XPAK_ALARM_EXCESS_LASER_OUTPUT:
		xge_debug_osdep(XGE_ERR, "%s", "Take Xframe NIC out of "
		    "service Excessive laser output power may saturate "
		    "far-end receiver\n");

		break;
	default:
		xge_debug_osdep(XGE_ERR, "%s", "Undefined Xpak Alarm");
		break;
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
	uld_callbacks.event = NULL;
	uld_callbacks.event_queued = NULL;
	uld_callbacks.before_device_poll = NULL;
	uld_callbacks.after_device_poll = NULL;
	uld_callbacks.sched_timer = NULL;
	uld_callbacks.xpak_alarm_log = xge_xpak_alarm_log;

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
/* ARGSUSED */
static uint_t
xge_isr(caddr_t arg0, caddr_t arg1)
{
	xge_hal_status_e status;
	xge_hal_device_t *hldev = (xge_hal_device_t *)arg0;
	xgelldev_t *lldev = xge_hal_device_private(hldev);

	if (!lldev->is_initialized) {
		return (DDI_INTR_UNCLAIMED);
	}

	status = xge_hal_device_handle_irq(hldev);

	return ((status == XGE_HAL_ERR_WRONG_IRQ) ?
	    DDI_INTR_UNCLAIMED : DDI_INTR_CLAIMED);
}

/*
 * Interrupt handler for transmit when MSI-X interrupt mechasnism is used
 */
/* ARGSUSED */
static uint_t
xge_fifo_msix_isr(caddr_t arg0, caddr_t arg1)
{
	int got_tx;
	xge_hal_channel_t *channel = (xge_hal_channel_t *)arg0;
	xgelldev_t *lldev = xge_hal_device_private(channel->devh);

	if (!lldev->is_initialized) {
		return (DDI_INTR_UNCLAIMED);
	}
	(void) xge_hal_device_poll_tx_channel(channel, &got_tx);

	return (DDI_INTR_CLAIMED);
}

/*
 * Interrupt handler for receive when MSI-X interrupt mechasnism is used
 */
/* ARGSUSED */
static uint_t
xge_ring_msix_isr(caddr_t arg0, caddr_t arg1)
{
	int got_rx;
	xge_hal_channel_t *channel = (xge_hal_channel_t *)arg0;
	xgelldev_t *lldev = xge_hal_device_private(channel->devh);

	if (!lldev->is_initialized) {
		return (DDI_INTR_UNCLAIMED);
	}
	(void) xge_hal_device_poll_rx_channel(channel, &got_rx);

	return (DDI_INTR_CLAIMED);
}

/*
 * Configure single ring
 */
static void
xge_ring_config(dev_info_t *dev_info, xge_hal_device_config_t *device_config,
    int index)
{
	char msg[MSG_SIZE];

	(void) xge_os_snprintf(msg, MSG_SIZE, "ring%d_configured", index);
	device_config->ring.queue[index].configured =
	    ddi_prop_get_int(DDI_DEV_T_ANY, dev_info, DDI_PROP_DONTPASS,
	    msg, index < XGELL_RX_RING_NUM_MAX ? 1 : 0);

	/* no point to configure it further if unconfigured */
	if (!device_config->ring.queue[index].configured)
		return;

#if defined(__sparc)
	device_config->ring.queue[index].no_snoop_bits = 1;
#endif

	(void) xge_os_snprintf(msg, MSG_SIZE, "ring%d_max", index);
	device_config->ring.queue[index].max =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, msg,
	    XGE_HAL_DEFAULT_USE_HARDCODE);

	(void) xge_os_snprintf(msg, MSG_SIZE, "ring%d_initial", index);
	device_config->ring.queue[index].initial =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, msg,
	    XGE_HAL_DEFAULT_USE_HARDCODE);

	if (device_config->ring.queue[index].initial ==
	    XGE_HAL_DEFAULT_USE_HARDCODE) {
		device_config->ring.queue[index].initial =
		    device_config->ring.queue[index].max =
		    XGE_HAL_DEFAULT_RING_QUEUE_BLOCKS;
	}

	(void) xge_os_snprintf(msg, MSG_SIZE, "ring%d_buffer_mode", index);
	device_config->ring.queue[index].buffer_mode =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, msg,
	    XGE_HAL_RING_QUEUE_BUFFER_MODE_DEFAULT);

	(void) xge_os_snprintf(msg, MSG_SIZE, "ring%d_dram_size_mb", index);
	device_config->ring.queue[index].dram_size_mb =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, msg,
	    XGE_HAL_DEFAULT_USE_HARDCODE);

	(void) xge_os_snprintf(msg, MSG_SIZE,
	    "ring%d_backoff_interval_us", index);
	device_config->ring.queue[index].backoff_interval_us =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, msg,
	    XGE_HAL_DEFAULT_BACKOFF_INTERVAL_US);

	(void) xge_os_snprintf(msg, MSG_SIZE, "ring%d_max_frm_len", index);
	device_config->ring.queue[index].max_frm_len =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, msg,
	    XGE_HAL_RING_USE_MTU);


	(void) xge_os_snprintf(msg, MSG_SIZE, "ring%d_priority", index);
	device_config->ring.queue[index].priority =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, msg,
	    XGE_HAL_DEFAULT_RING_PRIORITY);

	(void) xge_os_snprintf(msg, MSG_SIZE, "ring%d_urange_a", index);
	device_config->ring.queue[index].rti.urange_a =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, msg,
	    XGE_HAL_DEFAULT_RX_URANGE_A);

	(void) xge_os_snprintf(msg, MSG_SIZE, "ring%d_ufc_a", index);
	device_config->ring.queue[index].rti.ufc_a =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, msg,
	    XGE_HAL_DEFAULT_RX_UFC_A);

	(void) xge_os_snprintf(msg, MSG_SIZE, "ring%d_urange_b", index);
	device_config->ring.queue[index].rti.urange_b =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, msg,
	    XGE_HAL_DEFAULT_RX_URANGE_B);

	(void) xge_os_snprintf(msg, MSG_SIZE, "ring%d_ufc_b", index);
	device_config->ring.queue[index].rti.ufc_b =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, msg,
	    device_config->mtu > XGE_HAL_DEFAULT_MTU ?
	    XGE_HAL_DEFAULT_RX_UFC_B_J:
	    XGE_HAL_DEFAULT_RX_UFC_B_N);

	(void) xge_os_snprintf(msg, MSG_SIZE, "ring%d_urange_c", index);
	device_config->ring.queue[index].rti.urange_c =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, msg,
	    XGE_HAL_DEFAULT_RX_URANGE_C);

	(void) xge_os_snprintf(msg, MSG_SIZE, "ring%d_ufc_c", index);
	device_config->ring.queue[index].rti.ufc_c =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, msg,
	    device_config->mtu > XGE_HAL_DEFAULT_MTU ?
	    XGE_HAL_DEFAULT_RX_UFC_C_J:
	    XGE_HAL_DEFAULT_RX_UFC_C_N);

	(void) xge_os_snprintf(msg, MSG_SIZE, "ring%d_ufc_d", index);
	device_config->ring.queue[index].rti.ufc_d =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, msg,
	    XGE_HAL_DEFAULT_RX_UFC_D);

	(void) xge_os_snprintf(msg, MSG_SIZE, "ring%d_timer_val", index);
	device_config->ring.queue[index].rti.timer_val_us =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, msg,
	    XGE_HAL_DEFAULT_RX_TIMER_VAL);

	(void) xge_os_snprintf(msg, MSG_SIZE, "ring%d_timer_ac_en", index);
	device_config->ring.queue[index].rti.timer_ac_en =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, msg,
	    XGE_HAL_DEFAULT_RX_TIMER_AC_EN);

	(void) xge_os_snprintf(msg, MSG_SIZE, "ring%d_indicate_max_pkts",
	    index);
	device_config->ring.queue[index].indicate_max_pkts =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, msg,
	    (device_config->bimodal_interrupts ?
	    XGE_HAL_DEFAULT_INDICATE_MAX_PKTS_B :
	    XGE_HAL_DEFAULT_INDICATE_MAX_PKTS_N));

	/*
	 * Enable RTH steering if needed HERE!!!!
	 */
	if (device_config->rth_en == XGE_HAL_RTH_ENABLE)
		device_config->ring.queue[index].rth_en = 1;
}

/*
 * Configure single fifo
 */
static void
xge_fifo_config(dev_info_t *dev_info, xge_hal_device_config_t *device_config,
    int index)
{
	char msg[MSG_SIZE];

	(void) xge_os_snprintf(msg, MSG_SIZE, "fifo%d_configured", index);
	device_config->fifo.queue[index].configured =
	    ddi_prop_get_int(DDI_DEV_T_ANY, dev_info, DDI_PROP_DONTPASS,
	    msg, index < XGELL_TX_RING_NUM_MAX ? 1 : 0);

	/* no point to configure it further */
	if (!device_config->fifo.queue[index].configured)
		return;

#if defined(__sparc)
	device_config->fifo.queue[index].no_snoop_bits = 1;
#endif

	(void) xge_os_snprintf(msg, MSG_SIZE, "fifo%d_max", index);
	device_config->fifo.queue[index].max = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, msg,
	    XGE_HAL_DEFAULT_USE_HARDCODE);

	(void) xge_os_snprintf(msg, MSG_SIZE, "fifo%d_initial", index);
	device_config->fifo.queue[index].initial =
	    ddi_prop_get_int(DDI_DEV_T_ANY, dev_info, DDI_PROP_DONTPASS, msg,
	    XGE_HAL_DEFAULT_USE_HARDCODE);

#if 0
	if (device_config->fifo.queue[index].initial ==
	    XGE_HAL_DEFAULT_USE_HARDCODE) {
		if (device_config->mtu > XGE_HAL_DEFAULT_MTU) {
			device_config->fifo.queue[index].initial =
			    device_config->fifo.queue[index].max =
			    XGE_HAL_DEFAULT_FIFO_QUEUE_LENGTH_J;
		} else {
			device_config->fifo.queue[index].initial =
			    device_config->fifo.queue[index].max =
			    XGE_HAL_DEFAULT_FIFO_QUEUE_LENGTH_N;
		}
	}
#else
	if (device_config->fifo.queue[index].initial ==
	    XGE_HAL_DEFAULT_USE_HARDCODE) {
		device_config->fifo.queue[index].max =
		    device_config->fifo.queue[index].initial =
		    XGE_HAL_DEFAULT_FIFO_QUEUE_LENGTH_A;
	}
#endif

	(void) xge_os_snprintf(msg, MSG_SIZE, "fifo%d_intr", index);
	device_config->fifo.queue[index].intr = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, msg,
	    XGE_HAL_DEFAULT_FIFO_QUEUE_INTR);

	/*
	 * TTI 0 configuration
	 */
	(void) xge_os_snprintf(msg, MSG_SIZE, "fifo%d_tti_enable", index);
	device_config->fifo.queue[index].tti[index].enabled = ddi_prop_get_int(
	    DDI_DEV_T_ANY, dev_info, DDI_PROP_DONTPASS, msg, 1);

	(void) xge_os_snprintf(msg, MSG_SIZE, "fifo%d_tti_urange_a", index);
	device_config->fifo.queue[index].tti[index].urange_a = ddi_prop_get_int(
	    DDI_DEV_T_ANY, dev_info, DDI_PROP_DONTPASS, msg,
	    XGE_HAL_DEFAULT_TX_URANGE_A);

	(void) xge_os_snprintf(msg, MSG_SIZE, "fifo%d_tti_ufc_a", index);
	device_config->fifo.queue[index].tti[index].ufc_a = ddi_prop_get_int(
	    DDI_DEV_T_ANY, dev_info, DDI_PROP_DONTPASS, msg,
	    XGE_HAL_DEFAULT_TX_UFC_A);

	(void) xge_os_snprintf(msg, MSG_SIZE, "fifo%d_tti_urange_b", index);
	device_config->fifo.queue[index].tti[index].urange_b = ddi_prop_get_int(
	    DDI_DEV_T_ANY, dev_info, DDI_PROP_DONTPASS, msg,
	    XGE_HAL_DEFAULT_TX_URANGE_B);

	(void) xge_os_snprintf(msg, MSG_SIZE, "fifo%d_tti_ufc_b", index);
	device_config->fifo.queue[index].tti[index].ufc_b = ddi_prop_get_int(
	    DDI_DEV_T_ANY, dev_info, DDI_PROP_DONTPASS, msg,
	    XGE_HAL_DEFAULT_TX_UFC_B);

	(void) xge_os_snprintf(msg, MSG_SIZE, "fifo%d_tti_urange_c", index);
	device_config->fifo.queue[index].tti[index].urange_c = ddi_prop_get_int(
	    DDI_DEV_T_ANY, dev_info, DDI_PROP_DONTPASS, msg,
	    XGE_HAL_DEFAULT_TX_URANGE_C);

	(void) xge_os_snprintf(msg, MSG_SIZE, "fifo%d_tti_ufc_c", index);
	device_config->fifo.queue[index].tti[index].ufc_c = ddi_prop_get_int(
	    DDI_DEV_T_ANY, dev_info, DDI_PROP_DONTPASS, msg,
	    XGE_HAL_DEFAULT_TX_UFC_C);

	(void) xge_os_snprintf(msg, MSG_SIZE, "fifo%d_tti_ufc_d", index);
	device_config->fifo.queue[index].tti[index].ufc_d = ddi_prop_get_int(
	    DDI_DEV_T_ANY, dev_info, DDI_PROP_DONTPASS, msg,
	    XGE_HAL_DEFAULT_TX_UFC_D);

	(void) xge_os_snprintf(msg, MSG_SIZE, "fifo%d_timer_ac_en", index);
	device_config->fifo.queue[index].tti[index].timer_ac_en =
	    ddi_prop_get_int(DDI_DEV_T_ANY, dev_info, DDI_PROP_DONTPASS, msg,
	    XGE_HAL_DEFAULT_TX_TIMER_AC_EN);

	(void) xge_os_snprintf(msg, MSG_SIZE, "fifo%d_tti_timer_val", index);
	device_config->fifo.queue[index].tti[index].timer_val_us =
	    ddi_prop_get_int(DDI_DEV_T_ANY, dev_info, DDI_PROP_DONTPASS, msg,
	    XGE_HAL_DEFAULT_TX_TIMER_VAL);

	(void) xge_os_snprintf(msg, MSG_SIZE, "fifo%d_tti_timer_ci_en", index);
	device_config->fifo.queue[index].tti[index].timer_ci_en =
	    ddi_prop_get_int(DDI_DEV_T_ANY, dev_info, DDI_PROP_DONTPASS, msg,
	    XGE_HAL_DEFAULT_TX_TIMER_CI_EN);
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
    xge_hal_device_config_t *device_config, xgell_config_t *xgell_config)
{
	int i, rings_configured = 0, fifos_configured = 0;

	/*
	 * Initialize link layer configuration first
	 */
	xgell_config->rx_dma_lowat = ddi_prop_get_int(DDI_DEV_T_ANY, dev_info,
	    DDI_PROP_DONTPASS, "rx_dma_lowat", XGELL_RX_DMA_LOWAT);
	xgell_config->rx_pkt_burst = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, "rx_pkt_burst", XGELL_RX_PKT_BURST);
	xgell_config->tx_dma_lowat = ddi_prop_get_int(DDI_DEV_T_ANY, dev_info,
	    DDI_PROP_DONTPASS, "tx_dma_lowat", XGELL_TX_DMA_LOWAT);
	xgell_config->lso_enable = ddi_prop_get_int(DDI_DEV_T_ANY, dev_info,
	    DDI_PROP_DONTPASS, "lso_enable", XGELL_CONF_ENABLE_BY_DEFAULT);
	xgell_config->msix_enable = ddi_prop_get_int(DDI_DEV_T_ANY, dev_info,
	    DDI_PROP_DONTPASS, "msix_enable", XGELL_CONF_ENABLE_BY_DEFAULT);

	xgell_config->grouping = ddi_prop_get_int(DDI_DEV_T_ANY, dev_info,
	    DDI_PROP_DONTPASS, "grouping", XGELL_CONF_GROUP_POLICY_DEFAULT);

	switch (xgell_config->grouping) {
	case XGELL_CONF_GROUP_POLICY_VIRT:
		/*
		 * Enable layer 2 steering for better virtualization
		 */
		device_config->rth_en = XGE_HAL_RTH_DISABLE;
		device_config->rts_mac_en = XGE_HAL_RTS_MAC_ENABLE;
		break;
	case XGELL_CONF_GROUP_POLICY_PERF:
		/*
		 * Configure layer 4 RTH to hashing inbound traffic
		 */
		device_config->rth_en = XGE_HAL_RTH_ENABLE;
		device_config->rth_bucket_size = XGE_HAL_MAX_RTH_BUCKET_SIZE;
		device_config->rth_spdm_en = XGE_HAL_RTH_SPDM_DISABLE;
		device_config->rth_spdm_use_l4 = XGE_HAL_RTH_SPDM_USE_L4;

		device_config->rts_mac_en = XGE_HAL_RTS_MAC_DISABLE;
		break;
	case XGELL_CONF_GROUP_POLICY_BASIC:
	default:
		/*
		 * Disable both RTS and RTH for single ring configuration
		 */
		device_config->rth_en = XGE_HAL_RTH_DISABLE;
		device_config->rts_mac_en = XGE_HAL_RTS_MAC_DISABLE;
		break;
	}

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
	 * Go through all possibly configured rings. Each ring could be
	 * configured individually. To enable/disable specific ring, just
	 * set ring->configured = [1|0].
	 *
	 * By default *all* rings enabled.
	 */
	for (i = 0; i < XGE_HAL_MAX_RING_NUM; i++) {
		xge_ring_config(dev_info, device_config, i);
		if (device_config->ring.queue[i].configured)
			rings_configured++;
	}

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

	/*
	 * Go through all possibly configured fifos. Each fifo could be
	 * configured individually. To enable/disable specific fifo, just
	 * set fifo->configured = [0|1].
	 *
	 * By default *all* fifos enabled.
	 */
	for (i = 0; i < XGE_HAL_MAX_FIFO_NUM; i++) {
		xge_fifo_config(dev_info, device_config, i);
		if (device_config->fifo.queue[i].configured)
			fifos_configured++;
	}

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
	 * Initialize other link layer configuration first
	 */
	xgell_config->rx_buffer_total = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, "rx_buffer_total",
	    device_config->ring.queue[XGELL_RX_RING_MAIN].initial *
	    XGELL_RX_BUFFER_TOTAL);
	xgell_config->rx_buffer_total += XGELL_RX_BUFFER_RECYCLE_CACHE;
	xgell_config->rx_buffer_post_hiwat = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dev_info, DDI_PROP_DONTPASS, "rx_buffer_post_hiwat",
	    device_config->ring.queue[XGELL_RX_RING_MAIN].initial *
	    XGELL_RX_BUFFER_POST_HIWAT);
	xgell_config->rx_buffer_post_hiwat += XGELL_RX_BUFFER_RECYCLE_CACHE;
}

/*
 * xge_alloc_intrs:
 *
 * Allocate FIXED or MSIX interrupts.
 */
static int
xge_alloc_intrs(xgelldev_t *lldev)
{
	dev_info_t *dip = lldev->dev_info;
	int avail, actual, count = 0;
	int i, intr_behavior, ret;

	if (lldev->intr_type == DDI_INTR_TYPE_MSIX) {
		intr_behavior = DDI_INTR_ALLOC_STRICT;
		(void) ddi_prop_create(DDI_DEV_T_NONE, dip,
		    DDI_PROP_CANSLEEP, "#msix-request", NULL, 0);
	} else {
		intr_behavior = DDI_INTR_ALLOC_NORMAL;
	}

	/* Get number of interrupts */
	ret = ddi_intr_get_nintrs(dip, lldev->intr_type, &count);
	if ((ret != DDI_SUCCESS) || (count == 0)) {
		xge_debug_osdep(XGE_ERR, "ddi_intr_get_nintrs() failed, "
		    "ret: %d, count: %d", ret, count);

		goto _err_exit0;
	}

	/* Get number of available interrupts */
	ret = ddi_intr_get_navail(dip, lldev->intr_type, &avail);
	if ((ret != DDI_SUCCESS) || (avail == 0)) {
		xge_debug_osdep(XGE_ERR, "ddi_intr_get_navail() failure, "
		    "ret: %d, avail: %d", ret, avail);

		goto _err_exit0;
	}

	if (avail < lldev->intr_cnt) {
		xge_debug_osdep(XGE_ERR, "%d interrupts wanted while only "
		    "%d available", lldev->intr_cnt, avail);
		goto _err_exit0;
	}

	/* Allocate an array of interrupt handles */
	lldev->intr_table_size = lldev->intr_cnt * sizeof (ddi_intr_handle_t);
	lldev->intr_table = kmem_alloc(lldev->intr_table_size, KM_SLEEP);

	/* Call ddi_intr_alloc() */
	ret = ddi_intr_alloc(dip, lldev->intr_table, lldev->intr_type, 0,
	    lldev->intr_cnt, &actual, intr_behavior);
	if ((ret != DDI_SUCCESS) || (actual == 0)) {
		xge_debug_osdep(XGE_ERR, "ddi_intr_alloc() failed %d", ret);
		goto _err_exit1;
	}

	xge_debug_osdep(XGE_TRACE, "%s: Requested: %d, Granted: %d",
	    lldev->intr_type == DDI_INTR_TYPE_MSIX ? "MSI-X" :
	    "IRQA", count, actual);

	if (lldev->intr_cnt != actual) {
		xge_debug_osdep(XGE_ERR, "Not enough resources granted");
		goto _err_exit2;
	}

	/*
	 * Get priority for first msi, assume remaining are all the same
	 */
	if ((ret = ddi_intr_get_pri(lldev->intr_table[0], &lldev->intr_pri)) !=
	    DDI_SUCCESS) {
		xge_debug_osdep(XGE_ERR, "ddi_intr_get_pri() failed %d", ret);
		goto _err_exit2;
	}

	return (DDI_SUCCESS);

_err_exit2:
	/* Free already allocated intr */
	for (i = 0; i < actual; i++) {
		(void) ddi_intr_free(lldev->intr_table[i]);
	}
_err_exit1:
	kmem_free(lldev->intr_table, lldev->intr_table_size);
	lldev->intr_table = NULL;
_err_exit0:
	if (lldev->intr_type == DDI_INTR_TYPE_MSIX)
		(void) ddi_prop_remove(DDI_DEV_T_NONE, dip, "#msix-request");
	return (DDI_FAILURE);
}

/*
 * xge_free_intrs:
 *
 * Free previously allocated interrupts.
 */
static void
xge_free_intrs(xgelldev_t *lldev)
{
	int i;
	dev_info_t *dip = lldev->dev_info;

	/* Free already allocated intr */
	for (i = 0; i < lldev->intr_cnt; i++) {
		(void) ddi_intr_free(lldev->intr_table[i]);
	}
	kmem_free(lldev->intr_table, lldev->intr_table_size);
	lldev->intr_table = NULL;

	if (lldev->intr_type == DDI_INTR_TYPE_MSIX)
		(void) ddi_prop_remove(DDI_DEV_T_NONE, dip, "#msix-request");
}

/*
 * xge_add_intrs:
 *
 * Register FIXED or MSI interrupts.
 */
int
xge_add_intrs(xgelldev_t *lldev)
{
	int i, ret;
	xge_hal_device_t *hldev = lldev->devh;
	xge_hal_device_config_t *hal_conf = &hldev->config;
	xge_hal_ring_config_t *ring_conf = &hal_conf->ring;
	xge_hal_fifo_config_t *fifo_conf = &hal_conf->fifo;
	xge_list_t *item;
	int msix_idx = 1; /* 0 by default is reserved for Alarms. */
	xge_hal_channel_t *assigned[XGELL_RX_RING_NUM_MAX +
	    XGELL_TX_RING_NUM_MAX + 1];

	xge_assert(lldev->intr_table != NULL);
	switch (lldev->intr_type) {
	case DDI_INTR_TYPE_FIXED:
		ret = ddi_intr_add_handler(lldev->intr_table[0],
		    (ddi_intr_handler_t *)xge_isr,
		    (caddr_t)hldev, 0);
		if (ret != DDI_SUCCESS) {
			xge_debug_osdep(XGE_ERR, "ddi_intr_add_handler(FIXED)"
			    "failed %d", ret);
			return (DDI_FAILURE);
		}
		break;

	case DDI_INTR_TYPE_MSIX:
		i = 0;
		xge_list_for_each(item, &hldev->free_channels) {
			xge_hal_channel_t *channel = xge_container_of(item,
			    xge_hal_channel_t, item);
			i = channel->post_qid;
			if (channel->type == XGE_HAL_CHANNEL_TYPE_FIFO) {
				if (fifo_conf->queue[i].configured) {
					assigned[msix_idx] = channel;
					msix_idx++;
				}
			} else {
				if (ring_conf->queue[i].configured) {
					assigned[msix_idx] = channel;
					msix_idx++;
				}
			}
		}
		for (i = 0; i < lldev->intr_cnt; i++) {
			uint_t (*intr)(caddr_t, caddr_t);
			caddr_t intr_arg;

			/* partition MSIX vectors */
			if (i == 0) {
				intr = xge_isr;
				intr_arg = (caddr_t)hldev;
				xge_debug_osdep(XGE_TRACE,
				    "Channel-A: using MSI-X #0");
			} else if (assigned[i] && assigned[i]->type ==
			    XGE_HAL_CHANNEL_TYPE_FIFO) {
				intr = xge_fifo_msix_isr;
				intr_arg = (caddr_t)assigned[i];
				xge_debug_osdep(XGE_TRACE, "Channel-Tx%d"
				    "using MSI-X #%d",
				    assigned[i]->post_qid, i);
			} else if (assigned[i] && assigned[i]->type ==
			    XGE_HAL_CHANNEL_TYPE_RING) {
				intr = xge_ring_msix_isr;
				intr_arg = (caddr_t)assigned[i];
				xge_debug_osdep(XGE_TRACE, "Channel-Rx%d: "
				    "using MSI-X #%d",
				    assigned[i]->post_qid, i);
			}
			ret = ddi_intr_add_handler(lldev->intr_table[i], intr,
			    intr_arg, (caddr_t)(uintptr_t)i);
			if (ret != DDI_SUCCESS) {
				int j;
				xge_debug_osdep(XGE_ERR,
				    "ddi_intr_add_handler()"
				    " failed %d", ret);
				for (j = 0; j < i; j++) {
					(void) ddi_intr_remove_handler(
					    lldev->intr_table[j]);
				}
				return (DDI_FAILURE);
			}
		}

		for (i = 1; i < msix_idx; i++)
			(void) xge_hal_channel_msix_set(assigned[i], i);
		break;

	default:
		break;
	}
	ret = ddi_intr_get_cap(lldev->intr_table[0], &lldev->intr_cap);
	if (ret != DDI_SUCCESS) {
		xge_debug_osdep(XGE_ERR, "ddi_intr_get_cap() failed %d", ret);
		for (i = 0; i < lldev->intr_cnt; i++) {
			(void) ddi_intr_remove_handler(lldev->intr_table[i]);
		}
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}


/*
 * xge_enable_intrs:
 *
 * Enable FIXED or MSI interrupts
 */
int
xge_enable_intrs(xgelldev_t *lldev)
{
	int ret, i;

	if (lldev->intr_cap & DDI_INTR_FLAG_BLOCK) {
		/* Call ddi_intr_block_enable() for MSI(X) interrupts */
		if ((ret = ddi_intr_block_enable(lldev->intr_table,
		    lldev->intr_cnt)) != DDI_SUCCESS) {
			xge_debug_osdep(XGE_ERR, "ddi_intr_enable() failed, "
			    "ret 0x%x", ret);
			return (DDI_FAILURE);
		}
	} else {
		/* Call ddi_intr_enable for MSI(X) or FIXED interrupts */
		for (i = 0; i < lldev->intr_cnt; i++) {
			if ((ret = ddi_intr_enable(lldev->intr_table[i]))
			    != DDI_SUCCESS) {
				int j;

				xge_debug_osdep(XGE_ERR, "ddi_intr_enable() "
				    "failed, ret 0x%x", ret);

				/* unwind */
				for (j = 0; j < i; j++) {
					(void) ddi_intr_disable(
					    lldev->intr_table[j]);
				}

				return (DDI_FAILURE);
			}
		}
	}

	return (DDI_SUCCESS);
}

/*
 * xge_disable_intrs:
 *
 * Disable FIXED or MSI interrupts
 */
void
xge_disable_intrs(xgelldev_t *lldev)
{
	int i;

	if (lldev->intr_cap & DDI_INTR_FLAG_BLOCK) {
		/* Call ddi_intr_block_disable() */
		(void) ddi_intr_block_disable(lldev->intr_table,
		    lldev->intr_cnt);
	} else {
		for (i = 0; i < lldev->intr_cnt; i++) {
			(void) ddi_intr_disable(lldev->intr_table[i]);
		}
	}
}

/*
 * xge_rem_intrs:
 *
 * Unregister FIXED or MSI interrupts
 */
void
xge_rem_intrs(xgelldev_t *lldev)
{
	int i;

	xge_assert(lldev->intr_table != NULL);

	/* Call ddi_intr_remove_handler() */
	for (i = 0; i < lldev->intr_cnt; i++) {
		(void) ddi_intr_remove_handler(lldev->intr_table[i]);
	}
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
	xgell_config_t *xgell_config;
	xge_hal_device_config_t *device_config;
	xge_hal_device_t *hldev;
	xge_hal_device_attr_t attr;
	xge_hal_status_e status;
	int ret, intr_types, i;

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

	xgell_config = kmem_zalloc(sizeof (xgell_config_t), KM_SLEEP);
	device_config = kmem_zalloc(sizeof (xge_hal_device_config_t), KM_SLEEP);

	/*
	 * Initialize all configurations
	 */
	xge_configuration_init(dev_info, device_config, xgell_config);

	/* Determine which types of interrupts supported */
	ret = ddi_intr_get_supported_types(dev_info, &intr_types);
	if ((ret != DDI_SUCCESS) || (!(intr_types & DDI_INTR_TYPE_FIXED))) {
		xge_debug_osdep(XGE_ERR, "%s",
		    "fixed type interrupt is not supported");
		goto _exit0a;
	}

	/* map BAR0 */
	ret = ddi_regs_map_setup(dev_info, 1, (caddr_t *)&attr.bar0,
	    (offset_t)0, (offset_t)0, &xge_dev_attr, &attr.regh0);
	if (ret != DDI_SUCCESS) {
		xge_debug_osdep(XGE_ERR, "unable to map bar0: [%d]", ret);
		goto _exit0a;
	}

	/* map BAR1 */
	ret = ddi_regs_map_setup(dev_info, 2, (caddr_t *)&attr.bar1,
	    (offset_t)0, (offset_t)0, &xge_dev_attr, &attr.regh1);
	if (ret != DDI_SUCCESS) {
		xge_debug_osdep(XGE_ERR, "unable to map bar1: [%d]", ret);
		goto _exit1;
	}

	/* map BAR2 MSI(X) */
	ret = ddi_regs_map_setup(dev_info, 2, (caddr_t *)&attr.bar2,
	    (offset_t)0, (offset_t)0, &xge_dev_attr, &attr.regh2);
	if (ret != DDI_SUCCESS) {
		xge_debug_osdep(XGE_ERR, "unable to map bar2: [%d]", ret);
		goto _exit1a;
	}

	/* preallocate memory for new HAL device and private LL part */
	hldev = kmem_zalloc(sizeof (xge_hal_device_t), KM_SLEEP);

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

	/*
	 * Init multiple rings configuration
	 */
	switch (xgell_config->grouping) {
	case XGELL_CONF_GROUP_POLICY_VIRT:
		ll->init_rx_rings = XGELL_RX_RING_NUM_MAX; /* 8 */
		ll->init_tx_rings = XGELL_TX_RING_NUM_MAX; /* 8 */
		ll->init_rx_groups = ll->init_rx_rings;
		break;
	case XGELL_CONF_GROUP_POLICY_PERF:
		ll->init_rx_rings = XGELL_RX_RING_NUM_MAX; /* 8 */
		ll->init_tx_rings = XGELL_TX_RING_NUM_MAX; /* 8 */
		ll->init_rx_groups = 1;
		break;
	case XGELL_CONF_GROUP_POLICY_BASIC:
		ll->init_rx_rings = XGELL_RX_RING_NUM_MIN; /* 1 */
		ll->init_tx_rings = XGELL_TX_RING_NUM_MIN; /* 1 */
		ll->init_rx_groups = ll->init_rx_rings;
		break;
	default:
		ASSERT(0);
		break;
	}

	/*
	 * Init MSI-X configuration
	 */
	if (xgell_config->msix_enable && intr_types & DDI_INTR_TYPE_MSIX) {
		ll->intr_type = DDI_INTR_TYPE_MSIX;
		ll->intr_cnt = 1;
		for (i = 0; i < XGE_HAL_MAX_FIFO_NUM; i++)
			if (device_config->fifo.queue[i].configured)
				ll->intr_cnt++;
		for (i = 0; i < XGE_HAL_MAX_RING_NUM; i++)
			if (device_config->ring.queue[i].configured)
				ll->intr_cnt++;
	} else {
		ll->intr_type = DDI_INTR_TYPE_FIXED;
		ll->intr_cnt = 1;
	}

	/*
	 * Allocate interrupt(s)
	 */
	while ((ret = xge_alloc_intrs(ll)) != DDI_SUCCESS) {
		if (ll->intr_type == DDI_INTR_TYPE_MSIX) {
			xgell_config->msix_enable = 0;
			ll->intr_type = DDI_INTR_TYPE_FIXED;
			ll->intr_cnt = 1;
			device_config->intr_mode = XGE_HAL_INTR_MODE_IRQLINE;
			xge_debug_osdep(XGE_TRACE,
			    "Unable to allocate MSI-X handlers"
			    " - defaulting to IRQA");
			continue;
		}
		goto _exit3a;
	}

	if (ll->intr_type == DDI_INTR_TYPE_MSIX) {
		device_config->intr_mode = XGE_HAL_INTR_MODE_MSIX;
		device_config->bimodal_interrupts = 0;
	} else {
		device_config->intr_mode = XGE_HAL_INTR_MODE_IRQLINE;
	}

	attr.irqh = ll->intr_pri;

	/* initialize HW */
	status = xge_hal_device_initialize(hldev, &attr, device_config);
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

	/* register interrupt handler for handling xge device interrupts */
	ret = xge_add_intrs(ll);
	if (ret != DDI_SUCCESS)
		goto _exit4;

	/* allocate and register Link Layer */
	ret = xgell_device_register(ll, xgell_config);
	if (ret != DDI_SUCCESS) {
		goto _exit5;
	}

	/* store ll as a HAL private part */
	xge_hal_device_private_set(hldev, ll);

	kmem_free(device_config, sizeof (xge_hal_device_config_t));
	kmem_free(xgell_config, sizeof (xgell_config_t));

	return (DDI_SUCCESS);

_exit5:
	xge_rem_intrs(ll);
_exit4:
	xge_hal_device_terminate(hldev);
_exit3b:
	xge_free_intrs(ll);
_exit3a:
	xgell_device_free(ll);
_exit3:
	pci_config_teardown(&attr.cfgh);
_exit2a:
	kmem_free(hldev, sizeof (xge_hal_device_t));
	ddi_regs_map_free(&attr.regh2);
_exit1a:
	ddi_regs_map_free(&attr.regh1);
_exit1:
	ddi_regs_map_free(&attr.regh0);
_exit0a:
	kmem_free(device_config, sizeof (xge_hal_device_config_t));
	kmem_free(xgell_config, sizeof (xgell_config_t));
_exit0:
	return (ret);
}

/*
 * quiesce(9E) entry point.
 *
 * This function is called when the system is single-threaded at high
 * PIL with preemption disabled. Therefore, this function must not be
 * blocked.
 *
 * This function returns DDI_SUCCESS on success, or DDI_FAILURE on failure.
 * DDI_FAILURE indicates an error condition and should almost never happen.
 */
static int
xge_quiesce(dev_info_t *dev_info)
{
	xge_hal_device_t *hldev =
	    (xge_hal_device_t *)ddi_get_driver_private(dev_info);

	xgelldev_t *lldev = xge_hal_device_private(hldev);

	xge_hal_device_quiesce(hldev, lldev->devh);

	return (DDI_SUCCESS);
}

/*
 * xge_detach
 * @dev_info: pointer to dev_info_t structure
 * @cmd: attach command to process
 *
 * This function is called by OS when the system is about
 * to shutdown or when the super user tries to unload
 * the driver. This function frees all the memory allocated
 * during xge_attach() and also unregisters the Xframe
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

	xge_rem_intrs(lldev);
	xge_free_intrs(lldev);
	xgell_device_free(lldev);
	pci_config_teardown(&attr->cfgh);
	ddi_regs_map_free(&attr->regh2);
	ddi_regs_map_free(&attr->regh1);
	ddi_regs_map_free(&attr->regh0);
	kmem_free(hldev, sizeof (xge_hal_device_t));

	return (DDI_SUCCESS);
}
