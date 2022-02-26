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
 * USB Ethernet Control Model
 *
 * USB-IF defines three ethernet network related specifications: EEM,
 * ECM and NCM. This driver focuses specifically on ECM compatible
 * devices. This kind of devices generally have one pair of bulk
 * endpoints for in/out packet data and one interrupt endpoint for
 * device notification.
 *
 * Devices which don't report ECM compatibility through descriptors but
 * implement the ECM functions may also bind to this driver. This driver
 * will try to find at least a bulk in endpoint and a bulk out endpoint
 * in this case. If the non-compatible devices use vendor specific data
 * format, this driver will not function.
 *
 * This driver is a normal USBA client driver. It's also a GLDv3 driver,
 * which provides the necessary interfaces the GLDv3 framework requires.
 *
 */

#include <sys/types.h>
#include <sys/strsun.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/byteorder.h>
#include <sys/usb/usba/usbai_version.h>
#include <sys/usb/usba.h>
#include <sys/usb/usba/usba_types.h>
#include <sys/usb/clients/usbcdc/usb_cdc.h>
#include <sys/usb/clients/usbecm/usbecm.h>
#include <sys/mac_provider.h>
#include <sys/strsubr.h>
#include <sys/ethernet.h>
#include <sys/mac_ether.h> /* MAC_PLUGIN_IDENT_ETHER */
#include <sys/random.h> /* random_get_bytes */
#include <sys/sdt.h>	/* sdt */
#include <inet/nd.h>

/* MAC callbacks */
static int	usbecm_m_stat(void *arg, uint_t stat, uint64_t *val);
static int	usbecm_m_start(void *arg);
static void	usbecm_m_stop(void *arg);
static int	usbecm_m_unicst(void *arg, const uint8_t *macaddr);
static int	usbecm_m_multicst(void *arg, boolean_t add, const uint8_t *m);
static int	usbecm_m_promisc(void *arg, boolean_t on);
static void	usbecm_m_ioctl(void *arg, queue_t *wq, mblk_t *mp);
static mblk_t	*usbecm_m_tx(void *arg, mblk_t *mp);
static int	usbecm_m_getprop(void *arg, const char *pr_name,
    mac_prop_id_t wldp_pr_num, uint_t wldp_length, void *wldp_buf);
static int	usbecm_m_setprop(void *arg, const char *pr_name,
    mac_prop_id_t wldp_pr_num, uint_t wldp_length, const void *wldp_buf);

static int	usbecm_usb_init(usbecm_state_t *ecmp);
static int	usbecm_mac_init(usbecm_state_t *ecmp);
static int	usbecm_mac_fini(usbecm_state_t *ecmp);


/* utils */
static void	generate_ether_addr(uint8_t *mac_addr);
static int	usbecm_rx_start(usbecm_state_t *ecmp);

static void	usbecm_pipe_start_polling(usbecm_state_t *ecmp);
static void	usbecm_intr_cb(usb_pipe_handle_t ph, usb_intr_req_t *req);
static void	usbecm_intr_ex_cb(usb_pipe_handle_t ph, usb_intr_req_t *req);
static void	usbecm_parse_intr_data(usbecm_state_t *ecmp, mblk_t *data);

static int	usbecm_reconnect_event_cb(dev_info_t *dip);
static int	usbecm_disconnect_event_cb(dev_info_t *dip);

static int	usbecm_open_pipes(usbecm_state_t *ecmp);
static void	usbecm_close_pipes(usbecm_state_t *ecmp);

static int	usbecm_ctrl_read(usbecm_state_t *ecmp, uchar_t request,
    uint16_t value, mblk_t **data, int len);
static int	usbecm_ctrl_write(usbecm_state_t *ecmp, uchar_t request,
    uint16_t value, mblk_t **data);
static int	usbecm_send_data(usbecm_state_t *ecmp, mblk_t *data);
static int	usbecm_send_zero_data(usbecm_state_t *ecmp);
static int	usbecm_get_statistics(usbecm_state_t *ecmp, uint32_t fs,
    uint32_t *stat_data);

static int	usbecm_create_pm_components(usbecm_state_t *ecmp);
static void	usbecm_destroy_pm_components(usbecm_state_t *ecmp);
static int	usbecm_power(dev_info_t *dip, int comp, int level);
static void	usbecm_pm_set_busy(usbecm_state_t *ecmp);
static void	usbecm_pm_set_idle(usbecm_state_t *ecmp);

static int	usbecm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int	usbecm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

static int	usbecm_suspend(usbecm_state_t *ecmp);
static int	usbecm_resume(usbecm_state_t *ecmp);
static int	usbecm_restore_device_state(usbecm_state_t *ecmp);
static void	usbecm_cleanup(usbecm_state_t *ecmp);

/* Driver identification */
static char usbecm_ident[] = "usbecm 1.0";

/* Global state pointer for managing per-device soft states */
void *usbecm_statep;

/* print levels */
static uint_t   usbecm_errlevel = USB_LOG_L3;
static uint_t   usbecm_errmask = 0xffffffff;
static uint_t   usbecm_instance_debug = (uint_t)-1;

/*
 * to prevent upper layers packet flood from exhausting system
 * resources(USBA does not set limitation of requests on a pipe),
 * we set a upper limit for the transfer queue length.
 */
static	int	usbecm_tx_max = 32;

#define	SUN_SP_VENDOR_ID	0x0430
#define	SUN_SP_PRODUCT_ID	0xa4a2

static uint8_t	usbecm_broadcast[ETHERADDRL] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static usb_event_t usbecm_events = {
	usbecm_disconnect_event_cb,
	usbecm_reconnect_event_cb,
	NULL, NULL
};

#define	ECM_DS_OP_VALID(op) ((ecmp->ecm_ds_ops) && (ecmp->ecm_ds_ops->op))

/*
 * MAC Call Back entries
 */
static mac_callbacks_t usbecm_m_callbacks = {
	MC_IOCTL | MC_SETPROP | MC_GETPROP,
	usbecm_m_stat,		/* Get the value of a statistic */
	usbecm_m_start,		/* Start the device */
	usbecm_m_stop,		/* Stop the device */
	usbecm_m_promisc,	/* Enable or disable promiscuous mode */
	usbecm_m_multicst,	/* Enable or disable a multicast addr */
	usbecm_m_unicst,	/* Set the unicast MAC address */
	usbecm_m_tx,		/* Transmit a packet */
	NULL,
	usbecm_m_ioctl,		/* Process an unknown ioctl */
	NULL,			/* mc_getcapab */
	NULL,			/* mc_open */
	NULL,			/* mc_close */
	usbecm_m_setprop, 	/* mc_setprop */
	usbecm_m_getprop,	/* mc_getprop */
	NULL
};


/*
 *  Module Loading Data & Entry Points
 *     Can't use DDI_DEFINE_STREAM_OPS, since it does
 *     not provide devo_power entry.
 */
static struct cb_ops cb_usbecm = {
	nulldev,		/* cb_open */
	nulldev,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	nodev,			/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* cb_stream */
	D_MP,			/* cb_flag */
	CB_REV,			/* cb_rev */
	nodev,			/* cb_aread */
	nodev,			/* cb_awrite */
};

static struct dev_ops usbecm_devops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	NULL,			/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	usbecm_attach,		/* devo_attach */
	usbecm_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&(cb_usbecm),		/* devo_cb_ops */
	(struct bus_ops *)NULL,	/* devo_bus_ops */
	usbecm_power,		/* devo_power */
	ddi_quiesce_not_needed	/* devo_quiesce */
};

static struct modldrv usbecm_modldrv = {
	&mod_driverops,		/* drv_modops */
	usbecm_ident,		/* drv_linkinfo */
	&usbecm_devops		/* drv_dev_ops */
};

static struct modlinkage usbecm_ml = {
	MODREV_1,		/* ml_rev */
	&usbecm_modldrv, NULL	/* ml_linkage */
};


/*
 * Device operations
 */
/*
 * Binding the driver to a device.
 *
 * Concurrency: Until usbecm_attach() returns with success,
 * the only other entry point that can be executed is getinfo().
 * Thus no locking here yet.
 */
static int
usbecm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	char strbuf[32];
	int instance;
	int err;
	usbecm_state_t *ecmp = NULL;

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		ecmp = (usbecm_state_t *)ddi_get_soft_state(usbecm_statep,
		    ddi_get_instance(dip));

		(void) usbecm_resume(ecmp);

		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);

	if (ddi_soft_state_zalloc(usbecm_statep, instance) == DDI_SUCCESS) {
		ecmp = ddi_get_soft_state(usbecm_statep, instance);
	}
	if (ecmp == NULL) {
		cmn_err(CE_WARN, "usbecm_attach: fail to get soft state");

		return (DDI_FAILURE);
	}

	ecmp->ecm_dip = dip;

	ecmp->ecm_lh = usb_alloc_log_hdl(ecmp->ecm_dip, "usbecm",
	    &usbecm_errlevel, &usbecm_errmask, &usbecm_instance_debug, 0);

	if (usbecm_usb_init(ecmp) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ecmp->ecm_lh,
		    "usbecm_attach: failed to init usb");

		goto fail;
	}

	if (ECM_DS_OP_VALID(ecm_ds_init)) {
		if (ecmp->ecm_ds_ops->ecm_ds_init(ecmp) != USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA, ecmp->ecm_lh,
			    "usbecm_attach: failed to init DS");

			goto fail;
		}
	}

	if (usbecm_mac_init(ecmp) != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ecmp->ecm_lh,
		    "usbecm_attach: failed to init mac");

		goto fail;
	}
	ecmp->ecm_init_flags |= USBECM_INIT_MAC;

	/*
	 * Create minor node of type usb_net. Not necessary to create
	 * DDI_NT_NET since it's created in mac_register(). Otherwise,
	 * system will panic.
	 */
	(void) snprintf(strbuf, sizeof (strbuf), "usbecm%d", instance);
	err = ddi_create_minor_node(dip, strbuf, S_IFCHR,
	    instance + 1, "usb_net", 0);
	if (err != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ecmp->ecm_lh,
		    "failed to create minor node");

		goto fail;
	}

	/* always busy. May change to a more precise PM in future */
	usbecm_pm_set_busy(ecmp);

	ddi_report_dev(dip);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ecmp->ecm_lh,
	    "usbecm_attach: succeed!");

	return (DDI_SUCCESS);

fail:
	USB_DPRINTF_L1(PRINT_MASK_ATTA, ecmp->ecm_lh,
	    "usbecm_attach: Attach fail");

	usbecm_cleanup(ecmp);
	ddi_prop_remove_all(dip);
	ddi_soft_state_free(usbecm_statep, instance);

	return (DDI_FAILURE);

}


/*
 * Detach the driver from a device.
 *
 * Concurrency: Will be called only after a successful attach
 * (and not concurrently).
 */
static int
usbecm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	usbecm_state_t *ecmp = NULL;
	int instance;

	instance = ddi_get_instance(dip);
	ecmp = ddi_get_soft_state(usbecm_statep, instance);
	ASSERT(ecmp != NULL);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ecmp->ecm_lh,
	    "usbecm_detach: entry ");

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:

		return (usbecm_suspend(ecmp));

	default:
		return (DDI_FAILURE);
	}

	usbecm_pm_set_idle(ecmp);

	if (ECM_DS_OP_VALID(ecm_ds_fini)) {
		if (ecmp->ecm_ds_ops->ecm_ds_fini(ecmp) != USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA, ecmp->ecm_lh,
			    "usbecm_detach: deinitialize DS fail!");

			return (DDI_FAILURE);
		}
	}

	if (usbecm_mac_fini(ecmp) != 0) {

		return (DDI_FAILURE);
	}

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ecmp->ecm_lh,
	    "usbecm_detach: exit");

	usbecm_cleanup(ecmp);
	ddi_soft_state_free(usbecm_statep, instance);

	return (DDI_SUCCESS);
}


/*
 * Mac Call Back functions
 */

/*
 * Read device statistic information.
 */
static int
usbecm_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	usbecm_state_t *ecmp = (usbecm_state_t *)arg;
	uint32_t	stats;
	int		rval;
	uint32_t	fs;

	USB_DPRINTF_L4(PRINT_MASK_OPS, ecmp->ecm_lh,
	    "usbecm_m_stat: entry, stat=%d", stat);

	/*
	 * Some of the stats are MII specific. We try to
	 * resolve all the statistics we understand. If
	 * the usb device can't provide it, return ENOTSUP.
	 */
	switch (stat) {
	case MAC_STAT_IFSPEED:
		/* return link speed */
		mutex_enter(&ecmp->ecm_mutex);
		if (ecmp->ecm_stat.es_downspeed) {
			*val = ecmp->ecm_stat.es_downspeed;
		} else {
			*val = 10 * 1000000ull; /* set a default value */
		}
		mutex_exit(&ecmp->ecm_mutex);

		return (0);
	case ETHER_STAT_LINK_DUPLEX:
		*val = LINK_DUPLEX_FULL;

		return (0);

	case ETHER_STAT_SQE_ERRORS:
		*val = 0;

		return (0);

	/* Map MAC/Ether stats to ECM statistics */
	case MAC_STAT_NORCVBUF:
		fs = ECM_RCV_NO_BUFFER;

		break;
	case MAC_STAT_NOXMTBUF:
		fs = ECM_XMIT_ERROR;

		break;
	case MAC_STAT_IERRORS:
		fs = ECM_RCV_ERROR;

		break;
	case MAC_STAT_OERRORS:
		fs = ECM_XMIT_ERROR;

		break;
	case MAC_STAT_RBYTES:
		fs = ECM_DIRECTED_BYTES_RCV;

		break;
	case MAC_STAT_IPACKETS:
		fs = ECM_RCV_OK; /* frames */

		break;
	case MAC_STAT_OBYTES:
		fs = ECM_DIRECTED_BYTES_XMIT;

		break;
	case MAC_STAT_OPACKETS:
		fs = ECM_XMIT_OK; /* frames */

		break;
	case MAC_STAT_MULTIRCV:
		fs = ECM_MULTICAST_FRAMES_RCV;

		break;
	case MAC_STAT_BRDCSTRCV:
		fs = ECM_BROADCAST_FRAMES_RCV;

		break;
	case MAC_STAT_MULTIXMT:
		fs = ECM_MULTICAST_FRAMES_XMIT;

		break;
	case MAC_STAT_BRDCSTXMT:
		fs = ECM_BROADCAST_FRAMES_XMIT;

		break;
	case MAC_STAT_COLLISIONS:
		fs = ECM_XMIT_MAX_COLLISIONS;

		break;
	case MAC_STAT_OVERFLOWS:
		fs = ECM_RCV_OVERRUN;

		break;
	case MAC_STAT_UNDERFLOWS:
		fs = ECM_XMIT_UNDERRUN;

		break;
	case ETHER_STAT_FCS_ERRORS:
		fs = ECM_RCV_CRC_ERROR;

		break;
	case ETHER_STAT_ALIGN_ERRORS:
		fs = ECM_RCV_ERROR_ALIGNMENT;

		break;
	case ETHER_STAT_DEFER_XMTS:
		fs = ECM_XMIT_DEFERRED;

		break;
	case ETHER_STAT_FIRST_COLLISIONS:
		fs = ECM_XMIT_ONE_COLLISION;

		break;
	case ETHER_STAT_MULTI_COLLISIONS:
		fs = ECM_XMIT_MORE_COLLISIONS;

		break;
	case ETHER_STAT_TX_LATE_COLLISIONS:
		fs = ECM_XMIT_LATE_COLLISIONS;

		break;

	default:
		return (ENOTSUP);
	}

	/*
	 * we need to access device to get required stats,
	 * so check device state first
	 */
	mutex_enter(&ecmp->ecm_mutex);
	if (ecmp->ecm_dev_state != USB_DEV_ONLINE) {
		USB_DPRINTF_L2(PRINT_MASK_OPS, ecmp->ecm_lh,
		    "usbecm_m_stat: device not ONLINE");

		mutex_exit(&ecmp->ecm_mutex);

		return (EIO);
	}
	mutex_exit(&ecmp->ecm_mutex);

	rval = usbecm_get_statistics(ecmp,
	    ECM_STAT_SELECTOR(fs), &stats);
	if (rval != USB_SUCCESS) {
		mutex_enter(&ecmp->ecm_mutex);
		switch (stat) {
		case MAC_STAT_IERRORS:
			*val = ecmp->ecm_stat.es_ierrors;

			break;
		case MAC_STAT_OERRORS:
			*val = ecmp->ecm_stat.es_oerrors;

			break;
		case MAC_STAT_RBYTES:
			*val = ecmp->ecm_stat.es_ibytes;

			break;
		case MAC_STAT_IPACKETS:
			*val = ecmp->ecm_stat.es_ipackets;

			break;
		case MAC_STAT_OBYTES:
			*val = ecmp->ecm_stat.es_obytes;

			break;
		case MAC_STAT_OPACKETS:
			*val = ecmp->ecm_stat.es_opackets;

			break;
		case MAC_STAT_MULTIRCV:
			*val = ecmp->ecm_stat.es_multircv;

			break;
		case MAC_STAT_MULTIXMT:
			*val = ecmp->ecm_stat.es_multixmt;

			break;
		case MAC_STAT_BRDCSTRCV:
			*val = ecmp->ecm_stat.es_brdcstrcv;

			break;
		case MAC_STAT_BRDCSTXMT:
			*val = ecmp->ecm_stat.es_brdcstxmt;

			break;
		case ETHER_STAT_MACXMT_ERRORS:
			*val = ecmp->ecm_stat.es_macxmt_err;
			break;
		default:
			*val = 0;

			break;
		}
		mutex_exit(&ecmp->ecm_mutex);
	} else {
		*val = stats;
	}

	USB_DPRINTF_L4(PRINT_MASK_OPS, ecmp->ecm_lh,
	    "usbecm_m_stat: end");

	return (0);
}


/*
 * Start the device:
 *	- Set proper altsettings of the data interface
 *	- Open status and data endpoints
 *	- Start status polling
 *	- Get bulk-in ep ready to receive data from ethernet
 *
 * Concurrency: Presumably fully concurrent, must lock.
 */
static int
usbecm_m_start(void *arg)
{
	usbecm_state_t *ecmp = (usbecm_state_t *)arg;
	int rval;

	USB_DPRINTF_L4(PRINT_MASK_OPS, ecmp->ecm_lh,
	    "usbecm_m_start: entry");

	(void) usb_serialize_access(ecmp->ecm_ser_acc, USB_WAIT, 0);
	mutex_enter(&ecmp->ecm_mutex);
	if (ecmp->ecm_dev_state != USB_DEV_ONLINE) {
		USB_DPRINTF_L2(PRINT_MASK_OPS, ecmp->ecm_lh,
		    "usbecm_m_start: device not online");
		rval = ENODEV;
		mutex_exit(&ecmp->ecm_mutex);

		goto fail;
	}
	mutex_exit(&ecmp->ecm_mutex);

	if (usbecm_open_pipes(ecmp) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_OPS, ecmp->ecm_lh,
		    "usbecm_m_start: open pipes fail");
		rval = EIO;

		goto fail;
	}

	mutex_enter(&ecmp->ecm_mutex);
	if (usbecm_rx_start(ecmp) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_OPS, ecmp->ecm_lh,
		    "usbecm_m_start: fail to start_rx");
		mutex_exit(&ecmp->ecm_mutex);
		rval = EIO;

		goto fail;
	}
	ecmp->ecm_mac_state = USBECM_MAC_STARTED;
	mutex_exit(&ecmp->ecm_mutex);

	/* set the device to receive all multicast/broadcast pkts */
	rval = usbecm_ctrl_write(ecmp, CDC_ECM_SET_ETH_PKT_FLT,
	    CDC_ECM_PKT_TYPE_DIRECTED | CDC_ECM_PKT_TYPE_ALL_MCAST |
	    CDC_ECM_PKT_TYPE_BCAST, NULL);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L3(PRINT_MASK_OPS, ecmp->ecm_lh,
		    "usbecm_m_start: set packet filters fail,"
		    " rval=%d, continue", rval);
	}

	if (ECM_DS_OP_VALID(ecm_ds_start)) {
		if (ecmp->ecm_ds_ops->ecm_ds_start(ecmp) != USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_OPS, ecmp->ecm_lh,
			    "usbecm_m_start: Can't start hardware");

			goto fail;
		}
	}

	usb_release_access(ecmp->ecm_ser_acc);

	USB_DPRINTF_L4(PRINT_MASK_OPS, ecmp->ecm_lh,
	    "usbecm_m_start: end");

	/*
	 * To mark the link as RUNNING.
	 *
	 * ECM spec doesn't provide a way for host to get the status
	 * of the physical link initiatively. Only the device can
	 * report the link state through interrupt endpoints.
	 */
	mac_link_update(ecmp->ecm_mh, LINK_STATE_UP);
	mutex_enter(&ecmp->ecm_mutex);
	ecmp->ecm_stat.es_linkstate = LINK_STATE_UP;
	mutex_exit(&ecmp->ecm_mutex);

	return (DDI_SUCCESS);
fail:
	usb_release_access(ecmp->ecm_ser_acc);

	return (rval);
}

/*
 * Stop the device.
 */
static void
usbecm_m_stop(void *arg)
{
	usbecm_state_t *ecmp = (usbecm_state_t *)arg;

	USB_DPRINTF_L4(PRINT_MASK_OPS, ecmp->ecm_lh,
	    "usbecm_m_stop: entry");

	(void) usb_serialize_access(ecmp->ecm_ser_acc, USB_WAIT, 0);
	if (ECM_DS_OP_VALID(ecm_ds_stop)) {
		if (ecmp->ecm_ds_ops->ecm_ds_stop(ecmp) != USB_SUCCESS) {
			USB_DPRINTF_L4(PRINT_MASK_OPS, ecmp->ecm_lh,
			    "usbecm_m_stop: fail to stop hardware");
		}
	}

	usbecm_close_pipes(ecmp);
	usb_release_access(ecmp->ecm_ser_acc);

	mutex_enter(&ecmp->ecm_mutex);
	ecmp->ecm_mac_state = USBECM_MAC_STOPPED;
	mutex_exit(&ecmp->ecm_mutex);

	mac_link_update(ecmp->ecm_mh, LINK_STATE_DOWN);
	mutex_enter(&ecmp->ecm_mutex);
	ecmp->ecm_stat.es_linkstate = LINK_STATE_DOWN;
	mutex_exit(&ecmp->ecm_mutex);

	USB_DPRINTF_L4(PRINT_MASK_OPS, ecmp->ecm_lh,
	    "usbecm_m_stop: end");
}

/*
 * Change the MAC address of the device.
 */
/*ARGSUSED*/
static int
usbecm_m_unicst(void *arg, const uint8_t *macaddr)
{
	usbecm_state_t *ecmp = (usbecm_state_t *)arg;
	uint16_t	filter;
	int		rval;

	USB_DPRINTF_L4(PRINT_MASK_OPS, ecmp->ecm_lh,
	    "usbecm_m_unicst: entry");

	/*
	 * The device doesn't support to set a different MAC addr.
	 * Hence, it's not necessary to stop the device first if
	 * the mac addresses are identical. And we just set unicast
	 * filter only.
	 */
	if (bcmp(macaddr, ecmp->ecm_srcaddr, ETHERADDRL) != 0) {
		USB_DPRINTF_L3(PRINT_MASK_OPS, ecmp->ecm_lh,
		    "usbecm_m_unicst: not supported to set a"
		    " different MAC addr");

		return (DDI_FAILURE);
	}
	mutex_enter(&ecmp->ecm_mutex);
	filter = ecmp->ecm_pkt_flt |= CDC_ECM_PKT_TYPE_DIRECTED;
	mutex_exit(&ecmp->ecm_mutex);

	(void) usb_serialize_access(ecmp->ecm_ser_acc, USB_WAIT, 0);
	rval = usbecm_ctrl_write(ecmp, CDC_ECM_SET_ETH_PKT_FLT,
	    filter, NULL);
	usb_release_access(ecmp->ecm_ser_acc);

	USB_DPRINTF_L4(PRINT_MASK_OPS, ecmp->ecm_lh,
	    "usbecm_m_unicst: rval = %d", rval);

	/* some devices may not support this request, we just return success */
	return (DDI_SUCCESS);
}

/*
 * Enable/disable multicast.
 */
/*ARGSUSED*/
static int
usbecm_m_multicst(void *arg, boolean_t add, const uint8_t *m)
{
	usbecm_state_t *ecmp = (usbecm_state_t *)arg;
	uint16_t	filter;
	int	rval = 0;

	USB_DPRINTF_L4(PRINT_MASK_OPS, ecmp->ecm_lh,
	    "usbecm_m_multicst: entry");
	mutex_enter(&ecmp->ecm_mutex);

	/*
	 * To simplify the implementation, we support switching
	 * all multicast on/off feature only
	 */
	if (add == B_TRUE) {
		ecmp->ecm_pkt_flt |= CDC_ECM_PKT_TYPE_ALL_MCAST;
	} else {
		ecmp->ecm_pkt_flt &= ~CDC_ECM_PKT_TYPE_ALL_MCAST;
	}
	filter = ecmp->ecm_pkt_flt;
	mutex_exit(&ecmp->ecm_mutex);

	(void) usb_serialize_access(ecmp->ecm_ser_acc, USB_WAIT, 0);
	if (ecmp->ecm_compatibility &&
	    (ecmp->ecm_desc.wNumberMCFilters & 0x7F)) {
	/* Device supports SetEthernetMulticastFilters request */
		rval = usbecm_ctrl_write(ecmp, CDC_ECM_SET_ETH_PKT_FLT,
		    filter, NULL);
		USB_DPRINTF_L4(PRINT_MASK_OPS, ecmp->ecm_lh,
		    "usbecm_m_multicst: rval = %d", rval);
	}
	usb_release_access(ecmp->ecm_ser_acc);

	/* some devices may not support this request, we just return success */
	return (DDI_SUCCESS);
}

/*
 * Enable/disable promiscuous mode.
 */
static int
usbecm_m_promisc(void *arg, boolean_t on)
{
	usbecm_state_t *ecmp = (usbecm_state_t *)arg;
	uint16_t	filter;
	int		rval;

	USB_DPRINTF_L4(PRINT_MASK_OPS, ecmp->ecm_lh,
	    "usbecm_m_promisc: entry");

	mutex_enter(&ecmp->ecm_mutex);
	if (ecmp->ecm_dev_state != USB_DEV_ONLINE) {
		USB_DPRINTF_L2(PRINT_MASK_OPS, ecmp->ecm_lh,
		    "usbecm_m_promisc: device not ONLINE");
		mutex_exit(&ecmp->ecm_mutex);

		return (DDI_FAILURE);
	}


	if (on == B_TRUE) {
		ecmp->ecm_pkt_flt |= CDC_ECM_PKT_TYPE_PROMISC;
	} else {
		ecmp->ecm_pkt_flt &= ~CDC_ECM_PKT_TYPE_PROMISC;
	}
	filter = ecmp->ecm_pkt_flt;
	mutex_exit(&ecmp->ecm_mutex);

	(void) usb_serialize_access(ecmp->ecm_ser_acc, USB_WAIT, 0);
	rval = usbecm_ctrl_write(ecmp, CDC_ECM_SET_ETH_PKT_FLT,
	    filter, NULL);
	usb_release_access(ecmp->ecm_ser_acc);

	USB_DPRINTF_L4(PRINT_MASK_OPS, ecmp->ecm_lh,
	    "usbecm_m_promisc: rval=%d", rval);

	/*
	 * devices may not support this request, we just
	 * return success to let upper layer to do further
	 * operation.
	 */
	return (DDI_SUCCESS);
}

/*
 * IOCTL request: Does not do anything. Will be enhanced
 *	in future.
 */
static void
usbecm_m_ioctl(void *arg, queue_t *wq, mblk_t *mp)
{
	usbecm_state_t *ecmp = (usbecm_state_t *)arg;
	struct iocblk   *iocp;
	int cmd;

	USB_DPRINTF_L4(PRINT_MASK_OPS, ecmp->ecm_lh,
	    "usbecm_m_ioctl: entry");

	mutex_enter(&ecmp->ecm_mutex);
	if (ecmp->ecm_dev_state != USB_DEV_ONLINE) {
		USB_DPRINTF_L2(PRINT_MASK_OPS, ecmp->ecm_lh,
		    "usbecm_m_ioctl: device not ONLINE");
		mutex_exit(&ecmp->ecm_mutex);

		miocnak(wq, mp, 0, EIO);

		return;
	}
	mutex_exit(&ecmp->ecm_mutex);

	iocp = (void *)mp->b_rptr;
	iocp->ioc_error = 0;
	cmd = iocp->ioc_cmd;

	(void) usb_serialize_access(ecmp->ecm_ser_acc, USB_WAIT, 0);

	switch (cmd) {
	default:
		USB_DPRINTF_L4(PRINT_MASK_OPS, ecmp->ecm_lh,
		    "unknown cmd 0x%x", cmd);
		usb_release_access(ecmp->ecm_ser_acc);
		miocnak(wq, mp, 0, EINVAL);

		return;
	}
}

/*
 * callback functions for get/set properties
 *	Does not do anything. Will be enhanced to
 *	support set/get properties in future.
 */
/*ARGSUSED*/
static int
usbecm_m_setprop(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    uint_t wldp_length, const void *wldp_buf)
{
	usbecm_state_t *ecmp = (usbecm_state_t *)arg;
	int err = ENOTSUP;

	USB_DPRINTF_L4(PRINT_MASK_OPS, ecmp->ecm_lh,
	    "usbecm_m_setprop: entry");

	return (err);
}

/*ARGSUSED*/
static int usbecm_m_getprop(void *arg, const char *pr_name,
    mac_prop_id_t wldp_pr_num, uint_t wldp_length, void *wldp_buf)
{
	usbecm_state_t *ecmp = (usbecm_state_t *)arg;
	int err = ENOTSUP;

	USB_DPRINTF_L4(PRINT_MASK_OPS, ecmp->ecm_lh,
	    "usbecm_m_getprop: entry");

	mutex_enter(&ecmp->ecm_mutex);
	if (ecmp->ecm_dev_state != USB_DEV_ONLINE) {
		mutex_exit(&ecmp->ecm_mutex);

		return (EIO);
	}
	mutex_exit(&ecmp->ecm_mutex);

	return (err);
}

/*
 * Transmit a data frame.
 */
static mblk_t *
usbecm_m_tx(void *arg, mblk_t *mp)
{
	usbecm_state_t *ecmp = (usbecm_state_t *)arg;
	mblk_t *next;
	int count = 0;

	ASSERT(mp != NULL);

	USB_DPRINTF_L4(PRINT_MASK_OPS, ecmp->ecm_lh,
	    "usbecm_m_tx: entry");

	mutex_enter(&ecmp->ecm_mutex);
	if (ecmp->ecm_dev_state != USB_DEV_ONLINE) {
		USB_DPRINTF_L2(PRINT_MASK_OPS, ecmp->ecm_lh,
		    "usbecm_m_tx: device not ONLINE");
		mutex_exit(&ecmp->ecm_mutex);

		return (mp);
	}
	mutex_exit(&ecmp->ecm_mutex);

	(void) usb_serialize_access(ecmp->ecm_ser_acc, USB_WAIT, 0);

	/*
	 * To make use of the device maximum capability,
	 * concatenate msg blocks in a msg to ETHERMAX length.
	 */
	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;

		if (usbecm_send_data(ecmp, mp) != DDI_SUCCESS) {
			USB_DPRINTF_L3(PRINT_MASK_OPS, ecmp->ecm_lh,
			    "usbecm_m_tx: send data fail");

			/* failure statistics */
			mutex_enter(&ecmp->ecm_mutex);
			ecmp->ecm_stat.es_oerrors++;
			mutex_exit(&ecmp->ecm_mutex);

			mp->b_next = next;

			break;
		}

		/*
		 * To make it simple, we count all packets, no matter
		 * the device supports ethernet statistics or not.
		 */
		mutex_enter(&ecmp->ecm_mutex);
		ecmp->ecm_stat.es_opackets++;
		ecmp->ecm_stat.es_obytes += MBLKL(mp);
		mutex_exit(&ecmp->ecm_mutex);

		freemsg(mp); /* free this msg upon success */

		mp = next;
		USB_DPRINTF_L4(PRINT_MASK_OPS, ecmp->ecm_lh,
		    "usbecm_m_tx: %d msgs processed", ++count);
	}

	usb_release_access(ecmp->ecm_ser_acc);

	return (mp);
}

/*
 * usbecm_bulkin_cb:
 *	Bulk In regular and exeception callback;
 *	USBA framework will call this callback
 *	after deal with bulkin request.
 */
/*ARGSUSED*/
static void
usbecm_bulkin_cb(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	usbecm_state_t	*ecmp = (usbecm_state_t *)req->bulk_client_private;
	mblk_t		*data, *mp;
	int		data_len;
	int		max_pkt_size = ecmp->ecm_bulkin_sz;

	data = req->bulk_data;
	data_len = (data) ? MBLKL(data) : 0;

	ASSERT(data->b_cont == NULL);

	mutex_enter(&ecmp->ecm_mutex);

	USB_DPRINTF_L4(PRINT_MASK_CB, ecmp->ecm_lh,
	    "usbecm_bulkin_cb: state=%d, len=%d", ecmp->ecm_bulkin_state,
	    data_len);

	/*
	 * may receive a zero length packet according
	 * to USB short packet semantics
	 */
	if ((ecmp->ecm_dev_state == USB_DEV_ONLINE) &&
	    (req->bulk_completion_reason == USB_CR_OK)) {
		if (data_len) {
			if (ecmp->ecm_rcv_queue == NULL) {
				ecmp->ecm_rcv_queue = data;
			} else {
				if ((msgsize(ecmp->ecm_rcv_queue) + data_len)
				    > ETHERMAX) {
				/*
				 * Exceed the ethernet maximum length, we think
				 * something is wrong with this frame and hence
				 * free older data. Accept new data instead.
				 */
					freemsg(ecmp->ecm_rcv_queue);
					ecmp->ecm_rcv_queue = data;
				} else {
					linkb(ecmp->ecm_rcv_queue, data);
				}
			}
		} else {
		/*
		 * Do not put zero length packet to receive queue.
		 * Otherwise, msgpullup will dupmsg() a zero length
		 * mblk, which will cause memleaks.
		 */
			freemsg(data);
		}

		/*
		 * ECM V1.2, section 3.3.1, a short(including zero length)
		 * packet signifies end of frame. We can submit this frame
		 * to upper layer now.
		 */
		if ((data_len < max_pkt_size) &&
		    (msgsize(ecmp->ecm_rcv_queue) > 0)) {
			mp = msgpullup(ecmp->ecm_rcv_queue, -1);
			freemsg(ecmp->ecm_rcv_queue);
			ecmp->ecm_rcv_queue = NULL;

			ecmp->ecm_stat.es_ipackets++;
			ecmp->ecm_stat.es_ibytes += msgsize(mp);
			if (mp && (mp->b_rptr[0] & 0x01)) {
				if (bcmp(mp->b_rptr, usbecm_broadcast,
				    ETHERADDRL) != 0) {
					ecmp->ecm_stat.es_multircv++;
				} else {
					ecmp->ecm_stat.es_brdcstrcv++;
				}
			}

			if (mp) {
				mutex_exit(&ecmp->ecm_mutex);
				mac_rx(ecmp->ecm_mh, NULL, mp);
				mutex_enter(&ecmp->ecm_mutex);
			}
		}

		/* prevent USBA from freeing data along with the request */
		req->bulk_data = NULL;
	} else if (req->bulk_completion_reason != USB_CR_OK) {
		ecmp->ecm_stat.es_ierrors++;
	}
	mutex_exit(&ecmp->ecm_mutex);

	usb_free_bulk_req(req);

	/* receive more */
	mutex_enter(&ecmp->ecm_mutex);
	if (((ecmp->ecm_bulkin_state == USBECM_PIPE_BUSY) ||
	    (ecmp->ecm_bulkin_state == USBECM_PIPE_IDLE)) &&
	    (ecmp->ecm_dev_state == USB_DEV_ONLINE)) {
		if (usbecm_rx_start(ecmp) != USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_CB, ecmp->ecm_lh,
			    "usbecm_bulkin_cb: restart rx fail "
			    "ecmp_state = %d", ecmp->ecm_bulkin_state);
		}
	} else if (ecmp->ecm_bulkin_state == USBECM_PIPE_BUSY) {
		ecmp->ecm_bulkin_state = USBECM_PIPE_IDLE;
	}
	mutex_exit(&ecmp->ecm_mutex);
}

/*
 * usbsecm_rx_start:
 *	start data receipt
 */
static int
usbecm_rx_start(usbecm_state_t *ecmp)
{
	usb_bulk_req_t	*br;
	int		rval = USB_FAILURE;
	int		data_len;

	ASSERT(mutex_owned(&ecmp->ecm_mutex));

	DTRACE_PROBE2(usbecm_rx__start, int, ecmp->ecm_xfer_sz,
	    int, ecmp->ecm_bulkin_sz);

	ecmp->ecm_bulkin_state = USBECM_PIPE_BUSY;
	data_len = ecmp->ecm_bulkin_sz;

	mutex_exit(&ecmp->ecm_mutex);
	br = usb_alloc_bulk_req(ecmp->ecm_dip, data_len, USB_FLAGS_SLEEP);
	if (br == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_CB, ecmp->ecm_lh,
		    "usbsecm_rx_start: allocate bulk request failed");

		mutex_enter(&ecmp->ecm_mutex);

		return (USB_FAILURE);
	}
	/* initialize bulk in request. */
	br->bulk_len = data_len;
	br->bulk_timeout = 0;
	br->bulk_cb = usbecm_bulkin_cb;
	br->bulk_exc_cb = usbecm_bulkin_cb;
	br->bulk_client_private = (usb_opaque_t)ecmp;
	br->bulk_attributes = USB_ATTRS_AUTOCLEARING
	    | USB_ATTRS_SHORT_XFER_OK;

	rval = usb_pipe_bulk_xfer(ecmp->ecm_bulkin_ph, br, 0);
	mutex_enter(&ecmp->ecm_mutex);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_CB, ecmp->ecm_lh,
		    "usbsecm_rx_start: bulk transfer failed %d", rval);
		usb_free_bulk_req(br);
		ecmp->ecm_bulkin_state = USBECM_PIPE_IDLE;
	}

	return (rval);
}

/*
 * usbecm_bulkout_cb:
 *	Bulk Out regular and exeception callback;
 *	USBA framework will call this callback function
 *	after deal with bulkout request.
 */
/*ARGSUSED*/
static void
usbecm_bulkout_cb(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	usbecm_state_t *ecmp = (usbecm_state_t *)req->bulk_client_private;
	int		data_len;
	boolean_t	need_update = B_FALSE;

	data_len = (req->bulk_data) ? MBLKL(req->bulk_data) : 0;

	USB_DPRINTF_L4(PRINT_MASK_CB, ecmp->ecm_lh,
	    "usbecm_bulkout_cb: data_len = %d, cr=%d", data_len,
	    req->bulk_completion_reason);

	mutex_enter(&ecmp->ecm_mutex);
	if ((data_len > 0) && (ecmp->ecm_tx_cnt > 0)) {
		if (ecmp->ecm_tx_cnt == usbecm_tx_max) {
			need_update = B_TRUE;
		}
		ecmp->ecm_tx_cnt--;
	}
	mutex_exit(&ecmp->ecm_mutex);

	if (req->bulk_completion_reason && (data_len > 0)) {
		mutex_enter(&ecmp->ecm_mutex);
		ecmp->ecm_stat.es_oerrors++;
		mutex_exit(&ecmp->ecm_mutex);

		need_update = B_TRUE;
	}

	/*
	 * notify MAC layer to retransfer the failed packet
	 * Or notity MAC that we have more buffer now.
	 */
	if (need_update) {
		mac_tx_update(ecmp->ecm_mh);
	}

	usb_free_bulk_req(req);
}

static int
usbecm_send_data(usbecm_state_t *ecmp, mblk_t *data)
{
	usb_bulk_req_t	*br;
	int		rval = USB_FAILURE;
	int		data_len = MBLKL(data);
	int		max_pkt_size;
	mblk_t		*new_data = NULL;
	int		new_data_len = 0;

	USB_DPRINTF_L4(PRINT_MASK_OPS, ecmp->ecm_lh,
	    "usbecm_send_data: length = %d, total len=%d",
	    data_len, (int)msgdsize(data));

	mutex_enter(&ecmp->ecm_mutex);
	if (ecmp->ecm_tx_cnt >= usbecm_tx_max) {
		USB_DPRINTF_L4(PRINT_MASK_OPS, ecmp->ecm_lh,
		    "usbecm_send_data: (%d) exceeds TX max queue length",
		    ecmp->ecm_tx_cnt);
		mutex_exit(&ecmp->ecm_mutex);

		return (USB_FAILURE);
	}
	mutex_exit(&ecmp->ecm_mutex);

	data_len = msgsize(data);
	if (data_len > ETHERMAX) {
		mutex_enter(&ecmp->ecm_mutex);
		ecmp->ecm_stat.es_macxmt_err++;
		mutex_exit(&ecmp->ecm_mutex);

		USB_DPRINTF_L2(PRINT_MASK_OPS, ecmp->ecm_lh,
		    "usbecm_send_data: packet too long, %d", data_len);

		return (USB_FAILURE);
	}

	if (data_len < ETHERMIN) {
		mblk_t *tmp;

		USB_DPRINTF_L4(PRINT_MASK_OPS, ecmp->ecm_lh,
		    "usbecm_send_data: short packet, padding to ETHERMIN");

		new_data_len = ETHERMIN;
		if ((new_data = allocb(new_data_len, 0)) == NULL) {
			USB_DPRINTF_L2(PRINT_MASK_OPS, ecmp->ecm_lh,
			    "usbecm_send_data: fail to allocb");

			return (USB_FAILURE);
		}
		bzero(new_data->b_wptr, new_data_len);
		for (tmp = data; tmp != NULL; tmp = tmp->b_cont) {
			bcopy(tmp->b_rptr, new_data->b_wptr, MBLKL(tmp));
			new_data->b_wptr += MBLKL(tmp);
		}

		new_data->b_wptr = new_data->b_rptr + new_data_len;
	}

	br = usb_alloc_bulk_req(ecmp->ecm_dip, 0, USB_FLAGS_SLEEP);
	if (br == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_OPS, ecmp->ecm_lh,
		    "usbecm_send_data: alloc req failed.");

		return (USB_FAILURE);
	}

	/* initialize the bulk out request */
	if (new_data) {
		br->bulk_data = msgpullup(new_data, -1); /* msg allocated! */
		br->bulk_len = new_data_len;
	} else {
		br->bulk_data = msgpullup(data, -1); /* msg allocated! */
		br->bulk_len = data_len;
	}

	USB_DPRINTF_L4(PRINT_MASK_OPS, ecmp->ecm_lh,
	    "usbecm_send_data: bulk_len = %d", br->bulk_len);

	br->bulk_timeout = USBECM_BULKOUT_TIMEOUT;
	br->bulk_cb = usbecm_bulkout_cb;
	br->bulk_exc_cb = usbecm_bulkout_cb;
	br->bulk_client_private = (usb_opaque_t)ecmp;
	br->bulk_attributes = USB_ATTRS_AUTOCLEARING;

	if (br->bulk_data != NULL) {
		if (br->bulk_data->b_rptr[0] & 0x01) {
			mutex_enter(&ecmp->ecm_mutex);
			if (bcmp(br->bulk_data->b_rptr, usbecm_broadcast,
			    ETHERADDRL) != 0) {
				ecmp->ecm_stat.es_multixmt++;
			} else {
				ecmp->ecm_stat.es_brdcstxmt++;
			}
			mutex_exit(&ecmp->ecm_mutex);
		}
		rval = usb_pipe_bulk_xfer(ecmp->ecm_bulkout_ph, br, 0);
	}

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_OPS, ecmp->ecm_lh,
		    "usbecm_send_data: Send Data failed.");

		/*
		 * br->bulk_data should be freed because we allocated
		 * it in this function.
		 */
		usb_free_bulk_req(br);

	} else {
		mutex_enter(&ecmp->ecm_mutex);
		ecmp->ecm_tx_cnt++;
		mutex_exit(&ecmp->ecm_mutex);

		/*
		 * ECM V1.2, section 3.3.1, a short(including zero length)
		 * packet signifies end of frame. We should send a zero length
		 * packet to device if the total data lenght is multiple of
		 * bulkout endpoint's max packet size.
		 */
		max_pkt_size = ecmp->ecm_bulk_out_ep->ep_descr.wMaxPacketSize;
		if ((data_len % max_pkt_size) == 0) {
			if ((rval = usbecm_send_zero_data(ecmp))
			    != USB_SUCCESS) {
				USB_DPRINTF_L2(PRINT_MASK_OPS, ecmp->ecm_lh,
				    "usbecm_send_data: fail to send padding");
			}
		}
	}

	if (new_data) {
		freemsg(new_data);
	}

	USB_DPRINTF_L4(PRINT_MASK_EVENTS, ecmp->ecm_lh,
	    "usbecm_send_data: len(%d) data sent, rval=%d",
	    new_data_len ? new_data_len : data_len, rval);

	return (rval);
}

static int
usbecm_send_zero_data(usbecm_state_t *ecmp)
{
	usb_bulk_req_t	*br;
	int		rval = USB_FAILURE;

	USB_DPRINTF_L4(PRINT_MASK_OPS, ecmp->ecm_lh,
	    "usbecm_send_zero_data: entry");

	br = usb_alloc_bulk_req(ecmp->ecm_dip, 0, USB_FLAGS_SLEEP);
	if (br == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_OPS, ecmp->ecm_lh,
		    "usbecm_send_data: alloc req failed.");

		return (USB_FAILURE);
	}

	/* initialize the bulk out request */
	br->bulk_len = 0;
	br->bulk_timeout = USBECM_BULKOUT_TIMEOUT;
	br->bulk_cb = usbecm_bulkout_cb;
	br->bulk_exc_cb = usbecm_bulkout_cb;
	br->bulk_client_private = (usb_opaque_t)ecmp;
	br->bulk_attributes = USB_ATTRS_AUTOCLEARING;

	rval = usb_pipe_bulk_xfer(ecmp->ecm_bulkout_ph, br, 0);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_OPS, ecmp->ecm_lh,
		    "usbecm_send_zero_data: Send data failed, rval=%d",
		    rval);

		/*
		 * br->bulk_data should be freed because we allocated
		 * it in this function.
		 */
		usb_free_bulk_req(br);

	}

	USB_DPRINTF_L4(PRINT_MASK_OPS, ecmp->ecm_lh,
	    "usbecm_send_zero_data: end");

	return (rval);
}

/*
 * Loadable module configuration entry points
 */

/*
 * _init module entry point.
 *
 * Called when the module is being loaded into memory.
 */
int
_init(void)
{
	int err;

	err = ddi_soft_state_init(&usbecm_statep, sizeof (usbecm_state_t), 1);

	if (err != DDI_SUCCESS)
		return (err);

	mac_init_ops(&usbecm_devops, "usbecm");
	err = mod_install(&usbecm_ml);

	if (err != DDI_SUCCESS) {
		mac_fini_ops(&usbecm_devops);
		ddi_soft_state_fini(&usbecm_statep);
	}

	return (err);
}

/*
 * _info module entry point.
 *
 * Called to obtain information about the module.
 */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&usbecm_ml, modinfop));
}

/*
 * _fini module entry point.
 *
 * Called when the module is being unloaded.
 */
int
_fini(void)
{
	int err;

	err = mod_remove(&usbecm_ml);
	if (err == DDI_SUCCESS) {
		mac_fini_ops(&usbecm_devops);
		ddi_soft_state_fini(&usbecm_statep);
	}

	return (err);
}

/*
 * usbecm_pipe_start_polling:
 *	start polling on the interrupt pipe
 */
static void
usbecm_pipe_start_polling(usbecm_state_t *ecmp)
{
	usb_intr_req_t	*intr;
	int		rval;

	USB_DPRINTF_L4(PRINT_MASK_OPEN, ecmp->ecm_lh,
	    "usbecm_pipe_start_polling: ");

	if (ecmp->ecm_intr_ph == NULL) {

		return;
	}

	intr = usb_alloc_intr_req(ecmp->ecm_dip, 0, USB_FLAGS_SLEEP);

	/*
	 * If it is in interrupt context, usb_alloc_intr_req will return NULL if
	 * called with SLEEP flag.
	 */
	if (!intr) {
		USB_DPRINTF_L2(PRINT_MASK_OPEN, ecmp->ecm_lh,
		    "usbecm_pipe_start_polling: alloc req failed.");

		return;
	}

	/* initialize the interrupt request. */
	intr->intr_attributes = USB_ATTRS_SHORT_XFER_OK |
	    USB_ATTRS_AUTOCLEARING;
	intr->intr_len = ecmp->ecm_intr_ep->ep_descr.wMaxPacketSize;
	intr->intr_client_private = (usb_opaque_t)ecmp;
	intr->intr_cb = usbecm_intr_cb;
	intr->intr_exc_cb = usbecm_intr_ex_cb;

	rval = usb_pipe_intr_xfer(ecmp->ecm_intr_ph, intr, USB_FLAGS_SLEEP);

	mutex_enter(&ecmp->ecm_mutex);
	if (rval == USB_SUCCESS) {
		ecmp->ecm_intr_state = USBECM_PIPE_BUSY;
	} else {
		usb_free_intr_req(intr);
		ecmp->ecm_intr_state = USBECM_PIPE_IDLE;
		USB_DPRINTF_L3(PRINT_MASK_OPEN, ecmp->ecm_lh,
		    "usbecm_pipe_start_polling: failed (%d)", rval);
	}
	mutex_exit(&ecmp->ecm_mutex);

	USB_DPRINTF_L3(PRINT_MASK_OPEN, ecmp->ecm_lh,
	    "usbecm_pipe_start_polling: end, rval=%d", rval);
}


/*
 * usbsecm_intr_cb:
 *	interrupt pipe normal callback
 */
/*ARGSUSED*/
static void
usbecm_intr_cb(usb_pipe_handle_t ph, usb_intr_req_t *req)
{
	usbecm_state_t *ecmp = (usbecm_state_t *)req->intr_client_private;
	mblk_t		*data = req->intr_data;
	int		data_len;

	data_len = (data) ? MBLKL(data) : 0;

	DTRACE_PROBE2(usbecm_intr__cb, (usb_intr_req_t *), req, int, data_len);

	/* check data length */
	if (data_len < 8) {
		USB_DPRINTF_L2(PRINT_MASK_CB, ecmp->ecm_lh,
		    "usbsecm_intr_cb: %d packet too short", data_len);
		usb_free_intr_req(req);

		return;
	}
	req->intr_data = NULL;
	usb_free_intr_req(req);

	mutex_enter(&ecmp->ecm_mutex);
	/* parse interrupt data -- notifications */
	usbecm_parse_intr_data(ecmp, data);
	mutex_exit(&ecmp->ecm_mutex);
}


/*
 * usbsecm_intr_ex_cb:
 *	interrupt pipe exception callback
 */
/*ARGSUSED*/
static void
usbecm_intr_ex_cb(usb_pipe_handle_t ph, usb_intr_req_t *req)
{
	usbecm_state_t *ecmp = (usbecm_state_t *)req->intr_client_private;
	usb_cr_t	cr = req->intr_completion_reason;

	DTRACE_PROBE2(usbecm_intr_ex__cb, int, ecmp->ecm_dev_state,
	    (usb_cr_t), cr);

	usb_free_intr_req(req);

	/*
	 * If completion reason isn't USB_CR_PIPE_CLOSING and
	 * USB_CR_STOPPED_POLLING, restart polling.
	 */
	if ((cr != USB_CR_PIPE_CLOSING) && (cr != USB_CR_STOPPED_POLLING)) {
		mutex_enter(&ecmp->ecm_mutex);

		if (ecmp->ecm_dev_state != USB_DEV_ONLINE) {

			USB_DPRINTF_L2(PRINT_MASK_CB, ecmp->ecm_lh,
			    "usbsecm_intr_ex_cb: state = %d",
			    ecmp->ecm_dev_state);

			mutex_exit(&ecmp->ecm_mutex);

			return;
		}
		mutex_exit(&ecmp->ecm_mutex);

		usbecm_pipe_start_polling(ecmp);
	}
}


/*
 * usbsecm_parse_intr_data:
 *	Parse data received from interrupt callback
 */
static void
usbecm_parse_intr_data(usbecm_state_t *ecmp, mblk_t *data)
{
	uint8_t		bmRequestType;
	uint8_t		bNotification;
	uint16_t	wValue;
	uint16_t	wLength;
	int		linkstate;

	bmRequestType = data->b_rptr[0];
	bNotification = data->b_rptr[1];
	/*
	 * If Notification type is NETWORK_CONNECTION, wValue is 0 or 1,
	 * mLength is 0. If Notification type is SERIAL_TYPE, mValue is 0,
	 * mLength is 2. So we directly get the value from the byte.
	 */
	wValue = data->b_rptr[2];
	wLength = data->b_rptr[6];

	if (ecmp->ecm_compatibility) {
		if (bmRequestType != USB_CDC_NOTIFICATION_REQUEST_TYPE) {
			USB_DPRINTF_L2(PRINT_MASK_CB, ecmp->ecm_lh,
			    "usbsecm_parse_intr_data: unknown request "
			    "type - 0x%x", bmRequestType);

			freemsg(data);

			return;
		}
	} else {
		/* non-compatible device specific parsing */
		if (ECM_DS_OP_VALID(ecm_ds_intr_cb)) {
			if (ecmp->ecm_ds_ops->ecm_ds_intr_cb(ecmp, data)
			    != USB_SUCCESS) {
				USB_DPRINTF_L2(PRINT_MASK_CB, ecmp->ecm_lh,
				    "usbsecm_parse_intr_data: unknown request"
				    "type - 0x%x", bmRequestType);
			}
		}
		freemsg(data);

		return;
	}

	/*
	 * Check the return value of compatible devices
	 */
	switch (bNotification) {
	case USB_CDC_NOTIFICATION_NETWORK_CONNECTION:
		USB_DPRINTF_L3(PRINT_MASK_CB, ecmp->ecm_lh,
		    "usbsecm_parse_intr_data: %s network!",
		    wValue ? "connected to" :"disconnected from");

		linkstate = wValue ? LINK_STATE_UP:LINK_STATE_DOWN;
		if (ecmp->ecm_stat.es_linkstate == linkstate) {
		/* no changes to previous state */
			break;
		}

		ecmp->ecm_stat.es_linkstate = linkstate;
		mutex_exit(&ecmp->ecm_mutex);
		mac_link_update(ecmp->ecm_mh, linkstate);
		mutex_enter(&ecmp->ecm_mutex);

		break;
	case USB_CDC_NOTIFICATION_RESPONSE_AVAILABLE:
		USB_DPRINTF_L3(PRINT_MASK_CB, ecmp->ecm_lh,
		    "usbsecm_parse_intr_data: A response is a available.");

		break;
	case USB_CDC_NOTIFICATION_SPEED_CHANGE:
		USB_DPRINTF_L3(PRINT_MASK_CB, ecmp->ecm_lh,
		    "usbsecm_parse_intr_data: speed change");

		/* check the parameter's length. */
		if (wLength != 8) {
			USB_DPRINTF_L3(PRINT_MASK_CB, ecmp->ecm_lh,
			    "usbsecm_parse_intr_data: error data length.");
		} else {
			uint32_t	us_rate, ds_rate;
			uint8_t		*sp;

			sp = &data->b_rptr[8];
			LE_TO_UINT32(sp, us_rate);
			sp = &data->b_rptr[12];
			LE_TO_UINT32(sp, ds_rate);
			ecmp->ecm_stat.es_upspeed = us_rate;
			ecmp->ecm_stat.es_downspeed = ds_rate;
		}

		break;
	default:
		USB_DPRINTF_L3(PRINT_MASK_CB, ecmp->ecm_lh,
		    "usbsecm_parse_intr_data: unknown notification - 0x%x!",
		    bNotification);

		break;
	}

	freemsg(data);
}

/*
 * usbecm_restore_device_state:
 *	restore device state after CPR resume or reconnect
 */
static int
usbecm_restore_device_state(usbecm_state_t *ecmp)
{
	int	state;

	USB_DPRINTF_L4(PRINT_MASK_EVENTS, ecmp->ecm_lh,
	    "usbecm_restore_device_state: ");

	mutex_enter(&ecmp->ecm_mutex);
	state = ecmp->ecm_dev_state;
	mutex_exit(&ecmp->ecm_mutex);

	/* Check device status */
	if ((state != USB_DEV_DISCONNECTED) && (state != USB_DEV_SUSPENDED)) {

		return (state);
	}

	/* Check if we are talking to the same device */
	if (usb_check_same_device(ecmp->ecm_dip, ecmp->ecm_lh, USB_LOG_L0,
	    -1, USB_CHK_ALL, NULL) != USB_SUCCESS) {
		mutex_enter(&ecmp->ecm_mutex);
		state = ecmp->ecm_dev_state = USB_DEV_DISCONNECTED;
		mutex_exit(&ecmp->ecm_mutex);

		return (state);
	}

	if (state == USB_DEV_DISCONNECTED) {
		USB_DPRINTF_L1(PRINT_MASK_EVENTS, ecmp->ecm_lh,
		    "usbecm_restore_device_state: Device has been reconnected "
		    "but data may have been lost");
	}

	/* if MAC was started, restarted it */
	mutex_enter(&ecmp->ecm_mutex);
	if (ecmp->ecm_mac_state == USBECM_MAC_STARTED) {
		USB_DPRINTF_L3(PRINT_MASK_EVENTS, ecmp->ecm_lh,
		    "usbecm_restore_device_state: MAC was started");

		mutex_exit(&ecmp->ecm_mutex);
		/* Do the same operation as usbecm_m_start() does */
		if (usbecm_open_pipes(ecmp) != USB_SUCCESS) {

			return (state);
		}

		mutex_enter(&ecmp->ecm_mutex);
		if (usbecm_rx_start(ecmp) != USB_SUCCESS) {
			mutex_exit(&ecmp->ecm_mutex);

			return (state);
		}
	}
	mutex_exit(&ecmp->ecm_mutex);

	/*
	 * init device state
	 */
	mutex_enter(&ecmp->ecm_mutex);
	state = ecmp->ecm_dev_state = USB_DEV_ONLINE;
	mutex_exit(&ecmp->ecm_mutex);

	return (state);
}

/*
 * usbecm_reconnect_event_cb:
 *     called upon when the device is hotplugged back
 */
/*ARGSUSED*/
static int
usbecm_reconnect_event_cb(dev_info_t *dip)
{
	usbecm_state_t	*ecmp =
	    (usbecm_state_t *)ddi_get_soft_state(usbecm_statep,
	    ddi_get_instance(dip));

	ASSERT(ecmp != NULL);

	USB_DPRINTF_L4(PRINT_MASK_EVENTS, ecmp->ecm_lh,
	    "usbecm_reconnect_event_cb: entry");

	(void) usb_serialize_access(ecmp->ecm_ser_acc, USB_WAIT, 0);

	mutex_enter(&ecmp->ecm_mutex);
	ASSERT(ecmp->ecm_dev_state == USB_DEV_DISCONNECTED);

	mutex_exit(&ecmp->ecm_mutex);

	if (usbecm_restore_device_state(ecmp) != USB_DEV_ONLINE) {
		usb_release_access(ecmp->ecm_ser_acc);

		return (USB_FAILURE);
	}

	usb_release_access(ecmp->ecm_ser_acc);

	return (USB_SUCCESS);
}


/*
 * usbecm_disconnect_event_cb:
 *	callback for disconnect events
 */
/*ARGSUSED*/
static int
usbecm_disconnect_event_cb(dev_info_t *dip)
{
	usbecm_state_t	*ecmp = (usbecm_state_t *)ddi_get_soft_state(
	    usbecm_statep, ddi_get_instance(dip));

	USB_DPRINTF_L4(PRINT_MASK_EVENTS, ecmp->ecm_lh,
	    "usbecm_disconnect_event_cb: entry");

	(void) usb_serialize_access(ecmp->ecm_ser_acc, USB_WAIT, 0);

	mutex_enter(&ecmp->ecm_mutex);
	ecmp->ecm_dev_state = USB_DEV_DISCONNECTED;
	mutex_exit(&ecmp->ecm_mutex);

	usbecm_close_pipes(ecmp);

	usb_release_access(ecmp->ecm_ser_acc);

	USB_DPRINTF_L4(PRINT_MASK_EVENTS, ecmp->ecm_lh,
	    "usbecm_disconnect_event_cb: End");

	return (USB_SUCCESS);
}

/*
 * power management
 * ----------------
 *
 * usbecm_create_pm_components:
 *	create PM components
 */
static int
usbecm_create_pm_components(usbecm_state_t *ecmp)
{
	dev_info_t	*dip = ecmp->ecm_dip;
	usbecm_pm_t	*pm;
	uint_t		pwr_states;

	USB_DPRINTF_L4(PRINT_MASK_PM, ecmp->ecm_lh,
	    "usbecm_create_pm_components: entry");

	if (usb_create_pm_components(dip, &pwr_states) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_PM, ecmp->ecm_lh,
		    "usbecm_create_pm_components: failed");

		/* don't fail the attach process */
		return (USB_SUCCESS);
	}

	pm = ecmp->ecm_pm =
	    (usbecm_pm_t *)kmem_zalloc(sizeof (usbecm_pm_t), KM_SLEEP);

	pm->pm_pwr_states = (uint8_t)pwr_states;
	pm->pm_cur_power = USB_DEV_OS_FULL_PWR;
	pm->pm_wakeup_enabled = (usb_handle_remote_wakeup(dip,
	    USB_REMOTE_WAKEUP_ENABLE) == USB_SUCCESS);

	(void) pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);

	return (USB_SUCCESS);
}

/*
 * usbecm_cleanup:
 *	Release resources of current device during detach.
 */
static void
usbecm_cleanup(usbecm_state_t *ecmp)
{
	USB_DPRINTF_L4(PRINT_MASK_CLOSE, ecmp->ecm_lh,
	    "usbecm_cleanup: ");

	if (ecmp == NULL) {

		return;
	}

	usbecm_close_pipes(ecmp);

	/* unregister callback function */
	if (ecmp->ecm_init_flags & USBECM_INIT_EVENTS) {
		USB_DPRINTF_L4(PRINT_MASK_CLOSE, ecmp->ecm_lh,
		    "usbecm_cleanup: unregister events");

		usb_unregister_event_cbs(ecmp->ecm_dip, &usbecm_events);
	}

	/* destroy power management components */
	if (ecmp->ecm_pm != NULL) {
		USB_DPRINTF_L4(PRINT_MASK_CLOSE, ecmp->ecm_lh,
		    "usbecm_cleanup: destroy pm");
		usbecm_destroy_pm_components(ecmp);
	}

	/* free description of device tree. */
	if (ecmp->ecm_def_ph != NULL) {
		mutex_destroy(&ecmp->ecm_mutex);

		usb_free_descr_tree(ecmp->ecm_dip, ecmp->ecm_dev_data);
		ecmp->ecm_def_ph = NULL;
	}

	if (ecmp->ecm_lh != NULL) {
		usb_free_log_hdl(ecmp->ecm_lh);
		ecmp->ecm_lh = NULL;
	}

	/* detach client device */
	if (ecmp->ecm_dev_data != NULL) {
		usb_client_detach(ecmp->ecm_dip, ecmp->ecm_dev_data);
	}

	if (ecmp->ecm_init_flags & USBECM_INIT_MAC) {
		(void) usbecm_mac_fini(ecmp);
	}

	if (ecmp->ecm_init_flags & USBECM_INIT_SER) {
		usb_fini_serialization(ecmp->ecm_ser_acc);
	}

	ddi_prop_remove_all(ecmp->ecm_dip);
	ddi_remove_minor_node(ecmp->ecm_dip, NULL);
}

/*
 * usbecm_destroy_pm_components:
 *	destroy PM components
 */
static void
usbecm_destroy_pm_components(usbecm_state_t *ecmp)
{
	usbecm_pm_t	*pm = ecmp->ecm_pm;
	dev_info_t	*dip = ecmp->ecm_dip;
	int		rval;

	USB_DPRINTF_L4(PRINT_MASK_PM, ecmp->ecm_lh,
	    "usbecm_destroy_pm_components: ");

	if (ecmp->ecm_dev_state != USB_DEV_DISCONNECTED) {
		if (pm->pm_wakeup_enabled) {
			rval = pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);
			if (rval != DDI_SUCCESS) {
				USB_DPRINTF_L2(PRINT_MASK_PM, ecmp->ecm_lh,
				    "usbecm_destroy_pm_components: "
				    "raising power failed (%d)", rval);
			}

			rval = usb_handle_remote_wakeup(dip,
			    USB_REMOTE_WAKEUP_DISABLE);
			if (rval != USB_SUCCESS) {
				USB_DPRINTF_L2(PRINT_MASK_PM, ecmp->ecm_lh,
				    "usbecm_destroy_pm_components: "
				    "disable remote wakeup failed (%d)", rval);
			}
		}

		(void) pm_lower_power(dip, 0, USB_DEV_OS_PWR_OFF);
	}
	kmem_free((caddr_t)pm, sizeof (usbecm_pm_t));
	ecmp->ecm_pm = NULL;
}

/*
 * usbecm_pm_set_busy:
 *	mark device busy and raise power
 */
static void
usbecm_pm_set_busy(usbecm_state_t *ecmp)
{
	usbecm_pm_t	*pm = ecmp->ecm_pm;
	dev_info_t	*dip = ecmp->ecm_dip;
	int		rval;

	USB_DPRINTF_L4(PRINT_MASK_PM, ecmp->ecm_lh,
	    "usbecm_pm_set_busy: pm = 0x%p", (void *)pm);

	if (pm == NULL) {

		return;
	}

	mutex_enter(&ecmp->ecm_mutex);
	/* if already marked busy, just increment the counter */
	if (pm->pm_busy_cnt++ > 0) {
		mutex_exit(&ecmp->ecm_mutex);

		return;
	}

	(void) pm_busy_component(dip, 0);

	if (pm->pm_cur_power == USB_DEV_OS_FULL_PWR) {
		mutex_exit(&ecmp->ecm_mutex);

		return;
	}

	/* need to raise power	*/
	pm->pm_raise_power = B_TRUE;
	mutex_exit(&ecmp->ecm_mutex);

	rval = pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);
	if (rval != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_PM, ecmp->ecm_lh,
		    "usbecm_pm_set_busy: raising power failed");
	}

	mutex_enter(&ecmp->ecm_mutex);
	pm->pm_raise_power = B_FALSE;
	mutex_exit(&ecmp->ecm_mutex);
}


/*
 * usbecm_pm_set_idle:
 *	mark device idle
 */
static void
usbecm_pm_set_idle(usbecm_state_t *ecmp)
{
	usbecm_pm_t	*pm = ecmp->ecm_pm;
	dev_info_t	*dip = ecmp->ecm_dip;

	USB_DPRINTF_L4(PRINT_MASK_PM, ecmp->ecm_lh,
	    "usbecm_pm_set_idle: ");

	if (pm == NULL) {

		return;
	}

	mutex_enter(&ecmp->ecm_mutex);
	if (--pm->pm_busy_cnt > 0) {
		mutex_exit(&ecmp->ecm_mutex);

		return;
	}

	if (pm) {
		(void) pm_idle_component(dip, 0);
	}
	mutex_exit(&ecmp->ecm_mutex);
}


/*
 * usbecm_pwrlvl0:
 *	Functions to handle power transition for OS levels 0 -> 3
 *	The same level as OS state, different from USB state
 */
static int
usbecm_pwrlvl0(usbecm_state_t *ecmp)
{
	int		rval;

	ASSERT(mutex_owned(&ecmp->ecm_mutex));

	USB_DPRINTF_L4(PRINT_MASK_PM, ecmp->ecm_lh,
	    "usbecm_pwrlvl0: ");

	switch (ecmp->ecm_dev_state) {
	case USB_DEV_ONLINE:
		/* issue USB D3 command to the device */
		rval = usb_set_device_pwrlvl3(ecmp->ecm_dip);
		ASSERT(rval == USB_SUCCESS);
		if ((ecmp->ecm_intr_ph != NULL) &&
		    (ecmp->ecm_intr_state == USBECM_PIPE_BUSY)) {
			mutex_exit(&ecmp->ecm_mutex);
			usb_pipe_stop_intr_polling(ecmp->ecm_intr_ph,
			    USB_FLAGS_SLEEP);
			mutex_enter(&ecmp->ecm_mutex);

			ecmp->ecm_intr_state = USBECM_PIPE_IDLE;
		}
		ecmp->ecm_dev_state = USB_DEV_PWRED_DOWN;
		ecmp->ecm_pm->pm_cur_power = USB_DEV_OS_PWR_OFF;

		/* FALLTHRU */
	case USB_DEV_DISCONNECTED:
	case USB_DEV_SUSPENDED:
		/* allow a disconnect/cpr'ed device to go to lower power */

		return (USB_SUCCESS);
	case USB_DEV_PWRED_DOWN:
	default:
		USB_DPRINTF_L2(PRINT_MASK_PM, ecmp->ecm_lh,
		    "usbecm_pwrlvl0: illegal device state");

		return (USB_FAILURE);
	}
}


/*
 * usbecm_pwrlvl1:
 *	Functions to handle power transition for OS levels 1 -> 2
 */
static int
usbecm_pwrlvl1(usbecm_state_t *ecmp)
{
	/* issue USB D2 command to the device */
	(void) usb_set_device_pwrlvl2(ecmp->ecm_dip);

	return (USB_FAILURE);
}


/*
 * usbecm_pwrlvl2:
 *	Functions to handle power transition for OS levels 2 -> 1
 */
static int
usbecm_pwrlvl2(usbecm_state_t *ecmp)
{
	/* issue USB D1 command to the device */
	(void) usb_set_device_pwrlvl1(ecmp->ecm_dip);

	return (USB_FAILURE);
}


/*
 * usbecm_pwrlvl3:
 *	Functions to handle power transition for OS levels 3 -> 0
 *	The same level as OS state, different from USB state
 */
static int
usbecm_pwrlvl3(usbecm_state_t *ecmp)
{
	int		rval;

	USB_DPRINTF_L4(PRINT_MASK_PM, ecmp->ecm_lh,
	    "usbecm_pwrlvl3: ");

	ASSERT(mutex_owned(&ecmp->ecm_mutex));

	switch (ecmp->ecm_dev_state) {
	case USB_DEV_PWRED_DOWN:
		/* Issue USB D0 command to the device here */
		rval = usb_set_device_pwrlvl0(ecmp->ecm_dip);
		ASSERT(rval == USB_SUCCESS);

		if (ecmp->ecm_intr_ph != NULL &&
		    ecmp->ecm_intr_state == USBECM_PIPE_IDLE) {
			mutex_exit(&ecmp->ecm_mutex);
			usbecm_pipe_start_polling(ecmp);
			mutex_enter(&ecmp->ecm_mutex);
		}

		ecmp->ecm_dev_state = USB_DEV_ONLINE;
		ecmp->ecm_pm->pm_cur_power = USB_DEV_OS_FULL_PWR;

		/* FALLTHRU */
	case USB_DEV_ONLINE:
		/* we are already in full power */

		/* FALLTHRU */
	case USB_DEV_DISCONNECTED:
	case USB_DEV_SUSPENDED:

		return (USB_SUCCESS);
	default:
		USB_DPRINTF_L2(PRINT_MASK_PM, ecmp->ecm_lh,
		    "usbecm_pwrlvl3: illegal device state");

		return (USB_FAILURE);
	}
}

/*ARGSUSED*/
static int
usbecm_power(dev_info_t *dip, int comp, int level)
{
	usbecm_state_t	*ecmp;
	usbecm_pm_t	*pm;
	int		rval = USB_SUCCESS;

	ecmp = ddi_get_soft_state(usbecm_statep, ddi_get_instance(dip));
	pm = ecmp->ecm_pm;

	USB_DPRINTF_L4(PRINT_MASK_PM, ecmp->ecm_lh,
	    "usbecm_power: entry");

	/* check if pm is NULL */
	if (pm == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_PM, ecmp->ecm_lh,
		    "usbecm_power: pm is NULL.");

		return (USB_FAILURE);
	}

	mutex_enter(&ecmp->ecm_mutex);
	/*
	 * check if we are transitioning to a legal power level
	 */
	if (USB_DEV_PWRSTATE_OK(pm->pm_pwr_states, level)) {
		USB_DPRINTF_L2(PRINT_MASK_PM, ecmp->ecm_lh,
		    "usbecm_power: "
		    "illegal power level %d, pwr_states=%x",
		    level, pm->pm_pwr_states);
		mutex_exit(&ecmp->ecm_mutex);

		return (USB_FAILURE);
	}

	/*
	 * if we are about to raise power and asked to lower power, fail
	 */
	if (pm->pm_raise_power && (level < (int)pm->pm_cur_power)) {
		USB_DPRINTF_L2(PRINT_MASK_PM, ecmp->ecm_lh,
		    "usbecm_power: wrong condition.");
		mutex_exit(&ecmp->ecm_mutex);

		return (USB_FAILURE);
	}

	/*
	 * Set the power status of device by request level.
	 */
	switch (level) {
	case USB_DEV_OS_PWR_OFF:
		rval = usbecm_pwrlvl0(ecmp);

		break;
	case USB_DEV_OS_PWR_1:
		rval = usbecm_pwrlvl1(ecmp);

		break;
	case USB_DEV_OS_PWR_2:
		rval = usbecm_pwrlvl2(ecmp);

		break;
	case USB_DEV_OS_FULL_PWR:
		rval = usbecm_pwrlvl3(ecmp);

		break;
	}

	mutex_exit(&ecmp->ecm_mutex);

	return (rval);
}

/*
 * Register with the MAC layer.
 */
static int
usbecm_mac_init(usbecm_state_t *ecmp)
{
	mac_register_t *macp;
	int err;

	/*
	 * Initialize mac structure
	 */
	macp = mac_alloc(MAC_VERSION);
	if (macp == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ecmp->ecm_lh,
		    "failed to allocate MAC structure");

		return (USB_FAILURE);
	}

	/*
	 * Initialize pointer to device specific functions
	 */
	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_driver = ecmp;
	macp->m_dip = ecmp->ecm_dip;

	macp->m_src_addr = ecmp->ecm_srcaddr;
	macp->m_callbacks = &usbecm_m_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = ETHERMTU;

	/*
	 * Register the macp to mac
	 */
	err = mac_register(macp, &ecmp->ecm_mh);
	mac_free(macp);

	if (err != DDI_SUCCESS) {
		USB_DPRINTF_L1(PRINT_MASK_ATTA, ecmp->ecm_lh,
		    "failed to register MAC structure");

		return (USB_FAILURE);
	}

	mac_link_update(ecmp->ecm_mh, LINK_STATE_DOWN);
	ecmp->ecm_stat.es_linkstate = LINK_STATE_DOWN;
	ecmp->ecm_tx_cnt = 0;

	return (USB_SUCCESS);
}

static int
usbecm_mac_fini(usbecm_state_t *ecmp)
{
	int rval = DDI_SUCCESS;

	if ((ecmp->ecm_init_flags & USBECM_INIT_MAC) == 0) {
		return (DDI_SUCCESS);
	}

	ecmp->ecm_init_flags &= ~USBECM_INIT_MAC;
	if ((rval = mac_disable(ecmp->ecm_mh)) != 0) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ecmp->ecm_lh,
		    "failed to disable MAC");

		return (rval);
	}

	(void) mac_unregister(ecmp->ecm_mh);

	return (rval);
}

static int
usbecm_resume(usbecm_state_t *ecmp)
{
	int		current_state;
	int		ret;

	USB_DPRINTF_L4(PRINT_MASK_PM, ecmp->ecm_lh,
	    "usbecm_resume: ");

	mutex_enter(&ecmp->ecm_mutex);
	current_state = ecmp->ecm_dev_state;
	mutex_exit(&ecmp->ecm_mutex);

	/* restore the status of device */
	if (current_state != USB_DEV_ONLINE) {
		ret = usbecm_restore_device_state(ecmp);
	} else {
		ret = USB_DEV_ONLINE;
	}

	return (ret);
}

static int
usbecm_suspend(usbecm_state_t *ecmp)
{
	(void) usb_serialize_access(ecmp->ecm_ser_acc, USB_WAIT, 0);

	mutex_enter(&ecmp->ecm_mutex);
	ecmp->ecm_dev_state = USB_DEV_SUSPENDED;
	mutex_exit(&ecmp->ecm_mutex);

	usbecm_close_pipes(ecmp);

	usb_release_access(ecmp->ecm_ser_acc);

	return (0);
}

/*
 * Translate MAC address from string to 6 bytes array int value
 * Can't use ether_aton() since it requires format of x:x:x:x:x:x
 */
void
label_to_mac(char *hex, unsigned char *mac)
{
	int i;
	char c;

	/* can only count 6 bytes! */
	for (i = 0; i < 6; i++) {
		/* upper 4 bits */
		if (!isdigit(hex[2*i])) {
			c = (toupper(hex[2 * i]) - 'A' + 10);
		} else {
			c = (hex[2 * i] - '0');
		}
		mac[i] = c * 16;

		/* lower 4 bits */
		if (!isdigit(hex[2*i + 1])) {
			c = (toupper(hex[2 * i + 1]) - 'A' + 10);
		} else {
			c = hex[2 * i + 1] - '0';
		}
		mac[i] += c;
	}
}

/*
 * usbecm_get_descriptors:
 *	parse functional descriptors of ecm compatible device
 */
static int
usbecm_get_descriptors(usbecm_state_t *ecmp)
{
	int			i;
	usb_cfg_data_t		*cfg;
	usb_alt_if_data_t	*altif;
	usb_cvs_data_t		*cvs;
	int16_t			master_if = -1, slave_if = -1;
	usb_cdc_ecm_descr_t	ecm_desc;
	usb_ep_data_t		*ep_data;
	usb_dev_descr_t		*usb_dev_desc;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ecmp->ecm_lh,
	    "usbecm_get_descriptors: ");

	usb_dev_desc = ecmp->ecm_dev_data->dev_descr;

	/*
	 * Special treatment of Sun's SP Ethernet device.
	 */
	if ((usb_dev_desc->idVendor == SUN_SP_VENDOR_ID) &&
	    (usb_dev_desc->idProduct == SUN_SP_PRODUCT_ID)) {
		if (usb_set_cfg(ecmp->ecm_dip, ecmp->ecm_cfg_index,
		    USB_FLAGS_SLEEP, NULL, NULL) != USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA, ecmp->ecm_lh,
			    "usbecm_get_descriptors: fail to set cfg ");
		} else {
			usb_free_dev_data(ecmp->ecm_dip, ecmp->ecm_dev_data);
			if (usb_get_dev_data(ecmp->ecm_dip, &ecmp->ecm_dev_data,
			    USB_PARSE_LVL_ALL, 0) != USB_SUCCESS) {
				USB_DPRINTF_L2(PRINT_MASK_ATTA, ecmp->ecm_lh,
				    "usbecm_get_descriptors: fail to get"
				    " dev_data");

				return (USB_FAILURE);
			}
		}
	}

	cfg = ecmp->ecm_dev_data->dev_curr_cfg;

	/* set default control and data interface */
	ecmp->ecm_ctrl_if_no = ecmp->ecm_data_if_no = 0;

	/* get current interfaces */
	ecmp->ecm_ctrl_if_no = ecmp->ecm_dev_data->dev_curr_if;
	if (cfg->cfg_if[ecmp->ecm_ctrl_if_no].if_n_alt == 0) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ecmp->ecm_lh,
		    "usbecm_get_descriptors: elements in if_alt is %d",
		    cfg->cfg_if[ecmp->ecm_ctrl_if_no].if_n_alt);

		return (USB_FAILURE);
	}

	altif = &cfg->cfg_if[ecmp->ecm_ctrl_if_no].if_alt[0];

	/*
	 * Based on CDC specification, ECM devices usually include the
	 * following function descriptors: Header, Union and ECM
	 * Contry Selection function descriptors. This loop search tree data
	 * structure for each ecm class descriptor.
	 */
	for (i = 0; i < altif->altif_n_cvs; i++) {
		cvs = &altif->altif_cvs[i];

		if ((cvs->cvs_buf == NULL) ||
		    (cvs->cvs_buf[1] != USB_CDC_CS_INTERFACE)) {
			continue;
		}

		switch (cvs->cvs_buf[2]) {
		case USB_CDC_DESCR_TYPE_HEADER:
			/*
			 * parse header functional descriptor
			 * Just to check integrity.
			 */
			if (cvs->cvs_buf_len != 5) {
				return (USB_FAILURE);
			}
			break;
		case USB_CDC_DESCR_TYPE_ETHERNET:
			/* parse ECM functional descriptor */
			if (cvs->cvs_buf_len >= USB_CDC_ECM_LEN) {
				char buf[USB_MAXSTRINGLEN];

				if (usb_parse_data("4cl2sc", cvs->cvs_buf,
				    cvs->cvs_buf_len, (void *)&ecm_desc,
				    (size_t)USB_CDC_ECM_LEN) <
				    USB_CDC_ECM_LEN) {

					return (USB_FAILURE);
				}

				/* get the MAC address */
				if (usb_get_string_descr(ecmp->ecm_dip,
				    USB_LANG_ID, ecm_desc.iMACAddress, buf,
				    USB_MAXSTRINGLEN) != USB_SUCCESS) {

					return (USB_FAILURE);
				}

				USB_DPRINTF_L3(PRINT_MASK_ATTA, ecmp->ecm_lh,
				    "usbecm_get_descriptors: macaddr=%s ",
				    buf);

				/* expects 12 characters */
				if (strlen(buf) < 12) {
					return (USB_FAILURE);
				}
				label_to_mac(buf, ecmp->ecm_srcaddr);

				bcopy(&ecm_desc, &ecmp->ecm_desc,
				    USB_CDC_ECM_LEN);
			}
			break;
		case USB_CDC_DESCR_TYPE_UNION:
			/* parse Union functional descriptor. */
			if (cvs->cvs_buf_len >= 5) {
				master_if = cvs->cvs_buf[3];
				slave_if = cvs->cvs_buf[4];
			}
			break;
		default:
			break;
		}
	}

	/* For usb ecm devices, it must satisfy the following options. */
	if (cfg->cfg_n_if < 2) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ecmp->ecm_lh,
		    "usbecm_get_descriptors: # of interfaces %d < 2",
		    cfg->cfg_n_if);

		return (USB_FAILURE);
	}

	if (ecmp->ecm_data_if_no == 0 &&
	    slave_if != ecmp->ecm_data_if_no) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ecmp->ecm_lh,
		    "usbecm_get_descriptors: Device has no call management "
		    "descriptor and use Union Descriptor.");

		ecmp->ecm_data_if_no = slave_if;
	}

	if ((master_if != ecmp->ecm_ctrl_if_no) ||
	    (slave_if != ecmp->ecm_data_if_no)) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ecmp->ecm_lh,
		    "usbecm_get_descriptors: control interface or "
		    "data interface don't match.");

		return (USB_FAILURE);
	}

	if ((ecmp->ecm_ctrl_if_no >= cfg->cfg_n_if) ||
	    (ecmp->ecm_data_if_no >= cfg->cfg_n_if)) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ecmp->ecm_lh,
		    "usbecm_get_descriptors: control interface %d or "
		    "data interface %d out of range.",
		    ecmp->ecm_ctrl_if_no, ecmp->ecm_data_if_no);

		return (USB_FAILURE);
	}

	/* ECM data interface has a minimal of two altsettings */
	if (cfg->cfg_if[ecmp->ecm_data_if_no].if_n_alt < 2) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ecmp->ecm_lh,
		    "usbecm_get_descriptors: elements in if_alt is %d,"
		    " MUST >= 2", cfg->cfg_if[ecmp->ecm_ctrl_if_no].if_n_alt);

		return (USB_FAILURE);
	}

	/* control interface must have interrupt endpoint */
	if ((ep_data = usb_lookup_ep_data(ecmp->ecm_dip, ecmp->ecm_dev_data,
	    ecmp->ecm_ctrl_if_no, 0, 0, USB_EP_ATTR_INTR,
	    USB_EP_DIR_IN)) == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ecmp->ecm_lh,
		    "usbecm_get_descriptors: "
		    "ctrl interface %d has no interrupt endpoint",
		    ecmp->ecm_data_if_no);

		return (USB_FAILURE);
	}
	ecmp->ecm_intr_ep = ep_data;

	/* data interface alt 1 must have bulk in and out(ECM v1.2,p5) */
	if ((ep_data = usb_lookup_ep_data(ecmp->ecm_dip, ecmp->ecm_dev_data,
	    ecmp->ecm_data_if_no, 1, 0, USB_EP_ATTR_BULK,
	    USB_EP_DIR_IN)) == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ecmp->ecm_lh,
		    "usbecm_get_descriptors: "
		    "data interface %d has no bulk in endpoint",
		    ecmp->ecm_data_if_no);

		return (USB_FAILURE);
	}
	ecmp->ecm_bulk_in_ep = ep_data;

	if ((ep_data = usb_lookup_ep_data(ecmp->ecm_dip, ecmp->ecm_dev_data,
	    ecmp->ecm_data_if_no, 1, 0, USB_EP_ATTR_BULK,
	    USB_EP_DIR_OUT)) == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ecmp->ecm_lh,
		    "usbecm_get_descriptors: "
		    "data interface %d has no bulk out endpoint",
		    ecmp->ecm_data_if_no);

		return (USB_FAILURE);
	}
	ecmp->ecm_bulk_out_ep = ep_data;

	/* set default value for ethernet packet filter */
	ecmp->ecm_pkt_flt = CDC_ECM_PKT_TYPE_DIRECTED;

	return (USB_SUCCESS);
}

/* Generate IEEE802 style MAC address */
static void
generate_ether_addr(uint8_t *mac_addr)
{
	(void) random_get_bytes(mac_addr, 6);
	mac_addr [0] &= 0xfe;	/* unicast only */
	mac_addr [0] |= 0x02;	/* set locally administered bit */
}

/*
 * Find a pair of bulk In/Out endpoints
 */
int usbecm_find_bulk_in_out_eps(usbecm_state_t *ecmp,
    uint16_t ifc, usb_if_data_t *intf)
{
	uint16_t alt, alt_num;
	usb_ep_data_t *intr_ep = NULL;
	usb_ep_data_t *bulk_in, *bulk_out, *ep;

	alt_num = intf->if_n_alt;

	/*
	 * for the non-compatible devices, to make it simple, we
	 * suppose the devices have this kind of configuration:
	 *	INTR In EP(if exists) + BULK In + Bulk Out in the
	 *	same altsetting of the same interface
	 */
	for (alt = 0; alt < alt_num; alt++) {
		/* search pair of bulk in/out EPs */
		if (((bulk_in = usb_lookup_ep_data(ecmp->ecm_dip,
		    ecmp->ecm_dev_data, ifc, alt, 0,
		    USB_EP_ATTR_BULK,
		    USB_EP_DIR_IN)) == NULL) ||
		    (bulk_out = usb_lookup_ep_data(ecmp->ecm_dip,
		    ecmp->ecm_dev_data, ifc, alt, 0,
		    USB_EP_ATTR_BULK,
		    USB_EP_DIR_OUT)) == NULL) {

			continue;
		}

		/*
		 * search interrupt pipe.
		 */
		if ((ep = usb_lookup_ep_data(ecmp->ecm_dip,
		    ecmp->ecm_dev_data, ifc, alt, 0,
		    USB_EP_ATTR_INTR, USB_EP_DIR_IN)) != NULL) {
			intr_ep = ep;
		}


		ecmp->ecm_data_if_no = ifc;
		ecmp->ecm_data_if_alt = alt;
		ecmp->ecm_intr_ep = intr_ep;
		ecmp->ecm_ctrl_if_no = ifc;
		ecmp->ecm_bulk_in_ep = bulk_in;
		ecmp->ecm_bulk_out_ep = bulk_out;

		return (USB_SUCCESS);
	}

	return (USB_FAILURE);
}

static int
usbecm_init_non_compatible_device(usbecm_state_t *ecmp)
{
	usb_if_data_t *cur_if;
	uint16_t if_num, i;

	/*
	 * If device don't conform to spec, search pairs of bulk in/out
	 * endpoints and fill related structure. We suppose this driver
	 * is bound to a interface.
	 */
	cur_if = ecmp->ecm_dev_data->dev_curr_cfg->cfg_if;
	if_num = ecmp->ecm_dev_data->dev_curr_cfg->cfg_n_if;

	/* search each interface which have bulk in and out */
	for (i = 0; i < if_num; i++) {
		if (usbecm_find_bulk_in_out_eps(ecmp, i,
		    cur_if) == USB_SUCCESS) {

			break;
		}
		cur_if++;
	}

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ecmp->ecm_lh,
	    "usbecm_init_non_compatible_device: ctrl_if=%d,"
	    " data_if=%d, alt=%d", ecmp->ecm_ctrl_if_no,
	    ecmp->ecm_data_if_no, ecmp->ecm_data_if_alt);

	return (USB_SUCCESS);
}

static boolean_t
usbecm_is_compatible(usbecm_state_t *ecmp)
{
	usb_cfg_data_t *cfg_data;
	usb_if_data_t *intf;
	usb_alt_if_data_t *alt;
	int alt_num, if_num, cfg_num;
	int i, j, cfg_index;

	cfg_num = ecmp->ecm_dev_data->dev_n_cfg;
	USB_DPRINTF_L3(PRINT_MASK_ATTA, ecmp->ecm_lh,
	    "usbecm_is_compatible: entry, cfg_num=%d", cfg_num);

	for (cfg_index = 0; cfg_index < cfg_num; cfg_index++) {
		cfg_data = &(ecmp->ecm_dev_data->dev_cfg[cfg_index]);

		USB_DPRINTF_L3(PRINT_MASK_ATTA, ecmp->ecm_lh,
		    "usbecm_is_compatible: cfg_index=%d, value=%d",
		    cfg_index, cfg_data->cfg_descr.bConfigurationValue);

		intf = cfg_data->cfg_if;
		if_num = cfg_data->cfg_n_if;

		for (i = 0; i < if_num; i++) {
			alt_num = intf->if_n_alt;
			for (j = 0; j < alt_num; j++) {
			alt = &intf->if_alt[j];
			if ((alt->altif_descr.bInterfaceClass == 0x02) &&
			    (alt->altif_descr.bInterfaceSubClass == 0x06)) {
				ecmp->ecm_cfg_index = cfg_index;

				USB_DPRINTF_L3(PRINT_MASK_ATTA, ecmp->ecm_lh,
				    "usbecm_is_compatible: cfg_index=%d",
				    cfg_index);

				return (B_TRUE);
			}
			}
			intf++;
		}
	}

	return (B_FALSE);
}


static int
usbecm_usb_init(usbecm_state_t *ecmp)
{

	if (usb_client_attach(ecmp->ecm_dip, USBDRV_VERSION, 0) !=
	    USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ecmp->ecm_lh,
		"usbecm_usb_init: fail to attach");

		return (USB_FAILURE);
	}

	/* Get the configuration information of device */
	if (usb_get_dev_data(ecmp->ecm_dip, &ecmp->ecm_dev_data,
	    USB_PARSE_LVL_ALL, 0) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ecmp->ecm_lh,
		"usbecm_usb_init: fail to get_dev_data");

		return (USB_FAILURE);
	}
	ecmp->ecm_def_ph = ecmp->ecm_dev_data->dev_default_ph;
	ecmp->ecm_dev_state = USB_DEV_ONLINE;

	mutex_init(&ecmp->ecm_mutex, NULL, MUTEX_DRIVER,
	    ecmp->ecm_dev_data->dev_iblock_cookie);

	if ((strcmp(ddi_binding_name(ecmp->ecm_dip),
	    "usbif,class2.6") == 0) ||
	    ((strcmp(ddi_binding_name(ecmp->ecm_dip),
	    "usb,class2.6.0") == 0))) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ecmp->ecm_lh,
		    "usbecm_usb_init: A CDC ECM device is attached");
		ecmp->ecm_compatibility = B_TRUE;
	} else if (usb_owns_device(ecmp->ecm_dip) &&
	    usbecm_is_compatible(ecmp)) {
		/*
		 * Current Sun SP ECM device has two configurations. Hence
		 * USBA doesn't create interface level compatible names
		 * for it, see usba_ready_device_node(). We have to check
		 * manually to see if compatible interfaces exist, when
		 * the driver owns the entire device.
		 */
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ecmp->ecm_lh,
		    "usbecm_usb_init: A CDC ECM device is attached");
		ecmp->ecm_compatibility = B_TRUE;
	} else {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ecmp->ecm_lh,
		    "usbecm_usb_init: A nonstandard device is attached to "
		    "usbecm(4D) driver. This device doesn't conform to "
		    "usb cdc spec.");
		ecmp->ecm_compatibility = B_FALSE;

		/* generate a random MAC addr */
		generate_ether_addr(ecmp->ecm_srcaddr);
	}

	if ((ecmp->ecm_compatibility == B_TRUE) &&
	    (usbecm_get_descriptors(ecmp) != USB_SUCCESS)) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ecmp->ecm_lh,
		    "usbecm_usb_init: A compatible device is attached, but "
		    "fail to get standard descriptors");

		return (USB_FAILURE);
	}

	if (ecmp->ecm_compatibility == B_FALSE) {
		(void) usbecm_init_non_compatible_device(ecmp);
	}

	/* Create power management components */
	if (usbecm_create_pm_components(ecmp) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ecmp->ecm_lh,
		    "usbecm_usb_init: create pm components failed.");

		return (USB_FAILURE);
	}

	/* Register to get callbacks for USB events */
	if (usb_register_event_cbs(ecmp->ecm_dip, &usbecm_events, 0)
	    != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ecmp->ecm_lh,
		    "usbsecm_attach: register event callback failed.");

		return (USB_FAILURE);
	}
	ecmp->ecm_init_flags |= USBECM_INIT_EVENTS;


	/* Get max data size of bulk transfer */
	if (usb_pipe_get_max_bulk_transfer_size(ecmp->ecm_dip,
	    &ecmp->ecm_xfer_sz) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ecmp->ecm_lh,
		    "usbsecm_ds_attach: get max size of transfer failed.");

		return (USB_FAILURE);
	}


	ecmp->ecm_ser_acc = usb_init_serialization(ecmp->ecm_dip,
	    USB_INIT_SER_CHECK_SAME_THREAD);
	ecmp->ecm_init_flags |= USBECM_INIT_SER;

	return (USB_SUCCESS);
}


/*
 * Open operation pipes. Each ECM device should have Bulk In, Bulk Out
 * and Interrupt In endpoints
 */
static int
usbecm_open_pipes(usbecm_state_t *ecmp)
{
	int		rval = USB_SUCCESS;
	usb_ep_data_t	*in_data, *out_data, *intr_pipe;
	usb_pipe_policy_t policy;
	int		altif;

	ASSERT(!mutex_owned(&ecmp->ecm_mutex));

	USB_DPRINTF_L4(PRINT_MASK_OPEN, ecmp->ecm_lh,
	    "usbsecm_open_pipes: ecmp = 0x%p", (void *)ecmp);

	if (ecmp->ecm_compatibility == B_TRUE) {
	/* compatible device has minimum of 2 altsetting, select alt 1 */
		altif = 1;
	} else {
		altif = ecmp->ecm_data_if_alt;
	}
	intr_pipe = ecmp->ecm_intr_ep;
	in_data = ecmp->ecm_bulk_in_ep;
	out_data = ecmp->ecm_bulk_out_ep;

	/* Bulk in and out must exist simultaneously. */
	if ((in_data == NULL) || (out_data == NULL)) {
		USB_DPRINTF_L2(PRINT_MASK_OPEN, ecmp->ecm_lh,
		    "usbsecm_open_pipes: look up bulk pipe failed in "
		    "interface %d ",
		    ecmp->ecm_data_if_no);

		return (USB_FAILURE);
	}
	/*
	 * If device conform to ecm spec, it must have an interrupt pipe
	 * for this device.
	 */
	if (ecmp->ecm_compatibility == B_TRUE && intr_pipe == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_OPEN, ecmp->ecm_lh,
		    "usbecm_open_pipes: look up interrupt pipe failed in "
		    "interface %d", ecmp->ecm_ctrl_if_no);

		return (USB_FAILURE);
	}

	USB_DPRINTF_L3(PRINT_MASK_OPEN, ecmp->ecm_lh,
	    "usbsecm_open_pipes: open intr %02x, bulkin %02x bulkout %02x",
	    intr_pipe?intr_pipe->ep_descr.bEndpointAddress:0,
	    in_data->ep_descr.bEndpointAddress,
	    out_data->ep_descr.bEndpointAddress);

	USB_DPRINTF_L3(PRINT_MASK_OPEN, ecmp->ecm_lh,
	    "usbsecm_open_pipes: set data if(%d) alt(%d) ",
	    ecmp->ecm_data_if_no, altif);

	if ((rval = usb_set_alt_if(ecmp->ecm_dip, ecmp->ecm_data_if_no,
	    altif, USB_FLAGS_SLEEP, NULL, NULL)) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ecmp->ecm_lh,
		    "usbecm_open_pipes: set alternate failed (%d)",
		    rval);

		return (rval);
	}

	policy.pp_max_async_reqs = 2;

	/* Open bulk in endpoint */
	if (usb_pipe_open(ecmp->ecm_dip, &in_data->ep_descr, &policy,
	    USB_FLAGS_SLEEP, &ecmp->ecm_bulkin_ph) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_OPEN, ecmp->ecm_lh,
		    "usbecm_open_pipes: open bulkin pipe failed!");

		return (USB_FAILURE);
	}

	/* Open bulk out endpoint */
	if (usb_pipe_open(ecmp->ecm_dip, &out_data->ep_descr, &policy,
	    USB_FLAGS_SLEEP, &ecmp->ecm_bulkout_ph) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_OPEN, ecmp->ecm_lh,
		    "usbecm_open_pipes: open bulkout pipe failed!");

		usb_pipe_close(ecmp->ecm_dip, ecmp->ecm_bulkin_ph,
		    USB_FLAGS_SLEEP, NULL, NULL);

		return (USB_FAILURE);
	}

	/* Open interrupt endpoint if found. */
	if (intr_pipe != NULL) {
		if (usb_pipe_open(ecmp->ecm_dip, &intr_pipe->ep_descr, &policy,
		    USB_FLAGS_SLEEP, &ecmp->ecm_intr_ph) != USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_OPEN, ecmp->ecm_lh,
			    "usbecm_open_pipes: "
			    "open intr pipe failed");

			usb_pipe_close(ecmp->ecm_dip, ecmp->ecm_bulkin_ph,
			    USB_FLAGS_SLEEP, NULL, NULL);
			usb_pipe_close(ecmp->ecm_dip, ecmp->ecm_bulkout_ph,
			    USB_FLAGS_SLEEP, NULL, NULL);

			return (USB_FAILURE);
		}
	}

	/* initialize the pipe related data */
	mutex_enter(&ecmp->ecm_mutex);
	ecmp->ecm_bulkin_sz = in_data->ep_descr.wMaxPacketSize;
	ecmp->ecm_bulkin_state = USBECM_PIPE_IDLE;
	ecmp->ecm_bulkout_state = USBECM_PIPE_IDLE;
	if (ecmp->ecm_intr_ph != NULL) {
		ecmp->ecm_intr_state = USBECM_PIPE_IDLE;
	}
	mutex_exit(&ecmp->ecm_mutex);

	if (ecmp->ecm_intr_ph != NULL) {

		usbecm_pipe_start_polling(ecmp);
	}

	USB_DPRINTF_L4(PRINT_MASK_OPEN, ecmp->ecm_lh,
	    "usbsecm_open_pipes: end");

	return (rval);
}


/*
 * usbsecm_close_pipes:
 *	Close pipes
 *	Each device could include three pipes: bulk in, bulk out and interrupt.
 */
static void
usbecm_close_pipes(usbecm_state_t *ecmp)
{

	mutex_enter(&ecmp->ecm_mutex);

	USB_DPRINTF_L4(PRINT_MASK_CLOSE, ecmp->ecm_lh,
	    "usbsecm_close_pipes: ecm_bulkin_state = %d",
	    ecmp->ecm_bulkin_state);

	/*
	 * Check the status of the pipes. If pipe is closing or closed,
	 * return directly.
	 */
	if ((ecmp->ecm_bulkin_state == USBECM_PIPE_CLOSED) ||
	    (ecmp->ecm_bulkin_state == USBECM_PIPE_CLOSING)) {
		USB_DPRINTF_L2(PRINT_MASK_CLOSE, ecmp->ecm_lh,
		    "usbsecm_close_pipes: pipe is closing or has closed");
		mutex_exit(&ecmp->ecm_mutex);

		return;
	}

	ecmp->ecm_bulkin_state = USBECM_PIPE_CLOSING;
	mutex_exit(&ecmp->ecm_mutex);

	/* reset the data interface's altsetting to 0 */
	if ((ecmp->ecm_dev_state == USB_DEV_ONLINE) &&
	    (usb_set_alt_if(ecmp->ecm_dip, ecmp->ecm_data_if_no,
	    0, USB_FLAGS_SLEEP, NULL, NULL) != USB_SUCCESS)) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ecmp->ecm_lh,
		    "usbecm_close_pipes: reset alternate failed ");
	}

	/* Close pipes */
	usb_pipe_reset(ecmp->ecm_dip, ecmp->ecm_bulkin_ph,
	    USB_FLAGS_SLEEP, NULL, 0);
	usb_pipe_close(ecmp->ecm_dip, ecmp->ecm_bulkin_ph,
	    USB_FLAGS_SLEEP, NULL, 0);
	usb_pipe_close(ecmp->ecm_dip, ecmp->ecm_bulkout_ph,
	    USB_FLAGS_SLEEP, NULL, 0);

	if (ecmp->ecm_intr_ph != NULL) {
		usb_pipe_stop_intr_polling(ecmp->ecm_intr_ph,
		    USB_FLAGS_SLEEP);
		usb_pipe_close(ecmp->ecm_dip, ecmp->ecm_intr_ph,
		    USB_FLAGS_SLEEP, NULL, 0);
	}

	mutex_enter(&ecmp->ecm_mutex);
	/* Reset the status of pipes to closed */
	ecmp->ecm_bulkin_state = USBECM_PIPE_CLOSED;
	ecmp->ecm_bulkin_ph = NULL;
	ecmp->ecm_bulkout_state = USBECM_PIPE_CLOSED;
	ecmp->ecm_bulkout_ph = NULL;
	if (ecmp->ecm_intr_ph != NULL) {
		ecmp->ecm_intr_state = USBECM_PIPE_CLOSED;
		ecmp->ecm_intr_ph = NULL;
	}

	mutex_exit(&ecmp->ecm_mutex);

	USB_DPRINTF_L4(PRINT_MASK_CLOSE, ecmp->ecm_lh,
	    "usbsecm_close_pipes: pipes have been closed.");
}


static int
usbecm_ctrl_write(usbecm_state_t *ecmp, uchar_t request,
    uint16_t value, mblk_t **data)
{
	usb_ctrl_setup_t setup;
	usb_cb_flags_t	cb_flags;
	usb_cr_t	cr;
	int		rval;

	USB_DPRINTF_L4(PRINT_MASK_ALL, ecmp->ecm_lh,
	    "usbecm_ctrl_write: ");

	/* initialize the control request. */
	setup.bmRequestType = USB_DEV_REQ_HOST_TO_DEV |
	    USB_DEV_REQ_TYPE_CLASS | USB_DEV_REQ_RCPT_IF;
	setup.bRequest = request;
	setup.wValue = value;
	setup.wIndex = ecmp->ecm_ctrl_if_no;
	setup.wLength = ((data != NULL) && (*data != NULL)) ? MBLKL(*data) : 0;
	setup.attrs = 0;

	rval = usb_pipe_ctrl_xfer_wait(ecmp->ecm_def_ph, &setup, data,
	    &cr, &cb_flags, 0);

	USB_DPRINTF_L4(PRINT_MASK_ALL, ecmp->ecm_lh,
	    "usbecm_ctrl_write: rval = %d", rval);

	return (rval);
}

static int
usbecm_ctrl_read(usbecm_state_t *ecmp, uchar_t request,
    uint16_t value, mblk_t **data, int len)
{
	usb_ctrl_setup_t setup;
	usb_cb_flags_t	cb_flags;
	usb_cr_t	cr;

	USB_DPRINTF_L4(PRINT_MASK_ALL, ecmp->ecm_lh,
	    "usbecm_ctrl_read: ");

	/* initialize the control request. */
	setup.bmRequestType = USB_DEV_REQ_DEV_TO_HOST |
	    USB_DEV_REQ_TYPE_CLASS | USB_DEV_REQ_RCPT_IF;
	setup.bRequest = request;
	setup.wValue = value;
	setup.wIndex = ecmp->ecm_ctrl_if_no;
	setup.wLength = (uint16_t)len;
	setup.attrs = 0;

	return (usb_pipe_ctrl_xfer_wait(ecmp->ecm_def_ph, &setup, data,
	    &cr, &cb_flags, 0));
}

/* Get specific statistic data from device */
static int
usbecm_get_statistics(usbecm_state_t *ecmp, uint32_t fs, uint32_t *stat_data)
{
	mblk_t *data = NULL;
	uint32_t stat;

	/* first check to see if this stat is collected by device */
	if ((ecmp->ecm_compatibility == B_TRUE) &&
	    (ecmp->ecm_desc.bmEthernetStatistics & ECM_STAT_CAP_MASK(fs))) {
		if (usbecm_ctrl_read(ecmp, CDC_ECM_GET_ETH_STAT,
		    ecmp->ecm_ctrl_if_no, &data, 4) != USB_SUCCESS) {

			return (USB_FAILURE);
		}
		stat = (data->b_rptr[3] << 24) | (data->b_rptr[2] << 16) |
		    (data->b_rptr[1] << 8) | (data->b_rptr[0]);
		*stat_data = stat;

		freemsg(data);

		return (USB_SUCCESS);
	}

	return (USB_FAILURE);
}
