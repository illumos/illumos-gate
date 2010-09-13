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


/*
 * USBA: Solaris USB Architecture support
 *
 * whcdi.c is part of the WUSB extension to the USBA framework.
 *
 * It mainly contains functions that can be shared by whci and hwahc
 * drivers to enable WUSB host functionality, such as WUSB channel
 * resource management, MMC IE handling, WUSB HC specific requests,
 * WUSB device authentication, child connection/disconnection, etc.
 */
#define	USBA_FRAMEWORK
#include <sys/usb/usba.h>
#include <sys/usb/usba/usba_impl.h>
#include <sys/usb/usba/usba_types.h>
#include <sys/usb/usba/hcdi_impl.h>	/* for usba_hcdi_t */
#include <sys/usb/usba/whcdi.h>
#include <sys/usb/usba/wa.h>
#include <sys/strsubr.h>
#include <sys/crypto/api.h>
#include <sys/strsun.h>
#include <sys/random.h>

/*
 * local variables
 */
static kmutex_t whcdi_mutex;

/* use 0-30 bit as wusb cluster_id bitmaps */
static uint32_t cluster_id_mask = 0;

_NOTE(MUTEX_PROTECTS_DATA(whcdi_mutex, cluster_id_mask))

usb_log_handle_t	whcdi_log_handle;
uint_t			whcdi_errlevel = USB_LOG_L4;
uint_t			whcdi_errmask = (uint_t)-1;

/*
 * initialize private data
 */
void
usba_whcdi_initialization()
{
	whcdi_log_handle = usb_alloc_log_hdl(NULL, "whcdi", &whcdi_errlevel,
	    &whcdi_errmask, NULL, 0);

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "whcdi_initialization");

	mutex_init(&whcdi_mutex, NULL, MUTEX_DRIVER, NULL);
}

void
usba_whcdi_destroy()
{
	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "whcdi_destroy");

	mutex_destroy(&whcdi_mutex);

	usb_free_log_hdl(whcdi_log_handle);
}

/*
 * Assign a cluster id for a WUSB channel
 * return 0 if no free cluster id is available
 */
uint8_t
wusb_hc_get_cluster_id()
{
	int	i;
	uint8_t	id;

	mutex_enter(&whcdi_mutex);
	for (i = 0; i < WUSB_CLUSTER_ID_COUNT; i++) {
		/* find the first unused slot */
		if (cluster_id_mask & (1 << i)) {
			continue;
		}

		/* set the bitmask */
		cluster_id_mask |= (1 << i);
		id = WUSB_MIN_CLUSTER_ID + i;
		USB_DPRINTF_L3(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "new cluster id %d, mask %d", id, cluster_id_mask);
		mutex_exit(&whcdi_mutex);

		return (id);
	}

	mutex_exit(&whcdi_mutex);

	USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "no cluster id available");

	return (0);
}

/* Free the cluster id */
void
wusb_hc_free_cluster_id(uint8_t id)
{
	int	i = id - WUSB_MIN_CLUSTER_ID;

	if ((i < 0) || (i >= WUSB_CLUSTER_ID_COUNT)) {

		return;
	}

	mutex_enter(&whcdi_mutex);
	if (cluster_id_mask & (1 << i)) {
		/* unset the bitmask */
		cluster_id_mask &= ~(1 << i);
	} else {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "cluster id already freed");
	}
	mutex_exit(&whcdi_mutex);
}

/*
 * Allocate iehdl according to the order specified in WUSB 1.0/7.5
 * WUSB Errata 06.12 requires iehdl to be zero based
 */
int
wusb_hc_get_iehdl(wusb_hc_data_t *hc_data, wusb_ie_header_t *hdr,
	uint8_t *iehdl)
{
	int	i, rval = USB_SUCCESS;
	uint8_t hdl = 0xFF;

	switch (hdr->bIEIdentifier) {
	case WUSB_IE_HOSTINFO:
	/*
	 * 7.5.2(and 7.5 under Table 7-38) says this IE should be located
	 * in an MMC afte all WCTA_IEs. This mean its handle should
	 * be the last one. See also whci r0.95 page 105 top. HC sends
	 * IE blocks in ascending IE_HANDLE order.
	 */
		hdl = hc_data->hc_num_mmcies - 1;
		hc_data->hc_mmcie_list[hdl] = hdr;
		break;
	case WUSB_IE_ISOC_DISCARD:
	/*
	 * 7.5.10 says this IE must be included before any WxCTAs.
	 */
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "IE type 0x%x unimplemented\n", hdr->bIEIdentifier);
		rval = USB_NOT_SUPPORTED;
		break;
	default:
		/*
		 * search for existing slot or find the last empty slot
		 * so that the other IEs would always set after WCTA_IEs
		 */
		for (i = hc_data->hc_num_mmcies - 2; i >= 0; i--) {
			if ((hc_data->hc_mmcie_list[i] == hdr) ||
			    (hc_data->hc_mmcie_list[i] == NULL)) {
				hdl = (uint8_t)i;
				hc_data->hc_mmcie_list[i] = hdr;
				break;
			}
		}
		if (hdl == 0xFF) {
			USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
			    "no IE handle available\n");
			rval = USB_NO_RESOURCES;
		}
		break;
	}

	if (rval == USB_SUCCESS) {
		*iehdl = hdl;
	}

	return (rval);
}

/* Deallocate iehdl */
void
wusb_hc_free_iehdl(wusb_hc_data_t *hc_data, uint8_t iehdl)
{
	ASSERT(mutex_owned(&hc_data->hc_mutex));

	if (iehdl >= hc_data->hc_num_mmcies) {

		return;
	}

	if (hc_data->hc_mmcie_list[iehdl] != NULL) {
		hc_data->hc_mmcie_list[iehdl] = NULL;
	}
}


/*
 * ******************************************************************
 * WUSB host controller specific requests, refer to WUSB 1.0/8.5.3
 *
 * WHCI driver needs to translate the requests to register operations
 * ******************************************************************
 */

/* For HWA, see WUSB 8.5.3.11 - Set WUSB Cluster ID */
int
wusb_hc_set_cluster_id(wusb_hc_data_t *hc_data, uint8_t cluster_id)
{
	dev_info_t	*dip = hc_data->hc_dip;
	int		rval;

	if (dip == NULL) {

		return (USB_INVALID_ARGS);
	}

	if ((rval = hc_data->set_cluster_id(dip, cluster_id))
	    != USB_SUCCESS) {

		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "Set_Cluster_ID fails: rval=%d ", rval);
	} else {
		mutex_enter(&hc_data->hc_mutex);
		hc_data->hc_cluster_id = cluster_id;
		mutex_exit(&hc_data->hc_mutex);
	}

	return (rval);
}

/*
 * WUSB 8.5.3.13 - Set WUSB Stream Index
 * From 7.7, stream index should be 3bits and less than 8.
 */
int
wusb_hc_set_stream_idx(wusb_hc_data_t *hc_data, uint8_t stream_idx)
{
	dev_info_t	*dip = hc_data->hc_dip;
	int		rval;

	if (stream_idx > 7) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "Set_Stream_Idx fails: invalid idx = %d",
		    stream_idx);

		return (USB_INVALID_ARGS);
	}

	rval = hc_data->set_stream_idx(dip, stream_idx);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "Set_Stream_Idx fails: rval=%d",
		    rval);
	}

	return (rval);
}

/* For HWA, see WUSB 8.5.3.12 - Set WUSB MAS */
int
wusb_hc_set_wusb_mas(wusb_hc_data_t *hc_data, uint8_t *data)
{
	dev_info_t	*dip = hc_data->hc_dip;
	int		rval;

	rval = hc_data->set_wusb_mas(dip, data);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "Set_WUSB_MAS fails: rval=%d", rval);
	}

	return (rval);

}

/* For HWA, see WUSB 8.5.3.1 - Add MMC IE */
int
wusb_hc_add_mmc_ie(wusb_hc_data_t *hc_data, uint8_t interval,
	uint8_t rcnt, uint8_t iehdl, uint16_t len, uint8_t *data)
{
	dev_info_t	*dip = hc_data->hc_dip;
	int		rval;

	rval = hc_data->add_mmc_ie(dip, interval, rcnt, iehdl, len, data);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "Add_MMC_IE fails: rval=%d ",
		    rval);
	}

	return (rval);
}

/* For HWA, see WUSB 8.5.3.5 - Remove MMC IE */
int
wusb_hc_remove_mmc_ie(wusb_hc_data_t *hc_data, uint8_t iehdl)
{
	dev_info_t	*dip = hc_data->hc_dip;
	int		rval;

	ASSERT(mutex_owned(&hc_data->hc_mutex));

	if ((iehdl >= hc_data->hc_num_mmcies) ||
	    (hc_data->hc_mmcie_list[iehdl] == NULL)) {

		return (USB_FAILURE);
	}

	mutex_exit(&hc_data->hc_mutex);
	rval = hc_data->rem_mmc_ie(dip, iehdl);
	mutex_enter(&hc_data->hc_mutex);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "Remove_MMC_IE fails: rval=%d ", rval);
	}

	return (rval);
}

/* For HWA, see WUSB 8.5.3.14 - WUSB Channel Stop */
int
wusb_hc_stop_ch(wusb_hc_data_t *hc_data, uint32_t timeoff)
{
	dev_info_t	*dip = hc_data->hc_dip;
	int		rval;

	rval = hc_data->stop_ch(dip, timeoff);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "WUSB_Ch_Stop fails: rval=%d ", rval);
	}

	return (rval);
}

/* For HWA, see WUSB 8.5. 3.10 - Set Num DNTS Slots */
int
wusb_hc_set_num_dnts(wusb_hc_data_t *hc_data, uint8_t interval,
    uint8_t nslots)
{
	dev_info_t	*dip = hc_data->hc_dip;
	int		rval;

	rval = hc_data->set_num_dnts(dip, interval, nslots);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "Set_Num_DNTS fails: rval=%d ", rval);
	}

	return (rval);
}

/*
 * For HWA, see WUSB 8.5.3.2 - 8.5.3.4 Get Time
 * time_type:
 *	WUSB_TIME_ADJ	- Get BPST Adjustment
 *	WUSB_TIME_BPST	- Get BPST Time
 *	WUSB_TIME_WUSB	- Get WUSB Time
 */
int
wusb_hc_get_time(wusb_hc_data_t *hc_data, uint8_t time_type,
    uint16_t len, uint32_t *time)
{
	dev_info_t	*dip = hc_data->hc_dip;
	int		rval;

	/* call the HC's specific get_time function */
	rval = hc_data->get_time(dip, time_type, len, time);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "Set_Num_DNTS fails: rval=%d ", rval);
	}

	return (rval);
}

/*
 * Remove the specified IE from host MMC and release the related IE handle
 */
void
wusb_hc_rem_ie(wusb_hc_data_t *hc_data, wusb_ie_header_t *ieh)
{
	int	i;
	int16_t	iehdl = -1;

	mutex_enter(&hc_data->hc_mutex);
	for (i = 0; i < hc_data->hc_num_mmcies; i++) {
		if (hc_data->hc_mmcie_list[i] == ieh) {
			iehdl = (int16_t)i;

			break;
		}
	}

	if (iehdl == -1) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_hc_rem_ie: IE(%p) iehdl not found", (void *)ieh);
		mutex_exit(&hc_data->hc_mutex);

		return;
	}

	(void) wusb_hc_remove_mmc_ie(hc_data, (uint8_t)iehdl);

	wusb_hc_free_iehdl(hc_data, (uint8_t)iehdl);
	mutex_exit(&hc_data->hc_mutex);
}

/* Add Host Info IE */
int
wusb_hc_add_host_info(wusb_hc_data_t *hc_data, uint8_t stream_idx)
{
	wusb_ie_host_info_t	*hinfo;
	uint8_t			iehdl;
	int			rval;

	hinfo = kmem_zalloc(sizeof (wusb_ie_host_info_t), KM_SLEEP);

	mutex_enter(&hc_data->hc_mutex);

	hinfo->bIEIdentifier = WUSB_IE_HOSTINFO;
	hinfo->bLength = sizeof (wusb_ie_host_info_t);
	if (hc_data->hc_newcon_enabled) {
		hinfo->bmAttributes[0] = (stream_idx << WUSB_HI_STRIDX_SHIFT) |
		    WUSB_HI_CONN_ALL;
	} else {
		hinfo->bmAttributes[0] = (stream_idx << WUSB_HI_STRIDX_SHIFT) |
		    WUSB_HI_CONN_LMTED;
	}
	(void) memcpy(hinfo->CHID, hc_data->hc_chid, sizeof (hinfo->CHID));

	rval = wusb_hc_get_iehdl(hc_data, (wusb_ie_header_t *)hinfo, &iehdl);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_hc_add_host_info: get ie handle fails");
		mutex_exit(&hc_data->hc_mutex);

		return (rval);
	}

	USB_DPRINTF_L3(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_hc_add_host_info: iehdl=%d", iehdl);

	mutex_exit(&hc_data->hc_mutex);
	rval = wusb_hc_add_mmc_ie(hc_data, 10, 1, iehdl,
	    sizeof (wusb_ie_host_info_t), (uint8_t *)hinfo);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_hc_add_host_info: add host info mmc ie fails");
		mutex_enter(&hc_data->hc_mutex);
		wusb_hc_free_iehdl(hc_data, iehdl);
		mutex_exit(&hc_data->hc_mutex);

		return (rval);
	}


	return (USB_SUCCESS);
}

/* Remove Host Info IE */
void
wusb_hc_rem_host_info(wusb_hc_data_t *hc_data)
{
	int16_t	iehdl = -1;
	wusb_ie_header_t *iehead;

	mutex_enter(&hc_data->hc_mutex);
	/* host info IE is always the last one */
	iehdl = hc_data->hc_num_mmcies - 1;
	iehead = hc_data->hc_mmcie_list[iehdl];

	/* something wrong */
	if ((iehead == NULL) || (iehead->bIEIdentifier != WUSB_IE_HOSTINFO)) {
		mutex_exit(&hc_data->hc_mutex);
		return;
	}

	(void) wusb_hc_remove_mmc_ie(hc_data, (uint8_t)iehdl);
	wusb_hc_free_iehdl(hc_data, (uint8_t)iehdl);
	kmem_free(iehead, sizeof (wusb_ie_host_info_t));

	mutex_exit(&hc_data->hc_mutex);
}

/*
 * Check if a device with certain CDID is connected
 * return 1 if a device with the same CDID is found;
 * return 0 if not
 */
uint_t
wusb_hc_is_dev_connected(wusb_hc_data_t *hc_data, uint8_t *cdid,
	usb_port_t *port)
{
	int			i;
	wusb_dev_info_t		*dev_info;

	ASSERT(mutex_owned(&hc_data->hc_mutex));

	for (i = 1; i <= hc_data->hc_num_ports; i++) {
		dev_info = hc_data->hc_dev_infos[i];
		if ((dev_info != NULL) &&
		    (memcmp(cdid, dev_info->wdev_cdid, 16) == 0)) {
			*port = (usb_port_t)i;
			USB_DPRINTF_L3(DPRINT_MASK_WHCDI, whcdi_log_handle,
			    "wusb_hc_is_dev_connected: find dev at port "
			    "%d", *port);

			return (1);
		}
	}

	return (0);
}

/*
 * Check if a device with certain address is connected
 * return 1 if a device with the same address is found;
 * return 0 if not
 */
uint_t
wusb_hc_is_addr_valid(wusb_hc_data_t *hc_data, uint8_t addr,
	usb_port_t *port)
{
	int			i;
	wusb_dev_info_t		*dev_info;

	for (i = 1; i <= hc_data->hc_num_ports; i++) {
		dev_info = hc_data->hc_dev_infos[i];
		if ((dev_info != NULL) && (dev_info->wdev_addr == addr)) {
			*port = (usb_port_t)i;
			USB_DPRINTF_L3(DPRINT_MASK_WHCDI, whcdi_log_handle,
			    "wusb_hc_is_addr_valid: find addr at port "
			    "%d", *port);

			return (1);
		}
	}

	return (0);
}


/*
 * Assign port number for a newly connected device
 * return the first free port number if any, or 0 if none
 */
usb_port_t
wusb_hc_get_free_port(wusb_hc_data_t *hc_data)
{
	int		i;
	usb_port_t	port;

	for (i = 1; i <= hc_data->hc_num_ports; i++) {
		if (hc_data->hc_dev_infos[i] == NULL) {
			port = (usb_port_t)i;
			USB_DPRINTF_L3(DPRINT_MASK_WHCDI, whcdi_log_handle,
			    "wusb_hc_get_free_port: find free port %d", port);

			return (port);
		}
	}

	return (0);
}

/* Add Connect Acknowledge IE */
int
wusb_hc_ack_conn(wusb_hc_data_t *hc_data, usb_port_t port)
{
	wusb_dev_info_t		*dev_info;
	wusb_ie_connect_ack_t	*ack_ie;
	wusb_connectack_block_t	*ack_block;
	uint8_t			iehdl;
	int			rval;

	ASSERT(mutex_owned(&hc_data->hc_mutex));

	dev_info = hc_data->hc_dev_infos[port];
	ASSERT(dev_info != NULL);

	ack_ie = kmem_zalloc(sizeof (wusb_ie_connect_ack_t), KM_SLEEP);

	ack_ie->bIEIdentifier = WUSB_IE_CONNECTACK;
	ack_block = (wusb_connectack_block_t *)ack_ie->bAckBlock;
	(void) memcpy(ack_block->CDID, dev_info->wdev_cdid, 16);
	ack_block->bDeviceAddress = dev_info->wdev_addr;
	ack_ie->bLength = 20;

	rval = wusb_hc_get_iehdl(hc_data, (wusb_ie_header_t *)ack_ie, &iehdl);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_hc_ack_conn: get ie handle fails");
		kmem_free(ack_ie, sizeof (wusb_ie_connect_ack_t));

		return (rval);
	}

	rval = wusb_hc_add_mmc_ie(hc_data, 0, 3, iehdl,
	    ack_ie->bLength, (uint8_t *)ack_ie);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_hc_ack_conn: add connect ack ie fails");
		wusb_hc_free_iehdl(hc_data, iehdl);
		kmem_free(ack_ie, sizeof (wusb_ie_connect_ack_t));

		return (rval);
	}

	mutex_exit(&hc_data->hc_mutex);
	/*
	 * WUSB 1.0/7.5.1 requires at least 2ms delay between ConnectAck
	 * and WUSB transactions, wait for 2ms here
	 */
	delay(drv_usectohz(2000));
	mutex_enter(&hc_data->hc_mutex);

	return (USB_SUCCESS);
}

/* Remove Connect Acknowledge IE */
void
wusb_hc_rm_ack(wusb_hc_data_t *hc_data)
{
	int	i;
	int16_t	iehdl = -1;
	wusb_ie_header_t *ieh;

	for (i = 0; i < hc_data->hc_num_mmcies; i++) {
		ieh = hc_data->hc_mmcie_list[i];
		if ((ieh != NULL) &&
		    (ieh->bIEIdentifier == WUSB_IE_CONNECTACK)) {
			iehdl = (int16_t)i;

			break;
		}
	}

	if (iehdl == -1) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_hc_rm_ack: ack iehdl not found");

		return;
	}

	/* remove mmc ie and free handle & memory */
	(void) wusb_hc_remove_mmc_ie(hc_data, (uint8_t)iehdl);
	wusb_hc_free_iehdl(hc_data, iehdl);
	kmem_free(ieh, sizeof (wusb_ie_connect_ack_t));
}

/*
 * Send a KeepAlive IE to the device. See WUSB 1.0 section 7.5.9
 */
int
wusb_hc_send_keepalive_ie(wusb_hc_data_t *hc_data, uint8_t addr)
{
	wusb_ie_keepalive_t	*alive_ie;
	uint8_t			iehdl;
	int			rval;

	mutex_enter(&hc_data->hc_mutex);
	/*
	 * the scheme ensures each time only one device addr
	 * is set each time
	 */
	alive_ie = &hc_data->hc_alive_ie;
	alive_ie->bDeviceAddress[0] = addr;
	/* padding, no active wusb device addr will be 1 */
	alive_ie->bDeviceAddress[1] = 1;
	alive_ie->bLength = 4;

	rval = wusb_hc_get_iehdl(hc_data, (wusb_ie_header_t *)alive_ie,
	    &iehdl);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_hc_send_keepalive_ie: get ie handle fails");
		mutex_exit(&hc_data->hc_mutex);

		return (rval);
	}

	USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_hc_send_keepalive_ie: get ie handle = %d", iehdl);
	/*
	 * we must release the lock so that the DN notification
	 * thread can update the device active bit
	 */
	mutex_exit(&hc_data->hc_mutex);

	rval = wusb_hc_add_mmc_ie(hc_data, 0, 0, iehdl,
	    alive_ie->bLength, (uint8_t *)alive_ie);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_hc_send_keepalive_ie: add keepalive ie fails");

		/* no need to free the ack iehdl since it is reused */
		return (rval);
	}

	/*
	 * wait 400ms for the device to reply a DN_Alive notification
	 */
	delay(drv_usectohz(400000));

	/*
	 * cease transmitting the IE and release the IE handle,
	 * no matter we receive a response or not.
	 */
	mutex_enter(&hc_data->hc_mutex);
	(void) wusb_hc_remove_mmc_ie(hc_data, iehdl);
	wusb_hc_free_iehdl(hc_data, iehdl);
	mutex_exit(&hc_data->hc_mutex);

	return (USB_SUCCESS);
}

/*
 * Check the hc_cc_list for matching CDID and return the pointer
 * to the matched cc. Return NULL if no matching cc is found.
 */
wusb_cc_t *
wusb_hc_cc_matched(wusb_hc_cc_list_t *cc_list, uint8_t *cdid)
{
	wusb_cc_t	*cc = NULL, *tcc;

	while (cc_list != NULL) {
		tcc = &cc_list->cc;
		if (memcmp(tcc->CDID, cdid, 16) == 0) {
			cc = tcc;

			break;
		}
		cc_list = cc_list->next;
	}

	return (cc);
}

/*
 * ***************************************************************
 * WUSB specific standard device requests, refer to WUSB 1.0/7.3.1
 * ***************************************************************
 */
/* Get WUSB device BOS descr and UWB capability descr */
int
wusb_get_dev_uwb_descr(wusb_hc_data_t *hc_data, usb_port_t port)
{
	dev_info_t		*child_dip;
	usba_device_t		*child_ud;
	wusb_dev_info_t		*dev_info;
	int			rval;
	uint8_t			*buf;
	size_t			size, buflen;

	ASSERT(mutex_owned(&hc_data->hc_mutex));

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_get_dev_uwb_descr: port = %d", port);

	dev_info = hc_data->hc_dev_infos[port];
	child_dip = hc_data->hc_children_dips[port];
	if (child_dip == NULL) {

		return (USB_FAILURE);
	}

	child_ud = usba_get_usba_device(child_dip);
	if (child_ud == NULL) {

		return (USB_FAILURE);
	}

	/* only get bos descr the first time */
	if (dev_info->wdev_uwb_descr == NULL) {
		mutex_exit(&hc_data->hc_mutex);
		rval = wusb_get_bos_cloud(child_dip, child_ud);
		if (rval != USB_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
			    "wusb_get_dev_uwb_descr: failed to "
			    "get bos descriptor");

			mutex_enter(&hc_data->hc_mutex);

			return (rval);
		}
		mutex_enter(&hc_data->hc_mutex);

		buf = child_ud->usb_wireless_data->wusb_bos;
		buflen = child_ud->usb_wireless_data->wusb_bos_length;

		dev_info->wdev_uwb_descr = kmem_zalloc(
		    sizeof (usb_uwb_cap_descr_t), KM_SLEEP);

		size = usb_parse_uwb_bos_descr(buf, buflen,
		    dev_info->wdev_uwb_descr, sizeof (usb_uwb_cap_descr_t));

		USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_get_dev_uwb_descr: parsed uwb descr size is %d",
		    (int)size);
		if (size < USB_UWB_CAP_DESCR_SIZE) {
			kmem_free(dev_info->wdev_uwb_descr,
			    sizeof (usb_uwb_cap_descr_t));
			dev_info->wdev_uwb_descr = NULL;

			return (USB_FAILURE);
		}

		/* store a parsed uwb descriptor */
		child_ud->usb_wireless_data->uwb_descr =
		    dev_info->wdev_uwb_descr;
	} else {
		USB_DPRINTF_L3(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_get_dev_uwb_descr: already done");
	}

	return (USB_SUCCESS);
}

/* Get WUSB device BOS descr cloud, refer to WUSB 1.0/7.4.1 */
int
wusb_get_bos_cloud(dev_info_t *child_dip, usba_device_t *child_ud)
{
	usb_bos_descr_t		*bos_descr;
	mblk_t			*pdata = NULL;
	int			rval;
	size_t			size;
	usb_cr_t		completion_reason;
	usb_cb_flags_t		cb_flags;
	usb_pipe_handle_t	def_ph;
	usba_wireless_data_t	*wireless_data;

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_get_bos_cloud: ");

	bos_descr = (usb_bos_descr_t *)kmem_zalloc(sizeof (usb_bos_descr_t),
	    KM_SLEEP);

	def_ph = usba_get_dflt_pipe_handle(child_dip);

	if ((rval = usb_pipe_sync_ctrl_xfer(child_dip, def_ph,
	    USB_DEV_REQ_DEV_TO_HOST | USB_DEV_REQ_TYPE_STANDARD,
	    USB_REQ_GET_DESCR,
	    USB_DESCR_TYPE_BOS << 8,
	    0,
	    USB_BOS_DESCR_SIZE,
	    &pdata,
	    0,
	    &completion_reason,
	    &cb_flags,
	    0)) == USB_SUCCESS) {

		/* this must be true since we didn't allow data underruns */
		if (MBLKL(pdata) != USB_BOS_DESCR_SIZE) {
			USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
			    "device returned incorrect bos "
			    "descriptor size.");

			rval = USB_FAILURE;
			goto done;
		}

		/*
		 * Parse the bos descriptor
		 */
		size = usb_parse_bos_descr(pdata->b_rptr,
		    MBLKL(pdata), bos_descr,
		    sizeof (usb_bos_descr_t));

		/* if parse bos descr error, it should return failure */
		if (size == USB_PARSE_ERROR) {

			if (pdata->b_rptr[1] != USB_DESCR_TYPE_BOS) {
				USB_DPRINTF_L2(DPRINT_MASK_WHCDI,
				    whcdi_log_handle,
				    "device returned incorrect "
				    "bos descriptor type.");
			}
			rval = USB_FAILURE;
			goto done;
		}

		if (bos_descr->wTotalLength < USB_BOS_DESCR_SIZE) {
			USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
			    "device returned incorrect "
			    "bos descriptor size.");

			rval = USB_FAILURE;
			goto done;
		}

		freemsg(pdata);
		pdata = NULL;

		/* Now fetch the complete bos cloud */
		if ((rval = usb_pipe_sync_ctrl_xfer(child_dip, def_ph,
		    USB_DEV_REQ_DEV_TO_HOST | USB_DEV_REQ_TYPE_STANDARD,
		    USB_REQ_GET_DESCR,
		    USB_DESCR_TYPE_BOS << 8,
		    0,
		    bos_descr->wTotalLength,
		    &pdata,
		    0,
		    &completion_reason,
		    &cb_flags,
		    0)) == USB_SUCCESS) {

			if (MBLKL(pdata) != bos_descr->wTotalLength) {

				USB_DPRINTF_L2(DPRINT_MASK_WHCDI,
				    whcdi_log_handle,
				    "device returned incorrect "
				    "bos descriptor cloud.");

				rval = USB_FAILURE;
				goto done;
			}

			/*
			 * copy bos descriptor into usba_device
			 */
			mutex_enter(&child_ud->usb_mutex);
			wireless_data = child_ud->usb_wireless_data;
			wireless_data->wusb_bos =
			    kmem_zalloc(bos_descr->wTotalLength, KM_SLEEP);
			wireless_data->wusb_bos_length =
			    bos_descr->wTotalLength;
			bcopy((caddr_t)pdata->b_rptr,
			    (caddr_t)wireless_data->wusb_bos,
			    bos_descr->wTotalLength);
			USB_DPRINTF_L3(DPRINT_MASK_WHCDI, whcdi_log_handle,
			    "bos_length = %d",
			    wireless_data->wusb_bos_length);
			mutex_exit(&child_ud->usb_mutex);
		}
	}

done:
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_get_bos_cloud: "
		    "error in retrieving bos descriptor, rval=%d cr=%d",
		    rval, completion_reason);
	}

	if (pdata) {
		freemsg(pdata);
		pdata = NULL;
	}

	kmem_free(bos_descr, sizeof (usb_bos_descr_t));

	return (rval);
}

/* Get WUSB device security descriptors, refer to WUSB 1.0/7.4.5 */
int
wusb_get_dev_security_descr(usb_pipe_handle_t ph,
	wusb_secrt_data_t *secrt_data)
{
	usb_ctrl_setup_t	setup;
	mblk_t			*pdata = NULL;
	usb_cr_t		cr;
	usb_cb_flags_t		cb_flags;
	int			i, rval;
	size_t			size, len;
	uint8_t			*p;

	setup.bmRequestType = USB_DEV_REQ_DEV_TO_HOST;
	setup.bRequest = USB_REQ_GET_DESCR;
	setup.wValue = USB_DESCR_TYPE_SECURITY << 8;
	setup.wIndex = 0;
	setup.wLength = USB_SECURITY_DESCR_SIZE;
	setup.attrs = USB_ATTRS_NONE;

	rval = usb_pipe_ctrl_xfer_wait(ph, &setup, &pdata, &cr, &cb_flags,
	    USB_FLAGS_SLEEP);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_get_dev_security_descr "
		    "failed, rval = %d, cr = %d", rval, cr);

		return (rval);
	}

	if (MBLKL(pdata) != USB_SECURITY_DESCR_SIZE) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "received incorrect security descriptor size");
		rval = USB_FAILURE;

		goto done;
	}

	/* Parse the security descriptor */
	size = usb_parse_data("ccsc", pdata->b_rptr,
	    MBLKL(pdata), &secrt_data->secrt_descr,
	    sizeof (usb_security_descr_t));

	/* check if the parsed descr is good */
	if (size < USB_SECURITY_DESCR_SIZE) {
		rval = USB_FAILURE;

		goto done;
	}

	if (secrt_data->secrt_descr.wTotalLength < USB_SECURITY_DESCR_SIZE) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "device returned incorrect security descriptor size");
		rval = USB_FAILURE;

		goto done;
	}

	freemsg(pdata);
	pdata = NULL;

	secrt_data->secrt_n_encry =
	    secrt_data->secrt_descr.bNumEncryptionTypes;
	len = sizeof (usb_encryption_descr_t) * secrt_data->secrt_n_encry;
	secrt_data->secrt_encry_descr =
	    (usb_encryption_descr_t *)kmem_zalloc(len, KM_SLEEP);

	/* Now fetch the complete security descr cloud */
	setup.wLength = secrt_data->secrt_descr.wTotalLength;
	rval = usb_pipe_ctrl_xfer_wait(ph, &setup, &pdata, &cr, &cb_flags,
	    USB_FLAGS_SLEEP);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_get_dev_security_descr "
		    "for total cloud failed, rval = %d, cr = %d", rval, cr);

		goto done;
	}

	if (MBLKL(pdata) != secrt_data->secrt_descr.wTotalLength) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "received incorrect security descriptor cloud size");
		rval = USB_FAILURE;

		goto done;
	}

	p = pdata->b_rptr + USB_SECURITY_DESCR_SIZE;
	for (i = 0; i < secrt_data->secrt_n_encry; i++) {
		size = usb_parse_data("ccccc", p, _PTRDIFF(pdata->b_wptr, p),
		    &secrt_data->secrt_encry_descr[i],
		    sizeof (usb_encryption_descr_t));
		if (size < USB_ENCRYPTION_DESCR_SIZE) {
			USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
			    "parse %dth encryption descr failed", i);
			rval = USB_FAILURE;

			goto done;
		}
		p += USB_ENCRYPTION_DESCR_SIZE;
	}

done:
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_get_dev_security_descr: "
		    "error in retrieving security descriptors");
		if (secrt_data->secrt_encry_descr) {
			kmem_free(secrt_data->secrt_encry_descr, len);
			secrt_data->secrt_encry_descr = NULL;
		}
	}

	if (pdata) {
		freemsg(pdata);
		pdata = NULL;
	}

	return (rval);
}

/* Get WUSB device status, refer to WUSB 1.0/7.3.1.2 */
int
wusb_get_dev_status(usb_pipe_handle_t ph, uint16_t selector,
	uint16_t len, uint8_t *status)
{
	usb_ctrl_setup_t	setup;
	mblk_t			*pdata = NULL;
	usb_cr_t		cr;
	usb_cb_flags_t		cb_flags;
	int			rval;

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_get_dev_status: selector = %d, len = %d", selector, len);

	setup.bmRequestType = USB_DEV_REQ_DEV_TO_HOST;
	setup.bRequest = USB_REQ_GET_STATUS;
	setup.wValue = 0;
	setup.wIndex = selector;
	setup.wLength = len;
	setup.attrs = USB_ATTRS_NONE;

	rval = usb_pipe_ctrl_xfer_wait(ph, &setup, &pdata, &cr, &cb_flags,
	    USB_FLAGS_SLEEP);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_get_dev_status failed, rval = %d, cr = %d", rval, cr);

		return (rval);
	}
	if (pdata == NULL) {
		return (USB_FAILURE);
	}
	if (MBLKL(pdata) != len) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "received incorrect dev status size");
		freemsg(pdata);

		return (USB_FAILURE);
	}

	bcopy(pdata->b_rptr, status, len);
	freemsg(pdata);

	if ((selector == WUSB_STS_TYPE_MAS_AVAIL) &&
	    (len == WUSB_SET_WUSB_MAS_LEN)) {
		uint8_t	*p = status;

		USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "mas_avail: %x %x %x %x %x %x %x %x %x %x %x %x "
		    "%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x "
		    "%x %x %x %x", p[0], p[1], p[2], p[3], p[4], p[5], p[6],
		    p[7], p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15],
		    p[16], p[17], p[18], p[19], p[20], p[21], p[22], p[23],
		    p[24], p[25], p[26], p[27], p[28], p[29], p[30], p[31]);
	}

	return (USB_SUCCESS);
}

/* test function, can be removed */
void
wusb_test_ctrlreq(usb_pipe_handle_t ph)
{
	int	i, rval;
	uint8_t	mas[WUSB_SET_WUSB_MAS_LEN];

	for (i = 0; i < 10; i++) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_test_ctrlreq %d started:", i);
		rval = wusb_get_dev_status(ph,
		    WUSB_STS_TYPE_MAS_AVAIL, WUSB_SET_WUSB_MAS_LEN, mas);
		if (rval != USB_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
			    "get mas availability status %d failed, "
			    "rval = %d", i, rval);

			continue;
		}
	}
}

/* test function, can be removed */
void
wusb_test_loopback(usb_pipe_handle_t ph)
{
	usb_ctrl_setup_t	setup;
	mblk_t			*pdata;
	usb_cr_t		cr;
	usb_cb_flags_t		cb_flags;
	int			i, j, rval;
	uint16_t		len = 20;

	for (j = 0; j < 10; j++) {
		pdata = allocb_wait(len, BPRI_LO, STR_NOSIG, NULL);
		for (i = 0; i < len; i++) {
			*pdata->b_wptr++ = (uint8_t)j;
		}

		setup.bmRequestType = USB_DEV_REQ_HOST_TO_DEV;
		setup.bRequest = USB_REQ_LOOPBACK_DATA_WRITE;
		setup.wValue = 0;
		setup.wIndex = 0;
		setup.wLength = len;
		setup.attrs = USB_ATTRS_NONE;

		USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_test_loopback_write %d start:", j);

		rval = usb_pipe_ctrl_xfer_wait(ph, &setup, &pdata, &cr,
		    &cb_flags, USB_FLAGS_SLEEP);
		if (rval != USB_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
			    "wusb_test_loopback_write %d failed, "
			    "rval = %d, cr = %d", j, rval, cr);
			freemsg(pdata);

			return;
		}

		freemsg(pdata);
		pdata = NULL;
	}
}

/* test function, can be removed */
void
wusb_test_write(wusb_dev_info_t *dev_info)
{
	int16_t		value;
	int		i, rval;
	usb_pipe_handle_t dev_ph;

	value = wusb_get_ccm_encryption_value(&dev_info->wdev_secrt_data);
	if (value == -1) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_test_write: cannot find ccm encryption type");

		return;
	}
	/* failed at 2nd write */
	for (i = 0; i < 1; i++) {
		USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_test_write %d start:", i);
		mutex_enter(&dev_info->wdev_hc->hc_mutex);
		dev_ph = dev_info->wdev_ph;
		mutex_exit(&dev_info->wdev_hc->hc_mutex);

		rval = wusb_dev_set_encrypt(dev_ph, (uint8_t)value);
		if (rval != USB_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
			    "wusb_test_write: %dth set encryption failed", i);

			continue;
		}
	}
}


/* enable CCM encryption on the device */
int
wusb_enable_dev_encrypt(wusb_hc_data_t *hc_data, wusb_dev_info_t *dev_info)
{
	int16_t		value;
	int		rval;
	usb_pipe_handle_t ph;

	USB_DPRINTF_L3(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_enable_dev_encrypt:enter");

	value = wusb_get_ccm_encryption_value(&dev_info->wdev_secrt_data);
	if (value == -1) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_enable_dev_encrypt: cannot find ccm encryption type");

		return (USB_FAILURE);
	}

	mutex_enter(&hc_data->hc_mutex);
	ph = dev_info->wdev_ph;
	mutex_exit(&hc_data->hc_mutex);

	rval = wusb_dev_set_encrypt(ph, (uint8_t)value);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_enable_dev_encrypt: set encryption failed");
	}
	USB_DPRINTF_L3(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_enable_dev_encrypti:exit");

	return (rval);
}

/*
 * Perform the authentication process, refer to WUSB 1.0/7.1.2.
 * host secrt_data will be used for 4-way handshake
 */
/* ARGSUSED */
int
wusb_hc_auth_dev(wusb_hc_data_t *hc_data, usb_port_t port,
	usb_pipe_handle_t ph, uint8_t ifc,
	wusb_secrt_data_t *secrt_data)
{
	wusb_dev_info_t		*dev_info;
	usb_pipe_handle_t	child_ph;
	dev_info_t		*child_dip;

	ASSERT(mutex_owned(&hc_data->hc_mutex));

	dev_info = hc_data->hc_dev_infos[port];
	USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_hc_auth_dev: dev addr =  %d",  dev_info->wdev_addr);
	if (dev_info == NULL) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_hc_auth_dev: port %d invalid", port);

		return (USB_INVALID_ARGS);
	}
	child_ph = dev_info->wdev_ph;
	child_dip = hc_data->hc_children_dips[port];

	mutex_exit(&hc_data->hc_mutex);
	/* get device security descrs */
	if (wusb_get_dev_security_descr(child_ph,
	    &dev_info->wdev_secrt_data) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_hc_auth_dev: failed to get device security descrs");
		mutex_enter(&hc_data->hc_mutex);

		return (USB_FAILURE);
	}

	/*
	 * enable CCM encryption on the device, this needs to be done
	 * before 4-way handshake. [WUSB 1.0/7.3.2.5]
	 */
	if (wusb_enable_dev_encrypt(hc_data, dev_info) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_hc_auth_dev: set encryption failed");

		mutex_enter(&hc_data->hc_mutex);
		return (USB_FAILURE);
	}


	/* this seems to relieve the non-response issue somehow */
	usb_pipe_close(child_dip, child_ph,
	    USB_FLAGS_SLEEP | USBA_FLAGS_PRIVILEGED, NULL, NULL);

	mutex_enter(&hc_data->hc_mutex);
	dev_info->wdev_ph = NULL;

	/* unauthenticated state */
	/* check cc_list for existing cc with the same CDID */
	if ((dev_info->wdev_cc = wusb_hc_cc_matched(hc_data->hc_cc_list,
	    dev_info->wdev_cdid)) == NULL) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_hc_auth_dev: no matching cc found");

		if (dev_info->wdev_is_newconn == 0) {
			USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
			    "wusb_hc_auth_dev: not new connection, "
			    "just fail");

			return (USB_FAILURE);
		}

		/* now we simply return not supported */
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_hc_auth_dev: numeric association not supported");

		return (USB_NOT_SUPPORTED);
	}

	USB_DPRINTF_L3(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_hc_auth_dev: matching cc found 0x%p",
	    (void *)dev_info->wdev_cc);

	mutex_exit(&hc_data->hc_mutex);
	if (usb_pipe_open(child_dip, NULL, NULL,
	    USB_FLAGS_SLEEP | USBA_FLAGS_PRIVILEGED, &child_ph) !=
	    USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "usb_pipe_open failed");

		mutex_enter(&hc_data->hc_mutex);

		return (USB_FAILURE);
	}

	mutex_enter(&hc_data->hc_mutex);
	/* recording the default pipe */
	dev_info->wdev_ph = child_ph;

	mutex_exit(&hc_data->hc_mutex);
	/* perform 4-way handshake */
	if (wusb_4way_handshake(hc_data, port, ph, ifc) != 0) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "port(%d) 4-way handshake authentication failed!",
		    port);

		/* perhaps resetting the device is better */
		usb_pipe_reset(child_dip, child_ph,
		    USB_FLAGS_SLEEP | USBA_FLAGS_PRIVILEGED,
		    NULL, NULL);
		(void) wusb_dev_set_encrypt(child_ph, 0);

		mutex_enter(&hc_data->hc_mutex);

		return (USB_FAILURE);
	}

	mutex_enter(&hc_data->hc_mutex);

	return (USB_SUCCESS);
}

/* Acknowledge WUSB Device Disconnect notification, refer to WUSB 1.0/7.6.2 */
int
wusb_hc_ack_disconn(wusb_hc_data_t *hc_data, uint8_t addr)
{
	wusb_ie_dev_disconnect_t	*disconn_ie;
	uint8_t				iehdl;
	int				rval;

	ASSERT(mutex_owned(&hc_data->hc_mutex));

	/*
	 * the scheme ensures each time only one device addr
	 * is set each time
	 */
	disconn_ie = kmem_zalloc(sizeof (wusb_ie_dev_disconnect_t), KM_SLEEP);
	if (!disconn_ie) {
		return (USB_NO_RESOURCES);
	}

	disconn_ie->bIEIdentifier = WUSB_IE_DEV_DISCONNECT;
	disconn_ie->bDeviceAddress[0] = addr;
	/* padding, no active wusb device addr will be 1 */
	disconn_ie->bDeviceAddress[1] = 1;
	disconn_ie->bLength = 4;

	rval = wusb_hc_get_iehdl(hc_data, (wusb_ie_header_t *)disconn_ie,
	    &iehdl);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_hc_ack_disconn: get ie handle fails");
		kmem_free(disconn_ie, sizeof (wusb_ie_dev_disconnect_t));

		return (rval);
	}

	rval = wusb_hc_add_mmc_ie(hc_data, 0, 0, iehdl,
	    disconn_ie->bLength, (uint8_t *)disconn_ie);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_hc_ack_disconn: add dev disconnect ie fails");
		wusb_hc_free_iehdl(hc_data, iehdl);
		kmem_free(disconn_ie, sizeof (wusb_ie_dev_disconnect_t));

		return (rval);
	}

	mutex_exit(&hc_data->hc_mutex);
	/*
	 * WUSB 1.0/7.5.4 requires the IE to be transmitted at least
	 * 100ms before ceasing, wait for 150ms here
	 */
	delay(drv_usectohz(150000));
	mutex_enter(&hc_data->hc_mutex);

	/* cease transmitting the IE */
	(void) wusb_hc_remove_mmc_ie(hc_data, (uint8_t)iehdl);
	wusb_hc_free_iehdl(hc_data, iehdl);
	kmem_free(disconn_ie, sizeof (wusb_ie_dev_disconnect_t));

	return (USB_SUCCESS);
}

/* create child devinfo node and usba_device structure */
int
wusb_create_child_devi(dev_info_t *dip, char *node_name,
	usba_hcdi_ops_t *usba_hcdi_ops, dev_info_t *usb_root_hub_dip,
	usb_port_status_t port_status, usba_device_t *usba_device,
	dev_info_t **child_dip)
{
	ndi_devi_alloc_sleep(dip, node_name, (pnode_t)DEVI_SID_NODEID,
	    child_dip);

	usba_device = usba_alloc_usba_device(usb_root_hub_dip);

	/* grab the mutex to keep warlock happy */
	mutex_enter(&usba_device->usb_mutex);
	usba_device->usb_hcdi_ops = usba_hcdi_ops;
	usba_device->usb_port_status = port_status;
	usba_device->usb_is_wireless = B_TRUE;
	mutex_exit(&usba_device->usb_mutex);

	/* store the usba_device point in the dip */
	usba_set_usba_device(*child_dip, usba_device);

	return (USB_SUCCESS);
}

/*
 * Handle WUSB child device connection, including creating child devinfo
 * and usba strutures, authentication, configuration and attach.
 */
int
wusb_hc_handle_port_connect(wusb_hc_data_t *hc_data, usb_port_t port,
	usb_pipe_handle_t ph, uint8_t ifc, wusb_secrt_data_t *secrt_data)
{
	dev_info_t	*dip = hc_data->hc_dip;
	dev_info_t	*child_dip = NULL;
	usba_device_t	*child_ud = NULL;
	usba_device_t	*parent_ud;
	usba_hcdi_t	*hcdi = usba_hcdi_get_hcdi(dip);
	usb_pipe_handle_t child_ph = NULL;
	int		rval;
	int		child_created = 0;
	wusb_dev_info_t	*dev_info;
	usb_dev_descr_t	usb_dev_descr;
	int		ackie_removed = 0;

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_hc_handle_port_connect: hc_data=0x%p, port=%d",
	    (void *)hc_data, port);

	ASSERT(mutex_owned(&hc_data->hc_mutex));
	dev_info = hc_data->hc_dev_infos[port];
	if (dev_info == NULL) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_hc_handle_port_connect: port %d invalid", port);
		wusb_hc_rm_ack(hc_data);

		return (USB_INVALID_ARGS);
	}

	dev_info->wdev_hc = hc_data;

	/* prepare child devinfo and usba structures */
	if (hc_data->hc_children_dips[port]) {
		child_dip = hc_data->hc_children_dips[port];
		child_ud = hc_data->hc_usba_devices[port];
		child_ph = usba_get_dflt_pipe_handle(child_dip);
		mutex_exit(&hc_data->hc_mutex);
		usb_pipe_close(child_dip, child_ph,
		    USB_FLAGS_SLEEP | USBA_FLAGS_PRIVILEGED, NULL, NULL);
		mutex_enter(&hc_data->hc_mutex);
	} else {
		rval = wusb_create_child_devi(dip,
		    "device",
		    hcdi->hcdi_ops,
		    dip,
		    USBA_HIGH_SPEED_DEV,
		    child_ud,
		    &child_dip);
		if (rval != USB_SUCCESS) {
			wusb_hc_rm_ack(hc_data); // , ph, ifc);

			return (rval);
		}
		child_ud = usba_get_usba_device(child_dip);
		ASSERT(child_ud != NULL);

		mutex_enter(&child_ud->usb_mutex);
		child_ud->usb_dev_descr = kmem_zalloc(sizeof (usb_dev_descr_t),
		    KM_SLEEP);
		child_ud->usb_wireless_data =
		    kmem_zalloc(sizeof (usba_wireless_data_t), KM_SLEEP);
		mutex_exit(&child_ud->usb_mutex);
		child_created = 1;
		hc_data->hc_children_dips[port] = child_dip;
		hc_data->hc_usba_devices[port] = child_ud;
	}

	/* do necessary setup */
	parent_ud = usba_get_usba_device(dip);
	mutex_enter(&child_ud->usb_mutex);
	child_ud->usb_addr = dev_info->wdev_addr;
	child_ud->usb_port = port;

	/*
	 * TODO: now only consider the situation that HWA is high
	 * speed dev for the children. The situation that HWA is
	 * connected to the USB 1.1 port is not considered. The
	 * available HWA devices can't work behind USB1.1 port.
	 */
	child_ud->usb_hs_hub_usba_dev = parent_ud;
	child_ud->usb_hs_hub_addr = parent_ud->usb_addr;
	child_ud->usb_hs_hub_port = port;
	bzero(&usb_dev_descr, sizeof (usb_dev_descr_t));

	/*
	 * 255 for WUSB devices, refer to WUSB 1.0/4.8.1.
	 * default ctrl pipe will ignore this value
	 */
	usb_dev_descr.bMaxPacketSize0 = 255;
	bcopy(&usb_dev_descr, child_ud->usb_dev_descr,
	    sizeof (usb_dev_descr_t));
	mutex_exit(&child_ud->usb_mutex);

	dev_info->wdev_ph = NULL;

	/*
	 * set device info and encryption mode for the host so that
	 * open child pipe can work later
	 */
	rval = wusb_hc_set_device_info(hc_data, port);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_hc_handle_port_connect: set device info for"
		    " host failed, rval = %d", rval);

		goto error;
	}

	/* set the host to unsecure mode before authentication starts */
	rval = wusb_hc_set_encrypt(hc_data, port, WUSB_ENCRYP_TYPE_UNSECURE);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_hc_handle_port_connect:set unsecure encryption"
		    " for host failed, rval = %d", rval);

		goto error;
	}

	/*
	 * Open the default pipe for the child device
	 * the MaxPacketSize for the default ctrl pipe is
	 * set in usba_init_pipe_handle().
	 */
	mutex_exit(&hc_data->hc_mutex);
	if ((rval = usb_pipe_open(child_dip, NULL, NULL,
	    USB_FLAGS_SLEEP | USBA_FLAGS_PRIVILEGED, &child_ph)) !=
	    USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_hc_handle_port_connect:open default pipe failed (%d)",
		    rval);
		mutex_enter(&hc_data->hc_mutex);

		goto error;
	}
	mutex_enter(&hc_data->hc_mutex);

	/* recording the default pipe */
	dev_info->wdev_ph = child_ph;

	/* verify the default child pipe works */
	if (wusb_get_dev_uwb_descr(hc_data, port) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_hc_handle_port_connect: failed to get"
		    " device uwb descr");

		goto error;
	}

	/* remove connect acknowledge IE */
	wusb_hc_rm_ack(hc_data);
	ackie_removed = 1;

	/* do authentication */
	if (wusb_hc_auth_dev(hc_data, port, ph, ifc, secrt_data) !=
	    USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_hc_handle_port_connect: "
		    "device authentication fails");

		goto error;
	}

	/* online child */
	if (dev_info->wdev_state == WUSB_STATE_RECONNTING) {
		dev_info->wdev_state = WUSB_STATE_CONFIGURED;
		/* post reconnect event to child */
		wusb_hc_reconnect_dev(hc_data, port);
	} else {
		if (wusb_hc_create_child(hc_data, port) != USB_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
			    "wusb_hc_handle_port_connect: create child fails");

			goto error;
		}
		dev_info->wdev_state = WUSB_STATE_CONFIGURED;
	}

	return (USB_SUCCESS);

error:
	if (dev_info->wdev_ph != NULL) {
		mutex_exit(&hc_data->hc_mutex);
		usb_pipe_close(child_dip, child_ph,
		    USB_FLAGS_SLEEP | USBA_FLAGS_PRIVILEGED, NULL, NULL);
		mutex_enter(&hc_data->hc_mutex);

		dev_info->wdev_ph = NULL;
	}

	if (child_created) {

		rval = usba_destroy_child_devi(child_dip,
		    NDI_DEVI_REMOVE);

		if (rval != USB_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
			    "wusb_hc_handle_port_connect: "
			    "failure to remove child node");
		}

		mutex_exit(&hc_data->hc_mutex);
		usba_free_usba_device(child_ud);
		mutex_enter(&hc_data->hc_mutex);

		hc_data->hc_children_dips[port] = NULL;
		hc_data->hc_usba_devices[port] = NULL;
	}

	if (ackie_removed == 0) {
		wusb_hc_rm_ack(hc_data);
	}

	return (USB_FAILURE);
}

/*
 * Handle device connect notification: assign port number, acknowledge
 * device connection, and online child
 * Refer to WUSB 1.0 4.13, 6.10, 7.1 for connection process handling
 * and device state diagram
 */
void
wusb_hc_handle_dn_connect(wusb_hc_data_t *hc_data, usb_pipe_handle_t ph,
	uint8_t ifc, uint8_t *data, size_t len,
	wusb_secrt_data_t *secrt_data)
{
	wusb_dn_connect_t	*dn_con;
	uint8_t			addr;
	wusb_dev_info_t		*dev_info = NULL;
	usb_port_t		port = 0;
	uint_t			new_alloc = 0;
	wusb_secrt_data_t	*csecrt_data;

	if (len < WUSB_DN_CONN_PKT_LEN) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_hc_handle_dn_connect: short pkt len %d", (int)len);

		return;
	}

	dn_con = (wusb_dn_connect_t *)data;
	ASSERT(dn_con->bType == WUSB_DN_CONNECT);
	addr = dn_con->bmConnAttributes[0];

	mutex_enter(&hc_data->hc_mutex);

	/*
	 * check if the device requesting to connect was ever connected
	 * and decide connect request type
	 */
	if (wusb_hc_is_dev_connected(hc_data, dn_con->CDID, &port) == 0) {
		/*
		 * the device with the CDID was not connected.
		 * It should be a connect or new connect request
		 */
		if (addr) {
			/*
			 * the device may have been disconnected by the host
			 * the host expects to see a connect request instead
			 * of a reconnect request. The reconnect request is
			 * ignored.
			 */
			USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
			    "wusb_hc_handle_dn_connect: device has "
			    "disconnected, need to connect again");
			mutex_exit(&hc_data->hc_mutex);

			return;
		}

		/* assign port number */
		port = wusb_hc_get_free_port(hc_data);
		if (port == 0) {
			USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
			    "wusb_hc_handle_dn_connect: cannot find "
			    "a free port for the device connecting");
			mutex_exit(&hc_data->hc_mutex);

			return;
		}

		/* initialize dev_info structure */
		dev_info = kmem_zalloc(sizeof (wusb_dev_info_t), KM_SLEEP);
		/* unconnected dev addr is 0xff, refer to WUSB 1.0/7.6.1 */
		dev_info->wdev_addr = 0xff;
		(void) memcpy(dev_info->wdev_cdid, dn_con->CDID, 16);
		dev_info->wdev_state = WUSB_STATE_CONNTING;
		hc_data->hc_dev_infos[port] = dev_info;
		new_alloc = 1;
	} else {
		/*
		 * the device with the CDID was found connected.
		 * It should be a reconnect or connect request.
		 */
		dev_info = hc_data->hc_dev_infos[port];
		if ((addr != 0) && (addr == dev_info->wdev_addr)) {
			dev_info->wdev_state = WUSB_STATE_RECONNTING;
		} else if (addr == 0) {
			dev_info->wdev_state = WUSB_STATE_CONNTING;
			dev_info->wdev_addr = 0xff;
		} else {
			USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
			    "wusb_hc_handle_dn_connect: reconnecting, but "
			    "device addr doesn't match");
			mutex_exit(&hc_data->hc_mutex);

			return;
		}

		/*
		 * post removal event to child device before
		 * reconnecting it
		 */
		wusb_hc_disconnect_dev(hc_data, port);
	}

	dev_info->wdev_beacon_attr = dn_con->bmConnAttributes[1] &
	    WUSB_DN_CONN_BEACON_MASK;

	/* refer to WUSB 1.0/7.6.1/4.13 for how New Connection bit works */
	if (addr == 0) {
		dev_info->wdev_is_newconn = dn_con->bmConnAttributes[1] &
		    WUSB_DN_CONN_NEW;
	} else {
		dev_info->wdev_is_newconn = 0;
	}

	/*
	 * state=connting means new dev addr needs to be assigned
	 * new_alloc=1 means newly allocated dev_info structure needs to
	 * be freed later if the connection process fails
	 * To simplify, the assigned address corresponds to the faked
	 * port number.
	 */
	if (dev_info->wdev_addr == 0xff) {
		dev_info->wdev_addr = port + 0x7f;
	}

	/*
	 * Acknowledge dn connect notification.
	 * The notif queue scheme will ensure only one ack_ie exists
	 * at one time. Don't deal with multiple ack_ie elements now
	 */
	if (wusb_hc_ack_conn(hc_data, port) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_hc_handle_dn_connect: acknowledge "
		    "connection fails");

		if (new_alloc == 1) {
			kmem_free(dev_info, sizeof (wusb_dev_info_t));
			hc_data->hc_dev_infos[port] = NULL;
		} else {
			dev_info->wdev_state = WUSB_STATE_UNCONNTED;
		}
		mutex_exit(&hc_data->hc_mutex);

		return;
	}

	/*
	 * Handle device connection according to connect request type
	 * Connect Acknowledge IE is removed inside the function
	 */
	if (wusb_hc_handle_port_connect(hc_data, port, ph, ifc, secrt_data) !=
	    USB_SUCCESS) {
		char *pathname = kmem_alloc(MAXPATHLEN, KM_NOSLEEP);

		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_hc_handle_dn_connect: connect port %d fails", port);

		if (new_alloc == 1) {
			if (dev_info->wdev_secrt_data.secrt_encry_descr) {
				csecrt_data = &dev_info->wdev_secrt_data;
				kmem_free(csecrt_data->secrt_encry_descr,
				    sizeof (usb_encryption_descr_t) *
				    csecrt_data->secrt_n_encry);
			}
			if (dev_info->wdev_uwb_descr) {
				kmem_free(dev_info->wdev_uwb_descr,
				    sizeof (usb_uwb_cap_descr_t));
			}
			kmem_free(dev_info, sizeof (wusb_dev_info_t));
			hc_data->hc_dev_infos[port] = NULL;
		} else {
			dev_info->wdev_state = WUSB_STATE_UNCONNTED;
		}
		mutex_exit(&hc_data->hc_mutex);

		if (pathname) {
			/* output error message to syslog */
			cmn_err(CE_WARN, "%s %s%d: Connecting device"
			    " on WUSB port %d fails",
			    ddi_pathname(hc_data->hc_dip, pathname),
			    ddi_driver_name(hc_data->hc_dip),
			    ddi_get_instance(hc_data->hc_dip),
			    port);

			kmem_free(pathname, MAXPATHLEN);
		}

		return;
	}

	mutex_exit(&hc_data->hc_mutex);
}

/* Handle device disconnect notification, refer to WUSB 1.0/7.6.2 */
void
wusb_hc_handle_dn_disconnect(wusb_hc_data_t *hc_data, uint8_t addr,
	uint8_t *data, size_t len)
{
	wusb_dn_disconnect_t	*dn_discon;
	usb_port_t		port;

	if (len < WUSB_DN_DISCONN_PKT_LEN) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_hc_handle_dn_disconnect: short pkt len %d",
		    (int)len);

		return;
	}

	dn_discon = (wusb_dn_disconnect_t *)data;
	ASSERT(dn_discon->bType == WUSB_DN_DISCONNECT);

	mutex_enter(&hc_data->hc_mutex);

	/* send WDEV_DISCONNECT_IE to acknowledge the notification */
	if (wusb_hc_ack_disconn(hc_data, addr) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_hc_handle_dn_disconnect: send disconnect ie fails");
		mutex_exit(&hc_data->hc_mutex);

		return;
	}

	/* offline the device requesting disconnection */
	if (wusb_hc_is_addr_valid(hc_data, addr, &port)) {
		(void) wusb_hc_destroy_child(hc_data, port);
	} else {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_hc_handle_dn_disconnect: device with addr "
		    "0x%x not found", addr);
	}

	mutex_exit(&hc_data->hc_mutex);
}

/* post disconnect event to the device driver */
void
wusb_hc_disconnect_dev(wusb_hc_data_t *hc_data, usb_port_t port)
{
	dev_info_t	*dip = hc_data->hc_dip;

	ASSERT(dip != NULL);

	mutex_exit(&hc_data->hc_mutex);

	hc_data->disconnect_dev(dip, port);

	mutex_enter(&hc_data->hc_mutex);
}

/* post reconnect event to the device driver */
void
wusb_hc_reconnect_dev(wusb_hc_data_t *hc_data, usb_port_t port)
{
	dev_info_t	*dip = hc_data->hc_dip;

	ASSERT(dip != NULL);

	mutex_exit(&hc_data->hc_mutex);

	hc_data->reconnect_dev(dip, port);

	mutex_enter(&hc_data->hc_mutex);
}

/* configure child device and online it */
int
wusb_hc_create_child(wusb_hc_data_t *hc_data, usb_port_t port)
{
	dev_info_t	*dip = hc_data->hc_dip;
	int		rval;

	ASSERT(dip != NULL);

	mutex_exit(&hc_data->hc_mutex);

	rval = hc_data->create_child(dip, port);

	mutex_enter(&hc_data->hc_mutex);

	return (rval);
}

/* offline child device */
int
wusb_hc_destroy_child(wusb_hc_data_t *hc_data, usb_port_t port)
{
	dev_info_t	*dip = hc_data->hc_dip;
	int		rval;

	ASSERT(dip != NULL);

	mutex_exit(&hc_data->hc_mutex);

	rval = hc_data->destroy_child(dip, port);

	mutex_enter(&hc_data->hc_mutex);

	return (rval);
}


/*
 * ***********************
 * CC management functions
 * ***********************
 */

/* add a CC to the CC list */
void
wusb_hc_add_cc(wusb_hc_cc_list_t **cc_list, wusb_hc_cc_list_t *new_cc)
{
	wusb_hc_cc_list_t	*head;

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_hc_add_cc: cc_list = 0x%p, new_cc = 0x%p",
	    (void *)cc_list, (void *)new_cc);

	if (new_cc == NULL) {

		return;
	}

	if (*cc_list == NULL) {
		*cc_list = new_cc;

		return;
	}

	head = *cc_list;
	while (head != NULL) {
		/* update an existing CC */
		if (memcmp(head->cc.CDID, new_cc->cc.CDID, 16) == 0) {
			(void) memcpy(head->cc.CK, new_cc->cc.CK, 16);
			kmem_free(new_cc, sizeof (wusb_hc_cc_list_t));

			return;
		}

		/* add a new CC */
		if (head->next == NULL) {
			head->next = new_cc;

			return;
		}

		head = head->next;
	}
}

/* remove a CC from the CC list */
void
wusb_hc_rem_cc(wusb_hc_cc_list_t **cc_list, wusb_cc_t *old_cc)
{
	wusb_cc_t		*cc;
	wusb_hc_cc_list_t	*prev, *next;

	if (*cc_list == NULL || old_cc == NULL) {

		return;
	}

	prev = *cc_list;
	cc = &prev->cc;
	if (memcmp(cc, old_cc, sizeof (wusb_cc_t)) == 0) {
		*cc_list = prev->next;
		kmem_free(prev, sizeof (wusb_hc_cc_list_t));

		return;
	}
	next = prev->next;
	while (next != NULL) {
		cc = &next->cc;
		if (memcmp(cc, old_cc, sizeof (wusb_cc_t)) == 0) {
			prev->next = next->next;
			kmem_free(next, sizeof (wusb_hc_cc_list_t));

			return;
		}
		prev = next;
		next = prev->next;
	}
}

/* remove all CCs from the list */
void
wusb_hc_free_cc_list(wusb_hc_cc_list_t *cc_list)
{
	wusb_hc_cc_list_t	*list, *next;

	list = cc_list;
	while (list != NULL) {
		next = list->next;
		kmem_free(list, sizeof (wusb_hc_cc_list_t));
		list = next;
	}
}

/* Send Host Disconnect notification */
int
wusb_hc_send_host_disconnect(wusb_hc_data_t *hc_data)
{
	wusb_ie_host_disconnect_t	*disconn_ie;
	uint8_t				iehdl;
	int				rval;

	disconn_ie = kmem_zalloc(sizeof (wusb_ie_host_disconnect_t), KM_SLEEP);
	disconn_ie->bIEIdentifier = WUSB_IE_HOST_DISCONNECT;
	disconn_ie->bLength = sizeof (wusb_ie_host_disconnect_t);

	mutex_enter(&hc_data->hc_mutex);
	rval = wusb_hc_get_iehdl(hc_data, (wusb_ie_header_t *)disconn_ie,
	    &iehdl);
	mutex_exit(&hc_data->hc_mutex);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_hc_send_host_disconnect: get ie handle fails");
		kmem_free(disconn_ie, sizeof (wusb_ie_host_disconnect_t));

		return (rval);
	}

	rval = wusb_hc_add_mmc_ie(hc_data, 0, 0, iehdl,
	    disconn_ie->bLength, (uint8_t *)disconn_ie);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_hc_send_host_disconnect: add host "
		    "disconnect ie fails");
		mutex_enter(&hc_data->hc_mutex);
		wusb_hc_free_iehdl(hc_data, iehdl);
		mutex_exit(&hc_data->hc_mutex);
		kmem_free(disconn_ie, sizeof (wusb_ie_host_disconnect_t));

		return (rval);
	}

	delay(drv_usectohz(100000));	/* WUSB 1.0/7.5.5 */

	mutex_enter(&hc_data->hc_mutex);
	(void) wusb_hc_remove_mmc_ie(hc_data, iehdl);
	wusb_hc_free_iehdl(hc_data, iehdl);
	mutex_exit(&hc_data->hc_mutex);

	kmem_free(disconn_ie, sizeof (wusb_ie_host_disconnect_t));

	return (USB_SUCCESS);
}

/* Get RC dev_t by HC dip */
int
wusb_get_rc_dev_by_hc(dev_info_t *dip, dev_t *dev)
{
	dev_info_t	*pdip = ddi_get_parent(dip);
	dev_info_t	*rcdip;
	int		found = 0;
	major_t		major;
	minor_t		minor;
	int		inst;

	if (strcmp(ddi_driver_name(dip), "whci") == 0) {
		/* For WHCI, RC and HC share the same dip */
		rcdip = dip;
		inst = ddi_get_instance(rcdip);
		/* need to change when whci driver is ready */
		minor = inst;
		found = 1;
	} else {
		/* For HWA, RC and HC share the same parent dip */
		rcdip = ddi_get_child(pdip);
		while (rcdip != NULL) {
			if (strcmp(ddi_driver_name(rcdip), "hwarc") == 0) {
				found = 1;
				inst = ddi_get_instance(rcdip);
				// minor = HWAHC_CONSTRUCT_MINOR(inst);
				/*
				 * now hwarc driver uses inst# as minor#.
				 * this may change
				 */
				minor = inst;

				break;
			}
			rcdip = ddi_get_next_sibling(rcdip);
		}
	}

	if (found == 0) {
		*dev = 0;

		return (USB_FAILURE);
	}

	major = ddi_driver_major(rcdip);
	*dev = makedevice(major, minor);

	USB_DPRINTF_L3(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_get_rc_dev_by_hc: rc device(%s%d) major = %d, minor = %d",
	    ddi_driver_name(rcdip), inst, major, minor);

	return (USB_SUCCESS);
}

/* format nonce to a buffer according to WUSB Table 6-3 */
static void
nonce_to_buf(wusb_ccm_nonce_t *nonce, uchar_t *nbuf, int sfn_only)
{
	int i, offset;
	uchar_t *p = nbuf;

	for (i = 0, offset = 0; i < 6; i++, offset += 8) {
		*p++ = (nonce->sfn >> offset) & 0xff;
	}

	if (sfn_only) {

		return;
	}

	*p++ = (nonce->tkid) & 0xff;
	*p++ = (nonce->tkid >> 8) & 0xff;
	*p++ = (nonce->tkid >> 16) & 0xff;

	*p++ = (nonce->daddr) & 0xff;
	*p++ = (nonce->daddr >> 8) & 0xff;

	*p++ = (nonce->saddr) & 0xff;
	*p++ = (nonce->saddr >> 8) & 0xff;
}

/* Call the crypto framework to compute CCM MAC data */
static int
wusb_ccm_mac(
	CK_AES_CCM_PARAMS *ccm_params,
	const uchar_t *key, size_t klen,
	uchar_t *out, int olen)
{
	crypto_mechanism_t mech;
	crypto_key_t crkey;
	crypto_context_t ctx;
	crypto_data_t dmac;
	int ret;

	bzero(&crkey, sizeof (crkey));
	crkey.ck_format = CRYPTO_KEY_RAW;
	crkey.ck_data   = (char *)key;
	crkey.ck_length = klen * 8;

	mech.cm_type	  = crypto_mech2id(SUN_CKM_AES_CCM);
	mech.cm_param	  = (caddr_t)ccm_params;
	mech.cm_param_len = sizeof (CK_AES_CCM_PARAMS);

	if ((ret = crypto_encrypt_init(&mech, &crkey, NULL, &ctx, NULL)) !=
	    CRYPTO_SUCCESS) {

		return (ret);
	}

	/*
	 * Since we've known the encrypted data is none (l(m) = 0),
	 * the middle procedure crypto_encrypt_update() is ignored.
	 * The last 8-byte MAC is calculated directly.
	 */

	bzero(&dmac, sizeof (dmac));
	dmac.cd_format = CRYPTO_DATA_RAW;
	dmac.cd_offset = 0;
	dmac.cd_length = olen;
	dmac.cd_raw.iov_base = (char *)out;
	dmac.cd_raw.iov_len = olen;

	if ((ret = crypto_encrypt_final(ctx, &dmac, NULL)) != CRYPTO_SUCCESS) {

		return (ret);
	}

	return (CRYPTO_SUCCESS);
}

/* Pseudo-Random Function according to WUSB 1.0/6.5 */
int
PRF(const uchar_t *key, size_t klen,
	wusb_ccm_nonce_t *nonce,
	const uchar_t *adata, size_t alen,
	const uchar_t *bdata, size_t blen,
	uchar_t *out,
	size_t bitlen)
{
	CK_AES_CCM_PARAMS ccm_params;
	uchar_t *ab;
	uchar_t nbuf[CCM_NONCE_LEN];
	size_t lm, la;
	int i, offset, ret;

	/* from WUSB 6.4 */
	lm = 0;
	la = alen + blen;
	ab = (uchar_t *)kmem_alloc(la, KM_SLEEP);
	bcopy(adata, ab, alen);
	bcopy(bdata, ab + alen, blen);

	nonce_to_buf(nonce, nbuf, 0);

	ccm_params.ulMACSize = CCM_MAC_LEN;
	ccm_params.ulNonceSize = CCM_NONCE_LEN;
	ccm_params.nonce = nbuf;
	ccm_params.ulAuthDataSize = la;	/* l(a) */
	ccm_params.authData = ab;
	ccm_params.ulDataSize = lm;	/* l(m) */

	offset = 0;
	for (i = 0; i < (bitlen + 63)/64; i++) {
		ret = wusb_ccm_mac(&ccm_params, key, klen,
		    out + offset, CCM_MAC_LEN);

		if (ret != CRYPTO_SUCCESS) {
			kmem_free(ab, la);

			return (ret);
		};

		offset += CCM_MAC_LEN;
		nonce->sfn++;
		nonce_to_buf(nonce, nbuf, 1);
	}

	kmem_free(ab, la);

	return (CRYPTO_SUCCESS);
}

/* rbuf is a 16-byte buffer to store the random nonce */
int
wusb_gen_random_nonce(wusb_hc_data_t *hc_data,
	wusb_dev_info_t *dev_info, uchar_t *rbuf)
{
	usba_device_t *udev = usba_get_usba_device(hc_data->hc_dip);
	wusb_ccm_nonce_t n;
	uint16_t vid, pid;
	uint64_t ht;
	uint8_t kbuf[16], *p;
	uchar_t a[] = "Random Numbers";

	n.sfn = 0;
	n.tkid = dev_info->wdev_tkid[0] | (dev_info->wdev_tkid[1] << 8) |
	    (dev_info->wdev_tkid[2] << 16);
	n.daddr = hc_data->hc_addr;
	n.saddr = dev_info->wdev_addr;

	vid = udev->usb_dev_descr->idVendor;
	pid = udev->usb_dev_descr->idProduct;
	ht = gethrtime();

	p = kbuf;
	bcopy((uint8_t *)&vid, p, sizeof (uint16_t));
	p += sizeof (uint16_t);

	bcopy((uint8_t *)&pid, p, sizeof (uint16_t));
	p += sizeof (uint16_t);

	bcopy((uint8_t *)&p, p, sizeof (uint32_t));
	p += sizeof (uint32_t);

	bcopy((uint8_t *)&ht, p, sizeof (uint64_t));

	return (PRF_128(kbuf, 16, &n, a, sizeof (a),
	    (uchar_t *)hc_data, sizeof (wusb_hc_data_t), rbuf));
}

/* Set WUSB device encryption type, refer to WUSB 1.0/7.3.2.2 */
int
wusb_dev_set_encrypt(usb_pipe_handle_t ph, uint8_t value)
{
	usb_ctrl_setup_t	setup;
	usb_cr_t		cr;
	usb_cb_flags_t		cb_flags;

	setup.bmRequestType = USB_DEV_REQ_HOST_TO_DEV;
	setup.bRequest = USB_REQ_SET_ENCRYPTION;
	setup.wValue = value;
	setup.wIndex = 0;
	setup.wLength = 0;
	setup.attrs = USB_ATTRS_NONE;

	return (usb_pipe_ctrl_xfer_wait(ph, &setup, NULL,
	    &cr, &cb_flags, USB_FLAGS_SLEEP));
}

/*
 * Set WUSB device key descriptor, refer to WUSB 1.0/7.3.2.4
 *	ph - Device's default control pipe
 *	key_index - Key Index
 */
int
wusb_dev_set_key(usb_pipe_handle_t ph, uint8_t key_index,
	usb_key_descr_t *key, size_t klen)
{
	usb_ctrl_setup_t	setup;
	usb_cr_t		cr;
	usb_cb_flags_t		cb_flags;
	mblk_t			*pdata;
	int			rval;

	setup.bmRequestType = USB_DEV_REQ_HOST_TO_DEV;
	setup.bRequest = USB_REQ_SET_DESCR;
	setup.wValue = (USB_DESCR_TYPE_KEY << 8) | key_index;
	setup.wIndex = 0;
	setup.wLength = (uint16_t)klen;
	setup.attrs = USB_ATTRS_NONE;

	if ((pdata = allocb(klen, BPRI_HI)) == NULL) {

		return (USB_FAILURE);
	}
	bcopy(key, pdata->b_wptr, klen);
	pdata->b_wptr += klen;

	rval = usb_pipe_ctrl_xfer_wait(ph, &setup, &pdata,
	    &cr, &cb_flags, USB_FLAGS_SLEEP);

	freemsg(pdata);

	return (rval);
}

/*
 * Set encryption type for the specified device.
 */
int
wusb_hc_set_encrypt(wusb_hc_data_t *hc_data, usb_port_t port, uint8_t type)
{
	dev_info_t	*dip = hc_data->hc_dip;
	int		rval;

	if ((rval = hc_data->set_encrypt(dip, port, type)) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_hc_set_encrypt: set encryption type %d "
		    "for port %d failed, rval = %d", type, port, rval);
	}

	return (rval);
}

/*
 * Set Device Key for WUSB host, refer to WUSB 1.0/8.5.3.8
 * Call the HC's specific set_ptk function to set PTK for a device
 * len: length of key_data
 */
int
wusb_hc_set_ptk(wusb_hc_data_t *hc_data, uint8_t *key_data, usb_port_t port)
{
	dev_info_t	*dip = hc_data->hc_dip;
	wusb_dev_info_t	*dev_info = hc_data->hc_dev_infos[port];
	usb_key_descr_t	*key_descr;
	size_t		klen;
	int		rval;
	uint8_t		*p;

	ASSERT(mutex_owned(&hc_data->hc_mutex));

	if ((key_data == NULL) || (dev_info == NULL)) {

		return (USB_INVALID_ARGS);
	}

	klen = sizeof (usb_key_descr_t) + 15;
	key_descr = kmem_zalloc(klen, KM_SLEEP);

	key_descr->bLength = (uint16_t)klen;
	key_descr->bDescriptorType = USB_DESCR_TYPE_KEY;
	(void) memcpy(key_descr->tTKID, dev_info->wdev_tkid, 3);
	p = &key_descr->KeyData[0];
	(void) memcpy(p, key_data, 16);

	mutex_exit(&hc_data->hc_mutex);

	if ((rval = hc_data->set_ptk(dip, key_descr, klen, port)) !=
	    USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_hc_set_pkt: set ptk for port %d failed", port);
	}

	kmem_free(key_descr, klen);
	mutex_enter(&hc_data->hc_mutex);

	return (rval);
}

/*
 * Set GTK for a host
 * Call HC's specific set_gtk function
 *
 * Default gtk is set at hc_initial_start, and to be changed whenever
 * a device leaves the current group (refer to WUSB spec 6.2.11.2)
 */
int
wusb_hc_set_gtk(wusb_hc_data_t *hc_data, uint8_t *key_data, uint8_t *tkid)
{
	dev_info_t	*dip = hc_data->hc_dip;
	usb_key_descr_t	*key_descr;
	size_t		klen;
	int		rval;
	uint8_t		*p;

	if ((key_data == NULL) || (tkid == NULL)) {

		return (USB_INVALID_ARGS);
	}

	klen = sizeof (usb_key_descr_t) + 15;
	key_descr = kmem_zalloc(klen, KM_SLEEP);

	key_descr->bLength = (uint16_t)klen;
	key_descr->bDescriptorType = USB_DESCR_TYPE_KEY;
	(void) memcpy(key_descr->tTKID, tkid, 3);
	p = &key_descr->KeyData[0];
	(void) memcpy(p, key_data, 16);

	if ((rval = hc_data->set_gtk(dip, key_descr, klen)) !=
	    USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_hc_set_gkt: set gtk failed");
	}

	(void) memcpy(&hc_data->hc_gtk, key_descr, klen);
	kmem_free(key_descr, klen);

	return (rval);
}

/* Set Device Info for WUSB host, refer to WUSB 1.0/8.5.3.7 */
int
wusb_hc_set_device_info(wusb_hc_data_t *hc_data, usb_port_t port)
{
	wusb_dev_info_t		*dev_info;
	int			rval;

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_hc_set_device_info: port = %d", port);

	dev_info = hc_data->hc_dev_infos[port];
	rval = hc_data->set_device_info(hc_data->hc_dip, dev_info, port);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_hc_set_device_info: the host failed to set "
		    "device info, rval = %d", rval);
	}

	return (rval);
}

/*
 * Set/Get Handshake Data to/from WUSB device, refer to WUSB 1.0/7.3.2.5
 * step = 1, 2, 3
 */
int
wusb_handshake(usb_pipe_handle_t pipe, wusb_hndshk_data_t *hs, int step)
{
	usb_ctrl_setup_t	setup;
	mblk_t			*pdata;
	usb_cr_t		cr;
	usb_cb_flags_t		cb_flags;
	int			rval;

	if (step == 2) {
		/* get handshake */
		setup.bmRequestType = USB_DEV_REQ_DEV_TO_HOST;
		setup.bRequest = USB_REQ_GET_HANDSHAKE;
		pdata = NULL;
	} else if ((step == 1) || (step == 3)) {
		/* set handshake */
		setup.bmRequestType = USB_DEV_REQ_HOST_TO_DEV;
		setup.bRequest = USB_REQ_SET_HANDSHAKE;

		if ((pdata = allocb(WUSB_HNDSHK_DATA_LEN, BPRI_HI)) == NULL) {

			return (USB_NO_RESOURCES);
		}
		bcopy(hs, pdata->b_wptr, WUSB_HNDSHK_DATA_LEN);
		pdata->b_wptr += WUSB_HNDSHK_DATA_LEN;
	} else {
		/* step value is invalid */
		return (USB_INVALID_ARGS);
	}

	setup.wValue = (uint16_t)step;
	setup.wIndex = 0;
	setup.wLength = WUSB_HNDSHK_DATA_LEN;
	setup.attrs = USB_ATTRS_NONE;

	rval = usb_pipe_ctrl_xfer_wait(pipe, &setup, &pdata,
	    &cr, &cb_flags, USB_FLAGS_SLEEP);

	if (step == 2) {
		if (pdata) {
			bcopy(pdata->b_rptr, hs, msgsize(pdata));
			freemsg(pdata);
		}
	} else {
		freemsg(pdata);
	}

	return (rval);
}

/* search the security descrs for CCM encryption type descr */
int16_t
wusb_get_ccm_encryption_value(wusb_secrt_data_t *secrt_data)
{
	usb_encryption_descr_t	*encry_descr;
	int			i;
	int16_t			value = -1;

	for (i = 0; i < secrt_data->secrt_n_encry; i++) {
		encry_descr = &secrt_data->secrt_encry_descr[i];
		if (encry_descr->bEncryptionType == USB_ENC_TYPE_CCM_1) {
			value = encry_descr->bEncryptionValue;
			USB_DPRINTF_L3(DPRINT_MASK_WHCDI, whcdi_log_handle,
			    "ccm encryption value is %d", value);

			break;
		}
	}

	return (value);
}

static void
wusb_print_handshake_data(wusb_hndshk_data_t *hs, int step)
{
	uint8_t		*p;

	USB_DPRINTF_L3(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "handshake %d data:", step);
	USB_DPRINTF_L3(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "%x %x (TKID)%x %x %x %x", hs->bMessageNumber, hs->bStatus,
	    hs->tTKID[0], hs->tTKID[1], hs->tTKID[2], hs->bReserved);

	p = hs->CDID;

	USB_DPRINTF_L3(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "(CDID)%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x",
	    p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9],
	    p[10], p[11], p[12], p[13], p[14], p[15]);

	p = hs->Nonce;
	USB_DPRINTF_L3(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "(Nonce)%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x",
	    p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9],
	    p[10], p[11], p[12], p[13], p[14], p[15]);

	p = hs->MIC;
	USB_DPRINTF_L3(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "(MIC)%x %x %x %x %x %x %x %x",
	    p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
}

/* ARGSUSED */
/*
 * Do 4way handshake and other necessary control operations to
 * transit the device to authenticated state
 * refer to WUSB 1.0 [7.3.2.5, 6.2.10.9.1, 7.1.2]
 * ph - pipe handle of the host controller
 */
int
wusb_4way_handshake(wusb_hc_data_t *hc_data, usb_port_t port,
	usb_pipe_handle_t ph, uint8_t ifc)
{
	uint8_t			tkid[3];
	wusb_ccm_nonce_t	n;
	wusb_hndshk_data_t	*hs;
	wusb_dev_info_t		*dev_info;
	wusb_cc_t		*cc;
	uchar_t			adata1[] = "Pair-wise keys";
	uchar_t			adata2[] = "out-of-bandMIC";
	uchar_t			bdata[32], keyout[32], mic[8];
	int			rval;
	usb_pipe_handle_t	w_ph;

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_4way_handshake: port = %d", port);

	mutex_enter(&hc_data->hc_mutex);
	dev_info = hc_data->hc_dev_infos[port];
	if (dev_info == NULL) {
		mutex_exit(&hc_data->hc_mutex);

		return (USB_FAILURE);
	}
	cc = dev_info->wdev_cc;
	if (dev_info->wdev_ph == NULL || cc == NULL) {
		mutex_exit(&hc_data->hc_mutex);

		return (USB_FAILURE);
	}

	w_ph = dev_info->wdev_ph;

	hs = (wusb_hndshk_data_t *)kmem_zalloc(
	    3 * sizeof (wusb_hndshk_data_t), KM_SLEEP);

	/* tkid is generated dynamically and saved in dev_info */
	(void) random_get_pseudo_bytes(tkid, 3);

	(void) memcpy(dev_info->wdev_tkid, tkid, 3);

	/* handshake 1 */
	hs[0].bMessageNumber = 1;
	hs[0].bStatus = 0;
	(void) memcpy(hs[0].tTKID, tkid, 3);
	hs[0].bReserved = 0;
	bcopy(cc->CDID, hs[0].CDID, WUSB_CDID_LEN);

	if ((rval = wusb_gen_random_nonce(hc_data, dev_info, hs[0].Nonce))
	    != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "Nonce generation failed: %d", rval);
		mutex_exit(&hc_data->hc_mutex);

		goto done;
	}

	wusb_print_handshake_data(&hs[0], 1);
	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_4way_handshake: shake 1.............");

	mutex_exit(&hc_data->hc_mutex);
	rval = wusb_handshake(w_ph, &(hs[0]), 1);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "handshake 1 failed, rval = %d", rval);

		goto done;
	}

	/* handshake 2 */
	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_4way_handshake: shake 2.............");
	rval = wusb_handshake(w_ph, &(hs[1]), 2);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "handshake 2 failed, rval = %d", rval);

		goto done;
	}

	if (hs[1].bMessageNumber != 2 || hs[1].bStatus != 0) {
		rval = USB_FAILURE;

		goto done;
	}

	wusb_print_handshake_data(&hs[1], 2);

	/* derived session keys, refer to WUSB 1.0/6.5.1 */
	n.sfn = 0;
	n.tkid = tkid[0] | (tkid[1]<<8) | (tkid[2] << 16);

	mutex_enter(&hc_data->hc_mutex);
	n.daddr = dev_info->wdev_addr;

	n.saddr = hc_data->hc_addr;
	bcopy(hs[0].Nonce, bdata, 16);
	bcopy(hs[1].Nonce, bdata + 16, 16);
	mutex_exit(&hc_data->hc_mutex);

	rval = PRF_256(cc->CK, 16, &n, adata1, 14, bdata, 32, keyout);
	if (rval != 0) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "compute keys failed, rval = %d", rval);

		goto done;
	}

	/* sfn was changed in PRF(). Need to reset it to 0 */
	n.sfn = 0;

	/* used the derived KCK to verify received MIC (WUSB 1.0/6.5.2] */
	rval = PRF_64(keyout, 16, &n, adata2, 14, (uchar_t *)(&hs[1]),
	    WUSB_HNDSHK_DATA_LEN - 8, mic);
	if (rval != 0) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "compute MIC failed, rval = %d", rval);

		goto done;
	}

	if (memcmp(hs[1].MIC, mic, 8) != 0) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "verify mic failed");
		rval = USB_FAILURE;

		goto done;
	}

	/* handshake 3 */
	bcopy(&hs[0], &hs[2], WUSB_HNDSHK_DATA_LEN - 8);
	hs[2].bMessageNumber = 3;
	n.sfn = 0;
	rval = PRF_64(keyout, 16, &n, adata2, 14, (uchar_t *)(&hs[2]),
	    WUSB_HNDSHK_DATA_LEN - 8, hs[2].MIC);
	if (rval != 0) {
		goto done;
	}

	wusb_print_handshake_data(&hs[2], 3);

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_4way_handshake: shake 3.............");
	rval = wusb_handshake(w_ph, &(hs[2]), 3);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "handshake 3 failed, rval = %d", rval);

		goto done;
	}

	mutex_enter(&hc_data->hc_mutex);
	/* set PTK for host */
	(void) memcpy(dev_info->wdev_ptk, keyout + 16, 16);

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_4way_handshake: set ptk .............");
	rval = wusb_hc_set_ptk(hc_data, dev_info->wdev_ptk, port);
	mutex_exit(&hc_data->hc_mutex);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "set ptk for host failed, rval = %d", rval);

		goto done;
	}

	/*
	 * enable CCM encryption on the host
	 * according to WUSB 1.0/7.1.2, the encryption mode must be
	 * enabled before setting GTK onto device
	 */
	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_4way_handshake: hc set encrypt .............");
	rval = wusb_hc_set_encrypt(hc_data, port, WUSB_ENCRYP_TYPE_CCM_1);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "set encryption for host failed, rval = %d", rval);

		goto done;
	}

	/*
	 * set GTK for device
	 * GTK is initialized when hc_data is inited
	 */
	rval = wusb_dev_set_key(w_ph, 2 << 4,
	    &hc_data->hc_gtk, hc_data->hc_gtk.bLength);
done:
	kmem_free(hs, 3 * sizeof (wusb_hndshk_data_t));
	if (rval != USB_SUCCESS) {
		/* restore the host to unsecure mode */
		(void) wusb_hc_set_encrypt(hc_data, port,
		    WUSB_ENCRYP_TYPE_UNSECURE);
	}

	return (rval);
}
