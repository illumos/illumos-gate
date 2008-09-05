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

#ifndef	_SYS_USB_HCDI_IMPL_H
#define	_SYS_USB_HCDI_IMPL_H


#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Per HCD Data Structures
 */
typedef  struct usba_hcdi {
	dev_info_t		*hcdi_dip;	/* ptr to devinfo struct */

	ddi_dma_attr_t		*hcdi_dma_attr;

	/*
	 * list of HCD operations
	 */
	struct usba_hcdi_ops	*hcdi_ops;

	int			hcdi_flags;	    /* flag options */

	/* soft interrupt support */
	ddi_softint_handle_t	hcdi_softint_hdl;	/* soft intr handle */
	usba_list_entry_t	hcdi_cb_queue;

	/*
	 * min xfer and min/max burstsizes for DDI_CTLOPS_IOMIN
	 */
	uint_t			hcdi_min_xfer;
	uchar_t			hcdi_min_burst_size;
	uchar_t			hcdi_max_burst_size;

	/*
	 * usba_device ptr for root hub
	 */
	usba_device_t		*hcdi_usba_device;

	/*
	 * usb bus address allocation
	 */
	char		hcdi_usb_address_in_use[USBA_ADDRESS_ARRAY_SIZE];

	usb_log_handle_t	hcdi_log_handle;

	kmutex_t		hcdi_mutex;
	ddi_iblock_cookie_t	hcdi_iblock_cookie;
	ddi_iblock_cookie_t	hcdi_soft_iblock_cookie;

	/*
	 * Hotplug event statistics since hcdi loaded.
	 */
	ulong_t			hcdi_total_hotplug_success;
	ulong_t			hcdi_total_hotplug_failure;

	/*
	 * Resetable hotplug event statistics.
	 */
	ulong_t			hcdi_hotplug_success;
	ulong_t			hcdi_hotplug_failure;

	/*
	 * Total number of devices currently enumerated.
	 */
	uchar_t			hcdi_device_count;

	/*
	 * kstat structures
	 */
	kstat_t			*hcdi_hotplug_stats;
	kstat_t			*hcdi_error_stats;

	/*
	 * ugen default binding
	 */
	uint_t			hcdi_ugen_default_binding;
} usba_hcdi_t;

_NOTE(MUTEX_PROTECTS_DATA(usba_hcdi::hcdi_mutex,
				usba_hcdi::hcdi_usb_address_in_use))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_hcdi_t::hcdi_usba_device))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_hcdi_t::hcdi_ugen_default_binding))


/*
 * retrieving the hcdi structure from dip
 */
void usba_hcdi_set_hcdi(dev_info_t *dip, usba_hcdi_t *hcdi);
usba_hcdi_t *usba_hcdi_get_hcdi(dev_info_t *dip);

/* initialize/destroy HCDI info */
void usba_hcdi_initialization();
void usba_hcdi_destroy();

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USB_HCDI_IMPL_H */
