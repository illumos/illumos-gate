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

#ifndef	_SYS_USB_HWAHC_UTIL_H
#define	_SYS_USB_HWAHC_UTIL_H

#ifdef	__cplusplus
extern "C" {
#endif

usba_hcdi_ops_t *hwahc_alloc_hcdi_ops(hwahc_state_t *hwahcp);
int	hwahc_start_result_thread(hwahc_state_t *hwahcp);
int	hwahc_set_encrypt(dev_info_t *, usb_port_t, uint8_t type);
int	hwahc_set_ptk(dev_info_t *, usb_key_descr_t *, size_t, usb_port_t);
int	hwahc_set_gtk(dev_info_t *, usb_key_descr_t *, size_t);
int	hwahc_set_device_info(dev_info_t *, wusb_dev_info_t *, usb_port_t);
int	hwahc_set_cluster_id(dev_info_t *, uint8_t);
int	hwahc_set_stream_idx(dev_info_t *, uint8_t);
int	hwahc_set_wusb_mas(dev_info_t *, uint8_t *);
int	hwahc_add_mmc_ie(dev_info_t *dip, uint8_t interval, uint8_t rcnt,
		uint8_t iehdl, uint16_t len, uint8_t *data);
int	hwahc_remove_mmc_ie(dev_info_t *dip, uint8_t iehdl);
int	hwahc_stop_ch(dev_info_t *dip, uint32_t time);
int	hwahc_set_num_dnts(dev_info_t *dip, uint8_t interval, uint8_t nslot);
int	hwahc_get_time(dev_info_t *dip, uint8_t time_type, uint16_t len,
	    uint32_t *time);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_USB_HWAHC_UTIL_H */
