/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_1394_ADAPTERS_HCI1394_VERSION_H
#define	_SYS_1394_ADAPTERS_HCI1394_VERSION_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * hci1394_vendor.h
 *   These routines provide initialization, cleanup, and general
 *   access to vendor specific features on the OpenHCI adapter.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>


/* Vendor Id's */
#define	VENDOR_VID_SUN_MICROSYSTEMS		0x108E


/* Sun Microsystems Device Id's */
#define	VENDOR_DID_RIO_1394			0x1102

/*
 * we will support up to a maximum of 6 different Vendor Specific register
 * mappings.  I would be surprised to see more than 1, but it is possible.
 */
#define	VENDOR_MAX_REGSETS		6


/* Opaque handle */
typedef struct hci1394_vendor_s	*hci1394_vendor_handle_t;


/*
 * Vendor Specific Info
 *    vendor_id - VendorID from PCI config space (0x0-0x1)
 *    device_id - DeviceID from PCI config space (0x2-0x3)
 *    revision_id - RevisionID from PCI config space (0x8)
 *    ohci_version - 1394 OpenHCI Version Register (0x0)
 *    ohci_vendor_id - 1394 OpenHCI Vendor ID Register (0x40)
 */
typedef struct hci1394_vendor_info_s {
	uint_t		vendor_id;
	uint_t		device_id;
	uint_t		revision_id;
	uint32_t	ohci_version;
	uint32_t	ohci_vendor_id;
	uint_t		vendor_reg_count;
} hci1394_vendor_info_t;


/*
 * structure to store vendor specific register address and handle. We will have
 * one of these for each Vendor Specific register mapping.
 */
typedef struct hci1394_vendor_reg_s {
	caddr_t			vr_reg_addr;
	ddi_acc_handle_t	vr_reg_handle;
} hci1394_vendor_reg_t;


/*
 * structure to track all of the vendor specific register mappings.
 * ve_reg_count is the number of different register mappings. ve_reg_array is
 * an array of these registers. If ve_reg_count = 2, ve_reg_array[0] will have
 * the first register mapping and ve_reg_array[1] will have the second register
 * mapping.
 */
typedef struct hci1394_vendor_s {
	hci1394_ohci_handle_t	ve_ohci;
	uint_t			ve_reg_count;
	hci1394_vendor_reg_t	*ve_reg_array[VENDOR_MAX_REGSETS];
	hci1394_drvinfo_t	*ve_drvinfo;
	hci1394_vendor_info_t	ve_info;
} hci1394_vendor_t;



int hci1394_vendor_init(hci1394_drvinfo_t *drvinfo, hci1394_ohci_handle_t ohci,
    hci1394_vendor_info_t *vendor_info, hci1394_vendor_handle_t *vendor_handle);
void hci1394_vendor_fini(hci1394_vendor_handle_t *vendor_handle);
int hci1394_vendor_resume(hci1394_vendor_handle_t vendor_handle);

int hci1394_vendor_reg_write(hci1394_vendor_handle_t vendor_handle,
    uint_t reg_set, uint_t offset, uint32_t data);
int hci1394_vendor_reg_read(hci1394_vendor_handle_t vendor_handle,
    uint_t reg_set, uint_t offset, uint32_t *data);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_1394_ADAPTERS_HCI1394_VERSION_H */
