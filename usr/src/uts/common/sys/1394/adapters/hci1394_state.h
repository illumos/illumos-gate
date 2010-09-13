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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_1394_ADAPTERS_HCI1394_STATE_H
#define	_SYS_1394_ADAPTERS_HCI1394_STATE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * hci1394_state.h
 *    The hci1394 driver soft state structure.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/ddi.h>
#include <sys/modctl.h>
#include <sys/sunddi.h>
#include <sys/types.h>
#include <sys/note.h>

#include <sys/1394/h1394.h>

#include <sys/1394/adapters/hci1394_drvinfo.h>
#include <sys/1394/adapters/hci1394_vendor.h>
#include <sys/1394/adapters/hci1394_ohci.h>
#include <sys/1394/adapters/hci1394_csr.h>
#include <sys/1394/adapters/hci1394_async.h>
#include <sys/1394/adapters/hci1394_isoch.h>


/*
 * hci1394 state structure
 *    put all handles and pointers at the top so it is easier to find things
 *    when debugging
 */
struct hci1394_state_s {
	/* various module handles */
	hci1394_ohci_handle_t	ohci;	/* see hci1394_ohci.h */
	hci1394_async_handle_t	async;	/* see hci1394_async.h */
	hci1394_vendor_handle_t	vendor;	/* see hci1394_vendor.h */
	hci1394_csr_handle_t	csr;	/* see hci1394_csr.h */
	hci1394_isoch_handle_t	isoch;	/* see hci1394_isoch.h */

	/*
	 * This is the address of the buffer we are to copy the selfid info
	 * into. The Services layer will give us this during the Bus Reset
	 * interrupt and we will copy it into the buffer during the selfid
	 * complete interrupt.
	 */
	uint32_t		*sl_selfid_buf;

	/*
	 * drvinfo contains the core information which is shared among the
	 * various different parts of the this driver. (e.g. dip, instance,
	 * statistics, iblock_cookie, etc.)
	 */
	hci1394_drvinfo_t	drvinfo; /* see hci1394_drvinfo.h */

	/* Vendor Information about this adapter */
	hci1394_vendor_info_t	vendor_info; /* see hci1394_vendor.h */

	/* attach stuff */
	ddi_acc_handle_t	pci_config;
	boolean_t		swap_data;

	/* Adapter info passed up to the Services Layer */
	h1394_halinfo_t		halinfo; /* see h1394.h */
};

_NOTE(SCHEME_PROTECTS_DATA("Single thread modifies", \
	hci1394_state_s::drvinfo.di_gencnt \
	hci1394_state_s::drvinfo.di_stats.st_bus_reset_count \
	hci1394_state_s::drvinfo.di_stats.st_selfid_count))

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_1394_ADAPTERS_HCI1394_STATE_H */
