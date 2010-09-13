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

#ifndef _SYS_1394_ADAPTERS_HCI1394_DRVINFO_H
#define	_SYS_1394_ADAPTERS_HCI1394_DRVINFO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * hci1394_drvinfo.h
 *     drvinfo contains the core information which is shared amoung the various
 *     different parts of the this driver.  It should be the file that everyone
 *     else includes.
 *
 *     This file should not have any dependencies on any other hci1394 header
 *     files.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/ddi.h>
#include <sys/modctl.h>
#include <sys/sunddi.h>

#include <sys/1394/h1394.h>


/* State of the HAL driver */
typedef enum {
	HCI1394_INITIAL,
	HCI1394_BUS_RESET,
	HCI1394_NORMAL,
	HCI1394_SHUTDOWN
} hci1394_statevar_t;

/* protected state */
typedef struct hci1394_drvstate_s {
	hci1394_statevar_t	ds_state;
	kmutex_t		ds_mutex;
} hci1394_drvstate_t;


/* Driver Statistics */
typedef struct hci1394_stats_s {
	uint_t		st_bus_reset_count;
	uint_t		st_selfid_count;
	uint_t		st_phy_isr;
	uint_t		st_phy_loop_err;
	uint_t		st_phy_pwrfail_err;
	uint_t		st_phy_timeout_err;
	uint_t		st_phy_portevt_err;
} hci1394_stats_t;


/* General Driver Information use in all parts of the driver */
typedef struct hci1394_drvinfo_s {
	dev_info_t		*di_dip;
	void			*di_sl_private;
	int			di_instance;
	uint32_t		di_gencnt;
	hci1394_drvstate_t	di_drvstate;
	hci1394_stats_t		di_stats;
	ddi_iblock_cookie_t	di_iblock_cookie;
	ddi_device_acc_attr_t	di_reg_attr;
	ddi_device_acc_attr_t	di_buf_attr;
} hci1394_drvinfo_t;

_NOTE(SCHEME_PROTECTS_DATA("Single thread modifies", hci1394_drvinfo_s))

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_1394_ADAPTERS_HCI1394_DRVINFO_H */
