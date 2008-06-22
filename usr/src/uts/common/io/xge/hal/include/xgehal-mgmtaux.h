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
 *
 * Copyright (c) 2002-2006 Neterion, Inc.
 */

#ifndef XGE_HAL_MGMTAUX_H
#define XGE_HAL_MGMTAUX_H

#include "xgehal-mgmt.h"

__EXTERN_BEGIN_DECLS

#define XGE_HAL_AUX_SEPA		' '

xge_hal_status_e xge_hal_aux_about_read(xge_hal_device_h devh,
    int bufsize, char *retbuf, int *retsize);

xge_hal_status_e xge_hal_aux_stats_tmac_read(xge_hal_device_h devh,
    int	bufsize, char *retbuf, int *retsize);

xge_hal_status_e xge_hal_aux_stats_rmac_read(xge_hal_device_h devh,
    int	bufsize, char *retbuf, int *retsize);

xge_hal_status_e xge_hal_aux_stats_sw_dev_read(xge_hal_device_h devh,
    int bufsize, char *retbuf, int *retsize);

xge_hal_status_e xge_hal_aux_stats_pci_read(xge_hal_device_h devh,
    int bufsize, char *retbuf, int *retsize);

xge_hal_status_e xge_hal_aux_stats_hal_read(xge_hal_device_h devh,
    int bufsize, char *retbuf, int *retsize);

xge_hal_status_e xge_hal_aux_bar0_read(xge_hal_device_h	devh,
			unsigned int offset, int bufsize, char *retbuf, int *retsize);

xge_hal_status_e xge_hal_aux_bar0_write(xge_hal_device_h devh,
			unsigned int offset, u64 value);

xge_hal_status_e xge_hal_aux_bar1_read(xge_hal_device_h devh,
			unsigned int offset, int bufsize, char *retbuf, int *retsize);

xge_hal_status_e xge_hal_aux_pci_config_read(xge_hal_device_h devh,
    int	bufsize, char *retbuf, int *retsize);

xge_hal_status_e xge_hal_aux_stats_herc_enchanced(xge_hal_device_h devh,
			int bufsize, char *retbuf, int *retsize);

xge_hal_status_e xge_hal_aux_channel_read(xge_hal_device_h devh,
    int bufsize, char *retbuf, int *retsize);

xge_hal_status_e xge_hal_aux_device_dump(xge_hal_device_h devh);


xge_hal_status_e xge_hal_aux_driver_config_read(
    int bufsize, char *retbuf, int *retsize);

xge_hal_status_e xge_hal_aux_device_config_read(xge_hal_device_h devh,
    int bufsize, char *retbuf, int *retsize);

__EXTERN_END_DECLS

#endif /* XGE_HAL_MGMTAUX_H */
