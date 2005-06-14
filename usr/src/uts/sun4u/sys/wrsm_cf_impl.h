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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _WRSM_CONFIG_IMPL_H
#define	_WRSM_CONFIG_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Definitions private to the config layer of the wrsm driver.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/wrsm_config.h>
#include <sys/wrsm_nc.h>

enum wrsm_cf_state {
	cf_invalid,	/* no such controller yet */
	cf_replaced,	/* REPLACECFG succeeded */
	cf_installed,	/* INSTALCFG succeeded */
	cf_enabled	/* ENABLECFG succeeded */
};

typedef struct wrsm_wci_dev {
	wci_ids_t id;
	struct wrsm_wci_dev *next;
	uint32_t controller_id;
	boolean_t attached;	/* _attach has been called on this WCI */
} wrsm_wci_dev_t;

typedef struct wrsm_controller_dev {
	kmutex_t lock;
	boolean_t in_ioctl;	/* An ioctl is operating on this controller */
	uint32_t controller_id;
	size_t nbytes;		/* size of the conroller configuration data */
	size_t pending_nbytes;	/* size of the pending configuration */
	dev_info_t *devi;
	wrsm_controller_t *controller;
	wrsm_controller_t *pending;
	ncslice_bitmask_t ncslices;	/* ncslices used in config */
	ncslice_bitmask_t pending_ncslices; /* pending config ncslices */
	struct wrsm_controller_dev *next;
	enum wrsm_cf_state state;
} wrsm_controller_dev_t;

void wrsm_cf_free(wrsm_controller_t *cont);


#ifdef __cplusplus
}
#endif

#endif /* _WRSM_CONFIG_IMPL_H */
