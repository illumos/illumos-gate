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

#ifndef XGE_HAL_EVENT_H
#define XGE_HAL_EVENT_H

#include "xge-os-pal.h"

__EXTERN_BEGIN_DECLS

#define XGE_HAL_EVENT_BASE		0
#define XGE_LL_EVENT_BASE		100

/**
 * enum xge_hal_event_e - Enumerates slow-path HAL events.
 * @XGE_HAL_EVENT_UNKNOWN: Unknown (and invalid) event.
 * @XGE_HAL_EVENT_SERR: Serious hardware error event.
 * @XGE_HAL_EVENT_LINK_IS_UP: The link state has changed from 'down' to
 * 'up'; upper-layer driver (typically, link layer) is
 * supposed to wake the queue, etc.
 * @XGE_HAL_EVENT_LINK_IS_DOWN: Link-down event.
 *                    The link state has changed from 'down' to 'up';
 *                    upper-layer driver is supposed to stop traffic, etc.
 * @XGE_HAL_EVENT_ECCERR: ECC error event.
 * @XGE_HAL_EVENT_PARITYERR: Parity error event.
 * @XGE_HAL_EVENT_TARGETABORT: Target abort event. Used when device
 * aborts transmit operation with the corresponding transfer code
 * (for T_CODE enum see xgehal-fifo.h and xgehal-ring.h)
 * @XGE_HAL_EVENT_SLOT_FREEZE: Slot-freeze event. Driver tries to distinguish
 * slot-freeze from the rest critical events (e.g. ECC) when it is
 * impossible to PIO read "through" the bus, i.e. when getting all-foxes.
 *
 * xge_hal_event_e enumerates slow-path HAL eventis.
 *
 * See also: xge_hal_uld_cbs_t{}, xge_uld_link_up_f{},
 * xge_uld_link_down_f{}.
 */
typedef enum xge_hal_event_e {
	XGE_HAL_EVENT_UNKNOWN		= 0,
	/* HAL events */
	XGE_HAL_EVENT_SERR		= XGE_HAL_EVENT_BASE + 1,
	XGE_HAL_EVENT_LINK_IS_UP	= XGE_HAL_EVENT_BASE + 2,
	XGE_HAL_EVENT_LINK_IS_DOWN	= XGE_HAL_EVENT_BASE + 3,
	XGE_HAL_EVENT_ECCERR		= XGE_HAL_EVENT_BASE + 4,
	XGE_HAL_EVENT_PARITYERR		= XGE_HAL_EVENT_BASE + 5,
	XGE_HAL_EVENT_TARGETABORT       = XGE_HAL_EVENT_BASE + 6,
	XGE_HAL_EVENT_SLOT_FREEZE       = XGE_HAL_EVENT_BASE + 7,
} xge_hal_event_e;

__EXTERN_END_DECLS

#endif /* XGE_HAL_EVENT_H */
