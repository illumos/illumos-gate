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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _FMEV_CHANNELS_H
#define	_FMEV_CHANNELS_H

/*
 * libfmevent - private GPEC channel names
 *
 * Note: The contents of this file are private to the implementation of
 * libfmevent and are subject to change at any time without notice.
 * This file is not delivered into /usr/include.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Channel that fmd forwards protocol events on, feeding the subscription
 * aspect of libfmevent.
 */
#define	FMD_SNOOP_CHANNEL	"com.sun:fm:protocol_snoop"

/*
 * Channels on which published events are dispatched towards fmd for
 * processing into full protocol events.
 */
#define	FMEV_CHAN_USER_PRIV_HV		"com.sun:fm:user_priv_highval"
#define	FMEV_CHAN_USER_PRIV_LV		"com.sun:fm:user_priv_lowval"
#define	FMEV_CHAN_USER_NOPRIV_HV	"com.sun:fm:user_nopriv_highval"
#define	FMEV_CHAN_USER_NOPRIV_LV	"com.sun:fm:user_nopriv_lowval"
#define	FMEV_CHAN_KERNEL_HV		"com.sun:fm:kernel_highval"
#define	FMEV_CHAN_KERNEL_LV		"com.sun:fm:kernel_lowval"

#ifdef __cplusplus
}
#endif

#endif /* _FMEV_CHANNELS_H */
