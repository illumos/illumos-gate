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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _LIBWLADM_IMPL_H
#define	_LIBWLADM_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <inet/wifi_ioctl.h>

/*
 * Implementation-private data structures, macros, and constants.
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Map a signal value from 0-15 into an enumerated strength.  Since there are
 * 5 strengths but 16 values, by convention the "middle" strength gets the
 * extra value.  Thus, the buckets are 0-2, 3-5, 6-9, 10-12, and 13-15.
 */
#define	WLADM_SIGNAL2STRENGTH(signal)				\
	    (((signal) > 12 ? WLADM_STRENGTH_EXCELLENT :	\
	    ((signal) > 9 ? WLADM_STRENGTH_VERY_GOOD : 		\
	    ((signal) > 5 ? WLADM_STRENGTH_GOOD :		\
	    ((signal) > 2 ? WLADM_STRENGTH_WEAK : WLADM_STRENGTH_VERY_WEAK)))))

/*
 * Convert between an OFDM MHz and a channel number.
 */
#define	WLADM_OFDM2CHAN(mhz)		(((mhz) - 5000) / 5)

#define	WLADM_CONNECT_POLLRATE		200 /* milliseconds */
#define	WLADM_CONNECT_DEFAULT_CHANNEL	1

#define	WLADM_MAX_RATES	4
typedef	struct wladm_rates {
	uint8_t		wr_rates[WLADM_MAX_RATES];
	int		wr_cnt;
} wladm_rates_t;

typedef enum {
	WLADM_RADIO_ON = 1,
	WLADM_RADIO_OFF
} wladm_radio_t;

typedef	enum {
	WLADM_PM_OFF = 1,
	WLADM_PM_MAX,
	WLADM_PM_FAST
} wladm_powermode_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBWLADM_IMPL_H */
