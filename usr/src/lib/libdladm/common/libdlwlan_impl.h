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

#ifndef _LIBDLWLAN_IMPL_H
#define	_LIBDLWLAN_IMPL_H

#include <sys/types.h>
#include <inet/wifi_ioctl.h>
#include <sys/mac.h>

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
#define	DLADM_WLAN_SIGNAL2STRENGTH(signal)			\
	    (((signal) > 12 ? DLADM_WLAN_STRENGTH_EXCELLENT :	\
	    ((signal) > 9 ? DLADM_WLAN_STRENGTH_VERY_GOOD : 	\
	    ((signal) > 5 ? DLADM_WLAN_STRENGTH_GOOD :		\
	    ((signal) > 2 ? DLADM_WLAN_STRENGTH_WEAK :		\
	    DLADM_WLAN_STRENGTH_VERY_WEAK)))))

/*
 * Convert between an OFDM MHz and a channel number.
 */
#define	DLADM_WLAN_OFDM2CHAN(mhz)		(((mhz) - 5000) / 5)

#define	DLADM_WLAN_CONNECT_POLLRATE		200 /* milliseconds */

#define	DLADM_WLAN_MAX_RATES	4
typedef struct dladm_wlan_rates {
	uint8_t		wr_rates[DLADM_WLAN_MAX_RATES];
	int		wr_cnt;
} dladm_wlan_rates_t;

typedef enum {
	DLADM_WLAN_RADIO_ON = 1,
	DLADM_WLAN_RADIO_OFF
} dladm_wlan_radio_t;

typedef enum {
	DLADM_WLAN_PM_OFF = 1,
	DLADM_WLAN_PM_MAX,
	DLADM_WLAN_PM_FAST
} dladm_wlan_powermode_t;

extern	dladm_status_t i_dladm_wlan_legacy_ioctl(dladm_handle_t,
			    datalink_id_t, wldp_t *, uint_t, size_t, uint_t,
			    size_t);
extern dladm_status_t	i_dladm_wlan_param(dladm_handle_t, datalink_id_t,
			    void *, mac_prop_id_t, size_t, boolean_t);
extern boolean_t	i_dladm_wlan_convert_chan(wl_phy_conf_t *, uint32_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBDLWLAN_IMPL_H */
