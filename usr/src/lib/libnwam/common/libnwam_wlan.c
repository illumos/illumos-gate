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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "libnwam_impl.h"
#include <libnwam.h>

/*
 * Functions that request WLAN-specific actions (scan, WLAN selection
 * and key setting).
 */

/*
 * Launch scan on specified link linkname.
 */
nwam_error_t
nwam_wlan_scan(const char *linkname)
{
	return (nwam_request_wlan(NWAM_REQUEST_TYPE_WLAN_SCAN, linkname,
	    NULL, NULL, 0, 0, NULL, B_FALSE));
}

/*
 * Get most-recently-cached scan results for link linkname.
 */
nwam_error_t
nwam_wlan_get_scan_results(const char *linkname, uint_t *num_wlansp,
    nwam_wlan_t **wlansp)
{
	return (nwam_request_wlan_scan_results(linkname, num_wlansp,
	    wlansp));
}

/*
 * Select specified WLAN <essid, bssid> for link linkname.
 */
nwam_error_t
nwam_wlan_select(const char *linkname, const char *essid, const char *bssid,
    uint32_t secmode, boolean_t add_to_known_wlans)
{
	return (nwam_request_wlan(NWAM_REQUEST_TYPE_WLAN_SELECT,
	    linkname, essid, bssid, secmode, 0, NULL, add_to_known_wlans));
}

/*
 * Create/update security key for WLAN <essid, bssid>.
 */
nwam_error_t
nwam_wlan_set_key(const char *linkname, const char *essid, const char *bssid,
    uint32_t secmode, uint_t keyslot, const char *key)
{
	return (nwam_request_wlan(NWAM_REQUEST_TYPE_WLAN_SET_KEY,
	    linkname, essid, bssid, secmode, keyslot, key, B_FALSE));
}
