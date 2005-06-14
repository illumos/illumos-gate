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

#ifndef _WRSM_PLAT_IMPL_H
#define	_WRSM_PLAT_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Private definitions for the wrsm_plat module
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/wrsm_plat.h>

/* LC to SC message types */
/* (message codes defined in firmware - do not change) */

#define	UPLINK		0x3000	/* Request that a link be brought up */
#define	DOWNLINK 	0x3001	/* Request that a link be brought down */
#define	LINKDATA	0x3002	/* Get discovery data for specified link */
#define	NCSLICE		0x3003 	/* Request allocation of NC slices */
#define	SETLEDSTATE	0x3004 	/* Set the LED to specified state */
#define	SETSEPROM	0x3005 	/* Set SEPROM with error message */

/* Asynchronous SC to LC message types */
#define	LINKISUP	0x000e	/* Link has come up */

/*
 * During UPLINK request LC fills this in with local data.  During
 * LINKDATA request, SC fills this in with data from the remote node.
 */
typedef struct wrsm_uplink_data {
	uint64_t partition_version;
	uint32_t partition_id;
	uint32_t fmnodeid;
	uint32_t gnid;
} wrsm_uplink_data_t;
/*
 * In the comments below, a request is any message from the kernel to
 * the SC and a response is any message from the SC to the kernel.
 */

/* Message body for UPLINK and LINKDATA request/response  */
typedef struct wrsm_uplink_msg {
	wrsm_uplink_data_t config_data;
	uint32_t wci_port_id;
	uint32_t link_num;
	uint32_t status;
} wrsm_uplink_msg_t;

/*
 * A synchronous response message from the SC acknowledging a message.  The
 * format of the message body is defined by the wrsm_status_msg_t structure.
 * A status of 0 indicates the SC was able to process the message as expected.
 * NOTE: not used on a serengeti platform, errors are reported using the
 * provided mechanism of returing an error code from the mailbox function call
 */
typedef struct wrsm_status_msg {
	uint32_t status;
} wrsm_status_msg_t;

/*
 * Message body used for DOWNLINK request
 */
typedef struct wrsm_link_msg {
	uint32_t wci_port_id;
	uint32_t link_num;
} wrsm_link_msg_t;

/* Message body used for NCSLICE request/response */
typedef struct wrsm_ncslice_claim_msg {
	uint32_t status;
	ncslice_bitmask_t requested_ncslices;
} wrsm_ncslice_claim_msg_t;

/* Message body used for SETLEDSTATE request/response */
typedef struct wrsm_link_led_msg {
	uint32_t wci_port_id;
	uint32_t link_num;
	uint32_t led_state;
} wrsm_link_led_msg_t;

/* Message body used for SETSEPROM request */
typedef struct wrsm_wib_seprom_msg {
	uint32_t wci_port_id;
	uchar_t seprom_data[WIB_SEPROM_MSG_SIZE];
} wrsm_wib_seprom_msg_t;

/*
 * A synchronous response message from the SC acknowledges the message.  The
 * format of the message body is defined by the wrsm_status_msg_t structure
 * (above).  A status of 0 indicates the SC was able to process the message as
 * expected.
 */

/*
 * This message is sent by the SC to the wrmsplat module when link activation
 * is complete.  This message is only sent in response to an UPLINK message.
 * The format of the message body is defined by the wrsm_linkisup_msg_t
 * structure.  The async_msg_type field is set to 1, and the link_info
 * structure is filled in with the wci portid and link number of the link on
 * which activiation is complete.
 */

typedef struct wrsm_linkisup_msg {
	uint32_t async_msg_type;
	wrsm_link_msg_t link_info;
} wrsm_linkisup_msg_t;

#ifdef __cplusplus
}
#endif

#endif /* _WRSM_PLAT_IMPL_H */
