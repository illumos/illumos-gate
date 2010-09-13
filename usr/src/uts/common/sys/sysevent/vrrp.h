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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_SYSEVENT_VRRP_H
#define	_SYS_SYSEVENT_VRRP_H

/*
 * VRRP sysevent definitions.  Note that all of these definitions are
 * Sun-private and are subject to change at any time.
 */

#ifdef __cplusplus
extern "C" {
#endif


/*
 * Event type EC_VRRP/ESC_VRRP_GROUP_STATE event schema
 *
 *	Event Class     - EC_VRRP
 *	Event Sub-Class - ESC_VRRP_STATE_CHANGE
 *	Event Vendor	- SUNW_VENDOR		(defined in sys/sysevent.h)
 *	Event Publisher - VRRP_EVENT_PUBLISHER	(defined in this file)
 *
 * 	Attribute Name  - VRRP_EVENT_VERSION
 *	Attribute Type  - SE_DATA_TYPE_UINT8
 *	Attribute Value - <version>
 *
 *	Attribute Name  - VRRP_EVENT_ROUTER_NAME
 *	Attribute Type  - SE_DATA_TYPE_STRING
 *	Attribute Value - <router-name>
 *
 *	Attribute Name  - VRRP_EVENT_STATE
 *	Attribute Type  - SE_DATA_TYPE_UINT8
 * 	Attribute Value - <state>
 *
 *	Attribute Name  - VRRP_EVENT_PREV_STATE
 *	Attribute Type  - SE_DATA_TYPE_UINT8
 * 	Attribute Value - <previous-state>
 */

#define	VRRP_EVENT_PUBLISHER	"vrrpd"

#define	VRRP_EVENT_VERSION	"vrrp_event_version"
#define	VRRP_EVENT_ROUTER_NAME	"vrrp_router_name"
#define	VRRP_EVENT_STATE	"vrrp_state"
#define	VRRP_EVENT_PREV_STATE	"vrrp_prev_state"

#define	VRRP_EVENT_CUR_VERSION	1


#ifdef __cplusplus
}
#endif

#endif /* _SYS_SYSEVENT_VRRP_H */
