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

/*
 * This file include definition of message passed from hook provider
 * to hook consumer.  If necessary, each hook provider can add its
 * own message definition here.
 */

#ifndef _SYS_HOOK_EVENT_H
#define	_SYS_HOOK_EVENT_H

#include <sys/neti.h>
#include <sys/hook.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The hook_pkt_event_t structure is supplied with packet events on
 * associated network interfaces.
 *
 * The members of this structure are defined as follows:
 * hpe_protocol - protocol identifier that indicates which protocol the
 *                header data is associated with.
 * hpe_ifp - "in" interface for packets coming into the system or forwarded
 * hpe_ofp - "out" interface for packets being transmitted or forwarded
 * hpe_hdr - pointer to protocol header within the packet
 * hpe_mp  - pointer to the mblk pointer starting the chain for this packet
 * hpe_mb  - pointer to the mblk that contains hpe_hdr
 */
typedef struct hook_pkt_event {
	net_handle_t		hpe_protocol;
	phy_if_t		hpe_ifp;
	phy_if_t		hpe_ofp;
	void			*hpe_hdr;
	mblk_t			**hpe_mp;
	mblk_t			*hpe_mb;
	int			hpe_flags;
	void			*hpe_reserved[2];
} hook_pkt_event_t;

#define	HPE_MULTICAST	0x01
#define	HPE_BROADCAST	0x02

/*
 * NIC events hook provider
 */
typedef enum nic_event {
	NE_PLUMB = 1,
	NE_UNPLUMB,
	NE_UP,
	NE_DOWN,
	NE_ADDRESS_CHANGE
} nic_event_t;

typedef void *nic_event_data_t;

/*
 * The hook_nic_event data structure is provided with all network interface
 * events.
 *
 * hne_protocol- network protocol for events, returned from net_lookup
 * hne_nic     - physical interface associated with event
 * hne_lif     - logical interface (if any) associated with event
 * hne_event   - type of event occuring
 * hne_data    - pointer to extra data about event or NULL if none
 * hne_datalen - size of data pointed to by hne_data (can be 0)
 */
typedef struct hook_nic_event {
	net_handle_t		hne_protocol;
	phy_if_t		hne_nic;
	lif_if_t		hne_lif;
	nic_event_t		hne_event;
	nic_event_data_t	hne_data;
	size_t			hne_datalen;
} hook_nic_event_t;

/*
 * This structure is used internally by ip to queue events.
 */
struct hook_nic_event_int {
	netstackid_t		hnei_stackid;
	hook_nic_event_t	hnei_event;
};
typedef struct hook_nic_event_int hook_nic_event_int_t;

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_HOOK_EVENT_H */
