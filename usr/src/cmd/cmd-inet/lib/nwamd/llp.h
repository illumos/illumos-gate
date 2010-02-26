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

#ifndef _LLP_H
#define	_LLP_H

#include <search.h>
#include <libnwam.h>
#include <syslog.h>

#include "events.h"

/*
 * This file is here for legacy support.
 */

#define	LLPDIR		"/etc/nwam"
#define	LLPFILE		LLPDIR"/llp"

enum interface_type {
    IF_UNKNOWN, IF_WIRED, IF_WIRELESS, IF_TUN
};

typedef enum {
	IPV4SRC_STATIC,
	IPV4SRC_DHCP
} ipv4src_t;

/*
 * This structure contains a representation of legacy LLP configuration
 * which previously represented the intended configuration of the system as
 * differentiated from the actual IPv4 configuration of the system represented
 * by the interface structures.
 *
 * llp structures are held on the list llp_head.
 */
typedef struct llp {
	struct qelem llp_links;
	char	llp_lname[LIFNAMSIZ];
	uint32_t llp_pri;		/* lower number => higher priority */
	int	llp_fileorder;
	enum interface_type llp_type;
	ipv4src_t llp_ipv4src;
	char	*llp_ipv4addrstr;	/* if ipsrc is STATIC */
	char	*llp_ipv6addrstr;	/* if the user provided a static addr */
	boolean_t llp_ipv6onlink;	/* true if we plumb up a v6 interface */
} llp_t;

extern llp_t *link_layer_profile;

void nwamd_handle_upgrade(nwamd_event_t);

#endif /* _LLP_H */
