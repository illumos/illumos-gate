/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Joyent, Inc.  All rights reserved.
 */

/*
 * Decode VXLAN encapsulated packets.
 */

#include <sys/vxlan.h>
#include "snoop.h"

extern interpreter_fn_t interpret_ether;

int
interpret_vxlan(int flags, char *data, int fraglen)
{
	vxlan_hdr_t *vxlan = (vxlan_hdr_t *)data;
	uint32_t id, vxf;

	if (fraglen < sizeof (vxlan_hdr_t)) {
		if (flags & F_SUM)
			(void) snprintf(get_sum_line(), MAXLINE,
			    "VXLAN RUNT");
		if (flags & F_DTAIL)
			show_header("VXLAN RUNT:  ", "Short packet", fraglen);

		return (fraglen);
	}

	id = ntohl(vxlan->vxlan_id) >> VXLAN_ID_SHIFT;
	vxf = ntohl(vxlan->vxlan_flags);

	if (flags & F_SUM) {
		(void) snprintf(get_sum_line(), MAXLINE,
		    "VXLAN VNI=%d", id);
	}

	if (flags & F_DTAIL) {
		show_header("VXLAN:  ", "VXLAN Header", sizeof (vxlan_hdr_t));
		show_space();
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Flags = 0x%08x", vxf);
		(void) snprintf(get_line(0, 0), get_line_remain(), "      %s",
		    getflag(vxf >> 24, VXLAN_F_VDI >> 24, "vni present",
		    "vni missing"));
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "VXLAN network id (VNI) = %d", id);
		show_space();
	}

	if (flags & (F_DTAIL | F_ALLSUM)) {
		fraglen -= sizeof (vxlan_hdr_t);
		data += sizeof (vxlan_hdr_t);

		return (interpret_ether(flags, data, fraglen, fraglen));
	}

	return (0);
}
