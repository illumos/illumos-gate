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
 * Copyright (c) 2014 Joyent, Inc.  All rights reserved.
 */


#pragma D depends_on module vnd
#pragma D depends_on provider vnd
#pragma D depends_on library ip.d
#pragma D depends_on library mac.d

#pragma D binding "1.6.3" translator
translator ifinfo_t < vnd_str_t *vsp > {
	if_name = vsp != NULL ? stringof(vsp->vns_dev->vdd_lname) : "<null>";
	if_local = 0;
	if_ipstack = vsp != NULL ? vsp->vns_nsd->vpnd_nsid : 0;
	if_addr = (uintptr_t)vsp;
};
