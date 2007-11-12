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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/ethernet.h>
#include <sys/vnet_common.h>

/* convert mac address from string to uint64_t */
uint64_t
vnet_macaddr_strtoul(const uint8_t *macaddr)
{
	uint64_t val = 0;
	int i;

	for (i = 0; i < ETHERADDRL; i++) {
		val <<= 8;
		val |= macaddr[i];
	}

	return (val);
}

/* convert mac address from uint64_t to string */
void
vnet_macaddr_ultostr(uint64_t val, uint8_t *macaddr)
{
	int i;
	uint64_t value;

	value = val;
	for (i = ETHERADDRL - 1; i >= 0; i--) {
		macaddr[i] = value & 0xFF;
		value >>= 8;
	}
}
