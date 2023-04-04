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
 * Copyright 2023 Oxide Computer Company
 */

#ifndef _E1000_ILLUMOS_H
#define	_E1000_ILLUMOS_H

/*
 * illumos-specific e1000 common code pieces.
 */

#include "e1000_hw.h"

#include <sys/mac.h>
#include <sys/mac_ether.h>

#ifdef __cplusplus
extern "C" {
#endif

extern mac_ether_media_t e1000_link_to_media(struct e1000_hw *, uint32_t);

#ifdef __cplusplus
}
#endif

#endif /* _E1000_ILLUMOS_H */
