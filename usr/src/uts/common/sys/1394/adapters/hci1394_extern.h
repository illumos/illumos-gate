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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_1394_ADAPTERS_HCI1394_EXTERN_H
#define	_SYS_1394_ADAPTERS_HCI1394_EXTERN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * hci1394_extern.h
 *    Provides common location for extern definitions
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/1394/h1394.h>
#include <sys/1394/adapters/hci1394.h>

/* see hci1394.c for this externally referenced variable */
extern void		*hci1394_statep;

/* see hci1394_s1394if.c for this externally referenced variable */
extern h1394_evts_t	hci1394_evts;

/*
 * See hci1394_extern.c for a description of these externally referenced
 * variables
 */
extern uint32_t		hci1394_split_timeout;
extern h1394_addr_map_t	hci1394_addr_map[];
extern uint_t		hci1394_phy_delay_uS;
extern uint_t		hci1394_phy_stabilization_delay_uS;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_1394_ADAPTERS_HCI1394_EXTERN_H */
