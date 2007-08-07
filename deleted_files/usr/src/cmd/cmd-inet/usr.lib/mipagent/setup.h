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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SETUP_H
#define	_SETUP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * setup.h : Data structures and prototypes used by a Mobile IP agent
 *          to create data structures.
 */

#ifdef __cplusplus
extern "C" {
#endif


#define	TIME_INFINITY		-1

HaMobileNodeEntry *CreateMobileNodeEntry(boolean_t, ipaddr_t, char *,
    uint32_t, ipaddr_t, uint32_t, char *, uint32_t);
MobilityAgentEntry *CreateMobilityAgentEntry(boolean_t, ipaddr_t, uint32_t,
    uint32_t);
MipSecAssocEntry *CreateSecAssocEntry(boolean_t, uint32_t, int, int, int,
    int, char *, int);
int CreateInterfaceEntry(char *, int, boolean_t, int, int, int, uint16_t, int,
    boolean_t, uint8_t, uint8_t, boolean_t, uint8_t, uint32_t, boolean_t);

#ifdef __cplusplus
}
#endif

#endif /* _SETUP_H */
