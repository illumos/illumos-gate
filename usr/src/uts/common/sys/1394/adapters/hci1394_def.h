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

#ifndef _SYS_1394_ADAPTERS_HCI1394_DEF_H
#define	_SYS_1394_ADAPTERS_HCI1394_DEF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * hci1394_def.h
 *    This should be the first file included before any other hci1394
 *    include file.  It should only contain defines which are used by other
 *    hci1394 include files.
 *
 *    The one exception is for the typedef hci1394_state_t.  This is in here
 *    to simplify header organization.
 *
 *    Other than hci1394_state_t, no macros, structures, or prototypes should
 *    be in this file.
 */

#ifdef	__cplusplus
extern "C" {
#endif


/* The maximum number of Isochronous contexts in an OpenHCI adapter */
#define	HCI1394_MAX_ISOCH_CONTEXTS	32

/* hci1394 driver state pointer */
typedef struct hci1394_state_s	hci1394_state_t;


#ifdef __cplusplus
}
#endif

#endif	/* _SYS_1394_ADAPTERS_HCI1394_DEF_H */
