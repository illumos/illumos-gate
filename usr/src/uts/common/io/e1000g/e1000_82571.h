/*
 * This file is provided under a CDDLv1 license.  When using or
 * redistributing this file, you may do so under this license.
 * In redistributing this file this license must be included
 * and no other modification of this header file is permitted.
 *
 * CDDL LICENSE SUMMARY
 *
 * Copyright(c) 1999 - 2008 Intel Corporation. All rights reserved.
 *
 * The contents of this file are subject to the terms of Version
 * 1.0 of the Common Development and Distribution License (the "License").
 *
 * You should have received a copy of the License with this software.
 * You can obtain a copy of the License at
 *	http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms of the CDDLv1.
 */

/*
 * IntelVersion: 1.12 v2008-02-29
 */
#ifndef _E1000_82571_H_
#define	_E1000_82571_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#define	ID_LED_RESERVED_F746	0xF746
#define	ID_LED_DEFAULT_82573	((ID_LED_DEF1_DEF2 << 12) | \
				(ID_LED_OFF1_ON2  <<  8) | \
				(ID_LED_DEF1_DEF2 <<  4) | \
				(ID_LED_DEF1_DEF2))

#define	E1000_GCR_L1_ACT_WITHOUT_L0S_RX	0x08000000

#ifdef __cplusplus
}
#endif

#endif	/* _E1000_82571_H_ */
