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
 * IntelVersion: 1.6 v2008-02-29
 */
#ifndef _E1000_82543_H_
#define	_E1000_82543_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#define	PHY_PREAMBLE		0xFFFFFFFF
#define	PHY_PREAMBLE_SIZE	32
#define	PHY_SOF			0x1
#define	PHY_OP_READ		0x2
#define	PHY_OP_WRITE		0x1
#define	PHY_TURNAROUND		0x2

#define	TBI_COMPAT_ENABLED	0x1	/* Global "knob" for the workaround */
/* If TBI_COMPAT_ENABLED, then this is the current state (on/off) */
#define	TBI_SBP_ENABLED		0x2

#ifdef __cplusplus
}
#endif

#endif	/* _E1000_82543_H_ */
