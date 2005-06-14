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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_SYSEVENT_AP_DRIVER_H
#define	_SYS_SYSEVENT_AP_DRIVER_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Event type EC_AP_DRIVER/ESC_AP_DRIVER_PATHSWITCH schema
 *	Event Class	- EC_AP_DRIVER
 *	Event Sub-Class	- ESC_AP_DRIVER_PATHSWITCH
 *	Event Publisher	- SUNW:kern:ap
 *	Attribute Name	- AP_DRIVER_PATHGROUP
 *	Attribute Type  - SE_DATA_TYPE_STRING
 *	Attribute Value	- [pathgroup name, e.g. "sf:0", "mether1", etc.]
 *
 * Event type EC_AP_DRIVER/ESC_AP_DRIVER_COMMIT schema
 *	Event Class	- EC_AP_DRIVER
 *	Event Sub-Class	- ESC_AP_DRIVER_PATHSWITCH
 *	Event Publisher	- SUNW:kern:ap
 *	[no attributes]
 *
 * Event type EC_AP_DRIVER/ESC_AP_DRIVER_PATHSWITCH schema
 *	Event Class	- EC_AP_DRIVER
 *	Event Sub-Class	- ESC_AP_DRIVER_PATHSWITCH
 *	Event Publisher	- SUNW:kern:ap
 *	Attribute Name	- AP_DRIVER_PATHGROUP
 *	Attribute Type  - SE_DATA_TYPE_STRING
 *	Attribute Value	- [pathgroup name, e.g. "msf:0", "mether1", etc.]
 *	Attribute Name	- AP_DRIVER_PHYSICAL
 *	Attribute Type  - SE_DATA_TYPE_STRING
 *	Attribute Value	- [physical path name, e.g. "pln:0", "hme2", etc.]
 */

#define	AP_DRIVER_PATHGROUP	"ap_driver_pathgroup"	/* pathgroup name */
#define	AP_DRIVER_PHYSICAL	"ap_driver_physical"	/* physpath name */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_SYSEVENT_AP_DRIVER_H */
