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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _IPMI_PLUGIN_H
#define	_IPMI_PLUGIN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * IPMI Plugin definitions
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Controls whether to fire-up a thread to monitor the BMC's state
 * and to update it with cached state information when a BMC reset
 * is detected.
 */
#define	GLOBAL_PROP_IPMI_BMC_MON "ipmi-bmc-monitor-enable"
#define	GLOBAL_PROP_IPMI_ERR_INJ "ipmi-error-inj-rate"

#ifdef __cplusplus
}
#endif

#endif /* _IPMI_PLUGIN_H */
