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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_HOTPLUG_PCI_PCIHP_IMPL_H
#define	_SYS_HOTPLUG_PCI_PCIHP_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * we recognize the non transparent bridge child nodes with the
 * following property. This is specific to an implementation only.
 * This property is specific to AP nodes only.
 */
#define	PCI_DEV_CONF_MAP_PROP	"pci-parent-indirect"

/*
 * If a bridge device provides its own config space access services,
 * and supports a hotplug/hotswap bus below at any level, then
 * the following property must be defined for the node either by
 * the driver or the OBP.
 */
#define	PCI_BUS_CONF_MAP_PROP	"pci-conf-indirect"

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_HOTPLUG_PCI_PCIHP_IMPL_H */
