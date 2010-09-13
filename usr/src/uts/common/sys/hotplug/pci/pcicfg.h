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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_HOTPLUG_PCI_PCICFG_H
#define	_SYS_HOTPLUG_PCI_PCICFG_H

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum pcicfg_flags {
	/* No probing; used in case of virtual hotplug */
	PCICFG_FLAG_READ_ONLY = 0x1,
	/* Enable ARI; used in case of boot case */
	PCICFG_FLAG_ENABLE_ARI = 0x2
} pcicfg_flags_t;

/*
 * Interfaces exported by PCI configurator module, kernel/misc/pcicfg.
 */
int pcicfg_configure(dev_info_t *, uint_t, uint_t, pcicfg_flags_t);
int pcicfg_unconfigure(dev_info_t *, uint_t, uint_t, pcicfg_flags_t);

#define	PCICFG_SUCCESS DDI_SUCCESS
#define	PCICFG_FAILURE DDI_FAILURE

#define	PCICFG_ALL_FUNC 0xffffffff

/*
 * The following subclass definition for Non Transparent bridge should
 * be moved to pci.h.
 */
#define	PCI_BRIDGE_STBRIDGE	0x9

#define	PCICFG_CONF_INDIRECT_MAP	1
#define	PCICFG_CONF_DIRECT_MAP		0

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_HOTPLUG_PCI_PCICFG_H */
