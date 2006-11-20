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

#ifndef	_SYS_HOTPLUG_PCI_PCISHPC_REGS_H
#define	_SYS_HOTPLUG_PCI_PCISHPC_REGS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * SHPC controller registers accessed via the SHPC DWORD select and DATA
 * registers in PCI configuration space relative to the SHPC capibility
 * pointer.
 */
#define	SHPC_DWORD_SELECT_OFF		0x2
#define	SHPC_DWORD_DATA_OFF		0x4

#define	SHPC_BASE_OFFSET_REG		0x00
#define	SHPC_SLOTS_AVAIL_I_REG		0x01
#define	SHPC_SLOTS_AVAIL_II_REG		0x02
#define	SHPC_SLOT_CONFIGURATION_REG	0x03
#define	SHPC_PROF_IF_SBCR_REG		0x04
#define	SHPC_COMMAND_STATUS_REG		0x05
#define	SHPC_IRQ_LOCATOR_REG		0x06
#define	SHPC_SERR_LOCATOR_REG		0x07
#define	SHPC_CTRL_SERR_INT_REG		0x08
#define	SHPC_LOGICAL_SLOT_REGS		0x09
#define	SHPC_VENDOR_SPECIFIC		0x28

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_HOTPLUG_PCI_PCISHPC_REGS_H */
