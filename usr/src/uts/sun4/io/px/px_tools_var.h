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

#ifndef _SYS_PX_TOOLS_VAR_H
#define	_SYS_PX_TOOLS_VAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This file contains definitions shared between the platform specific
 * px_tools_4[u/v].c files and px_tools.c
 */

/*
 * Build device address based on base addr from range prop, and
 * bus, dev and func values passed in.
 */
#define	PX_GET_BDF(p_p)				\
	(((p_p)->bus_no << PCI_REG_BUS_SHIFT) +	\
	((p_p)->dev_no << PCI_REG_DEV_SHIFT) +	\
	((p_p)->func_no << PCI_REG_FUNC_SHIFT))

/*
 * PX hardware shifts bus / dev / function bits 4 to the left of their
 * normal PCI placement.
 */
#define	PX_PCI_BDF_OFFSET_DELTA	4

#define	PCI_BAR_OFFSET(x)	(pci_bars[x.barnum])

#define	PX_ISWRITE		B_TRUE
#define	PX_ISREAD		B_FALSE

#define	SUCCESS	0

/* Exported from px_tools.c */

extern uint8_t pci_bars[];
extern int pci_num_bars;

/* pxtool internal platform spec stuff exported by px_tools_4[u/v].c files */

extern int pxtool_num_inos;

int pxtool_pcicfg_access(px_t *px_p, pcitool_reg_t *prg_p,
    uint64_t *data_p, boolean_t is_write);
int pxtool_pciiomem_access(px_t *px_p, pcitool_reg_t *prg_p,
    uint64_t *data_p, boolean_t is_write);
int pxtool_dev_reg_ops_platchk(dev_info_t *dip, pcitool_reg_t *prg_p);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PX_TOOLS_VAR_H */
