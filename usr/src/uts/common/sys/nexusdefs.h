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

#ifndef	_SYS_NEXUSDEFS_H
#define	_SYS_NEXUSDEFS_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Bus Nexus Control Operations
 */

typedef enum {
	DDI_CTLOPS_DMAPMAPC,
	DDI_CTLOPS_INITCHILD,
	DDI_CTLOPS_UNINITCHILD,
	DDI_CTLOPS_REPORTDEV,
	DDI_CTLOPS_REPORTINT,
	DDI_CTLOPS_REGSIZE,
	DDI_CTLOPS_NREGS,
	DDI_CTLOPS_RESERVED0,	/* Originally DDI_CTLOPS_NINTRS, obsolete */
	DDI_CTLOPS_SIDDEV,
	DDI_CTLOPS_SLAVEONLY,
	DDI_CTLOPS_AFFINITY,
	DDI_CTLOPS_IOMIN,
	DDI_CTLOPS_PTOB,
	DDI_CTLOPS_BTOP,
	DDI_CTLOPS_BTOPR,
	DDI_CTLOPS_RESERVED1,	/* Originally DDI_CTLOPS_POKE_INIT, obsolete */
	DDI_CTLOPS_RESERVED2,	/* Originally DDI_CTLOPS_POKE_FLUSH, obsolete */
	DDI_CTLOPS_RESERVED3,	/* Originally DDI_CTLOPS_POKE_FINI, obsolete */
	DDI_CTLOPS_RESERVED4, /* Originally DDI_CTLOPS_INTR_HILEVEL, obsolete */
	DDI_CTLOPS_RESERVED5, /* Originally DDI_CTLOPS_XLATE_INTRS, obsolete */
	DDI_CTLOPS_DVMAPAGESIZE,
	DDI_CTLOPS_POWER,
	DDI_CTLOPS_ATTACH,
	DDI_CTLOPS_DETACH,
	DDI_CTLOPS_QUIESCE,
	DDI_CTLOPS_UNQUIESCE,
	DDI_CTLOPS_PEEK,
	DDI_CTLOPS_POKE
} ddi_ctl_enum_t;

/*
 * For source compatibility, we define the following obsolete code:
 * Do NOT use this, use the real constant name.
 */
#define	DDI_CTLOPS_REMOVECHILD	DDI_CTLOPS_UNINITCHILD

/*
 * Bus config ops
 */
typedef enum {
	BUS_ENUMERATE = 0,
	BUS_CONFIG_ONE,
	BUS_CONFIG_ALL,
	BUS_CONFIG_AP,
	BUS_CONFIG_DRIVER,
	BUS_UNCONFIG_ONE,
	BUS_UNCONFIG_DRIVER,
	BUS_UNCONFIG_ALL,
	BUS_UNCONFIG_AP,
	BUS_CONFIG_OBP_ARGS
} ddi_bus_config_op_t;

/*
 * Bus Power Operations
 */
typedef enum {
	BUS_POWER_CHILD_PWRCHG = 0,
	BUS_POWER_NEXUS_PWRUP,
	BUS_POWER_PRE_NOTIFICATION,
	BUS_POWER_POST_NOTIFICATION,
	BUS_POWER_HAS_CHANGED,
	BUS_POWER_NOINVOL
} pm_bus_power_op_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NEXUSDEFS_H */
