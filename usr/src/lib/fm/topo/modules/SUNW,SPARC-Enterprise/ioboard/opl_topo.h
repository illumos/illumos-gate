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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _OPL_TOPO_H
#define	_OPL_TOPO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fm/topo_hc.h>
#include <fm/topo_mod.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	PCI_BUS_VERS	1

/*
 * OPL uses the Jupiter Bus Bindings (see FWARC/2005/076) which specifies
 * the hostbridge port id (the part of the bus address before the comma) as
 *	[10:9] = 00
 * 	[8]    = LSB_ID[4] = 0
 *	[7:4]  = LSB_ID[3:0]
 *	[3]    = IO_Channel#[2] = 0
 *	[2:1]  = IO_Channel#[1:0]
 *	[0]    = PCI Leaf Number (0=leaf-A, 1=leaf-B)
 * where the LSB_ID is the logical system board, the IO_Channel is the
 * hostbridge, and the PCI leaf is the root complex. The definitions
 * allow up to 32 system boards, 8 hostbridges per system board, and
 * two root complexes per hostbridge.
 */

/* Common OPL limits */
#define	OPL_IOB_MAX	32	/* Max 32 IOBs per machine */
#define	OPL_HB_MAX	8	/* Max 8 hostbridges per IOB */
#define	OPL_RC_MAX	2	/* Max 2 root complexes per hostbridge */
#define	OPL_BUS_MAX	4	/* Max PCI-Ex buses under root complex */

/* Macros for manipulating px driver bus address. */
#define	OPL_PX_DRV	"px"			/* Oberon driver name */
#define	OPL_PX_STR2BA(s) strtol(s, NULL, 16)	/* Convert ba string to int */
#define	OPL_PX_LSB(a)	(((a) >> 4) & 0x1f)	/* Extract board from ba */
#define	OPL_PX_HB(a)	(((a) >> 1) & 0x07)	/* Extract hb from ba */
#define	OPL_PX_RC(a)	((a) & 0x01)		/* Extract rc from ba */
#define	OPL_SLOT_NAMES	"slot-names"		/* Slot name property */
#define	OPL_PX_DEVTYPE	"pciex"			/* Oberon is PCI-Ex devtype */
#define	OPL_PX_BDF	"0x08"			/* BDF is always 0/1/0 */

/* Macros for manipulating mc-opl driver bus address. */
#define	OPL_MC_DRV	"mc-opl"		/* Driver name */
#define	OPL_MC_STR2BA(s) strtol(s, NULL, 16)	/* Convert ba string to int */
#define	OPL_MC_LSB(a)	(((a) >> 4) & 0x1f)	/* Extract board from ba */
#define	OPL_PHYSICAL_BD	"physical-board#"	/* Physical board for the mc */

/* Structure listing devices on an ioboard */
typedef struct {
	int count;
	di_node_t rcs[OPL_HB_MAX][OPL_RC_MAX];
} ioboard_contents_t;

/* Shared device tree root node */
int opl_hb_enum(topo_mod_t *mp, const ioboard_contents_t *iob,
    tnode_t *parent, int brd);

#ifdef __cplusplus
}
#endif

#endif /* _OPL_TOPO_H */
