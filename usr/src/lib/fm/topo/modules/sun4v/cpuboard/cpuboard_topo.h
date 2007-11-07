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

#ifndef _CPUBOARD_TOPO_H
#define	_CPUBOARD_TOPO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fm/topo_hc.h>
#include <fm/topo_mod.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	PCI_BUS_VERS    1

#define	CPUBOARD_PX_DEVTYPE	"pciex"		/* T5440 is PCI-Ex devtype */
#define	CPUBOARD_PX_DRV  	"px"

#define	CPUBOARD_MAX		4		/* Max 4 cpuboards */
#define	CHIP_MAX		CPUBOARD_MAX	/* Max 4 chips */
#define	HOSTBRIDGE_MAX		CPUBOARD_MAX	/* Max 4 hostbridges */

#define	CPUBOARD_PX_BDF		"0x200"		/* BDF is always 2/0/0 */

/* cpuboard info */
typedef struct {
	int present;		/* cpuboard present */
	char *sn;		/* cpuboard serial # */
	char *pn;		/* cpuboard part # + dash # */
} cpuboard_contents_t;

/* Shared device tree root node */
int cpuboard_hb_enum(topo_mod_t *mp, di_node_t dnode, tnode_t *cpubn, int brd);

/* Until future PRI changes, make connection between cpuboard id and RC */
#define	CPUBOARD0_RC	"/pci@400"
#define	CPUBOARD1_RC	"/pci@500"
#define	CPUBOARD2_RC	"/pci@600"
#define	CPUBOARD3_RC	"/pci@700"

#ifdef __cplusplus
}
#endif

#endif /* _CPUBOARD_TOPO_H */
