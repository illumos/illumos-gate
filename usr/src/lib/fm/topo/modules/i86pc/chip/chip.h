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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _CHIP_H
#define	_CHIP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <kstat.h>
#include <libnvpair.h>
#include <fm/libtopo.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	CHIP_VERSION		TOPO_VERSION

#define	MC_NODE_NAME	"memory-controller"
#define	CPU_NODE_NAME	"cpu"
#define	CS_NODE_NAME	"chip-select"
#define	DIMM_NODE_NAME	"dimm"

#define	CHIP_PGROUP	"chip-properties"
#define	CS_PGROUP	"chip-select-properties"
#define	MC_PGROUP	"memory-contoller-properties"
#define	DIMM_PGROUP	"dimm-properties"

/*
 * CHIP_PGROUP properties
 */
#define	CHIP_VENDOR_ID	"vendor-id"
#define	CHIP_FAMILY	"family"
#define	CHIP_MODEL	"model"
#define	CHIP_STEPPING	"stepping"

typedef struct chip {
	kstat_ctl_t *chip_kc;
	kstat_t **chip_cpustats;
	uint_t chip_ncpustats;
} chip_t;

#ifdef __cplusplus
}
#endif

#endif /* _CHIP_H */
