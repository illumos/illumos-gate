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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_WRSM_PLUGIN_H
#define	_SYS_WRSM_PLUGIN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types32.h>
#include <sys/rsm/rsm_common.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * the plugin_offset is passed by mmap to the wrsm driver. the driver
 * breaks the offset into pieces to accurately determine the real offset
 * required to map in the page(s) the plugin (librsmwrsm.so) is requesting
 * The following represent valid values for page_type:
 * 0X0 = interrupt INTR page map type (small put)
 * 0x2000 = BARRIER page
 * 0x4000 BARRIER_REGS  - wci_cluster_error_count register and CESR
 * 0x6000 RECONFIG - network->reroutingp and network->route_count to check
 * for configuration changes.
 */

#define	WRSM_PAGESIZE 0x2000 /* 8 k */


#define	WRSM_MMAP_BARRIER_SCRATCH	0x2000
#define	WRSM_MMAP_BARRIER_REGS	0x4000
#define	WRSM_MMAP_RECONFIG	0x6000

/* structure used to pass PUT args between plugin and driver */
typedef struct msg_pluginput_args {
	rsm_memseg_id_t	segment_id;
	caddr_t buf;
	uint64_t len;
	off64_t offset;
	uint64_t remote_cnodeid;
} msg_pluginput_args_t;

typedef struct msg_pluginput_args32 {
	rsm_memseg_id_t segment_id;
	caddr32_t buf;
	uint64_t len;
	off64_t offset;
	uint64_t remote_cnodeid;
} msg_pluginput_args32_t;
/*
 * The plugin (librsmwrsm.so) creates an wrsm_plugin_offset_t to pass to the
 * driver during mmap with the offset arg. The driver breaks down the
 * components of wrsm_plugin_offset_t to determine the real offset of the page
 * requested by the plug-in.
 */

typedef union {
	struct plugin_offset {
		rsm_memseg_id_t segment_id	: 32;	/* 63:32 */
		unsigned char export_cnodeid	: 8;	/* 31:24 */
		uint32_t page_type		: 24;	/* 23:0 */
	} bit;
	off64_t val;
} wrsm_plugin_offset_t;

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_WRSM_PLUGIN_H */
