/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2019 by Chelsio Communications, Inc.
 */

#ifndef __CUDBG_ENTITY_COMPAT_H__
#define __CUDBG_ENTITY_COMPAT_H__

#include "cudbg_entity.h"

struct cudbg_ulptx_la_rev0 {
	u32 rdptr[CUDBG_NUM_ULPTX];
	u32 wrptr[CUDBG_NUM_ULPTX];
	u32 rddata[CUDBG_NUM_ULPTX];
	u32 rd_data[CUDBG_NUM_ULPTX][CUDBG_NUM_ULPTX_READ];
};

struct struct_meminfo_rev0 {
	struct struct_mem_desc avail[4];
	struct struct_mem_desc mem[ARRAY_SIZE(region) + 3];
	u32 avail_c;
	u32 mem_c;
	u32 up_ram_lo;
	u32 up_ram_hi;
	u32 up_extmem2_lo;
	u32 up_extmem2_hi;
	u32 rx_pages_data[3];
	u32 tx_pages_data[4];
	u32 p_structs;
	struct struct_port_usage port_data[4];
	u32 port_used[4];
	u32 port_alloc[4];
	u32 loopback_used[NCHAN];
	u32 loopback_alloc[NCHAN];
};

int view_ulptx_la_rev0(void *, struct cudbg_buffer *);

#endif
