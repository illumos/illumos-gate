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

#include "cudbg_view_compat.h"
#include "cudbg.h"

int
view_ulptx_la_rev0(void *data, struct cudbg_buffer *cudbg_poutbuf)
{
	struct cudbg_ulptx_la_rev0 *ulptx_la_buff;
	int i, j, rc = 0; 

	ulptx_la_buff = (struct cudbg_ulptx_la_rev0 *)data;
	
	for (i = 0; i < CUDBG_NUM_ULPTX; i++) {
		printf("==============================\n");
		printf("DUMPING ULP_TX_LA_%d\n", i);
		printf("==============================\n");

		printf("[0x%x] %-24s %#x\n",
			     (A_ULP_TX_LA_RDPTR_0 + 0x10 * i),
			     cudbg_ulptx_rdptr[i], ulptx_la_buff->rdptr[i]);
		printf("[0x%x] %-24s %#x\n",
			     (A_ULP_TX_LA_WRPTR_0 + 0x10 * i),
			     cudbg_ulptx_wrptr[i], ulptx_la_buff->wrptr[i]);
		printf("[0x%x] %-24s %#-13x\n",
			     (A_ULP_TX_LA_RDDATA_0 + 0x10 * i),
			     cudbg_ulptx_rddata[i], ulptx_la_buff->rddata[i]);

		for (j = 0; j < CUDBG_NUM_ULPTX_READ; j++) {
			printf("[%#x]   %#-16x [%u]\n",
				     j, ulptx_la_buff->rd_data[i][j],
				     ulptx_la_buff->rd_data[i][j]);
		}
	}

	return rc;
}
