/*
* CDDL HEADER START
*
* The contents of this file are subject to the terms of the
* Common Development and Distribution License, v.1,  (the "License").
* You may not use this file except in compliance with the License.
*
* You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
* or http://opensource.org/licenses/CDDL-1.0.
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
* Copyright 2014-2017 Cavium, Inc. 
* The contents of this file are subject to the terms of the Common Development 
* and Distribution License, v.1,  (the "License").

* You may not use this file except in compliance with the License.

* You can obtain a copy of the License at available 
* at http://opensource.org/licenses/CDDL-1.0

* See the License for the specific language governing permissions and 
* limitations under the License.
*/

/****************************************************************************
 *
 * Name:        mfw_hsi.h
 *
 * Description: Global definitions
 *
 ****************************************************************************/

#ifndef MFW_HSI_H
#define MFW_HSI_H

#define MFW_TRACE_SIGNATURE	0x25071946

/* The trace in the buffer */
#define MFW_TRACE_EVENTID_MASK		0x00ffff
#define MFW_TRACE_PRM_SIZE_MASK		0x0f0000
#define MFW_TRACE_PRM_SIZE_SHIFT	16
#define MFW_TRACE_ENTRY_SIZE		3

struct mcp_trace {
	u32	signature;	/* Help to identify that the trace is valid */
	u32	size;		/* the size of the trace buffer in bytes*/
	u32	curr_level;	/* 2 - all will be written to the buffer
				 * 1 - debug trace will not be written
				 * 0 - just errors will be written to the buffer
				 */
	u32	modules_mask[2];/* a bit per module, 1 means write it, 0 means mask it */

	/* Warning: the following pointers are assumed to be 32bits as they are used only in the MFW */
	u32	trace_prod;	/* The next trace will be written to this offset */
	u32	trace_oldest;	/* The oldest valid trace starts at this offset (usually very close after the current producer) */
};

#endif /* MFW_HSI_H */


