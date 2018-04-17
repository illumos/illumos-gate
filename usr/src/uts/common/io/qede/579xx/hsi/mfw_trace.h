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

/* To use this file, please define the following macros:
 * MFWT_ALLOC(size)	- allocate memory for array
 * MFWT_FREE(void *)	- free memory
 * MFWT_STRNCPY(d,s,n)	- copy string up to size n
 * MFWT_ERROR(fmt, ...)	- error print
 * MFWT_TRACE(fmt, ...)	- debug trace
 * ENOMEM 		- return value for: Out of memory
 * EINVAL 		- return value for: Invalid argument
 */
#ifndef MFW_TRACE_H
#define MFW_TRACE_H

#include "mfw_hsi.h"

struct mfw_trace_fmt;

struct mfw_trace_meta {
	unsigned int		modules_num;
	char			**modules;
	unsigned int		fmts_num;
	struct mfw_trace_fmt	*fmts;
};

/**
 * @brief mfw_trace_load_meta_data - load the meta data into memory
 *
 * This function allocates memory for all the formats. The
 * mfw_trace_free_meta_data should be called to release this memory.
 *
 * @param input_str	- the content of the meta data
 * @param p_meta	- the output struct that will contain all the allocated
 *      		  memory for the fromats
 *
 * @status		- 0 on success
 */
u32 mfw_trace_load_meta_data(const char			*input_str,
			      struct mfw_trace_meta	*p_meta);

/**
 * @brief mfw_trace_free_meta_data - releases all the allocated memory
 *
 * This function releases the memory allocated by mfw_trace_load_meta_data.
 *
 * @param p_meta
 */
void mfw_trace_free_meta_data(struct mfw_trace_meta	*p_meta);

/**
 * @brief mfw_trace_parse_trace - releases all the allocated memory
 *
 * This function releases the memory allocated by mfw_trace_load_meta_data.
 *
 * @param trace_buffer	- the buffer read from the chip
 * @param p_meta	- the parsed meta data
 * @param p_print	- the function used to print the parsed trace
 *
 * @status		- 0 on success
 */
typedef int (*output_printf) (const char *fmt, ...);
u32 mfw_trace_parse_trace(struct mcp_trace	*p_trace,
			  struct mfw_trace_meta	*p_meta,
			  output_printf		p_print);

#endif /* MFW_TRACE_H */
