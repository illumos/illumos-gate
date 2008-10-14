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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SPCS_S_H
#define	_SPCS_S_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 *	SPCS Uniform status handling public definitions
 *	@author Soper
 *	@version PROTOTYPE
 */




/*
 *	Function returned normally, no status info available (== 0)
 */
#define	SPCS_S_OK 0

/*
 *	Function returned abnormally, status info available (== -1)
 */
#define	SPCS_S_ERROR -1

/*
 *	The maximum status line character array length (== 1024)
 *	@see spcs_s_string
 */
#define	SPCS_S_MAXLINE	1024

/*
 *	The maximum number of "%s" format descriptors in status message
 *	text and data parameters that can be passed along with status
 *	@see spcs_s_string
 */
#define	SPCS_S_MAXSUPP	8

/*
 *	The opaque status information type
 */
typedef uintptr_t spcs_s_info_t;

/*
 *	The status information type as a 32 bit entity for model conversions
 */
typedef uint32_t spcs_s_info32_t;

/*
 *	The type of bytestream data (see spcs_s_add_bytestream() )
 */
typedef uchar_t *spcs_s_bytestream_ptr_t;

/*
 *	The type of a status code
 */
typedef int spcs_s_status_t;

#ifdef __cplusplus
}
#endif

#endif /* _SPCS_S_H */
