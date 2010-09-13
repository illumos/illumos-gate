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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * HEADER: dapl_srq_util.h
 *
 * PURPOSE: Utility defs & routines for the SRQ data structure
 *
 */

#ifndef _DAPL_SRQ_UTIL_H_
#define	_DAPL_SRQ_UTIL_H_

#ifdef __cplusplus
extern "C" {
#endif

extern DAPL_SRQ *
dapl_srq_alloc(IN DAPL_IA *ia_ptr, IN const DAT_SRQ_ATTR *srq_attr);

extern void
dapl_srq_dealloc(IN DAPL_SRQ *srq_ptr);

#ifdef __cplusplus
}
#endif

#endif /* _DAPL_SRQ_UTIL_H_ */
