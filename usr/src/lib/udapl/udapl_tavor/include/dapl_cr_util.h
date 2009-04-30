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
 * Copyright (c) 2002-2003, Network Appliance, Inc. All rights reserved.
 */

/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * HEADER: dapl_cr_util.h
 *
 * PURPOSE: Utility defs & routines for the CR data structure
 *
 */

#ifndef _DAPL_CR_UTIL_H_
#define	_DAPL_CR_UTIL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "dapl.h"

DAPL_CR	*
dapls_cr_alloc(
	DAPL_IA		*ia_ptr);

void
dapls_cr_free(
	IN DAPL_CR	*cr_ptr);

void
dapls_cr_callback(
	IN ib_cm_handle_t		ib_cm_handle,
	IN const ib_cm_events_t		ib_cm_event,
	IN const void			*instant_data_p,
	IN const void			*context);

#ifdef __cplusplus
}
#endif

#endif /* _DAPL_CR_UTIL_H_ */
