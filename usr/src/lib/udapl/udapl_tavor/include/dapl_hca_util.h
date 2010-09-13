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
 * HEADER: dapl_hca_util.h
 *
 * PURPOSE: Utility defs & routines for the HCA data structure
 *
 */

#ifndef _DAPL_HCA_UTIL_H_
#define	_DAPL_HCA_UTIL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "dapl.h"

DAPL_HCA *
dapl_hca_alloc(char *name, char	*port);

void
dapl_hca_free(DAPL_HCA	*hca_ptr);

void
dapl_hca_link_ia(
	IN DAPL_HCA	*hca_ptr,
	IN DAPL_IA	*ia_info);

void
dapl_hca_unlink_ia(
	IN DAPL_HCA	*hca_ptr,
	IN DAPL_IA	*ia_info);

#ifdef __cplusplus
}
#endif

#endif /* _DAPL_HCA_UTIL_H_ */
