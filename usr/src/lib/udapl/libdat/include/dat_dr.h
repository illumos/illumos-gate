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
 * Copyright (c) 2002-2003, Network Appliance, Inc. All rights reserved.
 */

/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * HEADER: dat_dr.h
 *
 * PURPOSE: dynamic registry interface declarations
 *
 * $Id: dat_dr.h,v 1.7 2003/07/31 14:04:19 jlentini Exp $
 */

#ifndef __DAT_DR_H__
#define	__DAT_DR_H__

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <dat/udat.h>
#include <dat/dat_registry.h>

#include <dat_osd.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 *
 * Strucutres
 *
 */

typedef struct
{
    DAT_COUNT 			ref_count;
    DAT_IA_OPEN_FUNC 		ia_open_func;
    DAT_PROVIDER_INFO 		info;
} DAT_DR_ENTRY;


/*
 *
 * Function Declarations
 *
 */

extern DAT_RETURN
dat_dr_init(void);

extern DAT_RETURN
dat_dr_fini(void);

extern DAT_RETURN
dat_dr_insert(
    IN  const DAT_PROVIDER_INFO *info,
    IN  DAT_DR_ENTRY 		*entry);

extern DAT_RETURN
dat_dr_remove(
    IN  const DAT_PROVIDER_INFO *info);


extern DAT_RETURN
dat_dr_provider_open(
    IN  const DAT_PROVIDER_INFO *info,
    OUT DAT_IA_OPEN_FUNC	*p_ia_open_func);

extern DAT_RETURN
dat_dr_provider_close(
    IN  const DAT_PROVIDER_INFO *info);

extern DAT_RETURN
dat_dr_size(
    OUT	DAT_COUNT		*size);

extern DAT_RETURN
dat_dr_list(
    IN	DAT_COUNT		max_to_return,
    OUT	DAT_COUNT		*entries_returned,
    OUT	DAT_PROVIDER_INFO	* (dat_provider_list[]));

#ifdef	__cplusplus
}
#endif

#endif /* __DAT_DR_H__ */
