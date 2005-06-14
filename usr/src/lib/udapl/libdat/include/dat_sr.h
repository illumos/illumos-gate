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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * HEADER: dat_sr.h
 *
 * PURPOSE: static registry (SR) inteface declarations
 *
 * $Id: dat_sr.h,v 1.7 2003/07/31 14:04:19 jlentini Exp $
 */

#ifndef _DAT_SR_H_
#define	_DAT_SR_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <dat/udat.h>
#include <dat/dat_registry.h>

#include <dat_osd.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 *
 * Structures
 *
 */

typedef struct
{
    DAT_PROVIDER_INFO 		info;
    char			*lib_path;
    char  			*ia_params;
    DAT_OS_LIBRARY_HANDLE 	lib_handle;
    DAT_PROVIDER_INIT_FUNC 	init_func;
    DAT_PROVIDER_FINI_FUNC	fini_func;
    DAT_COUNT 			ref_count;
} DAT_SR_ENTRY;


/*
 *
 * Function Declarations
 *
 */

extern DAT_RETURN
dat_sr_init(void);

extern DAT_RETURN
dat_sr_fini(void);

extern DAT_RETURN
dat_sr_insert(
    IN  const DAT_PROVIDER_INFO *info,
    IN  DAT_SR_ENTRY 		*entry);

extern DAT_RETURN
dat_sr_size(
    OUT	DAT_COUNT		*size);

extern DAT_RETURN
dat_sr_list(
    IN  DAT_COUNT		max_to_return,
    OUT DAT_COUNT		*entries_returned,
    OUT DAT_PROVIDER_INFO	*(dat_provider_list[]));

extern DAT_RETURN
dat_sr_provider_open(
    IN  const DAT_PROVIDER_INFO *info);

extern DAT_RETURN
dat_sr_provider_close(
    IN  const DAT_PROVIDER_INFO *info);

#ifdef	__cplusplus
}
#endif

#endif	/* _DAT_SR_H_ */
