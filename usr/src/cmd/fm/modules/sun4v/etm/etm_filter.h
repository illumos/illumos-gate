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

/*
 * etm_filter.h
 *
 * Header file of the event filter
 *
 */

#ifndef _ETM_FILTER_H
#define	_ETM_FILTER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <fm/fmd_api.h>

#include "etm_iosvc.h"

/* A physical root complex */
typedef struct etm_prc {
	int32_t		prc_id;			/* physical id of the rc */
	uint64_t	prc_cfg_handle;		/* bus address */
	char		*prc_name;		/* bound ldom name */
	size_t		prc_name_sz;		/* size of name */
	int		prc_status;		/* ldom query status */
	uint64_t	prc_did;		/* ldom id */
} etm_prc_t;

void etm_filter_init(fmd_hdl_t *hdl);
void etm_filter_fini(fmd_hdl_t *hdl);

int etm_filter_find_ldom_id(fmd_hdl_t *hdl, nvlist_t *erpt, char *name,
    int name_size, uint64_t *did);
int etm_filter_find_ldom_name(fmd_hdl_t *hdl, uint64_t did, char *name,
    int name_size);
void etm_filter_handle_ldom_event(fmd_hdl_t *hdl, etm_async_event_type_t event,
    char *name);

#ifdef __cplusplus
}
#endif

#endif /* _ETM_FILTER_H */
