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
 * etm_ckpt.h
 *
 * Header file of checkpointing ereports for persistence
 *
 */

#ifndef _ETM_CKPT_H
#define	_ETM_CKPT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <fm/fmd_api.h>

#define	ETM_CKPT_VERSION	0x10
#define	ETM_CKPT_ERPT_PREFIX	"ev"
#define	ETM_LINE_LEN		256

/*
 * Format of a named buffer that stores an ereport.
 */
typedef struct etm_ckpt_erpt_buf {
	uint8_t		eb_ver;		/* version major.minor */
	uint8_t		eb_rev;		/* reserved field */
	uint16_t	eb_len;		/* size of packed ereport */
					/* nvlist packed erpt event */
} etm_ckpt_erpt_buf_t;

/*
 * Ereport id
 * Each ereport, which is stored in a named buffer, is uniquely identified by
 * fields in the ereport. The named buffer name is derived from this struct
 * as following
 *     ev_${ena}_${hash{class)}_${tod[1]}_${primary}
 */
typedef struct etm_ckpt_erpt_id {
	uint64_t	ei_ena;		/* ereport ena */
	uint32_t	ei_tod1;	/* tod[1]: fractional second */
	uint16_t	ei_hash;	/* hash(ereport class name) */
	uint8_t		ei_pri;		/* primary field */
	uint8_t		ei_rev;		/* reserved field */
} etm_ckpt_erpt_id_t;

/*
 * A circular list of ereport ids
 */
typedef struct etm_ckpt_id_list {
	uint8_t		il_ver;		/* version major.minor */
	uint8_t		il_rev1;	/* reserve  field */
	uint16_t	il_max;		/* max number of erpt ids in list */
	uint16_t	il_cnt;		/* number of valid ids in list */
	uint16_t	il_head;	/* head of the list */
	uint16_t	il_tail;	/* tail of the list */
	uint16_t	il_ids_sz;	/* size of the array of ids */
	uint32_t	il_rev2;	/* reserve  field */
					/* array of ids */
} etm_ckpt_id_list_t;

#define	ETM_CKPT_IL_BUF		"idlist"
#define	ETM_CKPT_IL_MIN_SIZE	0x8

/*
 * Checkpoint options
 */
#define	ETM_CKPT_NOOP		0x0
#define	ETM_CKPT_SAVE		0x1
#define	ETM_CKPT_RESTORE	0x2

void etm_ckpt_recover(fmd_hdl_t *hdl);
int etm_ckpt_add(fmd_hdl_t *hdl, nvlist_t *evp);
int etm_ckpt_delete(fmd_hdl_t *hdl, nvlist_t *evp);

void etm_ckpt_init(fmd_hdl_t *hdl);
void etm_ckpt_fini(fmd_hdl_t *hdl);

#ifdef __cplusplus
}
#endif

#endif /* _ETM_CKPT_H */
