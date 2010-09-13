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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_1394_ADAPTERS_HCI1394_TLABEL_H
#define	_SYS_1394_ADAPTERS_HCI1394_TLABEL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * hci1394_tlabel.h
 *   These routines track the tlabel usage for a 1394 adapter.
 */

#ifdef __cplusplus
extern "C" {
#endif


#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/time.h>
#include <sys/note.h>

/*
 * TLABEL_RANGE specifies the number of tlabels that will be allocated for a
 * given node. tlabels are allocated starting at 0 and going up to
 * (TLABEL_RANGE - 1).
 *
 * e.g. if TLABEL_RANGE was set to 4, each node could have at most 4 outstanding
 *    transactions to any other node at any given time and the tlabels allocated
 *    would be 0, 1, 2, and 3.
 *
 * NOTE: the maximum value of TLABEL_RANGE is 64.
 */
#define	TLABEL_RANGE		64

/* TLABEL_MASK is the mask used to extract the 6-bit tlabel */
#define	TLABEL_MASK		0x3F


/*
 * destination - a 16-bit value where the most significant 10-bits are the bus
 *		 # and the least significant 6 bits are the node #.  The upper
 *		 16 bits of this word are not used.
 *
 * tlabel - the 1394 tlabel to be used.  A number ranging from
 *	    0 - (TLABEL_RANGE - 1)
 */
typedef struct hci1394_tlabel_info_s {
	uint_t	tbi_destination;
	uint_t	tbi_tlabel;
} hci1394_tlabel_info_t;

_NOTE(SCHEME_PROTECTS_DATA("Single thread modifies", \
	hci1394_tlabel_info_s::tbi_destination \
	hci1394_tlabel_info_s::tbi_tlabel))

/* structure used to keep track of tlabels */
typedef struct hci1394_tlabel_s {
	/*
	 * The maximum node number that we have sent a tlabel to inclusive. This
	 * is used as an optimization during reset processing.
	 */
	uint_t tb_max_node;

	/*
	 * Status if we have sent a broadcast request out.  This is used as an
	 * optimization during reset processing.
	 */
	boolean_t tb_bcast_sent;

	/*
	 * free is used to keep track of free tlabels. The free tlabels are
	 * tracked as a bit mask. If the bit is set to 1 the tlabel is free,
	 * if set to 0 the tlabel is used.
	 */
	uint64_t tb_free[IEEE1394_MAX_NODES];

	/*
	 * bad is used to keep track of bad tlabels. A bad tlabel is used for a
	 * ATREQ that was pended but the response was never received. They will
	 * be put back into the free list when > 2 times the split timeout has
	 * gone by (from the initial transfer). The bad tlabels are tracked as
	 * a bit mask. If the bit is set to 1 the tlabel is bad, if set to 0 the
	 * tlabel is good.
	 */
	uint64_t tb_bad[IEEE1394_MAX_NODES];

	/*
	 * last tracks the last used tlabel for a given node. This allows us to
	 * walk through the tlabels for each node during tlabel allocation
	 * (i.e. so we always don't allocate the same tlabel over and over again
	 * if the device is accessed serially).
	 */
	uint8_t tb_last[IEEE1394_MAX_NODES];

	/*
	 * Times are in nS.  reclaim_time is set to the duration to wait to
	 * reclaim the bad tlabels. bad_timestamp is a timestamp for when the
	 * last bad tlabel was added into the bit mask.
	 */
	hrtime_t tb_bad_timestamp[IEEE1394_MAX_NODES];
	hrtime_t tb_reclaim_time;

	/*
	 * *_lookup[node][tlabel]
	 *    Used to track a generic pointer for a given node/tlabel.
	 */
	void *tb_lookup[IEEE1394_MAX_NODES][TLABEL_RANGE];

	/* general driver info */
	hci1394_drvinfo_t *tb_drvinfo;

	kmutex_t tb_mutex;
} hci1394_tlabel_t;

_NOTE(SCHEME_PROTECTS_DATA("Single thread modifies", \
	hci1394_tlabel_s::tb_reclaim_time))

/* handle passed back from init() and used for rest of functions */
typedef	struct hci1394_tlabel_s	*hci1394_tlabel_handle_t;



void hci1394_tlabel_init(hci1394_drvinfo_t *drvinfo, hrtime_t reclaim_time_nS,
    hci1394_tlabel_handle_t *tlabel_handle);
void hci1394_tlabel_fini(hci1394_tlabel_handle_t *tlabel_handle);

int hci1394_tlabel_alloc(hci1394_tlabel_handle_t tlabel_handle,
    uint_t destination, hci1394_tlabel_info_t *tlabel_info);
void hci1394_tlabel_free(hci1394_tlabel_handle_t tlabel_handle,
    hci1394_tlabel_info_t *tlabel_info);

void hci1394_tlabel_register(hci1394_tlabel_handle_t tlabel_handle,
    hci1394_tlabel_info_t *tlabel_info, void *cmd);
void hci1394_tlabel_lookup(hci1394_tlabel_handle_t tlabel_handle,
    hci1394_tlabel_info_t *tlabel_info, void **cmd);

void hci1394_tlabel_bad(hci1394_tlabel_handle_t tlabel_handle,
    hci1394_tlabel_info_t *tlabel_info);

void hci1394_tlabel_reset(hci1394_tlabel_handle_t tlabel_handle);

void hci1394_tlabel_set_reclaim_time(hci1394_tlabel_handle_t tlabel_handle,
    hrtime_t reclaim_time_nS);


#ifdef __cplusplus
}
#endif

#endif	/* _SYS_1394_ADAPTERS_HCI1394_TLABEL_H */
