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

#ifndef _SYS_1394_ADAPTERS_HCI1394_CSR_H
#define	_SYS_1394_ADAPTERS_HCI1394_CSR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * hci1394_csr.h
 *    This file contains the code for the CSR registers handled by the HAL in
 *    SW.  The HW implemented CSR registers are in hci1394_ohci.c
 *
 *   For more information on CSR registers, see
 *	IEEE 1212
 *	IEEE 1394-1995
 *		section 8.3.2
 *	IEEE P1394A Draft 3.0
 *		sections 10.32,10.33
 *
 * NOTE: A read/write to a CSR SW based register will first go to the Services
 *    Layer which will do some filtering and then come through the s1394if.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/ddi.h>
#include <sys/modctl.h>
#include <sys/sunddi.h>

#include <sys/1394/adapters/hci1394_def.h>


/*
 * The 1394 bus sends out cycle start packets periodically.  The time in
 * between these packets is commonly referred to as a bus cycle.  The 1394
 * cycle start packets come every 125uS. split_timeout is represented in 1394
 * bus cycles (e.g. to have ATREQ ACK_PENDED timeout after 100mS, you would set
 * split_timeout to 800).
 *
 * The CSR register interface has the split timeout broken into two registers,
 * split_timeout_hi and split_timeout_lo.  The least significant 3 bits of
 * split_timeout_hi contain the # of seconds and the most significant 13 bits
 * of split_timeout_lo contain the fraction of a seconds in 125uS increments.
 * There is a further constraint that the value in split_timeout_lo must be >=
 * 800 && <= 7999 (>=100mS && < 1S). (don't forget that this value is in the
 * most significant 13 bits, i.e. 800 << 19)  We will threshold the writes into
 * these registers to make sure they always have legal values (i.e. if
 * [8000 << 19] is written to split_timeout_lo, we will write [7999 << 19].
 *
 * The split timeout CSR registers have some inherent problems. There is a race
 * condition when updating the split timeout value since you cannot atomically
 * write to both the hi and lo registers.  This should not be a serious problem
 * since we should never get close to having a split timeout of 1S or greater.
 */


/* CSR Register Address Offsets (1394-1995 8.3.2.2) */
#define	CSR_STATE_CLEAR			0x000
#define	CSR_STATE_SET			0x004
#define	CSR_NODE_IDS			0x008
#define	CSR_RESET_START			0x00C
#define	CSR_SPLIT_TIMEOUT_HI		0x018
#define	CSR_SPLIT_TIMEOUT_LO		0x01C
#define	CSR_CYCLE_TIME			0x200
#define	CSR_BUS_TIME			0x204
#define	CSR_BUSY_TIMEOUT		0x210
#define	CSR_BUS_MANAGER_ID		0x21C
#define	CSR_BANDWIDTH_AVAILABLE		0x220
#define	CSR_CHANNELS_AVAILABLE_HI	0x224
#define	CSR_CHANNELS_AVAILABLE_LO	0x228


typedef struct hci1394_csr_s {
	/* SW registers */
	uint32_t csr_state;
	uint32_t csr_split_timeout_lo;
	uint32_t csr_split_timeout_hi;

	/* split timeout that we are observing */
	uint_t csr_split_timeout;

	/* were we root last bus reset */
	boolean_t csr_was_root;

	/* our node capabilities */
	uint32_t csr_capabilities;

	/* copies of OpenHCI handle and pointer to general driver info */
	hci1394_ohci_handle_t csr_ohci;
	hci1394_drvinfo_t *csr_drvinfo;

	kmutex_t csr_mutex;
} hci1394_csr_t;

/* handle passed back from init() and used for rest of functions */
typedef	struct hci1394_csr_s	*hci1394_csr_handle_t;


void hci1394_csr_init(hci1394_drvinfo_t *drvinfo, hci1394_ohci_handle_t ohci,
    hci1394_csr_handle_t *csr_handle);
void hci1394_csr_fini(hci1394_csr_handle_t *csr_handle);
void hci1394_csr_resume(hci1394_csr_handle_t csr_handle);

void hci1394_csr_node_capabilities(hci1394_csr_handle_t csr_handle,
    uint32_t *capabilities);

void hci1394_csr_state_get(hci1394_csr_handle_t csr_handle, uint32_t *state);
void hci1394_csr_state_bset(hci1394_csr_handle_t csr_handle, uint32_t state);
void hci1394_csr_state_bclr(hci1394_csr_handle_t csr_handle, uint32_t state);

void hci1394_csr_split_timeout_hi_get(hci1394_csr_handle_t csr_handle,
    uint32_t *split_timeout_hi);
void hci1394_csr_split_timeout_lo_get(hci1394_csr_handle_t csr_handle,
    uint32_t *split_timeout_lo);
void hci1394_csr_split_timeout_hi_set(hci1394_csr_handle_t csr_handle,
    uint32_t split_timeout_hi);
void hci1394_csr_split_timeout_lo_set(hci1394_csr_handle_t csr_handle,
    uint32_t split_timeout_lo);
uint_t hci1394_csr_split_timeout_get(hci1394_csr_handle_t csr_handle);

void hci1394_csr_bus_reset(hci1394_csr_handle_t csr_handle);


#ifdef __cplusplus
}
#endif

#endif	/* _SYS_1394_ADAPTERS_HCI1394_CSR_H */
