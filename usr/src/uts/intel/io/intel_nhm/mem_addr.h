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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _MEM_ADDR_H
#define	_MEM_ADDR_H

#ifdef __cplusplus
extern "C" {
#endif

#include "intel_nhm.h"

#ifdef	_KERNEL

extern uint64_t rankaddr_to_dimm(uint64_t rankaddr, int node,
    int channel, int dimm, int writing, uint64_t *bank,
    uint64_t *row, uint64_t *column);
extern uint64_t dimm_to_rankaddr(int node, int channel,
    int dimm, uint64_t rowaddr, uint64_t bankaddr,
    uint64_t coladr, int *log_chan);
extern uint64_t rankaddr_to_phyaddr(int node, int log_chan,
    int dimm, int rank, int rankaddr);
extern uint64_t caddr_to_dimm(int node, int channel, uint64_t caddr,
    int *rank_p, uint64_t *rank_addr_p);

#pragma weak caddr_to_dimm
#pragma weak rankaddr_to_dimm
#pragma weak dimm_to_rankaddr
#pragma weak rankaddr_to_phyaddr

extern char closed_page;
extern char ecc_enabled;
extern char divby3_enabled;
extern char lockstep[2];
extern char mirror_mode[2];
extern char spare_channel[2];
extern sad_t sad[MAX_SAD_DRAM_RULE];
extern tad_t tad[MAX_CPU_NODES][MAX_TAD_DRAM_RULE];
extern sag_ch_t sag_ch[MAX_CPU_NODES][CHANNELS_PER_MEMORY_CONTROLLER]
	[MAX_TAD_DRAM_RULE];
extern rir_t rir[MAX_CPU_NODES][CHANNELS_PER_MEMORY_CONTROLLER]
	[MAX_TAD_DRAM_RULE];
extern dod_t dod_reg[MAX_CPU_NODES][CHANNELS_PER_MEMORY_CONTROLLER]
	[MAX_DIMMS_PER_CHANNEL];

#endif	/* _KERNEL */

#define	CAS_MASK	0xFFFFFF
#define	BANK_MASK	0xFF
#define	RAS_MASK	0xFFFFF
#define	RANK_MASK	0x7FF

#ifdef __cplusplus
}
#endif

#endif /* _MEM_ADDR_H */
