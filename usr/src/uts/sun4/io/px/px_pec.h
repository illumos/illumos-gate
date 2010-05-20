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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_PX_PEC_H
#define	_SYS_PX_PEC_H

#include <sys/types.h>
#include <sys/ontrap.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The following structure represents the pci-express configuration
 * header for a fire PEC.
 */
typedef struct px_config_header {
	volatile uint16_t ch_vendor_id;
	volatile uint16_t ch_device_id;
	volatile uint16_t ch_command_reg;
	volatile uint16_t ch_status_reg;
	volatile uint8_t ch_revision_id_reg;
	volatile uint8_t ch_programming_if_code_reg;
	volatile uint8_t ch_sub_class_reg;
	volatile uint8_t ch_base_class_reg;
	volatile uint8_t ch_cache_line_size_reg;
	volatile uint8_t ch_latency_timer_reg;
	volatile uint8_t ch_header_type_reg;
} px_config_header_t;

/*
 * Bit fields of ch_status_reg for cmn_err's %b
 */
#define	PX_STATUS_BITS "\020\
\11signaled-parity-error\
\14signaled-target-abort\
\15received-target-abort\
\16received-master-abort\
\17signaled-system-error\
\20detected-parity-error"

/*
 * pec block soft state structure:
 *
 * Each px node has its own private pec block structure.
 */
typedef struct px_pec {
	px_t		*pec_px_p;	/* link back to px soft state */

	/*
	 * Memory address range on this PBM used to determine DMA on this pec
	 */
	px_iopfn_t		pec_base32_pfn;
	px_iopfn_t		pec_last32_pfn;
	px_iopfn_t		pec_base64_pfn;
	px_iopfn_t		pec_last64_pfn;

	/*
	 * support for ddi_poke:
	 */
	on_trap_data_t	*pec_ontrap_data;
	int		pec_safeacc_type;
	kmutex_t	pec_pokefault_mutex;

	/*
	 * support for cautious
	 */
	ddi_acc_handle_t pec_acc_hdl;

#define	PBM_NAMESTR_BUFLEN 	64
	/* driver name & instance */
	char		pec_nameinst_str[PBM_NAMESTR_BUFLEN];

	/* nodename & node_addr */
	char		*pec_nameaddr_str;

	/* MSIQ used for correctable/fatal/non fatala PCIe messages */
	msiqid_t	pec_corr_msg_msiq_id;
	msiqid_t	pec_non_fatal_msg_msiq_id;
	msiqid_t	pec_fatal_msg_msiq_id;
} px_pec_t;

/*
 * forward declarations (object creation and destruction):
 */

extern int px_pec_attach(px_t *px_p);
extern void px_pec_detach(px_t *px_p);
extern int  px_pec_msg_add_intr(px_t *px_p);
extern void px_pec_msg_rem_intr(px_t *px_p);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PX_PEC_H */
