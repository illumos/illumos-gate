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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_PCI_PBM_H
#define	_SYS_PCI_PBM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/dditypes.h>
#include <sys/ontrap.h>
#include <sys/callb.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The following structure represents the pci configuration header
 * for a psycho or schizo PBM.
 */
typedef struct config_header config_header_t;
struct config_header {
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
};

typedef enum { PBM_SPEED_33MHZ, PBM_SPEED_66MHZ } pbm_speed_t;

/*
 * Bit fields of ch_status_reg for cmn_err's %b
 */
#define	PCI_STATUS_BITS "\020\
\11signaled-parity-error\
\14signaled-target-abort\
\15received-target-abort\
\16received-master-abort\
\17signaled-system-error\
\20detected-parity-error"

/*
 * pbm block soft state structure:
 *
 * Each pci node has its own private pbm block structure.
 */
struct pbm {
	pci_t *pbm_pci_p;	/* link back to pci soft state */
	pbm_speed_t pbm_speed;	/* PCI bus speed (33 or 66 Mhz) */

	/*
	 * PBM control and error registers:
	 */
	volatile uint64_t *pbm_ctrl_reg;
	volatile uint64_t *pbm_async_flt_status_reg;
	volatile uint64_t *pbm_async_flt_addr_reg;
	volatile uint64_t *pbm_diag_reg;
	volatile uint64_t *pbm_estar_reg;
	volatile uint64_t *pbm_pcix_err_stat_reg;
	volatile uint64_t *pbm_pci_ped_ctrl;
	volatile uint64_t *pbm_upper_retry_counter_reg; /* for xmits */

	/*
	 * PCI configuration header block for the PBM:
	 */
	config_header_t *pbm_config_header;

	/*
	 * Memory address range on this PBM used to determine DMA on this pbm
	 */
	iopfn_t pbm_base_pfn;
	iopfn_t pbm_last_pfn;

	/*
	 * pbm Interrupt Mapping Register save area
	 */
	uint64_t pbm_imr_save;

	/* To save CDMA interrupt state across CPR */
	uint64_t pbm_cdma_imr_save;

	/*
	 * pbm error interrupt priority:
	 */
	ddi_iblock_cookie_t pbm_iblock_cookie;

	/*
	 * Consistent Mode DMA Sync
	 */
	uint64_t pbm_sync_reg_pa;	/* pending reg for xmits/tomatillo */
	ib_ino_t pbm_sync_ino;

	volatile uint32_t pbm_cdma_flag;

	/*
	 * DMA sync lock to serialize access to sync hardware.
	 * Used for schizo (>= 2.3) and xmits. Tomatillo does not require
	 * serialization.
	 */
	kmutex_t pbm_sync_mutex;

	/*
	 * support for ddi_poke:
	 */
	on_trap_data_t *pbm_ontrap_data;

	kmutex_t pbm_pokefault_mutex;

	/*
	 * Support for cautious IO accesses
	 */
	ddi_acc_handle_t pbm_excl_handle;

	/*
	 * Support for PCI bus quiesce/unquiesce
	 */
	uint64_t pbm_saved_ctrl_reg;
	uint_t pbm_quiesce_count;
	callb_id_t pbm_panic_cb_id;
	callb_id_t pbm_debug_cb_id;
	uint64_t pbm_anychild_cfgpa;

	/*
	 * Sun Fire 15k PIO limiting semaphore
	 */
	uint32_t pbm_pio_limit;
	volatile uint32_t pbm_pio_counter;

#define	PBM_NAMESTR_BUFLEN 	64
	/* driver name & instance */
	char pbm_nameinst_str[PBM_NAMESTR_BUFLEN];

	/* nodename & node_addr */
	char *pbm_nameaddr_str;
};

/*
 * forward declarations (object creation and destruction):
 */

extern void pbm_create(pci_t *pci_p);
extern void pbm_destroy(pci_t *pci_p);
extern void pbm_configure(pbm_t *pbm_p);
extern void pbm_clear_error(pbm_t *pbm_p);
extern void pbm_enable_intr(pbm_t *pbm_p);
extern void pbm_suspend(pbm_t *pbm_p);
extern void pbm_resume(pbm_t *pbm_p);
extern void pbm_intr_dist(void *arg);
extern int pbm_register_intr(pbm_t *pbm_p);
extern int pbm_afsr_report(dev_info_t *dip, uint64_t fme_ena,
		pbm_errstate_t *pbm_err_p);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCI_PBM_H */
