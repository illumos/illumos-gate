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

#ifndef _NB_LOG_H
#define	_NB_LOG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/cpu_module.h>
#include "nb5000.h"

#define	NB_MAX_ERRORS	4

/* North Bridge front side bus error registers */

typedef struct nb_fsb_regs {
	uint8_t	fsb;		/* cpu slot */
	uint8_t ferr_fat_fsb;
	uint8_t nerr_fat_fsb;
	uint8_t ferr_nf_fsb;
	uint8_t nerr_nf_fsb;
	uint64_t nrecfsb_addr;
	uint32_t nrecfsb;
	uint32_t recfsb;
} nb_fsb_regs_t;

/* PCI express ESI (South Bridge) error registers */

typedef struct nb_pex_regs {
	uint8_t pex;		/* pci express slot */
	uint32_t pex_fat_ferr;
	uint32_t pex_fat_nerr;
	uint32_t pex_nf_corr_ferr;
	uint32_t pex_nf_corr_nerr;
	uint32_t uncerrsev;		/* uncorrectable error severity */
	uint32_t rperrsts;		/* root error status */
	uint32_t rperrsid;		/* error source identification */
	uint32_t uncerrsts;		/* uncorrectable error status */
	uint32_t aerrcapctrl;	/* advanced error capabilities and control */
	uint32_t corerrsts;	/* correctable error status */
	uint16_t pexdevsts;	/* pci express device status */
} nb_pex_regs_t;

/* North Bridge memory controller hub internal error registers */

typedef struct nb_int {
	uint8_t ferr_fat_int;	/* first fatal error */
	uint8_t ferr_nf_int;	/* first non-fatal error */
	uint8_t nerr_fat_int;	/* next fatal error */
	uint8_t nerr_nf_int;	/* next non-fatal error */
	uint32_t nrecint;	/* non recoverable error log */
	uint32_t recint;	/* recoverable error log */
	uint64_t nrecsf;	/* non recoverable control information */
	uint64_t recsf;		/* recoverable control information */
} nb_int_t;

/* memory errors */

typedef struct nb_fat_fbd {
	uint32_t ferr_fat_fbd;	/* fb-dimm first fatal error */
	uint32_t nerr_fat_fbd;	/* fb-dimm next fatal error */
	uint16_t nrecmema;	/* non recoverable memory error log */
	uint32_t nrecmemb;	/* non recoverable memory error log */
	uint32_t nrecfglog;	/* non recoverable dimm configuration */
	uint32_t nrecfbda;	/* non recoverable dimm log A */
	uint32_t nrecfbdb;	/* non recoverable dimm log B */
	uint32_t nrecfbdc;	/* non recoverable dimm log C */
	uint32_t nrecfbdd;	/* non recoverable dimm log D */
	uint32_t nrecfbde;	/* non recoverable dimm log E */
	uint32_t nrecfbdf;	/* non recoverable dimm log F */
	uint32_t spcpc;		/* spare copy control */
	uint8_t spcps;		/* spare copy status */
	uint32_t uerrcnt;	/* uncorrectable error count */
	uint32_t uerrcnt_last;	/* saved copy of uncorrectable error count */
	uint32_t badrama;	/* bad dram marker A */
	uint16_t badramb;	/* bad dram marker B */
	uint32_t badcnt;	/* bad dram counter */
} nb_fat_fbd_t;

typedef struct nb_nf_fbd {
	uint32_t ferr_nf_fbd;	/* fb-dimm first non-fatal error */
	uint32_t nerr_nf_fbd;	/* fb-dimm next non-fatal error */
	uint32_t redmemb;	/* recoverable dimm data error log */
	uint16_t recmema;	/* recoverable memory error log A */
	uint32_t recmemb;	/* recoverable memory error log B */
	uint32_t recfglog;	/* recoverable dimm configuration */
	uint32_t recfbda;	/* recoverable dimm log A */
	uint32_t recfbdb;	/* recoverable dimm log B */
	uint32_t recfbdc;	/* recoverable dimm log C */
	uint32_t recfbdd;	/* recoverable dimm log D */
	uint32_t recfbde;	/* recoverable dimm log E */
	uint32_t recfbdf;	/* recoverable dimm log F */
	uint32_t spcpc;		/* spare copy control */
	uint8_t spcps;		/* spare copy status */
	uint32_t cerrcnt;	/* correctable error count */
	uint32_t cerrcnt_last;	/* saved copy of correctable error count */
	uint32_t badrama;	/* bad dram marker A */
	uint16_t badramb;	/* bad dram marker B */
	uint32_t badcnt;	/* bad dram counter */
} nb_nf_fbd_t;

typedef struct nb_dma {
	uint16_t pcists;
	uint16_t pexdevsts;
} nb_dma_t;

typedef struct nb_regs {
	int flag;
	uint32_t chipset;
	uint64_t ferr;
	uint32_t nerr;
	union {
		nb_fsb_regs_t fsb_regs;
		nb_pex_regs_t pex_regs;
		nb_int_t int_regs;
		nb_fat_fbd_t fat_fbd_regs;
		nb_nf_fbd_t nf_fbd_regs;
		nb_dma_t dma_regs;
	} nb;
} nb_regs_t;

#define	NB_REG_LOG_FREE		0
#define	NB_REG_LOG_FSB		1
#define	NB_REG_LOG_PEX		2
#define	NB_REG_LOG_INT		3
#define	NB_REG_LOG_FAT_FBD	4
#define	NB_REG_LOG_NF_FBD	5
#define	NB_REG_LOG_DMA		6

typedef struct nb_logout {
	uint64_t acl_timestamp;
	char *type;
	nb_regs_t nb_regs;
} nb_logout_t;

typedef struct nb_mem_scatchpad {
	int intel_error_list;		/* error number in Chipset Error List */
	int branch;
	int channel;
	int rank;
	int dimm;
	int bank;
	int cas;
	int ras;
	uint64_t offset;
	uint64_t pa;
} nb_mem_scatchpad_t;

typedef union nb_scatchpad {
	nb_mem_scatchpad_t ms;
	int intel_error_list;		/* error number in Chipset Error List */
} nb_scatchpad_t;

typedef struct nb_dimm {
	uint64_t dimm_size;
	uint8_t mtr_present;
	uint8_t nranks;
	uint8_t nbanks;
	uint8_t ncolumn;
	uint8_t nrow;
	uint8_t width;
	uint8_t manufacture_location;
	uint8_t manufacture_week;
	uint8_t manufacture_year;	/* years from 2000 */
	uint16_t manufacture_id;
	uint32_t serial_number;
	char part_number[16];
	char revision[2];
	char label[64];
} nb_dimm_t;

typedef struct bank_select {
	uint64_t base;
	uint64_t limit;
	uint8_t	way[2];
} bank_select_t;

typedef struct rank_select {
	uint64_t base;
	uint64_t limit;
	uint32_t hole_base;
	uint32_t hole_size;
	uint8_t	rank[4];
	uint8_t interleave;
	uint8_t branch_interleave;
} rank_select_t;

enum nb_memory_mode { NB_MEMORY_SINGLE_CHANNEL, NB_MEMORY_NORMAL,
    NB_MEMORY_SPARE_RANK, NB_MEMORY_MIRROR };

extern int nb_5000_memory_controller;
extern int nb_number_memory_controllers;
extern int nb_dimms_per_channel;

extern nb_dimm_t **nb_dimms;
extern uint32_t nb_chipset;

extern int nb_init(void);
extern int nb_dev_init(void);
extern void nb_dev_reinit(void);
extern void nb_unload(void);
extern void nb_dev_unload(void);
extern uint32_t top_of_low_memory;
extern bank_select_t nb_banks[NB_MAX_MEM_BRANCH_SELECT];
extern rank_select_t nb_ranks[NB_5000_MAX_MEM_CONTROLLERS]
	[NB_MAX_MEM_RANK_SELECT];
extern uint8_t spare_rank[NB_5000_MAX_MEM_CONTROLLERS];
extern enum nb_memory_mode nb_mode;

extern int inb_mc_register(cmi_hdl_t, void *, void *, void *);
extern void nb_scrubber_enable(void);
extern void nb_error_trap(cmi_hdl_t, boolean_t, boolean_t);

extern void nb_pci_cfg_setup(dev_info_t *);
extern void nb_pci_cfg_free(void);

extern void *ras_regs;

extern uint8_t nb_pci_getb(int, int, int, int, int *);
extern uint16_t nb_pci_getw(int, int, int, int, int *);
extern uint32_t nb_pci_getl(int, int, int, int, int *);
extern void nb_pci_putb(int, int, int, int, uint8_t);
extern void nb_pci_putw(int, int, int, int, uint16_t);
extern void nb_pci_putl(int, int, int, int, uint32_t);

extern void nb_fsb_mask_mc(int, uint16_t);
extern void nb_fbd_mask_mc(uint32_t);
extern void nb_int_mask_mc(uint8_t);
extern void nb_mask_mc_reset(void);

extern int nb_mask_mc_set;

extern errorq_t *nb_queue;
extern kmutex_t nb_mutex;

extern void nb_drain(void *, const void *, const errorq_elem_t *);
extern void nb_used_spare_rank(int, int);

extern uint_t nb_config_gen;

#ifdef __cplusplus
}
#endif

#endif /* _NB_LOG_H */
