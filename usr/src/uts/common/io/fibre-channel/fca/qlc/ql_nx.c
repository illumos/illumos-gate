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
 * Copyright 2015 QLogic Corporation.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * ISP2xxx Solaris Fibre Channel Adapter (FCA) driver source file.
 *
 * ***********************************************************************
 * *									**
 * *				NOTICE					**
 * *		COPYRIGHT (C) 1996-2015 QLOGIC CORPORATION		**
 * *			ALL RIGHTS RESERVED				**
 * *									**
 * ***********************************************************************
 *
 */

#include <ql_apps.h>
#include <ql_api.h>
#include <ql_debug.h>
#include <ql_init.h>
#include <ql_mbx.h>
#include <ql_nx.h>

/*
 *  Local Function Prototypes.
 */
static void ql_crb_addr_transform_setup(ql_adapter_state_t *);
static void ql_8021_pci_set_crbwindow_2M(ql_adapter_state_t *, uint64_t *);
static int ql_8021_crb_win_lock(ql_adapter_state_t *);
static void ql_8021_crb_win_unlock(ql_adapter_state_t *);
static int ql_8021_pci_get_crb_addr_2M(ql_adapter_state_t *, uint64_t *);
static uint32_t ql_8021_pci_mem_bound_check(ql_adapter_state_t *, uint64_t,
    uint32_t);
static uint64_t ql_8021_pci_set_window(ql_adapter_state_t *, uint64_t);
static int ql_8021_pci_is_same_window(ql_adapter_state_t *, uint64_t);
static int ql_8021_pci_mem_read_direct(ql_adapter_state_t *, uint64_t, void *,
    uint32_t);
static int ql_8021_pci_mem_write_direct(ql_adapter_state_t *, uint64_t, void *,
    uint32_t);
static int ql_8021_pci_mem_read_2M(ql_adapter_state_t *, uint64_t, void *,
    uint32_t);
static int ql_8021_pci_mem_write_2M(ql_adapter_state_t *, uint64_t, void *,
    uint32_t);
static uint32_t ql_8021_decode_crb_addr(ql_adapter_state_t *, uint32_t);
static int ql_8021_rom_lock(ql_adapter_state_t *);
static void ql_8021_rom_unlock(ql_adapter_state_t *);
static int ql_8021_wait_rom_done(ql_adapter_state_t *);
static int ql_8021_wait_flash_done(ql_adapter_state_t *);
static int ql_8021_do_rom_fast_read(ql_adapter_state_t *, uint32_t, uint32_t *);
static int ql_8021_rom_fast_read(ql_adapter_state_t *, uint32_t, uint32_t *);
static int ql_8021_do_rom_write(ql_adapter_state_t *, uint32_t, uint32_t);
static int ql_8021_do_rom_erase(ql_adapter_state_t *, uint32_t);
static int ql_8021_phantom_init(ql_adapter_state_t *);
static int ql_8021_pinit_from_rom(ql_adapter_state_t *);
static int ql_8021_load_from_flash(ql_adapter_state_t *);
static int ql_8021_load_firmware(ql_adapter_state_t *);
static int ql_8021_reset_hw(ql_adapter_state_t *, int);
static int ql_8021_init_p3p(ql_adapter_state_t *);
static int ql_8021_hw_lock(ql_adapter_state_t *, uint32_t);
static void ql_8021_hw_unlock(ql_adapter_state_t *);
static void ql_8021_need_reset_handler(ql_adapter_state_t *);
static int ql_8021_load_fw(ql_adapter_state_t *);
static uint32_t ql_8021_check_fw_alive(ql_adapter_state_t *);
static int ql_8021_get_fw_dump(ql_adapter_state_t *);
static void ql_8021_md_parse_template(ql_adapter_state_t *, caddr_t, caddr_t,
    uint32_t, uint32_t);
static int ql_8021_md_rdcrb(ql_adapter_state_t *, md_entry_rdcrb_t *,
    uint32_t *);
static int ql_8021_md_L2Cache(ql_adapter_state_t *, md_entry_cache_t *,
    uint32_t *);
static int ql_8021_md_L1Cache(ql_adapter_state_t *, md_entry_cache_t *,
    uint32_t *);
static int ql_8021_md_rdocm(ql_adapter_state_t *, md_entry_rdocm_t *,
    uint32_t *);
static int ql_8021_md_rdmem(ql_adapter_state_t *, md_entry_rdmem_t *,
    uint32_t *);
static int ql_8021_md_rdrom(ql_adapter_state_t *, md_entry_rdrom_t *,
    uint32_t *);
static int ql_8021_md_rdmux(ql_adapter_state_t *, md_entry_mux_t *,
    uint32_t *);
static int ql_8021_md_rdqueue(ql_adapter_state_t *, md_entry_queue_t *,
    uint32_t *);
static int ql_8021_md_cntrl(ql_adapter_state_t *, md_template_hdr_t *,
    md_entry_cntrl_t *);
static void ql_8021_md_entry_err_chk(ql_adapter_state_t *, md_entry_t *,
    uint32_t, int);
static uint32_t ql_8021_md_template_checksum(ql_adapter_state_t *);
static uint32_t ql_8021_read_reg(ql_adapter_state_t *, uint32_t);
static void ql_8021_write_reg(ql_adapter_state_t *, uint32_t, uint32_t);
static uint32_t ql_8021_read_ocm(ql_adapter_state_t *, uint32_t);

/*
 * Local Data.
 */
static uint32_t	crb_addr_xform[MAX_CRB_XFORM];
static int	crb_table_initialized = 0;
static int	pci_set_window_warning_count = 0;

static struct legacy_intr_set legacy_intr[] = NX_LEGACY_INTR_CONFIG;

static crb_128M_2M_block_map_t crb_128M_2M_map[64] = {
	{{{0, 0,	 0,	 0}}},			/* 0: PCI */
	{{{1, 0x0100000, 0x0102000, 0x120000},		/* 1: PCIE */
	    {1, 0x0110000, 0x0120000, 0x130000},
	    {1, 0x0120000, 0x0122000, 0x124000},
	    {1, 0x0130000, 0x0132000, 0x126000},
	    {1, 0x0140000, 0x0142000, 0x128000},
	    {1, 0x0150000, 0x0152000, 0x12a000},
	    {1, 0x0160000, 0x0170000, 0x110000},
	    {1, 0x0170000, 0x0172000, 0x12e000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {1, 0x01e0000, 0x01e0800, 0x122000},
	    {0, 0x0000000, 0x0000000, 0x000000}}},
	{{{1, 0x0200000, 0x0210000, 0x180000}}},	/* 2: MN */
	{{{0, 0,	 0,	 0}}},			/* 3: */
	{{{1, 0x0400000, 0x0401000, 0x169000}}},	/* 4: P2NR1 */
	{{{1, 0x0500000, 0x0510000, 0x140000}}},	/* 5: SRE   */
	{{{1, 0x0600000, 0x0610000, 0x1c0000}}},	/* 6: NIU   */
	{{{1, 0x0700000, 0x0704000, 0x1b8000}}},	/* 7: QM    */
	{{{1, 0x0800000, 0x0802000, 0x170000},		/* 8: SQM0  */
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {1, 0x08f0000, 0x08f2000, 0x172000}}},
	{{{1, 0x0900000, 0x0902000, 0x174000},		/* 9: SQM1 */
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {1, 0x09f0000, 0x09f2000, 0x176000}}},
	{{{0, 0x0a00000, 0x0a02000, 0x178000},		/* 10: SQM2 */
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {1, 0x0af0000, 0x0af2000, 0x17a000}}},
	{{{0, 0x0b00000, 0x0b02000, 0x17c000},		/* 11: SQM3 */
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {1, 0x0bf0000, 0x0bf2000, 0x17e000}}},
	{{{1, 0x0c00000, 0x0c04000, 0x1d4000}}},	/* 12: I2Q */
	{{{1, 0x0d00000, 0x0d04000, 0x1a4000}}},	/* 13: TMR */
	{{{1, 0x0e00000, 0x0e04000, 0x1a0000}}},	/* 14: ROMUSB */
	{{{1, 0x0f00000, 0x0f01000, 0x164000}}},	/* 15: PEG4 */
	{{{0, 0x1000000, 0x1004000, 0x1a8000}}},	/* 16: XDMA */
	{{{1, 0x1100000, 0x1101000, 0x160000}}},	/* 17: PEG0 */
	{{{1, 0x1200000, 0x1201000, 0x161000}}},	/* 18: PEG1 */
	{{{1, 0x1300000, 0x1301000, 0x162000}}},	/* 19: PEG2 */
	{{{1, 0x1400000, 0x1401000, 0x163000}}},	/* 20: PEG3 */
	{{{1, 0x1500000, 0x1501000, 0x165000}}},	/* 21: P2ND */
	{{{1, 0x1600000, 0x1601000, 0x166000}}},	/* 22: P2NI */
	{{{0, 0,	 0,	 0}}},			/* 23: */
	{{{0, 0,	 0,	 0}}},			/* 24: */
	{{{0, 0,	 0,	 0}}},			/* 25: */
	{{{0, 0,	 0,	 0}}},			/* 26: */
	{{{0, 0,	 0,	 0}}},			/* 27: */
	{{{0, 0,	 0,	 0}}},			/* 28: */
	{{{1, 0x1d00000, 0x1d10000, 0x190000}}},	/* 29: MS */
	{{{1, 0x1e00000, 0x1e01000, 0x16a000}}},	/* 30: P2NR2 */
	{{{1, 0x1f00000, 0x1f10000, 0x150000}}},	/* 31: EPG */
	{{{0}}},					/* 32: PCI */
	{{{1, 0x2100000, 0x2102000, 0x120000},		/* 33: PCIE */
	    {1, 0x2110000, 0x2120000, 0x130000},
	    {1, 0x2120000, 0x2122000, 0x124000},
	    {1, 0x2130000, 0x2132000, 0x126000},
	    {1, 0x2140000, 0x2142000, 0x128000},
	    {1, 0x2150000, 0x2152000, 0x12a000},
	    {1, 0x2160000, 0x2170000, 0x110000},
	    {1, 0x2170000, 0x2172000, 0x12e000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000},
	    {0, 0x0000000, 0x0000000, 0x000000}}},
	{{{1, 0x2200000, 0x2204000, 0x1b0000}}},	/* 34: CAM */
	{{{0}}},					/* 35: */
	{{{0}}},					/* 36: */
	{{{0}}},					/* 37: */
	{{{0}}},					/* 38: */
	{{{0}}},					/* 39: */
	{{{1, 0x2800000, 0x2804000, 0x1a4000}}},	/* 40: TMR */
	{{{1, 0x2900000, 0x2901000, 0x16b000}}},	/* 41: P2NR3 */
	{{{1, 0x2a00000, 0x2a00400, 0x1ac400}}},	/* 42: RPMX1 */
	{{{1, 0x2b00000, 0x2b00400, 0x1ac800}}},	/* 43: RPMX2 */
	{{{1, 0x2c00000, 0x2c00400, 0x1acc00}}},	/* 44: RPMX3 */
	{{{1, 0x2d00000, 0x2d00400, 0x1ad000}}},	/* 45: RPMX4 */
	{{{1, 0x2e00000, 0x2e00400, 0x1ad400}}},	/* 46: RPMX5 */
	{{{1, 0x2f00000, 0x2f00400, 0x1ad800}}},	/* 47: RPMX6 */
	{{{1, 0x3000000, 0x3000400, 0x1adc00}}},	/* 48: RPMX7 */
	{{{0, 0x3100000, 0x3104000, 0x1a8000}}},	/* 49: XDMA */
	{{{1, 0x3200000, 0x3204000, 0x1d4000}}},	/* 50: I2Q */
	{{{1, 0x3300000, 0x3304000, 0x1a0000}}},	/* 51: ROMUSB */
	{{{0}}},					/* 52: */
	{{{1, 0x3500000, 0x3500400, 0x1ac000}}},	/* 53: RPMX0 */
	{{{1, 0x3600000, 0x3600400, 0x1ae000}}},	/* 54: RPMX8 */
	{{{1, 0x3700000, 0x3700400, 0x1ae400}}},	/* 55: RPMX9 */
	{{{1, 0x3800000, 0x3804000, 0x1d0000}}},	/* 56: OCM0 */
	{{{1, 0x3900000, 0x3904000, 0x1b4000}}},	/* 57: CRYPTO */
	{{{1, 0x3a00000, 0x3a04000, 0x1d8000}}},	/* 58: SMB */
	{{{0}}},					/* 59: I2C0 */
	{{{0}}},					/* 60: I2C1 */
	{{{1, 0x3d00000, 0x3d04000, 0x1dc000}}},	/* 61: LPC */
	{{{1, 0x3e00000, 0x3e01000, 0x167000}}},	/* 62: P2NC */
	{{{1, 0x3f00000, 0x3f01000, 0x168000}}}		/* 63: P2NR0 */
};

/*
 * top 12 bits of crb internal address (hub, agent)
 */
static uint32_t crb_hub_agt[64] = {
	0,
	UNM_HW_CRB_HUB_AGT_ADR_PS,
	UNM_HW_CRB_HUB_AGT_ADR_MN,
	UNM_HW_CRB_HUB_AGT_ADR_MS,
	0,
	UNM_HW_CRB_HUB_AGT_ADR_SRE,
	UNM_HW_CRB_HUB_AGT_ADR_NIU,
	UNM_HW_CRB_HUB_AGT_ADR_QMN,
	UNM_HW_CRB_HUB_AGT_ADR_SQN0,
	UNM_HW_CRB_HUB_AGT_ADR_SQN1,
	UNM_HW_CRB_HUB_AGT_ADR_SQN2,
	UNM_HW_CRB_HUB_AGT_ADR_SQN3,
	UNM_HW_CRB_HUB_AGT_ADR_I2Q,
	UNM_HW_CRB_HUB_AGT_ADR_TIMR,
	UNM_HW_CRB_HUB_AGT_ADR_ROMUSB,
	UNM_HW_CRB_HUB_AGT_ADR_PGN4,
	UNM_HW_CRB_HUB_AGT_ADR_XDMA,
	UNM_HW_CRB_HUB_AGT_ADR_PGN0,
	UNM_HW_CRB_HUB_AGT_ADR_PGN1,
	UNM_HW_CRB_HUB_AGT_ADR_PGN2,
	UNM_HW_CRB_HUB_AGT_ADR_PGN3,
	UNM_HW_CRB_HUB_AGT_ADR_PGND,
	UNM_HW_CRB_HUB_AGT_ADR_PGNI,
	UNM_HW_CRB_HUB_AGT_ADR_PGS0,
	UNM_HW_CRB_HUB_AGT_ADR_PGS1,
	UNM_HW_CRB_HUB_AGT_ADR_PGS2,
	UNM_HW_CRB_HUB_AGT_ADR_PGS3,
	0,
	UNM_HW_CRB_HUB_AGT_ADR_PGSI,
	UNM_HW_CRB_HUB_AGT_ADR_SN,
	0,
	UNM_HW_CRB_HUB_AGT_ADR_EG,
	0,
	UNM_HW_CRB_HUB_AGT_ADR_PS,
	UNM_HW_CRB_HUB_AGT_ADR_CAM,
	0,
	0,
	0,
	0,
	0,
	UNM_HW_CRB_HUB_AGT_ADR_TIMR,
	0,
	UNM_HW_CRB_HUB_AGT_ADR_RPMX1,
	UNM_HW_CRB_HUB_AGT_ADR_RPMX2,
	UNM_HW_CRB_HUB_AGT_ADR_RPMX3,
	UNM_HW_CRB_HUB_AGT_ADR_RPMX4,
	UNM_HW_CRB_HUB_AGT_ADR_RPMX5,
	UNM_HW_CRB_HUB_AGT_ADR_RPMX6,
	UNM_HW_CRB_HUB_AGT_ADR_RPMX7,
	UNM_HW_CRB_HUB_AGT_ADR_XDMA,
	UNM_HW_CRB_HUB_AGT_ADR_I2Q,
	UNM_HW_CRB_HUB_AGT_ADR_ROMUSB,
	0,
	UNM_HW_CRB_HUB_AGT_ADR_RPMX0,
	UNM_HW_CRB_HUB_AGT_ADR_RPMX8,
	UNM_HW_CRB_HUB_AGT_ADR_RPMX9,
	UNM_HW_CRB_HUB_AGT_ADR_OCM0,
	0,
	UNM_HW_CRB_HUB_AGT_ADR_SMB,
	UNM_HW_CRB_HUB_AGT_ADR_I2C0,
	UNM_HW_CRB_HUB_AGT_ADR_I2C1,
	0,
	UNM_HW_CRB_HUB_AGT_ADR_PGNC,
	0,
};

/* ARGSUSED */
static void
ql_crb_addr_transform_setup(ql_adapter_state_t *ha)
{
	crb_addr_transform(XDMA);
	crb_addr_transform(TIMR);
	crb_addr_transform(SRE);
	crb_addr_transform(SQN3);
	crb_addr_transform(SQN2);
	crb_addr_transform(SQN1);
	crb_addr_transform(SQN0);
	crb_addr_transform(SQS3);
	crb_addr_transform(SQS2);
	crb_addr_transform(SQS1);
	crb_addr_transform(SQS0);
	crb_addr_transform(RPMX7);
	crb_addr_transform(RPMX6);
	crb_addr_transform(RPMX5);
	crb_addr_transform(RPMX4);
	crb_addr_transform(RPMX3);
	crb_addr_transform(RPMX2);
	crb_addr_transform(RPMX1);
	crb_addr_transform(RPMX0);
	crb_addr_transform(ROMUSB);
	crb_addr_transform(SN);
	crb_addr_transform(QMN);
	crb_addr_transform(QMS);
	crb_addr_transform(PGNI);
	crb_addr_transform(PGND);
	crb_addr_transform(PGN3);
	crb_addr_transform(PGN2);
	crb_addr_transform(PGN1);
	crb_addr_transform(PGN0);
	crb_addr_transform(PGSI);
	crb_addr_transform(PGSD);
	crb_addr_transform(PGS3);
	crb_addr_transform(PGS2);
	crb_addr_transform(PGS1);
	crb_addr_transform(PGS0);
	crb_addr_transform(PS);
	crb_addr_transform(PH);
	crb_addr_transform(NIU);
	crb_addr_transform(I2Q);
	crb_addr_transform(EG);
	crb_addr_transform(MN);
	crb_addr_transform(MS);
	crb_addr_transform(CAS2);
	crb_addr_transform(CAS1);
	crb_addr_transform(CAS0);
	crb_addr_transform(CAM);
	crb_addr_transform(C2C1);
	crb_addr_transform(C2C0);
	crb_addr_transform(SMB);
	crb_addr_transform(OCM0);
	/*
	 * Used only in P3 just define it for P2 also.
	 */
	crb_addr_transform(I2C0);

	crb_table_initialized = 1;
}

/*
 * In: 'off' is offset from CRB space in 128M pci map
 * Out: 'off' is 2M pci map addr
 * side effect: lock crb window
 */
static void
ql_8021_pci_set_crbwindow_2M(ql_adapter_state_t *ha, uint64_t *off)
{
	uint32_t	win_read, crb_win;

	crb_win = (uint32_t)CRB_HI(*off);
	WRT_REG_DWORD(ha, CRB_WINDOW_2M + ha->nx_pcibase, crb_win);

	/*
	 * Read back value to make sure write has gone through before trying
	 * to use it.
	 */
	win_read = RD_REG_DWORD(ha, CRB_WINDOW_2M + ha->nx_pcibase);
	if (win_read != crb_win) {
		EL(ha, "Written crbwin (0x%x) != Read crbwin (0x%x), "
		    "off=0x%llx\n", crb_win, win_read, *off);
	}
	*off = (*off & MASK(16)) + CRB_INDIRECT_2M + (uintptr_t)ha->nx_pcibase;
}

void
ql_8021_wr_32(ql_adapter_state_t *ha, uint64_t off, uint32_t data)
{
	int	rv;

	rv = ql_8021_pci_get_crb_addr_2M(ha, &off);
	if (rv == -1) {
		cmn_err(CE_PANIC, "ql_8021_wr_32, ql_8021_pci_get_crb_addr_"
		    "2M=-1\n");
	}
	if (rv == 1) {
		(void) ql_8021_crb_win_lock(ha);
		ql_8021_pci_set_crbwindow_2M(ha, &off);
	}

	WRT_REG_DWORD(ha, (uintptr_t)off, data);

	if (rv == 1) {
		ql_8021_crb_win_unlock(ha);
	}
}

void
ql_8021_rd_32(ql_adapter_state_t *ha, uint64_t off, uint32_t *data)
{
	int		rv;
	uint32_t	n;

	rv = ql_8021_pci_get_crb_addr_2M(ha, &off);
	if (rv == -1) {
		cmn_err(CE_PANIC, "ql_8021_rd_32, ql_8021_pci_get_crb_addr_"
		    "2M=-1\n");
	}

	if (rv == 1) {
		(void) ql_8021_crb_win_lock(ha);
		ql_8021_pci_set_crbwindow_2M(ha, &off);
	}
	n = RD_REG_DWORD(ha, (uintptr_t)off);

	if (data != NULL) {
		*data = n;
	}

	if (rv == 1) {
		ql_8021_crb_win_unlock(ha);
	}
}

static int
ql_8021_crb_win_lock(ql_adapter_state_t *ha)
{
	uint32_t	done = 0, timeout = 0;

	while (!done) {
		/* acquire semaphore3 from PCI HW block */
		ql_8021_rd_32(ha, UNM_PCIE_REG(PCIE_SEM7_LOCK), &done);
		if (done == 1) {
			break;
		}
		if (timeout >= CRB_WIN_LOCK_TIMEOUT) {
			EL(ha, "timeout\n");
			return (-1);
		}
		timeout++;

		/* Yield CPU */
		delay(1);
	}
	ql_8021_wr_32(ha, UNM_CRB_WIN_LOCK_ID, ha->pci_function_number);

	return (0);
}

static void
ql_8021_crb_win_unlock(ql_adapter_state_t *ha)
{
	ql_8021_rd_32(ha, UNM_PCIE_REG(PCIE_SEM7_UNLOCK), NULL);
}

static int
ql_8021_pci_get_crb_addr_2M(ql_adapter_state_t *ha, uint64_t *off)
{
	crb_128M_2M_sub_block_map_t	*m;

	if (*off >= UNM_CRB_MAX) {
		EL(ha, "%llx >= %llx\n", *off, UNM_CRB_MAX);
		return (-1);
	}

	if (*off >= UNM_PCI_CAMQM && (*off < UNM_PCI_CAMQM_2M_END)) {
		*off = (*off - UNM_PCI_CAMQM) + UNM_PCI_CAMQM_2M_BASE +
		    (uintptr_t)ha->nx_pcibase;
		return (0);
	}

	if (*off < UNM_PCI_CRBSPACE) {
		EL(ha, "%llx < %llx\n", *off, UNM_PCI_CRBSPACE);
		return (-1);
	}

	*off -= UNM_PCI_CRBSPACE;
	/*
	 * Try direct map
	 */

	m = &crb_128M_2M_map[CRB_BLK(*off)].sub_block[CRB_SUBBLK(*off)];

	if (m->valid && ((uint64_t)m->start_128M <= *off) &&
	    ((uint64_t)m->end_128M > *off)) {
		*off = (uint64_t)(*off + m->start_2M - m->start_128M +
		    (uintptr_t)ha->nx_pcibase);
		return (0);
	}

	/*
	 * Not in direct map, use crb window
	 */
	return (1);
}

/*
 * check memory access boundary.
 * used by test agent. support ddr access only for now
 */
/* ARGSUSED */
static uint32_t
ql_8021_pci_mem_bound_check(ql_adapter_state_t *ha, uint64_t addr,
    uint32_t size)
{
	/*LINTED suspicious 0 comparison*/
	if (!QL_8021_ADDR_IN_RANGE(addr, UNM_ADDR_DDR_NET,
	    UNM_ADDR_DDR_NET_MAX) ||
	    /*LINTED suspicious 0 comparison*/
	    !QL_8021_ADDR_IN_RANGE(addr + size - 1, UNM_ADDR_DDR_NET,
	    UNM_ADDR_DDR_NET_MAX) ||
	    ((size != 1) && (size != 2) && (size != 4) && (size != 8))) {
		return (0);
	}

	return (1);
}

static uint64_t
ql_8021_pci_set_window(ql_adapter_state_t *ha, uint64_t addr)
{
	uint32_t	window, win_read;

	/*LINTED suspicious 0 comparison*/
	if (QL_8021_ADDR_IN_RANGE(addr, UNM_ADDR_DDR_NET,
	    UNM_ADDR_DDR_NET_MAX)) {
		/* DDR network side */
		window = (uint32_t)MN_WIN(addr);
		ql_8021_wr_32(ha, UNM_PCI_CRBSPACE, window);
		ql_8021_rd_32(ha, UNM_PCI_CRBSPACE, &win_read);
		if ((win_read << 17) != window) {
			EL(ha, "Warning, Written MNwin (0x%x) != Read MNwin "
			    "(0x%x)\n", window, win_read);
		}
		addr = GET_MEM_OFFS_2M(addr) + UNM_PCI_DDR_NET;
	} else if (QL_8021_ADDR_IN_RANGE(addr, UNM_ADDR_OCM0,
	    UNM_ADDR_OCM0_MAX)) {
		uint32_t	temp1;

		if ((addr & 0x00ff800) == 0xff800) {
			/* if bits 19:18&17:11 are on */
			EL(ha, "QM access not handled\n");
			addr = -1UL;
		}

		window = (uint32_t)OCM_WIN(addr);
		ql_8021_wr_32(ha, UNM_PCI_CRBSPACE, window);
		ql_8021_rd_32(ha, UNM_PCI_CRBSPACE, &win_read);
		temp1 = ((window & 0x1FF) << 7) |
		    ((window & 0x0FFFE0000) >> 17);
		if (win_read != temp1) {
			EL(ha, "Written OCMwin (0x%x) != Read OCMwin (0x%x)\n",
			    temp1, win_read);
		}
		addr = GET_MEM_OFFS_2M(addr) + UNM_PCI_OCM0_2M;
	} else if (QL_8021_ADDR_IN_RANGE(addr, UNM_ADDR_QDR_NET,
	    NX_P3_ADDR_QDR_NET_MAX)) {
		/* QDR network side */
		window = (uint32_t)MS_WIN(addr);
		ha->qdr_sn_window = window;
		ql_8021_wr_32(ha, UNM_PCI_CRBSPACE, window);
		ql_8021_rd_32(ha, UNM_PCI_CRBSPACE, &win_read);
		if (win_read != window) {
			EL(ha, "Written MSwin (0x%x) != Read MSwin (0x%x)\n",
			    window, win_read);
		}
		addr = GET_MEM_OFFS_2M(addr) + UNM_PCI_QDR_NET;
	} else {
		/*
		 * peg gdb frequently accesses memory that doesn't exist,
		 * this limits the chit chat so debugging isn't slowed down.
		 */
		if ((pci_set_window_warning_count++ < 8) ||
		    (pci_set_window_warning_count % 64 == 0)) {
			EL(ha, "Unknown address range\n");
		}
		addr = -1UL;
	}

	return (addr);
}

/* check if address is in the same windows as the previous access */
static int
ql_8021_pci_is_same_window(ql_adapter_state_t *ha, uint64_t addr)
{
	uint32_t	window;
	uint64_t	qdr_max;

	qdr_max = NX_P3_ADDR_QDR_NET_MAX;

	/*LINTED suspicious 0 comparison*/
	if (QL_8021_ADDR_IN_RANGE(addr, UNM_ADDR_DDR_NET,
	    UNM_ADDR_DDR_NET_MAX)) {
		/* DDR network side */
		EL(ha, "DDR network side\n");
		return (0);	/* MN access can not come here */
	} else if (QL_8021_ADDR_IN_RANGE(addr, UNM_ADDR_OCM0,
	    UNM_ADDR_OCM0_MAX)) {
		return (1);
	} else if (QL_8021_ADDR_IN_RANGE(addr, UNM_ADDR_OCM1,
	    UNM_ADDR_OCM1_MAX)) {
		return (1);
	} else if (QL_8021_ADDR_IN_RANGE(addr, UNM_ADDR_QDR_NET, qdr_max)) {
		/* QDR network side */
		window = (uint32_t)(((addr - UNM_ADDR_QDR_NET) >> 22) & 0x3f);
		if (ha->qdr_sn_window == window) {
			return (1);
		}
	}

	return (0);
}

static int
ql_8021_pci_mem_read_direct(ql_adapter_state_t *ha, uint64_t off, void *data,
    uint32_t size)
{
	void		*addr;
	int		ret = 0;
	uint64_t	start;

	/*
	 * If attempting to access unknown address or straddle hw windows,
	 * do not access.
	 */
	if (((start = ql_8021_pci_set_window(ha, off)) == -1UL) ||
	    (ql_8021_pci_is_same_window(ha, off + size - 1) == 0)) {
		EL(ha, "out of bound pci memory access. offset is 0x%llx\n",
		    off);
		return (-1);
	}

	addr = (void *)((uint8_t *)ha->nx_pcibase + start);

	switch (size) {
	case 1:
		*(uint8_t *)data = RD_REG_BYTE(ha, addr);
		break;
	case 2:
		*(uint16_t *)data = RD_REG_WORD(ha, addr);
		break;
	case 4:
		*(uint32_t *)data = RD_REG_DWORD(ha, addr);
		break;
	case 8:
		*(uint64_t *)data = RD_REG_DDWORD(ha, addr);
		break;
	default:
		EL(ha, "invalid size=%x\n", size);
		ret = -1;
		break;
	}

	return (ret);
}

static int
ql_8021_pci_mem_write_direct(ql_adapter_state_t *ha, uint64_t off, void *data,
    uint32_t size)
{
	void		*addr;
	int		ret = 0;
	uint64_t	start;

	/*
	 * If attempting to access unknown address or straddle hw windows,
	 * do not access.
	 */
	if (((start = ql_8021_pci_set_window(ha, off)) == -1UL) ||
	    (ql_8021_pci_is_same_window(ha, off + size -1) == 0)) {
		EL(ha, "out of bound pci memory access. offset is 0x%llx\n",
		    off);
		return (-1);
	}

	addr = (void *)((uint8_t *)ha->nx_pcibase + start);

	switch (size) {
	case 1:
		WRT_REG_BYTE(ha, addr, *(uint8_t *)data);
		break;
	case 2:
		WRT_REG_WORD(ha, addr, *(uint16_t *)data);
		break;
	case 4:
		WRT_REG_DWORD(ha, addr, *(uint32_t *)data);
		break;
	case 8:
		WRT_REG_DDWORD(ha, addr, *(uint64_t *)data);
		break;
	default:
		EL(ha, "invalid size=%x\n", size);
		ret = -1;
		break;
	}

	return (ret);
}

static int
ql_8021_pci_mem_read_2M(ql_adapter_state_t *ha, uint64_t off, void *data,
    uint32_t size)
{
	int		j = 0;
	uint32_t	i, temp, sz[2], loop, shift_amount;
	uint64_t	start, end, k;
	uint64_t	off8, off0[2], val, mem_crb, word[2] = {0, 0};

	/*
	 * If not MN, go check for MS or invalid.
	 */

	if (off >= UNM_ADDR_QDR_NET && off <= NX_P3_ADDR_QDR_NET_MAX) {
		mem_crb = UNM_CRB_QDR_NET;
	} else {
		mem_crb = UNM_CRB_DDR_NET;
		if (ql_8021_pci_mem_bound_check(ha, off, size) == 0) {
			return (ql_8021_pci_mem_read_direct(ha, off, data,
			    size));
		}
	}

	if (NX_IS_REVISION_P3PLUS(ha->rev_id)) {
		off8 = off & 0xfffffff0;
		off0[0] = off & 0xf;
		sz[0] = (uint32_t)(((uint64_t)size < (16 - off0[0])) ? size :
		    (16 - off0[0]));
		shift_amount = 4;
	} else {
		off8 = off & 0xfffffff8;
		off0[0] = off & 0x7;
		sz[0] = (uint32_t)(((uint64_t)size < (8 - off0[0])) ? size :
		    (8 - off0[0]));
		shift_amount = 3;
	}
	loop = (uint32_t)(((off0[0] + size - 1) >> shift_amount) + 1);
	off0[1] = 0;
	sz[1] = size - sz[0];

	/*
	 * don't lock here - write_wx gets the lock if each time
	 * write_lock_irqsave(&adapter->adapter_lock, flags);
	 * netxen_nic_pci_change_crbwindow_128M(adapter, 0);
	 */

	for (i = 0; i < loop; i++) {
		temp = (uint32_t)(off8 + (i << shift_amount));
		ql_8021_wr_32(ha, mem_crb + MIU_TEST_AGT_ADDR_LO, temp);
		temp = 0;
		ql_8021_wr_32(ha, mem_crb + MIU_TEST_AGT_ADDR_HI, temp);
		temp = MIU_TA_CTL_ENABLE;
		ql_8021_wr_32(ha, mem_crb + MIU_TEST_AGT_CTRL, temp);
		temp = MIU_TA_CTL_START | MIU_TA_CTL_ENABLE;
		ql_8021_wr_32(ha, mem_crb + MIU_TEST_AGT_CTRL, temp);

		for (j = 0; j < MAX_CTL_CHECK; j++) {
			ql_8021_rd_32(ha, mem_crb + MIU_TEST_AGT_CTRL, &temp);
			if ((temp & MIU_TA_CTL_BUSY) == 0) {
				break;
			}
		}

		if (j >= MAX_CTL_CHECK) {
			EL(ha, "failed to read through agent\n");
			break;
		}

		start = off0[i] >> 2;
		end = (off0[i] + sz[i] - 1) >> 2;
		for (k = start; k <= end; k++) {
			ql_8021_rd_32(ha, mem_crb + MIU_TEST_AGT_RDDATA(k),
			    &temp);
			word[i] |= ((uint64_t)temp << (32 * (k & 1)));
		}
	}

	/*
	 * netxen_nic_pci_change_crbwindow_128M(adapter, 1);
	 * write_unlock_irqrestore(&adapter->adapter_lock, flags);
	 */

	if (j >= MAX_CTL_CHECK) {
		return (-1);
	}

	if ((off0[0] & 7) == 0) {
		val = word[0];
	} else {
		val = ((word[0] >> (off0[0] * 8)) & (~(~0ULL << (sz[0] * 8)))) |
		    ((word[1] & (~(~0ULL << (sz[1] * 8)))) << (sz[0] * 8));
	}

	switch (size) {
	case 1:
		*(uint8_t *)data = (uint8_t)val;
		break;
	case 2:
		*(uint16_t *)data = (uint16_t)val;
		break;
	case 4:
		*(uint32_t *)data = (uint32_t)val;
		break;
	case 8:
		*(uint64_t *)data = val;
		break;
	}

	return (0);
}

static int
ql_8021_pci_mem_write_2M(ql_adapter_state_t *ha, uint64_t off, void *data,
    uint32_t size)
{
	int		j, ret = 0;
	uint32_t	i, temp, loop, sz[2];
	uint32_t	scale, shift_amount, p3p, startword;
	uint64_t	off8, off0, mem_crb, tmpw, word[2] = {0, 0};

	/*
	 * If not MN, go check for MS or invalid.
	 */
	if (off >= UNM_ADDR_QDR_NET && off <= NX_P3_ADDR_QDR_NET_MAX) {
		mem_crb = UNM_CRB_QDR_NET;
	} else {
		mem_crb = UNM_CRB_DDR_NET;
		if (ql_8021_pci_mem_bound_check(ha, off, size) == 0) {
			return (ql_8021_pci_mem_write_direct(ha, off, data,
			    size));
		}
	}

	off0 = off & 0x7;
	sz[0] = (uint32_t)(((uint64_t)size < (8 - off0)) ? size : (8 - off0));
	sz[1] = size - sz[0];

	if (NX_IS_REVISION_P3PLUS(ha->rev_id)) {
		off8 = off & 0xfffffff0;
		loop = (uint32_t)((((off & 0xf) + size - 1) >> 4) + 1);
		shift_amount = 4;
		scale = 2;
		p3p = 1;
		startword = (uint32_t)((off & 0xf) / 8);
	} else {
		off8 = off & 0xfffffff8;
		loop = (uint32_t)(((off0 + size - 1) >> 3) + 1);
		shift_amount = 3;
		scale = 1;
		p3p = 0;
		startword = 0;
	}

	if (p3p || (size != 8) || (off0 != 0)) {
		for (i = 0; i < loop; i++) {
			if (ql_8021_pci_mem_read_2M(ha, off8 +
			    (i << shift_amount), &word[i * scale], 8)) {
				EL(ha, "8021_pci_mem_read_2M != 0\n");
				return (-1);
			}
		}
	}

	switch (size) {
	case 1:
		tmpw = (uint64_t)(*((uint8_t *)data));
		break;
	case 2:
		tmpw = (uint64_t)(*((uint16_t *)data));
		break;
	case 4:
		tmpw = (uint64_t)(*((uint32_t *)data));
		break;
	case 8:
	default:
		tmpw = *((uint64_t *)data);
		break;
	}

	if (p3p) {
		if (sz[0] == 8) {
			word[startword] = tmpw;
		} else {
			word[startword] &= ~((~(~0ULL << (sz[0] * 8))) <<
			    (off0 * 8));
			word[startword] |= tmpw << (off0 * 8);
		}
		if (sz[1] != 0) {
			word[startword + 1] &= ~(~0ULL << (sz[1] * 8));
			word[startword + 1] |= tmpw >> (sz[0] * 8);
		}
	} else {
		word[startword] &= ~((~(~0ULL << (sz[0] * 8))) << (off0 * 8));
		word[startword] |= tmpw << (off0 * 8);

		if (loop == 2) {
			word[1] &= ~(~0ULL << (sz[1] * 8));
			word[1] |= tmpw >> (sz[0] * 8);
		}
	}

	/*
	 * don't lock here - write_wx gets the lock if each time
	 * write_lock_irqsave(&adapter->adapter_lock, flags);
	 * netxen_nic_pci_change_crbwindow_128M(adapter, 0);
	 */

	for (i = 0; i < loop; i++) {
		temp = (uint32_t)(off8 + (i << shift_amount));
		ql_8021_wr_32(ha, mem_crb + MIU_TEST_AGT_ADDR_LO, temp);
		temp = 0;
		ql_8021_wr_32(ha, mem_crb + MIU_TEST_AGT_ADDR_HI, temp);
		temp = (uint32_t)(word[i * scale] & 0xffffffff);
		ql_8021_wr_32(ha, mem_crb + MIU_TEST_AGT_WRDATA_LO, temp);
		temp = (uint32_t)((word[i * scale] >> 32) & 0xffffffff);
		ql_8021_wr_32(ha, mem_crb + MIU_TEST_AGT_WRDATA_HI, temp);
		if (p3p) {
			temp = (uint32_t)(word[i * scale + 1] & 0xffffffff);
			ql_8021_wr_32(ha,
			    mem_crb + MIU_TEST_AGT_WRDATA_UPPER_LO, temp);
			temp = (uint32_t)((word[i * scale + 1] >> 32) &
			    0xffffffff);
			ql_8021_wr_32(ha,
			    mem_crb + MIU_TEST_AGT_WRDATA_UPPER_HI, temp);
		}
		temp = MIU_TA_CTL_ENABLE | MIU_TA_CTL_WRITE;
		ql_8021_wr_32(ha, mem_crb + MIU_TEST_AGT_CTRL, temp);
		temp = MIU_TA_CTL_START | MIU_TA_CTL_ENABLE | MIU_TA_CTL_WRITE;
		ql_8021_wr_32(ha, mem_crb + MIU_TEST_AGT_CTRL, temp);

		for (j = 0; j < MAX_CTL_CHECK; j++) {
			ql_8021_rd_32(ha, mem_crb + MIU_TEST_AGT_CTRL, &temp);
			if ((temp & MIU_TA_CTL_BUSY) == 0)
				break;
		}

		if (j >= MAX_CTL_CHECK) {
			EL(ha, "failed to write through agent\n");
			ret = -1;
			break;
		}
	}

	return (ret);
}

static uint32_t
ql_8021_decode_crb_addr(ql_adapter_state_t *ha, uint32_t addr)
{
	int		i;
	uint32_t	base_addr, offset, pci_base;

	if (!crb_table_initialized) {
		ql_crb_addr_transform_setup(ha);
	}

	pci_base = ADDR_ERROR;
	base_addr = addr & 0xfff00000;
	offset = addr & 0x000fffff;

	for (i = 0; i < MAX_CRB_XFORM; i++) {
		if (crb_addr_xform[i] == base_addr) {
			pci_base = i << 20;
			break;
		}
	}
	if (pci_base == ADDR_ERROR) {
		return (pci_base);
	} else {
		return (pci_base + offset);
	}
}

static int
ql_8021_hw_lock(ql_adapter_state_t *ha, uint32_t timer)
{
	uint32_t	done = 0, timeout = 0;

	while (!done) {
		/* acquire semaphore5 from PCI HW block */
		ql_8021_rd_32(ha, UNM_PCIE_REG(PCIE_SEM5_LOCK), &done);
		if (done == 1) {
			break;
		}
		if (timeout >= timer) {
			EL(ha, "timeout\n");
			return (-1);
		}
		timeout++;

		/*
		 * Yield CPU
		 */
		delay(1);
	}

	return (0);
}

static void
ql_8021_hw_unlock(ql_adapter_state_t *ha)
{
	ql_8021_rd_32(ha, UNM_PCIE_REG(PCIE_SEM5_UNLOCK), NULL);
}

static int
ql_8021_rom_lock(ql_adapter_state_t *ha)
{
	uint32_t	done = 0, timeout = 0;

	while (!done) {
		/* acquire semaphore2 from PCI HW block */
		ql_8021_rd_32(ha, UNM_PCIE_REG(PCIE_SEM2_LOCK), &done);
		if (done == 1) {
			break;
		}
		if (timeout >= ROM_LOCK_TIMEOUT) {
			EL(ha, "timeout\n");
			return (-1);
		}
		timeout++;

		/*
		 * Yield CPU
		 */
		delay(1);
	}
	ql_8021_wr_32(ha, UNM_ROM_LOCK_ID, ROM_LOCK_DRIVER);

	return (0);
}

static void
ql_8021_rom_unlock(ql_adapter_state_t *ha)
{
	ql_8021_rd_32(ha, UNM_PCIE_REG(PCIE_SEM2_UNLOCK), NULL);
}

static int
ql_8021_wait_rom_done(ql_adapter_state_t *ha)
{
	uint32_t	timeout = 0, done = 0;

	while (done == 0) {
		ql_8021_rd_32(ha, UNM_ROMUSB_GLB_STATUS, &done);
		done &= 2;
		timeout++;
		if (timeout >= ROM_MAX_TIMEOUT) {
			EL(ha, "Timeout reached waiting for rom done\n");
			return (-1);
		}
	}

	return (0);
}

static int
ql_8021_wait_flash_done(ql_adapter_state_t *ha)
{
	clock_t		timer;
	uint32_t	status;

	for (timer = 500000; timer; timer--) {
		ql_8021_wr_32(ha, UNM_ROMUSB_ROM_ABYTE_CNT, 0);
		ql_8021_wr_32(ha, UNM_ROMUSB_ROM_INSTR_OPCODE,
		    UNM_ROMUSB_ROM_RDSR_INSTR);
		if (ql_8021_wait_rom_done(ha)) {
			EL(ha, "Error waiting for rom done2\n");
			return (-1);
		}

		/* Get status. */
		ql_8021_rd_32(ha, UNM_ROMUSB_ROM_RDATA, &status);
		if (!(status & BIT_0)) {
			return (0);
		}
		drv_usecwait(10);
	}

	EL(ha, "timeout status=%x\n", status);
	return (-1);
}

static int
ql_8021_do_rom_fast_read(ql_adapter_state_t *ha, uint32_t addr, uint32_t *valp)
{
	ql_8021_wr_32(ha, UNM_ROMUSB_ROM_ADDRESS, addr);
	ql_8021_wr_32(ha, UNM_ROMUSB_ROM_DUMMY_BYTE_CNT, 0);
	ql_8021_wr_32(ha, UNM_ROMUSB_ROM_ABYTE_CNT, 3);
	ql_8021_wr_32(ha, UNM_ROMUSB_ROM_INSTR_OPCODE,
	    UNM_ROMUSB_ROM_FAST_RD_INSTR);
	if (ql_8021_wait_rom_done(ha)) {
		EL(ha, "Error waiting for rom done\n");
		return (-1);
	}
	/* reset abyte_cnt and dummy_byte_cnt */
	ql_8021_wr_32(ha, UNM_ROMUSB_ROM_DUMMY_BYTE_CNT, 0);
	drv_usecwait(10);
	ql_8021_wr_32(ha, UNM_ROMUSB_ROM_ABYTE_CNT, 0);

	ql_8021_rd_32(ha, UNM_ROMUSB_ROM_RDATA, valp);

	return (0);
}

int
ql_8021_rom_fast_read(ql_adapter_state_t *ha, uint32_t addr, uint32_t *valp)
{
	int	ret, loops = 0;

	while ((ql_8021_rom_lock(ha) != 0) && (loops < 500000)) {
		drv_usecwait(10);
		loops++;
	}
	if (loops >= 50000) {
		EL(ha, "rom_lock failed\n");
		return (-1);
	}
	ret = ql_8021_do_rom_fast_read(ha, addr, valp);
	ql_8021_rom_unlock(ha);

	return (ret);
}

static int
ql_8021_do_rom_write(ql_adapter_state_t *ha, uint32_t addr, uint32_t data)
{
	ql_8021_wr_32(ha, UNM_ROMUSB_ROM_ABYTE_CNT, 0);
	ql_8021_wr_32(ha, UNM_ROMUSB_ROM_INSTR_OPCODE,
	    UNM_ROMUSB_ROM_WREN_INSTR);
	if (ql_8021_wait_rom_done(ha)) {
		EL(ha, "Error waiting for rom done\n");
		return (-1);
	}

	ql_8021_wr_32(ha, UNM_ROMUSB_ROM_WDATA, data);
	ql_8021_wr_32(ha, UNM_ROMUSB_ROM_ADDRESS, addr);
	ql_8021_wr_32(ha, UNM_ROMUSB_ROM_ABYTE_CNT, 3);
	ql_8021_wr_32(ha, UNM_ROMUSB_ROM_INSTR_OPCODE,
	    UNM_ROMUSB_ROM_PP_INSTR);
	if (ql_8021_wait_rom_done(ha)) {
		EL(ha, "Error waiting for rom done1\n");
		return (-1);
	}

	if (ql_8021_wait_flash_done(ha)) {
		EL(ha, "Error waiting for flash done\n");
		return (-1);
	}

	return (0);
}

static int
ql_8021_do_rom_erase(ql_adapter_state_t *ha, uint32_t addr)
{
	ql_8021_wr_32(ha, UNM_ROMUSB_ROM_ABYTE_CNT, 0);
	ql_8021_wr_32(ha, UNM_ROMUSB_ROM_INSTR_OPCODE,
	    UNM_ROMUSB_ROM_WREN_INSTR);
	if (ql_8021_wait_rom_done(ha)) {
		EL(ha, "Error waiting for rom done\n");
		return (-1);
	}

	ql_8021_wr_32(ha, UNM_ROMUSB_ROM_ADDRESS, addr);
	ql_8021_wr_32(ha, UNM_ROMUSB_ROM_ABYTE_CNT, 3);
	ql_8021_wr_32(ha, UNM_ROMUSB_ROM_INSTR_OPCODE,
	    UNM_ROMUSB_ROM_SE_INSTR);
	if (ql_8021_wait_rom_done(ha)) {
		EL(ha, "Error waiting for rom done1\n");
		return (-1);
	}

	if (ql_8021_wait_flash_done(ha)) {
		EL(ha, "Error waiting for flash done\n");
		return (-1);
	}

	return (0);
}

int
ql_8021_rom_read(ql_adapter_state_t *ha, uint32_t addr, uint32_t *bp)
{
	int	ret;

	ret = ql_8021_rom_fast_read(ha, addr << 2, bp) == 0 ? QL_SUCCESS :
	    QL_FUNCTION_FAILED;

	return (ret);
}

int
ql_8021_rom_write(ql_adapter_state_t *ha, uint32_t addr, uint32_t data)
{
	int	ret, loops = 0;

	while ((ql_8021_rom_lock(ha) != 0) && (loops < 500000)) {
		drv_usecwait(10);
		loops++;
	}
	if (loops >= 50000) {
		EL(ha, "rom_lock failed\n");
		ret = QL_FUNCTION_TIMEOUT;
	} else {
		ret = ql_8021_do_rom_write(ha, addr << 2, data) == 0 ?
		    QL_SUCCESS : QL_FUNCTION_FAILED;
		ql_8021_rom_unlock(ha);
	}

	return (ret);
}

int
ql_8021_rom_erase(ql_adapter_state_t *ha, uint32_t addr)
{
	int	ret, loops = 0;

	while ((ql_8021_rom_lock(ha) != 0) && (loops < 500000)) {
		drv_usecwait(10);
		loops++;
	}
	if (loops >= 50000) {
		EL(ha, "rom_lock failed\n");
		ret = QL_FUNCTION_TIMEOUT;
	} else {
		ret = ql_8021_do_rom_erase(ha, addr << 2) == 0 ? QL_SUCCESS :
		    QL_FUNCTION_FAILED;
		ql_8021_rom_unlock(ha);
	}

	return (ret);
}

int
ql_8021_rom_wrsr(ql_adapter_state_t *ha, uint32_t data)
{
	int	ret = QL_SUCCESS, loops = 0;

	while ((ql_8021_rom_lock(ha) != 0) && (loops < 500000)) {
		drv_usecwait(10);
		loops++;
	}
	if (loops >= 50000) {
		EL(ha, "rom_lock failed\n");
		ret = QL_FUNCTION_TIMEOUT;
	} else {
		ql_8021_wr_32(ha, UNM_ROMUSB_ROM_ABYTE_CNT, 0);
		ql_8021_wr_32(ha, UNM_ROMUSB_ROM_INSTR_OPCODE,
		    UNM_ROMUSB_ROM_WREN_INSTR);
		if (ql_8021_wait_rom_done(ha)) {
			EL(ha, "Error waiting for rom done\n");
			ret = QL_FUNCTION_FAILED;
		} else {
			ql_8021_wr_32(ha, UNM_ROMUSB_ROM_WDATA, data);
			ql_8021_wr_32(ha, UNM_ROMUSB_ROM_ABYTE_CNT, 0);
			ql_8021_wr_32(ha, UNM_ROMUSB_ROM_INSTR_OPCODE,
			    UNM_ROMUSB_ROM_WRSR_INSTR);
			if (ql_8021_wait_rom_done(ha)) {
				EL(ha, "Error waiting for rom done1\n");
				ret = QL_FUNCTION_FAILED;
			} else if (ql_8021_wait_flash_done(ha)) {
				EL(ha, "Error waiting for flash done\n");
				ret = QL_FUNCTION_FAILED;
			}
		}
		ql_8021_rom_unlock(ha);
	}

	return (ret);
}

static int
ql_8021_phantom_init(ql_adapter_state_t *ha)
{
	uint32_t	val = 0, err = 0;
	int		retries = 60;

	do {
		ql_8021_rd_32(ha, CRB_CMDPEG_STATE, &val);

		switch (val) {
		case PHAN_INITIALIZE_COMPLETE:
		case PHAN_INITIALIZE_ACK:
			EL(ha, "success=%xh\n", val);
			return (0);
		case PHAN_INITIALIZE_FAILED:
			EL(ha, "PHAN_INITIALIZE_FAILED\n");
			err = 1;
			break;
		default:
			break;
		}

		if (err) {
			break;
		}
		/* 500 msec wait */
		delay(50);

	} while (--retries);

	if (!err) {
		ql_8021_wr_32(ha, CRB_CMDPEG_STATE, PHAN_INITIALIZE_FAILED);
	}

	EL(ha, "firmware init failed=%x\n", val);
	return (-1);
}

static int
ql_8021_pinit_from_rom(ql_adapter_state_t *ha)
{
	int			init_delay = 0;
	struct crb_addr_pair	*buf;
	uint32_t		offset, off, i, n, addr, val;

	/* Grab the lock so that no one can read flash when we reset the chip */
	(void) ql_8021_rom_lock(ha);
	ql_8021_wr_32(ha, UNM_ROMUSB_GLB_SW_RESET, 0xffffffff);
	/* Just in case it was held when we reset the chip */
	ql_8021_rom_unlock(ha);
	delay(100);

	if (ql_8021_rom_fast_read(ha, 0, &n) != 0 || n != 0xcafecafe ||
	    ql_8021_rom_fast_read(ha, 4, &n) != 0) {
		EL(ha, "ERROR Reading crb_init area: n: %08x\n", n);
		return (-1);
	}
	offset = n & 0xffff;
	n = (n >> 16) & 0xffff;
	if (n >= 1024) {
		EL(ha, "n=0x%x Error! NetXen card flash not initialized\n", n);
		return (-1);
	}

	buf = kmem_zalloc(n * sizeof (struct crb_addr_pair), KM_SLEEP);
	if (buf == NULL) {
		EL(ha, "Unable to zalloc memory\n");
		return (-1);
	}

	for (i = 0; i < n; i++) {
		if (ql_8021_rom_fast_read(ha, 8 * i + 4 * offset, &val) != 0 ||
		    ql_8021_rom_fast_read(ha, 8 * i + 4 * offset + 4, &addr) !=
		    0) {
			kmem_free(buf, n * sizeof (struct crb_addr_pair));
			EL(ha, "ql_8021_rom_fast_read != 0 to zalloc memory\n");
			return (-1);
		}

		buf[i].addr = addr;
		buf[i].data = val;
	}

	for (i = 0; i < n; i++) {
		off = ql_8021_decode_crb_addr(ha, buf[i].addr);
		if (off == ADDR_ERROR) {
			EL(ha, "Err: Unknown addr: 0x%lx\n", buf[i].addr);
			continue;
		}
		off += UNM_PCI_CRBSPACE;

		if (off & 1) {
			continue;
		}

		/* skipping cold reboot MAGIC */
		if (off == UNM_RAM_COLD_BOOT) {
			continue;
		}
		if (off == (UNM_CRB_I2C0 + 0x1c)) {
			continue;
		}
		/* do not reset PCI */
		if (off == (ROMUSB_GLB + 0xbc)) {
			continue;
		}
		if (off == (ROMUSB_GLB + 0xa8)) {
			continue;
		}
		if (off == (ROMUSB_GLB + 0xc8)) {	/* core clock */
			continue;
		}
		if (off == (ROMUSB_GLB + 0x24)) {	/* MN clock */
			continue;
		}
		if (off == (ROMUSB_GLB + 0x1c)) {	/* MS clock */
			continue;
		}
		if ((off & 0x0ff00000) == UNM_CRB_DDR_NET) {
			continue;
		}
		if (off == (UNM_CRB_PEG_NET_1 + 0x18) &&
		    !NX_IS_REVISION_P3PLUS(ha->rev_id)) {
			buf[i].data = 0x1020;
		}
		/* skip the function enable register */
		if (off == UNM_PCIE_REG(PCIE_SETUP_FUNCTION)) {
			continue;
		}
		if (off == UNM_PCIE_REG(PCIE_SETUP_FUNCTION2)) {
			continue;
		}
		if ((off & 0x0ff00000) == UNM_CRB_SMB) {
			continue;
		}

		/* After writing this register, HW needs time for CRB */
		/* to quiet down (else crb_window returns 0xffffffff) */
		init_delay = 1;
		if (off == UNM_ROMUSB_GLB_SW_RESET) {
			init_delay = 100;	/* Sleep 1000 msecs */
		}

		ql_8021_wr_32(ha, off, buf[i].data);

		delay(init_delay);
	}
	kmem_free(buf, n * sizeof (struct crb_addr_pair));

	/* disable_peg_cache_all */

	/* p2dn replyCount */
	ql_8021_wr_32(ha, UNM_CRB_PEG_NET_D + 0xec, 0x1e);
	/* disable_peg_cache 0 */
	ql_8021_wr_32(ha, UNM_CRB_PEG_NET_D + 0x4c, 8);
	/* disable_peg_cache 1 */
	ql_8021_wr_32(ha, UNM_CRB_PEG_NET_I + 0x4c, 8);

	/* peg_clr_all */
	/* peg_clr 0 */
	ql_8021_wr_32(ha, UNM_CRB_PEG_NET_0 + 0x8, 0);
	ql_8021_wr_32(ha, UNM_CRB_PEG_NET_0 + 0xc, 0);
	/* peg_clr 1 */
	ql_8021_wr_32(ha, UNM_CRB_PEG_NET_1 + 0x8, 0);
	ql_8021_wr_32(ha, UNM_CRB_PEG_NET_1 + 0xc, 0);
	/* peg_clr 2 */
	ql_8021_wr_32(ha, UNM_CRB_PEG_NET_2 + 0x8, 0);
	ql_8021_wr_32(ha, UNM_CRB_PEG_NET_2 + 0xc, 0);
	/* peg_clr 3 */
	ql_8021_wr_32(ha, UNM_CRB_PEG_NET_3 + 0x8, 0);
	ql_8021_wr_32(ha, UNM_CRB_PEG_NET_3 + 0xc, 0);

	return (0);
}

static int
ql_8021_load_from_flash(ql_adapter_state_t *ha)
{
	int		i;
	uint32_t	flashaddr, memaddr;
	uint32_t	high, low, size;
	uint64_t	data;

	size = ha->bootloader_size / 2;
	memaddr = flashaddr = ha->bootloader_addr << 2;

	for (i = 0; i < size; i++) {
		if ((ql_8021_rom_fast_read(ha, flashaddr, &low)) ||
		    (ql_8021_rom_fast_read(ha, flashaddr + 4, &high))) {
			EL(ha, "ql_8021_rom_fast_read != 0\n");
			return (-1);
		}
		data = ((uint64_t)high << 32) | low;
		if (ql_8021_pci_mem_write_2M(ha, memaddr, &data, 8)) {
			EL(ha, "qla_fc_8021_pci_mem_write_2M != 0\n");
			return (-1);
		}
		flashaddr += 8;
		memaddr += 8;

		/* Allow other system activity. */
		if (i % 0x1000 == 0) {
			/* Delay for 1 tick (10ms). */
			delay(1);
		}
	}

#if 0
	/* Allow other system activity, delay for 1 tick (10ms). */
	delay(1);

	size = ha->flash_fw_size / 2;
	memaddr = flashaddr = ha->flash_fw_addr << 2;

	for (i = 0; i < size; i++) {
		if ((ql_8021_rom_fast_read(ha, flashaddr, &low)) ||
		    (ql_8021_rom_fast_read(ha, flashaddr + 4, &high))) {
			EL(ha, "ql_8021_rom_fast_read3 != 0\n");
			return (-1);
		}
		data = ((uint64_t)high << 32) | low;
		(void) ql_8021_pci_mem_write_2M(ha, memaddr, &data, 8);
		flashaddr += 8;
		memaddr += 8;

		/* Allow other system activity. */
		if (i % 0x1000 == 0) {
			/* Delay for 1 tick (10ms). */
			delay(1);
		}
	}
#endif
	return (0);
}

static int
ql_8021_load_firmware(ql_adapter_state_t *ha)
{
	uint64_t	data;
	uint32_t	i, flashaddr, size;
	uint8_t		*bp, n, *dp;

	bp = (uint8_t *)(ha->risc_fw[0].code);
	dp = (uint8_t *)&size;
	for (n = 0; n < 4; n++) {
		dp[n] = *bp++;
	}
	LITTLE_ENDIAN_32(&size);
	EL(ha, "signature=%x\n", size);

	size = ha->bootloader_size / 2;
	flashaddr = ha->bootloader_addr << 2;

	bp = (uint8_t *)(ha->risc_fw[0].code + flashaddr);
	dp = (uint8_t *)&data;
	for (i = 0; i < size; i++) {
		for (n = 0; n < 8; n++) {
			dp[n] = *bp++;
		}
		LITTLE_ENDIAN_64(&data);
		if (ql_8021_pci_mem_write_2M(ha, flashaddr, &data, 8)) {
			EL(ha, "qla_fc_8021_pci_mem_write_2M != 0\n");
			return (-1);
		}
		flashaddr += 8;
	}

	bp = (uint8_t *)(ha->risc_fw[0].code + FW_SIZE_OFFSET);
	dp = (uint8_t *)&size;
	for (n = 0; n < 4; n++) {
		dp[n] = *bp++;
	}
	LITTLE_ENDIAN_32(&size);
	EL(ha, "IMAGE_START size=%llx\n", size);
	size = (size + 7) / 8;

	flashaddr = ha->flash_fw_addr << 2;
	bp = (uint8_t *)(ha->risc_fw[0].code + flashaddr);

	dp = (uint8_t *)&data;
	for (i = 0; i < size; i++) {
		for (n = 0; n < 8; n++) {
			dp[n] = *bp++;
		}
		LITTLE_ENDIAN_64(&data);
		if (ql_8021_pci_mem_write_2M(ha, flashaddr, &data, 8)) {
			EL(ha, "qla_fc_8021_pci_mem_write_2M != 0\n");
			return (-1);
		}
		flashaddr += 8;
	}

	return (0);
}

static int
ql_8021_init_p3p(ql_adapter_state_t *ha)
{
	uint32_t	data;

	/* ??? */
	ql_8021_wr_32(ha, UNM_PORT_MODE_ADDR, UNM_PORT_MODE_AUTO_NEG);
	delay(drv_usectohz(1000000));

	/* CAM RAM Cold Boot Register */
	ql_8021_rd_32(ha, UNM_RAM_COLD_BOOT, &data);
	if (data == 0x55555555) {
		ql_8021_rd_32(ha, UNM_ROMUSB_GLB_SW_RESET, &data);
		if (data != 0x80000f) {
			EL(ha, "CRB_UNM_GLB_SW_RST=%x exit\n", data);
			return (-1);
		}
		ql_8021_wr_32(ha, UNM_RAM_COLD_BOOT, 0);
	}
	ql_8021_rd_32(ha, UNM_ROMUSB_GLB_PEGTUNE_DONE, &data);
	data |= 1;
	ql_8021_wr_32(ha, UNM_ROMUSB_GLB_PEGTUNE_DONE, data);

	/*
	 * ???
	 * data = ha->pci_bus_addr | BIT_31;
	 * ql_8021_wr_32(ha, UNM_BUS_DEV_NO, data);
	 */

	return (0);
}

/* ARGSUSED */
void
ql_8021_reset_chip(ql_adapter_state_t *ha)
{
	/*
	 * Disable interrupts does not work on a per function bases
	 * leave them enabled
	 */
	ql_8021_enable_intrs(ha);

	ADAPTER_STATE_LOCK(ha);
	ha->flags |= INTERRUPTS_ENABLED;
	ADAPTER_STATE_UNLOCK(ha);
	if (!(ha->task_daemon_flags & ISP_ABORT_NEEDED)) {
		(void) ql_stop_firmware(ha);
	}
}

static int
ql_8021_reset_hw(ql_adapter_state_t *ha, int type)
{
	int		ret;
	uint32_t	rst;

	/* scrub dma mask expansion register */
	ql_8021_wr_32(ha, CRB_DMA_SHIFT, 0x55555555);

	/* Overwrite stale initialization register values */
	ql_8021_wr_32(ha, CRB_CMDPEG_STATE, 0);
	ql_8021_wr_32(ha, CRB_RCVPEG_STATE, 0);
	ql_8021_wr_32(ha, UNM_PEG_HALT_STATUS1, 0);
	ql_8021_wr_32(ha, UNM_PEG_HALT_STATUS2, 0);

	/*
	 * This reset sequence is to provide a graceful shutdown of the
	 * different hardware blocks prior to performing an ASIC Reset,
	 * has to be done before writing 0xffffffff to ASIC_RESET.
	 */
	ql_8021_wr_32(ha, UNM_CRB_I2Q + 0x10, 0);
	ql_8021_wr_32(ha, UNM_CRB_I2Q + 0x14, 0);
	ql_8021_wr_32(ha, UNM_CRB_I2Q + 0x18, 0);
	ql_8021_wr_32(ha, UNM_CRB_I2Q + 0x1c, 0);
	ql_8021_wr_32(ha, UNM_CRB_I2Q + 0x20, 0);
	ql_8021_wr_32(ha, UNM_CRB_I2Q + 0x24, 0);
	ql_8021_wr_32(ha, UNM_CRB_NIU + 0x40, 0xff);
	ql_8021_wr_32(ha, UNM_CRB_NIU + 0x70000, 0x0);
	ql_8021_wr_32(ha, UNM_CRB_NIU + 0x80000, 0x0);
	ql_8021_wr_32(ha, UNM_CRB_NIU + 0x90000, 0x0);
	ql_8021_wr_32(ha, UNM_CRB_NIU + 0xa0000, 0x0);
	ql_8021_wr_32(ha, UNM_CRB_NIU + 0xb0000, 0x0);
	ql_8021_wr_32(ha, UNM_CRB_SRE + 0x1000, 0x28ff000c);
	ql_8021_wr_32(ha, UNM_CRB_EPG + 0x1300, 0x1);
	ql_8021_wr_32(ha, UNM_CRB_TIMER + 0x0, 0x0);
	ql_8021_wr_32(ha, UNM_CRB_TIMER + 0x8, 0x0);
	ql_8021_wr_32(ha, UNM_CRB_TIMER + 0x10, 0x0);
	ql_8021_wr_32(ha, UNM_CRB_TIMER + 0x18, 0x0);
	ql_8021_wr_32(ha, UNM_CRB_TIMER + 0x100, 0x0);
	ql_8021_wr_32(ha, UNM_CRB_TIMER + 0x200, 0x0);
	ql_8021_wr_32(ha, UNM_CRB_PEG_NET_0 + 0x3C, 0x1);
	ql_8021_wr_32(ha, UNM_CRB_PEG_NET_1 + 0x3C, 0x1);
	ql_8021_wr_32(ha, UNM_CRB_PEG_NET_2 + 0x3C, 0x1);
	ql_8021_wr_32(ha, UNM_CRB_PEG_NET_3 + 0x3C, 0x1);
	ql_8021_wr_32(ha, UNM_CRB_PEG_NET_4 + 0x3C, 0x1);
	delay(1);

	ret = ql_8021_pinit_from_rom(ha);
	if (ret) {
		EL(ha, "pinit_from_rom ret=%d\n", ret);
		return (ret);
	}
	delay(1);

	/* Bring QM and CAMRAM out of reset */
	ql_8021_rd_32(ha, UNM_ROMUSB_GLB_SW_RESET, &rst);
	rst &= ~((1 << 28) | (1 << 24));
	ql_8021_wr_32(ha, UNM_ROMUSB_GLB_SW_RESET, rst);

	switch (type) {
	case 0:
		ret = ql_8021_init_p3p(ha);
		break;
	case 1:
		ret = ql_8021_load_from_flash(ha);
		break;
	case 2:
		ret = ql_8021_load_firmware(ha);
		break;
	}
	delay(1);

	ql_8021_wr_32(ha, UNM_CRB_PEG_NET_0 + 0x18, 0x1020);
	ql_8021_wr_32(ha, UNM_ROMUSB_GLB_SW_RESET, 0x80001e);

	if (ret) {
		EL(ha, "type=%d, ret=%d\n", type, ret);
	} else {
		ret = ql_8021_phantom_init(ha);
	}
	return (ret);
}

static int
ql_8021_load_fw(ql_adapter_state_t *ha)
{
	int	rv = 0;

	GLOBAL_HW_LOCK();
	if (ha->risc_fw[0].code) {
		EL(ha, "from driver\n");
		rv = ql_8021_reset_hw(ha, 2);
	} else {
		/*
		 * BIOS method
		 * ql_8021_reset_hw(ha, 0)
		 */
		EL(ha, "from flash\n");
		rv = ql_8021_reset_hw(ha, 1);
	}
	if (rv == 0) {
		ql_8021_wr_32(ha, CRB_DMA_SHIFT, 0x55555555);
		ql_8021_wr_32(ha, UNM_PEG_HALT_STATUS1, 0x0);
		ql_8021_wr_32(ha, UNM_PEG_HALT_STATUS2, 0x0);

		GLOBAL_HW_UNLOCK();

		ADAPTER_STATE_LOCK(ha);
		ha->flags &= ~INTERRUPTS_ENABLED;
		ADAPTER_STATE_UNLOCK(ha);

		/* clear the mailbox command pointer. */
		INTR_LOCK(ha);
		ha->mcp = NULL;
		INTR_UNLOCK(ha);

		MBX_REGISTER_LOCK(ha);
		ha->mailbox_flags = (uint8_t)(ha->mailbox_flags &
		    ~(MBX_BUSY_FLG | MBX_WANT_FLG | MBX_ABORT | MBX_INTERRUPT));
		MBX_REGISTER_UNLOCK(ha);

		(void) ql_8021_enable_intrs(ha);

		ADAPTER_STATE_LOCK(ha);
		ha->flags |= INTERRUPTS_ENABLED;
		ADAPTER_STATE_UNLOCK(ha);
	} else {
		GLOBAL_HW_UNLOCK();
	}

	if (rv == 0) {
		ql_8021_rd_32(ha, UNM_FW_VERSION_MAJOR, &ha->fw_major_version);
		ql_8021_rd_32(ha, UNM_FW_VERSION_MINOR, &ha->fw_minor_version);
		ql_8021_rd_32(ha, UNM_FW_VERSION_SUB, &ha->fw_subminor_version);
		EL(ha, "fw v%d.%02d.%02d\n", ha->fw_major_version,
		    ha->fw_minor_version, ha->fw_subminor_version);
	} else {
		EL(ha, "status = -1\n");
	}

	return (rv);
}

void
ql_8021_clr_hw_intr(ql_adapter_state_t *ha)
{
	ql_8021_wr_32(ha, ha->nx_legacy_intr.tgt_status_reg, 0xffffffff);
	ql_8021_rd_32(ha, ISR_INT_VECTOR, NULL);
	ql_8021_rd_32(ha, ISR_INT_VECTOR, NULL);
}

void
ql_8021_clr_fw_intr(ql_adapter_state_t *ha)
{
	WRT32_IO_REG(ha, nx_risc_int, 0);
	ql_8021_wr_32(ha, ha->nx_legacy_intr.tgt_status_reg, 0xfbff);
}

void
ql_8021_enable_intrs(ql_adapter_state_t *ha)
{
	GLOBAL_HW_LOCK();
	ql_8021_wr_32(ha, ha->nx_legacy_intr.tgt_mask_reg, 0xfbff);
	GLOBAL_HW_UNLOCK();
	if (!(ha->task_daemon_flags & ISP_ABORT_NEEDED)) {
		(void) ql_toggle_interrupt(ha, 1);
	}
}

void
ql_8021_disable_intrs(ql_adapter_state_t *ha)
{
	(void) ql_toggle_interrupt(ha, 0);
	GLOBAL_HW_LOCK();
	ql_8021_wr_32(ha, ha->nx_legacy_intr.tgt_mask_reg, 0x0400);
	GLOBAL_HW_UNLOCK();
}

void
ql_8021_update_crb_int_ptr(ql_adapter_state_t *ha)
{
	struct legacy_intr_set	*nx_legacy_intr;

	ha->qdr_sn_window = (uint32_t)-1;
	nx_legacy_intr = &legacy_intr[ha->pci_function_number];

	ha->nx_legacy_intr.int_vec_bit = nx_legacy_intr->int_vec_bit;
	ha->nx_legacy_intr.tgt_status_reg = nx_legacy_intr->tgt_status_reg;
	ha->nx_legacy_intr.tgt_mask_reg = nx_legacy_intr->tgt_mask_reg;
	ha->nx_legacy_intr.pci_int_reg = nx_legacy_intr->pci_int_reg;
}

void
ql_8021_set_drv_active(ql_adapter_state_t *ha)
{
	uint32_t	val;

	if (ql_8021_hw_lock(ha, IDC_LOCK_TIMEOUT)) {
		return;
	}

	ql_8021_rd_32(ha, CRB_DRV_ACTIVE, &val);
	if (val == 0xffffffff) {
		val = (1 << (ha->pci_function_number * 4));
	} else {
		val |= (1 << (ha->pci_function_number * 4));
	}
	ql_8021_wr_32(ha, CRB_DRV_ACTIVE, val);

	ql_8021_hw_unlock(ha);
}

void
ql_8021_clr_drv_active(ql_adapter_state_t *ha)
{
	uint32_t	val;

	if (ql_8021_hw_lock(ha, IDC_LOCK_TIMEOUT)) {
		return;
	}

	ql_8021_rd_32(ha, CRB_DRV_ACTIVE, &val);
	val &= ~(1 << (ha->pci_function_number * 4));
	ql_8021_wr_32(ha, CRB_DRV_ACTIVE, val);

	ql_8021_hw_unlock(ha);
}

static void
ql_8021_need_reset_handler(ql_adapter_state_t *ha)
{
	uint32_t	drv_state, drv_active, cnt;

	ql_8021_rd_32(ha, CRB_DRV_STATE, &drv_state);
	if (drv_state == 0xffffffff) {
		drv_state = 0;
	}
	if (!(ha->ql_dump_state & QL_DUMPING)) {
		drv_state |= (1 << (ha->pci_function_number * 4));
	}
	ql_8021_wr_32(ha, CRB_DRV_STATE, drv_state);

	for (cnt = 60; cnt; cnt--) {
		ql_8021_hw_unlock(ha);
		delay(100);
		(void) ql_8021_hw_lock(ha, IDC_LOCK_TIMEOUT);

		ql_8021_rd_32(ha, CRB_DRV_STATE, &drv_state);
		ql_8021_rd_32(ha, CRB_DRV_ACTIVE, &drv_active);
		if (ha->ql_dump_state & QL_DUMPING) {
			drv_state |= (1 << (ha->pci_function_number * 4));
		}
		if (drv_state == drv_active) {
			if (ha->ql_dump_state & QL_DUMPING) {
				ql_8021_wr_32(ha, CRB_DRV_STATE, drv_state);
			}
			break;
		}
	}
}

int
ql_8021_fw_reload(ql_adapter_state_t *ha)
{
	int	rval;

	(void) ql_stall_driver(ha, BIT_0);

	(void) ql_8021_hw_lock(ha, IDC_LOCK_TIMEOUT);
	ql_8021_wr_32(ha, CRB_DEV_STATE, NX_DEV_INITIALIZING);
	ql_8021_hw_unlock(ha);

	rval = ql_8021_load_fw(ha) == 0 ? NX_DEV_READY : NX_DEV_FAILED;

	(void) ql_8021_hw_lock(ha, IDC_LOCK_TIMEOUT);
	ql_8021_wr_32(ha, CRB_DEV_STATE, rval);
	ql_8021_hw_unlock(ha);

	TASK_DAEMON_LOCK(ha);
	ha->task_daemon_flags &= ~(TASK_DAEMON_STALLED_FLG | DRIVER_STALL);
	TASK_DAEMON_UNLOCK(ha);

	if (rval != NX_DEV_READY) {
		EL(ha, "status=%xh\n", QL_FUNCTION_FAILED);
		return (QL_FUNCTION_FAILED);
	}
	return (QL_SUCCESS);
}

void
ql_8021_idc_poll(ql_adapter_state_t *ha)
{
	uint32_t	new_state;

	if (ha->ql_dump_state & QL_DUMPING) {
		return;
	}
	new_state = ql_8021_check_fw_alive(ha);

	if (new_state == NX_DEV_NEED_RESET &&
	    !(ha->ql_dump_state & QL_DUMPING ||
	    (ha->ql_dump_state & QL_DUMP_VALID &&
	    !(ha->ql_dump_state & QL_DUMP_UPLOADED)))) {
		(void) ql_dump_firmware(ha);
	} else {
		(void) ql_8021_idc_handler(ha, new_state);
	}
}

int
ql_8021_idc_handler(ql_adapter_state_t *ha, uint32_t new_state)
{
	int		rval;
	uint32_t	dev_state, drv_state, loop;
	ql_mbx_data_t	mr;
	boolean_t	stalled = B_FALSE, reset_needed = B_FALSE;
	boolean_t	force_load = B_FALSE;

	(void) ql_8021_hw_lock(ha, IDC_LOCK_TIMEOUT);

	/* wait for 180 seconds for device to go ready */
	for (loop = 180; loop; loop--) {
		if (new_state != NX_DEV_POLL) {
			ql_8021_wr_32(ha, CRB_DEV_STATE, new_state);
			dev_state = new_state;
			new_state = NX_DEV_POLL;
		} else {
			ql_8021_rd_32(ha, CRB_DEV_STATE, &dev_state);
		}

		switch (dev_state) {
		case 0xffffffff:
		case NX_DEV_COLD:
			if (ha->dev_state != dev_state) {
				EL(ha, "dev_state=NX_DEV_COLD\n");
			}
			rval = NX_DEV_COLD;
			ql_8021_wr_32(ha, CRB_DEV_STATE, NX_DEV_INITIALIZING);
			ql_8021_wr_32(ha, CRB_DRV_IDC_VERSION, NX_IDC_VERSION);
			ql_8021_hw_unlock(ha);
			if (!force_load &&
			    ql_get_fw_version(ha, &mr, 2) == QL_SUCCESS &&
			    (mr.mb[1] | mr.mb[2] | mr.mb[3])) {
				ql_8021_rd_32(ha, UNM_FW_VERSION_MAJOR,
				    &ha->fw_major_version);
				ql_8021_rd_32(ha, UNM_FW_VERSION_MINOR,
				    &ha->fw_minor_version);
				ql_8021_rd_32(ha, UNM_FW_VERSION_SUB,
				    &ha->fw_subminor_version);
				rval = NX_DEV_READY;
			} else {
				if (!stalled) {
					TASK_DAEMON_LOCK(ha);
					ha->task_daemon_flags |=
					    TASK_DAEMON_STALLED_FLG;
					TASK_DAEMON_UNLOCK(ha);
					ql_abort_queues(ha);
					stalled = B_TRUE;
				}
				if (ha->ql_dump_state & QL_DUMPING) {
					(void) ql_8021_get_fw_dump(ha);
				}
				rval = ql_8021_load_fw(ha) == 0 ?
				    NX_DEV_READY : NX_DEV_FAILED;
			}
			(void) ql_8021_hw_lock(ha, IDC_LOCK_TIMEOUT);
			ql_8021_wr_32(ha, CRB_DEV_STATE, rval);
			break;
		case NX_DEV_READY:
			if (ha->dev_state != dev_state) {
				EL(ha, "dev_state=NX_DEV_READY\n");
			}
			rval = NX_DEV_READY;
			loop = 1;
			break;
		case NX_DEV_FAILED:
			if (ha->dev_state != dev_state) {
				EL(ha, "dev_state=NX_DEV_FAILED\n");
			}
			rval = NX_DEV_FAILED;
			loop = 1;
			break;
		case NX_DEV_NEED_RESET:
			if (ha->dev_state != dev_state) {
				EL(ha, "dev_state=NX_DEV_NEED_RESET\n");
			}
			rval = NX_DEV_NEED_RESET;
			ql_8021_need_reset_handler(ha);
			/*
			 * Force to DEV_COLD unless someone else is starting
			 * a reset
			 */
			ql_8021_rd_32(ha, CRB_DEV_STATE, &dev_state);
			if (dev_state == NX_DEV_NEED_RESET) {
				EL(ha, "HW State: COLD/RE-INIT\n");
				ql_8021_wr_32(ha, CRB_DEV_STATE, NX_DEV_COLD);
				force_load = B_TRUE;
			}
			reset_needed = B_TRUE;
			break;
		case NX_DEV_NEED_QUIESCENT:
			if (ha->dev_state != dev_state) {
				EL(ha, "dev_state=NX_DEV_NEED_QUIESCENT\n");
			}
			ql_8021_rd_32(ha, CRB_DRV_STATE, &drv_state);
			drv_state |= (2 << (ha->pci_function_number * 4));
			ql_8021_wr_32(ha, CRB_DRV_STATE, drv_state);
			ql_8021_hw_unlock(ha);
			if (!stalled) {
				TASK_DAEMON_LOCK(ha);
				ha->task_daemon_flags |=
				    TASK_DAEMON_STALLED_FLG;
				TASK_DAEMON_UNLOCK(ha);
				(void) ql_stall_driver(ha, BIT_0);
				stalled = B_TRUE;
			}
			(void) ql_8021_hw_lock(ha, IDC_LOCK_TIMEOUT);
			break;
		case NX_DEV_INITIALIZING:
			if (ha->dev_state != dev_state) {
				EL(ha, "dev_state=NX_DEV_INITIALIZING\n");
			}
			ql_8021_hw_unlock(ha);
			if (!stalled) {
				TASK_DAEMON_LOCK(ha);
				ha->task_daemon_flags |=
				    TASK_DAEMON_STALLED_FLG;
				TASK_DAEMON_UNLOCK(ha);
				ql_awaken_task_daemon(ha, NULL,
				    DRIVER_STALL, 0);
				stalled = B_TRUE;
				ql_requeue_all_cmds(ha);
				ADAPTER_STATE_LOCK(ha);
				ha->flags &= ~INTERRUPTS_ENABLED;
				ADAPTER_STATE_UNLOCK(ha);
			}
			delay(100);
			(void) ql_8021_hw_lock(ha, IDC_LOCK_TIMEOUT);
			reset_needed = B_TRUE;
			break;
		case NX_DEV_QUIESCENT:
			if (ha->dev_state != dev_state) {
				EL(ha, "dev_state=NX_DEV_QUIESCENT\n");
			}
			ql_8021_hw_unlock(ha);
			delay(100);
			(void) ql_8021_hw_lock(ha, IDC_LOCK_TIMEOUT);
			break;
		default:
			if (ha->dev_state != dev_state) {
				EL(ha, "dev_state=%x, default\n", dev_state);
			}
			ql_8021_hw_unlock(ha);
			delay(100);
			(void) ql_8021_hw_lock(ha, IDC_LOCK_TIMEOUT);
			break;
		}
		ha->dev_state = dev_state;
	}

	/* Clear reset ready and quiescent flags. */
	ql_8021_rd_32(ha, CRB_DRV_STATE, &drv_state);
	drv_state &= ~(1 << (ha->pci_function_number * 4));
	drv_state &= ~(2 << (ha->pci_function_number * 4));
	ql_8021_wr_32(ha, CRB_DRV_STATE, drv_state);

	ql_8021_hw_unlock(ha);
	if (reset_needed && ha->flags & ONLINE &&
	    !(ha->task_daemon_flags & ABORT_ISP_ACTIVE)) {
		delay(100);
		ql_awaken_task_daemon(ha, NULL, ISP_ABORT_NEEDED, 0);
	}
	if (stalled) {
		TASK_DAEMON_LOCK(ha);
		ha->task_daemon_flags &= ~TASK_DAEMON_STALLED_FLG;
		TASK_DAEMON_UNLOCK(ha);
		ql_restart_driver(ha);
	}
	return (rval);
}

void
ql_8021_wr_req_in(ql_adapter_state_t *ha, uint32_t index)
{
	index = index << 16 | ha->pci_function_number << 5 | 4;

	if (NX_IS_REVISION_P3PLUS_B0(ha->rev_id)) {
		uint64_t	addr;

		addr = ha->function_number ? (uint64_t)CRB_PORT_1_REQIN :
		    (uint64_t)CRB_PORT_0_REQIN;
		ql_8021_wr_32(ha, addr, index);
	} else {
		do {
			ddi_put32(ha->db_dev_handle, ha->nx_req_in, index);
		} while (RD_REG_DWORD(ha, ha->db_read) != index);
	}
}

/* Called every 2 seconds */
static uint32_t
ql_8021_check_fw_alive(ql_adapter_state_t *ha)
{
	uint32_t	dev_state, fw_heartbeat_counter, cnt, data[7];
	uint32_t	new_state = NX_DEV_POLL;

	ql_8021_rd_32(ha, CRB_DEV_STATE, &dev_state);
	if (dev_state != NX_DEV_READY) {
		return (new_state);
	}

	ql_8021_rd_32(ha, UNM_PEG_ALIVE_COUNTER, &fw_heartbeat_counter);

	if (ha->fw_heartbeat_counter == fw_heartbeat_counter) {
		ha->seconds_since_last_heartbeat++;
		/* FW not alive after 6 seconds */
		if (ha->seconds_since_last_heartbeat == 3) {
			ha->seconds_since_last_heartbeat = 0;
			/* FW not alive after 5 milliseconds */
			for (cnt = 5; cnt; cnt--) {
				ql_8021_rd_32(ha, UNM_PEG_ALIVE_COUNTER,
				    &fw_heartbeat_counter);
				if (ha->fw_heartbeat_counter !=
				    fw_heartbeat_counter) {
					break;
				}
				drv_usecwait(1000);
			}
			if (ha->fw_heartbeat_counter == fw_heartbeat_counter) {
				EL(ha, "nx_dev_need_reset\n");
				ql_8021_rd_32(ha, UNM_PEG_HALT_STATUS1,
				    &data[0]);
				ql_8021_rd_32(ha, UNM_PEG_HALT_STATUS2,
				    &data[1]);
				ql_8021_rd_32(ha, UNM_CRB_PEG_NET_0 + 0x3C,
				    &data[2]);
				ql_8021_rd_32(ha, UNM_CRB_PEG_NET_1 + 0x3C,
				    &data[3]);
				ql_8021_rd_32(ha, UNM_CRB_PEG_NET_2 + 0x3C,
				    &data[4]);
				ql_8021_rd_32(ha, UNM_CRB_PEG_NET_3 + 0x3C,
				    &data[5]);
				ql_8021_rd_32(ha, UNM_CRB_PEG_NET_4 + 0x3C,
				    &data[6]);
				EL(ha, "halt_status1=%xh, halt_status2=%xh,\n"
				    "peg_pc0=%xh, peg_pc1=%xh, peg_pc2=%xh, "
				    "peg_pc3=%xh, peg_pc4=%xh\n", data[0],
				    data[1], data[2], data[3], data[4],
				    data[5], data[6]);
				new_state = NX_DEV_NEED_RESET;
			}
		}
	} else {
		ha->seconds_since_last_heartbeat = 0;
	}

	ha->fw_heartbeat_counter = fw_heartbeat_counter;
	return (new_state);
}

int
ql_8021_reset_fw(ql_adapter_state_t *ha)
{
	return (ql_8021_idc_handler(ha, NX_DEV_NEED_RESET));
}

int
ql_8021_fw_chk(ql_adapter_state_t *ha)
{
	uint32_t	dev_state, new_state = NX_DEV_POLL;
	int		rval;
	ql_mbx_data_t	mr;

	ql_8021_rd_32(ha, CRB_DEV_STATE, &dev_state);
	switch (dev_state) {
	case 0xffffffff:
	case NX_DEV_COLD:
	case NX_DEV_NEED_RESET:
	case NX_DEV_NEED_QUIESCENT:
	case NX_DEV_INITIALIZING:
	case NX_DEV_QUIESCENT:
	case NX_DEV_BADOBADO:
		break;
	case NX_DEV_READY:
		if (ql_get_fw_version(ha, &mr, 2) != QL_SUCCESS ||
		    (mr.mb[1] | mr.mb[2] | mr.mb[3]) == 0) {
			EL(ha, "version check needs reset\n", dev_state);
			new_state = NX_DEV_NEED_RESET;
		}
		break;
	case NX_DEV_FAILED:
		EL(ha, "device needs reset\n");
		new_state = NX_DEV_NEED_RESET;
		break;
	default:
		EL(ha, "state=%xh needs reset\n", dev_state);
		new_state = NX_DEV_COLD;
		break;
	}

	/* Test for firmware running. */
	rval = ql_8021_idc_handler(ha, new_state) == NX_DEV_READY ?
	    QL_SUCCESS : QL_FUNCTION_FAILED;

	return (rval);
}

/* ****************************************************************** */
/* ***************** NetXen MiniDump Functions ********************** */
/* ****************************************************************** */

/*
 * ql_8021_get_fw_dump
 *
 * Input:
 *	pi:	FC port info pointer.
 *
 * Returns:
 *	qla driver local function return status codes
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
static int
ql_8021_get_fw_dump(ql_adapter_state_t *ha)
{
	uint32_t	tsize, cnt, *dp, *bp;

	QL_PRINT_10(ha, "started\n");

	tsize = ha->dmp_template.size;
	cnt = (uint32_t)(tsize / sizeof (uint32_t));
	dp = (uint32_t *)ha->ql_dump_ptr;
	bp = (uint32_t *)ha->dmp_template.bp;
	while (cnt--) {
		*dp++ = ddi_get32(ha->dmp_template.acc_handle, bp++);
	}
	ql_8021_md_parse_template(ha, ha->ql_dump_ptr, (caddr_t)dp,
	    ha->md_capture_size - tsize, ha->md_capture_mask);

#ifdef _BIG_ENDIAN
	cnt = (uint32_t)(ha->ql_dump_size / sizeof (uint32_t));
	dp = (uint32_t *)ha->ql_dump_ptr;
	while (cnt--) {
		ql_chg_endian((uint8_t *)dp, 4);
		dp++;
	}
#endif
	QL_PRINT_10(ha, "done\n");
	return (QL_SUCCESS);
}

/*
 * ql_8021_get_md_template
 *	Get mini-dump template
 *
 * Input:
 *	ha:	adapter state pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_8021_get_md_template(ql_adapter_state_t *ha)
{
	ql_mbx_data_t	mr;
	uint32_t	tsize, chksum;
	int		rval;

	rval = ql_get_md_template(ha, NULL, &mr, 0, GTO_TEMPLATE_SIZE);
	if (rval != QL_SUCCESS ||
	    (tsize = SHORT_TO_LONG(mr.mb[2], mr.mb[3])) == 0) {
		EL(ha, "size=%xh status=%xh\n", tsize, rval);
		ha->md_capture_size = 0;
		ql_free_phys(ha, &ha->dmp_template);
		return (rval);
	}
	if (ha->dmp_template.dma_handle && ha->dmp_template.size != tsize) {
		ql_free_phys(ha, &ha->dmp_template);
	}
	ha->md_capture_mask = 0x1f;
	ha->md_capture_size = SHORT_TO_LONG(mr.mb[4], mr.mb[5]) +
	    SHORT_TO_LONG(mr.mb[6], mr.mb[7]) +
	    SHORT_TO_LONG(mr.mb[8], mr.mb[9]) +
	    SHORT_TO_LONG(mr.mb[10], mr.mb[11]) + tsize;
	/*
	 * Determine ascii dump file size
	 * 2 ascii bytes per binary byte + a space and
	 * a newline every 16 binary bytes
	 */
	ha->risc_dump_size = ha->md_capture_size << 1;
	ha->risc_dump_size += ha->md_capture_size;
	ha->risc_dump_size += ha->md_capture_size / 16 + 1;

	/* Allocate template buffer. */
	if (ha->dmp_template.dma_handle == NULL) {
		rval = ql_get_dma_mem(ha, &ha->dmp_template, tsize,
		    LITTLE_ENDIAN_DMA, QL_DMA_RING_ALIGN);
		if (rval != QL_SUCCESS) {
			EL(ha, "unable to allocate template buffer, "
			    "status=%xh\n", rval);
			ha->md_capture_size = 0;
			ql_free_phys(ha, &ha->dmp_template);
			return (rval);
		}
	}
	rval = ql_get_md_template(ha, &ha->dmp_template, &mr, 0, GTO_TEMPLATE);
	if (rval != QL_SUCCESS ||
	    (chksum = ql_8021_md_template_checksum(ha))) {
		EL(ha, "status=%xh, chksum=%xh\n", rval, chksum);
		if (rval == QL_SUCCESS) {
			rval = QL_FUNCTION_FAILED;
		}
		ql_free_phys(ha, &ha->dmp_template);
		ha->md_capture_size = 0;
	}

	return (rval);
}

static void
ql_8021_md_parse_template(ql_adapter_state_t *ha, caddr_t template_buff,
    caddr_t dump_buff, uint32_t buff_size, uint32_t capture_mask)
{
	int			e_cnt, buff_level, esize;
	uint32_t		num_of_entries;
	time_t			time;
	caddr_t			dbuff;
	int			sane_start = 0, sane_end = 0;
	md_template_hdr_t	*template_hdr;
	md_entry_t		*entry;

	if ((capture_mask & 0x3) != 0x3) {
		EL(ha, "capture mask %02xh below minimum needed for valid "
		    "dump\n", capture_mask);
		return;
	}
	/* Setup parameters */
	template_hdr = (md_template_hdr_t *)template_buff;
	if (template_hdr->entry_type == TLHDR) {
		sane_start = 1;
	}
	(void) drv_getparm(TIME, &time);
	template_hdr->driver_timestamp = LSD(time);
	template_hdr->driver_capture_mask = capture_mask;
	num_of_entries = template_hdr->num_of_entries;
	entry = (md_entry_t *)((caddr_t)template_buff +
	    template_hdr->first_entry_offset);
	for (buff_level = 0, e_cnt = 0; e_cnt < num_of_entries; e_cnt++) {
		/*
		 * If the capture_mask of the entry does not match capture mask
		 * skip the entry after marking the driver_flags indicator.
		 */
		if (!(entry->h.a.ecw.entry_capture_mask & capture_mask)) {
			entry->h.a.ecw.driver_flags = (uint8_t)
			    (entry->h.a.ecw.driver_flags |
			    QL_DBG_SKIPPED_FLAG);
			entry = (md_entry_t *)((char *)entry +
			    entry->h.entry_size);
			continue;
		}
		/*
		 * This is ONLY needed in implementations where
		 * the capture buffer allocated is too small to capture
		 * all of the required entries for a given capture mask.
		 * We need to empty the buffer contents to a file
		 * if possible, before processing the next entry
		 * If the buff_full_flag is set, no further capture will
		 * happen and all remaining non-control entries will be
		 * skipped.
		 */
		if (entry->h.entry_capture_size != 0) {
			if ((buff_level + entry->h.entry_capture_size) >
			    buff_size) {
				entry = (md_entry_t *)((char *)entry +
				    entry->h.entry_size);
				continue;
			}
		}
		/*
		 * Decode the entry type and process it accordingly
		 */
		switch (entry->h.entry_type) {
		case RDNOP:
			break;
		case RDEND:
			sane_end += 1;
			break;
		case RDCRB:
			dbuff = dump_buff + buff_level;
			esize = ql_8021_md_rdcrb(ha, (void *)entry,
			    (void *)dbuff);
			ql_8021_md_entry_err_chk(ha, entry, esize, e_cnt);
			buff_level += esize;
			break;
		case L2ITG:
		case L2DTG:
		case L2DAT:
		case L2INS:
			dbuff = dump_buff + buff_level;
			esize = ql_8021_md_L2Cache(ha, (void *)entry,
			    (void *)dbuff);
			if (esize == -1) {
				entry->h.a.ecw.driver_flags = (uint8_t)
				    (entry->h.a.ecw.driver_flags |
				    QL_DBG_SKIPPED_FLAG);
			} else {
				ql_8021_md_entry_err_chk(ha, entry, esize,
				    e_cnt);
				buff_level += esize;
			}
			break;
		case L1DAT:
		case L1INS:
			dbuff = dump_buff + buff_level;
			esize = ql_8021_md_L1Cache(ha, (void *)entry,
			    (void *)dbuff);
			ql_8021_md_entry_err_chk(ha, entry, esize, e_cnt);
			buff_level += esize;
			break;
		case RDOCM:
			dbuff = dump_buff + buff_level;
			esize = ql_8021_md_rdocm(ha, (void *)entry,
			    (void *)dbuff);
			ql_8021_md_entry_err_chk(ha, entry, esize, e_cnt);
			buff_level += esize;
			break;
		case RDMEM:
			dbuff = dump_buff + buff_level;
			esize = ql_8021_md_rdmem(ha, (void *)entry,
			    (void *)dbuff);
			ql_8021_md_entry_err_chk(ha, entry, esize, e_cnt);
			buff_level += esize;
			break;
		case BOARD:
		case RDROM:
			dbuff = dump_buff + buff_level;
			esize = ql_8021_md_rdrom(ha, (void *)entry,
			    (void *)dbuff);
			ql_8021_md_entry_err_chk(ha, entry, esize, e_cnt);
			buff_level += esize;
			break;
		case RDMUX:
			dbuff = dump_buff + buff_level;
			esize = ql_8021_md_rdmux(ha, (void *)entry,
			    (void *)dbuff);
			ql_8021_md_entry_err_chk(ha, entry, esize, e_cnt);
			buff_level += esize;
			break;
		case QUEUE:
			dbuff = dump_buff + buff_level;
			esize = ql_8021_md_rdqueue(ha, (void *)entry,
			    (void *)dbuff);
			ql_8021_md_entry_err_chk(ha, entry, esize, e_cnt);
			buff_level += esize;
			break;
		case CNTRL:
			if (ql_8021_md_cntrl(ha, template_hdr,
			    (void *)entry)) {
				entry->h.a.ecw.driver_flags = (uint8_t)
				    (entry->h.a.ecw.driver_flags |
				    QL_DBG_SKIPPED_FLAG);
				EL(ha, "Entry ID=%d, entry_type=%d non zero "
				    "status\n", e_cnt, entry->h.entry_type);
			}
			break;
		default:
			entry->h.a.ecw.driver_flags = (uint8_t)
			    (entry->h.a.ecw.driver_flags |
			    QL_DBG_SKIPPED_FLAG);
			EL(ha, "Entry ID=%d, entry_type=%d unknown\n", e_cnt,
			    entry->h.entry_type);
			break;
		}
		/* next entry in the template */
		entry = (md_entry_t *)((caddr_t)entry + entry->h.entry_size);
	}
	if (!sane_start || (sane_end > 1)) {
		EL(ha, "Template configuration error. Check Template\n");
	}
	QL_PRINT_10(ha, "Minidump num of entries=%d\n",
	    template_hdr->num_of_entries);
}

/*
 * Read CRB operation.
 */
static int
ql_8021_md_rdcrb(ql_adapter_state_t *ha, md_entry_rdcrb_t *crbEntry,
    uint32_t *data_buff)
{
	uint32_t	loop_cnt, op_count, addr, stride, value;
	int		i;

	addr = crbEntry->addr;
	op_count = crbEntry->op_count;
	stride = crbEntry->a.ac.addr_stride;

	for (loop_cnt = 0; loop_cnt < op_count; loop_cnt++) {
		value = ql_8021_read_reg(ha, addr);
		*data_buff++ = addr;
		*data_buff++ = value;
		addr = addr + stride;
	}

	/*
	 * for testing purpose we return amount of data written
	 */
	i = (int)(loop_cnt * (2 * sizeof (uint32_t)));

	return (i);
}

/*
 * Handle L2 Cache.
 */
static int
ql_8021_md_L2Cache(ql_adapter_state_t *ha, md_entry_cache_t *cacheEntry,
    uint32_t *data_buff)
{
	int			i, k, tflag;
	uint32_t		read_value, loop_cnt, read_cnt;
	uint32_t		addr, read_addr, cntrl_addr, tag_reg_addr;
	uint32_t		cntl_value_w, tag_value, tag_value_stride;
	volatile uint8_t	cntl_value_r;
	clock_t			timeout, elapsed;

	read_addr = cacheEntry->read_addr;
	loop_cnt = cacheEntry->op_count;
	cntrl_addr = cacheEntry->control_addr;
	cntl_value_w = CHAR_TO_SHORT(cacheEntry->b.cv.write_value[0],
	    cacheEntry->b.cv.write_value[1]);
	tag_reg_addr = cacheEntry->tag_reg_addr;
	tag_value = CHAR_TO_SHORT(cacheEntry->a.sac.init_tag_value[0],
	    cacheEntry->a.sac.init_tag_value[1]);
	tag_value_stride = CHAR_TO_SHORT(cacheEntry->a.sac.tag_value_stride[0],
	    cacheEntry->a.sac.tag_value_stride[1]);
	read_cnt = cacheEntry->c.rac.read_addr_cnt;

	for (i = 0; i < loop_cnt; i++) {
		ql_8021_write_reg(ha, tag_value, tag_reg_addr);
		if (cntl_value_w) {
			ql_8021_write_reg(ha, cntl_value_w, cntrl_addr);
		}
		if (cacheEntry->b.cv.poll_wait) {
			(void) drv_getparm(LBOLT, &timeout);
			timeout += drv_usectohz(cacheEntry->b.cv.poll_wait *
			    1000) + 1;
			cntl_value_r = (uint8_t)ql_8021_read_reg(ha,
			    cntrl_addr);
			tflag = 0;
			while (!tflag && ((cntl_value_r &
			    cacheEntry->b.cv.poll_mask) != 0)) {
				(void) drv_getparm(LBOLT, &elapsed);
				if (elapsed > timeout) {
					tflag = 1;
				}
				cntl_value_r = (uint8_t)ql_8021_read_reg(ha,
				    cntrl_addr);
			}
			if (tflag) {
				/*
				 *  Report timeout error.  core dump capture
				 *  failed
				 *  Skip remaining entries. Write buffer out
				 *  to file
				 *  Use driver specific fields in template
				 *  header
				 *  to report this error.
				 */
				EL(ha, "timeout\n");
				return (-1);
			}
		}
		addr = read_addr;
		for (k = 0; k < read_cnt; k++) {
			read_value = ql_8021_read_reg(ha, addr);
			*data_buff++ = read_value;
			addr += cacheEntry->c.rac.read_addr_stride;
		}
		tag_value += tag_value_stride;
	}
	i = (int)(read_cnt * loop_cnt * sizeof (uint32_t));

	return (i);
}

/*
 * Handle L1 Cache.
 */
static int
ql_8021_md_L1Cache(ql_adapter_state_t *ha, md_entry_cache_t *cacheEntry,
    uint32_t *data_buff)
{
	int			i, k;
	uint32_t		read_value, tag_value, tag_value_stride;
	uint32_t		read_cnt, loop_cnt;
	uint32_t		addr, read_addr, cntrl_addr, tag_reg_addr;
	volatile uint32_t	cntl_value_w;

	read_addr = cacheEntry->read_addr;
	loop_cnt = cacheEntry->op_count;
	cntrl_addr = cacheEntry->control_addr;
	cntl_value_w = CHAR_TO_SHORT(cacheEntry->b.cv.write_value[0],
	    cacheEntry->b.cv.write_value[1]);
	tag_reg_addr = cacheEntry->tag_reg_addr;
	tag_value = CHAR_TO_SHORT(cacheEntry->a.sac.init_tag_value[0],
	    cacheEntry->a.sac.init_tag_value[1]);
	tag_value_stride = CHAR_TO_SHORT(cacheEntry->a.sac.tag_value_stride[0],
	    cacheEntry->a.sac.tag_value_stride[1]);
	read_cnt = cacheEntry->c.rac.read_addr_cnt;

	for (i = 0; i < loop_cnt; i++) {
		ql_8021_write_reg(ha, tag_value, tag_reg_addr);
		ql_8021_write_reg(ha, cntl_value_w, cntrl_addr);
		addr = read_addr;
		for (k = 0; k < read_cnt; k++) {
			read_value = ql_8021_read_reg(ha, addr);
			*data_buff++ = read_value;
			addr += cacheEntry->c.rac.read_addr_stride;
		}
		tag_value += tag_value_stride;
	}
	i = (int)(read_cnt * loop_cnt * sizeof (uint32_t));

	return (i);
}

/*
 * Reading OCM memory
 */
static int
ql_8021_md_rdocm(ql_adapter_state_t *ha, md_entry_rdocm_t *ocmEntry,
    uint32_t *data_buff)
{
	int		i;
	uint32_t	addr, value, loop_cnt;

	addr = ocmEntry->read_addr;
	loop_cnt = ocmEntry->op_count;

	for (i = 0; i < loop_cnt; i++) {
		value = ql_8021_read_ocm(ha, addr);
		*data_buff++ = value;
		addr += ocmEntry->read_addr_stride;
	}
	i = (int)(loop_cnt * sizeof (value));

	return (i);
}

/*
 * Read memory
 */
static int
ql_8021_md_rdmem(ql_adapter_state_t *ha, md_entry_rdmem_t *memEntry,
    uint32_t *data_buff)
{
	int		i, k;
	uint32_t	addr, value, loop_cnt;

	addr = memEntry->read_addr;
	loop_cnt = (uint32_t)(memEntry->read_data_size /
	    (sizeof (uint32_t) * 4));		/* size in bytes / 16 */

	ql_8021_write_reg(ha, 0, MD_MIU_TEST_AGT_ADDR_HI);
	for (i = 0; i < loop_cnt; i++) {
		/*
		 * Write address
		 */
		ql_8021_write_reg(ha, addr, MD_MIU_TEST_AGT_ADDR_LO);
		ql_8021_write_reg(ha, MD_TA_CTL_ENABLE,
		    MD_MIU_TEST_AGT_CTRL);
		ql_8021_write_reg(ha, (MD_TA_CTL_START | MD_TA_CTL_ENABLE),
		    MD_MIU_TEST_AGT_CTRL);
		/*
		 * Check busy bit.
		 */
		for (k = 0; k < MD_TA_CTL_CHECK; k++) {
			value = ql_8021_read_reg(ha, MD_MIU_TEST_AGT_CTRL);
			if ((value & MD_TA_CTL_BUSY) == 0) {
				break;
			}
		}
		if (k == MD_TA_CTL_CHECK) {
			i = (int)((uint_t)i * (sizeof (uint32_t) * 4));
			EL(ha, "failed to read=xh\n", i);
			return (i);
		}
		/*
		 * Read data
		 */
		value = ql_8021_read_reg(ha, MD_MIU_TEST_AGT_RDDATA_0_31);
		*data_buff++ = value;
		value = ql_8021_read_reg(ha, MD_MIU_TEST_AGT_RDDATA_32_63);
		*data_buff++ = value;
		value = ql_8021_read_reg(ha, MD_MIU_TEST_AGT_RDDATA_64_95);
		*data_buff++ = value;
		value = ql_8021_read_reg(ha, MD_MIU_TEST_AGT_RDDATA_96_127);
		*data_buff++ = value;
		/*
		 *  next address to read
		 */
		addr = (uint32_t)(addr + (sizeof (uint32_t) * 4));
	}
	i = (int)(loop_cnt * (sizeof (uint32_t) * 4));

	return (i);
}

/*
 * Read Rom
 */
static int
ql_8021_md_rdrom(ql_adapter_state_t *ha, md_entry_rdrom_t *romEntry,
    uint32_t *data_buff)
{
	int		i;
	uint32_t	addr, waddr, raddr, value, loop_cnt;

	addr = romEntry->read_addr;
	loop_cnt = romEntry->read_data_size;	/* This is size in bytes */
	loop_cnt = (uint32_t)(loop_cnt / sizeof (value));

	for (i = 0; i < loop_cnt; i++) {
		waddr = addr & 0xFFFF0000;
		(void) ql_8021_rom_lock(ha);
		ql_8021_write_reg(ha, waddr, MD_DIRECT_ROM_WINDOW);
		raddr = MD_DIRECT_ROM_READ_BASE + (addr & 0x0000FFFF);
		value = ql_8021_read_reg(ha, raddr);
		ql_8021_rom_unlock(ha);
		*data_buff++ = value;
		addr = (uint32_t)(addr + sizeof (value));
	}
	i = (int)(loop_cnt * sizeof (value));

	return (i);
}

/*
 * Read MUX data
 */
static int
ql_8021_md_rdmux(ql_adapter_state_t *ha, md_entry_mux_t *muxEntry,
    uint32_t *data_buff)
{
	uint32_t	read_value, sel_value, loop_cnt;
	uint32_t	read_addr, select_addr;
	int		i;

	select_addr = muxEntry->select_addr;
	sel_value = muxEntry->select_value;
	read_addr = muxEntry->read_addr;

	for (loop_cnt = 0; loop_cnt < muxEntry->op_count; loop_cnt++) {
		ql_8021_write_reg(ha, sel_value, select_addr);
		read_value = ql_8021_read_reg(ha, read_addr);
		*data_buff++ = sel_value;
		*data_buff++ = read_value;
		sel_value += muxEntry->select_value_stride;
	}
	i = (int)(loop_cnt * (2 * sizeof (uint32_t)));

	return (i);
}

/*
 * Handling Queue State Reads.
 */
static int
ql_8021_md_rdqueue(ql_adapter_state_t *ha, md_entry_queue_t *queueEntry,
    uint32_t *data_buff)
{
	int		k;
	uint32_t	read_value, read_addr, read_stride, select_addr;
	uint32_t	queue_id, loop_cnt, read_cnt;

	read_cnt = queueEntry->b.rac.read_addr_cnt;
	read_stride = queueEntry->b.rac.read_addr_stride;
	select_addr = queueEntry->select_addr;

	for (loop_cnt = 0, queue_id = 0; loop_cnt < queueEntry->op_count;
	    loop_cnt++) {
		ql_8021_write_reg(ha, queue_id, select_addr);
		read_addr = queueEntry->read_addr;
		for (k = 0; k < read_cnt; k++) {
			read_value = ql_8021_read_reg(ha, read_addr);
			*data_buff++ = read_value;
			read_addr += read_stride;
		}
		queue_id += CHAR_TO_SHORT(queueEntry->a.sac.queue_id_stride[0],
		    queueEntry->a.sac.queue_id_stride[1]);
	}
	k = (int)(loop_cnt * (read_cnt * sizeof (uint32_t)));

	return (k);
}

/*
 * Handling control entries.
 */
static int
ql_8021_md_cntrl(ql_adapter_state_t *ha, md_template_hdr_t *template_hdr,
    md_entry_cntrl_t *crbEntry)
{
	int		tflag;
	uint32_t	opcode, read_value, addr, entry_addr, loop_cnt;
	clock_t		timeout, elapsed;

	entry_addr = crbEntry->addr;

	for (loop_cnt = 0; loop_cnt < crbEntry->op_count; loop_cnt++) {
		opcode = crbEntry->b.cv.opcode;
		if (opcode & QL_DBG_OPCODE_WR) {
			ql_8021_write_reg(ha, crbEntry->value_1, entry_addr);
			opcode &= ~QL_DBG_OPCODE_WR;
		}
		if (opcode & QL_DBG_OPCODE_RW) {
			read_value = ql_8021_read_reg(ha, entry_addr);
			ql_8021_write_reg(ha, read_value, entry_addr);
			opcode &= ~QL_DBG_OPCODE_RW;
		}
		if (opcode & QL_DBG_OPCODE_AND) {
			read_value = ql_8021_read_reg(ha, entry_addr);
			read_value &= crbEntry->value_2;
			opcode &= ~QL_DBG_OPCODE_AND;

			/* Checking for OR here to avoid extra register write */
			if (opcode & QL_DBG_OPCODE_OR) {
				read_value |= crbEntry->value_3;
				opcode &= ~QL_DBG_OPCODE_OR;
			}
			ql_8021_write_reg(ha, read_value, entry_addr);
		}
		if (opcode & QL_DBG_OPCODE_OR) {
			read_value = ql_8021_read_reg(ha, entry_addr);
			read_value |= crbEntry->value_3;
			ql_8021_write_reg(ha, read_value, entry_addr);
			opcode &= ~QL_DBG_OPCODE_OR;
		}
		if (opcode & QL_DBG_OPCODE_POLL) {
			opcode &= ~QL_DBG_OPCODE_POLL;
			(void) drv_getparm(LBOLT, &timeout);
			timeout += drv_usectohz(
			    CHAR_TO_SHORT(crbEntry->a.ac.poll_timeout[0],
			    crbEntry->a.ac.poll_timeout[1]) * 1000) + 1;
			addr = entry_addr;
			read_value = ql_8021_read_reg(ha, addr);
			tflag = 0;
			while (!tflag && ((read_value & crbEntry->value_2) !=
			    crbEntry->value_1)) {
				(void) drv_getparm(LBOLT, &elapsed);
				if (elapsed > timeout) {
					tflag = 1;
				}
				read_value = ql_8021_read_reg(ha, addr);
			}
			if (tflag) {
				/*
				 *  Report timeout error.  core dump capture
				 *  failed Skip remaining entries. Write buffer
				 *  out to file Use driver specific fields in
				 *  template header to report this error.
				 */
				EL(ha, "timeout\n");
				return (-1);
			}
		}
		if (opcode & QL_DBG_OPCODE_RDSTATE) {
			/*
			 * decide which address to use.
			 */
			if (crbEntry->a.ac.state_index_a) {
				addr = template_hdr->saved_state_array[
				    crbEntry->a.ac.state_index_a];
			} else {
				addr = entry_addr;
			}
			read_value = ql_8021_read_reg(ha, addr);
			template_hdr->saved_state_array[
			    crbEntry->b.cv.state_index_v] = read_value;
			opcode &= ~QL_DBG_OPCODE_RDSTATE;
		}
		if (opcode & QL_DBG_OPCODE_WRSTATE) {
			/*
			 * decide which value to use.
			 */
			if (crbEntry->b.cv.state_index_v) {
				read_value = template_hdr->saved_state_array[
				    crbEntry->b.cv.state_index_v];
			} else {
				read_value = crbEntry->value_1;
			}
			/*
			 * decide which address to use.
			 */
			if (crbEntry->a.ac.state_index_a) {
				addr = template_hdr->saved_state_array[
				    crbEntry->a.ac.state_index_a];
			} else {
				addr = entry_addr;
			}
			ql_8021_write_reg(ha, read_value, addr);
			opcode &= ~QL_DBG_OPCODE_WRSTATE;
		}
		if (opcode & QL_DBG_OPCODE_MDSTATE) {
			/* Read value from saved state using index */
			read_value = template_hdr->saved_state_array[
			    crbEntry->b.cv.state_index_v];
			/* Shift left operation */
			read_value <<= crbEntry->b.cv.shl;
			/* Shift right operation */
			read_value >>= crbEntry->b.cv.shr;
			/* check if AND mask is provided */
			if (crbEntry->value_2) {
				read_value &= crbEntry->value_2;
			}
			read_value |= crbEntry->value_3; /* OR operation */
			read_value += crbEntry->value_1; /* inc operation */
			/* Write value back to state area. */
			template_hdr->saved_state_array[
			    crbEntry->b.cv.state_index_v] = read_value;
			opcode &= ~QL_DBG_OPCODE_MDSTATE;
		}
		entry_addr += crbEntry->a.ac.addr_stride;
	}

	return (0);
}

/*
 * Error Checking routines for template consistency.
 *
 * We catch an error where driver does not read
 * as much data as we expect from the entry.
 */
static void
ql_8021_md_entry_err_chk(ql_adapter_state_t *ha, md_entry_t *entry,
    uint32_t esize, int e_cnt)
{
	if (esize != entry->h.entry_capture_size) {
		EL(ha, "%d %04x Dump write count = %d did not match entry "
		    "capture size = %d entry_count = %d\n", entry->h.entry_type,
		    entry->h.a.ecw.entry_capture_mask, esize,
		    entry->h.entry_capture_size, e_cnt);
		entry->h.entry_capture_size = esize;
		entry->h.a.ecw.driver_flags = (uint8_t)
		    (entry->h.a.ecw.driver_flags | QL_DBG_SKIPPED_FLAG);
	}
}

static uint32_t
ql_8021_md_template_checksum(ql_adapter_state_t *ha)
{
	uint64_t	sum = 0;
	uint32_t	cnt, *bp;

	cnt = (uint32_t)(ha->dmp_template.size / sizeof (uint32_t));
	bp = ha->dmp_template.bp;
	while (cnt-- > 0) {
		sum += ddi_get32(ha->dmp_template.acc_handle, bp++);
	}
	while (sum >> 32) {
		sum = (sum & 0xFFFFFFFF) + (sum >> 32);
	}
	cnt = (uint32_t)~sum;

	return (cnt);
}

static uint32_t
ql_8021_read_reg(ql_adapter_state_t *ha, uint32_t addr)
{
	uint32_t	addr0, addr1, value;

	(void) ql_8021_crb_win_lock(ha);

	addr0 = addr & 0xFFFF0000;
	WRT_REG_DWORD(ha, (ha->nx_pcibase + 0x00130060), addr0);
	/* PCI posting read */
	(void) RD_REG_DWORD(ha, (ha->nx_pcibase + 0x00130060));
	addr1 = addr & 0x0000FFFF;
	value = RD_REG_DWORD(ha, (ha->nx_pcibase + 0x001E0000 + addr1));

	ql_8021_crb_win_unlock(ha);

	return (value);
}

static void
ql_8021_write_reg(ql_adapter_state_t *ha, uint32_t value, uint32_t addr)
{
	uint32_t	addr0, addr1;

	(void) ql_8021_crb_win_lock(ha);

	addr0 = addr & 0xFFFF0000;
	WRT_REG_DWORD(ha, (ha->nx_pcibase + 0x00130060), addr0);
	/* PCI posting read */
	(void) RD_REG_DWORD(ha, (ha->nx_pcibase + 0x00130060));
	addr1 = addr & 0x0000FFFF;
	WRT_REG_DWORD(ha, (ha->nx_pcibase + 0x001E0000 + addr1), value);
	/* PCI posting read */
	(void) RD_REG_DWORD(ha, (ha->nx_pcibase + 0x001E0000 + addr1));

	ql_8021_crb_win_unlock(ha);
}

static uint32_t
ql_8021_read_ocm(ql_adapter_state_t *ha, uint32_t addr)
{
	uint32_t	value;

	value = RD_REG_DWORD(ha, (ha->nx_pcibase + addr));

	return (value);
}
