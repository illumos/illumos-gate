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

#ifndef _SYS_PX_LIB4U_H
#define	_SYS_PX_LIB4U_H


#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Errors returned.
 */
#define	H_EOK			0	/* Successful return */
#define	H_ENOINTR		1	/* Invalid interrupt id */
#define	H_EINVAL		2	/* Invalid argument */
#define	H_ENOACCESS		3	/* No access to resource */
#define	H_EIO			4	/* I/O error */
#define	H_ENOTSUPPORTED		5	/* Function not supported */
#define	H_ENOMAP		6	/* Mapping is not valid, */
					/* no translation exists */

/*
 * Register base definitions.
 *
 * The specific numeric values for CSR, XBUS, Configuration,
 * Interrupt blocks and other register bases.
 */
typedef enum {
	PX_REG_CSR = 0,
	PX_REG_XBC,
	PX_REG_CFG,
	PX_REG_IC,
	PX_REG_MAX
} px_reg_bank_t;

/*
 * Registers/state/variables that need to be saved and restored during
 * suspend/resume.
 *
 * SUN4U px specific data structure.
 */

/* Control block soft state structure */
typedef struct px_cb_list {
	px_t			*pxp;
	struct px_cb_list	*next;
} px_cb_list_t;

/* IO chip type */
typedef enum {
	PX_CHIP_UNIDENTIFIED = 0,
	PX_CHIP_FIRE = 1,
	PX_CHIP_OBERON = 2
} px_chip_type_t;

#define	PX_CHIP_TYPE(pxu_p)	((pxu_p)->chip_type)

typedef struct px_cb {
	px_cb_list_t	*pxl;		/* linked list px */
	kmutex_t	cb_mutex;	/* lock for CB */
	sysino_t	sysino;		/* proxy sysino */
	cpuid_t		cpuid;		/* proxy cpuid */
	int		attachcnt;	/* number of attached px */
	uint_t		(*px_cb_func)(caddr_t); /* CB intr dispatcher */
} px_cb_t;

typedef struct pxu {
	px_chip_type_t	chip_type;
	uint8_t		portid;
	uint16_t	tsb_cookie;
	uint32_t	tsb_size;
	uint64_t	*tsb_vaddr;
	uint64_t	tsb_paddr;	/* Only used for Oberon */
	sysino_t	hp_sysino;	/* Oberon hotplug interrupt */

	void		*msiq_mapped_p;
	px_cb_t		*px_cb_p;

	/* Soft state for suspend/resume */
	uint64_t	*pec_config_state;
	uint64_t	*mmu_config_state;
	uint64_t	*ib_intr_map;
	uint64_t	*ib_config_state;
	uint64_t	*xcb_config_state;
	uint64_t	*msiq_config_state;
	uint_t		cpr_flag;

	/* sun4u specific vars */
	caddr_t			px_address[4];
	ddi_acc_handle_t	px_ac[4];

	/* PCItool */
	caddr_t		pcitool_addr;
} pxu_t;

#define	PX2CB(px_p) (((pxu_t *)px_p->px_plat_p)->px_cb_p)

/* cpr_flag */
#define	PX_NOT_CPR	0
#define	PX_ENTERED_CPR	1

/*
 * Event Queue data structure.
 */
typedef	struct eq_rec {
	uint64_t	eq_rec_rsvd0 : 1,	/* DW 0 - 63 */
			eq_rec_fmt_type : 7,	/* DW 0 - 62:56 */
			eq_rec_len : 10,	/* DW 0 - 55:46 */
			eq_rec_addr0 : 14,	/* DW 0 - 45:32 */
			eq_rec_rid : 16,	/* DW 0 - 31:16 */
			eq_rec_data0 : 16;	/* DW 0 - 15:00 */
	uint64_t	eq_rec_addr1 : 48,	/* DW 1 - 63:16 */
			eq_rec_data1 : 16;	/* DW 1 - 15:0 */
	uint64_t	eq_rec_rsvd[6];		/* DW 2-7 */
} eq_rec_t;

/*
 * EQ record type
 *
 * Upper 4 bits of eq_rec_fmt_type is used
 * to identify the EQ record type.
 */
#define	EQ_REC_MSG	0x6			/* MSG   - 0x3X */
#define	EQ_REC_MSI32	0xB			/* MSI32 - 0x58 */
#define	EQ_REC_MSI64	0xF			/* MSI64 - 0x78 */

/* EQ State */
#define	EQ_IDLE_STATE	0x1			/* IDLE */
#define	EQ_ACTIVE_STATE	0x2			/* ACTIVE */
#define	EQ_ERROR_STATE	0x4			/* ERROR */

#define	MMU_INVALID_TTE		0ull
#define	MMU_TTE_VALID(tte)	(((tte) & MMU_TTE_V) == MMU_TTE_V)
#define	MMU_OBERON_PADDR_MASK	0x7fffffffffff
#define	MMU_FIRE_PADDR_MASK	0x7ffffffffff

/*
 * control register decoding
 */
/* tsb size: 0=1k 1=2k 2=4k 3=8k 4=16k 5=32k 6=64k 7=128k */
#define	MMU_CTL_TO_TSBSIZE(ctl)		((ctl) >> 16)
#define	MMU_TSBSIZE_TO_TSBENTRIES(s)	((1 << (s)) << (13 - 3))

/*
 * For Fire mmu bypass addresses, bit 43 specifies cacheability.
 */
#define	MMU_FIRE_BYPASS_NONCACHE	 (1ull << 43)

/*
 * For Oberon mmu bypass addresses, bit 47 specifies cacheability.
 */
#define	MMU_OBERON_BYPASS_NONCACHE	 (1ull << 47)

/*
 * The following macros define the address ranges supported for DVMA
 * and mmu bypass transfers. For Oberon, bit 63 is used for ordering.
 */
#define	MMU_FIRE_BYPASS_BASE		0xFFFC000000000000ull
#define	MMU_FIRE_BYPASS_END		0xFFFC03FFFFFFFFFFull

#define	MMU_OBERON_BYPASS_BASE		0x7FFC000000000000ull
#define	MMU_OBERON_BYPASS_END		0x7FFC7FFFFFFFFFFFull

#define	MMU_OBERON_BYPASS_RO		0x8000000000000000ull

#define	MMU_TSB_PA_MASK		0x7FFFFFFFE000

/*
 * The following macros are for loading and unloading io tte
 * entries.
 */
#define	MMU_TTE_SIZE		8
#define	MMU_TTE_V		(1ull << 63)
#define	MMU_TTE_W		(1ull << 1)
#define	MMU_TTE_RO		(1ull << 62)	/* Oberon Relaxed Ordering */

#define	INO_BITS		6	/* INO#s are 6 bits long */
#define	INO_MASK		0x3F	/* INO#s mask */

#define	SYSINO_TO_DEVINO(sysino)	(sysino & INO_MASK)

#define	FIRE_IGN_MASK		0x1F	/* IGN#s mask, 5 bits long for Fire */
#define	OBERON_IGN_MASK		0xFF	/* IGN#s mask, 8 bits long for Oberon */

#define	ID_TO_IGN(chip, portid) ((portid) & ((chip) == PX_CHIP_OBERON ? \
	OBERON_IGN_MASK : FIRE_IGN_MASK))

#define	DEVINO_TO_SYSINO(portid, devino) \
	(((portid) << INO_BITS) | ((devino) & INO_MASK))

/* Interrupt states */
#define	INTERRUPT_IDLE_STATE		0
#define	INTERRUPT_RECEIVED_STATE	1
#define	INTERRUPT_PENDING_STATE		3

/*
 * Defines for link width and max packet size for ACKBAK Latency Threshold Timer
 * and TxLink Replay Timer Latency Table array sizes
 * Num		Link Width		Packet Size
 * 0		1			128
 * 1		4			256
 * 2		8			512
 * 3		16			1024
 * 4		-			2048
 * 5		-			4096
 */
#define	LINK_WIDTH_ARR_SIZE		4
#define	LINK_MAX_PKT_ARR_SIZE		6

/*
 * Defines for registers which have multi-bit fields.
 */
#define	TLU_LINK_CONTROL_ASPM_DISABLED			0x0
#define	TLU_LINK_CONTROL_ASPM_L0S_EN			0x1
#define	TLU_LINK_CONTROL_ASPM_L1_EN			0x2
#define	TLU_LINK_CONTROL_ASPM_L0S_L1_EN			0x3

#define	TLU_CONTROL_CONFIG_DEFAULT			0x1
#define	TLU_CONTROL_L0S_TIM_DEFAULT			0xdaull
#define	TLU_CONTROL_MPS_MASK				0x1C
#define	TLU_CONTROL_MPS_SHIFT				2

#define	LPU_TXLINK_REPLAY_NUMBER_STATUS_RPLAY_NUM_0	0x0
#define	LPU_TXLINK_REPLAY_NUMBER_STATUS_RPLAY_NUM_1	0x1
#define	LPU_TXLINK_REPLAY_NUMBER_STATUS_RPLAY_NUM_2	0x2
#define	LPU_TXLINK_REPLAY_NUMBER_STATUS_RPLAY_NUM_3	0x3

#define	LPU_TXLINK_RETRY_FIFO_POINTER_RTRY_FIFO_TLPTR_DEFAULT	0xFFFFull
#define	LPU_TXLINK_RETRY_FIFO_POINTER_RTRY_FIFO_HDPTR_DEFAULT	0x0ull

#define	LPU_TXLINK_SEQUENCE_COUNTER_ACK_SEQ_CNTR_DEFAULT	0xFFF
#define	LPU_TXLINK_SEQUENCE_COUNTER_NXT_TX_SEQ_CNTR_DEFAULT	0x0
#define	LPU_TXLINK_SEQUENCE_COUNT_FIFO_MAX_ADDR_SEQ_CNT_MAX_ADDR_DEF	0x157

#define	LPU_TXLINK_SEQUENCE_COUNT_FIFO_POINTERS_SEQ_CNT_TLPTR_DEFAULT	0xFFF
#define	LPU_TXLINK_SEQUENCE_COUNT_FIFO_POINTERS_SEQ_CNT_HDPTR_DEFAULT	0x0

#define	LPU_LTSSM_CONFIG1_LTSSM_8_TO_DEFAULT		0x2
#define	LPU_LTSSM_CONFIG1_LTSSM_20_TO_DEFAULT		0x5
#define	LPU_LTSSM_CONFIG2_LTSSM_12_TO_DEFAULT		0x2DC6C0
#define	LPU_LTSSM_CONFIG3_LTSSM_2_TO_DEFAULT		0x7A120
#define	LPU_LTSSM_CONFIG4_DATA_RATE_DEFAULT		0x2
#define	LPU_LTSSM_CONFIG4_N_FTS_DEFAULT			0x8c

/* LPU LTSSM states */
#define	LPU_LTSSM_L0			0x0
#define	LPU_LTSSM_L1_IDLE		0x15

/* TLU Control register bits */
#define	TLU_REMAIN_DETECT_QUIET		8

/* PX BDF Shift in a Phyiscal Address - used FMA Fabric only */
#define	PX_PA_BDF_SHIFT			12
#define	PX_BDF_TO_CFGADDR(bdf, offset) (((bdf) << PX_PA_BDF_SHIFT) + (offset))

/*
 * Fire hardware specific version definitions.
 * All Fire versions > 2.0 will be numerically greater than FIRE_MOD_REV_20
 */
#define	FIRE_MOD_REV_20	0x03

/*
 * Oberon specific definitions.
 */
#define	OBERON_RANGE_PROP_MASK	0x7fff

/*
 * HW specific paddr mask.
 */
extern uint64_t px_paddr_mask;

extern void hvio_cb_init(caddr_t xbc_csr_base, pxu_t *pxu_p);
extern void hvio_ib_init(caddr_t csr_base, pxu_t *pxu_p);
extern void hvio_mmu_init(caddr_t csr_base, pxu_t *pxu_p);
extern void hvio_pec_init(caddr_t csr_base, pxu_t *pxu_p);

extern uint64_t hvio_intr_devino_to_sysino(devhandle_t dev_hdl, pxu_t *pxu_p,
    devino_t devino, sysino_t *sysino);
extern uint64_t hvio_intr_getvalid(devhandle_t dev_hdl, sysino_t sysino,
    intr_valid_state_t *intr_valid_state);
extern uint64_t hvio_intr_setvalid(devhandle_t dev_hdl, sysino_t sysino,
    intr_valid_state_t intr_valid_state);
extern uint64_t hvio_intr_getstate(devhandle_t dev_hdl, sysino_t sysino,
    intr_state_t *intr_state);
extern uint64_t hvio_intr_setstate(devhandle_t dev_hdl, sysino_t sysino,
    intr_state_t intr_state);
extern uint64_t hvio_intr_gettarget(devhandle_t dev_hdl, pxu_t *pxu_p,
    sysino_t sysino, cpuid_t *cpuid);
extern uint64_t hvio_intr_settarget(devhandle_t dev_hdl, pxu_t *pxu_p,
    sysino_t sysino, cpuid_t cpuid);

extern uint64_t hvio_iommu_map(devhandle_t dev_hdl, pxu_t *pxu_p, tsbid_t tsbid,
    pages_t pages, io_attributes_t attr, void *addr, size_t pfn_index,
    int flags);
extern uint64_t hvio_iommu_demap(devhandle_t dev_hdl, pxu_t *pxu_p,
    tsbid_t tsbid, pages_t pages);
extern uint64_t hvio_iommu_getmap(devhandle_t dev_hdl, pxu_t *pxu_p,
    tsbid_t tsbid, io_attributes_t *attr_p, r_addr_t *r_addr_p);
extern uint64_t hvio_iommu_getbypass(devhandle_t dev_hdl, pxu_t *pxu_p,
    r_addr_t ra, io_attributes_t attr, io_addr_t *io_addr_p);
extern uint64_t hvio_get_bypass_base(pxu_t *pxu_p);
extern uint64_t hvio_get_bypass_end(pxu_t *pxu_p);
extern uint64_t px_get_range_prop(px_t *px_p, px_ranges_t *rp, int bank);


/*
 * MSIQ Functions:
 */
extern uint64_t hvio_msiq_init(devhandle_t dev_hdl, pxu_t *pxu_p);
extern uint64_t hvio_msiq_getvalid(devhandle_t dev_hdl, msiqid_t msiq_id,
    pci_msiq_valid_state_t *msiq_valid_state);
extern uint64_t hvio_msiq_setvalid(devhandle_t dev_hdl, msiqid_t msiq_id,
    pci_msiq_valid_state_t msiq_valid_state);
extern uint64_t hvio_msiq_getstate(devhandle_t dev_hdl, msiqid_t msiq_id,
    pci_msiq_state_t *msiq_state);
extern uint64_t hvio_msiq_setstate(devhandle_t dev_hdl, msiqid_t msiq_id,
    pci_msiq_state_t msiq_state);
extern uint64_t hvio_msiq_gethead(devhandle_t dev_hdl, msiqid_t msiq_id,
    msiqhead_t *msiq_head);
extern uint64_t hvio_msiq_sethead(devhandle_t dev_hdl, msiqid_t msiq_id,
    msiqhead_t msiq_head);
extern uint64_t hvio_msiq_gettail(devhandle_t dev_hdl, msiqid_t msiq_id,
    msiqtail_t *msiq_tail);

/*
 * MSI Functions:
 */
extern uint64_t hvio_msi_init(devhandle_t dev_hdl, uint64_t addr32,
    uint64_t addr64);
extern uint64_t hvio_msi_getmsiq(devhandle_t dev_hdl, msinum_t msi_num,
    msiqid_t *msiq_id);
extern uint64_t hvio_msi_setmsiq(devhandle_t dev_hdl, msinum_t msi_num,
    msiqid_t msiq_id);
extern uint64_t hvio_msi_getvalid(devhandle_t dev_hdl, msinum_t msi_num,
    pci_msi_valid_state_t *msi_valid_state);
extern uint64_t hvio_msi_setvalid(devhandle_t dev_hdl, msinum_t msi_num,
    pci_msi_valid_state_t msi_valid_state);
extern uint64_t hvio_msi_getstate(devhandle_t dev_hdl, msinum_t msi_num,
    pci_msi_state_t *msi_state);
extern uint64_t hvio_msi_setstate(devhandle_t dev_hdl, msinum_t msi_num,
    pci_msi_state_t msi_state);

/*
 * MSG Functions:
 */
extern uint64_t hvio_msg_getmsiq(devhandle_t dev_hdl, pcie_msg_type_t msg_type,
    msiqid_t *msiq_id);
extern uint64_t hvio_msg_setmsiq(devhandle_t dev_hdl, pcie_msg_type_t msg_type,
    msiqid_t msiq_id);
extern uint64_t hvio_msg_getvalid(devhandle_t dev_hdl, pcie_msg_type_t msg_type,
    pcie_msg_valid_state_t *msg_valid_state);
extern uint64_t hvio_msg_setvalid(devhandle_t dev_hdl, pcie_msg_type_t msg_type,
    pcie_msg_valid_state_t msg_valid_state);

/*
 * Suspend/Resume Functions:
 */
extern uint64_t hvio_suspend(devhandle_t dev_hdl, pxu_t *pxu_p);
extern void hvio_resume(devhandle_t dev_hdl,
    devino_t devino, pxu_t *pxu_p);
extern uint64_t hvio_cb_suspend(devhandle_t dev_hdl, pxu_t *pxu_p);
extern void hvio_cb_resume(devhandle_t pci_dev_hdl, devhandle_t xbus_dev_hdl,
    devino_t devino, pxu_t *pxu_p);
extern int px_send_pme_turnoff(caddr_t csr_base);
extern int px_link_wait4l1idle(caddr_t csr_base);
extern int px_link_retrain(caddr_t csr_base);
extern void px_enable_detect_quiet(caddr_t csr_base);

extern void px_lib_clr_errs(px_t *px_p, dev_info_t *rdip, uint64_t addr);

/*
 * Hotplug functions:
 */
extern int hvio_hotplug_init(dev_info_t *dip, void *arg);
extern int hvio_hotplug_uninit(dev_info_t *dip);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PX_LIB4U_H */
