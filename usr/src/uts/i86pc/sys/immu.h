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
 * Portions Copyright (c) 2010, Oracle and/or its affiliates.
 * All rights reserved.
 */

/*
 * Copyright (c) 2008, Intel Corporation.
 * All rights reserved.
 */

#ifndef	_SYS_INTEL_IOMMU_H
#define	_SYS_INTEL_IOMMU_H

/*
 * Intel IOMMU implementation specific state
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/bitset.h>
#include <sys/kstat.h>
#include <sys/kmem.h>
#include <sys/vmem.h>
#include <sys/rootnex.h>
#include <sys/iommulib.h>
#include <sys/sdt.h>

/*
 * Some ON drivers have bugs. Keep this define until all such drivers
 * have been fixed
 */
#define	BUGGY_DRIVERS 1

/* PD(T)E entries */
typedef uint64_t hw_pdte_t;

#define	IMMU_MAXNAMELEN (64)
#define	IMMU_MAXSEG	(1)
#define	IMMU_REGSZ	(1UL << 12)
#define	IMMU_PAGESIZE   (4096)
#define	IMMU_PAGESHIFT	(12)
#define	IMMU_PAGEOFFSET	(IMMU_PAGESIZE - 1)
#define	IMMU_PAGEMASK	(~IMMU_PAGEOFFSET)
#define	IMMU_BTOP(b)	(((uint64_t)b) >> IMMU_PAGESHIFT)
#define	IMMU_PTOB(p)	(((uint64_t)p) << IMMU_PAGESHIFT)
#define	IMMU_BTOPR(x)	((((x) + IMMU_PAGEOFFSET) >> IMMU_PAGESHIFT))
#define	IMMU_PGTABLE_MAX_LEVELS	(6)
#define	IMMU_ROUNDUP(size) (((size) + IMMU_PAGEOFFSET) & ~IMMU_PAGEOFFSET)
#define	IMMU_ROUNDOWN(addr) ((addr) & ~IMMU_PAGEOFFSET)
#define	IMMU_PGTABLE_LEVEL_STRIDE	(9)
#define	IMMU_PGTABLE_LEVEL_MASK	((1<<IMMU_PGTABLE_LEVEL_STRIDE) - 1)
#define	IMMU_PGTABLE_OFFSHIFT  (IMMU_PAGESHIFT - IMMU_PGTABLE_LEVEL_STRIDE)
#define	IMMU_PGTABLE_MAXIDX  ((IMMU_PAGESIZE / sizeof (hw_pdte_t)) - 1)

/*
 * DMAR global defines
 */
#define	DMAR_TABLE	"dmar-table"
#define	DMAR_INTRMAP_SUPPORT	(0x01)

/* DMAR unit types */
#define	DMAR_DRHD	0
#define	DMAR_RMRR	1
#define	DMAR_ATSR	2
#define	DMAR_RHSA	3

/* DRHD flag values */
#define	DMAR_INCLUDE_ALL	(0x01)

/* Device scope types */
#define	DMAR_ENDPOINT	1
#define	DMAR_SUBTREE	2
#define	DMAR_IOAPIC	3
#define	DMAR_HPET	4


/* Forward declarations for IOMMU state structure and DVMA domain struct */
struct immu;
struct domain;

/*
 * The following structure describes the formate of DMAR ACPI table format.
 * They are used to parse DMAR ACPI table. Read the spec for the meaning
 * of each member.
 */

/* lengths of various strings */
#define	DMAR_SIG_LEN    (4)	/* table signature */
#define	DMAR_OEMID_LEN  (6)	/* OEM ID */
#define	DMAR_TBLID_LEN  (8)	/* OEM table ID */
#define	DMAR_ASL_LEN    (4)	/* ASL len */

typedef struct dmar_table {
	kmutex_t	tbl_lock;
	uint8_t		tbl_haw;
	boolean_t	tbl_intrmap;
	list_t		tbl_drhd_list[IMMU_MAXSEG];
	list_t		tbl_rmrr_list[IMMU_MAXSEG];
	char		*tbl_oem_id;
	char		*tbl_oem_tblid;
	uint32_t	tbl_oem_rev;
	caddr_t		tbl_raw;
	int		tbl_rawlen;
} dmar_table_t;

typedef struct drhd {
	kmutex_t	dr_lock;   /* protects the dmar field */
	struct immu	*dr_immu;
	dev_info_t	*dr_dip;
	uint16_t 	dr_seg;
	uint64_t 	dr_regs;
	boolean_t	dr_include_all;
	list_t 		dr_scope_list;
	list_node_t 	dr_node;
} drhd_t;

typedef struct rmrr {
	kmutex_t	rm_lock;
	uint16_t	rm_seg;
	uint64_t	rm_base;
	uint64_t	rm_limit;
	list_t		rm_scope_list;
	list_node_t	rm_node;
} rmrr_t;

#define	IMMU_UNIT_NAME	"iommu"

/*
 * Macros based on PCI spec
 */
#define	IMMU_PCI_DEV(devfunc)    ((uint64_t)devfunc >> 3) /* from devfunc  */
#define	IMMU_PCI_FUNC(devfunc)   (devfunc & 7)  /* get func from devfunc */
#define	IMMU_PCI_DEVFUNC(d, f)   (((d) << 3) | (f))  /* create devfunc */

typedef struct scope {
	uint8_t scp_type;
	uint8_t scp_enumid;
	uint8_t scp_bus;
	uint8_t scp_dev;
	uint8_t scp_func;
	list_node_t scp_node;
} scope_t;

/*
 * interrupt source id and drhd info for ioapic
 */
typedef struct ioapic_drhd {
	uchar_t		ioapic_ioapicid;
	uint16_t	ioapic_sid;	/* ioapic source id */
	drhd_t		*ioapic_drhd;
	list_node_t	ioapic_node;
} ioapic_drhd_t;

typedef struct memrng {
	uint64_t mrng_start;
	uint64_t mrng_npages;
} memrng_t;

typedef enum immu_flags {
	IMMU_FLAGS_NONE = 0x1,
	IMMU_FLAGS_SLEEP = 0x1,
	IMMU_FLAGS_NOSLEEP = 0x2,
	IMMU_FLAGS_READ = 0x4,
	IMMU_FLAGS_WRITE = 0x8,
	IMMU_FLAGS_DONTPASS = 0x10,
	IMMU_FLAGS_ALLOC = 0x20,
	IMMU_FLAGS_MUST_MATCH = 0x40,
	IMMU_FLAGS_PAGE1 = 0x80,
	IMMU_FLAGS_UNITY = 0x100,
	IMMU_FLAGS_DMAHDL = 0x200,
	IMMU_FLAGS_MEMRNG = 0x400
} immu_flags_t;

typedef enum cont_avail {
	IMMU_CONT_BAD = 0x0,
	IMMU_CONT_UNINITED = 0x1,
	IMMU_CONT_INITED = 0x2
} cont_avail_t;

/* Size of root and context tables and their entries */
#define	IMMU_ROOT_TBLSZ		(4096)
#define	IMMU_CONT_TBLSZ		(4096)
#define	IMMU_ROOT_NUM		(256)
#define	IMMU_CONT_NUM		(256)

/* register offset */
#define	IMMU_REG_VERSION	(0x00)  /* Version Rigister, 32 bit */
#define	IMMU_REG_CAP		(0x08)  /* Capability Register, 64 bit */
#define	IMMU_REG_EXCAP		(0x10)  /* Extended Capability Reg, 64 bit */
#define	IMMU_REG_GLOBAL_CMD	(0x18)  /* Global Command Register, 32 bit */
#define	IMMU_REG_GLOBAL_STS	(0x1C)  /* Global Status Register, 32 bit */
#define	IMMU_REG_ROOTENTRY	(0x20)  /* Root-Entry Table Addr Reg, 64 bit */
#define	IMMU_REG_CONTEXT_CMD	(0x28)  /* Context Comand Register, 64 bit */
#define	IMMU_REG_FAULT_STS	(0x34)  /* Fault Status Register, 32 bit */
#define	IMMU_REG_FEVNT_CON	(0x38)  /* Fault Event Control Reg, 32 bit */
#define	IMMU_REG_FEVNT_DATA	(0x3C)  /* Fault Event Data Register, 32 bit */
#define	IMMU_REG_FEVNT_ADDR	(0x40)  /* Fault Event Address Reg, 32 bit */
#define	IMMU_REG_FEVNT_UADDR	(0x44)  /* Fault Event Upper Addr Reg, 32 bit */
#define	IMMU_REG_AFAULT_LOG	(0x58)  /* Advanced Fault Log Reg, 64 bit */
#define	IMMU_REG_PMER		(0x64)  /* Protected Memory Enble Reg, 32 bit */
#define	IMMU_REG_PLMBR		(0x68)  /* Protected Low Mem Base Reg, 32 bit */
#define	IMMU_REG_PLMLR		(0x6C)  /* Protected Low Mem Lim Reg, 32 bit */
#define	IMMU_REG_PHMBR		(0X70)  /* Protectd High Mem Base Reg, 64 bit */
#define	IMMU_REG_PHMLR		(0x78)  /* Protected High Mem Lim Reg, 64 bit */
#define	IMMU_REG_INVAL_QH	(0x80)  /* Invalidation Queue Head, 64 bit */
#define	IMMU_REG_INVAL_QT	(0x88)  /* Invalidation Queue Tail, 64 bit */
#define	IMMU_REG_INVAL_QAR	(0x90)  /* Invalidtion Queue Addr Reg, 64 bit */
#define	IMMU_REG_INVAL_CSR	(0x9C)  /* Inval Compl Status Reg, 32 bit */
#define	IMMU_REG_INVAL_CECR	(0xA0)  /* Inval Compl Evnt Ctrl Reg, 32 bit */
#define	IMMU_REG_INVAL_CEDR	(0xA4)  /* Inval Compl Evnt Data Reg, 32 bit */
#define	IMMU_REG_INVAL_CEAR	(0xA8)  /* Inval Compl Event Addr Reg, 32 bit */
#define	IMMU_REG_INVAL_CEUAR	(0xAC)  /* Inval Comp Evnt Up Addr reg, 32bit */
#define	IMMU_REG_IRTAR		(0xB8)  /* INTR Remap Tbl Addr Reg, 64 bit */

/* ioapic memory region */
#define	IOAPIC_REGION_START	(0xfee00000)
#define	IOAPIC_REGION_END	(0xfeefffff)

/* fault register */
#define	IMMU_FAULT_STS_PPF		(2)
#define	IMMU_FAULT_STS_PFO		(1)
#define	IMMU_FAULT_STS_ITE		(1 << 6)
#define	IMMU_FAULT_STS_ICE		(1 << 5)
#define	IMMU_FAULT_STS_IQE		(1 << 4)
#define	IMMU_FAULT_GET_INDEX(x)		((((uint64_t)x) >> 8) & 0xff)
#define	IMMU_FRR_GET_F(x)		(((uint64_t)x) >> 63)
#define	IMMU_FRR_GET_FR(x)		((((uint64_t)x) >> 32) & 0xff)
#define	IMMU_FRR_GET_FT(x)		((((uint64_t)x) >> 62) & 0x1)
#define	IMMU_FRR_GET_SID(x)		((x) & 0xffff)

/* (ex)capability register */
#define	IMMU_CAP_GET_NFR(x)		(((((uint64_t)x) >> 40) & 0xff) + 1)
#define	IMMU_CAP_GET_DWD(x)		((((uint64_t)x) >> 54) & 1)
#define	IMMU_CAP_GET_DRD(x)		((((uint64_t)x) >> 55) & 1)
#define	IMMU_CAP_GET_PSI(x)		((((uint64_t)x) >> 39) & 1)
#define	IMMU_CAP_GET_SPS(x)		((((uint64_t)x) >> 34) & 0xf)
#define	IMMU_CAP_GET_ISOCH(x)		((((uint64_t)x) >> 23) & 1)
#define	IMMU_CAP_GET_ZLR(x)		((((uint64_t)x) >> 22) & 1)
#define	IMMU_CAP_GET_MAMV(x)		((((uint64_t)x) >> 48) & 0x3f)
#define	IMMU_CAP_GET_CM(x)		((((uint64_t)x) >> 7) & 1)
#define	IMMU_CAP_GET_PHMR(x)		((((uint64_t)x) >> 6) & 1)
#define	IMMU_CAP_GET_PLMR(x)		((((uint64_t)x) >> 5) & 1)
#define	IMMU_CAP_GET_RWBF(x)		((((uint64_t)x) >> 4) & 1)
#define	IMMU_CAP_GET_AFL(x)		((((uint64_t)x) >> 3) & 1)
#define	IMMU_CAP_GET_FRO(x)		(((((uint64_t)x) >> 24) & 0x3ff) * 16)
#define	IMMU_CAP_MGAW(x)		(((((uint64_t)x) >> 16) & 0x3f) + 1)
#define	IMMU_CAP_SAGAW(x)		((((uint64_t)x) >> 8) & 0x1f)
#define	IMMU_CAP_ND(x)			(1 << (((x) & 0x7) *2 + 4)) -1
#define	IMMU_ECAP_GET_IRO(x)		(((((uint64_t)x) >> 8) & 0x3ff) << 4)
#define	IMMU_ECAP_GET_MHMV(x)		(((uint64_t)x >> 20) & 0xf)
#define	IMMU_ECAP_GET_SC(x)		((x) & 0x80)
#define	IMMU_ECAP_GET_PT(x)		((x) & 0x40)
#define	IMMU_ECAP_GET_CH(x)		((x) & 0x20)
#define	IMMU_ECAP_GET_EIM(x)		((x) & 0x10)
#define	IMMU_ECAP_GET_IR(x)		((x) & 0x8)
#define	IMMU_ECAP_GET_DI(x)		((x) & 0x4)
#define	IMMU_ECAP_GET_QI(x)		((x) & 0x2)
#define	IMMU_ECAP_GET_C(x)		((x) & 0x1)

#define	IMMU_CAP_SET_RWBF(x)		((x) |= (1 << 4))


/* iotlb invalidation */
#define	TLB_INV_GLOBAL		(((uint64_t)1) << 60)
#define	TLB_INV_DOMAIN		(((uint64_t)2) << 60)
#define	TLB_INV_PAGE		(((uint64_t)3) << 60)
#define	TLB_INV_GET_IAIG(x)	((((uint64_t)x) >> 57) & 7)
#define	TLB_INV_DRAIN_READ	(((uint64_t)1) << 49)
#define	TLB_INV_DRAIN_WRITE	(((uint64_t)1) << 48)
#define	TLB_INV_DID(x)		(((uint64_t)((x) & 0xffff)) << 32)
#define	TLB_INV_IVT		(((uint64_t)1) << 63)
#define	TLB_IVA_HINT(x)		(((x) & 0x1) << 6)
#define	TLB_IVA_LEAF		1
#define	TLB_IVA_WHOLE		0

/* dont use value 0 for  enums - to catch unit 8 */
typedef enum iotlb_inv {
	IOTLB_PSI = 1,
	IOTLB_DSI,
	IOTLB_GLOBAL
} immu_iotlb_inv_t;

typedef enum context_inv {
	CONTEXT_FSI = 1,
	CONTEXT_DSI,
	CONTEXT_GLOBAL
} immu_context_inv_t;

/* context invalidation */
#define	CCMD_INV_ICC		(((uint64_t)1) << 63)
#define	CCMD_INV_GLOBAL		(((uint64_t)1) << 61)
#define	CCMD_INV_DOMAIN		(((uint64_t)2) << 61)
#define	CCMD_INV_DEVICE		(((uint64_t)3) << 61)
#define	CCMD_INV_DID(x)		((uint64_t)((x) & 0xffff))
#define	CCMD_INV_SID(x)		(((uint64_t)((x) & 0xffff)) << 16)
#define	CCMD_INV_FM(x)		(((uint64_t)((x) & 0x3)) << 32)

/* global command register */
#define	IMMU_GCMD_TE		(((uint32_t)1) << 31)
#define	IMMU_GCMD_SRTP		(((uint32_t)1) << 30)
#define	IMMU_GCMD_SFL		(((uint32_t)1) << 29)
#define	IMMU_GCMD_EAFL		(((uint32_t)1) << 28)
#define	IMMU_GCMD_WBF		(((uint32_t)1) << 27)
#define	IMMU_GCMD_QIE		(((uint32_t)1) << 26)
#define	IMMU_GCMD_IRE		(((uint32_t)1) << 25)
#define	IMMU_GCMD_SIRTP	(((uint32_t)1) << 24)
#define	IMMU_GCMD_CFI		(((uint32_t)1) << 23)

/* global status register */
#define	IMMU_GSTS_TES		(((uint32_t)1) << 31)
#define	IMMU_GSTS_RTPS		(((uint32_t)1) << 30)
#define	IMMU_GSTS_FLS		(((uint32_t)1) << 29)
#define	IMMU_GSTS_AFLS		(((uint32_t)1) << 28)
#define	IMMU_GSTS_WBFS		(((uint32_t)1) << 27)
#define	IMMU_GSTS_QIES		(((uint32_t)1) << 26)
#define	IMMU_GSTS_IRES		(((uint32_t)1) << 25)
#define	IMMU_GSTS_IRTPS	(((uint32_t)1) << 24)
#define	IMMU_GSTS_CFIS		(((uint32_t)1) << 23)

/* psi address mask */
#define	ADDR_AM_MAX(m)		(((uint_t)1) << (m))
#define	ADDR_AM_OFFSET(n, m)	((n) & (ADDR_AM_MAX(m) - 1))

/* dmar fault event */
#define	IMMU_INTR_IPL			(4)
#define	IMMU_REG_FEVNT_CON_IM_SHIFT	(31)

#define	IMMU_ALLOC_RESOURCE_DELAY    (drv_usectohz(5000))

/* max value of Size field of Interrupt Remapping Table Address Register */
#define	INTRMAP_MAX_IRTA_SIZE	0xf

/* interrupt remapping table entry size */
#define	INTRMAP_RTE_SIZE		0x10

/* ioapic redirection table entry related shift of remappable interrupt */
#define	INTRMAP_IOAPIC_IDX_SHIFT		17
#define	INTRMAP_IOAPIC_FORMAT_SHIFT	16
#define	INTRMAP_IOAPIC_TM_SHIFT		15
#define	INTRMAP_IOAPIC_POL_SHIFT		13
#define	INTRMAP_IOAPIC_IDX15_SHIFT	11

/* msi intr entry related shift of remappable interrupt */
#define	INTRMAP_MSI_IDX_SHIFT	5
#define	INTRMAP_MSI_FORMAT_SHIFT	4
#define	INTRMAP_MSI_SHV_SHIFT	3
#define	INTRMAP_MSI_IDX15_SHIFT	2

#define	INTRMAP_IDX_FULL		(uint_t)-1

#define	RDT_DLM(rdt)	BITX((rdt), 10, 8)
#define	RDT_DM(rdt)	BT_TEST(&(rdt), 11)
#define	RDT_POL(rdt)	BT_TEST(&(rdt), 13)
#define	RDT_TM(rdt)	BT_TEST(&(rdt), 15)

#define	INTRMAP_DISABLE	(void *)-1

/*
 * invalidation granularity
 */
typedef enum {
	TLB_INV_G_GLOBAL = 1,
	TLB_INV_G_DOMAIN,
	TLB_INV_G_PAGE
} tlb_inv_g_t;

typedef enum {
	CTT_INV_G_GLOBAL = 1,
	CTT_INV_G_DOMAIN,
	CTT_INV_G_DEVICE
} ctt_inv_g_t;

typedef enum {
	IEC_INV_GLOBAL = 0,
	IEC_INV_INDEX
} iec_inv_g_t;


struct inv_queue_state;
struct intrmap_tbl_state;

/* A software page table structure */
typedef struct pgtable {
	krwlock_t swpg_rwlock;
	caddr_t hwpg_vaddr;   /* HW pgtable VA */
	paddr_t hwpg_paddr;   /* HW pgtable PA */
	ddi_dma_handle_t hwpg_dmahdl;
	ddi_acc_handle_t hwpg_memhdl;
	struct pgtable **swpg_next_array;
	list_node_t swpg_domain_node;  /* domain list of pgtables */
} pgtable_t;

/* interrupt remapping table state info */
typedef struct intrmap {
	kmutex_t		intrmap_lock;
	ddi_dma_handle_t	intrmap_dma_hdl;
	ddi_acc_handle_t	intrmap_acc_hdl;
	caddr_t			intrmap_vaddr;
	paddr_t			intrmap_paddr;
	uint_t			intrmap_size;
	bitset_t		intrmap_map;
	uint_t			intrmap_free;
} intrmap_t;

typedef struct hw_rce {
	uint64_t lo;
	uint64_t hi;
} hw_rce_t;


#define	ROOT_GET_P(hrent) ((hrent)->lo & 0x1)
#define	ROOT_SET_P(hrent) ((hrent)->lo |= 0x1)

#define	ROOT_GET_CONT(hrent) ((hrent)->lo & ~(0xFFF))
#define	ROOT_SET_CONT(hrent, paddr) ((hrent)->lo |= (paddr & (~0xFFF)))

#define	TTYPE_XLATE_ONLY  (0x0)
#define	TTYPE_XLATE_IOTLB (0x1)
#define	TTYPE_PASSTHRU    (0x2)
#define	TTYPE_RESERVED    (0x3)

#define	CONT_GET_DID(hcent) ((((uint64_t)(hcent)->hi) >> 8) & 0xFFFF)
#define	CONT_SET_DID(hcent, did) ((hcent)->hi |= ((0xFFFF & (did)) << 8))

#define	CONT_GET_AVAIL(hcent) ((((uint64_t)((hcent)->hi)) >> 0x3) & 0xF)
#define	CONT_SET_AVAIL(hcent, av) ((hcent)->hi |= ((0xF & (av)) << 0x3))

#define	CONT_GET_LO_AW(hcent) (30 + 9 *((hcent)->hi & 0x7))
#define	CONT_GET_AW(hcent) \
	((CONT_GET_LO_AW(hcent) == 66) ? 64 : CONT_GET_LO_AW(hcent))
#define	CONT_SET_AW(hcent, aw) \
	((hcent)->hi |= (((((aw) + 2) - 30) / 9) & 0x7))

#define	CONT_GET_ASR(hcent) ((hcent)->lo & ~(0xFFF))
#define	CONT_SET_ASR(hcent, paddr) ((hcent)->lo |= (paddr & (~0xFFF)))

#define	CONT_GET_TTYPE(hcent) ((((uint64_t)(hcent)->lo) >> 0x2) & 0x3)
#define	CONT_SET_TTYPE(hcent, ttype) ((hcent)->lo |= (((ttype) & 0x3) << 0x2))

#define	CONT_GET_P(hcent) ((hcent)->lo & 0x1)
#define	CONT_SET_P(hcent) ((hcent)->lo |= 0x1)

#define	CONT_GET_ALH(hcent) ((hcent)->lo & 0x20)
#define	CONT_SET_ALH(hcent) ((hcent)->lo |= 0x20)

#define	CONT_GET_EH(hcent) ((hcent)->lo & 0x10)
#define	CONT_SET_EH(hcent) ((hcent)->lo |= 0x10)


/* we use the bit 63 (available for system SW) as a present bit */
#define	PDTE_SW4(hw_pdte) ((hw_pdte) & ((uint64_t)1<<63))
#define	PDTE_CLEAR_SW4(hw_pdte) ((hw_pdte) &= ~((uint64_t)1<<63))

#define	PDTE_P(hw_pdte) ((hw_pdte) & ((uint64_t)1<<63))
#define	PDTE_CLEAR_P(hw_pdte) ((hw_pdte) &= ~((uint64_t)1<<63))
#define	PDTE_SET_P(hw_pdte) ((hw_pdte) |= ((uint64_t)1<<63))

#define	PDTE_TM(hw_pdte) ((hw_pdte) & ((uint64_t)1<<62))
#define	PDTE_CLEAR_TM(hw_pdte) ((hw_pdte) &= ~((uint64_t)1<<62))

#define	PDTE_SW3(hw_pdte) \
	(((hw_pdte) & ~(((uint64_t)0x3<<62)|(((uint64_t)1<<52)-1))) >> 52)
#define	PDTE_SW3_OVERFLOW(hw_pdte) \
	(PDTE_SW3(hw_pdte) == 0x3FF)
#define	PDTE_CLEAR_SW3(hw_pdte) \
	((hw_pdte) &= (((uint64_t)0x3<<62)|(((uint64_t)1<<52)-1)))
#define	PDTE_SET_SW3(hw_pdte, ref) \
	((hw_pdte) |= ((((uint64_t)(ref)) & 0x3FF) << 52))

#define	PDTE_PADDR(hw_pdte) ((hw_pdte) & ~(((uint64_t)0xFFF<<52)|((1<<12)-1)))
#define	PDTE_CLEAR_PADDR(hw_pdte) \
		((hw_pdte) &= (((uint64_t)0xFFF<<52)|((1<<12)-1)))
#define	PDTE_SET_PADDR(hw_pdte, paddr) ((hw_pdte) |= PDTE_PADDR(paddr))

#define	PDTE_SNP(hw_pdte) ((hw_pdte) & (1<<11))
#define	PDTE_CLEAR_SNP(hw_pdte) ((hw_pdte) &= ~(1<<11))
#define	PDTE_SET_SNP(hw_pdte) ((hw_pdte) |= (1<<11))

#define	PDTE_SW2(hw_pdte) ((hw_pdte) & (0x700))
#define	PDTE_CLEAR_SW2(hw_pdte) ((hw_pdte) &= ~(0x700))

#define	PDTE_SP(hw_pdte) ((hw_pdte) & (0x80))
#define	PDTE_CLEAR_SP(hw_pdte) ((hw_pdte) &= ~(0x80))

#define	PDTE_SW1(hw_pdte) ((hw_pdte) & (0x7C))
#define	PDTE_CLEAR_SW1(hw_pdte) ((hw_pdte) &= ~(0x7C))

#define	PDTE_WRITE(hw_pdte) ((hw_pdte) & (0x2))
#define	PDTE_CLEAR_WRITE(hw_pdte) ((hw_pdte) &= ~(0x2))
#define	PDTE_SET_WRITE(hw_pdte) ((hw_pdte) |= (0x2))

#define	PDTE_READ(hw_pdte) ((hw_pdte) & (0x1))
#define	PDTE_CLEAR_READ(hw_pdte) ((hw_pdte) &= ~(0x1))
#define	PDTE_SET_READ(hw_pdte) ((hw_pdte) |= (0x1))

#define	PDTE_MASK_R	((uint64_t)1 << 0)
#define	PDTE_MASK_W	((uint64_t)1 << 1)
#define	PDTE_MASK_SNP	((uint64_t)1 << 11)
#define	PDTE_MASK_TM	((uint64_t)1 << 62)
#define	PDTE_MASK_P	((uint64_t)1 << 63)

struct immu_flushops;

/*
 * Used to wait for invalidation completion.
 *     vstatus is the virtual address of the status word that will be written
 *     pstatus is the physical addres
 * If sync is true, then the the operation will be waited on for
 * completion immediately. Else, the wait interface can be called
 * to wait for completion later.
 */

#define	IMMU_INV_DATA_PENDING	1
#define	IMMU_INV_DATA_DONE	2

typedef struct immu_inv_wait {
	volatile uint32_t iwp_vstatus;
	uint64_t iwp_pstatus;
	boolean_t iwp_sync;
	const char *iwp_name;		/* ID for debugging/statistics */
} immu_inv_wait_t;

/*
 * Used to batch IOMMU pagetable writes.
 */
typedef struct immu_dcookie {
	paddr_t dck_paddr;
	uint64_t dck_npages;
} immu_dcookie_t;

typedef struct immu {
	kmutex_t		immu_lock;
	char			*immu_name;

	/* lock grabbed by interrupt handler */
	kmutex_t		immu_intr_lock;

	/* ACPI/DMAR table related */
	void			*immu_dmar_unit;
	dev_info_t		*immu_dip;
	struct domain		*immu_unity_domain;

	/* IOMMU register related */
	kmutex_t		immu_regs_lock;
	kcondvar_t		immu_regs_cv;
	boolean_t		immu_regs_busy;
	boolean_t		immu_regs_setup;
	boolean_t		immu_regs_running;
	boolean_t		immu_regs_quiesced;
	ddi_acc_handle_t	immu_regs_handle;
	caddr_t			immu_regs_addr;
	uint64_t		immu_regs_cap;
	uint64_t		immu_regs_excap;
	uint32_t		immu_regs_cmdval;
	uint32_t		immu_regs_intr_msi_addr;
	uint32_t		immu_regs_intr_msi_data;
	uint32_t		immu_regs_intr_uaddr;

	/* DVMA related */
	kmutex_t		immu_dvma_lock;
	boolean_t		immu_dvma_setup;
	boolean_t		immu_dvma_running;
	int			immu_dvma_gaw;
	int			immu_dvma_agaw;
	int			immu_dvma_nlevels;
	boolean_t		immu_dvma_coherent;
	boolean_t		immu_TM_reserved;
	boolean_t		immu_SNP_reserved;
	uint64_t		immu_ptemask;

	/* DVMA context related */
	krwlock_t		immu_ctx_rwlock;
	pgtable_t		*immu_ctx_root;
	immu_inv_wait_t		immu_ctx_inv_wait;

	/* DVMA domain related */
	int			immu_max_domains;
	vmem_t			*immu_did_arena;
	char			immu_did_arena_name[IMMU_MAXNAMELEN];
	list_t			immu_domain_list;

	/* DVMA special devices */
	boolean_t		immu_dvma_gfx_only;
	list_t			immu_dvma_lpc_list;
	list_t			immu_dvma_gfx_list;

	/* interrupt remapping related */
	kmutex_t		immu_intrmap_lock;
	boolean_t		immu_intrmap_setup;
	boolean_t		immu_intrmap_running;
	intrmap_t		*immu_intrmap;
	uint64_t		immu_intrmap_irta_reg;
	immu_inv_wait_t		immu_intrmap_inv_wait;

	/* queued invalidation related */
	kmutex_t		immu_qinv_lock;
	boolean_t		immu_qinv_setup;
	boolean_t		immu_qinv_running;
	boolean_t		immu_qinv_enabled;
	void			*immu_qinv;
	uint64_t		immu_qinv_reg_value;

	/* list_node for system-wide list of DMAR units */
	list_node_t		immu_node;

	struct immu_flushops	*immu_flushops;

	kmem_cache_t		*immu_hdl_cache;
	kmem_cache_t		*immu_pgtable_cache;

	iommulib_handle_t	immu_iommulib_handle;
} immu_t;

/*
 * Enough space to hold the decimal number of any device instance.
 * Used for device/cache names.
 */
#define	IMMU_ISTRLEN 	11	/* log10(2^31)  + 1 */

/* properties that control DVMA */
#define	DDI_DVMA_MAPTYPE_ROOTNEX_PROP	"immu-dvma-mapping"

#define	DDI_DVMA_MAPTYPE_UNITY		"unity"
#define	DDI_DVMA_MAPTYPE_XLATE		"xlate"

typedef enum immu_maptype {
	IMMU_MAPTYPE_BAD = 0,    /* 0 is always bad */
	IMMU_MAPTYPE_UNITY = 1,
	IMMU_MAPTYPE_XLATE
} immu_maptype_t;

#define	IMMU_COOKIE_HASHSZ	(512)

/*
 * domain_t
 *
 */
typedef struct domain {
	/* the basics */
	uint_t			dom_did;
	immu_t			*dom_immu;

	/* mapping related */
	immu_maptype_t		dom_maptype;
	vmem_t			*dom_dvma_arena;
	char			dom_dvma_arena_name[IMMU_MAXNAMELEN];

	/* pgtables */
	pgtable_t		*dom_pgtable_root;
	krwlock_t		dom_pgtable_rwlock;

	/* list node for list of domains (unity or xlate) */
	list_node_t		dom_maptype_node;
	/* list node for list of domains off immu */
	list_node_t		dom_immu_node;

	mod_hash_t 		*dom_cookie_hash;

	/* topmost device in domain; usually the device itself (non-shared) */
	dev_info_t		*dom_dip;
} domain_t;

typedef enum immu_pcib {
	IMMU_PCIB_BAD = 0,
	IMMU_PCIB_NOBDF,
	IMMU_PCIB_PCIE_PCIE,
	IMMU_PCIB_PCIE_PCI,
	IMMU_PCIB_PCI_PCI,
	IMMU_PCIB_ENDPOINT
} immu_pcib_t;

/*
 *  immu_devi_t
 *      Intel IOMMU in devinfo node
 */
typedef struct immu_devi {
	/* pci seg, bus, dev, func */
	int		imd_seg;
	int		imd_bus;
	int		imd_devfunc;

	/* ppb information */
	immu_pcib_t	imd_pcib_type;
	int		imd_sec;
	int		imd_sub;

	/* identifier for special devices */
	boolean_t	imd_display;
	boolean_t	imd_lpc;

	/* set if premapped DVMA space is used */
	boolean_t	imd_use_premap;

	/* dmar unit to which this dip belongs */
	immu_t		*imd_immu;

	immu_flags_t	imd_dvma_flags;

	/* domain ptr */
	domain_t	*imd_domain;
	dev_info_t	*imd_ddip;

	/* my devinfo */
	dev_info_t	*imd_dip;

	/*
	 * if we are a "special" devinfo
	 * the node for the special linked list
	 * off the DMAR unit structure
	 */
	list_node_t	imd_spc_node;
} immu_devi_t;

#define	IMMU_DEVI(dip)		((immu_devi_t *)(DEVI(dip)->devi_iommu))
#define	IMMU_DEVI_SET(dip, imd)	(DEVI(dip)->devi_iommu = (void *)imd)

/*
 * struct dmar_arg
 */
typedef struct immu_arg {
	int		ima_seg;
	int		ima_bus;
	int		ima_devfunc;
	dev_info_t	*ima_rdip;
	dev_info_t	*ima_ddip;
} immu_arg_t;

#define	IMMU_NDVSEG	8
#define	IMMU_NDCK	64
#define	IMMU_NPREPTES	8

typedef struct immu_hdl_private {
	immu_inv_wait_t ihp_inv_wait;
	size_t ihp_ndvseg;
	struct dvmaseg ihp_dvseg[IMMU_NDVSEG];
	immu_dcookie_t ihp_dcookies[IMMU_NDCK];

	hw_pdte_t *ihp_preptes[IMMU_NPREPTES];
	uint64_t ihp_predvma;
	int ihp_npremapped;
} immu_hdl_priv_t;

/*
 * Invalidation operation function pointers for context and IOTLB.
 * These will be set to either the register or the queue invalidation
 * interface functions, since the hardware does not allow using them
 * both at the same time.
 */
struct immu_flushops {
	void (*imf_context_fsi)(immu_t *, uint8_t, uint16_t, uint_t,
	    immu_inv_wait_t *);
	void (*imf_context_dsi)(immu_t *, uint_t, immu_inv_wait_t *);
	void (*imf_context_gbl)(immu_t *, immu_inv_wait_t *);

	void (*imf_iotlb_psi)(immu_t *, uint_t, uint64_t, uint_t, uint_t,
	    immu_inv_wait_t *);
	void (*imf_iotlb_dsi)(immu_t *, uint_t, immu_inv_wait_t *);
	void (*imf_iotlb_gbl)(immu_t *, immu_inv_wait_t *);

	void (*imf_wait)(immu_inv_wait_t *);
};

#define	immu_flush_context_fsi(i, f, s, d, w) \
	(i)->immu_flushops->imf_context_fsi(i, f, s, d, w)
#define	immu_flush_context_dsi(i, d, w) \
	(i)->immu_flushops->imf_context_dsi(i, d, w)
#define	immu_flush_context_gbl(i, w) \
	(i)->immu_flushops->imf_context_gbl(i, w)

#define	immu_flush_iotlb_psi(i, d, v, c, h, w) \
	(i)->immu_flushops->imf_iotlb_psi(i, d, v, c, h, w)
#define	immu_flush_iotlb_dsi(i, d, w) \
	(i)->immu_flushops->imf_iotlb_dsi(i, d, w)
#define	immu_flush_iotlb_gbl(i, w) \
	(i)->immu_flushops->imf_iotlb_gbl(i, w)

#define	immu_flush_wait(i, w) \
	(i)->immu_flushops->imf_wait(w)

/*
 * Globals used by IOMMU code
 */
/* shared between IOMMU files */
extern dev_info_t *root_devinfo;
extern kmutex_t immu_lock;
extern list_t immu_list;
extern boolean_t immu_setup;
extern boolean_t immu_running;
extern kmutex_t ioapic_drhd_lock;
extern list_t ioapic_drhd_list;
extern struct iommulib_ops immulib_ops;

/* switches */

/* Various features */
extern boolean_t immu_enable;
extern boolean_t immu_gfxdvma_enable;
extern boolean_t immu_intrmap_enable;
extern boolean_t immu_qinv_enable;

/* various quirks that need working around */
extern boolean_t immu_quirk_usbpage0;
extern boolean_t immu_quirk_usbfullpa;
extern boolean_t immu_quirk_usbrmrr;
extern boolean_t immu_quirk_mobile4;

/* debug messages */
extern boolean_t immu_dmar_print;

/* tunables */
extern int64_t immu_flush_gran;

extern immu_flags_t immu_global_dvma_flags;

extern int immu_use_tm;
extern int immu_use_alh;

/* ################### Interfaces exported outside IOMMU code ############## */
void immu_init(void);
void immu_startup(void);
void immu_shutdown(void);
void immu_destroy(void);
int immu_map_sgl(ddi_dma_impl_t *hp, struct ddi_dma_req *dmareq,
    int prealloc_count, dev_info_t *rdip);
int immu_unmap_sgl(ddi_dma_impl_t *hp, dev_info_t *rdip);
void immu_device_tree_changed(void);
void immu_physmem_update(uint64_t addr, uint64_t size);
int immu_quiesce(void);
int immu_unquiesce(void);
/* ######################################################################### */

/* ################# Interfaces used within IOMMU code #################### */
/* immu_dmar.c interfaces */
int immu_dmar_setup(void);
int immu_dmar_parse(void);
void immu_dmar_startup(void);
void immu_dmar_shutdown(void);
void immu_dmar_destroy(void);
boolean_t immu_dmar_blacklisted(char **strings_array, uint_t nstrings);
immu_t *immu_dmar_get_immu(dev_info_t *rdip);
dev_info_t *immu_dmar_unit_dip(void *dmar_unit);
void immu_dmar_set_immu(void *dmar_unit, immu_t *immu);
void *immu_dmar_walk_units(int seg, void *dmar_unit);
boolean_t immu_dmar_intrmap_supported(void);
uint16_t immu_dmar_ioapic_sid(int ioapicid);
immu_t *immu_dmar_ioapic_immu(int ioapicid);
void immu_dmar_rmrr_map(void);

/* immu.c interfaces */
int immu_walk_ancestor(dev_info_t *rdip, dev_info_t *ddip,
    int (*func)(dev_info_t *, void *arg), void *arg,
    int *level, immu_flags_t immu_flags);
void immu_init_inv_wait(immu_inv_wait_t *iwp, const char *s, boolean_t sync);

/* immu_regs.c interfaces */
void immu_regs_setup(list_t *immu_list);
void immu_regs_startup(immu_t *immu);
int immu_regs_resume(immu_t *immu);
void immu_regs_suspend(immu_t *immu);
void immu_regs_shutdown(immu_t *immu);
void immu_regs_destroy(list_t *immu_list);

void immu_regs_intr(immu_t *immu, uint32_t msi_addr, uint32_t msi_data,
    uint32_t uaddr);

boolean_t immu_regs_passthru_supported(immu_t *immu);
boolean_t immu_regs_is_TM_reserved(immu_t *immu);
boolean_t immu_regs_is_SNP_reserved(immu_t *immu);

void immu_regs_wbf_flush(immu_t *immu);
void immu_regs_cpu_flush(immu_t *immu, caddr_t addr, uint_t size);

void immu_regs_context_fsi(immu_t *immu, uint8_t function_mask,
    uint16_t source_id, uint_t domain_id, immu_inv_wait_t *iwp);
void immu_regs_context_dsi(immu_t *immu, uint_t domain_id,
    immu_inv_wait_t *iwp);
void immu_regs_context_gbl(immu_t *immu, immu_inv_wait_t *iwp);
void immu_regs_iotlb_psi(immu_t *immu, uint_t domain_id,
    uint64_t dvma, uint_t count, uint_t hint, immu_inv_wait_t *iwp);
void immu_regs_iotlb_dsi(immu_t *immu, uint_t domain_id, immu_inv_wait_t *iwp);
void immu_regs_iotlb_gbl(immu_t *immu, immu_inv_wait_t *iwp);

void immu_regs_set_root_table(immu_t *immu);
void immu_regs_qinv_enable(immu_t *immu, uint64_t qinv_reg_value);
void immu_regs_intr_enable(immu_t *immu, uint32_t msi_addr, uint32_t msi_data,
    uint32_t uaddr);
void immu_regs_intrmap_enable(immu_t *immu, uint64_t irta_reg);
uint64_t immu_regs_get64(immu_t *immu, uint_t reg);
void immu_regs_put64(immu_t *immu, uint_t reg, uint64_t val);
uint32_t immu_regs_get32(immu_t *immu, uint_t reg);
void immu_regs_put32(immu_t *immu, uint_t reg, uint32_t val);

/* immu_dvma.c interfaces */
void immu_dvma_setup(list_t *immu_list);
void immu_dvma_startup(immu_t *immu);
void immu_dvma_shutdown(immu_t *immu);
void immu_dvma_destroy(list_t *immu_list);

void immu_dvma_physmem_update(uint64_t addr, uint64_t size);
int immu_map_memrange(dev_info_t *, memrng_t *);
int immu_dvma_map(ddi_dma_impl_t *hp, struct ddi_dma_req *dmareq,
    uint_t prealloc_count, dev_info_t *rdip);
int immu_dvma_unmap(ddi_dma_impl_t *hp, dev_info_t *rdip);
int immu_devi_set(dev_info_t *dip, immu_flags_t immu_flags);
immu_devi_t *immu_devi_get(dev_info_t *dip);
immu_t *immu_dvma_get_immu(dev_info_t *dip, immu_flags_t immu_flags);
int pgtable_ctor(void *buf, void *arg, int kmflag);
void pgtable_dtor(void *buf, void *arg);

int immu_hdl_priv_ctor(void *buf, void *arg, int kmf);

int immu_dvma_device_setup(dev_info_t *rdip, immu_flags_t immu_flags);

void immu_print_fault_info(uint_t sid, uint64_t dvma);

/* immu_intrmap.c interfaces */
void immu_intrmap_setup(list_t *immu_list);
void immu_intrmap_startup(immu_t *immu);
void immu_intrmap_shutdown(immu_t *immu);
void immu_intrmap_destroy(list_t *immu_list);

/* registers interrupt handler for IOMMU unit */
void immu_intr_register(immu_t *immu);
int immu_intr_handler(immu_t *immu);


/* immu_qinv.c interfaces */
int immu_qinv_setup(list_t *immu_list);
void immu_qinv_startup(immu_t *immu);
void immu_qinv_shutdown(immu_t *immu);
void immu_qinv_destroy(list_t *immu_list);

void immu_qinv_context_fsi(immu_t *immu, uint8_t function_mask,
    uint16_t source_id, uint_t domain_id, immu_inv_wait_t *iwp);
void immu_qinv_context_dsi(immu_t *immu, uint_t domain_id,
    immu_inv_wait_t *iwp);
void immu_qinv_context_gbl(immu_t *immu, immu_inv_wait_t *iwp);
void immu_qinv_iotlb_psi(immu_t *immu, uint_t domain_id,
    uint64_t dvma, uint_t count, uint_t hint, immu_inv_wait_t *iwp);
void immu_qinv_iotlb_dsi(immu_t *immu, uint_t domain_id, immu_inv_wait_t *iwp);
void immu_qinv_iotlb_gbl(immu_t *immu, immu_inv_wait_t *iwp);

void immu_qinv_intr_global(immu_t *immu, immu_inv_wait_t *iwp);
void immu_qinv_intr_one_cache(immu_t *immu, uint_t idx, immu_inv_wait_t *iwp);
void immu_qinv_intr_caches(immu_t *immu, uint_t idx, uint_t cnt,
    immu_inv_wait_t *);
void immu_qinv_report_fault(immu_t *immu);

#ifdef DEBUG
#define	IMMU_DPROBE1(name, type1, arg1) \
	DTRACE_PROBE1(name, type1, arg1)
#define	IMMU_DPROBE2(name, type1, arg1, type2, arg2) \
	DTRACE_PROBE2(name, type1, arg1, type2, arg2)
#define	IMMU_DPROBE3(name, type1, arg1, type2, arg2, type3, arg3) \
	DTRACE_PROBE3(name, type1, arg1, type2, arg2, type3, arg3)
#define	IMMU_DPROBE4(name, type1, arg1, type2, arg2, type3, arg3, type4, arg4) \
	DTRACE_PROBE4(name, type1, arg1, type2, arg2, type3, arg3, type4, arg4)
#else
#define	IMMU_DPROBE1(name, type1, arg1)
#define	IMMU_DPROBE2(name, type1, arg1, type2, arg2)
#define	IMMU_DPROBE3(name, type1, arg1, type2, arg2, type3, arg3)
#define	IMMU_DPROBE4(name, type1, arg1, type2, arg2, type3, arg3, type4, arg4)
#endif


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_INTEL_IOMMU_H */
