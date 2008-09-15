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
 * Portions Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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
#include <sys/dmar_acpi.h>
#include <sys/iommu_rscs.h>
#include <sys/cpu.h>
#include <sys/kstat.h>

/* extern functions */
extern int intel_iommu_attach_dmar_nodes(void);
extern int intel_iommu_map_sgl(ddi_dma_handle_t handle,
    struct ddi_dma_req *dmareq, uint_t prealloc);
extern void intel_iommu_unmap_sgl(ddi_dma_handle_t handle);
extern void return_instr(void);

/* define the return value for iommu_map_sgl */
#define	IOMMU_SGL_SUCCESS	0
#define	IOMMU_SGL_DISABLE	1
#define	IOMMU_SGL_NORESOURCES	2

/* register offset */
#define	IOMMU_REG_VERSION	(0x00)  /* Version Rigister, 32 bit */
#define	IOMMU_REG_CAP		(0x08)  /* Capability Register, 64 bit */
#define	IOMMU_REG_EXCAP		(0x10)  /* Extended Capability Reg, 64 bit */
#define	IOMMU_REG_GLOBAL_CMD	(0x18)  /* Global Command Register, 32 bit */
#define	IOMMU_REG_GLOBAL_STS	(0x1C)  /* Global Status Register, 32 bit */
#define	IOMMU_REG_ROOTENTRY	(0x20)  /* Root-Entry Table Addr Reg, 64 bit */
#define	IOMMU_REG_CONTEXT_CMD	(0x28)  /* Context Comand Register, 64 bit */
#define	IOMMU_REG_FAULT_STS	(0x34)  /* Fault Status Register, 32 bit */
#define	IOMMU_REG_FEVNT_CON	(0x38)  /* Fault Event Control Reg, 32 bit */
#define	IOMMU_REG_FEVNT_DATA	(0x3C)  /* Fault Event Data Register, 32 bit */
#define	IOMMU_REG_FEVNT_ADDR	(0x40)  /* Fault Event Address Reg, 32 bit */
#define	IOMMU_REG_FEVNT_UADDR	(0x44)  /* Fault Event Upper Addr Reg, 32 bit */
#define	IOMMU_REG_AFAULT_LOG	(0x58)  /* Advanced Fault Log Reg, 64 bit */
#define	IOMMU_REG_PMER		(0x64)  /* Protected Memory Enble Reg, 32 bit */
#define	IOMMU_REG_PLMBR		(0x68)  /* Protected Low Mem Base Reg, 32 bit */
#define	IOMMU_REG_PLMLR		(0x6C)  /* Protected Low Mem Lim Reg, 32 bit */
#define	IOMMU_REG_PHMBR		(0X70)  /* Protectd High Mem Base Reg, 64 bit */
#define	IOMMU_REG_PHMLR		(0x78)  /* Protected High Mem Lim Reg, 64 bit */
#define	IOMMU_REG_INVAL_QH	(0x80)  /* Invalidation Queue Head, 64 bit */
#define	IOMMU_REG_INVAL_QT	(0x88)  /* Invalidation Queue Tail, 64 bit */
#define	IOMMU_REG_INVAL_QAR	(0x90)  /* Invalidtion Queue Addr Reg, 64 bit */
#define	IOMMU_REG_INVAL_CSR	(0x9C)  /* Inval Compl Status Reg, 32 bit */
#define	IOMMU_REG_INVAL_CECR	(0xA0)  /* Inval Compl Evnt Ctrl Reg, 32 bit */
#define	IOMMU_REG_INVAL_CEDR	(0xA4)  /* Inval Compl Evnt Data Reg, 32 bit */
#define	IOMMU_REG_INVAL_CEAR	(0xA8)  /* Inval Compl Event Addr Reg, 32 bit */
#define	IOMMU_REG_INVAL_CEUAR	(0xAC)  /* Inval Comp Evnt Up Addr reg, 32bit */
#define	IOMMU_REG_IRTAR		(0xB8)  /* INTR Remap Tbl Addr Reg, 64 bit */

/* ioapic memory region */
#define	IOAPIC_REGION_START	(0xfee00000)
#define	IOAPIC_REGION_END	(0xfeefffff)

/* iommu page */
#define	IOMMU_LEVEL_STRIDE	(9)
#define	IOMMU_LEVEL_SIZE	((uint64_t)1 << IOMMU_LEVEL_STRIDE)
#define	IOMMU_LEVEL_OFFSET	(IOMMU_LEVEL_SIZE - 1)
#define	IOMMU_PAGE_SHIFT	(12)
#define	IOMMU_PAGE_SIZE		(uint64_t)((uint64_t)1 << IOMMU_PAGE_SHIFT)
#define	IOMMU_PAGE_MASK		~(IOMMU_PAGE_SIZE - 1)
#define	IOMMU_PAGE_OFFSET	(IOMMU_PAGE_SIZE - 1)
#define	IOMMU_PAGE_ROUND(x)	(((x) + IOMMU_PAGE_OFFSET) & IOMMU_PAGE_MASK)
#define	IOMMU_PTOB(x)		(((uint64_t)(x)) << IOMMU_PAGE_SHIFT)
#define	IOMMU_BTOP(x)		((x) >> IOMMU_PAGE_SHIFT)
#define	IOMMU_BTOPR(x)		IOMMU_BTOP((x) + IOMMU_PAGE_OFFSET)
#define	IOMMU_LEVEL_TO_AGAW(x)	((x) * 9 + 12)
#define	IOMMU_IOVA_MAX_4G	(((uint64_t)1 << 32) - 1)
#define	IOMMU_SIZE_4G		((uint64_t)1 << 32)
#define	IOMMU_SIZE_2M		((uint64_t)1 << 21)
#define	IOMMU_2M_MASK		~(IOMMU_SIZE_2M - 1)
#define	IOMMU_PTE_MAX		(IOMMU_PAGE_SIZE >> 3)

/* iommu page entry property */
#define	IOMMU_PAGE_PROP_READ	(1)
#define	IOMMU_PAGE_PROP_WRITE	(2)
#define	IOMMU_PAGE_PROP_RW	(IOMMU_PAGE_PROP_READ | IOMMU_PAGE_PROP_WRITE)
#define	IOMMU_PAGE_PROP_NOSYNC	(4)

/* root context entry */
#define	ROOT_ENTRY_GET_P(x)		(((x)->lo) & 0x1)
#define	ROOT_ENTRY_SET_P(x)		((x)->lo) |= 0x1
#define	ROOT_ENTRY_GET_CTP(x)		(((x)->lo) & IOMMU_PAGE_MASK)
#define	ROOT_ENTRY_SET_CTP(x, p)	((x)->lo) |= ((p) & IOMMU_PAGE_MASK)
#define	CONT_ENTRY_GET_P(x)		(((x)->lo) & 0x1)
#define	CONT_ENTRY_SET_P(x)		((x)->lo) |= 0x1
#define	CONT_ENTRY_SET_ASR(x, p)	((x)->lo) |= ((p) & IOMMU_PAGE_MASK)
#define	CONT_ENTRY_GET_ASR(x)		(((x)->lo) & IOMMU_PAGE_MASK)
#define	CONT_ENTRY_SET_AW(x, v)		((x)->hi) |= ((v) & 7)
#define	CONT_ENTRY_SET_DID(x, v) ((x)->hi) |= (((v) & ((1 << 16) - 1)) << 8)

/* fault register */
#define	IOMMU_FAULT_STS_PPF		(2)
#define	IOMMU_FAULT_STS_PFO		(1)
#define	IOMMU_FAULT_STS_IQE		(1 << 4)
#define	IOMMU_FAULT_GET_INDEX(x)	(((x) >> 8) & 0xff)
#define	IOMMU_FRR_GET_F(x)		((x) >> 63)
#define	IOMMU_FRR_GET_FR(x)		(((x) >> 32) & 0xff)
#define	IOMMU_FRR_GET_FT(x)		(((x) >> 62) & 0x1)
#define	IOMMU_FRR_GET_SID(x)		((x) & 0xffff)

/* (ex)capability register */
#define	IOMMU_CAP_GET_NFR(x)		((((x) >> 40) & 0xff) + 1)
#define	IOMMU_CAP_GET_DWD(x)		(((x) >> 54) & 1)
#define	IOMMU_CAP_GET_DRD(x)		(((x) >> 55) & 1)
#define	IOMMU_CAP_GET_PSI(x)		(((x) >> 39) & 1)
#define	IOMMU_CAP_GET_MAMV(x)		(((x) >> 48) & 0x3f)
#define	IOMMU_CAP_GET_CM(x)		(((x) >> 7) & 1)
#define	IOMMU_CAP_GET_RWBF(x)		(((x) >> 4) & 1)
#define	IOMMU_CAP_GET_FRO(x)		((((x) >> 24) & 0x3ff) * 16)
#define	IOMMU_CAP_MGAW(x)		(((((uint64_t)x) >> 16) & 0x3f) + 1)
#define	IOMMU_CAP_SAGAW(x)		(((x) >> 8) & 0x1f)
#define	IOMMU_CAP_ND(x)			(1 << (((x) & 0x7) *2 + 4)) -1
#define	IOMMU_ECAP_GET_IRO(x)		((((x) >> 8) & 0x3ff) << 4)
#define	IOMMU_ECAP_GET_C(x)		((x) & 0x1)
#define	IOMMU_ECAP_GET_IR(x)		((x) & 0x8)
#define	IOMMU_ECAP_GET_DI(x)		((x) & 0x4)
#define	IOMMU_ECAP_GET_QI(x)		((x) & 0x2)


/* iotlb invalidation */
#define	TLB_INV_GLOBAL		(((uint64_t)1) << 60)
#define	TLB_INV_DOMAIN		(((uint64_t)2) << 60)
#define	TLB_INV_PAGE		(((uint64_t)3) << 60)
#define	TLB_INV_GET_IAIG(x)	(((x) >> 57) & 7)
#define	TLB_INV_DRAIN_READ	(((uint64_t)1) << 49)
#define	TLB_INV_DRAIN_WRITE	(((uint64_t)1) << 48)
#define	TLB_INV_DID(x)		(((uint64_t)((x) & 0xffff)) << 32)
#define	TLB_INV_IVT		(((uint64_t)1) << 63)
#define	TLB_IVA_HINT(x)		(((x) & 0x1) << 6)
#define	TLB_IVA_LEAF		1
#define	TLB_IVA_WHOLE		0

/* context invalidation */
#define	CCMD_INV_ICC		(((uint64_t)1) << 63)
#define	CCMD_INV_GLOBAL		(((uint64_t)1) << 61)
#define	CCMD_INV_DOMAIN		(((uint64_t)2) << 61)
#define	CCMD_INV_DEVICE		(((uint64_t)3) << 61)
#define	CCMD_INV_DID(x)		((uint64_t)((x) & 0xffff))
#define	CCMD_INV_SID(x)		(((uint64_t)((x) & 0xffff)) << 16)
#define	CCMD_INV_FM(x)		(((uint64_t)((x) & 0x3)) << 32)

/* global command register */
#define	IOMMU_GCMD_TE		(((uint32_t)1) << 31)
#define	IOMMU_GCMD_SRTP		(((uint32_t)1) << 30)
#define	IOMMU_GCMD_SFL		(((uint32_t)1) << 29)
#define	IOMMU_GCMD_EAFL		(((uint32_t)1) << 28)
#define	IOMMU_GCMD_WBF		(((uint32_t)1) << 27)
#define	IOMMU_GCMD_QIE		(((uint32_t)1) << 26)
#define	IOMMU_GCMD_IRE		(((uint32_t)1) << 25)
#define	IOMMU_GCMD_SIRTP	(((uint32_t)1) << 24)
#define	IOMMU_GCMD_CFI		(((uint32_t)1) << 23)

/* global status register */
#define	IOMMU_GSTS_TES		(((uint32_t)1) << 31)
#define	IOMMU_GSTS_RTPS		(((uint32_t)1) << 30)
#define	IOMMU_GSTS_FLS		(((uint32_t)1) << 29)
#define	IOMMU_GSTS_AFLS		(((uint32_t)1) << 28)
#define	IOMMU_GSTS_WBFS		(((uint32_t)1) << 27)
#define	IOMMU_GSTS_QIES		(((uint32_t)1) << 26)
#define	IOMMU_GSTS_IRES		(((uint32_t)1) << 25)
#define	IOMMU_GSTS_IRTPS	(((uint32_t)1) << 24)
#define	IOMMU_GSTS_CFIS		(((uint32_t)1) << 23)

/* psi address mask */
#define	ADDR_AM_MAX(m)		(((uint_t)1) << (m))
#define	ADDR_AM_OFFSET(n, m)	((n) & (ADDR_AM_MAX(m) - 1))

/* dmar fault event */
#define	IOMMU_INTR_IPL			(8)
#define	IOMMU_REG_FEVNT_CON_IM_SHIFT	(31)

/* page entry structure */
typedef uint64_t *iopte_t;

/* root/context entry structure */
typedef struct iorce {
	uint64_t lo;
	uint64_t hi;
} *iorce_t;

/* kernel maintained page table entry */
typedef struct iovpte {
	/*
	 * pointer to the cpu accessable
	 * iommu page table
	 */
	caddr_t vp;
	/*
	 * pointer to the real iommu
	 * page table
	 */
	caddr_t pp;
} *iovpte_t;

/*
 * struct iommu_kstat
 *   kstat tructure for iommu
 */
typedef struct iommu_kstat {

	/* hardware dependent */
	kstat_named_t is_enabled;
	kstat_named_t is_iotlb_psi;
	kstat_named_t is_iotlb_domain;
	kstat_named_t is_iotlb_global;
	kstat_named_t is_write_buffer;
	kstat_named_t is_context_cache;
	kstat_named_t is_wait_complete_us;
	kstat_named_t is_domain_alloc;

	/* hardware independent */
	kstat_named_t is_page_used;
} iommu_kstat_t;

/*
 * struct iommu_stat
 *   statistics for iommu
 */
typedef struct iommu_stat {
	uint64_t st_iotlb_psi;
	uint64_t st_iotlb_domain;
	uint64_t st_iotlb_global;
	uint64_t st_write_buffer;
	uint64_t st_context_cache;
	uint64_t st_wait_complete_us;
	uint64_t st_domain_alloc;
} iommu_stat_t;

struct intel_iommu_state;
struct iommu_dvma_cookie;
struct dmar_domain_state;

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

/*
 * struct dmar_ops
 *   dmar hardware operation functions
 */
struct dmar_ops {
	/* enable */
	void (*do_enable)(struct intel_iommu_state *iommu);

	/* page fault */
	int (*do_fault)(struct intel_iommu_state *iommu);

	/* cache related */
	void (*do_flwb)(struct intel_iommu_state *iommu);
	void (*do_iotlb_psi)(struct intel_iommu_state *iommu, uint_t domain_id,
	    uint64_t dvma, uint_t count, uint_t hint);
	void (*do_iotlb_dsi)(struct intel_iommu_state *iommu, uint_t domain_id);
	void (*do_iotlb_gbl)(struct intel_iommu_state *iommu);
	void (*do_context_fsi)(struct intel_iommu_state *iommu,
	    uint8_t function_mask,
	    uint16_t source_id, uint_t domain_id);
	void (*do_context_dsi)(struct intel_iommu_state *iommu,
	    uint_t domain_id);
	void (*do_context_gbl)(struct intel_iommu_state *iommu);
	void (*do_plant_wait)(struct intel_iommu_state *iommu,
	    struct iommu_dvma_cookie *dcookies, uint_t count,
	    uint_t array_size);
	void (*do_reap_wait)(struct intel_iommu_state *iommu);

	/* root entry */
	void (*do_set_root_table)(struct intel_iommu_state *iommu);

	/* cpu cache line flush */
	void (*do_clflush)(caddr_t addr, uint_t size);
};

/*
 * struct iotlb_cache_node
 *   the pending data for iotlb flush
 */
typedef struct iotlb_pend_node {
	/* node to hook into the list */
	list_node_t			node;
	/* ptr to dvma cookie array */
	struct iommu_dvma_cookie	*icn_dcookies;
	/* valid cookie count */
	uint_t				icn_count;
	/* array size */
	uint_t				icn_array_size;
} iotlb_pend_node_t;

/*
 * struct iotlb_cache_head
 *   the pending head for the iotlb flush
 */
typedef struct iotlb_pend_head {
	/* the pending iotlb list */
	kmutex_t	ich_pend_lock;
	list_t		ich_pend_list;
	uint_t		ich_pend_count;

	/* the pending node cache list */
	kmutex_t	ich_mem_lock;
	list_t		ich_mem_list;
} iotlb_pend_head_t;

/*
 * struct intel_iommu_state
 *   This structure describes the state information
 *   of each iommu unit in the platform. It is cre-
 *   ated in the dmarnex driver's attach(), and will
 *   be used in every DMA DDI and the iommu transla-
 *   tion functions
 *
 * node			- the list node to hook it in iommu_states
 * iu_drhd		- the related drhd
 * iu_reg_handle	- register access handler
 * iu_reg_lock		- lock to protect register operation
 * iu_reg_address	- virtual address of the register base address
 * iu_capability	- copy of the capability register
 * iu_excapability	- copy of the extention register
 * iu_root_entry_paddr	- root entry page table
 * iu_root_context_lock	- root context entry lock
 * iu_gaw		- guest address width
 * iu_agaw		- adjusted guest address width
 * iu_level		- the page table level
 * iu_global_cmd_reg	- global command register save place
 * iu_max_domain	- the maximum domain numbers
 * iu_domain_id_hdl	- domain id allocator handler
 * iu_enabled		- the soft state of the iommu
 * iu_coherency		- hardware access is coherent
 * iu_kstat		- kstat pointer
 * iu_statistics	- iommu statistics
 * iu_dmar_ops		- iommu operation functions
 * iu_pend_head		- pending iotlb list
 */
typedef struct intel_iommu_state {
	list_node_t		node;
	drhd_info_t		*iu_drhd;
	ddi_acc_handle_t	iu_reg_handle;
	kmutex_t		iu_reg_lock;
	caddr_t			iu_reg_address;
	uint64_t		iu_capability;
	uint64_t		iu_excapability;
	paddr_t			iu_root_entry_paddr;
	kmutex_t		iu_root_context_lock;
	int			iu_gaw;
	int			iu_agaw;
	int			iu_level;
	uint32_t		iu_global_cmd_reg;
	int			iu_max_domain;
	iommu_rscs_t		iu_domain_id_hdl;
	boolean_t		iu_enabled;
	boolean_t		iu_coherency;
	kstat_t			*iu_kstat;
	iommu_stat_t		iu_statistics;
	struct dmar_ops		*iu_dmar_ops;
	iotlb_pend_head_t	iu_pend_head;
} intel_iommu_state_t;

/*
 * struct dvma_cache_node
 *   dvma cache node
 */
typedef struct dvma_cache_node {
	list_node_t		node;

	/* parameters */
	size_t			dcn_align;
	uint64_t		dcn_dvma;
} dvma_cache_node_t;

/*
 * struct dvma_cache_head
 *   dvma cache head
 */
typedef struct dvma_cache_head {
	/* the list of the free dvma */
	kmutex_t	dch_free_lock;
	list_t		dch_free_list;
	uint_t		dch_free_count;

	/* the cache for the node memory */
	kmutex_t	dch_mem_lock;
	list_t		dch_mem_list;
} dvma_cache_head_t;

#define	DVMA_CACHE_HEAD_CNT	64

/*
 * struct dmar_domain_state
 *   This structure describes the state information
 *   of an iommu domain. It is created and initiated
 *   when the driver call ddi_dma_bind_handle(). And
 *   will be used in each iommu translation fucntions
 *
 * dm_domain_id		- the domain id
 * dm_iommu		- iommu pointer this domain belongs to
 * dm_dvma_map		- dvma map
 * dm_dvma_cache	- dvma cahce lists
 * dm_page_table_paddr	- page table address for this domain
 * dm_pt_tree		- the kernel maintained page tables
 * dm_identity		- does this domain identity mapped
 */
typedef struct dmar_domain_state {
	uint_t			dm_domain_id;
	intel_iommu_state_t	*dm_iommu;
	vmem_t			*dm_dvma_map;
	dvma_cache_head_t	dm_dvma_cache[DVMA_CACHE_HEAD_CNT];
	paddr_t			dm_page_table_paddr;
	struct iovpte		dm_pt_tree;
	boolean_t		dm_identity;
} dmar_domain_state_t;

/*
 * struct dmar_reserve_mem
 *   This structure describes the reserved memory regions which can
 *   not be allocated by vmem.
 *
 * node		- list node
 * rm_pfn_start	- the start page frame number
 * rm_pfn_end	- the end page frame number
 */
typedef struct dmar_reserve_pages {
	list_node_t	node;
	uint64_t	rm_pfn_start;
	uint64_t	rm_pfn_end;
} dmar_reserve_pages_t;

/*
 * struct pci_dev_info
 *   pci device info structure
 */
typedef struct pci_dev_info {
	list_node_t	node;
	int		pdi_seg;
	int		pdi_bus;
	int		pdi_devfn;
	dev_info_t	*pdi_dip;
} pci_dev_info_t;

/*
 * struct iommu_dip_private
 *   the intel iommu private structure hook on dev_info
 */
typedef struct iommu_private {
	/* pci seg, bus, dev, func */
	int		idp_seg;
	int		idp_bus;
	int		idp_devfn;

	/* ppb information */
	boolean_t	idp_is_bridge;
	int		idp_bbp_type;
	int		idp_sec;
	int		idp_sub;

	/* identifier for special devices */
	boolean_t	idp_is_display;
	boolean_t	idp_is_lpc;

	/* domain ptr */
	dmar_domain_state_t	*idp_domain;
} iommu_private_t;

#define		IOMMU_PPB_NONE		0
#define		IOMMU_PPB_PCIE_PCIE	1
#define		IOMMU_PPB_PCIE_PCI	2
#define		IOMMU_PPB_PCI_PCI	3

#define		MAX_COOKIE_CACHE_SIZE	20
/*
 * struct iommu_dvma_cookie
 *   this cookie record the dvma allocated for
 *   an individual device
 */
typedef struct iommu_dvma_cookie {
	uint64_t	dc_addr;
	uint64_t	dc_size;
	struct dmar_domain_state	*dc_domain;
	size_t		dc_align;
	struct iommu_dvma_cookie	*dc_next;
} iommu_dvma_cookie_t;

/*
 * struct dvma_cookie_head
 *   the cookie cache head
 */
typedef struct dvma_cookie_head {
	kmutex_t		dch_lock;
	iommu_dvma_cookie_t	*dch_next;
	uint_t			dch_count;
} dvma_cookie_head_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_INTEL_IOMMU_H */
