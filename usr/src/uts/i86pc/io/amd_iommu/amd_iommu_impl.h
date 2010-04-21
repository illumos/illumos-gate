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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_AMD_IOMMU_IMPL_H
#define	_AMD_IOMMU_IMPL_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/pci.h>

#ifdef	_KERNEL

#define	AMD_IOMMU_PCI_PROG_IF	(0x0)

#define	AMD_IOMMU_CAP		(0x3)

#define	AMD_IOMMU_REG_SIZE	(0x2028)
#define	AMD_IOMMU_DEVTBL_SZ	(16)
#define	AMD_IOMMU_CMDBUF_SZ	(15)
#define	AMD_IOMMU_EVENTLOG_SZ	(15)
#define	AMD_IOMMU_DEVENT_SZ	(32)
#define	AMD_IOMMU_CMD_SZ	(16)
#define	AMD_IOMMU_EVENT_SZ	(16)

/* Capability Register offsets */
#define	AMD_IOMMU_CAP_HDR_OFF		(0x00)
#define	AMD_IOMMU_CAP_ADDR_LOW_OFF	(0x04)
#define	AMD_IOMMU_CAP_ADDR_HI_OFF	(0x08)
#define	AMD_IOMMU_CAP_RANGE_OFF		(0x0C)
#define	AMD_IOMMU_CAP_MISC_OFF		(0x10)

/* ControL Registers offsets */
#define	AMD_IOMMU_DEVTBL_REG_OFF	(0x00)
#define	AMD_IOMMU_CMDBUF_REG_OFF	(0x08)
#define	AMD_IOMMU_EVENTLOG_REG_OFF	(0x10)
#define	AMD_IOMMU_CTRL_REG_OFF		(0x18)
#define	AMD_IOMMU_EXCL_BASE_REG_OFF	(0x20)
#define	AMD_IOMMU_EXCL_LIM_REG_OFF	(0x28)
#define	AMD_IOMMU_CMDBUF_HEAD_REG_OFF	(0x2000)
#define	AMD_IOMMU_CMDBUF_TAIL_REG_OFF	(0x2008)
#define	AMD_IOMMU_EVENTLOG_HEAD_REG_OFF	(0x2010)
#define	AMD_IOMMU_EVENTLOG_TAIL_REG_OFF	(0x2018)
#define	AMD_IOMMU_STATUS_REG_OFF	(0x2020)

/* Capability Header Register Bits */
#define	AMD_IOMMU_CAP_NPCACHE	(26 << 16 | 26)
#define	AMD_IOMMU_CAP_HTTUN	(25 << 16 | 25)
#define	AMD_IOMMU_CAP_IOTLB	(24 << 16 | 24)
#define	AMD_IOMMU_CAP_TYPE	(18 << 16 | 16)
#define	AMD_IOMMU_CAP_ID	(7 << 16 | 0)

/* Capability Range Register bits */
#define	AMD_IOMMU_LAST_DEVFN	(31 << 16 | 24)
#define	AMD_IOMMU_FIRST_DEVFN	(23 << 16 | 16)
#define	AMD_IOMMU_RNG_BUS	(15 << 16 | 8)
#define	AMD_IOMMU_RNG_VALID	(7 << 16 | 7)
#define	AMD_IOMMU_HT_UNITID	(4 << 16 | 0)


/* Capability Misc Register bits */
#define	AMD_IOMMU_HT_ATSRSV	(22 << 16 | 22)
#define	AMD_IOMMU_VA_SIZE	(21 << 16 | 15)
#define	AMD_IOMMU_PA_SIZE	(14 << 16 | 8)
#define	AMD_IOMMU_MSINUM	(4 << 16 | 0)

/* Device Table Base Address register bits */
#define	AMD_IOMMU_DEVTABBASE	(51 << 16 | 12)
#define	AMD_IOMMU_DEVTABSIZE	(8 << 16 | 0)

/* Command Buffer Base Address register bits */
#define	AMD_IOMMU_COMLEN	(59 << 16 | 56)
#define	AMD_IOMMU_COMBASE	(51 << 16 | 12)

#define	AMD_IOMMU_CMDBUF_MINSZ	(8)
#define	AMD_IOMMU_CMDBUF_MAXSZ	(15)

/* Event Log Base Address register bits */
#define	AMD_IOMMU_EVENTLEN	(59 << 16 | 56)
#define	AMD_IOMMU_EVENTBASE	(51 << 16 | 12)

#define	AMD_IOMMU_EVENTLOG_MINSZ	(8)
#define	AMD_IOMMU_EVENTLOG_MAXSZ	(15)

/* Control register bits */
#define	AMD_IOMMU_CMDBUF_ENABLE		(12 << 16 | 12)
#define	AMD_IOMMU_ISOC			(11 << 16 | 11)
#define	AMD_IOMMU_COHERENT		(10 << 16 | 10)
#define	AMD_IOMMU_RESPASSPW		(9 << 16 | 9)
#define	AMD_IOMMU_PASSPW		(8 << 16 | 8)
#define	AMD_IOMMU_INVTO			(7 << 16 | 5)
#define	AMD_IOMMU_COMWAITINT_ENABLE	(4 << 16 | 4)
#define	AMD_IOMMU_EVENTINT_ENABLE	(3 << 16 | 3)
#define	AMD_IOMMU_EVENTLOG_ENABLE	(2 << 16 | 2)
#define	AMD_IOMMU_HT_TUN_ENABLE		(1 << 16 | 1)
#define	AMD_IOMMU_ENABLE		(0 << 16 | 0)

/* Exclusion Base Register bits */
#define	AMD_IOMMU_EXCL_BASE_ADDR	(51 << 16 | 12)
#define	AMD_IOMMU_EXCL_BASE_ALLOW	(1 << 16 | 1)
#define	AMD_IOMMU_EXCL_BASE_EXEN	(0 << 16 | 0)

/* Exclusion Limit Register bits */
#define	AMD_IOMMU_EXCL_LIM		(51 << 16 | 12)

/* Command Buffer Head Pointer Register bits */
#define	AMD_IOMMU_CMDHEADPTR		(18 << 16 | 4)

/* Command Buffer Tail Pointer Register bits */
#define	AMD_IOMMU_CMDTAILPTR		(18 << 16 | 4)

/* Event Log Head Pointer Register bits */
#define	AMD_IOMMU_EVENTHEADPTR		(18 << 16 | 4)

/* Event Log Tail Pointer Register bits */
#define	AMD_IOMMU_EVENTTAILPTR		(18 << 16 | 4)

/* Status Register bits */
#define	AMD_IOMMU_CMDBUF_RUN		(4 << 16 | 4)
#define	AMD_IOMMU_EVENT_LOG_RUN		(3 << 16 | 3)
#define	AMD_IOMMU_COMWAIT_INT		(2 << 16 | 2)
#define	AMD_IOMMU_EVENT_LOG_INT		(1 << 16 | 1)
#define	AMD_IOMMU_EVENT_OVERFLOW_INT	(0 << 16 | 0)

/* Device Table Bits */

/* size in bytes of each device table entry */
#define	AMD_IOMMU_DEVTBL_ENTRY_SZ	(32)

/* Interrupt Remapping related Device Table bits */
#define	AMD_IOMMU_DEVTBL_LINT1PASS	((191-128) << 16 | (191-128))
#define	AMD_IOMMU_DEVTBL_LINT0PASS	((190-128) << 16 | (190-128))
#define	AMD_IOMMU_DEVTBL_INTCTL		((189-128) << 16 | (188-128))
#define	AMD_IOMMU_DEVTBL_NMIPASS	((186-128) << 16 | (186-128))
#define	AMD_IOMMU_DEVTBL_EXTINTPAS	((185-128) << 16 | (185-128))
#define	AMD_IOMMU_DEVTBL_INITPASS	((184-128) << 16 | (184-128))
#define	AMD_IOMMU_DEVTBL_INTR_ROOT	((179-128) << 16 | (134-128))
#define	AMD_IOMMU_DEVTBL_IG		((133-128) << 16 | (133-128))
#define	AMD_IOMMU_DEVTBL_INTTABLEN	((132-128) << 16 | (129-128))
#define	AMD_IOMMU_DEVTBL_IV		((128-128) << 16 | (128-128))

/* DMA Remapping related Device Table Bits */
#define	AMD_IOMMU_DEVTBL_SYSMGT		((105-64) << 16 | (104-64))
#define	AMD_IOMMU_DEVTBL_EX		((103-64) << 16 | (103-64))
#define	AMD_IOMMU_DEVTBL_SD		((102-64) << 16 | (102-64))
#define	AMD_IOMMU_DEVTBL_CACHE		((101-64) << 16 | (101-64))
#define	AMD_IOMMU_DEVTBL_IOCTL		((100-64) << 16 | (99-64))
#define	AMD_IOMMU_DEVTBL_SA		((98-64) << 16 | (98-64))
#define	AMD_IOMMU_DEVTBL_SE		((97-64) << 16 | (97-64))
#define	AMD_IOMMU_DEVTBL_IOTLB		((96-64) << 16 | (96-64))
#define	AMD_IOMMU_DEVTBL_DOMAINID	((79-64) << 16 | (64-64))
#define	AMD_IOMMU_DEVTBL_IW		(62 << 16 | 62)
#define	AMD_IOMMU_DEVTBL_IR		(61 << 16 | 61)
#define	AMD_IOMMU_DEVTBL_ROOT_PGTBL	(51 << 16 | 12)
#define	AMD_IOMMU_DEVTBL_PG_MODE	(11 << 16 | 9)
#define	AMD_IOMMU_DEVTBL_TV		(1 << 16 | 1)
#define	AMD_IOMMU_DEVTBL_V		(0 << 16 | 0)

#define	BUS_DEVFN_TO_BDF(b, devfn)	(devfn)
#define	AMD_IOMMU_ALIAS_HASH_SZ		(256)

#define	AMD_IOMMU_REG_ADDR_LOCKED	(0x1)

/*
 * IOMMU Command bits
 */

typedef enum {
	AMD_IOMMU_CMD_INVAL = 0,
	AMD_IOMMU_CMD_COMPL_WAIT,
	AMD_IOMMU_CMD_INVAL_DEVTAB_ENTRY,
	AMD_IOMMU_CMD_INVAL_IOMMU_PAGES,
	AMD_IOMMU_CMD_INVAL_IOTLB_PAGES,
	AMD_IOMMU_CMD_INVAL_INTR_TABLE,
} amd_iommu_cmd_t;

typedef enum {
	AMD_IOMMU_CMD_FLAGS_NONE = 0,
	AMD_IOMMU_CMD_FLAGS_COMPL_WAIT = 1,
	AMD_IOMMU_CMD_FLAGS_COMPL_WAIT_F = 2,
	AMD_IOMMU_CMD_FLAGS_COMPL_WAIT_S = 4,
	AMD_IOMMU_CMD_FLAGS_PAGE_PDE_INVAL = 8,
	AMD_IOMMU_CMD_FLAGS_PAGE_INVAL_S = 16,
	AMD_IOMMU_CMD_FLAGS_IOTLB_INVAL_S = 32
} amd_iommu_cmd_flags_t;

/* Common command bits */
#define	AMD_IOMMU_CMD_OPCODE		(31 << 16 | 28)

/* Completion Wait command bits */
#define	AMD_IOMMU_CMD_COMPL_WAIT_S		(0 << 16 | 0)
#define	AMD_IOMMU_CMD_COMPL_WAIT_I		(1 << 16 | 1)
#define	AMD_IOMMU_CMD_COMPL_WAIT_F		(2 << 16 | 2)
#define	AMD_IOMMU_CMD_COMPL_WAIT_STORE_ADDR_LO	(31 << 16 | 3)
#define	AMD_IOMMU_CMD_COMPL_WAIT_STORE_ADDR_HI	(19 << 16 | 0)

/* Invalidate Device Table entry command bits */
#define	AMD_IOMMU_CMD_INVAL_DEVTAB_DEVICEID		(15 << 16 | 0)

/* Invalidate IOMMU Pages command bits */
#define	AMD_IOMMU_CMD_INVAL_PAGES_DOMAINID		(15 << 16 | 0)
#define	AMD_IOMMU_CMD_INVAL_PAGES_S			(0 << 16 | 0)
#define	AMD_IOMMU_CMD_INVAL_PAGES_PDE			(1 << 16 | 1)
#define	AMD_IOMMU_CMD_INVAL_PAGES_ADDR_LO		(31 << 16 | 12)
#define	AMD_IOMMU_CMD_INVAL_PAGES_ADDR_HI		(63 << 16 | 32)


/* Invalidate IOTLB command bits */
#define	AMD_IOMMU_CMD_INVAL_IOTLB_DEVICEID		(15 << 16 | 0)
#define	AMD_IOMMU_CMD_INVAL_IOTLB_MAXPEND		(31 << 16 | 24)
#define	AMD_IOMMU_CMD_INVAL_IOTLB_QUEUEID		(15 << 16 | 0)
#define	AMD_IOMMU_CMD_INVAL_IOTLB_S			(0 << 16 | 0)
#define	AMD_IOMMU_CMD_INVAL_IOTLB_ADDR_LO		(31 << 16 | 12)
#define	AMD_IOMMU_CMD_INVAL_IOTLB_ADDR_HI		(31 << 16 | 0)

#define	AMD_IOMMU_DEFAULT_MAXPEND			(10)

/* Invalidate Interrupt Table bits */
#define	AMD_IOMMU_CMD_INVAL_INTR_DEVICEID		(15 << 16 | 0)

#if defined(__amd64)
#define	dmac_cookie_addr	dmac_laddress
#else
#define	dmac_cookie_addr	dmac_address
#endif

#define	AMD_IOMMU_TABLE_ALIGN	((1ULL << 12) - 1)

#define	AMD_IOMMU_MAX_DEVICEID	(0xFFFF)

/*
 * DMA sync macros
 * TODO: optimize sync only small ranges
 */
#define	SYNC_FORDEV(h)	(void) ddi_dma_sync(h, 0, 0, DDI_DMA_SYNC_FORDEV)
#define	SYNC_FORKERN(h)	(void) ddi_dma_sync(h, 0, 0, DDI_DMA_SYNC_FORKERNEL)

#define	WAIT_SEC(s)	drv_usecwait(1000000*(s))

#define	CMD2OFF(c)	((c) << 4)
#define	OFF2CMD(o)	((o) >> 4)

typedef union split {
	uint64_t u64;
	uint32_t u32[2];
} split_t;

#define	BITPOS_START(b)	((b) >> 16)
#define	BITPOS_END(b)	((b) & 0xFFFF)

#define	START_MASK64(s)	(((s) == 63) ? ~((uint64_t)0) : \
	(uint64_t)((1ULL << ((s)+1)) - 1))
#define	START_MASK32(s)	(((s) == 31) ? ~((uint32_t)0) : \
	(uint32_t)((1ULL << ((s)+1)) - 1))
#define	START_MASK16(s)	(((s) == 15) ? ~((uint16_t)0) : \
	(uint16_t)((1ULL << ((s)+1)) - 1))
#define	START_MASK8(s)	(((s) == 7) ? ~((uint8_t)0) : \
	(uint8_t)((1ULL << ((s)+1)) - 1))

#define	END_MASK(e)	((1ULL << (e)) - 1)

#define	BIT_MASK64(s, e)	(uint64_t)(START_MASK64(s) & ~END_MASK(e))
#define	BIT_MASK32(s, e)	(uint32_t)(START_MASK32(s) & ~END_MASK(e))
#define	BIT_MASK16(s, e)	(uint16_t)(START_MASK16(s) & ~END_MASK(e))
#define	BIT_MASK8(s, e)		(uint8_t)(START_MASK8(s) & ~END_MASK(e))

#define	AMD_IOMMU_REG_GET64_IMPL(rp, b) \
	(((*(rp)) & (START_MASK64(BITPOS_START(b)))) >> BITPOS_END(b))
#define	AMD_IOMMU_REG_GET64(rp, b) 					 \
	((amd_iommu_64bit_bug) ? amd_iommu_reg_get64_workaround(rp, b) : \
	AMD_IOMMU_REG_GET64_IMPL(rp, b))
#define	AMD_IOMMU_REG_GET32(rp, b) \
	(((*(rp)) & (START_MASK32(BITPOS_START(b)))) >> BITPOS_END(b))
#define	AMD_IOMMU_REG_GET16(rp, b) \
	(((*(rp)) & (START_MASK16(BITPOS_START(b)))) >> BITPOS_END(b))
#define	AMD_IOMMU_REG_GET8(rp, b) \
	(((*(rp)) & (START_MASK8(BITPOS_START(b)))) >> BITPOS_END(b))

#define	AMD_IOMMU_REG_SET64_IMPL(rp, b, v) \
	((*(rp)) = \
	(((uint64_t)(*(rp)) & ~(BIT_MASK64(BITPOS_START(b), BITPOS_END(b)))) \
	| ((uint64_t)(v) << BITPOS_END(b))))

#define	AMD_IOMMU_REG_SET64(rp, b, v) 			\
	(void) ((amd_iommu_64bit_bug) ?			\
	amd_iommu_reg_set64_workaround(rp, b, v) : 	\
	AMD_IOMMU_REG_SET64_IMPL(rp, b, v))

#define	AMD_IOMMU_REG_SET32(rp, b, v) \
	((*(rp)) = \
	(((uint32_t)(*(rp)) & ~(BIT_MASK32(BITPOS_START(b), BITPOS_END(b)))) \
	| ((uint32_t)(v) << BITPOS_END(b))))

#define	AMD_IOMMU_REG_SET16(rp, b, v) \
	((*(rp)) = \
	(((uint16_t)(*(rp)) & ~(BIT_MASK16(BITPOS_START(b), BITPOS_END(b)))) \
	| ((uint16_t)(v) << BITPOS_END(b))))

#define	AMD_IOMMU_REG_SET8(rp, b, v) \
	((*(rp)) = \
	(((uint8_t)(*(rp)) & ~(BIT_MASK8(BITPOS_START(b), BITPOS_END(b)))) \
	| ((uint8_t)(v) << BITPOS_END(b))))

/*
 * Cast a 64 bit pointer to a uint64_t *
 */
#define	REGADDR64(a)	((uint64_t *)(uintptr_t)(a))

typedef enum {
	AMD_IOMMU_INTR_INVALID = 0,
	AMD_IOMMU_INTR_TABLE,
	AMD_IOMMU_INTR_ALLOCED,
	AMD_IOMMU_INTR_HANDLER,
	AMD_IOMMU_INTR_ENABLED
} amd_iommu_intr_state_t;


typedef struct amd_iommu {
	kmutex_t aiomt_mutex;
	kmutex_t aiomt_eventlock;
	kmutex_t aiomt_cmdlock;
	dev_info_t *aiomt_dip;
	uint16_t aiomt_bdf;
	int aiomt_idx;
	iommulib_handle_t aiomt_iommulib_handle;
	iommulib_ops_t *aiomt_iommulib_ops;
	uint32_t aiomt_cap_hdr;
	uint8_t aiomt_npcache;
	uint8_t aiomt_httun;
	uint8_t aiomt_iotlb;
	uint8_t aiomt_captype;
	uint8_t aiomt_capid;
	uint32_t aiomt_low_addr32;
	uint32_t aiomt_hi_addr32;
	uint64_t aiomt_reg_pa;
	uint64_t aiomt_va;
	uint64_t aiomt_reg_va;
	uint32_t aiomt_range;
	uint8_t aiomt_rng_bus;
	uint8_t aiomt_first_devfn;
	uint8_t aiomt_last_devfn;
	uint8_t aiomt_rng_valid;
	uint8_t aiomt_ht_unitid;
	uint32_t aiomt_misc;
	uint8_t aiomt_htatsresv;
	uint8_t aiomt_vasize;
	uint8_t aiomt_pasize;
	uint8_t aiomt_msinum;
	uint8_t aiomt_reg_pages;
	uint32_t aiomt_reg_size;
	uint32_t aiomt_devtbl_sz;
	uint32_t aiomt_cmdbuf_sz;
	uint32_t aiomt_eventlog_sz;
	caddr_t aiomt_devtbl;
	caddr_t aiomt_cmdbuf;
	caddr_t aiomt_eventlog;
	uint32_t *aiomt_cmd_tail;
	uint32_t *aiomt_event_head;
	ddi_dma_handle_t aiomt_dmahdl;
	void *aiomt_dma_bufva;
	uint64_t aiomt_dma_mem_realsz;
	ddi_acc_handle_t aiomt_dma_mem_hdl;
	ddi_dma_cookie_t aiomt_buf_dma_cookie;
	uint_t aiomt_buf_dma_ncookie;
	amd_iommu_intr_state_t aiomt_intr_state;
	ddi_intr_handle_t *aiomt_intr_htable;
	uint32_t aiomt_intr_htable_sz;
	uint32_t aiomt_actual_intrs;
	uint32_t aiomt_intr_cap;
	uint64_t aiomt_reg_devtbl_va;
	uint64_t aiomt_reg_cmdbuf_va;
	uint64_t aiomt_reg_eventlog_va;
	uint64_t aiomt_reg_ctrl_va;
	uint64_t aiomt_reg_excl_base_va;
	uint64_t aiomt_reg_excl_lim_va;
	uint64_t aiomt_reg_cmdbuf_head_va;
	uint64_t aiomt_reg_cmdbuf_tail_va;
	uint64_t aiomt_reg_eventlog_head_va;
	uint64_t aiomt_reg_eventlog_tail_va;
	uint64_t aiomt_reg_status_va;
	struct amd_iommu *aiomt_next;
} amd_iommu_t;

typedef struct amd_iommu_dma_devtbl_ent {
	uint16_t de_domainid;
	uint8_t de_R;
	uint8_t de_W;
	caddr_t de_root_pgtbl;
	uint8_t de_pgmode;
} amd_iommu_dma_devtbl_entry_t;

typedef struct amd_iommu_alias {
	uint16_t al_bdf;
	uint16_t al_src_bdf;
	struct amd_iommu_alias *al_next;
} amd_iommu_alias_t;

typedef struct amd_iommu_cmdargs {
	uint64_t ca_addr;
	uint16_t ca_domainid;
	uint16_t ca_deviceid;
} amd_iommu_cmdargs_t;

struct amd_iommu_page_table;

typedef struct amd_iommu_page_table_hash {
	kmutex_t ampt_lock;
	struct amd_iommu_page_table **ampt_hash;
} amd_iommu_page_table_hash_t;

typedef enum {
	AMD_IOMMU_LOG_INVALID_OP = 0,
	AMD_IOMMU_LOG_DISPLAY,
	AMD_IOMMU_LOG_DISCARD
} amd_iommu_log_op_t;

typedef enum {
	AMD_IOMMU_DEBUG_NONE = 0,
	AMD_IOMMU_DEBUG_ALLOCHDL = 0x1,
	AMD_IOMMU_DEBUG_FREEHDL = 0x2,
	AMD_IOMMU_DEBUG_BIND = 0x4,
	AMD_IOMMU_DEBUG_UNBIND = 0x8,
	AMD_IOMMU_DEBUG_WIN = 0x10,
	AMD_IOMMU_DEBUG_PAGE_TABLES = 0x20,
	AMD_IOMMU_DEBUG_DEVTBL = 0x40,
	AMD_IOMMU_DEBUG_CMDBUF = 0x80,
	AMD_IOMMU_DEBUG_EVENTLOG = 0x100,
	AMD_IOMMU_DEBUG_ACPI = 0x200,
	AMD_IOMMU_DEBUG_PA2VA = 0x400,
	AMD_IOMMU_DEBUG_TABLES = 0x800,
	AMD_IOMMU_DEBUG_EXCL = 0x1000,
	AMD_IOMMU_DEBUG_INTR = 0x2000
} amd_iommu_debug_t;

extern const char *amd_iommu_modname;
extern kmutex_t amd_iommu_global_lock;
extern amd_iommu_alias_t **amd_iommu_alias;
extern amd_iommu_page_table_hash_t amd_iommu_page_table_hash;
extern ddi_device_acc_attr_t amd_iommu_devacc;
extern amd_iommu_debug_t amd_iommu_debug;

extern uint8_t amd_iommu_htatsresv;
extern uint8_t amd_iommu_vasize;
extern uint8_t amd_iommu_pasize;
extern int amd_iommu_64bit_bug;
extern int amd_iommu_unity_map;
extern int amd_iommu_no_RW_perms;
extern int amd_iommu_no_unmap;
extern int amd_iommu_pageva_inval_all;
extern int amd_iommu_disable;
extern char *amd_iommu_disable_list;

extern uint64_t amd_iommu_reg_get64_workaround(uint64_t *regp, uint32_t bits);
extern uint64_t amd_iommu_reg_set64_workaround(uint64_t *regp, uint32_t bits,
    uint64_t value);
extern dev_info_t *amd_iommu_pci_dip(dev_info_t *rdip, const char *path);

int amd_iommu_cmd(amd_iommu_t *iommu, amd_iommu_cmd_t cmd,
    amd_iommu_cmdargs_t *cmdargs, amd_iommu_cmd_flags_t flags, int lock_held);
int amd_iommu_page_table_hash_init(amd_iommu_page_table_hash_t *ampt);
void amd_iommu_page_table_hash_fini(amd_iommu_page_table_hash_t *ampt);

int amd_iommu_read_log(amd_iommu_t *iommu, amd_iommu_log_op_t op);
void amd_iommu_read_boot_props(void);
void amd_iommu_lookup_conf_props(dev_info_t *dip);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _AMD_IOMMU_IMPL_H */
