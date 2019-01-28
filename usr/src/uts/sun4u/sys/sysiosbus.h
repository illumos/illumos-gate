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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2019 Peter Tribble.
 */

#ifndef _SYS_SYSIOSBUS_H
#define	_SYS_SYSIOSBUS_H

#ifndef _ASM
#include <sys/avintr.h>
#include <sys/vmem.h>
#include <sys/ontrap.h>
#include <sys/machsystm.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/* Things for debugging */
#ifdef SYSIO_MEM_DEBUG
#define	IO_MEMUSAGE
#endif /* SYSIO_MEM_DEBUG */

/*
 * sysio sbus constant definitions.
 */
#define	NATURAL_REG_SIZE	0x8	/* 8 Bytes is Fusion reg size */
#define	MIN_REG_SIZE		0x4	/* Smallest Fusion reg size */
#define	OFF_SYSIO_CTRL_REG	0x10
#define	SYSIO_CTRL_REG_SIZE	(NATURAL_REG_SIZE)
#define	OFF_SBUS_CTRL_REG	0x2000
#define	SBUS_CTRL_REG_SIZE	(NATURAL_REG_SIZE)
#define	OFF_SBUS_SLOT_CONFIG	0x2020
#define	SBUS_SLOT_CONFIG_SIZE	(NATURAL_REG_SIZE * 7)
#define	OFF_INTR_MAPPING_REG	0x2c00
/* #define	INTR_MAPPING_REG_SIZE	(NATURAL_REG_SIZE * 16 * 8)  */
#define	INTR_MAPPING_REG_SIZE	0x490
#define	OFF_CLR_INTR_REG	0x3408
/* #define	CLR_INTR_REG_SIZE	(NATURAL_REG_SIZE * 16 * 8) */
#define	CLR_INTR_REG_SIZE	0x488
#define	OFF_INTR_RETRY_REG	0x2c20
#define	INTR_RETRY_REG_SIZE	(MIN_REG_SIZE)
#define	OFF_SBUS_INTR_STATE_REG	0x4800
#define	SBUS_INTR_STATE_REG_SIZE (NATURAL_REG_SIZE * 2)
#define	SYSIO_IGN		46
#define	SBUS_ARBIT_ALL		0x3full
#define	SYSIO_VER_SHIFT		56

/* Error registers */
#define	OFF_SYSIO_ECC_REGS	0x20
#define	SYSIO_ECC_REGS_SIZE	NATURAL_REG_SIZE
#define	OFF_SYSIO_UE_REGS	0x30
#define	SYSIO_UE_REGS_SIZE	(NATURAL_REG_SIZE * 2)
#define	OFF_SYSIO_CE_REGS	0x40
#define	SYSIO_CE_REGS_SIZE	(NATURAL_REG_SIZE * 2)
#define	OFF_SBUS_ERR_REGS	0x2010
#define	SBUS_ERR_REGS_SIZE	(NATURAL_REG_SIZE * 2)

/* Interrupts */
#define	INTERRUPT_CPU_FIELD	26	/* Bit shift for mondo TID field */
#define	INTERRUPT_GROUP_NUMBER	6	/* Bit shift for mondo IGN field */
#define	INTERRUPT_VALID		0x80000000ull /* Mondo valid bit */
#define	SBUS_INTR_IDLE		0ull
#define	INT_PENDING 		3	/* state of the interrupt dispatch */
/*
 * Fix these (RAZ)
 * Interrupt Mapping Register defines
 */
#define	IMR_VALID		0x80000000ull	/* Valid bit */
#define	IMR_TID			0x7C000000ull	/* TID bits */
#define	IMR_IGN			0x000007C0ull	/* IGN bits */
#define	IMR_INO			0x0000003Full	/* INO bits */
#define	IMR_TID_SHIFT		26		/* Bit shift for TID field */
#define	IMR_IGN_SHIFT		6		/* Bit shift for IGN field */

#define	MAX_SBUS		(30)
#define	MAX_SBUS_LEVEL		(7)
#define	MAX_SBUS_SLOTS	(7)		/* 4 external slots + 3 internal */
#define	EXT_SBUS_SLOTS		4	/* Number of external sbus slots */
#define	MAX_SBUS_SLOT_ADDR	0x10	/* Max slot address on SYSIO */
#define	SYSIO_BURST_RANGE	(0x7f)	/* 32 bit: 64 Byte to 1 Byte burst */
#define	SYSIO64_BURST_RANGE	(0x78)	/* 64 bit: 64 Byte to 8 Byte burst */
#define	SYSIO_BURST_MASK	0xffff
#define	SYSIO64_BURST_MASK	0xffff0000
#define	SYSIO64_BURST_SHIFT	16
#define	MAX_PIL			16

/* Slot config register defines */
#define	SBUS_ETM		0x4000ull
#define	SYSIO_SLAVEBURST_MASK	0x1e	/* Mask for hardware register */
#define	SYSIO_SLAVEBURST_RANGE	(0x78)	/* 32 bit: 64 Byte to 8 Byte burst */
#define	SYSIO64_SLAVEBURST_RANGE (0x78)	/* 64 bit: 64 Byte to 8 Byte burst */
#define	SYSIO_SLAVEBURST_REGSHIFT 2	/* Convert bit positions 2**8 to 2**1 */

/*
 * Offsets of sysio, sbus, registers
 */
/* Slot configuration register mapping offsets */
#define	SBUS_SLOT0_CONFIG	0x0
#define	SBUS_SLOT1_CONFIG	0x1
#define	SBUS_SLOT2_CONFIG	0x2
#define	SBUS_SLOT3_CONFIG	0x3
#define	SBUS_SLOT4_CONFIG	0x4
#define	SBUS_SLOT5_CONFIG	0x5
#define	SBUS_SLOT6_CONFIG	0x6

/* Interrupt mapping register mapping offsets */
#define	SBUS_SLOT0_MAPREG	0x0
#define	SBUS_SLOT1_MAPREG	0x1
#define	SBUS_SLOT2_MAPREG	0x2
#define	SBUS_SLOT3_MAPREG	0x3
#define	ESP_MAPREG		0x80
#define	ETHER_MAPREG		0x81
#define	PP_MAPREG		0x82
#define	AUDIO_MAPREG		0x83
#define	KBDMOUSE_MAPREG		0x85
#define	FLOPPY_MAPREG		0x86
#define	THERMAL_MAPREG		0x87
#define	TIMER0_MAPREG		0x8C
#define	TIMER1_MAPREG		0x8D
#define	UE_ECC_MAPREG		0x8E
#define	CE_ECC_MAPREG		0x8F
#define	SBUS_ERR_MAPREG		0x90
#define	PM_WAKEUP_MAPREG	0x91
#define	FFB_MAPPING_REG		0x92
#define	EXP_MAPPING_REG		0x93

/* Interrupt clear register mapping offsets */
#define	SBUS_SLOT0_L1_CLEAR	0x0
#define	SBUS_SLOT0_L2_CLEAR	0x1
#define	SBUS_SLOT0_L3_CLEAR	0x2
#define	SBUS_SLOT0_L4_CLEAR	0x3
#define	SBUS_SLOT0_L5_CLEAR	0x4
#define	SBUS_SLOT0_L6_CLEAR	0x5
#define	SBUS_SLOT0_L7_CLEAR	0x6
#define	SBUS_SLOT1_L1_CLEAR	0x8
#define	SBUS_SLOT1_L2_CLEAR	0x9
#define	SBUS_SLOT1_L3_CLEAR	0xa
#define	SBUS_SLOT1_L4_CLEAR	0xb
#define	SBUS_SLOT1_L5_CLEAR	0xc
#define	SBUS_SLOT1_L6_CLEAR	0xd
#define	SBUS_SLOT1_L7_CLEAR	0xe
#define	SBUS_SLOT2_L1_CLEAR	0x10
#define	SBUS_SLOT2_L2_CLEAR	0x11
#define	SBUS_SLOT2_L3_CLEAR	0x12
#define	SBUS_SLOT2_L4_CLEAR	0x13
#define	SBUS_SLOT2_L5_CLEAR	0x14
#define	SBUS_SLOT2_L6_CLEAR	0x15
#define	SBUS_SLOT2_L7_CLEAR	0x16
#define	SBUS_SLOT3_L1_CLEAR	0x18
#define	SBUS_SLOT3_L2_CLEAR	0x19
#define	SBUS_SLOT3_L3_CLEAR	0x1a
#define	SBUS_SLOT3_L4_CLEAR	0x1b
#define	SBUS_SLOT3_L5_CLEAR	0x1c
#define	SBUS_SLOT3_L6_CLEAR	0x1d
#define	SBUS_SLOT3_L7_CLEAR	0x1e
#define	ESP_CLEAR		0x7f
#define	ETHER_CLEAR		0x80
#define	PP_CLEAR		0x81
#define	AUDIO_CLEAR		0x82
#define	KBDMOUSE_CLEAR		0x84
#define	FLOPPY_CLEAR		0x85
#define	THERMAL_CLEAR		0x86
#define	TIMER0_CLEAR		0x8B
#define	TIMER1_CLEAR		0x8C
#define	UE_ECC_CLEAR		0x8D
#define	CE_ECC_CLEAR		0x8E
#define	SBUS_ERR_CLEAR		0x8F
#define	PM_WAKEUP_CLEAR		0x90

/*
 * Bit shift for accessing the keyboard mouse interrupt state reg.
 * note - The external devices are the only other devices where
 * we need to check the interrupt state before adding or removing
 * interrupts.  There is an algorithm to calculate their bit shift.
 */
#define	ESP_INTR_STATE_SHIFT		0
#define	ETHER_INTR_STATE_SHIFT		2
#define	PP_INTR_STATE_SHIFT		4
#define	AUDIO_INTR_STATE_SHIFT		6
#define	KBDMOUSE_INTR_STATE_SHIFT	10
#define	FLOPPY_INTR_STATE_SHIFT		12
#define	THERMAL_INTR_STATE_SHIFT	14
#define	TIMER0_INTR_STATE_SHIFT		22
#define	TIMER1_INTR_STATE_SHIFT		24
#define	UE_INTR_STATE_SHIFT		26
#define	CE_INTR_STATE_SHIFT		28
#define	SERR_INTR_STATE_SHIFT		30
#define	PM_INTR_STATE_SHIFT		32

#define	MAX_INO_TABLE_SIZE	58	/* Max num of sbus devices on sysio */
#define	MAX_MONDO_EXTERNAL	0x1f
#define	SBUS_MAX_INO		0x3f
#define	THERMAL_MONDO		0x2a
#define	UE_ECC_MONDO		0x34
#define	CE_ECC_MONDO		0x35
#define	SBUS_ERR_MONDO		0x36

/* used for the picN kstats */
#define	SBUS_NUM_PICS	2
#define	SBUS_NUM_EVENTS	14
#define	SBUS_PIC0_MASK	0x00000000FFFFFFFFULL	/* pic0 bits of %pic */

/* Offsets for Performance registers */
#define	OFF_SBUS_PCR	0x100
#define	OFF_SBUS_PIC	0x108

/*
 * used to build array of event-names and pcr-mask values
 */
typedef	struct	sbus_event_mask {
	char	*event_name;
	uint64_t pcr_mask;
} sbus_event_mask_t;

/*
 * This type is used to describe addresses that we expect a device
 * to place on a bus i.e. addresses from the iommu address space.
 */
typedef	uint32_t	ioaddr_t;


/*
 * sysio sbus soft state data structure.
 * We use the sbus_ctrl_reg to flush hardware store buffers because
 * there is very little hardware contention on this register.
 */
struct sbus_soft_state {
	dev_info_t *dip;		/* dev info of myself */
	int upa_id;			/* UPA ID of this SYSIO */

	/*
	 * device node address property:
	 */
	caddr_t address;

	/*
	 * access handles in case we need to map the registers ourself:
	 */
	ddi_acc_handle_t ac;

	volatile uint64_t *iommu_flush_reg; /* IOMMU regs */
	volatile uint64_t *iommu_ctrl_reg;
	volatile uint64_t *tsb_base_addr;  /* Hardware reg for phys TSB base */
	volatile uint64_t *soft_tsb_base_addr; /* virtual address of TSB base */
	volatile uint64_t *iommu_tlb_tag;
	volatile uint64_t *iommu_tlb_data;

	size_t iommu_dvma_size;
	ioaddr_t iommu_dvma_base;
	uint16_t iommu_tsb_cookie;


	volatile uint64_t *sysio_ctrl_reg;	/* sysio regs */
	volatile uint64_t *sbus_ctrl_reg;   /* also used to flush store bufs */
	volatile uint64_t *sbus_slot_config_reg;
	uint_t sbus_slave_burstsizes[MAX_SBUS_SLOTS];

	volatile uint64_t *intr_mapping_reg;	/* Interrupt regs */
	volatile uint64_t *clr_intr_reg;
	volatile uint64_t *intr_retry_reg;
	volatile uint64_t *sbus_intr_state;
	volatile uint64_t *obio_intr_state;
	int8_t intr_hndlr_cnt[MAX_SBUS_SLOT_ADDR]; /* intmapreg cntr by slot */
	uchar_t spurious_cntrs[MAX_PIL + 1];	/* Spurious intr counter */

	volatile uint64_t *sysio_ecc_reg;	/* sysio ecc control reg */
	volatile uint64_t *sysio_ue_reg;	/* sysio ue ecc error regs */
	volatile uint64_t *sysio_ce_reg;	/* sysio ce ecc error regs */
	volatile uint64_t *sbus_err_reg;	/* sbus async error regs */

	volatile uint64_t *str_buf_ctrl_reg;	/* streaming buffer regs */
	volatile uint64_t *str_buf_flush_reg;
	volatile uint64_t *str_buf_sync_reg;
	volatile uint64_t *str_buf_pg_tag_diag;
	kmutex_t sync_reg_lock;			/* lock around sync flush reg */
	int stream_buf_off;

	uint_t sbus_burst_sizes;
	uint_t sbus64_burst_sizes;

	vmem_t *dvma_arena;		/* DVMA arena for this IOMMU */
	uintptr_t dvma_call_list_id;	/* DVMA callback list */
	kmutex_t dma_pool_lock;
	caddr_t dmaimplbase;		/* dma_pool_lock protects this */
	int	dma_reserve;		/* Size reserved for fast DVMA */

	struct sbus_wrapper_arg *intr_list[MAX_INO_TABLE_SIZE];
	kmutex_t intr_poll_list_lock;	/* to add/rem to intr poll list */
	kmutex_t pokefault_mutex;	/* mutex for pokefaults */
	on_trap_data_t *ontrap_data;	/* Data used to handle poke faults */
	hrtime_t bto_timestamp;		/* time of first timeout */
	int bto_ctr;			/* counter for timeouts thereafter */
	pfn_t sbus_io_lo_pfn;
	pfn_t sbus_io_hi_pfn;
	struct iophyslist *sbus_io_ranges;
	int intr_mapping_ign;		/* placeholder for the IGN */
#ifdef	DEBUG
	kmutex_t iomemlock;		/* Memory usage lock (debug only) */
	struct io_mem_list *iomem;	/* Memory usage list (debug only) */
#endif /* DEBUG */
	/*
	 * Performance registers and kstat.
	 */
	volatile uint64_t *sbus_pcr;	/* perf counter control */
	volatile uint64_t *sbus_pic; 	/* perf counter register */
	kstat_t	*sbus_counters_ksp;	/* perf counter kstat */
};


/*
 * Ugly interrupt cruft due to sysio inconsistencies.
 */
struct sbus_slot_entry {
	uint64_t slot_config;
	uint64_t mapping_reg;
	uint64_t clear_reg;
	int diagreg_shift;
};

struct sbus_intr_handler {
	dev_info_t *dip;
	uint32_t inum;
	uint_t (*funcp)();
	caddr_t arg1;
	caddr_t arg2;
	uint_t	intr_state;
	struct sbus_intr_handler *next;
};

/* sbus Interrupt routine wrapper structure */
struct sbus_wrapper_arg {
	struct sbus_soft_state *softsp;
	volatile uint64_t *clear_reg;
	uint32_t pil;
	struct sbus_intr_handler *handler_list;
};


/*
 * SYSIO parent private data structure contains register, interrupt, property
 * and range information.
 * Note: the only thing different from the "generic" sbus parent private
 * data is the interrupt specification.
 */
struct sysio_parent_private_data {
	int par_nreg;			/* number of regs */
	struct regspec *par_reg;	/* array of regs */
	int par_nintr;			/* number of interrupts */
	struct sysiointrspec *par_intr;	/* array of possible interrupts */
	int par_nrng;			/* number of ranges */
	struct rangespec *par_rng;	/* array of ranges */
	uint_t slot;			/* Slot number, on this sbus */
	uint_t offset;			/* Offset of first real "reg" */
};
#define	SYSIO_PD(d)	\
	((struct sysio_parent_private_data *)DEVI((d))->devi_parent_data)

#define	sysio_pd_getnreg(dev)		(SYSIO_PD(dev)->par_nreg)
#define	sysio_pd_getnintr(dev)		(SYSIO_PD(dev)->par_nintr)
#define	sysio_pd_getnrng(dev)		(SYSIO_PD(dev)->par_nrng)
#define	sysio_pd_getslot(dev)		(SYSIO_PD(dev)->slot)
#define	sysio_pd_getoffset(dev)		(SYSIO_PD(dev)->offset)

#define	sysio_pd_getreg(dev, n)		(&SYSIO_PD(dev)->par_reg[(n)])
#define	sysio_pd_getintr(dev, n)	(&SYSIO_PD(dev)->par_intr[(n)])
#define	sysio_pd_getrng(dev, n)		(&SYSIO_PD(dev)->par_rng[(n)])

#define	IS_INTRA_SBUS(softsp, pfn)	(pfn >= softsp->sbus_io_lo_pfn && \
					    pfn <= softsp->sbus_io_hi_pfn)

/* Used for legacy interrupts */
#define	SBUS_INTR_STATE_DISABLE		0	/* disabled */
#define	SBUS_INTR_STATE_ENABLE		1	/* enabled */

struct io_mem_list {
	dev_info_t *rdip;
	ulong_t	ioaddr;
	ulong_t	addr;
	pgcnt_t npages;
	pfn_t *pfn;
	struct io_mem_list *next;
};

/*
 * Function prototypes.
 */


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SYSIOSBUS_H */
