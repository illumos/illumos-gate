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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_AXQ_H
#define	_SYS_AXQ_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* AXQ register offset constant */
#define	AXQ_REG_OFFSET		0x20
#define	AXQ_REGOFF(idx)		((idx) * AXQ_REG_OFFSET)

/*
 * AXQ system register offsets
 * Each Starcat AXQ asic instance is logically
 * associated with each slot in the expander board.
 * Slot 0 is the full slot (or full bandwidth slot)
 * and Slot1 is the half slot (or half bandwidth slot).
 * Some system registers are only accessible in certain
 * slot type.
 */

/* domain control register (slot0 & slot1) */
#define	AXQ_SLOT0_DOMCTRL	AXQ_REGOFF(0x1)
#define	AXQ_SLOT1_DOMCTRL	AXQ_REGOFF(0x2)

/* cpu2ssc intr register */
#define	AXQ_SLOT_CPU2SSC_INTR	AXQ_REGOFF(0x3)

/* performance counters (one set per slot) */
#define	AXQ_SLOT0_PERFCNT_SEL	AXQ_REGOFF(0x9)
#define	AXQ_SLOT0_PERFCNT0	AXQ_REGOFF(0xA)
#define	AXQ_SLOT0_PERFCNT1	AXQ_REGOFF(0xB)
#define	AXQ_SLOT0_PERFCNT2	AXQ_REGOFF(0xC)
#define	AXQ_SLOT1_PERFCNT_SEL	AXQ_REGOFF(0x8)
#define	AXQ_SLOT1_PERFCNT0	AXQ_REGOFF(0xD)
#define	AXQ_SLOT1_PERFCNT1	AXQ_REGOFF(0xE)
#define	AXQ_SLOT1_PERFCNT2	AXQ_REGOFF(0xF)

/* CASM slots (for both slot0 & slot1) */
#define	AXQ_CASM_SLOT_START	AXQ_REGOFF(0x10)
#define	AXQ_CASM_SLOT_END	AXQ_REGOFF(0x21)

/* CDC registers (only available in slot0) */
#define	AXQ_SLOT0_CDC_ADR_TEST	AXQ_REGOFF(0x2C)
#define	AXQ_SLOT0_CDC_CTL_TEST	AXQ_REGOFF(0x2D)
#define	AXQ_SLOT0_CDC_DATA_WR3	AXQ_REGOFF(0x2E)
#define	AXQ_SLOT0_CDC_DATA_WR2	AXQ_REGOFF(0x2F)
#define	AXQ_SLOT0_CDC_DATA_WR1	AXQ_REGOFF(0x30)
#define	AXQ_SLOT0_CDC_DATA_WR0	AXQ_REGOFF(0x31)
#define	AXQ_SLOT0_CDC_CNT_TEST	AXQ_REGOFF(0x32)
#define	AXQ_SLOT0_CDC_RD_DATA3	AXQ_REGOFF(0x33)
#define	AXQ_SLOT0_CDC_RD_DATA2	AXQ_REGOFF(0x34)
#define	AXQ_SLOT0_CDC_RD_DATA1	AXQ_REGOFF(0x35)
#define	AXQ_SLOT0_CDC_RD_DATA0	AXQ_REGOFF(0x36)

/* NASM registers */
#define	AXQ_SLOT0_NASM		AXQ_REGOFF(0x37)
#define	AXQ_SLOT1_NASM		AXQ_REGOFF(0x38)

#define	AXQ_NASM_TYPE_IO		0
#define	AXQ_NASM_TYPE_SLOT0_CMMU	1
#define	AXQ_NASM_TYPE_WIB		2
#define	AXQ_NASM_TYPE_WIB_STRIPED	3
#define	AXQ_NASM_TYPE_SHIFT		5

/* SDI Timeout register */
#define	AXQ_SLOT_SDI_TIMEOUT_RD		AXQ_REGOFF(0x2A)
#define	AXQ_SLOT_SDI_TIMEOUT_RDCLR	AXQ_REGOFF(0x2B)

/*
 * Bits for domain control register
 */
#define	AXQ_DOMCTRL_BUSY	0x1
#define	AXQ_DOMCTRL_PAUSE	0x10
#define	AXQ_DOMCTRL_PIOFIX	0x40

/*
 * Bits for CDC registers
 */
/* CDC control test register */
#define	AXQ_CDC_TMODE_WR		0x20000
#define	AXQ_CDC_TMODE_RDCMP		0x40000
#define	AXQ_CDC_TMODE_WR_RDCMP0		0x60000
#define	AXQ_CDC_TMODE_WR_RDCMP1		0x80000
#define	AXQ_CDC_DATA_ECC_CHK_EN		0x10000
#define	AXQ_CDC_ADR_PAR_CHK_EN		0x08000
#define	AXQ_CDC_DATA_ECC_GEN_EN		0x04000
#define	AXQ_CDC_ADR_PAR_GEN_EN		0x02000
#define	AXQ_CDC_DATA2PAR_MUX_SEL_DATA	0x00800
#define	AXQ_CDC_ADR2SRAM_MUX_SEL_TEST	0x00080
#define	AXQ_CDC_ADR_INCR_XOR_CTRL	0x00010
#define	AXQ_CDC_DIS			0x00001

/* CDC Address Test register */
#define	AXQ_CDC_ADR_TEST_EN		0x80000

/* CDC counter test register */
#define	AXQ_CDC_CNT_TEST_DONE		0x80000000

/*
 * Bits for CPU to SSC interrupt register
 */
#define	AXQ_CPU2SSC_INTR_PEND		0x80000000

/*
 * Each AXQ instance has one pcr (performance control
 * register) controlling 3 pics (performance instru-
 * mentation counter).  pic0 and pic1 are similar
 * and have identical inputs to their muxes. pic2
 * only counts the clock.
 */

/* Bit masks for selecting pic mux input */
#define	FREEZE_CNT	0x0
#define	COUNT_CLK	0x1
#define	HA_INPUT_FIFO	0x2
#define	HA_INTR_INFO	0x3
#define	HA_PIO_FIFO	0x4
#define	HA_ADR_FIFO_LK3	0x5
#define	HA_ADR_FIFO_LK2	0x6
#define	HA_ADR_FIFO_LK1	0x7
#define	HA_ADR_FIFO_LK0	0x8
#define	HA_DUMP_Q	0x9
#define	HA_RD_F_STB_Q	0xA
#define	HA_DP_WR_Q	0xB
#define	HA_INT_Q	0xC
#define	HA_WRB_Q	0xD
#define	HA_WR_MP_Q	0xE
#define	HA_WRTAG_Q	0xF
#define	HA_WT_WAIT_FIFO	0x10
#define	HA_WRB_STB_FIFO	0x11
#define	HA_AP0_Q	0x12
#define	HA_AP1_Q	0x13
#define	HA_NEW_WR_Q	0x14
#define	HA_DP_RD_Q	0x15
#define	HA_UNLOCK_Q	0x16
#define	HA_CDC_UPD_Q	0x17
#define	HA_DS_Q		0x18
#define	HA_UNLK_WAIT_Q	0x19
#define	HA_RD_MP_Q	0x1A
#define	L2_IO_Q		0x1B
#define	L2_SB_Q		0x1C
#define	L2_RA_Q		0x1D
#define	L2_HA_Q		0x1E
#define	L2_SA_Q		0x1F
#define	RA_WAIT_FIFO	0x20
#define	RA_WRB_INV_FIFO	0x21
#define	RA_WRB_FIFO	0x22
#define	RA_CC_PTR_FIFO	0x23
#define	RA_IO_PTR_FIFO	0x24
#define	RA_INT_PTR_FIFO	0x25
#define	RA_RP_Q		0x26
#define	RA_WRB_RP_Q	0x27
#define	RA_DP_Q		0x28
#define	RA_DP_STB_Q	0x29
#define	RA_GTARG_Q	0x2A
#define	SDC_RECV_Q	0x2B
#define	SDC_REDIR_IO_Q	0x2C
#define	SDC_REDIR_SB_Q	0x2D
#define	SDC_OUTB_IO_Q	0x2E
#define	SDC_OUTB_SB_Q	0x2F
#define	SA_ADD1_INPUT_Q	0x30
#define	SA_ADD2_INPUT_Q	0x31
#define	SA_INV_Q	0x32
#define	SA_NO_INV_Q	0x33
#define	SA_INT_DP_Q	0x34
#define	SA_DP_Q		0x35
#define	SL_WRTAG_Q	0x36
#define	SL_RTO_DP_Q	0x37
#define	SYSREG_INPUT_Q	0x38
#define	SDI_SYS_STATUS1	0x39
#define	SDI_SYS_STATUS0	0x3A
#define	CDC_HITS	0x3B
#define	TOTAL_CDC_READ	0x3C
#define	HA_WATRANID_SD	0x3D
#define	HA_STB_SD	0x3E
#define	HA_L2_IRQ_SD	0x3F
#define	HA_SL_WRTAG_SD	0x40
#define	AA_HOME_CC_FULL	0x41
#define	AA_HOME_IO_FULL	0x42
#define	AA_SLAVE_FULL	0x43
#define	AA_RP_FULL	0x44

/* Shift definitions into pcr for programming pics */
#define	AXQ_PIC_SHIFT	7

/* event constants */
#define	AXQ_NUM_EVENTS		0x45
#define	AXQ_PIC0_1_NUM_EVENTS	0x45
#define	AXQ_PIC2_NUM_EVENTS	0x2
#define	AXQ_NUM_PICS	3
#define	AXQ_PIC_CLEAR_MASK	0x7F

/* AXQ constants */
#define	SLOT0_AXQ		0
#define	SLOT1_AXQ		1
#define	AXQ_MAX_EXP		18
#define	AXQ_MAX_SLOT_PER_EXP	2
#define	AXQ_CDC_SRAM_SIZE	0x40000
#define	AXQ_CDC_FLUSH_WAIT	4
#define	AXQ_INTR_PEND_WAIT	10
#define	AXQ_NASM_SIZE		256

/*
 * Struct element describing a eventname and
 * its pcr-mask.
 */
typedef struct axq_event_mask {
	char	*event_name;
	uint64_t pcr_mask;
} axq_event_mask_t;

/*
 * NASM RAM system register for reading
 */
typedef union {
	struct axq_nasm_read {
		uint32_t pad	: 16;
		uint32_t valid	: 1;
		uint32_t addr	: 8;
		uint32_t data	: 7;
	} bit;
	uint32_t val;
} axq_nasm_read_u;

/*
 * NASM RAM system register for reading
 */
typedef union {
	struct axq_nasm_write {
		uint32_t pad	: 16;
		uint32_t addr	: 8;
		uint32_t rw	: 1;
		uint32_t data	: 7;
	} bit;
	uint32_t val;
} axq_nasm_write_u;


/*
 * Global data structure that is used to
 * export certain axq registers in
 * local space. Right now, the only
 * register we want to access in local space
 * is the cheetah2ssc interrupt reg. There
 * could be more in future.
 */
struct axq_local_regs {
	kmutex_t axq_local_lock;
	int initflag;
	caddr_t laddress;
	ddi_acc_handle_t ac;
	volatile uint32_t *axq_cpu2ssc_intr;
};

/*
 * axq soft state data structure.
 */
struct axq_soft_state {
	dev_info_t *dip;		/* devinfo of myself */
	uint32_t portid;		/* port id */
	uint32_t expid;			/* expander id */
	uchar_t slotnum;		/* slot 0 or 1 */
	caddr_t address;		/* mapped devnode addr property */
	ddi_acc_handle_t ac0;		/* access handle for reg0 mapping */
	uint64_t axq_phyaddr;		/* physical address of conf space */
	kmutex_t axq_lock;		/* mutex protecting this softstate */

	volatile uint32_t *axq_domain_ctrl;

	/* CASM register slots */
	volatile uint32_t *axq_casm_slot[18];

	/* NASM register */
	volatile uint32_t *axq_nasm;

	/* CDC registers (only in slot0) */
	volatile uint32_t *axq_cdc_addrtest;
	volatile uint32_t *axq_cdc_ctrltest;
	volatile uint32_t *axq_cdc_datawrite0;
	volatile uint32_t *axq_cdc_datawrite1;
	volatile uint32_t *axq_cdc_datawrite2;
	volatile uint32_t *axq_cdc_datawrite3;
	volatile uint32_t *axq_cdc_counter;
	volatile uint32_t *axq_cdc_readdata0;
	volatile uint32_t *axq_cdc_readdata1;
	volatile uint32_t *axq_cdc_readdata2;
	volatile uint32_t *axq_cdc_readdata3;

	/* performance counters */
	volatile uint32_t *axq_pcr;
	volatile uint32_t *axq_pic0;
	volatile uint32_t *axq_pic1;
	volatile uint32_t *axq_pic2;
	kstat_t *axq_counters_ksp;	/* perf counter kstat */

	/* SDI timeout register */
	volatile uint32_t *axq_sdi_timeout_rd;
	volatile uint32_t *axq_sdi_timeout_rdclr;

	uint32_t axq_cdc_state;		/* CDC state - enabled/disabled */
	int paused;			/* AXQ_DOMCTRL_PAUSE asserted */

#ifndef _AXQ_LOCAL_ACCESS_SUPPORTED
	/*
	 * No local access for cpu2ssc intr
	 * Need to provide per instance explicit expander addressing
	 */
	volatile uint32_t *axq_cpu2ssc_intr;
#endif /* _AXQ_LOCAL_ACCESS_SUPPORTED */
};

/*
 * Public interface
 */
extern int axq_cdc_flush(uint32_t, int, int);
extern int axq_cdc_flush_all();
extern int axq_cdc_disable_flush_all();
extern void axq_cdc_enable_all();
extern int axq_iopause_enable_all(uint32_t *);
extern void axq_iopause_disable_all();
extern uint32_t axq_casm_read(uint32_t, uint32_t, int);
extern int axq_casm_write(uint32_t, uint32_t, int, uint32_t);
extern int axq_casm_write_all(int, uint32_t);
extern int axq_do_casm_rename_script(uint64_t **, int, int);
extern int axq_cpu2ssc_intr(uint8_t);
extern uint32_t axq_read_sdi_timeout_reg(uint32_t, uint32_t, int);
extern int axq_nasm_read(uint32_t expid, uint32_t slot, uint32_t nasm_entry,
    uint32_t *data);
extern int axq_nasm_write(uint32_t expid, uint32_t slot, uint32_t nasm_entry,
    uint32_t data);
extern int axq_nasm_write_all(uint32_t nasm_entry, uint32_t data);
extern void axq_array_rw_enter(void);
extern void axq_array_rw_exit(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_AXQ_H */
