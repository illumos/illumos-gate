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
 * Copyright (c) 1993, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 */

#ifndef _SYS_APIC_APIC_H
#define	_SYS_APIC_APIC_H

#include <sys/psm_types.h>
#include <sys/avintr.h>
#include <sys/pci.h>

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/psm_common.h>

#define	APIC_PCPLUSMP_NAME	"pcplusmp"
#define	APIC_APIX_NAME		"apix"

#define	APIC_IO_ADDR	0xfec00000
#define	APIC_LOCAL_ADDR	0xfee00000
#define	APIC_IO_MEMLEN	0xf
#define	APIC_LOCAL_MEMLEN	0xfffff

/* Local Unit ID register */
#define	APIC_LID_REG		0x8

/* I/o Unit Version Register */
#define	APIC_VERS_REG		0xc

/* Task Priority register */
#define	APIC_TASK_REG		0x20

/* EOI register */
#define	APIC_EOI_REG		0x2c

/* Remote Read register		*/
#define	APIC_REMOTE_READ	0x30

/* Logical Destination register */
#define	APIC_DEST_REG		0x34

/* Destination Format register */
#define	APIC_FORMAT_REG		0x38

/* Spurious Interrupt Vector register */
#define	APIC_SPUR_INT_REG	0x3c

/* Error Status Register */
#define	APIC_ERROR_STATUS	0xa0

/* Interrupt Command registers */
#define	APIC_INT_CMD1		0xc0
#define	APIC_INT_CMD2		0xc4

/* Local Interrupt Vector registers */
#define	APIC_CMCI_VECT		0xbc
#define	APIC_THERM_VECT		0xcc
#define	APIC_PCINT_VECT		0xd0
#define	APIC_INT_VECT0		0xd4
#define	APIC_INT_VECT1		0xd8
#define	APIC_ERR_VECT		0xdc

/* IPL for performance counter interrupts */
#define	APIC_PCINT_IPL		0xe
#define	APIC_LVT_MASK		0x10000		/* Mask bit (16) in LVT */

/* Initial Count register */
#define	APIC_INIT_COUNT		0xe0

/* Current Count Register */
#define	APIC_CURR_COUNT		0xe4
#define	APIC_CURR_ADD		0x39	/* used for remote read command */
#define	CURR_COUNT_OFFSET	(sizeof (int32_t) * APIC_CURR_COUNT)

/* Divider Configuration Register */
#define	APIC_DIVIDE_REG		0xf8

/* Various mode for local APIC. Modes are mutually exclusive  */
typedef enum apic_mode {
	APIC_IS_DISABLED = 0,
	APIC_MODE_NOTSET,
	LOCAL_APIC,
	LOCAL_X2APIC
} apic_mode_t;

/* x2APIC SELF IPI Register */
#define	X2APIC_SELF_IPI		0xFC

/* General x2APIC constants used at various places */
#define	APIC_SVR_SUPPRESS_BROADCAST_EOI		0x1000
#define	APIC_DIRECTED_EOI_BIT			0x1000000

/* IRR register	*/
#define	APIC_IRR_REG		0x80

/* ISR register	*/
#define	APIC_ISR_REG		0x40

#define	APIC_IO_REG		0x0
#define	APIC_IO_DATA		0x4
#define	APIC_IO_EOI		0x10

/* Bit offset of APIC ID in LID_REG, INT_CMD and in DEST_REG */
#define	APIC_ID_BIT_OFFSET	24
#define	APIC_ICR_ID_BIT_OFFSET	24
#define	APIC_LDR_ID_BIT_OFFSET	24

/*
 * Choose between flat and clustered models by writing the following to the
 * FORMAT_REG. 82489 DX documentation seemed to suggest that writing 0 will
 * disable logical destination mode.
 * Does not seem to be in the docs for local APICs on the processors.
 */
#define	APIC_FLAT_MODEL		0xFFFFFFFFUL
#define	APIC_CLUSTER_MODEL	0x0FFFFFFF

/*
 * The commands which follow are window selectors written to APIC_IO_REG
 * before data can be read/written from/to APIC_IO_DATA
 */

#define	APIC_ID_CMD		0x0
#define	APIC_VERS_CMD		0x1
#define	APIC_RDT_CMD		0x10
#define	APIC_RDT_CMD2		0x11

#define	APIC_INTEGRATED_VERS	0x10	/* 0x10 & above indicates integrated */
#define	IOAPIC_VER_82489DX	0x01	/* Version ID: 82489DX External APIC */

#define	APIC_INT_SPURIOUS	-1

#define	APIC_IMCR_P1	0x22		/* int mode conf register port 1 */
#define	APIC_IMCR_P2	0x23		/* int mode conf register port 2 */
#define	APIC_IMCR_SELECT 0x70		/* select imcr by writing into P1 */
#define	APIC_IMCR_PIC	0x0		/* selects PIC mode (8259-> BSP) */
#define	APIC_IMCR_APIC	0x1		/* selects APIC mode (8259->APIC) */

#define	APIC_CT_VECT	0x4ac		/* conf table vector		*/
#define	APIC_CT_SIZE	1024		/* conf table size		*/

#define	APIC_ID		'MPAT'		/* conf table signature 	*/

#define	VENID_AMD		0x1022
#define	DEVID_8131_IOAPIC	0x7451
#define	DEVID_8132_IOAPIC	0x7459

#define	IOAPICS_NODE_NAME	"ioapics"
#define	IOAPICS_CHILD_NAME	"ioapic"
#define	IOAPICS_DEV_TYPE	"ioapic"
#define	IOAPICS_PROP_VENID	"vendor-id"
#define	IOAPICS_PROP_DEVID	"device-id"

#define	IS_CLASS_IOAPIC(b, s, p) \
	((b) == PCI_CLASS_PERIPH && (s) == PCI_PERIPH_PIC &&	\
	((p) == PCI_PERIPH_PIC_IF_IO_APIC ||			\
	(p) == PCI_PERIPH_PIC_IF_IOX_APIC))

/*
 * These macros are used in frequently called routines like
 * apic_intr_enter().
 */
#define	X2APIC_WRITE(reg, v) \
	wrmsr((REG_X2APIC_BASE_MSR + (reg >> 2)), v)

#define	LOCAL_APIC_WRITE_REG(reg, v) \
	apicadr[reg] = v

/*
 * MP floating pointer structure defined in Intel MP Spec 1.1
 */
struct apic_mpfps_hdr {
	uint32_t	mpfps_sig;	/* _MP_ (0x5F4D505F)		*/
	uint32_t	mpfps_mpct_paddr; /* paddr of MP configuration tbl */
	uchar_t	mpfps_length;		/* in paragraph (16-bytes units) */
	uchar_t	mpfps_spec_rev;		/* version number of MP spec	 */
	uchar_t	mpfps_checksum;		/* checksum of complete structure */
	uchar_t	mpfps_featinfo1;	/* mp feature info bytes 1	 */
	uchar_t	mpfps_featinfo2;	/* mp feature info bytes 2	 */
	uchar_t	mpfps_featinfo3;	/* mp feature info bytes 3	 */
	uchar_t	mpfps_featinfo4;	/* mp feature info bytes 4	 */
	uchar_t	mpfps_featinfo5;	/* mp feature info bytes 5	 */
};

#define	MPFPS_FEATINFO2_IMCRP		0x80	/* IMCRP presence bit	*/

#define	APIC_MPS_OEM_ID_LEN		8
#define	APIC_MPS_PROD_ID_LEN		12

struct apic_mp_cnf_hdr {
	uint_t	mpcnf_sig;

	uint_t	mpcnf_tbl_length:	16,
		mpcnf_spec:		8,
		mpcnf_cksum:		8;

	char	mpcnf_oem_str[APIC_MPS_OEM_ID_LEN];

	char	mpcnf_prod_str[APIC_MPS_PROD_ID_LEN];

	uint_t	mpcnf_oem_ptr;

	uint_t	mpcnf_oem_tbl_size:	16,
		mpcnf_entry_cnt:	16;

	uint_t	mpcnf_local_apic;

	uint_t	mpcnf_resv;
};

struct apic_procent {
	uint_t	proc_entry:		8,
		proc_apicid:		8,
		proc_version:		8,
		proc_cpuflags:		8;

	uint_t	proc_stepping:		4,
		proc_model:		4,
		proc_family:		4,
		proc_type:		2,	/* undocumented feature */
		proc_resv1:		18;

	uint_t	proc_feature;

	uint_t	proc_resv2;

	uint_t	proc_resv3;
};

/*
 * proc_cpuflags definitions
 */
#define	CPUFLAGS_EN	1	/* if not set, this processor is unusable */
#define	CPUFLAGS_BP	2	/* set if this is the bootstrap processor */


struct apic_bus {
	uchar_t	bus_entry;
	uchar_t	bus_id;
	ushort_t	bus_str1;
	uint_t	bus_str2;
};

struct apic_io_entry {
	uint_t	io_entry:		8,
		io_apicid:		8,
		io_version:		8,
		io_flags:		8;

	uint_t	io_apic_addr;
};

#define	IOAPIC_FLAGS_EN		0x01	/* this I/O apic is enable or not */

#define	MAX_IO_APIC		32	/* maximum # of IOAPICs supported */

struct apic_io_intr {
	uint_t	intr_entry:		8,
		intr_type:		8,
		intr_po:		2,
		intr_el:		2,
		intr_resv:		12;

	uint_t	intr_busid:		8,
		intr_irq:		8,
		intr_destid:		8,
		intr_destintin:		8;
};

/*
 * intr_type definitions
 */
#define	IO_INTR_INT	0x00
#define	IO_INTR_NMI	0x01
#define	IO_INTR_SMI	0x02
#define	IO_INTR_EXTINT	0x03

/*
 * destination APIC ID
 */
#define	INTR_ALL_APIC		0xff


/* local vector table							*/
#define	AV_MASK		0x10000

/* interrupt command register 32-63					*/
#define	AV_TOALL	0x7fffffff
#define	AV_HIGH_ORDER	0x40000000
#define	AV_IM_OFF	0x40000000

/* interrupt command register 0-31					*/
#define	AV_DELIV_MODE	0x700

#define	AV_FIXED	0x000
#define	AV_LOPRI	0x100
#define	AV_SMI		0x200
#define	AV_REMOTE	0x300
#define	AV_NMI		0x400
#define	AV_RESET	0x500
#define	AV_STARTUP	0x600
#define	AV_EXTINT	0x700

#define	AV_PDEST	0x000
#define	AV_LDEST	0x800

/* IO & Local APIC Bit Definitions */
#define	RDT_VECTOR(x)	((uchar_t)((x) & 0xFF))
#define	AV_PENDING	0x1000
#define	AV_ACTIVE_LOW	0x2000		/* only for integrated APIC */
#define	AV_REMOTE_IRR   0x4000		/* IOAPIC RDT-specific */
#define	AV_LEVEL	0x8000
#define	AV_DEASSERT	AV_LEVEL
#define	AV_ASSERT	0xc000

#define	AV_READ_PENDING	0x10000
#define	AV_REMOTE_STATUS	0x20000	/* 1 = valid, 0 = invalid */

#define	AV_SH_SELF		0x40000	/* Short hand for self */
#define	AV_SH_ALL_INCSELF	0x80000 /* All processors */
#define	AV_SH_ALL_EXCSELF	0xc0000 /* All excluding self */
/* spurious interrupt vector register					*/
#define	AV_UNIT_ENABLE	0x100

#define	APIC_MAXVAL	0xffffffffUL
#define	APIC_TIME_MIN	0x5000
#define	APIC_TIME_COUNT	0x4000

/*
 * Range of the low byte value in apic_tick before starting calibration
 */
#define	APIC_LB_MIN	0x60
#define	APIC_LB_MAX	0xe0

#define	APIC_MAX_VECTOR		255
#define	APIC_RESV_VECT		0x00
#define	APIC_RESV_IRQ		0xfe
#define	APIC_BASE_VECT		0x20	/* This will come in as interrupt 0 */
#define	APIC_AVAIL_VECTOR	(APIC_MAX_VECTOR+1-APIC_BASE_VECT)
#define	APIC_VECTOR_PER_IPL	0x10	/* # of vectors before PRI changes */
#define	APIC_VECTOR(ipl)	(apic_ipltopri[ipl] | APIC_RESV_VECT)
#define	APIC_VECTOR_MASK	0x0f
#define	APIC_HI_PRI_VECTS	2	/* vects reserved for hi pri reqs */
#define	APIC_IPL_MASK		0xf0
#define	APIC_IPL_SHIFT		4	/* >> to get ipl part of vector */
#define	APIC_FIRST_FREE_IRQ	0x10
#define	APIC_MAX_ISA_IRQ	15
#define	APIC_IPL0		0x0f	/* let IDLE_IPL be the lowest */
#define	APIC_IDLE_IPL		0x00

#define	APIC_MASK_ALL		0xf0	/* Mask all interrupts */

/* spurious interrupt vector						*/
#define	APIC_SPUR_INTR		0xFF

/* special or reserve vectors */
#define	APIC_CHECK_RESERVE_VECTORS(v) \
	(((v) == T_FASTTRAP) || ((v) == APIC_SPUR_INTR) || \
	((v) == T_SYSCALLINT) || ((v) == T_DTRACE_RET))

/* cmos shutdown code for BIOS						*/
#define	BIOS_SHUTDOWN		0x0a

/* define the entry types for BIOS information tables as defined in PC+MP */
#define	APIC_CPU_ENTRY		0
#define	APIC_BUS_ENTRY		1
#define	APIC_IO_ENTRY		2
#define	APIC_IO_INTR_ENTRY	3
#define	APIC_LOCAL_INTR_ENTRY	4
#define	APIC_MPTBL_ADDR		(639 * 1024)
/*
 * The MP Floating Point structure could be in 1st 1KB of EBDA or last KB
 * of system base memory or in ROM between 0xF0000 and 0xFFFFF
 */
#define	MPFPS_RAM_WIN_LEN	1024
#define	MPFPS_ROM_WIN_START	(uint32_t)0xf0000
#define	MPFPS_ROM_WIN_LEN	0x10000

#define	EISA_LEVEL_CNTL		0x4D0

/* definitions for apic_irq_table */
#define	FREE_INDEX		(short)-1	/* empty slot */
#define	RESERVE_INDEX		(short)-2	/* ipi, softintr, clkintr */
#define	ACPI_INDEX		(short)-3	/* ACPI */
#define	MSI_INDEX		(short)-4	/* MSI */
#define	MSIX_INDEX		(short)-5	/* MSI-X */
#define	DEFAULT_INDEX		(short)0x7FFF
	/* biggest positive no. to avoid conflict with actual index */

#define	APIC_IS_MSI_OR_MSIX_INDEX(index) \
	((index) == MSI_INDEX || (index) == MSIX_INDEX)

/*
 * definitions for MSI Address
 */
#define	MSI_ADDR_HDR		APIC_LOCAL_ADDR
#define	MSI_ADDR_DEST_SHIFT	12	/* Destination CPU's apic id */
#define	MSI_ADDR_RH_FIXED	0x0	/* Redirection Hint Fixed */
#define	MSI_ADDR_RH_LOPRI	0x1	/* Redirection Hint Lowest priority */
#define	MSI_ADDR_RH_SHIFT	3
#define	MSI_ADDR_DM_PHYSICAL	0x0	/* Physical Destination Mode */
#define	MSI_ADDR_DM_LOGICAL	0x1	/* Logical Destination Mode */
#define	MSI_ADDR_DM_SHIFT	2

/*
 * TM is either edge or level.
 */
#define	TRIGGER_MODE_EDGE		0x0	/* edge sensitive */
#define	TRIGGER_MODE_LEVEL		0x1	/* level sensitive */

/*
 * definitions for MSI Data
 */
#define	MSI_DATA_DELIVERY_FIXED		0x0	/* Fixed delivery */
#define	MSI_DATA_DELIVERY_LOPRI		0x1	/* Lowest priority delivery */
#define	MSI_DATA_DELIVERY_SMI		0x2
#define	MSI_DATA_DELIVERY_NMI		0x4
#define	MSI_DATA_DELIVERY_INIT		0x5
#define	MSI_DATA_DELIVERY_EXTINT	0x7
#define	MSI_DATA_DELIVERY_SHIFT		8
#define	MSI_DATA_TM_EDGE		TRIGGER_MODE_EDGE
#define	MSI_DATA_TM_LEVEL		TRIGGER_MODE_LEVEL
#define	MSI_DATA_TM_SHIFT		15
#define	MSI_DATA_LEVEL_DEASSERT		0x0
#define	MSI_DATA_LEVEL_ASSERT		0x1	/* Edge always assert */
#define	MSI_DATA_LEVEL_SHIFT		14

/*
 * use to define each irq setup by the apic
 */
typedef struct	apic_irq {
	short	airq_mps_intr_index;	/* index into mps interrupt entries */
					/*  table */
	uchar_t	airq_intin_no;
	uchar_t	airq_ioapicindex;
	dev_info_t	*airq_dip; /* device corresponding to this interrupt */
	/*
	 * IRQ could be shared (in H/W) in which case dip & major will be
	 * for the one that was last added at this level. We cannot keep a
	 * linked list as delspl does not tell us which device has just
	 * been unloaded. For most servers where we are worried about
	 * performance, interrupt should not be shared & should not be
	 * a problem. This does not cause any correctness issue - dip is
	 * used only as an optimisation to avoid going thru all the tables
	 * in translate IRQ (which is always called twice due to brokenness
	 * in the way IPLs are determined for devices). major is used only
	 * to bind interrupts corresponding to the same device on the same
	 * CPU. Not finding major will just cause it to be potentially bound
	 * to another CPU.
	 */
	major_t	airq_major;	/* major number corresponding to the device */
	ushort_t airq_rdt_entry;	/* level, polarity & trig mode */
	uint32_t airq_cpu;		/* target CPU, non-reserved IRQ only */
	uint32_t airq_temp_cpu;   /* non-reserved IRQ only, for disable_intr */
	uchar_t	airq_vector;		/* Vector chosen for this irq */
	uchar_t	airq_share;		/* number of interrupts at this irq */
	uchar_t	airq_share_id;		/* id to identify source from irqno */
	uchar_t	airq_ipl;		/* The ipl at which this is handled */
	iflag_t airq_iflag;		/* interrupt flag */
	uchar_t	airq_origirq;		/* original irq passed in */
	uint_t	airq_busy;		/* How frequently did clock find */
					/* us in this */
	struct apic_irq *airq_next;	/* chain of intpts sharing a vector */
	void		*airq_intrmap_private; /* intr remap private data */
} apic_irq_t;

#define	IRQ_USER_BOUND	0x80000000 /* user requested bind if set in airq_cpu */
#define	IRQ_UNBOUND	(uint32_t)-1	/* set in airq_cpu and airq_temp_cpu */
#define	IRQ_UNINIT	(uint32_t)-2 /* in airq_temp_cpu till addspl called */

/* Macros to help deal with shared interrupts */
#define	VIRTIRQ(irqno, share_id)	((irqno) | ((share_id) << 8))
#define	IRQINDEX(irq)	((irq) & 0xFF)	/* Mask to get irq from virtual irq */

/*
 * We align apic_cpus_info at 64-byte cache line boundary. Please make sure we
 * adjust APIC_PADSZ as we add/modify any member of apic_cpus_info. We also
 * don't want the compiler to optimize apic_cpus_info.
 */
#define	APIC_PADSZ	15

#pragma	pack(1)
typedef struct apic_cpus_info {
	uint32_t aci_local_id;
	uchar_t	aci_local_ver;
	uchar_t	aci_status;
	uchar_t	aci_redistribute;	/* Selected for redistribution */
	uint_t	aci_busy;		/* Number of ticks we were in ISR */
	uint_t	aci_spur_cnt;		/* # of spurious intpts on this cpu */
	uint_t	aci_ISR_in_progress;	/* big enough to hold 1 << MAXIPL */
	uchar_t	aci_curipl;		/* IPL of current ISR */
	uchar_t	aci_current[MAXIPL];	/* Current IRQ at each IPL */
	uint32_t aci_bound;		/* # of user requested binds ? */
	uint32_t aci_temp_bound;	/* # of non user IRQ binds */
	uint32_t aci_processor_id;	/* Only used in ACPI mode. */
	uchar_t	aci_idle;		/* The CPU is idle */
	/*
	 * Fill to make sure each struct is in separate 64-byte cache line.
	 */
	uchar_t	aci_pad[APIC_PADSZ];	/* padding for 64-byte cache line */
} apic_cpus_info_t;
#pragma	pack()

#define	APIC_CPU_ONLINE		0x1
#define	APIC_CPU_INTR_ENABLE	0x2
#define	APIC_CPU_FREE		0x4	/* APIC CPU slot is free */
#define	APIC_CPU_DIRTY		0x8	/* Slot was once used */
#define	APIC_CPU_SUSPEND	0x10

/*
 * APIC ops to support various flavors of APIC like APIC and x2APIC.
 */
typedef	struct apic_regs_ops {
	uint64_t	(*apic_read)(uint32_t);
	void 		(*apic_write)(uint32_t, uint64_t);
	int		(*apic_get_pri)(void);
	void		(*apic_write_task_reg)(uint64_t);
	void		(*apic_write_int_cmd)(uint32_t, uint32_t);
	void		(*apic_send_eoi)(uint32_t);
} apic_reg_ops_t;

/*
 * interrupt structure for ioapic and msi
 */
typedef struct ioapic_rdt {
	uint32_t	ir_lo;
	uint32_t	ir_hi;
} ioapic_rdt_t;

typedef struct msi_regs {
	uint32_t	mr_data;
	uint64_t	mr_addr;
}msi_regs_t;

/*
 * APIC ops to support intel interrupt remapping
 */
typedef struct apic_intrmap_ops {
	int	(*apic_intrmap_init)(int);
	void	(*apic_intrmap_enable)(int);
	void	(*apic_intrmap_alloc_entry)(void **, dev_info_t *, uint16_t,
		    int, uchar_t);
	void	(*apic_intrmap_map_entry)(void *, void *, uint16_t, int);
	void	(*apic_intrmap_free_entry)(void **);
	void	(*apic_intrmap_record_rdt)(void *, ioapic_rdt_t *);
	void	(*apic_intrmap_record_msi)(void *, msi_regs_t *);
} apic_intrmap_ops_t;

/*
 * Various poweroff methods and ports & bits for them
 */
#define	APIC_POWEROFF_NONE		0
#define	APIC_POWEROFF_VIA_RTC		1
#define	APIC_POWEROFF_VIA_ASPEN_BMC	2
#define	APIC_POWEROFF_VIA_SITKA_BMC	3

/* For RTC */
#define	RTC_REGA		0x0a
#define	PFR_REG			0x4a    /* extended control register */
#define	PAB_CBIT		0x08
#define	WF_FLAG			0x02
#define	KS_FLAG			0x01
#define	EXT_BANK		0x10

/* For Aspen/Drake BMC */

#define	CC_SMS_GET_STATUS	0x40
#define	CC_SMS_WR_START		0x41
#define	CC_SMS_WR_NEXT		0x42
#define	CC_SMS_WR_END		0x43

#define	MISMIC_DATA_REGISTER	0x0ca9
#define	MISMIC_CNTL_REGISTER	0x0caa
#define	MISMIC_FLAG_REGISTER	0x0cab

#define	MISMIC_BUSY_MASK	0x01

/* For Sitka/Cabrillo BMC */

#define	SMS_GET_STATUS		0x60
#define	SMS_WRITE_START		0x61
#define	SMS_WRITE_END		0x62

#define	SMS_DATA_REGISTER	0x0ca2
#define	SMS_STATUS_REGISTER	0x0ca3
#define	SMS_COMMAND_REGISTER	0x0ca3

#define	SMS_IBF_MASK		0x02
#define	SMS_STATE_MASK		0xc0

#define	SMS_IDLE_STATE		0x00
#define	SMS_READ_STATE		0x40
#define	SMS_WRITE_STATE		0x80
#define	SMS_ERROR_STATE		0xc0

extern uint32_t ioapic_read(int ioapic_ix, uint32_t reg);
extern void ioapic_write(int ioapic_ix, uint32_t reg, uint32_t value);
extern void ioapic_write_eoi(int ioapic_ix, uint32_t value);

/* Macros for reading/writing the IOAPIC RDT entries */
#define	READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic_ix, ipin) \
	ioapic_read(ioapic_ix, APIC_RDT_CMD + (2 * (ipin)))

#define	READ_IOAPIC_RDT_ENTRY_HIGH_DWORD(ioapic_ix, ipin) \
	ioapic_read(ioapic_ix, APIC_RDT_CMD2 + (2 * (ipin)))

#define	WRITE_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic_ix, ipin, value) \
	ioapic_write(ioapic_ix, APIC_RDT_CMD + (2 * (ipin)), value)

#define	WRITE_IOAPIC_RDT_ENTRY_HIGH_DWORD(ioapic_ix, ipin, value) \
	ioapic_write(ioapic_ix, APIC_RDT_CMD2 + (2 * (ipin)), value)

/* Used by PSM_INTR_OP_GET_INTR to return device information. */
typedef struct {
	uint16_t	avgi_req_flags;	/* request flags - to kernel */
	uint8_t		avgi_num_devs;	/* # devs on this ino - from kernel */
	uint8_t		avgi_vector;	/* vector */
	uint32_t	avgi_cpu_id;	/* cpu of interrupt - from kernel */
	dev_info_t	**avgi_dip_list; /* kmem_alloc'ed list of dev_infos. */
					/* Contains num_devs elements. */
} apic_get_intr_t;

/* Used by PSM_INTR_OP_GET_TYPE to return platform information. */
typedef struct {
	char		*avgi_type;	/*  platform type - from kernel */
	uint32_t	avgi_num_intr;	/*  max intr number - from kernel */
	uint32_t	avgi_num_cpu;	/*  max cpu number - from kernel */
} apic_get_type_t;

/* Masks for avgi_req_flags. */
#define	PSMGI_REQ_CPUID		0x1	/* Request CPU ID */
#define	PSMGI_REQ_NUM_DEVS	0x2	/* Request num of devices on vector */
#define	PSMGI_REQ_VECTOR	0x4
#define	PSMGI_REQ_GET_DEVS	0x8	/* Request device list */
#define	PSMGI_REQ_ALL		0xf	/* Request everything */

/* Other flags */
#define	PSMGI_INTRBY_VEC	0	/* Vec passed.  xlate to IRQ needed */
#define	PSMGI_INTRBY_IRQ	0x8000	/* IRQ passed.  no xlate needed */
#define	PSMGI_INTRBY_DEFAULT	0x4000	/* PSM specific default value */
#define	PSMGI_INTRBY_FLAGS	0xc000	/* Mask for this flag */

extern int	apic_verbose;

/* Flag definitions for apic_verbose */
#define	APIC_VERBOSE_IOAPIC_FLAG		0x00000001
#define	APIC_VERBOSE_IRQ_FLAG			0x00000002
#define	APIC_VERBOSE_POWEROFF_FLAG		0x00000004
#define	APIC_VERBOSE_POWEROFF_PAUSE_FLAG	0x00000008
#define	APIC_VERBOSE_INIT			0x00000010
#define	APIC_VERBOSE_REBIND			0x00000020
#define	APIC_VERBOSE_ALLOC			0x00000040
#define	APIC_VERBOSE_IPI			0x00000080
#define	APIC_VERBOSE_INTR			0x00000100

/* required test to wait until APIC command is sent on the bus */
#define	APIC_AV_PENDING_SET() \
	while (apic_reg_ops->apic_read(APIC_INT_CMD1) & AV_PENDING) \
		apic_ret();

#ifdef	DEBUG

#define	DENT		0x0001
extern int	apic_debug;
/*
 * set apic_restrict_vector to the # of vectors we want to allow per range
 * useful in testing shared interrupt logic by setting it to 2 or 3
 */
extern int	apic_restrict_vector;

#define	APIC_DEBUG_MSGBUFSIZE	2048
extern int	apic_debug_msgbuf[];
extern int	apic_debug_msgbufindex;

/*
 * Put "int" info into debug buffer. No MP consistency, but light weight.
 * Good enough for most debugging.
 */
#define	APIC_DEBUG_BUF_PUT(x) \
	apic_debug_msgbuf[apic_debug_msgbufindex++] = x; \
	if (apic_debug_msgbufindex >= (APIC_DEBUG_MSGBUFSIZE - NCPU)) \
		apic_debug_msgbufindex = 0;

#define	APIC_VERBOSE(flag, fmt)			     \
	if (apic_verbose & APIC_VERBOSE_##flag) \
		cmn_err fmt;

#define	APIC_VERBOSE_POWEROFF(fmt) \
	if (apic_verbose & APIC_VERBOSE_POWEROFF_FLAG) \
		prom_printf fmt;

#else	/* DEBUG */

#define	APIC_VERBOSE(flag, fmt)
#define	APIC_VERBOSE_POWEROFF(fmt)

#endif	/* DEBUG */

#define	APIC_VERBOSE_IOAPIC(fmt)	APIC_VERBOSE(IOAPIC_FLAG, fmt)
#define	APIC_VERBOSE_IRQ(fmt)		APIC_VERBOSE(IRQ_FLAG, fmt)

extern int	apic_error;
/* values which apic_error can take. Not catastrophic, but may help debug */
#define	APIC_ERR_BOOT_EOI		0x1
#define	APIC_ERR_GET_IPIVECT_FAIL	0x2
#define	APIC_ERR_INVALID_INDEX		0x4
#define	APIC_ERR_MARK_VECTOR_FAIL	0x8
#define	APIC_ERR_APIC_ERROR		0x40000000
#define	APIC_ERR_NMI			0x80000000

/*
 * ACPI definitions
 */
/* _PIC method arguments */
#define	ACPI_PIC_MODE	0
#define	ACPI_APIC_MODE	1

/* APIC error flags we care about */
#define	APIC_SEND_CS_ERROR	0x01
#define	APIC_RECV_CS_ERROR	0x02
#define	APIC_CS_ERRORS		(APIC_SEND_CS_ERROR|APIC_RECV_CS_ERROR)

/* Maximum number of times to retry reprogramming at apic_intr_exit time */
#define	APIC_REPROGRAM_MAX_TRIES 10000

/* Parameter to ioapic_init_intr(): Should ioapic ints be masked? */
#define	IOAPIC_MASK 1
#define	IOAPIC_NOMASK 0

#define	INTR_ROUND_ROBIN_WITH_AFFINITY	0
#define	INTR_ROUND_ROBIN		1
#define	INTR_LOWEST_PRIORITY		2

struct ioapic_reprogram_data {
	boolean_t			done;
	apic_irq_t			*irqp;
	/* The CPU to which the int will be bound */
	int				bindcpu;
	/* # times the reprogram timeout was called */
	unsigned			tries;
};

/* The irq # is implicit in the array index: */
extern struct ioapic_reprogram_data apic_reprogram_info[];

extern void apic_intr_exit(int ipl, int irq);
extern void x2apic_intr_exit(int ipl, int irq);
extern int apic_probe_common();
extern void apic_init_common();
extern void ioapic_init_intr();
extern void ioapic_disable_redirection();
extern int apic_addspl_common(int irqno, int ipl, int min_ipl, int max_ipl);
extern int apic_delspl_common(int irqno, int ipl, int min_ipl, int max_ipl);
extern void apic_cleanup_busy();
extern void apic_intr_redistribute();
extern uchar_t apic_xlate_vector(uchar_t vector);
extern uchar_t apic_allocate_vector(int ipl, int irq, int pri);
extern void apic_free_vector(uchar_t vector);
extern int apic_allocate_irq(int irq);
extern uint32_t apic_bind_intr(dev_info_t *dip, int irq, uchar_t ioapicid,
    uchar_t intin);
extern int apic_rebind(apic_irq_t *irq_ptr, int bind_cpu,
    struct ioapic_reprogram_data *drep);
extern int apic_rebind_all(apic_irq_t *irq_ptr, int bind_cpu);
extern int apic_introp_xlate(dev_info_t *dip, struct intrspec *ispec, int type);
extern int apic_intr_ops(dev_info_t *dip, ddi_intr_handle_impl_t *hdlp,
    psm_intr_op_t intr_op, int *result);
extern int apic_state(psm_state_request_t *);
extern boolean_t apic_cpu_in_range(int cpu);
extern int apic_check_msi_support();
extern apic_irq_t *apic_find_irq(dev_info_t *dip, struct intrspec *ispec,
    int type);
extern int apic_navail_vector(dev_info_t *dip, int pri);
extern int apic_alloc_msi_vectors(dev_info_t *dip, int inum, int count,
    int pri, int behavior);
extern int apic_alloc_msix_vectors(dev_info_t *dip, int inum, int count,
    int pri, int behavior);
extern void  apic_free_vectors(dev_info_t *dip, int inum, int count, int pri,
    int type);
extern int apic_get_vector_intr_info(int vecirq,
    apic_get_intr_t *intr_params_p);
extern uchar_t apic_find_multi_vectors(int pri, int count);
extern int apic_setup_io_intr(void *p, int irq, boolean_t deferred);
extern uint32_t *mapin_apic(uint32_t addr, size_t len, int flags);
extern uint32_t *mapin_ioapic(uint32_t addr, size_t len, int flags);
extern void mapout_apic(caddr_t addr, size_t len);
extern void mapout_ioapic(caddr_t addr, size_t len);
extern uchar_t apic_modify_vector(uchar_t vector, int irq);
extern void apic_pci_msi_unconfigure(dev_info_t *rdip, int type, int inum);
extern void apic_pci_msi_disable_mode(dev_info_t *rdip, int type);
extern void apic_pci_msi_enable_mode(dev_info_t *rdip, int type, int inum);
extern void apic_pci_msi_enable_vector(apic_irq_t *, int type, int inum,
    int vector, int count, int target_apic_id);
extern char *apic_get_apic_type();
extern uint16_t	apic_get_apic_version();
extern void x2apic_send_ipi();
extern void apic_ret();
extern int apic_detect_x2apic();
extern void apic_enable_x2apic();
extern int apic_local_mode();
extern void apic_change_eoi();
extern void apic_send_EOI(uint32_t);
extern void apic_send_directed_EOI(uint32_t);
extern uint_t apic_calibrate(volatile uint32_t *, uint16_t *);

extern volatile uint32_t *apicadr;	/* virtual addr of local APIC   */
extern int apic_forceload;
extern apic_cpus_info_t *apic_cpus;
#ifdef _MACHDEP
extern cpuset_t apic_cpumask;
#endif
extern uint_t apic_picinit_called;
extern uchar_t apic_ipltopri[MAXIPL+1];
extern uchar_t apic_vector_to_irq[APIC_MAX_VECTOR+1];
extern int apic_max_device_irq;
extern int apic_min_device_irq;
extern apic_irq_t *apic_irq_table[APIC_MAX_VECTOR+1];
extern volatile uint32_t *apicioadr[MAX_IO_APIC];
extern uchar_t apic_io_id[MAX_IO_APIC];
extern lock_t apic_ioapic_lock;
extern uint32_t apic_physaddr[MAX_IO_APIC];
extern kmutex_t airq_mutex;
extern int apic_first_avail_irq;
extern uchar_t apic_vectortoipl[APIC_AVAIL_VECTOR / APIC_VECTOR_PER_IPL];
extern int apic_imcrp;
extern int apic_revector_pending;
extern char apic_level_intr[APIC_MAX_VECTOR+1];
extern uchar_t apic_resv_vector[MAXIPL+1];
extern int apic_sample_factor_redistribution;
extern int apic_int_busy_mark;
extern int apic_int_free_mark;
extern int apic_diff_for_redistribution;
extern int apic_poweroff_method;
extern int apic_enable_acpi;
extern int apic_nproc;
extern int apic_max_nproc;
extern int apic_next_bind_cpu;
extern int apic_redistribute_sample_interval;
extern int apic_multi_msi_enable;
extern int apic_sci_vect;
extern int apic_hpet_vect;
extern uchar_t apic_ipls[];
extern apic_reg_ops_t *apic_reg_ops;
extern apic_mode_t apic_mode;
extern void x2apic_update_psm();
extern void apic_change_ops();
extern void apic_common_send_ipi(int, int);
extern void apic_set_directed_EOI_handler();
extern int apic_directed_EOI_supported();

extern apic_intrmap_ops_t *apic_vt_ops;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_APIC_APIC_H */
