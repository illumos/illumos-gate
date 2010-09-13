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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * PCIC driver specific data structures
 */

#ifndef _PCIC_VAR_H
#define	_PCIC_VAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * defines and default values for power management simulation
 */
#define	PCIC_PM_TIME		3	/* PM timer timeout time in secs */
#define	PCIC_PM_DETWIN		6	/* detection window in secs */
#define	PCIC_PM_METHOD_TIME	0x0001	/* use time check */
#define	PCIC_PM_METHOD_REG	0x0002	/* use reg check */
#define	PCIC_PM_DEF_METHOD	0	/* use no methods as default */

#define	PCIC_PM_INIT	0x0001	/* init PM handler */
#define	PCIC_PM_RUN	0x0002	/* normal PM handler operation */

typedef struct pcic_pm_t {
	int		state;	/* state */
	uint32_t	ptime;	/* previous time check */
	dev_info_t	*dip;	/* dip to pass */
} pcic_pm_t;

/*
 * Card insertion/removal processing debounce parameters
 */
#define	PCIC_REM_DEBOUNCE_CNT	40
#define	PCIC_REM_DEBOUNCE_TIME	0x1000	/* in uS */
#define	PCIC_DEBOUNCE_OK_CNT    10

/*
 * Loop control in pcic_ready_wait
 *
 * Multiplying PCIC_READY_WAIT_LOOPS * PCIC_READY_WAIT_TIME gives
 *	total loop time in mS
 */
#define	PCIC_READY_WAIT_LOOPS	205	/* count */
#define	PCIC_READY_WAIT_TIME	20	/* mS */

typedef struct pcs_memwin {
	int			pcw_status;
	uint32_t		pcw_base;
	int			pcw_len;
	uint32_t		pcw_speed;
	volatile caddr_t	pcw_hostmem;
	off_t			pcw_offset;
	ddi_acc_handle_t	pcw_handle;
	dev_info_t		*res_dip; /* dip from which mem is allocated */
} pcs_memwin_t;

typedef struct pci_iowin {
	int 			pcw_status;
	uint32_t		pcw_base;
	int			pcw_len;
	uint32_t		pcw_speed;
	volatile caddr_t	pcw_hostmem;
				/* Cirrus Logic specific offset info */
	int			pcw_offset;
	ddi_acc_handle_t	pcw_handle;
	dev_info_t		*res_dip; /* dip from which io is allocated */
} pcs_iowin_t;

#define	PCW_MAPPED	0x0001	/* window is mapped */
#define	PCW_ENABLED	0x0002	/* window is enabled */
#define	PCW_ATTRIBUTE	0x0004	/* window is in attribute memory */
#define	PCW_WP		0x0008	/* window is write protected */
#define	PCW_OFFSET	0x0010	/* window uses CL style offset */

typedef
struct pcic_socket {
	int	pcs_flags;
	uchar_t	*pcs_io;	/* I/O address of PCIC controller */
	int	pcs_socket;	/* socket to determine register set */
	char    pcs_cd_softint_flg;
	timeout_id_t pcs_debounce_id;	/* timeout for CD debounce */
	ddi_softint_handle_t pcs_cd_softint_hdl; /* Debounce softint id */
	struct pcicdev_t *pcs_pcic;
	caddr_t pcs_phys;
	int	pcs_iobase;
	int	pcs_iolen;
	caddr_t pcs_confbase;
	int	pcs_conflen;
	int	pcs_conf_index;	/* used to select which cftable entry to use */
	int 	pcs_irq;
	int	pcs_smi;
	int	pcs_state;
	int	pcs_status;
	int	pcs_intmask;
	uint32_t pcs_vcc;
	uint32_t pcs_vpp1;
	uint32_t pcs_vpp2;
	union pcic_window {
		pcs_memwin_t mem;
		pcs_iowin_t  io;
	}	pcs_windows[PCIC_IOWINDOWS + PCIC_MEMWINDOWS];
} pcic_socket_t;

#define	PCS_CARD_PRESENT	0x0001	/* card inserted in socket */
#define	PCS_CARD_IDENTIFIED	0x0002	/* card has been identified */
#define	PCS_CARD_ENABLED	0x0004	/* card and socket enabled */
#define	PCS_CARD_WPS		0x0008	/* write protect ignored */
#define	PCS_IRQ_ENABLED		0x0010	/* irq is a mask of values */
#define	PCS_CARD_RAM		0x0020	/* ram needs to be mapped */
#define	PCS_CARD_IO		0x0040	/* card is I/O type */
#define	PCS_CARD_16BIT		0x0080	/* set in 16-bit mode */
#define	PCS_SOCKET_IO		0x0100	/* socket is I/O type */
#define	PCS_READY		0x0200	/* socket just came ready */
#define	PCS_WAITING		0x0400	/* Doing a wait on this socket */
#define	PCS_STARTING		0x0800	/* Starting up flag */
#define	PCS_CARD_ISCARDBUS	0x1000	/* NJH - 32 bit (CARDBUS) card */
#define	PCS_CARD_IS16BIT	0x2000	/* So we can tell if it's OK */
#define	PCS_CARD_REMOVED	0x4000	/* Removed but still work to do */
#define	PCS_CARD_CBREM		0x8000	/* Cardbus specific work to do */
#define	PCS_DEBOUNCING		0x10000  /* Socket in debouncing state */

#define	PCIC_MAX_SOCKETS 4	/* 2 per chip up to 2 chips per IO addr */

typedef struct pcic_debounce_state {
	int insert_cnt;
	int remove_cnt;
	int uncertain_cnt;
	int prev_status;
	int debounce_cnt;
	timeout_id_t timeout_id;
} pcic_debounce_state_t;

typedef struct pcicdev_t {
	uint32_t		pc_flags;
	uint32_t		pc_type;
	char			*pc_chipname;
	uint32_t		pc_irqs;	/* the possible IRQ levels */
	uint32_t		pc_smi;		/* SMI IRQ */
	uint32_t		pc_irq;		/* IO IRQ */
	int			pc_io_type;
	int			pc_intr_mode;	/* which interrupt method */
	dev_info_t		*dip;
	ddi_idevice_cookie_t	pc_dcookie;	/* Stay compatible w/ PCMCIA */
	inthandler_t		*sirq[14];	/* List for each level */
	uint16_t		si_actflg;	/* Bit for each active level */
	inthandler_t		*irq_top;
	inthandler_t		*irq_current;
	ddi_intr_handle_t	*pc_pci_intr_hdlp; /* For PCI based adapters */
	ddi_iblock_cookie_t	pc_pri;		/* Priority saved for mutexes */
	ddi_intr_handle_t	*pc_intr_htblp;	/* ISA: interrupt handles */
	ddi_softint_handle_t	pc_softint_hdl;	/* Softinterrupt handle */
	kmutex_t		pc_lock;	/* general register lock */
	kmutex_t		intr_lock;	/* protects fields modified */
						/* in pcic_intr() */
	int			pc_numsockets;
				/* used to inform nexus of events */
	int			(*pc_callback)();
	int			pc_cb_arg;
	int			(*pc_ss_bios)();
	struct pcic_socket	pc_sockets[PCIC_MAX_SOCKETS];
	int			pc_numpower;
	struct power_entry	*pc_power;
	timeout_id_t		pc_pmtimer;	/* timeout for simulating PM */
	pcic_pm_t		pmt;		/* PM handler structure */
	kcondvar_t		pm_cv;		/* CV for suspend/resume sync */
	ddi_acc_handle_t	handle;		/* PCIC register handle */
	ddi_acc_handle_t	cfg_handle;	/* PCIC config space handle */
	uchar_t			*cfgaddr;	/* config address */
	uchar_t			*ioaddr;	/* PCIC register IO base */
	int			mem_reg_num;	/* memory space reg number */
	offset_t		mem_reg_offset;
	int			io_reg_num;	/* IO space reg number */
	offset_t		io_reg_offset;
	int			bus_speed;	/* parent bus speed */
	uint32_t		pc_timestamp;   /* last time touched */
	inthandler_t		*pc_handlers;
	int			pc_lastreg;
	uint32_t		pc_base;	/* first possible mem-addr */
	uint32_t		pc_bound;	/* bound length */
	uint32_t		pc_iobase;	/* first io addr */
	uint32_t		pc_iobound;
	pcic_debounce_state_t   deb_state[PCIC_MAX_SOCKETS];
	int			pc_softintr_req[PCIC_MAX_SOCKETS];
	struct pcic_cd_change_param {
		struct pcicdev_t	*pcic;
		pcic_socket_t		*sockp;
		int			sn;
	}  pcic_cd_change_param[PCIC_MAX_SOCKETS];
} pcicdev_t;



#define	PCF_ATTACHED	0x00000001
#define	PCF_CALLBACK	0x00000002	/* callback handler registered */
#define	PCF_GPI_EJECT	0x00000004	/* GPI signal is eject/insert */
#define	PCF_INTRENAB	0x00000008
#define	PCF_USE_SMI	0x00000010	/* use the SMI enable */
#define	PCF_AUDIO	0x00000020	/* use audio if available */
#define	PCF_SUSPENDED	0x00000040	/* driver attached but suspended */
#define	PCF_EXTEND_INTR	0x00000080	/* Use Vadem interrupt sharing */
#define	PCF_1SOCKET	0x00000100	/* Chip only has one socket  */
#define	PCF_33VCAP	0x00000200	/* 3.3 Volt capable and coded */
#define	PCF_CBPWRCTL	0x00000400	/* Use cardbus regs for power ctl */
#define	PCF_DEBOUNCE	0x00002000	/* Chip has hardware debounce enabled */
#define	PCF_VPPX	0x00004000	/* Vpp1 and Vpp2 tied together */
#define	PCF_EXTBUFF	0x00008000	/* Chip strapped for external buffers */
#define	PCF_PCIBUS	0x00010000	/* this instance on a PCI bus */
#define	PCF_NOIO_OFF	0x00020000	/* 0 offset for IO mapping */
#define	PCF_MULT_IRQ	0x00040000
#define	PCF_IO_REMAP	0x00080000	/* adapter can remap I/O */
#define	PCF_CARDBUS	0x00100000	/* Yenta CardBus */
#define	PCF_MEM_PAGE	0x00200000	/* all windows same 16M page */

/* newer features */
#define	PCF_DMA		0x00400000	/* supports DMA */
#define	PCF_ZV		0x00800000	/* supports Zoom Video */

#define	PCF_ISA6729	0x01000000	/* 6729 */

/*
 * misc flags
 */
#define	PCIC_FOUND_ADAPTER	0x00000001
#define	PCIC_ENABLE_IO		0x00000002
#define	PCIC_ENABLE_MEM		0x00000004

#define	PCIC_SOFTINT_PRI_VAL	0x04	/* value used while adding softint */

/*
 * interrupt modes
 * the pcic variants provide a number of interrupt modes.
 * e.g. on PCI, we can either use PCI interrupts or ISA interrupts
 * but the SPARC version must use PCI interrupts and x86 "depends"
 */

#define	PCIC_INTR_MODE_ISA	00 /* default- use ISA mode */
#define	PCIC_INTR_MODE_PCI	01 /* use pure PCI */
#define	PCIC_INTR_MODE_PCI_1	02 /* use pure PCI but share */
#define	PCIC_INTR_MODE_PCI_S	03 /* serial PCI interrupts */

#define	PCIC_INTR_DEF_PRI	11 /* default IPL level */

/*
 * I/O access types
 */
#define	PCIC_IO_TYPE_82365SL	0 /* uses index/data reg model */
#define	PCIC_IO_TYPE_YENTA	1 /* uses the Yenta spec memory model */

/*
 * On some PCI busses, the IO and memory resources available to us are
 *	available via the last two tuples in the reg property. The
 *	following defines are the reg numbers from the end of the reg
 *	property, and NOT the reg number itself.
 */
#define	PCIC_PCI_MEM_REG_OFFSET	2
#define	PCIC_PCI_IO_REG_OFFSET	3

/* I/O type 82365SL is default, Yenta is alternative */
#define	PCIC_IOTYPE_82365SL	0
#define	PCIC_IOTYPE_YENTA	1 /* CardBus memory mode */

/*
 * On Yenta cards, the PCI configuration space bridge control register
 * must match the interrupt * type we have selected.
 */

#define	PCIC_CB_BRIDGE_CTL	0x3E
#define	PCIC_BCTL_IREQ_ISA	0x80

/*
 * On all PCI busses, we get at least two tuples in the reg property. One
 *	of the tuples is the config space tuple and the other is the PCIC
 *	IO control register space tuple.
 */

#define	PCIC_PCI_CONFIG_REG_NUM	0
#define	PCIC_PCI_CONFIG_REG_OFFSET	0
#define	PCIC_PCI_CONFIG_REG_LENGTH	0x100

#define	PCIC_PCI_CONTROL_REG_NUM	1
#define	PCIC_PCI_CONTROL_REG_OFFSET	0
#define	PCIC_PCI_CONTROL_REG_LENGTH	4
#define	PCIC_CB_CONTROL_REG_LENGTH	4096 /* CardBus is 4K mem page */

/*
 * On ISA/EISA/MCA our reg property must look like this:
 *
 *	IOreg,0x0,0x8, 0x0,0x0,0x100000, 0x1,0x0,0x1000
 *	^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^
 *	adapter regs    general memory	   general IO
 *
 * where IOreg specifies the adapter's control registers in
 *	IO space.
 * The value of PCIC_ISA_IO_REG_OFFSET must be the first
 *	component of the third (general IO) register spec.
 */
#define	PCIC_ISA_IO_REG_OFFSET		1
#define	PCIC_ISA_CONTROL_REG_NUM	0
#define	PCIC_ISA_CONTROL_REG_OFFSET	0	/* XXX MUST be 0! */
#define	PCIC_ISA_CONTROL_REG_LENGTH	2

#define	PCIC_ISA_MEM_REG_NUM		1
#define	PCIC_ISA_IO_REG_NUM		2

/*
 * there are several variants of the 82365 chip from different "clone"
 * vendors.  Each has a few differences which may or may not have to be
 * handled.  The following defines are used to identify the chip being
 * used.  If it can't be determined, then 82365SL is assumed.
 *
 * The following are ISA/EISA/MCA-R2 adapters
 */
#define	PCIC_I82365SL		0x00 /* Intel 82365SL */
#define	PCIC_TYPE_I82365SL	"i82365SL"
#define	PCIC_CL_PD6710		0x01 /* Cirrus Logic CL-PD6710/6720 */
#define	PCIC_CL_PD6722		0x05 /* Cirrus Logic CL-PD6722 */
#define	PCIC_TYPE_PD6710	"PD6710"
#define	PCIC_TYPE_PD6720	"PD6720"
#define	PCIC_TYPE_PD6722	"PD6722"
#define	PCIC_VADEM		0x02 /* Vadem VG465/365 */
#define	PCIC_VADEM_VG469	0x03 /* Vadem VG469 - P&P, etc. */
#define	PCIC_VG_465		"VG465"
#define	PCIC_VG_365		"VG365"
#define	PCIC_VG_468		"VG468"
#define	PCIC_VG_469		"VG469"
#define	PCIC_RICOH		0x04
#define	PCIC_TYPE_RF5C296	"RF5C296"
#define	PCIC_TYPE_RF5C396	"RF5C396"

/* PCI adapters are known by 32-bit value of vendor+device id */
#define	PCI_ID(vend, dev)	((uint32_t)(((uint32_t)(vend) << 16) | (dev)))

/*
 * The following are PCI-R2 adapters
 * The Cirrus Logic PCI adapters typically have their IRQ3 line
 *	routed to the PCI INT A# line.
 */
#define	PCIC_CL_VENDORID	0x1013
#define	PCIC_PD6729_DEVID	0x1100
#define	PCIC_TYPE_PD6729	"PD6729"
#define	PCIC_CL_PD6729		PCI_ID(PCIC_CL_VENDORID, PCIC_PD6729_DEVID)
#define	PCIC_PD6729_INTA_ROUTE	0x03

#define	PCIC_TYPE_PD6730	"PD6730"
#define	PCIC_PD6730_DEVID	0x1101
#define	PCIC_CL_PD6730		PCI_ID(PCIC_CL_VENDORID, PCIC_PD6730_DEVID)
#define	PCIC_PD6730_INTA_ROUTE	0x09

#define	PCIC_TYPE_PD6832	"PD6832"
#define	PCIC_PD6832_DEVID	0x1110
#define	PCIC_CL_PD6832		PCI_ID(PCIC_CL_VENDORID, PCIC_PD6832_DEVID)

/* Intel i82092AA controller */

#define	PCIC_INTEL_VENDORID	0x8086
#define	PCIC_TYPE_i82092	"i82092"
#define	PCIC_i82092_DEVID	0x1221
#define	PCIC_INTEL_i82092	PCI_ID(PCIC_INTEL_VENDORID, \
					PCIC_i82092_DEVID)
#define	PCIC_i82092_INTA_ROUTE	0x0	/* XXX ? what is it really ? XXX */

/* Texas Instruments */

#define	PCIC_TI_VENDORID	0x104C
#define	PCIC_PCI1050_DEVID	0xAC10
#define	PCIC_PCI1130_DEVID	0xAC12
#define	PCIC_PCI1031_DEVID	0xAC13 /* R2 only with Yenta IF */
#define	PCIC_PCI1131_DEVID	0xAC15
#define	PCIC_PCI1250_DEVID	0xAC16
#define	PCIC_PCI1221_DEVID	0xAC19
#define	PCIC_PCI1225_DEVID	0xAC1C
#define	PCIC_PCI1220_DEVID	0xAC17
#define	PCIC_PCI1260_DEVID	0xAC18
#define	PCIC_PCI1210_DEVID	0xAC1A
#define	PCIC_PCI1450_DEVID	0xAC1B
#define	PCIC_PCI1251_DEVID	0xAC1D
#define	PCIC_PCI1211_DEVID	0xAC1E
#define	PCIC_PCI1251B_DEVID	0xAC1F
#define	PCIC_PCI1260B_DEVID	0xAC30
#define	PCIC_PCI4450_DEVID	0xAC40
#define	PCIC_PCI4410_DEVID	0xAC41
#define	PCIC_PCI4451_DEVID	0xAC42
#define	PCIC_PCI4510_DEVID	0xAC44
#define	PCIC_PCI1410_DEVID	0xAC50
#define	PCIC_PCI1420_DEVID	0xAC51
#define	PCIC_PCI1451_DEVID	0xAC52
#define	PCIC_PCI1421_DEVID	0xAC53
#define	PCIC_PCI1520_DEVID	0xAC55
#define	PCIC_PCI1510_DEVID	0xAC56

#define	PCIC_TI_PCI1130		PCI_ID(PCIC_TI_VENDORID, PCIC_PCI1130_DEVID)
#define	PCIC_TYPE_PCI1130	"PCI1130"
#define	PCIC_TI_PCI1031		PCI_ID(PCIC_TI_VENDORID, PCIC_PCI1031_DEVID)
#define	PCIC_TYPE_PCI1031	"PCI1031"
#define	PCIC_TI_PCI1131		PCI_ID(PCIC_TI_VENDORID, PCIC_PCI1131_DEVID)
#define	PCIC_TYPE_PCI1131	"PCI1131"
#define	PCIC_TI_PCI1250		PCI_ID(PCIC_TI_VENDORID, PCIC_PCI1250_DEVID)
#define	PCIC_TYPE_PCI1250	"PCI1250"
#define	PCIC_TI_PCI1050		PCI_ID(PCIC_TI_VENDORID, PCIC_PCI1050_DEVID)
#define	PCIC_TYPE_PCI1050	"PCI1050"
#define	PCIC_TI_PCI1221		PCI_ID(PCIC_TI_VENDORID, PCIC_PCI1221_DEVID)
#define	PCIC_TYPE_PCI1221	"PCI1221"
#define	PCIC_TI_PCI1225		PCI_ID(PCIC_TI_VENDORID, PCIC_PCI1225_DEVID)
#define	PCIC_TYPE_PCI1225	"PCI1225"
#define	PCIC_TI_PCI1220		PCI_ID(PCIC_TI_VENDORID, PCIC_PCI1220_DEVID)
#define	PCIC_TYPE_PCI1220	"PCI1220"
#define	PCIC_TI_PCI1260		PCI_ID(PCIC_TI_VENDORID, PCIC_PCI1260_DEVID)
#define	PCIC_TYPE_PCI1260	"PCI1260"
#define	PCIC_TI_PCI1210		PCI_ID(PCIC_TI_VENDORID, PCIC_PCI1210_DEVID)
#define	PCIC_TYPE_PCI1210	"PCI1210"
#define	PCIC_TI_PCI1450		PCI_ID(PCIC_TI_VENDORID, PCIC_PCI1450_DEVID)
#define	PCIC_TYPE_PCI1450	"PCI1450"
#define	PCIC_TI_PCI1251		PCI_ID(PCIC_TI_VENDORID, PCIC_PCI1251_DEVID)
#define	PCIC_TYPE_PCI1251	"PCI1251"
#define	PCIC_TI_PCI1211		PCI_ID(PCIC_TI_VENDORID, PCIC_PCI1211_DEVID)
#define	PCIC_TYPE_PCI1211	"PCI1211"
#define	PCIC_TI_PCI1251B	PCI_ID(PCIC_TI_VENDORID, PCIC_PCI1251B_DEVID)
#define	PCIC_TYPE_PCI1251B	"PCI1251B"
#define	PCIC_TI_PCI1260B	PCI_ID(PCIC_TI_VENDORID, PCIC_PCI1260B_DEVID)
#define	PCIC_TYPE_PCI1260B	"PCI1260B"
#define	PCIC_TI_PCI4450		PCI_ID(PCIC_TI_VENDORID, PCIC_PCI4450_DEVID)
#define	PCIC_TYPE_PCI4450	"PCI4450"
#define	PCIC_TI_PCI4410		PCI_ID(PCIC_TI_VENDORID, PCIC_PCI4410_DEVID)
#define	PCIC_TYPE_PCI4410	"PCI4410"
#define	PCIC_TI_PCI4451		PCI_ID(PCIC_TI_VENDORID, PCIC_PCI4451_DEVID)
#define	PCIC_TYPE_PCI4451	"PCI4451"
#define	PCIC_TI_PCI4510		PCI_ID(PCIC_TI_VENDORID, PCIC_PCI4510_DEVID)
#define	PCIC_TYPE_PCI4510	"PCI4510"
#define	PCIC_TI_PCI1410		PCI_ID(PCIC_TI_VENDORID, PCIC_PCI1410_DEVID)
#define	PCIC_TYPE_PCI1410	"PCI1410"
#define	PCIC_TI_PCI1420		PCI_ID(PCIC_TI_VENDORID, PCIC_PCI1420_DEVID)
#define	PCIC_TYPE_PCI1420	"PCI1420"
#define	PCIC_TI_PCI1451		PCI_ID(PCIC_TI_VENDORID, PCIC_PCI1451_DEVID)
#define	PCIC_TYPE_PCI1451	"PCI1451"
#define	PCIC_TI_PCI1421		PCI_ID(PCIC_TI_VENDORID, PCIC_PCI1421_DEVID)
#define	PCIC_TYPE_PCI1421	"PCI1421"
#define	PCIC_TI_PCI1510		PCI_ID(PCIC_TI_VENDORID, PCIC_PCI1510_DEVID)
#define	PCIC_TYPE_PCI1510	"PCI1510"
#define	PCIC_TI_PCI1520		PCI_ID(PCIC_TI_VENDORID, PCIC_PCI1520_DEVID)
#define	PCIC_TYPE_PCI1520	"PCI1520"
#define	PCIC_TI_VENDOR		PCI_ID(PCIC_TI_VENDORID, 0x0000)
#define	PCIC_TYPE_TI		"PCIC_TI"

/* O2 Micro */
#define	PCIC_O2_VENDORID	0x1217
#define	PCIC_OZ6912_DEVID	0x6972
#define	PCIC_O2_OZ6912		PCI_ID(PCIC_O2_VENDORID, PCIC_OZ6912_DEVID)
#define	PCIC_TYPE_OZ6912	"OZ6912"
#define	PCIC_O2MICRO_VENDOR	PCI_ID(PCIC_O2_VENDORID, 0x0000)
#define	PCIC_TYPE_O2MICRO	"O2Micro"

/* ENE */
#define	PCIC_ENE_VENDORID	0x1524
#define	PCIC_ENE1410_DEVID	0x1410
#define	PCIC_ENE_1410		PCI_ID(PCIC_ENE_VENDORID, PCIC_ENE1410_DEVID)
#define	PCIC_TYPE_1410		"ENE1410"
#define	PCIC_ENE1420_DEVID	0x1420
#define	PCIC_ENE_1420		PCI_ID(PCIC_ENE_VENDORID, PCIC_ENE1420_DEVID)
#define	PCIC_TYPE_1420		"ENE1420"

/* SMC 34C90 */
#define	PCIC_SMC_VENDORID	0x10B3
#define	PCIC_SMC34C90_DEVID	0xB106
#define	PCIC_SMC_34C90		PCI_ID(PCIC_SMC_VENDORID, PCIC_SMC34C90_DEVID)
#define	PCIC_TYPE_34C90		"SMC34c90"

/* Ricoh RL5CXXX */
#define	PCIC_RICOH_VENDORID	0x1180
#define	PCIC_RL5C466_DEVID	0x0466
#define	PCIC_RL5C475_DEVID	0x0475
#define	PCIC_RL5C476_DEVID	0x0476
#define	PCIC_RL5C477_DEVID	0x0477
#define	PCIC_RL5C478_DEVID	0x0478
#define	PCIC_RICOH_RL5C466	PCI_ID(PCIC_RICOH_VENDORID, PCIC_RL5C466_DEVID)
#define	PCIC_RICOH_RL5C475	PCI_ID(PCIC_RICOH_VENDORID, PCIC_RL5C475_DEVID)
#define	PCIC_RICOH_RL5C476	PCI_ID(PCIC_RICOH_VENDORID, PCIC_RL5C476_DEVID)
#define	PCIC_RICOH_RL5C477	PCI_ID(PCIC_RICOH_VENDORID, PCIC_RL5C477_DEVID)
#define	PCIC_RICOH_RL5C478	PCI_ID(PCIC_RICOH_VENDORID, PCIC_RL5C478_DEVID)
#define	PCIC_TYPE_RL5C466		"RL5C466"
#define	PCIC_TYPE_RL5C475		"RL5C475"
#define	PCIC_TYPE_RL5C476		"RL5C476"
#define	PCIC_TYPE_RL5C477		"RL5C477"
#define	PCIC_TYPE_RL5C478		"RL5C478"
#define	PCIC_RICOH_VENDOR	PCI_ID(PCIC_RICOH_VENDORID, 0x0000)
#define	PCIC_TYPE_RICOH		"Ricoh"

/* Toshiba */
#define	PCIC_TOSHIBA_VENDORID	0x1179
#define	PCIC_TOPIC95_DEVID	0x0603
#define	PCIC_TOSHIBA_TOPIC95	PCI_ID(PCIC_TOSHIBA_VENDORID, \
					PCIC_TOPIC95_DEVID)
#define	PCIC_TYPE_TOPIC95	"ToPIC95"
#define	PCIC_TOPIC100_DEVID	0x0617
#define	PCIC_TOSHIBA_TOPIC100	PCI_ID(PCIC_TOSHIBA_VENDORID, \
					PCIC_TOPIC100_DEVID)
#define	PCIC_TYPE_TOPIC100	"ToPIC100"
#define	PCIC_TOSHIBA_VENDOR	PCI_ID(PCIC_TOSHIBA_VENDORID, 0x0000)
#define	PCIC_TYPE_TOSHIBA	"Toshiba"

/* Generic Yenta compliant chip */
#define	PCIC_TYPE_YENTA		"Yenta"

/* Yenta-compliant vcc register, bits */
#define	PCIC_PRESENT_STATE_REG	0x8
#define	PCIC_VCC_MASK		0xc00
#define	PCIC_VCC_3VCARD		0x800
#define	PCIC_VCC_5VCARD		0x400

#define	PCIC_16BIT_CARD		0x010		/* 16 bit card */
#define	PCIC_CB_CARD		0x020		/* cardbus card */
#define	PCIC_CINT_IREQ		0x040		/* Interrupt present */
#define	PCIC_NOT_A_CARD		0x080		/* Not a card */
#define	PCIC_DATA_LOST		0x100		/* Data lost */
#define	PCIC_BAD_VCC_REQ	0x200		/* Bad Vcc request */


/* TI Multi Function Terminal selection (MFUNC0 selected as INTA) */
#define	PCIC_TI_MFUNC_SEL	0x22

#define	PCICPROP_CTL		"controller"

#define	PCIC_REV_LEVEL_LOW	0x02
#define	PCIC_REV_LEVEL_HI 	0x04
#define	PCIC_REV_C		0x04
#define	PCIC_REV_MASK		0x0f

#define	PCIC_ID_NAME		"pcic"
#define	PCIC_DEV_NAME		"pcic"

#ifndef	DEVI_PCI_NEXNAME
#define	DEVI_PCI_NEXNAME	"pci"
#endif

#ifndef DEVI_PCIEX_NEXNAME
#define	DEVI_PCIEX_NEXNAME	"pciex"
#endif

/* PCI Class Code stuff */
#define	PCIC_PCI_CLASS(cls, subclass)	(((cls) << 16) | ((subclass) << 8))
#define	PCIC_PCI_PCMCIA	PCIC_PCI_CLASS(PCI_CLASS_BRIDGE, PCI_BRIDGE_PCMCIA)
#define	PCIC_PCI_CARDBUS PCIC_PCI_CLASS(PCI_CLASS_BRIDGE, PCI_BRIDGE_CARDBUS)

#define	PCIC_MEM_AM	0	/* Attribute Memory */
#define	PCIC_MEM_CM	1	/* Common Memory */

#define	PCS_SUBTYPE_UNKNOWN	0x00 /* haven't processed this yet */
#define	PCS_SUBTYPE_MEMORY	0x01 /* normal memory access */
#define	PCS_SUBTYPE_FAT		0x02 /* DOS floppy (FAT) file system */

/*
 * For speed calculation, assume a SYSCLK rate of 8.33MHz
 *	unless our parent tells us otherwise. 8.33MHz is a
 *	reasonable default for an ISA bus.
 */
#define	PCIC_ISA_DEF_SYSCLK	8	/* MHZ */
#define	PCIC_PCI_DEF_SYSCLK	33	/* MHZ */
#define	PCIC_PCI_25MHZ		25
#define	mhztons(c)		(1000000 / (uint32_t)((c) * 1000))
#define	PCIC_SYSCLK_25MHZ	25 * 1000 * 1000
#define	PCIC_SYSCLK_33MHZ	33 * 1000 * 1000

/* simplify the callback so it looks like straight function call */
#define	PC_CALLBACK	(*pcic->pc_callback)

/* hardware event capabilities -- needs sservice.h */
#define	PCIC_DEFAULT_INT_CAPS	(SBM_BVD1|SBM_BVD2|SBM_RDYBSY|SBM_CD)
#define	PCIC_DEFAULT_RPT_CAPS	(PCIC_DEFAULT_INT_CAPS|SBM_WP)
/* note that we don't support indicators via the PCIC */
#define	PCIC_DEFAULT_CTL_CAPS	(0)

/* format of pcic "ranges" property */
typedef struct pcic_ranges {
	uint32_t pcic_range_caddrhi;
	uint32_t pcic_range_caddrlo;
	uint32_t pcic_range_paddrhi;
	uint32_t pcic_range_paddrmid;
	uint32_t pcic_range_paddrlo;
	uint32_t pcic_range_size;
} pcic_ranges_t;

/* debug stuff */
#if defined(DEBUG)
#define	PCIC_DEBUG
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _PCIC_VAR_H */
