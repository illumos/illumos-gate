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

#ifndef _SYS_USB_EHCI_H
#define	_SYS_USB_EHCI_H


#ifdef __cplusplus
extern "C" {
#endif

/*
 * Enhanced Host Controller Driver (EHCI)
 *
 * The EHCI driver is a software driver which interfaces to the Universal
 * Serial Bus layer (USBA) and the Host Controller (HC). The interface to
 * the Host Controller is defined by the EHCI Host Controller Interface.
 *
 * This header file describes the registers and data structures shared by
 * the EHCI USB controller (HC) and the EHCI Driver.
 */

#include <sys/types.h>
#include <sys/pci.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ndi_impldefs.h>
#include <sys/disp.h>

#include <sys/usb/usba.h>

#include <sys/usb/usba/hcdi.h>

#include <sys/usb/hubd/hub.h>
#include <sys/usb/usba/hubdi.h>
#include <sys/usb/hubd/hubdvar.h>

#include <sys/id32.h>

#define	EHCI_MAX_RH_PORTS	31	/* Maximum root hub ports */


/*
 * Each EHCI buffer can hold upto 4k bytes of data. Hence there is a
 * restriction of 4k alignment while allocating a dma buffer.
 */
#define	EHCI_4K_ALIGN			0x1000

/*
 * USB Host controller DMA scatter gather list defines for
 * Sparc and non-sparc architectures.
 */
#if defined(__sparc)
#define	EHCI_DMA_ATTR_MAX_XFER		0xffffffffull
#define	EHCI_DMA_ATTR_COUNT_MAX		0xffffffffull
#define	EHCI_DMA_ATTR_GRANULAR		512
#define	EHCI_DMA_ATTR_ALIGNMENT		EHCI_4K_ALIGN
#else
#define	EHCI_DMA_ATTR_MAX_XFER		0x00ffffffull
#define	EHCI_DMA_ATTR_COUNT_MAX		0x00ffffffull
#define	EHCI_DMA_ATTR_GRANULAR		1
#define	EHCI_DMA_ATTR_ALIGNMENT		EHCI_4K_ALIGN
#endif

/* Set the default data structure (QTD,QH,SITD,ITD) to a 32 byte alignment */
#define	EHCI_DMA_ATTR_TD_QH_ALIGNMENT	0x0020
#define	EHCI_DMA_ATTR_PFL_ALIGNMENT	EHCI_4K_ALIGN

/* TW scatter/gatter list defines */
#define	EHCI_DMA_ATTR_TW_SGLLEN		0x7fffffff

/*
 * EHCI Capability Registers
 *
 * The registers specify the limits, restrictions and capabilities of the
 * specific EHCI Host Controller implementation.
 */
typedef	volatile struct	ehci_caps {
	uint8_t		ehci_caps_length;	/* Capability register length */
	uint8_t		ehci_pad;		/* Reserved */
	uint16_t	ehci_version;		/* Interface version number */
	uint32_t	ehci_hcs_params;	/* Structural paramters */
	uint32_t	ehci_hcc_params;	/* Capability paramters */
	uint8_t		ehci_port_route[8];	/* Companion port route */
} ehci_caps_t;

/*
 * EHCI revision
 *
 * EHCI driver supports EHCI host controllers compliant to 0.95 and higher
 * revisions of EHCI specifications.
 */
#define	EHCI_REVISION_0_95		0x95	   /* Revision 0.95 */

/* EHCI HCS Params Register Bits */
#define	EHCI_HCS_PORT_INDICATOR		0x00010000 /* Port indicator control */
#define	EHCI_HCS_NUM_COMP_CTRLS		0x0000F000 /* No of companion ctrls */
#define	EHCI_HCS_NUM_COMP_CTRL_SHIFT	12
#define	EHCI_HCS_NUM_PORTS_CC		0x00000F00 /* Ports per classic ctrls */
#define	EHCI_HCS_NUM_PORTS_CC_SHIFT	8
#define	EHCI_HCS_PORT_ROUTING_RULES	0x00000080 /* Port routing rules */
#define	EHCI_HCS_PORT_POWER_CONTROL	0x00000010 /* Port power control */
#define	EHCI_HCS_NUM_PORTS		0x0000000F /* No of root hub ports */

/* EHCI HCC Params Register Bits */
#define	EHCI_HCC_EECP			0x0000FF00 /* Extended capbilities */
#define	EHCI_HCC_EECP_SHIFT		8
#define	EHCI_HCC_EECP_MIN_OFFSET	0x00000040 /* Minimum valid offset */
#define	EHCI_HCC_ISOCH_SCHED_THRESHOLD	0x000000F0 /* Isoch sched threshold */
#define	EHCI_HCC_ASYNC_SCHED_PARK_CAP	0x00000004 /* Async schedule park cap */
#define	EHCI_HCC_PROG_FRAME_LIST_FLAG	0x00000002 /* Prog frame list flag */
#define	EHCI_HCC_64BIT_ADDR_CAP		0x00000001 /* 64bit addr capability */

/* EHCI Port Route Register Bits */
#define	EHCI_PORT_ROUTE_EVEN		0x0F	   /* Classic even port route */
#define	EHCI_PORT_ROUTE_ODD		0xF0	   /* Classic odd port route */
#define	EHCI_PORT_ROUTE_ODD_SHIFT	4


/*
 * EHCI Operational Registers
 *
 * The EHCI Host Controller contains a set of on-chip operational registers
 * which are mapped into a non-cacheable portion  of the system addressable
 * space. These registers are also used by the EHCI Host Controller Driver.
 * This structure must be aligned to 32 byte boundary.
 */
typedef volatile struct ehci_regs {
	/* Control and status registers */
	uint32_t	ehci_command;		 /* USB commands */
	uint32_t	ehci_status;		 /* USB status */
	uint32_t	ehci_interrupt;		 /* Interrupt enable */
	uint32_t	ehci_frame_index;	 /* Frame index */

	/* Memory pointer registers */
	uint32_t	ehci_ctrl_segment;	 /* Control data segment */
	uint32_t	ehci_periodic_list_base; /* Period frm list base addr */
	uint32_t	ehci_async_list_addr;	 /* Async list base address */
	uint32_t	ehci_pad[9];		 /* Head of the bulk list */

	/* Root hub registers */
	uint32_t	ehci_config_flag;	 /* Config Flag */
	uint32_t	ehci_rh_port_status[EHCI_MAX_RH_PORTS];
			/* Root hub port status and control information */
} ehci_regs_t;

/* EHCI Command Register Bits */
#define	EHCI_CMD_INTR_THRESHOLD		0x00FF0000 /* Intr threshold control */
#define	EHCI_CMD_INTR_SHIFT		16
#define	EHCI_CMD_01_INTR		0x00010000 /* 01 micro-frame */
#define	EHCI_CMD_02_INTR		0x00020000 /* 02 micro-frames */
#define	EHCI_CMD_04_INTR		0x00040000 /* 04 micro-frames */
#define	EHCI_CMD_08_INTR		0x00080000 /* 08 micro-frames */
#define	EHCI_CMD_16_INTR		0x00100000 /* 16 micro-frames */
#define	EHCI_CMD_32_INTR		0x00200000 /* 32 micro-frames */
#define	EHCI_CMD_64_INTR		0x00400000 /* 64 micro-frames */

#define	EHCI_CMD_ASYNC_PARK_ENABLE	0x00000800 /* Async sched park enable */
#define	EHCI_CMD_ASYNC_PARK_COUNT	0x00000300 /* Async sched park count */
#define	EHCI_CMD_ASYNC_PARK_COUNT_1	0x00000100 /* Async sched park cnt 1 */
#define	EHCI_CMD_ASYNC_PARK_COUNT_2	0x00000200 /* Async sched park cnt 2 */
#define	EHCI_CMD_ASYNC_PARK_COUNT_3	0x00000300 /* Async sched park cnt 3 */
#define	EHCI_CMD_ASYNC_PARK_SHIFT	8
#define	EHCI_CMD_LIGHT_HC_RESET		0x00000080 /* Light host ctrl reset */
#define	EHCI_CMD_INTR_ON_ASYNC_ADVANCE	0x00000040 /* Async advance doorbell */
#define	EHCI_CMD_ASYNC_SCHED_ENABLE	0x00000020 /* Async schedule enable */
#define	EHCI_CMD_PERIODIC_SCHED_ENABLE	0x00000010 /* Periodic sched enable */
#define	EHCI_CMD_FRAME_LIST_SIZE	0x0000000C /* Frame list size */
#define	EHCI_CMD_FRAME_LIST_SIZE_SHIFT	2
#define	EHCI_CMD_FRAME_1024_SIZE	0x00000000 /* 1024 frame list size */
#define	EHCI_CMD_FRAME_512_SIZE		0x00000004 /* 512 frame list size */
#define	EHCI_CMD_FRAME_256_SIZE		0X00000008 /* 256 frame list size */
#define	EHCI_CMD_HOST_CTRL_RESET	0x00000002 /* Host controller reset */
#define	EHCI_CMD_HOST_CTRL_RS		0x00000001 /* Host ctrl run or stop */
#define	EHCI_CMD_HOST_CTRL_RUN		0x00000001 /* Host controller run */
#define	EHCI_CMD_HOST_CTRL_STOP		0x00000000 /* Host controller stop */

/* EHCI Status Register Bits */
#define	EHCI_STS_ASYNC_SCHED_STATUS	0x00008000 /* Async schedule status */
#define	EHCI_STS_PERIODIC_SCHED_STATUS	0x00004000 /* Periodic sched status */
#define	EHCI_STS_EMPTY_ASYNC_SCHEDULE	0x00002000 /* Empty async schedule */
#define	EHCI_STS_HOST_CTRL_HALTED	0x00001000 /* Host controller Halted */
#define	EHCI_STS_ASYNC_ADVANCE_INTR	0x00000020 /* Intr on async advance */
#define	EHCI_STS_HOST_SYSTEM_ERROR_INTR	0x00000010 /* Host system error */
#define	EHCI_STS_FRM_LIST_ROLLOVER_INTR	0x00000008 /* Frame list rollover */
#define	EHCI_STS_RH_PORT_CHANGE_INTR	0x00000004 /* Port change detect */
#define	EHCI_STS_USB_ERROR_INTR		0x00000002 /* USB error interrupt */
#define	EHCI_STS_USB_INTR		0x00000001 /* USB interrupt */

/* EHCI Interrupt Register Bits */
#define	EHCI_INTR_ASYNC_ADVANCE		0x00000020 /* Async advance interrupt */
#define	EHCI_INTR_HOST_SYSTEM_ERROR	0x00000010 /* Host system error intr */
#define	EHCI_INTR_FRAME_LIST_ROLLOVER	0x00000008 /* Framelist rollover intr */
#define	EHCI_INTR_RH_PORT_CHANGE	0x00000004 /* Port change interrupt */
#define	EHCI_INTR_USB_ERROR		0x00000002 /* USB error interrupt */
#define	EHCI_INTR_USB			0x00000001 /* USB interrupt */

/* EHCI Frame Index Register Bits */
#define	EHCI_FRAME_INDEX		0x00003FFF /* Frame index */
#define	EHCI_FRAME_1024			0x00003FFF /* 1024 elements */
#define	EHCI_FRAME_0512			0x00001FFF /* 512 elements */
#define	EHCI_FRAME_0256			0x00000FFF /* 256 elements */

/* EHCI Control Data Structure Segment Register Bits */
/* Most significant 32 bits for all EHCI data structures in 64bit addressing */
#define	EHCI_CTRLD_SEGMENT		0xFFFFFFFF /* Control data segment */

/* EHCI Periodic Frame List Base Address Register Bits */
#define	EHCI_PERIODIC_LIST_BASE		0xFFFFF000 /* Periodic framelist addr */
#define	EHCI_PERIODIC_LIST_BASE_SHIFT	12

/* EHCI Asynchronous List Address Register Bits */
#define	EHCI_ASYNC_LIST_ADDR		0xFFFFFFE0 /* Async list address */
#define	EHCI_ASYNC_LIST_ADDR_SHIFT	5

/* EHCI Config Flag Register Bits */
#define	EHCI_CONFIG_FLAG		0x00000001 /* Route host controllers */
#define	EHCI_CONFIG_FLAG_CLASSIC	0x00000000 /* Route to Classic ctrl */
#define	EHCI_CONFIG_FLAG_EHCI		0x00000001 /* Route to EHCI ctrl */

/* EHCI Root Hub Port Status and Control Register Bits */
#define	EHCI_RH_PORT_OVER_CURENT_ENABLE	0x00400000 /* Over current enable */
#define	EHCI_RH_PORT_DISCONNECT_ENABLE	0x00200000 /* Disconnect enable */
#define	EHCI_RH_PORT_CONNECT_ENABLE	0x00100000 /* Connect enable */
#define	EHCI_RH_PORT_INDICATOR		0x0000C000 /* Port indicator control */
#define	EHCI_RH_PORT_IND_SHIFT		14
#define	EHCI_RH_PORT_IND_OFF		0x00000000 /* Port indicators off */
#define	EHCI_RH_PORT_IND_AMBER		0x00004000 /* Amber port indicator */
#define	EHCI_RH_PORT_IND_GREEN		0x00008000 /* Green port indicator */
#define	EHCI_RH_PORT_OWNER		0x00002000 /* Port ownership */
#define	EHCI_RH_PORT_OWNER_CLASSIC	0x00002000 /* Classic port ownership */
#define	EHCI_RH_PORT_OWNER_EHCI		0x00000000 /* EHCI port ownership */
#define	EHCI_RH_PORT_POWER		0x00001000 /* Port power */
#define	EHCI_RH_PORT_LINE_STATUS	0x00000C00 /* USB speed line status */
#define	EHCI_RH_PORT_LOW_SPEED		0x00000400 /* Low speed */
#define	EHCI_RH_PORT_RESET		0x00000100 /* Port reset */
#define	EHCI_RH_PORT_SUSPEND		0x00000080 /* Port suspend */
#define	EHCI_RH_PORT_RESUME		0x00000040 /* Port resume */
#define	EHCI_RH_PORT_OVER_CURR_CHANGE	0x00000020 /* Over current change */
#define	EHCI_RH_PORT_OVER_CURR_ACTIVE	0x00000010 /* Over current active */
#define	EHCI_RH_PORT_ENABLE_CHANGE	0x00000008 /* Port enable change */
#define	EHCI_RH_PORT_ENABLE		0x00000004 /* Port enable */
#define	EHCI_RH_PORT_CONNECT_STS_CHANGE	0x00000002 /* Connect status change */
#define	EHCI_RH_PORT_CONNECT_STATUS	0x00000001 /* Connect status */

/* Root hub port change bits mask */
#define	EHCI_RH_PORT_CLEAR_MASK		0x0000002A /* Clear bits mask */


/*
 * EHCI Extended Capability Registers
 *
 * Currently this register only specifies BIOS handoff information.
 */
#define	EHCI_EX_CAP_SPECIFICS		0xFFFF0000
#define	EHCI_EX_CAP_SPECIFICS_SHIFT	16
#define	EHCI_EX_CAP_NEXT_PTR		0x0000FF00
#define	EHCI_EX_CAP_NEXT_PTR_SHIFT	8
#define	EHCI_EX_CAP_ID			0x000000FF
#define	EHCI_EX_CAP_ID_SHIFT		0
#define	EHCI_EX_CAP_ID_RESERVED		0
#define	EHCI_EX_CAP_ID_BIOS_HANDOFF	1

#define	EHCI_LEGSUP_OS_OWNED_SEM	0x01000000
#define	EHCI_LEGSUP_BIOS_OWNED_SEM	0x00010000


/*
 * Host Controller Periodic Frame List Area
 *
 * The Host Controller Periodic Frame List Area is a 4K structre of system
 * memory that is established by the Host Controller Driver (HCD) and this
 * structre is used for communication between HCD and HC. The HCD maintains
 * a pointer to this structure in the Host Controller (HC). This structure
 * must be aligned to a 4K boundary. There are 1024 periodic frame list
 * entries.
 */

#define	EHCI_NUM_INTR_QH_LISTS		32	/* No of intr lists */
#define	EHCI_NUM_STATIC_NODES		63	/* No of static QHs */
#define	EHCI_NUM_PERIODIC_FRAME_LISTS	1024	/* No of entries */

typedef volatile struct ehci_periodic_frame_list {
	uint32_t	ehci_periodic_frame_list_table[
			    EHCI_NUM_PERIODIC_FRAME_LISTS]; /* 1024 lists */
} ehci_periodic_frame_list_t;


/*
 * Host Controller Queue Head
 *
 * An Queue Head (QH) is a memory structure that describes the information
 * necessary for the Host Controller to communicate with a device endpoint
 * except High Speed and Full Speed Isochronous's endpoints. An QH includes
 * a Queue Element Transfer Descriptor (QTD) pointer.  This structure must
 * be aligned to a 32 byte boundary.
 */
typedef volatile struct ehci_qh {
	/* Endpoint capabilities or characteristics */
	uint32_t	qh_link_ptr;	  /* Next QH or ITD or SITD */
	uint32_t	qh_ctrl;	  /* Generic control information */
	uint32_t	qh_split_ctrl;	  /* Split transaction control info */
	uint32_t	qh_curr_qtd;	  /* Current QTD */

	/* Tranfer overlay */
	uint32_t	qh_next_qtd;	  /* Next QTD */
	uint32_t	qh_alt_next_qtd;  /* Next alternate QTD */
	uint32_t	qh_status;	  /* Status of current QTD */
	uint32_t	qh_buf[5];	  /* Buffer pointers */
	uint32_t	qh_buf_high[5];	  /* For 64 bit addressing */

	/* HCD private fields */
	uint32_t	qh_dummy_qtd;	  /* Current dummy qtd */
	uint32_t	qh_prev;	  /* Prevous QH */
	uint32_t	qh_state;	  /* QH's state */
	uint32_t	qh_reclaim_next;  /* Next QH on reclaim list */
	uint32_t	qh_reclaim_frame; /* Reclaim usb frame number */
	uint8_t		qh_pad[8];	  /* Required padding */
} ehci_qh_t;

/*
 * qh_link_ptr control bits.
 */
#define	EHCI_QH_LINK_PTR		0xFFFFFFE0	/* QH link ptr mask */
#define	EHCI_QH_LINK_REF		0x00000006	/* Ref to QH/ITD/SITD */
#define	EHCI_QH_LINK_REF_ITD		0x00000000	/* Isoch QTD pointer */
#define	EHCI_QH_LINK_REF_QH		0x00000002	/* QH pointer */
#define	EHCI_QH_LINK_REF_SITD		0x00000004	/* SIQTD pointer */
#define	EHCI_QH_LINK_REF_FSTN		0x00000006	/* FSTN pointer */
#define	EHCI_QH_LINK_PTR_VALID		0x00000001	/* Link ptr validity */

/*
 * qh_ctrl control bits.
 */
#define	EHCI_QH_CTRL_NC_RL		0xF0000000	/* Nak count reload */
#define	EHCI_QH_CTRL_NC_RL_SHIFT	28		/* NC reload shift */
#define	EHCI_QH_CTRL_MAX_NC		0xF0000000	/* Max Nak counts */
#define	EHCI_QH_CTRL_CONTROL_ED_FLAG	0x08000000	/* Ctrl endpoint flag */
#define	EHCI_QH_CTRL_MAXPKTSZ		0x07FF0000	/* Max packet length */
#define	EHCI_QH_CTRL_MAXPKTSZ_SHIFT	16		/* Max packet shift */
#define	EHCI_QH_CTRL_RECLAIM_HEAD	0x00008000	/* Head reclaim list */
#define	EHCI_QH_CTRL_DATA_TOGGLE	0x00004000	/* Data toggle */
#define	EHCI_QH_CTRL_ED_SPEED		0x00003000	/* Endpoint speed */
#define	EHCI_QH_CTRL_ED_FULL_SPEED	0x00000000	/* FullSpeed endpoint */
#define	EHCI_QH_CTRL_ED_LOW_SPEED	0x00001000	/* LowSpeed endpoint */
#define	EHCI_QH_CTRL_ED_HIGH_SPEED	0x00002000	/* HighSpeed endpoint */
#define	EHCI_QH_CTRL_ED_SPEED_SHIFT	12		/* ED speed shift */
#define	EHCI_QH_CTRL_ED_NUMBER		0x00000F00	/* Endpoint number */
#define	EHCI_QH_CTRL_ED_NUMBER_SHIFT	8		/* ED number shift */
#define	EHCI_QH_CTRL_ED_INACTIVATE	0x00000080	/* Inctivate endpoint */
#define	EHCI_QH_CTRL_DEVICE_ADDRESS	0x0000007F	/* Device address */

/*
 * q_split_ctrl control bits.
 */
#define	EHCI_QH_SPLIT_CTRL_MULT		0xC0000000	/* HB multiplier */
#define	EHCI_QH_SPLIT_CTRL_MULT_SHIFT	30		/* HB mult Shift */
#define	EHCI_QH_SPLIT_CTRL_1_XACTS	0x40000000	/* 1 Xacts per uFrame */
#define	EHCI_QH_SPLIT_CTRL_2_XACTS	0x80000000	/* 2 Xacts per uFrame */
#define	EHCI_QH_SPLIT_CTRL_3_XACTS	0xC0000000	/* 3 Xacts per uFrame */
#define	EHCI_QH_SPLIT_CTRL_HUB_PORT	0x3F800000	/* HS hub port number */
#define	EHCI_QH_SPLIT_CTRL_HUB_PORT_SHIFT 23		/* HS hubport no shft */
#define	EHCI_QH_SPLIT_CTRL_HUB_ADDR	0x007F0000	/* HS hub address */
#define	EHCI_QH_SPLIT_CTRL_HUB_ADDR_SHIFT 16		/* HS hub addr mask */
#define	EHCI_QH_SPLIT_CTRL_COMP_MASK	0x0000FF00	/* Split comp mask */
#define	EHCI_QH_SPLIT_CTRL_COMP_SHIFT	8		/* Split comp shift */
#define	EHCI_QH_SPLIT_CTRL_INTR_MASK	0x000000FF	/* Intr schedule mask */

/*
 * qh_curr_qtd control bits.
 */
#define	EHCI_QH_CURR_QTD_PTR		0xFFFFFFE0	/* Curr element QTD */

/*
 * qh_next_qtd control bits.
 */
#define	EHCI_QH_NEXT_QTD_PTR		0xFFFFFFE0	/* Next QTD */
#define	EHCI_QH_NEXT_QTD_PTR_VALID	0x00000001	/* Next QTD validity */

/*
 * qh_alt_next_qtd control bits.
 */
#define	EHCI_QH_ALT_NEXT_QTD_PTR	0xFFFFFFE0	/* Alternate next QTD */
#define	EHCI_QH_ALT_NEXT_QTD_PTR_VALID	0x00000001	/* Alt QTD validity */
#define	EHCI_QH_ALT_NEXT_QTD_NAKCNT	0x0000001E	/* NAK counter */

/*
 * qh_status control bits.
 */
#define	EHCI_QH_STS_DATA_TOGGLE		0x80000000	/* Data toggle */
#define	EHCI_QH_STS_BYTES_TO_XFER	0x7FFF0000	/* Bytes to transfer */
#define	EHCI_QH_STS_BYTES_TO_XFER_SHIFT	16		/* Bytes to xfer mask */
#define	EHCI_QH_STS_INTR_ON_COMPLETE	0x00008000	/* Intr on complete */
#define	EHCI_QH_STS_C_PAGE		0x00007000	/* C page */
#define	EHCI_QH_STS_ERROR_COUNTER	0x00000C00	/* Error counter */
#define	EHCI_QH_STS_ERROR_COUNT_MASK	0x00000C00	/* Error count mask */
#define	EHCI_QH_STS_PID_CODE		0x00000300	/* PID code */
#define	EHCI_QH_STS_XACT_STATUS		0x000000FF	/* Xact Status */
#define	EHCI_QH_STS_HS_XACT_STATUS	0x000000F8	/* HS Xact status */
#define	EHCI_QH_STS_NON_HS_XACT_STATUS	0x000000FD	/* Non HS Xact status */
#define	EHCI_QH_STS_NO_ERROR		0x00000000	/* No error */
#define	EHCI_QH_STS_ACTIVE		0x00000080	/* Active */
#define	EHCI_QH_STS_HALTED		0x00000040	/* Halted */
#define	EHCI_QH_STS_DATA_BUFFER_ERR	0x00000020	/* Data buffer error */
#define	EHCI_QH_STS_BABBLE_DETECTED	0x00000010	/* Babble detected */
#define	EHCI_QH_STS_XACT_ERROR		0x00000008	/* Transaction error */
#define	EHCI_QH_STS_MISSED_uFRAME	0x00000004	/* Missed micro frame */
#define	EHCI_QH_STS_SPLIT_XSTATE	0x00000002	/* Split xact state */
#define	EHCI_QH_STS_DO_START_SPLIT	0x00000000	/* Do start split */
#define	EHCI_QH_STS_DO_COMPLETE_SPLIT	0x00000002	/* Do complete split */
#define	EHCI_QH_STS_PING_STATE		0x00000001	/* Ping state */
#define	EHCI_QH_STS_DO_OUT		0x00000000	/* Do OUT */
#define	EHCI_QH_STS_DO_PING		0x00000001	/* Do PING */
#define	EHCI_QH_STS_PRD_SPLIT_XACT_ERR	0x00000001	/* Periodic split err */

/*
 * qh_buf[X] control bits.
 */
#define	EHCI_QH_BUF_PTR			0xFFFFF000	/* Buffer pointer */
#define	EHCI_QH_BUF_CURR_OFFSET		0x00000FFF	/* Current offset */
#define	EHCI_QH_BUF_CPROG_MASK		0x000000FF	/* Split progress */
#define	EHCI_QH_BUF_SBYTES		0x00000FE0	/* Software S bytes */
#define	EHCI_QH_BUF_FRAME_TAG		0x0000001F	/* Split xct frametag */

/*
 * qh_buf_high[X] control bits.
 */
#define	EHCI_QH_BUF_HIGH_PTR		0xFFFFFFFF	/* For 64 addressing */

/*
 * qh_state
 *
 * QH States
 */
#define	EHCI_QH_FREE			1		/* Free QH */
#define	EHCI_QH_STATIC			2		/* Static QH */
#define	EHCI_QH_ACTIVE			3		/* Active QH */


/*
 * Host Controller Queue Element Transfer Descriptor
 *
 * A Queue Element Transfer Descriptor (QTD) is a memory structure that
 * describes the information necessary for the Host Controller	(HC) to
 * transfer a block  of data to or from a device endpoint except High
 * Speed and Full Speed Isochronous's endpoints. These QTD's will be
 * attached to a Queue Head (QH). This structure must be aligned to a
 * 32 byte boundary.
 */
typedef	volatile struct ehci_qtd {
	uint32_t	qtd_next_qtd;		/* Next QTD */
	uint32_t	qtd_alt_next_qtd;	/* Next alternate QTD */
	uint32_t	qtd_ctrl;		/* Control information */
	uint32_t	qtd_buf[5];		/* Buffer pointers */
	uint32_t	qtd_buf_high[5];	/* For 64 bit addressing */

	/* HCD private fields */
	uint32_t	qtd_trans_wrapper;	/* Transfer wrapper */
	uint32_t	qtd_tw_next_qtd;	/* Next qtd on TW */
	uint32_t	qtd_active_qtd_next;	/* Next QTD on active list */
	uint32_t	qtd_active_qtd_prev;	/* Prev QTD on active list */
	uint32_t	qtd_state;		/* QTD state */
	uint32_t	qtd_ctrl_phase;		/* Control xfer phase info */
	uint32_t	qtd_xfer_offs;		/* Starting buffer offset */
	uint32_t	qtd_xfer_len;		/* Transfer length */
	uint8_t		qtd_pad[12];		/* Required padding */
} ehci_qtd_t;

/*
 * qtd_next_qtd control bits.
 */
#define	EHCI_QTD_NEXT_QTD_PTR		0xFFFFFFE0	/* Next QTD pointer */
#define	EHCI_QTD_NEXT_QTD_PTR_VALID	0x00000001	/* Next QTD validity */

/*
 * qtd_alt_next_qtd control bits.
 */
#define	EHCI_QTD_ALT_NEXT_QTD_PTR	0xFFFFFFE0	/* Alt QTD pointer */
#define	EHCI_QTD_ALT_NEXT_QTD_PTR_VALID 0x00000001	/* Alt QTD validity */

/*
 * qtd_ctrl control bits.
 */
#define	EHCI_QTD_CTRL_DATA_TOGGLE	0x80000000	/* Data toggle */
#define	EHCI_QTD_CTRL_DATA_TOGGLE_0	0x00000000	/* Data toggle 0 */
#define	EHCI_QTD_CTRL_DATA_TOGGLE_1	0x80000000	/* Data toggle 1 */
#define	EHCI_QTD_CTRL_BYTES_TO_XFER	0x7FFF0000	/* Bytes to xfer */
#define	EHCI_QTD_CTRL_BYTES_TO_XFER_SHIFT 16		/* Bytes xfer mask */
#define	EHCI_QTD_CTRL_INTR_ON_COMPLETE	0x00008000	/* Intr on complete */
#define	EHCI_QTD_CTRL_C_PAGE		0x00007000	/* Current page */
#define	EHCI_QTD_CTRL_MAX_ERR_COUNTS	0x00000C00	/* Max error counts */
#define	EHCI_QTD_CTRL_PID_CODE		0x00000300	/* PID code */
#define	EHCI_QTD_CTRL_OUT_PID		0x00000000	/* OUT token */
#define	EHCI_QTD_CTRL_IN_PID		0x00000100	/* IN token */
#define	EHCI_QTD_CTRL_SETUP_PID		0x00000200	/* SETUP token */
#define	EHCI_QTD_CTRL_XACT_STATUS	0x000000FF	/* Xact status */
#define	EHCI_QTD_CTRL_HS_XACT_STATUS	0x000000F8	/* HS Xact status */
#define	EHCI_QTD_CTRL_NON_HS_XACT_STATUS 0x000000FD	/* Non HS Xact status */
#define	EHCI_QTD_CTRL_NO_ERROR		0x00000000	/* No error */
#define	EHCI_QTD_CTRL_ACTIVE_XACT	0x00000080	/* Active xact */
#define	EHCI_QTD_CTRL_HALTED_XACT	0x00000040	/* Halted due to err */
#define	EHCI_QTD_CTRL_DATA_BUFFER_ERROR	0x00000020	/* Data buffer error */
#define	EHCI_QTD_CTRL_ERR_COUNT_MASK	0x00000C00	/* Error count */
#define	EHCI_QTD_CTRL_BABBLE_DETECTED	0x00000010	/* Babble detected */
#define	EHCI_QTD_CTRL_XACT_ERROR	0x00000008	/* Transaction error */
#define	EHCI_QTD_CTRL_MISSED_uFRAME	0x00000004	/* Missed uFrame */
#define	EHCI_QTD_CTRL_SPLIT_XACT_STATE	0x00000002	/* Split xact state */
#define	EHCI_QTD_CTRL_DO_START_SPLIT	0x00000000	/* Do start split */
#define	EHCI_QTD_CTRL_DO_COMPLETE_SPLIT	0x00000002	/* Do complete split */
#define	EHCI_QTD_CTRL_PING_STATE	0x00000001	/* Ping state */
#define	EHCI_QTD_CTRL_DO_OUT		0x00000000	/* Do OUT */
#define	EHCI_QTD_CTRL_DO_PING		0x00000001	/* Do PING */
#define	EHCI_QTD_CTRL_PRD_SPLIT_XACT_ERR 0x00000001	/* Periodic split err */

/*
 * qtd_buf[X] control bits.
 */
#define	EHCI_QTD_BUF_PTR		0xFFFFF000	/* Buffer pointer */
#define	EHCI_QTD_BUF_CURR_OFFSET	0x00000FFF	/* Current offset */

/*
 * qtd_buf_high[X] control bits.
 */
#define	EHCI_QTD_BUF_HIGH_PTR		0xFFFFFFFF	/* 64 bit addressing */

/*
 * qtd_state
 *
 * QTD States
 */
#define	EHCI_QTD_FREE			1		/* Free QTD */
#define	EHCI_QTD_DUMMY			2		/* Dummy QTD */
#define	EHCI_QTD_ACTIVE			3		/* Active QTD */
#define	EHCI_QTD_RECLAIM		4		/* Reclaim QTD */

/*
 * qtd_ctrl_phase
 *
 * Control Transfer Phase information
 */
#define	EHCI_CTRL_SETUP_PHASE		1		/* Setup phase */
#define	EHCI_CTRL_DATA_PHASE		2		/* Data phase */
#define	EHCI_CTRL_STATUS_PHASE		3		/* Status phase */

/*
 * Host Controller Split Isochronous Transfer Descripter
 *
 * iTD/siTD is a memory structure that describes the information necessary for
 * the Host Controller (HC) to transfer a block of data to or from a
 * 1.1 isochronous device end point.  The iTD/siTD will be inserted between
 * the periodic frame list and the interrupt tree lattice.  This structure
 * must be aligned to a 32 byte boundary.
 */
typedef	volatile struct ehci_itd {
	uint32_t	itd_link_ptr;		/* Next TD */
	uint32_t	itd_body[15];		/* iTD and siTD body */
	uint32_t	itd_body_high[7];	/* For 64 bit addressing */

	/* Padding required */
	uint32_t	itd_pad;

	/* HCD private fields */
	uint32_t	itd_trans_wrapper;	/* Transfer wrapper */
	uint32_t	itd_itw_next_itd;	/* Next iTD on TW */
	uint32_t	itd_next_active_itd;	/* Next iTD in active list */
	uint32_t	itd_state;		/* iTD state */
	uint32_t	itd_index[8];		/* iTD index */
	uint64_t	itd_frame_number;	/* Frame iTD exists */
	uint64_t	itd_reclaim_number;	/* Frame iTD is reclaimed */
} ehci_itd_t;

/*
 * Generic Link Ptr Bits
 * EHCI_TD_LINK_PTR : Points to the next data object to be processed
 * EHCI_TD_LINK_PTR_TYPE : Type of reference this descriptor is
 * EHCI_TD_LINK_PTR_VALID : Is this link pointer valid
 */
#define	EHCI_ITD_LINK_PTR		0xFFFFFFE0	/* TD link ptr mask */
#define	EHCI_ITD_LINK_REF		0x00000006	/* Ref to TD/ITD/SITD */
#define	EHCI_ITD_LINK_REF_ITD		0x00000000	/* ITD pointer */
#define	EHCI_ITD_LINK_REF_QH		0x00000002	/* QH pointer */
#define	EHCI_ITD_LINK_REF_SITD		0x00000004	/* SITD pointer */
#define	EHCI_ITD_LINK_REF_FSTN		0x00000006	/* FSTN pointer */
#define	EHCI_ITD_LINK_PTR_INVALID	0x00000001	/* Link ptr validity */

#define	EHCI_ITD_CTRL_LIST_SIZE		8
#define	EHCI_ITD_BUFFER_LIST_SIZE	7
#define	EHCI_ITD_CTRL0			0	/* Status and Ctrl List */
#define	EHCI_ITD_CTRL1			1
#define	EHCI_ITD_CTRL2			2
#define	EHCI_ITD_CTRL3			3
#define	EHCI_ITD_CTRL4			4
#define	EHCI_ITD_CTRL5			5
#define	EHCI_ITD_CTRL6			6
#define	EHCI_ITD_CTRL7			7
#define	EHCI_ITD_BUFFER0		8	/* Buffer Page Ptr List */
#define	EHCI_ITD_BUFFER1		9
#define	EHCI_ITD_BUFFER2		10
#define	EHCI_ITD_BUFFER3		11
#define	EHCI_ITD_BUFFER4		12
#define	EHCI_ITD_BUFFER5		13
#define	EHCI_ITD_BUFFER6		14

/*
 * iTD Transaction Status and Control bits
 */
#define	EHCI_ITD_XFER_STATUS_MASK	0xF0000000
#define	EHCI_ITD_XFER_STATUS_SHIFT	28
#define	EHCI_ITD_XFER_ACTIVE		0x80000000
#define	EHCI_ITD_XFER_DATA_BUFFER_ERR	0x40000000
#define	EHCI_ITD_XFER_BABBLE		0x20000000
#define	EHCI_ITD_XFER_ERROR		0x10000000
#define	EHCI_ITD_XFER_LENGTH		0x0FFF0000
#define	EHCI_ITD_XFER_IOC		0x00008000
#define	EHCI_ITD_XFER_IOC_ON		0x00008000
#define	EHCI_ITD_XFER_IOC_OFF		0x00000000
#define	EHCI_ITD_XFER_PAGE_SELECT	0x00007000
#define	EHCI_ITD_XFER_OFFSET		0x00000FFF

/*
 * iTD Buffer Page Pointer bits
 */
#define	EHCI_ITD_CTRL_BUFFER_MASK	0xFFFFF000
#define	EHCI_ITD_CTRL_ENDPT_MASK	0x00000F00
#define	EHCI_ITD_CTRL_DEVICE_MASK	0x0000007F
#define	EHCI_ITD_CTRL_DIR		0x00000800
#define	EHCI_ITD_CTRL_DIR_IN		0x00000800
#define	EHCI_ITD_CTRL_DIR_OUT		0x00000000
#define	EHCI_ITD_CTRL_MAX_PACKET_MASK	0x000007FF
#define	EHCI_ITD_CTRL_MULTI_MASK	0x00000003
#define	EHCI_ITD_CTRL_ONE_XACT		0x00000001
#define	EHCI_ITD_CTRL_TWO_XACT		0x00000002
#define	EHCI_ITD_CTRL_THREE_XACT	0x00000003

/* Unused iTD index */
#define	EHCI_ITD_UNUSED_INDEX		0xFFFFFFFF

#define	EHCI_SITD_CTRL			0
#define	EHCI_SITD_UFRAME_SCHED		1
#define	EHCI_SITD_XFER_STATE		2
#define	EHCI_SITD_BUFFER0		3
#define	EHCI_SITD_BUFFER1		4
#define	EHCI_SITD_PREV_SITD		5

/*
 * sitd_ctrl bits
 * EHCI_SITD_CTRL_DIR : Direction of transaction
 * EHCI_SITD_CTRL_PORT_MASK : Port # of recipient transaction translator(TT)
 * EHCI_SITD_CTRL_HUB_MASK : Device address of the TT's hub
 * EHCI_SITD_CTRL_END_PT_MASK : Endpoint # on device serving as data source/sink
 * EHCI_SITD_CTRL_DEVICE_MASK : Address of device serving as data source/sink
 */
#define	EHCI_SITD_CTRL_DIR		0x80000000
#define	EHCI_SITD_CTRL_DIR_IN		0x80000000
#define	EHCI_SITD_CTRL_DIR_OUT		0x00000000
#define	EHCI_SITD_CTRL_PORT_MASK	0x7F000000
#define	EHCI_SITD_CTRL_PORT_SHIFT	24
#define	EHCI_SITD_CTRL_HUB_MASK		0x007F0000
#define	EHCI_SITD_CTRL_HUB_SHIFT	16
#define	EHCI_SITD_CTRL_END_PT_MASK	0x00000F00
#define	EHCI_SITD_CTRL_END_PT_SHIFT	8
#define	EHCI_SITD_CTRL_DEVICE_MASK	0x0000007F
#define	EHCI_SITD_CTRL_DEVICE_SHIFT	0

/*
 * sitd_uframe_sched bits
 * EHCI_SITD_UFRAME_CMASK_MASK : Determines which uFrame the HC executes CSplit
 * EHCI_SITD_UFRAME_SMASK_MASK : Determines which uFrame the HC executes SSplit
 */
#define	EHCI_SITD_UFRAME_CMASK_MASK	0x0000FF00
#define	EHCI_SITD_UFRAME_CMASK_SHIFT	8
#define	EHCI_SITD_UFRAME_SMASK_MASK	0x000000FF
#define	EHCI_SITD_UFRAME_SMASK_SHIFT	0

/*
 * sitd_xfer_state bits
 * EHCI_SITD_XFER_IOC_MASK : Interrupt when transaction is complete.
 * EHCI_SITD_XFER_PAGE_MASK : Which data page pointer should be concatenated
 *				with the CurrentOffset to construct a data
 *				buffer pointer
 * EHCI_SITD_XFER_TOTAL_MASK : Total number of bytes expected in xfer(1023 Max).
 * EHCI_SITD_XFER_CPROG_MASK : HC tracks which CSplit has been executed.
 * EHCI_SITD_XFER_STATUS_MASK : Status of xfer
 */
#define	EHCI_SITD_XFER_IOC_MASK		0x80000000
#define	EHCI_SITD_XFER_IOC_ON		0x80000000
#define	EHCI_SITD_XFER_IOC_OFF		0x00000000
#define	EHCI_SITD_XFER_PAGE_MASK	0x40000000
#define	EHCI_SITD_XFER_PAGE_0		0x00000000
#define	EHCI_SITD_XFER_PAGE_1		0x40000000
#define	EHCI_SITD_XFER_TOTAL_MASK	0x03FF0000
#define	EHCI_SITD_XFER_TOTAL_SHIFT	16
#define	EHCI_SITD_XFER_CPROG_MASK	0x0000FF00
#define	EHCI_SITD_XFER_CPROG_SHIFT	8
#define	EHCI_SITD_XFER_STATUS_MASK	0x000000FF
#define	EHCI_SITD_XFER_STATUS_SHIFT	0
#define	EHCI_SITD_XFER_ACTIVE		0x80
#define	EHCI_SITD_XFER_ERROR		0x40
#define	EHCI_SITD_XFER_DATA_BUFFER_ERR	0x20
#define	EHCI_SITD_XFER_BABBLE		0x10
#define	EHCI_SITD_XFER_XACT_ERROR	0x08
#define	EHCI_SITD_XFER_MISSED_UFRAME	0x04
#define	EHCI_SITD_XFER_SPLIT_XACT_STATE	0x02
#define	EHCI_SITD_XFER_SSPLIT_STATE	0x00
#define	EHCI_SITD_XFER_CSPLIT_STATE	0x02

/*
 * sitd_xfer_buffer0/1
 * EHCI_SITD_XFER_BUFFER_MASK : Buffer Pointer List
 * EHCI_SITD_XFER_OFFSET_MASK : Current byte offset
 * EHCI_SITD_XFER_TP_MASK : Transaction position
 * EHCI_SITD_XFER_TCOUNT_MASK : Transaction count
 */
#define	EHCI_SITD_XFER_BUFFER_MASK	0xFFFFF000
#define	EHCI_SITD_XFER_BUFFER_SHIFT	12
#define	EHCI_SITD_XFER_OFFSET_MASK	0x00000FFF
#define	EHCI_SITD_XFER_OFFSET_SHIFT	0
#define	EHCI_SITD_XFER_TP_MASK		0x00000018
#define	EHCI_SITD_XFER_TP_ALL		0x0
#define	EHCI_SITD_XFER_TP_BEGIN		0x1
#define	EHCI_SITD_XFER_TP_MID		0x2
#define	EHCI_SITD_XFER_TP_END		0x3
#define	EHCI_SITD_XFER_TCOUNT_MASK	0x00000007
#define	EHCI_SITD_XFER_TCOUNT_SHIFT	0

/*
 * qtd_state
 *
 * ITD States
 */
#define	EHCI_ITD_FREE			1		/* Free ITD */
#define	EHCI_ITD_DUMMY			2		/* Dummy ITD */
#define	EHCI_ITD_ACTIVE			3		/* Active ITD */
#define	EHCI_ITD_RECLAIM		4		/* Reclaim ITD */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USB_EHCI_H */
