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

#ifndef _SYS_USB_UHCI_H
#define	_SYS_USB_UHCI_H


#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Universal Host Controller Driver (UHCI)
 *
 * The UHCI driver is a driver which interfaces to the Universal
 * Serial Bus Driver (USBA) and the Host Controller (HC). The interface to
 * the Host Controller is defined by the Universal Host Controller
 * Interface spec.
 */


#define	LEGACYMODE_REG_OFFSET		0xc0
#define	LEGACYMODE_REG_INIT_VALUE	0xaf00

/*
 *   The register set of the UCHI controller
 *   This structure is laid out for proper alignment so no need to pack(1).
 */
typedef volatile struct hcr_regs {
	uint16_t	USBCMD;
	uint16_t	USBSTS;
	uint16_t	USBINTR;
	uint16_t	FRNUM;
	uint32_t	FRBASEADD;
	uchar_t		SOFMOD;
	uchar_t		rsvd[3];
	uint16_t	PORTSC[2];
} hc_regs_t;

/*
 * #defines for the USB Command Register
 */
#define	USBCMD_REG_MAXPKT_64		0x0080
#define	USBCMD_REG_CONFIG_FLAG		0x0040
#define	USBCMD_REG_SW_DEBUG		0x0020
#define	USBCMD_REG_FGBL_RESUME		0x0010
#define	USBCMD_REG_ENTER_GBL_SUSPEND	0x0008
#define	USBCMD_REG_GBL_RESET		0x0004
#define	USBCMD_REG_HC_RESET		0x0002
#define	USBCMD_REG_HC_RUN		0x0001


/*
 * #defines for the USB Status Register
 */
#define	USBSTS_REG_HC_HALTED		0x0020
#define	USBSTS_REG_HC_PROCESS_ERR	0x0010
#define	USBSTS_REG_HOST_SYS_ERR 	0x0008
#define	USBSTS_REG_RESUME_DETECT	0x0004
#define	USBSTS_REG_USB_ERR_INTR		0x0002
#define	USBSTS_REG_USB_INTR		0x0001

/*
 * #defines for the USB Root Hub Port Register
 */
#define	HCR_PORT_CCS			0x1
#define	HCR_PORT_CSC			0x2
#define	HCR_PORT_ENABLE			0x4
#define	HCR_PORT_ENDIS_CHG		0x8
#define	HCR_PORT_LINE_STATSU		0x30
#define	HCR_PORT_RESUME_DETECT		0x40
#define	HCR_PORT_LSDA			0x100
#define	HCR_PORT_RESET			0x200
#define	HCR_PORT_SUSPEND		0x1000

/*
 * #defines for USB Interrupt Enable Register
 */
#define	USBINTR_REG_SPINT_EN		0x0008
#define	USBINTR_REG_IOC_EN		0x0004
#define	USBINTR_REG_RESUME_INT_EN	0x0002
#define	USBINTR_REG_TOCRC_INT_EN	0x0001

#define	ENABLE_ALL_INTRS		0x000F
#define	DISABLE_ALL_INTRS		0x0000
#define	UHCI_INTR_MASK			0x1f


#define	SetReg32(hndl, addr, val)	ddi_put32((hndl), \
						&(addr), (val))
#define	GetReg32(hndl, addr)		ddi_get32((hndl), &(addr))

#define	SetQH32(ucp, addr, val)		\
		SetReg32((ucp)->uhci_qh_pool_mem_handle, (addr), (val))
#define	GetQH32(ucp, addr)		\
		GetReg32((ucp)->uhci_qh_pool_mem_handle, (addr))

#define	SetTD32(ucp, addr, val)		\
		SetReg32((ucp)->uhci_td_pool_mem_handle, (addr), (val))
#define	GetTD32(ucp, addr)		\
		GetReg32((ucp)->uhci_td_pool_mem_handle, (addr))

#define	SetFL32(ucp, addr, val)		\
		SetReg32((ucp)->uhci_flt_mem_handle, (addr), (val))
#define	GetFL32(ucp, addr)		\
		GetReg32((ucp)->uhci_flt_mem_handle, (addr))


/*
 * UHCI Queue Head structure, aligned on 16 byte boundary
 */
typedef struct uhci_qh {
	/* Hardware controlled bits */
	uint32_t		link_ptr;	/* Next Queue Head / TD */
	uint32_t		element_ptr;	/* Next queue head / TD	*/

	/* Software controlled bits */
	uint16_t	node;		/* Node	that its attached */
	uint16_t	qh_flag;	/* See	below */

	struct	uhci_qh	*prev_qh;	/* Pointer to Prev queue head */
	struct	uhci_td	*td_tailp;	/* Pointer to the last TD of QH	*/
	struct	uhci_bulk_isoc_xfer_info *bulk_xfer_info;
	uint64_t	__pad1;		/* align to 16 bytes */
} queue_head_t;

#define	NUM_STATIC_NODES		63
#define	NUM_INTR_QH_LISTS		64
#define	NUM_FRAME_LST_ENTRIES		1024
#define	TREE_HEIGHT			5
#define	VIRTUAL_TREE_HEIGHT		5
#define	SIZE_OF_FRAME_LST_TABLE		1024 * 4

#define	HC_TD_HEAD			0x0
#define	HC_QUEUE_HEAD			0x2
#define	HC_DEPTH_FIRST			0x4
#define	HC_END_OF_LIST			0x1

#define	QUEUE_HEAD_FLAG_STATIC		0x1
#define	QUEUE_HEAD_FLAG_FREE		0x2
#define	QUEUE_HEAD_FLAG_BUSY		0x3

#define	QH_LINK_PTR_MASK		0xFFFFFFF0
#define	QH_ELEMENT_PTR_MASK		0xFFFFFFF0
#define	FRAME_LST_PTR_MASK		0xFFFFFFF0


#define	GetField(u, td, f, o, l) \
	((GetTD32(u, (td)->f) >> (o)) & ((1U<<l)-1))

#define	SetField(u, td, f, o, l, v) \
	SetTD32(u, (td)->f, \
	(GetTD32(u, (td)->f) & ~(((1U<<l)-1) << o)) | \
	(((v) & ((1U<<l)-1)) << o))

#define	GetTD_alen(u, td)	GetField((u), (td), dw2, 0, 11)
#define	GetTD_status(u, td)	GetField((u), (td), dw2, 16, 8)
#define	GetTD_ioc(u, td)	GetField((u), (td), dw2, 24, 1)
#define	GetTD_iso(u, td)	GetField((u), (td), dw2, 25, 1)
#define	GetTD_ls(u, td)		GetField((u), (td), dw2, 26, 1)
#define	GetTD_c_err(u, td)	GetField((u), (td), dw2, 27, 2)
#define	GetTD_spd(u, td)	GetField((u), (td), dw2, 29, 1)
#define	GetTD_PID(u, td)	GetField((u), (td), dw3, 0, 8)
#define	GetTD_devaddr(u, td)	GetField((u), (td), dw3, 8, 7)
#define	GetTD_endpt(u, td)	GetField((u), (td), dw3, 15, 4)
#define	GetTD_dtogg(u, td)	GetField((u), (td), dw3, 19, 1)
#define	GetTD_mlen(u, td)	GetField((u), (td), dw3, 21, 11)

#define	SetTD_alen(u, td, v)	SetField((u), (td), dw2, 0, 11, (v))
#define	SetTD_status(u, td, v)	SetField((u), (td), dw2, 16, 8, (v))
#define	SetTD_ioc(u, td, v)	SetField((u), (td), dw2, 24, 1, (v))
#define	SetTD_iso(u, td, v)	SetField((u), (td), dw2, 25, 1, (v))
#define	SetTD_ls(u, td, v)	SetField((u), (td), dw2, 26, 1, (v))
#define	SetTD_c_err(u, td, v)	SetField((u), (td), dw2, 27, 2, (v))
#define	SetTD_spd(u, td, v)	SetField((u), (td), dw2, 29, 1, (v))
#define	SetTD_PID(u, td, v)	SetField((u), (td), dw3, 0, 8, (v))
#define	SetTD_devaddr(u, td, v)	SetField((u), (td), dw3, 8, 7, (v))
#define	SetTD_endpt(u, td, v)	SetField((u), (td), dw3, 15, 4, (v))
#define	SetTD_dtogg(u, td, v)	SetField((u), (td), dw3, 19, 1, (v))
#define	SetTD_mlen(u, td, v)	SetField((u), (td), dw3, 21, 11, (v))

/*
 * UHCI Transfer Descriptor structure, aligned on 16 byte boundary
 */
typedef struct uhci_td {

	/* Information required by HC for executing the request */
					/* Pointer to the next TD/QH */
	uint32_t			link_ptr;
	uint32_t			dw2;
	uint32_t			dw3;
					/* Data buffer address */
	uint32_t			buffer_address;

	/* Information required by HCD for managing the request */
	struct	uhci_td			*qh_td_prev;
	struct	uhci_td			*tw_td_next;
	struct	uhci_td			*outst_td_next;
	struct	uhci_td			*outst_td_prev;
	struct	uhci_trans_wrapper	*tw;
	struct	uhci_td			*isoc_next;
	struct	uhci_td			*isoc_prev;
	ushort_t			isoc_pkt_index;
	ushort_t			flag;
	uint_t				starting_frame;
	uint_t				_pad[3];	/* 16 byte alignment */
} uhci_td_t;

#define	TD_FLAG_FREE			0x1
#define	TD_FLAG_BUSY			0x2
#define	TD_FLAG_DUMMY			0x3

#define	INTERRUPT_ON_COMPLETION		0x1
#define	END_POINT_ADDRESS_MASK		0xF
#define	UHCI_MAX_ERR_COUNT		3
#define	MAX_NUM_BULK_TDS_PER_XFER	128

/* section 3.2.2 of UHCI1.1 spec, bits 23:16 of status field */
#define	UHCI_TD_ACTIVE			0x80
#define	UHCI_TD_STALLED			0x40
#define	UHCI_TD_DATA_BUFFER_ERR		0x20
#define	UHCI_TD_BABBLE_ERR		0x10
#define	UHCI_TD_NAK_RECEIVED		0x08
#define	UHCI_TD_CRC_TIMEOUT		0x04
#define	UHCI_TD_BITSTUFF_ERR		0x02

#define	TD_INACTIVE			0x7F
#define	TD_STATUS_MASK			0x76
#define	ZERO_LENGTH			0x7FF

#define	PID_SETUP			0x2D
#define	PID_IN				0x69
#define	PID_OUT				0xe1

#define	SETUP_SIZE			8

#define	SETUP				0x11
#define	DATA				0x12
#define	STATUS				0x13

#define	UHCI_INVALID_PTR		NULL
#define	LOW_SPEED_DEVICE		1

/*
 * These provide synchronization between TD deletions.
 */
#define	UHCI_NOT_CLAIMED		0x0
#define	UHCI_INTR_HDLR_CLAIMED		0x1
#define	UHCI_MODIFY_TD_BITS_CLAIMED	0x2
#define	UHCI_TIMEOUT_HDLR_CLAIMED	0x3


/*
 * Structure for Bulk and Isoc TD pools
 */
typedef struct uhci_bulk_isoc_td_pool {
	caddr_t				pool_addr;
	ddi_dma_cookie_t		cookie;	    /* DMA cookie */
	ddi_dma_handle_t		dma_handle; /* DMA handle */
	ddi_acc_handle_t		mem_handle; /* Memory handle */
	ushort_t			num_tds;
} uhci_bulk_isoc_td_pool_t;

/*
 *  Structure for Bulk and Isoc transfers
 */
typedef struct uhci_bulk_isoc_xfer_info {
	uhci_bulk_isoc_td_pool_t	*td_pools;
	ushort_t			num_pools;
	ushort_t			num_tds;
} uhci_bulk_isoc_xfer_t;

/*
 * Structure for Isoc DMA buffer
 *	One Isoc transfer includes multiple Isoc packets.
 *	One DMA buffer is allocated for one packet each.
 */
typedef struct uhci_isoc_buf {
	caddr_t			buf_addr;	/* Starting buffer address */
	ddi_dma_cookie_t	cookie;		/* DMA cookie */
	ddi_dma_handle_t	dma_handle;	/* DMA handle */
	ddi_acc_handle_t	mem_handle;	/* Memory handle */
	size_t			length;		/* Buffer length */
	ushort_t		index;
} uhci_isoc_buf_t;

/*
 * Macros related to ISOC transfers
 */
#define	UHCI_SIZE_OF_HW_FRNUM		11
#define	UHCI_BIT_10_MASK		0x400
#define	UHCI_MAX_ISOC_FRAMES		1024
#define	UHCI_MAX_ISOC_PKTS		256
#define	UHCI_DEFAULT_ISOC_RCV_PKTS	1	/* isoc pkts per req */

#define	FRNUM_MASK			0x3FF
#define	SW_FRNUM_MASK			0xFFFFFFFFFFFFF800
#define	INVALID_FRNUM			0
#define	FRNUM_OFFSET			5
#define	MAX_FRAME_NUM			1023

typedef	uint32_t frame_lst_table_t;

/*
 * Bandwidth allocation
 *	The following definitions are  used during  bandwidth
 *	calculations for a given endpoint maximum packet size.
 */
#define	MAX_BUS_BANDWIDTH	1500	/* Up to 1500 bytes per frame */
#define	MAX_POLL_INTERVAL	255	/* Maximum polling interval */
#define	MIN_POLL_INTERVAL	1	/* Minimum polling interval */
#define	SOF			6	/* Length in bytes of SOF */
#define	EOF			2	/* Length in bytes of EOF */

/*
 * Minimum polling interval for low speed endpoint
 *
 * According USB Specifications, a full-speed endpoint can specify
 * a desired polling interval 1ms to 255ms and a low speed endpoints
 * are limited to specifying only 10ms to 255ms. But some old keyboards
 * and mice uses polling interval of 8ms. For compatibility purpose,
 * we are using polling interval between 8ms and 255ms for low speed
 * endpoints.
 */
#define	MIN_LOW_SPEED_POLL_INTERVAL	8

/*
 * For non-periodic transfers, reserve at least for one low-speed device
 * transaction and according to USB Bandwidth Analysis white paper,  it
 * comes around 12% of USB frame time. Then periodic transfers will get
 * 88% of USB frame time.
 */
#define	MAX_PERIODIC_BANDWIDTH	(((MAX_BUS_BANDWIDTH - SOF - EOF)*88)/100)

/*
 * The following are the protocol overheads in terms of Bytes for the
 * different transfer types.  All these protocol overhead  values are
 * derived from the 5.9.3 section of USB Specification	and  with the
 * help of Bandwidth Analysis white paper which is posted on the  USB
 * developer forum.
 */
#define	FS_NON_ISOC_PROTO_OVERHEAD	14
#define	FS_ISOC_INPUT_PROTO_OVERHEAD	11
#define	FS_ISOC_OUTPUT_PROTO_OVERHEAD	10
#define	LOW_SPEED_PROTO_OVERHEAD	97
#define	HUB_LOW_SPEED_PROTO_OVERHEAD	01

/*
 * The Host Controller (HC) delays are the USB host controller specific
 * delays. The value shown below is the host  controller delay for  the
 * Sand core USB host controller.
 */
#define	HOST_CONTROLLER_DELAY		18

/*
 * The low speed clock below represents that to transmit one low-speed
 * bit takes eight times more than one full speed bit time.
 */
#define	LOW_SPEED_CLOCK			8

/* the 16 byte alignment is required for every TD and QH start addr */
#define	UHCI_QH_ALIGN_SZ		16
#define	UHCI_TD_ALIGN_SZ		16

#ifdef __cplusplus
}
#endif

#endif /* _SYS_USB_UHCI_H */
