/*
 * Copyright (c) 2014 Martin Pieuchot. All rights reserved.
 * Copyright (c) 2010 Hans Petter Selasky. All rights reserved.
 * Copyright 2016 Joyent, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _SYS_USB_HCD_XHCI_XHCIREG_H
#define	_SYS_USB_HCD_XHCI_XHCIREG_H

/*
 * xHCI Register and Field Definitions
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * xHCI PCI config registers
 */
#define	PCI_XHCI_CBMEM		0x10	/* configuration base MEM */
#define	PCI_XHCI_USBREV		0x60	/* RO USB protocol revision */
#define	PCI_USB_REV_3_0		0x30	/* USB 3.0 */
#define	PCI_XHCI_FLADJ		0x61	/* RW frame length adjust */

#define	PCI_XHCI_INTEL_XUSB2PR	0xD0	/* Intel USB2 Port Routing */
#define	PCI_XHCI_INTEL_USB2PRM	0xD4	/* Intel USB2 Port Routing Mask */
#define	PCI_XHCI_INTEL_USB3_PSSEN 0xD8	/* Intel USB3 Port SuperSpeed Enable */
#define	PCI_XHCI_INTEL_USB3PRM	0xDC	/* Intel USB3 Port Routing Mask */

/*
 * xHCI capability registers
 */
#define	XHCI_CAPLENGTH		0x00	/* RO capability */
#define	XHCI_RESERVED		0x01	/* Reserved */
#define	XHCI_HCIVERSION		0x02	/* RO Interface version number */
#define	XHCI_HCIVERSION_0_9	0x0090	/* xHCI version 0.9 */
#define	XHCI_HCIVERSION_1_0	0x0100	/* xHCI version 1.0 */

/*
 * Structural Parameters 1 - xHCI 1.1 / 5.3.3
 */
#define	XHCI_HCSPARAMS1		0x04
#define	XHCI_HCS1_DEVSLOT_MAX(x)	((x) & 0xFF)
#define	XHCI_HCS1_IRQ_MAX(x)	(((x) >> 8) & 0x3FF)
#define	XHCI_HCS1_N_PORTS(x)	(((x) >> 24) & 0xFF)

/*
 * Structural Parameters 2 - xHCI 1.1 / 5.3.4
 */
#define	XHCI_HCSPARAMS2		0x08
#define	XHCI_HCS2_IST(x)	((x) & 0x7)
#define	XHCI_HCS2_IST_MICRO(x)	(!((x) & 0x8))
#define	XHCI_HCS2_ERST_MAX(x)	(((x) >> 4) & 0xF)
#define	XHCI_HCS2_SPR(x)	(((x) >> 24) & 0x1)
#define	XHCI_HCS2_SPB_MAX(x)	((((x) >> 16) & 0x3e0) | (((x) >> 27) & 0x1f))

/*
 * Structural Parameters 3 - xHCI 1.1 / 5.3.5
 */
#define	XHCI_HCSPARAMS3		0x0C
#define	XHCI_HCS3_U1_DEL(x)	((x) & 0xFF)
#define	XHCI_HCS3_U2_DEL(x)	(((x) >> 16) & 0xFFFF)

/*
 * Capability Parameters 1 - xHCI 1.1 / 5.3.6
 */
#define	XHCI_HCCPARAMS1		0x10
#define	XHCI_HCC1_FLAGS_MASK(x)	((x) & 0x7FF)
#define	XHCI_HCC1_PSA_SZ_MAX(x)	(((x) >> 12) & 0xF)
#define	XHCI_HCC1_XECP(x)	(((x) >> 16) & 0xFFFF)

/*
 * Capability Parameters 1 - xHCI 1.1 / 5.3.9
 */
#define	XHCI_HCCPARAMS2		0x1C
#define	XHCI_HCC2_FLAGS_MASK(x)	((x) & 0x3F)

#define	XHCI_DBOFF		0x14	/* RO doorbell offset */
#define	XHCI_RTSOFF		0x18	/* RO runtime register space offset */

/*
 * xHCI operational registers.
 * Offset given by XHCI_CAPLENGTH register
 */
#define	XHCI_USBCMD		0x00		/* XHCI command */
#define	XHCI_CMD_RS		0x00000001	/* RW Run/Stop */
#define	XHCI_CMD_HCRST		0x00000002	/* RW HC Reset */
#define	XHCI_CMD_INTE		0x00000004	/* RW Interrupter Enable */
#define	XHCI_CMD_HSEE		0x00000008	/* RW System Error Enable */
#define	XHCI_CMD_LHCRST		0x00000080	/* RW Light HC Reset */
#define	XHCI_CMD_CSS		0x00000100	/* RW Controller Save */
#define	XHCI_CMD_CRS		0x00000200	/* RW Controller Restore */
#define	XHCI_CMD_EWE		0x00000400	/* RW Enable Wrap Event */
#define	XHCI_CMD_EU3S		0x00000800	/* RW Enable U3 MFINDEX Stop */


#define	XHCI_USBSTS		0x04		/* XHCI status */
#define	XHCI_STS_HCH		0x00000001	/* RO - HC Halted */
#define	XHCI_STS_HSE		0x00000004	/* RW - Host System Error */
#define	XHCI_STS_EINT		0x00000008	/* RW - Event Interrupt */
#define	XHCI_STS_PCD		0x00000010	/* RW - Port Change Detect */
#define	XHCI_STS_SSS		0x00000100	/* RO - Save State Status */
#define	XHCI_STS_RSS		0x00000200	/* RO - Restore State Status */
#define	XHCI_STS_SRE		0x00000400	/* RW - Save/Restore Error */
#define	XHCI_STS_CNR		0x00000800	/* RO - Controller Not Ready */
#define	XHCI_STS_HCE		0x00001000	/* RO - HC Error */

#define	XHCI_PAGESIZE		0x08		/* XHCI page size mask */
#define	XHCI_PAGESIZE_4K	0x00000001	/* 4K Page Size */
#define	XHCI_PAGESIZE_8K	0x00000002	/* 8K Page Size */
#define	XHCI_PAGESIZE_16K	0x00000004	/* 16K Page Size */
#define	XHCI_PAGESIZE_32K	0x00000008	/* 32K Page Size */
#define	XHCI_PAGESIZE_64K	0x00000010	/* 64K Page Size */

#define	XHCI_DNCTRL		0x14	/* XHCI device notification control */
#define	XHCI_DNCTRL_MASK(n)	(1U << (n))

#define	XHCI_CRCR		0x18		/* XHCI command ring control */
#define	XHCI_CRCR_RCS		0x00000001	/* RW - consumer cycle state */
#define	XHCI_CRCR_CS		0x00000002	/* RW - command stop */
#define	XHCI_CRCR_CA		0x00000004	/* RW - command abort */
#define	XHCI_CRCR_CRR		0x00000008	/* RW - command ring running */
#define	XHCI_CRCR_MASK		0x0000000F

/*
 * Device context base address pointer register.
 */
#define	XHCI_DCBAAP		0x30

#define	XHCI_CONFIG		0x38
#define	XHCI_CONFIG_SLOTS_MASK	0x000000FF

/*
 * xHCI Port Status Registers and bits. See xHCI 1.1 / 5.4.8.
 */
#define	XHCI_PORTSC(n)		(0x3F0 + (0x10 * (n)))	/* XHCI port status */
#define	XHCI_PS_CCS	0x00000001	/* RO - current connect status */
#define	XHCI_PS_PED	0x00000002	/* RW - port enabled / disabled */
#define	XHCI_PS_OCA	0x00000008	/* RO - over current active */
#define	XHCI_PS_PR	0x00000010	/* RW - port reset */
#define	XHCI_PS_PLS_GET(x)	(((x) >> 5) & 0xF) /* RW - port link state */
#define	XHCI_PS_PLS_SET(x)	(((x) & 0xF) << 5) /* RW - port link state */
#define	XHCI_PS_PP	0x00000200	/* RW - port power */
#define	XHCI_PS_SPEED_GET(x)	(((x) >> 10) & 0xF) /* RO - port speed */
#define	XHCI_PS_PIC_GET(x)	(((x) >> 14) & 0x3) /* RW - port indicator */
#define	XHCI_PS_PIC_SET(x)	(((x) & 0x3) << 14) /* RW - port indicator */
#define	XHCI_PS_LWS	0x00010000	/* RW - port link state write strobe */
#define	XHCI_PS_CSC	0x00020000	/* RW - connect status change */
#define	XHCI_PS_PEC	0x00040000	/* RW - port enable/disable change */
#define	XHCI_PS_WRC	0x00080000	/* RW - warm port reset change */
#define	XHCI_PS_OCC	0x00100000	/* RW - over-current change */
#define	XHCI_PS_PRC	0x00200000	/* RW - port reset change */
#define	XHCI_PS_PLC	0x00400000	/* RW - port link state change */
#define	XHCI_PS_CEC	0x00800000	/* RW - config error change */
#define	XHCI_PS_CAS	0x01000000	/* RO - cold attach status */
#define	XHCI_PS_WCE	0x02000000	/* RW - wake on connect enable */
#define	XHCI_PS_WDE	0x04000000	/* RW - wake on disconnect enable */
#define	XHCI_PS_WOE	0x08000000	/* RW - wake on over-current enable */
#define	XHCI_PS_DR	0x40000000	/* RO - device removable */
#define	XHCI_PS_WPR	0x80000000U	/* RW - warm port reset */
#define	XHCI_PS_CLEAR	0x80FF01FFU	/* command bits */
#define	XHCI_PS_INDPORT(x)	((x) & 0xFF)
#define	XHCI_PS_INDVAL(x)	(((x) & 0xFF00) >> 8)

/*
 * xHCI Port Power Management and Control Register. See xHCI 1.1 / 5.4.9.
 */
#define	XHCI_PORTPMSC(n)	(0x3F4 + (0x10 * (n)))
#define	XHCI_PM3_U1TO_GET(x)	(((x) >> 0) & 0xFF)	/* RW - U1 timeout */
#define	XHCI_PM3_U1TO_SET(x)	(((x) & 0xFF) << 0)	/* RW - U1 timeout */
#define	XHCI_PM3_U2TO_GET(x)	(((x) >> 8) & 0xFF)	/* RW - U2 timeout */
#define	XHCI_PM3_U2TO_SET(x)	(((x) & 0xFF) << 8)	/* RW - U2 timeout */
#define	XHCI_PM3_FLA		0x00010000	/* RW - Force Link PM Accept */
#define	XHCI_PM2_L1S_GET(x)	(((x) >> 0) & 0x7)	/* RO - L1 status */
#define	XHCI_PM2_RWE		0x00000008	/* RW - remote wakup enable */
/* RW - host initiated resume durations */
#define	XHCI_PM2_HIRD_GET(x)	(((x) >> 4) & 0xF)
#define	XHCI_PM2_HIRD_SET(x)	(((x) & 0xF) << 4)
#define	XHCI_PM2_L1SLOT_GET(x)	(((x) >> 8) & 0xFF) /* RW - L1 device slot */
#define	XHCI_PM2_L1SLOT_SET(x)	(((x) & 0xFF) << 8) /* RW - L1 device slot */
#define	XHCI_PM2_HLE		0x00010000	/* RW - hardware LPM enable */
#define	XHCI_PORTLI(n)		(0x3F8 + (0x10 * (n))) /* RO - port link info */
#define	XHCI_PLI3_ERR_GET(x)	(((x) >> 0) & 0xFFFF) /* RO - port link errs */
#define	XHCI_PORTRSV(n)		(0x3FC + (0x10 * (n)))	/* XHCI port reserved */

/*
 * xHCI runtime registers - xHCI 1.1 / 5.5.
 * Offset given by XHCI_CAPLENGTH + XHCI_RTSOFF registers.
 */
#define	XHCI_MFINDEX		0x0000		/* RO - microframe index */
#define	XHCI_MFINDEX_GET(x)	((x) & 0x3FFF)
#define	XHCI_IMAN(n)		(0x0020 + (0x20 * (n)))	/* XHCI interrupt */
							/* management */
#define	XHCI_IMAN_INTR_PEND	0x00000001	/* RW - interrupt pending */
#define	XHCI_IMAN_INTR_ENA	0x00000002	/* RW - interrupt enable */

/*
 * XHCI Interrupt moderation
 */
#define	XHCI_IMOD(n)		(0x0024 + (0x20 * (n)))

/*
 * XHCI event ring segment table size
 */
#define	XHCI_ERSTSZ(n)		(0x0028 + (0x20 * (n)))
#define	XHCI_ERSTS_MASK		0xffff
#define	XHCI_ERSTS_SET(x)	((x) & XHCI_ERSTS_MASK)

/*
 * XHCI event ring segment table BA
 */
#define	XHCI_ERSTBA(n)		(0x0030 + (0x20 * (n)))

/*
 * XHCI event ring dequeue pointer
 */
#define	XHCI_ERDP(n)		(0x0038 + (0x20 * (n)))
#define	XHCI_ERDP_SINDEX(x)	((x) & 0x7)	/* RO - dequeue segment index */
#define	XHCI_ERDP_BUSY		0x00000008	/* RW - event handler busy */

/*
 * XHCI doorbell registers - xHCI 1.1 / 5.6.
 * Offset given by XHCI_CAPLENGTH + XHCI_DBOFF registers
 */
#define	XHCI_DOORBELL(n)	(0x0000 + (4 * (n)))
#define	XHCI_DB_TARGET_GET(x)	((x) & 0xFF)
#define	XHCI_DB_TARGET_SET(x)	((x) & 0xFF)
#define	XHCI_DB_SID_GET(x)	(((x) >> 16) & 0xFFFF)
#define	XHCI_DB_SID_SET(x)	(((x) & 0xFFFF) << 16)

/*
 * XHCI capability IDs - xHCI 1.1 / 7 - Table 146
 */
#define	XHCI_ID_XECP_DONE	0x0000
#define	XHCI_ID_USB_LEGACY	0x0001
#define	XHCI_ID_PROTOCOLS	0x0002
#define	XHCI_ID_POWER_MGMT	0x0003
#define	XHCI_ID_VIRTUALIZATION	0x0004
#define	XHCI_ID_MSG_IRQ		0x0005
#define	XHCI_ID_USB_LOCAL_MEM	0x0006
#define	XHCI_ID_DEBUG		0x000A
#define	XHCI_ID_EXT_MSG_IRQ	0x0011

#define	XHCI_XECP_ID(x)		((x) & 0xFF)
#define	XHCI_XECP_NEXT(x)	(((x) >> 8) & 0xFF)

/*
 * xHCI USB Legacy Support Capability - xHCI 1.1 / 7.1.
 */
#define	XHCI_BIOS_OWNED		(1 << 16)
#define	XHCI_OS_OWNED		(1 << 24)

/*
 * These definitions manipulate the generation of SMIs. Note that the contents
 * of reserved registers are required to be preserved. In addition, Several of
 * the bits require you to write one to clear.
 */
#define	XHCI_XECP_LEGCTLSTS	0x04
#define	XHCI_XECP_SMI_MASK	(0x7 << 1) + (0xff << 5) + (0x7UL << 17)
#define	XHCI_XECP_CLEAR_SMI	(0x7UL << 29)

/*
 * xHCI Supported Protocol Capability. See xHCI 1.1 / 7.2.
 */
#define	XHCI_XECP_PROT_MAJOR(x)		((x >> 24) & 0xff)
#define	XHCI_XECP_PROT_MINOR(x)		((x >> 16) & 0xff)
#define	XHCI_XECP_PROT_PCOUNT(x)	((x >> 8) & 0xff)

/*
 * xHCI Slot Context definitions - xHCI 1.1 / 6.2.2.
 */
#define	XHCI_SCTX_GET_ROUTE(x)		((x) & 0xfffff)
#define	XHCI_SCTX_SET_ROUTE(x)		((x) & 0xfffff)
#define	XHCI_SCTX_GET_SPEED(x)		(((x) >> 20) & 0xf)
#define	XHCI_SCTX_SET_SPEED(x)		(((x) & 0xf) << 20)
#define	XHCI_SCTX_GET_MTT(x)		(((x) >> 25) & 0x1)
#define	XHCI_SCTX_SET_MTT(x)		(((x) & 0x1) << 25)
#define	XHCI_SCTX_GET_HUB(x)		(((x) >> 26) & 0x1)
#define	XHCI_SCTX_SET_HUB(x)		(((x) & 0x1) << 26)
#define	XHCI_SCTX_GET_DCI(x)		(((x) >> 27) & 0x1f)
#define	XHCI_SCTX_SET_DCI(x)		(((x) & 0x1f) << 27)
#define	XHCI_SCTX_DCI_MASK		(0x1fUL << 27)

#define	XHCI_SCTX_GET_MAX_EL(x)		((x) & 0xffff)
#define	XHCI_SCTX_SET_MAX_EL(x)		((x) & 0xffff)
#define	XHCI_SCTX_GET_RHPORT(x)		(((x) >> 16) & 0xff)
#define	XHCI_SCTX_SET_RHPORT(x)		(((x) & 0xff) << 16)
#define	XHCI_SCTX_GET_NPORTS(x)		(((x) >> 24) & 0xff)
#define	XHCI_SCTX_SET_NPORTS(x)		(((x) & 0xff) << 24)

#define	XHCI_SCTX_GET_TT_HUB_SID(x)	((x) & 0xff)
#define	XHCI_SCTX_SET_TT_HUB_SID(x)	((x) & 0xff)
#define	XHCI_SCTX_GET_TT_PORT_NUM(x)	(((x) >> 8) & 0xff)
#define	XHCI_SCTX_SET_TT_PORT_NUM(x)	(((x) & 0xff) << 8)
#define	XHCI_SCTX_GET_TT_THINK_TIME(x)	(((x) >> 16) & 0x3)
#define	XHCI_SCTX_SET_TT_THINK_TIME(x)	(((x) & 0x3) << 16)
#define	XHCI_SCTX_SET_IRQ_TARGET(x)	(((x) & 0x3ff) << 22)
#define	XHCI_SCTX_GET_IRQ_TARGET(x)	(((x) >> 22) & 0x3ff)

#define	XHCI_SCTX_GET_DEV_ADDR(x)	((x) & 0xff)
#define	XHCI_SCTX_GET_SLOT_STATE(x)	(((x) >> 27) & 0x1f)

#define	XHCI_SLOT_DIS_ENAB	0
#define	XHCI_SLOT_DEFAULT	1
#define	XHCI_SLOT_ADDRESSED	2
#define	XHCI_SLOT_CONFIGURED	3

/*
 * xHCI Slot Context definitions - xHCI 1.1 / 6.2.3.
 */
#define	XHCI_EPCTX_STATE(x)		((x) & 0x7)
#define	XHCI_EP_DISABLED	0x0
#define	XHCI_EP_RUNNING		0x1
#define	XHCI_EP_HALTED		0x2
#define	XHCI_EP_STOPPED		0x3
#define	XHCI_EP_ERROR		0x4
#define	XHCI_EPCTX_SET_MULT(x)		(((x) & 0x3) << 8)
#define	XHCI_EPCTX_GET_MULT(x)		(((x) >> 8) & 0x3)
#define	XHCI_EPCTX_SET_MAXP_STREAMS(x)	(((x) & 0x1F) << 10)
#define	XHCI_EPCTX_GET_MAXP_STREAMS(x)	(((x) >> 10) & 0x1F)
#define	XHCI_EPCTX_SET_LSA(x)		(((x) & 0x1) << 15)
#define	XHCI_EPCTX_GET_LSA(x)		(((x) >> 15) & 0x1)
#define	XHCI_EPCTX_SET_IVAL(x)		(((x) & 0xff) << 16)
#define	XHCI_EPCTX_GET_IVAL(x)		(((x) >> 16) & 0xFF)
#define	XHCI_EPCTX_GET_MAX_ESIT_HI(x)	((((x) >> 24) & 0xFF) << 16)
#define	XHCI_EPCTX_SET_MAX_ESIT_HI(x)	((((x) >> 16) & 0xFF) << 24)

#define	XHCI_EPCTX_GET_CERR(x)		(((x) >> 1) & 0x3)
#define	XHCI_EPCTX_SET_CERR(x)		(((x) & 0x3) << 1)
#define	XHCI_EPCTX_SET_EPTYPE(x)	(((x) & 0x7) << 3)
#define	XHCI_EPCTX_GET_EPTYPE(x)	(((x) >> 3) & 0x7)
#define	XHCI_EPCTX_SET_HID(x)		(((x) & 0x1) << 7)
#define	XHCI_EPCTX_GET_HID(x)		(((x) >> 7) & 0x1)
#define	XHCI_EPCTX_SET_MAXB(x)		(((x) & 0xff) << 8)
#define	XHCI_EPCTX_GET_MAXB(x)		(((x) >> 8) & 0xff)
#define	XHCI_EPCTX_SET_MPS(x)		(((x) & 0xffff) << 16)
#define	XHCI_EPCTX_GET_MPS(x)		(((x) >> 16) & 0xffff)
#define	XHCI_SPEED_FULL		1
#define	XHCI_SPEED_LOW		2
#define	XHCI_SPEED_HIGH		3
#define	XHCI_SPEED_SUPER	4

#define	XHCI_EPCTX_TYPE_ISOCH_OUT	(1)
#define	XHCI_EPCTX_TYPE_BULK_OUT	(2)
#define	XHCI_EPCTX_TYPE_INTR_OUT	(3)
#define	XHCI_EPCTX_TYPE_CTRL		(4)
#define	XHCI_EPCTX_TYPE_ISOCH_IN	(5)
#define	XHCI_EPCTX_TYPE_BULK_IN		(6)
#define	XHCI_EPCTX_TYPE_INTR_IN		(7)

#define	XHCI_EPCTX_AVG_TRB_LEN(x)		((x) & 0xffff)
#define	XHCI_EPCTX_MAX_ESIT_PAYLOAD(x)		(((x) & 0xffff) << 16)
#define	XHCI_EPCTX_GET_MAX_ESIT_PAYLOAD(x)	(((x) >> 16) & 0xffff)

#define	XHCI_INCTX_MASK_DCI(n)	(0x1 << (n))

/*
 * Transfer Request Block definitions.
 */
#define	XHCI_TRB_TYPE_MASK	0xfc00
#define	XHCI_TRB_TYPE(x)	(((x) & XHCI_TRB_TYPE_MASK) >> 10)
#define	XHCI_TRB_PORTID(x)	(((x) & (0xffUL << 24)) >> 24)	/* Port ID */
#define	XHCI_TRB_MAXSIZE	(64 * 1024)

#define	XHCI_TRB_GET_CODE(x)	(((x) >> 24) & 0xff) /* Get TRB code */
#define	XHCI_TRB_TDREM(x)	(((x) & 0x1f) << 17) /* Set TD remaining len. */
#define	XHCI_TRB_GET_TDREM(x)	(((x) >> 17) & 0x1f) /* Get TD remaining len. */
#define	XHCI_TRB_REMAIN(x)	((x) & 0xffffff)	/* Remaining length */
#define	XHCI_TRB_LEN(x)		((x) & 0x1ffff)		/* Transfer length */
#define	XHCI_TRB_INTR(x)	(((x) & 0x3ff) << 22) /* Set MSI-X target */
#define	XHCI_TRB_GET_INTR(x)	(((x) >> 22) & 0x3ff) /* Get MSI-X target */

/*
 * TRB flags that are used between different different TRB types.
 */
#define	XHCI_TRB_CYCLE		(1 << 0) 	/* Enqueue point of xfer ring */
#define	XHCI_TRB_ENT		(1 << 1)	/* Evaluate next TRB */
#define	XHCI_TRB_LINKSEG	XHCI_TRB_ENT	/* Link to next segment */
#define	XHCI_TRB_ISP		(1 << 2)	/* Interrupt on short packet */
#define	XHCI_TRB_NOSNOOP	(1 << 3)	/* PCIe no snoop */
#define	XHCI_TRB_CHAIN		(1 << 4)	/* Chained with next TRB */
#define	XHCI_TRB_IOC		(1 << 5)	/* Interrupt On Completion */
#define	XHCI_TRB_IDT		(1 << 6)	/* Immediate Data */
#define	XHCI_TRB_GET_TBC(x)	(((x) >> 7) & 0x3)	/* Get/Set Transfer */
#define	XHCI_TRB_SET_TBC(x)	(((x) & 0x3) << 7)	/* Burst Count */
#define	XHCI_TRB_BSR		(1 << 9)	/* Block Set Address */
#define	XHCI_TRB_DCEP		(1 << 9)	/* Deconfigure endpoint */
#define	XHCI_TRB_TSP		(1 << 9)	/* Transfer State Preserve */
#define	XHCI_TRB_BEI		(1 << 9)	/* Block Event Interrupt */
#define	XHCI_TRB_DIR_IN		(1 << 16)
#define	XHCI_TRB_TRT_OUT	(2 << 16)
#define	XHCI_TRB_TRT_IN		(3 << 16)
#define	XHCI_TRB_GET_CYCLE(x)	((x) & 0x1)
#define	XHCI_TRB_GET_ED(x)	(((x) >> 2) & 0x1)
#define	XHCI_TRB_GET_FLAGS(x)	((x) & 0x1ff)
#define	XHCI_TRB_GET_TYPE(x)	(((x) >> 10) & 0x3f)
#define	XHCI_TRB_GET_EP(x)	(((x) >> 16) & 0x1f)
#define	XHCI_TRB_SET_EP(x)	(((x) & 0x1f) << 16)
#define	XHCI_TRB_GET_STYPE(x)	(((x) >> 16) & 0x1f)
#define	XHCI_TRB_SET_STYPE(x)	(((x) & 0x1f) << 16)
#define	XHCI_TRB_GET_SLOT(x)	(((x) >> 24) & 0xff)
#define	XHCI_TRB_SET_SLOT(x)	(((x) & 0xff) << 24)

/*
 * Isochronous specific fields. See xHCI 1.1 / 6.4.1.3.
 */
#define	XHCI_TRB_GET_TLBPC(x)	(((x) >> 16) & 0xf)
#define	XHCI_TRB_SET_TLBPC(x)	(((x) & 0xf) << 16)
#define	XHCI_TRB_GET_FRAME(x)	(((x) >> 20) & 0x7ff)
#define	XHCI_TRB_SET_FRAME(x)	(((x) & 0x7ff) << 20)
#define	XHCI_TRB_SIA		(1UL << 31)		/* Start Isoch ASAP */

/*
 * TRB Types. See xHCI 1.1 / 6.4.6.
 */

/* Transfer Ring Types */
#define	XHCI_TRB_TYPE_NORMAL	(1 << 10)
#define	XHCI_TRB_TYPE_SETUP	(2 << 10)
#define	XHCI_TRB_TYPE_DATA	(3 << 10)
#define	XHCI_TRB_TYPE_STATUS	(4 << 10)
#define	XHCI_TRB_TYPE_ISOCH	(5 << 10)
#define	XHCI_TRB_TYPE_LINK	(6 << 10)
#define	XHCI_TRB_TYPE_EVENT	(7 << 10)
#define	XHCI_TRB_TYPE_NOOP	(8 << 10)

/* Command ring Types */
#define	XHCI_CMD_ENABLE_SLOT	(9 << 10)
#define	XHCI_CMD_DISABLE_SLOT	(10 << 10)
#define	XHCI_CMD_ADDRESS_DEVICE	(11 << 10)
#define	XHCI_CMD_CONFIG_EP	(12 << 10)
#define	XHCI_CMD_EVAL_CTX	(13 << 10)
#define	XHCI_CMD_RESET_EP	(14 << 10)
#define	XHCI_CMD_STOP_EP	(15 << 10)
#define	XHCI_CMD_SET_TR_DEQ	(16 << 10)
#define	XHCI_CMD_RESET_DEV	(17 << 10)
#define	XHCI_CMD_FEVENT		(18 << 10)
#define	XHCI_CMD_NEG_BW		(19 << 10)
#define	XHCI_CMD_SET_LT  	(20 << 10)
#define	XHCI_CMD_GET_BW		(21 << 10)
#define	XHCI_CMD_FHEADER	(22 << 10)
#define	XHCI_CMD_NOOP		(23 << 10)

/* Event ring Types */
#define	XHCI_EVT_XFER		(32 << 10)
#define	XHCI_EVT_CMD_COMPLETE	(33 << 10)
#define	XHCI_EVT_PORT_CHANGE	(34 << 10)
#define	XHCI_EVT_BW_REQUEST	(35 << 10)
#define	XHCI_EVT_DOORBELL	(36 << 10)
#define	XHCI_EVT_HOST_CTRL	(37 << 10)
#define	XHCI_EVT_DEVICE_NOTIFY	(38 << 10)
#define	XHCI_EVT_MFINDEX_WRAP	(39 << 10)

#define	XHCI_RING_TYPE_SHIFT(x)	((x) << 10)

/*
 * TRB Completion Codes. See xHCI 1.1 / 6.4.5.
 */
#define	XHCI_CODE_INVALID	 0	/* Producer didn't update the code. */
#define	XHCI_CODE_SUCCESS	 1	/* Badaboum, plaf, plouf, yeepee! */
#define	XHCI_CODE_DATA_BUF	 2	/* Overrun or underrun */
#define	XHCI_CODE_BABBLE	 3	/* Device is "babbling" */
#define	XHCI_CODE_TXERR		 4	/* USB Transaction error */
#define	XHCI_CODE_TRB		 5	/* Invalid TRB  */
#define	XHCI_CODE_STALL		 6	/* Stall condition */
#define	XHCI_CODE_RESOURCE	 7	/* No resource available for the cmd */
#define	XHCI_CODE_BANDWIDTH	 8	/* Not enough bandwidth  for the cmd */
#define	XHCI_CODE_NO_SLOTS	 9	/* MaxSlots limit reached */
#define	XHCI_CODE_STREAM_TYPE	10	/* Stream Context Type value detected */
#define	XHCI_CODE_SLOT_NOT_ON	11	/* Related device slot is disabled */
#define	XHCI_CODE_ENDP_NOT_ON	12	/* Related enpoint is disabled */
#define	XHCI_CODE_SHORT_XFER	13	/* Short packet */
#define	XHCI_CODE_RING_UNDERRUN	14	/* Empty ring when transmitting isoc */
#define	XHCI_CODE_RING_OVERRUN	15	/* Empty ring when receiving isoc */
#define	XHCI_CODE_VF_RING_FULL	16	/* VF's event ring is full */
#define	XHCI_CODE_PARAMETER	17	/* Context parameter is invalid */
#define	XHCI_CODE_BW_OVERRUN	18 	/* TD exceeds the bandwidth */
#define	XHCI_CODE_CONTEXT_STATE	19	/* Transition from illegal ctx state */
#define	XHCI_CODE_NO_PING_RESP	20	/* Unable to complete periodic xfer */
#define	XHCI_CODE_EV_RING_FULL	21	/* Unable to post an evt to the ring */
#define	XHCI_CODE_INCOMPAT_DEV	22	/* Device cannot be accessed */
#define	XHCI_CODE_MISSED_SRV	23	/* Unable to service isoc EP in ESIT */
#define	XHCI_CODE_CMD_RING_STOP	24 	/* Command Stop (CS) requested */
#define	XHCI_CODE_CMD_ABORTED	25 	/* Command Abort (CA) operation */
#define	XHCI_CODE_XFER_STOPPED	26 	/* xfer terminated by a stop endpoint */
#define	XHCI_CODE_XFER_STOPINV	27 	/* TRB transfer length invalid */
#define	XHCI_CODE_XFER_STOPSHORT	28 	/* Stopped before end of TD */
#define	XHCI_CODE_MELAT		29	/* Max Exit Latency too large */
#define	XHCI_CODE_RESERVED	30
#define	XHCI_CODE_ISOC_OVERRUN	31	/* IN data buffer < Max ESIT Payload */
#define	XHCI_CODE_EVENT_LOST	32 	/* Internal overrun - impl. specific */
#define	XHCI_CODE_UNDEFINED	33 	/* Fatal error - impl. specific */
#define	XHCI_CODE_INVALID_SID	34 	/* Invalid stream ID received */
#define	XHCI_CODE_SEC_BW	35 	/* Cannot alloc secondary BW Domain */
#define	XHCI_CODE_SPLITERR	36 	/* USB2 split transaction */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_USB_HCD_XHCI_XHCIREG_H */
