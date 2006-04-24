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
 * All Rights Reserved, Copyright (c) FUJITSU LIMITED 2006
 */

#ifndef _SCFREG_H
#define	_SCFREG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * register map count
 */
#define	SCF_REGMAP_COUNT	5		/* register map cnt */

/*
 * register and SRAM max size
 */
#define	SRAM_MAX_DSCP		0x00010000	/* SCF system SRAM max size */
#define	SRAM_MAX_SYSTEM		0x00010000	/* SCF DSCP SRAM max size */
#define	SRAM_MAX_INTERFACE	0x00060000	/* SCF interface max size */
#define	SRAM_MAX_DRVDRVE	0x00001000	/* SCF SRAM driver trac */

/*
 * SCF registers
 */
typedef struct scf_regs {
	uint16_t	COMMAND;	/* SCF command register */
	uint8_t		rsv002[2];	/* reserved */
	uint16_t	STATUS;		/* SCF status register */
	uint8_t		rsv006[2];	/* reserved */
	uint8_t		VERSION;	/* SCF version register */
	uint8_t		rsv009[3];	/* reserved */
	uint8_t		rsv00c[4];	/* reserved */

	uint32_t	TDATA0;		/* SCF Tx DATA0 register */
	uint32_t	TDATA1;		/* SCF Tx DATA1 register */
	uint32_t	TDATA2;		/* SCF Tx DATA2 register */
	uint32_t	TDATA3;		/* SCF Tx DATA3 register */

	uint32_t	RDATA0;		/* SCF Rx DATA0 register */
	uint32_t	RDATA1;		/* SCF Rx DATA1 register */
	uint32_t	RDATA2;		/* SCF Rx DATA2 register */
	uint32_t	RDATA3;		/* SCF Rx DATA3 register */

	uint8_t		rsv030[16];	/* reserved */
	uint8_t		rsv040[2];	/* reserved */
	uint8_t		COMMAND_ExR;	/* SCF command extended register */
	uint8_t		rsv043;		/* reserved */
	uint8_t		FIRMREQ1;	/* Firmware request register1 */
	uint8_t		FIRMREQ0;	/* Firmware request register0 */
	uint8_t		rsv046[2];	/* reserved */
	uint8_t		ACR;		/* Alive check register */
	uint8_t		ATR;		/* Alive timer register */
	uint8_t		rsv04a[6];	/* reserved */

	uint8_t		rsv050[4];	/* reserved */
	uint32_t	STATUS_ExR;	/* SCFI status extended register */
	uint8_t		rsv058[8];	/* reserved */
	uint8_t		rsv060[160];	/* reserved */

	uint8_t		DCR;		/* DSCP buffer control register */
	uint8_t		DSR;		/* DSCP buffer status register */
	uint8_t		rsv102[14];	/* reserved */

	uint16_t	TxDCR_C_FLAG;	/* DSCP Tx DSC control register */
	uint16_t	TxDCR_OFFSET;	/* DSCP Tx DSC control register */
	uint32_t	TxDCR_LENGTH;	/* DSCP Tx DSC control register */
	uint16_t	TxDSR_C_FLAG;	/* DSCP Tx DSC status register */
	uint16_t	TxDSR_OFFSET;	/* DSCP Tx DSC status register */
	uint8_t		rsv11c[4];	/* reserved */

	uint16_t	RxDCR_C_FLAG;	/* DSCP Rx DSC control register */
	uint16_t	RxDCR_OFFSET;	/* DSCP Rx DSC control register */
	uint32_t	RxDCR_LENGTH;	/* DSCP Rx DSC control register */
	uint16_t	RxDSR_C_FLAG;	/* DSCP Rx DSC status register */
	uint16_t	RxDSR_OFFSET;	/* DSCP Rx DSC status register */
	uint8_t		rsv12c[4];	/* reserved */
} scf_regs_t;

/*
 * SCF control registers
 */
typedef struct scf_regs_c {
	uint16_t	CONTROL;	/* SCF Control register */
	uint8_t		rsv02[2];	/* reserved */
	uint16_t	INT_ST;		/* SCF Interrupt Status register */
	uint8_t		rsv06[2];	/* reserved */
} scf_regs_c_t;

/*
 * System buffer (SRAM)
 */
typedef struct scf_sys_sram {
	uint8_t		DATA[SRAM_MAX_SYSTEM];	/* System Tx/Rx buffer */
} scf_sys_sram_t;

/*
 * DSCP buffer (SRAM)
 */
typedef struct scf_dscp_sram {
	uint8_t		DATA[SRAM_MAX_DSCP];	/* DSCP Tx/Rx buffer */
} scf_dscp_sram_t;

/*
 * Interface buffer hedder (SRAM)
 */
typedef struct scf_interface {
	uint32_t	other1[0x40 / 4];	/* other area */
	uint32_t	DRVTRC_OFFSET;		/* SCF driver trace offset */
	uint32_t	DRVTRC_SIZE;		/* SCF driver trace size */
	uint32_t	other2[0xa8 / 4];	/* other area  */
} scf_interface_t;

/*
 * SCF driver trace table
 */
#define	DRV_ID_SIZE	16

typedef	struct scf_if_drvtrc {
	uint8_t		DRV_ID[DRV_ID_SIZE];	/* driver ID */
	uint32_t	DATA_TOP;		/* trace data top offset */
	uint32_t	DATA_LAST;		/* trace data last offset */
	uint32_t	DATA_WRITE;		/* trace data write offset */
	uint8_t		rsv01c[4];		/* reserved */
} scf_if_drvtrc_t;

/*
 * SRAM driver trace entry
 */
typedef	struct scf_drvtrc_ent {
	uint8_t		LOG_ID;			/* log ID */
	uint8_t		LOG_TIME[3];		/* log time */
	uint8_t		INFO[12];		/* log info */
} scf_drvtrc_ent_t;

/*
 * SRAM trace log ID
 */
#define	DTC_CMD			0x01	/* SCF command start */
#define	DTC_INT			0x02	/* SCF interrupt */
#define	DTC_SENDDATA		0x03	/* SCF send command data */
#define	DTC_RECVDATA		0x04	/* SCF recv command data */
#define	DTC_SENDDATA_SRAM	0x05	/* SCF send command data for SRAM */
#define	DTC_RECVDATA_SRAM	0x06	/* SCF recv command data for SRAM */
#define	DTC_CMDTO		0x11	/* SCF command timeout */
#define	DTC_CMDBUSYTO		0x12	/* SCF command busy timeout */
#define	DTC_ONLINETO		0x13	/* SCF online timeout */
#define	DTC_ERRRTN		0x20	/* SCF command retuen error */
#define	DTC_RCI_BUF_FUL		0x21	/* SCF command return for buff full */
#define	DTC_RCI_BUSY		0x22	/* SCF command return for rci busy */
#define	DTC_INTERFACE		0x23	/* SCF command return for */
					/* interface error */
#define	DTC_E_NOT_SUPPORT	0x28	/* SCF command return for */
					/* not support */
#define	DTC_E_PARAM		0x29	/* SCF command return for */
					/* parameter error */
#define	DTC_E_SCFC_PATH		0x2a	/* SCF command return for */
					/* SCFI path error */
#define	DTC_E_RCI_ACCESS	0x2b	/* SCF command return for */
					/* RCI access error */
#define	DTC_E_SEQUENCE		0x2d	/* SCF command return for */
					/* sequence error */
#define	DTC_RSUMERR		0x31	/* SCF command receive sum error */
#define	DTC_ONLINE		0x32	/* SCF offline start */
#define	DTC_OFFLINE		0x33	/* SCF offline start */
#define	DTC_DSCP_TXREQ		0x41	/* DSCP TxREQ request */
#define	DTC_DSCP_RXACK		0x42	/* DSCP RxACK request */
#define	DTC_DSCP_RXEND		0x43	/* DSCP RxEND request */
#define	DTC_DSCP_RXREQ		0x44	/* DSCP RxREQ interrupt */
#define	DTC_DSCP_TXACK		0x45	/* DSCP TxACK interrupt */
#define	DTC_DSCP_TXEND		0x46	/* DSCP TxEND interrupt */
#define	DTC_DSCP_SENDDATA	0x47	/* DSCP send data */
#define	DTC_DSCP_RECVDATA	0x48	/* DSCP recv data */
#define	DTC_DSCP_ACKTO		0x51	/* DSCP ACK timeout */
#define	DTC_DSCP_ENDTO		0x52	/* DSCP END timeout */

#define	DTC_MASK_HIGH		0xf0	/* mask high */

/* SRAM trace define */
#define	SCF_SRAM_TRACE(a, b)	scf_sram_trace(a, b)

#define	SCF_SET_SRAM_DATA1_2(a, b, c)					\
	statep->memo_scf_drvtrc.INFO[a] = (uint8_t)(b);			\
	statep->memo_scf_drvtrc.INFO[a + 1] = (uint8_t)(c)

#define	SCF_SET_SRAM_DATA2_1(a, b)					\
	statep->memo_scf_drvtrc.INFO[a] = (uint8_t)(b >> 8);		\
	statep->memo_scf_drvtrc.INFO[a + 1] = (uint8_t)(b)

#define	SCF_SET_SRAM_DATA2_2(a, b, c)					\
	statep->memo_scf_drvtrc.INFO[a] = (uint8_t)(b >> 8);		\
	statep->memo_scf_drvtrc.INFO[a + 1] = (uint8_t)(b);		\
	statep->memo_scf_drvtrc.INFO[a + 2] = (uint8_t)(c >> 8);	\
	statep->memo_scf_drvtrc.INFO[a + 3] = (uint8_t)(c)

#define	SCF_SET_SRAM_DATA4_1(a, b)					\
	statep->memo_scf_drvtrc.INFO[a] = (uint8_t)(b >> 24);		\
	statep->memo_scf_drvtrc.INFO[a + 1] = (uint8_t)(b >> 16);	\
	statep->memo_scf_drvtrc.INFO[a + 2] = (uint8_t)(b >> 8);	\
	statep->memo_scf_drvtrc.INFO[a + 3] = (uint8_t)(b)

#define	SCF_SET_SRAM_DATA4_3(a, b, c, d)				\
	statep->memo_scf_drvtrc.INFO[a] = (uint8_t)(b >> 24);		\
	statep->memo_scf_drvtrc.INFO[a + 1] = (uint8_t)(b >> 16);	\
	statep->memo_scf_drvtrc.INFO[a + 2] = (uint8_t)(b >> 8);	\
	statep->memo_scf_drvtrc.INFO[a + 3] = (uint8_t)(b);		\
	statep->memo_scf_drvtrc.INFO[a + 4] = (uint8_t)(c >> 24);	\
	statep->memo_scf_drvtrc.INFO[a + 5] = (uint8_t)(c >> 16);	\
	statep->memo_scf_drvtrc.INFO[a + 6] = (uint8_t)(c >> 8);	\
	statep->memo_scf_drvtrc.INFO[a + 7] = (uint8_t)(c);		\
	statep->memo_scf_drvtrc.INFO[a + 8] = (uint8_t)(d >> 24);	\
	statep->memo_scf_drvtrc.INFO[a + 9] = (uint8_t)(d >> 16);	\
	statep->memo_scf_drvtrc.INFO[a + 10] = (uint8_t)(d >> 8);	\
	statep->memo_scf_drvtrc.INFO[a + 11] = (uint8_t)(d)

/*
 * SCF registers define
 */

/* COMMAND : SCF command register define */
#define	COMMAND_BUSY		0x8000		/* Command interface busy */
#define	COMMAND_SUBCODE		0x7f00		/* Command subcode */
#define	COMMAND_CODE		0x00ff		/* Command code */

#define	CMD_SCFI_PATH		0x10		/* SCF path change */
#define		SUB_CMD_PATH		0x00	/* Command path change */

#define		CMD_PATH_TYPE_SCFD	0x01	/* Command path type(scfd) */

#define	CMD_ALIVE_CHECK		0x20		/* Alive check */
#define		SUB_ALIVE_START		0x30	/* Start */
#define		SUB_ALIVE_STOP		0x50	/* Stop */

#define	CMD_REPORT		0x21		/* Report */
#define		SUB_SYSTEM_STATUS_RPT	0x40	/* System status */
#define		SUB_SYSTEM_STATUS_RPT_NOPATH	0x51
					/* System status (no path check) */

#define	CMD_PHASE			0x22	/* Domain phase print */
#define		SUB_PHASE_PRINT		0x10	/* Phase print */

#define	CMD_PART_POW_CTR	0x30		/* power control */
#define		SUB_PON			0x01	/* Power on */
#define		SUB_POFF		0x02	/* Power off */
#define		SUB_FPOFF		0x13	/* Forced power off */
#define		SUB_RESET		0x04	/* Power reset */
#define		SUB_POFFID		0x19	/* Power off factor */

#define	CMD_SYS_AUTOPOW		0x35	/* System automatic power control */
#define		SUB_SYS_AUTO_ONOFF_SET	0x01	/* on/off time set */
#define		SUB_SYS_AUTO_ONOFF_DISP 0x02	/* on/off time disp */
#define		SUB_SYS_AUTO_ONOFF_CLRAR 0x04	/* on/off time clear */
#define		SUB_FORCED_POFF_SET	0x08	/* Forced power off time set */
#define		SUB_PRESET_MODE_DISP	0x10	/* Power resume mode disp */
#define		SUB_PRESET_MODE_SET	0x20	/* Power resume mode set */

#define	CMD_RCI_CTL		0x40		/* RCI control */
#define		SUB_HOSTADDR_DISP2	0xff	/* Host address disp 2 */
#define		SUB_DEVICE_LIST		0x0a	/* Device list disp */
#define		SUB_PANIC		0x03	/* Panic request */

#define	CMD_INT_REASON		0x50		/* Event information */
#define		SUB_INT_REASON_DISP	0x10	/* Factor detail disp */
#define		SUB_INT_REASON_RETRY	0x01	/* Factor detail re-disp */

#define	CMD_FILE_DOWNLOAD	0x74		/* File dounload or upload */

#define	CMD_DOMAIN_INFO		0x81		/* Domain information */
#define		SUB_OPTION_DISP		0x04	/* Option disp */
#define		SUB_PCI_HP_CONFIG	0x52	/* PCI configuration set */
#define		SUB_PCI_DISP		0x54	/* PCI configuration disp */
#define		SUB_DISK_LED_DISP	0x70	/* DISK LED disp */
#define		SUB_DISK_LED_ON		0x73	/* DISK LED on */
#define		SUB_DISK_LED_BLINK	0x75	/* DISK LED blink */
#define		SUB_DISK_LED_OFF	0x76	/* DISK LED off */

#define	CMD_DR			0xa2		/* DR function */

#define	CMD_ERRLOG		0xb0		/* Error log control */
#define		SUB_ERRLOG_SET_MADMIN	0x26	/* Log set madmin */

#define	CMD_REMCS_SPT		0xc3		/* REMCS command */

#define	CMD_SPARE		0xc4		/* SPARE command */

#define	CMD_OS_XSCF_CTL		0xc5		/* OS to ESCF */

/* STATUS : SCF status register define */
#define	STATUS_SCF_READY	0x8000	/* bit15: SCF READY */
#define	STATUS_SHUTDOWN		0x4000	/* bit14: SHUTDOWN */
#define	STATUS_POFF		0x2000	/* bit13: POFF */
#define	STATUS_EVENT		0x1000	/* bit12: EVENT */
#define	STATUS_TIMER_ADJUST	0x0800	/* bit11: TIMER ADJUST */
#define	STATUS_ALIVE		0x0400	/* bit10: ALIVE (Not use) */
#define	STATUS_MODE_CHANGED	0x0200	/* bit 9: MODE CHANGED */
#define	STATUS_U_PARITY		0x0100	/* bit 8: U Parity (Not use */
#define	STATUS_CMD_RTN_CODE	0x00f0	/* bit 7-4: CMD return code */
#define	STATUS_SECURE_MODE	0x0008	/* bit 3: secure mode status */
#define	STATUS_BOOT_MODE	0x0004	/* bit 2: boot mode status */
#define	STATUS_CMD_COMPLETE	0x0002	/* bit 1: Command complete */
#define	STATUS_L_PARITY		0x0001	/* bit 0: L Parity (Not use) */

/* secure mode status */
#define	STATUS_MODE_UNLOCK	0x0000		/* UNLOCK */
#define	STATUS_MODE_LOCK	0x0008		/* LOCK */

/* boot mode status */
#define	STATUS_MODE_OBP_STOP	0x0000		/* OBP stop */
#define	STATUS_MODE_AUTO_BOOT	0x0004		/* Auto boot */

/* STATUS_CMD_RTN_CODE : Command return value */
#define	NORMAL_END	0x00			/* Normal end */
#define	BUF_FUL		0x01			/* Buff full */
#define	RCI_BUSY	0x02			/* RCI busy */
#define	INTERFACE	0x03			/* Parity/Sum error */

#define	E_NOT_SUPPORT	0x08			/* Not support */
#define	E_PARAM		0x09			/* Parameter error */
#define	E_SCFC_NOPATH	0x0a			/* No SCFC path */
#define	E_RCI_ACCESS	0x0b			/* RCI access error */
#define	E_HARD		0x0c			/* Hard error */
#define	RCI_NS		0x0f			/* Not support RCI */

/* COMMAND_ExR : SCF command extended register define */
#define	COMMAND_ExR_BUSY	0x80		/* Command busy */
#define	COMMAND_ExR_RETRY	0x40		/* Command retry */

/* STATUS_ExR : SCF status extended register define */
#define	STATUS_POWER_FAILURE	0x80000000	/* Power failure */
#define	STATUS_SCF_STATUS_CHANGE 0x40000000	/* SCF status change */
#define	STATUS_SCF_STATUS	0x20000000	/* SCF status */
#define	STATUS_SCF_NO		0x10000000	/* Offline SCF No. */
#define	STATUS_STATUS_DETAIL	0x0000ffff	/* Return code detail code */

#define	STATUS_SCF_ONLINE	0x20000000	/* SCF status online */
#define	STATUS_SCF_OFFLINE	0x00000000	/* SCF status offline */

/* ACR : Alive check register define */
#define	ACR_ALIVE_INT		0x80		/* Alive Interrupt for SCF */
#define	ACR_PHASE_CODE		0x7f		/* Phase code */

/* ATR : Alive timer register define */
#define	ATR_INTERVAL		0x07		/* Interrupt interval */
#define	ATR_INTERVAL_STOP	0x00		/* Interrupt interval stop */
#define	ATR_INTERVAL_30S	0x01		/* Interrupt interval 30 s */
#define	ATR_INTERVAL_60S	0x02		/* Interrupt interval 1 min */
#define	ATR_INTERVAL_120S	0x04		/* Interrupt interval 2 min */

/* DCR : DSCP Buffer Control Register */
	/* Domain to SCF data transfer request isuued */
#define	DCR_TxREQ		(uint8_t)0x80
	/* SCF to domain data transfer request accepted */
#define	DCR_RxACK		0x40
	/* SCF to domain data transfer request end */
#define	DCR_RxEND		0x20

/* DSR : DSCP Buffer Status Register */
	/* SCF to domain data transfer request issued */
#define	DSR_RxREQ		(uint8_t)0x80
	/* domain to SCF data transfer request accepted */
#define	DSR_TxACK		0x40
	/* domain to SCF data transfer request end */
#define	DSR_TxEND		0x20

/* Tx/Rx SUM magicnumber */
#define	SCF_MAGICNUMBER_S	0xaa		/* Small Buffer SUM */
#define	SCF_MAGICNUMBER_L	(uint32_t)0xaaaaaaaa	/* Large Buffer SUM */

/* Length border conversion */
#define	SCF_LENGTH_16BYTE_CNV	0xfffffff0	/* 16byte border conversion */


/*
 * SCF registers define
 */

/* CONTROL/INT_ST : SCF Control/SCF Interrupt Status register define */

	/* SCF Path Change Interrupt enable */
#define	CONTROL_PATHCHGIE	0x8000
	/* SCF Interrupt enable */
#define	CONTROL_SCFIE		0x4000
	/* DSCP Communication Buffer Interrupt enable */
#define	CONTROL_IDBCIE		0x2000
	/* Alive Interrupt enable */
#define	CONTROL_ALIVEINE	0x1000
	/* interrupt enable */
#define	CONTROL_ENABLE							\
	(CONTROL_PATHCHGIE | CONTROL_SCFIE | CONTROL_IDBCIE)
	/* interrupt disable */
#define	CONTROL_DISABLE		0x0000

	/* SCF Path Change Interrupt  */
#define	INT_ST_PATHCHGIE	0x8000
	/* SCF interrupt */
#define	INT_ST_SCFINT		0x4000
	/* DSCP Communication Buffer Interrupt */
#define	INT_ST_IDBCINT		0x2000
		/* Alive Interrupt */
#define	INT_ST_ALIVEINT		0x1000

	/* All Interrupt */
#define	INT_ST_ALL							\
	(INT_ST_PATHCHGIE | INT_ST_SCFINT | INT_ST_IDBCINT | INT_ST_ALIVEINT)

/* Machine address */
#define	SCF_CMD_SYSTEM_ADDR	0x00000000	/* Owner address */

/* status */
#define	REPORT_STAT_PANIC		0x01	/* panic */
#define	REPORT_STAT_SHUTDOWN_START	0x02	/* shutdown start */
#define	REPORT_STAT_SYSTEM_RUNNING	0x0a	/* system running */
#define	REPORT_STAT_RCIDWN	(uint8_t)0xf0	/* rci down */

/* POFF ID */
#define	POFF_ID_PANEL		0x00		/* panel */
#define	POFF_ID_RCI		0x20		/* RCI */
#define	POFF_ID_XSCF		0x03		/* XSCF */
#define	POFF_ID_MASK		0xf0

/* category type */
#define	DEV_SENSE_ATTR_OWN	0x00		/* Owner host */
#define	DEV_SENSE_ATTR_OTHER	0x01		/* Other host */
#define	DEV_SENSE_ATTR_IO	0x80		/* I/O unit */

/* Remote Device Control */
#define	RCI_DEVCLASS_MASK	0xfff		/* mask for device class */
#define	RCI_DEVCLASS_CPU_START	0x001		/* CPU start */
#define	RCI_DEVCLASS_CPU_END	0x0ff		/* CPU end */
#define	RCI_DEVCLASS_DISK_START	0x400		/* disk start */
#define	RCI_DEVCLASS_DISK_END	0x4ff		/* disk end */

#define	RMT_DEV_CLASS_START_SHIFT	16

/* sense */
#define	DEV_SENSE_SHUTDOWN	0x80		/* need shutdown bit */

#define	DEV_SENSE_FANUNIT	0x01		/* fan unit error */

#define	DEV_SENSE_PWRUNIT	0x02		/* power unit error */

#define	DEV_SENSE_UPS		0x05		/* UPS error */
#define	DEV_SENSE_UPS_MASK		0x0f
#define	DEV_SENSE_UPS_LOWBAT		0x8	/* Low Battery */

#define	DEV_SENSE_THERMAL	0x06		/* thermal error */

#define	DEV_SENSE_PWRSR		0x07		/* power stop/resume */
#define	DEV_SENSE_PWRSR_MASK		0x0f
#define	DEV_SENSE_PWRSR_STOP		0x8	/* power stop */

#define	DEV_SENSE_NODE		0x08		/* node error */
#define	DEV_SENSE_NODE_STCKTO		0x90	/* status check timeout */

#define	DEV_SENSE_RCI_PATH40	0x40		/* Devive status print */
#define	DEV_SENSE_SYS_REPORT	0x60		/* system status report */
#define	DEV_SENSE_PANIC_REQ	0x61		/* panic request */
#define	DEV_SENSE_IONODESTAT	0x62		/* I/O node status */
#define	DEV_SENSE_STATUS_RPT	0x71		/* Deveice status print */


/*
 * SCF command send control
 */
typedef struct scf_cmd {
	uint_t 		flag;			/* buff type flag */
	uchar_t		cmd;			/* SCF command code */
	uchar_t		subcmd;			/* SCF sub command code */
	ushort_t	stat0;			/* Interrupt status */
	uint_t		scount;			/* Tx data count */
	uint_t		rcount;			/* Rx data count */
	uchar_t		*sbuf;			/* Tx buff address */
	uchar_t		*rbuf;			/* Rx buff address */
	uint_t		rbufleng;		/* recv data leng */
	ushort_t	status;			/* SCF status reg */
	uchar_t		cexr[4];		/* Command extension info */
} scf_cmd_t;

/* SCF interrupt error status make */
#define	SCF_STAT0_RDATA_SUM	0xf0		/* Rx data sum error */
#define	SCF_STAT0_NOT_PATH	0xff		/* Non change path */

/* SCF comannd buff type */
#define	SCF_USE_S_BUF		0		/* Tx : -/S Rx : - */
#define	SCF_USE_SSBUF		1		/* Tx : -/S Rx : S */
#define	SCF_USE_SLBUF		2		/* Tx : -/S Rx : L */
#define	SCF_USE_L_BUF		3		/* Tx : L Rx : - */
#define	SCF_USE_LSBUF		4		/* Tx : L Tx : S */

#define	SCF_USE_STOP		0x7e
#define	SCF_USE_START		0x7f
#define	SCF_USE_SP		(uint8_t)0x80

/* SCF command size */
#define	SCF_S_CNT_32		32		/* TxRx Small buff size */
#define	SCF_S_CNT_16		16		/* TxRx Small buff size */
#define	SCF_S_CNT_15		15		/* Small buff cnt 15byte */
#define	SCF_S_CNT_12		12		/* Small buff cnt 12byte */
#define	SCF_S_CNT_8		8		/* Small buff cnt 8byte */

#define	SCF_L_CNT_MAX		SRAM_MAX_SYSTEM
					/* Command buffer max size (64Kyte) */

#define	SCF_SBUFR_SIZE		64	/* RDCTL data size */
#define	SCF_SHORT_BUFFER_SIZE	(16 * 5) /* Short bauuer size (16byte * 5) */
#define	SCF_SHORT_BUFFER_SIZE_4BYTE	(SCF_SHORT_BUFFER_SIZE / 4)
#define	SCF_INT_REASON_SIZE	32	/* INT_REASON size */
#define	SCF_INT_CNT_MAX		(SCF_INT_REASON_SIZE * 4)
					/* INT_REASON max size (128yte) */
#define	SCF_DEVLIST_MAXCNT	2	/* Device list max count */
#define	SCF_DEVLIST_ENTSIZE	8	/* Device list entry size */


/* CMD_RCI_CTL SUB_RCI_PATH_4* value */
#define	SCF_RCI_PATH_PARITY	0x10		/* SUB_RCI_PATH_4* parity */

/* Alive check function value */
#define	SCF_ALIVE_FUNC_ON	"on"		/* parameter alive start */
#define	SCF_ALIVE_FUNC_OFF	"off"		/* parameter alive stop */

#define	SCF_ALIVE_START		1		/* Alive check start */
#define	SCF_ALIVE_STOP		0		/* Alive check stop */

/* Alive check timer value (10s) */
#define	INTERVAL_TIME_MIN	0x06		/* interval time min (1min) */
#define	INTERVAL_TIME_MAX	0x3c		/* cycle_time max (10min) */
#define	INTERVAL_TIME_DEF	0x0c		/* cycle_time default (2min) */
#define	MONITOR_TIME_MIN	0x12		/* watch_time min (3min) */
#define	MONITOR_TIME_MAX	0xb4		/* monitor time max (30min) */
#define	MONITOR_TIME_DEF	0x24		/* monitor default (6min) */
#define	PANIC_TIME_MIN		0x00b4		/* panic time min (30min) */
#define	PANIC_TIME_MAX		0x0870		/* panic time max (360min) */
#define	PANIC_TIME_DEF		0x00b4		/* panic time default (30min) */
#define	PANIC_TIME_NONE		0x0000		/* no panic time monitor */

#define	MONITOR_TIME_CORRECT	0x03	/* monitor time correct (30sec) */

#define	SCF_MIN_TO_10SEC(a)	a = a * 6;	/* minutes to 10 seconds */

/* Short buffer structure */
typedef union scf_short_buffer {
	uchar_t		b[SCF_SHORT_BUFFER_SIZE];
	uint_t		four_bytes_access[SCF_SHORT_BUFFER_SIZE_4BYTE];
} scf_short_buffer_t;

/* Event information structure */
typedef union scf_int_reason {
	uchar_t		b[SCF_INT_CNT_MAX];
	uint_t		four_bytes_access[SCF_INT_CNT_MAX / 4];
} scf_int_reason_t;

#ifdef	__cplusplus
}
#endif

#endif /* _SCFREG_H */
