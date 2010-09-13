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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_SDCARD_SDA_H
#define	_SYS_SDCARD_SDA_H

#include <sys/types.h>
#include <sys/note.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * SD card common framework.  This module provides most of the common
 * functionality so that SecureDigital host adapters and client devices
 * (such as the sdmem driver) can share common code.
 */

/*
 * SD Commands.  Commmand format is 48-bits as follows:
 *
 * bits		value		desc
 * -------------------------------------------
 * 47		0		start bit
 * 46		1		transmission bit
 * 45:40	cmd		command index (see values listed below)
 * 39:8		arg		32-bit command argument
 * 7:1		crc7		crc7 check value
 * 0		1		end bit
 * -------------------------------------------
 */
typedef enum {
	CMD_GO_IDLE = 0,
	CMD_SEND_OCR = 1,		/* MMC only */
	CMD_BCAST_CID = 2,
	CMD_SEND_RCA = 3,
	CMD_SET_DSR = 4,
	CMD_IO_SEND_OCR = 5,		/* SDIO only */
	CMD_SWITCH_FUNC = 6,
	CMD_SELECT_CARD = 7,
	CMD_SEND_IF_COND = 8,
	CMD_SEND_CSD = 9,
	CMD_SEND_CID = 10,
	CMD_STOP_TRANSMIT = 12,
	CMD_SEND_STATUS = 13,
	CMD_GO_INACTIVE = 15,
	CMD_SET_BLOCKLEN = 16,
	CMD_READ_SINGLE = 17,
	CMD_READ_MULTI = 18,
	CMD_WRITE_SINGLE = 24,
	CMD_WRITE_MULTI = 25,
	CMD_PROGRAM_CSD = 27,
	CMD_SET_WRITE_PROT = 28,
	CMD_CLR_WRITE_PROT = 29,
	CMD_SEND_WRITE_PROT = 30,
	CMD_ERASE_START = 32,
	CMD_ERASE_END = 33,
	CMD_ERASE = 38,
	CMD_LOCK = 42,
	CMD_IO_RW_DIRECT = 52,
	CMD_IO_RW_EXTENDED = 53,
	CMD_APP_CMD = 55,
	CMD_GEN_CMD = 56,
	/* APP CMD values, send ACMD first */
	ACMD_SET_BUS_WIDTH = 6,
	ACMD_SD_STATUS = 13,
	ACMD_SEND_NUM_WR_BLKS = 22,
	ACMD_SET_WR_BLK_ERASE_COUNT = 23,
	ACMD_SD_SEND_OCR = 41,
	ACMD_SET_CLR_CARD_DETECT = 42,
	ACMD_SEND_SCR = 51
} sda_index_t;

/*
 * Classes of response type.  Note that we encode the "busy bit" as
 * value 0x10.
 */
typedef enum {
	R0 = 0,
	R1 = 1,
	R2 = 2,
	R3 = 3,
	R4 = 4,
	R5 = 5,
	R6 = 6,
	R7 = 7,
	Rb = 0x10,
	R1b = 0x11,
	R5b = 0x15
} sda_rtype_t;

/*
 * R1 status bits.
 */
#define	R1_OUT_OF_RANGE		(1U << 31)
#define	R1_ADDRESS_ERROR	(1U << 30)
#define	R1_BLOCK_LEN_ERROR	(1U << 29)
#define	R1_ERASE_SEQ_ERROR	(1U << 28)
#define	R1_ERASE_PARAM		(1U << 27)
#define	R1_WP_VIOLATION		(1U << 26)
#define	R1_CARD_IS_LOCKED	(1U << 25)
#define	R1_LOCK_FAILED		(1U << 24)
#define	R1_COM_CRC_ERROR	(1U << 23)
#define	R1_ILLEGAL_COMMAND	(1U << 22)
#define	R1_CARD_ECC_FAILED	(1U << 21)
#define	R1_CC_ERROR		(1U << 20)
#define	R1_ERROR		(1U << 19)
#define	R1_CSD_OVERWRITE	(1U << 16)
#define	R1_WP_ERASE_SKIP	(1U << 15)
#define	R1_CARD_ECC_DIS		(1U << 14)
#define	R1_ERASE_RESET		(1U << 13)
#define	R1_READY_FOR_DATA	(1U << 8)
#define	R1_APP_CMD		(1U << 5)
#define	R1_AKE_SEQ_ERROR	(1U << 3)

/*
 * Note that R1_COM_CRC_ERR, R1_ILLEGAL_COMMAND, R1_ERASE_SEQ_ERROR, and
 * R1_AKE_SEQ_ERROR errors are delayed error bits reported on the next
 * command.  So we don't list them here.
 */
#define	R1_ERRS	(\
	R1_ERROR | R1_OUT_OF_RANGE | R1_ADDRESS_ERROR | R1_BLOCK_LEN_ERROR | \
	R1_ERASE_PARAM | R1_WP_VIOLATION | R1_LOCK_FAILED | \
	R1_CARD_ECC_FAILED | R1_CC_ERROR | R1_CSD_OVERWRITE | \
	R1_WP_ERASE_SKIP)

#define	R1_STATE(x)	(((x) & 0xf) >> 9)

/*
 * R5 status bits.
 */
#define	R5_COM_CRC_ERROR	(1U << 7)
#define	R5_ILLEGAL_COMMAND	(1U << 6)
#define	R5_ERROR		(1U << 3)
#define	R5_RFU			(1U << 2)
#define	R5_FUNCTION_NUMBER	(1U << 1)
#define	R5_OUT_OF_RANGE		(1U << 0)

#define	R5_ERRS	(R5_ERROR | R5_FUNCTION_NUMBER | R5_OUT_OF_RANGE)

#define	R5_IO_STATE(x)	(((x) & 0x3) >> 4)

/*
 * R7 bits (CMD8).
 */
#define	R7_VHS_27_36V		(1U << 8)
#define	R7_PATTERN		(0xAA)

/*
 * OCR bits.
 */
#define	OCR_POWER_UP		(1U << 31)
#define	OCR_CCS			(1U << 30)
#define	OCR_FUNCS(x)		(((x) & 7) >> 28)	/* SDIO only */
#define	OCR_MEM_PRESENT		(1U << 27)		/* SDIO only */
#define	OCR_VOLTAGE_MASK	(0xffffffU)		/* (bits 0-23 */
#define	OCR_HI_MASK		(0xff8000U)		/* 2.7-3.6V */
#define	OCR_35_36V		(1U << 23)
#define	OCR_34_35V		(1U << 22)
#define	OCR_33_34V		(1U << 21)
#define	OCR_32_33V		(1U << 20)
#define	OCR_31_32V		(1U << 19)
#define	OCR_30_31V		(1U << 18)
#define	OCR_29_30V		(1U << 17)
#define	OCR_28_29V		(1U << 16)
#define	OCR_27_28V		(1U << 15)
#define	OCR_26_27V		(1U << 14)
#define	OCR_25_26V		(1U << 14)
#define	OCR_24_25V		(1U << 13)
#define	OCR_23_24V		(1U << 12)
#define	OCR_22_23V		(1U << 11)
#define	OCR_21_22V		(1U << 10)
#define	OCR_20_21V		(1U << 9)
#define	OCR_19_20V		(1U << 8)
#define	OCR_18_19V		(1U << 7)
#define	OCR_17_18V		(1U << 6)


/*
 * Command structure.  Used internally by the framework, and by host
 * drivers.  Note that it is forbidden to depend on the size of this
 * structure.
 */
typedef struct sda_cmd sda_cmd_t;

struct sda_cmd {
	/*
	 * The ordering of these is done to maximize packing.
	 */
	sda_index_t		sc_index;	/* command name */
	sda_rtype_t		sc_rtype;	/* response type expected */
	uint16_t		sc_flags;
	uint32_t		sc_argument;	/* command argument */

	uint32_t		sc_response[4];

	uint16_t		sc_nblks;
	uint16_t		sc_blksz;

	uint32_t		sc_resid;

	ddi_dma_handle_t	sc_dmah;
	uint_t			sc_ndmac;	/* # DMA cookies */
	ddi_dma_cookie_t	sc_dmac;	/* actual DMA cookies */
	caddr_t			sc_kvaddr;	/* kernel virtual address */

#define	SDA_CMDF_READ		0x0001		/* transfer direction */
#define	SDA_CMDF_WRITE		0x0002		/* transfer direction */
#define	SDA_CMDF_AUTO_CMD12	0x0004		/* cmd12 requested */
/* private flags .. not for driver consumption */
#define	SDA_CMDF_DAT		0x0100		/* data phase pending */
#define	SDA_CMDF_BUSY		0x0200		/* cmd in-flight or queued */
#define	SDA_CMDF_INIT		0x0400		/* initialization command */
#define	SDA_CMDF_MEM		0x0800		/* memory target command */
};

/*
 * The framework has two APIs.  The first API is for host controllers,
 * and is referred to as SDHOST.  The second API is for target devices,
 * and is referred to as SDCLIENT.  Please don't mix and match usage outside
 * of the framework implementation itself!
 */

typedef struct sda_host sda_host_t;

typedef enum {
	SDA_PROP_INSERTED = 	1,	/* R: is card inserted? */
	SDA_PROP_WPROTECT =	2,	/* R: is card write protected */
	SDA_PROP_LED =		3,	/* W: LED */
	SDA_PROP_CLOCK =	4,	/* R: frequency, Hz */
	SDA_PROP_BUSWIDTH =	5,	/* W: bus width */
	SDA_PROP_OCR =		6,	/* RW: ocr R: supported, W: set curr */
	SDA_PROP_CAP_4BITS =	7,	/* R: 4 bit data bus? */
	SDA_PROP_CAP_8BITS =	8,	/* R: MMC future expansion */
	SDA_PROP_CAP_HISPEED =	9,	/* R: fast bus rates (> 25MHz) */
	SDA_PROP_CAP_INTR =	10,	/* R: SDIO interrupt support */
	SDA_PROP_CAP_NOPIO =	11,	/* R: Never needs bp_mapin */
	SDA_PROP_HISPEED =	12	/* W: high speed (>25MHz) */
} sda_prop_t;

typedef enum {
	SDA_FAULT_NONE =	0,	/* No failure */
	SDA_FAULT_ACMD12 =	1,	/* Auto CMD12 failure */
	SDA_FAULT_CRC7 =	2,	/* CRC7 failure on CMD/DAT line */
	SDA_FAULT_PROTO =	3,	/* SD/MMC protocol error */
	SDA_FAULT_CURRENT =	4,	/* Current overlimit detected */
	SDA_FAULT_INIT =	5,	/* Card initialization failure */
	SDA_FAULT_TIMEOUT =	6,	/* Unexpected timeout failure */
	SDA_FAULT_HOST =	7,	/* Internal host or slot failure */
	SDA_FAULT_RESET =	8,	/* Slot failed to reset */
} sda_fault_t;

typedef enum {
	SDA_EOK =		0,	/* Success */
	SDA_ECRC7 =		1,	/* CRC7 failure */
	SDA_EPROTO =		2,	/* SD/MMC protocol error */
	SDA_EINVAL =		3,	/* Invalid argument */
	SDA_ETIME =		4,	/* Timeout */
	SDA_ECMD12 =		5,	/* Failed during stop cmd */
	SDA_ENOTSUP =		6,	/* Setting/property not supported */
	SDA_ERESID =		7,	/* Incomplete transfer */
	SDA_EFAULT =		8,	/* Previous fault condition present */
	SDA_ENOMEM =		9,	/* Memory exhausted */
	SDA_EWPROTECT =		10,	/* Media is write protected */
	SDA_ENODEV =		11,	/* Card removed */
	SDA_ERESET =		12,	/* Memory card reset */
	SDA_EABORT =		13,	/* Memory command aborted */
	SDA_EIO =		14,	/* Other generic error */
	SDA_ESUSPENDED =	15,	/* Slot has been suspended */
} sda_err_t;

typedef struct sda_ops {
	int	so_version;
#define	SDA_OPS_VERSION	1
	sda_err_t	(*so_cmd)(void *, sda_cmd_t *);
	sda_err_t	(*so_getprop)(void *, sda_prop_t, uint32_t *);
	sda_err_t	(*so_setprop)(void *, sda_prop_t, uint32_t);
	sda_err_t	(*so_poll)(void *);
	sda_err_t	(*so_reset)(void *);
	sda_err_t	(*so_halt)(void *);
} sda_ops_t;

/*
 * Host operations.
 */
void sda_host_init_ops(struct dev_ops *);
void sda_host_fini_ops(struct dev_ops *);
sda_host_t *sda_host_alloc(dev_info_t *, int, sda_ops_t *, ddi_dma_attr_t *);
void sda_host_free(sda_host_t *);
void sda_host_set_private(sda_host_t *, int, void *);
int sda_host_attach(sda_host_t *);
void sda_host_detach(sda_host_t *);
void sda_host_suspend(sda_host_t *);
void sda_host_resume(sda_host_t *);
void sda_host_detect(sda_host_t *, int);
void sda_host_fault(sda_host_t *, int, sda_fault_t);
void sda_host_transfer(sda_host_t *, int, sda_err_t);
/*PRINTFLIKE3*/
void sda_host_log(sda_host_t *, int, const char *, ...);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SDCARD_SDA_H */
