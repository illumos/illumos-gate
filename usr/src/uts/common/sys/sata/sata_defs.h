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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SATA_DEFS_H
#define	_SATA_DEFS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Common ATA commands (subset)
 */
#define	SATAC_DIAG		0x90    /* diagnose command */
#define	SATAC_RECAL		0x10	/* restore cmd, 4 bits step rate */
#define	SATAC_FORMAT		0x50	/* format track command */
#define	SATAC_SET_FEATURES	0xef	/* set features	*/
#define	SATAC_IDLE_IM		0xe1	/* idle immediate */
#define	SATAC_STANDBY_IM	0xe0	/* standby immediate */
#define	SATAC_DOOR_LOCK		0xde	/* door lock */
#define	SATAC_DOOR_UNLOCK	0xdf	/* door unlock */
#define	SATAC_IDLE		0xe3	/* idle	*/

/*
 * ATA/ATAPI disk commands (subset)
 */
#define	SATAC_DEVICE_RESET	0x08    /* ATAPI device reset */
#define	SATAC_EJECT		0xed	/* media eject */
#define	SATAC_FLUSH_CACHE	0xe7	/* flush write-cache */
#define	SATAC_ID_DEVICE		0xec    /* IDENTIFY DEVICE */
#define	SATAC_ID_PACKET_DEVICE	0xa1	/* ATAPI identify packet device */
#define	SATAC_INIT_DEVPARMS	0x91	/* initialize device parameters */
#define	SATAC_PACKET		0xa0	/* ATAPI packet */
#define	SATAC_RDMULT		0xc4	/* read multiple w/DMA */
#define	SATAC_RDSEC		0x20    /* read sector */
#define	SATAC_RDVER		0x40	/* read verify */
#define	SATAC_READ_DMA		0xc8	/* read DMA */
#define	SATAC_SEEK		0x70    /* seek */
#define	SATAC_SERVICE		0xa2	/* queued/overlap service */
#define	SATAC_SETMULT		0xc6	/* set multiple mode */
#define	SATAC_WRITE_DMA		0xca	/* write (multiple) w/DMA */
#define	SATAC_WRMULT		0xc5	/* write multiple */
#define	SATAC_WRSEC		0x30    /* write sector */
#define	SATAC_RDSEC_EXT		0x24    /* read sector extended (LBA48) */
#define	SATAC_READ_DMA_EXT	0x25	/* read DMA extended (LBA48) */
#define	SATAC_RDMULT_EXT	0x29	/* read multiple extended (LBA48) */
#define	SATAC_WRSEC_EXT		0x34    /* read sector extended (LBA48) */
#define	SATAC_WRITE_DMA_EXT	0x35	/* read DMA extended (LBA48) */
#define	SATAC_WRMULT_EXT	0x39	/* read multiple extended (LBA48) */

#define	SATAC_READ_DMA_QUEUED	0xc7	/* read DMA / may be queued */
#define	SATAC_READ_DMA_QUEUED_EXT 0x26	/* read DMA ext / may be queued */
#define	SATAC_WRITE_DMA_QUEUED	0xcc	/* read DMA / may be queued */
#define	SATAC_WRITE_DMA_QUEUED_EXT 0x36	/* read DMA ext / may be queued */
#define	SATAC_READ_PM_REG	0xe4	/* read port mult reg */
#define	SATAC_WRITE_PM_REG	0xe8	/* write port mult reg */

#define	SATAC_READ_FPDMA_QUEUED	0x60	/* First-Party-DMA read queued */
#define	SATAC_WRITE_FPDMA_QUEUED 0x61	/* First-Party-DMA write queued */

#define	SATAC_READ_LOG_EXT	0x2f	/* read log */
#define	SATA_LOG_PAGE_10	0x10	/* log page 0x10 - SATA error */
/*
 * Power Managment Commands (subset)
 */
#define	SATAC_CHECK_POWER_MODE	0xe5	/* check power mode */

#define	SATA_PWRMODE_STANDBY	0	/* standby mode */
#define	SATA_PWRMODE_IDLE	0x80	/* idle mode */
#define	SATA_PWRMODE_ACTIVE	0xFF	/* active or idle mode, rev7 spec */


/*
 * SET FEATURES Subcommands
 */
#define	SATAC_SF_ENABLE_WRITE_CACHE	0x02
#define	SATAC_SF_TRANSFER_MODE		0x03
#define	SATAC_SF_DISABLE_READ_AHEAD	0x55
#define	SATAC_SF_DISABLE_WRITE_CACHE	0x82
#define	SATAC_SF_ENABLE_READ_AHEAD	0xaa

/*
 * SET FEATURES transfer mode values
 */
#define	SATAC_TRANSFER_MODE_PIO_DEFAULT		0x00
#define	SATAC_TRANSFER_MODE_PIO_DISABLE_IODRY	0x01
#define	SATAC_TRANSFER_MODE_PIO_FLOW_CONTROL	0x08
#define	SATAC_TRANSFER_MODE_MULTI_WORD_DMA	0x20
#define	SATAC_TRANSFER_MODE_ULTRA_DMA		0x40

/* Generic ATA definitions */

/*
 * Identify Device data
 * Although bot ATA and ATAPI devices' Identify Data has the same lenght,
 * some words have different meaning/content and/or are irrelevant for
 * other type of device.
 * Following is the ATA Device Identify data layout
 */
typedef struct sata_id {
/*  					WORD				*/
/* 					OFFSET COMMENT			*/
	ushort_t  ai_config;	  /*   0  general configuration bits 	*/
	ushort_t  ai_fixcyls;	  /*   1  # of cylinders (obsolete)	*/
	ushort_t  ai_resv0;	  /*   2  # reserved			*/
	ushort_t  ai_heads;	  /*   3  # of heads (obsolete)		*/
	ushort_t  ai_trksiz;	  /*   4  # of bytes/track (retired)	*/
	ushort_t  ai_secsiz;	  /*   5  # of bytes/sector (retired)	*/
	ushort_t  ai_sectors;	  /*   6  # of sectors/track (obsolete)	*/
	ushort_t  ai_resv1[3];	  /*   7  "Vendor Unique"		*/
	char	ai_drvser[20];	  /*  10  Serial number			*/
	ushort_t ai_buftype;	  /*  20  Buffer type			*/
	ushort_t ai_bufsz;	  /*  21  Buffer size in 512 byte incr  */
	ushort_t ai_ecc;	  /*  22  # of ecc bytes avail on rd/wr */
	char	ai_fw[8];	  /*  23  Firmware revision		*/
	char	ai_model[40];	  /*  27  Model #			*/
	ushort_t ai_mult1;	  /*  47  Multiple command flags	*/
	ushort_t ai_dwcap;	  /*  48  Doubleword capabilities	*/
	ushort_t ai_cap;	  /*  49  Capabilities			*/
	ushort_t ai_resv2;	  /*  50  Reserved			*/
	ushort_t ai_piomode;	  /*  51  PIO timing mode		*/
	ushort_t ai_dmamode;	  /*  52  DMA timing mode		*/
	ushort_t ai_validinfo;	  /*  53  bit0: wds 54-58, bit1: 64-70	*/
	ushort_t ai_curcyls;	  /*  54  # of current cylinders	*/
	ushort_t ai_curheads;	  /*  55  # of current heads		*/
	ushort_t ai_cursectrk;	  /*  56  # of current sectors/track	*/
	ushort_t ai_cursccp[2];	  /*  57  current sectors capacity	*/
	ushort_t ai_mult2;	  /*  59  multiple sectors info		*/
	ushort_t ai_addrsec[2];	  /*  60  LBA only: no of addr secs	*/
	ushort_t ai_sworddma;	  /*  62  single word dma modes		*/
	ushort_t ai_dworddma;	  /*  63  double word dma modes		*/
	ushort_t ai_advpiomode;	  /*  64  advanced PIO modes supported	*/
	ushort_t ai_minmwdma;	  /*  65  min multi-word dma cycle info	*/
	ushort_t ai_recmwdma;	  /*  66  rec multi-word dma cycle info	*/
	ushort_t ai_minpio;	  /*  67  min PIO cycle info		*/
	ushort_t ai_minpioflow;	  /*  68  min PIO cycle info w/flow ctl */
	ushort_t ai_resv3[2];	  /* 69,70 reserved			*/
	ushort_t ai_typtime[2];	  /* 71-72 timing			*/
	ushort_t ai_resv4[2];	  /* 73-74 reserved			*/
	ushort_t ai_qdepth;	  /*  75  queue depth			*/
	ushort_t ai_satacap;	  /*  76  SATA capabilities		*/
	ushort_t ai_resv5;	  /*  77 reserved			*/
	ushort_t ai_satafsup;	  /*  78 SATA features supported	*/
	ushort_t ai_satafenbl;	  /*  79 SATA features enabled		*/
	ushort_t ai_majorversion; /*  80  major versions supported	*/
	ushort_t ai_minorversion; /*  81  minor version number supported */
	ushort_t ai_cmdset82;	  /*  82  command set supported		*/
	ushort_t ai_cmdset83;	  /*  83  more command sets supported	*/
	ushort_t ai_cmdset84;	  /*  84  more command sets supported	*/
	ushort_t ai_features85;	  /*  85 enabled features		*/
	ushort_t ai_features86;	  /*  86 enabled features		*/
	ushort_t ai_features87;	  /*  87 enabled features		*/
	ushort_t ai_ultradma;	  /*  88 Ultra DMA mode			*/
	ushort_t ai_erasetime;	  /*  89 security erase time		*/
	ushort_t ai_erasetimex;	  /*  90 enhanced security erase time	*/
	ushort_t ai_padding1[9];  /* pad through 99			*/
	ushort_t ai_addrsecxt[4]; /* 100 extended max LBA sector	*/
	ushort_t ai_padding2[22]; /* pad to 126				*/
	ushort_t ai_lastlun;	  /* 126 last LUN, as per SFF-8070i	*/
	ushort_t ai_resv6;	  /* 127 reserved			*/
	ushort_t ai_securestatus; /* 128 security status		*/
	ushort_t ai_vendor[31];	  /* 129-159 vendor specific		*/
	ushort_t ai_padding3[16]; /* 160 pad to 176			*/
	ushort_t ai_curmedser[30]; /* 176-205 current media serial number */
	ushort_t ai_padding4[49]; /* 206 pad to 255			*/
	ushort_t ai_integrity;	  /* 255 integrity word			*/
} sata_id_t;


/* Identify Device: general config bits  - word 0 */

#define	SATA_ATA_TYPE_MASK	0x8001	/* ATA Device type mask */
#define	SATA_ATA_TYPE		0x0000	/* ATA device */
#define	SATA_REM_MEDIA  	0x0080 	/* Removable media */

#define	SATA_ID_SERIAL_OFFSET	10
#define	SATA_ID_SERIAL_LEN	20
#define	SATA_ID_MODEL_OFFSET	27
#define	SATA_ID_MODEL_LEN	40

/* Identify Device: common capability bits - word 49 */

#define	SATA_DMA_SUPPORT	0x0100
#define	SATA_LBA_SUPPORT	0x0200
#define	SATA_IORDY_DISABLE	0x0400
#define	SATA_IORDY_SUPPORT	0x0800
#define	SATA_STANDBYTIMER	0x2000

/* Identify Device: ai_validinfo (word 53) */

#define	SATA_VALIDINFO_88	0x0004	/* word 88 supported fields valid */

/* Identify Device: ai_majorversion (word 80) */

#define	SATA_MAJVER_6		0x0040	/* ATA/ATAPI-6 version supported */
#define	SATA_MAJVER_4		0x0010	/* ATA/ATAPI-4 version supported */

/* Identify Device: command set supported/enabled bits - words 83 and 86 */

#define	SATA_EXT48		0x0400	/* 48 bit address feature */
#define	SATA_RW_DMA_QUEUED_CMD	0x0002	/* R/W DMA Queued supported */
#define	SATA_DWNLOAD_MCODE_CMD	0x0001	/* Download Microcode CMD supp/enbld */

/* Identify Device: command set supported/enabled bits - words 82 and 85 */

#define	SATA_WRITE_CACHE	0x0020	/* Write Cache supported/enabled */
#define	SATA_LOOK_AHEAD		0x0040	/* Look Ahead supported/enabled */
#define	SATA_DEVICE_RESET_CMD	0x0200	/* Device Reset CMD supported/enbld */
#define	SATA_READ_BUFFER_CMD	0x2000	/* Read Buffer CMD supported/enbld */
#define	SATA_WRITE_BUFFER_CMD	0x1000	/* Write Buffer CMD supported/enbld */

#define	SATA_MDMA_SEL_MASK	0x0700	/* Multiword DMA selected */
#define	SATA_MDMA_2_SEL		0x0400	/* Multiword DMA mode 2 selected */
#define	SATA_MDMA_1_SEL		0x0200	/* Multiword DMA mode 1 selected */
#define	SATA_MDMA_0_SEL		0x0100	/* Multiword DMA mode 0 selected */
#define	SATA_MDMA_2_SUP		0x0004	/* Multiword DMA mode 2 supported */
#define	SATA_MDMA_1_SUP		0x0002	/* Multiword DMA mode 1 supported */
#define	SATA_MDMA_0_SUP		0x0001	/* Multiword DMA mode 0 supported */

#define	SATA_DISK_SECTOR_SIZE	512	/* HD physical sector size */

/* Identify Packet Device data definitions (ATAPI devices) */

/* Identify Packet Device: general config bits  - word 0 */

#define	SATA_ATAPI_TYPE_MASK	0xc000
#define	SATA_ATAPI_TYPE		0x8000 	/* ATAPI device */
#define	SATA_ATAPI_ID_PKT_SZ	0x0003 	/* Packet size mask */
#define	SATA_ATAPI_ID_PKT_12B	0x0000  /* Packet size 12 bytes */
#define	SATA_ATAPI_ID_PKT_16B	0x0001  /* Packet size 16 bytes */
#define	SATA_ATAPI_ID_DRQ_TYPE	0x0060 	/* DRQ asserted in 3ms after pkt */
#define	SATA_ATAPI_ID_DRQ_INTR	0x0020 	/* Obsolete in ATA/ATAPI 7 */

#define	SATA_ATAPI_ID_DEV_TYPE	0x0f00	/* device type/command set mask */
#define	SATA_ATAPI_ID_DEV_SHFT	8
#define	SATA_ATAPI_DIRACC_DEV	0x0000	/* Direct Access device */
#define	SATA_ATAPI_SQACC_DEV	0x0100	/* Sequential access dev (tape ?) */
#define	SATA_ATAPI_CDROM_DEV	0x0500	/* CD_ROM device */

/*
 * Status bits from ATAPI Interrupt reason register (AT_COUNT) register
 */
#define	SATA_ATAPI_I_COD	0x01	/* Command or Data */
#define	SATA_ATAPI_I_IO		0x02	/* IO direction */
#define	SATA_ATAPI_I_RELEASE	0x04	/* Release for ATAPI overlap */

/* ATAPI feature reg definitions */

#define	SATA_ATAPI_F_OVERLAP	0x02


/*
 * ATAPI IDENTIFY_DRIVE capabilities word
 */

#define	SATA_ATAPI_ID_CAP_DMA		0x0100
#define	SATA_ATAPI_ID_CAP_OVERLAP	0x2000

/*
 * ATAPI signature bits
 */
#define	SATA_ATAPI_SIG_HI	0xeb	/* in high cylinder register */
#define	SATA_ATAPI_SIG_LO	0x14	/* in low cylinder register */

/* These values are pre-set for CD_ROM/DVD ? */

#define	SATA_ATAPI_SECTOR_SIZE		2048
#define	SATA_ATAPI_MAX_BYTES_PER_DRQ	0xf800 /* 16 bits - 2KB  ie 62KB */
#define	SATA_ATAPI_HEADS		64
#define	SATA_ATAPI_SECTORS_PER_TRK	32

/* SATA Capabilites bits (word 76) */

#define	SATA_NCQ		0x100
#define	SATA_2_SPEED		0x004
#define	SATA_1_SPEED		0x002

/* SATA Features Supported (word 78) - not used */

/* SATA Features Enabled (word 79) - not used */

/*
 * Status bits from AT_STATUS register
 */
#define	SATA_STATUS_BSY		0x80    /* controller busy */
#define	SATA_STATUS_DRDY	0x40    /* drive ready 	*/
#define	SATA_STATUS_DF		0x20    /* device fault	*/
#define	SATA_STATUS_DSC    	0x10    /* seek operation complete */
#define	SATA_STATUS_DRQ		0x08	/* data request */
#define	SATA_STATUS_CORR	0x04    /* obsolete */
#define	SATA_STATUS_IDX		0x02    /* obsolete */
#define	SATA_STATUS_ERR		0x01    /* error flag */

/*
 * Status bits from AT_ERROR register
 */
#define	SATA_ERROR_ICRC		0x80	/* CRC data transfer error detected */
#define	SATA_ERROR_UNC		0x40	/* uncorrectable data error */
#define	SATA_ERROR_MC		0x20    /* Media change	*/
#define	SATA_ERROR_IDNF		0x10    /* ID/Address not found	*/
#define	SATA_ERROR_MCR		0x08	/* media change request	*/
#define	SATA_ERROR_ABORT	0x04    /* aborted command */
#define	SATA_ERROR_NM		0x02	/* no media */
#define	SATA_ERROR_EOM		0x02    /* end of media (Packet cmds) */
#define	SATA_ERROR_ILI		0x01    /* cmd sepcific */

/* device_reg */
#define	SATA_ADH_LBA		0x40	/* addressing in LBA mode not chs */

#ifdef	__cplusplus
}
#endif

#endif /* _SATA_DEFS_H */
