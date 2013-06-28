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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _SATA_DEFS_H
#define	_SATA_DEFS_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/scsi/generic/mode.h>

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
#define	SATAC_STANDBY		0xe2	/* standby */

/*
 * ATA/ATAPI disk commands (subset)
 */
#define	SATAC_DSM		0x06	/* Data Set Management */
#define	SATAC_DEVICE_RESET	0x08    /* ATAPI device reset */
#define	SATAC_DOWNLOAD_MICROCODE 0x92   /* Download microcode */
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

#define	SATAC_SMART		0xb0	/* SMART */

#define	SATA_LOG_PAGE_10	0x10	/* log page 0x10 - SATA error */
/*
 * Port Multiplier Commands
 */
#define	SATAC_READ_PORTMULT	0xe4	/* read port multiplier */
#define	SATAC_WRITE_PORTMULT	0xe8	/* write port multiplier */

/*
 * Power Managment Commands (subset)
 */
#define	SATAC_CHECK_POWER_MODE	0xe5	/* check power mode */

#define	SATA_PWRMODE_STANDBY		0	/* standby mode */
#define	SATA_PWRMODE_IDLE		0x80	/* idle mode */
#define	SATA_PWRMODE_ACTIVE_SPINDOWN	0x40	/* PM0 and spinning down */
#define	SATA_PWRMODE_ACTIVE_SPINUP	0x41	/* PM0 and spinning up */
#define	SATA_PWRMODE_ACTIVE		0xFF	/* active or idle mode */


/*
 * SMART FEATURES Subcommands
 */
#define	SATA_SMART_READ_DATA		0xd0
#define	SATA_SMART_ATTR_AUTOSAVE	0xd2
#define	SATA_SMART_EXECUTE_OFFLINE_IMM	0xd4
#define	SATA_SMART_READ_LOG		0xd5
#define	SATA_SMART_WRITE_LOG		0xd6
#define	SATA_SMART_ENABLE_OPS		0xd8
#define	SATA_SMART_DISABLE_OPS		0xd9
#define	SATA_SMART_RETURN_STATUS	0xda

/*
 * SET FEATURES Subcommands
 */
#define	SATAC_SF_ENABLE_WRITE_CACHE	0x02
#define	SATAC_SF_TRANSFER_MODE		0x03
#define	SATAC_SF_DISABLE_RMSN		0x31
#define	SATAC_SF_ENABLE_ACOUSTIC	0x42
#define	SATAC_SF_DISABLE_READ_AHEAD	0x55
#define	SATAC_SF_DISABLE_WRITE_CACHE	0x82
#define	SATAC_SF_ENABLE_READ_AHEAD	0xaa
#define	SATAC_SF_DISABLE_ACOUSTIC	0xc2
#define	SATAC_SF_ENABLE_RMSN		0x95

/*
 * SET FEATURES transfer mode values
 */
#define	SATAC_TRANSFER_MODE_PIO_DEFAULT		0x00
#define	SATAC_TRANSFER_MODE_PIO_DISABLE_IODRY	0x01
#define	SATAC_TRANSFER_MODE_PIO_FLOW_CONTROL	0x08
#define	SATAC_TRANSFER_MODE_MULTI_WORD_DMA	0x20
#define	SATAC_TRANSFER_MODE_ULTRA_DMA		0x40

/*
 * Download microcode subcommands
 */
#define	SATA_DOWNLOAD_MCODE_TEMP	1	/* Revert on/ reset/pwr cycle */
#define	SATA_DOWNLOAD_MCODE_SAVE	7	/* No offset, keep mcode */


/* Generic ATA definitions */

#define	SATA_TAG_QUEUING_SHIFT 3
#define	SATA_TAG_QUEUING_MASK 0x1f
/*
 * Identify Device data
 * Although both ATA and ATAPI devices' Identify Data have the same length,
 * some words have different meaning/content and/or are irrelevant for
 * other type of device.
 * Following is the ATA Device Identify data layout
 */
typedef struct sata_id {
/*					WORD				  */
/*					OFFSET COMMENT			  */
	ushort_t  ai_config;	   /*   0  general configuration bits	  */
	ushort_t  ai_fixcyls;	   /*   1  # of cylinders (obsolete)	  */
	ushort_t  ai_resv0;	   /*   2  # reserved			  */
	ushort_t  ai_heads;	   /*   3  # of heads (obsolete)	  */
	ushort_t  ai_trksiz;	   /*   4  # of bytes/track (retired)	  */
	ushort_t  ai_secsiz;	   /*   5  # of bytes/sector (retired)	  */
	ushort_t  ai_sectors;	   /*   6  # of sectors/track (obsolete)  */
	ushort_t  ai_resv1[3];	   /*   7  "Vendor Unique"		  */
	char	ai_drvser[20];	   /*  10  Serial number		  */
	ushort_t ai_buftype;	   /*  20  Buffer type			  */
	ushort_t ai_bufsz;	   /*  21  Buffer size in 512 byte incr   */
	ushort_t ai_ecc;	   /*  22  # of ecc bytes avail on rd/wr  */
	char	ai_fw[8];	   /*  23  Firmware revision		  */
	char	ai_model[40];	   /*  27  Model #			  */
	ushort_t ai_mult1;	   /*  47  Multiple command flags	  */
	ushort_t ai_dwcap;	   /*  48  Doubleword capabilities	  */
	ushort_t ai_cap;	   /*  49  Capabilities			  */
	ushort_t ai_resv2;	   /*  50  Reserved			  */
	ushort_t ai_piomode;	   /*  51  PIO timing mode		  */
	ushort_t ai_dmamode;	   /*  52  DMA timing mode		  */
	ushort_t ai_validinfo;	   /*  53  bit0: wds 54-58, bit1: 64-70	  */
	ushort_t ai_curcyls;	   /*  54  # of current cylinders	  */
	ushort_t ai_curheads;	   /*  55  # of current heads		  */
	ushort_t ai_cursectrk;	   /*  56  # of current sectors/track	  */
	ushort_t ai_cursccp[2];	   /*  57  current sectors capacity	  */
	ushort_t ai_mult2;	   /*  59  multiple sectors info	  */
	ushort_t ai_addrsec[2];	   /*  60  LBA only: no of addr secs	  */
	ushort_t ai_dirdma;	   /*  62  valid in ATA/ATAPI7, DMADIR	  */
	ushort_t ai_dworddma;	   /*  63  multi word dma modes	  */
	ushort_t ai_advpiomode;	   /*  64  advanced PIO modes supported	  */
	ushort_t ai_minmwdma;	   /*  65  min multi-word dma cycle info  */
	ushort_t ai_recmwdma;	   /*  66  rec multi-word dma cycle info  */
	ushort_t ai_minpio;	   /*  67  min PIO cycle info		  */
	ushort_t ai_minpioflow;	   /*  68  min PIO cycle info w/flow ctl  */
	ushort_t ai_addsupported;  /*  69  additional supported		  */
	ushort_t ai_resv3;	   /*  70 reserved			  */
	ushort_t ai_typtime[2];	   /* 71-72 timing			  */
	ushort_t ai_resv4[2];	   /* 73-74 reserved			  */
	ushort_t ai_qdepth;	   /*  75  queue depth			  */
	ushort_t ai_satacap;	   /*  76  SATA capabilities		  */
	ushort_t ai_resv5;	   /*  77 reserved			  */
	ushort_t ai_satafsup;	   /*  78 SATA features supported	  */
	ushort_t ai_satafenbl;	   /*  79 SATA features enabled		  */
	ushort_t ai_majorversion;  /*  80  major versions supported	  */
	ushort_t ai_minorversion;  /*  81  minor version number supported */
	ushort_t ai_cmdset82;	   /*  82  command set supported	  */
	ushort_t ai_cmdset83;	   /*  83  more command sets supported	  */
	ushort_t ai_cmdset84;	   /*  84  more command sets supported	  */
	ushort_t ai_features85;	   /*  85 enabled features		  */
	ushort_t ai_features86;	   /*  86 enabled features		  */
	ushort_t ai_features87;	   /*  87 enabled features		  */
	ushort_t ai_ultradma;	   /*  88 Ultra DMA mode		  */
	ushort_t ai_erasetime;	   /*  89 security erase time		  */
	ushort_t ai_erasetimex;	   /*  90 enhanced security erase time	  */
	ushort_t ai_adv_pwr_mgmt;  /*  91 advanced power management time  */
	ushort_t ai_master_pwd;    /*  92 master password revision code   */
	ushort_t ai_hrdwre_reset;  /*  93 hardware reset result		  */
	ushort_t ai_acoustic;	   /*  94 accoustic management values	  */
	ushort_t ai_stream_min_sz; /*  95 stream minimum request size	  */
	ushort_t ai_stream_xfer_d; /*  96 streaming transfer time (DMA)   */
	ushort_t ai_stream_lat;    /*  97 streaming access latency	  */
	ushort_t ai_streamperf[2]; /* 98-99 streaming performance gran.   */
	ushort_t ai_addrsecxt[4];  /* 100 extended max LBA sector	  */
	ushort_t ai_stream_xfer_p; /* 104 streaming transfer time (PIO)   */
	ushort_t ai_maxcount;	   /* 105 max count of 512-byte blocks of */
				    /* LBA range entries		  */
	ushort_t ai_phys_sect_sz;  /* 106 physical sector size		  */
	ushort_t ai_seek_delay;	   /* 107 inter-seek delay time (usecs)	  */
	ushort_t ai_naa_ieee_oui;  /* 108 NAA/IEEE OUI			  */
	ushort_t ai_ieee_oui_uid;  /* 109 IEEE OUT/unique id		  */
	ushort_t ai_uid_mid;	   /* 110 unique id (mid)		  */
	ushort_t ai_uid_low;	   /* 111 unique id (low)		  */
	ushort_t ai_resv_wwn[4];   /* 112-115 reserved for WWN ext.	  */
	ushort_t ai_incits;	   /* 116 reserved for INCITS TR-37-2004  */
	ushort_t ai_words_lsec[2]; /* 117-118 words per logical sector	  */
	ushort_t ai_cmdset119;	   /* 119 more command sets supported	  */
	ushort_t ai_features120;   /* 120 enabled features		  */
	ushort_t ai_padding1[6];   /* pad to 126			  */
	ushort_t ai_rmsn;	   /* 127 removable media notification	  */
	ushort_t ai_securestatus;  /* 128 security status		  */
	ushort_t ai_vendor[31];	   /* 129-159 vendor specific		  */
	ushort_t ai_padding2[8];   /* 160 pad to 168			  */
	ushort_t ai_nomformfactor; /* 168 nominal form factor		  */
	ushort_t ai_dsm;	   /* 169 data set management		  */
	ushort_t ai_padding3[6];   /* 170 pad to 176			  */
	ushort_t ai_curmedser[30]; /* 176-205 current media serial #	  */
	ushort_t ai_sctsupport;	   /* 206 SCT command transport		  */
	ushort_t ai_padding4[10];  /* 207 pad to 217			  */
	ushort_t ai_medrotrate;	   /* 217 nominal media rotation rate	  */
	ushort_t ai_padding5[37];  /* 218 pad to 255			  */
	ushort_t ai_integrity;	   /* 255 integrity word		  */
} sata_id_t;


/* Identify Device: general config bits  - word 0 */

#define	SATA_ATA_TYPE_MASK	0x8001	/* ATA Device type mask */
#define	SATA_ATA_TYPE		0x0000	/* ATA device */
#define	SATA_REM_MEDIA		0x0080	/* Removable media */
#define	SATA_INCOMPLETE_DATA	0x0004	/* Incomplete Identify Device data */
#define	SATA_CFA_TYPE		0x848a	/* CFA feature set device */

#define	SATA_ID_SERIAL_OFFSET	10
#define	SATA_ID_SERIAL_LEN	20
#define	SATA_ID_MODEL_OFFSET	27
#define	SATA_ID_MODEL_LEN	40
#define	SATA_ID_FW_LEN		8
#define	SATA_ID_BDC_LEN		0x3c
#define	SATA_ID_ATA_INFO_LEN	0x238

/* Identify Device: common capability bits - word 49 */

#define	SATA_DMA_SUPPORT	0x0100
#define	SATA_LBA_SUPPORT	0x0200
#define	SATA_IORDY_DISABLE	0x0400
#define	SATA_IORDY_SUPPORT	0x0800
#define	SATA_STANDBYTIMER	0x2000

/* Identify Device: ai_validinfo (word 53) */

#define	SATA_VALIDINFO_88	0x0004	/* word 88 supported fields valid */
#define	SATA_VALIDINFO_70_64	0x0004	/* words 70-64 fields valid */

/* Identify Device: ai_addsupported (word 69) */

#define	SATA_DETERMINISTIC_READ	0x4000	/* word 69 deterministic read supp. */
#define	SATA_READ_ZERO		0x0020	/* word 69 read zero after TRIM supp. */

/* Identify Device: ai_majorversion (word 80) */

#define	SATA_MAJVER_7		0x0080	/* ATA/ATAPI-7 version supported */
#define	SATA_MAJVER_654		0x0070	/* ATA/ATAPI-6,5 or 4 ver supported */
#define	SATA_MAJVER_6		0x0040	/* ATA/ATAPI-6 version supported */
#define	SATA_MAJVER_5		0x0020	/* ATA/ATAPI-7 version supported */
#define	SATA_MAJVER_4		0x0010	/* ATA/ATAPI-4 version supported */

/* Identify Device: command set supported/enabled bits - words 83 and 86 */

#define	SATA_EXT48		0x0400	/* 48 bit address feature */
#define	SATA_PWRUP_IN_STANDBY	0x0020	/* Power-up in standby mode supp/en */
#define	SATA_RM_STATUS_NOTIFIC	0x0010	/* Removable Media Stat Notification */
#define	SATA_RW_DMA_QUEUED_CMD	0x0002	/* R/W DMA Queued supported */
#define	SATA_DWNLOAD_MCODE_CMD	0x0001	/* Download Microcode CMD supp/enbld */
#define	SATA_ACOUSTIC_MGMT	0x0200	/* Acoustic Management features */

/* Identify Device: command set supported/enabled bits - words 82 and 85 */

#define	SATA_SMART_SUPPORTED	0x0001	/* SMART feature set is supported */
#define	SATA_WRITE_CACHE	0x0020	/* Write Cache supported/enabled */
#define	SATA_LOOK_AHEAD		0x0040	/* Look Ahead supported/enabled */
#define	SATA_DEVICE_RESET_CMD	0x0200	/* Device Reset CMD supported/enbld */
#define	SATA_READ_BUFFER_CMD	0x2000	/* Read Buffer CMD supported/enbld */
#define	SATA_WRITE_BUFFER_CMD	0x1000	/* Write Buffer CMD supported/enbld */
#define	SATA_SMART_ENABLED	0x0001	/* SMART feature set is enabled */

/* Identify Device: command set supported/enabled bits - words 84 & 87 */
#define	SATA_SMART_SELF_TEST_SUPPORTED	0x0002	/* SMART self-test supported */
/* IDLE IMMEDIATE with UNLOAD FEATURE supported */
#define	SATA_IDLE_UNLOAD_SUPPORTED	0x2000

/* Identify Device: physical sector size - word 106 */
#define	SATA_L2PS_CHECK_BIT	0x4000	/* Set when this word valid */
#define	SATA_L2PS_HAS_MULT	0x2000	/* Multiple logical sectors per phys */
#define	SATA_L2PS_BIG_SECTORS	0x1000	/* Logical sector size > 512 */
#define	SATA_L2PS_EXP_MASK	0x000f	/* Logical sectors per phys exponent */

/* Identify (Packet) Device word 63,  ATA/ATAPI-6 & 7 */
#define	SATA_MDMA_SEL_MASK	0x0700	/* Multiword DMA selected */
#define	SATA_MDMA_2_SEL		0x0400	/* Multiword DMA mode 2 selected */
#define	SATA_MDMA_1_SEL		0x0200	/* Multiword DMA mode 1 selected */
#define	SATA_MDMA_0_SEL		0x0100	/* Multiword DMA mode 0 selected */
#define	SATA_MDMA_2_SUP		0x0004	/* Multiword DMA mode 2 supported */
#define	SATA_MDMA_1_SUP		0x0002	/* Multiword DMA mode 1 supported */
#define	SATA_MDMA_0_SUP		0x0001	/* Multiword DMA mode 0 supported */
#define	SATA_MDMA_SUP_MASK	0x0007	/* Multiword DMA supported */

/* Identify (Packet) Device Word 88 */
#define	SATA_UDMA_SUP_MASK		0x007f	/* UDMA modes supported */
#define	SATA_UDMA_SEL_MASK	0x7f00	/* UDMA modes selected */

/* Identify Device: command set supported/enabled bits - word 206 */

/* All are SCT Command Transport support */
#define	SATA_SCT_CMD_TRANS_SUP		0x0001	/* anything */
#define	SATA_SCT_CMD_TRANS_LNG_SECT_SUP	0x0002	/* Long Sector Access */
#define	SATA_SCT_CMD_TRANS_WR_SAME_SUP	0x0004	/* Write Same */
#define	SATA_SCT_CMD_TRANS_ERR_RCOV_SUP	0x0008	/* Error Recovery Control */
#define	SATA_SCT_CMD_TRANS_FEAT_CTL_SUP	0x0010	/* Features Control */
#define	SATA_SCT_CMD_TRANS_DATA_TBL_SUP	0x0020	/* Data Tables supported */

#define	SATA_DISK_SECTOR_SIZE	512	/* HD physical sector size */

/* Identify Packet Device data definitions (ATAPI devices) */

/* Identify Packet Device: general config bits  - word 0 */

#define	SATA_ATAPI_TYPE_MASK	0xc000
#define	SATA_ATAPI_TYPE		0x8000	/* ATAPI device */
#define	SATA_ATAPI_ID_PKT_SZ	0x0003	/* Packet size mask */
#define	SATA_ATAPI_ID_PKT_12B	0x0000  /* Packet size 12 bytes */
#define	SATA_ATAPI_ID_PKT_16B	0x0001  /* Packet size 16 bytes */
#define	SATA_ATAPI_ID_DRQ_TYPE	0x0060	/* DRQ asserted in 3ms after pkt */
#define	SATA_ATAPI_ID_DRQ_INTR	0x0020  /* Obsolete in ATA/ATAPI 7 */

#define	SATA_ATAPI_ID_DEV_TYPE	0x1f00	/* device type/command set mask */
#define	SATA_ATAPI_ID_DEV_SHFT	8
#define	SATA_ATAPI_DIRACC_DEV	0x0000	/* Direct Access device */
#define	SATA_ATAPI_SQACC_DEV	0x0100  /* Sequential access dev (tape ?) */
#define	SATA_ATAPI_PROC_DEV	0x0300	/* Processor device */
#define	SATA_ATAPI_CDROM_DEV	0x0500  /* CD_ROM device */

/*
 * Status bits from ATAPI Interrupt reason register (AT_COUNT) register
 */
#define	SATA_ATAPI_I_COD	0x01	/* Command or Data */
#define	SATA_ATAPI_I_IO		0x02	/* IO direction */
#define	SATA_ATAPI_I_RELEASE	0x04	/* Release for ATAPI overlap */

/* ATAPI feature reg definitions */

#define	SATA_ATAPI_F_DATA_DIR_READ 0x04	/* DMA transfer to the host */
#define	SATA_ATAPI_F_OVERLAP	0x02	/* Not used by Sun drivers */
#define	SATA_ATAPI_F_DMA	0x01	/* Packet DMA command */


/* ATAPI IDENTIFY_DRIVE capabilities word (49) */

#define	SATA_ATAPI_ID_CAP_DMA		0x0100 /* if zero, check word 62  */
#define	SATA_ATAPI_ID_CAP_OVERLAP	0x2000

/*
 * ATAPI Identify Packet Device word 62
 * Word 62 is not valid for ATA/ATAPI-6
 * Defs below are for ATA/ATAPI-7
 */
#define	SATA_ATAPI_ID_DMADIR_REQ	0x8000 /* DMA direction required */
#define	SATA_ATAPI_ID_DMA_SUP		0x0400 /* DMA is supported */

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
#define	SATA_3_SPEED		0x008
#define	SATA_2_SPEED		0x004
#define	SATA_1_SPEED		0x002

/* SATA Features Supported (word 78) - not used */

/* SATA Features Enabled (word 79) - not used */

#define	SATA_READ_AHEAD_SUPPORTED(x)	((x).ai_cmdset82 & SATA_LOOK_AHEAD)
#define	SATA_READ_AHEAD_ENABLED(x)	((x).ai_features85 & SATA_LOOK_AHEAD)
#define	SATA_WRITE_CACHE_SUPPORTED(x)	((x).ai_cmdset82 & SATA_WRITE_CACHE)
#define	SATA_WRITE_CACHE_ENABLED(x)	((x).ai_features85 & SATA_WRITE_CACHE)
#define	SATA_RM_NOTIFIC_SUPPORTED(x)	\
	((x).ai_cmdset83 & SATA_RM_STATUS_NOTIFIC)
#define	SATA_RM_NOTIFIC_ENABLED(x)	\
	((x).ai_features86 & SATA_RM_STATUS_NOTIFIC)

/*
 * Generic NCQ related defines
 */

#define	NQ			0x80	/* Not a queued cmd - tag not valid */
#define	NCQ_TAG_MASK		0x1f	/* NCQ command tag mask */
#define	FIS_TYPE_REG_H2D	0x27	/* Reg FIS - Host to Device */
#define	FIS_CMD_UPDATE		0x80
/*
 * Status bits from AT_STATUS register
 */
#define	SATA_STATUS_BSY		0x80    /* controller busy */
#define	SATA_STATUS_DRDY	0x40    /* drive ready	*/
#define	SATA_STATUS_DF		0x20    /* device fault	*/
#define	SATA_STATUS_DSC		0x10    /* seek operation complete */
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


/*
 * Bits from the device control register
 */
#define	SATA_DEVCTL_NIEN	0x02	/* not interrupt enabled */
#define	SATA_DEVCTL_SRST	0x04	/* software reset */
#define	SATA_DEVCTL_HOB		0x80	/* high order bit */

/* device_reg */
#define	SATA_ADH_LBA		0x40	/* addressing in LBA mode not chs */

/* ATAPI transport version-in Inquiry data */
#define	SATA_ATAPI_TRANS_VERSION(inq) \
	(*((uint8_t *)(inq) + 3) >> 4)

#define	SCSI_LOG_PAGE_HDR_LEN	4	/* # bytes of a SCSI log page header */
#define	SCSI_LOG_PARAM_HDR_LEN	4	/* # byttes of a SCSI log param hdr */

/* Number of log entries per extended selftest log block */
#define	ENTRIES_PER_EXT_SELFTEST_LOG_BLK	19

/* Number of entries per SCSI LOG SENSE SELFTEST RESULTS page */
#define	SCSI_ENTRIES_IN_LOG_SENSE_SELFTEST_RESULTS	20

/* Length of a SCSI LOG SENSE SELFTEST RESULTS parameter */
#define	SCSI_LOG_SENSE_SELFTEST_PARAM_LEN	0x10

#define	DIAGNOSTIC_FAILURE_ON_COMPONENT	0x40

#define	SCSI_COMPONENT_81	0x81
#define	SCSI_COMPONENT_82	0x82
#define	SCSI_COMPONENT_83	0x83
#define	SCSI_COMPONENT_84	0x84
#define	SCSI_COMPONENT_85	0x85
#define	SCSI_COMPONENT_86	0x86
#define	SCSI_COMPONENT_87	0x87
#define	SCSI_COMPONENT_88	0x88

#define	SCSI_ASC_ATA_DEV_FEAT_NOT_ENABLED	0x67
#define	SCSI_ASCQ_ATA_DEV_FEAT_NOT_ENABLED	0x0b

#define	SCSI_PREDICTED_FAILURE	0x5d
#define	SCSI_GENERAL_HD_FAILURE	0x10

#define	SCSI_INFO_EXCEPTIONS_PARAM_LEN	4

#define	READ_LOG_EXT_LOG_DIRECTORY	0
#define	READ_LOG_EXT_NCQ_ERROR_RECOVERY	0x10
#define	SMART_SELFTEST_LOG_PAGE		6
#define	EXT_SMART_SELFTEST_LOG_PAGE	7

/*
 * SATA NCQ error recovery page (0x10)
 */
struct sata_ncq_error_recovery_page {
	uint8_t	ncq_tag;
	uint8_t reserved1;
	uint8_t ncq_status;
	uint8_t ncq_error;
	uint8_t ncq_sector_number;
	uint8_t ncq_cyl_low;
	uint8_t ncq_cyl_high;
	uint8_t ncq_dev_head;
	uint8_t ncq_sector_number_ext;
	uint8_t ncq_cyl_low_ext;
	uint8_t ncq_cyl_high_ext;
	uint8_t reserved2;
	uint8_t ncq_sector_count;
	uint8_t ncq_sector_count_ext;
	uint8_t reserved3[242];
	uint8_t ncq_vendor_unique[255];
	uint8_t ncq_checksum;
};

/* SMART attribute of Start/Stop Count */
#define	SMART_START_STOP_COUNT_ID	0x4

/*
 * SMART data structures
 */
struct smart_data {
	uint8_t smart_vendor_specific[362];
	uint8_t smart_offline_data_collection_status;
	uint8_t smart_selftest_exec_status;
	uint8_t smart_secs_to_complete_offline_data[2];
	uint8_t smart_vendor_specific2;
	uint8_t smart_offline_data_collection_capability;
	uint8_t smart_capability[2];
	uint8_t	smart_error_logging_capability;
	uint8_t smart_vendor_specific3;
	uint8_t smart_short_selftest_polling_time;
	uint8_t smart_extended_selftest_polling_time;
	uint8_t smart_conveyance_selftest_polling_time;
	uint8_t smart_reserved[11];
	uint8_t smart_vendor_specific4[125];
	uint8_t smart_checksum;
};

struct smart_selftest_log_entry {
	uint8_t	smart_selftest_log_lba_low;
	uint8_t	smart_selftest_log_status;
	uint8_t	smart_selftest_log_timestamp[2];
	uint8_t smart_selftest_log_checkpoint;
	uint8_t smart_selftest_log_failing_lba[4];	/* from LSB to MSB */
	uint8_t smart_selftest_log_vendor_specific[15];
};

#define	NUM_SMART_SELFTEST_LOG_ENTRIES	21
struct smart_selftest_log {
	uint8_t	smart_selftest_log_revision[2];
	struct	smart_selftest_log_entry
	    smart_selftest_log_entries[NUM_SMART_SELFTEST_LOG_ENTRIES];
	uint8_t	smart_selftest_log_vendor_specific[2];
	uint8_t smart_selftest_log_index;
	uint8_t smart_selftest_log_reserved[2];
	uint8_t smart_selftest_log_checksum;
};

struct smart_ext_selftest_log_entry {
	uint8_t	smart_ext_selftest_log_lba_low;
	uint8_t smart_ext_selftest_log_status;
	uint8_t smart_ext_selftest_log_timestamp[2];
	uint8_t smart_ext_selftest_log_checkpoint;
	uint8_t smart_ext_selftest_log_failing_lba[6];
	uint8_t smart_ext_selftest_log_vendor_specific[15];
};

struct smart_ext_selftest_log {
	uint8_t	smart_ext_selftest_log_rev;
	uint8_t	smart_ext_selftest_log_reserved;
	uint8_t	smart_ext_selftest_log_index[2];
	struct smart_ext_selftest_log_entry smart_ext_selftest_log_entries[19];
	uint8_t	smart_ext_selftest_log_vendor_specific[2];
	uint8_t	smart_ext_selftest_log_reserved2[11];
	uint8_t	smart_ext_selftest_log_checksum;
};

struct read_log_ext_directory {
	uint8_t	read_log_ext_vers[2];	/* general purpose log version */
	uint8_t read_log_ext_nblks[255][2]; /* # of blks @ log addr index+1 */
};

/*
 * The definition of CONTROL byte field in SCSI command
 * according to SAM 5
 */
#define	CTL_BYTE_VENDOR_MASK		0xc0
#define	CTL_BYTE_NACA_MASK		0x04

/*
 * The definition of mask in START STOP UNIT command
 */
#define	START_STOP_IMMED_MASK		0x01
#define	START_STOP_POWER_COND_MASK	0xF0
#define	START_STOP_START_MASK		0x01
#define	START_STOP_LOEJ_MASK		0x02
#define	START_STOP_NOFLUSH_MASK		0x04
#define	START_STOP_MODIFIER_MASK	0x0f
#define	START_STOP_POWER_COND_SHIFT	4

/*
 * SMART specific data
 * These eventually need to go to a generic scsi header file
 * for now they will reside here
 */
#define	PC_CUMULATIVE_VALUES			0x01
#define	PAGE_CODE_GET_SUPPORTED_LOG_PAGES	0x00
#define	PAGE_CODE_SELF_TEST_RESULTS		0x10
#define	PAGE_CODE_INFORMATION_EXCEPTIONS	0x2f
#define	PAGE_CODE_SMART_READ_DATA		0x30
#define	PAGE_CODE_START_STOP_CYCLE_COUNTER	0x0e


struct log_parameter {
	uint8_t param_code[2];		/* parameter dependant */
	uint8_t param_ctrl_flags;	/* see defines below */
	uint8_t param_len;		/* # of bytes following */
	uint8_t param_values[1];	/* # of bytes defined by param_len */
};

/* param_ctrl_flag fields */
#define	LOG_CTRL_LP	0x01	/* list parameter */
#define	LOG_CTRL_LBIN	0x02	/* list is binary */
#define	LOG_CTRL_TMC	0x0c	/* threshold met criteria */
#define	LOG_CTRL_ETC	0x10	/* enable threshold comparison */
#define	LOG_CTRL_TSD	0x20	/* target save disable */
#define	LOG_CTRL_DS	0x40	/* disable save */
#define	LOG_CTRL_DU	0x80	/* disable update */

#define	SMART_MAGIC_VAL_1	0x4f
#define	SMART_MAGIC_VAL_2	0xc2
#define	SMART_MAGIC_VAL_3	0xf4
#define	SMART_MAGIC_VAL_4	0x2c

#define	SCT_STATUS_LOG_PAGE	0xe0

/*
 * Acoustic management
 */

struct mode_acoustic_management {
	struct mode_page	mode_page;	/* common mode page header */
	uchar_t	acoustic_manag_enable;	/* Set to 1 enable, Set 0 disable */
	uchar_t	acoustic_manag_level;	/* Acoustic management level	  */
	uchar_t	vendor_recommended_value; /* Vendor recommended value	  */
};

#define	PAGELENGTH_DAD_MODE_ACOUSTIC_MANAGEMENT 3 /* Acoustic manag pg len */
#define	P_CNTRL_CURRENT		0
#define	P_CNTRL_CHANGEABLE	1
#define	P_CNTRL_DEFAULT		2
#define	P_CNTRL_SAVED		3

#define	ACOUSTIC_DISABLED	0
#define	ACOUSTIC_ENABLED	1

#define	MODEPAGE_ACOUSTIC_MANAG 0x30

/*
 * Port Multiplier registers' offsets
 */
#define	SATA_PMULT_GSCR0		0x0
#define	SATA_PMULT_GSCR1		0x1
#define	SATA_PMULT_GSCR2		0x2
#define	SATA_PMULT_GSCR32		0x20
#define	SATA_PMULT_GSCR33		0x21
#define	SATA_PMULT_GSCR64		0x40
#define	SATA_PMULT_GSCR96		0x60

#define	SATA_PMULT_PORTNUM_MASK		0xf

#define	SATA_PMULT_PSCR0		0x0
#define	SATA_PMULT_PSCR1		0x1
#define	SATA_PMULT_PSCR2		0x2
#define	SATA_PMULT_PSCR3		0x3
#define	SATA_PMULT_PSCR4		0x4

#define	SATA_PMULT_REG_SSTS		(SATA_PMULT_PSCR0)
#define	SATA_PMULT_REG_SERR		(SATA_PMULT_PSCR1)
#define	SATA_PMULT_REG_SCTL		(SATA_PMULT_PSCR2)
#define	SATA_PMULT_REG_SACT		(SATA_PMULT_PSCR3)
#define	SATA_PMULT_REG_SNTF		(SATA_PMULT_PSCR4)

/*
 * Port Multiplier capabilities
 * (Indicated by GSCR64, and enabled by GSCR96)
 */
#define	SATA_PMULT_CAP_BIST		(1 << 0)
#define	SATA_PMULT_CAP_PMREQ		(1 << 1)
#define	SATA_PMULT_CAP_SSC		(1 << 2)
#define	SATA_PMULT_CAP_SNOTIF		(1 << 3)
#define	SATA_PMULT_CAP_PHYEVENT		(1 << 4)

/*
 * sstatus field definitions
 */
#define	SSTATUS_DET_SHIFT	0
#define	SSTATUS_SPD_SHIFT	4
#define	SSTATUS_IPM_SHIFT	8

#define	SSTATUS_DET	(0xf << SSTATUS_DET_SHIFT)
#define	SSTATUS_SPD	(0xf << SSTATUS_SPD_SHIFT)
#define	SSTATUS_IPM	(0xf << SSTATUS_IPM_SHIFT)

/*
 * sstatus DET values
 */
#define	SSTATUS_DET_NODEV		0	/* No dev detected */
#define	SSTATUS_DET_DEVPRE_NOPHYCOM	1	/* dev detected */
#define	SSTATUS_DET_DEVPRE_PHYCOM	3	/* dev detected */
#define	SSTATUS_DET_PHYOFFLINE		4	/* PHY is in offline */

#define	SSTATUS_GET_DET(x) \
	(x & SSTATUS_DET)

#define	SSTATUS_SET_DET(x, new_val) \
	(x = (x & ~SSTATUS_DET) | (new_val & SSTATUS_DET))

#define	SSTATUS_SPD_NODEV	0 /* No device present */
#define	SSTATUS_SPD_GEN1	1 /* Gen 1 rate negotiated */
#define	SSTATUS_SPD_GEN2	2 /* Gen 2 rate negotiated */
#define	SSTATUS_SPD_GEN3	3 /* Gen 3 rate negotiated */

/*
 * sstatus IPM values
 */
#define	SSTATUS_IPM_NODEV_NOPHYCOM	0x0 /* No dev, no PHY */
#define	SSTATUS_IPM_ACTIVE		0x1 /* Interface active */
#define	SSTATUS_IPM_POWERPARTIAL	0x2 /* partial power mgmnt */
#define	SSTATUS_IPM_POWERSLUMBER	0x6 /* slumber power mgmt */

#define	SSTATUS_GET_IPM(x) \
	((x & SSTATUS_IPM) >> SSTATUS_IPM_SHIFT)

#define	SSTATUS_SET_IPM(x, new_val) \
	(x = (x & ~SSTATUS_IPM) | \
	((new_val << SSTATUS_IPM_SHIFT) & SSTATUS_IPM))


/*
 * serror register fields
 */
#define	SERROR_DATA_ERR_FIXED	(1 << 0) /* D integrity err */
#define	SERROR_COMM_ERR_FIXED	(1 << 1) /* comm err recov */
#define	SERROR_DATA_ERR		(1 << 8) /* D integrity err */
#define	SERROR_PERSISTENT_ERR	(1 << 9)  /* norecov com err */
#define	SERROR_PROTOCOL_ERR	(1 << 10) /* protocol err */
#define	SERROR_INT_ERR		(1 << 11) /* internal err */
#define	SERROR_PHY_RDY_CHG	(1 << 16) /* PHY state change */
#define	SERROR_PHY_INT_ERR	(1 << 17) /* PHY internal err */
#define	SERROR_COMM_WAKE	(1 << 18) /* COM wake */
#define	SERROR_10B_TO_8B_ERR	(1 << 19) /* 10B-to-8B decode */
#define	SERROR_DISPARITY_ERR	(1 << 20) /* disparity err */
#define	SERROR_CRC_ERR		(1 << 21) /* CRC err */
#define	SERROR_HANDSHAKE_ERR	(1 << 22) /* Handshake err */
#define	SERROR_LINK_SEQ_ERR	(1 << 23) /* Link seq err */
#define	SERROR_TRANS_ERR	(1 << 24) /* Tran state err */
#define	SERROR_FIS_TYPE		(1 << 25) /* FIS type err */
#define	SERROR_EXCHANGED_ERR	(1 << 26) /* Device exchanged */

/*
 * S-Control Bridge port x register fields
 */
#define	SCONTROL_DET_SHIFT	0
#define	SCONTROL_SPD_SHIFT	4
#define	SCONTROL_IPM_SHIFT	8
#define	SCONTROL_SPM_SHIFT	12

#define	SCONTROL_DET		(0xf << SCONTROL_DET_SHIFT)
#define	SCONTROL_SPD		(0xf << SCONTROL_SPD_SHIFT)
#define	SCONTROL_IPM		(0xf << SCONTROL_IPM_SHIFT)
#define	SCONTROL_SPM		(0xf << SCONTROL_SPM_SHIFT)

#define	SCONTROL_GET_DET(x)	\
	(x & SCONTROL_DET)

#define	SCONTROL_SET_DET(x, new_val)    \
	(x = (x & ~SCONTROL_DET) | (new_val & SCONTROL_DET))

#define	SCONTROL_DET_NOACTION	0 /* Do nothing to port */
#define	SCONTROL_DET_COMRESET	1 /* Re-initialize port */
#define	SCONTROL_DET_DISABLE	4 /* Disable port */

#define	SCONTROL_SPD_NOLIMIT	0 /* No speed limit */
#define	SCONTROL_SPD_GEN1	1 /* Limit Gen 1 rate */
#define	SCONTROL_SPD_GEN2	2 /* Limit Gen 2 rate */
#define	SCONTROL_SPD_GEN3	3 /* Limit Gen 3 rate */

#define	SCONTROL_GET_IPM(x)	\
	((x & SCONTROL_IPM) >> SCONTROL_IPM_SHIFT)

#define	SCONTROL_SET_IPM(x, new_val)	\
	(x = (x & ~SCONTROL_IPM) | \
	((new_val << SCONTROL_IPM_SHIFT) & SCONTROL_IPM))

#define	SCONTROL_IPM_NORESTRICT		0 /* No PM limit */
#define	SCONTROL_IPM_DISABLE_PARTIAL	1 /* Disable partial */
#define	SCONTROL_IPM_DISABLE_SLUMBER	2 /* Disable slumber */
#define	SCONTROL_IPM_DISABLE_BOTH	3 /* Disable both */

#define	SCONTROL_SPM_NORESTRICT		0 /* No PM limits */
#define	SCONTROL_SPM_DO_PARTIAL		1 /* Go to partial */
#define	SCONTROL_SPM_DO_SLUMBER		2 /* Go to slumber */
#define	SCONTROL_SPM_DO_ACTIVE		4 /* Go to active */

#ifdef	__cplusplus
}
#endif

#endif /* _SATA_DEFS_H */
