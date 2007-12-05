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

#ifndef _ATA_COMMON_H
#define	_ATA_COMMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/varargs.h>

#include <sys/scsi/scsi.h>
#include <sys/dktp/dadkio.h>
#include <sys/dktp/dadev.h>
#include <sys/dkio.h>
#include <sys/dktp/tgdk.h>

#include <sys/ddi.h>
#include <sys/sunddi.h>

#include "ghd.h"

#include "pciide.h"
#include "ata_cmd.h"
#include "ata_fsm.h"
#include "ata_debug.h"


/*
 * device types
 */
#define	ATA_DEV_NONE	0
#define	ATA_DEV_DISK	1
#define	ATA_DEV_ATAPI	2

/*
 * Largest sector allowed in 28 bit mode
 */
#define	MAX_28BIT_CAPACITY	0xfffffff

/*
 * Largest sector count allowed for device firmware file in one command.
 */
#define	MAX_FWFILE_SIZE_ONECMD	0xffff

/*
 * ata-options property configuration bits
 */

#define	ATA_OPTIONS_DMA		0x01

#define	ATAPRT(fmt)	ghd_err fmt

/* ad_flags (per-drive) */

#define	AD_ATAPI		0x01	/* is an ATAPI drive */
#define	AD_DISK			0x02
#define	AD_MUTEX_INIT		0x04
#define	AD_NO_CDB_INTR		0x20
#define	AD_1SECTOR		0x40
#define	AD_INT13LBA		0x80	/* supports LBA at Int13 interface */
#define	AD_NORVRT		0x100	/* block revert-to-defaults */
#define	AD_EXT48		0x200	/* 48 bit (extended) LBA */
#define	ATAPIDRV(X)  ((X)->ad_flags & AD_ATAPI)


/* max targets and luns */

#define	ATA_MAXTARG	2
#define	ATA_MAXLUN	16

/*
 * PCI-IDE Bus Mastering Scatter/Gather list size
 */
#define	ATA_DMA_NSEGS	17	/* enough for at least 64K */

/*
 * Controller port address defaults
 */
#define	ATA_BASE0	0x1f0
#define	ATA_BASE1	0x170

/*
 * port offsets from base address ioaddr1
 */
#define	AT_DATA		0x00	/* data register 			*/
#define	AT_ERROR	0x01	/* error register (read)		*/
#define	AT_FEATURE	0x01	/* features (write)			*/
#define	AT_COUNT	0x02    /* sector count 			*/
#define	AT_SECT		0x03	/* sector number 			*/
#define	AT_LCYL		0x04	/* cylinder low byte 			*/
#define	AT_HCYL		0x05	/* cylinder high byte 			*/
#define	AT_DRVHD	0x06    /* drive/head register 			*/
#define	AT_STATUS	0x07	/* status/command register 		*/
#define	AT_CMD		0x07	/* status/command register 		*/

/*
 * port offsets from base address ioaddr2
 */
#define	AT_ALTSTATUS	0x00	/* alternate status (read)		*/
#define	AT_DEVCTL	0x00	/* device control (write)		*/

/*	Device control register						*/
#define	ATDC_NIEN    	0x02    /* disable interrupts 			*/
#define	ATDC_SRST	0x04	/* controller reset			*/
#define	ATDC_D3		0x08	/* Mysterious bit, must be set  	*/
/*
 * ATA-6 spec
 * In 48-bit addressing, reading the LBA location and count
 * registers when the high-order bit is set reads the "previous
 * content" (LBA bits 47:24, count bits 15:8) instead of the
 * "most recent" values (LBA bits 23:0, count bits 7:0).
 */
#define	ATDC_HOB	0x80	/* High order bit			*/

/*
 * Status bits from AT_STATUS register
 */
#define	ATS_BSY		0x80    /* controller busy 			*/
#define	ATS_DRDY	0x40    /* drive ready 				*/
#define	ATS_DF		0x20    /* device fault				*/
#define	ATS_DSC    	0x10    /* seek operation complete 		*/
#define	ATS_DRQ		0x08	/* data request 			*/
#define	ATS_CORR	0x04    /* ECC correction applied 		*/
#define	ATS_IDX		0x02    /* disk revolution index 		*/
#define	ATS_ERR		0x01    /* error flag 				*/

/*
 * Status bits from AT_ERROR register
 */
#define	ATE_BBK_ICRC	0x80	/* bad block detected in ATA-1		*/
				/* ICRC error in ATA-4 and newer	*/
#define	ATE_UNC		0x40	/* uncorrectable data error		*/
#define	ATE_MC		0x20    /* Media change				*/
#define	ATE_IDNF	0x10    /* ID not found				*/
#define	ATE_MCR		0x08	/* media change request			*/
#define	ATE_ABORT	0x04    /* aborted command			*/
#define	ATE_TKONF	0x02    /* track 0 not found			*/
#define	ATE_AMNF	0x01    /* address mark not found		*/

#define	ATE_NM		0x02	/* no media				*/

/*
 * Drive selectors for AT_DRVHD register
 */
#define	ATDH_LBA	0x40	/* addressing in LBA mode not chs 	*/
#define	ATDH_DRIVE0	0xa0    /* or into AT_DRVHD to select drive 0 	*/
#define	ATDH_DRIVE1	0xb0    /* or into AT_DRVHD to select drive 1 	*/

/*
 * Feature register bits
 */
#define	ATF_ATAPI_DMA	0x01	/* ATAPI DMA enable bit */
#define	ATF_XFRMOD_UDMA	0x40	/* Ultra DMA mode	*/
#define	ATACM_UDMA_SEL(id)	(((id)->ai_ultradma >> 8) & 0x7f)

/*
 * Set feature register definitions.
 */
#define	ATSF_SET_XFRMOD	0X03	/* Set transfer mode			  */
#define	ATSF_DIS_REVPOD	0x66	/* Disable reverting to power on defaults */
#define	ATSF_ENA_REVPOD	0xcc	/* Enable reverting to power on defaults  */

/*
 * common bits and options for set features (ATC_SET_FEAT)
 */
#define	FC_WRITE_CACHE_ON	0x02
#define	FC_WRITE_CACHE_OFF	0x82

/* Test which version of ATA is supported */
#define	IS_ATA_VERSION_SUPPORTED(idp, n) \
	((idp->ai_majorversion != 0xffff) && \
	(idp->ai_majorversion & (1<<n)))

/* Test if supported version >= ATA-n */
#define	IS_ATA_VERSION_GE(idp, n) \
	((idp->ai_majorversion != 0xffff) && \
	(idp->ai_majorversion != 0) && \
	(idp->ai_majorversion >= (1<<n)))

/* Test whether a device is a CD drive */
#define	IS_CDROM(dp) \
		((dp->ad_flags & AD_ATAPI) && \
		    ((dp->ad_id.ai_config >> 8) & DTYPE_MASK) == \
		    DTYPE_RODIRECT)

/*  macros from old common hba code */

#define	ATA_INTPROP(devi, pname, pval, plen) \
	(ddi_prop_op(DDI_DEV_T_ANY, (devi), PROP_LEN_AND_VAL_BUF, \
		DDI_PROP_DONTPASS, (pname), (caddr_t)(pval), (plen)))

#define	ATA_LONGPROP(devi, pname, pval, plen) \
	(ddi_getlongprop(DDI_DEV_T_ANY, (devi), DDI_PROP_DONTPASS, \
		(pname), (caddr_t)(pval), (plen)))

/*
 *
 * per-controller soft-state data structure
 *
 */

#define	CTL2DRV(cp, t, l)	(cp->ac_drvp[t][l])

typedef struct ata_ctl {

	dev_info_t	*ac_dip;
	uint_t		 ac_flags;
	uint_t		 ac_timing_flags;
	struct ata_drv	*ac_drvp[ATA_MAXTARG][ATA_MAXLUN];
	int		 ac_max_transfer; /* max transfer in sectors */
	uint_t		 ac_standby_time; /* timer value seconds */

	ccc_t		 ac_ccc;	  /* for GHD module */
	struct ata_drv	*ac_active_drvp;  /* active drive, if any */
	struct ata_pkt	*ac_active_pktp;  /* active packet, if any */
	uchar_t		 ac_state;

	scsi_hba_tran_t *ac_atapi_tran;	  /* for atapi module */

	/*
	 * port addresses associated with ioaddr1
	 */
	ddi_acc_handle_t ac_iohandle1;	  /* DDI I/O handle */
	caddr_t		 ac_ioaddr1;
	ushort_t	*ac_data;	  /* data register 		*/
	uchar_t		*ac_error;	  /* error register (read)	*/
	uchar_t		*ac_feature;	  /* features (write)		*/
	uchar_t		*ac_count;	  /* sector count 		*/
	uchar_t		*ac_sect;	  /* sector number 		*/
	uchar_t		*ac_lcyl;	  /* cylinder low byte 		*/
	uchar_t		*ac_hcyl;	  /* cylinder high byte 	*/
	uchar_t		*ac_drvhd;	  /* drive/head register 	*/
	uchar_t		*ac_status;	  /* status/command register 	*/
	uchar_t		*ac_cmd;	  /* status/command register 	*/

	/*
	 * port addresses associated with ioaddr2
	 */
	ddi_acc_handle_t ac_iohandle2;	  /* DDI I/O handle		*/
	caddr_t		 ac_ioaddr2;
	uchar_t		*ac_altstatus;	  /* alternate status (read)	*/
	uchar_t		*ac_devctl;	  /* device control (write)	*/

	/*
	 * handle and port addresss for PCI-IDE Bus Master controller
	 */
	ddi_acc_handle_t ac_bmhandle;	  /* DDI I/O handle		*/
	caddr_t		 ac_bmaddr;	  /* base addr of Bus Master Regs */
	uchar_t		 ac_pciide;	  /* PCI-IDE device */
	uchar_t		 ac_pciide_bm;	  /* Bus Mastering PCI-IDE device */

	/*
	 * Scatter/Gather list for PCI-IDE Bus Mastering controllers
	 */
	caddr_t		 ac_sg_list;	  /* virtual addr of S/G list */
	paddr_t		 ac_sg_paddr;	  /* phys addr of S/G list */
	ddi_acc_handle_t ac_sg_acc_handle;
	ddi_dma_handle_t ac_sg_handle;

	/*
	 * data for managing ARQ on ATAPI devices
	 */
	struct ata_pkt	*ac_arq_pktp;	  /* pkt for performing ATAPI ARQ */
	struct ata_pkt	*ac_fault_pktp;	  /* pkt that caused ARQ */
	uchar_t		 ac_arq_cdb[6];

	/*
	 * Power Management
	 */
	int		ac_pm_support;
	int		ac_pm_level;
} ata_ctl_t;

/* ac_flags (per-controller) */

#define	AC_GHD_INIT			0x02
#define	AC_ATAPI_INIT			0x04
#define	AC_DISK_INIT			0x08
#define	AC_ATTACHED			0x10
#define	AC_SCSI_HBA_TRAN_ALLOC		0x1000
#define	AC_SCSI_HBA_ATTACH		0x2000

#define	AC_BMSTATREG_PIO_BROKEN		0x80000000

/*
 * Bug 1256489:
 *
 * If AC_BSY_WAIT needs to be set  for laptops that do
 * suspend/resume but do not correctly wait for the busy bit to
 * drop after a resume.
 */

/* ac_timing_flags (per-controller) */
#define	AC_BSY_WAIT	0x1	/* tweak timing in ata_start & atapi_start */



/* Identify drive data */
struct ata_id {
/*  					WORD				*/
/* 					OFFSET COMMENT			*/
	ushort_t  ai_config;	  /*   0  general configuration bits 	*/
	ushort_t  ai_fixcyls;	  /*   1  # of fixed cylinders		*/
	ushort_t  ai_resv0;	  /*   2  # reserved			*/
	ushort_t  ai_heads;	  /*   3  # of heads			*/
	ushort_t  ai_trksiz;	  /*   4  # of unformatted bytes/track 	*/
	ushort_t  ai_secsiz;	  /*   5  # of unformatted bytes/sector	*/
	ushort_t  ai_sectors;	  /*   6  # of sectors/track		*/
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
	ushort_t ai_resv4[4];	  /* 71-74 reserved			*/
	ushort_t ai_qdepth;	  /*  75  queue depth			*/
	ushort_t ai_resv5[4];	  /* 76-79 reserved			*/
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
};

/* Identify Drive: general config bits  - word 0 */

#define	ATA_ID_REM_DRV  	0x80
#define	ATA_ID_COMPACT_FLASH 	0x848a
#define	ATA_ID_CF_TO_ATA 	0x040a
#define	ATA_ID_INCMPT		0x0004

/* Identify Drive: common capability bits - word 49 */

#define	ATAC_DMA_SUPPORT	0x0100
#define	ATAC_LBA_SUPPORT	0x0200
#define	ATAC_IORDY_DISABLE	0x0400
#define	ATAC_IORDY_SUPPORT	0x0800
#define	ATAC_RESERVED_IDPKT	0x1000	/* rsrvd for identify pkt dev */
#define	ATAC_STANDBYTIMER	0x2000
#define	ATAC_ATA_TYPE_MASK	0x8001
#define	ATAC_ATA_TYPE		0x0000
#define	ATAC_ATAPI_TYPE_MASK	0xc000
#define	ATAC_ATAPI_TYPE		0x8000

/* Identify Driver ai_validinfo (word 53) */

#define	ATAC_VALIDINFO_83	0x0004	/* word 83 supported fields valid */
#define	ATAC_VALIDINFO_70_64	0x0002	/* word 70:64 sup. fields valid */

/* Identify Drive: ai_dworddma (word 63) */

#define	ATAC_MDMA_SEL_MASK	0x0700	/* Multiword DMA selected */
#define	ATAC_MDMA_2_SEL		0x0400	/* Multiword DMA mode 2 selected */
#define	ATAC_MDMA_1_SEL		0x0200	/* Multiword DMA mode 1 selected */
#define	ATAC_MDMA_0_SEL		0x0100	/* Multiword DMA mode 0 selected */
#define	ATAC_MDMA_2_SUP		0x0004	/* Multiword DMA mode 2 supported */
#define	ATAC_MDMA_1_SUP		0x0002	/* Multiword DMA mode 1 supported */
#define	ATAC_MDMA_0_SUP		0x0001	/* Multiword DMA mode 0 supported */

/* Identify Drive: ai_advpiomode (word 64) */

#define	ATAC_ADVPIO_4_SUP	0x0002	/* PIO mode 4 supported */
#define	ATAC_ADVPIO_3_SUP	0x0001	/* PIO mode 3 supported */
#define	ATAC_ADVPIO_SERIAL	0x0003	/* Serial interface */

/* Identify Drive: ai_majorversion (word 80) */

#define	ATAC_MAJVER_8		0x0100	/* ATA/ATAPI-8 version supported */
#define	ATAC_MAJVER_6		0x0040	/* ATA/ATAPI-6 version supported */
#define	ATAC_MAJVER_4		0x0010	/* ATA/ATAPI-4 version supported */

/* Identify Drive: command set supported/enabled bits - words 83 and 86 */

#define	ATACS_EXT48		0x0400	/* 48 bit address feature */

/* Identify Drive: ai_features85 (word 85) */
#define	ATAC_FEATURES85_WCE	0x0020	/* write cache enabled */

/* per-drive data struct */

typedef struct ata_drv {
	ata_ctl_t		*ad_ctlp; 	/* pointer back to ctlr */
	struct ata_id		ad_id;  	/* IDENTIFY DRIVE data */

	uint_t			ad_flags;
	uchar_t			ad_pciide_dma;	/* PCIIDE DMA supported */
	uchar_t			ad_targ;	/* target */
	uchar_t			ad_lun;		/* lun */
	uchar_t			ad_drive_bits;

	/* Used by atapi side only */

	uchar_t			ad_state;	/* state of ATAPI FSM */
	uchar_t			ad_cdb_len;	/* Size of ATAPI CDBs */

	uchar_t			ad_bogus_drq;
	uchar_t			ad_nec_bad_status;

	/* Used by disk side only */

	struct scsi_device	ad_device;
	struct scsi_inquiry	ad_inquiry;
	struct ctl_obj		ad_ctl_obj;
	uchar_t			ad_rd_cmd;
	uchar_t			ad_wr_cmd;
	ushort_t		ad_acyl;

	/*
	 * Geometry note: The following three values are the geometry
	 * that the driver will use.  They may differ from the
	 * geometry reported by the controller and/or BIOS.  See note
	 * on ata_fix_large_disk_geometry in ata_disk.c for more
	 * details.
	 */
	uint32_t		ad_drvrcyl;	/* number of cyls */
	uint32_t		ad_drvrhd;	/* number of heads */
	uint32_t		ad_drvrsec;	/* number of sectors */
	ushort_t		ad_phhd;	/* number of phys heads */
	ushort_t		ad_phsec;	/* number of phys sectors */
	short			ad_block_factor;
	short			ad_bytes_per_block;

	/*
	 * Support for 48-bit LBA (ATA-6)
	 */
	uint64_t		ad_capacity;	/* Total sectors on disk */
} ata_drv_t;

typedef	struct	ata_tgt {
	ata_drv_t	*at_drvp;
	int		 at_arq;
	ulong_t		 at_total_sectors;
	ddi_dma_attr_t	 at_dma_attr;
} ata_tgt_t;

/* values for ad_pciide_dma */
#define	ATA_DMA_OFF		0x0
#define	ATA_DMA_ON		0x1
#define	ATA_DMA_UNINITIALIZED	0x2

/*
 * (ata_pkt_t *) to (gcmd_t *)
 */
#define	APKT2GCMD(apktp)	(apktp->ap_gcmdp)

/*
 * (gcmd_t *) to (ata_pkt_t *)
 */
#define	GCMD2APKT(gcmdp)	((ata_pkt_t *)gcmdp->cmd_private)

/*
 * (gtgt_t *) to (ata_ctl_t *)
 */
#define	GTGTP2ATAP(gtgtp)	((ata_ctl_t *)GTGTP2HBA(gtgtp))

/*
 * (gtgt_t *) to (ata_tgt_t *)
 */
#define	GTGTP2ATATGTP(gtgtp)	((ata_tgt_t *)GTGTP2TARGET(gtgtp))

/*
 * (gtgt_t *) to (ata_drv_t *)
 */
#define	GTGTP2ATADRVP(gtgtp)	(GTGTP2ATATGTP(gtgtp)->at_drvp)

/*
 * (gcmd_t *) to (ata_tgt_t *)
 */
#define	GCMD2TGT(gcmdp)		GTGTP2ATATGTP(GCMDP2GTGTP(gcmdp))

/*
 * (gcmd_t *) to (ata_drv_t *)
 */
#define	GCMD2DRV(gcmdp)		GTGTP2ATADRVP(GCMDP2GTGTP(gcmdp))

/*
 * (ata_pkt_t *) to (ata_drv_t *)
 */
#define	APKT2DRV(apktp)		GCMD2DRV(APKT2GCMD(apktp))


/*
 * (struct hba_tran *) to (ata_ctl_t *)
 */
#define	TRAN2ATAP(tranp) 	((ata_ctl_t *)TRAN2HBA(tranp))


/*
 * ata common packet structure
 */
typedef struct ata_pkt {

	gcmd_t		*ap_gcmdp;	/* GHD command struct */

	uint_t		ap_flags;	/* packet flags */

	caddr_t		ap_baddr;	/* I/O buffer base address */
	size_t		ap_boffset;	/* current offset into I/O buffer */
	size_t		ap_bcount;	/* # bytes in this request */

	caddr_t		ap_v_addr;	/* I/O buffer address */
	size_t		ap_resid;	/* # bytes left to read/write */

	uchar_t		ap_pciide_dma;	/* This pkt uses DMA transfer mode */
	prde_t		ap_sg_list[ATA_DMA_NSEGS]; /* Scatter/Gather list */
	int		ap_sg_cnt;	/* number of entries in S/G list */

	/* command, starting sector number, sector count */

	daddr_t		ap_startsec;	/* starting sector number */
	ushort_t	ap_count;	/* sector count */
	uchar_t		ap_sec;
	uchar_t		ap_lwcyl;
	uchar_t		ap_hicyl;
	uchar_t		ap_hd;
	uchar_t		ap_cmd;

	/* saved status and error registers for error case */

	uchar_t		ap_status;
	uchar_t		ap_error;

	/* disk/atapi callback routines */

	int		(*ap_start)(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
				struct ata_pkt *ata_pktp);
	int		(*ap_intr)(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
				struct ata_pkt *ata_pktp);
	void		(*ap_complete)(ata_drv_t *ata_drvp,
				struct ata_pkt *ata_pktp, int do_callback);

	/* Used by disk side */

	char		ap_cdb;		/* disk command */
	char		ap_scb;		/* status after disk cmd */
	uint_t		ap_bytes_per_block; /* blk mode factor */
	uint_t		ap_wrt_count;	/* size of last write */
	caddr_t		ap_v_addr_sav;	/* Original I/O buffer address. */
	size_t		ap_resid_sav;	/* Original # of bytes */
					/* left to read/write. */

	/* Used by atapi side */

	uchar_t		*ap_cdbp;	/* ptr to SCSI CDB */
	uchar_t		ap_cdb_len;	/* length of SCSI CDB (in bytes) */
	uchar_t		ap_cdb_pad;	/* padding after SCSI CDB (in shorts) */

	struct scsi_arq_status *ap_scbp; /* ptr to SCSI status block */
	uchar_t		ap_statuslen;	/* length of SCSI status block */
} ata_pkt_t;


/*
 * defines for ap_flags
 */
#define	AP_ATAPI		0x0001	/* device is atapi */
#define	AP_ERROR		0x0002	/* normal error */
#define	AP_TRAN_ERROR		0x0004	/* transport error */
#define	AP_READ			0x0008	/* read data */
#define	AP_WRITE		0x0010	/* write data */
#define	AP_ABORT		0x0020	/* packet aborted */
#define	AP_TIMEOUT		0x0040	/* packet timed out */
#define	AP_BUS_RESET		0x0080	/* bus reset */
#define	AP_DEV_RESET		0x0100	/* device reset */

#define	AP_SENT_CMD		0x0200	/* atapi: cdb sent */
#define	AP_XFERRED_DATA		0x0400	/* atapi: data transferred */
#define	AP_GOT_STATUS		0x0800	/* atapi: status received */
#define	AP_ARQ_ON_ERROR		0x1000	/* atapi: do ARQ on error */
#define	AP_ARQ_OKAY		0x2000
#define	AP_ARQ_ERROR		0x4000

#define	AP_FREE		   0x80000000u	/* packet is free! */


/*
 * public function prototypes
 */

int	ata_check_drive_blacklist(struct ata_id *aidp, uint_t flags);
int	ata_command(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp, int expect_drdy,
		int silent, uint_t busy_wait, uchar_t cmd, uchar_t feature,
		uchar_t count, uchar_t sector, uchar_t head, uchar_t cyl_low,
		uchar_t cyl_hi);
int	ata_get_status_clear_intr(ata_ctl_t *ata_ctlp, ata_pkt_t *ata_pktp);
int	ata_id_common(uchar_t id_cmd, int drdy_expected,
		ddi_acc_handle_t io_hdl1, caddr_t ioaddr1,
		ddi_acc_handle_t io_hdl2, caddr_t ioaddr2,
		struct ata_id *ata_idp);
int	ata_prop_create(dev_info_t *tgt_dip, ata_drv_t *ata_drvp, char *name);
int	ata_queue_cmd(int (*func)(ata_ctl_t *, ata_drv_t *, ata_pkt_t *),
		void *arg, ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
		gtgt_t *gtgtp);
int	ata_set_feature(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
		uchar_t feature, uchar_t value);
int	ata_wait(ddi_acc_handle_t io_hdl, caddr_t ioaddr, uchar_t onbits,
		uchar_t offbits, uint_t timeout_usec);
int	ata_wait3(ddi_acc_handle_t io_hdl, caddr_t ioaddr, uchar_t onbits1,
		uchar_t offbits1, uchar_t failure_onbits2,
		uchar_t failure_offbits2, uchar_t failure_onbits3,
		uchar_t failure_offbits3, uint_t timeout_usec);
int	ata_test_lba_support(struct ata_id *aidp);
void	ata_nsecwait(clock_t count);


/*
 * PCIIDE DMA (Bus Mastering) functions and data in ata_dma.c
 */
extern	ddi_dma_attr_t ata_pciide_dma_attr;
extern	int	ata_dma_disabled;

int	ata_pciide_alloc(dev_info_t *dip, ata_ctl_t *ata_ctlp);
void	ata_pciide_free(ata_ctl_t *ata_ctlp);

void	ata_pciide_dma_sg_func(gcmd_t *gcmdp, ddi_dma_cookie_t *dmackp,
		int single_segment, int seg_index);
void	ata_pciide_dma_setup(ata_ctl_t *ata_ctlp, prde_t *srcp, int sg_cnt);
void	ata_pciide_dma_start(ata_ctl_t *ata_ctlp, uchar_t direction);
void	ata_pciide_dma_stop(ata_ctl_t *ata_ctlp);
int	ata_pciide_status_clear(ata_ctl_t *ata_ctlp);
int	ata_pciide_status_dmacheck_clear(ata_ctl_t *ata_ctlp);
int	ata_pciide_status_pending(ata_ctl_t *ata_ctlp);

#ifdef	__cplusplus
}
#endif

#endif /* _ATA_COMMON_H */
