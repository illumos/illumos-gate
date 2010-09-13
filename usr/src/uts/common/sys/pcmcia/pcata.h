/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_PCATA_H
#define	_SYS_PCATA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	FALSE	0
#define	TRUE	1

#if defined(DEBUG)
#define	ATA_DEBUG 	1
#endif	/* defined(DEBUG) */

/*
 * port offsets from base address ioaddr1
 */
#define	AT_DATA		0x00	/* data register			*/
#define	AT_ERROR	0x01	/* error register (read)		*/
#define	AT_FEATURE	0x01	/* feature (write)			*/
#define	AT_COUNT	0x02	/* sector count				*/
#define	AT_SECT		0x03	/* sector number			*/
#define	AT_LCYL		0x04	/* cylinder low byte			*/
#define	AT_HCYL		0x05	/* cylinder high byte			*/
#define	AT_DRVHD	0x06	/* drive/head register			*/
#define	AT_STATUS	0x07	/* status/command register		*/
#define	AT_CMD		0x07	/* status/command register		*/

/*
 * port offsets from base address ioaddr2
 */
#define	AT_ALTSTATUS	0x0E	/* alternate status (read)		*/
#define	AT_DEVCTL	0x0E	/* device control (write)		*/
#define	AT_DRVADDR	0x0F	/* drive address (read)			*/


/*
 *	Device control register
 */

#define	AT_NIEN		0x02	/* disable interrupts			*/
#define	AT_SRST		0x04	/* controller reset			*/
#define	AT_DEVCTL_D3	0x08	/* bit 3 is always set, see spec */

#define	ENABLE_INTERRUPT	AT_DEVCTL_D3	/* clear AT_NIEN bit 	*/
#define	DISABLE_INTERRUPT	AT_DEVCTL_D3|AT_NIEN

/*
 * Status bits from AT_STATUS register
 */
#define	ATS_BSY		0x80	/* controller busy			*/
#define	ATS_DRDY	0x40	/* drive ready				*/
#define	ATS_DWF		0x20	/* write fault				*/
#define	ATS_DSC		0x10	/* seek operation complete		*/
#define	ATS_DRQ		0x08	/* data request				*/
#define	ATS_CORR	0x04	/* ECC correction applied		*/
#define	ATS_IDX		0x02	/* disk revolution index		*/
#define	ATS_ERR		0x01	/* error flag				*/

/*
 * Status bits from AT_ERROR register
 */
#define	ATE_AMNF	0x01	/* address mark not found		*/
#define	ATE_TKONF	0x02	/* track 0 not found			*/
#define	ATE_ABORT	0x04	/* aborted command			*/
#define	ATE_IDNF	0x10	/* ID not found				*/
#define	ATE_UNC		0x40	/* uncorrectable data error		*/
#define	ATE_BBK		0x80	/* bad block detected			*/

/*
 * Drive selectors for AT_DRVHD register
 */
#define	ATDH_DRIVE0	0xa0	/* or into AT_DRVHD to select drive 0	*/
#define	ATDH_DRIVE1	0xb0	/* or into AT_DRVHD to select drive 1	*/

/*
 * ATA commands.
 */
#define	ATC_DIAG	0x90	/* diagnose command			*/
#define	ATC_RECAL	0x10	/* restore cmd, bottom 4 bits step rate	*/
#define	ATC_SEEK	0x70	/* seek cmd, bottom 4 bits step rate	*/
#define	ATC_RDVER	0x40	/* read verify cmd			*/
#define	ATC_RDSEC	0x20	/* read sector cmd			*/
#define	ATC_RDLONG	0x23	/* read long without retry		*/
#define	ATC_WRSEC	0x30	/* write sector cmd			*/
#define	ATC_SETMULT	0xc6	/* set multiple mode			*/
#define	ATC_RDMULT	0xc4	/* read multiple			*/
#define	ATC_WRMULT	0xc5	/* write multiple			*/
#define	ATC_FORMAT	0x50	/* format track command			*/
#define	ATC_SETPARAM	0x91	/* set parameters command		*/
#define	ATC_READPARMS	0xec	/* Read Parameters command		*/
#define	ATC_READDEFECTS	0xa0	/* Read defect list			*/
#define	ATC_SET_FEAT	0xef	/* set features				*/
#define	ATC_IDLE_IMMED	0xe1	/* idle immediate			*/
#define	ATC_STANDBY_IM	0xe0	/* standby immediate			*/
#define	ATC_ACK_MC	0xdb	/* acknowledge media change		*/
#define	ATC_DOOR_LOCK	0xde	/* door lock				*/
#define	ATC_DOOR_UNLOCK	0xdf	/* door unlock				*/
#define	ATC_PI_SRESET	0x08    /* ATAPI soft reset			*/
#define	ATC_PI_ID_DEV	0xa1	/* ATAPI identify device		*/
#define	ATC_PI_PKT	0xa0	/* ATAPI packet command 		*/

/*
 * ata device type
 */
#define	ATA_DEV_NONE	0
#define	ATA_DEV_DISK	1
#define	ATA_DEV_12	2 /* atapi 1.2 spec unit */
#define	ATA_DEV_17	3 /* atapi 1.7B spec unit */

/*
 * write into config. opt. reg to configure level interrupt and
 * I/O mapped addressing.
 */
#define	LEVEL_MODE_IO_MAP	0x41


/*
 * Low bits for Read/Write commands...
 */
#define	ATCM_ECCRETRY	0x01	/* Enable ECC and RETRY by controller	*/
				/* enabled if bit is CLEARED!!!		*/
#define	ATCM_LONGMODE	0x02	/* Use Long Mode (get/send data & ECC)	*/
				/* enabled if bit is SET!!!		*/

/*
 * direction bits
 * for ac_direction
 */
#define	AT_NO_DATA	0		/* No data transfer */
#define	AT_OUT		1		/* for writes */
#define	AT_IN		2		/* for reads */

/*
 * status bits for ab_ctl_status
 */
#define	ATA_ONLINE	0
#define	ATA_OFFLINE	1
#define	ATA_PRESENT	2

#define	B_PASSTHRU	0x1000000

/*
 * timeout and timing parameters
 *
 */
#define	MS2HZ(time)		drv_usectohz(time * 1000)
#define	PCATA_READY_TIMEOUT	(MS2HZ(6000))  /* card ready */
#define	PCATA_READYWAIT_TIMEOUT	(MS2HZ(8000))	/* wait for ready in open */

/* for non attached driver or when instance is unknown */
#define	PCATA_BIO_TIMEOUT1	(MS2HZ(100))	/* sometimes we need it fast */

/* for attached driver or when instance is known */
#define	PCATA_BIO_TIMEOUT2	(MS2HZ(200))	/* pcata bio timeout */

/* for non attached driver or when instance is unknown */
#define	PCATA_BIOTIMEOUT_CNT1	10		/* maximum of 10 pkts id */

/* for attached driver or when instance is known */
#define	PCATA_BIOTIMEOUT_CNT2	40		/* maximum of 40 pkts id */

#define	PCATA_DRIVESETUP_TIMEOUT MS2HZ(1000)	/* drive setup timeout */
#define	PCATA_DRIVESETUP_CNT	2		/* only two instances for now */

struct ata_cmpkt {
	struct ata_cmpkt *pkt_forw; 	/* link in chain of packets */

	struct ata_unit	*cp_ctl_private; /* link to struct ata_unit	*/
	struct	buf	*cp_bp;		/* link to buf structure	*/
	caddr_t		ac_start_v_addr; /* start memory I/O address	*/
	daddr_t		cp_srtsec;	/* starting sector number	*/
	int		cp_bytexfer;	/* bytes xfer in this operation */

	char		ac_cdb;		/* target driver command	*/
	char		ac_scb;		/* controller status aft cmd	*/
	ushort_t	ac_flags;	/* controller flags		*/

	int		ac_bytes_per_block; /* blk mode factor per xfer	*/
	caddr_t		ac_v_addr;	/* I/O should be done to/from 	*/

	int		cp_resid;	/* data bytes not transferred	*/
	int		cp_reason;	/* error status */
	int		cp_flags;
	void		*cp_passthru;
	char		ac_direction;	/* AT_IN - read AT_OUT - write	*/
	int		cp_retry;
	/*
	 * task file registers setting
	 */
					/* sec count in ac_pkt		*/
#ifdef NOT_USED
	uchar_t		ac_devctl;
	uchar_t		ac_sec;
	uchar_t		ac_count;
	uchar_t		ac_lwcyl;
	uchar_t		ac_hicyl;
	uchar_t		ac_hd;
#endif
	uchar_t		ac_cmd;

	/*
	 * error status
	 */
	uchar_t		ac_error;
	uchar_t		ac_status;
};




/*	structure of 'Read Parameters' command 				*/
struct atarpbuf {
/*  					WORD				*/
/* 					OFFSET COMMENT			*/
	ushort_t atarp_config;		/*  0 general configuration bits */
	ushort_t atarp_fixcyls;		/*  1 # of fixed cylinders */
	ushort_t atarp_remcyls;		/*  2 # of removable cylinders */
	ushort_t atarp_heads;		/*  3 # of heads */
	ushort_t atarp_trksiz;		/*  4 # of unformatted bytes/track */
	ushort_t atarp_secsiz;		/*  5 # of unformatted bytes/sector */
	ushort_t atarp_sectors;		/*  6 # of sectors/track */
	ushort_t atarp_resv1[3];	/*  7 "Vendor Unique" */
	char	atarp_drvser[20];	/* 10 Serial number */
	ushort_t atarp_buftype;		/* 20 Buffer type */
	ushort_t atarp_bufsz;		/* 21 Buffer size in 512 byte incr */
	ushort_t atarp_ecc;		/* 22 # of ecc bytes avail on rd/wr */
	char	atarp_fw[8];		/* 23 Firmware revision */
	char	atarp_model[40];	/* 27 Model # */
	ushort_t atarp_mult1;		/* 47 Multiple command flags */
	ushort_t atarp_dwcap;		/* 48 Doubleword capabilities */
	ushort_t atarp_cap;		/* 49 Capabilities */
	ushort_t atarp_resv2;		/* 50 Reserved */
	ushort_t atarp_piomode;		/* 51 PIO timing mode */
	ushort_t atarp_dmamode;		/* 52 DMA timing mode */
	ushort_t atarp_validinfo;	/* 53 bit0: wds 54-58, bit1: 64-70 */
	ushort_t atarp_curcyls;		/* 54 # of current cylinders */
	ushort_t atarp_curheads;	/* 55 # of current heads */
	ushort_t atarp_cursectrk;	/* 56 # of current sectors/track */
	ushort_t atarp_cursccp[2];	/* 57 current sectors capacity */
	ushort_t atarp_mult2;		/* 59 multiple sectors info */
	ushort_t atarp_addrsec[2];	/* 60 LBA only: no of addr secs */
	ushort_t atarp_sworddma;	/* 62 single word dma modes */
	ushort_t atarp_dworddma;	/* 63 double word dma modes */
	ushort_t atarp_advpiomode;	/* 64 advanced PIO modes supported */
	ushort_t atarp_minmwdma;	/* 65 min multi-word dma cycle info */
	ushort_t atarp_recmwdma;	/* 66 rec multi-word dma cycle info */
	ushort_t atarp_minpio;		/* 67 min PIO cycle info */
	ushort_t atarp_minpioflow;	/* 68 min PIO cycle info w/flow ctl */
};

/*	direct coupled disk driver command				*/
#define	DCMD_READ	1	/* Read Sectors/Blocks			*/
#define	DCMD_WRITE	2	/* Write Sectors/Blocks			*/
#define	DCMD_FMTTRK	3	/* Format Track				*/
#define	DCMD_FMTDRV	4	/* Format entire drive			*/
#define	DCMD_RECAL	5	/* Recalibrate				*/
#define	DCMD_SEEK	6	/* Seek to Cylinder			*/
#define	DCMD_RDVER	7	/* Read Verify sectors on disk		*/
#define	DCMD_GETDEF	8	/* Read manufacturers defect list	*/

/*	driver error code						*/
#define	DERR_SUCCESS	0	/* success				*/
#define	DERR_AMNF	1	/* address mark not found		*/
#define	DERR_TKONF	2	/* track 0 not found			*/
#define	DERR_ABORT	3	/* aborted command			*/
#define	DERR_DWF	4	/* write fault				*/
#define	DERR_IDNF	5	/* ID not found				*/
#define	DERR_BUSY	6	/* drive busy				*/
#define	DERR_UNC	7	/* uncorrectable data error		*/
#define	DERR_BBK	8	/* bad block detected			*/
#define	DERR_INVCDB	9	/* invalid cdb				*/

/*	reason code for completion status				*/
#define	CPS_SUCCESS	0		/* command completes with no err */
#define	CPS_FAILURE	1		/* command fails		*/
#define	CPS_CHKERR	2		/* command fails with status	*/
#define	CPS_ABORTED	3		/* command aborted		*/

/*	flags definitions						*/
#define	CPF_NOINTR	0x0001		/* polling mode			*/


/*	debug	definitions 						*/
#ifdef ATA_DEBUG

#define	DENT	0x0001
#define	DPKT	0x0002
#define	DIO	0x0004
#define	DDAT	0x0008
#define	DPCM	0x0010
#define	DLBL	0x0020			/* disk label routines		*/
#define	DINT	0x0040
#define	DINIT	0x0080
#define	DOPEN	0x0100
#define	DMKDEV	0x0200			/* creation of devices		*/
#define	DERR	0x0400			/* Error Condition		*/
#define	DMUTEX	0x0800			/* mutex entry/exit		*/
#define	DVOLD	0x1000			/* volmgt debug			*/
#endif /* ATA_DEBUG */


/*
 * misc	definition
 */
#define	ATA_LOOP_CNT	10000	/* for looping on registers */
#define	DDI_XSUSPEND	1
#define	DDI_XRESUME	2
#define	CFLAG_ERROR	1
#define	CFLAG_FREE	2
#define	CTL_SEND_FAILURE	1
#define	CTL_SEND_SUCCESS	0
#define	RETRY_CNT	10
#define	PCATA_GO_RETRY	1
#define	PCATA_WAIT_CNT	100
#define	ROUNDUP(a, n)	(((a) + ((n) - 1)) & ~((n) - 1))
#define	LPART(dev)	(((getminor(dev) & 0x1F) % NUM_PARTS))
#define	PCIDE_OUTB(a, b, c)	csx_Put8(a, b, c);\
				drv_usecwait(5);

/*
 * XXX/lcl - LPART uses 5 bits, shouldn't unit shift right 5?
 * also UNIT seems to be incompatible with PCATA_SETMINOR
 * also in sysmacros.h O_MAXMIN seems to be 0xff which means << 10 is bad
 */
#define	UNIT(dev)	(getminor(dev)>>2 &1)

#define	PCATA_SOCKET(dev)		((getminor(dev) >> 10) & 0x3f)
#define	PCATA_SETMINOR(skt, part)	((skt<<10) | (part))

#define	MAX_SLICES	16
#define	NUM_PARTS	(MAX_SLICES + FD_NUMPART + 1)
#define	PCATA_NAME	"pcata"
#define	FDISK_OFFSET	MAX_SLICES	/* vtoc slice 16 == fdisk partition 0 */
#if defined(_SUNOS_VTOC_16)
#define	VTOC_OFFSET	1
#elif defined(_SUNOS_VTOC_8)
#define	VTOC_OFFSET	0
#else
#error No VTOC format defined.
#endif
#define	USLICE_WHOLE	2

typedef struct	{
	kmutex_t		mutex;
	struct dk_label		ondsklbl;
	struct partition	pmap[NUM_PARTS];
	struct dk_map		un_map[NDKMAP];	/* logical partitions */
	int			fdiskpresent;	/* fdisk present	*/
	int			uidx;		/* UNIX partition number */
	} dsk_label_t;

/*
 * linked list of drives on this controller
 */
typedef struct ata_unit {
	struct ata_soft	*a_blkp;	/* controller structure */

	uchar_t		au_targ;
	uchar_t		au_drive_bits;
	uchar_t		au_ctl_bits;
	int		au_cyl;		/* cylinders */
	int		au_acyl;	/* alternate cylinders */
	int		au_hd;
	int		au_sec;
	int		au_blksz;
	short		au_block_factor;
	short		au_bytes_per_block;
	uchar_t		au_rd_cmd;
	uchar_t		au_wr_cmd;
	buf_t		*un_sbufp;
	struct atarpbuf *au_rpbuf;

	struct ata_unit	*a_forw;	/* linked list for all ata's 	*/
	dsk_label_t	lbl;		/* per targer label information */
} ata_unit_t;

/*
 * pcata_cftable_t and pcata_cftable_params_t structures are used
 *	to store values from the CISTPL_CFTABLE_ENTRY tuples.
 */
typedef struct pcata_cftable_params_t {
	uchar_t		config_index;
	uint32_t	addr_lines;	/* IO addr lines decoded */
	uint32_t	ata_length[2];	/* length of first IO range */
	uint32_t	pin;		/* PRR bits valid mask */
	uint32_t	ata_vcc;
	uint32_t	ata_vpp1;
	uint32_t	ata_vpp2;
	uint32_t	ata_base[2];	/* base of IO range ata registers */
	int		ranges;		/* number of IO range		*/
} pcata_cftable_params_t;

typedef struct pcata_cftable_t {
	uint32_t		desireability;	/* desireability factor */
	pcata_cftable_params_t	p;		/* parameters */
	struct pcata_cftable_t	*prev;
	struct pcata_cftable_t	*next;
} pcata_cftable_t;



typedef struct pcata_cis_vars_t {
	uint32_t	present;	/* config register present flags */
	uint32_t	pin;		/* PRR bits valid mask */
	char		prod_strings[CISTPL_VERS_1_MAX_PROD_STRINGS]
					[CIS_MAX_TUPLE_DATA_LEN];
	uint32_t	major_revision;	/* card major revision level */
	uint32_t	minor_revision;	/* card minor revision level */
	uint32_t	manufacturer_id; /* manufacturer ID */
	uint32_t	card_id;	/* card ID */
	uint32_t	config_base;	/* base offset of config registers */
	uint32_t	ata_base[2];	/* base offset of ata registers */
	uint32_t	ata_length[2];
	uchar_t		config_index;
	uint32_t	addr_lines;	/* number of IO addr lines decoded */
	/* misc card requirements */
	uint32_t	ata_vcc;
	uint32_t	ata_vpp1;
	uint32_t	ata_vpp2;
	pcata_cftable_t	cftable;	/* active CFTABLE_ENTRY values */
} pcata_cis_vars_t;

typedef struct pcata_biotimeout {
	timeout_id_t    timeout_id;
	buf_t		*bp;
} pcata_biotimeout_t;

#define	ATA_MAXDRIVE	8

/*
 * soft state structure
 */
typedef struct ata_soft  {
	int 		flags;		/* misc state info		*/
	int 		sn;		/* socket number		*/

	enum dkio_state	media_state;	/* up-to-date media state	*/
	int		checkmedia_flag;
	int		ejected_media_flag;

	int		instance;	/* instantiation of ourselves	*/
	struct	buf	*crashbuf;	/* dumping to root device	*/
	uint32_t	card_state;	/* like it says			*/
	int		ejected_while_mounted;
	int		chr_open;	/* open in character mode	*/
	int		blk_open;	/* open in block mode		*/
	int		lyr_open[NUM_PARTS]; /* open in layered mode 	*/
	client_handle_t	client_handle;	/* client handle for socket	*/
	acc_handle_t	handle;		/* pcata registers handle	*/
	ddi_iblock_cookie_t soft_blk_cookie;	/* soft intr cookie	*/
	ddi_softintr_t	softint_id;
	timeout_id_t	ready_timeout_id;
	timeout_id_t	readywait_timeout_id;
	dev_info_t	*dip;		/* pointer to device node	*/
	kmutex_t	hi_mutex;	/* protect hi-level interrupt	*/
	kmutex_t	ata_mutex;
	kmutex_t	event_hilock;	/* protects hi-level events	*/
			/*
			 * wait for cv_broadcast of condvar_mediastate
			 * in pcata_check_media
			 */
	kcondvar_t	condvar_mediastate; /* for DKIOCSTATE ioctl()   */
	kcondvar_t	readywait_cv;
	pcata_cis_vars_t cis_vars; 	/* saved things ATA's CIS	*/
	int		intr_pending;	/* an interrupt is pending	*/
	int		softint_pending;
	int		write_in_progress;
	uint32_t	flash;
	struct ata_unit	*ab_link;	/* linked units			*/
	struct ata_cmpkt *ab_active;	/* outstanding requests		*/
	kmutex_t 	ab_mutex;
	void		*ab_lkarg;
	ushort_t	ab_status_flag;
	ushort_t	ab_resv;

	/*
	 * Even though we can only have 2 targets, we need 8 slots
	 * for the generic code
	 */
	struct atarpbuf	*ab_rpbp[ATA_MAXDRIVE];
	uchar_t		ab_dev_type[ATA_MAXDRIVE];
	dev_info_t	*ab_dip;
	/*
	 * port addresses associated with ioaddr1
	 */
	uint32_t	ab_data;	/* data register 		*/
	uint32_t	ab_error;	/* error register (read)	*/
	uint32_t	ab_feature;	/* features (write)		*/
	uint32_t	ab_count;	/* sector count 		*/
	uint32_t	ab_sect;	/* sector number 		*/
	uint32_t	ab_lcyl;	/* cylinder low byte 		*/
	uint32_t	ab_hcyl;	/* cylinder high byte 		*/
	uint32_t	ab_drvhd;	/* drive/head register 		*/
	uint32_t	ab_status;	/* status/command register 	*/
	uint32_t	ab_cmd;		/* status/command register 	*/

	/*
	 * port addresses associated with ioaddr2
	 */
	uint32_t	ab_altstatus;	/* alternate status (read)	*/
	uint32_t	ab_devctl;	/* device control (write)	*/
	uint32_t	ab_drvaddr;	/* drive address (read)		*/

	int		ab_block_factor[2]; /* hold dev blk factor 	*/
				/* until unit structure is alloc	*/
	uchar_t		ab_rd_cmd[2];	/* hold read command until	*/
					/* unit structure is alloc	*/
	uchar_t		ab_wr_cmd[2];	/* hold write command until	*/
					/* unit structure is alloc	*/
	int		ab_max_transfer;

	struct ata_cmpkt *ab_head;	/* linked list of I/O requests	*/
	struct ata_cmpkt *ab_last;
	kmutex_t	label_mutex;	/* protect dsk_label_t		*/
} ata_soft_t;


/*
 * flags in ata_soft.flags field
 */
#define	PCATA_DIDLOCKS		0x00000001	/* cv/mutex_init in attach */
#define	PCATA_REGCLIENT		0x00000002	/* RegisterClient is OK */
#define	PCATA_REQSOCKMASK	0x00000004	/* RequestSocketMask is OK */
#define	PCATA_SOFTINTROK	0x00000008	/* added to interrupt chain */
#define	PCATA_ATTACHOK		0x00000010	/* made it through attach(OK) */
#define	PCATA_REQUESTIO		0x00000020	/* did RequestIO */
#define	PCATA_REQUESTIRQ	0x00000040	/* did RequestIRQ */
#define	PCATA_REQUESTCONFIG	0x00000080	/* did RequestConfiguration */
#define	PCATA_MAKEDEVICENODE	0x00000100	/* did MakeDeviceNode */
#define	PCATA_SUSPENDED		0x00000200	/* device is suspended ? */
#define	PCATA_READY		0x00000400	/* device is ready to be used */
#define	PCATA_VALID_IO_INFO	0x00000800	/* have valid IO info frm CIS */
#define	PCATA_DIDLOCKS2		0x00001000	/* cv/mutex_init in attach */
#define	PCATA_LABELLOCK		0x00002000	/* Disk label lock */
#define	PCATA_DIDLOCKS3		0x00004000	/* ata_mutex initialized */

/*
 * flags in card_state field
 */
#define	PCATA_CARD_INSERTED	0x00000001	/* card is here */
#define	PCATA_WAIT_FOR_READY	0x00000002	/* waiting for card ready */
#define	PCATA_CARD_IS_READY	0x00000004	/* card is ready */
#define	PCATA_READY_WAIT	0x00000008	/* waiting for READY */
#define	PCATA_HAS_WINDOW	0x00000010	/* we have a register window */
#define	PCATA_WAITINIT		0x00000020	/* initialization in progress */

#define	CARD_PRESENT_VALID(pm)	((pm)->card_state & PCATA_CARD_INSERTED)

/*
 * UNTIMEOUT() macro to make sure we're not trying untimeout a bogus timeout
 */
#define	UNTIMEOUT(utt)	{		\
	if (utt) {			\
		(void) untimeout(utt);	\
		utt = 0;		\
	}				\
}

/*
 * global variables
 */
/*
 * linkage to soft state structures by instance (see ddi_get_soft_state)
 */
extern	void			*pcata_soft;
extern	char			*pcata_name;
extern	int			pcata_debug;
extern	struct cb_ops		pcata_cb_ops;

/*
 * pcata.c
 */
int pcata_event(event_t event, int priority, event_callback_args_t *eca);
int pcata_card_removal(ata_soft_t *softp, int priority);
int pcata_parse_cis(ata_soft_t *softp, pcata_cftable_t **cftable);
void pcata_destroy_cftable_list(pcata_cftable_t **cftable);
char	*pcata_CS_etext(int ret);
int pcata_readywait(ata_soft_t *softp);
void pcata_minor_wait(ata_soft_t *softp);
int pcata_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
	void **result);

/*
 * pcide.c
 */
int _init(void);
int _fini(void);
int _info(struct modinfo *modinfop);
int pcata_start(ata_unit_t *, buf_t *, int);
int pcata_intr_hi(ata_soft_t *softp);
uint32_t pcata_intr(char *softp);
int pcata_getedt(ata_soft_t *ata_blkp, int dmax);
void pcata_byte_swap(char *buf, int n);
int pcata_set_rw_multiple(ata_soft_t *ata_blkp, int drive);
void pcata_min(buf_t *bp);
int pcata_spinup(ata_soft_t *softp, int slot);

/*
 * pcdisk.c
 */
int pcata_strategy(buf_t *bp);
int pcata_ioctl(dev_t dev, int cmd, intptr_t arg, int flag, cred_t *cred_p,
	int *rval_p);
int pcata_lbl_ioctl(dev_t dev, int cmd, intptr_t arg, int flag);
int pcata_open(dev_t *dev_p, int flag, int otyp, cred_t *cred_p);
int pcata_close(dev_t dev, int flag, int otyp, cred_t *cred_p);
int pcata_update_vtoc(ata_soft_t *softp, dev_t dev);
int pcata_write_dskvtoc(ata_soft_t *softp, dev_t dev, dsk_label_t *lblp,
	struct vtoc *vtocp);
int pcata_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int mod_flags, char *name, caddr_t valuep, int *lengthp);

/*
 * pclabel.c
 */
int pcfdisk_parse(buf_t *bp, ata_unit_t *unitp);
int pcfdisk_read(buf_t *bp, ata_unit_t *unitp);
int pcdsklbl_wrvtoc(dsk_label_t *lblp, struct vtoc *vtocp, buf_t *bp);
void pcdsklbl_ondsklabel_to_vtoc(dsk_label_t *lblp, struct vtoc *vtocp);
void pcdsklbl_vtoc_to_ondsklabel(dsk_label_t *lblp, struct vtoc *vtocp);
void pcdsklbl_dgtoug(struct dk_geom *up, struct dk_label *dp);
void pcdsklbl_ugtodg(struct dk_geom *up, struct dk_label *dp);
void pcinit_pmap(ata_unit_t *unitp);

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_PCATA_H */
