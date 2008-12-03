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

#ifndef	_SYS_FDC_H
#define	_SYS_FDC_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	OTYPCNT
#define	OTYPCNT	5
#endif

typedef struct xlate_tbl {
	int	value;
	uchar_t	code;
} xlate_tbl_t;

/*
 * the floppy disk minor device number is interpreted as follows:
 *
 *	 7 6 5 4 3 2 1 0
 * 	+---------+-----+
 * 	|  drive  | part|
 * 	+---------+-----+
 * where:
 *		drive = instance
 *		part = partition
 */
/*
 * Macros for partition/drive from floppy device number,
 * plus other manifest defines....
 */

#define	PARTITION(x)	(getminor(x) & 7)
#define	DRIVE(x)	(getminor(x) >> 3)
#define	FDUNIT(x)	((x) & 3)	/* unit on controller */
#define	FDCTLR(x)	((x) >> 2)	/* controller instance */
#define	NFDUN	4


/*
 * Floppy drive / diskette type numbers.
 */
#define	FMT_5H	  0
#define	FMT_5Q	  1
#define	FMT_5D9	  2
#define	FMT_5D8	  3
#define	FMT_5D4	  4
#define	FMT_5D16  5
#define	FMT_3E	  6
#define	FMT_3H	  7
#define	FMT_3I	  8
#define	FMT_3M	  9
#define	FMT_3D	  10
#define	FMT_AUTO  11
#define	FMT_MAX	  11
#define	FMT_UNKWN 11


/*
 * Mini- and Micro- Diskettes Attributes Structure
 */
struct fdattr {
	ushort_t fda_rotatespd;		/* rotational speed */
	ushort_t fda_intrlv;		/* interleave factor */

	uchar_t fda_gapl;		/* gap 3 length */
	uchar_t fda_gapf;		/* gap 3 length for format */
};

/*
 * Miscellaneous
 */
#define	FDWRITE	0			/* for fdrw() flag */
#define	FDREAD	1			/* for fdrw() flag */
#define	FDRDONE	86			/*  . read with no retries */

/*
 * Per floppy-drive / diskette state structure
 */

struct fdisk {
	struct fcu_obj	*d_obj;
	int		d_media;	/* drive media capacities */
	struct kstat 	*d_iostat;	/* pointer to iostat statistics */
	int		d_bpsshf;	/* shift count for bytes to sector */

	ksema_t		d_ocsem;	/* sem for serializing opens/closes */

	struct buf	*d_actf;	/* head of wait list */
	struct buf	*d_actl;	/* tail of wait list */
	struct buf	*d_current;	/* currently active buf */
	struct partition d_part[NDKMAP];	/* partitions descriptions */

	/*
	 * Regular open type flags.
	 * Open types BLK, MNT, CHR, SWP assumed to be values 0-3.
	 */
	ulong_t	d_regopen[OTYPCNT - 1];
	ulong_t	d_lyropen[NDKMAP];	/* Layered open counters */

	/*
	 * Exclusive open flags (per partition).
	 *
	 * The rules are that in order to open a partition exclusively,
	 * the partition must be completely closed already. Once any
	 * partition of the device is opened exclusively, no other open
	 * on that partition may succeed until the partition is closed.
	 */
	ulong_t		d_exclmask;	/* set to indicate exclusive open */

	/*
	 * Current drive characteristics type.
	 * If -1, then it was set via an ioctl.  Note that a close
	 * and then an open loses the ioctl set characteristics.
	 */
	signed char	d_curfdtype;
	uchar_t		d_deffdtype;

	uchar_t		d_bsec;		/* encoded bytes_per_sector */
	uchar_t		d_drate;	/* encoded data_rate */
	uchar_t		d_motor;	/* motor-on bit */

	uchar_t		d_hutsrt;	/* encoded head unload & step_rate */
	uchar_t		d_hlt;		/* encoded head load time */
	uchar_t		d_dtl;		/* dtl code */

	int	d_media_timeout;	/* media detection timeout */
	timeout_id_t	d_media_timeout_id; /* media detection timeout id */
	enum dkio_state d_media_state;	/* up-to-date media state */
	int		d_ejected;
	kcondvar_t	d_statecv;	/* condition var for media state */

	ulong_t		d_vtoc_bootinfo[3];	/* from label */
	ulong_t		d_vtoc_version;
	time_t		d_vtoc_timestamp[NDKMAP];
	char		d_vtoc_volume[LEN_DKL_VVOL];
	char		d_vtoc_asciilabel[LEN_DKL_ASCII];
};


/* a place to keep some statistics on what's going on */
struct fdstat {
	/* first operations */
	int rd;		/* count reads */
	int wr;		/* count writes */
	int recal;	/* count recalibrates */
	int form;	/* count format_tracks */
	int other;	/* count other ops */

	/* then errors */
	int reset;	/* count resets */
	int to;		/* count timeouts */
	int run;	/* count overrun/underrun */
	int de;		/* count data errors */
	int bfmt;	/* count bad format errors */
};

/*
 * floppy disk command and status block.
 *
 * Needed to execute a command. Since the floppy chip is
 * single threaded with respect to having only one drive
 * active at a time, this block of information is only
 * valid for the length of a command and gets rewritten
 * for each command.
 */

enum fxstate {
	FXS_START,
	FXS_MTRON,
	FXS_RCAL,
	FXS_DKCHGX,
	FXS_RESTART,
	FXS_RESEEK,
	FXS_SEEK,
	FXS_HDST,
	FXS_RDID,
	FXS_DOIT,
	FXS_DOWT,
	FXS_KILL,
	FXS_RESET,
	FXS_END
};

enum fmtrstate {
	FMS_OFF,
	FMS_START,
	FMS_KILLST,
	FMS_ON,
	FMS_DELAY,
	FMS_IDLE
};

enum fmtrinput {
	FMI_TIMER,
	FMI_STARTCMD,
	FMI_RSTARTCMD,
	FMI_DELAYCMD,
	FMI_IDLECMD
};

struct fdcsb {
	struct buf *csb_bufp;	/* associated buf */
	ddi_dma_handle_t csb_dmahandle;
	int csb_handle_bound;		/* DMA handle has been bound */
	uint_t csb_dmacookiecnt;	/* number of DMA cookies */
	uint_t csb_dmacurrcookie;	/* current cookie number */
	uint_t csb_dmawincnt;		/* number of DMA windows */
	uint_t csb_dmacurrwin;		/* current DMA window */
	ddi_dma_cookie_t csb_dmacookie;
	enum fxstate csb_xstate;	/* Current execution state */
	enum fxstate csb_oldxs;	/* old execution state */
	uchar_t	csb_npcyl;	/* new physical cylinder number */
	uchar_t	csb_drive;	/* floppy unit number */
	uchar_t	csb_ncmds;	/* how many command bytes to send */
	uchar_t	csb_nrslts;	/* number of result bytes gotten */
	uchar_t	csb_opflags;	/* opflags, see below */
	uchar_t	csb_timer;	/* op timer, in 0.1 sec */
	uchar_t	csb_maxretry;	/* maximum retries this operation */
	uchar_t	csb_retrys;	/* how may retrys done so far */
	uchar_t	csb_ourtrys;	/* how may over/underrun retrys done so far */
	uchar_t	csb_status;	/* status returned from hwintr */
	uchar_t	csb_cmdstat;	/* if 0 then success, else failure */
	uchar_t	csb_cmd[10];	/* command to send to chip */
	uchar_t	csb_rslt[10];	/* results from chip */
};

/*
 * defines for csb_opflags
 */
#define	CSB_OFINRPT	0x01		/* generates an interrupt */
#define	CSB_OFDMARD	0x02		/* uses DMA for reading */
#define	CSB_OFDMAWT	0x04		/* uses DMA for writing */
#define	CSB_OFRESLT	0x08		/* generates results */
#define	CSB_OFRAWIOCTL	0x10		/* raw i/o control */

#define	CSB_CMDTO   0x01
#define	CSB_CMDDMA  0x03
#define	CSB_CMDNGNR 0x07


/*
 * 82077AA Controller modes
 */
enum fdcmode077 {
	FDCMODE_AT,
	FDCMODE_PS2,	/* not supported */
	FDCMODE_30
};

/*
 * Per controller data
 */

struct fdcntlr {
	kmutex_t	c_lock;		/* controller mutex */
	kmutex_t	c_dorlock;	/* digital_output_register mutex */
	kcondvar_t	c_iocv;		/* condition var for I/O done */
	ksema_t		c_selsem;	/* sem for select unit */
	boolean_t	c_suspended;	/* if DDI_SUSPENDed */

	dev_info_t	*c_dip;
	int		c_number;	/* logical controller number */
	int		c_regbase;	/* base i/o address */
	int		c_dmachan;	/* DMA channel number */
	int		c_intprio;	/* interrupt priority */
	int		c_intvec;	/* interrupt vector num */
	int		c_chip;
	enum fdcmode077	c_mode;		/* 82077 controller mode */

	ulong_t		c_flags;	/* state information */
	struct kstat	*c_intrstat;	/* interrupt stats pointer */
	struct	fdstat	fdstats;	/* statistics */

	ddi_iblock_cookie_t c_iblock;	/* returned from ddi_add_intr */
	ddi_idevice_cookie_t c_idevice;	/* returned from ddi_add_intr */

	int		c_curunit;	/* current/last selected unit */
	timeout_id_t	c_timeid;	/* watchdog timer id */

	struct	fcu_obj	*c_unit[NFDUN];	/* slave on controller */
	timeout_id_t	c_motort[NFDUN]; /* motor timer id */
	enum fmtrstate	c_mtrstate[NFDUN];
	int		c_curpcyl[NFDUN]; /* current physical cylinder */
	signed char	c_sekdir[NFDUN]; /* direction of last seek */

	struct	fdcsb	c_csb;		/* current csb */

	/*
	 * floppy controller register values
	 */
	uchar_t		c_digout;
	uchar_t		c_drate;	/* only 82072 and 82077AA controllers */
	uchar_t		c_config;	/* DSR on PC/AT with 8272A */
	uchar_t		c_mstat;
	uchar_t		c_data;
	uchar_t		c_digin;

	uchar_t		c_bsec;		/* encoded bytes_per_sector */
	uchar_t		c_hutsrt;	/* encoded head unload & step_rate */
	uchar_t		c_hlt;		/* encoded head load time */
};

/*
 * Controller flags
 */
#define	FCFLG_BUSY	0x01	/* operation in progress */
#define	FCFLG_WANT	0x02	/* csb structure wanted */
#define	FCFLG_WAITMR	0x10	/* waiting for motor to start I/O */
#define	FCFLG_WAITING	0x20	/* waiting on I/O completion */
#define	FCFLG_TIMEOUT	0x80	/* the current operation just timed out */
#define	FCFLG_DSOUT	0x100	/* DENSEL ouput is in use for speed ctl */
#define	FCFLG_3DMODE	0x800	/* ctlr is 3D Mode capable */


/*
 * FDC operations
 */

struct fcobjops {
	int	(*fco_abort)();		/* controller abort */
	int	(*fco_dkinfo)();	/* get disk controller info */

	int	(*fco_select)();	/* select / deselect unit */
	int	(*fco_getchng)();	/* get media change */
	int	(*fco_resetchng)();	/* reset media change */
	int	(*fco_rcseek)();	/* recal / seek */
	int	(*fco_rwbuf)();		/* read /write request */
	int	(*fco_rw)();		/* read /write sector */
	int	(*fco_format)();	/* format track */
	int	(*fco_rwioctl)();	/* raw ioctl */
};

/*
 * FDC unit object
 */

struct fcu_obj {
	ulong_t		fj_flags;	/* state information */
	kmutex_t 	fj_lock;	/* unit mutex */
	caddr_t		fj_data;
	struct fd_drive *fj_drive;	/* pointer to drive characteristics */
	struct fd_char	*fj_chars;	/* ptr to diskette characteristics */
	struct fdattr	*fj_attr;	/* additional diskette attributes */
	dev_info_t	*fj_dip;
	ushort_t	fj_rotspd;	/* rotational speed */
	ulong_t		fj_unit;
	struct fcobjops *fj_ops;
	struct fdcntlr	*fj_fdc;
	ddi_iblock_cookie_t *fj_iblock;
};

/* unit flags (state info) */
#define	FUNIT_DRVATCH		0x001	/* this is drive present */
#define	FUNIT_WPROT		0x004	/* diskette is read only */
#define	FUNIT_CHAROK		0x010	/* characteristics are known */
#define	FUNIT_LABELOK		0x020	/* label was read from disk */
#define	FUNIT_UNLABELED		0x040	/* no label using default */
#define	FUNIT_CHANGED		0x100	/* diskette was changed after open */
#define	FUNIT_CHGDET		0x200	/* diskette removal was detected */
#define	FUNIT_3DMODE		0x4000	/* unit is in fast speed mode */
#define	FUNIT_BUSY		0x8000	/* unit is busy */

#ifdef _VPIX
#define	DRV_NONE	0x00
#define	DRV_DBL		0x01
#define	DRV_QUAD	0x02
#define	DRV_720		0x04	/* LOW_35 gets changed to this for or'ing */
#define	DRV_144		0x08	/* HI35 gets changed to this for or'ing */

/* ioctl numbers used by VPIX */
#define	FIOC		('F'<<8)
#define	F_DTYP		(FIOC|60)	/* returns fd_drvtype */
#define	F_FCR		(FIOC|61)	/* output to Floppy Control Register */
#define	F_DOR		(FIOC|62)	/* output to Digital Output Register */
#define	F_RAW		(FIOC|63)	/* general raw controller interface */
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* !_SYS_FDC_H */
