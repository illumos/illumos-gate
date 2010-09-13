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
 * Copyright (c) 1989-1994,1997-1998,2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_FDVAR_H
#define	_SYS_FDVAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	OTYPCNT
#define	OTYPCNT	5
#endif
#ifndef	NDKMAP
#define	NDKMAP	8
#endif

/*
 * Compile with our without high level interrupt in trap window
 */

/* #define	NO_TRAPWIN_INTR	*/

/*
 * Macros for partition/unit from floppy device number,
 * plus other manifest defines....
 */

#define	FDUNITSHIFT	(3)
#define	FDINSTSHIFT	(2 + FDUNITSHIFT)
#define	FDPARTITION(x)	(getminor(x) & 0x7)
#define	FDUNIT(x)	((getminor(x) >> FDUNITSHIFT) & 0x3)

#define	FDCTLR(x)	(getminor(x) >> FDINSTSHIFT)	/* instance */

/*
 * Structure definitions for the floppy driver.
 */

/*
 * floppy disk command and status block.
 *
 * Needed to execute a command. Since the floppy chip is
 * single threaded with respect to having only one drive
 * active at a time, this block of information is only
 * valid for the length of a commnand and gets rewritten
 * for each command.
 */

#ifndef	_ASM
struct fdcsb {
	caddr_t	csb_addr;	/* Data buffer address */
	uint_t	csb_len;	/* Data buffer Length */
	caddr_t	csb_raddr;	/* modified data buffer address */
	uint_t	csb_rlen;	/* modified data buffer len (resid) */
	uchar_t	csb_opmode;	/* Current operating mode */
	uchar_t	csb_unit;	/* floppy slave unit number */
	uchar_t	csb_ncmds;	/* how many command bytes to send */
	uchar_t	csb_nrslts;	/* number of result bytes gotten */
	uchar_t	csb_opflags;	/* opflags, see below */
	uchar_t	csb_maxretry;	/* maximum retries this opertion */
	uchar_t	csb_retrys;	/* how may retrys done so far */
	uchar_t	csb_status;	/* status returned from hwintr */
	uchar_t	csb_cmdstat;	/* if 0 then success, else failure */
	uchar_t	csb_cmds[10];	/* commands to send to chip */
	uchar_t	csb_rslt[10];	/* results from chip */
	uchar_t  csb_dcsr_rslt;  /* set to 1 if there's an error in the DCSR */
	uchar_t	csb_dma_rslt;	/* set to 1 if there's an error with the DMA */
	ddi_dma_cookie_t csb_dmacookie; /* DMA cookie */

	uint_t	csb_ccount;	/* no. of DMA cookies for current window */
	uint_t	csb_nwin;	/* no. of DMA windows */
	uint_t	csb_windex;	/* DMA window currently in use */
	uint_t	csb_read;	/* indicates read or write */
};
#endif	/* !_ASM */

/*
 * defines for csb_opflags
 */
#define	CSB_OFIMMEDIATE	0x01		/* grab results immediately */
#define	CSB_OFSEEKOPS	0x02		/* seek/recal type cmd */
#define	CSB_OFXFEROPS	0x04		/* read/write type cmd */
#define	CSB_OFRAWIOCTL	0x10		/* raw ioctl - no recovery */
#define	CSB_OFNORESULTS	0x20		/* no results at all */
#define	CSB_OFTIMEIT	0x40		/* timeout (timer) */

#define	CSB_CMDTO 0x01

/*
 * csb_read flags
 */
#define	CSB_NULL	0x0
#define	CSB_READ	0x1
#define	CSB_WRITE	0x2

#ifndef	_ASM
#ifndef	_GENASSYM

/*
 * Define a structure to hold the packed default labels,
 * based on the real dk_label structure - but shorter
 * than 512 bytes. Now only used to define default info
 */
struct packed_label {
	char		dkl_vname[128];	/* for ascii compatibility */
	unsigned short	dkl_rpm;	/* rotations per minute */
	unsigned short	dkl_pcyl;	/* # physical cylinders */
	unsigned short	dkl_apc;	/* alternates per cylinder */
	unsigned short	dkl_intrlv;	/* interleave factor */
	unsigned short	dkl_ncyl;	/* # of data cylinders */
	unsigned short	dkl_acyl;	/* # of alternate cylinders */
	unsigned short	dkl_nhead;	/* # of heads in this partition */
	unsigned short	dkl_nsect;	/* # of 512 byte sectors per track */
	struct dk_map32	dkl_map[NDKMAP]; /* partition map, see dkio.h */
	struct dk_vtoc  dkl_vtoc;	/* vtoc stuff from AT&T SVr4 */
};

/*
 * Per drive data
 */
struct fdunit {

	/*
	 * Packed label for this unit
	 */
	struct	dk_label un_label;

	/*
	 * Pointer to iostat statistics
	 */
	struct kstat *un_iostat;	/* iostat numbers */

	/*
	 * Layered open counters
	 */
	uint_t	un_lyropen[NDKMAP];

	/*
	 * Regular open type flags. If
	 * NDKMAP gets > 8, change the
	 * uchar_t type.
	 *
	 * Open types BLK, MNT, CHR, SWP
	 * assumed to be values 0-3.
	 */
	uchar_t	un_regopen[OTYPCNT - 1];

	/*
	 * Exclusive open flags (per partition).
	 *
	 * The rules are that in order to open
	 * a partition exclusively, the partition
	 * must be completely closed already. Once
	 * any partition of the device is opened
	 * exclusively, no other open on that
	 * partition may succeed until the partition
	 * is closed.
	 *
	 * If NDKMAP gets > 8, this must change.
	 */
	uchar_t	un_exclmask;		/* set to indicate exclusive open */

	struct	fd_char *un_chars;	/* ptr to diskette characteristics */
	char	un_curfdtype;		/* current driver characteristics */
					/* type. If -1, then it was set */
					/* via an ioctl. Note that a close */
					/* and then and open loses the */
					/* ioctl set characteristics. */

	struct fd_drive *un_drive;	/* ptr to drive characteristics */
	int	un_unit_no;		/* drive id number */
	uchar_t	un_flags;		/* state information */
	clock_t	un_media_timeout;	/* media detection timeout */
	timeout_id_t un_media_timeout_id; /* media detection timeout id */
	enum dkio_state	un_media_state;	/* up-to-date media state */
	int	un_ejected;
	short	un_state;		/* Current power level of drive */
};

/* unit flags (state info) */
#define	FDUNIT_DRVCHECKED	0x01	/* this is drive present */
#define	FDUNIT_DRVPRESENT	0x02	/* this is drive present */
/* (the presence of a diskette is another matter) */
#define	FDUNIT_CHAROK		0x04	/* characteristics are known */
#define	FDUNIT_UNLABELED	0x10	/* no label using default */
#define	FDUNIT_CHANGED		0x20	/* diskette was changed after open */
#define	FDUNIT_MEDIUM		0x40	/* fd drive is in medium density */
#define	FDUNIT_SET_SPEED	0x80	/* Flag to force updating the */
					/* registers with current speed */

#endif	/* !_GENASSYM */

/* unit flags for power (un_power) */
#define	FD_STATE_NORMAL		0x0 /* Normal running state */
#define	FD_STATE_SUSPENDED	0x1 /* Device suspended for cpr */
#define	FD_STATE_STOPPED	0x2 /* Device is stopped, can be turned off */

/*
 * --------|   fd_detach:DDI_SUSPEND ncmds may be != 0 |-----------|
 * |running|------------------------------------------>|           |
 * |NORMAL |  fd_attach:DDI_RESUME                     |           |
 * |       |<------------------------------------------| SUSPENDED |
 * |       |                                           |           |
 * |       |                                           -------------
 * |       |                                                ^
 * |       |                                                |DDI_SUSPEND
 * |       |                                                |
 * |       | fd_power: PM_LEVEL_OFF, ncmds == 0         -------------
 * |       |------------------------------------------->|STOPPED     |
 * |       | fd_power: PM_LEVEL_ON                      |            |
 * |       |<-------------------------------------------|            |
 * --------                                              ------------|
 *
 * running => FD_STATE_NORMAL
 *
 */

/* flags for power levels for auto power management */
#define	PM_LEVEL_ON	0x1   /* Changes the state to FD_STATE_STOPPED */
#define	PM_LEVEL_OFF	0x0   /* Changes the state to FD_STATE_NORMAL */

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
 * Per controller data
 */

struct fdctlr {
	struct	fdctlr	*c_next;	/* next in a linked list */
	union  fdcreg   *c_reg;		/* controller registers */
	volatile uchar_t *c_control; 	/* addr of c_reg->fdc_control */
	uchar_t		*c_fifo;	/* addr of c_reg->fdc_fifo */
	uchar_t		*c_dor;		/* addr of c_reg->fdc_dor (077) */
	uchar_t		*c_dir;		/* addr of c_reg->fdc_dir (077) */
	caddr_t		*c_dma_regs;	/* DMA engine registers */
	uint_t		c_fdtype;	/* type of ctlr */
	uint_t		*c_hiintct;	/* for convenience.. */
	uint_t		c_softic;	/* for use by hi level interrupt */
	uchar_t		c_fasttrap;	/* 1 if fast traps enabled, else 0 */
	struct	fdcsb	c_csb;		/* current csb */
	kmutex_t	c_hilock;	/* high level mutex */
	kmutex_t	c_lolock;	/* low level mutex */
	kcondvar_t	c_iocv;		/* condition var for I/O done */
	kcondvar_t	c_csbcv;	/* condition var for owning csb */
	kcondvar_t	c_motoncv;	/* condition var for motor on */
	kcondvar_t	c_statecv;	/* condition var for media state */
	kcondvar_t	c_suspend_cv;  /* Cond Var on power management */
	ksema_t		c_ocsem;	/* sem for serializing opens/closes */
	ddi_iblock_cookie_t c_block;	/* returned from ddi_add_fastintr */
	ddi_softintr_t	c_softid;	/* returned from ddi_add_softintr */
	dev_info_t	*c_dip;		/* controller's dev_info node */
	timeout_id_t	c_timeid;	/* watchdog timer id */
	timeout_id_t	c_mtimeid;	/* motor off timer id */
	struct	fdunit	*c_un;		/* unit on controller */
	struct	buf	*c_actf;	/* head of wait list */
	struct	buf	*c_actl;	/* tail of wait list */
	struct	buf	*c_current;	/* currently active buf */
	struct kstat	*c_intrstat;	/* interrupt stats pointer */
	struct	fdstat	fdstats;	/* statistics */
	uchar_t		c_flags;	/* state information */
	caddr_t		c_auxiova;	/* auxio virtual address */
	uchar_t		c_auxiodata;	/* auxio data to enable TC */
	uchar_t		c_auxiodata2;	/* auxio data to disable TC */
	ddi_acc_handle_t c_handlep_cont;
					/* data access handle for controller */
	ddi_acc_handle_t c_handlep_dma; /* data access handle for DMA engine */
	ddi_acc_handle_t c_handlep_aux;  /* data access handle for aux regs */
	ddi_dma_handle_t c_dmahandle; 	/* DMA handle */
	uint_t		 *c_auxio_reg; 	/* auxio registers */
	ddi_dma_attr_t 	c_fd_dma_lim;	/* DMA limit structure */
	caddr_t		dma_buf;	/* Temporary DMAble buffer */
	ddi_acc_handle_t c_dma_buf_handle; /* DMA handle for dma_buf */
	uint_t		sb_dma_channel; /* 8237 dma channel no. */
	uchar_t		sb_dma_lock;	/* Status of DMA lock by isadma */
};
#endif	/* !_ASM */

/* types of controllers supported by this driver */
#define	FDCTYPE_82072	0x0001
#define	FDCTYPE_82077   0x0002
#define	FDCTYPE_CTRLMASK 0x000f

/* types of io chips which indicates the type of auxio register */
#define	FDCTYPE_MACHIO		0x0010
#define	FDCTYPE_SLAVIO		0x0020
#define	FDCTYPE_CHEERIO		0x0040
#define	FDCTYPE_SB		0x0080
#define	FDCTYPE_AUXIOMASK 	0x00f0

/* Method used for transferring data */
#define	FDCTYPE_DMA		0x1000	/* supports DMA for the floppy */
#define	FDCTYPE_DMA8237		FDCTYPE_DMA	/* 8237 DMA controller */
#define	FDCTYPE_TRNSFER_MASTK	0xf000

/*
 * Early revs of the 82077 have a bug by which they
 * will not respond to the TC (Terminal count) signal.
 * Because this behavior is exhibited on the clone machines
 * for which the 077 code has been targeted, special workaround
 * logic has had to implemented for read/write commands.
 */
#define	FDCTYPE_TCBUG	0x0100
#define	FDCTYPE_BUGMASK	0x0f00

/*
 * Controller flags
 */
#define	FDCFLG_BUSY	0x01	/* operation in progress */
#define	FDCFLG_WANT	0x02	/* csb structure wanted */
#define	FDCFLG_WAITING	0x04	/* waiting on I/O completion */
#define	FDCFLG_TIMEDOUT	0x08	/* the current operation just timed out */


#ifndef	_ASM
/*
 * Miscellaneous
 */
#define	FDREAD	1			/* for fdrw() flag */
#define	FDWRITE	2			/* for fdrw() flag */
#define	FD_CRETRY 1000000		/* retry while sending comand */
#define	FD_RRETRY 1000000		/* retry while getting results */
#define	FDXC_SLEEP	0x1		/* tell fdexec to sleep 'till done */
#define	FDXC_CHECKCHG	0x2		/* tell fdexec to check disk chnged */
#define	FD_SB_DMA_ALIGN	0x10000		/* DMA alignment for South Bridge */


/*
 * flags/masks for error printing.
 * the levels are for severity
 */
#define	FDEP_L0		0	/* chatty as can be - for debug! */
#define	FDEP_L1		1	/* best for debug */
#define	FDEP_L2		2	/* minor errors - retries, etc. */
#define	FDEP_L3		3	/* major errors */
#define	FDEP_L4		4	/* catastophic errors, don't mask! */
#define	FDEP_LMAX	4	/* catastophic errors, don't mask! */
#define	FDERRPRINT(l, m, args)	\
	{ if (((l) >= fderrlevel) && ((m) & fderrmask)) cmn_err args; }

/*
 * for each function, we can mask off its printing by clearing its bit in
 * the fderrmask.  Some functions (attach, ident) share a mask bit
 */
#define	FDEM_IDEN 0x00000001	/* fdidentify */
#define	FDEM_ATTA 0x00000001	/* fdattach */
#define	FDEM_SIZE 0x00000002	/* fdsize */
#define	FDEM_OPEN 0x00000004	/* fdopen */
#define	FDEM_GETL 0x00000008	/* fdgetlabel */
#define	FDEM_CLOS 0x00000010	/* fdclose */
#define	FDEM_STRA 0x00000020	/* fdstrategy */
#define	FDEM_STRT 0x00000040	/* fdstart */
#define	FDEM_RDWR 0x00000080	/* fdrdwr */
#define	FDEM_CMD  0x00000100	/* fdcmd */
#define	FDEM_EXEC 0x00000200	/* fdexec */
#define	FDEM_RECO 0x00000400	/* fdrecover */
#define	FDEM_INTR 0x00000800	/* fdintr */
#define	FDEM_WATC 0x00001000	/* fdwatch */
#define	FDEM_IOCT 0x00002000	/* fdioctl */
#define	FDEM_RAWI 0x00004000	/* fdrawioctl */
#define	FDEM_DUMP 0x00008000	/* fddump */
#define	FDEM_GETC 0x00010000	/* fdgetcsb */
#define	FDEM_RETC 0x00020000	/* fdretcsb */
#define	FDEM_RESE 0x00040000	/* fdreset */
#define	FDEM_RECA 0x00080000	/* fdrecalseek */
#define	FDEM_FORM 0x00100000	/* fdformat */
#define	FDEM_RW   0x00200000	/* fdrw */
#define	FDEM_CHEK 0x00400000	/* fdcheckdisk */
#define	FDEM_DSEL 0x00800000	/* fdselect */
#define	FDEM_EJEC 0x01000000	/* fdeject */
#define	FDEM_SCHG 0x02000000	/* fdsense_chng */
#define	FDEM_PACK 0x04000000	/* fdpacklabel */
#define	FDEM_MODS 0x08000000	/* _init, _info, _fini */
#define	FDEM_MOFF 0x10000000	/* fdmotoff */
#define	FDEM_SDMA 0x20000000    /* fdstart_dma */
#define	FDEM_PWR  0x40000000	/* fd power management */
#define	FDEM_ALL  0xFFFFFFFF	/* all */

#endif	/* !_ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* !_SYS_FDVAR_H */
