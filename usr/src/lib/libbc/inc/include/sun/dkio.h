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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _sun_dkio_h
#define	_sun_dkio_h

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* #include <sys/ioctl.h> not needed? */
#include <sun/dklabel.h>

/*
 * Structures and definitions for disk io control commands
 */

/*
 * Structures used as data by ioctl calls.
 */

/*
 * Used for controller info
 */
struct dk_info {
	int	dki_ctlr;		/* controller address */
	short	dki_unit;		/* unit (slave) address */
	short	dki_ctype;		/* controller type */
	short	dki_flags;		/* flags */
};

#define	DK_DEVLEN	16		/* device name max length, including */
					/* unit # & NULL (ie - "xyc1") */
/*
 * Used for configuration info
 */
struct dk_conf {
	char	dkc_cname[DK_DEVLEN];	/* controller name (no unit #) */
	u_short	dkc_ctype;		/* controller type */
	u_short	dkc_flags;		/* flags */
	short	dkc_cnum;		/* controller number */
	int	dkc_addr;		/* controller address */
	u_int	dkc_space;		/* controller bus type */
	int	dkc_prio;		/* interrupt priority */
	int	dkc_vec;		/* interrupt vector */
	char	dkc_dname[DK_DEVLEN];	/* drive name (no unit #) */
	short	dkc_unit;		/* unit number */
	short	dkc_slave;		/* slave number */
};

/*
 * Controller types
 */
#define	DKC_UNKNOWN	0
/* 1 used to be Interphase 2180 */
#define	DKC_WDC2880	2
/* 3 used to be Interphase 2181 */
/* 4 used to be Xylogics 440 */
#define	DKC_DSD5215	5
#define	DKC_XY450	6
#define	DKC_ACB4000	7
#define	DKC_MD21	8
/* 9 used to be Xylogics 751 */
#define	DKC_NCRFLOPPY	10
/* #define	DKC_XB1401	10 does not match dkinfo.c*/
#define	DKC_XD7053	11
#define	DKC_SMSFLOPPY	12
#define	DKC_SCSI_CCS	13
#define	DKC_INTEL82072	14	/* floppy ctlr on campus and hydra */
#define	DKC_PANTHER	15
#define DKC_SUN_IPI1	DKC_PANTHER	/* Sun Panther VME/IPI controller */
#define	DKC_MD		16	/* meta-disk (virtual-disk) driver */
#define DKC_CDC_9057	17	/* CDC 9057-321 (CM-3) IPI String Controller */
#define DKC_FJ_M1060	18	/* Fujitsu/Intellistor M1060 IPI-3 SC */

/*
 * Flags
 */
#define	DKI_BAD144	0x01	/* use DEC std 144 bad sector fwding */
#define	DKI_MAPTRK	0x02	/* controller does track mapping */
#define	DKI_FMTTRK	0x04	/* formats only full track at a time */
#define	DKI_FMTVOL	0x08	/* formats only full volume at a time */
#define	DKI_FMTCYL	0x10	/* formats only full cylinders at a time */
#define DKI_HEXUNIT	0x20	/* unit number is printed as 3 hex digits */

/*
 * Used for drive info
 */
struct dk_type {
	u_short dkt_hsect;		/* hard sector count (read only) */
	u_short dkt_promrev;		/* prom revision (read only) */
	u_char	dkt_drtype;		/* drive type (ctlr specific) */
	u_char	dkt_drstat;		/* drive status (ctlr specific, ro) */
};

/*
 * Used for all partitions
 */
struct dk_allmap {
	struct dk_map	dka_map[NDKMAP];
};

/*
 * Used for bad sector map
 */
struct dk_badmap {
	caddr_t dkb_bufaddr;		/* address of user's map buffer */
};

/*
 * Definition of a disk's geometry
 */
struct dk_geom {
	unsigned short	dkg_ncyl;	/* # of data cylinders */
	unsigned short	dkg_acyl;	/* # of alternate cylinders */
	unsigned short	dkg_bcyl;	/* cyl offset (for fixed head area) */
	unsigned short	dkg_nhead;	/* # of heads */
	unsigned short	dkg_obs1;	/* obsolete */
	unsigned short	dkg_nsect;	/* # of data sectors per track */
	unsigned short	dkg_intrlv;	/* interleave factor */
	unsigned short	dkg_obs2;	/* obsolete */
	unsigned short	dkg_obs3;	/* obsolete */
	unsigned short	dkg_apc;	/* alternates per cyl (SCSI only) */
	unsigned short	dkg_rpm;	/* revolutions per minute */
	unsigned short	dkg_pcyl;	/* # of physical cylinders */
	unsigned short	dkg_extra[7];	/* for compatible expansion */
};
/*
 * These defines are for historic compatibility with old drivers.
 */
#define	dkg_bhead	dkg_obs1	/* used to be head offset */
#define	dkg_gap1	dkg_obs2	/* used to be gap1 */
#define	dkg_gap2	dkg_obs3	/* used to be gap2 */

/*
 * Used for generic commands
 */
struct dk_cmd {
	u_short	dkc_cmd;		/* command to be executed */
	int	dkc_flags;		/* execution flags */
	daddr_t	dkc_blkno;		/* disk address for command */
	int	dkc_secnt;		/* sector count for command */
	caddr_t	dkc_bufaddr;		/* user's buffer address */
	u_int	dkc_buflen;		/* size of user's buffer */
};

/*
 * Execution flags.
 */
#define	DK_SILENT	0x01		/* no error messages */
#define	DK_DIAGNOSE	0x02		/* fail if any error occurs */
#define	DK_ISOLATE	0x04		/* isolate from normal commands */
#define	DK_READ		0x08		/* read from device */
#define	DK_WRITE	0x10		/* write to device */

/*
 * Used for disk diagnostics
 */
struct dk_diag {
	u_short	dkd_errcmd;		/* most recent command in error */
	daddr_t	dkd_errsect;		/* most recent sector in error */
	u_char	dkd_errno;		/* most recent error number */
	u_char	dkd_severe;		/* severity of most recent error */
};

/*
 * Used for getting disk error log.
 */
struct dk_loghdr {
	long	dkl_entries;		/* number of dk_log entries */
	long	dkl_max_size;		/* max. size of dk_log table */
	caddr_t	dkl_logbfr;		/* pointer to dk_log table */
};

/*
 * Disk error log table entry.
 */
struct dk_log {
	daddr_t	block;			/* location of block in error */
	u_long	count;			/* number of failures */
	short	type;			/* type of error (e.g. soft error) */
	short	err1;			/* primary error code (e.g sense key) */
	short	err2;			/* secondary error code */
};

/*
 * Dk_log type flags.
 *
 * FIXME:  Really should specify dkd_errno error codes.
 *	For some reason they're specified in the drivers
 *	instead of here??  Should also use those here for
 *	dk_log.type too.
 */
#define	DKL_SOFT	0x01		/* recoverable erro */
#define	DKL_HARD	0x02		/* unrecoverable error */

/* 
 * Used for floppies
 */
struct fdk_char{
	u_char medium;		/* medium type. Unused, why have it? history! */
	int transfer_rate;	/* transfer rate */
	int ncyl;		/* number of cylinders */
	int nhead;		/* number of heads */
	int sec_size;		/* sector size */
	int secptrack;		/* sectors per track */
	int steps;		/* number of steps per  */
};

struct fdk_state {
	int	fkc_bsec;		/* bytes per sector */
	int 	fkc_strack;		/* sectors per track */
	int	fkc_step;		/* step rate */
	int	fkc_rate;		/* data rate */
	int	fkc_error;		/* error returned by controller */
};

struct fdk_cmd {		/* used by generic command */
	struct dk_cmd dcmd;	/* disk command info */
	struct fdk_state fstate; /* floppy state info */
};

/*
 * Floppy commands
 */
#define	FKWRITE 	1
#define	FKREAD  	2
#define	FKSEEK		3
#define	FKREZERO 	4
#define	FKFORMAT_UNIT 	5
#define	FKFORMAT_TRACK 	6

/*
 * Used by FDKGETCHANGE, return state of the sense disk change bit.
 */
#define	FDKGC_HISTORY	0x01	/* disk has changed since last call */
#define	FDKGC_CURRENT	0x02	/* current state of disk change */

/*
 * Used by FDK{G, S}ETDRIVECHAR
 */
struct fdk_drive {
	int fdd_ejectable;	/* does the drive support eject? */
	int fdd_maxsearch;	/* size of per-unit search table */

	int fdd_writeprecomp;	/* cyl to start write prcompensation */
	int fdd_writereduce;	/* cyl to start recucing write current */
	int fdd_stepwidth;	/* width of step pulse in 1 us units */
	int fdd_steprate;	/* step rate in 100 us units */
	int fdd_headsettle;	/* delay, in 100 us units */
	int fdd_headload;	/* delay, in 100 us units */
	int fdd_headunload;	/* delay, in 100 us units */
	int fdd_motoron;	/* delay, in 100 ms units */
	int fdd_motoroff;	/* delay, in 100 ms units */
	int fdd_precomplevel;	/* bit shift, in nano-secs */
	int fdd_pins;		/* defines meaning of pin 1, 2, 4, and 34 */
	int fdd_flags;		/* TRUE READY, Starting Sector #, & Motor On */
};

/*
 * Used by FDK{G, S}ETSEARCH
 */
struct fdk_search {
	int	fdk_numentries; /* number of elements in the table */
	struct fdk_char *fdk_search;
};

/*
 * Used by F_RAW
 */
struct fdraw {
	char	fr_cmd[10];	/* user-supplied command bytes */
	short   fr_cnum;	/* number of command bytes */
	char    fr_result[10];  /* controller-supplied result bytes */
	short	fr_nbytes;	/* number to transfer if read/write command */
	char	*fr_addr;	/* where to transfer if read/write command */
};

/*
 * Floppy raw commands
 */
#define	FRAW_SPECIFY	0x03
#define	FRAW_READID	0x0a
#define	FRAW_SENSE_DRV	0x04
#define	FRAW_REZERO	0x07
#define	FRAW_SEEK	0x0f
#define	FRAW_SENSE_INT	0x08
#define	FRAW_FORMAT	0x0d
#define	FRAW_READTRACK	0x02
#define	FRAW_WRCMD	0x05
#define	FRAW_RDCMD	0x06
#define	FRAW_WRITEDEL	0x09
#define	FRAW_READDEL	0x0c

/*
 * Severity values
 */
#define	DK_NOERROR	0
#define	DK_CORRECTED	1
#define	DK_RECOVERED	2
#define	DK_FATAL	3

/*
 * Error types
 */
#define	DK_NONMEDIA	0		/* not caused by a media defect */
#define	DK_ISMEDIA	1		/* caused by a media defect */


/*
 * Disk io control commands
 */
#define	DKIOCGGEOM	_IOR('d', 2, struct dk_geom)	/* Get geometry */
#define	DKIOCSGEOM	_IOW('d', 3, struct dk_geom)	/* Set geometry */
#define	DKIOCGPART	_IOR('d', 4, struct dk_map)	/* Get partition info */
#define	DKIOCSPART	_IOW('d', 5, struct dk_map)	/* Set partition info */
#define	DKIOCINFO	_IOR('d', 8, struct dk_info)	/* Get info */
#define	DKIOCGCONF	_IOR('d', 126, struct dk_conf)	/* Get conf info */
#define	DKIOCSTYPE	_IOW('d', 125, struct dk_type)	/* Set drive info */
#define	DKIOCGTYPE	_IOR('d', 124, struct dk_type)	/* Get drive info */
#define	DKIOCSAPART	_IOW('d', 123, struct dk_allmap)	/* Set all partitions */
#define	DKIOCGAPART	_IOR('d', 122, struct dk_allmap)	/* Get all partitions */
#define	DKIOCSBAD	_IOW('d', 121, struct dk_badmap)	/* Set bad sector map */
#define	DKIOCGBAD	_IOW('d', 120, struct dk_badmap)	/* Get bad sector map */
#define	DKIOCSCMD	_IOW('d', 119, struct dk_cmd)	/* Set generic cmd */
#define	DKIOCGLOG	_IOR('d', 118, struct dk_loghdr)	/* Get error log */
#define	DKIOCGDIAG	_IOR('d', 116, struct dk_diag)	/* Get diagnostics */
#define	DKIOCWCHK	_IOWR('d', 115, int)		/* Toggle write check */
#define	FDKIOGCHAR	_IOR('d', 114, struct fdk_char)	/* GetCharacteristics */
#define	FDKIOSCHAR	_IOW('d', 113, struct fdk_char)	/* SetCharacteristics */
#define	FDKEJECT	_IO('d', 112)			/* Eject floppy disk */
#define	FDKGETCHANGE	_IOR('d', 111, int)		/* Get diskchng stat */
#define	FDKGETDRIVECHAR	_IOR('d', 110, struct fdk_drive)	/* Get drivechar */
#define	FDKSETDRIVECHAR	_IOW('d', 109, struct fdk_drive)	/* Set drivechar */
#define	FDKGETSEARCH	_IOR('d', 108, struct fdk_search)	/* Get search tbl */
#define	FDKSETSEARCH	_IOW('d', 107, struct fdk_search)	/* Set search tbl */
#define	FDKIOCSCMD	_IOWR('d', 106, struct fdk_cmd)	/* Floppy command */
#define	F_RAW		_IOWR('d', 105, struct fdraw)	/* ECDstyle genericcmd*/

#endif /* !_sun_dkio_h */
