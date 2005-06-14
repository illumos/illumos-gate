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

#ifndef _SYS_FDIO_H
#define	_SYS_FDIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Floppy Disk Characteristic Structure
 */
struct fd_char {
	uchar_t fdc_medium;		/* medium type. */
	int fdc_transfer_rate;		/* transfer rate */
	int fdc_ncyl;			/* number of cylinders */
	int fdc_nhead;			/* number of heads */
	int fdc_sec_size;		/* sector size */
	int fdc_secptrack;		/* sectors per track */
	int fdc_steps;			/* number of steps per  */
};

/*
 * Floppy State Structure
 */
struct fd_state {
	int	fds_bsec;		/* bytes per sector */
	int 	fds_strack;		/* sectors per track */
	int	fds_step;		/* step rate */
	int	fds_rate;		/* data rate */
	int	fds_error;		/* error returned by controller */
};

/*
 * Used by FDGETCHANGE, return state of the sense disk change bit.
 */
#define	FDGC_HISTORY	0x01	/* disk has changed since last i/o */
#define	FDGC_CURRENT	0x02	/* current state of disk change */
#define	FDGC_CURWPROT	0x10	/* current state of write protect */
#define	FDGC_DETECTED	0x20	/* previous state of DISK CHANGE */

/*
 * Used by FD{G, S}ETDRIVECHAR
 */
struct fd_drive {
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
 * fdd_flags:
 */
#define	FDD_READY	0x1
#define	FDD_MOTON	0x2
#define	FDD_POLLABLE	0x4

/*
 * Used by FD{G, S}ETSEARCH
 */
struct fd_search {
	int	fds_numentries; /* number of elements in the table */
	struct	fd_char *fds_search;
};

/*
 * Used by FDIOCMD
 */
struct fd_cmd {
	ushort_t	fdc_cmd;	/* command to be executed */
	int		fdc_flags;	/* execution flags */
	daddr_t		fdc_blkno;	/* disk address for command */
	int		fdc_secnt;	/* sector count for command */
	caddr_t		fdc_bufaddr;	/* user's buffer address */
	uint_t		fdc_buflen;	/* size of user's buffer */
};

#if defined(_SYSCALL32)
struct fd_cmd32 {
	ushort_t	fdc_cmd;	/* command to be executed */
	int		fdc_flags;	/* execution flags */
	daddr32_t	fdc_blkno;	/* disk address for command */
	int		fdc_secnt;	/* sector count for command */
	caddr32_t	fdc_bufaddr;	/* user's buffer address */
	uint_t		fdc_buflen;	/* size of user's buffer */
};
#endif /* _SYSCALL32 */

/*
 * Floppy commands
 */
#define	FDCMD_WRITE		1
#define	FDCMD_READ		2
#define	FDCMD_SEEK		3
#define	FDCMD_REZERO		4
#define	FDCMD_FORMAT_UNIT 	5
#define	FDCMD_FORMAT_TRACK	6

/*
 * Execution flags.
 */
#define	FD_SILENT	0x01		/* no error messages */
#define	FD_DIAGNOSE	0x02		/* fail if any error occurs */
#define	FD_ISOLATE	0x04		/* isolate from normal commands */
#define	FD_READ		0x08		/* read from device */
#define	FD_WRITE	0x10		/* write to  device */

/*
 * Used by FDRAW
 */
struct fd_raw {
	char	fdr_cmd[10];	/* user-supplied command bytes */
	short   fdr_cnum;	/* number of command bytes */
	char    fdr_result[10];	/* controller-supplied result bytes */
	ushort_t fdr_nbytes;	/* number to transfer if read/write command */
	caddr_t	fdr_addr;	/* where to transfer if read/write command */
};

#ifdef _SYSCALL32

struct fd_raw32 {
	char	fdr_cmd[10];	/* user-supplied command bytes */
	short   fdr_cnum;	/* number of command bytes */
	char    fdr_result[10];	/* controller-supplied result bytes */
	ushort_t fdr_nbytes;	/* number to transfer if read/write command */
	caddr32_t fdr_addr;	/* where to transfer if read/write command */
};

#endif	/* _SYSCALL32 */


/*
 * Floppy raw commands
 */
#define	FDRAW_SPECIFY	0x03
#define	FDRAW_READID	0x0a
#define	FDRAW_SENSE_DRV	0x04
#define	FDRAW_REZERO	0x07
#define	FDRAW_SEEK	0x0f
#define	FDRAW_SENSE_INT	0x08
#define	FDRAW_FORMAT	0x0d
#define	FDRAW_READTRACK	0x02
#define	FDRAW_WRCMD	0x05
#define	FDRAW_RDCMD	0x06
#define	FDRAW_WRITEDEL	0x09
#define	FDRAW_READDEL	0x0c


/*
 * Disk io control commands
 */
#define	FDIOC		(0x04 << 8)
#define	FDIOGCHAR	(FDIOC|51)		/* GetCharacteristics */
#define	FDIOSCHAR	(FDIOC|52)		/* SetCharacteristics */
#define	FDEJECT		(FDIOC|53)		/* Eject floppy disk */
#define	FDGETCHANGE	(FDIOC|54)		/* Get diskchng stat */
#define	FDGETDRIVECHAR	(FDIOC|55)		/* Get drivechar */
#define	FDSETDRIVECHAR	(FDIOC|56)		/* Set drivechar */
#define	FDGETSEARCH	(FDIOC|57)		/* Get search tbl */
#define	FDSETSEARCH	(FDIOC|58)		/* Set search tbl */
#define	FDIOCMD		(FDIOC|59)		/* Floppy command */
#define	FDRAW		(FDIOC|70)		/* ECDstyle genericcmd */
#define	FDDEFGEOCHAR	(FDIOC|86)		/* restore default geometry */
						/* & characteristics */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FDIO_H */
