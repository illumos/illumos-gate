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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 *	Copyright (c) 1983-1989 by AT&T.
 *	All rights reserved.
 */

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#ifndef	_SYS_MTIO_H
#define	_SYS_MTIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Structures and definitions for mag tape io control commands
 */

/*
 * structure for MTIOCTOP - mag tape op command
 */
struct mtop	{
	short		mt_op;		/* operations defined below */
	daddr_t		mt_count;	/* how many of them */
};

#if defined(_SYSCALL32)
struct mtop32	{
	short		mt_op;		/* operations defined below */
	daddr32_t	mt_count;	/* how many of them */
};
#endif /* _SYSCALL32 */


/*
 * values for mt_op
 */
#define	MTWEOF		0	/* write an end-of-file record */
#define	MTFSF		1	/* forward space over file mark */
#define	MTBSF		2	/* backward space over file mark (1/2" only ) */
#define	MTFSR		3	/* forward space to inter-record gap */
#define	MTBSR		4	/* backward space to inter-record gap */
#define	MTREW		5	/* rewind */
#define	MTOFFL		6	/* rewind and put the drive offline */
#define	MTNOP		7	/* no operation, sets status only */
#define	MTRETEN		8	/* retension the tape (cartridge tape only) */
#define	MTERASE		9	/* erase the entire tape */
#define	MTEOM		10	/* position to end of media */
#define	MTNBSF		11	/* backward space file to BOF */
#define	MTSRSZ		12	/* set record size */
#define	MTGRSZ		13	/* get record size */
#define	MTLOAD		14	/* for loading a tape (use o_delay to open */
				/* the tape device) */

/*
 * structure for MTIOCGET - mag tape get status command
 */
struct mtget	{
	short		mt_type;	/* type of magtape device */
	/* the following two registers are grossly device dependent */
	short		mt_dsreg;	/* ``drive status'' register */
	short		mt_erreg;	/* ``error'' register */
	/* optional error info. */
	daddr_t		mt_resid;	/* residual count */
	daddr_t		mt_fileno;	/* file number of current position */
	daddr_t		mt_blkno;	/* block number of current position */
	ushort_t	mt_flags;
	short		mt_bf;		/* optimum blocking factor */
};

#if defined(_SYSCALL32)
struct mtget32	{
	short		mt_type;	/* type of magtape device */
	/* the following two registers are grossly device dependent */
	short		mt_dsreg;	/* ``drive status'' register */
	short		mt_erreg;	/* ``error'' register */
	/* optional error info. */
	daddr32_t	mt_resid;	/* residual count */
	daddr32_t	mt_fileno;	/* file number of current position */
	daddr32_t	mt_blkno;	/* block number of current position */
	ushort_t	mt_flags;
	short		mt_bf;		/* optimum blocking factor */
};
#endif /* _SYSCALL32 */

#define	MT_NDENSITIES	4
#define	MT_NSPEEDS	4

/*
 * struct for MTIOCGETDRIVETYPE - get tape config data
 */
struct mtdrivetype {
	char    name[64];		/* Name, for debug */
	char    vid[25];		/* Vendor id and model (product) id */
	char    type;			/* Drive type for driver */
	int	bsize;			/* Block size */
	int	options;		/* Drive options */
	int	max_rretries;		/* Max read retries */
	int	max_wretries;		/* Max write retries */
	uchar_t densities[MT_NDENSITIES];	/* density codes, low->hi */
	uchar_t	default_density;	/* Default density chosen */
	uchar_t speeds[MT_NSPEEDS];	/* speed codes, low->hi */
	ushort_t non_motion_timeout;    /* Inquiry type commands */
	ushort_t io_timeout;		/* io timeout. seconds */
	ushort_t rewind_timeout;	/* rewind timeout. seconds */
	ushort_t space_timeout;		/* space cmd timeout. seconds */
	ushort_t load_timeout;		/* load tape time in seconds */
	ushort_t unload_timeout;	/* Unload tape time in scounds */
	ushort_t erase_timeout;		/* erase timeout. seconds */
};


struct mtdrivetype_request {
	int	size;
	struct  mtdrivetype *mtdtp;
};

#if defined(_SYSCALL32)
struct mtdrivetype_request32 {
	int		size;
	caddr32_t	mtdtp;
};
#endif /* _SYSCALL32 */


/*
 * values for mt_flags
 */
#define	MTF_SCSI	0x01
#define	MTF_REEL	0x02
#define	MTF_ASF		0x04

#define	MTF_TAPE_HEAD_DIRTY	0x08
#define	MTF_TAPE_CLN_SUPPORTED	0x10

/*
 * Constants for mt_type byte (these are somewhat obsolete)
 */
#define	MT_ISTS		0x01		/* vax: unibus ts-11 */
#define	MT_ISHT		0x02		/* vax: massbus tu77, etc */
#define	MT_ISTM		0x03		/* vax: unibus tm-11 */
#define	MT_ISMT		0x04		/* vax: massbus tu78 */
#define	MT_ISUT		0x05		/* vax: unibus gcr */
#define	MT_ISCPC	0x06		/* sun: multibus cpc */
#define	MT_ISAR		0x07		/* sun: multibus archive */
#define	MT_ISSC		0x08		/* sun: SCSI archive */
#define	MT_ISSYSGEN11	0x10		/* sun: SCSI Sysgen, QIC-11 only */
#define	MT_ISSYSGEN	0x11		/* sun: SCSI Sysgen QIC-24/11 */
#define	MT_ISDEFAULT	0x12		/* sun: SCSI default CCS */
#define	MT_ISCCS3	0x13		/* sun: SCSI generic (unknown) CCS */
#define	MT_ISMT02	0x14		/* sun: SCSI Emulex MT02 */
#define	MT_ISVIPER1	0x15		/* sun: SCSI Archive QIC-150 Viper */
#define	MT_ISWANGTEK1	0x16		/* sun: SCSI Wangtek QIC-150 */
#define	MT_ISCCS7	0x17		/* sun: SCSI generic (unknown) CCS */
#define	MT_ISCCS8	0x18		/* sun: SCSI generic (unknown) CCS */
#define	MT_ISCCS9	0x19		/* sun: SCSI generic (unknown) CCS */
#define	MT_ISCCS11	0x1a		/* sun: SCSI generic (unknown) CCS */
#define	MT_ISCCS12	0x1b		/* sun: SCSI generic (unknown) CCS */
#define	MT_ISCCS13	0x1c		/* sun: SCSI generic (unknown) CCS */
#define	MT_ISCCS14	0x1d		/* sun: SCSI generic (unknown) CCS */
#define	MT_ISCCS15	0x1e		/* sun: SCSI generic (unknown) CCS */
#define	MT_ISCCS16	0x1f		/* sun: SCSI generic (unknown) CCS */
#define	MT_ISCDC	0x20		/* sun: SCSI CDC 1/2" cartridge */
#define	MT_ISFUJI	0x21		/* sun: SCSI Fujitsu 1/2" cartridge */
#define	MT_ISKENNEDY	0x22		/* sun: SCSI Kennedy 1/2" reel */
#define	MT_ISHP		0x23		/* sun: SCSI HP 1/2" reel */
#define	MT_ISSTC	0x24		/* sun: SCSI IBM STC 3490 */
#define	MT_ISANRITSU	0x25		/* nihon sun: Anritsu 1/2" reel */
#define	MT_ISCCS23	0x26		/* sun: SCSI generic  1/2" */
#define	MT_ISCCS24	0x27		/* sun: SCSI generic  1/2" */
#define	MT_ISEXABYTE	0x28		/* sun: SCSI Exabyte 8mm cartridge */
#define	MT_ISEXB8500	0x29		/* sun: SCSI Exabyte 8500 8mm cart */
#define	MT_ISWANGTHS	0x2a		/* sun: SCSI Wangtek 6130HS RDAT */
#define	MT_ISWANGDAT	0x2b		/* sun: SCSI WangDAT */
#define	MT_ISPYTHON	0x2c		/* sun: SCSI Archive Python DAT  */
#define	MT_ISCCS28	0x2d		/* sun: SCSI generic DAT CCS */
#define	MT_ISCCS29	0x2e		/* sun: SCSI generic (unknown) CCS */
#define	MT_ISCCS30	0x2f		/* sun: SCSI generic (unknown) CCS */
#define	MT_ISCCS31	0x30		/* sun: SCSI generic (unknown) CCS */
#define	MT_ISCCS32	0x31		/* sun: SCSI generic (unknown) CCS */


/*
 * these are recommended
 */
#define	MT_ISQIC	0x32		/* generic QIC tape drive */
#define	MT_ISREEL	0x33		/* generic reel tape drive */
#define	MT_ISDAT	0x34		/* generic DAT tape drive */
#define	MT_IS8MM	0x35		/* generic 8mm tape drive */
#define	MT_ISOTHER	0x36		/* generic other type of tape drive */

/* more Sun devices */
#define	MT_ISTAND25G	0x37		/* sun: SCSI Tandberg 2.5 Gig QIC */
#define	MT_ISDLT	0x38		/* sun: SCSI DLT tape drive */
#define	MT_ISSTK9840	0x39		/* sun: STK 9840, 9940, 9840B */
#define	MT_ISBMDLT1	0x3a		/* sun: Benchmark DLT1 */
#define	MT_LTO		0x3b		/* sun: LTO,s by Hp, Seagate, IBM .. */

/*
 * Device table structure and data for looking tape name from
 * tape id number.  Used by mt.c.
 */
struct mt_tape_info {
	short	t_type;		/* type of magtape device */
	char	*t_name;	/* printing name */
	char	*t_dsbits;	/* "drive status" register */
	char	*t_erbits;	/* "error" register */
};

/*
 * this table is now obsolete, use MTIOCGETDRIVETYPE ioctl
 *
 * WARNING: this table will be eliminated in some future release
 */
#define	MT_TAPE_INFO  {\
{ MT_ISSYSGEN11,	"Sysgen QIC-11",		0, 0 }, \
{ MT_ISSYSGEN,		"Sysgen QIC-24",		0, 0 }, \
{ MT_ISMT02,		"Emulex MT-02 QIC-24",		0, 0 }, \
{ MT_ISVIPER1,		"Archive QIC-150",		0, 0 }, \
{ MT_ISWANGTEK1,	"Wangtek QIC-150",		0, 0 }, \
{ MT_ISKENNEDY,		"Kennedy 9612 1/2-inch",	0, 0 }, \
{ MT_ISANRITSU,		"Anritsu 1/2-inch",		0, 0 }, \
{ MT_ISHP,		"HP 88780 1/2-inch",		0, 0 }, \
{ MT_ISEXABYTE,		"Exabyte EXB-8200 8mm",		0, 0 }, \
{ MT_ISEXB8500,		"Exabyte EXB-8500 8mm",		0, 0 }, \
{ MT_ISWANGDAT,		"WangDAT 3.81mm",		0, 0 }, \
{ MT_ISWANGTHS,		"Wangtek 4mm RDAT",		0, 0 }, \
{ MT_ISPYTHON,		"Archive Python 4mm Helical Scan",	0, 0 }, \
{ MT_ISSTC,		"STC 1/2\" Cartridge",		0, 0}, \
{ MT_ISTAND25G,		"Tandberg 2.5 Gig QIC",		0, 0}, \
{ MT_ISQIC,		"QIC",		0, 0}, \
{ MT_ISREEL,		"REEL",		0, 0}, \
{ MT_ISDAT,		"DAT",		0, 0}, \
{ MT_IS8MM,		"8mm",		0, 0}, \
{ MT_ISOTHER,		"Other",	0, 0}, \
{ 0 } \
}

/* mag tape io control commands */
#define	MTIOC			('m'<<8)
#define	MTIOCTOP		(MTIOC|1)	/* do a mag tape op */
#define	MTIOCGET		(MTIOC|2)	/* get tape status */
#define	MTIOCGETDRIVETYPE	(MTIOC|3)	/* get tape config data */
#define	MTIOCPERSISTENT		(MTIOC|4)	/* turn on persistent errors */
#define	MTIOCPERSISTENTSTATUS	(MTIOC|5)	/* query persis. err status */
#define	MTIOCLRERR		(MTIOC|6)	/* clear a persitent error */
#define	MTIOCGUARANTEEDORDER	(MTIOC|7)	/* check for guaranteed order */
#define	MTIOCRESERVE		(MTIOC|8)	/* preserve reserve */
#define	MTIOCRELEASE		(MTIOC|9)	/* turnoff preserve reserve */
#define	MTIOCFORCERESERVE	(MTIOC|10)	/* break reservation drive */

#define	MTIOCSTATE		(MTIOC|13)	/* Inquire insert/eject state */

#define	MTIOCREADIGNOREILI  	(MTIOC|14)	/* Enable/Disable ILI */
#define	MTIOCREADIGNOREEOFS 	(MTIOC|15)	/* Enable/Disable Ignore EOF */
#define	MTIOCSHORTFMK		(MTIOC|16)	/* Enable/Disable Short FMK */

/*
 * This state enum is the argument passed to the MTIOCSTATE ioctl.
 */
enum mtio_state { MTIO_NONE, MTIO_EJECTED, MTIO_INSERTED };

#ifndef KERNEL
/*
 * don't use DEFTAPE.
 */
#define	DEFTAPE	"/dev/rmt/0"
#endif

/*
 * Layout of minor device byte
 * 15 - 8    7    6    5    4    3    2    1    0
 * --------------------------------------------
 * |    |    |    |    |    |    |    |    |----| Unit #. lower 2 bits
 * |    |    |    |    |    |    |    |---------- No rewind on close bit....
 * |    |    |    |    |    |----|--------------- Density Select
 * |    |    |    |    |------------------------- Resrvd.(add. campus dens. bit)
 * |    |    |    |------------------------------ BSD behavior
 * |----|----|----------------------------------- Unit #  bit 2-6
 */

#define	MTUNIT(dev)	(((getminor(dev) & 0xff80) >> 5) + \
			    (getminor(dev) & 0x3))
#define	MT_NOREWIND	(1 <<2)
#define	MT_DENSITY_MASK	(3 <<3)
#define	MT_DENSITY1	(0 <<3)		/* Lowest density/format */
#define	MT_DENSITY2	(1 <<3)
#define	MT_DENSITY3	(2 <<3)
#define	MT_DENSITY4	(3 <<3)		/* Highest density/format */
#define	MTMINOR(unit)	(((unit & 0x7fc) << 5) + (unit & 0x3))
#define	MT_BSD		(1 <<6)		/* BSD behavior on close */
#define	MT_DENSITY(dev) ((getminor(dev) & MT_DENSITY_MASK) >> 3)


#ifdef	__cplusplus
}
#endif

#endif /* _SYS_MTIO_H */
