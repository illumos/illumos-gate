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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1983,1984,1985,1986,1987,1988,1989  AT&T. */
/*	All rights reserved. */

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#ifndef _PROTOCOLS_DUMPRESTORE_H
#define	_PROTOCOLS_DUMPRESTORE_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This header file defines two different versions of the
 * ufsdump/ufsrestore interface.  If the defined constant
 * SUPPORTS_MTB_TAPE_FORMAT is set, the data structures in
 * this header file will support backups of more than 2 terabytes
 * of data.
 *
 * In the old format (the format that only supports dumps
 * of less than 2 terabytes), TP_BSIZE is the size of file blocks
 * on the dump tapes.
 * Note that TP_BSIZE must be a multiple of DEV_BSIZE.
 *
 * In the new format, tp_bsize is used to store the
 * tape block size, which is variable.  The tape block size
 * is like 'fragsize', in that 'c_tapea' in each tape record
 * contains the 'tape block record' number in a signed int.
 * We set TP_BSIZE_MAX to 65536, which will handle 128TB
 * of data.  The new format is indicated by a magic number
 * in the tape header of MTB_MAGIC.  The new format is only
 * used when the size of the backup exceeds 2 TB.  If the
 * backup can be stored in less thatn 2 TB, ufsdump still
 * uses the format indicated by the NFS_MAGIC magic number.
 * Therefore, backups of less than 2 TB are still readable
 * by earlier versions of ufsrestore.
 *
 * NTREC is the number of TP_BSIZE blocks that are written
 * in each tape record. HIGHDENSITYTREC is the number of
 * TP_BSIZE blocks that are written in each tape record on
 * 6250 BPI or higher density tapes.  CARTRIDGETREC is the
 * number of TP_BSIZE (or tp_bsize) blocks that are written
 * in each tape record on cartridge tapes.
 *
 * TP_NINDIR is the number of indirect pointers in a TS_INODE
 * or TS_ADDR record. Note that it must be a power of two.
 *
 */
#define	TP_BSIZE_MAX	65536
#define	TP_BSIZE_MIN	1024
#define	ESIZE_SHIFT_MAX	6	/* shift TP_BSIZE_MIN to TP_BSIZE_MAX */

#ifdef SUPPORTS_MTB_TAPE_FORMAT
#define	TP_BUFSIZE	TP_BSIZE_MAX
extern	int32_t		tp_bsize;
#else
#define	TP_BSIZE	1024
#define	TP_BUFSIZE	TP_BSIZE
#endif /* SUPPORTS_MTB_TAPE_FORMAT */

#define	NTREC		10
#define	HIGHDENSITYTREC	32
#define	CARTRIDGETREC	63
#define	TP_NINDIR	(TP_BSIZE_MIN/2)
#define	TP_NINOS	(TP_NINDIR / sizeof (long))
#define	LBLSIZE		16
#define	NAMELEN		64

#define	OFS_MAGIC	(int)60011
#define	NFS_MAGIC	(int)60012
#define	MTB_MAGIC	(int)60013
#define	CHECKSUM	(int)84446

union u_data {
	char	s_addrs[TP_NINDIR];	/* 1 => data; 0 => hole in inode */
	int32_t	s_inos[TP_NINOS];	/* starting inodes on tape */
};

union u_shadow {
	struct s_nonsh {
		int32_t	c_level;		/* level of this dump */
		char	c_filesys[NAMELEN];	/* dumpped file system name */
		char	c_dev[NAMELEN];		/* name of dumpped device */
		char	c_host[NAMELEN];	/* name of dumpped host */
	} c_nonsh;
	char    c_shadow[1];
};

/* if you change anything here, be sure to change normspcl in byteorder.c */

union u_spcl {
	char dummy[TP_BUFSIZE];
	struct	s_spcl {
		int32_t	c_type;		    /* record type (see below) */
		time32_t c_date;	    /* date of previous dump */
		time32_t c_ddate;	    /* date of this dump */
		int32_t	c_volume;	    /* dump volume number */
		daddr32_t c_tapea;	    /* logical block of this record */
		ino32_t	c_inumber;	    /* number of inode */
		int32_t	c_magic;	    /* magic number (see above) */
		int32_t	c_checksum;	    /* record checksum */
		struct	dinode	c_dinode;   /* ownership and mode of inode */
		int32_t	c_count;	    /* number of valid c_addr entries */
		union	u_data c_data;	    /* see union above */
		char	c_label[LBLSIZE];   /* dump label */
		union	u_shadow c_shadow;  /* see union above */
		int32_t	c_flags;	    /* additional information */
		int32_t	c_firstrec;	    /* first record on volume */
#ifdef SUPPORTS_MTB_TAPE_FORMAT
		int32_t	c_tpbsize;	    /* tape block size */
		int32_t	c_spare[31];	    /* reserved for future uses */
#else
		int32_t c_spare[32];
#endif /* SUPPORTS_MTB_TAPE_FORMAT */
	} s_spcl;
} u_spcl;
#define	spcl u_spcl.s_spcl
#define	c_addr c_data.s_addrs
#define	c_inos c_data.s_inos
#define	c_level c_shadow.c_nonsh.c_level
#define	c_filesys c_shadow.c_nonsh.c_filesys
#define	c_dev c_shadow.c_nonsh.c_dev
#define	c_host c_shadow.c_nonsh.c_host

/*
 * special record types
 */
#define	TS_TAPE		1	/* dump tape header */
#define	TS_INODE	2	/* beginning of file record */
#define	TS_ADDR		4	/* continuation of file record */
#define	TS_BITS		3	/* map of inodes on tape */
#define	TS_CLRI		6	/* map of inodes deleted since last dump */
#define	TS_END		5	/* end of volume marker */
#define	TS_EOM		7	/* floppy EOM - restore compat w/ old dump */

/*
 * flag values
 */
#define	DR_NEWHEADER	1	/* new format tape header */
#define	DR_INODEINFO	2	/* header contains starting inode info */
#define	DR_REDUMP	4	/* dump contains recopies of active files */
#define	DR_TRUEINC	8	/* dump is a "true incremental"	*/
#define	DR_HASMETA	16	/* metadata in this header */



#define	DUMPOUTFMT	"%-32s %c %s"		/* for printf */
						/* name, incno, ctime(date) */
#define	DUMPINFMT	"%258s %c %128[^\n]\n"	/* inverse for scanf */

#ifdef __cplusplus
}
#endif

#endif	/* !_PROTOCOLS_DUMPRESTORE_H */
