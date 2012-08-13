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
 * Copyright (c) 2012 Gary Mills
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#ifndef	_CPIO_H
#define	_CPIO_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <archives.h>

/* Option Character keys (OC#), where '#' is the option character specified. */

#define	OCa	0x1
#define	OCb	0x2
#define	OCc	0x4
#define	OCd	0x8
#define	OCf	0x10
#define	OCi	0x20
#define	OCk	0x40
#define	OCl	0x80
#define	OCm	0x100
#define	OCo	0x200
#define	OCp	0x400
#define	OCr	0x800
#define	OCs	0x1000
#define	OCt	0x2000
#define	OCu	0x4000
#define	OCv	0x8000
#define	OCA	0x10000
#define	OCB	0x20000
#define	OCC	0x40000
#define	OCE	0x80000
#define	OCH	0x100000
#define	OCI	0x200000
#define	OCL	0x400000
#define	OCM	0x800000
#define	OCO	0x1000000
#define	OCR	0x2000000
#define	OCS	0x4000000
#define	OCV	0x8000000
#define	OC6	0x10000000
#define	BSM	0x20000000
#define	OCP	0x40000000
#define	OCq	0x80000000

/* Sparse file support */
#define	C_ISSPARSE	0200000
#define	S_IFSPARSE	0x10000
#define	HIGH_ORD_MASK	0x30000
#define	S_ISSPARSE(mode) \
	(S_ISREG(mode) && (mode & HIGH_ORD_MASK) == S_IFSPARSE)

/* Invalid option masks for each action option (-i, -o or -p). */

#define	INV_MSK4i	(OCo | OCp | OCA | OCL | OCO)

#define	INV_MSK4o	(OCi | OCp | OCE | OCI | OCR)

#define	INV_MSK4p	(OCf | OCi | OCo | OCr | OCt | OCA \
			| OCE | OCH | OCI | OCO)

/* Header types */

#define	NONE	0	/* No header value verified */
#define	BIN	1	/* Binary */
#define	CHR	2	/* ASCII character (-c) */
#define	ASC	3	/* ASCII with expanded maj/min numbers */
#define	CRC	4	/* CRC with expanded maj/min numbers */
#define	TARTYP	5	/* Tar or USTAR */
#define	SECURE	6	/* Secure system */

/* Differentiate between TAR and USTAR */

#define	TAR	7	/* Regular tar */
#define	USTAR	8	/* IEEE data interchange standard */

#define	ULL_MAX_SIZE	20
#define	UL_MAX_SIZE	10

/* constants for bar, used for extracting bar archives */
#define	BAR	9
#define	BAR_VOLUME_MAGIC	'V'
#define	BARTYP	7
#define	BARSZ	512
#define	BAR_TAPE_SIZE	(126*BARSZ)
#define	BAR_FLOPPY_SIZE	(18*BARSZ)

/* the pathname lengths for the USTAR header */

#define	MAXNAM	256	/* The maximum pathname length */
#define	NAMSIZ	100	/* The maximum length of the name field */
#define	PRESIZ	155	/* The maximum length of the prefix */

/* HDRSZ: header size minus filename field length */

#define	HDRSZ (Hdr.h_name - (char *)&Hdr)

/*
 * IDENT: Determine if two stat() structures represent identical files.
 * Assumes that if the device and inode are the same the files are
 * identical (prevents the archive file from appearing in the archive).
 */

#define	IDENT(a, b) ((a.st_ino == b.st_ino && a.st_dev == b.st_dev) ? 1 : 0)

/*
 * FLUSH: Determine if enough space remains in the buffer to hold
 * cnt bytes, if not, call bflush() to flush the buffer to the archive.
 */

#define	FLUSH(cnt) if ((Buffr.b_end_p - Buffr.b_in_p) < cnt) bflush()

/*
 * FILL: Determine if enough bytes remain in the buffer to meet current needs,
 * if not, call rstbuf() to reset and refill the buffer from the archive.
 */

#define	FILL(cnt) while (Buffr.b_cnt < cnt) rstbuf()

/*
 * VERBOSE: If x is non-zero, call verbose().
 */

#define	VERBOSE(x, name) if (x) verbose(name)

/*
 * FORMAT: Date time formats
 * b - abbreviated month name
 * e - day of month (1 - 31)
 * H - hour (00 - 23)
 * M - minute (00 - 59)
 * Y - year as ccyy
 */

#define	FORMAT	"%b %e %H:%M %Y"

/* Extended system attributes */
#ifndef	VIEW_READONLY
#define	VIEW_READONLY	"SUNWattr_ro"
#endif

#ifndef	VIEW_READWRITE
#define	VIEW_READWRITE	"SUNWattr_rw"
#endif

#define	min(a, b)	((a) < (b) ? (a) : (b))

/* Values used in typeflag field */
#define	REGTYPE		'0'		/* Regular File */
#define	LNKTYPE		'1'		/* Link */
#define	SYMTYPE		'2'		/* Reserved */
#define	CHRTYPE		'3'		/* Character Special File */
#define	BLKTYPE		'4'		/* Block Special File */
#define	DIRTYPE		'5'		/* Directory */
#define	FIFOTYPE	'6'		/* FIFO */
#define	CONTTYPE	'7'		/* Reserved */
#define	XHDRTYPE	'X'		/* Extended header */

#define	INPUT	0	/* -i mode (used for chgreel() */
#define	OUTPUT	1	/* -o mode (used for chgreel() */
#define	APATH	1024	/* maximum ASC or CRC header path length */
#define	CPATH	256	/* maximum -c and binary path length */
#define	BUFSZ	512	/* default buffer size for archive I/O */
#define	CPIOBSZ	8192	/* buffer size for file system I/O */
#define	LNK_INC	500	/* link allocation increment */
#define	MX_BUFS	10	/* max. number of buffers to allocate */

#define	F_SKIP	0	/* an object did not match the patterns */
#define	F_LINK	1	/* linked file */
#define	F_EXTR	2	/* extract non-linked object that matched patterns */

#define	MX_SEEKS	10	/* max. number of lseek attempts after error */
#define	SEEK_ABS	0	/* lseek absolute */
#define	SEEK_REL	1	/* lseek relative */

/*
 * xxx_CNT represents the number of sscanf items that will be matched
 * if the sscanf to read a header is successful.  If sscanf returns a number
 * that is not equal to this, an error occured (which indicates that this
 * is not a valid header of the type assumed.
 */

#define	ASC_CNT	14	/* ASC and CRC headers */
#define	CHR_CNT	11	/* CHR header */

/* These defines determine the severity of the message sent to the user. */

#define	ERR	1	/* Error message (warning) - not fatal */
#define	EXT	2	/* Error message - fatal, causes exit */
#define	ERRN	3	/* Error message with errno (warning) - not fatal */
#define	EXTN	4	/* Error message with errno - fatal, causes exit */
#define	POST	5	/* Information message, not an error */
#define	EPOST	6	/* Information message to stderr */

#define	SIXTH	060000	/* UNIX 6th edition files */

#define	P_SKIP	0	/* File should be skipped */
#define	P_PROC	1	/* File should be processed */

#define	U_KEEP	0	/* Keep the existing version of a file (-u) */
#define	U_OVER	1	/* Overwrite the existing version of a file (-u) */

/*
 * _20K: Allocate the maximum of (20K or (MX_BUFS * Bufsize)) bytes
 * for the main I/O buffer.  Therefore if a user specifies a small buffer
 * size, they still get decent performance due to the buffering strategy.
 */

#define	_20K	20480

#define	HALFWD	1	/* Pad headers/data to halfword boundaries */
#define	FULLWD	3	/* Pad headers/data to word boundaries */
#define	FULLBK	511	/* Pad headers/data to 512 byte boundaries */

/* bar structure */
union b_block {
	char dummy[TBLOCK];
	struct bar_header {
		char mode[8];
		char uid[8];
		char gid[8];
		char size[12];
		char mtime[12];
		char chksum[8];
		char rdev[8];
		char linkflag;

		/*
		 * The following fields are specific to the volume
		 * header.  They are set to zero in all file headers
		 * in the archive.
		 */
		char bar_magic[2];	/* magic number */
		char volume_num[4];	/* volume number */
		char compressed;	/* files compressed = 1 */
		char date[12];		/* date of archive mmddhhmm */
		char start_of_name;	/* start of the filename */
	} dbuf;
};

/* svr32 stat structure -- for -Hodc headers */

typedef struct cpioinfo {
	o_dev_t st_dev;
	o_ino_t st_ino;
	o_mode_t	st_mode;
	o_nlink_t	st_nlink;
	uid_t st_uid;		/* actual uid */
	gid_t st_gid;		/* actual gid */
	o_dev_t st_rdev;
	off_t	st_size;
	time_t	st_modtime;
} cpioinfo_t;

extern void msg(int severity, const char *fmt, ...);
extern void stat_to_svr32_stat(cpioinfo_t *TmpSt, struct stat *FromStat);

/*
 * Allocation wrappers and their flags
 */
#define	E_NORMAL	0x0	/* Return NULL if allocation fails */
#define	E_EXIT		0x1	/* Exit if allocation fails */

extern void *e_realloc(int flag, void *old, size_t newsize);
extern char *e_strdup(int flag, const char *arg);
extern void *e_valloc(int flag, size_t size);
extern void *e_zalloc(int flag, size_t size);

/*
 * If compiling on a system that doesn't
 * support extended attributes, then
 * define a couple of things so we can compile.
 */
#if !defined(O_XATTR)
#define	AT_SYMLINK_NOFOLLOW	0x1000
#define	AT_REMOVEDIR		0x0001
#define	_XATTR_CPIO_MODE	0xB000
#define	_XATTR_HDRTYPE		'E'
#endif /* O_XATTR */

/*
 * Sparse file support
 */
#define	MIN_HOLES_HDRSIZE	(UL_MAX_SIZE + 1 + ULL_MAX_SIZE + 1)

typedef struct holes_list {
	off_t	hl_data;
	off_t	hl_hole;
	struct holes_list *hl_next;
} holes_list_t;

typedef struct holes_info {
	holes_list_t	*holes_list;	/* linked list of holes_list */
	off_t		orig_size;	/* original file size */
	off_t		data_size;	/* compressed file size */
	char		*holesdata;	/* holesdata string */
	size_t		holesdata_sz;	/* string size */
} holes_info_t;

extern	holes_info_t *get_holes_info(int, off_t, boolean_t);
extern	holes_info_t *read_holes_header(const char *, off_t);
extern	int	parse_holesdata(holes_info_t *, const char *);
extern	void	free_holes_info(holes_info_t *);

extern	void	str_fprintf(FILE *, const char *, ...);

#ifdef	__cplusplus
}
#endif

#endif /* _CPIO_H */
