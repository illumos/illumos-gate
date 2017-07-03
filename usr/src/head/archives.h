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
 * Copyright (c) 1988,1997-1998,2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


#ifndef	_ARCHIVES_H
#define	_ARCHIVES_H

#include <tar.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* Magic numbers */

#define	CMN_ASC	0x070701	/* Cpio Magic Number for ASCii header */
#define	CMN_BIN	070707		/* Cpio Magic Number for Binary header */
#define	CMN_BBS	0143561		/* Cpio Magic Number for Byte-Swap header */
#define	CMN_CRC	0x070702	/* Cpio Magic Number for CRC header */
#define	CMS_ASC	"070701"	/* Cpio Magic String for ASCii header */
#define	CMS_CHR	"070707"	/* Cpio Magic String for CHR (-c) header */
#define	CMS_CRC	"070702"	/* Cpio Magic String for CRC header */
#define	CMS_LEN	6		/* Cpio Magic String LENgth */

/* Various header and field lengths */

#define	CHRSZ	76		/* -c hdr size minus filename field */
#define	ASCSZ	110		/* ASC and CRC hdr size minus filename field */
#define	TARSZ	512		/* TAR hdr size */

#define	HNAMLEN	256	/* maximum filename length for binary and -c headers */
#define	EXPNLEN	1024	/* maximum filename length for ASC and CRC headers */
#define	HTIMLEN	2	/* length of modification time field */
#define	HSIZLEN	2	/* length of file size field */

/* cpio binary header definition */

struct hdr_cpio {
	short	h_magic,		/* magic number field */
		h_dev;			/* file system of file */
	ushort_t h_ino,			/* inode of file */
		h_mode,			/* modes of file */
		h_uid,			/* uid of file */
		h_gid;			/* gid of file */
	short	h_nlink,		/* number of links to file */
		h_rdev,			/* maj/min numbers for special files */
		h_mtime[HTIMLEN],	/* modification time of file */
		h_namesize,		/* length of filename */
		h_filesize[HSIZLEN];	/* size of file */
	char	h_name[HNAMLEN];	/* filename */
};

/* cpio ODC header format */

struct c_hdr {
	char	c_magic[CMS_LEN],
		c_dev[6],
		c_ino[6],
		c_mode[6],
		c_uid[6],
		c_gid[6],
		c_nlink[6],
		c_rdev[6],
		c_mtime[11],
		c_namesz[6],
		c_filesz[11],
		c_name[HNAMLEN];
};

/* -c and CRC header format */

struct Exp_cpio_hdr {
	char	E_magic[CMS_LEN],
		E_ino[8],
		E_mode[8],
		E_uid[8],
		E_gid[8],
		E_nlink[8],
		E_mtime[8],
		E_filesize[8],
		E_maj[8],
		E_min[8],
		E_rmaj[8],
		E_rmin[8],
		E_namesize[8],
		E_chksum[8],
		E_name[EXPNLEN];
};

/* Tar header structure and format */

#define	TBLOCK	512	/* length of tar header and data blocks */
#define	TNAMLEN	100	/* maximum length for tar file names */
#define	TMODLEN	8	/* length of mode field */
#define	TUIDLEN	8	/* length of uid field */
#define	TGIDLEN	8	/* length of gid field */
#define	TSIZLEN	12	/* length of size field */
#define	TTIMLEN	12	/* length of modification time field */
#define	TCRCLEN	8	/* length of header checksum field */

/* tar header definition */

union tblock {
	char dummy[TBLOCK];
	struct tar_hdr {
		char	t_name[TNAMLEN],	/* name of file */
			t_mode[TMODLEN],	/* mode of file */
			t_uid[TUIDLEN],		/* uid of file */
			t_gid[TGIDLEN],		/* gid of file */
			t_size[TSIZLEN],	/* size of file in bytes */
			t_mtime[TTIMLEN],	/* modification time of file */
			t_cksum[TCRCLEN],	/* checksum of header */
			t_typeflag,
			t_linkname[TNAMLEN],	/* file this file linked with */
			t_magic[TMAGLEN],
			t_version[TVERSLEN],
			t_uname[32],
			t_gname[32],
			t_devmajor[8],
			t_devminor[8],
			t_prefix[155];
	} tbuf;
};

/* volcopy tape label format and structure */

#define	VMAGLEN 8
#define	VVOLLEN 6
#define	VFILLEN 464

struct volcopy_label {
	char	v_magic[VMAGLEN],
		v_volume[VVOLLEN],
		v_reels,
		v_reel;
	int	v_time,
		v_length,
		v_dens,
		v_reelblks,	/* u370 added field */
		v_blksize,	/* u370 added field */
		v_nblocks;	/* u370 added field */
	char	v_fill[VFILLEN];
	int	v_offset;	/* used with -e and -reel options */
	int	v_type;		/* does tape have nblocks field? */
};

/*
 * Define archive formats for extended attributes.
 *
 * Extended attributes are stored in two pieces.
 * 1. An attribute header which has information about
 *    what file the attribute is for and what the attribute
 *    is named.
 * 2. The attribute record itself.  Stored as a normal file type
 *    of entry.
 * Both the header and attribute record have special modes/typeflags
 * associated with them.
 *
 * The names of the header in the archive look like:
 * /dev/null/attr.hdr
 *
 * The name of the attribute looks like:
 * /dev/null/attr.
 *
 * This is done so that an archiver that doesn't understand these formats
 * can just dispose of the attribute records unless the user chooses to
 * rename them via cpio -r or pax -i
 *
 * The format is composed of a fixed size header followed
 * by a variable sized xattr_buf. If the attribute is a hard link
 * to another attribute, then another xattr_buf section is included
 * for the link.
 *
 * The xattr_buf is used to define the necessary "pathing" steps
 * to get to the extended attribute.  This is necessary to support
 * a fully recursive attribute model where an attribute may itself
 * have an attribute.
 *
 * The basic layout looks like this.
 *
 *     --------------------------------
 *     |                              |
 *     |         xattr_hdr            |
 *     |                              |
 *     --------------------------------
 *     --------------------------------
 *     |                              |
 *     |        xattr_buf             |
 *     |                              |
 *     --------------------------------
 *     --------------------------------
 *     |                              |
 *     |      (optional link info)    |
 *     |                              |
 *     --------------------------------
 *     --------------------------------
 *     |                              |
 *     |      attribute itself        |
 *     |      stored as normal tar    |
 *     |      or cpio data with       |
 *     |      special mode or         |
 *     |      typeflag                |
 *     |                              |
 *     --------------------------------
 *
 */
#define	XATTR_ARCH_VERS	"1.0"

/*
 * extended attribute fixed header
 *
 * h_version		format version.
 * h_size               size of header + variable sized data sections.
 * h_component_len      Length of entire pathing section.
 * h_link_component_len Length of link component section.  Again same definition
 *                      as h_component_len.
 */
struct xattr_hdr {
	char	h_version[7];
	char	h_size[10];
	char	h_component_len[10];	   /* total length of path component */
	char	h_link_component_len[10];
};

/*
 * The name is encoded like this:
 * filepathNULattrpathNUL[attrpathNULL]...
 */
struct xattr_buf {
	char	h_namesz[7];   /* length of h_names */
	char	h_typeflag;    /* actual typeflag of file being archived */
	char	h_names[1];	/* filepathNULattrpathNUL... */
};

/*
 * Special values for tar archives
 */

/*
 * typeflag for tar archives.
 */

/*
 * Attribute hdr and attribute files have the following typeflag
 */
#define	_XATTR_HDRTYPE		'E'

/*
 * For cpio archives the header and attribute have
 * _XATTR_CPIO_MODE ORED into the mode field in both
 * character and binary versions of the archive format
 */
#define	_XATTR_CPIO_MODE	0xB000

#ifdef	__cplusplus
}
#endif

#endif	/* _ARCHIVES_H */
