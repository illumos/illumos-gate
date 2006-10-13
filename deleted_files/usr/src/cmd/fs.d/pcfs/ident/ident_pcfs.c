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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<fcntl.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<string.h>
#include	<rpc/types.h>
#include	<sys/types.h>
#include	<sys/fs/pc_label.h>
#include	<sys/dktp/fdisk.h>
#include	<rmmount.h>
#include	<errno.h>

#define	DOS_READLEN	(PC_SECSIZE * 4)
#define	DOS_READLEN_MASK	(DOS_READLEN - 1)

/*
 * We call it a pcfs file system iff:
 *	The "media type" descriptor in the label == the media type
 *		descriptor that's supposed to be the first byte
 *		of the FAT.
 *	The second byte of the FAT is 0xff.
 *	The third byte of the FAT is 0xff.
 *
 *	Assumptions:
 *
 *	1.	I don't really know how safe this is, but it is
 *	mentioned as a way to tell whether you have a dos disk
 *	in my book (Advanced MSDOS Programming, Microsoft Press).
 *	Actually it calls it an "IBM-compatible disk" but that's
 *	good enough for me.
 *
 * 	2.	The FAT is right after the reserved sector(s), and both
 *	the sector size and number of reserved sectors must be gotten
 *	from the boot sector.
 */

static bool_t	ident_fs_offset(int, off_t);
static bool_t	find_dos_part(int);

/*ARGSUSED*/
bool_t
ident_fs(int fd, char *rawpath, bool_t *clean, bool_t verbose)
{
	/*
	 * pcfs is always clean... at least there's no way to tell if
	 * it isn't!
	 */
	*clean = TRUE;

	/* try no offset first (i.e. a floppy?) */
	if (ident_fs_offset(fd, 0L))
		return (TRUE);

	return (find_dos_part(fd));
}

static int
is_dos_drive(uchar_t check)
{
	return ((check == DOSOS12) || (check == DOSOS16) ||
	    (check == DOSHUGE) || (check == FDISK_WINDOWS) ||
	    (check == FDISK_EXT_WIN) || (check == FDISK_FAT95) ||
	    (check == DIAGPART));
}

static int
is_dos_extended(uchar_t check)
{
	return ((check == EXTDOS) || (check == FDISK_EXTLBA));
}

/*
 * find DOS partitions offset *iff* there's no Solaris partition *at all*
 */
static bool_t
find_dos_part(int fd)
{
	union {
		char	mbrb[DOS_READLEN];	/* master boot record buf */
		struct	mboot mbr;
	} mbr_u;
	struct ipart	dosp[FD_NUMPART];
	int		i, extended_part, loop;
	off_t		ssect, nsect, lastseek, diskblk, blk;


	/* seek to start of disk (assume it works) */
	if (lseek(fd, 0L, SEEK_SET) != 0L) {
		return (FALSE);
	}

	/* try to read */
	if (read(fd, mbr_u.mbrb, DOS_READLEN) != DOS_READLEN) {
		return (FALSE);
	}

	/* get pointer to master boot struct and validate */
	if (ltohs(mbr_u.mbr.signature) != MBB_MAGIC) {
		/* not an FDISK table */
		return (FALSE);
	}

	(void) memcpy(dosp, mbr_u.mbr.parts, sizeof (dosp));
	/*
	 * scan fdisk entries, looking for first BIG-DOS/DOSOS16 entry
	 * and also DOSOS12/FDISK_WINDOWS/FDISK_EXT and FDISK_FAT95 entries.
	 */
	extended_part = -1;

	for (i = 0; i < FD_NUMPART; i++) {
		if (is_dos_drive(dosp[i].systid)) {
			if (ident_fs_offset(fd,
				PC_SECSIZE * ltohi(dosp[i].relsect))) {
				return (TRUE);
			}
		} else if (is_dos_extended(dosp[i].systid)) {
			if (extended_part < 0)
				extended_part = i;
		} else if (dosp[i].systid == SUNIXOS ||
		    dosp[i].systid == SUNIXOS2) {
			/* oh oh -- not suposed to be solaris here! */
			return (FALSE);
		}
		/* continue looking */
	}

	if (extended_part < 0)
		return (FALSE);

	lastseek = 0;
	ssect = diskblk = ltohi(dosp[extended_part].relsect);
	nsect = ltohi(dosp[extended_part].numsect);

	/*
	 * No sure how many extended dos partition we can really allocate.
	 * 512 would be enough?
	 */
	for (loop = 0; loop < 512; loop++) {
		if (lastseek ==	diskblk)
			break;

		if (lseek(fd, diskblk * PC_SECSIZE, SEEK_SET)
				!= (diskblk * PC_SECSIZE)) {
			return (FALSE);
		}
		if (read(fd, mbr_u.mbrb, DOS_READLEN) != DOS_READLEN) {
			return (FALSE);
		}

		lastseek = diskblk;

		if (ltohs(mbr_u.mbr.signature) != MBB_MAGIC) {
			/* Not a valid extended partition */
			return (FALSE);
		}

		(void) memcpy(dosp, mbr_u.mbr.parts, sizeof (dosp));

		for (i = 0; i < FD_NUMPART; i++) {
			if (is_dos_drive(dosp[i].systid)) {
				blk = lastseek + ltohi(dosp[i].relsect);
				if (blk == lastseek || blk <= ssect ||
					blk >= (ssect + nsect))
					continue;
				if (ident_fs_offset(fd, PC_SECSIZE * blk)) {
					return (TRUE);
				}
			} else if (is_dos_extended(dosp[i].systid)) {
				if (diskblk != lastseek)
					continue;
				diskblk = ssect + ltohi(dosp[i].relsect);
			}
		}
	}
	return (FALSE);
}

static bool_t
ident_fs_offset(int fd, off_t offset)
{
	uchar_t	pc_stuff[DOS_READLEN];
	uint_t	fat_off;
	bool_t	result = TRUE;

	/* go to start of image */
	if (lseek(fd, offset, SEEK_SET) != offset) {
		result = FALSE;	/* should be able to seek to 0 */
	}

	/* read the boot sector (plus some) */
	if ((result == TRUE) &&
		(read(fd, pc_stuff, DOS_READLEN) != DOS_READLEN)) {
		result = FALSE;
	}

	/* no need to go farther if magic# is wrong */
	if ((result == TRUE) &&
	    (*pc_stuff != (uchar_t)DOS_ID1) &&
	    (*pc_stuff != (uchar_t)DOS_ID2a)) {
		result = FALSE;	/* magic# wrong */
	}

	/* calculate where FAT starts */
	if (result == TRUE) {
		fat_off = ltohs(pc_stuff[PCB_BPSEC]) *
			ltohs(pc_stuff[PCB_RESSEC]);
	}

	/* if offset is too large we probably have garbage */
	if ((result == TRUE) && fat_off >= sizeof (pc_stuff)) {
		uchar_t		pc_stuff2[DOS_READLEN];
		unsigned long	fat_sec_off;	/* offset of FAT sector */
		unsigned int	fat_sub_off;	/* offset w/in sector */

		/* we need to read another sector to get the FAT */
		/* get sec# for FAT */
		fat_sec_off = (fat_off & ~DOS_READLEN_MASK) + offset;
		fat_sub_off = fat_off & DOS_READLEN_MASK;

		/* seek to FAT sec# */
		if (llseek(fd, fat_sec_off, SEEK_SET) != fat_sec_off) {
			result = FALSE;
		}

		/* read the new sector */
		if ((result == TRUE) &&
		    (read(fd, pc_stuff2, DOS_READLEN) != DOS_READLEN)) {
			result = FALSE;
		}

		/* now lets check if we got a good FAT */
		if ((result == TRUE) &&
		    ((pc_stuff[PCB_MEDIA] != pc_stuff2[fat_sub_off]) ||
		    ((uchar_t)0xff != pc_stuff2[fat_sub_off + 1]) ||
		    ((uchar_t)0xff != pc_stuff2[fat_sub_off + 2]))) {
			result = FALSE;
		}
	} else {

		if ((result == TRUE) &&
			((pc_stuff[PCB_MEDIA] != pc_stuff[fat_off]) ||
			((uchar_t)0xff != pc_stuff[fat_off + 1]) ||
			((uchar_t)0xff != pc_stuff[fat_off + 2]))) {
			result = FALSE;
		}
	}

	return (result);
}
