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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * fsck_pcfs -- routines for manipulating the FAT.
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <libintl.h>
#include <sys/dktp/fdisk.h>
#include <sys/fs/pc_fs.h>
#include <sys/fs/pc_dir.h>
#include <sys/fs/pc_label.h>
#include "pcfs_common.h"
#include "fsck_pcfs.h"

extern	int32_t	BytesPerCluster;
extern	int32_t	TotalClusters;
extern	int32_t	LastCluster;
extern	off64_t	FirstClusterOffset;
extern	off64_t	PartitionOffset;
extern	bpb_t	TheBIOSParameterBlock;
extern	int	ReadOnly;
extern	int	IsFAT32;
extern	int	Verbose;

static	uchar_t	*TheFAT;
static	int	FATRewriteNeeded = 0;

int32_t		FATSize;
short		FATEntrySize;

static off64_t
seekFAT(int fd)
{
	off64_t seekto;
	/*
	 *  The FAT(s) immediately follows the reserved sectors.
	 */
	seekto = TheBIOSParameterBlock.bpb.resv_sectors *
		TheBIOSParameterBlock.bpb.bytes_per_sector + PartitionOffset;
	return (lseek64(fd, seekto, SEEK_SET));
}

void
getFAT(int fd)
{
	ssize_t bytesRead;

	if (TheFAT != NULL) {
		return;
	} else if ((TheFAT = (uchar_t *)malloc(FATSize)) == NULL) {
		mountSanityCheckFails();
		perror(gettext("No memory for a copy of the FAT"));
		(void) close(fd);
		exit(7);
	}
	if (seekFAT(fd) < 0) {
		mountSanityCheckFails();
		perror(gettext("Cannot seek to FAT"));
		(void) close(fd);
		exit(7);
	}
	if (Verbose)
		(void) fprintf(stderr,
		    gettext("Reading FAT\n"));
	if ((bytesRead = read(fd, TheFAT, FATSize)) != FATSize) {
		mountSanityCheckFails();
		if (bytesRead < 0) {
			perror(gettext("Cannot read a FAT"));
		} else {
			(void) fprintf(stderr,
			    gettext("Short read of FAT."));
		}
		(void) close(fd);
		exit(7);
	}
	/*
	 * XXX - might want to read the other copies of the FAT
	 * for comparison and/or to use if the first one seems hosed.
	 */
	if (Verbose) {
		(void) fprintf(stderr,
		    gettext("Dump of FAT's first 32 bytes.\n"));
		header_for_dump();
		dump_bytes(TheFAT, 32);
	}
}

void
writeFATMods(int fd)
{
	ssize_t bytesWritten;

	if (TheFAT == NULL) {
		(void) fprintf(stderr,
		    gettext("Internal error: No FAT to write\n"));
		(void) close(fd);
		exit(11);
	}
	if (!FATRewriteNeeded) {
		if (Verbose) {
			(void) fprintf(stderr,
			    gettext("No FAT changes need to be written.\n"));
		}
		return;
	}
	if (ReadOnly)
		return;
	if (Verbose)
		(void) fprintf(stderr, gettext("Writing FAT\n"));
	if (seekFAT(fd) < 0) {
		perror(gettext("Cannot seek to FAT"));
		(void) close(fd);
		exit(11);
	}
	if ((bytesWritten = write(fd, TheFAT, FATSize)) != FATSize) {
		if (bytesWritten < 0) {
			perror(gettext("Cannot write FAT"));
		} else {
			(void) fprintf(stderr,
			    gettext("Short write of FAT."));
		}
		(void) close(fd);
		exit(11);
	}
	FATRewriteNeeded = 0;
}

/*
 *  checkFAT32CleanBit()
 *	Return non-zero if the bit indicating proper Windows shutdown has
 *	been set.
 */
int
checkFAT32CleanBit(int fd)
{
	getFAT(fd);
	return (TheFAT[WIN_SHUTDOWN_STATUS_BYTE] & WIN_SHUTDOWN_BIT_MASK);
}

static uchar_t *
findClusterEntryInFAT(int32_t currentCluster)
{
	int32_t idx;
	if (FATEntrySize == 32) {
		idx = currentCluster * 4;
	} else if (FATEntrySize == 16) {
		idx = currentCluster * 2;
	} else {
		idx = currentCluster + currentCluster/2;
	}
	return (TheFAT + idx);
}

/*
 *  {read,write}FATentry
 *	For the 16 and 32 bit FATs these routines are relatively easy
 *	to follow.
 *
 *	12 bit FATs are kind of strange, though.  The magic index for
 *	12 bit FATS computed below, 1.5 * clusterNum, is a
 *	simplification that there are 8 bits in a byte, so you need
 *	1.5 bytes per entry.
 *
 *	It's easiest to think about FAT12 entries in pairs:
 *
 *	---------------------------------------------
 *	| mid1 | low1 | low2 | high1 | high2 | mid2 |
 *	---------------------------------------------
 *
 *	Each box in the diagram represents a nibble (4 bits) of a FAT
 *	entry.  A FAT entry is made up of three nibbles.  So if you
 *	look closely, you'll see that first byte of the pair of
 *	entries contains the low and middle nibbles of the first
 *	entry.  The second byte has the low nibble of the second entry
 *	and the high nibble of the first entry.  Those two bytes alone
 *	are enough to read the first entry.  The second FAT entry is
 *	finished out by the last nibble pair.
 */
int32_t
readFATEntry(int32_t currentCluster)
{
	int32_t value;
	uchar_t *ep;

	ep = findClusterEntryInFAT(currentCluster);
	if (FATEntrySize == 32) {
		read_32_bits(ep, (uint32_t *)&value);
	} else if (FATEntrySize == 16) {
		read_16_bits(ep, (uint32_t *)&value);
		/*
		 *  Convert 16 bit entry to 32 bit if we are
		 *  into the reserved or higher values.
		 */
		if (value >= PCF_RESCLUSTER)
			value |= 0xFFF0000;
	} else {
		value = 0;
		if (currentCluster & 1) {
			/*
			 * Odd numbered cluster
			 */
			value = (((unsigned int)*ep++ & 0xf0) >> 4);
			value += (*ep << 4);
		} else {
			value = *ep++;
			value += ((*ep & 0x0f) << 8);
		}
		/*
		 *  Convert 12 bit entry to 32 bit if we are
		 *  into the reserved or higher values.
		 */
		if (value >= PCF_12BCLUSTER)
			value |= 0xFFFF000;
	}
	return (value);
}

void
writeFATEntry(int32_t currentCluster, int32_t value)
{
	uchar_t *ep;

	FATRewriteNeeded = 1;
	ep = findClusterEntryInFAT(currentCluster);
	if (FATEntrySize == 32) {
		store_32_bits(&ep, value);
	} else if (FATEntrySize == 16) {
		store_16_bits(&ep, value);
	} else {
		if (currentCluster & 1) {
			/*
			 * Odd numbered cluster
			 */
			*ep = (*ep & 0x0f) | ((value << 4) & 0xf0);
			ep++;
			*ep = (value >> 4) & 0xff;
		} else {
			*ep++ = value & 0xff;
			*ep = (*ep & 0xf0) | ((value >> 8) & 0x0f);
		}
	}
}

/*
 * reservedInFAT - Is this cluster marked in the reserved range?
 *	The range from PCF_RESCLUSTER32 to PCF_BADCLUSTER32 - 1,
 *	have been reserved by Microsoft.  No cluster should be
 *	marked with these; they are effectively invalid cluster values.
 */
int
reservedInFAT(int32_t clusterNum)
{
	int32_t e;

	e = readFATEntry(clusterNum);
	return (e >= PCF_RESCLUSTER32 && e < PCF_BADCLUSTER32);
}

/*
 *  badInFAT - Is this cluster marked as bad?  I.e., is it inaccessible?
 */
int
badInFAT(int32_t clusterNum)
{
	return (readFATEntry(clusterNum) == PCF_BADCLUSTER32);
}

/*
 *  lastInFAT - Is this cluster marked as free?  I.e., is it available
 *	for use?
 */
int
freeInFAT(int32_t clusterNum)
{
	return (readFATEntry(clusterNum) == PCF_FREECLUSTER);
}

/*
 *  lastInFAT - Is this cluster the last in its cluster chain?
 */
int
lastInFAT(int32_t clusterNum)
{
	return (readFATEntry(clusterNum) == PCF_LASTCLUSTER32);
}

/*
 *  markLastInFAT - Mark this cluster as the last in its cluster chain.
 */
void
markLastInFAT(int32_t clusterNum)
{
	writeFATEntry(clusterNum, PCF_LASTCLUSTER32);
}

void
markFreeInFAT(int32_t clusterNum)
{
	writeFATEntry(clusterNum, PCF_FREECLUSTER);
}

void
markBadInFAT(int32_t clusterNum)
{
	writeFATEntry(clusterNum, PCF_BADCLUSTER32);
}
