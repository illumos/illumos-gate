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
 * Copyright (c) 1999,2000 by Sun Microsystems, Inc.
 * All rights reserved.
 * Copyright (c) 2011 Gary Mills
 * Copyright 2024 MNX Cloud, Inc.
 */

/*
 * fsck_pcfs -- routines for manipulating the BPB (BIOS parameter block)
 * of the file system.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libintl.h>
#include <sys/types.h>
#include <sys/dktp/fdisk.h>
#include <sys/fs/pc_fs.h>
#include <sys/fs/pc_dir.h>
#include <sys/fs/pc_label.h>
#include "pcfs_common.h"
#include "fsck_pcfs.h"
#include "pcfs_bpb.h"

extern	off64_t	FirstClusterOffset;
extern	off64_t	PartitionOffset;
extern	int32_t	BytesPerCluster;
extern	int32_t	TotalClusters;
extern	int32_t	LastCluster;
extern	int32_t	RootDirSize;
extern	int32_t	FATSize;
extern	short	FATEntrySize;
extern	bpb_t	TheBIOSParameterBlock;
extern	int	IsFAT32;
extern	int	Verbose;

static void
computeFileAreaSize(void)
{
	int32_t	dataSectors;
	int32_t	overhead;

	/*
	 * Compute bytes/cluster for later reference
	 */
	BytesPerCluster =  TheBIOSParameterBlock.bpb.sectors_per_cluster *
	    TheBIOSParameterBlock.bpb.bytes_per_sector;

	/*
	 * First we'll find total number of sectors in the file area...
	 */
	if (TheBIOSParameterBlock.bpb.sectors_in_volume > 0)
		dataSectors = TheBIOSParameterBlock.bpb.sectors_in_volume;
	else
		dataSectors =
		    TheBIOSParameterBlock.bpb.sectors_in_logical_volume;

	overhead = TheBIOSParameterBlock.bpb.resv_sectors;

	RootDirSize = TheBIOSParameterBlock.bpb.num_root_entries *
	    sizeof (struct pcdir);
	overhead += RootDirSize / TheBIOSParameterBlock.bpb.bytes_per_sector;

	if (TheBIOSParameterBlock.bpb.sectors_per_fat) {
		/*
		 * Good old FAT12 or FAT16
		 */
		overhead += TheBIOSParameterBlock.bpb.num_fats *
		    TheBIOSParameterBlock.bpb.sectors_per_fat;
		/*
		 * Compute this for later - when we actually pull in a copy
		 * of the FAT
		 */
		FATSize = TheBIOSParameterBlock.bpb.sectors_per_fat *
		    TheBIOSParameterBlock.bpb.bytes_per_sector;
	} else {
		/*
		 *  FAT32
		 *  I'm unsure if this is always going to work.  At one
		 *  point during the creation of this program and mkfs_pcfs
		 *  it seemed that Windows had created an fs where it had
		 *  rounded big_sectors_per_fat up to a cluster boundary.
		 *  Later, though, I encountered a problem where I wasn't
		 *  finding the root directory because I was looking in the
		 *  wrong place by doing that same roundup.  So, for now,
		 *  I'm backing off on the cluster boundary thing and just
		 *  believing what I am told.
		 */
		overhead += TheBIOSParameterBlock.bpb.num_fats *
		    TheBIOSParameterBlock.bpb32.big_sectors_per_fat;
		/*
		 * Compute this for later - when we actually pull in a copy
		 * of the FAT
		 */
		FATSize = TheBIOSParameterBlock.bpb32.big_sectors_per_fat *
		    TheBIOSParameterBlock.bpb.bytes_per_sector;
	}

	/*
	 * Now change sectors to clusters.  The computed value for
	 * TotalClusters is persistent for the remainder of execution.
	 */
	dataSectors -= overhead;
	TotalClusters = dataSectors /
	    TheBIOSParameterBlock.bpb.sectors_per_cluster;

	/*
	 *  Also need to compute last cluster and offset of the first cluster
	 */
	LastCluster = TotalClusters + FIRST_CLUSTER;
	FirstClusterOffset = overhead *
	    TheBIOSParameterBlock.bpb.bytes_per_sector;
	FirstClusterOffset += PartitionOffset;

	/*
	 * XXX this should probably be more sophisticated
	 */
	if (IsFAT32)
		FATEntrySize = 32;
	else {
		if (TotalClusters <= DOS_F12MAXC)
			FATEntrySize = 12;
		else
			FATEntrySize = 16;
	}

	if (Verbose) {
		(void) fprintf(stderr,
		    gettext("Disk has a file area of %d "
		    "allocation units,\neach with %d sectors = %llu "
		    "bytes.\n"), TotalClusters,
		    TheBIOSParameterBlock.bpb.sectors_per_cluster,
		    (uint64_t)TotalClusters *
		    TheBIOSParameterBlock.bpb.sectors_per_cluster *
		    TheBIOSParameterBlock.bpb.bytes_per_sector);
		(void) fprintf(stderr,
		    gettext("File system overhead of %d sectors.\n"), overhead);
		(void) fprintf(stderr,
		    gettext("The last cluster is %d\n"), LastCluster);
	}
}

/*
 *  XXX - right now we aren't attempting to fix anything that looks bad,
 *	instead we just give up.
 */
void
readBPB(int fd)
{
	boot_sector_t ubpb;

	/*
	 *  The BPB is the first sector of the file system
	 */
	if (lseek64(fd, PartitionOffset, SEEK_SET) < 0) {
		mountSanityCheckFails();
		perror(gettext("Cannot seek to start of disk partition"));
		(void) close(fd);
		exit(7);
	}
	if (Verbose)
		(void) fprintf(stderr,
		    gettext("Reading BIOS parameter block\n"));
	if (read(fd, ubpb.buf, bpsec) < bpsec) {
		mountSanityCheckFails();
		perror(gettext("Read BIOS parameter block"));
		(void) close(fd);
		exit(2);
	}

	if (ltohs(ubpb.mb.signature) != BOOTSECSIG) {
		mountSanityCheckFails();
		(void) fprintf(stderr,
		    gettext("Bad signature on BPB. Giving up.\n"));
		exit(2);
	}

#ifdef _BIG_ENDIAN
	swap_pack_grabbpb(&TheBIOSParameterBlock, &(ubpb.bs));
#else
	(void) memcpy(&(TheBIOSParameterBlock.bpb), &(ubpb.bs.bs_front.bs_bpb),
	    sizeof (TheBIOSParameterBlock.bpb));
	(void) memcpy(&(TheBIOSParameterBlock.ebpb), &(ubpb.bs.bs_ebpb),
	    sizeof (TheBIOSParameterBlock.ebpb));
#endif
	if (TheBIOSParameterBlock.bpb.bytes_per_sector != 512 &&
	    TheBIOSParameterBlock.bpb.bytes_per_sector != 1024 &&
	    TheBIOSParameterBlock.bpb.bytes_per_sector != 2048 &&
	    TheBIOSParameterBlock.bpb.bytes_per_sector != 4096) {
		mountSanityCheckFails();
		(void) fprintf(stderr,
		    gettext("Bogus bytes per sector value.  Giving up.\n"));
		exit(2);
	}
	if (!(ISP2(TheBIOSParameterBlock.bpb.sectors_per_cluster) &&
	    IN_RANGE(TheBIOSParameterBlock.bpb.sectors_per_cluster,
	    1, 128))) {
		mountSanityCheckFails();
		(void) fprintf(stderr,
		    gettext("Bogus sectors per cluster value.  Giving up.\n"));
		(void) close(fd);
		exit(6);
	}
	if (TheBIOSParameterBlock.bpb.sectors_per_fat == 0) {
#ifdef _BIG_ENDIAN
		swap_pack_grab32bpb(&TheBIOSParameterBlock, &(ubpb.bs));
#else
		(void) memcpy(&(TheBIOSParameterBlock.bpb32),
		    &(ubpb.bs32.bs_bpb32),
		    sizeof (TheBIOSParameterBlock.bpb32));
#endif
		IsFAT32 = 1;
	}
	if (!IsFAT32) {
		if ((TheBIOSParameterBlock.bpb.num_root_entries == 0) ||
		    ((TheBIOSParameterBlock.bpb.num_root_entries *
		    sizeof (struct pcdir)) %
		    TheBIOSParameterBlock.bpb.bytes_per_sector) != 0) {
			mountSanityCheckFails();
			(void) fprintf(stderr,
			    gettext("Bogus number of root entries.  "
			    "Giving up.\n"));
			exit(2);
		}
	} else {
		if (TheBIOSParameterBlock.bpb.num_root_entries != 0) {
			mountSanityCheckFails();
			(void) fprintf(stderr,
			    gettext("Bogus number of root entries.  "
			    "Giving up.\n"));
			exit(2);
		}
	}
	/*
	 * In general, we would expect the number of FATs field to
	 * equal 2.  Our mkfs and Windows have this as a default
	 * value.  I suppose someone could override the default,
	 * though, so we'll sort of arbitrarily accept any number
	 * between 1 and 4 inclusive as reasonable values.
	 *
	 * XXX: Warn, but continue, if value is suspicious? (>2?)
	 */
	if (TheBIOSParameterBlock.bpb.num_fats > 4 ||
	    TheBIOSParameterBlock.bpb.num_fats < 1) {
		mountSanityCheckFails();
		(void) fprintf(stderr,
		    gettext("Bogus number of FATs.  Giving up.\n"));
		exit(2);
	}
	computeFileAreaSize();
}
