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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2011 Gary Mills
 * Copyright 2024 MNX Cloud, Inc.
 */

/*
 * fsck_pcfs -- common.c
 *	All the routines in this file are being swiped directly from
 *	mkfs_pcfs.  Eventually this file should only exist in one place
 *	and be part of a library that both mkfs and fsck link against.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <libintl.h>
#include <sys/isa_defs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/dktp/fdisk.h>
#include <sys/fs/pc_fs.h>
#include <sys/fs/pc_dir.h>
#include <sys/fs/pc_label.h>
#include "fsck_pcfs.h"
#include "pcfs_common.h"
#include "pcfs_bpb.h"

/*
 *	The assumption here is that _BIG_ENDIAN implies sparc, and
 *	so in addition to swapping bytes we also have to construct
 *	packed structures by hand to avoid bus errors due to improperly
 *	aligned pointers.
 */
#ifdef _BIG_ENDIAN
void swap_pack_grab32bpb(bpb_t *wbpb, struct _boot_sector *bsp);
void swap_pack_grabbpb(bpb_t *wbpb, struct _boot_sector *bsp);
#endif /* _BIG_ENDIAN */

/*
 *  Global variables related to input questions
 */
extern int AlwaysYes;
extern int AlwaysNo;

/*
 * store_16_bits
 *	Save the lower 16 bits of a 32 bit value (v) into the provided
 *	buffer (pointed at by *bp), and increment the buffer pointer
 *	as well.  This way the routine can be called multiple times in
 *	succession to fill buffers.  The value is stored in little-endian
 *	order.
 */
void
store_16_bits(uchar_t **bp, uint32_t v)
{
	uchar_t *l = *bp;

	*l++ = v & 0xff;
	*l = (v >> 8) & 0xff;
	*bp += 2;
}

void
read_16_bits(uchar_t *bp, uint32_t *value)
{
	*value = *bp++;
	*value += *bp << 8;
}

/*
 * store_32_bits
 *	Save the 32 bit value (v) into the provided buffer (pointed
 *	at by *bp), and increment the buffer pointer as well.  This way
 *	the routine can be called multiple times in succession to fill
 *	buffers.  The value is stored in little-endian order.
 */
void
store_32_bits(uchar_t **bp, uint32_t v)
{
	uchar_t *l = *bp;
	int b;

	for (b = 0; b < 4; b++) {
		*l++ = v & 0xff;
		v = v >> 8;
	}
	*bp += 4;
}

void
read_32_bits(uchar_t *bp, uint32_t *value)
{
	*value = *bp++;
	*value += *bp++ << 8;
	*value += *bp++ << 16;
	*value += *bp++ << 24;
}

/*
 *  dump_bytes  -- display bytes as hex numbers.
 *		   b is the pointer to the byte buffer
 *		   n is the number of bytes in the buffer
 */
/* Note: BPL = bytes to display per line */
#define	BPL 16

void
dump_bytes(uchar_t *buf, int n)
{
	int printedCount;
	int countdown = n;
	int countup = 0;
	int offset = 0;
	int byte;

	/* Display offset, 16 bytes per line, and printable ascii version */
	while (countdown > 0) {
		printedCount = 0;
		(void) fprintf(stderr, "\n%06x: ", offset);
		/*
		 * Print Hex value of characters in columns on left
		 */
		for (byte = 0; byte < BPL; byte++) {
			if (countup + byte < n) {
				(void) fprintf(stderr,
				    "%02x ", (buf[countup + byte] & 0xff));
				printedCount++;
			} else {
				(void) fprintf(stderr, "   ");
			}
		}
		/*
		 * Right side has the printable character or '.' for
		 * unprintable for each column of the left.
		 */
		for (byte = 0; byte < BPL; byte++) {
			if ((countup + byte < n) &&
			    ((buf[countup + byte] >= ' ') &&
			    (buf[countup + byte] <= '~'))) {
				(void) fprintf(stderr, "%c",
				    buf[countup + byte]);
			} else {
				(void) fprintf(stderr, ".");
			}
		}
		countup += printedCount;
		offset += printedCount;
		countdown -= printedCount;
	}
	(void) fprintf(stderr, "\n\n");
}

/*
 *  header_for_dump  --  display simple header over what will be output.
 */
void
header_for_dump(void)
{
	int byte;

	(void) fprintf(stderr, "\n        ");
	for (byte = 0; byte < BPL; byte++)
		(void) fprintf(stderr, "%02x ", byte);
	(void) fprintf(stderr, "\n       ");
	byte = 3*BPL;
	while (byte-- > 0)
		(void) fprintf(stderr, "-");
}

/*
 *  We are basically (incorrectly) assuming that if you aren't running
 *  on x86 the BPB has to be packed by hand AND that the bytes must
 *  be swapped.  One or both of these assumptions may one day be invalid.
 *  (if they aren't already :-))
 */
#ifdef _BIG_ENDIAN
/*
 *  swap_pack_grab{32}bpb
 *	If not on an x86 we assume the structures making up the bpb
 *	were not packed and that longs and shorts need to be byte swapped
 *	(we've kept everything in host order up until now).  A new architecture
 *	might not need to swap or might not need to pack, in which case
 *	new routines will have to be written.  Of course if an architecture
 *	supports both packing and little-endian host order, it can follow the
 *	same path as the x86 code.
 */
void
swap_pack_grabbpb(bpb_t *wbpb, struct _boot_sector *bsp)
{
	uchar_t *grabp;

	grabp = (uchar_t *)&(bsp->bs_filler[ORIG_BPB_START_INDEX]);

	((uchar_t *)&(wbpb->bpb.bytes_per_sector))[1] = *grabp++;
	((uchar_t *)&(wbpb->bpb.bytes_per_sector))[0] = *grabp++;
	wbpb->bpb.sectors_per_cluster = *grabp++;
	((uchar_t *)&(wbpb->bpb.resv_sectors))[1] = *grabp++;
	((uchar_t *)&(wbpb->bpb.resv_sectors))[0] = *grabp++;
	wbpb->bpb.num_fats = *grabp++;
	((uchar_t *)&(wbpb->bpb.num_root_entries))[1] = *grabp++;
	((uchar_t *)&(wbpb->bpb.num_root_entries))[0] = *grabp++;
	((uchar_t *)&(wbpb->bpb.sectors_in_volume))[1] = *grabp++;
	((uchar_t *)&(wbpb->bpb.sectors_in_volume))[0] = *grabp++;
	wbpb->bpb.media = *grabp++;
	((uchar_t *)&(wbpb->bpb.sectors_per_fat))[1] = *grabp++;
	((uchar_t *)&(wbpb->bpb.sectors_per_fat))[0] = *grabp++;
	((uchar_t *)&(wbpb->bpb.sectors_per_track))[1] = *grabp++;
	((uchar_t *)&(wbpb->bpb.sectors_per_track))[0] = *grabp++;
	((uchar_t *)&(wbpb->bpb.heads))[1] = *grabp++;
	((uchar_t *)&(wbpb->bpb.heads))[0] = *grabp++;
	((uchar_t *)&(wbpb->bpb.hidden_sectors))[3] = *grabp++;
	((uchar_t *)&(wbpb->bpb.hidden_sectors))[2] = *grabp++;
	((uchar_t *)&(wbpb->bpb.hidden_sectors))[1] = *grabp++;
	((uchar_t *)&(wbpb->bpb.hidden_sectors))[0] = *grabp++;
	((uchar_t *)&(wbpb->bpb.sectors_in_logical_volume))[3] = *grabp++;
	((uchar_t *)&(wbpb->bpb.sectors_in_logical_volume))[2] = *grabp++;
	((uchar_t *)&(wbpb->bpb.sectors_in_logical_volume))[1] = *grabp++;
	((uchar_t *)&(wbpb->bpb.sectors_in_logical_volume))[0] = *grabp++;
	wbpb->ebpb.phys_drive_num = *grabp++;
	wbpb->ebpb.reserved = *grabp++;
	wbpb->ebpb.ext_signature = *grabp++;
	((uchar_t *)&(wbpb->ebpb.volume_id))[3] = *grabp++;
	((uchar_t *)&(wbpb->ebpb.volume_id))[2] = *grabp++;
	((uchar_t *)&(wbpb->ebpb.volume_id))[1] = *grabp++;
	((uchar_t *)&(wbpb->ebpb.volume_id))[0] = *grabp++;

	(void) strncpy((char *)wbpb->ebpb.volume_label, (char *)grabp, 11);
	grabp += 11;
	(void) strncpy((char *)wbpb->ebpb.type, (char *)grabp, 8);
}

void
swap_pack_grab32bpb(bpb_t *wbpb, struct _boot_sector *bsp)
{
	uchar_t *grabp;

	grabp = (uchar_t *)&(bsp->bs_filler[BPB_32_START_INDEX]);

	((uchar_t *)&(wbpb->bpb32.big_sectors_per_fat))[3] = *grabp++;
	((uchar_t *)&(wbpb->bpb32.big_sectors_per_fat))[2] = *grabp++;
	((uchar_t *)&(wbpb->bpb32.big_sectors_per_fat))[1] = *grabp++;
	((uchar_t *)&(wbpb->bpb32.big_sectors_per_fat))[0] = *grabp++;
	((uchar_t *)&(wbpb->bpb32.ext_flags))[1] = *grabp++;
	((uchar_t *)&(wbpb->bpb32.ext_flags))[0] = *grabp++;
	wbpb->bpb32.fs_vers_lo = *grabp++;
	wbpb->bpb32.fs_vers_hi = *grabp++;
	((uchar_t *)&(wbpb->bpb32.root_dir_clust))[3] = *grabp++;
	((uchar_t *)&(wbpb->bpb32.root_dir_clust))[2] = *grabp++;
	((uchar_t *)&(wbpb->bpb32.root_dir_clust))[1] = *grabp++;
	((uchar_t *)&(wbpb->bpb32.root_dir_clust))[0] = *grabp++;
	((uchar_t *)&(wbpb->bpb32.fsinfosec))[1] = *grabp++;
	((uchar_t *)&(wbpb->bpb32.fsinfosec))[0] = *grabp++;
	((uchar_t *)&(wbpb->bpb32.backupboot))[1] = *grabp++;
	((uchar_t *)&(wbpb->bpb32.backupboot))[0] = *grabp++;
	((uchar_t *)&(wbpb->bpb32.reserved[0]))[1] = *grabp++;
	((uchar_t *)&(wbpb->bpb32.reserved[0]))[0] = *grabp++;
	((uchar_t *)&(wbpb->bpb32.reserved[1]))[1] = *grabp++;
	((uchar_t *)&(wbpb->bpb32.reserved[1]))[0] = *grabp++;
	((uchar_t *)&(wbpb->bpb32.reserved[2]))[1] = *grabp++;
	((uchar_t *)&(wbpb->bpb32.reserved[2]))[0] = *grabp++;
	((uchar_t *)&(wbpb->bpb32.reserved[3]))[1] = *grabp++;
	((uchar_t *)&(wbpb->bpb32.reserved[3]))[0] = *grabp++;
	((uchar_t *)&(wbpb->bpb32.reserved[4]))[1] = *grabp++;
	((uchar_t *)&(wbpb->bpb32.reserved[4]))[0] = *grabp++;
	((uchar_t *)&(wbpb->bpb32.reserved[5]))[1] = *grabp++;
	((uchar_t *)&(wbpb->bpb32.reserved[5]))[0] = *grabp++;
}
#endif	/* _BIG_ENDIAN */

int
yes(void)
{
	char *affirmative = gettext("yY");
	char *a = affirmative;
	char input[80];

	if (AlwaysYes) {
		(void) printf("y\n");
		return (1);
	} else if (AlwaysNo) {
		(void) printf("n\n");
		return (0);
	}
	if (fgets(input, sizeof (input), stdin) == NULL) {
		AlwaysNo = 1;
		(void) printf("n\n");
		return (0);
	}
	while (*a) {
		if (input[0] == (int)*a)
			break;
		a++;
	}
	return ((int)*a);
}

char *
stat_actual_disk(char *diskname, struct stat *info, char **suffix)
{
	char *actualdisk;

	if (stat(diskname, info)) {
		/*
		 *  Device named on command line doesn't exist.  That
		 *  probably means there is a partition-specifying
		 *  suffix attached to the actual disk name.
		 */
		if ((actualdisk = strdup(diskname)) == NULL) {
			(void) fprintf(stderr,
			    gettext("Out of memory for disk name.\n"));
			exit(2);
		}
		if ((*suffix = strchr(actualdisk, ':')) != NULL) {
			**suffix = '\0';
			(*suffix)++;
		}

		if (stat(actualdisk, info)) {
			perror(actualdisk);
			exit(2);
		}
	} else {
		if ((actualdisk = strdup(diskname)) == NULL) {
			(void) fprintf(stderr,
			    gettext("Out of memory for disk name.\n"));
			exit(2);
		}
	}

	return (actualdisk);
}

extern void usage(void);

void
bad_arg(char *option)
{
	(void) fprintf(stderr,
	    gettext("Unrecognized option -o %s.\n"), option);
	usage();
	exit(2);
}

void
missing_arg(char *option)
{
	(void) fprintf(stderr,
	    gettext("Option %s requires a value.\n"), option);
	usage();
	exit(3);
}

static int
parse_drvnum(char *pn)
{
	int drvnum;

	/*
	 * Determine logical drive to seek after.
	 */
	if ((strlen(pn) == 1) && ((*pn >= 'c') && (*pn <= 'z'))) {
		drvnum = *pn - 'c' + 1;
	} else if ((*pn >= '0') && (*pn <= '9')) {
		char *d;
		int v = 0;

		d = pn;
		while ((*d != '\0') && (*d >= '0') && (*d <= '9')) {
			v *= 10;
			v += *d - '0';
			d++;
		}
		if ((*d != '\0') || (v > 24)) {
			(void) fprintf(stderr,
			    gettext("%s: bogus logical drive specification.\n"),
			    pn);
			return (-1);
		}
		drvnum = v;
	} else if (strcmp(pn, "boot") == 0) {
		drvnum = 99;
	} else {
		(void) fprintf(stderr,
		    gettext("%s: bogus logical drive specification.\n"), pn);
		return (-1);
	}

	return (drvnum);
}

/*
 * isDosDrive()
 *	Boolean function.  Give it the systid field for an fdisk partition
 *	and it decides if that's a systid that describes a DOS drive.  We
 *	use systid values defined in sys/dktp/fdisk.h.
 */
static int
isDosDrive(uchar_t checkMe)
{
	return ((checkMe == DOSOS12) || (checkMe == DOSOS16) ||
	    (checkMe == DOSHUGE) || (checkMe == FDISK_WINDOWS) ||
	    (checkMe == FDISK_EXT_WIN) || (checkMe == FDISK_FAT95) ||
	    (checkMe == DIAGPART));
}

/*
 * isDosExtended()
 *	Boolean function.  Give it the systid field for an fdisk partition
 *	and it decides if that's a systid that describes an extended DOS
 *	partition.
 */
static int
isDosExtended(uchar_t checkMe)
{
	return ((checkMe == EXTDOS) || (checkMe == FDISK_EXTLBA));
}

/*
 * isBootPart()
 *	Boolean function.  Give it the systid field for an fdisk partition
 *	and it decides if that's a systid that describes a Solaris boot
 *	partition.
 */
static int
isBootPart(uchar_t checkMe)
{
	return (checkMe == X86BOOT);
}

off64_t
findPartitionOffset(int fd, char *ldrive)
{
	struct ipart part[FD_NUMPART];
	struct mboot extmboot;
	struct mboot mb;
	diskaddr_t xstartsect;
	off64_t nextseek = 0;
	off64_t lastseek = 0;
	off64_t found = 0;
	off64_t error = -1;
	int logicalDriveCount = 0;
	int extendedPart = -1;
	int primaryPart = -1;
	int bootPart = -1;
	uint32_t xnumsect = 0;
	int drvnum;
	int driveIndex;
	int i;
	/*
	 * Count of drives in the current extended partition's
	 * FDISK table, and indexes of the drives themselves.
	 */
	int extndDrives[FD_NUMPART];
	int numDrives = 0;
	/*
	 * Count of drives (beyond primary) in master boot record's
	 * FDISK table, and indexes of the drives themselves.
	 */
	int extraDrives[FD_NUMPART];
	int numExtraDrives = 0;

	if ((drvnum = parse_drvnum(ldrive)) < 0)
		return (error);

	if (read(fd, &mb, bpsec) != (ssize_t)bpsec) {
		(void) fprintf(stderr,
		    gettext("Couldn't read a Master Boot Record\n"));
		return (error);
	}

	if (ltohs(mb.signature) != BOOTSECSIG) {
		(void) fprintf(stderr,
		    gettext("Bad signature on master boot record (%x)\n"),
		    ltohs(mb.signature));
		return (error);
	}

	/*
	 * Copy partition table into memory
	 */
	(void) memcpy(part, mb.parts, sizeof (part));

	/*
	 * Get a summary of what is in the Master FDISK table.
	 * Normally we expect to find one partition marked as a DOS drive.
	 * This partition is the one Windows calls the primary dos partition.
	 * If the machine has any logical drives then we also expect
	 * to find a partition marked as an extended DOS partition.
	 *
	 * Sometimes we'll find multiple partitions marked as DOS drives.
	 * The Solaris fdisk program allows these partitions
	 * to be created, but Windows fdisk no longer does.  We still need
	 * to support these, though, since Windows does.  We also need to fix
	 * our fdisk to behave like the Windows version.
	 *
	 * It turns out that some off-the-shelf media have *only* an
	 * Extended partition, so we need to deal with that case as
	 * well.
	 *
	 * Only a single (the first) Extended or Boot Partition will
	 * be recognized.  Any others will be ignored.
	 */
	for (i = 0; i < FD_NUMPART; i++) {
		if (isDosDrive(part[i].systid)) {
			if (primaryPart < 0) {
				logicalDriveCount++;
				primaryPart = i;
			} else {
				extraDrives[numExtraDrives++] = i;
			}
			continue;
		}
		if ((extendedPart < 0) && isDosExtended(part[i].systid)) {
			extendedPart = i;
			continue;
		}
		if ((bootPart < 0) && isBootPart(part[i].systid)) {
			bootPart = i;
			continue;
		}
	}

	if (drvnum == BOOT_PARTITION_DRIVE) {
		if (bootPart < 0) {
			(void) fprintf(stderr,
			    gettext("No boot partition found on drive\n"));
			return (error);
		}
		found = ltohi(part[bootPart].relsect) * bpsec;
		return (found);
	}

	if (drvnum == PRIMARY_DOS_DRIVE && primaryPart >= 0) {
		found = ltohi(part[primaryPart].relsect) * bpsec;
		return (found);
	}

	/*
	 * We are not looking for the C: drive (or there was no primary
	 * drive found), so we had better have an extended partition or
	 * extra drives in the Master FDISK table.
	 */
	if ((extendedPart < 0) && (numExtraDrives == 0)) {
		(void) fprintf(stderr,
		    gettext("No such logical drive "
		    "(missing extended partition entry)\n"));
		return (error);
	}

	if (extendedPart >= 0) {
		nextseek = xstartsect = ltohi(part[extendedPart].relsect);
		xnumsect = ltohi(part[extendedPart].numsect);
		do {
			/*
			 *  If the seek would not cause us to change
			 *  position on the drive, then we're out of
			 *  extended partitions to examine.
			 */
			if (nextseek == lastseek)
				break;
			logicalDriveCount += numDrives;
			/*
			 *  Seek the next extended partition, and find
			 *  logical drives within it.
			 */
			if (lseek64(fd, nextseek * bpsec, SEEK_SET) < 0 ||
			    read(fd, &extmboot, sizeof (extmboot)) !=
			    sizeof (extmboot)) {
				perror(gettext("Unable to read extended "
				    "partition record"));
				return (error);
			}
			(void) memcpy(part, extmboot.parts, sizeof (part));
			lastseek = nextseek;
			if (ltohs(extmboot.signature) != MBB_MAGIC) {
				(void) fprintf(stderr,
				    gettext("Bad signature on "
				    "extended partition\n"));
				return (error);
			}
			/*
			 *  Count up drives, and track where the next
			 *  extended partition is in case we need it.  We
			 *  are expecting only one extended partition.  If
			 *  there is more than one we'll only go to the
			 *  first one we see, but warn about ignoring.
			 */
			numDrives = 0;
			for (i = 0; i < FD_NUMPART; i++) {
				if (isDosDrive(part[i].systid)) {
					extndDrives[numDrives++] = i;
					continue;
				} else if (isDosExtended(part[i].systid)) {
					if (nextseek != lastseek) {
						/*
						 * Already found an extended
						 * partition in this table.
						 */
						(void) fprintf(stderr,
						    gettext("WARNING: "
						    "Ignoring unexpected "
						    "additional extended "
						    "partition"));
						continue;
					}
					nextseek = xstartsect +
					    ltohi(part[i].relsect);
					continue;
				}
			}
		} while (drvnum > logicalDriveCount + numDrives);

		if (drvnum <= logicalDriveCount + numDrives) {
			/*
			 * The number of logical drives we've found thus
			 * far is enough to get us to the one we were
			 * searching for.
			 */
			driveIndex = logicalDriveCount + numDrives - drvnum;
			found =
			    ltohi(part[extndDrives[driveIndex]].relsect) +
			    lastseek;
			if (found > (xstartsect + xnumsect)) {
				(void) fprintf(stderr,
				    gettext("Logical drive start sector (%d) "
				    "is not within the partition!\n"), found);
				return (error);
			} else {
				found *= bpsec;
			}
			return (found);
		} else {
			/*
			 * We ran out of extended dos partition
			 * drives.  The only hope now is to go
			 * back to extra drives defined in the master
			 * fdisk table.  But we overwrote that table
			 * already, so we must load it in again.
			 */
			logicalDriveCount += numDrives;
			(void) memcpy(part, mb.parts, sizeof (part));
		}
	}
	/*
	 *  Still haven't found the drive, is it an extra
	 *  drive defined in the main FDISK table?
	 */
	if (drvnum <= logicalDriveCount + numExtraDrives) {
		driveIndex = logicalDriveCount + numExtraDrives - drvnum;
		found = ltohi(part[extraDrives[driveIndex]].relsect) * bpsec;
		return (found);
	}
	return (error);
}
