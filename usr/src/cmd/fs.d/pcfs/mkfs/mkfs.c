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
 * Copyright (c) 2011 Gary Mills
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <ctype.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <libintl.h>
#include <locale.h>
#include <sys/fdio.h>
#include <sys/dktp/fdisk.h>
#include <sys/dkio.h>
#include <sys/vtoc.h>
#include <sys/efi_partition.h>
#include <sys/sysmacros.h>
#include "mkfs_pcfs.h"
#include <sys/fs/pc_fs.h>
#include <sys/fs/pc_dir.h>
#include <sys/fs/pc_label.h>
#include <macros.h>

/*
 *	mkfs (for pcfs)
 *
 *	Install a boot block, FAT, and (if desired) the first resident
 *	of the new fs.
 *
 *	XXX -- floppy opens need O_NDELAY?
 */
#define	IN_RANGE(n, x, y) (((n) >= (x)) && ((n) <= (y)))
#define	DEFAULT_LABEL "NONAME"

static char	*BootBlkFn = NULL;
static char	*DiskName = NULL;
static char	*FirstFn = NULL;
static char	*Label = NULL;
static char	Firstfileattr = 0x20;
static int	Outputtofile = 0;
static int	SunBPBfields = 0;
static int	GetFsParams = 0;
static int	Fatentsize = 0;
static int	Imagesize = 3;
static int	Notreally = 0;
static int	Verbose = 0;
static int	MakeFAT32 = 0;

/*
 * If there is an FDISK entry for the device where we're about to
 * make the file system, we ought to make a file system that has the
 * same size FAT as the FDISK table claims.  We track the size FDISK
 * thinks in this variable.
 */
static int	FdiskFATsize = 0;

static int	GetSize = 1;	/* Unless we're given as arg, must look it up */
static ulong_t	TotSize;	/* Total size of FS in # of sectors */
static int	GetSPC = 1;	/* Unless we're given as arg, must calculate */
static ulong_t	SecPerClust;	/* # of sectors per cluster */
static int	GetOffset = 1;	/* Unless we're given as arg, must look it up */
static ulong_t	RelOffset;	/* Relative start sector (hidden sectors) */
static int	GetSPT = 1;	/* Unless we're given as arg, must look it up */
static ushort_t	SecPerTrk;	/* # of sectors per track */
static int	GetTPC = 1;	/* Unless we're given as arg, must look it up */
static ushort_t	TrkPerCyl;	/* # of tracks per cylinder */
static int	GetResrvd = 1;	/* Unless we're given as arg, must calculate */
static int	Resrvd;		/* Number of reserved sectors */
static int	GetBPF = 1;	/* Unless we're given as arg, must calculate */
static int	BitsPerFAT;	/* Total size of FS in # of sectors */

static ulong_t	TotalClusters;	/* Computed total number of clusters */

/*
 * Unless we are told otherwise, we should use fdisk table for non-diskettes.
 */
static int	DontUseFdisk = 0;

/*
 * Function prototypes
 */
#ifndef i386
static void swap_pack_grabsebpb(bpb_t *wbpb, struct _boot_sector *bsp);
static void swap_pack_bpb32cpy(struct _boot_sector32 *bsp, bpb_t *wbpb);
static void swap_pack_sebpbcpy(struct _boot_sector *bsp, bpb_t *wbpb);
static void swap_pack_grabbpb(bpb_t *wbpb, struct _boot_sector *bsp);
static void swap_pack_bpbcpy(struct _boot_sector *bsp, bpb_t *wbpb);
#endif

static uchar_t *build_rootdir(bpb_t *wbpb, char *ffn, int fffd,
	ulong_t ffsize, pc_cluster32_t ffstart, ulong_t *rdirsize);
static uchar_t *build_fat(bpb_t *wbpb, struct fat_od_fsi *fsinfop,
	ulong_t bootblksize, ulong_t *fatsize, char *ffn, int *fffd,
	ulong_t *ffsize, pc_cluster32_t *ffstartclust);

static char *stat_actual_disk(char *diskname, struct stat *info, char **suffix);

static void compare_existing_with_computed(int fd, char *suffix,
	bpb_t *wbpb, int *prtsize, int *prtspc, int *prtbpf, int *prtnsect,
	int *prtntrk, int *prtfdisk, int *prthidden, int *prtrsrvd,
	int *dashos);
static void print_reproducing_command(int fd, char *actualdisk, char *suffix,
	bpb_t *wbpb);
static void compute_file_area_size(bpb_t *wbpb);
static void write_fat32_bootstuff(int fd, boot_sector_t *bsp,
	struct fat_od_fsi *fsinfop, off64_t seekto);
static void sanity_check_options(int argc, int optind);
static void compute_cluster_size(bpb_t *wbpb);
static void find_fixed_details(int fd, bpb_t *wbpb);
static void dirent_fname_fill(struct pcdir *dep, char *fn);
static void floppy_bpb_fillin(bpb_t *wbpb,
	int diam, int hds, int spt);
static void read_existing_bpb(int fd, bpb_t *wbpb);
static void warn_funky_fatsize(void);
static void warn_funky_floppy(void);
static void dirent_time_fill(struct pcdir *dep);
static void parse_suboptions(char *optsstr);
static void header_for_dump(void);
static void write_bootsects(int fd, boot_sector_t *bsp, bpb_t *wbpb,
	struct fat_od_fsi *fsinfop, off64_t seekto);
static void fill_bpb_sizes(bpb_t *wbpb, struct ipart part[],
	int partno, off64_t offset);
static void set_fat_string(bpb_t *wbpb, int fatsize);
static void partn_lecture(char *dn);
static void store_16_bits(uchar_t **bp, uint32_t v);
static void store_32_bits(uchar_t **bp, uint32_t v);
static void lookup_floppy(struct fd_char *fdchar, bpb_t *wbpb);
static void label_volume(char *lbl, bpb_t *wbpb);
static void mark_cluster(uchar_t *fatp, pc_cluster32_t clustnum,
	uint32_t value);
static void missing_arg(char *option);
static void dashm_bail(int fd);
static void dump_bytes(uchar_t *, int);
static void write_rest(bpb_t *wbpb, char *efn,
	int dfd, int sfd, int remaining);
static void write_fat(int fd, off64_t seekto, char *fn, char *lbl,
	char *ffn, bpb_t *wbpb);
static void bad_arg(char *option);
static void usage(void);

static int prepare_image_file(char *fn, bpb_t *wbpb);
static int verify_bootblkfile(char *fn, boot_sector_t *bs,
	ulong_t *blkfilesize);
static int open_and_examine(char *dn, bpb_t *wbpb);
static int verify_firstfile(char *fn, ulong_t *filesize);
static int lookup_FAT_size(uchar_t partid);
static int open_and_seek(char *dn, bpb_t *wbpb, off64_t *seekto);
static int warn_mismatch(char *desc, char *src, int expect, int assigned);
static int copy_bootblk(char *fn, boot_sector_t *bootsect,
	ulong_t *bootblksize);
static int parse_drvnum(char *pn);
static int seek_nofdisk(int fd, bpb_t *wbpb, off64_t *seekto);
static int ask_nicely(char *special);
static int seek_partn(int fd, char *pn, bpb_t *wbpb, off64_t *seekto);
static int yes(void);

/*
 *  usage
 *
 *	Display usage message and exit.
 */
static
void
usage(void)
{
	(void) fprintf(stderr,
	    gettext("pcfs usage: mkfs [-F FSType] [-V] [-m] "
	    "[-o specific_options] special\n"));

	(void) fprintf(stderr,
	    gettext(" -V: print this command line and return\n"
	    " -m: dump command line used to create a FAT on this media\n"
	    "\t(other options are ignored if this option is chosen).\n"
	    " -o: pcfs_specific_options:\n"
	    "\t'pcfs_specific_options' is a comma separated list\n"
	    "\tincluding one or more of the following options:\n"
	    "\t    N,v,r,h,s,b=label,B=filename,i=filename,\n"
	    "\t    spc=n,fat=n,nsect=n,ntrack=n,nofdisk,size=n,\n"
	    "\t    reserve=n,hidden=n\n\n"));

	(void) fprintf(stderr,
	    gettext("'Special' should specify a raw diskette "
	    "or raw fixed disk device.  \"Fixed\"\n"
	    "disks (which include high-capacity removable "
	    "media such as Zip disks)\n"
	    "may be further qualified with a logical "
	    "drive specifier.\n"
	    "Examples are: /dev/rdiskette and "
	    "/dev/rdsk/c0t0d0p0:c\n"));
	exit(1);
}

static
int
yes(void)
{
	char *affirmative = gettext("yY");
	char *a = affirmative;
	int b;

	b = getchar();
	while (b == '\n' && b != '\0' && b != EOF)
		b = getchar();
	while (*a) {
		if (b == (int)*a)
			break;
		a++;
	}
	return (*a);
}

static
int
ask_nicely(char *special)
{
	/*
	 * 4228473 - No way to non-interactively make a pcfs filesystem
	 *
	 *	If we don't have an input TTY, or we aren't really doing
	 *	anything, then don't ask questions.  Assume a yes answer
	 *	to any questions we would ask.
	 */
	if (Notreally || !isatty(fileno(stdin)))
		return (1);

	(void) printf(
	    gettext("Construct a new FAT file system on %s: (y/n)? "), special);
	(void) fflush(stdout);
	return (yes());
}

/*
 * store_16_bits
 *	Save the lower 16 bits of a 32 bit value (v) into the provided
 *	buffer (pointed at by *bp), and increment the buffer pointer
 *	as well.  This way the routine can be called multiple times in
 *	succession to fill buffers.  The value is stored in little-endian
 *	order.
 */
static
void
store_16_bits(uchar_t **bp, uint32_t v)
{
	uchar_t *l = *bp;

	*l++ = v & 0xff;
	*l = (v >> 8) & 0xff;
	*bp += 2;
}

/*
 * store_32_bits
 * 	Save the 32 bit value (v) into the provided buffer (pointed
 *	at by *bp), and increment the buffer pointer as well.  This way
 *	the routine can be called multiple times in succession to fill
 *	buffers.  The value is stored in little-endian order.
 */
static
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

/*
 *  dump_bytes  -- display bytes as hex numbers.
 *		   b is the pointer to the byte buffer
 *		   n is the number of bytes in the buffer
 */
/* Note: BPL = bytes to display per line */
#define	BPL 16

static
void
dump_bytes(uchar_t *b, int n)
{
	int cd = n;
	int cu = 0;
	int o = 0;
	int bl;
	int ac;

	/* Display offset, 16 bytes per line, and printable ascii version */
	while (cd > 0) {
		ac = 0;
		(void) printf("\n%06x: ", o);
		for (bl = 0; bl < BPL; bl++) {
			if (cu+bl < n) {
				(void) printf("%02x ", (b[cu+bl] & 0xff));
				ac++;
			}
			else
				(void) printf("   ");
		}
		for (bl = 0; bl < BPL; bl++) {
			if ((cu+bl < n) &&
			    ((b[cu+bl] >= ' ') && (b[cu+bl] <= '~')))
				(void) printf("%c", b[cu+bl]);
			else
				(void) printf(".");
		}
		cu += ac; o += ac; cd -= ac;
	}
	(void) printf("\n\n");
}

/*
 *  header_for_dump  --  display simple header over what will be output.
 */
static
void
header_for_dump(void)
{
	int bl;

	(void) printf("\n        ");
	for (bl = 0; bl < BPL; bl++)
		(void) printf("%02x ", bl);
	(void) printf("\n       ");
	bl = 3*BPL;
	while (bl-- > 0)
		(void) printf("-");
}

/*
 *  parse_drvnum
 *	Convert a partition name into a drive number.
 */
static
int
parse_drvnum(char *pn)
{
	int drvnum;

	/*
	 * Determine logical drive to seek after.
	 */
	if (strlen(pn) == 1 && *pn >= 'c' && *pn <= 'z') {
		drvnum = *pn - 'c' + 1;
	} else if (*pn >= '0' && *pn <= '9') {
		char *d;
		int v, m, c;

		v = 0;
		d = pn;
		while (*d && *d >= '0' && *d <= '9') {
			c = strlen(d);
			m = 1;
			while (--c)
				m *= 10;
			v += m * (*d - '0');
			d++;
		}

		if (*d || v > 24) {
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
 *  Define some special logical drives we use.
 */
#define	BOOT_PARTITION_DRIVE	99
#define	PRIMARY_DOS_DRIVE	1

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

static
int
warn_mismatch(char *desc, char *src, int expect, int assigned)
{
	if (expect == assigned)
		return (assigned);

	/*
	 * 4228473 - No way to non-interactively make a pcfs filesystem
	 *
	 *	If we don't have an input TTY, or we aren't really doing
	 *	anything, then don't ask questions.  Assume a yes answer
	 *	to any questions we would ask.
	 */
	if (Notreally || !isatty(fileno(stdin))) {
		(void) printf(gettext("WARNING: User supplied %s is %d,"
		    "\nbut value obtained from the %s is %d.\n"
		    "Using user supplied value.\n"),
		    desc, assigned, src, expect);
		return (assigned);
	}

	(void) printf(gettext("User supplied %s is %d."
	    "\nThe value obtained from the %s is %d.\n"),
	    desc, assigned, src, expect);

	(void) printf(
	    gettext("Continue with value given on command line (y/n)? "));
	(void) fflush(stdout);
	if (yes())
		return (assigned);
	else
		exit(2);
	/*NOTREACHED*/
}

static
void
fill_fat32_bpb(bpb_t *wbpb)
{
	/*
	 * ExtFlags means (according to MSDN BPB (FAT32) document)
	 *
	 * Bit 8 indicates info written to the active FAT is written
	 * to all copies of the FAT.  (I think they mean bit 7, with
	 * numbering starting at 0)
	 *
	 * Lowest 4 bits of field are the 0 based FAT number of the
	 * Active FAT.  (only meaningful if bit 8 is set)
	 *
	 * Field contains combination of these values:
	 *
	 *	VALUE				DESCRIPTION
	 * BGBPB_F_ActiveFATMsk		Mask for low four bits
	 * (0x000F)
	 * BGBPB_F_NoFATMirror		If set FAT mirroring disabled.
	 * (0x0080)			If clear, FAT mirroring enabled.
	 *
	 * We set the value based on what I've seen on all the FAT32 drives
	 * I've seen created by Windows.
	 *
	 */
	wbpb->bpb32.ext_flags = 0x0;
	/*
	 * No real explanation of the fs_vers file in the BPB doc.  The
	 * high byte is supposed to be the major version and the low the
	 * minor version.  Again I set according to what I've seen on Windows.
	 */
	wbpb->bpb32.fs_vers_lo = '\0';
	wbpb->bpb32.fs_vers_hi = '\0';
	/*
	 * The convention appears to be to place the fs info sector
	 * immediately after the boot sector, and that the backup boot
	 * sector should be at sector 6. (based on what I see with
	 * Windows)
	 */
	wbpb->bpb32.fsinfosec = 1;
	wbpb->bpb32.backupboot = 6;
}

static
void
fill_bpb_sizes(bpb_t *wbpb, struct ipart part[], int partno, off64_t offset)
{
	ulong_t usesize;

	if (GetFsParams || GetSize) {
		usesize = ltohi(part[partno].numsect);
		if (Verbose) {
			(void) printf(
			    gettext("Partition size (from FDISK table) "
			    "= %d sectors.\n"), usesize);
		}
	} else {
		usesize = warn_mismatch(
		    gettext("length of partition (in sectors)"),
		    gettext("FDISK table"),
		    ltohi(part[partno].numsect), TotSize);
	}

	if (GetFsParams) {
		TotSize = usesize;
	} else {
		if (usesize > 0xffff)
			wbpb->bpb.sectors_in_volume = 0;
		else
			wbpb->bpb.sectors_in_volume = usesize;
		wbpb->bpb.sectors_in_logical_volume = usesize;
	}

	wbpb->bpb.hidden_sectors = offset;

	if (GetFsParams) {
		RelOffset = offset;
	} else {
		wbpb->sunbpb.bs_offset_high = offset >> 16;
		wbpb->sunbpb.bs_offset_low = offset & 0xFFFF;
	}
}

/*
 *  lookup_FAT_size
 *
 *	Given the FDISK partition file system identifier, return the
 *	expected FAT size for the partition.
 */
static
int
lookup_FAT_size(uchar_t partid)
{
	int rval;

	switch (partid) {
	case DOSOS12:
		rval = 12;
		break;
	case DOSOS16:
	case DOSHUGE:
	case FDISK_FAT95:
	case X86BOOT:
		rval = 16;
		break;
	case FDISK_WINDOWS:
	case FDISK_EXT_WIN:
		rval = 32;
		break;
	case EXTDOS:
	case FDISK_EXTLBA:
	default:
		rval = -1;
		break;
	}

	return (rval);
}

/*
 *  seek_partn
 *
 *	Seek to the beginning of the partition where we need to install
 *	the new FAT.  Zero return for any error, but print error
 *	messages here.
 */
static
int
seek_partn(int fd, char *pn, bpb_t *wbpb, off64_t *seekto)
{
	struct ipart part[FD_NUMPART];
	struct mboot extmboot;
	struct mboot mb;
	diskaddr_t xstartsect;
	off64_t nextseek = 0;
	off64_t lastseek = 0;
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

	if ((drvnum = parse_drvnum(pn)) < 0)
		return (PART_NOT_FOUND);

	if (read(fd, &mb, sizeof (mb)) != sizeof (mb)) {
		(void) fprintf(stderr,
		    gettext("Couldn't read a Master Boot Record?!\n"));
		return (PART_NOT_FOUND);
	}

	if (ltohs(mb.signature) != BOOTSECSIG) {
		(void) fprintf(stderr,
		    gettext("Bad Sig on master boot record!\n"));
		return (PART_NOT_FOUND);
	}

	*seekto = 0;

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
			return (PART_NOT_FOUND);
		}
		if ((*seekto = ltohi(part[bootPart].relsect)) == 0) {
			(void) fprintf(stderr, gettext("Bogus FDISK entry? "
			    "A boot partition starting\nat sector 0 would "
			    "collide with the FDISK table!\n"));
			return (PART_NOT_FOUND);
		}

		fill_bpb_sizes(wbpb, part, bootPart, *seekto);
		*seekto *= BPSEC;
		FdiskFATsize = lookup_FAT_size(part[bootPart].systid);
		if (Verbose)
			(void) printf(gettext("Boot partition's offset: "
			    "Sector %x.\n"), *seekto/BPSEC);
		if (lseek64(fd, *seekto, SEEK_SET) < 0) {
			(void) fprintf(stderr, gettext("Partition %s: "), pn);
			perror("");
			return (PART_NOT_FOUND);
		}
		return (PART_FOUND);
	}

	if (drvnum == PRIMARY_DOS_DRIVE && primaryPart >= 0) {
		if ((*seekto = ltohi(part[primaryPart].relsect)) == 0) {
			(void) fprintf(stderr, gettext("Bogus FDISK entry? "
			    "A partition starting\nat sector 0 would "
			    "collide with the FDISK table!\n"));
			return (PART_NOT_FOUND);
		}

		fill_bpb_sizes(wbpb, part, primaryPart, *seekto);
		*seekto *= BPSEC;
		FdiskFATsize = lookup_FAT_size(part[primaryPart].systid);
		if (Verbose)
			(void) printf(gettext("Partition's offset: "
			    "Sector %x.\n"), *seekto/BPSEC);
		if (lseek64(fd, *seekto, SEEK_SET) < 0) {
			(void) fprintf(stderr, gettext("Partition %s: "), pn);
			perror("");
			return (PART_NOT_FOUND);
		}
		return (PART_FOUND);
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
		return (PART_NOT_FOUND);
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
			if (lseek64(fd, nextseek * BPSEC, SEEK_SET) < 0 ||
			    read(fd, &extmboot, sizeof (extmboot)) !=
			    sizeof (extmboot)) {
				perror(gettext("Unable to read extended "
				    "partition record"));
				return (PART_NOT_FOUND);
			}
			(void) memcpy(part, extmboot.parts, sizeof (part));
			lastseek = nextseek;
			if (ltohs(extmboot.signature) != MBB_MAGIC) {
				(void) fprintf(stderr,
				    gettext("Bad signature on "
				    "extended partition\n"));
				return (PART_NOT_FOUND);
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
			*seekto =
			    ltohi(part[extndDrives[driveIndex]].relsect) +
			    lastseek;
			if (*seekto == lastseek) {
				(void) fprintf(stderr,
				    gettext("Bogus FDISK entry?  A logical "
				    "drive starting at\nsector 0x%llx would "
				    "collide with the\nFDISK information in "
				    "that sector.\n"), *seekto);
				return (PART_NOT_FOUND);
			} else if (*seekto <= xstartsect ||
			    *seekto >= (xstartsect + xnumsect)) {
				(void) fprintf(stderr,
				    gettext("Bogus FDISK entry?  "
				    "Logical drive start sector (0x%llx)\n"
				    "not within extended partition! "
				    "(Expected in range 0x%x - 0x%x)\n"),
				    *seekto, xstartsect + 1,
				    xstartsect + xnumsect - 1);
				return (PART_NOT_FOUND);
			}
			fill_bpb_sizes(wbpb, part, extndDrives[driveIndex],
			    *seekto);
			*seekto *= BPSEC;
			FdiskFATsize = lookup_FAT_size(
			    part[extndDrives[driveIndex]].systid);
			if (Verbose)
				(void) printf(gettext("Partition's offset: "
				    "Sector 0x%x.\n"), *seekto/BPSEC);
			if (lseek64(fd, *seekto, SEEK_SET) < 0) {
				(void) fprintf(stderr,
				    gettext("Partition %s: "), pn);
				perror("");
				return (PART_NOT_FOUND);
			}
			return (PART_FOUND);
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
		*seekto = ltohi(part[extraDrives[driveIndex]].relsect);
		if (*seekto == 0) {
			(void) fprintf(stderr, gettext("Bogus FDISK entry? "
			    "A partition starting\nat sector 0 would "
			    "collide with the FDISK table!\n"));
			return (PART_NOT_FOUND);
		}

		fill_bpb_sizes(wbpb, part, extraDrives[driveIndex], *seekto);
		*seekto *= BPSEC;
		FdiskFATsize =
		    lookup_FAT_size(part[extraDrives[driveIndex]].systid);
		if (Verbose)
			(void) printf(gettext("Partition's offset: "
			    "Sector %x.\n"), *seekto/BPSEC);
		if (lseek64(fd, *seekto, SEEK_SET) < 0) {
			(void) fprintf(stderr,
			    gettext("Partition %s: "), pn);
			perror("");
			return (PART_NOT_FOUND);
		}
		return (PART_FOUND);
	}
	(void) fprintf(stderr, gettext("No such logical drive\n"));
	return (PART_NOT_FOUND);
}

/*
 *  seek_nofdisk
 *
 *	User is asking us to trust them that they know best.
 *	We basically won't do much seeking here, the only seeking we'll do
 *	is if the 'hidden' parameter was given.
 */
static
int
seek_nofdisk(int fd, bpb_t *wbpb, off64_t *seekto)
{
	if (TotSize > 0xffff)
		wbpb->bpb.sectors_in_volume = 0;
	else
		wbpb->bpb.sectors_in_volume = (short)TotSize;
	wbpb->bpb.sectors_in_logical_volume = TotSize;

	*seekto = RelOffset * BPSEC;
	wbpb->bpb.hidden_sectors = RelOffset;
	wbpb->sunbpb.bs_offset_high = RelOffset >> 16;
	wbpb->sunbpb.bs_offset_low = RelOffset & 0xFFFF;

	if (Verbose)
		(void) printf(gettext("Requested offset: Sector %x.\n"),
		    *seekto/BPSEC);

	if (lseek64(fd, *seekto, SEEK_SET) < 0) {
		(void) fprintf(stderr,
		    gettext("User specified start sector %d"), RelOffset);
		perror("");
		return (PART_NOT_FOUND);
	}
	return (PART_FOUND);
}

/*
 * set_fat_string
 *
 *	Fill in the type string of the FAT
 */
static
void
set_fat_string(bpb_t *wbpb, int fatsize)
{
	if (fatsize == 12) {
		(void) strncpy((char *)wbpb->ebpb.type, FAT12_TYPE_STRING,
		    strlen(FAT12_TYPE_STRING));
	} else if (fatsize == 16) {
		(void) strncpy((char *)wbpb->ebpb.type, FAT16_TYPE_STRING,
		    strlen(FAT16_TYPE_STRING));
	} else {
		(void) strncpy((char *)wbpb->ebpb.type, FAT32_TYPE_STRING,
		    strlen(FAT32_TYPE_STRING));
	}
}

/*
 *  prepare_image_file
 *
 *	Open the file that will hold the image (as opposed to the image
 *	being written to the boot sector of an actual disk).
 */
static
int
prepare_image_file(char *fn, bpb_t *wbpb)
{
	int fd;
	char zerobyte = '\0';

	if ((fd = open(fn, O_RDWR | O_CREAT | O_EXCL, 0666)) < 0) {
		perror(fn);
		exit(2);
	}

	if (Imagesize == 5) {
		/* Disk image of a 1.2M floppy */
		wbpb->bpb.sectors_in_volume = 2 * 80 * 15;
		wbpb->bpb.sectors_in_logical_volume = 2 * 80 * 15;
		wbpb->bpb.sectors_per_track = 15;
		wbpb->bpb.heads = 2;
		wbpb->bpb.media = 0xF9;
		wbpb->bpb.num_root_entries = 224;
		wbpb->bpb.sectors_per_cluster = 1;
		wbpb->bpb.sectors_per_fat = 7;
	} else {
		/* Disk image of a 1.44M floppy */
		wbpb->bpb.sectors_in_volume = 2 * 80 * 18;
		wbpb->bpb.sectors_in_logical_volume = 2 * 80 * 18;
		wbpb->bpb.sectors_per_track = 18;
		wbpb->bpb.heads = 2;
		wbpb->bpb.media = 0xF0;
		wbpb->bpb.num_root_entries = 224;
		wbpb->bpb.sectors_per_cluster = 1;
		wbpb->bpb.sectors_per_fat = 9;
	}

	/*
	 * Make a holey file, with length the exact
	 * size of the floppy image.
	 */
	if (lseek(fd, (wbpb->bpb.sectors_in_volume * BPSEC)-1, SEEK_SET) < 0) {
		(void) close(fd);
		perror(fn);
		exit(2);
	}

	if (write(fd, &zerobyte, 1) != 1) {
		(void) close(fd);
		perror(fn);
		exit(2);
	}

	if (lseek(fd, 0, SEEK_SET) < 0) {
		(void) close(fd);
		perror(fn);
		exit(2);
	}

	Fatentsize = 12;  /* Size of fat entry in bits */
	set_fat_string(wbpb, Fatentsize);

	wbpb->ebpb.phys_drive_num = 0;

	wbpb->sunbpb.bs_offset_high = 0;
	wbpb->sunbpb.bs_offset_low = 0;

	return (fd);
}

/*
 *  partn_lecture
 *
 *	Give a brief sermon on dev_name user should pass to
 *	the program from the command line.
 *
 */
static
void
partn_lecture(char *dn)
{
	(void) fprintf(stderr,
	    gettext("\nDevice %s was assumed to be a diskette.\n"
	    "A diskette specific operation failed on this device.\n"
	    "If the device is a hard disk, provide the name of "
	    "the full physical disk,\n"
	    "and qualify that name with a logical drive specifier.\n\n"
	    "Hint: the device is usually something similar to\n\n"
	    "/dev/rdsk/c0d0p0 or /dev/rdsk/c0t0d0p0 (x86)\n"
	    "/dev/rdsk/c0t5d0s2 (sparc)\n\n"
	    "The drive specifier is appended to the device name."
	    " For example:\n\n"
	    "/dev/rdsk/c0t5d0s2:c or /dev/rdsk/c0d0p0:boot\n\n"), dn);
}

static
void
warn_funky_floppy(void)
{
	(void) fprintf(stderr,
	    gettext("Use the 'nofdisk' option to create file systems\n"
	    "on non-standard floppies.\n\n"));
	exit(4);
}

static
void
warn_funky_fatsize(void)
{
	(void) fprintf(stderr,
	    gettext("Non-standard FAT size requested for floppy.\n"
	    "The 'nofdisk' option must be used to\n"
	    "override the 12 bit floppy default.\n\n"));
	exit(4);
}

static
void
floppy_bpb_fillin(bpb_t *wbpb, int diam, int hds, int spt)
{
	switch (diam) {
	case 3:
		switch (hds) {
		case 2:
			switch (spt) {
			case 9:
				wbpb->bpb.media = 0xF9;
				wbpb->bpb.num_root_entries = 112;
				wbpb->bpb.sectors_per_cluster = 2;
				wbpb->bpb.sectors_per_fat = 3;
				break;
			case 18:
				wbpb->bpb.media = 0xF0;
				wbpb->bpb.num_root_entries = 224;
				wbpb->bpb.sectors_per_cluster = 1;
				wbpb->bpb.sectors_per_fat = 9;
				break;
			case 36:
				wbpb->bpb.media = 0xF0;
				wbpb->bpb.num_root_entries = 240;
				wbpb->bpb.sectors_per_cluster = 2;
				wbpb->bpb.sectors_per_fat = 9;
				break;
			default:
				(void) fprintf(stderr,
				    gettext("Unknown diskette parameters!  "
				    "3.5'' diskette with %d heads "
				    "and %d sectors/track.\n"), hds, spt);
				warn_funky_floppy();
			}
			break;
		case 1:
		default:
			(void) fprintf(stderr,
			    gettext("Unknown diskette parameters!  "
			    "3.5'' diskette with %d heads "), hds);
			warn_funky_floppy();
		}
		break;
	case 5:
		switch (hds) {
		case 2:
			switch (spt) {
			case 15:
				wbpb->bpb.media = 0xF9;
				wbpb->bpb.num_root_entries = 224;
				wbpb->bpb.sectors_per_cluster = 1;
				wbpb->bpb.sectors_per_fat = 7;
				break;
			case 9:
				wbpb->bpb.media = 0xFD;
				wbpb->bpb.num_root_entries = 112;
				wbpb->bpb.sectors_per_cluster = 2;
				wbpb->bpb.sectors_per_fat = 2;
				break;
			case 8:
				wbpb->bpb.media = 0xFF;
				wbpb->bpb.num_root_entries = 112;
				wbpb->bpb.sectors_per_cluster = 1;
				wbpb->bpb.sectors_per_fat = 2;
				break;
			default:
				(void) fprintf(stderr,
				    gettext("Unknown diskette parameters!  "
				    "5.25'' diskette with %d heads "
				    "and %d sectors/track.\n"), hds, spt);
				warn_funky_floppy();
			}
			break;
		case 1:
			switch (spt) {
			case 9:
				wbpb->bpb.media = 0xFC;
				wbpb->bpb.num_root_entries = 64;
				wbpb->bpb.sectors_per_cluster = 1;
				wbpb->bpb.sectors_per_fat = 2;
				break;
			case 8:
				wbpb->bpb.media = 0xFE;
				wbpb->bpb.num_root_entries = 64;
				wbpb->bpb.sectors_per_cluster = 1;
				wbpb->bpb.sectors_per_fat = 1;
				break;
			default:
				(void) fprintf(stderr,
				    gettext("Unknown diskette parameters! "
				    "5.25'' diskette with %d heads "
				    "and %d sectors/track.\n"), hds, spt);
				warn_funky_floppy();
			}
			break;
		default:
			(void) fprintf(stderr,
			    gettext("Unknown diskette parameters! "
			    "5.25'' diskette with %d heads."), hds);
			warn_funky_floppy();
		}
		break;
	default:
		(void) fprintf(stderr,
		    gettext("\nUnknown diskette type.  Only know about "
		    "5.25'' and 3.5'' diskettes.\n"));
		warn_funky_floppy();
	}
}

/*
 *  lookup_floppy
 *
 *	Look up a media descriptor byte and other crucial BPB values
 *	based on floppy characteristics.
 */
static
void
lookup_floppy(struct fd_char *fdchar, bpb_t *wbpb)
{
	ulong_t tsize;
	ulong_t cyls, spt, hds, diam;

	cyls = fdchar->fdc_ncyl;
	diam = fdchar->fdc_medium;
	spt = fdchar->fdc_secptrack;
	hds = fdchar->fdc_nhead;

	tsize = cyls * hds * spt;

	if (GetFsParams)
		TotSize = tsize;

	if (GetSize) {
		wbpb->bpb.sectors_in_logical_volume = tsize;
	} else {
		wbpb->bpb.sectors_in_logical_volume =
		    warn_mismatch(
		    gettext("length of partition (in sectors)"),
		    gettext("FDIOGCHAR call"), tsize, TotSize);
	}
	wbpb->bpb.sectors_in_volume =
	    (short)wbpb->bpb.sectors_in_logical_volume;

	if (GetSPT) {
		wbpb->bpb.sectors_per_track = spt;
	} else {
		wbpb->bpb.sectors_per_track =
		    warn_mismatch(
		    gettext("sectors per track"),
		    gettext("FDIOGCHAR call"), spt, SecPerTrk);
		spt = wbpb->bpb.sectors_per_track;
	}

	if (GetTPC) {
		wbpb->bpb.heads = hds;
	} else {
		wbpb->bpb.heads =
		    warn_mismatch(
		    gettext("number of heads"),
		    gettext("FDIOGCHAR call"), hds, TrkPerCyl);
		hds = wbpb->bpb.heads;
	}

	Fatentsize = 12;  /* Size of fat entry in bits */
	if (!GetBPF && BitsPerFAT != Fatentsize) {
		warn_funky_fatsize();
	}
	set_fat_string(wbpb, Fatentsize);

	wbpb->ebpb.phys_drive_num = 0;

	wbpb->bpb.hidden_sectors = 0;
	wbpb->sunbpb.bs_offset_high = 0;
	wbpb->sunbpb.bs_offset_low = 0;

	floppy_bpb_fillin(wbpb, diam, hds, spt);
}

/*
 *  compute_cluster_size
 *
 *	Compute an acceptable sectors/cluster value.
 *
 * 	Based on values from the Hardware White Paper
 *	from Microsoft.
 *	"Microsoft Extensible Firmware Initiative
 *	 FAT32 File System Specification
 *	 FAT: General Overview of On-Disk Format"
 *
 *	Version 1.03, December 6, 2000
 *
 */
static
void
compute_cluster_size(bpb_t *wbpb)
{
	ulong_t volsize;
	ulong_t spc;
	ulong_t rds, tmpval1, tmpval2;
	ulong_t fatsz;
	int newfat = 16;

#define	FAT12_MAX_CLUSTERS	0x0FF4
#define	FAT16_MAX_CLUSTERS	0xFFF4
#define	FAT32_MAX_CLUSTERS	0x0FFFFFF0
#define	FAT32_SUGGESTED_NCLUST	0x400000

	/* compute volume size in sectors. */
	volsize = wbpb->bpb.sectors_in_volume ? wbpb->bpb.sectors_in_volume :
	    wbpb->bpb.sectors_in_logical_volume;
	volsize -= wbpb->bpb.resv_sectors;

	if (GetSPC) {
		/*
		 * User indicated what sort of FAT to create,
		 * make sure it is valid with the given size
		 * and compute an SPC value.
		 */
		if (!MakeFAT32) { /* FAT16 */
			/* volsize is in sectors */
			if (volsize < FAT12_MAX_CLUSTERS) {
				(void) fprintf(stderr,
				    gettext("Requested size is too "
				    "small for FAT16.\n"));
				exit(4);
			}
			/* SPC must be a power of 2 */
			for (spc = 1; spc <= 64; spc = spc * 2) {
				if (volsize < spc * FAT16_MAX_CLUSTERS)
					break;
			}
			if (volsize > (spc * FAT16_MAX_CLUSTERS)) {
				(void) fprintf(stderr,
				    gettext("Requested size is too "
				    "large for FAT16.\n"));
				exit(4);
			}
		} else { /* FAT32 */
			/* volsize is in sectors */
			if (volsize < FAT16_MAX_CLUSTERS) {
				(void) fprintf(stderr,
				    gettext("Requested size is too "
				    "small for FAT32.\n"));
				exit(4);
			}
			/* SPC must be a power of 2 */
			for (spc = 1; spc <= 64; spc = spc * 2) {
				if (volsize < (spc * FAT32_SUGGESTED_NCLUST))
					break;
			}
			if (volsize > (spc * FAT32_MAX_CLUSTERS)) {
				(void) fprintf(stderr,
				    gettext("Requested size is too "
				    "large for FAT32.\n"));
				exit(4);
			}
		}
	} else {
		/*
		 * User gave the SPC as an explicit option,
		 * make sure it will work with the requested
		 * volume size.
		 */
		int nclust;

		spc = SecPerClust;
		nclust = volsize / spc;

		if (nclust <= FAT16_MAX_CLUSTERS && MakeFAT32) {
			(void) fprintf(stderr, gettext("Requested size is too "
			    "small for FAT32.\n"));
			exit(4);
		}
		if (!MakeFAT32) {
			/* Determine if FAT12 or FAT16 */
			if (nclust < FAT12_MAX_CLUSTERS)
				newfat = 12;
			else if (nclust < FAT16_MAX_CLUSTERS)
				newfat = 16;
			else {
				(void) fprintf(stderr,
				    gettext("Requested size is too "
				    "small for FAT32.\n"));
				exit(4);
			}
		}
	}

	/*
	 * RootDirSectors = ((BPB_RootEntCnt * 32) +
	 *	(BPB_BytsPerSec  1)) / BPB_BytsPerSec;
	 */
	rds = ((wbpb->bpb.num_root_entries * 32) +
	    (wbpb->bpb.bytes_sector - 1)) / wbpb->bpb.bytes_sector;

	if (GetBPF) {
		if (MakeFAT32)
			Fatentsize = 32;
		else
			Fatentsize = newfat;
	} else {
		Fatentsize = BitsPerFAT;

		if (Fatentsize == 12 &&
		    (volsize - rds) >= DOS_F12MAXC * spc) {
			/*
			 * If we don't have an input TTY, or we aren't
			 * really doing anything, then don't ask
			 * questions.  Assume a yes answer to any
			 * questions we would ask.
			 */
			if (Notreally || !isatty(fileno(stdin))) {
				(void) printf(
				gettext("Volume too large for 12 bit FAT,"
				    " increasing to 16 bit FAT size.\n"));
				(void) fflush(stdout);
				Fatentsize = 16;
			} else {
				(void) printf(
				gettext("Volume too large for a 12 bit FAT.\n"
				    "Increase to 16 bit FAT "
				    "and continue (y/n)? "));
				(void) fflush(stdout);
				if (yes())
					Fatentsize = 16;
				else
					exit(5);
			}
		}
	}
	wbpb->bpb.sectors_per_cluster = spc;

	if (!GetFsParams && FdiskFATsize < 0) {
		(void) printf(
		    gettext("Cannot verify chosen/computed FAT "
		    "entry size (%d bits) with FDISK table.\n"
		    "FDISK table has an unknown file system "
		    "type for this device.  Giving up...\n"),
		    Fatentsize, Fatentsize);
		exit(6);
	} else if (!GetFsParams && FdiskFATsize && FdiskFATsize != Fatentsize) {
		(void) printf(
		    gettext("Chosen/computed FAT entry size (%d bits) "
		    "does not match FDISK table (%d bits).\n"),
		    Fatentsize, FdiskFATsize);
		(void) printf(
		    gettext("Use -o fat=%d to build a FAT "
		    "that matches the FDISK entry.\n"), FdiskFATsize);
		exit(6);
	}
	set_fat_string(wbpb, Fatentsize);
	/*
	 * Compure the FAT sizes according to algorithm from Microsoft:
	 *
	 * RootDirSectors = ((BPB_RootEntCnt * 32) +
	 *	(BPB_BytsPerSec  1)) / BPB_BytsPerSec;
	 * TmpVal1 = DskSize - (BPB_ResvdSecCnt + RootDirSectors);
	 * TmpVal2 = (256 * BPB_SecPerClus) + BPB_NumFATs;
	 * If (FATType == FAT32)
	 * 	TmpVal2 = TmpVal2 / 2;
	 * FATSz = (TMPVal1 + (TmpVal2  1)) / TmpVal2;
	 * If (FATType == FAT32) {
	 * 	BPB_FATSz16 = 0;
	 *	BPB_FATSz32 = FATSz;
	 * } else {
	 *	BPB_FATSz16 = LOWORD(FATSz);
	 * 	// there is no BPB_FATSz32 in a FAT16 BPB
	 * }
	 */
	tmpval1 = volsize - (wbpb->bpb.resv_sectors + rds);

	tmpval2 = (256 * wbpb->bpb.sectors_per_cluster) + wbpb->bpb.num_fats;

	if (Fatentsize == 32)
		tmpval2 = tmpval2 / 2;

	fatsz = (tmpval1 + (tmpval2 - 1)) / tmpval2;

	/* Compute a sector/fat figure */
	switch (Fatentsize) {
	case 32:
		wbpb->bpb.sectors_per_fat = 0;
		wbpb->bpb32.big_sectors_per_fat = fatsz;
		if (Verbose)
			(void) printf("compute_cluster_size: Sectors per "
			    "FAT32 = %d\n", wbpb->bpb32.big_sectors_per_fat);
		break;
	case 12:
	default:	/* 16 bit FAT */
		wbpb->bpb.sectors_per_fat = (ushort_t)(fatsz & 0x0000FFFF);
		if (Verbose)
			(void) printf("compute_cluster_size: Sectors per "
			    "FAT16 = %d\n", wbpb->bpb.sectors_per_fat);
		break;
	}
}

static
void
find_fixed_details(int fd, bpb_t *wbpb)
{
	struct dk_geom dginfo;

	/*
	 *  Look up the last remaining bits of info we need
	 *  that is specific to the hard drive using a disk ioctl.
	 */
	if (GetSPT || GetTPC) {
		if (ioctl(fd, DKIOCG_VIRTGEOM, &dginfo) == -1 &&
		    ioctl(fd, DKIOCG_PHYGEOM, &dginfo) == -1 &&
		    ioctl(fd, DKIOCGGEOM, &dginfo) == -1) {
			(void) close(fd);
			perror(
			    gettext("Drive geometry lookup (need "
			    "tracks/cylinder and/or sectors/track"));
			exit(2);
		}
	}

	wbpb->bpb.heads = (GetTPC ? dginfo.dkg_nhead : TrkPerCyl);
	wbpb->bpb.sectors_per_track = (GetSPT ? dginfo.dkg_nsect : SecPerTrk);

	if (Verbose) {
		if (GetTPC) {
			(void) printf(
			    gettext("DKIOCG determined number of heads = %d\n"),
			    dginfo.dkg_nhead);
		}
		if (GetSPT) {
			(void) printf(
			    gettext("DKIOCG determined sectors per track"
			    " = %d\n"), dginfo.dkg_nsect);
		}
	}

	/*
	 * XXX - MAY need an additional flag (or flags) to set media
	 * and physical drive number fields.  That in the case of weird
	 * floppies that have to go through 'nofdisk' route for formatting.
	 */
	wbpb->bpb.media = 0xF8;
	if (MakeFAT32)
		wbpb->bpb.num_root_entries = 0;
	else
		wbpb->bpb.num_root_entries = 512;
	wbpb->ebpb.phys_drive_num = 0x80;
	compute_cluster_size(wbpb);
}

static
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
		actualdisk = strtok(strdup(diskname), ":");
		if (*suffix = strchr(diskname, ':'))
			(*suffix)++;

		if (stat(actualdisk, info)) {
			perror(actualdisk);
			exit(2);
		}
	} else {
		actualdisk = strdup(diskname);
	}

	return (actualdisk);
}

static
void
compute_file_area_size(bpb_t *wbpb)
{
	int FATSz;
	int TotSec;
	int DataSec;
	int RootDirSectors =
	    ((wbpb->bpb.num_root_entries * 32) + (wbpb->bpb.bytes_sector - 1)) /
	    wbpb->bpb.bytes_sector;

	if (wbpb->bpb.sectors_per_fat) {
		/*
		 * Good old FAT12 or FAT16
		 */
		FATSz = wbpb->bpb.sectors_per_fat;
		TotSec = wbpb->bpb.sectors_in_volume;
	} else {
		/*
		 *  FAT32
		 */
		FATSz = wbpb->bpb32.big_sectors_per_fat;
		TotSec = wbpb->bpb.sectors_in_logical_volume;
	}

	DataSec = TotSec -
	    (wbpb->bpb.resv_sectors + (wbpb->bpb.num_fats * FATSz) +
	    RootDirSectors);


	/*
	 * Now change sectors to clusters
	 */
	TotalClusters = DataSec / wbpb->bpb.sectors_per_cluster;

	if (Verbose)
		(void) printf(gettext("Disk has a file area of %d "
		    "allocation units,\neach with %d sectors = %d "
		    "bytes.\n"), TotalClusters, wbpb->bpb.sectors_per_cluster,
		    TotalClusters * wbpb->bpb.sectors_per_cluster * BPSEC);
}

#ifndef i386
/*
 *  swap_pack_{bpb,bpb32,sebpb}cpy
 *
 *	If not on an x86 we assume the structures making up the bpb
 *	were not packed and that longs and shorts need to be byte swapped
 *	(we've kept everything in host order up until now).  A new architecture
 *	might not need to swap or might not need to pack, in which case
 *	new routines will have to be written.  Of course if an architecture
 *	supports both packing and little-endian host order, it can follow the
 *	same path as the x86 code.
 */
static
void
swap_pack_bpbcpy(struct _boot_sector *bsp, bpb_t *wbpb)
{
	uchar_t *fillp;

	fillp = (uchar_t *)&(bsp->bs_filler[ORIG_BPB_START_INDEX]);

	store_16_bits(&fillp, wbpb->bpb.bytes_sector);
	*fillp++ = wbpb->bpb.sectors_per_cluster;
	store_16_bits(&fillp, wbpb->bpb.resv_sectors);
	*fillp++ = wbpb->bpb.num_fats;
	store_16_bits(&fillp, wbpb->bpb.num_root_entries);
	store_16_bits(&fillp, wbpb->bpb.sectors_in_volume);
	*fillp++ = wbpb->bpb.media;
	store_16_bits(&fillp, wbpb->bpb.sectors_per_fat);
	store_16_bits(&fillp, wbpb->bpb.sectors_per_track);
	store_16_bits(&fillp, wbpb->bpb.heads);
	store_32_bits(&fillp, wbpb->bpb.hidden_sectors);
	store_32_bits(&fillp, wbpb->bpb.sectors_in_logical_volume);

	*fillp++ = wbpb->ebpb.phys_drive_num;
	*fillp++ = wbpb->ebpb.reserved;
	*fillp++ = wbpb->ebpb.ext_signature;
	store_32_bits(&fillp, wbpb->ebpb.volume_id);
	(void) strncpy((char *)fillp, (char *)wbpb->ebpb.volume_label, 11);
	fillp += 11;
	(void) strncpy((char *)fillp, (char *)wbpb->ebpb.type, 8);
}

static
void
swap_pack_bpb32cpy(struct _boot_sector32 *bsp, bpb_t *wbpb)
{
	uchar_t *fillp;
	int r;

	fillp = (uchar_t *)&(bsp->bs_filler[ORIG_BPB_START_INDEX]);

	store_16_bits(&fillp, wbpb->bpb.bytes_sector);
	*fillp++ = wbpb->bpb.sectors_per_cluster;
	store_16_bits(&fillp, wbpb->bpb.resv_sectors);
	*fillp++ = wbpb->bpb.num_fats;
	store_16_bits(&fillp, wbpb->bpb.num_root_entries);
	store_16_bits(&fillp, wbpb->bpb.sectors_in_volume);
	*fillp++ = wbpb->bpb.media;
	store_16_bits(&fillp, wbpb->bpb.sectors_per_fat);
	store_16_bits(&fillp, wbpb->bpb.sectors_per_track);
	store_16_bits(&fillp, wbpb->bpb.heads);
	store_32_bits(&fillp, wbpb->bpb.hidden_sectors);
	store_32_bits(&fillp, wbpb->bpb.sectors_in_logical_volume);

	store_32_bits(&fillp, wbpb->bpb32.big_sectors_per_fat);
	store_16_bits(&fillp, wbpb->bpb32.ext_flags);
	*fillp++ = wbpb->bpb32.fs_vers_lo;
	*fillp++ = wbpb->bpb32.fs_vers_hi;
	store_32_bits(&fillp, wbpb->bpb32.root_dir_clust);
	store_16_bits(&fillp, wbpb->bpb32.fsinfosec);
	store_16_bits(&fillp, wbpb->bpb32.backupboot);
	for (r = 0; r < 6; r++)
		store_16_bits(&fillp, wbpb->bpb32.reserved[r]);

	*fillp++ = wbpb->ebpb.phys_drive_num;
	*fillp++ = wbpb->ebpb.reserved;
	*fillp++ = wbpb->ebpb.ext_signature;
	store_32_bits(&fillp, wbpb->ebpb.volume_id);
	(void) strncpy((char *)fillp, (char *)wbpb->ebpb.volume_label, 11);
	fillp += 11;
	(void) strncpy((char *)fillp, (char *)wbpb->ebpb.type, 8);
}

static
void
swap_pack_sebpbcpy(struct _boot_sector *bsp, bpb_t *wbpb)
{
	uchar_t *fillp;

	fillp = bsp->bs_sun_bpb;
	store_16_bits(&fillp, wbpb->sunbpb.bs_offset_high);
	store_16_bits(&fillp, wbpb->sunbpb.bs_offset_low);
}

static
void
swap_pack_grabbpb(bpb_t *wbpb, struct _boot_sector *bsp)
{
	uchar_t *grabp;

	grabp = (uchar_t *)&(bsp->bs_filler[ORIG_BPB_START_INDEX]);

	((uchar_t *)&(wbpb->bpb.bytes_sector))[1] = *grabp++;
	((uchar_t *)&(wbpb->bpb.bytes_sector))[0] = *grabp++;
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

static
void
swap_pack_grabsebpb(bpb_t *wbpb, struct _boot_sector *bsp)
{
	uchar_t *grabp;

	grabp = bsp->bs_sun_bpb;
	((uchar_t *)&(wbpb->sunbpb.bs_offset_high))[1] = *grabp++;
	((uchar_t *)&(wbpb->sunbpb.bs_offset_high))[0] = *grabp++;
	((uchar_t *)&(wbpb->sunbpb.bs_offset_low))[1] = *grabp++;
	((uchar_t *)&(wbpb->sunbpb.bs_offset_low))[0] = *grabp++;
}

static
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
#endif	/* ! i386 */

static
void
dashm_bail(int fd)
{
	(void) fprintf(stderr,
	    gettext("This media does not appear to be "
	    "formatted with a FAT file system.\n"));
	(void) close(fd);
	exit(6);
}

/*
 *  read_existing_bpb
 *
 *	Grab the first sector, which we think is a bios parameter block.
 *	If it looks bad, bail.  Otherwise fill in the parameter struct
 *	fields that matter.
 */
static
void
read_existing_bpb(int fd, bpb_t *wbpb)
{
	boot_sector_t ubpb;

	if (read(fd, ubpb.buf, BPSEC) < BPSEC) {
		perror(gettext("Read BIOS parameter block "
		    "from previously formatted media"));
		(void) close(fd);
		exit(6);
	}

	if (ltohs(ubpb.mb.signature) != BOOTSECSIG) {
		dashm_bail(fd);
	}

#ifdef i386
	(void) memcpy(&(wbpb->bpb), &(ubpb.bs.bs_front.bs_bpb),
	    sizeof (wbpb->bpb));
	(void) memcpy(&(wbpb->ebpb), &(ubpb.bs.bs_ebpb), sizeof (wbpb->ebpb));
#else
	swap_pack_grabbpb(wbpb, &(ubpb.bs));
#endif
	if (SunBPBfields) {
#ifdef i386
		(void) memcpy(&(wbpb->sunbpb), &(ubpb.bs.bs_sebpb),
		    sizeof (wbpb->sunbpb));
#else
		swap_pack_grabsebpb(wbpb, &(ubpb.bs));
#endif
	}
	if (wbpb->bpb.bytes_sector != BPSEC) {
		(void) fprintf(stderr,
		    gettext("Bogus bytes per sector value.\n"));
		if (!(ISP2(wbpb->bpb.bytes_sector) &&
		    IN_RANGE(wbpb->bpb.bytes_sector, 1, BPSEC * 8))) {
			(void) fprintf(stderr,
			    gettext("The device name may be missing a "
			    "logical drive specifier.\n"));
			(void) close(fd);
			exit(6);
		} else {
			(void) fprintf(stderr,
			    gettext("Do not know how to build FATs with a\n"
			    "non-standard sector size. Standard "
			    "size is %d bytes,\nyour sector size "
			    "is %d bytes.\n"), BPSEC,
			    wbpb->bpb.bytes_sector);
			(void) close(fd);
			exit(6);
		}
	}
	if (!(ISP2(wbpb->bpb.sectors_per_cluster) &&
	    IN_RANGE(wbpb->bpb.sectors_per_cluster, 1, 128))) {
		(void) fprintf(stderr,
		    gettext("Bogus sectors per cluster value.\n"));
		(void) fprintf(stderr,
		    gettext("The device name may be missing a "
		    "logical drive specifier.\n"));
		(void) close(fd);
		exit(6);
	}

	if (wbpb->bpb.sectors_per_fat == 0) {
#ifdef i386
		(void) memcpy(&(wbpb->bpb32), &(ubpb.bs32.bs_bpb32),
		    sizeof (wbpb->bpb32));
#else
		swap_pack_grab32bpb(wbpb, &(ubpb.bs));
#endif
		compute_file_area_size(wbpb);
		if ((wbpb->bpb32.big_sectors_per_fat * BPSEC / 4) >=
		    TotalClusters) {
			MakeFAT32 = 1;
		} else {
			dashm_bail(fd);
		}
	} else {
		compute_file_area_size(wbpb);
	}
}

/*
 *  compare_existing_with_computed
 *
 *	We use this function when we the user specifies the -m option.
 *	We compute and look up things like we would if they had asked
 *	us to make the fs, and compare that to what's already layed down
 *	in the existing fs.  If there's a difference we can tell them what
 *	options to specify in order to reproduce their existing layout.
 *	Note that they still may not get an exact duplicate, because we
 *	don't, for example, preserve their existing boot code.  We think
 *	we've got all the fields that matter covered, though.
 *
 *	XXX - We're basically ignoring sbpb at this point.  I'm unsure
 *	if we'll ever care about those fields, in terms of the -m option.
 */
static
void
compare_existing_with_computed(int fd, char *suffix,
    bpb_t *wbpb, int *prtsize, int *prtspc, int *prtbpf, int *prtnsect,
    int *prtntrk, int *prtfdisk, int *prthidden, int *prtrsrvd, int *dashos)
{
	struct dk_geom	dginfo;
	struct fd_char	fdchar;
	bpb_t		compare;
	int		fd_ioctl_worked = 0;
	int		fatents;

	/*
	 *  For all non-floppy cases we expect to find a 16-bit FAT
	 */
	int expectfatsize = 16;

	compare = *wbpb;

	if (!suffix) {
		if (ioctl(fd, FDIOGCHAR, &fdchar) != -1) {
			expectfatsize = 12;
			fd_ioctl_worked++;
		}
	}

	if (fd_ioctl_worked) {
#ifdef sparc
		fdchar.fdc_medium = 3;
#endif
		GetSize = GetSPT = GetSPC = GetTPC = GetBPF = 1;
		lookup_floppy(&fdchar, &compare);
		if (compare.bpb.heads != wbpb->bpb.heads) {
			(*prtntrk)++;
			(*dashos)++;
		}
		if (compare.bpb.sectors_per_track !=
		    wbpb->bpb.sectors_per_track) {
			(*prtnsect)++;
			(*dashos)++;
		}
	} else {
		int dk_ioctl_worked = 1;

		if (!suffix) {
			(*prtfdisk)++;
			(*prtsize)++;
			*dashos += 2;
		}
		if (ioctl(fd, DKIOCG_VIRTGEOM, &dginfo) == -1 &&
		    ioctl(fd, DKIOCG_PHYGEOM, &dginfo) == -1 &&
		    ioctl(fd, DKIOCGGEOM, &dginfo) == -1) {
			*prtnsect = *prtntrk = 1;
			*dashos += 2;
			dk_ioctl_worked = 0;
		}
		if (dk_ioctl_worked) {
			if (dginfo.dkg_nhead != wbpb->bpb.heads) {
				(*prtntrk)++;
				(*dashos)++;
			}
			if (dginfo.dkg_nsect !=
			    wbpb->bpb.sectors_per_track) {
				(*prtnsect)++;
				(*dashos)++;
			}
		}
		GetBPF = GetSPC = 1;
		compute_cluster_size(&compare);
	}

	if (!*prtfdisk && TotSize != wbpb->bpb.sectors_in_volume &&
	    TotSize != wbpb->bpb.sectors_in_logical_volume) {
		(*dashos)++;
		(*prtsize)++;
	}

	if (compare.bpb.sectors_per_cluster != wbpb->bpb.sectors_per_cluster) {
		(*dashos)++;
		(*prtspc)++;
	}

	if (compare.bpb.hidden_sectors != wbpb->bpb.hidden_sectors) {
		(*dashos)++;
		(*prthidden)++;
	}

	if (compare.bpb.resv_sectors != wbpb->bpb.resv_sectors) {
		(*dashos)++;
		(*prtrsrvd)++;
	}

	/*
	 * Compute approximate Fatentsize.  It's approximate because the
	 * size of the FAT may not be exactly a multiple of the number of
	 * clusters.  It should be close, though.
	 */
	if (MakeFAT32) {
		Fatentsize = 32;
		(*dashos)++;
		(*prtbpf)++;
	} else {
		fatents = wbpb->bpb.sectors_per_fat * BPSEC * 2 / 3;
		if (fatents >= TotalClusters && wbpb->ebpb.type[4] == '2')
			Fatentsize = 12;
		else
			Fatentsize = 16;
		if (Fatentsize != expectfatsize) {
			(*dashos)++;
			(*prtbpf)++;
		}
	}
}

static
void
print_reproducing_command(int fd, char *actualdisk, char *suffix, bpb_t *wbpb)
{
	int needcomma = 0;
	int prthidden = 0;
	int prtrsrvd = 0;
	int prtfdisk = 0;
	int prtnsect = 0;
	int prtntrk = 0;
	int prtsize = 0;
	int prtbpf = 0;
	int prtspc = 0;
	int dashos = 0;
	int ll, i;

	compare_existing_with_computed(fd, suffix, wbpb,
	    &prtsize, &prtspc, &prtbpf, &prtnsect, &prtntrk,
	    &prtfdisk, &prthidden, &prtrsrvd, &dashos);

	/*
	 *  Print out the command line they can use to reproduce the
	 *  file system.
	 */
	(void) printf("mkfs -F pcfs");

	ll = min(11, (int)strlen((char *)wbpb->ebpb.volume_label));
	/*
	 * First, eliminate trailing spaces. Now compare the name against
	 * our default label.  If there's a match we don't need to print
	 * any label info.
	 */
	i = ll;
	while (wbpb->ebpb.volume_label[--i] == ' ')
		;
	ll = i;

	if (ll == strlen(DEFAULT_LABEL) - 1) {
		char cmpbuf[11];

		(void) strcpy(cmpbuf, DEFAULT_LABEL);
		for (i = ll; i >= 0; i--) {
			if (cmpbuf[i] !=
			    toupper((int)(wbpb->ebpb.volume_label[i]))) {
				break;
			}
		}
		if (i < 0)
			ll = i;
	}

	if (ll >= 0) {
		(void) printf(" -o ");
		(void) printf("b=\"");
		for (i = 0; i <= ll; i++) {
			(void) printf("%c", wbpb->ebpb.volume_label[i]);
		}
		(void) printf("\"");
		needcomma++;
	} else if (dashos) {
		(void) printf(" -o ");
	}

#define	NEXT_DASH_O	dashos--; needcomma++; continue

	while (dashos) {
		if (needcomma) {
			(void) printf(",");
			needcomma = 0;
		}
		if (prtfdisk) {
			(void) printf("nofdisk");
			prtfdisk--;
			NEXT_DASH_O;
		}
		if (prtsize) {
			(void) printf("size=%u", wbpb->bpb.sectors_in_volume ?
			    wbpb->bpb.sectors_in_volume :
			    wbpb->bpb.sectors_in_logical_volume);
			prtsize--;
			NEXT_DASH_O;
		}
		if (prtnsect) {
			(void) printf("nsect=%d", wbpb->bpb.sectors_per_track);
			prtnsect--;
			NEXT_DASH_O;
		}
		if (prtspc) {
			(void) printf("spc=%d", wbpb->bpb.sectors_per_cluster);
			prtspc--;
			NEXT_DASH_O;
		}
		if (prtntrk) {
			(void) printf("ntrack=%d", wbpb->bpb.heads);
			prtntrk--;
			NEXT_DASH_O;
		}
		if (prtbpf) {
			(void) printf("fat=%d", Fatentsize);
			prtbpf--;
			NEXT_DASH_O;
		}
		if (prthidden) {
			(void) printf("hidden=%u", wbpb->bpb.hidden_sectors);
			prthidden--;
			NEXT_DASH_O;
		}
		if (prtrsrvd) {
			(void) printf("reserve=%d", wbpb->bpb.resv_sectors);
			prtrsrvd--;
			NEXT_DASH_O;
		}
	}

	(void) printf(" %s%c%c\n", actualdisk,
	    suffix ? ':' : '\0', suffix ? *suffix : '\0');
}

/*
 *  open_and_examine
 *
 *	Open the requested 'dev_name'.  Seek to point where
 *	we'd expect to find boot sectors, etc., based on any ':partition'
 *	attachments to the dev_name.
 *
 *	Examine the fields of any existing boot sector and display best
 *	approximation of how this fs could be reproduced with this command.
 */
static
int
open_and_examine(char *dn, bpb_t *wbpb)
{
	struct stat di;
	off64_t ignored;
	char *actualdisk = NULL;
	char *suffix = NULL;
	int fd;
	struct dk_minfo dkminfo;

	if (Verbose)
		(void) printf(gettext("Opening destination device/file.\n"));

	actualdisk = stat_actual_disk(dn, &di, &suffix);

	/*
	 *  Destination exists, now find more about it.
	 */
	if (!(S_ISCHR(di.st_mode))) {
		(void) fprintf(stderr,
		    gettext("\n%s: device name must be a "
		    "character special device.\n"), actualdisk);
		exit(2);
	} else if ((fd = open(actualdisk, O_RDWR)) < 0) {
		perror(actualdisk);
		exit(2);
	}

	/*
	 * Check the media sector size
	 */
	if (ioctl(fd, DKIOCGMEDIAINFO, &dkminfo) != -1) {
		if (dkminfo.dki_lbsize != 0 &&
		    ISP2(dkminfo.dki_lbsize / DEV_BSIZE) &&
		    dkminfo.dki_lbsize != DEV_BSIZE) {
			(void) fprintf(stderr,
			    gettext("The device sector size %u is not "
			    "supported by pcfs!\n"), dkminfo.dki_lbsize);
			(void) close(fd);
			exit(1);
		}
	}

	/*
	 * Find appropriate partition if we were requested to do so.
	 */
	if (suffix && !(seek_partn(fd, suffix, wbpb, &ignored))) {
		(void) close(fd);
		exit(2);
	}

	read_existing_bpb(fd, wbpb);
	print_reproducing_command(fd, actualdisk, suffix, wbpb);

	return (fd);
}

/*
 * getdiskinfo
 *
 * Extracts information about disk path in dn. We need to return both a
 * file descriptor and the device's suffix.
 * Secondarily, we need to detect the FAT type and size when dealing with
 * GPT partitions.
 */
static int
getdiskinfo(char *dn, char **suffix)
{
	struct dk_minfo	dkminfo;
	struct stat di;
	int rv, fd, reserved;
	char *actualdisk = NULL;
	dk_gpt_t *gpt = NULL;

	actualdisk = stat_actual_disk(dn, &di, suffix);

	/*
	 * Destination exists, now find more about it.
	 */
	if (!(S_ISCHR(di.st_mode))) {
		(void) fprintf(stderr,
		    gettext("Device name must indicate a "
		    "character special device: %s\n"), actualdisk);
		exit(2);
	} else if ((fd = open(actualdisk, O_RDWR)) < 0) {
		perror(actualdisk);
		exit(2);
	}

	/*
	 * Check the media sector size
	 */
	if (ioctl(fd, DKIOCGMEDIAINFO, &dkminfo) != -1) {
		if (dkminfo.dki_lbsize != 0 &&
		    ISP2(dkminfo.dki_lbsize / DEV_BSIZE) &&
		    dkminfo.dki_lbsize != DEV_BSIZE) {
			(void) fprintf(stderr,
			    gettext("The device sector size %u is not "
			    "supported by pcfs!\n"), dkminfo.dki_lbsize);
			(void) close(fd);
			exit(2);
		}
	}

	rv = efi_alloc_and_read(fd, &gpt);
	/*
	 * We should see only VT_EINVAL, VT_EIO and VT_ERROR.
	 * VT_EINVAL is for the case there is no GPT label.
	 * VT_ERROR will happen if device does no support the ioctl, so
	 * we will exit only in case of VT_EIO and unknown value of rv.
	 */
	if (rv < 0 && rv != VT_EINVAL && rv != VT_ERROR) {
		switch (rv) {
		case VT_EIO:
			(void) fprintf(stderr,
			    gettext("IO Error reading EFI label\n"));
			break;
		default:
			(void) fprintf(stderr,
			    gettext("Unknown Error %d reading EFI label\n"),
			    rv);
			break;
		}
		(void) close(fd);
		exit(2);
	}
	if (rv >= 0) {
		DontUseFdisk = 1;
		if (*suffix != NULL) {
			(void) fprintf(stderr,
			    gettext("Can not use drive specifier \"%s\" with "
			    "GPT partitioning.\n"), *suffix);
			efi_free(gpt);
			(void) close(fd);
			exit(2);
		}
		/* Can not use whole disk, 7 is GPT minor node "wd" */
		if (rv == 7) {
			(void) fprintf(stderr,
			    gettext("Device name must indicate a "
			    "partition: %s\n"), actualdisk);
			efi_free(gpt);
			(void) close(fd);
			exit(2);
		}

		if (GetSize == 1) {
			TotSize = gpt->efi_parts[rv].p_size;
			GetSize = 0;
		}

		if (GetBPF == 1) {
			if (GetResrvd == 1) {
				/* FAT32 has 32 reserved sectors */
				reserved = 32;
			} else {
				reserved = Resrvd;
			}
			/*
			 * The type of FAT is determined by the size of
			 * the partition - reserved sectors.
			 * The calculation is based on logic used in
			 * compute_cluster_size() and therefore we will not
			 * get into error situation when
			 * compute_cluster_size() will be called.
			 */
			if (TotSize - reserved < FAT16_MAX_CLUSTERS) {
				if (GetResrvd == 1)
					reserved = 1;

				if (TotSize - reserved < FAT12_MAX_CLUSTERS) {
					int spc;
					MakeFAT32 = 0;
					Fatentsize = 12;
					/*
					 * compute sectors per cluster
					 * for fat12
					 */
					for (spc = 1; spc <= 64;
					    spc = spc * 2) {
						if (TotSize - reserved <
						    spc * FAT12_MAX_CLUSTERS)
							break;
					}
					if (GetSPC == 1) {
						GetSPC = 0;
						SecPerClust = spc;
					}
				} else {
					MakeFAT32 = 0;
					Fatentsize = 16;
				}
			} else {
				MakeFAT32 = 1;
				Fatentsize = 32;
			}
		}
		efi_free(gpt);
	}
	return (fd);
}

/*
 *  open_and_seek
 *
 *	Open the requested 'dev_name'.  Seek to point where
 *	we'll write boot sectors, etc., based on any ':partition'
 *	attachments to the dev_name.
 *
 *	By the time we are finished here, the entire BPB will be
 *	filled in, excepting the volume label.
 */
static
int
open_and_seek(char *dn, bpb_t *wbpb, off64_t *seekto)
{
	struct fd_char fdchar;
	struct dk_geom dg;
	char *actualdisk = NULL;
	char *suffix = NULL;
	int fd;

	if (Verbose)
		(void) printf(gettext("Opening destination device/file.\n"));

	/*
	 * We hold these truths to be self evident, all BPBs we create
	 * will have these values in these fields.
	 */
	wbpb->bpb.num_fats = 2;
	wbpb->bpb.bytes_sector = BPSEC;

	/*
	 * Assign or use supplied numbers for hidden and
	 * reserved sectors in the file system.
	 */
	if (GetResrvd)
		if (MakeFAT32)
			wbpb->bpb.resv_sectors = 32;
		else
			wbpb->bpb.resv_sectors = 1;
	else
		wbpb->bpb.resv_sectors = Resrvd;

	wbpb->ebpb.ext_signature = 0x29; /* Magic number for modern format */
	wbpb->ebpb.volume_id = 0;

	if (MakeFAT32)
		fill_fat32_bpb(wbpb);

	/*
	 * If all output goes to a simple file, call a routine to setup
	 * that scenario. Otherwise, try to find the device.
	 */
	if (Outputtofile)
		return (prepare_image_file(dn, wbpb));

	/* Collect info about device */
	fd = getdiskinfo(dn, &suffix);

	/*
	 * Sanity check.  If we've been provided a partition-specifying
	 * suffix, we shouldn't also have been told to ignore the
	 * fdisk table.
	 */
	if (DontUseFdisk && suffix) {
		(void) fprintf(stderr,
		    gettext("Using 'nofdisk' option precludes "
		    "appending logical drive\nspecifier "
		    "to the device name.\n"));
		goto err_out;
	}

	/*
	 * Find appropriate partition if we were requested to do so.
	 */
	if (suffix && !(seek_partn(fd, suffix, wbpb, seekto)))
		goto err_out;

	if (!suffix) {
		/*
		 * We have one of two possibilities.  Chances are we have
		 * a floppy drive.  But the user may be trying to format
		 * some weird drive that we don't know about and is supplying
		 * all the important values.  In that case, they should have set
		 * the 'nofdisk' flag.
		 *
		 * If 'nofdisk' isn't set, do a floppy-specific ioctl to
		 * get the remainder of our info. If the ioctl fails, we have
		 * a good idea that they aren't really on a floppy.  In that
		 * case, they should have given us a partition specifier.
		 */
		if (DontUseFdisk) {
			if (!(seek_nofdisk(fd, wbpb, seekto)))
				goto err_out;

			find_fixed_details(fd, wbpb);
		} else if (ioctl(fd, FDIOGCHAR, &fdchar) == -1) {
			/*
			 * It is possible that we are trying to use floppy
			 * specific FDIOGCHAR ioctl on USB floppy. Since sd
			 * driver, by which USB floppy is handled, doesn't
			 * support it, we can try to use disk DKIOCGGEOM ioctl
			 * to retrieve data we need. sd driver itself
			 * determines floppy disk by number of blocks
			 * (<=0x1000), then it sets geometry to 80 cylinders,
			 * 2 heads.
			 *
			 * Note that DKIOCGGEOM cannot supply us with type
			 * of media (e.g. 3.5" or 5.25"). We will set it to
			 * 3 (3.5") which is most probable value.
			 */
			if (errno == ENOTTY) {
				if (ioctl(fd, DKIOCGGEOM, &dg) != -1 &&
				    dg.dkg_ncyl == 80 && dg.dkg_nhead == 2) {
					fdchar.fdc_ncyl = dg.dkg_ncyl;
					fdchar.fdc_medium = 3;
					fdchar.fdc_secptrack = dg.dkg_nsect;
					fdchar.fdc_nhead = dg.dkg_nhead;
					lookup_floppy(&fdchar, wbpb);
				} else {
					partn_lecture(actualdisk);
					goto err_out;
				}
			}
		} else {
#ifdef sparc
			fdchar.fdc_medium = 3;
#endif
			lookup_floppy(&fdchar, wbpb);
		}
	} else {
		find_fixed_details(fd, wbpb);
	}

	return (fd);

err_out:
	(void) close(fd);
	exit(2);
}

/*
 * The following is a copy of MS-DOS 4.0 boot block.
 * It consists of the BIOS parameter block, and a disk
 * bootstrap program.
 *
 * The BIOS parameter block contains the right values
 * for the 3.5" high-density 1.44MB floppy format.
 *
 * This will be our default boot sector, if the user
 * didn't point us at a different one.
 *
 */
static
uchar_t DefBootSec[512] = {
	0xeb, 0x3c, 0x90, 	/* 8086 short jump + displacement + NOP */
	'M', 'S', 'D', 'O', 'S', '4', '.', '0',	/* OEM name & version */
	0x00, 0x02, 0x01, 0x01, 0x00,
	0x02, 0xe0, 0x00, 0x40, 0x0b,
	0xf0, 0x09, 0x00, 0x12, 0x00,
	0x02, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00,
	0x29, 0x00, 0x00, 0x00, 0x00,
	'N', 'O', 'N', 'A', 'M', 'E', ' ', ' ', ' ', ' ', ' ',
	'F', 'A', 'T', '1', '2', ' ', ' ', ' ',
	0xfa, 0x33,
	0xc0, 0x8e, 0xd0, 0xbc, 0x00, 0x7c, 0x16, 0x07,
	0xbb, 0x78, 0x00, 0x36, 0xc5, 0x37, 0x1e, 0x56,
	0x16, 0x53, 0xbf, 0x3e, 0x7c, 0xb9, 0x0b, 0x00,
	0xfc, 0xf3, 0xa4, 0x06, 0x1f, 0xc6, 0x45, 0xfe,
	0x0f, 0x8b, 0x0e, 0x18, 0x7c, 0x88, 0x4d, 0xf9,
	0x89, 0x47, 0x02, 0xc7, 0x07, 0x3e, 0x7c, 0xfb,
	0xcd, 0x13, 0x72, 0x7c, 0x33, 0xc0, 0x39, 0x06,
	0x13, 0x7c, 0x74, 0x08, 0x8b, 0x0e, 0x13, 0x7c,
	0x89, 0x0e, 0x20, 0x7c, 0xa0, 0x10, 0x7c, 0xf7,
	0x26, 0x16, 0x7c, 0x03, 0x06, 0x1c, 0x7c, 0x13,
	0x16, 0x1e, 0x7c, 0x03, 0x06, 0x0e, 0x7c, 0x83,
	0xd2, 0x00, 0xa3, 0x50, 0x7c, 0x89, 0x16, 0x52,
	0x7c, 0xa3, 0x49, 0x7c, 0x89, 0x16, 0x4b, 0x7c,
	0xb8, 0x20, 0x00, 0xf7, 0x26, 0x11, 0x7c, 0x8b,
	0x1e, 0x0b, 0x7c, 0x03, 0xc3, 0x48, 0xf7, 0xf3,
	0x01, 0x06, 0x49, 0x7c, 0x83, 0x16, 0x4b, 0x7c,
	0x00, 0xbb, 0x00, 0x05, 0x8b, 0x16, 0x52, 0x7c,
	0xa1, 0x50, 0x7c, 0xe8, 0x87, 0x00, 0x72, 0x20,
	0xb0, 0x01, 0xe8, 0xa1, 0x00, 0x72, 0x19, 0x8b,
	0xfb, 0xb9, 0x0b, 0x00, 0xbe, 0xdb, 0x7d, 0xf3,
	0xa6, 0x75, 0x0d, 0x8d, 0x7f, 0x20, 0xbe, 0xe6,
	0x7d, 0xb9, 0x0b, 0x00, 0xf3, 0xa6, 0x74, 0x18,
	0xbe, 0x93, 0x7d, 0xe8, 0x51, 0x00, 0x32, 0xe4,
	0xcd, 0x16, 0x5e, 0x1f, 0x8f, 0x04, 0x8f, 0x44,
	0x02, 0xcd, 0x19, 0x58, 0x58, 0x58, 0xeb, 0xe8,
	0xbb, 0x00, 0x07, 0xb9, 0x03, 0x00, 0xa1, 0x49,
	0x7c, 0x8b, 0x16, 0x4b, 0x7c, 0x50, 0x52, 0x51,
	0xe8, 0x3a, 0x00, 0x72, 0xe6, 0xb0, 0x01, 0xe8,
	0x54, 0x00, 0x59, 0x5a, 0x58, 0x72, 0xc9, 0x05,
	0x01, 0x00, 0x83, 0xd2, 0x00, 0x03, 0x1e, 0x0b,
	0x7c, 0xe2, 0xe2, 0x8a, 0x2e, 0x15, 0x7c, 0x8a,
	0x16, 0x24, 0x7c, 0x8b, 0x1e, 0x49, 0x7c, 0xa1,
	0x4b, 0x7c, 0xea, 0x00, 0x00, 0x70, 0x00, 0xac,
	0x0a, 0xc0, 0x74, 0x29, 0xb4, 0x0e, 0xbb, 0x07,
	0x00, 0xcd, 0x10, 0xeb, 0xf2, 0x3b, 0x16, 0x18,
	0x7c, 0x73, 0x19, 0xf7, 0x36, 0x18, 0x7c, 0xfe,
	0xc2, 0x88, 0x16, 0x4f, 0x7c, 0x33, 0xd2, 0xf7,
	0x36, 0x1a, 0x7c, 0x88, 0x16, 0x25, 0x7c, 0xa3,
	0x4d, 0x7c, 0xf8, 0xc3, 0xf9, 0xc3, 0xb4, 0x02,
	0x8b, 0x16, 0x4d, 0x7c, 0xb1, 0x06, 0xd2, 0xe6,
	0x0a, 0x36, 0x4f, 0x7c, 0x8b, 0xca, 0x86, 0xe9,
	0x8a, 0x16, 0x24, 0x7c, 0x8a, 0x36, 0x25, 0x7c,
	0xcd, 0x13, 0xc3, 0x0d, 0x0a, 0x4e, 0x6f, 0x6e,
	0x2d, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x20,
	0x64, 0x69, 0x73, 0x6b, 0x20, 0x6f, 0x72, 0x20,
	0x64, 0x69, 0x73, 0x6b, 0x20, 0x65, 0x72, 0x72,
	0x6f, 0x72, 0x0d, 0x0a, 0x52, 0x65, 0x70, 0x6c,
	0x61, 0x63, 0x65, 0x20, 0x61, 0x6e, 0x64, 0x20,
	0x70, 0x72, 0x65, 0x73, 0x73, 0x20, 0x61, 0x6e,
	0x79, 0x20, 0x6b, 0x65, 0x79, 0x20, 0x77, 0x68,
	0x65, 0x6e, 0x20, 0x72, 0x65, 0x61, 0x64, 0x79,
	0x0d, 0x0a, 0x00, 0x49, 0x4f, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x53, 0x59, 0x53, 0x4d, 0x53,
	0x44, 0x4f, 0x53, 0x20, 0x20, 0x20, 0x53, 0x59,
	0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0xaa
};

/*
 *  verify_bootblkfile
 *
 *	We were provided with the name of a file containing the bootblk
 *	to install.  Verify it has a valid boot sector as best we can. Any
 *	errors and we return a bad file descriptor.  Otherwise we fill up the
 *	provided buffer with the boot sector, return the file
 *	descriptor for later use and leave the file pointer just
 *	past the boot sector part of the boot block file.
 */
static
int
verify_bootblkfile(char *fn, boot_sector_t *bs, ulong_t *blkfilesize)
{
	struct stat fi;
	int bsfd = -1;

	if (stat(fn, &fi)) {
		perror(fn);
	} else if (fi.st_size < BPSEC) {
		(void) fprintf(stderr,
		    gettext("%s: Too short to be a boot sector.\n"), fn);
	} else if ((bsfd = open(fn, O_RDONLY)) < 0) {
		perror(fn);
	} else if (read(bsfd, bs->buf, BPSEC) < BPSEC) {
		(void) close(bsfd);
		bsfd = -1;
		perror(gettext("Boot block read"));
	} else {
		if ((bs->bs.bs_signature[0] != (BOOTSECSIG & 0xFF) &&
		    bs->bs.bs_signature[1] != ((BOOTSECSIG >> 8) & 0xFF)) ||
#ifdef i386
		    (bs->bs.bs_front.bs_jump_code[0] != OPCODE1 &&
		    bs->bs.bs_front.bs_jump_code[0] != OPCODE2)
#else
		    (bs->bs.bs_jump_code[0] != OPCODE1 &&
		    bs->bs.bs_jump_code[0] != OPCODE2)
#endif
		    /* CSTYLED */
		    ) {
			(void) close(bsfd);
			bsfd = -1;
			(void) fprintf(stderr,
			    gettext("Boot block (%s) bogus.\n"), fn);
		}
		*blkfilesize = fi.st_size;
	}
	return (bsfd);
}

/*
 *  verify_firstfile
 *
 *	We were provided with the name of a file to be the first file
 *	installed on the disk.  We just need to verify it exists and
 *	find out how big it is.  If it doesn't exist, we print a warning
 *	message about how the file wasn't found.  We don't exit fatally,
 *	though, rather we return a size of 0 and the FAT will be built
 *	without installing any first file.  They can then presumably
 *	install the correct first file by hand.
 */
static
int
verify_firstfile(char *fn, ulong_t *filesize)
{
	struct stat fi;
	int fd = -1;

	*filesize = 0;
	if (stat(fn, &fi) || (fd = open(fn, O_RDONLY)) < 0) {
		perror(fn);
		(void) fprintf(stderr,
		    gettext("Could not access requested file.  It will not\n"
		    "be installed in the new file system.\n"));
	} else {
		*filesize = fi.st_size;
	}

	return (fd);
}

/*
 *  label_volume
 *
 *	Fill in BPB with volume label.
 */
static
void
label_volume(char *lbl, bpb_t *wbpb)
{
	int ll, i;

	/* Put a volume label into our BPB. */
	if (!lbl)
		lbl = DEFAULT_LABEL;

	ll = min(11, (int)strlen(lbl));
	for (i = 0; i < ll; i++) {
		wbpb->ebpb.volume_label[i] = toupper(lbl[i]);
	}
	for (; i < 11; i++) {
		wbpb->ebpb.volume_label[i] = ' ';
	}
}

static
int
copy_bootblk(char *fn, boot_sector_t *bootsect, ulong_t *bootblksize)
{
	int bsfd = -1;

	if (Verbose && fn)
		(void) printf(gettext("Request to install boot "
		    "block file %s.\n"), fn);
	else if (Verbose)
		(void) printf(gettext("Request to install DOS boot block.\n"));

	/*
	 *  If they want to install their own boot block, sanity check
	 *  that block.
	 */
	if (fn) {
		bsfd = verify_bootblkfile(fn, bootsect, bootblksize);
		if (bsfd < 0) {
			exit(3);
		}
		*bootblksize = roundup(*bootblksize, BPSEC);
	} else {
		(void) memcpy(bootsect, DefBootSec, BPSEC);
		*bootblksize = BPSEC;
	}

	return (bsfd);
}

/*
 *  mark_cluster
 *
 *	This routine fills a FAT entry with the value supplied to it as an
 *	argument.  The fatp argument is assumed to be a pointer to the FAT's
 *	0th entry.  The clustnum is the cluster entry that should be updated.
 *	The value is the new value for the entry.
 */
static
void
mark_cluster(uchar_t *fatp, pc_cluster32_t clustnum, uint32_t value)
{
	uchar_t *ep;
	ulong_t idx;

	idx = (Fatentsize == 32) ? clustnum * 4 :
	    (Fatentsize == 16) ? clustnum * 2 : clustnum + clustnum/2;
	ep = fatp + idx;

	if (Fatentsize == 32) {
		store_32_bits(&ep, value);
	} else if (Fatentsize == 16) {
		store_16_bits(&ep, value);
	} else {
		if (clustnum & 1) {
			*ep = (*ep & 0x0f) | ((value << 4) & 0xf0);
			ep++;
			*ep = (value >> 4) & 0xff;
		} else {
			*ep++ = value & 0xff;
			*ep = (*ep & 0xf0) | ((value >> 8) & 0x0f);
		}
	}
}

static
uchar_t *
build_fat(bpb_t *wbpb, struct fat_od_fsi *fsinfop, ulong_t bootblksize,
    ulong_t *fatsize, char *ffn, int *fffd, ulong_t *ffsize,
    pc_cluster32_t *ffstartclust)
{
	pc_cluster32_t nextfree, ci;
	uchar_t *fatp;
	ushort_t numclust, numsect;
	int  remclust;

	/* Alloc space for a FAT and then null it out. */
	if (Verbose) {
		(void) printf(gettext("BUILD FAT.\n%d sectors per fat.\n"),
		    wbpb->bpb.sectors_per_fat ? wbpb->bpb.sectors_per_fat :
		    wbpb->bpb32.big_sectors_per_fat);
	}

	if (MakeFAT32) {
		*fatsize = BPSEC * wbpb->bpb32.big_sectors_per_fat;
	} else {
		*fatsize = BPSEC * wbpb->bpb.sectors_per_fat;
	}

	if (!(fatp = (uchar_t *)malloc(*fatsize))) {
		perror(gettext("FAT table alloc"));
		exit(4);
	} else {
		(void) memset(fatp, 0, *fatsize);
	}

	/* Build in-memory FAT */
	*fatp = wbpb->bpb.media;
	*(fatp + 1) = 0xFF;
	*(fatp + 2) = 0xFF;

	if (Fatentsize == 16) {
		*(fatp + 3) = 0xFF;
	} else if (Fatentsize == 32) {
		*(fatp + 3) = 0x0F;
		*(fatp + 4) = 0xFF;
		*(fatp + 5) = 0xFF;
		*(fatp + 6) = 0xFF;
		*(fatp + 7) = 0x0F;
	}

	/*
	 * Keep track of clusters used.
	 */
	remclust = TotalClusters;
	nextfree = 2;

	/*
	 * Get info on first file to install, if any.
	 */
	if (ffn)
		*fffd = verify_firstfile(ffn, ffsize);

	/*
	 * Compute number of clusters to preserve for bootblk overage.
	 * Remember that we already wrote the first sector of the boot block.
	 * These clusters are marked BAD to prevent them from being deleted
	 * or used.  The first available cluster is 2, so we always offset
	 * the clusters.
	 */
	numsect = idivceil((bootblksize - BPSEC), BPSEC);
	numclust = idivceil(numsect, wbpb->bpb.sectors_per_cluster);

	if (Verbose && numclust)
		(void) printf(gettext("Hiding %d excess bootblk cluster(s).\n"),
		    numclust);
	for (ci = 0; ci < numclust; ci++)
		mark_cluster(fatp, nextfree++,
		    MakeFAT32 ? PCF_BADCLUSTER32 : PCF_BADCLUSTER);
	remclust -= numclust;

	/*
	 * Reserve a cluster for the root directory on a FAT32.
	 */
	if (MakeFAT32) {
		mark_cluster(fatp, nextfree, PCF_LASTCLUSTER32);
		wbpb->bpb32.root_dir_clust = nextfree++;
		remclust--;
	}

	/*
	 * Compute and preserve number of clusters for first file.
	 */
	if (*fffd >= 0) {
		*ffstartclust = nextfree;
		numsect = idivceil(*ffsize, BPSEC);
		numclust = idivceil(numsect, wbpb->bpb.sectors_per_cluster);

		if (numclust > remclust) {
			(void) fprintf(stderr,
			    gettext("Requested first file too large to be\n"
			    "installed in the new file system.\n"));
			(void) close(*fffd);
			*fffd = -1;
			goto finish;
		}

		if (Verbose)
			(void) printf(gettext("Reserving %d first file "
			    "cluster(s).\n"), numclust);
		for (ci = 0; (int)ci < (int)(numclust-1); ci++, nextfree++)
			mark_cluster(fatp, nextfree, nextfree + 1);
		mark_cluster(fatp, nextfree++,
		    MakeFAT32 ? PCF_LASTCLUSTER32 : PCF_LASTCLUSTER);
		remclust -= numclust;
	}

finish:
	if (Verbose) {
		(void) printf(gettext("First sector of FAT"));
		header_for_dump();
		dump_bytes(fatp, BPSEC);
	}

	(void) memset(fsinfop, 0, sizeof (*fsinfop));
	fsinfop->fsi_leadsig = LE_32(FSI_LEADSIG);
	fsinfop->fsi_strucsig = LE_32(FSI_STRUCSIG);
	fsinfop->fsi_trailsig = LE_32(FSI_TRAILSIG);
	fsinfop->fsi_incore.fs_free_clusters = LE_32(remclust);
	fsinfop->fsi_incore.fs_next_free = LE_32(nextfree);
	return (fatp);
}

static
void
dirent_time_fill(struct pcdir *dep)
{
	struct  timeval tv;
	struct	tm	*tp;
	ushort_t	dostime;
	ushort_t	dosday;

	(void) gettimeofday(&tv, (struct timezone *)0);
	tp = localtime(&tv.tv_sec);
	/* get the time & day into DOS format */
	dostime = tp->tm_sec / 2;
	dostime |= tp->tm_min << 5;
	dostime |= tp->tm_hour << 11;
	dosday = tp->tm_mday;
	dosday |= (tp->tm_mon + 1) << 5;
	dosday |= (tp->tm_year - 80) << 9;
	dep->pcd_mtime.pct_time = htols(dostime);
	dep->pcd_mtime.pct_date = htols(dosday);
}

static
void
dirent_label_fill(struct pcdir *dep, char *fn)
{
	int nl, i;

	/*
	 * We spread the volume label across both the NAME and EXT fields
	 */
	nl = min(PCFNAMESIZE, strlen(fn));
	for (i = 0; i < nl; i++) {
		dep->pcd_filename[i] = toupper(fn[i]);
	}
	if (i < PCFNAMESIZE) {
		for (; i < PCFNAMESIZE; i++)
			dep->pcd_filename[i] = ' ';
		for (i = 0; i < PCFEXTSIZE; i++)
			dep->pcd_ext[i] = ' ';
		return;
	}
	nl = min(PCFEXTSIZE, strlen(fn) - PCFNAMESIZE);
	for (i = 0; i < nl; i++)
		dep->pcd_ext[i] = toupper(fn[i + PCFNAMESIZE]);
	if (i < PCFEXTSIZE) {
		for (; i < PCFEXTSIZE; i++)
			dep->pcd_ext[i] = ' ';
	}
}

static
void
dirent_fname_fill(struct pcdir *dep, char *fn)
{
	char *fname, *fext;
	int nl, i;

	if (fname = strrchr(fn, '/')) {
		fname++;
	} else {
		fname = fn;
	}

	if (fext = strrchr(fname, '.')) {
		fext++;
	} else {
		fext = "";
	}

	fname = strtok(fname, ".");

	nl = min(PCFNAMESIZE, (int)strlen(fname));
	for (i = 0; i < nl; i++) {
		dep->pcd_filename[i] = toupper(fname[i]);
	}
	for (; i < PCFNAMESIZE; i++) {
		dep->pcd_filename[i] = ' ';
	}

	nl = min(PCFEXTSIZE, (int)strlen(fext));
	for (i = 0; i < nl; i++) {
		dep->pcd_ext[i] = toupper(fext[i]);
	}
	for (; i < PCFEXTSIZE; i++) {
		dep->pcd_ext[i] = ' ';
	}
}

static
uchar_t *
build_rootdir(bpb_t *wbpb, char *ffn, int fffd,
    ulong_t ffsize, pc_cluster32_t ffstart, ulong_t *rdirsize)
{
	struct pcdir *rootdirp;
	struct pcdir *entry;

	/*
	 * Build a root directory.  It will have at least one entry,
	 * the volume label and a second if the first file was defined.
	 */
	if (MakeFAT32) {
		/*
		 * We devote an entire cluster to the root
		 * directory on FAT32.
		 */
		*rdirsize = wbpb->bpb.sectors_per_cluster * BPSEC;
	} else {
		*rdirsize = wbpb->bpb.num_root_entries * sizeof (struct pcdir);
	}
	if ((rootdirp = (struct pcdir *)malloc(*rdirsize)) == NULL) {
		perror(gettext("Root directory allocation"));
		exit(4);
	} else {
		entry = rootdirp;
		(void) memset((char *)rootdirp, 0, *rdirsize);
	}

	/* Create directory entry for first file, if there is one */
	if (fffd >= 0) {
		dirent_fname_fill(entry, ffn);
		entry->pcd_attr = Firstfileattr;
		dirent_time_fill(entry);
		entry->pcd_scluster_lo = htols(ffstart);
		if (MakeFAT32) {
			ffstart = ffstart >> 16;
			entry->un.pcd_scluster_hi = htols(ffstart);
		}
		entry->pcd_size = htoli(ffsize);
		entry++;
	}

	/* Create directory entry for volume label, if there is one */
	if (Label != NULL) {
		dirent_label_fill(entry, Label);
		entry->pcd_attr = PCA_ARCH | PCA_LABEL;
		dirent_time_fill(entry);
		entry->pcd_scluster_lo = 0;
		if (MakeFAT32) {
			entry->un.pcd_scluster_hi = 0;
		}
		entry->pcd_size = 0;
		entry++;
	}

	if (Verbose) {
		(void) printf(gettext("First two directory entries"));
		header_for_dump();
		dump_bytes((uchar_t *)rootdirp, 2 * sizeof (struct pcdir));
	}

	return ((uchar_t *)rootdirp);
}

/*
 * write_rest
 *
 *	Write all the bytes from the current file pointer to end of file
 *	in the source file out to the destination file.  The writes should
 *	be padded to whole clusters with 0's if necessary.
 */
static
void
write_rest(bpb_t *wbpb, char *efn, int dfd, int sfd, int remaining)
{
	char buf[BPSEC];
	ushort_t numsect, numclust;
	ushort_t wnumsect, s;
	int doneread = 0;
	int rstat;

	/*
	 * Compute number of clusters required to contain remaining bytes.
	 */
	numsect = idivceil(remaining, BPSEC);
	numclust = idivceil(numsect, wbpb->bpb.sectors_per_cluster);

	wnumsect = numclust * wbpb->bpb.sectors_per_cluster;
	for (s = 0; s < wnumsect; s++) {
		if (!doneread) {
			if ((rstat = read(sfd, buf, BPSEC)) < 0) {
				perror(efn);
				doneread = 1;
				rstat = 0;
			} else if (rstat == 0) {
				doneread = 1;
			}
			(void) memset(&(buf[rstat]), 0, BPSEC - rstat);
		}
		if (write(dfd, buf, BPSEC) != BPSEC) {
			(void) fprintf(stderr, gettext("Copying "));
			perror(efn);
		}
	}
}

static
void
write_fat32_bootstuff(int fd, boot_sector_t *bsp,
    struct fat_od_fsi *fsinfop, off64_t seekto)
{
	if (Verbose) {
		(void) printf(gettext("Dump of the fs info sector"));
		header_for_dump();
		dump_bytes((uchar_t *)fsinfop, sizeof (*fsinfop));
	}

	if (!Notreally) {
		/*
		 * FAT32's have an FS info sector, then a backup of the boot
		 * sector, and a modified backup of the FS Info sector.
		 */
		if (write(fd, fsinfop, sizeof (*fsinfop)) != BPSEC) {
			perror(gettext("FS info sector write"));
			exit(4);
		}
		if (lseek64(fd,	seekto + BKUP_BOOTSECT_OFFSET, SEEK_SET) < 0) {
			(void) close(fd);
			perror(gettext("Boot sector backup seek"));
			exit(4);
		}
		if (write(fd, bsp->buf, sizeof (bsp->buf)) != BPSEC) {
			perror(gettext("Boot sector backup write"));
			exit(4);
		}
	}

	/*
	 * Second copy of fs info sector is modified to have "don't know"
	 * as the number of free clusters
	 */
	fsinfop->fsi_incore.fs_next_free = LE_32(FSINFO_UNKNOWN);

	if (Verbose) {
		(void) printf(gettext("Dump of the backup fs info sector"));
		header_for_dump();
		dump_bytes((uchar_t *)fsinfop, sizeof (*fsinfop));
	}

	if (!Notreally) {
		if (write(fd, fsinfop, sizeof (*fsinfop)) != BPSEC) {
			perror(gettext("FS info sector backup write"));
			exit(4);
		}
	}
}

static
void
write_bootsects(int fd, boot_sector_t *bsp, bpb_t *wbpb,
    struct fat_od_fsi *fsinfop, off64_t seekto)
{
	if (MakeFAT32) {
		/* Copy our BPB into bootsec structure */
#ifdef i386
		(void) memcpy(&(bsp->bs32.bs_front.bs_bpb), &(wbpb->bpb),
		    sizeof (wbpb->bpb));
		(void) memcpy(&(bsp->bs32.bs_bpb32), &(wbpb->bpb32),
		    sizeof (wbpb->bpb32));
		(void) memcpy(&(bsp->bs32.bs_ebpb), &(wbpb->ebpb),
		    sizeof (wbpb->ebpb));
#else
		swap_pack_bpb32cpy(&(bsp->bs32), wbpb);
#endif
	} else {
		/* Copy our BPB into bootsec structure */
#ifdef i386
		(void) memcpy(&(bsp->bs.bs_front.bs_bpb), &(wbpb->bpb),
		    sizeof (wbpb->bpb));
		(void) memcpy(&(bsp->bs.bs_ebpb), &(wbpb->ebpb),
		    sizeof (wbpb->ebpb));
#else
		swap_pack_bpbcpy(&(bsp->bs), wbpb);
#endif

		/* Copy SUN BPB extensions into bootsec structure */
		if (SunBPBfields) {
#ifdef i386
			(void) memcpy(&(bsp->bs.bs_sebpb), &(wbpb->sunbpb),
			    sizeof (wbpb->sunbpb));
#else
			swap_pack_sebpbcpy(&(bsp->bs), wbpb);
#endif
		}
	}

	/* Write boot sector */
	if (!Notreally && write(fd, bsp->buf, sizeof (bsp->buf)) != BPSEC) {
		perror(gettext("Boot sector write"));
		exit(4);
	}

	if (Verbose) {
		(void) printf(gettext("Dump of the boot sector"));
		header_for_dump();
		dump_bytes(bsp->buf, sizeof (bsp->buf));
	}

	if (MakeFAT32)
		write_fat32_bootstuff(fd, bsp, fsinfop, seekto);
}

static
void
write_fat(int fd, off64_t seekto, char *fn, char *lbl, char *ffn, bpb_t *wbpb)
{
	struct fat_od_fsi fsinfo;
	pc_cluster32_t ffsc;
	boot_sector_t bootsect;
	uchar_t *fatp, *rdirp;
	ulong_t bootblksize, fatsize, rdirsize, ffsize;
	int bsfd = -1;
	int fffd = -1;

	compute_file_area_size(wbpb);

	bsfd = copy_bootblk(fn, &bootsect, &bootblksize);
	label_volume(lbl, wbpb);

	if (Verbose)
		(void) printf(gettext("Building FAT.\n"));
	fatp = build_fat(wbpb, &fsinfo, bootblksize, &fatsize,
	    ffn, &fffd, &ffsize, &ffsc);

	write_bootsects(fd, &bootsect, wbpb, &fsinfo, seekto);

	if (lseek64(fd,
	    seekto + (BPSEC * wbpb->bpb.resv_sectors), SEEK_SET) < 0) {
		(void) close(fd);
		perror(gettext("Seek to end of reserved sectors"));
		exit(4);
	}

	/* Write FAT */
	if (Verbose)
		(void) printf(gettext("Writing FAT(s). %d bytes times %d.\n"),
		    fatsize, wbpb->bpb.num_fats);
	if (!Notreally) {
		int nf, wb;
		for (nf = 0; nf < (int)wbpb->bpb.num_fats; nf++)
			if ((wb = write(fd, fatp, fatsize)) != fatsize) {
				perror(gettext("FAT write"));
				exit(4);
			} else {
				if (Verbose)
					(void) printf(
					    gettext("Wrote %d bytes\n"), wb);
			}
	}
	free(fatp);

	if (Verbose)
		(void) printf(gettext("Building root directory.\n"));
	rdirp = build_rootdir(wbpb, ffn, fffd, ffsize, ffsc, &rdirsize);

	/*
	 *  In non FAT32, root directory exists outside of the file area
	 */
	if (!MakeFAT32) {
		if (Verbose)
			(void) printf(gettext("Writing root directory. "
			    "%d bytes.\n"), rdirsize);
		if (!Notreally) {
			if (write(fd, rdirp, rdirsize) != rdirsize) {
				perror(gettext("Root directory write"));
				exit(4);
			}
		}
		free(rdirp);
	}

	/*
	 * Now write anything that needs to be in the file space.
	 */
	if (bootblksize > BPSEC) {
		if (Verbose)
			(void) printf(gettext("Writing remainder of "
			    "boot block.\n"));
		if (!Notreally)
			write_rest(wbpb, fn, fd, bsfd, bootblksize - BPSEC);
	}

	if (MakeFAT32) {
		if (Verbose)
			(void) printf(gettext("Writing root directory. "
			    "%d bytes.\n"), rdirsize);
		if (!Notreally) {
			if (write(fd, rdirp, rdirsize) != rdirsize) {
				perror(gettext("Root directory write"));
				exit(4);
			}
		}
		free(rdirp);
	}

	if (fffd >= 0) {
		if (Verbose)
			(void) printf(gettext("Writing first file.\n"));
		if (!Notreally)
			write_rest(wbpb, ffn, fd, fffd, ffsize);
	}
}

static
char *LegalOpts[] = {
#define	NFLAG 0
	"N",
#define	VFLAG 1
	"v",
#define	RFLAG 2
	"r",
#define	HFLAG 3
	"h",
#define	SFLAG 4
	"s",
#define	SUNFLAG 5
	"S",
#define	LABFLAG 6
	"b",
#define	BTRFLAG 7
	"B",
#define	INITFLAG 8
	"i",
#define	SZFLAG 9
	"size",
#define	SECTFLAG 10
	"nsect",
#define	TRKFLAG 11
	"ntrack",
#define	SPCFLAG 12
	"spc",
#define	BPFFLAG 13
	"fat",
#define	FFLAG 14
	"f",
#define	DFLAG 15
	"d",
#define	NOFDISKFLAG 16
	"nofdisk",
#define	RESRVFLAG 17
	"reserve",
#define	HIDDENFLAG 18
	"hidden",
	NULL
};

static
void
bad_arg(char *option)
{
	(void) fprintf(stderr,
	    gettext("Unrecognized option %s.\n"), option);
	usage();
	exit(2);
}

static
void
missing_arg(char *option)
{
	(void) fprintf(stderr,
	    gettext("Option %s requires a value.\n"), option);
	usage();
	exit(3);
}

static
void
parse_suboptions(char *optsstr)
{
	char *value;
	int c;

	while (*optsstr != '\0') {
		switch (c = getsubopt(&optsstr, LegalOpts, &value)) {
		case NFLAG:
			Notreally++;
			break;
		case VFLAG:
			Verbose++;
			break;
		case RFLAG:
			Firstfileattr |= 0x01;
			break;
		case HFLAG:
			Firstfileattr |= 0x02;
			break;
		case SFLAG:
			Firstfileattr |= 0x04;
			break;
		case SUNFLAG:
			SunBPBfields = 1;
			break;
		case LABFLAG:
			if (value == NULL) {
				missing_arg(LegalOpts[c]);
			} else {
				Label = value;
			}
			break;
		case BTRFLAG:
			if (value == NULL) {
				missing_arg(LegalOpts[c]);
			} else {
				BootBlkFn = value;
			}
			break;
		case INITFLAG:
			if (value == NULL) {
				missing_arg(LegalOpts[c]);
			} else {
				FirstFn = value;
			}
			break;
		case SZFLAG:
			if (value == NULL) {
				missing_arg(LegalOpts[c]);
			} else {
				TotSize = atoi(value);
				GetSize = 0;
			}
			break;
		case SECTFLAG:
			if (value == NULL) {
				missing_arg(LegalOpts[c]);
			} else {
				SecPerTrk = atoi(value);
				GetSPT = 0;
			}
			break;
		case TRKFLAG:
			if (value == NULL) {
				missing_arg(LegalOpts[c]);
			} else {
				TrkPerCyl = atoi(value);
				GetTPC = 0;
			}
			break;
		case SPCFLAG:
			if (value == NULL) {
				missing_arg(LegalOpts[c]);
			} else {
				SecPerClust = atoi(value);
				GetSPC = 0;
			}
			break;
		case BPFFLAG:
			if (value == NULL) {
				missing_arg(LegalOpts[c]);
			} else {
				BitsPerFAT = atoi(value);
				GetBPF = 0;
			}
			break;
		case NOFDISKFLAG:
			DontUseFdisk = 1;
			break;
		case RESRVFLAG:
			if (value == NULL) {
				missing_arg(LegalOpts[c]);
			} else {
				Resrvd = atoi(value);
				GetResrvd = 0;
			}
			break;
		case HIDDENFLAG:
			if (value == NULL) {
				missing_arg(LegalOpts[c]);
			} else {
				RelOffset = atoi(value);
				GetOffset = 0;
			}
			break;
		case FFLAG:
			if (value == NULL) {
				missing_arg(LegalOpts[c]);
			} else {
				DiskName = value;
				Outputtofile = 1;
			}
			break;
		case DFLAG:
			if (value == NULL) {
				missing_arg(LegalOpts[c]);
			} else {
				Imagesize = atoi(value);
			}
			break;
		default:
			bad_arg(value);
			break;
		}
	}
}

static
void
sanity_check_options(int argc, int optind)
{
	if (GetFsParams) {
		if (argc - optind != 1)
			usage();
		return;
	}

	if (DontUseFdisk && GetOffset) {
		/* Set default relative offset of zero */
		RelOffset = 0;
	}

	if (BitsPerFAT == 32)
		MakeFAT32 = 1;

	if (Outputtofile && (argc - optind)) {
		usage();
	} else if (Outputtofile && !DiskName) {
		usage();
	} else if (!Outputtofile && (argc - optind != 1)) {
		usage();
	} else if (SunBPBfields && !BootBlkFn) {
		(void) fprintf(stderr,
		    gettext("Use of the 'S' option requires that\n"
		    "the 'B=' option also be used.\n\n"));
		usage();
	} else if (Firstfileattr != 0x20 && !FirstFn) {
		(void) fprintf(stderr,
		    gettext("Use of the 'r', 'h', or 's' options requires\n"
		    "that the 'i=' option also be used.\n\n"));
		usage();
	} else if (!GetOffset && !DontUseFdisk) {
		(void) fprintf(stderr,
		    gettext("Use of the 'hidden' option requires that\n"
		    "the 'nofdisk' option also be used.\n\n"));
		usage();
	} else if (DontUseFdisk && GetSize) {
		(void) fprintf(stderr,
		    gettext("Use of the 'nofdisk' option requires that\n"
		    "the 'size=' option also be used.\n\n"));
		usage();
	} else if (!GetBPF &&
	    BitsPerFAT != 12 && BitsPerFAT != 16 && BitsPerFAT != 32) {
		(void) fprintf(stderr, gettext("Invalid Bits/Fat value."
		    " Must be 12, 16 or 32.\n"));
		exit(2);
	} else if (!GetSPC && !(ISP2(SecPerClust) &&
	    IN_RANGE(SecPerClust, 1, 128))) {
		(void) fprintf(stderr,
		    gettext("Invalid Sectors/Cluster value.  Must be a "
		    "power of 2 between 1 and 128.\n"));
		exit(2);
	} else if (!GetResrvd && (Resrvd < 1 || Resrvd > 0xffff)) {
		(void) fprintf(stderr,
		    gettext("Invalid number of reserved sectors.  "
		    "Must be at least 1 but\nno larger than 65535."));
		exit(2);
	} else if (!GetResrvd && MakeFAT32 &&
	    (Resrvd < 32 || Resrvd > 0xffff)) {
		(void) fprintf(stderr,
		    gettext("Invalid number of reserved sectors.  "
		    "Must be at least 32 but\nno larger than 65535."));
		exit(2);
	} else if (Imagesize != 3 && Imagesize != 5) {
		usage();
	}
}

int
main(int argc, char **argv)
{
	off64_t AbsBootSect = 0;
	bpb_t dskparamblk;
	char *string;
	int  fd;
	int  c;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "F:Vmo:")) != EOF) {
		switch (c) {
		case 'F':
			string = optarg;
			if (strcmp(string, "pcfs") != 0)
				usage();
			break;
		case 'V':
			{
				char	*opt_text;
				int	opt_count;

				(void) fprintf(stdout,
				    gettext("mkfs -F pcfs "));
				for (opt_count = 1; opt_count < argc;
				    opt_count++) {
					opt_text = argv[opt_count];
					if (opt_text)
						(void) fprintf(stdout,
						    " %s ", opt_text);
				}
				(void) fprintf(stdout, "\n");
			}
			break;
		case 'm':
			GetFsParams++;
			break;
		case 'o':
			string = optarg;
			parse_suboptions(string);
			break;
		}
	}

	sanity_check_options(argc, optind);

	if (!Outputtofile)
		DiskName = argv[optind];

	(void) memset(&dskparamblk, 0, sizeof (dskparamblk));

	if (GetFsParams) {
		fd = open_and_examine(DiskName, &dskparamblk);
	} else {
		fd = open_and_seek(DiskName, &dskparamblk, &AbsBootSect);
		if (ask_nicely(DiskName))
			write_fat(fd, AbsBootSect, BootBlkFn, Label,
			    FirstFn, &dskparamblk);
	}
	(void) close(fd);
	return (0);
}
