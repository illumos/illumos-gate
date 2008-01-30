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
 */

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved	*/

/*	Copyright (c) 1987, 1988 Microsoft Corporation	*/
/*	  All Rights Reserved	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * PROGRAM: fdisk(1M)
 * This program reads the partition table on the specified device and
 * also reads the drive parameters. The user can perform various
 * operations from a supplied menu or from the command line. Diagnostic
 * options are also available.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/systeminfo.h>
#include <sys/efi_partition.h>
#include <sys/byteorder.h>
#include <sys/systeminfo.h>

#include <sys/dktp/fdisk.h>
#include <sys/dkio.h>
#include <sys/vtoc.h>

#define	CLR_SCR "[1;1H[0J"
#define	CLR_LIN "[0K"
#define	HOME "[1;1H[0K[2;1H[0K[3;1H[0K[4;1H[0K[5;1H[0K" \
	"[6;1H[0K[7;1H[0K[8;1H[0K[9;1H[0K[10;1H[0K[1;1H"
#define	Q_LINE "[22;1H[0K[21;1H[0K[20;1H[0K"
#define	W_LINE "[12;1H[0K[11;1H[0K"
#define	E_LINE "[24;1H[0K[23;1H[0K"
#define	M_LINE "[13;1H[0K[14;1H[0K[15;1H[0K[16;1H[0K[17;1H" \
	"[0K[18;1H[0K[19;1H[0K[13;1H"
#define	T_LINE "[1;1H[0K"

#define	DEFAULT_PATH	"/dev/rdsk/"

/* XXX - should be in fdisk.h, used by sd as well */

/*
 * the MAX values are the maximum usable values for BIOS chs values
 * The MAX_CYL value of 1022 is the maximum usable value
 *   the value of 1023 is a fence value,
 *   indicating no CHS geometry exists for the corresponding LBA value.
 * HEAD range [ 0 .. MAX_HEAD ], so number of heads is (MAX_HEAD + 1)
 * SECT range [ 1 .. MAX_SECT ], so number of sectors is (MAX_SECT)
 */
#define	MAX_SECT	(63)
#define	MAX_CYL		(1022)
#define	MAX_HEAD	(254)

/* for clear_vtoc() */
#define	OLD		0
#define	NEW		1

/* readvtoc/writevtoc return codes */
#define	VTOC_OK		0	/* Good VTOC */
#define	VTOC_INVAL	1	/* invalid VTOC */
#define	VTOC_NOTSUP	2	/* operation not supported - EFI label */
#define	VTOC_RWERR	3	/* couldn't read or write VTOC */

/*
 * Support for fdisk(1M) on the SPARC platform
 *	In order to convert little endian values to big endian for SPARC,
 *	byte/short and long values must be swapped.
 *	These swapping macros will be used to access information in the
 *	mboot and ipart structures.
 */

#ifdef sparc
#define	les(val)	((((val)&0xFF)<<8)|(((val)>>8)&0xFF))
#define	lel(val)	(((unsigned)(les((val)&0x0000FFFF))<<16) | \
			    (les((unsigned)((val)&0xffff0000)>>16)))
#else
#define	les(val)	(val)
#define	lel(val)	(val)
#endif

#if defined(_SUNOS_VTOC_16)
#define	VTOC_OFFSET	512
#elif defined(_SUNOS_VTOC_8)
#define	VTOC_OFFSET	0
#else
#error No VTOC format defined.
#endif

static char Usage[] = "Usage: fdisk\n"
"[ -A id:act:bhead:bsect:bcyl:ehead:esect:ecyl:rsect:numsect ]\n"
"[ -b masterboot ]\n"
"[ -D id:act:bhead:bsect:bcyl:ehead:esect:ecyl:rsect:numsect ]\n"
"[ -F fdisk_file ] [ -h ] [ -o offset ] [ -P fill_patt ] [ -s size ]\n"
"[ -S geom_file ] [ [ -v ] -W { creat_fdisk_file | - } ]\n"
"[ -w | r | d | n | I | B | E | g | G | R | t | T ] rdevice";

static char Usage1[] = "    Partition options:\n"
"	-A id:act:bhead:bsect:bcyl:ehead:esect:ecyl:rsect:numsect\n"
"		Create a partition with specific attributes:\n"
"		id      = system id number (fdisk.h) for the partition type\n"
"		act     = active partition flag (0 is off and 128 is on)\n"
"		bhead   = beginning head for start of partition\n"
"		bsect   = beginning sector for start of partition\n"
"		bcyl    = beginning cylinder for start of partition\n"
"		ehead   = ending head for end of partition\n"
"		esect   = ending sector for end of partition\n"
"		ecyl    = ending cylinder for end of partition\n"
"		rsect   = sector number from start of disk for\n"
"			  start of partition\n"
"		numsect = partition size in sectors\n"
"	-b master_boot\n"
"		Use master_boot as the master boot file.\n"
"	-B	Create one Solaris partition that uses the entire disk.\n"
"	-E	Create one EFI partition that uses the entire disk.\n"
"	-D id:act:bhead:bsect:bcyl:ehead:esect:ecyl:rsect:numsect\n"
"		Delete a partition. See attribute definitions for -A.\n"
"	-F fdisk_file\n"
"		Use fdisk_file to initialize on-line fdisk table.\n"
"	-I	Forego device checks. Generate a file image of what would go\n"
"		on a disk using the geometry specified with the -S option.\n"
"	-n	Do not run in interactive mode.\n"
"	-R	Open the disk device as read-only.\n"
"	-t	Check and adjust VTOC to be consistent with fdisk table.\n"
"		VTOC slices exceeding the partition size will be truncated.\n"
"	-T	Check and adjust VTOC to be consistent with fdisk table.\n"
"		VTOC slices exceeding the partition size will be removed.\n"
"	-W fdisk_file\n"
"		Write on-disk table to fdisk_file.\n"
"	-W -	Write on-disk table to standard output.\n"
"	-v	Display virtual geometry. Must be used with the -W option.\n"
"    Diagnostic options:\n"
"	-d	Activate debug information about progress.\n"
"	-g	Write label geometry to standard output:\n"
"		PCYL		number of physical cylinders\n"
"		NCYL		number of usable cylinders\n"
"		ACYL		number of alternate cylinders\n"
"		BCYL		cylinder offset\n"
"		NHEADS		number of heads\n"
"		NSECTORS	number of sectors per track\n"
"		SECTSIZ		size of a sector in bytes\n"
"	-G	Write physical geometry to standard output (see -g).\n"
"	-h	Issue this verbose help message.\n"
"	-o offset\n"
"		Block offset from start of disk (default 0). Ignored if\n"
"		-P # specified.\n"
"	-P fill_patt\n"
"		Fill disk with pattern fill_patt. fill_patt can be decimal or\n"
"		hexadecimal and is used as number for constant long word\n"
"		pattern. If fill_patt is \"#\" then pattern of block #\n"
"		for each block. Pattern is put in each block as long words\n"
"		and fills each block (see -o and -s).\n"
"	-r	Read from a disk to stdout (see -o and -s).\n"
"	-s size	Number of blocks on which to perform operation (see -o).\n"
"	-S geom_file\n"
"		Use geom_file to set the label geometry (see -g).\n"
"	-w	Write to a disk from stdin (see -o and -s).";

static char Ostr[] = "Other OS";
static char Dstr[] = "DOS12";
static char D16str[] = "DOS16";
static char DDstr[] = "DOS-DATA";
static char EDstr[] = "EXT-DOS";
static char DBstr[] = "DOS-BIG";
static char PCstr[] = "PCIX";
static char Ustr[] = "UNIX System";
static char SUstr[] = "Solaris";
static char SU2str[] = "Solaris2";
static char X86str[] = "x86 Boot";
static char DIAGstr[] = "Diagnostic";
static char IFSstr[] = "IFS: NTFS";
static char AIXstr[] = "AIX Boot";
static char AIXDstr[] = "AIX Data";
static char OS2str[] = "OS/2 Boot";
static char WINstr[] = "Win95 FAT32";
static char EWINstr[] = "Ext Win95";
static char FAT95str[] = "FAT16 LBA";
static char EXTLstr[] = "EXT LBA";
static char LINUXstr[] = "Linux";
static char CPMstr[] = "CP/M";
static char NOVstr[] = "Netware 3.x+";
static char QNXstr[] = "QNX 4.x";
static char QNX2str[] = "QNX part 2";
static char QNX3str[] = "QNX part 3";
static char LINNATstr[] = "Linux native";
static char NTFSVOL1str[] = "NT volset 1";
static char NTFSVOL2str[] = "NT volset 2";
static char BSDstr[] = "BSD OS";
static char NEXTSTEPstr[] = "NeXTSTEP";
static char BSDIFSstr[] = "BSDI FS";
static char BSDISWAPstr[] = "BSDI swap";
static char Actvstr[] = "Active";
static char EFIstr[] = "EFI";
static char NAstr[] = "      ";

/* All the user options and flags */
static char *Dfltdev;			/* name of fixed disk drive */

/* Diagnostic options */
static int	io_wrt = 0;		/* write stdin to disk (-w) */
static int	io_rd = 0;		/* read disk and write stdout (-r) */
static char	*io_fatt;		/* user supplied pattern (-P pattern) */
static int	io_patt = 0;		/* write pattern to disk (-P pattern) */
static int	io_lgeom = 0;		/* get label geometry (-g) */
static int	io_pgeom = 0;		/* get drive physical geometry (-G) */
static char	*io_sgeom = 0;		/* set label geometry (-S geom_file) */
static int	io_readonly = 0;	/* do not write to disk (-R) */

/* The -o offset and -s size options specify the area of the disk on */
/* which to perform the particular operation; i.e., -P, -r, or -w. */
static int	io_offset = 0;		/* offset sector (-o offset) */
static int	io_size = 0;		/* size in sectors (-s size) */

/* Partition table flags */
static int	v_flag = 0;		/* virtual geometry-HBA flag (-v) */
static int 	stdo_flag = 0;		/* stdout flag (-W -) */
static int	io_fdisk = 0;		/* do fdisk operation */
static int	io_ifdisk = 0;		/* interactive partition */
static int	io_nifdisk = 0;		/* non-interactive partition (-n) */

static int	io_adjt = 0;		/* check/adjust VTOC (truncate (-t)) */
static int	io_ADJT = 0;		/* check/adjust VTOC (delete (-T)) */
static char	*io_ffdisk = 0;		/* input fdisk file name (-F file) */
static char	*io_Wfdisk = 0;		/* output fdisk file name (-W file) */
static char	*io_Afdisk = 0;		/* add entry to partition table (-A) */
static char	*io_Dfdisk = 0;		/* delete entry from part. table (-D) */

static char	*io_mboot = 0;		/* master boot record (-b boot_file) */

static struct mboot BootCod;		/* buffer for master boot record */

static int	io_wholedisk = 0;	/* use whole disk for Solaris (-B) */
static int	io_EFIdisk = 0;		/* use whole disk for EFI (-E) */
static int	io_debug = 0;		/* activate verbose mode (-d) */
static int	io_image = 0;		/* create image using geometry (-I) */

static struct mboot *Bootblk;		/* pointer to cut/paste sector zero */
static char	*Bootsect;		/* pointer to sector zero buffer */
static char	*Nullsect;
static struct vtoc	disk_vtoc;	/* verify VTOC table */
static int	vt_inval = 0;
static int	no_virtgeom_ioctl = 0;	/* ioctl for virtual geometry failed */
static int	no_physgeom_ioctl = 0;	/* ioctl for physical geometry failed */

static struct ipart	Table[FD_NUMPART];
static struct ipart	Old_Table[FD_NUMPART];

/* Disk geometry information */
static struct dk_minfo	minfo;
static struct dk_geom	disk_geom;

static diskaddr_t	dev_capacity;	/* number of blocks on device */
static diskaddr_t	chs_capacity;	/* Numcyl * heads * sectors */

static int Dev;			/* fd for open device */
/* Physical geometry for the drive */
static int	Numcyl;			/* number of cylinders */
static int	heads;			/* number of heads */
static int	sectors;		/* number of sectors per track */
static int	acyl;			/* number of alternate sectors */

/* HBA (virtual) geometry for the drive */
static int	hba_Numcyl;		/* number of cylinders */
static int	hba_heads;		/* number of heads */
static int	hba_sectors;		/* number of sectors per track */

static int	sectsiz;		/* sector size */

/* Load functions for fdisk table modification */
#define	LOADFILE	0	/* load fdisk from file */
#define	LOADDEL		1	/* delete an fdisk entry */
#define	LOADADD		2	/* add an fdisk entry */

#define	CBUFLEN 80
static char s[CBUFLEN];

static void update_disk_and_exit(boolean_t table_changed);
int main(int argc, char *argv[]);
static int read_geom(char *sgeom);
static void dev_mboot_read(void);
static void dev_mboot_write(int sect, char *buff, int bootsiz);
static void mboot_read(void);
static void fill_patt(void);
static void abs_read(void);
static void abs_write(void);
static void load(int funct, char *file);
static void Set_Table_CHS_Values(int ti);
static int insert_tbl(int id, int act,
    int bhead, int bsect, int bcyl,
    int ehead, int esect, int ecyl,
    int rsect, int numsect);
static int verify_tbl(void);
static int pars_fdisk(char *line,
    int *id, int *act,
    int *bhead, int *bsect, int *bcyl,
    int *ehead, int *esect, int *ecyl,
    int *rsect, int *numsect);
static int validate_part(int id, int rsect, int numsect);
static void stage0(void);
static int pcreate(void);
static int specify(uchar_t tsystid);
static void dispmenu(void);
static int pchange(void);
static int ppartid(void);
static char pdelete(void);
static void rm_blanks(char *s);
static int getcyl(void);
static void disptbl(void);
static void print_Table(void);
static void copy_Table_to_Old_Table(void);
static void nulltbl(void);
static void copy_Bootblk_to_Table(void);
static void fill_ipart(char *bootptr, struct ipart *partp);
#ifdef sparc
uchar_t getbyte(char **bp);
uint32_t getlong(char **bp);
#endif
static void copy_Table_to_Bootblk(void);
static int TableChanged(void);
static void ffile_write(char *file);
static void fix_slice(void);
static int yesno(void);
static int readvtoc(void);
static int writevtoc(void);
static int efi_ioctl(int fd, int cmd, dk_efi_t *dk_ioc);
static int clear_efi(void);
static void clear_vtoc(int table, int part);
static int lecture_and_query(char *warning, char *devname);
static void sanity_check_provided_device(char *devname, int fd);
static char *get_node(char *devname);

static void
update_disk_and_exit(boolean_t table_changed)
{
	if (table_changed) {
		/*
		 * Copy the new table back to the sector buffer
		 * and write it to disk
		 */
		copy_Table_to_Bootblk();
		dev_mboot_write(0, Bootsect, sectsiz);
	}

	/* If the VTOC table is wrong fix it (truncation only) */
	if (io_adjt)
		fix_slice();

	exit(0);
}



/*
 * main
 * Process command-line options.
 */
int
main(int argc, char *argv[])
{
	int c, i;
	extern	int optind;
	extern	char *optarg;
	int	errflg = 0;
	int	diag_cnt = 0;
	int openmode;

	setbuf(stderr, 0);	/* so all output gets out on exit */
	setbuf(stdout, 0);

	/* Process the options. */
	while ((c = getopt(argc, argv, "o:s:P:F:b:A:D:W:S:tTIhwvrndgGRBE"))
	    != EOF) {
		switch (c) {

			case 'o':
				io_offset = strtoul(optarg, 0, 0);
				continue;
			case 's':
				io_size = strtoul(optarg, 0, 0);
				continue;
			case 'P':
				diag_cnt++;
				io_patt++;
				io_fatt = optarg;
				continue;
			case 'w':
				diag_cnt++;
				io_wrt++;
				continue;
			case 'r':
				diag_cnt++;
				io_rd++;
				continue;
			case 'd':
				io_debug++;
				continue;
			case 'I':
				io_image++;
				continue;
			case 'R':
				io_readonly++;
				continue;
			case 'S':
				diag_cnt++;
				io_sgeom = optarg;
				continue;
			case 'T':
				io_ADJT++;
				/* FALLTHRU */
			case 't':
				io_adjt++;
				continue;
			case 'B':
				io_wholedisk++;
				io_fdisk++;
				continue;
			case 'E':
				io_EFIdisk++;
				io_fdisk++;
				continue;
			case 'g':
				diag_cnt++;
				io_lgeom++;
				continue;
			case 'G':
				diag_cnt++;
				io_pgeom++;
				continue;
			case 'n':
				io_nifdisk++;
				io_fdisk++;
				continue;
			case 'F':
				io_fdisk++;
				io_ffdisk = optarg;
				continue;
			case 'b':
				io_mboot = optarg;
				continue;
			case 'W':
				/*
				 * If '-' is the -W argument, then write
				 * to standard output, otherwise write
				 * to the specified file.
				 */
				if (strncmp(optarg, "-", 1) == 0)
					stdo_flag = 1;
				else
					io_Wfdisk = optarg;
				io_fdisk++;
				continue;
			case 'A':
				io_fdisk++;
				io_Afdisk = optarg;
				continue;
			case 'D':
				io_fdisk++;
				io_Dfdisk = optarg;
				continue;
			case 'h':
				(void) fprintf(stderr, "%s\n", Usage);
				(void) fprintf(stderr, "%s\n", Usage1);
				exit(0);
				/* FALLTHRU */
			case 'v':
				v_flag = 1;
				continue;
			case '?':
				errflg++;
				break;
		}
		break;
	}

	if (io_image && io_sgeom && diag_cnt == 1) {
		diag_cnt = 0;
	}

	/* User option checking */

	/* By default, run in interactive mode */
	if (!io_fdisk && !diag_cnt && !io_nifdisk) {
		io_ifdisk++;
		io_fdisk++;
	}
	if (((io_fdisk || io_adjt) && diag_cnt) || (diag_cnt > 1)) {
		errflg++;
	}

	/* Was any error detected? */
	if (errflg || argc == optind) {
		(void) fprintf(stderr, "%s\n", Usage);
		(void) fprintf(stderr,
		    "\nDetailed help is available with the -h option.\n");
		exit(2);
	}


	/* Figure out the correct device node to open */
	Dfltdev = get_node(argv[optind]);

	if (io_readonly)
		openmode = O_RDONLY;
	else
		openmode = O_RDWR|O_CREAT;

	if ((Dev = open(Dfltdev, openmode, 0666)) == -1) {
		(void) fprintf(stderr,
		    "fdisk: Cannot open device %s.\n",
		    Dfltdev);
		exit(1);
	}
	/*
	 * not all disk (or disklike) drivers support DKIOCGMEDIAINFO
	 * in that case leave the minfo structure zeroed
	 */
	if (ioctl(Dev, DKIOCGMEDIAINFO, &minfo)) {
		memset(&minfo, 0, sizeof (minfo));
	}

	/* Get the disk geometry */
	if (!io_image) {
		/* Get disk's HBA (virtual) geometry */
		errno = 0;
		if (ioctl(Dev, DKIOCG_VIRTGEOM, &disk_geom)) {

			/*
			 * If ioctl isn't implemented on this platform, then
			 * turn off flag to print out virtual geometry (-v),
			 * otherwise use the virtual geometry.
			 */

			if (errno == ENOTTY) {
				v_flag = 0;
				no_virtgeom_ioctl = 1;
			} else if (errno == EINVAL) {
				/*
				 * This means that the ioctl exists, but
				 * is invalid for this disk, meaning the
				 * disk doesn't have an HBA geometry
				 * (like, say, it's larger than 8GB).
				 */
				v_flag = 0;
				hba_Numcyl = hba_heads = hba_sectors = 0;
			} else {
				(void) fprintf(stderr,
				    "%s: Cannot get virtual disk geometry.\n",
				    argv[optind]);
				exit(1);
			}
		} else {
			/* save virtual geometry values obtained by ioctl */
			hba_Numcyl = disk_geom.dkg_ncyl;
			hba_heads = disk_geom.dkg_nhead;
			hba_sectors = disk_geom.dkg_nsect;
		}

		errno = 0;
		if (ioctl(Dev, DKIOCG_PHYGEOM, &disk_geom)) {
			if (errno == ENOTTY) {
				no_physgeom_ioctl = 1;
			} else {
				(void) fprintf(stderr,
				    "%s: Cannot get physical disk geometry.\n",
				    argv[optind]);
				exit(1);
			}

		}
		/*
		 * Call DKIOCGGEOM if the ioctls for physical and virtual
		 * geometry fail. Get both from this generic call.
		 */
		if (no_virtgeom_ioctl && no_physgeom_ioctl) {
			errno = 0;
			if (ioctl(Dev, DKIOCGGEOM, &disk_geom)) {
				(void) fprintf(stderr,
				    "%s: Cannot get disk label geometry.\n",
				    argv[optind]);
				exit(1);
			}
		}

		Numcyl = disk_geom.dkg_ncyl;
		heads = disk_geom.dkg_nhead;
		sectors = disk_geom.dkg_nsect;
		sectsiz = 512;
		acyl = disk_geom.dkg_acyl;

		/*
		 * if hba geometry was not set by DKIOC_VIRTGEOM
		 * or we got an invalid hba geometry
		 * then set hba geometry based on max values
		 */
		if (no_virtgeom_ioctl ||
		    disk_geom.dkg_ncyl == 0 ||
		    disk_geom.dkg_nhead == 0 ||
		    disk_geom.dkg_nsect == 0 ||
		    disk_geom.dkg_ncyl > MAX_CYL ||
		    disk_geom.dkg_nhead > MAX_HEAD ||
		    disk_geom.dkg_nsect > MAX_SECT) {

			/*
			 * turn off flag to print out virtual geometry (-v)
			 */
			v_flag = 0;
			hba_sectors	= MAX_SECT;
			hba_heads	= MAX_HEAD + 1;
			hba_Numcyl	= (Numcyl * heads * sectors) /
			    (hba_sectors * hba_heads);
		}

		if (io_debug) {
			(void) fprintf(stderr, "Physical Geometry:\n");
			(void) fprintf(stderr,
			    "  cylinders[%d] heads[%d] sectors[%d]\n"
			    "  sector size[%d] blocks[%d] mbytes[%d]\n",
			    Numcyl,
			    heads,
			    sectors,
			    sectsiz,
			    Numcyl * heads * sectors,
			    (Numcyl * heads * sectors * sectsiz) / 1048576);
			(void) fprintf(stderr, "Virtual (HBA) Geometry:\n");
			(void) fprintf(stderr,
			    "  cylinders[%d] heads[%d] sectors[%d]\n"
			    "  sector size[%d] blocks[%d] mbytes[%d]\n",
			    hba_Numcyl,
			    hba_heads,
			    hba_sectors,
			    sectsiz,
			    hba_Numcyl * hba_heads * hba_sectors,
			    (hba_Numcyl * hba_heads * hba_sectors * sectsiz) /
			    1048576);
		}
	}

	/* If user has requested a geometry report just do it and exit */
	if (io_lgeom) {
		if (ioctl(Dev, DKIOCGGEOM, &disk_geom)) {
			(void) fprintf(stderr,
			    "%s: Cannot get disk label geometry.\n",
			    argv[optind]);
			exit(1);
		}
		Numcyl = disk_geom.dkg_ncyl;
		heads = disk_geom.dkg_nhead;
		sectors = disk_geom.dkg_nsect;
		sectsiz = 512;
		acyl = disk_geom.dkg_acyl;
		(void) printf("* Label geometry for device %s\n", Dfltdev);
		(void) printf(
		    "* PCYL     NCYL     ACYL     BCYL     NHEAD NSECT"
		    " SECSIZ\n");
		(void) printf("  %-8d %-8d %-8d %-8d %-5d %-5d %-6d\n",
		    Numcyl,
		    disk_geom.dkg_ncyl,
		    disk_geom.dkg_acyl,
		    disk_geom.dkg_bcyl,
		    heads,
		    sectors,
		    sectsiz);
		exit(0);
	} else if (io_pgeom) {
		if (ioctl(Dev, DKIOCG_PHYGEOM, &disk_geom)) {
			(void) fprintf(stderr,
			    "%s: Cannot get physical disk geometry.\n",
			    argv[optind]);
			exit(1);
		}
		(void) printf("* Physical geometry for device %s\n", Dfltdev);
		(void) printf(
		    "* PCYL     NCYL     ACYL     BCYL     NHEAD NSECT"
		    " SECSIZ\n");
		(void) printf("  %-8d %-8d %-8d %-8d %-5d %-5d %-6d\n",
		    disk_geom.dkg_pcyl,
		    disk_geom.dkg_ncyl,
		    disk_geom.dkg_acyl,
		    disk_geom.dkg_bcyl,
		    disk_geom.dkg_nhead,
		    disk_geom.dkg_nsect,
		    sectsiz);
		exit(0);
	} else if (io_sgeom) {
		if (read_geom(io_sgeom)) {
			exit(1);
		} else if (!io_image) {
			exit(0);
		}
	}

	/*
	 * some drivers may not support DKIOCGMEDIAINFO
	 * in that case use CHS
	 */
	chs_capacity = Numcyl * heads * sectors;
	dev_capacity = chs_capacity;
	if (minfo.dki_capacity > 0)
		dev_capacity = minfo.dki_capacity;

	/* Allocate memory to hold three complete sectors */
	Bootsect = (char *)malloc(3 * sectsiz);
	if (Bootsect == NULL) {
		(void) fprintf(stderr,
		    "fdisk: Unable to obtain enough buffer memory"
		    " (%d bytes).\n",
		    3 * sectsiz);
		exit(1);
	}

	Nullsect = Bootsect + sectsiz;
	/* Zero out the "NULL" sector */
	for (i = 0; i < sectsiz; i++) {
		Nullsect[i] = 0;
	}

	/* Find out what the user wants done */
	if (io_rd) {		/* abs disk read */
		abs_read();	/* will not return */
	} else if (io_wrt && !io_readonly) {
		abs_write();	/* will not return */
	} else if (io_patt && !io_readonly) {
		fill_patt();	/* will not return */
	}


	/* This is the fdisk edit, the real reason for the program.	*/

	sanity_check_provided_device(Dfltdev, Dev);

	/* Get the new BOOT program in case we write a new fdisk table */
	mboot_read();

	/* Read from disk master boot */
	dev_mboot_read();

	/*
	 * Verify and copy the device's fdisk table. This will be used
	 * as the prototype mboot if the device's mboot looks invalid.
	 */
	Bootblk = (struct mboot *)Bootsect;
	copy_Bootblk_to_Table();

	/* save away a copy of Table in Old_Table for sensing changes */
	copy_Table_to_Old_Table();

	/* Load fdisk table from specified file (-F fdisk_file) */
	if (io_ffdisk) {
		/* Load and verify user-specified table parameters */
		load(LOADFILE, io_ffdisk);
	}

	/* Does user want to delete or add an entry? */
	if (io_Dfdisk) {
		load(LOADDEL, io_Dfdisk);
	}
	if (io_Afdisk) {
		load(LOADADD, io_Afdisk);
	}

	if (!io_ffdisk && !io_Afdisk && !io_Dfdisk) {
		/* Check if there is no fdisk table */
		if (Table[0].systid == UNUSED || io_wholedisk || io_EFIdisk) {
			if (io_ifdisk && !io_wholedisk && !io_EFIdisk) {
				(void) printf(
				    "No fdisk table exists. The default"
				    " partition for the disk is:\n\n"
				    "  a 100%% \"SOLARIS System\" "
				    "partition\n\n"
				    "Type \"y\" to accept the default "
				    "partition,  otherwise type \"n\" to "
				    "edit the\n partition table.\n");
			}

			/* Edit the partition table as directed */
			if (io_wholedisk ||(io_ifdisk && yesno())) {

				/* Default scenario */
				nulltbl();

				/* now set up UNIX System partition */
				Table[0].bootid = ACTIVE;
				Table[0].relsect = lel(heads * sectors);
				Table[0].numsect = lel((long)((Numcyl - 1) *
				    heads * sectors));
				Table[0].systid = SUNIXOS2;   /* Solaris */

				/* calculate CHS values for table entry 0 */
				Set_Table_CHS_Values(0);

				update_disk_and_exit(B_TRUE);
			} else if (io_EFIdisk) {
				/* create an EFI partition for the whole disk */
				nulltbl();
				i = insert_tbl(EFI_PMBR, 0, 0, 0, 0, 0, 0, 0, 1,
				    dev_capacity - 1);
				if (i != 0) {
					(void) fprintf(stderr,
					    "Error creating EFI partition\n");
					exit(1);
				}
				update_disk_and_exit(B_TRUE);
			}
		}
	}

	/* Display complete fdisk table entries for debugging purposes */
	if (io_debug) {
		(void) fprintf(stderr, "Partition Table Entry Values:\n");
		print_Table();
		if (io_ifdisk) {
			(void) fprintf(stderr, "\n");
			(void) fprintf(stderr, "Press Enter to continue.\n");
			(void) gets(s);
		}
	}

	/* Interactive fdisk mode */
	if (io_ifdisk) {
		(void) printf(CLR_SCR);
		disptbl();
		for (;;) {
			stage0();
			copy_Bootblk_to_Table();
			disptbl();
		}
	}

	/* If user wants to write the table to a file, do it */
	if (io_Wfdisk)
		ffile_write(io_Wfdisk);
	else if (stdo_flag)
		ffile_write((char *)stdout);

	update_disk_and_exit(TableChanged() == 1);
	return (0);
}

/*
 * read_geom
 * Read geometry from specified file (-S).
 */

static int
read_geom(char *sgeom)
{
	char	line[256];
	FILE *fp;

	/* open the prototype file */
	if ((fp = fopen(sgeom, "r")) == NULL) {
		(void) fprintf(stderr, "fdisk: Cannot open file %s.\n",
		    io_sgeom);
		return (1);
	}

	/* Read a line from the file */
	while (fgets(line, sizeof (line) - 1, fp)) {
		if (line[0] == '\0' || line[0] == '\n' || line[0] == '*')
			continue;
		else {
			line[strlen(line)] = '\0';
			if (sscanf(line, "%hu %hu %hu %hu %hu %hu %d",
			    &disk_geom.dkg_pcyl,
			    &disk_geom.dkg_ncyl,
			    &disk_geom.dkg_acyl,
			    &disk_geom.dkg_bcyl,
			    &disk_geom.dkg_nhead,
			    &disk_geom.dkg_nsect,
			    &sectsiz) != 7) {
				(void) fprintf(stderr,
				    "Syntax error:\n	\"%s\".\n",
				    line);
				return (1);
			}
			break;
		} /* else */
	} /* while (fgets(line, sizeof (line) - 1, fp)) */

	if (!io_image) {
		if (ioctl(Dev, DKIOCSGEOM, &disk_geom)) {
			(void) fprintf(stderr,
			    "fdisk: Cannot set label geometry.\n");
			return (1);
		}
	} else {
		Numcyl = hba_Numcyl = disk_geom.dkg_ncyl;
		heads = hba_heads = disk_geom.dkg_nhead;
		sectors = hba_sectors = disk_geom.dkg_nsect;
		acyl = disk_geom.dkg_acyl;
	}

	(void) fclose(fp);
	return (0);
}

/*
 * dev_mboot_read
 * Read the master boot sector from the device.
 */
static void
dev_mboot_read(void)
{
	if ((ioctl(Dev, DKIOCGMBOOT, Bootsect) < 0) && (errno != ENOTTY)) {
		perror("Error in ioctl DKIOCGMBOOT");
	}
	if (errno == 0)
		return;
	if (lseek(Dev, 0, SEEK_SET) == -1) {
		(void) fprintf(stderr,
		    "fdisk: Error seeking to partition table on %s.\n",
		    Dfltdev);
		if (!io_image)
			exit(1);
	}
	if (read(Dev, Bootsect, sectsiz) != sectsiz) {
		(void) fprintf(stderr,
		    "fdisk: Error reading partition table from %s.\n",
		    Dfltdev);
		if (!io_image)
			exit(1);
	}
}

/*
 * dev_mboot_write
 * Write the master boot sector to the device.
 */
static void
dev_mboot_write(int sect, char *buff, int bootsiz)
{
	int 	new_pt, old_pt, error;
	int	clr_efi = -1, old_solaris = -1, new_solaris = -1;

	if (io_readonly)
		return;

	if (io_debug) {
		(void) fprintf(stderr, "About to write fdisk table:\n");
		print_Table();
		if (io_ifdisk) {
			(void) fprintf(stderr, "Press Enter to continue.\n");
			(void) gets(s);
		}
	}

	/* see if the old table had EFI or Solaris partitions */
	for (old_pt = 0; old_pt < FD_NUMPART; old_pt++) {
		if (Old_Table[old_pt].systid == SUNIXOS ||
		    Old_Table[old_pt].systid == SUNIXOS2) {
			old_solaris = old_pt;
		} else if (Old_Table[old_pt].systid == EFI_PMBR) {
			clr_efi = old_pt;
		}
	}

	/* look to see if Solaris partition changed in relsect/numsect */
	for (new_pt = 0; new_pt < FD_NUMPART; new_pt++) {

		/*
		 * if this is not a Solaris partition, ignore it
		 */
		if (Table[new_pt].systid != SUNIXOS &&
		    Table[new_pt].systid != SUNIXOS2)
			continue;

		/*
		 * if there was no previous Solaris partition
		 * or if the old partition was in a different place
		 * or if the old partition was a different size
		 * then this must be a new Solaris partition
		 */
		if (old_solaris == -1 ||
		    Old_Table[old_solaris].relsect != Table[new_pt].relsect ||
		    Old_Table[old_solaris].numsect != Table[new_pt].numsect) {
			new_solaris = new_pt;
			break;
		}
	}

	/* look to see if a EFI partition changed in relsect/numsect */
	for (new_pt = 0; new_pt < FD_NUMPART; new_pt++) {
		if (Table[new_pt].systid != EFI_PMBR)
			continue;
		for (old_pt = 0; old_pt < FD_NUMPART; old_pt++) {
			if ((Old_Table[old_pt].systid ==
			    Table[new_pt].systid) &&
			    (Old_Table[old_pt].relsect ==
			    Table[new_pt].relsect) &&
			    (Old_Table[old_pt].numsect ==
			    Table[new_pt].numsect))
				break;
		}

		/*
		 * if EFI partition changed, set the flag to clear
		 * the EFI GPT
		 */
		if (old_pt == FD_NUMPART && Table[new_pt].begcyl != 0) {
			clr_efi = 0;
		}
		break;
	}

	/* clear labels if necessary */
	if (clr_efi >= 0) {
		if (io_debug) {
			(void) fprintf(stderr, "Clearing EFI labels\n");
		}
		if ((error = clear_efi()) != 0) {
			if (io_debug) {
				(void) fprintf(stderr,
				    "\tError %d clearing EFI labels"
				    " (probably no EFI labels exist)\n",
				    error);
			}
		}
	}

	if (new_solaris >= 0) {
		if (io_debug) {
			(void) fprintf(stderr, "Clearing VTOC labels from NEW"
			    " table\n");
		}
		clear_vtoc(NEW, new_solaris);
	}

	if ((ioctl(Dev, DKIOCSMBOOT, buff) == -1) && (errno != ENOTTY)) {
		(void) fprintf(stderr,
		    "fdisk: Error in ioctl DKIOCSMBOOT on %s.\n",
		    Dfltdev);
	}
	if (errno == 0)
		return;

	/* write to disk drive */
	if (lseek(Dev, sect, SEEK_SET) == -1) {
		(void) fprintf(stderr,
		    "fdisk: Error seeking to master boot record on %s.\n",
		    Dfltdev);
		exit(1);
	}
	if (write(Dev, buff, bootsiz) != bootsiz) {
		(void) fprintf(stderr,
		    "fdisk: Error writing master boot record to %s.\n",
		    Dfltdev);
		exit(1);
	}
}

/*
 * mboot_read
 * Read the prototype boot records from the files.
 */
static void
mboot_read(void)
{
	int mDev, i;
	struct ipart *part;

#if defined(i386) || defined(sparc)
	/*
	 * If the master boot file hasn't been specified, use the
	 * implementation architecture name to generate the default one.
	 */
	if (io_mboot == (char *)0) {
		/*
		 * Bug ID 1249035:
		 *	The mboot file must be delivered on all platforms
		 *	and installed in a non-platform-dependent
		 *	directory; i.e., /usr/lib/fs/ufs.
		 */
		io_mboot = "/usr/lib/fs/ufs/mboot";
	}

	/* First read in the master boot record */

	/* Open the master boot proto file */
	if ((mDev = open(io_mboot, O_RDONLY, 0666)) == -1) {
		(void) fprintf(stderr,
		    "fdisk: Cannot open master boot file %s.\n",
		    io_mboot);
		exit(1);
	}

	/* Read the master boot program */
	if (read(mDev, &BootCod, sizeof (struct mboot)) != sizeof
	    (struct mboot)) {
		(void) fprintf(stderr,
		    "fdisk: Cannot read master boot file %s.\n",
		    io_mboot);
		exit(1);
	}

	/* Is this really a master boot record? */
	if (les(BootCod.signature) != MBB_MAGIC) {
		(void) fprintf(stderr,
		    "fdisk: Invalid master boot file %s.\n", io_mboot);
		(void) fprintf(stderr,
		    "Bad magic number: is %x, but should be %x.\n",
		    les(BootCod.signature), MBB_MAGIC);
		exit(1);
	}

	(void) close(mDev);
#else
#error	fdisk needs to be ported to new architecture
#endif

	/* Zero out the partitions part of this record */
	part = (struct ipart *)BootCod.parts;
	for (i = 0; i < FD_NUMPART; i++, part++) {
		(void) memset(part, 0, sizeof (struct ipart));
	}

}

/*
 * fill_patt
 * Fill the disk with user/sector number pattern.
 */
static void
fill_patt(void)
{
	int	*buff_ptr, i;
	int	io_fpatt = 0;
	int	io_ipatt = 0;

	if (strncmp(io_fatt, "#", 1) != 0) {
		io_fpatt++;
		io_ipatt = strtoul(io_fatt, 0, 0);
		buff_ptr = (int *)Bootsect;
		for (i = 0; i < sectsiz; i += 4, buff_ptr++)
			*buff_ptr = io_ipatt;
	}

	/*
	 * Fill disk with pattern based on block number.
	 * Write to the disk at absolute relative block io_offset
	 * for io_size blocks.
	 */
	while (io_size--) {
		buff_ptr = (int *)Bootsect;
		if (!io_fpatt) {
			for (i = 0; i < sectsiz; i += 4, buff_ptr++)
				*buff_ptr = io_offset;
		}
		/* Write the data to disk */
		if (lseek(Dev, sectsiz * io_offset++, SEEK_SET) == -1) {
			(void) fprintf(stderr, "fdisk: Error seeking on %s.\n",
			    Dfltdev);
			exit(1);
		}
		if (write(Dev, Bootsect, sectsiz) != sectsiz) {
			(void) fprintf(stderr, "fdisk: Error writing %s.\n",
			    Dfltdev);
			exit(1);
		}
	} /* while (--io_size); */
}

/*
 * abs_read
 * Read from the disk at absolute relative block io_offset for
 * io_size blocks. Write the data to standard ouput (-r).
 */
static void
abs_read(void)
{
	int c;

	while (io_size--) {
		if (lseek(Dev, sectsiz * io_offset++, SEEK_SET) == -1) {
			(void) fprintf(stderr, "fdisk: Error seeking on %s.\n",
			    Dfltdev);
			exit(1);
		}
		if (read(Dev, Bootsect, sectsiz) != sectsiz) {
			(void) fprintf(stderr, "fdisk: Error reading %s.\n",
			    Dfltdev);
			exit(1);
		}

		/* Write to standard ouptut */
		if ((c = write(1, Bootsect, (unsigned)sectsiz)) != sectsiz) {
			if (c >= 0) {
				if (io_debug)
					(void) fprintf(stderr,
					    "fdisk: Output warning: %d of %d"
					    " characters written.\n",
					    c, sectsiz);
				exit(2);
			} else {
				perror("write error on output file.");
				exit(2);
			}
		} /* if ((c = write(1, Bootsect, (unsigned)sectsiz)) */
			/* != sectsiz) */
	} /* while (--io_size); */
	exit(0);
}

/*
 * abs_write
 * Read the data from standard input. Write to the disk at
 * absolute relative block io_offset for io_size blocks (-w).
 */
static void
abs_write(void)
{
	int c, i;

	while (io_size--) {
		int part_exit = 0;
		/* Read from standard input */
		if ((c = read(0, Bootsect, (unsigned)sectsiz)) != sectsiz) {
			if (c >= 0) {
				if (io_debug)
				(void) fprintf(stderr,
				    "fdisk: WARNING: Incomplete read (%d of"
				    " %d characters read) on input file.\n",
				    c, sectsiz);
				/* Fill pattern to mark partial sector in buf */
				for (i = c; i < sectsiz; ) {
					Bootsect[i++] = 0x41;
					Bootsect[i++] = 0x62;
					Bootsect[i++] = 0x65;
					Bootsect[i++] = 0;
				}
				part_exit++;
			} else {
				perror("read error on input file.");
				exit(2);
			}

		}
		/* Write to disk drive */
		if (lseek(Dev, sectsiz * io_offset++, SEEK_SET) == -1) {
			(void) fprintf(stderr, "fdisk: Error seeking on %s.\n",
			    Dfltdev);
			exit(1);
		}
		if (write(Dev, Bootsect, sectsiz) != sectsiz) {
			(void) fprintf(stderr, "fdisk: Error writing %s.\n",
			    Dfltdev);
			exit(1);
		}
		if (part_exit)
		exit(0);
	} /* while (--io_size); */
	exit(1);
}


/*
 * load
 * Load will either read the fdisk table from a file or add or
 * delete an entry (-A, -D, -F).
 */

static void
load(int funct, char *file)
{
	int	id;
	int	act;
	int	bhead;
	int	bsect;
	int	bcyl;
	int	ehead;
	int	esect;
	int	ecyl;
	int	rsect;
	int	numsect;
	char	line[256];
	int	i = 0;
	int	j;
	FILE *fp;

	switch (funct) {

	case LOADFILE:

		/*
		 * Zero out the table before loading it, which will
		 * force it to be updated on disk later (-F
		 * fdisk_file).
		 */
		nulltbl();

		/* Open the prototype file */
		if ((fp = fopen(file, "r")) == NULL) {
			(void) fprintf(stderr,
			    "fdisk: Cannot open prototype partition file %s.\n",
			    file);
			exit(1);
		}

		/* Read a line from the file */
		while (fgets(line, sizeof (line) - 1, fp)) {
			if (pars_fdisk(line, &id, &act, &bhead, &bsect,
			    &bcyl, &ehead, &esect, &ecyl, &rsect, &numsect)) {
				continue;
			}

			/*
			 * Validate the partition. It cannot start at sector
			 * 0 unless it is UNUSED or already exists
			 */
			if (validate_part(id, rsect, numsect) < 0) {
				(void) fprintf(stderr,
				    "fdisk: Error on entry \"%s\".\n",
				    line);
				exit(1);
			}
			/*
			 * Find an unused entry to use and put the entry
			 * in table
			 */
			if (insert_tbl(id, act, bhead, bsect, bcyl, ehead,
			    esect, ecyl, rsect, numsect) < 0) {
				(void) fprintf(stderr,
				    "fdisk: Error on entry \"%s\".\n",
				    line);
				exit(1);
			}
		} /* while (fgets(line, sizeof (line) - 1, fp)) */

		if (verify_tbl() < 0) {
			(void) fprintf(stderr,
			    "fdisk: Cannot create partition table\n");
			exit(1);
		}

		(void) fclose(fp);
		return;

	case LOADDEL:

		/* Parse the user-supplied deletion line (-D) */
		if (pars_fdisk(file, &id, &act, &bhead, &bsect, &bcyl,
		    &ehead, &esect, &ecyl, &rsect, &numsect)) {
			(void) fprintf(stderr,
			    "fdisk: Syntax error \"%s\"\n", file);
			exit(1);
		}

		/* Find the exact entry in the table */
		for (i = 0; i < FD_NUMPART; i++) {
			if (Table[i].systid == id &&
			    Table[i].bootid == act &&
			    Table[i].beghead == bhead &&
			    Table[i].begsect == ((bsect & 0x3f) |
			    (uchar_t)((bcyl>>2) & 0xc0)) &&
			    Table[i].begcyl == (uchar_t)(bcyl & 0xff) &&
			    Table[i].endhead == ehead &&
			    Table[i].endsect == ((esect & 0x3f) |
			    (uchar_t)((ecyl>>2) & 0xc0)) &&
			    Table[i].endcyl == (uchar_t)(ecyl & 0xff) &&
			    Table[i].relsect == lel(rsect) &&
			    Table[i].numsect == lel(numsect)) {

				/*
				 * Found the entry. Now move rest of
				 * entries up toward the top of the
				 * table, leaving available entries at
				 * the end of the fdisk table.
				 */
				for (j = i; j < FD_NUMPART - 1; j++) {
					Table[j].systid = Table[j + 1].systid;
					Table[j].bootid = Table[j + 1].bootid;
					Table[j].beghead = Table[j + 1].beghead;
					Table[j].begsect = Table[j + 1].begsect;
					Table[j].begcyl = Table[j + 1].begcyl;
					Table[j].endhead = Table[j + 1].endhead;
					Table[j].endsect = Table[j + 1].endsect;
					Table[j].endcyl = Table[j + 1].endcyl;
					Table[j].relsect = Table[j + 1].relsect;
					Table[j].numsect = Table[j + 1].numsect;
				}

				/*
				 * Mark the last entry as unused in case
				 * all table entries were in use prior
				 * to the deletion.
				 */

				Table[FD_NUMPART - 1].systid = UNUSED;
				Table[FD_NUMPART - 1].bootid = 0;
				return;
			}
		}
		(void) fprintf(stderr,
		    "fdisk: Entry does not match any existing partition:\n"
		    "	\"%s\"\n",
		    file);
		exit(1);
		/* FALLTHRU */

	case LOADADD:

		/* Parse the user-supplied addition line (-A) */
		if (pars_fdisk(file, &id, &act, &bhead, &bsect, &bcyl, &ehead,
		    &esect, &ecyl, &rsect, &numsect)) {
			(void) fprintf(stderr,
			    "fdisk: Syntax error \"%s\"\n", file);
			exit(1);
		}

		/* Validate the partition. It cannot start at sector 0 */
		if (rsect == 0) {
			(void) fprintf(stderr,
			    "fdisk: New partition cannot start at sector 0:\n"
			    "   \"%s\".\n",
			    file);
			exit(1);
		}

		/*
		 * if the user wishes to add an EFI partition, we need
		 * more extensive validation.  rsect should be 1, and
		 * numsect should equal the entire disk capacity - 1
		 */

		if (id == EFI_PMBR) {
			if (rsect != 1) {
				(void) fprintf(stderr,
				    "fdisk: EFI partitions must start at sector"
				    " 1 (input rsect = %d)\n", rsect);
				exit(1);
			}

			if (numsect != dev_capacity - 1) {
				(void) fprintf(stderr,
				    "fdisk: EFI partitions must encompass the "
				    "entire disk\n"
				    "(input numsect: %d - avail: %llu)\n",
				    numsect,
				    dev_capacity - 1);
				exit(1);
			}
		}

		/* Find unused entry for use and put entry in table */
		if (insert_tbl(id, act, bhead, bsect, bcyl, ehead, esect,
		    ecyl, rsect, numsect) < 0) {
			(void) fprintf(stderr,
			    "fdisk: Invalid entry could not be inserted:\n"
			    "	\"%s\"\n",
			    file);
			exit(1);
		}

		/* Make sure new entry does not overlap existing entry */
		if (verify_tbl() < 0) {
			(void) fprintf(stderr,
			    "fdisk: Cannot create partition \"%s\"\n", file);
			exit(1);
		}
	} /* switch funct */
}

/*
 * Set_Table_CHS_Values
 *
 * This will calculate the CHS values for beginning and ending CHS
 * for a single partition table entry (ti) based on the relsect
 * and numsect values contained in the partion table entry.
 *
 * hba_heads and hba_sectors contain the number of heads and sectors.
 *
 * If the number of cylinders exceeds the MAX_CYL,
 * then maximum values will be placed in the corresponding chs entry.
 */
static void
Set_Table_CHS_Values(int ti)
{
	uint32_t	lba, cy, hd, sc;

	lba = (uint32_t)Table[ti].relsect;
	if (lba >= hba_heads * hba_sectors * MAX_CYL) {
		/*
		 * the lba address cannot be expressed in CHS value
		 * so store the maximum CHS field values in the CHS fields.
		 */
		cy = MAX_CYL + 1;
		hd = MAX_HEAD;
		sc = MAX_SECT;
	} else {
		cy = lba / hba_sectors / hba_heads;
		hd = lba / hba_sectors % hba_heads;
		sc = lba % hba_sectors + 1;
	}
	Table[ti].begcyl = cy & 0xff;
	Table[ti].beghead = (uchar_t)hd;
	Table[ti].begsect = (uchar_t)(((cy >> 2) & 0xc0) | sc);

	/*
	 * This code is identical to the code above
	 * except that it works on ending CHS values
	 */
	lba = (uint32_t)(Table[ti].relsect + Table[ti].numsect - 1);
	if (lba >= hba_heads * hba_sectors * MAX_CYL) {
		cy = MAX_CYL + 1;
		hd = MAX_HEAD;
		sc = MAX_SECT;
	} else {
		cy = lba / hba_sectors / hba_heads;
		hd = lba / hba_sectors % hba_heads;
		sc = lba % hba_sectors + 1;
	}
	Table[ti].endcyl = cy & 0xff;
	Table[ti].endhead = (uchar_t)hd;
	Table[ti].endsect = (uchar_t)(((cy >> 2) & 0xc0) | sc);
}

/*
 * insert_tbl
 * 	Insert entry into fdisk table. Check all user-supplied values
 *	for the entry, but not the validity relative to other table
 *	entries!
 */
static int
insert_tbl(
    int id, int act,
    int bhead, int bsect, int bcyl,
    int ehead, int esect, int ecyl,
    int rsect, int numsect)
{
	int	i;

	/* validate partition size */
	if (rsect + numsect > dev_capacity) {
		(void) fprintf(stderr,
		    "fdisk: Partition table exceeds the size of the disk.\n");
		return (-1);
	}

	/* find UNUSED partition table entry */
	for (i = 0; i < FD_NUMPART; i++) {
		if (Table[i].systid == UNUSED) {
			break;
		}
	}
	if (i >= FD_NUMPART) {
		(void) fprintf(stderr, "fdisk: Partition table is full.\n");
		return (-1);
	}


	Table[i].systid = (uchar_t)id;
	Table[i].bootid = (uchar_t)act;
	Table[i].numsect = lel(numsect);
	Table[i].relsect = lel(rsect);

	/*
	 * If we have been called with a valid geometry, use it
	 * valid means non-zero values that fit in the BIOS fields
	 */
	if (0 < bsect && bsect <= MAX_SECT &&
	    0 <= bhead && bhead <= MAX_HEAD &&
	    0 < esect && esect <= MAX_SECT &&
	    0 <= ehead && ehead <= MAX_HEAD) {
		if (bcyl > MAX_CYL)
			bcyl = MAX_CYL + 1;
		if (ecyl > MAX_CYL)
			ecyl = MAX_CYL + 1;
		Table[i].begcyl = bcyl & 0xff;
		Table[i].endcyl = ecyl & 0xff;
		Table[i].beghead = (uchar_t)bhead;
		Table[i].endhead = (uchar_t)ehead;
		Table[i].begsect = (uchar_t)(((bcyl >> 2) & 0xc0) | bsect);
		Table[i].endsect = ((ecyl >> 2) & 0xc0) | esect;
	} else {

		/*
		 * The specified values are invalid,
		 * so calculate the values based on hba_heads, hba_sectors
		 */
		Set_Table_CHS_Values(i);
	}

	/*
	 * return partition index
	 */
	return (i);
}

/*
 * verify_tbl
 * Verify that no partition entries overlap or exceed the size of
 * the disk.
 */
static int
verify_tbl(void)
{
	int	i, j, rsect, numsect;
	int	noMoreParts = 0;
	int	numParts = 0;

	/* Make sure new entry does not overlap an existing entry */
	for (i = 0; i < FD_NUMPART - 1; i++) {
		if (Table[i].systid != UNUSED) {
			numParts++;
			/*
			 * No valid partitions allowed after an UNUSED  or
			 * EFI_PMBR part
			 */
			if (noMoreParts) {
				return (-1);
			}

			/*
			 * EFI_PMBR partitions must be the only partition
			 * and must be Table entry 0
			 */
			if (Table[i].systid == EFI_PMBR) {
				if (i == 0) {
					noMoreParts = 1;
				} else {
					return (-1);
				}

				if (Table[i].relsect != 1) {
					(void) fprintf(stderr, "ERROR: "
					    "Invalid starting sector "
					    "for EFI_PMBR partition:\n"
					    "relsect %d "
					    "(should be 1)\n",
					    Table[i].relsect);

					return (-1);
				}

				if (Table[i].numsect != dev_capacity - 1) {
					(void) fprintf(stderr, "ERROR: "
					    "EFI_PMBR partition must "
					    "encompass the entire "
					    "disk.\n numsect %d - "
					    "actual %llu\n",
					    Table[i].numsect,
					    dev_capacity - 1);

					return (-1);
				}
			}

			/* make sure the partition isn't larger than the disk */
			rsect = lel(Table[i].relsect);
			numsect = lel(Table[i].numsect);
			if ((rsect + numsect) > dev_capacity) {
				return (-1);
			}

			for (j = i + 1; j < FD_NUMPART; j++) {
				if (Table[j].systid != UNUSED) {
					int t_relsect = lel(Table[j].relsect);
					int t_numsect = lel(Table[j].numsect);

					if (noMoreParts) {
						(void) fprintf(stderr,
						    "Cannot add partition to "
						    "table; no more partitions "
						    "allowed\n");

						if (io_debug) {
							(void) fprintf(stderr,
							    "DEBUG: Current "
							    "partition:\t"
							    "%d:%d:%d:%d:%d:"
							    "%d:%d:%d:%d:%d\n"
							    "       Next "
							    "partition:\t\t"
							    "%d:%d:%d:%d:%d:"
							    "%d:%d:%d:%d:%d\n",
							    Table[i].systid,
							    Table[i].bootid,
							    Table[i].begcyl,
							    Table[i].beghead,
							    Table[i].begsect,
							    Table[i].endcyl,
							    Table[i].endhead,
							    Table[i].endsect,
							    Table[i].relsect,
							    Table[i].numsect,
							    Table[j].systid,
							    Table[j].bootid,
							    Table[j].begcyl,
							    Table[j].beghead,
							    Table[j].begsect,
							    Table[j].endcyl,
							    Table[j].endhead,
							    Table[j].endsect,
							    Table[j].relsect,
							    Table[j].numsect);
						}

						return (-1);
					}

					if ((rsect >=
					    (t_relsect + t_numsect)) ||
					    ((rsect + numsect) <= t_relsect)) {
						continue;
					} else {
						(void) fprintf(stderr, "ERROR: "
						    "current partition overlaps"
						    " following partition\n");

						return (-1);
					}
				}
			}
		} else {
			noMoreParts = 1;
		}
	}
	if (Table[i].systid != UNUSED) {
		if (noMoreParts ||
		    ((lel(Table[i].relsect) + lel(Table[i].numsect)) >
		    dev_capacity)) {
			return (-1);
		}
	}

	return (numParts);
}

/*
 * pars_fdisk
 * Parse user-supplied data to set up fdisk partitions
 * (-A, -D, -F).
 */
static int
pars_fdisk(
    char *line,
    int *id, int *act,
    int *bhead, int *bsect, int *bcyl,
    int *ehead, int *esect, int *ecyl,
    int *rsect, int *numsect)
{
	int	i;
	if (line[0] == '\0' || line[0] == '\n' || line[0] == '*')
		return (1);
	line[strlen(line)] = '\0';
	for (i = 0; i < strlen(line); i++) {
		if (line[i] == '\0') {
			break;
		} else if (line[i] == ':') {
			line[i] = ' ';
		}
	}
	if (sscanf(line, "%d %d %d %d %d %d %d %d %d %d",
	    id, act, bhead, bsect, bcyl, ehead, esect, ecyl,
	    rsect, numsect) != 10) {
		(void) fprintf(stderr, "Syntax error:\n	\"%s\".\n", line);
		exit(1);
	}
	return (0);
}

/*
 * validate_part
 * Validate that a new partition does not start at sector 0. Only UNUSED
 * partitions and previously existing partitions are allowed to start at 0.
 */
static int
validate_part(int id, int rsect, int numsect)
{
	int i;
	if ((id != UNUSED) && (rsect == 0)) {
		for (i = 0; i < FD_NUMPART; i++) {
			if ((Old_Table[i].systid == id) &&
			    (Old_Table[i].relsect == lel(rsect)) &&
			    (Old_Table[i].numsect == lel(numsect)))
				return (0);
		}
		(void) fprintf(stderr,
		    "New partition cannot start at sector 0\n");
		return (-1);
	}
	return (0);
}

/*
 * stage0
 * Print out interactive menu and process user input.
 */
static void
stage0(void)
{
	dispmenu();
	for (;;) {
		(void) printf(Q_LINE);
		(void) printf("Enter Selection: ");
		(void) gets(s);
		rm_blanks(s);
		while (!((s[0] > '0') && (s[0] < '7') && (s[1] == 0))) {
			(void) printf(E_LINE); /* Clear any previous error */
			(void) printf(
			    "Enter a one-digit number between 1 and 6.");
			(void) printf(Q_LINE);
			(void) printf("Enter Selection: ");
			(void) gets(s);
			rm_blanks(s);
		}
		(void) printf(E_LINE);
		switch (s[0]) {
			case '1':
				if (pcreate() == -1)
					return;
				break;
			case '2':
				if (pchange() == -1)
					return;
				break;
			case '3':
				if (pdelete() == -1)
					return;
				break;
			case '4':
				if (ppartid() == -1)
					return;
				break;
			case '5':
				/* update disk partition table, if changed */
				if (TableChanged() == 1) {
					copy_Table_to_Bootblk();
					dev_mboot_write(0, Bootsect, sectsiz);
				}
				/*
				 * If the VTOC table is wrong fix it
				 * (truncate only)
				 */
				if (io_adjt) {
					fix_slice();
				}
				(void) close(Dev);
				exit(0);
				/* FALLTHRU */
			case '6':
				/*
				 * If the VTOC table is wrong fix it
				 * (truncate only)
				 */
				if (io_adjt) {
					fix_slice();
				}
				(void) close(Dev);
				exit(0);
				/* FALLTHRU */
			default:
				break;
		}
		copy_Table_to_Bootblk();
		disptbl();
		dispmenu();
	}
}

/*
 * pcreate
 * Create partition entry in the table (interactive mode).
 */
static int
pcreate(void)
{
	uchar_t tsystid = 'z';
	int i, j;
	int rsect = 1;
	int retCode = 0;

	i = 0;
	for (;;) {
		if (i == FD_NUMPART) {
			(void) printf(E_LINE);
			(void) printf(
			    "The partition table is full!\n"
			    "You must delete a partition before creating"
			    " a new one.\n");
			return (-1);
		}
		if (Table[i].systid == UNUSED) {
			break;
		}
		i++;
	}

	j = 0;
	for (i = 0; i < FD_NUMPART; i++) {
		if (Table[i].systid != UNUSED) {
			j += lel(Table[i].numsect);
		}
		if (j >= chs_capacity) {
			(void) printf(E_LINE);
			(void) printf("There is no more room on the disk for"
			    " another partition.\n");
			(void) printf(
			    "You must delete a partition before creating"
			    " a new one.\n");
			return (-1);
		}
	}
	while (tsystid == 'z') {
		(void) printf(Q_LINE);
		(void) printf(
		    "Select the partition type to create:\n"
		    "   1=SOLARIS2  2=UNIX        3=PCIXOS     4=Other\n"
		    "   5=DOS12     6=DOS16       7=DOSEXT     8=DOSBIG\n"
		    "   9=DOS16LBA  A=x86 Boot    B=Diagnostic C=FAT32\n"
		    "   D=FAT32LBA  E=DOSEXTLBA   F=EFI        0=Exit? ");
		(void) gets(s);
		rm_blanks(s);
		if (s[1] != 0) {
			(void) printf(E_LINE);
			(void) printf("Invalid selection, try again.");
			continue;
		}
		switch (s[0]) {
		case '0':		/* exit */
			(void) printf(E_LINE);
			return (-1);
		case '1':		/* Solaris partition */
			tsystid = SUNIXOS2;
			break;
		case '2':		/* UNIX partition */
			tsystid = UNIXOS;
			break;
		case '3':		/* PCIXOS partition */
			tsystid = PCIXOS;
			break;
		case '4':		/* OTHEROS System partition */
			tsystid = OTHEROS;
			break;
		case '5':
			tsystid = DOSOS12; /* DOS 12 bit fat */
			break;
		case '6':
			tsystid = DOSOS16; /* DOS 16 bit fat */
			break;
		case '7':
			tsystid = EXTDOS;
			break;
		case '8':
			tsystid = DOSHUGE;
			break;
		case '9':
			tsystid = FDISK_FAT95;  /* FAT16, need extended int13 */
			break;
		case 'a':		/* x86 Boot partition */
		case 'A':
			tsystid = X86BOOT;
			break;
		case 'b':		/* Diagnostic boot partition */
		case 'B':
			tsystid = DIAGPART;
			break;
		case 'c':		/* FAT32 */
		case 'C':
			tsystid = FDISK_WINDOWS;
			break;
		case 'd':		/* FAT32 and need extended int13 */
		case 'D':
			tsystid = FDISK_EXT_WIN;
			break;
		case 'e':	/* Extended partition, need extended int13 */
		case 'E':
			tsystid = FDISK_EXTLBA;
			break;
		case 'f':
		case 'F':
			tsystid = EFI_PMBR;
			break;
		default:
			(void) printf(E_LINE);
			(void) printf("Invalid selection, try again.");
			continue;
		}
	}

	(void) printf(E_LINE);

	if (tsystid != EFI_PMBR) {
		/* create the new partition */
		i = specify(tsystid);

		if (i != -1) {
			/* see if it should be the active partition */
			(void) printf(E_LINE);
			(void) printf(Q_LINE);

			(void) printf(
			    "Should this become the active partition? If "
			    "yes, it  will be activated\n"
			    "each time the computer is reset or turned on.\n"
			    "Please type \"y\" or \"n\". ");

			if (yesno()) {
				(void) printf(E_LINE);
				for (j = 0; j < FD_NUMPART; j++) {
					if (j == i) {
						Table[j].bootid = ACTIVE;
						(void) printf(E_LINE);
						(void) printf(
						    "Partition %d is now "
						    "the active partition.",
						    j + 1);
					} else {
						Table[j].bootid = 0;
					}
				}
			} else {
				Table[i].bootid = 0;
			}

			/* set up the return code */
			i = 1;
		}
	} else {
		/*
		 * partitions of type EFI_PMBR must be the only partitions in
		 * the table
		 *
		 * First, make sure there were no errors the table is
		 * empty
		 */
		retCode = verify_tbl();

		if (retCode < 0) {
			(void) fprintf(stderr,
			    "fdisk: Cannot create EFI partition table; \n"
			    "current partition table is invalid.\n");
			return (-1);
		} else if (retCode > 0) {
			(void) printf(
			    "An EFI partition must be the only partition on "
			    "disk.  You may manually delete existing\n"
			    "partitions, or fdisk can do it.\n"
			    "Do you want fdisk to destroy existing "
			    "partitions?\n"
			    "Please type \"y\" or \"n\". ");

			if (yesno()) {
				nulltbl();
			} else {
				return (-1);
			}
		}

		/* create the table entry - i should be 0 */
		i = insert_tbl(tsystid, 0, 0, 0, 0, 0, 0, 0, rsect,
		    dev_capacity - rsect);

		if (i != 0) {
			(void) printf("Error creating EFI partition!!!\n");
			i = -1;
		} else {

			/* EFI partitions are currently never active */
			Table[i].bootid = 0;

			/* set up the return code */
			i = 1;
		}
	}

	return (i);
}

/*
 * specify
 * Query the user to specify the size of the new partition in
 * terms of percentage of the disk or by specifying the starting
 * cylinder and length in cylinders.
 */
static int
specify(uchar_t tsystid)
{
	int	i, j, percent = -1;
	int	cyl, cylen, first_free, size_free;
	int	max_free;
	int	cyl_size;
	struct ipart *partition[FD_NUMPART];

	cyl_size = heads * sectors;

	/*
	 * make a local copy of the partition table
	 * and sort it into relsect order
	 */
	for (i = 0; i < FD_NUMPART; i++)
		partition[i] = &Table[i];

	for (i = 0; i < FD_NUMPART - 1; i++) {
		if (partition[i]->systid == UNUSED)
			break;
		for (j = i + 1; j < FD_NUMPART; j++) {
			if (partition[j]->systid == UNUSED)
				break;
			if (lel(partition[j]->relsect) <
			    lel(partition[i]->relsect)) {
				struct ipart *temp = partition[i];
				partition[i] = partition[j];
				partition[j] = temp;
			}
		}
	}

	(void) printf(Q_LINE);
	(void) printf(
	    "Specify the percentage of disk to use for this partition\n"
	    "(or type \"c\" to specify the size in cylinders). ");
	(void) gets(s);
	rm_blanks(s);
	if (s[0] != 'c') {	/* Specify size in percentage of disk */
		i = 0;
		while (s[i] != '\0') {
			if (s[i] < '0' || s[i] > '9') {
				(void) printf(E_LINE);
				(void) printf("Invalid percentage value "
				    "specified; retry the operation.");
				return (-1);
			}
			i++;
			if (i > 3) {
				(void) printf(E_LINE);
				(void) printf("Invalid percentage value "
				    "specified; retry the operation.");
				return (-1);
			}
		}
		if ((percent = atoi(s)) > 100) {
			(void) printf(E_LINE);
			(void) printf(
			    "Percentage value is too large. The value must be"
			    " between 1 and 100;\nretry the operation.\n");
			return (-1);
		}
		if (percent < 1) {
			(void) printf(E_LINE);
			(void) printf(
			    "Percentage value is too small. The value must be"
			    " between 1 and 100;\nretry the operation.\n");
			return (-1);
		}


		if (percent == 100)
			cylen = Numcyl - 1;
		else
			cylen = (Numcyl * percent) / 100;

		/* Verify DOS12 partition doesn't exceed max size of 32MB. */
		if ((tsystid == DOSOS12) &&
		    ((long)((long)cylen * cyl_size) > MAXDOS)) {
			int n;
			n = MAXDOS * 100 / (int)(cyl_size) / Numcyl;
			(void) printf(E_LINE);
			(void) printf("Maximum size for a DOS partition "
			    "is %d%%; retry the operation.",
			    n <= 100 ? n : 100);
			return (-1);
		}


		max_free = 0;
		for (i = 0; i < FD_NUMPART; i++) {

			/*
			 * check for free space before partition i
			 * where i varies from 0 to 3
			 *
			 * freespace after partition 3 is unusable
			 * because there are no free partitions
			 *
			 * freespace begins at the end of previous partition
			 * or cylinder 1
			 */
			if (i) {
				/* Not an empty table */
				first_free = lel(partition[i - 1]->relsect) +
				    lel(partition[i - 1]->numsect);
			} else {
				first_free = cyl_size;
			}

			/*
			 * freespace ends before the current partition
			 * or the end of the disk (chs end)
			 */
			if (partition[i]->systid == UNUSED) {
				size_free = chs_capacity - first_free;
			} else {
				size_free =
				    lel(partition[i]->relsect) - first_free;
			}

			/* save largest free space */
			if (max_free < size_free)
				max_free = size_free;

			if ((cylen * cyl_size) <= size_free) {
				/* We found a place to use */
				break;
			}
			if (partition[i]->systid == UNUSED) {
				(void) printf(E_LINE);
				max_free /= (cyl_size);
				(void) fprintf(stderr, "fdisk: "
				    "Maximum percentage available is %d\n",
				    100 * max_free / Numcyl);
				return (-1);
			}
		}

		(void) printf(E_LINE);
		if (i >= FD_NUMPART) {
			(void) fprintf(stderr,
			    "fdisk: Partition table is full.\n");
			return (-1);
		}

		if ((i = insert_tbl(tsystid, 0, 0, 0, 0, 0, 0, 0,
		    first_free, cylen * cyl_size)) >= 0)  {
			return (i);
		}
		return (-1);
	} else {

		/* Specifying size in cylinders */
		(void) printf(E_LINE);
		(void) printf(Q_LINE);
		(void) printf("Enter starting cylinder number: ");
		if ((cyl = getcyl()) == -1) {
			(void) printf(E_LINE);
			(void) printf("Invalid number; retry the operation.");
			return (-1);
		}
		if (cyl == 0) {
			(void) printf(E_LINE);
			(void) printf(
			    "New partition cannot start at cylinder 0.\n");
			return (-1);
		}
		if (cyl >= (unsigned int)Numcyl) {
			(void) printf(E_LINE);
			(void) printf(
			    "Cylinder %d is out of bounds, "
			    "the maximum is %d.\n",
			    cyl, Numcyl - 1);
			return (-1);
		}
		(void) printf(Q_LINE);
		(void) printf("Enter partition size in cylinders: ");
		if ((cylen = getcyl()) == -1) {
			(void) printf(E_LINE);
			(void) printf("Invalid number, retry the operation.");
			return (-1);
		}

		for (i = 0; i < FD_NUMPART; i++) {
			uint32_t	t_relsect, t_numsect;

			if (partition[i]->systid == UNUSED)
				break;
			t_relsect = lel(partition[i]->relsect);
			t_numsect = lel(partition[i]->numsect);

			if (cyl * cyl_size >= t_relsect &&
			    cyl * cyl_size < t_relsect + t_numsect) {
				(void) printf(E_LINE);
				(void) printf(
				    "Cylinder %d is already allocated"
				    "\nretry the operation.",
				    cyl);
				return (-1);
			}

			if (cyl * cyl_size < t_relsect &&
			    (cyl + cylen - 1) * cyl_size > t_relsect) {
				(void) printf(E_LINE);
				(void) printf(
				    "Maximum size for partition is %u cylinders"
				    "\nretry the operation.",
				    (t_relsect - cyl * cyl_size) / cyl_size);
				return (-1);
			}
		}

		/* Verify partition doesn't exceed disk size */
		if (cyl + cylen > Numcyl) {
			(void) printf(E_LINE);
			(void) printf(
			    "Maximum size for partition is %d cylinders;"
			    "\nretry the operation.",
			    Numcyl - cyl);
			return (-1);
		}

		/* Verify DOS12 partition doesn't exceed max size of 32MB. */
		if ((tsystid == DOSOS12) &&
		    ((long)((long)cylen * cyl_size) > MAXDOS)) {
			(void) printf(E_LINE);
			(void) printf(
			    "Maximum size for a %s partition is %ld cylinders;"
			    "\nretry the operation.",
			    Dstr, MAXDOS / (int)(cyl_size));
			return (-1);
		}

		(void) printf(E_LINE);
		i = insert_tbl(tsystid, 0, 0, 0, 0, 0, 0, 0,
		    cyl * cyl_size, cylen * cyl_size);
		if (i < 0)
			return (-1);

		if (verify_tbl() < 0) {
			(void) printf(E_LINE);
			(void) printf("fdisk: Cannot create partition table\n");
			return (-1);
		}

		return (i);
	}
}

/*
 * dispmenu
 * Display command menu (interactive mode).
 */
static void
dispmenu(void)
{
	(void) printf(M_LINE);
	(void) printf(
	    "SELECT ONE OF THE FOLLOWING:\n"
	    "   1. Create a partition\n"
	    "   2. Specify the active partition\n"
	    "   3. Delete a partition\n"
	    "   4. Change between Solaris and Solaris2 Partition IDs\n"
	    "   5. Exit (update disk configuration and exit)\n"
	    "   6. Cancel (exit without updating disk configuration)\n");
}

/*
 * pchange
 * Change the ACTIVE designation of a partition.
 */
static int
pchange(void)
{
	char s[80];
	int i, j;

	for (;;) {
		(void) printf(Q_LINE);
			{
			(void) printf(
			    "Specify the partition number to boot from"
			    " (or specify 0 for none): ");
			}
		(void) gets(s);
		rm_blanks(s);
		if ((s[1] != 0) || (s[0] < '0') || (s[0] > '4')) {
			(void) printf(E_LINE);
			(void) printf(
			    "Invalid response, please specify a number"
			    " between 0 and 4.\n");
		} else {
			break;
		}
	}
	if (s[0] == '0') {	/* No active partitions */
		for (i = 0; i < FD_NUMPART; i++) {
			if (Table[i].systid != UNUSED &&
			    Table[i].bootid == ACTIVE)
				Table[i].bootid = 0;
		}
		(void) printf(E_LINE);
			(void) printf(
			    "No partition is currently marked as active.");
		return (0);
	} else {	/* User has selected a partition to be active */
		i = s[0] - '1';
		if (Table[i].systid == UNUSED) {
			(void) printf(E_LINE);
			(void) printf("Partition does not exist.");
			return (-1);
		}
		/* a DOS-DATA or EXT-DOS partition cannot be active */
		else if ((Table[i].systid == DOSDATA) ||
		    (Table[i].systid == EXTDOS) ||
		    (Table[i].systid == FDISK_EXTLBA)) {
			(void) printf(E_LINE);
			(void) printf(
			    "DOS-DATA, EXT_DOS and EXT_DOS_LBA partitions "
			    "cannot be made active.\n");
			(void) printf("Select another partition.");
			return (-1);
		}
		Table[i].bootid = ACTIVE;
		for (j = 0; j < FD_NUMPART; j++) {
			if (j != i)
			Table[j].bootid = 0;
		}
	}
	(void) printf(E_LINE);
		{
		(void) printf(
		    "Partition %d is now active. The system will start up"
		    " from this\n", i + 1);
		(void) printf("partition after the next reboot.");
		}
	return (1);
}

/*
 * Change between SOLARIS and SOLARIS2 partition id
 */
static int
ppartid(void)
{
	char	*p, s[80];
	int	i;

	for (;;) {
		(void) printf(Q_LINE);
		(void) printf("Specify the partition number to change"
		    " (or enter 0 to exit): ");
		if (!fgets(s, sizeof (s), stdin))
			return (1);
		i = strtol(s, &p, 10);

		if (*p != '\n' || i < 0 || i > FD_NUMPART) {
			(void) printf(E_LINE);
			(void) printf(
			    "Invalid response, retry the operation.\n");
			continue;
		}

		if (i == 0) {
			/* exit delete command */
			(void) printf(E_LINE); /* clear error message */
			return (1);
		}

		i -= 1;
		if (Table[i].systid == SUNIXOS) {
			Table[i].systid = SUNIXOS2;
		} else if (Table[i].systid == SUNIXOS2) {
			Table[i].systid = SUNIXOS;
		} else {
			(void) printf(E_LINE);
			(void) printf(
			    "Partition %d is not a Solaris partition.",
			    i + 1);
			continue;
		}

		(void) printf(E_LINE);
		(void) printf("Partition %d has been changed.", i + 1);
		return (1);
	}
}

/*
 * pdelete
 * Remove partition entry from the table (interactive mode).
 */
static char
pdelete(void)
{
	char s[80];
	int i, j;
	char pactive;

DEL1:	(void) printf(Q_LINE);
	(void) printf("Specify the partition number to delete"
	    " (or enter 0 to exit): ");
	(void) gets(s);
	rm_blanks(s);
	if ((s[0] == '0')) {	/* exit delete command */
		(void) printf(E_LINE);	/* clear error message */
		return (1);
	}
	/* Accept only a single digit between 1 and 4 */
	if (s[1] != 0 || (i = atoi(s)) < 1 || i > FD_NUMPART) {
		(void) printf(E_LINE);
		(void) printf("Invalid response, retry the operation.\n");
		goto DEL1;
	} else {		/* Found a digit between 1 and 4 */
		--i;	/* Structure begins with element 0 */
	}

	if (Table[i].systid == UNUSED) {
		(void) printf(E_LINE);
		(void) printf("Partition %d does not exist.", i + 1);
		return (-1);
	}

	(void) printf(Q_LINE);
	(void) printf("Are you sure you want to delete partition %d?"
	    " This will make all files and \n", i + 1);
	(void) printf("programs in this partition inaccessible (type"
	    " \"y\" or \"n\"). ");

	(void) printf(E_LINE);
	if (! yesno()) {
		return (1);
	}

	if (Table[i].bootid == ACTIVE) {
		pactive = 1;
	} else {
		pactive = 0;
	}

	for (j = i; j < FD_NUMPART - 1; j++) {
		Table[j] = Table[j + 1];
	}

	Table[j].systid = UNUSED;
	Table[j].numsect = 0;
	Table[j].relsect = 0;
	Table[j].bootid = 0;
	(void) printf(E_LINE);
	(void) printf("Partition %d has been deleted.", i + 1);

	if (pactive) {
		(void) printf(" This was the active partition.");
	}

	return (1);
}

/*
 * rm_blanks
 * Remove blanks from strings of user responses.
 */
static void
rm_blanks(char *s)
{
	register int i, j;

	for (i = 0; i < CBUFLEN; i++) {
		if ((s[i] == ' ') || (s[i] == '\t'))
			continue;
		else
			/* Found first non-blank character of the string */
			break;
	}
	for (j = 0; i < CBUFLEN; j++, i++) {
		if ((s[j] = s[i]) == '\0') {
			/* Reached end of string */
			return;
		}
	}
}

/*
 * getcyl
 * Take the user-specified cylinder number and convert it from a
 * string to a decimal value.
 */
static int
getcyl(void)
{
int slen, i, j;
unsigned int cyl;
	(void) gets(s);
	rm_blanks(s);
	slen = strlen(s);
	j = 1;
	cyl = 0;
	for (i = slen - 1; i >= 0; i--) {
		if (s[i] < '0' || s[i] > '9') {
			return (-1);
		}
		cyl += (j * (s[i] - '0'));
		j *= 10;
	}
	return (cyl);
}

/*
 * disptbl
 * Display the current fdisk table; determine percentage
 * of the disk used for each partition.
 */
static void
disptbl(void)
{
	int i;
	unsigned int startcyl, endcyl, length, percent, remainder;
	char *stat, *type;

	if ((heads == 0) || (sectors == 0)) {
		(void) printf("WARNING: critical disk geometry information"
		    " missing!\n");
		(void) printf("\theads = %d, sectors = %d\n", heads, sectors);
		exit(1);
	}

	(void) printf(HOME);
	(void) printf(T_LINE);
	(void) printf("             Total disk size is %d cylinders\n", Numcyl);
	(void) printf("             Cylinder size is %d (512 byte) blocks\n\n",
	    heads * sectors);
	(void) printf(
	    "                                               Cylinders\n");
	(void) printf(
	    "      Partition   Status    Type          Start   End   Length"
	    "    %%\n");
	(void) printf(
	    "      =========   ======    ============  =====   ===   ======"
	    "   ===");
	for (i = 0; i < FD_NUMPART; i++) {
		if (Table[i].systid == UNUSED) {
			(void) printf("\n");
			(void) printf(CLR_LIN);
			continue;
		}
		if (Table[i].bootid == ACTIVE)
			stat = Actvstr;
		else
			stat = NAstr;
		switch (Table[i].systid) {
		case UNIXOS:
			type = Ustr;
			break;
		case SUNIXOS:
			type = SUstr;
			break;
		case SUNIXOS2:
			type = SU2str;
			break;
		case X86BOOT:
			type = X86str;
			break;
		case DOSOS12:
			type = Dstr;
			break;
		case DOSOS16:
			type = D16str;
			break;
		case EXTDOS:
			type = EDstr;
			break;
		case DOSDATA:
			type = DDstr;
			break;
		case DOSHUGE:
			type = DBstr;
			break;
		case PCIXOS:
			type = PCstr;
			break;
		case DIAGPART:
			type = DIAGstr;
			break;
		case FDISK_IFS:
			type = IFSstr;
			break;
		case FDISK_AIXBOOT:
			type = AIXstr;
			break;
		case FDISK_AIXDATA:
			type = AIXDstr;
			break;
		case FDISK_OS2BOOT:
			type = OS2str;
			break;
		case FDISK_WINDOWS:
			type = WINstr;
			break;
		case FDISK_EXT_WIN:
			type = EWINstr;
			break;
		case FDISK_FAT95:
			type = FAT95str;
			break;
		case FDISK_EXTLBA:
			type = EXTLstr;
			break;
		case FDISK_LINUX:
			type = LINUXstr;
			break;
		case FDISK_CPM:
			type = CPMstr;
			break;
		case FDISK_NOVELL3:
			type = NOVstr;
			break;
		case FDISK_QNX4:
			type = QNXstr;
			break;
		case FDISK_QNX42:
			type = QNX2str;
			break;
		case FDISK_QNX43:
			type = QNX3str;
			break;
		case FDISK_LINUXNAT:
			type = LINNATstr;
			break;
		case FDISK_NTFSVOL1:
			type = NTFSVOL1str;
			break;
		case FDISK_NTFSVOL2:
			type = NTFSVOL2str;
			break;
		case FDISK_BSD:
			type = BSDstr;
			break;
		case FDISK_NEXTSTEP:
			type = NEXTSTEPstr;
			break;
		case FDISK_BSDIFS:
			type = BSDIFSstr;
			break;
		case FDISK_BSDISWAP:
			type = BSDISWAPstr;
			break;
		case EFI_PMBR:
			type = EFIstr;
			break;
		default:
			type = Ostr;
			break;
		}
		startcyl = lel(Table[i].relsect) /
		    (unsigned long)(heads * sectors);
		length = lel(Table[i].numsect) /
		    (unsigned long)(heads * sectors);
		if (lel(Table[i].numsect) % (unsigned long)(heads * sectors))
			length++;
		endcyl = startcyl + length - 1;
		percent = length * 100 / Numcyl;
		if ((remainder = (length * 100 % Numcyl)) != 0) {
			if ((remainder * 100 / Numcyl) > 50) {
				/* round up */
				percent++;
			}
			/* Else leave the percent as is since it's already */
			/* rounded down */
		}
		if (percent > 100)
			percent = 100;
		(void) printf(
		    "\n          %d       %s    %-12.12s   %4d  %4d    %4d"
		    "    %3d",
		    i + 1, stat, type, startcyl, endcyl, length, percent);
	}
	/* Print warning message if table is empty */
	if (Table[0].systid == UNUSED) {
		(void) printf(W_LINE);
		(void) printf("WARNING: no partitions are defined!");
	} else {
		/* Clear the warning line */
		(void) printf(W_LINE);
	}
}

/*
 * print_Table
 * Write the detailed fdisk table to standard error for
 * the selected disk device.
 */
static void
print_Table(void)
{
	int i;

	(void) fprintf(stderr,
	    "  SYSID ACT BHEAD BSECT BEGCYL   EHEAD ESECT ENDCYL   RELSECT"
	    "   NUMSECT\n");

	for (i = 0; i < FD_NUMPART; i++) {
		(void) fprintf(stderr, "  %-5d ", Table[i].systid);
		(void) fprintf(stderr, "%-3d ", Table[i].bootid);
		(void) fprintf(stderr, "%-5d ", Table[i].beghead);
		(void) fprintf(stderr, "%-5d ", Table[i].begsect & 0x3f);
		(void) fprintf(stderr, "%-8d ",
		    (((uint_t)Table[i].begsect & 0xc0) << 2) + Table[i].begcyl);

		(void) fprintf(stderr, "%-5d ", Table[i].endhead);
		(void) fprintf(stderr, "%-5d ", Table[i].endsect & 0x3f);
		(void) fprintf(stderr, "%-8d ",
		    (((uint_t)Table[i].endsect & 0xc0) << 2) + Table[i].endcyl);
		(void) fprintf(stderr, "%-9d ", lel(Table[i].relsect));
		(void) fprintf(stderr, "%-9d\n", lel(Table[i].numsect));

	}
}

/*
 * copy_Table_to_Old_Table
 * Copy Table into Old_Table. The function only copies the systid,
 * numsect, relsect, and bootid values because they are the only
 * ones compared when determining if Table has changed.
 */
static void
copy_Table_to_Old_Table(void)
{
	int i;
	for (i = 0; i < FD_NUMPART; i++)  {
		(void) memcpy(&Old_Table[i], &Table[i], sizeof (Table[0]));
	}
}

/*
 * nulltbl
 * Zero out the systid, numsect, relsect, and bootid values in the
 * fdisk table.
 */
static void
nulltbl(void)
{
	int i;

	for (i = 0; i < FD_NUMPART; i++)  {
		Table[i].systid = UNUSED;
		Table[i].numsect = lel(UNUSED);
		Table[i].relsect = lel(UNUSED);
		Table[i].bootid = 0;
	}
}

/*
 * copy_Bootblk_to_Table
 * Copy the bytes from the boot record to an internal "Table".
 * All unused are padded with zeros starting at offset 446.
 */
static void
copy_Bootblk_to_Table(void)
{
	int i, j;
	char *bootptr;
	struct ipart iparts[FD_NUMPART];

	/* Get an aligned copy of the partition tables */
	(void) memcpy(iparts, Bootblk->parts, sizeof (iparts));
	bootptr = (char *)iparts;	/* Points to start of partition table */
	if (les(Bootblk->signature) != MBB_MAGIC)  {
		/* Signature is missing */
		nulltbl();
		(void) memcpy(Bootblk->bootinst, &BootCod, BOOTSZ);
		return;
	}
	/*
	 * When the DOS fdisk command deletes a partition, it is not
	 * recognized by the old algorithm.  The algorithm that
	 * follows looks at each entry in the Bootrec and copies all
	 * those that are valid.
	 */
	j = 0;
	for (i = 0; i < FD_NUMPART; i++) {
		if (iparts[i].systid == 0) {
			/* Null entry */
			bootptr += sizeof (struct ipart);
		} else {
			fill_ipart(bootptr, &Table[j]);
			j++;
			bootptr += sizeof (struct ipart);
		}
	}
	for (i = j; i < FD_NUMPART; i++) {
		Table[i].systid = UNUSED;
		Table[i].numsect = lel(UNUSED);
		Table[i].relsect = lel(UNUSED);
		Table[i].bootid = 0;

	}
	/* For now, always replace the bootcode with ours */
	(void) memcpy(Bootblk->bootinst, &BootCod, BOOTSZ);
	copy_Table_to_Bootblk();
}

/*
 * fill_ipart
 * Initialize ipart structure values.
 */
static void
fill_ipart(char *bootptr, struct ipart *partp)
{
#ifdef sparc
	/* Packing struct ipart for Sparc */
	partp->bootid	= getbyte(&bootptr);
	partp->beghead	= getbyte(&bootptr);
	partp->begsect	= getbyte(&bootptr);
	partp->begcyl	= getbyte(&bootptr);
	partp->systid	= getbyte(&bootptr);
	partp->endhead	= getbyte(&bootptr);
	partp->endsect	= getbyte(&bootptr);
	partp->endcyl	= getbyte(&bootptr);
	partp->relsect	= (int32_t)getlong(&bootptr);
	partp->numsect	= (int32_t)getlong(&bootptr);
#else
	*partp = *(struct ipart *)bootptr;
#endif
}

/*
 * getbyte, getlong
 * 	Get a byte, a short, or a long (SPARC only).
 */
#ifdef sparc
uchar_t
getbyte(char **bp)
{
	uchar_t	b;

	b = (uchar_t)**bp;
	*bp = *bp + 1;
	return (b);
}

uint32_t
getlong(char **bp)
{
	int32_t	b, bh, bl;

	bh = ((**bp) << 8) | *(*bp + 1);
	*bp += 2;
	bl = ((**bp) << 8) | *(*bp + 1);
	*bp += 2;

	b = (bh << 16) | bl;
	return ((uint32_t)b);
}
#endif

/*
 * copy_Table_to_Bootblk
 * Copy the table into the 512 boot record. Note that the unused
 * entries will always be the last ones in the table and they are
 * marked with 100 in sysind. The the unused portion of the table
 * is padded with zeros in the bytes after the used entries.
 */
static void
copy_Table_to_Bootblk(void)
{
	struct ipart *boot_ptr, *tbl_ptr;

	boot_ptr = (struct ipart *)Bootblk->parts;
	tbl_ptr = (struct ipart *)&Table[0].bootid;
	for (; tbl_ptr < (struct ipart *)&Table[FD_NUMPART].bootid;
	    tbl_ptr++, boot_ptr++) {
		if (tbl_ptr->systid == UNUSED)
			(void) memset(boot_ptr, 0, sizeof (struct ipart));
		else
			(void) memcpy(boot_ptr, tbl_ptr, sizeof (struct ipart));
	}
	Bootblk->signature = les(MBB_MAGIC);
}

/*
 * TableChanged
 * 	Check for any changes in the partition table.
 */
static int
TableChanged(void)
{
	int i, changed;

	changed = 0;
	for (i = 0; i < FD_NUMPART; i++) {
		if (memcmp(&Old_Table[i], &Table[i], sizeof (Table[0])) != 0) {
			/* Partition table changed, write back to disk */
			changed = 1;
		}
	}

	return (changed);
}

/*
 * ffile_write
 * 	Display contents of partition table to standard output or
 *	another file name without writing it to the disk (-W file).
 */
static void
ffile_write(char *file)
{
	register int	i;
	FILE *fp;

	/*
	 * If file isn't standard output, then it's a file name.
	 * Open file and write it.
	 */
	if (file != (char *)stdout) {
		if ((fp = fopen(file, "w")) == NULL) {
			(void) fprintf(stderr,
			    "fdisk: Cannot open output file %s.\n",
			    file);
			exit(1);
		}
	}
	else
		fp = stdout;

	/*
	 * Write the fdisk table information
	 */
	(void) fprintf(fp, "\n* %s default fdisk table\n", Dfltdev);
	(void) fprintf(fp, "* Dimensions:\n");
	(void) fprintf(fp, "*   %4d bytes/sector\n", sectsiz);
	(void) fprintf(fp, "*   %4d sectors/track\n", sectors);
	(void) fprintf(fp, "*   %4d tracks/cylinder\n", heads);
	(void) fprintf(fp, "*   %4d cylinders\n", Numcyl);
	(void) fprintf(fp, "*\n");
	/* Write virtual (HBA) geometry, if required	*/
	if (v_flag) {
		(void) fprintf(fp, "* HBA Dimensions:\n");
		(void) fprintf(fp, "*   %4d bytes/sector\n", sectsiz);
		(void) fprintf(fp, "*   %4d sectors/track\n", hba_sectors);
		(void) fprintf(fp, "*   %4d tracks/cylinder\n", hba_heads);
		(void) fprintf(fp, "*   %4d cylinders\n", hba_Numcyl);
		(void) fprintf(fp, "*\n");
	}
	(void) fprintf(fp, "* systid:\n");
	(void) fprintf(fp, "*    1: DOSOS12\n");
	(void) fprintf(fp, "*    2: PCIXOS\n");
	(void) fprintf(fp, "*    4: DOSOS16\n");
	(void) fprintf(fp, "*    5: EXTDOS\n");
	(void) fprintf(fp, "*    6: DOSBIG\n");
	(void) fprintf(fp, "*    7: FDISK_IFS\n");
	(void) fprintf(fp, "*    8: FDISK_AIXBOOT\n");
	(void) fprintf(fp, "*    9: FDISK_AIXDATA\n");
	(void) fprintf(fp, "*   10: FDISK_0S2BOOT\n");
	(void) fprintf(fp, "*   11: FDISK_WINDOWS\n");
	(void) fprintf(fp, "*   12: FDISK_EXT_WIN\n");
	(void) fprintf(fp, "*   14: FDISK_FAT95\n");
	(void) fprintf(fp, "*   15: FDISK_EXTLBA\n");
	(void) fprintf(fp, "*   18: DIAGPART\n");
	(void) fprintf(fp, "*   65: FDISK_LINUX\n");
	(void) fprintf(fp, "*   82: FDISK_CPM\n");
	(void) fprintf(fp, "*   86: DOSDATA\n");
	(void) fprintf(fp, "*   98: OTHEROS\n");
	(void) fprintf(fp, "*   99: UNIXOS\n");
	(void) fprintf(fp, "*  101: FDISK_NOVELL3\n");
	(void) fprintf(fp, "*  119: FDISK_QNX4\n");
	(void) fprintf(fp, "*  120: FDISK_QNX42\n");
	(void) fprintf(fp, "*  121: FDISK_QNX43\n");
	(void) fprintf(fp, "*  130: SUNIXOS\n");
	(void) fprintf(fp, "*  131: FDISK_LINUXNAT\n");
	(void) fprintf(fp, "*  134: FDISK_NTFSVOL1\n");
	(void) fprintf(fp, "*  135: FDISK_NTFSVOL2\n");
	(void) fprintf(fp, "*  165: FDISK_BSD\n");
	(void) fprintf(fp, "*  167: FDISK_NEXTSTEP\n");
	(void) fprintf(fp, "*  183: FDISK_BSDIFS\n");
	(void) fprintf(fp, "*  184: FDISK_BSDISWAP\n");
	(void) fprintf(fp, "*  190: X86BOOT\n");
	(void) fprintf(fp, "*  191: SUNIXOS2\n");
	(void) fprintf(fp, "*  238: EFI_PMBR\n");
	(void) fprintf(fp, "*  239: EFI_FS\n");
	(void) fprintf(fp, "*\n");
	(void) fprintf(fp,
	    "\n* Id    Act  Bhead  Bsect  Bcyl    Ehead  Esect  Ecyl"
	    "    Rsect    Numsect\n");
	for (i = 0; i < FD_NUMPART; i++) {
		if (Table[i].systid != UNUSED)
			(void) fprintf(fp,
			    "  %-5d %-4d %-6d %-6d %-7d %-6d %-6d %-7d %-8d"
			    " %-8d\n",
			    Table[i].systid,
			    Table[i].bootid,
			    Table[i].beghead,
			    Table[i].begsect & 0x3f,
			    ((Table[i].begcyl & 0xff) | ((Table[i].begsect &
			    0xc0) << 2)),
			    Table[i].endhead,
			    Table[i].endsect & 0x3f,
			    ((Table[i].endcyl & 0xff) | ((Table[i].endsect &
			    0xc0) << 2)),
			    lel(Table[i].relsect),
			    lel(Table[i].numsect));
	}
	if (fp != stdout)
		(void) fclose(fp);
}

/*
 * fix_slice
 * 	Read the VTOC table on the Solaris partition and check that no
 *	slices exist that extend past the end of the Solaris partition.
 *	If no Solaris partition exists, nothing is done.
 */
static void
fix_slice(void)
{
	int	i;
	int	numsect;

	if (io_image) {
		return;
	}

	for (i = 0; i < FD_NUMPART; i++) {
		if (Table[i].systid == SUNIXOS || Table[i].systid == SUNIXOS2) {
			/*
			 * Only the size matters (not starting point), since
			 * VTOC entries are relative to the start of
			 * the partition.
			 */
			numsect = lel(Table[i].numsect);
			break;
		}
	}

	if (i >= FD_NUMPART) {
		if (!io_nifdisk) {
			(void) fprintf(stderr,
			    "fdisk: No Solaris partition found - VTOC not"
			    " checked.\n");
		}
		return;
	}

	if (readvtoc() != VTOC_OK) {
		exit(1);		/* Failed to read the VTOC */
	}
	for (i = 0; i < V_NUMPAR; i++) {
		/* Special case for slice two (entire disk) */
		if (i == 2) {
			if (disk_vtoc.v_part[i].p_start != 0) {
				(void) fprintf(stderr,
				    "slice %d starts at %ld, is not at"
				    " start of partition",
				    i, disk_vtoc.v_part[i].p_start);
				if (!io_nifdisk) {
					(void) printf(" adjust ?:");
					if (yesno())
						disk_vtoc.v_part[i].p_start = 0;
				} else {
					disk_vtoc.v_part[i].p_start = 0;
					(void) fprintf(stderr, " adjusted!\n");
				}

			}
			if (disk_vtoc.v_part[i].p_size != numsect) {
				(void) fprintf(stderr,
				    "slice %d size %ld does not cover"
				    " complete partition",
				    i, disk_vtoc.v_part[i].p_size);
				if (!io_nifdisk) {
					(void) printf(" adjust ?:");
					if (yesno())
						disk_vtoc.v_part[i].p_size =
						    numsect;
				} else {
					disk_vtoc.v_part[i].p_size = numsect;
					(void) fprintf(stderr, " adjusted!\n");
				}
			}
			if (disk_vtoc.v_part[i].p_tag != V_BACKUP) {
				(void) fprintf(stderr,
				    "slice %d tag was %d should be %d",
				    i, disk_vtoc.v_part[i].p_tag,
				    V_BACKUP);
				if (!io_nifdisk) {
					(void) printf(" fix ?:");
					if (yesno())
						disk_vtoc.v_part[i].p_tag =
						    V_BACKUP;
				} else {
					disk_vtoc.v_part[i].p_tag = V_BACKUP;
					(void) fprintf(stderr, " fixed!\n");
				}
			}
			continue;
		}
		if (io_ADJT) {
			if (disk_vtoc.v_part[i].p_start > numsect ||
			    disk_vtoc.v_part[i].p_start +
			    disk_vtoc.v_part[i].p_size > numsect) {
				(void) fprintf(stderr,
				    "slice %d (start %ld, end %ld)"
				    " is larger than the partition",
				    i, disk_vtoc.v_part[i].p_start,
				    disk_vtoc.v_part[i].p_start +
				    disk_vtoc.v_part[i].p_size);
				if (!io_nifdisk) {
					(void) printf(" remove ?:");
					if (yesno()) {
						disk_vtoc.v_part[i].p_size = 0;
						disk_vtoc.v_part[i].p_start = 0;
						disk_vtoc.v_part[i].p_tag = 0;
						disk_vtoc.v_part[i].p_flag = 0;
					}
				} else {
					disk_vtoc.v_part[i].p_size = 0;
					disk_vtoc.v_part[i].p_start = 0;
					disk_vtoc.v_part[i].p_tag = 0;
					disk_vtoc.v_part[i].p_flag = 0;
					(void) fprintf(stderr,
					    " removed!\n");
				}
			}
			continue;
		}
		if (disk_vtoc.v_part[i].p_start > numsect) {
			(void) fprintf(stderr,
			    "slice %d (start %ld) is larger than the partition",
			    i, disk_vtoc.v_part[i].p_start);
			if (!io_nifdisk) {
				(void) printf(" remove ?:");
				if (yesno()) {
					disk_vtoc.v_part[i].p_size = 0;
					disk_vtoc.v_part[i].p_start = 0;
					disk_vtoc.v_part[i].p_tag = 0;
					disk_vtoc.v_part[i].p_flag = 0;
				}
			} else {
				disk_vtoc.v_part[i].p_size = 0;
				disk_vtoc.v_part[i].p_start = 0;
				disk_vtoc.v_part[i].p_tag = 0;
				disk_vtoc.v_part[i].p_flag = 0;
				(void) fprintf(stderr,
				" removed!\n");
			}
		} else if (disk_vtoc.v_part[i].p_start
		    + disk_vtoc.v_part[i].p_size > numsect) {
			(void) fprintf(stderr,
			    "slice %d (end %ld) is larger"
			    " than the partition",
			    i,
			    disk_vtoc.v_part[i].p_start +
			    disk_vtoc.v_part[i].p_size);
			if (!io_nifdisk) {
				(void) printf(" adjust ?:");
				if (yesno()) {
					disk_vtoc.v_part[i].p_size = numsect;
				}
			} else {
				disk_vtoc.v_part[i].p_size = numsect;
				(void) fprintf(stderr, " adjusted!\n");
			}
		}
	}
#if 1		/* bh for now */
	/* Make the VTOC look sane - ha ha */
	disk_vtoc.v_version = V_VERSION;
	disk_vtoc.v_sanity = VTOC_SANE;
	disk_vtoc.v_nparts = V_NUMPAR;
	if (disk_vtoc.v_sectorsz == 0)
		disk_vtoc.v_sectorsz = NBPSCTR;
#endif

	/* Write the VTOC back to the disk */
	if (!io_readonly)
		(void) writevtoc();
}

/*
 * yesno
 * Get yes or no answer. Return 1 for yes and 0 for no.
 */

static int
yesno(void)
{
	char	s[80];

	for (;;) {
		(void) gets(s);
		rm_blanks(s);
		if ((s[1] != 0) || ((s[0] != 'y') && (s[0] != 'n'))) {
			(void) printf(E_LINE);
			(void) printf("Please answer with \"y\" or \"n\": ");
			continue;
		}
		if (s[0] == 'y')
			return (1);
		else
			return (0);
	}
}

/*
 * readvtoc
 * 	Read the VTOC from the Solaris partition of the device.
 */
static int
readvtoc(void)
{
	int	i;
	int	retval = VTOC_OK;

	if ((i = read_vtoc(Dev, &disk_vtoc)) < VTOC_OK) {
		if (i == VT_EINVAL) {
			(void) fprintf(stderr, "fdisk: Invalid VTOC.\n");
			vt_inval++;
			retval = VTOC_INVAL;
		} else if (i == VT_ENOTSUP) {
			(void) fprintf(stderr, "fdisk: partition may have EFI "
			    "GPT\n");
			retval = VTOC_NOTSUP;
		} else {
			(void) fprintf(stderr, "fdisk: Cannot read VTOC.\n");
			retval = VTOC_RWERR;
		}
	}
	return (retval);
}

/*
 * writevtoc
 * 	Write the VTOC to the Solaris partition on the device.
 */
static int
writevtoc(void)
{
	int	i;
	int	retval = 0;

	if ((i = write_vtoc(Dev, &disk_vtoc)) != 0) {
		if (i == VT_EINVAL) {
			(void) fprintf(stderr,
			    "fdisk: Invalid entry exists in VTOC.\n");
			retval = VTOC_INVAL;
		} else if (i == VT_ENOTSUP) {
			(void) fprintf(stderr, "fdisk: partition may have EFI "
			    "GPT\n");
			retval = VTOC_NOTSUP;
		} else {
			(void) fprintf(stderr, "fdisk: Cannot write VTOC.\n");
			retval = VTOC_RWERR;
		}
	}
	return (retval);
}

/*
 * efi_ioctl
 * issues DKIOCSETEFI IOCTL
 * (duplicate of private efi_ioctl() in rdwr_efi.c
 */
static int
efi_ioctl(int fd, int cmd, dk_efi_t *dk_ioc)
{
	void *data = dk_ioc->dki_data;
	int error;

	dk_ioc->dki_data_64 = (uintptr_t)data;
	error = ioctl(fd, cmd, (void *)dk_ioc);

	return (error);
}

/*
 * clear_efi
 * Clear EFI labels from the EFI_PMBR partition on the device
 * This function is modeled on the libefi(3LIB) call efi_write()
 */
static int
clear_efi(void)
{
	struct dk_gpt	*efi_vtoc;
	dk_efi_t	dk_ioc;

	/*
	 * see if we can read the EFI label
	 */
	if (efi_alloc_and_read(Dev, &efi_vtoc) < 0) {
		return (VT_ERROR);
	}

	/*
	 * set up the dk_ioc structure for writing
	 */
	dk_ioc.dki_lba = 1;
	dk_ioc.dki_length = EFI_MIN_ARRAY_SIZE + efi_vtoc->efi_lbasize;

	if ((dk_ioc.dki_data = calloc(dk_ioc.dki_length, 1)) == NULL) {
		return (VT_ERROR);
	}

	/*
	 * clear the primary label
	 */
	if (io_debug) {
		(void) fprintf(stderr,
		    "\tClearing primary EFI label at block %lld\n",
		    dk_ioc.dki_lba);
	}

	if (efi_ioctl(Dev, DKIOCSETEFI, &dk_ioc) == -1) {
		free(dk_ioc.dki_data);
		switch (errno) {
			case EIO:
				return (VT_EIO);
			case EINVAL:
				return (VT_EINVAL);
			default:
				return (VT_ERROR);
		}
	}

	/*
	 * clear the backup partition table
	 */
	dk_ioc.dki_lba = efi_vtoc->efi_last_u_lba + 1;
	dk_ioc.dki_length -= efi_vtoc->efi_lbasize;
	dk_ioc.dki_data++;
	if (io_debug) {
		(void) fprintf(stderr,
		    "\tClearing backup partition table at block %lld\n",
		    dk_ioc.dki_lba);
	}

	if (efi_ioctl(Dev, DKIOCSETEFI, &dk_ioc) == -1) {
		(void) fprintf(stderr, "\tUnable to clear backup EFI label at "
		    "block %llu; errno %d\n", efi_vtoc->efi_last_u_lba + 1,
		    errno);
	}

	/*
	 * clear the backup label
	 */
	dk_ioc.dki_lba = efi_vtoc->efi_last_lba;
	dk_ioc.dki_length = efi_vtoc->efi_lbasize;
	dk_ioc.dki_data--;
	if (io_debug) {
		(void) fprintf(stderr, "\tClearing backup label at block "
		    "%lld\n", dk_ioc.dki_lba);
	}

	if (efi_ioctl(Dev, DKIOCSETEFI, &dk_ioc) == -1) {
		(void) fprintf(stderr,
		    "\tUnable to clear backup EFI label at "
		    "block %llu; errno %d\n",
		    efi_vtoc->efi_last_lba,
		    errno);
	}

	free(dk_ioc.dki_data);
	efi_free(efi_vtoc);

	return (0);
}

/*
 * clear_vtoc
 * 	Clear the VTOC from the current or previous Solaris partition on the
 *      device.
 */
static void
clear_vtoc(int table, int part)
{
	struct ipart *clr_table;
	struct dk_label disk_label;
	int pcyl, ncyl, backup_block, solaris_offset, count, bytes, seek_byte;

#ifdef DEBUG
	struct dk_label	read_label;
#endif /* DEBUG */

	if (table == OLD) {
		clr_table = &Old_Table[part];
	} else {
		clr_table = &Table[part];
	}

	(void) memset(&disk_label, 0, sizeof (struct dk_label));

	seek_byte = (lel(clr_table->relsect) * sectsiz) + VTOC_OFFSET;

	if (io_debug) {
		(void) fprintf(stderr, "\tClearing primary VTOC at byte %d\n",
		    seek_byte);
	}

	if (lseek(Dev, seek_byte, SEEK_SET) == -1) {
		(void) fprintf(stderr,
		    "\tError seeking to primary label at byte %d\n",
		    seek_byte);
		return;
	}

	bytes = write(Dev, &disk_label, sizeof (struct dk_label));

	if (bytes != sizeof (struct dk_label)) {
		(void) fprintf(stderr,
		    "\tWarning: only %d bytes written to clear primary VTOC!\n",
		    bytes);
	}

#ifdef DEBUG
	if (lseek(Dev, seek_byte, SEEK_SET) == -1) {
		(void) fprintf(stderr,
		    "DEBUG: Error seeking to primary label at byte %d\n",
		    seek_byte);
		return;
	} else {
		(void) fprintf(stderr, "DEBUG: Successful lseek() to byte %d\n",
		    seek_byte);
	}

	bytes = read(Dev, &read_label, sizeof (struct dk_label));

	if (bytes != sizeof (struct dk_label)) {
		(void) fprintf(stderr,
		    "DEBUG: Warning: only %d bytes read of label\n",
		    bytes);
	}

	if (memcmp(&disk_label, &read_label, sizeof (struct dk_label)) != 0) {
		(void) fprintf(stderr,
		    "DEBUG: Warning: disk_label and read_label differ!!!\n");
	} else {
		(void) fprintf(stderr, "DEBUG Good compare of disk_label and "
		    "read_label\n");
	}
#endif /* DEBUG */

	/* Clear backup label */
	pcyl = lel(clr_table->numsect) / (heads * sectors);
	solaris_offset = lel(clr_table->relsect);
	ncyl = pcyl - acyl;

	backup_block = ((ncyl + acyl - 1) *
	    (heads * sectors)) + ((heads - 1) * sectors) + 1;

	for (count = 1; count < 6; count++) {
		seek_byte = (solaris_offset + backup_block) * 512;

		if (lseek(Dev, seek_byte, SEEK_SET) == -1) {
			(void) fprintf(stderr,
			    "\tError seeking to backup label at byte %d on "
			    "%s.\n", seek_byte, Dfltdev);
			return;
		}

		if (io_debug) {
			(void) fprintf(stderr, "\tClearing backup VTOC at"
			    " byte %d (block %d)\n",
			    (solaris_offset + backup_block) * 512,
			    (solaris_offset + backup_block));
		}

		bytes = write(Dev, &disk_label, sizeof (struct dk_label));

		if (bytes != sizeof (struct dk_label)) {
			(void) fprintf(stderr,
			    "\t\tWarning: only %d bytes written to "
			    "clear backup VTOC at block %d!\n", bytes,
			    (solaris_offset + backup_block));
		}

#ifdef DEBUG
	if (lseek(Dev, seek_byte, SEEK_SET) == -1) {
		(void) fprintf(stderr,
		    "DEBUG: Error seeking to backup label at byte %d\n",
		    seek_byte);
		return;
	} else {
		(void) fprintf(stderr, "DEBUG: Successful lseek() to byte %d\n",
		    seek_byte);
	}

	bytes = read(Dev, &read_label, sizeof (struct dk_label));

	if (bytes != sizeof (struct dk_label)) {
		(void) fprintf(stderr,
		    "DEBUG: Warning: only %d bytes read of backup label\n",
		    bytes);
	}

	if (memcmp(&disk_label, &read_label, sizeof (struct dk_label)) != 0) {
		(void) fprintf(stderr,
		    "DEBUG: Warning: disk_label and read_label differ!!!\n");
	} else {
		(void) fprintf(stderr,
		    "DEBUG: Good compare of disk_label and backup "
		    "read_label\n");
	}
#endif /* DEBUG */

		backup_block += 2;
	}
}

#define	FDISK_STANDARD_LECTURE \
	"Fdisk is normally used with the device that " \
	"represents the entire fixed disk.\n" \
	"(For example, /dev/rdsk/c0d0p0 on x86 or " \
	"/dev/rdsk/c0t5d0s2 on sparc).\n"

#define	FDISK_LECTURE_NOT_SECTOR_ZERO \
	"The device does not appear to include absolute\n" \
	"sector 0 of the PHYSICAL disk " \
	"(the normal location for an fdisk table).\n"

#define	FDISK_LECTURE_NOT_FULL \
	"The device does not appear to encompass the entire PHYSICAL disk.\n"

#define	FDISK_LECTURE_NO_VTOC \
	"Unable to find a volume table of contents.\n" \
	"Cannot verify the device encompasses the full PHYSICAL disk.\n"

#define	FDISK_LECTURE_NO_GEOM \
	"Unable to get geometry from device.\n" \
	"Cannot verify the device encompasses the full PHYSICAL disk.\n"

#define	FDISK_SHALL_I_CONTINUE \
	"Are you sure you want to continue? (y/n) "

/*
 *  lecture_and_query
 *	Called when a sanity check fails.  This routine gives a warning
 *	specific to the check that fails, followed by a generic lecture
 *	about the "right" device to supply as input.  Then, if appropriate,
 *	it will prompt the user on whether or not they want to continue.
 *	Inappropriate times for prompting are when the user has selected
 *	non-interactive mode or read-only mode.
 */
static int
lecture_and_query(char *warning, char *devname)
{
	if (io_nifdisk)
		return (0);

	(void) fprintf(stderr, "WARNING: Device %s: \n", devname);
	(void) fprintf(stderr, "%s", warning);
	(void) fprintf(stderr, FDISK_STANDARD_LECTURE);
	(void) fprintf(stderr, FDISK_SHALL_I_CONTINUE);

	return (yesno());
}

static void
sanity_check_provided_device(char *devname, int fd)
{
	struct vtoc v;
	struct dk_geom d;
	struct part_info pi;
	long totsize;
	int idx = -1;

	/*
	 *  First try the PARTINFO ioctl.  If it works, we will be able
	 *  to tell if they've specified the full disk partition by checking
	 *  to see if they've specified a partition that starts at sector 0.
	 */
	if (ioctl(fd, DKIOCPARTINFO, &pi) != -1) {
		if (pi.p_start != 0) {
			if (!lecture_and_query(FDISK_LECTURE_NOT_SECTOR_ZERO,
			    devname)) {
				(void) close(fd);
				exit(1);
			}
		}
	} else {
		if ((idx = read_vtoc(fd, &v)) < 0) {
			if (!lecture_and_query(FDISK_LECTURE_NO_VTOC,
			    devname)) {
				(void) close(fd);
				exit(1);
			}
			return;
		}
		if (ioctl(fd, DKIOCGGEOM, &d) == -1) {
			perror(devname);
			if (!lecture_and_query(FDISK_LECTURE_NO_GEOM,
			    devname)) {
				(void) close(fd);
				exit(1);
			}
			return;
		}
		totsize = d.dkg_ncyl * d.dkg_nhead * d.dkg_nsect;
		if (v.v_part[idx].p_size != totsize) {
			if (!lecture_and_query(FDISK_LECTURE_NOT_FULL,
			    devname)) {
				(void) close(fd);
				exit(1);
			}
		}
	}
}


/*
 * get_node
 * Called from main to construct the name of the device node to open.
 * Initially tries to stat the node exactly as provided, if that fails
 * we prepend the default path (/dev/rdsk/).
 */
static char *
get_node(char *devname)
{
	char *node;
	struct stat statbuf;
	size_t space;

	/* Don't do anything if we are skipping device checks */
	if (io_image)
		return (devname);

	node = devname;

	/* Try the node as provided first */
	if (stat(node, (struct stat *)&statbuf) == -1) {
		/*
		 * Copy the passed in string to a new buffer, prepend the
		 * default path and try again.
		 */
		space = strlen(DEFAULT_PATH) + strlen(devname) + 1;

		if ((node = malloc(space)) == NULL) {
			(void) fprintf(stderr, "fdisk: Unable to obtain memory "
			    "for device node.\n");
			exit(1);
		}

		/* Copy over the default path and the provided node */
		(void) strncpy(node, DEFAULT_PATH, strlen(DEFAULT_PATH));
		space -= strlen(DEFAULT_PATH);
		(void) strlcpy(node + strlen(DEFAULT_PATH), devname, space);

		/* Try to stat it again */
		if (stat(node, (struct stat *)&statbuf) == -1) {
			/* Failed all options, give up */
			(void) fprintf(stderr,
			    "fdisk: Cannot stat device %s.\n",
			    devname);
			exit(1);
		}
	}

	/* Make sure the device specified is the raw device */
	if ((statbuf.st_mode & S_IFMT) != S_IFCHR) {
		(void) fprintf(stderr,
		    "fdisk: %s must be a raw device.\n", node);
		exit(1);
	}

	return (node);
}
