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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 *
 *	Portions of this source code were provided by International
 *	Computers Limited (ICL) under a development agreement with AT&T.
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */
/*
 * Sun Microsystems version of fmthard:
 *
 * Supports the following arguments:
 *
 *	-i		Writes VTOC to stdout, rather than disk
 *	-q		Quick check: exit code 0 if VTOC ok
 *	-d <data>	Incremental changes to the VTOC
 *	-n <vname>	Change volume name to <vname>
 *	-s <file>	Read VTOC information from <file>, or stdin ("-")
 *	-u <state>	Reboot after writing VTOC, according to <state>:
 *				boot: AD_BOOT (standard reboot)
 *				firm: AD_IBOOT (interactive reboot)
 *
 * Note that fmthard cannot write a VTOC on an unlabeled disk.
 * You must use format or SunInstall for this purpose.
 * (NOTE: the above restriction only applies on Sparc systems).
 *
 * The primary motivation for fmthard is to duplicate the
 * partitioning from disk to disk:
 *
 *	prtvtoc /dev/rdsk/c0t0d0s2 | fmthard -s - /dev/rdsk/c0t1d0s2
 */

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/int_limits.h>
#include <sys/stat.h>
#include <sys/uadmin.h>
#include <sys/open.h>
#include <sys/vtoc.h>
#include <sys/dkio.h>
#include <sys/isa_defs.h>
#include <sys/efi_partition.h>

#if defined(_SUNOS_VTOC_16)
#include <sys/dklabel.h>
#endif

#include <sys/sysmacros.h>

#ifndef	SECSIZE
#define	SECSIZE			DEV_BSIZE
#endif	/* SECSIZE */

/*
 * Internal functions.
 */
extern	int	main(int, char **);
static	void	display(struct dk_geom *, struct extvtoc *, char *);
static	void	display64(struct dk_gpt *,  char *);
static	void	insert(char *, struct extvtoc *);
static	void	insert64(char *, struct dk_gpt *);
static	void	load(FILE *, struct dk_geom *, struct extvtoc *);
static	void	load64(FILE *, int fd, struct dk_gpt **);
static	void	usage(void);
static	void	validate(struct dk_geom *, struct extvtoc *);
static	void	validate64(struct dk_gpt *);
static	int	vread(int, struct extvtoc *, char *);
static	void	vread64(int, struct dk_gpt **, char *);
static	void	vwrite(int, struct extvtoc *, char *);
static	void	vwrite64(int, struct dk_gpt *, char *);

/*
 * Static variables.
 */
static char	*delta;		/* Incremental update */
static short	eflag;		/* force write of an EFI label */
static short	iflag;		/* Prints VTOC w/o updating */
static short	qflag;		/* Check for a formatted disk */
static short	uflag;		/* Exit to firmware after writing  */
				/* new vtoc and reboot. Used during */
				/* installation of core floppies */
static diskaddr_t	lastlba = 0;	/* last LBA on 64-bit VTOC */

#if defined(sparc)
static char	*uboot = "boot";

#elif defined(i386)
/* use installgrub(1M) to install boot blocks */
static char *uboot = "";
#else
#error No platform defined.
#endif	/* various platform-specific definitions */

static char	*ufirm = "firm";
static int		sectsiz;
#if defined(_SUNOS_VTOC_16)
static struct extvtoc	disk_vtoc;
#endif	/* defined(_SUNOS_VTOC_16) */

int
main(int argc, char **argv)
{
	int		fd;
	int		c;
	char		*dfile;
	char		*vname;
	struct stat	statbuf;
#if defined(_SUNOS_VTOC_8)
	struct extvtoc	disk_vtoc;
#endif	/* defined(_SUNOS_VTOC_8) */
	struct dk_gpt	*disk_efi;
	struct dk_geom	disk_geom;
	struct dk_minfo	minfo;
	int		n;


	disk_efi = NULL;
	dfile = NULL;
	vname = NULL;
#if defined(sparc)
	while ((c = getopt(argc, argv, "ed:u:in:qs:")) != EOF)

#elif defined(i386)
	while ((c = getopt(argc, argv, "ed:u:in:qb:p:s:")) != EOF)

#else
#error No platform defined.
#endif
		switch (c) {
#if defined(i386)
		case 'p':
		case 'b':
			(void) fprintf(stderr,
			    "fmthard: -p and -b no longer supported."
			    " Use installgrub(1M) to install boot blocks\n");
			break;
#endif	/* defined(i386) */

		case 'd':
			delta = optarg;
			break;
		case 'e':
			++eflag;
			break;
		case 'i':
			++iflag;
			break;
		case 'n':
			vname = optarg;
			break;
		case 'q':
			++qflag;
			break;
		case 's':
			dfile = optarg;
			break;
		case 'u':
			if (strcmp(uboot, optarg) == 0)
				++uflag;
			else if (strcmp(ufirm, optarg) == 0)
				uflag = 2;

			break;
		default:
			usage();
		}


	if (argc - optind != 1)
		usage();

	if (stat(argv[optind], (struct stat *)&statbuf) == -1) {
		(void) fprintf(stderr,
		    "fmthard:  Cannot stat device %s\n",
		    argv[optind]);
		exit(1);
	}

	if ((statbuf.st_mode & S_IFMT) != S_IFCHR) {
		(void) fprintf(stderr,
		    "fmthard:  %s must be a raw device.\n",
		    argv[optind]);
		exit(1);
	}

	if ((fd = open(argv[optind], O_RDWR|O_NDELAY)) < 0) {
		(void) fprintf(stderr, "fmthard:  Cannot open device %s - %s\n",
		    argv[optind], strerror(errno));
		exit(1);
	}

	if (ioctl(fd, DKIOCGMEDIAINFO, &minfo) == 0) {
		sectsiz = minfo.dki_lbsize;
	}

	if (sectsiz == 0) {
		sectsiz = SECSIZE;
	}

	/*
	 * Get the geometry information for this disk from the driver
	 */
	if (!eflag && ioctl(fd, DKIOCGGEOM, &disk_geom)) {
#ifdef DEBUG
		perror("DKIOCGGEOM failed");
#endif /* DEBUG */
		if (errno == ENOTSUP) {
			/* disk has EFI labels */
			eflag++;
		} else {
			(void) fprintf(stderr,
			    "%s: Cannot get disk geometry\n", argv[optind]);
			(void) close(fd);
			exit(1);
		}
	}

	/*
	 * Read the vtoc on the disk
	 */
	if (!eflag) {
		if (vread(fd, &disk_vtoc, argv[optind]) == 1)
			eflag++;
	}
	if (eflag && ((dfile == NULL) || qflag)) {
		vread64(fd, &disk_efi, argv[optind]);
	}

	/*
	 * Quick check for valid disk: 0 if ok, 1 if not
	 */
	if (qflag) {
		(void) close(fd);
		if (!eflag) {
			exit(disk_vtoc.v_sanity == VTOC_SANE ? 0 : 1);
		} else {
			exit(disk_efi->efi_version <= EFI_VERSION102 ? 0 : 1);
		}
	}

	/*
	 * Incremental changes to the VTOC
	 */
	if (delta) {
		if (!eflag) {
			insert(delta, &disk_vtoc);
			validate(&disk_geom, &disk_vtoc);
			vwrite(fd, &disk_vtoc, argv[optind]);
		} else {
			insert64(delta, disk_efi);
			validate64(disk_efi);
			vwrite64(fd, disk_efi, argv[optind]);
		}
		(void) close(fd);
		exit(0);
	}

	if (!dfile && !vname)
		usage();

	/*
	 * Read new VTOC from stdin or data file
	 */
	if (dfile) {
		if (strcmp(dfile, "-") == 0) {
			if (!eflag)
				load(stdin, &disk_geom, &disk_vtoc);
			else
				load64(stdin, fd, &disk_efi);
		} else {
			FILE *fp;
			if ((fp = fopen(dfile, "r")) == NULL) {
				(void) fprintf(stderr, "Cannot open file %s\n",
				    dfile);
				(void) close(fd);
				exit(1);
			}
			if (!eflag)
				load(fp, &disk_geom, &disk_vtoc);
			else
				load64(fp, fd, &disk_efi);
			(void) fclose(fp);
		}
	}

	/*
	 * Print the modified VTOC, rather than updating the disk
	 */
	if (iflag) {
		if (!eflag)
			display(&disk_geom, &disk_vtoc, argv[optind]);
		else
			display64(disk_efi, argv[optind]);
		(void) close(fd);
		exit(0);
	}

	if (vname) {
		n = MIN(strlen(vname) + 1, LEN_DKL_VVOL);
		if (!eflag) {
			(void) memcpy(disk_vtoc.v_volume, vname, n);
		} else {
			for (c = 0; c < disk_efi->efi_nparts; c++) {
				if (disk_efi->efi_parts[c].p_tag ==
				    V_RESERVED) {
				(void) memcpy(&disk_efi->efi_parts[c].p_name,
				    vname, n);
				}
			}
		}

	}
	/*
	 * Write the new VTOC on the disk
	 */
	if (!eflag) {
		validate(&disk_geom, &disk_vtoc);
		vwrite(fd, &disk_vtoc, argv[optind]);
	} else {
		validate64(disk_efi);
		vwrite64(fd, disk_efi, argv[optind]);
	}

	/*
	 * Shut system down after writing a new vtoc to disk
	 * This is used during installation of core floppies.
	 */
	if (uflag == 1)
		(void) uadmin(A_REBOOT, AD_BOOT, 0);
	else if (uflag == 2)
		(void) uadmin(A_REBOOT, AD_IBOOT, 0);

	(void) printf("fmthard:  New volume table of contents now in place.\n");

	return (0);
}



/*
 * display ()
 *
 * display contents of VTOC without writing it to disk
 */
static void
display(struct dk_geom *geom, struct extvtoc *vtoc, char *device)
{
	int	i;
	int	c;

	/*
	 * Print out the VTOC
	 */
	(void) printf("* %s default partition map\n", device);
	if (*vtoc->v_volume) {
		(void) printf("* Volume Name:  ");
		for (i = 0; i < LEN_DKL_VVOL; i++) {
			if ((c = vtoc->v_volume[i]) == 0)
				break;
			(void) printf("%c", c);
		}
		(void) printf("\n");
	}
	(void) printf("*\n");
	(void) printf("* Dimensions:\n");
	(void) printf("*     %d bytes/sector\n", sectsiz);
	(void) printf("*      %d sectors/track\n", geom->dkg_nsect);
	(void) printf("*       %d tracks/cylinder\n", geom->dkg_nhead);
	(void) printf("*     %d cylinders\n", geom->dkg_pcyl);
	(void) printf("*     %d accessible cylinders\n", geom->dkg_ncyl);
	(void) printf("*\n");
	(void) printf("* Flags:\n");
	(void) printf("*   1:  unmountable\n");
	(void) printf("*  10:  read-only\n");
	(void) printf("*\n");
	(void) printf(
"\n* Partition    Tag     Flag	    First Sector    Sector Count\n");
	for (i = 0; i < V_NUMPAR; i++) {
		if (vtoc->v_part[i].p_size > 0)
			(void) printf(
"    %d		%d	0%x		%llu		%llu\n",
			    i, vtoc->v_part[i].p_tag,
			    vtoc->v_part[i].p_flag,
			    vtoc->v_part[i].p_start,
			    vtoc->v_part[i].p_size);
	}
	exit(0);
}

/*
 * display64 ()
 *
 * display64 contents of EFI partition without writing it to disk
 */
static void
display64(struct dk_gpt *efi, char *device)
{
	int	i;

	/*
	 * Print out the VTOC
	 */
	(void) printf("* %s default partition map\n", device);
	(void) printf("*\n");
	(void) printf("* Dimensions:\n");
	(void) printf("*     %d bytes/sector\n", efi->efi_lbasize);
	(void) printf("*     N/A sectors/track\n");
	(void) printf("*     N/A tracks/cylinder\n");
	(void) printf("*     N/A cylinders\n");
	(void) printf("*     N/A accessible cylinders\n");
	(void) printf("*\n");
	(void) printf("* Flags:\n");
	(void) printf("*   1:  unmountable\n");
	(void) printf("*  10:  read-only\n");
	(void) printf("*\n");
	(void) printf(
"\n* Partition    Tag     Flag	    First Sector    Sector Count\n");
	for (i = 0; i < efi->efi_nparts; i++) {
		if (efi->efi_parts[i].p_size > 0)
			(void) printf(
"    %d		%d	0%x		%8lld	%8lld\n",
			    i, efi->efi_parts[i].p_tag,
			    efi->efi_parts[i].p_flag,
			    efi->efi_parts[i].p_start,
			    efi->efi_parts[i].p_size);
	}
	exit(0);
}


/*
 * insert()
 *
 * Insert a change into the VTOC.
 */
static void
insert(char *data, struct extvtoc *vtoc)
{
	int		part;
	int		tag;
	uint_t		flag;
	diskaddr_t	start;
	uint64_t	size;

	if (sscanf(data, "%d:%d:%x:%llu:%llu",
	    &part, &tag, &flag, &start, &size) != 5) {
		(void) fprintf(stderr, "Delta syntax error on \"%s\"\n", data);
		exit(1);
	}
	if (part >= V_NUMPAR) {
		(void) fprintf(stderr,
		    "Error in data \"%s\": No such partition %x\n",
		    data, part);
		exit(1);
	}
	vtoc->v_part[part].p_tag = (ushort_t)tag;
	vtoc->v_part[part].p_flag = (ushort_t)flag;
	vtoc->v_part[part].p_start = start;
	vtoc->v_part[part].p_size = size;
}

/*
 * insert64()
 *
 * Insert a change into the VTOC.
 */
static void
insert64(char *data, struct dk_gpt *efi)
{
	int		part;
	int		tag;
	uint_t		flag;
	diskaddr_t	start;
	diskaddr_t	size;

	if (sscanf(data, "%d:%d:%x:%lld:%lld",
	    &part, &tag, &flag, &start, &size) != 5) {
		(void) fprintf(stderr, "Delta syntax error on \"%s\"\n", data);
		exit(1);
	}
	if (part >= efi->efi_nparts) {
		(void) fprintf(stderr,
		    "Error in data \"%s\": No such partition %x\n",
		    data, part);
		exit(1);
	}
	efi->efi_parts[part].p_tag = (ushort_t)tag;
	efi->efi_parts[part].p_flag = (ushort_t)flag;
	efi->efi_parts[part].p_start = start;
	efi->efi_parts[part].p_size = size;
}

/*
 * load()
 *
 * Load VTOC information from a datafile.
 */
static void
load(FILE *fp, struct dk_geom *geom, struct extvtoc *vtoc)
{
	int		part;
	int		tag;
	uint_t		flag;
	diskaddr_t	start;
	uint64_t	size;
	char		line[256];
	int		i;
	uint64_t	nblks;
	uint64_t	fullsz;

	for (i = 0; i < V_NUMPAR; ++i) {
		vtoc->v_part[i].p_tag = 0;
		vtoc->v_part[i].p_flag = V_UNMNT;
		vtoc->v_part[i].p_start = 0;
		vtoc->v_part[i].p_size = 0;
	}
	/*
	 * initialize partition 2, by convention it corresponds to whole
	 * disk. It will be overwritten, if specified in the input datafile
	 */
	fullsz = (uint64_t)geom->dkg_ncyl * geom->dkg_nsect * geom->dkg_nhead;
	vtoc->v_part[2].p_tag = V_BACKUP;
	vtoc->v_part[2].p_flag = V_UNMNT;
	vtoc->v_part[2].p_start = 0;
	vtoc->v_part[2].p_size = fullsz;

	nblks = geom->dkg_nsect * geom->dkg_nhead;

	while (fgets(line, sizeof (line) - 1, fp)) {
		if (line[0] == '\0' || line[0] == '\n' || line[0] == '*')
			continue;
		line[strlen(line) - 1] = '\0';
		if (sscanf(line, "%d %d %x %llu %llu",
		    &part, &tag, &flag, &start, &size) != 5) {
			(void) fprintf(stderr, "Syntax error: \"%s\"\n",
			    line);
			exit(1);
		}
		if (part >= V_NUMPAR) {
			(void) fprintf(stderr,
			    "No such partition %x: \"%s\"\n",
			    part, line);
			exit(1);
		}
		if (!eflag && ((start % nblks) != 0 || (size % nblks) != 0)) {
			(void) fprintf(stderr,
"Partition %d not aligned on cylinder boundary: \"%s\"\n",
			    part, line);
			exit(1);
		}
		vtoc->v_part[part].p_tag = (ushort_t)tag;
		vtoc->v_part[part].p_flag = (ushort_t)flag;
		vtoc->v_part[part].p_start = start;
		vtoc->v_part[part].p_size = size;
	}
	for (part = 0; part < V_NUMPAR; part++) {
		vtoc->timestamp[part] = (time_t)0;
	}
}

/*
 * load64()
 *
 * Load VTOC information from a datafile.
 */
static void
load64(FILE *fp, int fd, struct dk_gpt **efi)
{
	int	part;
	int	tag;
	uint_t	flag;
	diskaddr_t	start;
	diskaddr_t	size;
	int	nlines = 0;
	char	line[256];
	int	i;
	uint_t	max_part = 0;
	char	**mem = NULL;

	while (fgets(line, sizeof (line) - 1, fp)) {
		if (line[0] == '\0' || line[0] == '\n' || line[0] == '*')
			continue;
		line[strlen(line) - 1] = '\0';
		if (sscanf(line, "%d %d %x %lld %lld",
		    &part, &tag, &flag, &start, &size) != 5) {
			(void) fprintf(stderr, "Syntax error: \"%s\"\n",
			    line);
			exit(1);
		}
		mem = realloc(mem, sizeof (*mem) * (nlines + 1));
		if (mem == NULL) {
			(void) fprintf(stderr, "realloc failed\n");
			exit(1);
		}
		mem[nlines] = strdup(line);
		if (mem[nlines] == NULL) {
			(void) fprintf(stderr, "strdup failed\n");
			exit(1);
		}
		nlines++;
		if (part > max_part)
			max_part = part;
	}
	max_part++;

	if ((i = efi_alloc_and_init(fd, max_part, efi)) < 0) {
		(void) fprintf(stderr,
		    "efi_alloc_and_init failed: %d\n", i);
		exit(1);
	}
	for (i = 0; i < (*efi)->efi_nparts; ++i) {
		(*efi)->efi_parts[i].p_tag = V_UNASSIGNED;
		(*efi)->efi_parts[i].p_flag = V_UNMNT;
		(*efi)->efi_parts[i].p_start = 0;
		(*efi)->efi_parts[i].p_size = 0;
	}
	lastlba = (*efi)->efi_last_u_lba;

	for (i = 0; i < nlines; i++) {
		if (sscanf(mem[i], "%d %d %x %lld %lld",
		    &part, &tag, &flag, &start, &size) != 5) {
			(void) fprintf(stderr, "Syntax error: \"%s\"\n",
			    line);
			exit(1);
		}
		free(mem[i]);
		if (part >= (*efi)->efi_nparts) {
			(void) fprintf(stderr,
			    "No such partition %x: \"%s\"\n",
			    part, line);
			exit(1);
		}
		(*efi)->efi_parts[part].p_tag = (ushort_t)tag;
		(*efi)->efi_parts[part].p_flag = (ushort_t)flag;
		(*efi)->efi_parts[part].p_start = start;
		(*efi)->efi_parts[part].p_size = size;
	}
	(*efi)->efi_nparts = max_part;
	free(mem);
}


static void
usage()
{
#if defined(sparc)
	(void) fprintf(stderr,
"Usage:	fmthard [ -i ] [ -n volumename ] [ -s datafile ] [ -d arguments] \
raw-device\n");

#elif defined(i386)
	(void) fprintf(stderr,
"Usage:	fmthard [ -i ] [ -S ] [-I geom_file]  \
-n volumename | -s datafile  [ -d arguments] raw-device\n");

#else
#error No platform defined.
#endif
	exit(2);
}

/*
 * validate()
 *
 * Validate the new VTOC.
 */
static void
validate(struct dk_geom *geom, struct extvtoc *vtoc)
{
	int		i;
	int		j;
	uint64_t	fullsz;
	diskaddr_t	endsect;
	diskaddr_t	istart;
	diskaddr_t	jstart;
	uint64_t	isize;
	uint64_t	jsize;
	uint64_t	nblks;

	nblks = geom->dkg_nsect * geom->dkg_nhead;

	fullsz = (uint64_t)geom->dkg_ncyl * geom->dkg_nsect * geom->dkg_nhead;

#if defined(_SUNOS_VTOC_16)
	/* make the vtoc look sane - ha ha */
	vtoc->v_version = V_VERSION;
	vtoc->v_sanity = VTOC_SANE;
	vtoc->v_nparts = V_NUMPAR;
	if (vtoc->v_sectorsz == 0)
		vtoc->v_sectorsz = sectsiz;
#endif				/* defined(_SUNOS_VTOC_16) */

	for (i = 0; i < V_NUMPAR; i++) {
		if (vtoc->v_part[i].p_tag == V_BACKUP) {
			if (vtoc->v_part[i].p_size != fullsz) {
				(void) fprintf(stderr, "\
fmthard: Partition %d specifies the full disk and is not equal\n\
full size of disk.  The full disk capacity is %llu sectors.\n", i, fullsz);
#if defined(sparc)
			exit(1);
#endif
			}
		}
		if (vtoc->v_part[i].p_size == 0)
			continue;	/* Undefined partition */
		if ((vtoc->v_part[i].p_start % nblks) ||
		    (vtoc->v_part[i].p_size % nblks)) {
			(void) fprintf(stderr, "\
fmthard: Partition %d not aligned on cylinder boundary \n", i);
			exit(1);
		}
		if (vtoc->v_part[i].p_start > fullsz ||
		    vtoc->v_part[i].p_start +
		    vtoc->v_part[i].p_size > fullsz) {
			(void) fprintf(stderr, "\
fmthard: Partition %d specified as %llu sectors starting at %llu\n\
\tdoes not fit. The full disk contains %llu sectors.\n",
			    i, vtoc->v_part[i].p_size,
			    vtoc->v_part[i].p_start, fullsz);
#if defined(sparc)
			exit(1);
#endif
		}

		if (vtoc->v_part[i].p_tag != V_BACKUP &&
		    vtoc->v_part[i].p_size != fullsz) {
			for (j = 0; j < V_NUMPAR; j++) {
				if (vtoc->v_part[j].p_tag == V_BACKUP)
					continue;
				if (vtoc->v_part[j].p_size == fullsz)
					continue;
				isize = vtoc->v_part[i].p_size;
				jsize = vtoc->v_part[j].p_size;
				istart = vtoc->v_part[i].p_start;
				jstart = vtoc->v_part[j].p_start;
				if ((i != j) &&
				    (isize != 0) && (jsize != 0)) {
					endsect = jstart + jsize -1;
					if ((jstart <= istart) &&
					    (istart <= endsect)) {
						(void) fprintf(stderr, "\
fmthard: Partition %d overlaps partition %d. Overlap is allowed\n\
\tonly on partition on the full disk partition).\n",
						    i, j);
#if defined(sparc)
						exit(1);
#endif
					}
				}
			}
		}
	}
}

/*
 * validate64()
 *
 * Validate the new VTOC.
 */
static void
validate64(struct dk_gpt *efi)
{
	int		i;
	int		j;
	int		resv_part = 0;
	diskaddr_t	endsect;
	diskaddr_t	fullsz;
	diskaddr_t		istart;
	diskaddr_t		jstart;
	diskaddr_t		isize;
	diskaddr_t		jsize;

	fullsz = lastlba + 1;

	for (i = 0; i < efi->efi_nparts; i++) {
		if (efi->efi_parts[i].p_size == 0)
			continue;	/* Undefined partition */
		if (efi->efi_parts[i].p_tag == V_RESERVED)
			resv_part++;
		if (efi->efi_parts[i].p_start > fullsz ||
		    efi->efi_parts[i].p_start +
		    efi->efi_parts[i].p_size > fullsz) {
			(void) fprintf(stderr, "\
fmthard: Partition %d specified as %lld sectors starting at %lld\n\
\tdoes not fit. The full disk contains %lld sectors.\n",
			    i, efi->efi_parts[i].p_size,
			    efi->efi_parts[i].p_start, fullsz);
			exit(1);
		}

		if (efi->efi_parts[i].p_tag != V_BACKUP &&
		    efi->efi_parts[i].p_size != fullsz) {
			for (j = 0; j < efi->efi_nparts; j++) {
				if (efi->efi_parts[j].p_size == fullsz)
					continue;
				isize = efi->efi_parts[i].p_size;
				jsize = efi->efi_parts[j].p_size;
				istart = efi->efi_parts[i].p_start;
				jstart = efi->efi_parts[j].p_start;
				if ((i != j) &&
				    (isize != 0) && (jsize != 0)) {
					endsect = jstart + jsize - 1;
					if ((jstart <= istart) &&
					    (istart <= endsect)) {
						(void) fprintf(stderr, "\
fmthard: Partition %d overlaps partition %d. Overlap is allowed\n\
\tonly on partition on the full disk partition).\n",
						    i, j);
#if defined(sparc)
						exit(1);
#endif
					}
				}
			}
		}
	}
	if (resv_part != 1) {
		(void) fprintf(stderr,
		    "expected one reserved partition, but found %d\n",
		    resv_part);
		exit(1);
	}
}


/*
 * Read the VTOC
 */
int
vread(int fd, struct extvtoc *vtoc, char *devname)
{
	int	i;

	if ((i = read_extvtoc(fd, vtoc)) < 0) {
		if (i == VT_ENOTSUP) {
			return (1);
		}
		if (i == VT_EINVAL) {
			(void) fprintf(stderr, "%s: Invalid VTOC\n",
			    devname);
		} else {
			(void) fprintf(stderr, "%s: Cannot read VTOC\n",
			    devname);
		}
		exit(1);
	}
	return (0);
}

void
vread64(int fd, struct dk_gpt **efi_hdr, char *devname)
{
	int i;

	if ((i = efi_alloc_and_read(fd, efi_hdr)) < 0) {
		if (i == VT_EINVAL)
			(void) fprintf(stderr,
			    "%s: this disk must be labeled first\n",
			    devname);
		else
			(void) fprintf(stderr,
			    "%s: read_efi failed %d\n",
			    devname, i);
		exit(1);
	}
	lastlba = (*efi_hdr)->efi_last_u_lba;
}

/*
 * Write the VTOC
 */
void
vwrite(int fd, struct extvtoc *vtoc, char *devname)
{
	int	i;

	if ((i = write_extvtoc(fd, vtoc)) != 0) {
		if (i == VT_EINVAL) {
			(void) fprintf(stderr,
			"%s: invalid entry exists in vtoc\n",
			    devname);
		} else {
			(void) fprintf(stderr, "%s: Cannot write VTOC\n",
			    devname);
		}
		exit(1);
	}
}

/*
 * Write the VTOC
 */
void
vwrite64(int fd, struct dk_gpt *efi, char *devname)
{
	int	i;

	if ((i = efi_write(fd, efi)) != 0) {
		if (i == VT_EINVAL) {
			(void) fprintf(stderr,
			"%s: invalid entry exists in vtoc\n",
			    devname);
		} else {
			(void) fprintf(stderr, "%s: Cannot write EFI\n",
			    devname);
		}
		exit(1);
	}
}
