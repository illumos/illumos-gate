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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/*	  All Rights Reserved */


/*	Copyright (c) 1984 AT&T */
/*	  All Rights Reserved   */


/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2021 Jason King
 */

/*
 * Print a disk partition map (volume table of contents, or VTOC).
 */

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <err.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/dkio.h>
#include <sys/vtoc.h>
#include <sys/mnttab.h>
#include <sys/vfstab.h>
#include <sys/mkdev.h>

#include <sys/efi_partition.h>
/*
 * Assumes V_NUMPAR must be a power of 2.
 *
 * for V_NUMPAR = 8, we have
 *	parttn(x)=(x & 0x07)	noparttn(x)=(x & 0x3fff8)
 *
 * for V_NUMPAR = 16, we have
 *	parttn(x)=(x & 0x0f)	noparttn(x)=(x & 0x3fff0)
 */
#define	parttn(x)	(x % V_NUMPAR)
#define	noparttn(x)	(x & (MAXMIN & ~(V_NUMPAR-1)))

/*
 * Disk freespace structure.
 */
typedef struct {
	u_longlong_t	fr_start;	/* Start of free space */
	u_longlong_t	fr_size;	/* Length of free space */
} freemap_t;

static	freemap_t	*findfree(struct dk_geom *, struct extvtoc *);
static	int	partcmp(const void *, const void *);
static	int	partcmp64(const void *, const void *);
static	int	prtvtoc(char *);
static	void	putfree(struct extvtoc *, freemap_t *);
static	void	putfree64(struct dk_gpt *, freemap_t *);
static	void	puttable(struct dk_geom *, struct extvtoc *, freemap_t *,
			char *, char **);
static	void	puttable64(struct dk_gpt *, freemap_t *,
			char *, char **);
static	int	readgeom(int, char *, struct dk_geom *);
static	int	readvtoc(int, char *, struct extvtoc *);
static	int	readefi(int, char *, struct dk_gpt **);
static	void	usage(void);
static	char	*safe_strdup(const char *, const char *);
static	void	*safe_calloc(const char *, size_t, size_t);

#define	SAFE_STRDUP(a)		safe_strdup(__func__, (a))
#define	SAFE_CALLOC(a, b)	safe_calloc(__func__, (a), (b))

/*
 * External variables.
 */
extern char	*getfullrawname();
/*
 * Static variables.
 */
static short	fflag;			/* Print freespace shell assignments */
static short	hflag;			/* Omit headers */
static short	sflag;			/* Omit all but the column header */
static char	*fstab = VFSTAB;	/* Fstab pathname */
static char	*mnttab = MNTTAB;	/* mnttab pathname */

int
main(int argc, char *argv[])
{
	int status = EXIT_SUCCESS;
	int c;

	while ((c = getopt(argc, argv, "fhst:m:")) != -1) {
		switch (c) {
		case 'f':
			++fflag;
			break;
		case 'h':
			++hflag;
			break;
		case 's':
			++sflag;
			break;
		case 't':
			fstab = optarg;
			break;
		case 'm':
			mnttab = optarg;
			break;
		default:
			usage();
		}
	}

	if (optind >= argc)
		usage();

	for (int i = optind; i < argc; i++) {
		if (prtvtoc(argv[i]) != 0) {
			status = EXIT_FAILURE;
		}
	}

	return (status);
}

static freemap_t	*freemap;
/*
 * findfree(): Find free space on a disk.
 */
static freemap_t *
findfree(struct dk_geom *geom, struct extvtoc *vtoc)
{
	struct extpartition *part;
	struct extpartition **list;
	freemap_t *freeidx;
	diskaddr_t fullsize;
	ulong_t cylsize;
	struct extpartition *sorted[V_NUMPAR + 1];

	if (vtoc->v_nparts > V_NUMPAR) {
		errx(EXIT_FAILURE, "putfree(): Too many partitions on disk!");
	}

	freemap = SAFE_CALLOC(sizeof (freemap_t), V_NUMPAR + 1);
	cylsize = (geom->dkg_nsect) * (geom->dkg_nhead);
	fullsize = (diskaddr_t)(geom->dkg_ncyl) * cylsize;
	list = sorted;
	for (part = vtoc->v_part; part < vtoc->v_part + vtoc->v_nparts;
	    ++part) {
		if (part->p_size && part->p_tag != V_BACKUP)
			*list++ = part;
	}
	*list = 0;
	qsort(sorted, list - sorted, sizeof (*sorted), partcmp);
	freeidx = freemap;
	freeidx->fr_start = 0;
	for (list = sorted; (part = *list) != NULL; ++list) {
		if (part->p_start <= freeidx->fr_start) {
			freeidx->fr_start += part->p_size;
		} else {
			freeidx->fr_size = part->p_start - freeidx->fr_start;
			(++freeidx)->fr_start = part->p_start + part->p_size;
		}
	}
	if (freeidx->fr_start < fullsize) {
		freeidx->fr_size = fullsize - freeidx->fr_start;
		++freeidx;
	}
	freeidx->fr_start = freeidx->fr_size = 0;
	return (freemap);
}

/*
 * findfree64(): Find free space on a disk.
 */
static freemap_t *
findfree64(struct dk_gpt *efi)
{
	struct dk_part *part;
	struct dk_part **list;
	freemap_t *freeidx;
	diskaddr_t fullsize;
	struct dk_part **sorted;

	freemap = SAFE_CALLOC(sizeof (freemap_t), efi->efi_nparts + 1);
	sorted = SAFE_CALLOC(sizeof (struct dk_part), efi->efi_nparts + 1);
	fullsize = efi->efi_last_u_lba;
	list = sorted;
	for (part = efi->efi_parts; part < efi->efi_parts + efi->efi_nparts;
	    ++part) {
		if (part->p_size && part->p_tag != V_BACKUP)
			*list++ = part;
	}
	*list = 0;
	qsort(sorted, list - sorted, sizeof (*sorted), partcmp64);
	freeidx = freemap;
	freeidx->fr_start = efi->efi_first_u_lba;
	for (list = sorted; (part = *list) != NULL; ++list) {
		if (part->p_start == freeidx->fr_start) {
			freeidx->fr_start += part->p_size;
		} else {
			freeidx->fr_size = part->p_start - freeidx->fr_start;
			(++freeidx)->fr_start = part->p_start + part->p_size;
		}
	}
	if (freeidx->fr_start < fullsize) {
		freeidx->fr_size = fullsize - freeidx->fr_start;
		++freeidx;
	}
	freeidx->fr_start = freeidx->fr_size = 0;
	return (freemap);
}

/*
 * getmntpt()
 *
 * Get the filesystem mountpoint of each partition on the disk
 * from the fstab or mnttab. Returns a pointer to an array of pointers to
 * directory names (indexed by partition number).
 */
static char **
getmntpt(major_t slot, minor_t nopartminor)
{
	FILE *file;
	char devbuf[PATH_MAX], *item;
	static char *list[V_NUMPAR];
	struct stat sb;
	struct mnttab mtab;
	struct vfstab vtab;

	for (unsigned idx = 0; idx < V_NUMPAR; ++idx)
		list[idx] = NULL;

	/* read mnttab for partition mountpoints */
	if ((file = fopen(mnttab, "r")) == NULL) {
		warn("failed to open %s", mnttab);
	} else {
		while (getmntent(file, &mtab) == 0) {
			item = mtab.mnt_special;
			if (item == NULL || mtab.mnt_mountp == NULL)
				continue;

			/*
			 * Is it from /dev?
			 */
			if (strncmp(item, "/dev/", strlen("/dev/")) != 0)
				continue;

			/*
			 * Is it a character device?
			 */
			(void) snprintf(devbuf, sizeof (devbuf), "/dev/r%s",
			    item + strlen("/dev/"));

			if (stat(devbuf, &sb) != 0 ||
			    (sb.st_mode & S_IFMT) != S_IFCHR) {
				continue;
			}

			/*
			 * device must match input slot and nopartminor
			 */
			if (major(sb.st_rdev) != slot ||
			    noparttn(minor(sb.st_rdev)) != nopartminor) {
				continue;
			}

			list[parttn(minor(sb.st_rdev))] =
			    SAFE_STRDUP(mtab.mnt_mountp);
		}
		(void) fclose(file);
	}

	if ((file = fopen(fstab, "r")) == NULL) {
		warn("failed to open %s", fstab);
		return (list);
	}

	/*
	 * Look for the disk in the vfstab so that we can report its mount
	 * point even if it isn't currently mounted.
	 */
	while (getvfsent(file, &vtab) == 0) {
		item = vtab.vfs_special;
		if (item == NULL || vtab.vfs_mountp == NULL)
			continue;

		if (strncmp(item, "/dev/", strlen("/dev/")) != 0)
			continue;

		/*
		 * Is it a character device?
		 */
		(void) snprintf(devbuf, sizeof (devbuf), "/dev/r%s",
		    item + strlen("/dev/"));

		if (stat(devbuf, &sb) != 0 ||
		    (sb.st_mode & S_IFMT) != S_IFCHR) {
			continue;
		}

		/*
		 * device must match input slot and nopartminor
		 */
		if (major(sb.st_rdev) != slot ||
		    noparttn(minor(sb.st_rdev)) != nopartminor) {
			continue;
		}

		/*
		 * use mnttab entry if both tables have entries
		 */
		if (list[parttn(minor(sb.st_rdev))] != NULL)
			continue;

		list[parttn(minor(sb.st_rdev))] = SAFE_STRDUP(vtab.vfs_mountp);
	}
	(void) fclose(file);

	return (list);
}

/*
 * partcmp(): Qsort() key comparison of partitions by starting sector numbers.
 */
static int
partcmp(const void *one, const void *two)
{
	struct partition *p1 = *(struct partition **)one;
	struct partition *p2 = *(struct partition **)two;

	if (p1->p_start > p2->p_start) {
		return (1);
	} else if (p1->p_start < p2->p_start) {
		return (-1);
	} else {
		return (0);
	}
}

static int
partcmp64(const void *one, const void *two)
{
	dk_part_t *p1 = *(dk_part_t **)one;
	dk_part_t *p2 = *(dk_part_t **)two;

	if (p1->p_start > p2->p_start) {
		return (1);
	} else if (p1->p_start < p2->p_start) {
		return (-1);
	} else {
		return (0);
	}
}

/*
 * prtvtoc(): Read and print a VTOC.
 */
static int
prtvtoc(char *devname)
{
	int fd;
	int idx = 0;
	freemap_t *freemap;
	struct stat sb;
	struct extvtoc vtoc;
	int geo;
	struct dk_geom geom;
	char *name;
	int newvtoc = 0;
	struct dk_gpt *efi;

	name = getfullrawname(devname);
	if (name == NULL) {
		warnx("%s: internal administrative call (getfullrawname) "
		    "failed", devname);
		return (-1);
	}
	if (strcmp(name, "") == 0)
		name = devname;
	if ((fd = open(name, O_NONBLOCK|O_RDONLY)) < 0) {
		warn("%s: failed to open device", name);
		return (-1);
	}
	if (fstat(fd, &sb) < 0) {
		warn("%s: failed to stat device", name);
		return (-1);
	}
	if ((sb.st_mode & S_IFMT) != S_IFCHR) {
		warnx("%s: Not a raw device", name);
		return (-1);
	}

	geo = (readgeom(fd, name, &geom) == 0);
	if (geo) {
		if ((idx = readvtoc(fd, name, &vtoc)) == VT_ENOTSUP) {
			idx = (readefi(fd, name, &efi) == 0);
			newvtoc = 1;
		} else {
			idx = (idx == 0);
		}
	}
	(void) close(fd);
	if ((!geo) || (!idx))
		return (-1);
	if (!newvtoc)
		freemap = findfree(&geom, &vtoc);
	else
		freemap = findfree64(efi);
	if (fflag) {
		if (!newvtoc)
			putfree(&vtoc, freemap);
		else
			putfree64(efi, freemap);
	} else {
		if (!newvtoc) {
			puttable(&geom, &vtoc, freemap, devname,
			    getmntpt(major(sb.st_rdev),
			    noparttn(minor(sb.st_rdev))));
		} else {
			puttable64(efi, freemap, devname,
			    getmntpt(major(sb.st_rdev),
			    noparttn(minor(sb.st_rdev))));
		}
	}
	if (newvtoc)
		efi_free(efi);
	return (0);
}

/*
 * putfree():
 *
 * Print shell assignments for disk free space. FREE_START and FREE_SIZE
 * represent the starting block and number of blocks of the first chunk
 * of free space. FREE_PART lists the unassigned partitions.
 */
static void
putfree(struct extvtoc *vtoc, freemap_t *freemap)
{
	freemap_t *freeidx;
	ushort_t idx;
	int free_count = 0;

	for (freeidx = freemap; freeidx->fr_size; ++freeidx)
		free_count++;

	(void) printf("FREE_START=%llu FREE_SIZE=%llu FREE_COUNT=%d FREE_PART=",
	    freemap->fr_start, freemap->fr_size, free_count);

	for (idx = 0; idx < vtoc->v_nparts; ++idx) {
		if (vtoc->v_part[idx].p_size == 0 && idx != 2)
			(void) printf("%x", idx);
	}
	(void) printf("\n");
}

static void
putfree64(struct dk_gpt *efi, freemap_t *freemap)
{
	freemap_t *freeidx;
	ushort_t idx;
	int free_count = 0;

	for (freeidx = freemap; freeidx->fr_size; ++freeidx)
		free_count++;

	(void) printf("FREE_START=%llu FREE_SIZE=%llu FREE_COUNT=%d FREE_PART=",
	    freemap->fr_start, freemap->fr_size, free_count);

	for (idx = 0; idx < efi->efi_nparts; ++idx) {
		if (efi->efi_parts[idx].p_size == 0 && idx != 2)
			(void) printf("%x", idx);
	}
	(void) printf("\n");
}

static void
print_table_header()
{
	(void) printf("*                            First       Sector"
	    "      Last\n");
	(void) printf("* Partition  Tag  Flags      Sector       Count"
	    "      Sector  Mount Directory\n");
}

static void
print_table_row(uint_t partition, uint_t tag, uint_t flag,
    u_longlong_t first_sector, u_longlong_t sector_count,
    u_longlong_t last_sector, const char *mount_dir)
{
	(void) printf("  %6u   %4u    %02x  %11llu %11llu %11llu",
	    partition, tag, flag, first_sector, sector_count, last_sector);
	if (mount_dir != NULL) {
		(void) printf("   %s", mount_dir);
	}
	(void) printf("\n");
}

static void
print_freemap(freemap_t *freemap)
{
	if (freemap->fr_size == 0) {
		/*
		 * The freemap is completely empty, so do not print the header.
		 */
		return;
	}

	(void) printf("* Unallocated space:\n"
	    "*         First       Sector      Last\n"
	    "*         Sector       Count      Sector\n");

	do {
		(void) printf("*   %11llu %11llu %11llu\n",
		    freemap->fr_start, freemap->fr_size,
		    freemap->fr_size + freemap->fr_start - 1);
	} while ((++freemap)->fr_size != 0);

	(void) printf("*\n");
}

/*
 * puttable(): Print a human-readable VTOC.
 */
static void
puttable(struct dk_geom *geom, struct extvtoc *vtoc, freemap_t *freemap,
    char *name, char **mtab)
{
	ushort_t idx;
	ulong_t cylsize;

	cylsize = (geom->dkg_nsect) * (geom->dkg_nhead);
	if (!hflag && !sflag) {
		u_longlong_t asectors = (u_longlong_t)cylsize * geom->dkg_ncyl;
		u_longlong_t sectors = (u_longlong_t)cylsize * geom->dkg_pcyl;

		(void) printf("* %s", name);
		if (vtoc->v_volume[0] != '\0')
			(void) printf(" (volume \"%.8s\")", vtoc->v_volume);

		(void) printf(" partition map\n");
		(void) printf("*\n* Dimensions:\n");
		(void) printf("* %11u bytes/sector\n", vtoc->v_sectorsz);
		(void) printf("* %11u sectors/track\n", geom->dkg_nsect);
		(void) printf("* %11u tracks/cylinder\n", geom->dkg_nhead);
		(void) printf("* %11lu sectors/cylinder\n", cylsize);
		(void) printf("* %11u cylinders\n", geom->dkg_pcyl);
		(void) printf("* %11u accessible cylinders\n", geom->dkg_ncyl);
		(void) printf("* %11llu sectors\n", sectors);
		(void) printf("* %11llu accessible sectors\n", asectors);
		(void) printf("*\n* Flags:\n");
		(void) printf("*   1: unmountable\n");
		(void) printf("*  10: read-only\n*\n");

		print_freemap(freemap);
	}

	if (!hflag) {
		print_table_header();
	}

	for (idx = 0; idx < vtoc->v_nparts; ++idx) {
		const char *mount_dir = NULL;
		struct extpartition *p = &vtoc->v_part[idx];

		if (p->p_size == 0)
			continue;

		if (mtab != NULL) {
			mount_dir = mtab[idx];
		}

		print_table_row(idx, p->p_tag, p->p_flag, p->p_start,
		    p->p_size, p->p_start + p->p_size - 1, mount_dir);
	}
}

/*
 * puttable(): Print a human-readable VTOC.
 */
static void
puttable64(struct dk_gpt *efi, freemap_t *freemap, char *name, char **mtab)
{
	if (!hflag && !sflag) {
		(void) printf("* %s", name);
		for (uint_t idx = 0; idx < efi->efi_nparts; idx++) {
			if (efi->efi_parts[idx].p_tag == V_RESERVED &&
			    efi->efi_parts[idx].p_name[0] != '\0') {
				(void) printf(" (volume \"%.8s\")",
				    efi->efi_parts[idx].p_name);
			}
		}
		(void) printf(" partition map\n");
		(void) printf("*\n* Dimensions:\n");
		(void) printf("* %11u bytes/sector\n", efi->efi_lbasize);
		(void) printf("* %11llu sectors\n", efi->efi_last_lba + 1);
		(void) printf("* %11llu accessible sectors\n",
		    efi->efi_last_u_lba - efi->efi_first_u_lba + 1);
		(void) printf("*\n* Flags:\n");
		(void) printf("*   1: unmountable\n");
		(void) printf("*  10: read-only\n*\n");

		print_freemap(freemap);
	}

	if (!hflag) {
		print_table_header();
	}

	for (uint_t idx = 0; idx < efi->efi_nparts; ++idx) {
		const char *mount_dir = NULL;
		dk_part_t *p = &efi->efi_parts[idx];

		if (p->p_size == 0)
			continue;

		if (idx < 7 && mtab != NULL) {
			mount_dir = mtab[idx];
		}

		print_table_row(idx, p->p_tag, p->p_flag, p->p_start,
		    p->p_size, p->p_start + p->p_size - 1, mount_dir);
	}
}

/*
 * readgeom(): Read the disk geometry.
 */
static int
readgeom(int fd, char *name, struct dk_geom *geom)
{
	if (ioctl(fd, DKIOCGGEOM, geom) < 0) {
		if (errno != ENOTSUP) {
			warnx("%s: Unable to read Disk geometry errno = 0x%x",
			    name, errno);
			return (-1);
		}

		(void) memset(geom, 0, sizeof (struct dk_geom));
	}

	return (0);
}

/*
 * readvtoc(): Read a partition map.
 */
static int
readvtoc(int fd, char *name, struct extvtoc *vtoc)
{
	int retval;

	if ((retval = read_extvtoc(fd, vtoc)) >= 0)
		return (0);

	switch (retval) {
	case VT_EIO:
		warnx("%s: Unable to read VTOC", name);
		return (-1);
	case VT_EINVAL:
		warnx("%s: Invalid VTOC", name);
		return (-1);
	case VT_ERROR:
		warnx("%s: Unknown problem reading VTOC", name);
		return (-1);
	}

	return (retval);
}

/*
 * readefi(): Read a partition map.
 */
static int
readefi(int fd, char *name, struct dk_gpt **efi)
{
	int	retval;

	if ((retval = efi_alloc_and_read(fd, efi)) >= 0)
		return (0);

	switch (retval) {
	case VT_EIO:
		warnx("%s: Unable to read VTOC", name);
		return (-1);
	case VT_EINVAL:
		warnx("%s: Invalid VTOC", name);
		return (-1);
	case VT_ERROR:
		warnx("%s: Unknown problem reading VTOC", name);
		return (-1);
	}

	return (retval);
}

static void
memory_err(size_t l, int e, const char *fname)
{
	const char *reason;

	switch (e) {
	case EAGAIN:
		reason = "not enough memory was available, please try again";
		break;
	case ENOMEM:
		reason = "allocation size was too large";
		break;
	default:
		reason = strerror(e);
		break;
	}

	errx(EXIT_FAILURE, "%s: failed to allocate %llu bytes of memory: %s",
	    fname, (u_longlong_t)l, reason);
}

static void *
safe_calloc(const char *fname, size_t nelem, size_t elsize)
{
	void *r;

	if ((r = calloc(nelem, elsize)) == NULL) {
		memory_err(nelem * elsize, errno, fname);
	}

	return (r);
}

static char *
safe_strdup(const char *fname, const char *str)
{
	size_t l = strlen(str);
	char *r;

	if ((r = strndup(str, l)) == NULL) {
		memory_err(l + 1, errno, fname);
	}

	return (r);
}

/*
 * usage(): Print a helpful message and exit.
 */
static void
usage()
{
	(void) fprintf(stderr, "Usage:\t%s [ -fhs ] [ -t fstab ] [ -m mnttab ] "
	    "rawdisk ...\n", getprogname());
	exit(1);
}
