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


/*	Copyright (c) 1984 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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
 * 	parttn(x)=(x & 0x07)	noparttn(x)=(x & 0x3fff8)
 *
 * for V_NUMPAR = 16, we have
 * 	parttn(x)=(x & 0x0f)	noparttn(x)=(x & 0x3fff0)
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
static	int	warn(char *, char *);
static	char	*safe_strdup(char *);

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
static char	*progname;		/* Last qualifier of arg0 */

int
main(int ac, char **av)
{
	int		idx;

	if (progname = strrchr(av[0], '/'))
		++progname;
	else
		progname = av[0];
	while ((idx = getopt(ac, av, "fhst:m:")) != -1)
		switch (idx) {
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
	if (optind >= ac)
		usage();
	idx = 0;
	while (optind < ac)
		idx |= prtvtoc(av[optind++]);
	return (idx == 0 ? 0 : 1);
}

static freemap_t	*freemap;
/*
 * findfree(): Find free space on a disk.
 */
static freemap_t *
findfree(struct dk_geom *geom, struct extvtoc *vtoc)
{
	struct extpartition	*part;
	struct extpartition	**list;
	freemap_t		*freeidx;
	diskaddr_t		fullsize;
	ulong_t			cylsize;
	struct extpartition	*sorted[V_NUMPAR + 1];

	freemap = calloc(sizeof (freemap_t), V_NUMPAR + 1);
	cylsize  = (geom->dkg_nsect) * (geom->dkg_nhead);
	fullsize = (diskaddr_t)(geom->dkg_ncyl) * cylsize;
	if (vtoc->v_nparts > V_NUMPAR) {
		(void) warn("putfree()", "Too many partitions on disk!");
		exit(1);
	}
	list = sorted;
	for (part = vtoc->v_part; part < vtoc->v_part + vtoc->v_nparts; ++part)
		if (part->p_size && part->p_tag != V_BACKUP)
			*list++ = part;
	*list = 0;
	qsort((char *)sorted, (uint_t)(list - sorted),
		sizeof (*sorted), partcmp);
	freeidx = freemap;
	freeidx->fr_start = 0;
	for (list = sorted; (part = *list) != NULL; ++list)
		if (part->p_start <= freeidx->fr_start)
			freeidx->fr_start += part->p_size;
		else {
			freeidx->fr_size = part->p_start - freeidx->fr_start;
			(++freeidx)->fr_start = part->p_start + part->p_size;
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
	struct dk_part		*part;
	struct dk_part		**list;
	freemap_t		*freeidx;
	diskaddr_t		fullsize;
	struct dk_part		**sorted;

	freemap = calloc(sizeof (freemap_t), efi->efi_nparts + 1);
	sorted = calloc(sizeof (struct dk_part), efi->efi_nparts + 1);
	fullsize = efi->efi_last_u_lba;
	list = sorted;
	for (part = efi->efi_parts;
	    part < efi->efi_parts + efi->efi_nparts;
	    ++part)
		if (part->p_size && part->p_tag != V_BACKUP)
			*list++ = part;
	*list = 0;
	qsort((char *)sorted, (uint_t)(list - sorted),
		sizeof (*sorted), partcmp64);
	freeidx = freemap;
	freeidx->fr_start = efi->efi_first_u_lba;
	for (list = sorted; (part = *list) != NULL; ++list)
		if (part->p_start == freeidx->fr_start)
			freeidx->fr_start += part->p_size;
		else {
			freeidx->fr_size = part->p_start - freeidx->fr_start;
			(++freeidx)->fr_start = part->p_start + part->p_size;
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
	int idx;
	FILE *file;
	char devbuf[PATH_MAX], *item;
	static char *list[V_NUMPAR];
	struct stat sb;
	struct mnttab mtab;
	struct vfstab vtab;

	for (idx = 0; idx < V_NUMPAR; ++idx)
		list[idx] = NULL;

	/* read mnttab for partition mountpoints */
	if ((file = fopen(mnttab, "r")) == NULL) {
		(void) warn(mnttab, strerror(errno));
	} else {
		while (getmntent(file, &mtab) == 0) {
			item = mtab.mnt_special;
			if ((item == NULL) || (mtab.mnt_mountp == NULL))
				continue;

			/*
			 * Is it from /dev?
			 */
			if (strncmp(item, "/dev/", strlen("/dev/") != 0))
				continue;

			/*
			 * Is it a character device?
			 */
			(void) snprintf(devbuf, sizeof (devbuf), "/dev/r%s",
			    item + strlen("/dev/"));

			if ((stat(devbuf, &sb) != 0) ||
			    ((sb.st_mode & S_IFMT) != S_IFCHR))
				continue;

			/*
			 * device must match input slot and nopartminor
			 */
			if ((major(sb.st_rdev) != slot) ||
			    (noparttn(minor(sb.st_rdev)) != nopartminor))
				continue;

			list[parttn(minor(sb.st_rdev))] =
			    safe_strdup(mtab.mnt_mountp);
		}
		(void) fclose(file);
	}

	if ((file = fopen(fstab, "r")) == NULL) {
		(void) warn(fstab, strerror(errno));
		return (list);
	}

	/*
	 * Look for the disk in the vfstab so that we can report its mount
	 * point even if it isn't currently mounted.
	 */
	while (getvfsent(file, &vtab) == 0) {
		item = vtab.vfs_special;
		if ((item == NULL) || (vtab.vfs_mountp == NULL))
			continue;

		if (strncmp(item, "/dev/", strlen("/dev/")) != 0)
			continue;

		/*
		 * Is it a character device?
		 */
		(void) snprintf(devbuf, sizeof (devbuf), "/dev/r%s",
		    item + strlen("/dev/"));

		if ((stat(devbuf, &sb) != 0) ||
		    ((sb.st_mode & S_IFMT) != S_IFCHR))
			continue;

		/*
		 * device must match input slot and nopartminor
		 */
		if ((major(sb.st_rdev) != slot) ||
		    (noparttn(minor(sb.st_rdev)) != nopartminor))
			continue;

		/*
		 * use mnttab entry if both tables have entries
		 */
		if (list[parttn(minor(sb.st_rdev))] != NULL)
			continue;

		list[parttn(minor(sb.st_rdev))] = safe_strdup(vtab.vfs_mountp);
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
	return ((*(struct partition **)one)->p_start -
		(*(struct partition **)two)->p_start);
}

static int
partcmp64(const void *one, const void *two)
{
	if ((*(struct dk_part **)one)->p_start >
		(*(struct dk_part **)two)->p_start)
	    return (1);
	else if ((*(struct dk_part **)one)->p_start <
		(*(struct dk_part **)two)->p_start)
	    return (-1);
	else
	    return (0);

}

/*
 * prtvtoc(): Read and print a VTOC.
 */
static int
prtvtoc(char *devname)
{
	int		fd;
	int		idx;
	freemap_t	*freemap;
	struct stat	sb;
	struct extvtoc	vtoc;
	int		geo;
	struct dk_geom	geom;
	char		*name;
	int		newvtoc = 0;
	struct dk_gpt	*efi;

	name = getfullrawname(devname);
	if (name == NULL)
		return (warn(devname,
		    "internal administrative call (getfullrawname) failed"));
	if (strcmp(name, "") == 0)
		name = devname;
	if ((fd = open(name, O_NONBLOCK|O_RDONLY)) < 0)
		return (warn(name, strerror(errno)));
	if (fstat(fd, &sb) < 0)
		return (warn(name, strerror(errno)));
	if ((sb.st_mode & S_IFMT) != S_IFCHR)
		return (warn(name, "Not a raw device"));

	geo = (readgeom(fd, name, &geom) == 0);
	if (geo) {
		if ((idx = readvtoc(fd, name, &vtoc)) == VT_ENOTSUP) {
			idx = (readefi(fd, name, &efi) == 0);
			newvtoc = 1;
		} else
			idx = (idx == 0);
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
		if (!newvtoc)
			puttable(&geom, &vtoc, freemap, devname,
			    getmntpt(major(sb.st_rdev),
			    noparttn(minor(sb.st_rdev))));
		else
			puttable64(efi, freemap, devname,
			    getmntpt(major(sb.st_rdev),
			    noparttn(minor(sb.st_rdev))));
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

/*
 * puttable(): Print a human-readable VTOC.
 */
static void
puttable(struct dk_geom *geom, struct extvtoc *vtoc, freemap_t *freemap,
    char *name, char **mtab)
{
	ushort_t	idx;
	ulong_t	cylsize;

	cylsize = (geom->dkg_nsect) * (geom->dkg_nhead);
	if (!hflag && !sflag) {
		(void) printf("* %s", name);
		if (*vtoc->v_volume)
			(void) printf(" (volume \"%.8s\")", vtoc->v_volume);

		(void) printf(" partition map\n");
		(void) printf("*\n* Dimensions:\n");
		(void) printf("* %7u bytes/sector\n", vtoc->v_sectorsz);
		(void) printf("* %7u sectors/track\n", geom->dkg_nsect);
		(void) printf("* %7u tracks/cylinder\n", geom->dkg_nhead);
		(void) printf("* %7lu sectors/cylinder\n", cylsize);
		(void) printf("* %7u cylinders\n", geom->dkg_pcyl);
		(void) printf("* %7u accessible cylinders\n", geom->dkg_ncyl);
		(void) printf("*\n* Flags:\n");
		(void) printf("*   1: unmountable\n");
		(void) printf("*  10: read-only\n*\n");

		if (freemap->fr_size) {
			(void) printf("* Unallocated space:\n");
			(void) printf("*\tFirst     Sector    Last\n");
			(void) printf("*\tSector     Count    Sector \n");
			do {
				(void) printf("*   %9llu %9llu %9llu\n",
				    freemap->fr_start, freemap->fr_size,
				    freemap->fr_size + freemap->fr_start - 1);
			} while ((++freemap)->fr_size);
			(void) printf("*\n");
		}
	}
	if (!hflag)  {
		(void) printf(\
"*                          First     Sector    Last\n"
"* Partition  Tag  Flags    Sector     Count    Sector  Mount Directory\n");
	}
	for (idx = 0; idx < vtoc->v_nparts; ++idx) {
		if (vtoc->v_part[idx].p_size == 0)
			continue;
		(void) printf("      %2u  %5u    %02x  %9llu %9llu %9llu",
		    idx, vtoc->v_part[idx].p_tag, vtoc->v_part[idx].p_flag,
		    vtoc->v_part[idx].p_start, vtoc->v_part[idx].p_size,
		    vtoc->v_part[idx].p_start + vtoc->v_part[idx].p_size - 1);
		if (mtab && mtab[idx])
			(void) printf("   %s", mtab[idx]);
		(void) printf("\n");
	}
}

/*
 * puttable(): Print a human-readable VTOC.
 */
static void
puttable64(struct dk_gpt *efi, freemap_t *freemap, char *name,
	char **mtab)
{
	ushort_t	idx;

	if (!hflag && !sflag) {
		(void) printf("* %s", name);
		for (idx = 0; idx < efi->efi_nparts; idx++)
		    if (efi->efi_parts[idx].p_tag == V_RESERVED &&
			*efi->efi_parts[idx].p_name)
			    (void) printf(" (volume \"%.8s\")",
				    efi->efi_parts[idx].p_name);
		(void) printf(" partition map\n");
		(void) printf("*\n* Dimensions:\n");
		(void) printf("* %7u bytes/sector\n", efi->efi_lbasize);
		(void) printf("* %llu sectors\n", efi->efi_last_lba + 1);
		(void) printf("* %llu accessible sectors\n",
		    efi->efi_last_u_lba - efi->efi_first_u_lba + 1);
		(void) printf("*\n* Flags:\n");
		(void) printf("*   1: unmountable\n");
		(void) printf("*  10: read-only\n*\n");

		if (freemap->fr_size) {
			(void) printf("* Unallocated space:\n");
			(void) printf("*\tFirst     Sector    Last\n");
			(void) printf("*\tSector     Count    Sector \n");
			do {
				(void) printf("*   %9llu %9llu %9llu\n",
				    freemap->fr_start, freemap->fr_size,
				    freemap->fr_size + freemap->fr_start - 1);
			} while ((++freemap)->fr_size);
			(void) printf("*\n");
		}
	}
	if (!hflag)  {
		(void) printf(\
"*                          First     Sector    Last\n"
"* Partition  Tag  Flags    Sector     Count    Sector  Mount Directory\n");
	}
	for (idx = 0; idx < efi->efi_nparts; ++idx) {
	    if (efi->efi_parts[idx].p_size == 0)
		    continue;
	    (void) printf("      %2u  %5u    %02x  %9llu %9llu %9llu",
		idx, efi->efi_parts[idx].p_tag, efi->efi_parts[idx].p_flag,
		efi->efi_parts[idx].p_start, efi->efi_parts[idx].p_size,
		efi->efi_parts[idx].p_start + efi->efi_parts[idx].p_size - 1);
	    if ((idx < 7) && mtab && mtab[idx])
		    (void) printf("   %s", mtab[idx]);
	    (void) printf("\n");
	}
}

/*
 * readgeom(): Read the disk geometry.
 */
static int
readgeom(int fd, char *name, struct dk_geom *geom)
{
	char err_string[128];

	if ((ioctl(fd, DKIOCGGEOM, geom) < 0) && (errno != ENOTSUP)) {
		(void) sprintf(err_string,
		    "Unable to read Disk geometry errno = 0x%x",
		    errno);
		return (warn(name, err_string));
	} else if (errno == ENOTSUP) {
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
	int	retval;

	if ((retval = read_extvtoc(fd, vtoc)) >= 0)
		return (0);

	switch (retval) {
	case (VT_EIO):
		return (warn(name, "Unable to read VTOC"));
	case (VT_EINVAL):
		return (warn(name, "Invalid VTOC"));
	case (VT_ERROR):
		return (warn(name, "Unknown problem reading VTOC"));
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
	case (VT_EIO):
		return (warn(name, "Unable to read VTOC"));
	case (VT_EINVAL):
		return (warn(name, "Invalid VTOC"));
	case (VT_ERROR):
		return (warn(name, "Unknown problem reading VTOC"));
	}
	return (retval);
}

static char *
safe_strdup(char *str)
{
	char *ret;
	if ((ret = strdup(str)) == NULL) {
		(void) warn("memory allocation", strerror(errno));
		exit(1);
	}
	return (ret);
}

/*
 * usage(): Print a helpful message and exit.
 */
static void
usage()
{
	(void) fprintf(stderr, "Usage:\t%s [ -fhs ] [ -t fstab ] [ -m mnttab ] "
	    "rawdisk ...\n", progname);
	exit(1);
}

/*
 * warn(): Print an error message. Always returns -1.
 */
static int
warn(char *what, char *why)
{
	(void) fprintf(stderr, "%s: %s: %s\n", progname, what, why);
	return (-1);
}
