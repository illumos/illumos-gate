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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/dkio.h>
#include <sys/vtoc.h>
#include <sys/mkdev.h>
#ifdef DKIOCPARTITION
#include <sys/efi_partition.h>
#endif
#include <strings.h>
#include <stdarg.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <locale.h>
#include <unistd.h>
#include <libgen.h>
#include <kstat.h>

#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_u.h>
#include <sys/unistat/spcs_errors.h>

#include <sys/nsctl/dsw.h>
#include <sys/nsctl/dsw_dev.h>
#include <sys/nsctl/rdc_io.h>
#include <sys/nsctl/rdc_bitmap.h>

enum { UNKNOWN = 0, SNDR, II };

static char *program;

void
usage(void)
{
	(void) printf(gettext("usage: %s -h\n"), program);
	(void) printf(gettext("       %s { -p | -r } data_volume "
	    "[bitmap_volume]\n"), program);
	(void) printf(gettext("       -h : This usage message\n"));
	(void) printf(gettext("       -p : Calculate size of Point in Time "
	    "bitmap\n"));
	(void) printf(gettext("       -r : Calculate size of Remote Mirror "
	    "bitmap\n"));
}


static void
message(char *prefix, spcs_s_info_t *status, caddr_t string, va_list ap)
{
	(void) fprintf(stderr, "%s: %s: ", program, prefix);
	(void) vfprintf(stderr, string, ap);
	(void) fprintf(stderr, "\n");

	if (status) {
		spcs_s_report(*status, stderr);
		spcs_s_ufree(status);
	}
}


static void
error(spcs_s_info_t *status, char *string, ...)
{
	va_list ap;
	va_start(ap, string);

	message(gettext("error"), status, string, ap);
	va_end(ap);
	exit(1);
}


static void
warn(spcs_s_info_t *status, char *string, ...)
{
	va_list ap;
	va_start(ap, string);

	message(gettext("warning"), status, string, ap);
	va_end(ap);
}

#if defined(_LP64)
					/* max value of a "long int" */
#define	ULONG_MAX	18446744073709551615UL
#else /* _ILP32 */
#define	ULONG_MAX	4294967295UL	/* max of "unsigned long int" */
#endif

static uint64_t
get_partsize(char *partition)
{
#ifdef DKIOCPARTITION
	struct dk_cinfo dki_info;
	struct partition64 p64;
#endif
	struct vtoc vtoc;
	uint64_t size;
	int fd;
	int rc;

	if ((fd = open(partition, O_RDONLY)) < 0) {
		error(NULL, gettext("unable to open partition, %s: %s"),
		    partition, strerror(errno));
		/* NOTREACHED */
	}

	rc = read_vtoc(fd, &vtoc);
	if (rc >= 0) {
		size = (uint64_t)(ULONG_MAX & vtoc.v_part[rc].p_size);
		return (size);
	}
#ifdef DKIOCPARTITION
	else if (rc != VT_ENOTSUP) {
#endif
		error(NULL,
		    gettext("unable to read the vtoc from partition, %s: %s"),
		    partition, strerror(errno));
		/* NOTREACHED */
#ifdef DKIOCPARTITION
	}

	/* See if there is an EFI label */
	rc = ioctl(fd, DKIOCINFO, &dki_info);
	if (rc < 0) {
		error(NULL, gettext("unable to get controller info "
		    "from partition, %s: %s"),
		    partition, strerror(errno));
		/* NOTREACHED */
	}

	bzero(&p64, sizeof (p64));
	p64.p_partno = (uint_t)dki_info.dki_partition;
	rc = ioctl(fd, DKIOCPARTITION, &p64);
	if (rc >= 0) {
		size = (uint64_t)p64.p_size;
		return (size);
	} else {
		struct stat64 stb1, stb2;
		struct dk_minfo dkm;

		/*
		 * See if the stat64 for ZFS's zvol matches
		 * this file descriptor's fstat64 data.
		 */
		if (stat64("/devices/pseudo/zfs@0:zfs", &stb1) != 0 ||
		    fstat64(fd, &stb2) != 0 ||
		    !S_ISCHR(stb1.st_mode) ||
		    !S_ISCHR(stb2.st_mode) ||
		    major(stb1.st_rdev) != major(stb2.st_rdev)) {
			error(NULL,
			    gettext("unable to read disk partition, %s: %s"),
			    partition, strerror(errno));
			/* NOTREACHED */
		}

		rc = ioctl(fd, DKIOCGMEDIAINFO, (void *)&dkm);
		if (rc >= 0) {
			size = LE_64(dkm.dki_capacity) *
				dkm.dki_lbsize / 512;
			return (size);
		} else {
			error(NULL, gettext("unable to read EFI label "
			    "from partition, %s: %s"),
			    partition, strerror(errno));
			/* NOTREACHED */
		}
	}
	return (size);

#endif	/* DKIOCPARTITION */
}


int
do_sndr(char *volume, char *bitmap)
{
	uint64_t vblocks;
	uint64_t bblocks;
	uint64_t bsize_bits;	/* size of the bits alone */
	uint64_t bsize_simple;	/* size of the simple bitmap */
	uint64_t bsize_diskq;	/* size of the diskq bitmap, 8 bit refcnt */
	uint64_t bsize_diskq32;	/* size of the diskq bitmap, 32 bit refcnt */
	int rc = 0;

	vblocks = get_partsize(volume);
	if (bitmap) {
		bblocks = get_partsize(bitmap);
	}

	bsize_bits = BMAP_LOG_BYTES(vblocks);
	bsize_bits = (bsize_bits + 511) / 512;

	bsize_simple = RDC_BITMAP_FBA + bsize_bits;
	bsize_diskq = RDC_BITMAP_FBA + bsize_bits + (BITS_IN_BYTE * bsize_bits);
	bsize_diskq32 = RDC_BITMAP_FBA + bsize_bits + (BITS_IN_BYTE *
		bsize_bits * sizeof (unsigned int));

	(void) printf(gettext("Remote Mirror bitmap sizing\n\n"));
	(void) printf(gettext("Data volume (%s) size: %llu blocks\n"),
	    volume, vblocks);

	(void) printf(gettext("Required bitmap volume size:\n"));
	(void) printf(gettext("  Sync replication: %llu blocks\n"),
	    bsize_simple);
	(void) printf(gettext("  Async replication with memory queue: "
	    "%llu blocks\n"), bsize_simple);
	(void) printf(gettext("  Async replication with disk queue: "
	    "%llu blocks\n"), bsize_diskq);
	(void) printf(gettext("  Async replication with disk queue and 32 bit "
	    "refcount: %llu blocks\n"), bsize_diskq32);

	if (bitmap) {
		(void) printf("\n");
		(void) printf(gettext("Supplied bitmap volume %s "
		    "(%llu blocks)\n"),
		    bitmap, bblocks);
		if (bblocks >= bsize_diskq32) {
			(void) printf(gettext("is large enough for all "
			    "replication modes\n"));
		} else if (bblocks >= bsize_diskq) {
			(void) printf(gettext("is large enough for all "
			    "replication modes, but with restricted diskq "
			    "reference counts\n"));
		} else if (bblocks >= bsize_simple) {
			(void) printf(gettext(
			    "is large enough for: Sync and Async(memory) "
			    "replication modes only\n"));
			rc = 3;
		} else {
			(void) printf(gettext(
			    "is not large enough for any replication modes\n"));
			rc = 4;
		}
	}

	return (rc);
}


/* sizes in bytes */
#define	KILO	(1024)
#define	MEGA	(KILO * KILO)
#define	GIGA	(MEGA * KILO)
#define	TERA	((uint64_t)((uint64_t)GIGA * (uint64_t)KILO))

/* rounding function */
#define	roundup_2n(x, y)	(((x) + ((y) - 1)) & (~y))

int
do_ii(char *volume, char *bitmap)
{
	const uint64_t int64_bits = sizeof (uint64_t) * BITS_IN_BYTE;
	const uint64_t int32_bits = sizeof (uint32_t) * BITS_IN_BYTE;
	const uint64_t terablocks = TERA / ((uint64_t)FBA_SIZE(1));
	uint64_t vblocks_phys, vblocks;
	uint64_t bblocks;
	uint64_t bsize_ind;	/* indep and dep not compact */
	uint64_t bsize_cdep;	/* compact dep */
	int rc = 0;

	vblocks_phys = get_partsize(volume);
	if (bitmap) {
		bblocks = get_partsize(bitmap);
	}

	/* round up to multiple of DSW_SIZE blocks */
	vblocks = roundup_2n(vblocks_phys, DSW_SIZE);
	bsize_ind = DSW_SHD_BM_OFFSET + (2 * DSW_BM_FBA_LEN(vblocks));
	bsize_cdep = bsize_ind;
	bsize_cdep += DSW_BM_FBA_LEN(vblocks) *
	    ((vblocks < (uint64_t)(terablocks * DSW_SIZE)) ?
	    int32_bits : int64_bits);

	(void) printf(gettext("Point in Time bitmap sizing\n\n"));
	(void) printf(gettext("Data volume (%s) size: %llu blocks\n"),
	    volume, vblocks_phys);

	(void) printf(gettext("Required bitmap volume size:\n"));
	(void) printf(gettext("  Independent shadow: %llu blocks\n"),
	    bsize_ind);
	(void) printf(gettext("  Full size dependent shadow: %llu blocks\n"),
	    bsize_ind);
	(void) printf(gettext("  Compact dependent shadow: %llu blocks\n"),
	    bsize_cdep);

	if (bitmap) {
		(void) printf("\n");
		(void) printf(gettext("Supplied bitmap volume %s "
		    "(%llu blocks)\n"), bitmap, bblocks);

		if (bblocks >= bsize_cdep) {
			(void) printf(gettext("is large enough for all types "
			    "of shadow volume\n"));
		} else if (bblocks >= bsize_ind) {
			(void) printf(gettext("is large enough for: "
			    "Independent and full size dependent shadow "
			    "volumes only\n"));
			rc = 6;
		} else {
			(void) printf(gettext("is not large enough for"
			    "any type of shadow volume\n"));
			rc = 5;
		}
	}

	return (rc);
}


/*
 * Return codes:
 *	0 success (if bitmap was supplied it is large enough for all uses)
 *	1 usage, programing, or access errors
 *	2 unknown option supplied on command line
 *	3 SNDR bitmap is not large enough for diskq usage
 *	4 SNDR bitmap is not large enough for any usage
 *	5 II bitmap is not large enough for any usage
 *	6 II bitmap is not large enough for compact dependent usage
 */
int
main(int argc, char *argv[])
{
	extern int optind;
	char *volume, *bitmap;
	int type = UNKNOWN;
	int opt;
	int rc = 0;

	(void) setlocale(LC_ALL, "");
	(void) textdomain("dsbitmap");

	program = strdup(basename(argv[0]));

	while ((opt = getopt(argc, argv, "hpr")) != EOF) {
		switch (opt) {
		case 'p':
			if (type != UNKNOWN) {
				warn(NULL, gettext(
				    "cannot specify -p with other options"));
				usage();
				return (1);
			}
			type = II;
			break;

		case 'r':
			if (type != UNKNOWN) {
				warn(NULL, gettext(
				    "cannot specify -r with other options"));
				usage();
				return (1);
			}
			type = SNDR;
			break;

		case 'h':
			if (argc != 2) {
				warn(NULL, gettext(
				    "cannot specify -h with other options"));
				rc = 1;
			}
			usage();
			return (rc);
			/* NOTREACHED */

		default:
			usage();
			return (2);
			/* NOTREACHED */
		}
	}

	if (type == UNKNOWN) {
		warn(NULL, gettext("one of -p and -r must be specified"));
		usage();
		return (1);
	}

	if ((argc - optind) != 1 && (argc - optind) != 2) {
		warn(NULL, gettext("incorrect number of arguments to %s"),
		    (type == SNDR) ? "-r" : "-p");
		usage();
		return (1);
	}

	volume = argv[optind];
	if ((argc - optind) == 2) {
		bitmap = argv[optind+1];
	} else {
		bitmap = NULL;
	}

	switch (type) {
	case SNDR:
		rc = do_sndr(volume, bitmap);
		break;

	case II:
		rc = do_ii(volume, bitmap);
		break;

	default:
		/* cannot happen */
		warn(NULL, gettext("one of -p and -r must be specified"));
		rc = 1;
		break;
	}

	return (rc);
}
