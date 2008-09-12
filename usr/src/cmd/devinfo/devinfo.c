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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 *	Two output fields under the -i option will always be
 *	output as zero, since they are not supported by Sun:
 *		Software version, and
 *		Drive id number.
 *	AT&T filled these 2 fields with data from their "pdsector",
 *	which Sun doesn't support per se.
 */


#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/dkio.h>
#include <sys/efi_partition.h>
#include <sys/vtoc.h>
#include <sys/mkdev.h>
#include <errno.h>

#define	DRERR	2
#define	OPENERR	2

/*
 * Standard I/O file descriptors.
 */
#define	STDOUT	1		/* Standard output */
#define	STDERR	2		/* Standard error */

static	void	partinfo(int fd, char *device);
static	void	devinfo(struct dk_geom *geom, int fd, char *device);
static	int	readvtoc(int fd, char *name, struct extvtoc *vtoc);
static	int	warn(char *what, char *why);
static	void	usage(void);

int
main(int argc, char **argv)
{
	struct dk_geom  geom;
	int errflg, iflg, pflg, fd, c;
	char *device;

	iflg = 0;
	pflg = 0;
	errflg = 0;
	while ((c = getopt(argc, argv, "i:p:")) != EOF) {
		switch (c) {
			case 'i':
				iflg++;
				device = optarg;
				break;
			case 'p':
				pflg++;
				device = optarg;
				break;
			case '?':
				errflg++;
				break;
			default:
				errflg++;
				break;
		}
		if (errflg)
			usage();
	}
	if ((optind > argc) || (optind == 1) || (pflg && iflg))
		usage();

	if ((fd = open(device, O_RDONLY)) < 0) {
		(void) fprintf(stderr, "devinfo: %s: %s\n",
			device, strerror(errno));
		exit(OPENERR);
	}

	if (iflg) {
		if (ioctl(fd, DKIOCGGEOM, &geom) == -1) {
			if (errno == ENOTSUP) {
				(void) warn(device,
"This operation is not supported on EFI labeled devices");
			} else {
				(void) warn(device,
"Unable to read Disk geometry");
			}
			(void) close(fd);
			exit(DRERR);
		}
		devinfo(&geom, fd, device);
	}
	if (pflg)
		partinfo(fd, device);
	(void) close(fd);
	return (0);
}

static void
partinfo(int fd, char *device)
{
	int i;
	int	slice;
	major_t maj;
	minor_t min;
	struct stat64 statbuf;
	struct extvtoc vtdata;
	struct dk_gpt *efi;

	i = stat64(device, &statbuf);
	if (i < 0)
		exit(DRERR);
	maj = major(statbuf.st_rdev);
	min = minor(statbuf.st_rdev);

	if ((slice = readvtoc(fd, device, &vtdata)) >= 0) {

		(void) printf("%s\t%0lx\t%0lx\t%llu\t%llu\t%x\t%x\n",
			device, maj, min,
			vtdata.v_part[slice].p_start,
			vtdata.v_part[slice].p_size,
			vtdata.v_part[slice].p_flag,
			vtdata.v_part[slice].p_tag);
	} else if ((slice == VT_ENOTSUP) &&
	    (slice = efi_alloc_and_read(fd, &efi)) >= 0) {
		(void) printf("%s\t%lx\t%lx\t%lld\t%lld\t%hx\t%hx\n",
			device, maj, min,
			efi->efi_parts[slice].p_start,
			efi->efi_parts[slice].p_size,
			efi->efi_parts[slice].p_flag,
			efi->efi_parts[slice].p_tag);
	} else {
		exit(DRERR);
	}
}

static void
devinfo(struct dk_geom *geom, int fd, char *device)
{
	int i;
	unsigned int nopartitions, sectorcyl, bytes;
	struct extvtoc vtdata;
/*
 *	unsigned int version = 0;
 *	unsigned int driveid = 0;
 */

	nopartitions = 0;
	sectorcyl = 0;
	bytes = 0;

	if (readvtoc(fd, device, &vtdata) < 0)
		exit(DRERR);
	sectorcyl = geom->dkg_nhead  *  geom->dkg_nsect;
	bytes = vtdata.v_sectorsz;
/*
 *	these are not supported by Sun.
 *
 *	driveid = osect0->newsect0.pdinfo.driveid;
 *	version = osect0->newsect0.pdinfo.version;
 */
	for (i = 0; i < V_NUMPAR; i++)	{
		if (vtdata.v_part[i].p_size != 0x00)
			nopartitions++;
	}
/*
 *	(void) printf("%s	%0x	%0x	%d	%d	%d\n",
 *		device, version, driveid, sectorcyl, bytes, nopartitions);
 */
	(void) printf("%s	%0x	%0x	%d	%d	%d\n",
		device, 0, 0, sectorcyl, bytes, nopartitions);
}


/*
 * readvtoc()
 *
 * Read a partition map.
 */
static int
readvtoc(int fd, char *name, struct extvtoc *vtoc)
{
	int	retval;

	retval = read_extvtoc(fd, vtoc);

	switch (retval) {
		case (VT_ERROR):
			return (warn(name, strerror(errno)));
		case (VT_EIO):
			return (warn(name, "I/O error accessing VTOC"));
		case (VT_EINVAL):
			return (warn(name, "Invalid field in VTOC"));
		}

	return (retval);
}


/*
 * warn()
 *
 * Print an error message. Always returns -1.
 */
static int
warn(char *what, char *why)
{
	static char	myname[]  = "devinfo";
	static char	between[] = ": ";
	static char	after[]   = "\n";

	(void) write(STDERR, myname, (uint_t)strlen(myname));
	(void) write(STDERR, between, (uint_t)strlen(between));
	(void) write(STDERR, what, (uint_t)strlen(what));
	(void) write(STDERR, between, (uint_t)strlen(between));
	(void) write(STDERR, why, (uint_t)strlen(why));
	(void) write(STDERR, after, (uint_t)strlen(after));
	return (-1);
}

static void
usage(void)
{
	(void) fprintf(stderr, "Usage: devinfo -p device\n"
		"       devinfo -i device \n");
	exit(2);
}
