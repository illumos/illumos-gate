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

/*
 *   diskscan:
 *   performs a verification pass over a device specified on command line;
 *   display progress on stdout, and print bad sector numbers to stderr
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>
#include <memory.h>
#include <ctype.h>
#include <malloc.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/vtoc.h>
#include <sys/dkio.h>

static void verexit();	/* signal handler and exit routine	*/
static void report();	   /* tell user how we're getting on */
static void scandisk(char *device, int devfd, int writeflag);
static void report(char *what, diskaddr_t sector);
static void verexit(int code);

#define	TRUE		1
#define	FALSE		0
#define	VER_WRITE	1
#define	VER_READ	2

static char	*progname;
static struct  dk_geom	dkg;	  /* physical device boot info */
static char	replybuf[64];	  /* used for user replies to questions */
static diskaddr_t unix_base;	  /* first sector of UNIX System partition */
static diskaddr_t unix_size;	  /* # sectors in UNIX System partition */
static long	numbadrd = 0;	  /* number of bad sectors on read */
static long	numbadwr = 0;	  /* number of bad sectors on write */
static char	eol = '\n';	  /* end-of-line char (if -n, we set to '\n') */
static int	print_warn = 1;	  /* should the warning message be printed? */
static int do_scan = VER_READ;

int
main(int argc, char *argv[]) {
	extern int	optind;
	int		devfd;	/* device file descriptor */
	struct stat 	statbuf;
	struct part_info	part_info;
	struct extpart_info	extpartinfo;
	int		c;
	int		errflag = 0;
	char		*device;
	progname = argv[0];

	/* Don't buffer stdout - we don't want to see bursts */

	setbuf(stdout, NULL);

	while ((c = getopt(argc, argv, "Wny")) != -1)
	{
		switch (c) {
		case 'W':
			do_scan = VER_WRITE;
			break;

		case 'n':
			eol = '\r';
			break;

		case 'y':
			print_warn = 0;
			break;

		default:
			++errflag;
			break;
		}
	}

	if ((argc - optind) < 1)
		errflag++;

	if (errflag) {
		(void) fprintf(stderr,
		    "\nUsage: %s [-W] [-n] [-y] <phys_device_name> \n",
			    progname);
		exit(1);
	}

	device = argv[optind];

	if (stat(device, &statbuf)) {
		(void) fprintf(stderr,
		    "%s: invalid device %s, stat failed\n", progname, device);
		perror("");
		exit(4);
	}
	if ((statbuf.st_mode & S_IFMT) != S_IFCHR) {
		(void) fprintf(stderr,
		    "%s: device %s is not character special\n",
			    progname, device);
		exit(5);
	}
	if ((devfd = open(device, O_RDWR)) == -1) {
		(void) fprintf(stderr,
		    "%s: open of %s failed\n", progname, device);
		perror("");
		exit(8);
	}

	if ((ioctl(devfd, DKIOCGGEOM, &dkg)) == -1) {
		(void) fprintf(stderr,
		    "%s: unable to get disk geometry.\n", progname);
		perror("");
		exit(9);
	}

	if ((ioctl(devfd, DKIOCEXTPARTINFO, &extpartinfo)) == 0) {
		unix_base = extpartinfo.p_start;
		unix_size = extpartinfo.p_length;
	} else {
		if ((ioctl(devfd, DKIOCPARTINFO, &part_info)) == 0) {
			unix_base = (ulong_t)part_info.p_start;
			unix_size = (uint_t)part_info.p_length;
		} else {
			(void) fprintf(stderr, "%s: unable to get partition "
			    "info.\n", progname);
			perror("");
			exit(9);
		}
	}

	scandisk(device, devfd, do_scan);
	return (0);
}

/*
 *  scandisk:
 *	  attempt to read every sector of the drive;
 *	  display bad sectors found on stderr
 */

static void
scandisk(char *device, int devfd, int writeflag)
{
	int	 trksiz = NBPSCTR * dkg.dkg_nsect;
	char	*verbuf;
	diskaddr_t cursec;
	int	 cylsiz =  dkg.dkg_nsect * dkg.dkg_nhead;
	int	 i;
	char	*rptr;
	diskaddr_t tmpend = 0;
	diskaddr_t tmpsec = 0;

/* #define LIBMALLOC */

#ifdef LIBMALLOC

	extern int  mallopt();

	/* This adds 5k to the binary, but it's a lot prettier */


	/* make track buffer sector aligned */
	if (mallopt(M_GRAIN, 0x200)) {
		perror("mallopt");
		exit(1);
	}
	if ((verbuf = malloc(NBPSCTR * dkg.dkg_nsect)) == (char *)NULL) {
		perror("malloc");
		exit(1);
	}

#else

	if ((verbuf = malloc(0x200 + NBPSCTR * dkg.dkg_nsect))
	    == (char *)NULL) {
		perror("malloc");
		exit(1);
	}
	verbuf = (char *)(((unsigned long)verbuf + 0x00000200) & 0xfffffe00);

#endif

	/* write pattern in track buffer */

	for (i = 0; i < trksiz; i++)
		verbuf[i] = (char)0xe5;

	/* Turn off retry, and set trap to turn them on again */

	(void) signal(SIGINT, verexit);
	(void) signal(SIGQUIT, verexit);

	if (writeflag == VER_READ)
		goto do_readonly;

	/*
	 *   display warning only if -n arg not passed
	 *   (otherwise the UI system will take care of it)
	 */

	if (print_warn == 1) {
		(void) printf(
		    "\nCAUTION: ABOUT TO DO DESTRUCTIVE WRITE ON %s\n", device);
		(void) printf("	 THIS WILL DESTROY ANY DATA YOU HAVE ON\n");
		(void) printf("	 THAT PARTITION OR SLICE.\n");
		(void) printf("Do you want to continue (y/n)? ");

		rptr = fgets(replybuf, 64*sizeof (char), stdin);
		if (!rptr || !((replybuf[0] == 'Y') || (replybuf[0] == 'y')))
			exit(10);
	}

	for (cursec = 0; cursec < unix_size; cursec +=  dkg.dkg_nsect) {
		if (llseek(devfd, cursec * NBPSCTR, 0) == -1) {
			(void) fprintf(stderr,
			    "Error seeking sector %llu Cylinder %llu\n",
			    cursec, cursec / cylsiz);
			verexit(1);
		}

		/*
		 * verify sector at a time only when
		 * the whole track write fails;
		 *  (if we write a sector at a time, it takes forever)
		 */

		report("Writing", cursec);

		if (write(devfd, verbuf, trksiz) != trksiz) {
			tmpend = cursec +  dkg.dkg_nsect;
			for (tmpsec = cursec; tmpsec < tmpend; tmpsec++) {
				/*
				 *  try writing to it once; if this fails,
				 *  then announce the sector bad on stderr
				 */

				if (llseek(devfd, tmpsec * NBPSCTR, 0) == -1) {
					(void) fprintf(stderr, "Error seeking "
					    "sector %llu Cylinder %llu\n",
					    tmpsec, cursec / cylsiz);
					verexit(1);
				}

				report("Writing", tmpsec);

				if (write(devfd, verbuf, NBPSCTR) != NBPSCTR) {
					(void) fprintf(stderr,
					    "%llu\n", tmpsec + unix_base);
					numbadwr++;
				}
			}
		}
	}

	(void) putchar(eol);
	do_readonly:

	for (cursec = 0; cursec < unix_size; cursec +=  dkg.dkg_nsect) {
		if (llseek(devfd, cursec * NBPSCTR, 0) == -1) {
			(void) fprintf(stderr,
			    "Error seeking sector %llu Cylinder %llu\n",
			    cursec, cursec / cylsiz);
			verexit(1);
		}

		/*
		 * read a sector at a time only when
		 * the whole track write fails;
		 * (if we do a sector at a time read, it takes forever)
		 */

		report("Reading", cursec);
		if (read(devfd, verbuf, trksiz) != trksiz) {
			tmpend = cursec +  dkg.dkg_nsect;
			for (tmpsec = cursec; tmpsec < tmpend; tmpsec++) {
				if (llseek(devfd, tmpsec * NBPSCTR, 0) == -1) {
					(void) fprintf(stderr, "Error seeking"
					    " sector %llu Cylinder %llu\n",
					    tmpsec, cursec / cylsiz);
					verexit(1);
				}
				report("Reading", tmpsec);
				if (read(devfd, verbuf, NBPSCTR) != NBPSCTR) {
					(void) fprintf(stderr, "%llu\n",
					    tmpsec + unix_base);
					numbadrd++;
				}
			}
		}
	}
	(void) printf("%c%c======== Diskscan complete ========%c", eol,
	    eol, eol);

	if ((numbadrd > 0) || (numbadwr > 0)) {
		(void) printf("%cFound %ld bad sector(s) on read,"
		    " %ld bad sector(s) on write%c",
		    eol, numbadrd, numbadwr, eol);
	}
}

static void
verexit(int code)
{
	(void) printf("\n");
	exit(code);
}


/*
 *   report where we are...
 */

static void
report(char *what, diskaddr_t sector)
{
	(void) printf("%s sector %-19llu of %-19llu%c", what, sector,
	    unix_size, eol);
}
