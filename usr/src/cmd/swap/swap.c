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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * 	Swap administrative interface
 *	Used to add/delete/list swap devices.
 */

#include	<sys/types.h>
#include	<sys/dumpadm.h>
#include	<string.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<errno.h>
#include	<sys/param.h>
#include	<dirent.h>
#include	<sys/swap.h>
#include	<sys/sysmacros.h>
#include	<sys/mkdev.h>
#include	<sys/stat.h>
#include	<sys/statvfs.h>
#include	<sys/uadmin.h>
#include	<vm/anon.h>
#include	<fcntl.h>
#include	<locale.h>
#include	<libintl.h>
#include	<libdiskmgt.h>

#define	LFLAG	0x01	/* swap -l (list swap devices) */
#define	DFLAG	0x02	/* swap -d (delete swap device) */
#define	AFLAG	0x04	/* swap -a (add swap device) */
#define	SFLAG	0x08	/* swap -s (swap info summary) */
#define	P1FLAG	0x10	/* swap -1 (swapadd pass1; do not modify dump device) */
#define	P2FLAG	0x20	/* swap -2 (swapadd pass2; do not modify dump device) */

static char *prognamep;

static int add(char *, off_t, off_t, int);
static int delete(char *, off_t);
static void usage(void);
static int doswap(void);
static int valid(char *, off_t, off_t);
static int list(void);

int
main(int argc, char **argv)
{
	int c, flag = 0;
	int ret;
	int error = 0;
	off_t s_offset = 0;
	off_t length = 0;
	char *pathname;
	char *msg;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	prognamep = argv[0];
	if (argc < 2) {
		usage();
		exit(1);
	}

	while ((c = getopt(argc, argv, "lsd:a:12")) != EOF) {
		char *char_p;
		switch (c) {
		case 'l': 	/* list all the swap devices */
			if (argc != 2 || flag) {
				usage();
				exit(1);
			}
			flag |= LFLAG;
			ret = list();
			break;
		case 's':
			if (argc != 2 || flag) {
				usage();
				exit(1);
			}
			flag |= SFLAG;
			ret = doswap();
			break;
		case 'd':
			/*
			 * The argument for starting offset is optional.
			 * If no argument is specified, the entire swap file
			 * is added although this will fail if a non-zero
			 * starting offset was specified when added.
			 */
			if ((argc - optind) > 1 || flag != 0) {
				usage();
				exit(1);
			}
			flag |= DFLAG;
			pathname = optarg;
			if (optind < argc) {
				errno = 0;
				s_offset = strtol(argv[optind++], &char_p, 10);
				if (errno != 0 || *char_p != '\0') {
					(void) fprintf(stderr,
					    gettext("error in [low block]\n"));
					exit(1);
				}
			}
			ret = delete(pathname, s_offset);
			break;

		case 'a':
			/*
			 * The arguments for starting offset and number of
			 * blocks are optional.  If only the starting offset
			 * is specified, all the blocks to the end of the swap
			 * file will be added.  If no starting offset is
			 * specified, the entire swap file is assumed.
			 */
			if ((argc - optind) > 2 ||
			    (flag & ~(P1FLAG | P2FLAG)) != 0) {
				usage();
				exit(1);
			}
			if (*optarg != '/') {
				(void) fprintf(stderr,
				    gettext("%s: path must be absolute\n"),
				    prognamep);
				exit(1);
			}
			flag |= AFLAG;
			pathname = optarg;
			if (optind < argc) {
				errno = 0;
				s_offset = strtol(argv[optind++], &char_p, 10);
				if (errno != 0 || *char_p != '\0') {
					(void) fprintf(stderr,
					    gettext("error in [low block]\n"));
					exit(1);
				}
			}
			if (optind < argc) {
				errno = 0;
				length = strtol(argv[optind++], &char_p, 10);
				if (errno != 0 || *char_p != '\0') {
					(void) fprintf(stderr,
					gettext("error in [nbr of blocks]\n"));
					exit(1);
				}
			}
			break;

		case '1':
			flag |= P1FLAG;
			break;

		case '2':
			flag |= P2FLAG;
			break;

		case '?':
			usage();
			exit(1);
		}
	}
	/*
	 * do the add here. Check for in use prior to add.
	 * The values for length and offset are set above.
	 */
	if (flag & AFLAG) {
		/*
		 * If device is in use for a swap device, print message
		 * and exit.
		 */
		if (dm_inuse(pathname, &msg, DM_WHO_SWAP, &error) ||
		    error) {
			if (error != 0) {
				(void) fprintf(stderr, gettext("Error occurred"
				    " with device in use checking: %s\n"),
				    strerror(error));
			} else {
				(void) fprintf(stderr, "%s", msg);
				free(msg);
				exit(1);
			}
		}
		if ((ret = valid(pathname,
		    s_offset * 512, length * 512)) == 0) {
		    ret = add(pathname, s_offset, length, flag);
		}
	}
	if (!flag) {
		usage();
		exit(1);
	}
	return (ret);
}


static void
usage(void)
{
	(void) fprintf(stderr, gettext("Usage:\t%s -l\n"), prognamep);
	(void) fprintf(stderr, "\t%s -s\n", prognamep);
	(void) fprintf(stderr, gettext("\t%s -d <file name> [low block]\n"),
			prognamep);
	(void) fprintf(stderr, gettext("\t%s -a <file name> [low block]"
	    " [nbr of blocks]\n"), prognamep);
}

/*
 * Implement:
 *	#define ctok(x) ((ctob(x))>>10)
 * in a machine independent way. (Both assume a click > 1k)
 */
static size_t
ctok(pgcnt_t clicks)
{
	static int factor = -1;

	if (factor == -1)
		factor = (int)(sysconf(_SC_PAGESIZE) >> 10);
	return ((size_t)(clicks * factor));
}


static int
doswap(void)
{
	struct anoninfo ai;
	pgcnt_t allocated, reserved, available;

	/*
	 * max = total amount of swap space including physical memory
	 * ai.ani_max = MAX(anoninfo.ani_resv, anoninfo.ani_max) +
	 *	availrmem - swapfs_minfree;
	 * ai.ani_free = amount of unallocated anonymous memory
	 *	(ie. = resverved_unallocated + unreserved)
	 * ai.ani_free = anoninfo.ani_free + (availrmem - swapfs_minfree);
	 * ai.ani_resv = total amount of reserved anonymous memory
	 * ai.ani_resv = anoninfo.ani_resv;
	 *
	 * allocated = anon memory not free
	 * reserved = anon memory reserved but not allocated
	 * available = anon memory not reserved
	 */
	if (swapctl(SC_AINFO, &ai) == -1) {
		perror(prognamep);
		return (2);
	}

	allocated = ai.ani_max - ai.ani_free;
	reserved = ai.ani_resv - allocated;
	available = ai.ani_max - ai.ani_resv;

	/*
	 * TRANSLATION_NOTE
	 * Translations (if any) of these keywords should match with
	 * translations (if any) of the swap.1M man page keywords for
	 * -s option:  "allocated", "reserved", "used", "available"
	 */
	(void) printf(gettext("total: %luk bytes allocated + %luk reserved = \
%luk used, %luk available\n"),
	    ctok(allocated), ctok(reserved), ctok(reserved) + ctok(allocated),
	    ctok(available));

	return (0);
}

static int
list(void)
{
	struct swaptable 	*st;
	struct swapent	*swapent;
	int	i;
	struct stat64 statbuf;
	char		*path;
	char		fullpath[MAXPATHLEN+1];
	int		num;

	if ((num = swapctl(SC_GETNSWP, NULL)) == -1) {
		perror(prognamep);
		return (2);
	}
	if (num == 0) {
		(void) fprintf(stderr, gettext("No swap devices configured\n"));
		return (1);
	}

	if ((st = malloc(num * sizeof (swapent_t) + sizeof (int)))
	    == NULL) {
		(void) fprintf(stderr,
			gettext("Malloc failed. Please try later.\n"));
		perror(prognamep);
		return (2);
	}
	if ((path = malloc(num * MAXPATHLEN)) == NULL) {
		(void) fprintf(stderr,
			gettext("Malloc failed. Please try later.\n"));
		perror(prognamep);
		return (2);
	}
	swapent = st->swt_ent;
	for (i = 0; i < num; i++, swapent++) {
		swapent->ste_path = path;
		path += MAXPATHLEN;
	}

	st->swt_n = num;
	if ((num = swapctl(SC_LIST, st)) == -1) {
		perror(prognamep);
		return (2);
	}

	/*
	 * TRANSLATION_NOTE
	 * Following translations for "swap -l" should account for for
	 * alignment of header and output.
	 * The first translation is for the header.  If the alignment
	 *	of the header changes, change the next 5 formats as needed
	 *	to make alignment of output agree with alignment of the header.
	 * The next four translations are four cases for printing the
	 * 	1st & 2nd fields.
	 * The next translation is for printing the 3rd, 4th & 5th fields.
	 *
	 * Translations (if any) of the following keywords should match the
	 * translations (if any) of the swap.1M man page keywords for
	 * -l option:  "swapfile", "dev", "swaplo", "blocks", "free"
	 */
	(void) printf(
		gettext("swapfile             dev  swaplo blocks   free\n"));

	swapent = st->swt_ent;
	for (i = 0; i < num; i++, swapent++) {
		if (*swapent->ste_path != '/')
			(void) snprintf(fullpath, sizeof (fullpath),
				"/dev/%s", swapent->ste_path);
		else
			(void) snprintf(fullpath, sizeof (fullpath),
				"%s", swapent->ste_path);
		if (stat64(fullpath, &statbuf) < 0)
			if (*swapent->ste_path != '/')
				(void) printf(gettext("%-20s  -  "),
					swapent->ste_path);
			else
				(void) printf(gettext("%-20s ?,? "),
					fullpath);
		else {
			if (statbuf.st_mode & (S_IFBLK | S_IFCHR))
				(void) printf(gettext("%-19s %2lu,%-2lu"),
				    fullpath,
				    major(statbuf.st_rdev),
				    minor(statbuf.st_rdev));
			else
				(void) printf(gettext("%-20s  -  "), fullpath);
		}
		{
		int diskblks_per_page =
			(int)(sysconf(_SC_PAGESIZE) >> DEV_BSHIFT);
		(void) printf(gettext(" %6lu %6lu %6lu"), swapent->ste_start,
		    swapent->ste_pages * diskblks_per_page,
		    swapent->ste_free * diskblks_per_page);
		}
		if (swapent->ste_flags & ST_INDEL)
			(void) printf(" INDEL\n");
		else
			(void) printf("\n");
	}
	return (0);
}

static void
dumpadm_err(const char *warning)
{
	(void) fprintf(stderr, "%s (%s):\n", warning, strerror(errno));
	(void) fprintf(stderr, gettext(
	    "run dumpadm(1M) to verify dump configuration\n"));
}

static int
delete(char *path, off_t offset)
{
	swapres_t swr;
	int fd;

	swr.sr_name = path;
	swr.sr_start = offset;

	if (swapctl(SC_REMOVE, &swr) < 0) {
		switch (errno) {
		case (ENOSYS):
			(void) fprintf(stderr, gettext(
			    "%s: Invalid operation for this filesystem type\n"),
			    path);
			break;
		default:
			perror(path);
			break;
		}
		return (2);
	}

	/*
	 * If our swap -d succeeded, open up /dev/dump and ask what the dump
	 * device is set to.  If this returns ENODEV, we just deleted the
	 * dump device, so try to change the dump device to another swap
	 * device.  We do this by firing up /usr/sbin/dumpadm -ud swap.
	 */
	if ((fd = open("/dev/dump", O_RDONLY)) >= 0) {
		char dumpdev[MAXPATHLEN];

		if (ioctl(fd, DIOCGETDEV, dumpdev) == -1) {
			if (errno == ENODEV) {
				(void) printf(gettext("%s was dump device --\n"
				    "invoking dumpadm(1M) -d swap to "
				    "select new dump device\n"), path);
				/*
				 * Close /dev/dump prior to executing dumpadm
				 * since /dev/dump mandates exclusive open.
				 */
				(void) close(fd);

				if (system("/usr/sbin/dumpadm -ud swap") == -1)
					dumpadm_err(gettext(
				"Warning: failed to execute dumpadm -d swap"));
			} else
				dumpadm_err(gettext(
				"Warning: failed to check dump device"));
		}
		(void) close(fd);
	} else
		dumpadm_err(gettext("Warning: failed to open /dev/dump"));

	return (0);
}

/*
 * swapres_t structure units are in 512-blocks
 */
static int
add(char *path, off_t offset, off_t cnt, int flags)
{
	swapres_t swr;

	int fd, have_dumpdev = 1;
	struct statvfs fsb;

	/*
	 * Before adding swap, we first check to see if we have a dump
	 * device configured.  If we don't (errno == ENODEV), and if
	 * our SC_ADD is successful, then run /usr/sbin/dumpadm -ud swap
	 * to attempt to reconfigure the dump device to the new swap.
	 */
	if ((fd = open("/dev/dump", O_RDONLY)) >= 0) {
		char dumpdev[MAXPATHLEN];

		if (ioctl(fd, DIOCGETDEV, dumpdev) == -1) {
			if (errno == ENODEV)
				have_dumpdev = 0;
			else
				dumpadm_err(gettext(
				    "Warning: failed to check dump device"));
		}

		(void) close(fd);

	} else if (!(flags & P1FLAG))
		dumpadm_err(gettext("Warning: failed to open /dev/dump"));

	swr.sr_name = path;
	swr.sr_start = offset;
	swr.sr_length = cnt;

	if (swapctl(SC_ADD, &swr) < 0) {
		switch (errno) {
		case (ENOSYS):
			(void) fprintf(stderr, gettext(
			    "%s: Invalid operation for this filesystem type\n"),
			    path);
			break;
		case (EEXIST):
			(void) fprintf(stderr, gettext(
			    "%s: Overlapping swap files are not allowed\n"),
			    path);
			break;
		default:
			perror(path);
			break;
		}
		return (2);
	}

	/*
	 * If the swapctl worked and we don't have a dump device, and /etc
	 * is part of a writeable filesystem, then run dumpadm -ud swap.
	 * If /etc (presumably part of /) is still mounted read-only, then
	 * dumpadm will fail to write its config file, so there's no point
	 * running it now.  This also avoids spurious messages during boot
	 * when the first swapadd takes place, at which point / is still ro.
	 * Similarly, if swapadd invoked us with -1 or -2 (but root is
	 * writeable), we don't want to modify the dump device because
	 * /etc/init.d/savecore has yet to execute; if we run dumpadm now
	 * we would lose the user's previous setting.
	 */
	if (!have_dumpdev && !(flags & (P1FLAG | P2FLAG)) &&
	    statvfs("/etc", &fsb) == 0 && !(fsb.f_flag & ST_RDONLY)) {

		(void) printf(
			gettext("operating system crash dump was previously "
		    "disabled --\ninvoking dumpadm(1M) -d swap to select "
		    "new dump device\n"));

		if (system("/usr/sbin/dumpadm -ud swap") == -1)
			dumpadm_err(gettext(
			    "Warning: failed to execute dumpadm -d swap"));
	}

	return (0);
}

static int
valid(char *pathname, off_t offset, off_t length)
{
	struct stat64		f;
	struct statvfs64	fs;
	off_t		need;

	if (stat64(pathname, &f) < 0 || statvfs64(pathname,  &fs) < 0) {
		(void) perror(pathname);
		return (errno);
	}

	if (!((S_ISREG(f.st_mode) && (f.st_mode & S_ISVTX) == S_ISVTX) ||
		S_ISBLK(f.st_mode))) {
		(void) fprintf(stderr,
		    gettext("\"%s\" is not valid for swapping.\n"
		    "It must be a block device or a regular file with the\n"
		    "\"save user text on execution\" bit set.\n"),
		    pathname);
		return (EINVAL);
	}

	if (S_ISREG(f.st_mode)) {
		if (length == 0)
			length = (off_t)f.st_size;

		/*
		 * "f.st_blocks < 8" because the first eight
		 * 512-byte sectors are always skipped
		 */

		if (f.st_size < (length - offset) || f.st_size == 0 ||
		    f.st_size > MAXOFF_T || f.st_blocks < 8 || length < 0) {
			(void) fprintf(stderr, gettext("%s: size is invalid\n"),
			    pathname);
			return (EINVAL);
		}

		if (offset < 0) {
			(void) fprintf(stderr,
				gettext("%s: low block is invalid\n"),
				pathname);
			return (EINVAL);
		}

		need = roundup(length, fs.f_bsize) / DEV_BSIZE;

		/*
		 * "need > f.st_blocks" to account for indirect blocks
		 * Note:
		 *  This can be fooled by a file large enough to
		 *  contain indirect blocks that also contains holes.
		 *  However, we don't know (and don't want to know)
		 *  about the underlying storage implementation.
		 *  But, if it doesn't have at least this many blocks,
		 *  there must be a hole.
		 */

		if (need > f.st_blocks) {
			(void) fprintf(stderr, gettext(
			    "\"%s\" may contain holes - can't swap on it.\n"),
			    pathname);
			return (EINVAL);
		}
	}
	/*
	 * else, we cannot get st_size for S_ISBLK device and
	 * no meaningful checking can be done.
	 */

	return (0);
}
