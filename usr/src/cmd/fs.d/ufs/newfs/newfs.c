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
 * newfs: friendly front end to mkfs
 *
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <locale.h>
#include <sys/stat.h>
#include <sys/buf.h>
#include <sys/fs/ufs_fs.h>
#include <sys/vnode.h>
#include <sys/fs/ufs_inode.h>
#include <sys/sysmacros.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <libintl.h>
#include <sys/dkio.h>
#include <sys/vtoc.h>
#include <sys/mkdev.h>
#include <sys/efi_partition.h>

#include <fslib.h>

static unsigned int number(char *, char *, int, int);
static int64_t number64(char *, char *, int, int64_t);
static diskaddr_t getdiskbydev(char *);
static int  yes(void);
static int  notrand(char *);
static void usage();
static diskaddr_t get_device_size(int, char *);
static diskaddr_t brute_force_get_device_size(int);
static int validate_size(char *disk, diskaddr_t size);
static void exenv(void);
static struct fs *read_sb(char *);
/*PRINTFLIKE1*/
static void fatal(char *fmt, ...) __NORETURN;

#define	EPATH "PATH=/usr/sbin:/sbin:"
#define	CPATH "/sbin"					/* an EPATH element */
#define	MB (1024 * 1024)
#define	GBSEC ((1024 * 1024 * 1024) / DEV_BSIZE)	/* sectors in a GB */
#define	MINFREESEC ((64 * 1024 * 1024) / DEV_BSIZE)	/* sectors in 64 MB */
#define	MINCPG (16)	/* traditional */
#define	MAXDEFDENSITY (8 * 1024)	/* arbitrary */
#define	MINDENSITY (2 * 1024)	/* traditional */
#define	MIN_MTB_DENSITY (1024 * 1024)
#define	POWEROF2(num)	(((num) & ((num) - 1)) == 0)
#define	SECTORS_PER_TERABYTE	(1LL << 31)
/*
 * The following constant specifies an upper limit for file system size
 * that is actually a lot bigger than we expect to support with UFS. (Since
 * it's specified in sectors, the file system size would be 2**44 * 512,
 * which is 2**53, which is 8192 Terabytes.)  However, it's useful
 * for checking the basic sanity of a size value that is input on the
 * command line.
 */
#define	FS_SIZE_UPPER_LIMIT	0x100000000000LL

/* For use with number() */
#define	NR_NONE		0
#define	NR_PERCENT	0x01

/*
 * The following two constants set the default block and fragment sizes.
 * Both constants must be a power of 2 and meet the following constraints:
 *	MINBSIZE <= DESBLKSIZE <= MAXBSIZE
 *	DEV_BSIZE <= DESFRAGSIZE <= DESBLKSIZE
 *	DESBLKSIZE / DESFRAGSIZE <= 8
 */
#define	DESBLKSIZE	8192
#define	DESFRAGSIZE	1024

#ifdef DEBUG
#define	dprintf(x)	printf x
#else
#define	dprintf(x)
#endif

static int	Nflag;		/* run mkfs without writing file system */
static int	Tflag;		/* set up file system for growth to over 1 TB */
static int	verbose;	/* show mkfs line before exec */
static int	fsize = 0;		/* fragment size */
static int	fsize_flag = 0;	/* fragment size was specified on cmd line */
static int	bsize;		/* block size */
static int	ntracks;	/* # tracks/cylinder */
static int	ntracks_set = 0; /* true if the user specified ntracks */
static int	optim = FS_OPTTIME;	/* optimization, t(ime) or s(pace) */
static int	nsectors;	/* # sectors/track */
static int	cpg;		/* cylinders/cylinder group */
static int	cpg_set = 0;	/* true if the user specified cpg */
static int	minfree = -1;	/* free space threshold */
static int	rpm;		/* revolutions/minute of drive */
static int	rpm_set = 0;	/* true if the user specified rpm */
static int	nrpos = 8;	/* # of distinguished rotational positions */
				/* 8 is the historical default */
static int	nrpos_set = 0;	/* true if the user specified nrpos */
static int	density = 0;	/* number of bytes per inode */
static int	apc;		/* alternates per cylinder */
static int	apc_set = 0;	/* true if the user specified apc */
static int 	rot = -1;	/* rotational delay (msecs) */
static int	rot_set = 0;	/* true if the user specified rot */
static int 	maxcontig = -1;	/* maximum number of contig blocks */
static int	text_sb = 0;	/* no disk changes; just final sb text dump */
static int	binary_sb = 0;	/* no disk changes; just final sb binary dump */
static int	label_type;	/* see types below */

/*
 * The variable use_efi_dflts is an indicator of whether to use EFI logic
 * or the geometry logic in laying out the filesystem. This is decided
 * based on the size/type of the disk and is used only for non-EFI labeled
 * disks and removable media.
 */
static int	use_efi_dflts = 0;
static int	isremovable = 0;
static int	ishotpluggable = 0;

static char	device[MAXPATHLEN];
static char	cmd[BUFSIZ];

extern	char	*getfullrawname(); /* from libadm */

int
main(int argc, char *argv[])
{
	char *special, *name;
	struct stat64 st;
	int status;
	int option;
	struct fs *sbp;	/* Pointer to superblock (if present) */
	diskaddr_t actual_fssize;
	diskaddr_t max_possible_fssize;
	diskaddr_t req_fssize = 0;
	diskaddr_t fssize = 0;
	char	*req_fssize_str = NULL; /* requested size argument */

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	opterr = 0;	/* We print our own errors, disable getopt's message */
	while ((option = getopt(argc, argv,
	    "vNBSs:C:d:t:o:a:b:f:c:m:n:r:i:T")) != EOF) {
		switch (option) {
		case 'S':
			text_sb++;
			break;
		case 'B':
			binary_sb++;
			break;
		case 'v':
			verbose++;
			break;

		case 'N':
			Nflag++;
			break;

		case 's':
			/*
			 * The maximum file system size is a lot smaller
			 * than FS_SIZE_UPPER_LIMIT, but until we find out
			 * the device size and block size, we don't know
			 * what it is.  So save the requested size in a
			 * string so that we can print it out later if we
			 * determine it's too big.
			 */
			req_fssize = number64("fssize", optarg, NR_NONE,
			    FS_SIZE_UPPER_LIMIT);
			if (req_fssize < 1024)
				fatal(gettext(
				    "%s: fssize must be at least 1024"),
				    optarg);
			req_fssize_str = strdup(optarg);
			if (req_fssize_str == NULL)
				fatal(gettext(
				    "Insufficient memory for string copy."));
			break;

		case 'C':
			maxcontig = number("maxcontig", optarg, NR_NONE, -1);
			if (maxcontig < 0)
				fatal(gettext("%s: bad maxcontig"), optarg);
			break;

		case 'd':
			rot = number("rotdelay", optarg, NR_NONE, 0);
			rot_set = 1;
			if (rot < 0 || rot > 1000)
				fatal(gettext(
				    "%s: bad rotational delay"), optarg);
			break;

		case 't':
			ntracks = number("ntrack", optarg, NR_NONE, 16);
			ntracks_set = 1;
			if ((ntracks < 0) ||
			    (ntracks > INT_MAX))
				fatal(gettext("%s: bad total tracks"), optarg);
			break;

		case 'o':
			if (strcmp(optarg, "space") == 0)
				optim = FS_OPTSPACE;
			else if (strcmp(optarg, "time") == 0)
				optim = FS_OPTTIME;
			else
				fatal(gettext(
"%s: bad optimization preference (options are `space' or `time')"), optarg);
			break;

		case 'a':
			apc = number("apc", optarg, NR_NONE, 0);
			apc_set = 1;
			if (apc < 0 || apc > 32768) /* see mkfs.c */
				fatal(gettext(
				    "%s: bad alternates per cyl"), optarg);
			break;

		case 'b':
			bsize = number("bsize", optarg, NR_NONE, DESBLKSIZE);
			if (bsize < MINBSIZE || bsize > MAXBSIZE)
				fatal(gettext(
				    "%s: bad block size"), optarg);
			break;

		case 'f':
			fsize = number("fragsize", optarg, NR_NONE,
			    DESFRAGSIZE);
			fsize_flag++;
			/* xxx ought to test against bsize for upper limit */
			if (fsize < DEV_BSIZE)
				fatal(gettext("%s: bad frag size"), optarg);
			break;

		case 'c':
			cpg = number("cpg", optarg, NR_NONE, 16);
			cpg_set = 1;
			if (cpg < 1)
				fatal(gettext("%s: bad cylinders/group"),
				    optarg);
			break;

		case 'm':
			minfree = number("minfree", optarg, NR_PERCENT, 10);
			if (minfree < 0 || minfree > 99)
				fatal(gettext("%s: bad free space %%"), optarg);
			break;

		case 'n':
			nrpos = number("nrpos", optarg, NR_NONE, 8);
			nrpos_set = 1;
			if (nrpos <= 0)
				fatal(gettext(
				    "%s: bad number of rotational positions"),
				    optarg);
			break;

		case 'r':
			rpm = number("rpm", optarg, NR_NONE, 3600);
			rpm_set = 1;
			if (rpm < 0)
				fatal(gettext("%s: bad revs/minute"), optarg);
			break;

		case 'i':
			/* xxx ought to test against fsize */
			density = number("nbpi", optarg, NR_NONE, 2048);
			if (density < DEV_BSIZE)
				fatal(gettext("%s: bad bytes per inode"),
				    optarg);
			break;

		case 'T':
			Tflag++;
			break;

		default:
			usage();
			fatal(gettext("-%c: unknown flag"), optopt);
		}
	}

	/* At this point, there should only be one argument left:	*/
	/* The raw-special-device itself. If not, print usage message.	*/
	if ((argc - optind) != 1) {
		usage();
		exit(1);
	}

	name = argv[optind];

	special = getfullrawname(name);
	if (special == NULL) {
		(void) fprintf(stderr, gettext("newfs: malloc failed\n"));
		exit(1);
	}

	if (*special == '\0') {
		if (strchr(name, '/') != NULL) {
			if (stat64(name, &st) < 0) {
				(void) fprintf(stderr,
				    gettext("newfs: %s: %s\n"),
				    name, strerror(errno));
				exit(2);
			}
			fatal(gettext("%s: not a raw disk device"), name);
		}
		(void) snprintf(device, sizeof (device), "/dev/rdsk/%s", name);
		if ((special = getfullrawname(device)) == NULL) {
			(void) fprintf(stderr,
			    gettext("newfs: malloc failed\n"));
			exit(1);
		}

		if (*special == '\0') {
			(void) snprintf(device, sizeof (device), "/dev/%s",
			    name);
			if ((special = getfullrawname(device)) == NULL) {
				(void) fprintf(stderr,
				    gettext("newfs: malloc failed\n"));
				exit(1);
			}
			if (*special == '\0')
				fatal(gettext(
				    "%s: not a raw disk device"), name);
		}
	}

	/*
	 * getdiskbydev() determines the characteristics of the special
	 * device on which the file system will be built.  In the case
	 * of devices with SMI labels (that is, non-EFI labels), the
	 * following characteristics are set (if they were not already
	 * set on the command line, since the command line settings
	 * take precedence):
	 *
	 *	nsectors - sectors per track
	 *	ntracks - tracks per cylinder
	 *	rpm - disk revolutions per minute
	 *
	 *	apc is NOT set
	 *
	 * getdiskbydev() also sets the following quantities for all
	 * devices, if not already set:
	 *
	 *	bsize - file system block size
	 *	maxcontig
	 *	label_type (efi, vtoc, or other)
	 *
	 * getdiskbydev() returns the actual size of the device, in
	 * sectors.
	 */

	actual_fssize = getdiskbydev(special);

	if (req_fssize == 0) {
		fssize = actual_fssize;
	} else {
		/*
		 * If the user specified a size larger than what we've
		 * determined as the actual size of the device, see if the
		 * size specified by the user can be read.  If so, use it,
		 * since some devices and volume managers may not support
		 * the vtoc and EFI interfaces we use to determine device
		 * size.
		 */
		if (req_fssize > actual_fssize &&
		    validate_size(special, req_fssize)) {
			(void) fprintf(stderr, gettext(
"Warning: the requested size of this file system\n"
"(%lld sectors) is greater than the size of the\n"
"device reported by the driver (%lld sectors).\n"
"However, a read of the device at the requested size\n"
"does succeed, so the requested size will be used.\n"),
			    req_fssize, actual_fssize);
			fssize = req_fssize;
		} else {
			fssize = MIN(req_fssize, actual_fssize);
		}
	}

	if (label_type == LABEL_TYPE_VTOC) {
		if (nsectors < 0)
			fatal(gettext("%s: no default #sectors/track"),
			    special);
		if (!use_efi_dflts) {
			if (ntracks < 0)
				fatal(gettext("%s: no default #tracks"),
				    special);
		}
		if (rpm < 0)
			fatal(gettext(
			    "%s: no default revolutions/minute value"),
			    special);
		if (rpm < 60) {
			(void) fprintf(stderr,
			    gettext("Warning: setting rpm to 60\n"));
			rpm = 60;
		}
	}
	if (label_type == LABEL_TYPE_EFI || label_type == LABEL_TYPE_OTHER) {
		if (ntracks_set)
			(void) fprintf(stderr, gettext(
"Warning: ntracks is obsolete for this device and will be ignored.\n"));
		if (cpg_set)
			(void) fprintf(stderr, gettext(
"Warning: cylinders/group is obsolete for this device and will be ignored.\n"));
		if (rpm_set)
			(void) fprintf(stderr, gettext(
"Warning: rpm is obsolete for this device and will be ignored.\n"));
		if (rot_set)
			(void) fprintf(stderr, gettext(
"Warning: rotational delay is obsolete for this device and"
" will be ignored.\n"));
		if (nrpos_set)
			(void) fprintf(stderr, gettext(
"Warning: number of rotational positions is obsolete for this device and\n"
"will be ignored.\n"));
		if (apc_set)
			(void) fprintf(stderr, gettext(
"Warning: number of alternate sectors per cylinder is obsolete for this\n"
"device and will be ignored.\n"));

		/*
		 * We need these for the call to mkfs, even though they are
		 * meaningless.
		 */
		rpm = 60;
		nrpos = 1;
		apc = 0;
		rot = -1;

		/*
		 * These values are set to produce a file system with
		 * a cylinder group size of 48MB.   For disks with
		 * non-EFI labels, most geometries result in cylinder
		 * groups of around 40 - 50 MB, so we arbitrarily choose
		 * 48MB for disks with EFI labels.  mkfs will reduce
		 * cylinders per group even further if necessary.
		 */

		cpg = 16;
		nsectors = 128;
		ntracks = 48;

		/*
		 * mkfs produces peculiar results for file systems
		 * that are smaller than one cylinder so don't allow
		 * them to be created (this check is only made for
		 * disks with EFI labels.  Eventually, it should probably
		 * be enforced for all disks.)
		 */

		if (fssize < nsectors * ntracks) {
			fatal(gettext(
			    "file system size must be at least %d sectors"),
			    nsectors * ntracks);
		}
	}

	if (fssize > INT_MAX)
		Tflag = 1;

	/*
	 * If the user requested that the file system be set up for
	 * eventual growth to over a terabyte, or if it's already greater
	 * than a terabyte, set the inode density (nbpi) to MIN_MTB_DENSITY
	 * (unless the user has specified a larger nbpi), set the frag size
	 * equal to the block size, and set the cylinders-per-group value
	 * passed to mkfs to -1, which tells mkfs to make cylinder groups
	 * as large as possible.
	 */
	if (Tflag) {
		if (density < MIN_MTB_DENSITY)
			density = MIN_MTB_DENSITY;
		fsize = bsize;
		cpg = -1; 	/* says make cyl groups as big as possible */
	} else {
		if (fsize == 0)
			fsize = DESFRAGSIZE;
	}

	if (!POWEROF2(fsize)) {
		(void) fprintf(stderr, gettext(
		    "newfs: fragment size must a power of 2, not %d\n"), fsize);
		fsize = bsize/8;
		(void) fprintf(stderr, gettext(
		    "newfs: fragsize reset to %ld\n"), fsize);
	}

	/*
	 * The file system is limited in size by the fragment size.
	 * The number of fragments in the file system must fit into
	 * a signed 32-bit quantity, so the number of sectors in the
	 * file system is INT_MAX * the number of sectors in a frag.
	 */

	max_possible_fssize = ((uint64_t)fsize)/DEV_BSIZE * INT_MAX;
	if (fssize > max_possible_fssize)
		fssize = max_possible_fssize;

	/*
	 * Now fssize is the final size of the file system (in sectors).
	 * If it's less than what the user requested, print a message.
	 */
	if (fssize < req_fssize) {
		(void) fprintf(stderr, gettext(
		    "newfs: requested size of %s disk blocks is too large.\n"),
		    req_fssize_str);
		(void) fprintf(stderr, gettext(
		    "newfs: Resetting size to %lld\n"), fssize);
	}

	/*
	 * fssize now equals the size (in sectors) of the file system
	 * that will be created.
	 */

	/* XXX - following defaults are both here and in mkfs */
	if (density <= 0) {
		if (fssize < GBSEC)
			density = MINDENSITY;
		else
			density = (int)((((longlong_t)fssize + (GBSEC - 1)) /
			    GBSEC) * MINDENSITY);
		if (density <= 0)
			density = MINDENSITY;
		if (density > MAXDEFDENSITY)
			density = MAXDEFDENSITY;
	}
	if (cpg == 0) {
		/*
		 * maxcpg calculation adapted from mkfs
		 * In the case of disks with EFI labels, cpg has
		 * already been set, so we won't enter this code.
		 */
		long maxcpg, maxipg;

		maxipg = roundup(bsize * NBBY / 3,
		    bsize / sizeof (struct inode));
		maxcpg = (bsize - sizeof (struct cg) - howmany(maxipg, NBBY)) /
		    (sizeof (long) + nrpos * sizeof (short) +
		    nsectors / (MAXFRAG * NBBY));
		cpg = (fssize / GBSEC) * 32;
		if (cpg > maxcpg)
			cpg = maxcpg;
		if (cpg <= 0)
			cpg = MINCPG;
	}
	if (minfree < 0) {
		minfree = (int)(((float)MINFREESEC / fssize) * 100);
		if (minfree > 10)
			minfree = 10;
		if (minfree <= 0)
			minfree = 1;
	}
#ifdef i386	/* Bug 1170182 */
	if (ntracks > 32 && (ntracks % 16) != 0) {
		ntracks -= (ntracks % 16);
	}
#endif
	/*
	 * Confirmation
	 */
	if (isatty(fileno(stdin)) && !Nflag) {
		/*
		 * If we can read a valid superblock, report the mount
		 * point on which this filesystem was last mounted.
		 */
		if (((sbp = read_sb(special)) != 0) &&
		    (*sbp->fs_fsmnt != '\0')) {
			(void) printf(gettext(
			    "newfs: %s last mounted as %s\n"),
			    special, sbp->fs_fsmnt);
		}
		(void) printf(gettext(
		    "newfs: construct a new file system %s: (y/n)? "),
		    special);
		(void) fflush(stdout);
		if (!yes())
			exit(0);
	}

	dprintf(("DeBuG newfs : nsect=%d ntrak=%d cpg=%d\n",
	    nsectors, ntracks, cpg));
	/*
	 * If alternates-per-cylinder is ever implemented:
	 * need to get apc from dp->d_apc if no -a switch???
	 */
	(void) snprintf(cmd, sizeof (cmd), "mkfs -F ufs "
	    "%s%s%s%s %lld %d %d %d %d %d %d %d %d %s %d %d %d %d %s",
	    Nflag ? "-o N " : "", binary_sb ? "-o calcbinsb " : "",
	    text_sb ? "-o calcsb " : "", special,
	    fssize, nsectors, ntracks, bsize, fsize, cpg, minfree, rpm/60,
	    density, optim == FS_OPTSPACE ? "s" : "t", apc, rot, nrpos,
	    maxcontig, Tflag ? "y" : "n");
	if (verbose) {
		(void) printf("%s\n", cmd);
		(void) fflush(stdout);
	}
	exenv();
	if (status = system(cmd))
		exit(status >> 8);
	if (Nflag)
		exit(0);
	(void) snprintf(cmd, sizeof (cmd), "/usr/sbin/fsirand %s", special);
	if (notrand(special) && (status = system(cmd)) != 0)
		(void) fprintf(stderr,
		    gettext("%s: failed, status = %d\n"),
		    cmd, status);
	return (0);
}

static void
exenv(void)
{
	char *epath;				/* executable file path */
	char *cpath;				/* current path */

	if ((cpath = getenv("PATH")) == NULL) {
		(void) fprintf(stderr, gettext("newfs: no PATH in env\n"));
		/*
		 * Background: the Bourne shell interpolates "." into
		 * the path where said path starts with a colon, ends
		 * with a colon, or has two adjacent colons.  Thus,
		 * the path ":/sbin::/usr/sbin:" is equivalent to
		 * ".:/sbin:.:/usr/sbin:.".  Now, we have no cpath,
		 * and epath ends in a colon (to make for easy
		 * catenation in the normal case).  By the above, if
		 * we use "", then "." becomes part of path.  That's
		 * bad, so use CPATH (which is just a duplicate of some
		 * element in EPATH).  No point in opening ourselves
		 * up to a Trojan horse attack when we don't have to....
		 */
		cpath = CPATH;
	}
	if ((epath = malloc(strlen(EPATH) + strlen(cpath) + 1)) == NULL) {
		(void) fprintf(stderr, gettext("newfs: malloc failed\n"));
		exit(1);
	}
	(void) strcpy(epath, EPATH);
	(void) strcat(epath, cpath);
	if (putenv(epath) < 0) {
		(void) fprintf(stderr, gettext("newfs: putenv failed\n"));
		exit(1);
	}
}

static int
yes(void)
{
	int	i, b;

	i = b = getchar();
	while (b != '\n' && b != '\0' && b != EOF)
		b = getchar();
	return (i == 'y');
}

/*
 * xxx Caller must run fmt through gettext(3) for us, if we ever
 * xxx go the i18n route....
 */
static void
fatal(char *fmt, ...)
{
	va_list pvar;

	(void) fprintf(stderr, "newfs: ");
	va_start(pvar, fmt);
	(void) vfprintf(stderr, fmt, pvar);
	va_end(pvar);
	(void) putc('\n', stderr);
	exit(10);
}

static diskaddr_t
getdiskbydev(char *disk)
{
	struct dk_geom g;
	struct dk_cinfo ci;
	struct dk_minfo info;
	diskaddr_t actual_size;
	int fd;

	if ((fd = open64(disk, 0)) < 0) {
		perror(disk);
		exit(1);
	}

	/*
	 * get_device_size() determines the actual size of the
	 * device, and also the disk's attributes, such as geometry.
	 */
	actual_size = get_device_size(fd, disk);

	if (label_type == LABEL_TYPE_VTOC) {

		/*
		 * Geometry information does not make sense for removable or
		 * hotpluggable media anyway, so indicate mkfs to use EFI
		 * default parameters.
		 */
		if (ioctl(fd, DKIOCREMOVABLE, &isremovable)) {
			dprintf(("DeBuG newfs : Unable to determine if %s is"
			    " Removable Media. Proceeding with system"
			    " determined parameters.\n", disk));
			isremovable = 0;
		}

		/* If removable check if a floppy disk */
		if (isremovable) {
			if (ioctl(fd, DKIOCGMEDIAINFO, &info)) {
				dprintf(("DeBuG newfs : Unable to get media"
				    " info from %s.\n", disk));
			} else {
				if (info.dki_media_type == DK_FLOPPY) {
					isremovable = 0;
				}
			}
		}

		if (ioctl(fd, DKIOCHOTPLUGGABLE, &ishotpluggable)) {
			dprintf(("DeBuG newfs : Unable to determine if %s is"
			    " Hotpluggable Media. Proceeding with system"
			    " determined parameters.\n", disk));
			ishotpluggable = 0;
		}

		if ((isremovable || ishotpluggable) && !Tflag)
			use_efi_dflts = 1;

		if (ioctl(fd, DKIOCGGEOM, &g))
			fatal(gettext(
			    "%s: Unable to read Disk geometry"), disk);
		if ((((diskaddr_t)g.dkg_ncyl * g.dkg_nhead *
		    g.dkg_nsect) > CHSLIMIT) && !Tflag) {
			use_efi_dflts = 1;
		}
		dprintf(("DeBuG newfs : geom=%llu, CHSLIMIT=%d "
		    "isremovable = %d ishotpluggable = %d use_efi_dflts = %d\n",
		    (diskaddr_t)g.dkg_ncyl * g.dkg_nhead * g.dkg_nsect,
		    CHSLIMIT, isremovable, ishotpluggable, use_efi_dflts));
		/*
		 * The ntracks that is passed to mkfs is decided here based
		 * on 'use_efi_dflts' and whether ntracks was specified as a
		 * command line parameter to newfs.
		 * If ntracks of -1 is passed to mkfs, mkfs uses DEF_TRACKS_EFI
		 * and DEF_SECTORS_EFI for ntracks and nsectors respectively.
		 */
		if (nsectors == 0)
			nsectors = g.dkg_nsect;
		if (ntracks == 0)
			ntracks = use_efi_dflts ? -1 : g.dkg_nhead;
		if (rpm == 0)
			rpm = ((int)g.dkg_rpm <= 0) ? 3600: g.dkg_rpm;
	}

	if (bsize == 0)
		bsize = DESBLKSIZE;
	/*
	 * Adjust maxcontig by the device's maxtransfer. If maxtransfer
	 * information is not available, default to the min of a MB and
	 * maxphys.
	 */
	if (maxcontig == -1 && ioctl(fd, DKIOCINFO, &ci) == 0) {
		maxcontig = ci.dki_maxtransfer * DEV_BSIZE;
		if (maxcontig < 0) {
			int	error, gotit, maxphys;
			gotit = fsgetmaxphys(&maxphys, &error);

			/*
			 * If we cannot get the maxphys value, default
			 * to ufs_maxmaxphys (MB).
			 */
			if (gotit) {
				maxcontig = MIN(maxphys, MB);
			} else {
				(void) fprintf(stderr, gettext(
"Warning: Could not get system value for maxphys. The value for maxcontig\n"
"will default to 1MB.\n"));
			maxcontig = MB;
			}
		}
		maxcontig /= bsize;
	}
	(void) close(fd);
	return (actual_size);
}

/*
 * Figure out how big the partition we're dealing with is.
 */
static diskaddr_t
get_device_size(int fd, char *name)
{
	struct extvtoc vtoc;
	dk_gpt_t *efi_vtoc;
	diskaddr_t	slicesize;

	int index = read_extvtoc(fd, &vtoc);

	if (index >= 0) {
		label_type = LABEL_TYPE_VTOC;
	} else {
		if (index == VT_ENOTSUP || index == VT_ERROR) {
			/* it might be an EFI label */
			index = efi_alloc_and_read(fd, &efi_vtoc);
			if (index >= 0)
				label_type = LABEL_TYPE_EFI;
		}
	}

	if (index < 0) {
		/*
		 * Since both attempts to read the label failed, we're
		 * going to fall back to a brute force approach to
		 * determining the device's size:  see how far out we can
		 * perform reads on the device.
		 */

		slicesize = brute_force_get_device_size(fd);
		if (slicesize == 0) {
			switch (index) {
			case VT_ERROR:
				(void) fprintf(stderr, gettext(
				    "newfs: %s: %s\n"), name, strerror(errno));
				exit(10);
				/*NOTREACHED*/
			case VT_EIO:
				fatal(gettext(
				    "%s: I/O error accessing VTOC"), name);
				/*NOTREACHED*/
			case VT_EINVAL:
				fatal(gettext(
				    "%s: Invalid field in VTOC"), name);
				/*NOTREACHED*/
			default:
				fatal(gettext(
				    "%s: unknown error accessing VTOC"),
				    name);
				/*NOTREACHED*/
			}
		} else {
			label_type = LABEL_TYPE_OTHER;
		}
	}

	if (label_type == LABEL_TYPE_EFI) {
		slicesize = efi_vtoc->efi_parts[index].p_size;
		efi_free(efi_vtoc);
	} else if (label_type == LABEL_TYPE_VTOC) {
		slicesize = vtoc.v_part[index].p_size;
	}

	return (slicesize);
}

/*
 * brute_force_get_device_size
 *
 * Determine the size of the device by seeing how far we can
 * read.  Doing an llseek( , , SEEK_END) would probably work
 * in most cases, but we've seen at least one third-party driver
 * which doesn't correctly support the SEEK_END option when the
 * the device is greater than a terabyte.
 */

static diskaddr_t
brute_force_get_device_size(int fd)
{
	diskaddr_t	min_fail = 0;
	diskaddr_t	max_succeed = 0;
	diskaddr_t	cur_db_off;
	char 		buf[DEV_BSIZE];

	/*
	 * First, see if we can read the device at all, just to
	 * eliminate errors that have nothing to do with the
	 * device's size.
	 */

	if (((llseek(fd, (offset_t)0, SEEK_SET)) == -1) ||
	    ((read(fd, buf, DEV_BSIZE)) == -1))
		return (0);  /* can't determine size */

	/*
	 * Now, go sequentially through the multiples of 4TB
	 * to find the first read that fails (this isn't strictly
	 * the most efficient way to find the actual size if the
	 * size really could be anything between 0 and 2**64 bytes.
	 * We expect the sizes to be less than 16 TB for some time,
	 * so why do a bunch of reads that are larger than that?
	 * However, this algorithm *will* work for sizes of greater
	 * than 16 TB.  We're just not optimizing for those sizes.)
	 */

	for (cur_db_off = SECTORS_PER_TERABYTE * 4;
	    min_fail == 0 && cur_db_off < FS_SIZE_UPPER_LIMIT;
	    cur_db_off += 4 * SECTORS_PER_TERABYTE) {
		if (((llseek(fd, (offset_t)(cur_db_off * DEV_BSIZE),
		    SEEK_SET)) == -1) ||
		    ((read(fd, buf, DEV_BSIZE)) != DEV_BSIZE))
			min_fail = cur_db_off;
		else
			max_succeed = cur_db_off;
	}

	if (min_fail == 0)
		return (0);

	/*
	 * We now know that the size of the device is less than
	 * min_fail and greater than or equal to max_succeed.  Now
	 * keep splitting the difference until the actual size in
	 * sectors in known.  We also know that the difference
	 * between max_succeed and min_fail at this time is
	 * 4 * SECTORS_PER_TERABYTE, which is a power of two, which
	 * simplifies the math below.
	 */

	while (min_fail - max_succeed > 1) {
		cur_db_off = max_succeed + (min_fail - max_succeed)/2;
		if (((llseek(fd, (offset_t)(cur_db_off * DEV_BSIZE),
		    SEEK_SET)) == -1) ||
		    ((read(fd, buf, DEV_BSIZE)) != DEV_BSIZE))
			min_fail = cur_db_off;
		else
			max_succeed = cur_db_off;
	}

	/* the size is the last successfully read sector offset plus one */
	return (max_succeed + 1);
}

/*
 * validate_size
 *
 * Return 1 if the device appears to be at least "size" sectors long.
 * Return 0 if it's shorter or we can't read it.
 */

static int
validate_size(char *disk, diskaddr_t size)
{
	char 		buf[DEV_BSIZE];
	int fd, rc;

	if ((fd = open64(disk, O_RDONLY)) < 0) {
		perror(disk);
		exit(1);
	}

	if ((llseek(fd, (offset_t)((size - 1) * DEV_BSIZE), SEEK_SET) == -1) ||
	    (read(fd, buf, DEV_BSIZE)) != DEV_BSIZE)
		rc = 0;
	else
		rc = 1;
	(void) close(fd);
	return (rc);
}

/*
 * read_sb(char * rawdev) - Attempt to read the superblock from a raw device
 *
 * Returns:
 *	0 :
 *		Could not read a valid superblock for a variety of reasons.
 *		Since 'newfs' handles any fatal conditions, we're not going
 *		to make any guesses as to why this is failing or what should
 *		be done about it.
 *
 *	struct fs *:
 *		A pointer to (what we think is) a valid superblock. The
 *		space for the superblock is static (inside the function)
 *		since we will only be reading the values from it.
 */

struct fs *
read_sb(char *fsdev)
{
	static struct fs	sblock;
	struct stat64		statb;
	int			dskfd;
	char			*bufp = NULL;
	int			bufsz = 0;

	if (stat64(fsdev, &statb) < 0)
		return (0);

	if ((dskfd = open64(fsdev, O_RDONLY)) < 0)
		return (0);

	/*
	 * We need a buffer whose size is a multiple of DEV_BSIZE in order
	 * to read from a raw device (which we were probably passed).
	 */
	bufsz = ((sizeof (sblock) / DEV_BSIZE) + 1) * DEV_BSIZE;
	if ((bufp = malloc(bufsz)) == NULL) {
		(void) close(dskfd);
		return (0);
	}

	if (llseek(dskfd, (offset_t)SBOFF, SEEK_SET) < 0 ||
	    read(dskfd, bufp, bufsz) < 0) {
		(void) close(dskfd);
		free(bufp);
		return (0);
	}
	(void) close(dskfd);	/* Done with the file */

	(void) memcpy(&sblock, bufp, sizeof (sblock));
	free(bufp);	/* Don't need this anymore */

	if (((sblock.fs_magic != FS_MAGIC) &&
	    (sblock.fs_magic != MTB_UFS_MAGIC)) ||
	    sblock.fs_ncg < 1 || sblock.fs_cpg < 1)
		return (0);

	if (sblock.fs_ncg * sblock.fs_cpg < sblock.fs_ncyl ||
	    (sblock.fs_ncg - 1) * sblock.fs_cpg >= sblock.fs_ncyl)
		return (0);

	if (sblock.fs_sbsize < 0 || sblock.fs_sbsize > SBSIZE)
		return (0);

	return (&sblock);
}

/*
 * Read the UFS file system on the raw device SPECIAL.  If it does not
 * appear to be a UFS file system, return non-zero, indicating that
 * fsirand should be called (and it will spit out an error message).
 * If it is a UFS file system, take a look at the inodes in the first
 * cylinder group.  If they appear to be randomized (non-zero), return
 * zero, which will cause fsirand to not be called.  If the inode generation
 * counts are all zero, then we must call fsirand, so return non-zero.
 */

#define	RANDOMIZED	0
#define	NOT_RANDOMIZED	1

static int
notrand(char *special)
{
	long fsbuf[SBSIZE / sizeof (long)];
	struct dinode dibuf[MAXBSIZE/sizeof (struct dinode)];
	struct fs *fs;
	struct dinode *dip;
	offset_t seekaddr;
	int bno, inum;
	int fd;

	fs = (struct fs *)fsbuf;
	if ((fd = open64(special, 0)) == -1)
		return (NOT_RANDOMIZED);
	if (llseek(fd, (offset_t)SBLOCK * DEV_BSIZE, 0) == -1 ||
	    read(fd, (char *)fs, SBSIZE) != SBSIZE ||
	    ((fs->fs_magic != FS_MAGIC) && (fs->fs_magic != MTB_UFS_MAGIC))) {
		(void) close(fd);
		return (NOT_RANDOMIZED);
	}

	/* looks like a UFS file system; read the first cylinder group */
	bsize = INOPB(fs) * sizeof (struct dinode);
	inum = 0;
	while (inum < fs->fs_ipg) {
		bno = itod(fs, inum);
		seekaddr = (offset_t)fsbtodb(fs, bno) * DEV_BSIZE;
		if (llseek(fd, seekaddr, 0) == -1 ||
		    read(fd, (char *)dibuf, bsize) != bsize) {
			(void) close(fd);
			return (NOT_RANDOMIZED);
		}
		for (dip = dibuf; dip < &dibuf[INOPB(fs)]; dip++) {
			if (dip->di_gen != 0) {
				(void) close(fd);
				return (RANDOMIZED);
			}
			inum++;
		}
	}
	(void) close(fd);
	return (NOT_RANDOMIZED);
}

static void
usage(void)
{
	(void) fprintf(stderr, gettext(
	    "usage: newfs [ -v ] [ mkfs-options ] raw-special-device\n"));
	(void) fprintf(stderr, gettext("where mkfs-options are:\n"));
	(void) fprintf(stderr, gettext(
	    "\t-N do not create file system, just print out parameters\n"));
	(void) fprintf(stderr, gettext(
"\t-T configure file system for eventual growth to over a terabyte\n"));
	(void) fprintf(stderr, gettext("\t-s file system size (sectors)\n"));
	(void) fprintf(stderr, gettext("\t-b block size\n"));
	(void) fprintf(stderr, gettext("\t-f frag size\n"));
	(void) fprintf(stderr, gettext("\t-t tracks/cylinder\n"));
	(void) fprintf(stderr, gettext("\t-c cylinders/group\n"));
	(void) fprintf(stderr, gettext("\t-m minimum free space %%\n"));
	(void) fprintf(stderr, gettext(
	    "\t-o optimization preference (`space' or `time')\n"));
	(void) fprintf(stderr, gettext("\t-r revolutions/minute\n"));
	(void) fprintf(stderr, gettext("\t-i number of bytes per inode\n"));
	(void) fprintf(stderr, gettext(
	    "\t-a number of alternates per cylinder\n"));
	(void) fprintf(stderr, gettext("\t-C maxcontig\n"));
	(void) fprintf(stderr, gettext("\t-d rotational delay\n"));
	(void) fprintf(stderr, gettext(
	    "\t-n number of rotational positions\n"));
	(void) fprintf(stderr, gettext(
"\t-S print a textual version of the calculated superblock to stdout\n"));
	(void) fprintf(stderr, gettext(
"\t-B dump a binary version of the calculated superblock to stdout\n"));
}

/*
 * Error-detecting version of atoi(3).  Adapted from mkfs' number().
 */
static unsigned int
number(char *param, char *value, int flags, int def_value)
{
	char *cs;
	int n;
	int cut = INT_MAX / 10;    /* limit to avoid overflow */
	int minus = 0;

	cs = value;
	if (*cs == '-') {
		minus = 1;
		cs += 1;
	}
	if ((*cs < '0') || (*cs > '9')) {
		goto bail_out;
	}
	n = 0;
	while ((*cs >= '0') && (*cs <= '9') && (n <= cut)) {
		n = n*10 + *cs++ - '0';
	}
	if (minus)
		n = -n;
	for (;;) {
		switch (*cs++) {
		case '\0':
			return (n);

		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			(void) fprintf(stderr, gettext(
			    "newfs: value for %s overflowed, using %d\n"),
			    param, def_value);
			return (def_value);

		case '%':
			if (flags & NR_PERCENT)
				break;
			/* FALLTHROUGH */

		default:
bail_out:
			fatal(gettext("bad numeric arg for %s: \"%s\""),
			    param, value);

		}
	}
	/* NOTREACHED */
}

/*
 * Error-detecting version of atoi(3).  Adapted from mkfs' number().
 */
static int64_t
number64(char *param, char *value, int flags, int64_t def_value)
{
	char *cs;
	int64_t n;
	int64_t cut = FS_SIZE_UPPER_LIMIT/ 10;    /* limit to avoid overflow */
	int minus = 0;

	cs = value;
	if (*cs == '-') {
		minus = 1;
		cs += 1;
	}
	if ((*cs < '0') || (*cs > '9')) {
		goto bail_out;
	}
	n = 0;
	while ((*cs >= '0') && (*cs <= '9') && (n <= cut)) {
		n = n*10 + *cs++ - '0';
	}
	if (minus)
		n = -n;
	for (;;) {
		switch (*cs++) {
		case '\0':
			return (n);

		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			(void) fprintf(stderr, gettext(
			    "newfs: value for %s overflowed, using %d\n"),
			    param, def_value);
			return (def_value);

		case '%':
			if (flags & NR_PERCENT)
				break;
			/* FALLTHROUGH */

		default:
bail_out:
			fatal(gettext("bad numeric arg for %s: \"%s\""),
			    param, value);

		}
	}
	/* NOTREACHED */
}
