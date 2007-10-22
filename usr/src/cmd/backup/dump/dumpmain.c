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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "dump.h"
#include <rmt.h>
#include <sys/mtio.h>
#include <limits.h>
#include <priv_utils.h>
#include "roll_log.h"

int	notify = 0;		/* notify operator flag */
int	blockswritten = 0;	/* number of blocks written on current tape */
uint_t	tapeno = 0;		/* current tape number */
daddr32_t filenum = 0;		/* current file number on tape */
int	density = 0;		/* density in bytes/0.1" */
int	tenthsperirg;		/* inter-record-gap in 0.1"'s */
uint_t	ntrec = 0;		/* # tape blocks in each tape record */
uint_t	saved_ntrec = 0;	/* saved value of ntrec */
uint_t	forceflag = 0;		/* forced to change tp_bsize */
int	cartridge = 0;		/* assume non-cartridge tape */
uint_t	tracks;			/* # tracks on a cartridge tape */
int	diskette = 0;		/* assume not dumping to a diskette */
int	printsize = 0;		/* just print estimated size and exit */
int	mapfd = -1;		/* if >= 0, file descriptor for mmap */
int32_t	tp_bsize = TP_BSIZE_MIN; /* tape block record size (frag size) */
#ifdef DEBUG
int	xflag;			/* debugging switch */
#endif

char	*myname;

/*
 * This should be struct fs, but there are trailing bits on disk
 * that we also need to read in as part of it.  It's an array of
 * longs instead of char to force proper alignment.
 */
static long sblock_buf[SBSIZE/sizeof (long)];

#ifdef __STDC__
static char *mb(u_offset_t);
static void nextstate(int);
#else
static char *mb();
static void nextstate();
#endif

extern	jmp_buf checkpoint_buf;	/* context for return from checkpoint */
#define	FUDGE_FACTOR	0x2000000

int
main(int argc, char *argv[])
{
	char		*arg;
	int		bflag = 0, i, error = 0, saverr;
	double		fetapes = 0.0;
	struct	mnttab	*dt;
	char		msgbuf[3000], *msgp;
	char		kbsbuf[BUFSIZ];
	u_offset_t	esize_shift = 0;
	int32_t	new_mult = 0;
	time32_t	snapdate;

	host = NULL;

	if (myname = strrchr(argv[0], '/'))
		myname++;
	else
		myname = argv[0];

	if (strcmp("hsmdump", myname) == 0) {
		msg(gettext("hsmdump emulation is no longer supported.\n"));
		Exit(X_ABORT);
	}

	tape = DEFTAPE;
	autoload_period = 12;
	autoload_tries = 12;	/* traditional default of ~2.5 minutes */

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif  /* TEXT_DOMAIN */
	(void) textdomain(TEXT_DOMAIN);

	/*
	 * If someone strips the set-uid bit, dump will still work for local
	 * tapes.  Fail when we try to access a remote tape.
	 */
	(void) __init_suid_priv(0, PRIV_NET_PRIVADDR, (char *)NULL);

	if (sysinfo(SI_HOSTNAME, spcl.c_host, sizeof (spcl.c_host)) < 0) {
		saverr = errno;
		msg(gettext("Could not get host name: %s\n"),
		    strerror(saverr));
		bzero(spcl.c_host, sizeof (spcl.c_host));
	}

	dumppid = getpid();
	tsize = 0;	/* no default size, detect EOT dynamically */

	disk = NULL;
	dname = NULL;
	disk_dynamic = 0;
	increm = NINCREM;
	incno = '9';
	uflag = 0;
	arg = "u";
	tlabel = "none";
	if (argc > 1) {
		argv++;
		argc--;
		arg = *argv;
		if (*arg == '-')
			arg++;
	}
	while (*arg)
	switch (*arg++) {		/* BE CAUTIOUS OF FALLTHROUGHS */
	case 'M':
		/*
		 * This undocumented option causes each process to
		 * mkdir debug_chdir/getpid(), and chdir to it.  This is
		 * to ease the collection of profiling information and
		 * core dumps.
		 */
		if (argc > 1) {
			argv++;
			argc--;
			debug_chdir = *argv;
			msg(gettext(
			    "Each process shall try to chdir to %s/<pid>\n"),
			    debug_chdir);
			child_chdir();
		} else {
			msg(gettext("Missing move-to-dir (M) name\n"));
			dumpabort();
			/*NOTREACHED*/
		}
		break;

	case 'w':
		lastdump('w');		/* tell us only what has to be done */
		exit(0);
		break;

	case 'W':			/* what to do */
		lastdump('W');		/* tell state of what has been done */
		exit(0);		/* do nothing else */
		break;

	case 'T':
		if (argc > 1) {
			int count;
			int multiplier;
			char units;

			argv++;
			argc--;
			count = atoi(*argv);
			if (count < 1) {
				msg(gettext(
				    "Unreasonable autoload timeout period\n"));
				dumpabort();
				/*NOTREACHED*/
			}
			units = *(*argv + strlen(*argv) - 1);
			switch (units) {
			case 's':
				multiplier = 1;
				break;
			case 'h':
				multiplier = 3600;
				break;
			case '0': case '1': case '2': case '3': case '4':
			case '5': case '6': case '7': case '8': case '9':
			case 'm':
				multiplier = 60;
				break;
			default:
				msg(gettext(
				    "Unknown timeout units indicator `%c'\n"),
				    units);
				dumpabort();
				/*NOTREACHED*/
			}
			autoload_tries = 1 +
			    ((count * multiplier) / autoload_period);
		} else {
			msg(gettext("Missing autoload timeout period\n"));
			dumpabort();
			/*NOTREACHED*/
		}
		break;

	case 'f':			/* output file */
		if (argc > 1) {
			argv++;
			argc--;
			tape = *argv;
			if (*tape == '\0') {
				msg(gettext("Bad output device name\n"));
				dumpabort();
				/*NOTREACHED*/
			}
		} else {
			msg(gettext("Missing output device name\n"));
			dumpabort();
			/*NOTREACHED*/
		}
		if (strcmp(tape, "-") == 0 && verify) {
			msg(gettext(
			"Cannot verify when dumping to standard out.\n"));
			dumpabort();
			/*NOTREACHED*/
		}
		break;

	case 'd':			/* density, in bits per inch */
		if (argc > 1) {
			argv++;
			argc--;
			density = atoi(*argv) / 10;
			if (density <= 0) {
				msg(gettext(
				    "Density must be a positive integer\n"));
				dumpabort();
				/*NOTREACHED*/
			}
		} else {
			msg(gettext("Missing density\n"));
			dumpabort();
			/*NOTREACHED*/
		}
		break;

	case 's':			/* tape size, feet */
		if (argc > 1) {
			argv++;
			argc--;
			tsize = atol(*argv);
			if ((*argv[0] == '-') || (tsize == 0)) {
				msg(gettext(
			    "Tape size must be a positive integer\n"));
				dumpabort();
				/*NOTREACHED*/
			}
		} else {
			msg(gettext("Missing tape size\n"));
			dumpabort();
			/*NOTREACHED*/
		}
		break;

	case 't':			/* tracks */
		if (argc > 1) {
			argv++;
			argc--;
			tracks = atoi(*argv);
		} else {
			msg(gettext("Missing track count\n"));
			dumpabort();
			/*NOTREACHED*/
		}
		break;

	case 'b':			/* blocks per tape write */
		if (argc > 1) {
			argv++;
			argc--;
			bflag++;
			/*
			 * We save the ntrec in case we need to change
			 * tp_bsize later, we will have to recalculate
			 * it.
			 */
			saved_ntrec = ntrec = atoi(*argv);
			if (ntrec == 0 || (ntrec&1) || ntrec > (MAXNTREC*2)) {
				msg(gettext(
		    "Block size must be a positive, even integer <= %d\n"),
				    MAXNTREC*2);
				dumpabort();
				/*NOTREACHED*/
			}
			ntrec /= (tp_bsize/DEV_BSIZE);
		} else {
			msg(gettext("Missing blocking factor\n"));
			dumpabort();
			/*NOTREACHED*/
		}
		break;

	case 'c':			/* Tape is cart. not 9-track */
	case 'C':			/* 'C' to be consistent with 'D' */
		cartridge++;
		break;

	case '0':			/* dump level */
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
		incno = arg[-1];
		break;

	case 'u':			/* update /etc/dumpdates */
		uflag++;
		break;

	case 'n':			/* notify operators */
		notify++;
		break;

	case 'a':			/* create archive file */
		archive = 1;
		if (argc > 1) {
			argv++;
			argc--;
			if (**argv == '\0') {
				msg(gettext("Bad archive file name\n"));
				dumpabort();
				/*NOTREACHED*/
			}
			archivefile = strdup(*argv);
			if (archivefile == NULL) {
				saverr = errno;
				msg(gettext("Cannot allocate memory: %s\n"),
				    strerror(saverr));
				dumpabort();
				/*NOTREACHED*/
			}
		} else {
			msg(gettext("Missing archive file name\n"));
			dumpabort();
			/*NOTREACHED*/
		}
		break;

	case 'v':
		verify++;
		doingverify++;
		if (strcmp(tape, "-") == 0) {
			msg(gettext(
			"Cannot verify when dumping to standard out.\n"));
			dumpabort();
			/*NOTREACHED*/
		}
		break;

	case 'D':
		diskette++;
		break;

	case 'N':
		if (argc > 1) {
			argv++;
			argc--;
			if (**argv == '\0') {
				msg(gettext("Missing name for dumpdates "
				    "entry.\n"));
				dumpabort();
				/*NOTREACHED*/
			}
			dname = *argv;
			if (strlen(dname) > MAXNAMLEN + 2) {
				msg(gettext("Dumpdates entry name too "
				    "long.\n"));
				dumpabort();
				/*NOTREACHED*/
			}
			for (i = 0; i < strlen(dname); i++) {
				if (isspace(*(dname+i))) {
					msg(gettext("Dumpdates entry name may "
					    "not contain white space.\n"));
					dumpabort();
					/*NOTREACHED*/
				}
			}
		} else {
			msg(gettext("Missing name for dumpdates entry.\n"));
			dumpabort();
			/*NOTREACHED*/
		}
		break;
	case 'L':
		if (argc > 1) {
			argv++;
			argc--;
			if (**argv == '\0') {
				msg(gettext("Missing tape label name\n"));
				dumpabort();
				/*NOTREACHED*/
			}
			tlabel = *argv;
			if (strlen(tlabel) > (sizeof (spcl.c_label) - 1)) {
				tlabel[sizeof (spcl.c_label) - 1] = '\0';
				msg(gettext(
		    "Truncating label to maximum supported length: `%s'\n"),
				    tlabel);
			}
		} else {
			msg(gettext("Missing tape label name\n"));
			dumpabort();
			/*NOTREACHED*/
		}
		break;

	case 'l':
		autoload++;
		break;

	case 'o':
		offline++;
		break;

	case 'S':
		printsize++;
		break;

#ifdef DEBUG
	case 'z':
		xflag++;
		break;
#endif

	default:
		msg(gettext("Bad option `%c'\n"), arg[-1]);
		dumpabort();
		/*NOTREACHED*/
	}
	if (argc > 1) {
		argv++;
		argc--;
		if (**argv == '\0') {
			msg(gettext("Bad disk name\n"));
			dumpabort();
			/*NOTREACHED*/
		}
		disk = *argv;
		disk_dynamic = 0;
	}
	if (disk == NULL) {
		(void) fprintf(stderr, gettext(
	"Usage: %s [0123456789fustdWwnNDCcbavloS [argument]] filesystem\n"),
		    myname);
		Exit(X_ABORT);
	}
	if (!filenum)
		filenum = 1;

	if (signal(SIGINT, interrupt) == SIG_IGN)
		(void) signal(SIGINT, SIG_IGN);

	if (strcmp(tape, "-") == 0) {
		pipeout++;
		tape = gettext("standard output");
		dumpdev = sdumpdev = strdup(tape);
		if (dumpdev == NULL) {
			saverr = errno;
			msg(gettext("Cannot allocate memory: %s\n"),
			    strerror(saverr));
			dumpabort();
			/*NOTREACHED*/
		}
		/*CONSTANTCONDITION*/
		assert(sizeof (spcl.c_label) > 5);
		(void) strcpy(spcl.c_label, "none");
	} else if (*tape == '+') {
		nextdevice();
		(void) strcpy(spcl.c_label, tlabel);
	} else {
		/* if not already set, set diskette to default */
		if (diskette && strcmp(tape, DEFTAPE) == 0)
			tape = DISKETTE;
		nextdevice();
		(void) strcpy(spcl.c_label, tlabel);
	}
	if (cartridge && diskette) {
		error = 1;
		msg(gettext("Cannot select both cartridge and diskette\n"));
	}
	if (density && diskette) {
		error = 1;
		msg(gettext("Cannot select density of diskette\n"));
	}
	if (tracks && diskette) {
		error = 1;
		msg(gettext("Cannot select number of tracks of diskette\n"));
	}
	if (error) {
		dumpabort();
		/*NOTREACHED*/
	}

	/*
	 * Determine how to default tape size and density
	 *
	 *		density				tape size
	 * 9-track	1600 bpi (160 bytes/.1")	2300 ft.
	 * 9-track	6250 bpi (625 bytes/.1")	2300 ft.
	 *
	 * Most Sun-2's came with 4 track (20MB) cartridge tape drives,
	 * while most other machines (Sun-3's and non-Sun's) come with
	 * 9 track (45MB) cartridge tape drives.  Some Sun-2's came with
	 * 9 track drives, but there is no way for the software to detect
	 * which drive type is installed.  Sigh...  We make the gross
	 * assumption that #ifdef mc68010 will test for a Sun-2.
	 *
	 * cartridge	8000 bpi (100 bytes/.1")	425 * tracks ft.
	 */
	if (density == 0)
		density = cartridge ? 100 : 625;
	if (tracks == 0)
		tracks = 9;
	if (!bflag) {
		if (cartridge)
			ntrec = CARTRIDGETREC;
		else if (diskette)
			ntrec = NTREC;
		else if (density >= 625)
			ntrec = HIGHDENSITYTREC;
		else
			ntrec = NTREC;
		/*
		 * save ntrec in case we have to change tp_bsize later.
		 */
		saved_ntrec = (ntrec * (tp_bsize/DEV_BSIZE));
	}
	if (!diskette) {
		tsize *= 12L*10L;
		if (cartridge)
			tsize *= tracks;
	}
	rmtinit(msg, Exit);
	if (host) {
		char	*cp = strchr(host, '@');
		if (cp == (char *)0)
			cp = host;
		else
			cp++;

		if (rmthost(host, ntrec) == 0) {
			msg(gettext("Cannot connect to tape host `%s'\n"), cp);
			dumpabort();
			/*NOTREACHED*/
		}
	}
	if (signal(SIGHUP, sigAbort) == SIG_IGN)
		(void) signal(SIGHUP, SIG_IGN);
	if (signal(SIGTRAP, sigAbort) == SIG_IGN)
		(void) signal(SIGTRAP, SIG_IGN);
	if (signal(SIGFPE, sigAbort) == SIG_IGN)
		(void) signal(SIGFPE, SIG_IGN);
	if (signal(SIGBUS, sigAbort) == SIG_IGN)
		(void) signal(SIGBUS, SIG_IGN);
	if (signal(SIGSEGV, sigAbort) == SIG_IGN)
		(void) signal(SIGSEGV, SIG_IGN);
	if (signal(SIGTERM, sigAbort) == SIG_IGN)
		(void) signal(SIGTERM, SIG_IGN);
	if (signal(SIGUSR1, sigAbort) == SIG_IGN)
		(void) signal(SIGUSR1, SIG_IGN);
	if (signal(SIGPIPE, sigAbort) == SIG_IGN)
		(void) signal(SIGPIPE, SIG_IGN);

	mnttabread();		/* /etc/fstab, /etc/mtab snarfed */

	/*
	 *	disk can be either the full special file name,
	 *	the suffix of the special file name,
	 *	the special name missing the leading '/',
	 *	the file system name with or without the leading '/'.
	 *	NB:  we attempt to avoid dumping the block device
	 *	(using rawname) because specfs and the vm system
	 *	are not necessarily in sync.
	 */

	/*
	 * Attempt to roll the log before doing the dump.  There's nothing
	 * the user can do if we are unable to roll the log, so we'll silently
	 * ignore failures.
	 */
	if ((rl_roll_log(disk) != RL_SUCCESS) && (disk[0] != '/')) {
		/* Try it again with leading '/'. */
		char	*slashed;

		slashed = (char *)malloc(strlen(disk) + 2);
		if (slashed != (char *)NULL) {
			(void) sprintf(slashed, "%c%s", '/', disk);
			(void) rl_roll_log(slashed);
			free(slashed);
		}
	}
	dt = mnttabsearch(disk, 0);
	if (dt != 0) {
		filesystem = dt->mnt_mountp;
		if (disk_dynamic) {
			/* LINTED: disk is not NULL */
			free(disk);
		}
		disk = rawname(dt->mnt_special);
		disk_dynamic = (disk != dt->mnt_special);

		(void) strncpy(spcl.c_dev, dt->mnt_special,
		    sizeof (spcl.c_dev));
		spcl.c_dev[sizeof (spcl.c_dev) - 1] = '\0';
		(void) strncpy(spcl.c_filesys, dt->mnt_mountp,
		    sizeof (spcl.c_filesys));
		spcl.c_filesys[sizeof (spcl.c_filesys) - 1] = '\0';
	} else {
		(void) strncpy(spcl.c_dev, disk, sizeof (spcl.c_dev));
		spcl.c_dev[sizeof (spcl.c_dev) - 1] = '\0';
#ifdef PARTIAL
		/* check for partial filesystem dump */
		partial_check();
		dt = mnttabsearch(disk, 1);
		if (dt != 0) {
			filesystem = dt->mnt_mountp;
			if (disk_dynamic)
				free(disk);
			disk = rawname(dt->mnt_special);
			disk_dynamic = (disk != dt->mnt_special);

			(void) strncpy(spcl.c_filesys,
			    "a partial file system", sizeof (spcl.c_filesys));
			spcl.c_filesys[sizeof (spcl.c_filesys) - 1] = '\0';
		}
		else
#endif /* PARTIAL */
		{
			char *old_disk = disk;

			(void) strncpy(spcl.c_filesys,
			    "an unlisted file system",
			    sizeof (spcl.c_filesys));
			spcl.c_filesys[sizeof (spcl.c_filesys) - 1] = '\0';

			disk = rawname(old_disk);
			if (disk != old_disk) {
				if (disk_dynamic)
					free(old_disk);
				disk_dynamic = 1;
			}
			/*
			 * If disk == old_disk, then disk_dynamic's state
			 * does not change.
			 */
		}
	}

	fi = open64(disk, O_RDONLY);

	if (fi < 0) {
		saverr = errno;
		msg(gettext("Cannot open dump device `%s': %s\n"),
		    disk, strerror(saverr));
		Exit(X_ABORT);
	}

	if (sscanf(&incno, "%1d", &spcl.c_level) != 1) {
		msg(gettext("Bad dump level `%c' specified\n"), incno);
		dumpabort();
		/*NOTREACHED*/
	}
	getitime();		/* /etc/dumpdates snarfed */

	sblock = (struct fs *)&sblock_buf;
	sync();

	bread((diskaddr_t)SBLOCK, (uchar_t *)sblock, (long)SBSIZE);
	if ((sblock->fs_magic != FS_MAGIC) &&
	    (sblock->fs_magic != MTB_UFS_MAGIC)) {
		msg(gettext(
	    "Warning - super-block on device `%s' is corrupt - run fsck\n"),
		    disk);
		dumpabort();
		/*NOTREACHED*/
	}

	if (sblock->fs_magic == FS_MAGIC &&
	    (sblock->fs_version != UFS_EFISTYLE4NONEFI_VERSION_2 &&
	    sblock->fs_version != UFS_VERSION_MIN)) {
		msg(gettext("Unrecognized UFS version: %d\n"),
		    sblock->fs_version);
		dumpabort();
		/*NOTREACHED*/
	}

	if (sblock->fs_magic == MTB_UFS_MAGIC &&
	    (sblock->fs_version < MTB_UFS_VERSION_MIN ||
	    sblock->fs_version > MTB_UFS_VERSION_1)) {
		msg(gettext("Unrecognized UFS version: %d\n"),
		    sblock->fs_version);
		dumpabort();
		/*NOTREACHED*/
	}

	/*
	 * Try to set up for using mmap(2).  It only works on the block
	 * device, but if we can use it, things go somewhat faster.  If
	 * we can't open it, we'll silently fall back to the old method
	 * (read/memcpy). We also only try this if it's been cleanly
	 * unmounted. Dumping a live filesystem this way runs into
	 * buffer consistency problems. Of course, we don't support
	 * running dump on a mounted filesystem, but some people do it
	 * anyway.
	 */
	if (sblock->fs_clean == FSCLEAN) {
		char *block = unrawname(disk);

		if (block != NULL) {
			mapfd = open(block, O_RDONLY, 0);
			free(block);
		}
	}

restart:
	bread((diskaddr_t)SBLOCK, (uchar_t *)sblock, (long)SBSIZE);
	if ((sblock->fs_magic != FS_MAGIC) &&
	    (sblock->fs_magic != MTB_UFS_MAGIC)) {	/* paranoia */
		msg(gettext("bad super-block magic number, run fsck\n"));
		dumpabort();
		/*NOTREACHED*/
	}

	if (sblock->fs_magic == FS_MAGIC &&
	    (sblock->fs_version != UFS_EFISTYLE4NONEFI_VERSION_2 &&
	    sblock->fs_version != UFS_VERSION_MIN)) {
		msg(gettext("Unrecognized UFS version: %d\n"),
		    sblock->fs_version);
		dumpabort();
		/*NOTREACHED*/
	}

	if (sblock->fs_magic == MTB_UFS_MAGIC &&
	    (sblock->fs_version < MTB_UFS_VERSION_MIN ||
	    sblock->fs_version > MTB_UFS_VERSION_1)) {
		msg(gettext("Unrecognized UFS version: %d\n"),
		    sblock->fs_version);
		dumpabort();
		/*NOTREACHED*/
	}

	if (!doingactive)
		allocino();

	/* XXX should sanity-check the super block before trusting/using it */

	/* LINTED XXX time truncated - tolerate until tape format changes */
	spcl.c_date = (time32_t)time((time_t *)NULL);
	bcopy(&(spcl.c_shadow), c_shadow_save, sizeof (c_shadow_save));

	snapdate = is_fssnap_dump(disk);
	if (snapdate)
		spcl.c_date = snapdate;

	if (!printsize) {
		msg(gettext("Date of this level %c dump: %s\n"),
		    incno, prdate(spcl.c_date));
		msg(gettext("Date of last level %c dump: %s\n"),
		    (uchar_t)lastincno, prdate(spcl.c_ddate));
		msg(gettext("Dumping %s "), disk);
		if (filesystem != 0)
			msgtail("(%.*s:%s) ",
			    /* LINTED unsigned -> signed cast ok */
			    (int)sizeof (spcl.c_host), spcl.c_host, filesystem);
		msgtail(gettext("to %s.\n"), sdumpdev);
	}

	esize = f_esize = o_esize = 0;
	msiz = roundup(d_howmany(sblock->fs_ipg * sblock->fs_ncg, NBBY),
	    TP_BSIZE_MAX);
	if (!doingactive) {
		clrmap = (uchar_t *)xcalloc(msiz, sizeof (*clrmap));
		filmap = (uchar_t *)xcalloc(msiz, sizeof (*filmap));
		dirmap = (uchar_t *)xcalloc(msiz, sizeof (*dirmap));
		nodmap = (uchar_t *)xcalloc(msiz, sizeof (*nodmap));
		shamap = (uchar_t *)xcalloc(msiz, sizeof (*shamap));
		activemap = (uchar_t *)xcalloc(msiz, sizeof (*activemap));
	} else {
		if (clrmap == NULL || filmap == NULL || dirmap == NULL ||
		    nodmap == NULL || shamap == NULL || activemap == NULL) {
			msg(gettext(
	    "Internal error: NULL map pointer while re-dumping active files"));
			dumpabort();
			/*NOTREACHED*/
		}
		bzero(clrmap, msiz);
		bzero(filmap, msiz);
		bzero(dirmap, msiz);
		bzero(nodmap, msiz);
		bzero(shamap, msiz);
		/* retain active map */
	}

	dumpstate = DS_INIT;
	dumptoarchive = 1;

	/*
	 * Read cylinder group inode-used bitmaps to avoid reading clear inodes.
	 */
	{
		uchar_t *clrp = clrmap;
		struct cg *cgp =
		    (struct cg *)xcalloc((uint_t)sblock->fs_cgsize, 1);

		for (i = 0; i < sblock->fs_ncg; i++) {
			bread(fsbtodb(sblock, cgtod(sblock, i)),
			    (uchar_t *)cgp, sblock->fs_cgsize);
			bcopy(cg_inosused(cgp), clrp,
			    (int)sblock->fs_ipg / NBBY);
			clrp += sblock->fs_ipg / NBBY;
		}
		free((char *)cgp);
		/* XXX right-shift clrmap one bit.  why? */
		for (i = 0; clrp > clrmap; i <<= NBBY) {
			i |= *--clrp & ((1<<NBBY) - 1);
			*clrp = i >> 1;
		}
	}

	if (!printsize) {
		msgp = gettext("Mapping (Pass I) [regular files]\n");
		msg(msgp);
	}

	ino = 0;
#ifdef PARTIAL
	if (partial_mark(argc, argv)) {
#endif /* PARTIAL */
		if (!doingactive)
			pass(mark, clrmap);	/* mark updates 'x'_esize */
		else
			pass(active_mark, clrmap);	/* updates 'x'_esize */
#ifdef PARTIAL
	}
#endif /* PARTIAL */
	do {
		if (!printsize) {
			msgp = gettext("Mapping (Pass II) [directories]\n");
			msg(msgp);
		}
		nadded = 0;
		ino = 0;
		pass(add, dirmap);
	} while (nadded);

	ino = 0; /* adjust estimated size for shadow inodes */
	pass(markshad, nodmap);
	ino = 0;
	pass(estshad, shamap);
	freeshad();

	bmapest(clrmap);
	bmapest(nodmap);
	esize = o_esize + f_esize;
	if (diskette) {
		/* estimate number of floppies */
		if (tsize != 0)
			fetapes = (double)(esize + ntrec) / (double)tsize;
	} else if (cartridge) {
		/*
		 * Estimate number of tapes, assuming streaming stops at
		 * the end of each block written, and not in mid-block.
		 * Assume no erroneous blocks; this can be compensated for
		 * with an artificially low tape size.
		 */
		tenthsperirg = 16;	/* actually 15.48, says Archive */
		if (tsize != 0)
			fetapes = ((double)esize /* blocks */
			    * (tp_bsize		/* bytes/block */
			    * (1.0/density))	/* 0.1" / byte */
			    +
			    (double)esize	/* blocks */
			    * (1.0/ntrec)	/* streaming-stops per block */
			    * tenthsperirg)	/* 0.1" / streaming-stop */
			    * (1.0 / tsize);	/* tape / 0.1" */
	} else {
		/* Estimate number of tapes, for old fashioned 9-track tape */
#ifdef sun
		/* sun has long irg's */
		tenthsperirg = (density == 625) ? 6 : 12;
#else
		tenthsperirg = (density == 625) ? 5 : 8;
#endif
		if (tsize != 0)
			fetapes = ((double)esize /* blocks */
			    * (tp_bsize		/* bytes / block */
			    * (1.0/density))	/* 0.1" / byte */
			    +
			    (double)esize	/* blocks */
			    * (1.0/ntrec)	/* IRG's / block */
			    * tenthsperirg)	/* 0.1" / IRG */
			    * (1.0 / tsize);	/* tape / 0.1" */
	}

	etapes = fetapes;	/* truncating assignment */
	etapes++;
	/* count the nodemap on each additional tape */
	for (i = 1; i < etapes; i++)
		bmapest(nodmap);
	/*
	 * If the above bmapest is called, it changes o_esize and f_esize.
	 * So we will recalculate esize here anyway to make sure.
	 * Also, add tape headers and trailer records.
	 */
	esize = o_esize + f_esize + etapes + ntrec;

	/*
	 * If the estimated number of tp_bsize tape blocks is greater than
	 * INT_MAX we have to adjust tp_bsize and ntrec to handle
	 * the larger dump.  esize is an estimate, so we 'fudge'
	 * INT_MAX a little.  If tp_bsize is adjusted, it will be adjusted
	 * to the size needed for this dump (2048, 4096, 8192, ...)
	 */
	if (esize > (INT_MAX - FUDGE_FACTOR)) { /* esize is too big */
		forceflag++;
		esize_shift =
		    ((esize + (INT_MAX - FUDGE_FACTOR) - 1)/
		    ((u_offset_t)(INT_MAX - FUDGE_FACTOR))) - 1;
		if ((esize_shift > ESIZE_SHIFT_MAX) || (ntrec == 0)) {
			msgp = gettext(
	"Block factor %d ('b' flag) is too small for this size dump.");
			msg(msgp, saved_ntrec);
			dumpabort();
			/*NOTREACHED*/
		}
		/*
		 * recalculate esize from:
		 * o_esize - header tape records
		 * (f_esize + (num_mult -1)) >> esize_shift - new non-header
		 *	tape records for files/maps
		 * etapes - TS_TAPE records
		 * ntrec - TS_END records
		 *
		 * ntrec is adjusted so a tape record is still 'b' flag
		 * number of DEV_BSIZE (512) in size
		 */
		new_mult = (tp_bsize << esize_shift)/tp_bsize;
		tp_bsize = (tp_bsize << esize_shift);
		esize = o_esize + ((f_esize +
		    (new_mult - 1)) >> esize_shift) + etapes + ntrec;
		ntrec = (saved_ntrec/(tp_bsize/DEV_BSIZE));
	}
	if (forceflag != 0) {
		msgp = gettext(
		    "Forcing larger tape block size (%d).\n");
		msg(msgp, tp_bsize);
	}
	alloctape();			/* allocate tape buffers */

	assert((tp_bsize / DEV_BSIZE != 0) && (tp_bsize % DEV_BSIZE == 0));
	/*
	 * If all we wanted was the size estimate,
	 * just print it out and exit.
	 */
	if (printsize) {
		(void) printf("%llu\n", esize * tp_bsize);
		Exit(0);
	}

	if (tsize != 0) {
		if (diskette)
			msgp = gettext(
			    "Estimated %lld blocks (%s) on %3.2f diskettes.\n");
		else
			msgp = gettext(
			    "Estimated %lld blocks (%s) on %3.2f tapes.\n");

		msg(msgp,
		    (esize*(tp_bsize/DEV_BSIZE)), mb(esize), fetapes);
	} else {
		msgp = gettext("Estimated %lld blocks (%s).\n");
		msg(msgp, (esize*(tp_bsize/DEV_BSIZE)), mb(esize));
	}

	dumpstate = DS_CLRI;

	otape(1);			/* bitmap is the first to tape write */
	*telapsed = 0;
	(void) time(tstart_writing);

	/* filmap indicates all non-directory inodes */
	{
		uchar_t *np, *fp, *dp;
		np = nodmap;
		dp = dirmap;
		fp = filmap;
		for (i = 0; i < msiz; i++)
			*fp++ = *np++ ^ *dp++;
	}

	while (dumpstate != DS_DONE) {
		/*
		 * When we receive EOT notification from
		 * the writer, the signal handler calls
		 * rollforward and then jumps here.
		 */
		(void) setjmp(checkpoint_buf);
		switch (dumpstate) {
		case DS_INIT:
			/*
			 * We get here if a tape error occurred
			 * after releasing the name lock but before
			 * the volume containing the last of the
			 * dir info was completed.  We have to start
			 * all over in this case.
			 */
			{
				char *rmsg = gettext(
		"Warning - output error occurred after releasing name lock\n\
\tThe dump will restart\n");
				msg(rmsg);
				goto restart;
			}
			/* NOTREACHED */
		case DS_START:
		case DS_CLRI:
			ino = UFSROOTINO;
			dumptoarchive = 1;
			bitmap(clrmap, TS_CLRI);
			nextstate(DS_BITS);
			/* FALLTHROUGH */
		case DS_BITS:
			ino = UFSROOTINO;
			dumptoarchive = 1;
			if (BIT(UFSROOTINO, nodmap))	/* empty dump check */
				bitmap(nodmap, TS_BITS);
			nextstate(DS_DIRS);
			if (!doingverify) {
				msgp = gettext(
				    "Dumping (Pass III) [directories]\n");
				msg(msgp);
			}
			/* FALLTHROUGH */
		case DS_DIRS:
			dumptoarchive = 1;
			pass(dirdump, dirmap);
			nextstate(DS_FILES);
			if (!doingverify) {
				msgp = gettext(
				    "Dumping (Pass IV) [regular files]\n");
				msg(msgp);
			}
			/* FALLTHROUGH */
		case DS_FILES:
			dumptoarchive = 0;

			pass(lf_dump, filmap);

			flushcmds();
			dumpstate = DS_END;	/* don't reset ino */
			/* FALLTHROUGH */
		case DS_END:
			dumptoarchive = 1;
			spcl.c_type = TS_END;
			for (i = 0; i < ntrec; i++) {
				spclrec();
			}
			flusht();
			break;
		case DS_DONE:
			break;
		default:
			msg(gettext("Internal state error\n"));
			dumpabort();
			/*NOTREACHED*/
		}
	}

	if ((! doingactive) && (! active))
		trewind();
	if (verify && !doingverify) {
		msgp = gettext("Finished writing last dump volume\n");
		msg(msgp);
		Exit(X_VERIFY);
	}
	if (spcl.c_volume > 1)
		(void) snprintf(msgbuf, sizeof (msgbuf),
		    gettext("%lld blocks (%s) on %ld volumes"),
		    ((uint64_t)spcl.c_tapea*(tp_bsize/DEV_BSIZE)),
		    mb((u_offset_t)(unsigned)(spcl.c_tapea)),
		    spcl.c_volume);
	else
		(void) snprintf(msgbuf, sizeof (msgbuf),
		    gettext("%lld blocks (%s) on 1 volume"),
		    ((uint64_t)spcl.c_tapea*(tp_bsize/DEV_BSIZE)),
		    mb((u_offset_t)(unsigned)(spcl.c_tapea)));
	if (timeclock((time_t)0) != (time_t)0) {
		(void) snprintf(kbsbuf, sizeof (kbsbuf),
		    gettext(" at %ld KB/sec"),
		    (long)(((float)spcl.c_tapea / (float)timeclock((time_t)0))
		    * 1000.0));
		(void) strcat(msgbuf, kbsbuf);
	}
	(void) strcat(msgbuf, "\n");
	msg(msgbuf);
	(void) timeclock((time_t)-1);

	if (archive)
		msg(gettext("Archiving dump to `%s'\n"), archivefile);
	if (active && !verify) {
		nextstate(DS_INIT);
		activepass();
		goto restart;
	}
	msgp = gettext("DUMP IS DONE\n");
	msg(msgp);
	broadcast(msgp);
	if (! doingactive)
		putitime();
	Exit(X_FINOK);

	/*NOTREACHED*/
	return (0);
}

void
sigAbort(int sig)
{
	char	*sigtype;

	switch (sig) {
	case SIGHUP:
		sigtype = "SIGHUP";
		break;
	case SIGTRAP:
		sigtype = "SIGTRAP";
		break;
	case SIGFPE:
		sigtype = "SIGFPE";
		break;
	case SIGBUS:
		msg(gettext("%s  ABORTING!\n"), "SIGBUS()");
		(void) signal(SIGUSR2, SIG_DFL);
		abort();
		/*NOTREACHED*/
	case SIGSEGV:
		msg(gettext("%s  ABORTING!\n"), "SIGSEGV()");
		(void) signal(SIGUSR2, SIG_DFL);
		abort();
		/*NOTREACHED*/
	case SIGALRM:
		sigtype = "SIGALRM";
		break;
	case SIGTERM:
		sigtype = "SIGTERM";
		break;
	case SIGPIPE:
		msg(gettext("Broken pipe\n"));
		dumpabort();
		/*NOTREACHED*/
	default:
		sigtype = "SIGNAL";
		break;
	}
	msg(gettext("%s()  try rewriting\n"), sigtype);
	if (pipeout) {
		msg(gettext("Unknown signal, Cannot recover\n"));
		dumpabort();
		/*NOTREACHED*/
	}
	msg(gettext("Rewriting attempted as response to unknown signal.\n"));
	(void) fflush(stderr);
	(void) fflush(stdout);
	close_rewind();
	Exit(X_REWRITE);
}

/* Note that returned value is malloc'd if != cp && != NULL */
char *
rawname(char *cp)
{
	struct stat64 st;
	char *dp;
	extern char *getfullrawname();

	if (stat64(cp, &st) < 0 || (st.st_mode & S_IFMT) != S_IFBLK)
		return (cp);

	dp = getfullrawname(cp);
	if (dp == 0)
		return (0);
	if (*dp == '\0') {
		free(dp);
		return (0);
	}

	if (stat64(dp, &st) < 0 || (st.st_mode & S_IFMT) != S_IFCHR) {
		free(dp);
		return (cp);
	}

	return (dp);
}

static char *
mb(u_offset_t blks)
{
	static char buf[16];

	if (blks < 1024)
		(void) snprintf(buf, sizeof (buf), "%lldKB", blks);
	else
		(void) snprintf(buf, sizeof (buf), "%.2fMB",
		    ((double)(blks*tp_bsize)) / (double)(1024*1024));
	return (buf);
}

#ifdef signal
void (*nsignal(int sig, void (*act)(int)))(int)
{
	struct sigaction sa, osa;

	sa.sa_handler = act;
	(void) sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(sig, &sa, &osa) < 0)
		return ((void (*)(int))-1);
	return (osa.sa_handler);
}
#endif

static void
nextstate(int state)
{
	/* LINTED assigned value never used - kept for documentary purposes */
	dumpstate = state;
	/* LINTED assigned value never used - kept for documentary purposes */
	ino = 0;
	/* LINTED assigned value never used - kept for documentary purposes */
	pos = 0;
	leftover = 0;
}

/*
 * timeclock() function, for keeping track of how much time we've spent
 * writing to the tape device.  it always returns the amount of time
 * already spent, in milliseconds.  if you pass it a positive, then that's
 * telling it that we're writing, so the time counts.  if you pass it a
 * zero, then that's telling it we're not writing; perhaps we're waiting
 * for user input.
 *
 * a state of -1 resets everything.
 */
time32_t
timeclock(time32_t state)
{
	static int *currentState = NULL;
	static struct timeval *clockstart;
	static time32_t *emilli;

	struct timeval current[1];
	int fd, saverr;

#ifdef DEBUG
	fprintf(stderr, "pid=%d timeclock ", getpid());
	if (state == (time32_t)-1)
		fprintf(stderr, "cleared\n");
	else if (state > 0)
		fprintf(stderr, "ticking\n");
	else
		fprintf(stderr, "paused\n");
#endif /* DEBUG */

	/* if we haven't setup the shared memory, init */
	if (currentState == (int *)NULL) {
		if ((fd = open("/dev/zero", O_RDWR)) < 0) {
			saverr = errno;
			msg(gettext("Cannot open `%s': %s\n"),
			    "/dev/zero", strerror(saverr));
			dumpabort();
			/*NOTREACHED*/
		}
		/*LINTED [mmap always returns an aligned value]*/
		currentState = (int *)mmap((char *)0, getpagesize(),
		    PROT_READ|PROT_WRITE, MAP_SHARED, fd, (off_t)0);
		if (currentState == (int *)-1) {
			saverr = errno;
			msg(gettext(
			    "Cannot memory map monitor variables: %s\n"),
			    strerror(saverr));
			dumpabort();
			/*NOTREACHED*/
		}
		(void) close(fd);

		/* LINTED currentState is sufficiently aligned */
		clockstart = (struct timeval *)(currentState + 1);
		emilli = (time32_t *)(clockstart + 1);
		/* Note everything is initialized to zero via /dev/zero */
	}

	if (state == (time32_t)-1) {
		bzero(clockstart, sizeof (*clockstart));
		*currentState = 0;
		*emilli = (time32_t)0;
		return (0);
	}

	(void) gettimeofday(current, NULL);

	if (*currentState != 0) {
		current->tv_usec += 1000000;
		current->tv_sec--;

		/* LINTED: result will fit in a time32_t */
		*emilli += (current->tv_sec - clockstart->tv_sec) * 1000;
		/* LINTED: result will fit in a time32_t */
		*emilli += (current->tv_usec - clockstart->tv_usec) / 1000;
	}

	if (state != 0)
		bcopy(current, clockstart, sizeof (current));

	*currentState = state;

	return (*emilli);
}

static int
statcmp(const struct stat64 *left, const struct stat64 *right)
{
	int result = 1;

	if ((left->st_dev == right->st_dev) &&
	    (left->st_ino == right->st_ino) &&
	    (left->st_mode == right->st_mode) &&
	    (left->st_nlink == right->st_nlink) &&
	    (left->st_uid == right->st_uid) &&
	    (left->st_gid == right->st_gid) &&
	    (left->st_rdev == right->st_rdev) &&
	    (left->st_ctim.tv_sec == right->st_ctim.tv_sec) &&
	    (left->st_ctim.tv_nsec == right->st_ctim.tv_nsec) &&
	    (left->st_mtim.tv_sec == right->st_mtim.tv_sec) &&
	    (left->st_mtim.tv_nsec == right->st_mtim.tv_nsec)) {
		/*
		 * Unlike in the ufsrestore version
		 * st_blocks and st_blksiz are not
		 * compared. The reason for this is
		 * problems with zfs dump files. Zfs
		 * changes it's statistics in those
		 * fields.
		 */
		result = 0;
	}

	return (result);
}

/*
 * Safely open a file or device.
 */
static int
safe_open_common(const char *filename, int mode, int perms, int device)
{
	int fd;
	int working_mode;
	int saverr;
	char *errtext;
	struct stat64 pre_stat, pre_lstat;
	struct stat64 post_stat, post_lstat;

	/*
	 * Don't want to be spoofed into trashing something we
	 * shouldn't, thus the following rigamarole.  If it doesn't
	 * exist, we create it and proceed.  Otherwise, require that
	 * what's there be a real file with no extraneous links and
	 * owned by whoever ran us.
	 *
	 * The silliness with using both lstat() and fstat() is to avoid
	 * race-condition games with someone replacing the file with a
	 * symlink after we've opened it.  If there was an flstat(),
	 * we wouldn't need the fstat().
	 *
	 * The initial open with the hard-coded flags is ok even if we
	 * are intending to open only for reading.  If it succeeds,
	 * then the file did not exist, and we'll synthesize an appropriate
	 * complaint below.  Otherwise, it does exist, so we won't be
	 * truncating it with the open.
	 */
	if ((fd = open(filename, O_WRONLY|O_CREAT|O_TRUNC|O_EXCL|O_LARGEFILE,
	    perms)) < 0) {
		if (errno == EEXIST) {
			if (lstat64(filename, &pre_lstat) < 0) {
				return (-1);
			}

			if (stat64(filename, &pre_stat) < 0) {
				return (-1);
			}

			working_mode = mode & (O_WRONLY|O_RDWR|O_RDONLY);
			working_mode |= O_LARGEFILE;
			if ((fd = open(filename, working_mode)) < 0) {
				if (errno == ENOENT) {
					errtext = gettext(
"Unexpected condition detected: %s used to exist, but doesn't any longer\n");
					msg(errtext, filename);
					syslog(LOG_WARNING, errtext, filename);
					errno = ENOENT;
				}
				return (-1);
			}

			if (lstat64(filename, &post_lstat) < 0) {
				saverr = errno;
				(void) close(fd);
				errno = saverr;
				return (-1);
			}

			if (fstat64(fd, &post_stat) < 0) {
				saverr = errno;
				(void) close(fd);
				errno = saverr;
				return (-1);
			}

			/*
			 * Can't just use memcmp(3C), because the access
			 * time is updated by open(2).
			 */
			if (statcmp(&pre_lstat, &post_lstat) != 0) {
				errtext = gettext("Unexpected change detected: "
				    "%s's lstat(2) information changed\n");
				msg(errtext, filename);
				syslog(LOG_WARNING, errtext, filename);
				errno = EPERM;
				return (-1);
			}

			if (statcmp(&pre_stat, &post_stat) != 0) {
				errtext = gettext("Unexpected change detected: "
				    "%s's stat(2) information changed\n"),
				    msg(errtext, filename);
				syslog(LOG_WARNING, errtext, filename);
				errno = EPERM;
				return (-1);
			}

			/*
			 * If inode, device, or type are wrong, bail out.
			 * Note using post_stat instead of post_lstat for the
			 * S_ISCHR() test.  This is to allow the /dev ->
			 * /devices bit to work, as long as the final target
			 * is a character device (i.e., raw disk or tape).
			 */
			if (device && !(S_ISCHR(post_stat.st_mode)) &&
			    !(S_ISFIFO(post_stat.st_mode)) &&
			    !(S_ISREG(post_lstat.st_mode))) {
				errtext = gettext("Unexpected condition "
				    "detected: %s is not a supported device\n"),
				    msg(errtext, filename);
				syslog(LOG_WARNING, errtext, filename);
				(void) close(fd);
				errno = EPERM;
				return (-1);
			} else if (!device &&
			    (!S_ISREG(post_lstat.st_mode) ||
			    (post_stat.st_ino != post_lstat.st_ino) ||
			    (post_stat.st_dev != post_lstat.st_dev))) {
				errtext = gettext("Unexpected condition "
				    "detected: %s is not a regular file\n"),
				    msg(errtext, filename);
				syslog(LOG_WARNING, errtext, filename);
				(void) close(fd);
				errno = EPERM;
				return (-1);
			}

			/*
			 * Bad link count implies someone's linked our
			 * target to something else, which we probably
			 * shouldn't step on.
			 */
			if (post_lstat.st_nlink != 1) {
				errtext = gettext("Unexpected condition "
				    "detected: %s must have exactly one "
				    "link\n"), msg(errtext, filename);
				syslog(LOG_WARNING, errtext, filename);
				(void) close(fd);
				errno = EPERM;
				return (-1);
			}
			/*
			 * Root might make a file, but non-root might
			 * need to open it.  If the permissions let us
			 * get this far, then let it through.
			 */
			if (post_lstat.st_uid != getuid() &&
			    post_lstat.st_uid != 0) {
				errtext = gettext("Unsupported "
				    "condition detected: %s "
				    "must be owned by uid %ld or 0\n"),
				    msg(errtext, filename, (long)getuid());
				syslog(LOG_WARNING, errtext, filename,
				    (long)getuid());
				(void) close(fd);
				errno = EPERM;
				return (-1);
			}
			if (mode & O_TRUNC) {
				if (ftruncate(fd, (off_t)0) < 0) {
					msg("ftruncate(%s): %s\n",
					    filename, strerror(errno));
					(void) close(fd);
					return (-1);
				}
			}
		} else {
			/*
			 * Didn't exist, but couldn't open it.
			 */
			return (-1);
		}
	} else {
		/*
		 * If truncating open succeeded for a read-only open,
		 * bail out, as we really shouldn't have succeeded.
		 */
		if (mode & O_RDONLY) {
			/* Undo the O_CREAT */
			(void) unlink(filename);
			msg("open(%s): %s\n",
			    filename, strerror(ENOENT));
			(void) close(fd);
			errno = ENOENT;
			return (-1);
		}
	}

	return (fd);
}

/*
 * Safely open a file.
 */
int
safe_file_open(const char *filename, int mode, int perms)
{
	return (safe_open_common(filename, mode, perms, 0));
}

/*
 * Safely open a device.
 */
int
safe_device_open(const char *filename, int mode, int perms)
{
	return (safe_open_common(filename, mode, perms, 1));
}

/*
 * STDIO version of safe_open
 */
FILE *
safe_fopen(const char *filename, const char *smode, int perms)
{
	int fd;
	int bmode;

	/*
	 * accepts only modes  "r", "r+", and "w"
	 */
	if (smode[0] == 'r') {
		if (smode[1] == '\0') {
			bmode = O_RDONLY;
		} else if ((smode[1] == '+') && (smode[2] == '\0')) {
			bmode = O_RDWR;
		}
	} else if ((smode[0] == 'w') && (smode[1] == '\0')) {
		bmode = O_WRONLY;
	} else {
		msg(gettext("internal error: safe_fopen: invalid mode `%s'\n"),
		    smode);
		return (NULL);
	}

	fd = safe_file_open(filename, bmode, perms);

	/*
	 * caller is expected to report error.
	 */
	if (fd >= 0)
		return (fdopen(fd, smode));

	return ((FILE *)NULL);
}

void
child_chdir(void)
{
	char name[MAXPATHLEN];

	if (debug_chdir != NULL) {
		snprintf(name, sizeof (name), "%s/%ld",
		    debug_chdir, (long)getpid());
		if (mkdir(name, 0755) < 0)
			msg("mkdir(%s): %s", name, strerror(errno));
		if (chdir(name) < 0)
			msg("chdir(%s): %s", name, strerror(errno));
	}
}
