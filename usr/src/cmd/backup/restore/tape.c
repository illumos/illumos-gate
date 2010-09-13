/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <setjmp.h>
#include "restore.h"
#include <byteorder.h>
#include <rmt.h>
#include <sys/mtio.h>
#include <utime.h>
#include <sys/errno.h>
#include <sys/fdio.h>
#include <sys/sysmacros.h>	/* for expdev */
#include <assert.h>
#include <limits.h>
#include <priv_utils.h>
#include <aclutils.h>

#define	MAXINO	65535		/* KLUDGE */

#define	MAXTAPES	128

static size_t	fssize = MAXBSIZE; /* preferred size of writes to filesystem */
int mt = -1;
static int	continuemap = 0;
char		magtape[BUFSIZ];
int		pipein = 0;
char		*host;		/* used in dumprmt.c */
daddr32_t	rec_position;
static char	*archivefile;	/* used in metamucil.c */
static int	bct;		/* block # index into tape record buffer */
static int	numtrec;	/* # of logical blocks in current tape record */
static char	*tbf = NULL;
static size_t	tbfsize = 0;
static int	recsread;
static union	u_spcl endoftapemark;
static struct	s_spcl dumpinfo;
static long	blksread;	/* # of logical blocks actually read/touched */
static long	tapea;		/* current logical block # on tape */
static uchar_t	tapesread[MAXTAPES];
static jmp_buf	restart;
static int	gettingfile = 0;	/* restart has a valid frame */
static int	ofile;
static char	*map, *beginmap;
static char	*endmap;
static char	lnkbuf[MAXPATHLEN + 2];
static int	pathlen;
static int	inodeinfo;	/* Have starting volume information */
static int	hostinfo;	/* Have dump host information */

static int autoload_tape(void);
static void setdumpnum(void);
static void metacheck(struct s_spcl *);
static void xtrmeta(char *, size_t);
static void metaskip(char *, size_t);
static void xtrfile(char *, size_t);
static void xtrskip(char *, size_t);
static void xtrlnkfile(char *, size_t);
static void xtrlnkskip(char *, size_t);
static void xtrmap(char *, size_t);
static void xtrmapskip(char *, size_t);
static void readtape(char *);
static int checkvol(struct s_spcl *, int);
static void accthdr(struct s_spcl *);
static int ishead(struct s_spcl *);
static int checktype(struct s_spcl *, int);
static void metaset(char *name);

/*
 * Set up an input source
 */
void
setinput(char *source, char *archive)
{

	flsht();
	archivefile = archive;
	if (bflag == 0) {
		ntrec = ((CARTRIDGETREC > HIGHDENSITYTREC) ?
		    (NTREC > CARTRIDGETREC ? NTREC : CARTRIDGETREC) :
		    (NTREC > HIGHDENSITYTREC ? NTREC : HIGHDENSITYTREC));
		saved_ntrec = (ntrec * (tp_bsize/DEV_BSIZE));
	}
	newtapebuf(ntrec);
	terminal = stdin;

	if (source == NULL) {
		/* A can't-happen */
		(void) fprintf(stderr,
		    gettext("Internal consistency check failed.\n"));
		done(1);
	}

	if (strchr(source, ':')) {
		char *tape;

		host = source;
		tape = strchr(host, ':');
		*tape++ = '\0';
		if (strlen(tape) > (sizeof (magtape) - 1)) {
			(void) fprintf(stderr, gettext("Tape name too long\n"));
			done(1);
		}
		(void) strcpy(magtape, tape);
		if (rmthost(host, ntrec) == 0)
			done(1);
	} else {
		if (strlen(source) > (sizeof (magtape) - 1)) {
			(void) fprintf(stderr, gettext("Tape name too long\n"));
			done(1);
		}
		/* Not remote, no need for privileges */
		__priv_relinquish();
		host = NULL;
		if (strcmp(source, "-") == 0) {
			/*
			 * Since input is coming from a pipe we must establish
			 * our own connection to the terminal.
			 */
			terminal = fopen("/dev/tty", "r");
			if (terminal == NULL) {
				int saverr = errno;
				char *msg =
				    gettext("Cannot open(\"/dev/tty\")");
				errno = saverr;
				perror(msg);
				terminal = fopen("/dev/null", "r");
				if (terminal == NULL) {
					saverr = errno;
					msg = gettext(
					    "Cannot open(\"/dev/null\")");
					errno = saverr;
					perror(msg);
					done(1);
				}
			}
			pipein++;
			if (archive) {
				(void) fprintf(stderr, gettext(
	    "Cannot specify an archive file when reading from a pipe\n"));
				done(1);
			}
		}
		(void) strcpy(magtape, source);
	}
}

void
newtapebuf(size_t size)
{
	size_t nsize;

	nsize = size * tp_bsize;
	ntrec = size;
	if (nsize <= tbfsize)
		return;
	if (tbf != NULL)
		free(tbf);
	tbf = (char *)malloc(nsize);
	if (tbf == NULL) {
		(void) fprintf(stderr,
		    gettext("Cannot allocate space for buffer\n"));
		done(1);
	}
	tbfsize = nsize;
}

/*
 * Verify that the tape drive can be accessed and
 * that it actually is a dump tape.
 */
void
setup(void)
{
	int i, j;
	int32_t *ip;
	struct stat stbuf;
	size_t mapsize;
	char *syment = RESTORESYMTABLE;

	vprintf(stdout, gettext("Verify volume and initialize maps\n"));
	if (archivefile) {
		mt = open(archivefile, O_RDONLY|O_LARGEFILE);
		if (mt < 0) {
			perror(archivefile);
			done(1);
		}
		volno = 0;
	} else if (host) {
		if ((mt = rmtopen(magtape, O_RDONLY)) < 0) {
			perror(magtape);
			done(1);
		}
		volno = 1;
	} else {
		if (pipein)
			mt = 0;
		else if ((mt = open(magtape, O_RDONLY|O_LARGEFILE)) < 0) {
			perror(magtape);
			done(1);
		}
		volno = 1;
	}
	setdumpnum();
	flsht();
	if (!pipein && !bflag)
		if (archivefile)
			findtapeblksize(ARCHIVE_FILE);
		else
			findtapeblksize(TAPE_FILE);
	if (bflag == 1) {
		tape_rec_size = saved_ntrec * DEV_BSIZE;
	}

	/*
	 * Get the first header.  If c_magic is NOT NFS_MAGIC or if
	 * the checksum is in error, it will fail.  The magic could then
	 * be either OFS_MAGIC or MTB_MAGIC.  If OFS_MAGIC, assume we
	 * have an old dump, and try to convert it.  If it is MTB_MAGIC, we
	 * procees this after.
	 */
	if ((gethead(&spcl) == FAIL) && (spcl.c_magic != MTB_MAGIC)) {
		bct--; /* push back this block */
		blksread--;
		tapea--;
		cvtflag++;
		if (gethead(&spcl) == FAIL) {
			(void) fprintf(stderr,
			    gettext("Volume is not in dump format\n"));
			done(1);
		}
		(void) fprintf(stderr,
		    gettext("Converting to new file system format.\n"));
	}
	/*
	 * The above gethead will have failed if the magic is
	 * MTB_MAGIC. If that is true, we need to adjust tp_bsize.
	 * We have assumed to this time that tp_bsize was 1024, if
	 * this is a newer dump, get the real tp_bsize from the header,
	 * and recalculate ntrec, numtrec.
	 */
	if (spcl.c_magic == MTB_MAGIC) {
		tp_bsize = spcl.c_tpbsize;
		if ((tp_bsize % TP_BSIZE_MIN != 0) ||
		    (tp_bsize > TP_BSIZE_MAX)) {
			(void) fprintf(stderr,
			    gettext("Volume is not in dump format\n"));
			done(1);
		}
		ntrec = (tape_rec_size/tp_bsize);
		numtrec = ntrec;
		newtapebuf(ntrec);
		bct--; /* push back this block */
		blksread--;
		tapea--;
		/* we have to re-do this in case checksum is wrong */
		if (gethead(&spcl) == FAIL) {
			(void) fprintf(stderr,
			    gettext("Volume is not in dump format\n"));
			done(1);
		}
	}
	if (vflag)
		byteorder_banner(byteorder, stdout);
	if (pipein) {
		endoftapemark.s_spcl.c_magic = cvtflag ? OFS_MAGIC :
		    ((tp_bsize == TP_BSIZE_MIN) ? NFS_MAGIC : MTB_MAGIC);
		endoftapemark.s_spcl.c_type = TS_END;

		/*
		 * include this since the `resync' loop in findinode
		 * expects to find a header with the c_date field
		 * filled in.
		 */
		endoftapemark.s_spcl.c_date = spcl.c_date;

		ip = (int32_t *)&endoftapemark;
		/*LINTED [assertion always true]*/
		assert((sizeof (endoftapemark) % sizeof (int32_t)) == 0);
		j = sizeof (endoftapemark) / sizeof (int32_t);
		i = 0;
		do
			i += *ip++;
		while (--j)
			;
		endoftapemark.s_spcl.c_checksum = CHECKSUM - i;
	}
	if (vflag && command != 't')
		printdumpinfo();
	dumptime = spcl.c_ddate;
	dumpdate = spcl.c_date;
	if (stat(".", &stbuf) < 0) {
		perror(gettext("cannot stat ."));
		done(1);
	}
	if (stbuf.st_blksize >= tp_bsize && stbuf.st_blksize <= MAXBSIZE) {
		/* LINTED: value fits in a size_t */
		fssize = stbuf.st_blksize;
	} else {
		fssize = MAXBSIZE;
	}

	if (checkvol(&spcl, 1) == FAIL) {
		(void) fprintf(stderr,
		    gettext("This is not volume 1 of the dump\n"));
		done(1);
	}
	if (readhdr(&spcl) == FAIL)
		panic(gettext("no header after volume mark!\n"));

	findinode(&spcl);	/* sets curfile, resyncs the tape if need be */
	if (checktype(&spcl, TS_CLRI) == FAIL) {
		(void) fprintf(stderr,
		    gettext("Cannot find file removal list\n"));
		done(1);
	}
	maxino = (unsigned)((spcl.c_count * tp_bsize * NBBY) + 1);
	dprintf(stdout, "maxino = %lu\n", maxino);
	/*
	 * Allocate space for at least MAXINO inodes to allow us
	 * to restore partial dump tapes written before dump was
	 * fixed to write out the entire inode map.
	 */
	if (maxino > ULONG_MAX) {
		(void) fprintf(stderr,
		    gettext("file system too large\n"));
		done(1);
	}
	/* LINTED maxino size-checked above */
	mapsize = (size_t)d_howmany(maxino > MAXINO ? maxino : MAXINO, NBBY);
	beginmap = map = calloc((size_t)1, mapsize);
	if (map == (char *)NIL) {
		(void) fprintf(stderr,
		    gettext("no memory for file removal list\n"));
		done(1);
	}
	endmap = map + mapsize;
	clrimap = map;
	curfile.action = USING;
	continuemap = 1;
	getfile(xtrmap, xtrmapskip);
	if (MAXINO > maxino)
		maxino = MAXINO;
	if (checktype(&spcl, TS_BITS) == FAIL) {
		/* if we have TS_CLRI then no TS_BITS then a TS_END */
		/* then we have an empty dump file */
		if (gethead(&spcl) == GOOD &&
		    checktype(&spcl, TS_END) == GOOD) {
			if ((command == 'r') || (command == 'R')) {
				initsymtable(syment);
				dumpsymtable(syment, volno);
			}
			done(0);
		}
		/* otherwise we have an error */
		(void) fprintf(stderr, gettext("Cannot find file dump list\n"));
		done(1);
	}
	/* LINTED maxino size-checked above */
	mapsize = (size_t)d_howmany(maxino, NBBY);
	beginmap = map = calloc((size_t)1, mapsize);
	if (map == (char *)NULL) {
		(void) fprintf(stderr,
		    gettext("no memory for file dump list\n"));
		done(1);
	}
	endmap = map + mapsize;
	dumpmap = map;
	curfile.action = USING;
	continuemap = 1;
	getfile(xtrmap, xtrmapskip);
	continuemap = 0;
}

/*
 * Initialize fssize variable for 'R' command to work.
 */
void
setupR(void)
{
	struct stat stbuf;

	if (stat(".", &stbuf) < 0) {
		perror(gettext("cannot stat ."));
		done(1);
	}
	if (stbuf.st_blksize >= tp_bsize && stbuf.st_blksize <= MAXBSIZE) {
		/* LINTED: value fits in a size_t */
		fssize = stbuf.st_blksize;
	} else {
		fssize = MAXBSIZE;
	}
}

/*
 * Prompt user to load a new dump volume.
 * "Nextvol" is the next suggested volume to use.
 * This suggested volume is enforced when doing full
 * or incremental restores, but can be overrridden by
 * the user when only extracting a subset of the files.
 *
 * first_time is used with archive files and can have 1 of 3 states:
 *	FT_STATE_1	Tape has not been read yet
 *	FT_STATE_2	Tape has been read but not positioned past directory
 *			information
 *	FT_STATE_3	Tape has been read and is reading file information
 */
#define	FT_STATE_1	1
#define	FT_STATE_2	2
#define	FT_STATE_3	3

void
getvol(int nextvol)
{
	int newvol;
	long savecnt, savetapea, wantnext;
	long i;
	union u_spcl tmpspcl;
#define	tmpbuf tmpspcl.s_spcl
	char buf[TP_BSIZE_MAX];
	static int first_time = FT_STATE_1;

	if (tbf == NULL) {
		(void) fprintf(stderr, gettext(
		    "Internal consistency failure in getvol: tbf is NULL\n"));
		done(1);
	}

	if (nextvol == 1) {
		for (i = 0;  i < MAXTAPES;  i++)
			tapesread[i] = 0;
		gettingfile = 0;
	}
	if (pipein) {
		if (nextvol != 1)
			panic(gettext("changing volumes on pipe input\n"));
		if (volno == 1)
			return;
		goto gethdr;
	}
	savecnt = blksread;	/* ignore volume verification tape i/o */
	savetapea = tapea;
again:
	if (pipein)
		done(1); /* pipes do not get a second chance */
	if (command == 'R' || command == 'r' || curfile.action != SKIP) {
		wantnext = 1;
		newvol = nextvol;
	} else {
		wantnext = 0;
		newvol = 0;
	}

	if (autoload) {
		if ((volno == 1) && (nextvol == 1)) {
			tapesread[volno-1]++;
			return;
		}
		if (autoload_tape()) {
			wantnext = 1;
			newvol = nextvol;
			goto gethdr;
		}
	}

	while (newvol <= 0) {
		int n = 0;

		for (i = 0;  i < MAXTAPES;  i++)
			if (tapesread[i])
				n++;
		if (n == 0) {
			(void) fprintf(stderr, "%s", gettext(
"You have not read any volumes yet.\n\
Unless you know which volume your file(s) are on you should start\n\
with the last volume and work towards the first.\n"));
		} else {
			(void) fprintf(stderr,
			    gettext("You have read volumes"));
			(void) strcpy(tbf, ": ");
			for (i = 0; i < MAXTAPES; i++)
				if (tapesread[i]) {
					(void) fprintf(stderr, "%s%ld",
					    tbf, i+1);
					(void) strcpy(tbf, ", ");
				}
			(void) fprintf(stderr, "\n");
		}
		do {
			(void) fprintf(stderr,
			    gettext("Specify next volume #: "));
			(void) fflush(stderr);
			/* LINTED tbfsize is limited to a few MB */
			(void) fgets(tbf, (int)tbfsize, terminal);
		} while (!feof(terminal) && tbf[0] == '\n');
		if (feof(terminal))
			done(1);
		newvol = atoi(tbf);
		if (newvol <= 0) {
			(void) fprintf(stderr, gettext(
			    "Volume numbers are positive numerics\n"));
		}
		if (newvol > MAXTAPES) {
			(void) fprintf(stderr, gettext(
			    "This program can only deal with %d volumes\n"),
			    MAXTAPES);
			newvol = 0;
		}
	}
	if (newvol == volno) {
		tapesread[volno-1]++;
		return;
	}
	closemt(ALLOW_OFFLINE);
	/*
	 * XXX: if we are switching devices, we should probably try
	 * the device once without prompting to enable unattended
	 * operation.
	 */
	if (host)
		(void) fprintf(stderr, gettext(
"Mount volume %d\nthen enter volume name on host %s (default: %s) "),
		    newvol, host,  magtape);
	else
		(void) fprintf(stderr, gettext(
		    "Mount volume %d\nthen enter volume name (default: %s) "),
		    newvol, magtape);
	(void) fflush(stderr);
	/* LINTED tbfsize is limited to a few MB */
	(void) fgets(tbf, (int)tbfsize, terminal);
	if (feof(terminal))
		done(1);
	/*
	 * XXX We don't allow rotating among tape hosts, just drives.
	 */
	if (tbf[0] != '\n') {
		(void) strncpy(magtape, tbf, sizeof (magtape));
		magtape[sizeof (magtape) - 1] = '\0';
		/* LINTED unsigned -> signed conversion ok */
		i = (int)strlen(magtape);
		if (magtape[i - 1] == '\n')
			magtape[i - 1] = '\0';
	}
	if ((host != NULL && (mt = rmtopen(magtape, O_RDONLY)) == -1) ||
	    (host == NULL &&
	    (mt = open(magtape, O_RDONLY|O_LARGEFILE)) == -1)) {
		int error = errno;
		(void) fprintf(stderr, gettext("Cannot open %s: %s\n"),
		    magtape, strerror(error));
		volno = -1;
		goto again;
	}
gethdr:
	volno = newvol;
	setdumpnum();
	flsht();
	if (!pipein && !bflag && archivefile && (first_time == FT_STATE_1)) {
		first_time = FT_STATE_2;
		findtapeblksize(TAPE_FILE);
	}
	if (readhdr(&tmpbuf) == FAIL) {
		(void) fprintf(stderr,
		    gettext("volume is not in dump format\n"));
		volno = 0;
		goto again;
	}
	if (checkvol(&tmpbuf, volno) == FAIL) {
		(void) fprintf(stderr, gettext("Wrong volume (%d)\n"),
		    tmpbuf.c_volume);
		volno = 0;
		goto again;
	}

	if (((time_t)(tmpbuf.c_date) != dumpdate) ||
	    ((time_t)(tmpbuf.c_ddate) != dumptime)) {
		char *tmp_ct;
		time_t lc_date = (time_t)tmpbuf.c_date;

		/*
		 * This is used to save the return value from lctime(),
		 * since that's volatile across lctime() invocations.
		 */
		tmp_ct = strdup(lctime(&lc_date));
		if (tmp_ct == (char *)0) {
			(void) fprintf(stderr, gettext(
			    "Cannot allocate space for time string\n"));
			done(1);
		}

		(void) fprintf(stderr,
		    gettext("Wrong dump date\n\tgot: %s\twanted: %s"),
		    tmp_ct,  lctime(&dumpdate));
		volno = 0;
		free(tmp_ct);
		goto again;
	}
	tapesread[volno-1]++;
	blksread = savecnt;
	tapea = savetapea;
	/*
	 * If continuing from the previous volume, skip over any
	 * blocks read already at the end of the previous volume.
	 *
	 * If coming to this volume at random, skip to the beginning
	 * of the next record.
	 */
	if (tmpbuf.c_type == TS_TAPE && (tmpbuf.c_flags & DR_NEWHEADER)) {
		if (!wantnext) {
			if (archivefile && first_time == FT_STATE_2) {
				first_time = FT_STATE_3;
			}
			recsread = tmpbuf.c_firstrec;
			tapea = tmpbuf.c_tapea;
			dprintf(stdout,
			    "restore skipping %d records\n",
			    tmpbuf.c_count);
			for (i = tmpbuf.c_count; i > 0; i--)
				readtape(buf);
		} else if (tmpbuf.c_firstrec != 0) {
			savecnt = blksread;
			savetapea = tapea;

			if (archivefile && first_time == FT_STATE_2) {
				/*
				 * subtract 2, 1 for archive file's TS_END
				 * and 1 for tape's TS_TAPE
				 */
				first_time = FT_STATE_3;
				i = tapea - tmpbuf.c_tapea - 2;
			} else {
				i = tapea - tmpbuf.c_tapea;
			}
			if (i > 0)
				dprintf(stdout, gettext(
				    "restore skipping %d duplicate records\n"),
				    i);
			else if (i < 0)
				dprintf(stdout, gettext(
				    "restore duplicate record botch (%d)\n"),
				    i);
			while (--i >= 0)
				readtape(buf);
			blksread = savecnt;
			tapea = savetapea + 1; /* <= (void) gethead() below */
		}
	}
	if (curfile.action == USING) {
		if (volno == 1)
			panic(gettext("active file into volume 1\n"));
		return;
	}
	(void) gethead(&spcl);
	findinode(&spcl); /* do we always restart files in full? */
	if (gettingfile) { /* i.e. will we lose metadata? */
		gettingfile = 0;
		longjmp(restart, 1); /* will this set f1 & f2? */
	}
}

/*
 * handle multiple dumps per tape by skipping forward to the
 * appropriate one.  Note we don't use absolute positioning,
 * as that may take a very long time.
 */
static void
setdumpnum(void)
{
	struct mtop tcom;
	int retval;

	if (dumpnum == 1 || volno != 1)
		return;
	if (pipein) {
		(void) fprintf(stderr,
		    gettext("Cannot have multiple dumps on pipe input\n"));
		done(1);
	}
	tcom.mt_op = MTFSF;
	tcom.mt_count = dumpnum - 1;
	if (host)
		retval = rmtioctl(MTFSF, dumpnum - 1);
	else
		retval = ioctl(mt, (int)MTIOCTOP, (char *)&tcom);
	if (retval < 0)
		perror("ioctl MTFSF");
}

void
printdumpinfo(void)
{
	int i;
	time_t date;
	static char *epoch = NULL;

	if (epoch == NULL) {
		epoch = strdup(gettext("the epoch\n"));
		if (epoch == NULL) {
			(void) fprintf(stderr, gettext("Out of memory\n"));
			return;
		}
	}

	date = (time_t)dumpinfo.c_date;
	(void) fprintf(stdout,
	    gettext("Dump   date: %s"), lctime(&date));

	date = (time_t)dumpinfo.c_ddate;
	(void) fprintf(stdout, gettext("Dumped from: %s"),
	    (dumpinfo.c_ddate == 0) ? epoch : lctime(&date));
	if (hostinfo) {
		(void) fprintf(stdout,
		    gettext("Level %d dump of %s on %.*s:%s\n"),
		    dumpinfo.c_level, dumpinfo.c_filesys,
		    sizeof (dumpinfo.c_host), dumpinfo.c_host, dumpinfo.c_dev);
		(void) fprintf(stdout,
		    gettext("Label: %.*s\n"),
		    sizeof (dumpinfo.c_label), dumpinfo.c_label);
	}
	if (inodeinfo) {
		(void) fprintf(stdout,
		    gettext("Starting inode numbers by volume:\n"));
		for (i = 1; i <= dumpinfo.c_volume; i++)
			(void) fprintf(stdout, gettext("\tVolume %d: %6d\n"),
			    i, dumpinfo.c_inos[i]);
	}
}

int
extractfile(char *name)
{
	static int complained_chown = 0;
	static int complained_lchown = 0;
	static int complained_chmod = 0;
	static int complained_utime = 0;
	static int complained_mknod = 0;
	mode_t mode;
	time_t timep[2];
	struct entry *ep;
	uid_t uid;
	gid_t gid;
	char *errmsg;
	int result, saverr;
	dev_t full_dev;
	int dfd;
	char *rname;

	curfile.name = name;
	curfile.action = USING;
	timep[0] = (time_t)curfile.dip->di_atime;
	timep[1] = (time_t)curfile.dip->di_mtime;
	mode = curfile.dip->di_mode;

	uid = curfile.dip->di_suid == UID_LONG ?
	    curfile.dip->di_uid : (uid_t)curfile.dip->di_suid;
	gid = curfile.dip->di_sgid == GID_LONG ?
	    curfile.dip->di_gid : (gid_t)curfile.dip->di_sgid;

	resolve(name, &dfd, &rname);
	if (dfd != AT_FDCWD) {
		if (fchdir(dfd) < 0) {
			saverr = errno;
			(void) fprintf(stderr, gettext(
			    "%s: unable to set attribute context: %s\n"),
			    rname, strerror(saverr));
			skipfile();
			(void) close(dfd);
			return (FAIL);
		}
	}

	switch (mode & IFMT) {

	default:
		(void) fprintf(stderr, gettext("%s: unknown file mode 0%lo\n"),
		    rname, (ulong_t)(mode&IFMT));
		skipfile();
		result = FAIL;
		break;

	case IFSOCK:
		vprintf(stdout, gettext("skipped socket %s\n"), rname);
		skipfile();
		result = GOOD;
		break;

	case IFDIR:
		if (mflag) {
			ep = lookupname(name);
			if (ep == NIL || ep->e_flags & EXTRACT) {
				panic(gettext(
				    "directory %s was not restored\n"),
				    rname);
				skipfile();
				result = FAIL;
				break;
			}
			skipfile();
			result = GOOD;
			break;
		}
		vprintf(stdout, gettext("extract file %s\n"), rname);
		result = genliteraldir(rname, curfile.ino);
		break;

	case IFLNK:
		lnkbuf[0] = '\0';
		pathlen = 0;
		getfile(xtrlnkfile, xtrlnkskip);
		if (pathlen == 0) {
			vprintf(stdout, gettext(
			    "%s: zero length symbolic link (ignored)\n"),
			    rname);
			result = GOOD;
			break;
		}
		if ((result = lf_linkit(lnkbuf, rname, SYMLINK)) != GOOD)
			break;

		/* 1254700: set uid/gid (previously missing)  */
		if (lchown(rname, uid, gid) < 0 && !complained_lchown) {
			/* Just a warning */
			saverr = errno;
			errmsg = gettext(
			    "Unable to restore ownership of symlink %s: %s\n");
			(void) fprintf(stderr, errmsg,
			    rname, strerror(saverr));
			(void) fprintf(stderr, gettext(
			    "Additional such failures will be ignored.\n"));
			complained_lchown = 1;
		}
		metaset(rname);
		result = GOOD;
		break;

	case IFCHR:
	case IFBLK:
	case IFIFO:
		vprintf(stdout, gettext("extract special file %s\n"), rname);
		/* put device rdev into dev_t expanded format */
		/* XXX does this always do the right thing? */
		/* XXX does dump do the right thing? */
		if (((curfile.dip->di_ordev & 0xFFFF0000) == 0) ||
		    ((curfile.dip->di_ordev & 0xFFFF0000) == 0xFFFF0000)) {
			full_dev = expdev((unsigned)(curfile.dip->di_ordev));
		} else {
			/* LINTED sign extension ok */
			full_dev = (unsigned)(curfile.dip->di_ordev);
		}

		if (mknod(rname, mode, full_dev) < 0) {
			struct stat64 s[1];

			saverr = errno;
			if ((stat64(rname, s)) ||
			    ((s->st_mode & S_IFMT) != (mode & S_IFMT)) ||
			    (s->st_rdev != full_dev)) {
				if (saverr != EPERM || !complained_mknod) {
					(void) fprintf(stderr, "%s: ", rname);
					(void) fflush(stderr);
					errno = saverr;
					perror(gettext(
					    "cannot create special file"));
					if (saverr == EPERM) {
						(void) fprintf(stderr, gettext(
			    "Additional such failures will be ignored.\n"));
						complained_mknod = 1;
					}
				}
				skipfile();
				result = FAIL;
				break;
			}
		}
		if (chown(rname, uid, gid) < 0 && !complained_chown) {
			/* Just a warning */
			saverr = errno;
			errmsg = gettext(
			    "Unable to restore ownership of %s: %s\n");
			(void) fprintf(stderr, errmsg,
			    rname, strerror(saverr));
			(void) fprintf(stderr, gettext(
			    "Additional such failures will be ignored.\n"));
			complained_chown = 1;
		}
		if (chmod(rname, mode) < 0 && !complained_chmod) {
			saverr = errno;
			errmsg = gettext(
			    "Unable to restore permissions on %s: %s\n");
			(void) fprintf(stderr, errmsg,
			    rname, strerror(saverr));
			(void) fprintf(stderr, gettext(
			    "Additional such failures will be ignored.\n"));
			complained_chmod = 1;
		}
		skipfile();
		metaset(rname); /* skipfile() got the metadata, if any */
		if (utime(rname, (struct utimbuf *)timep) < 0 &&
		    !complained_utime) {
			saverr = errno;
			errmsg = gettext(
			    "Unable to restore times on %s: %s\n");
			(void) fprintf(stderr, errmsg,
			    rname, strerror(saverr));
			(void) fprintf(stderr, gettext(
			    "Additional such failures will be ignored.\n"));
			complained_utime = 1;
		}
		result = GOOD;
		break;

	case IFREG:
		vprintf(stdout, gettext("extract file %s\n"), rname);

		/*
		 * perform a restrictive creat(2) initally, we'll
		 * fchmod(2) according to the archive later after
		 * we've written the blocks.
		 */
		ofile = creat64(rname, 0600);

		if (ofile < 0) {
			saverr = errno;
			errmsg = gettext("cannot create file");
			(void) fprintf(stderr, "%s: ", rname);
			(void) fflush(stderr);
			errno = saverr;
			perror(errmsg);
			skipfile();
			result = FAIL;
			break;
		}
		if (fchown(ofile, uid, gid) < 0 && !complained_chown) {
			/* Just a warning */
			saverr = errno;
			errmsg = gettext(
			    "Unable to restore ownership of %s: %s\n");
			(void) fprintf(stderr, errmsg,
			    rname, strerror(saverr));
			(void) fprintf(stderr, gettext(
			    "Additional such failures will be ignored.\n"));
			complained_chown = 1;
		}

		getfile(xtrfile, xtrskip);
		metaset(rname);

		/*
		 * the fchmod(2) has to come after getfile() as some POSIX
		 * implementations clear the S_ISUID and S_ISGID bits of the
		 * file after every write(2).
		 */
		if (fchmod(ofile, mode) < 0 && !complained_chmod) {
			saverr = errno;
			errmsg = gettext(
			    "Unable to restore permissions on %s: %s\n");
			(void) fprintf(stderr, errmsg,
			    rname, strerror(saverr));
			(void) fprintf(stderr, gettext(
			    "Additional such failures will be ignored.\n"));
			complained_chmod = 1;
		}

		/*
		 * Some errors don't get reported until we close(2), so
		 * check for them.
		 * XXX unlink the file if an error is reported?
		 */
		if (close(ofile) < 0) {
			saverr = errno;
			errmsg = gettext("error closing file");
			(void) fprintf(stderr, "%s: ", rname);
			(void) fflush(stderr);
			errno = saverr;
			perror(errmsg);
			result = FAIL;
			break;
		}
		if (utime(rname, (struct utimbuf *)timep) < 0 &&
		    !complained_utime) {
			saverr = errno;
			errmsg = gettext(
			    "Unable to restore times on %s: %s\n");
			(void) fprintf(stderr, errmsg,
			    rname, strerror(saverr));
			(void) fprintf(stderr, gettext(
			    "Additional such failures will be ignored.\n"));
			complained_utime = 1;
		}

		result = GOOD;
		break;
	}
	if (dfd != AT_FDCWD) {
		fchdir(savepwd);
		(void) close(dfd);
	}
	return (result);
}

/*
 * skip over bit maps on the tape
 */
void
skipmaps(void)
{
	continuemap = 1;
	while (checktype(&spcl, TS_CLRI) == GOOD ||
	    checktype(&spcl, TS_BITS) == GOOD)
		skipfile();
	continuemap = 0;
}

/*
 * skip over a file on the tape
 */
void
skipfile(void)
{
	curfile.action = SKIP;
	getfile(null, null);
}
/*
 * Do the file extraction, calling the supplied functions
 * with the blocks
 */
void
getfile(void (*f1)(), void (*f2)())
{
	int i;
	size_t curblk = 0;
	offset_t size = (offset_t)spcl.c_dinode.di_size;
	static char clearedbuf[MAXBSIZE];
	char buf[TP_BSIZE_MAX];
	char *bufptr;
	char junk[TP_BSIZE_MAX];

	assert(MAXBSIZE >= tp_bsize);

	metaset(NULL);	/* flush old metadata */
	if (checktype(&spcl, TS_END) == GOOD) {
		panic(gettext("ran off end of volume\n"));
		return;
	}
	if (ishead(&spcl) == FAIL) {
		panic(gettext("not at beginning of a file\n"));
		return;
	}
	metacheck(&spcl); /* check for metadata in header */
	if (!gettingfile && setjmp(restart) != 0) {
		gettingfile = 0;	/* paranoia; longjmp'er should do */
		return;
	}
	gettingfile++;
loop:
	if ((spcl.c_dinode.di_mode & IFMT) == IFSHAD) {
		f1 = xtrmeta;
		f2 = metaskip;
	}
	for (i = 0, bufptr = buf; i < spcl.c_count; i++) {
		if ((i >= TP_NINDIR) || (spcl.c_addr[i])) {
			readtape(bufptr);
			bufptr += tp_bsize;
			curblk++;
			if (curblk == (fssize / tp_bsize)) {
				(*f1)(buf, size > tp_bsize ?
				    (size_t)(fssize) :
					/* LINTED size <= tp_bsize */
				    (curblk - 1) * tp_bsize + (size_t)size);
				curblk = 0;
				bufptr = buf;
			}
		} else {
			if (curblk > 0) {
				(*f1)(buf, size > tp_bsize ?
				    (size_t)(curblk * tp_bsize) :
					/* LINTED size <= tp_bsize */
				    (curblk - 1) * tp_bsize + (size_t)size);
				curblk = 0;
				bufptr = buf;
			}
			(*f2)(clearedbuf, size > tp_bsize ?
					/* LINTED size <= tp_bsize */
			    (long)tp_bsize : (size_t)size);
		}
		if ((size -= tp_bsize) <= 0) {
			for (i++; i < spcl.c_count; i++)
				if ((i >= TP_NINDIR) || (spcl.c_addr[i]))
					readtape(junk);
			break;
		}
	}
	if (curblk > 0) {
		/*
		 * Ok to cast size to size_t here. The above for loop reads
		 * data into the buffer then writes it to the output file. The
		 * call to f1 here is to write out the data that's in the
		 * buffer that has not yet been written to the file.
		 * This will be less than N-KB of data, since the
		 * above loop writes to the file in filesystem-
		 * blocksize chunks.
		 */
		/* LINTED: size fits into a size_t at this point */
		(*f1)(buf, (curblk * tp_bsize) + (size_t)size);

		curblk = 0;
		bufptr = buf;
	}
	if ((readhdr(&spcl) == GOOD) && (checktype(&spcl, TS_ADDR) == GOOD)) {
		if (continuemap)
			size = (offset_t)spcl.c_count * tp_bsize;
							/* big bitmap */
		else if ((size <= 0) &&
		    ((spcl.c_dinode.di_mode & IFMT) == IFSHAD)) {
			/* LINTED unsigned to signed conversion ok */
			size = spcl.c_dinode.di_size;
		}
		if (size > 0)
			goto loop;
	}
	if (size > 0)
		dprintf(stdout,
		    gettext("Missing address (header) block for %s\n"),
		    curfile.name);
	findinode(&spcl);
	gettingfile = 0;
}

/*
 * The next routines are called during file extraction to
 * put the data into the right form and place.
 */
static void
xtrfile(char *buf, size_t size)
{
	if (write(ofile, buf, (size_t)size) == -1) {
		int saverr = errno;
		(void) fprintf(stderr,
		    gettext("write error extracting inode %d, name %s\n"),
		    curfile.ino, curfile.name);
		errno = saverr;
		perror("write");
		done(1);
	}
}

/*
 * Even though size is a size_t, it's seeking to a relative
 * offset.  Thus, the seek could go beyond 2 GB, so lseek64 is needed.
 */

/*ARGSUSED*/
static void
xtrskip(char *buf, size_t size)
{
	if (lseek64(ofile, (offset_t)size, 1) == -1) {
		int saverr = errno;
		(void) fprintf(stderr,
		    gettext("seek error extracting inode %d, name %s\n"),
		    curfile.ino, curfile.name);
		errno = saverr;
		perror("lseek64");
		done(1);
	}
}

/* these are local to the next five functions */
static char *metadata = NULL;
static size_t metasize = 0;

static void
metacheck(struct s_spcl *head)
{
	if (! (head->c_flags & DR_HASMETA))
		return;
	if ((metadata = malloc(metasize = (size_t)sizeof (head->c_shadow)))
	    == NULL) {
		(void) fprintf(stderr,
		    gettext("Cannot malloc for metadata\n"));
		done(1);
	}
	bcopy(&(head->c_shadow), metadata, metasize);
}

static void
xtrmeta(char *buf, size_t size)
{
	if ((metadata == NULL) && ((spcl.c_dinode.di_mode & IFMT) != IFSHAD))
		return;
	if ((metadata = realloc(metadata, metasize + size)) == NULL) {
		(void) fprintf(stderr,
		    gettext("Cannot malloc for metadata\n"));
		done(1);
	}
	bcopy(buf, metadata + metasize, size);
	metasize += size;
}

/* ARGSUSED */
static void
metaskip(char *buf, size_t size)
{
	if (metadata == NULL)
		return;
	if ((metadata = realloc(metadata, metasize + size)) == NULL) {
		(void) fprintf(stderr,
		    gettext("Cannot malloc for metadata\n"));
		done(1);
	}
	bzero(metadata + metasize, size);
	metasize += size;
}

static void
metaset(char *name)
{
	if (metadata == NULL)
		return;
	if (name != NULL)
		metaproc(name, metadata, metasize);
	(void) free(metadata);
	metadata = NULL;
	metasize = 0;
}

void
metaget(data, size)
	char **data;
	size_t *size;
{
	*data = metadata;
	*size = metasize;
}

static void
fsd_acl(name, aclp, size)
	char *name, *aclp;
	unsigned size;
{
	static aclent_t *aclent = NULL;
	ufs_acl_t *diskacl;
	static int n = 0;
	acl_t *set_aclp;
	uint_t i;
	int saverr, j;

	if (aclp == NULL) {
		if (aclent != NULL)
			free(aclent);
		aclent = NULL;
		n = 0;
		return;
	}

	/*LINTED [aclp is malloc'd]*/
	diskacl = (ufs_acl_t *)aclp;
	/* LINTED: result fits in an int */
	j = size / sizeof (*diskacl);
	normacls(byteorder, diskacl, j);

	i = n;
	n += j;
	aclent = realloc(aclent, n * (size_t)sizeof (*aclent));
	if (aclent == NULL) {
		(void) fprintf(stderr, gettext("Cannot malloc acl list\n"));
		done(1);
	}

	j = 0;
	while (i < n) {
		aclent[i].a_type = diskacl[j].acl_tag;
		aclent[i].a_id = diskacl[j].acl_who;
		aclent[i].a_perm = diskacl[j].acl_perm;
		++i;
		++j;
	}

	set_aclp = acl_to_aclp(ACLENT_T, aclent, n);
	if (set_aclp == NULL) {
		(void) fprintf(stderr, gettext("Cannot build acl_t\n"));
		done(1);
	}

	if (acl_set(name, set_aclp) == -1) {
		static int once = 0;

		/*
		 * Treat some errors from the acl subsystem specially to
		 * avoid being too noisy:
		 *
		 * ENOSYS - ACLs not supported on this file system
		 * EPERM  - not the owner or not privileged
		 *
		 * The following is also supported for backwards compat.
		 * since acl(2) used to return the wrong errno:
		 *
		 * EINVAL - not the owner of the object
		 */
		if (errno == ENOSYS || errno == EPERM || errno == EINVAL) {
			if (once == 0) {
				saverr = errno;
				++once;
				fprintf(stderr,
				    gettext("setacl failed: %s\n"),
				    strerror(saverr));
			}
		} else {
			saverr = errno;
			fprintf(stderr, gettext("setacl on %s failed: %s\n"),
			    name, strerror(saverr));
		}
	}
	acl_free(set_aclp);
}

static struct fsdtypes {
	int type;
	void (*function)();
} fsdtypes[] = {
	{FSD_ACL, fsd_acl},
	{FSD_DFACL, fsd_acl},
	{0, NULL}
};

void
metaproc(char *name, char *mdata, size_t msize)
{
	struct fsdtypes *fsdtype;
	ufs_fsd_t *fsd;
	char *c;

	/*
	 * for the whole shadow inode, dispatch each piece
	 * to the appropriate function.
	 */
	c = mdata;
	/* LINTED (c - mdata) fits into a size_t */
	while ((size_t)(c - mdata) < msize) {
		/*LINTED [mdata is malloc'd]*/
		fsd = (ufs_fsd_t *)c;
		assert((fsd->fsd_size % 4) == 0);
		/* LINTED: lint thinks pointers are signed */
		c += FSD_RECSZ(fsd, fsd->fsd_size);
		if ((fsd->fsd_type == FSD_FREE) ||
		    ((unsigned)(fsd->fsd_size) <= sizeof (ufs_fsd_t)) ||
		    (c > (mdata + msize)))
			break;
		for (fsdtype = fsdtypes; fsdtype->type; fsdtype++)
			if (fsdtype->type == fsd->fsd_type)
				(*fsdtype->function)(name, fsd->fsd_data,
				    (unsigned)(fsd->fsd_size) -
				    sizeof (fsd->fsd_type) -
				    sizeof (fsd->fsd_size));
		/* ^^^ be sure to change if fsd ever changes ^^^ */
	}

	/* reset the state of all the functions */
	for (fsdtype = fsdtypes; fsdtype->type; fsdtype++)
		(*fsdtype->function)(NULL, NULL, 0);
}

static void
xtrlnkfile(char *buf, size_t size)
{
	/* LINTED: signed/unsigned mix ok */
	pathlen += size;
	if (pathlen > MAXPATHLEN) {
		(void) fprintf(stderr,
		    gettext("symbolic link name: %s->%s%s; too long %d\n"),
		    curfile.name, lnkbuf, buf, pathlen);
		done(1);
	}
	buf[size] = '\0';
	(void) strcat(lnkbuf, buf);
	/* add an extra NULL to make this a legal complex string */
	lnkbuf[pathlen+1] = '\0';
}

/*ARGSUSED*/
static void
xtrlnkskip(char *buf, size_t size)
{
	(void) fprintf(stderr,
	    gettext("unallocated block in symbolic link %s\n"),
	    curfile.name);
	done(1);
}

static void
xtrmap(char *buf, size_t size)
{
	if ((map+size) > endmap) {
		int64_t mapsize, increment;
		int64_t diff;

		if (spcl.c_type != TS_ADDR) {
			(void) fprintf(stderr,
			    gettext("xtrmap: current record not TS_ADDR\n"));
			done(1);
		}
		if ((spcl.c_count < 0) || (spcl.c_count > TP_NINDIR)) {
			(void) fprintf(stderr,
			    gettext("xtrmap: illegal c_count field (%d)\n"),
			    spcl.c_count);
			done(1);
		}

		increment = d_howmany(
		    ((spcl.c_count * tp_bsize * NBBY) + 1), NBBY);
		mapsize = endmap - beginmap + increment;
		if (mapsize > UINT_MAX) {
			(void) fprintf(stderr,
			    gettext("xtrmap: maximum bitmap size exceeded"));
			done(1);
		}

		diff = map - beginmap;
		/* LINTED mapsize checked above */
		beginmap = realloc(beginmap, (size_t)mapsize);
		if (beginmap == NULL) {
			(void) fprintf(stderr,
			    gettext("xtrmap: realloc failed\n"));
			done(1);
		}
		map = beginmap + diff;
		endmap = beginmap + mapsize;
		/* LINTED endmap - map cannot exceed 32 bits */
		bzero(map, (size_t)(endmap - map));
		maxino = NBBY * mapsize + 1;
	}

	bcopy(buf, map, size);
	/* LINTED character pointers aren't signed */
	map += size;
}

/*ARGSUSED*/
static void
xtrmapskip(char *buf, size_t size)
{
	(void) fprintf(stderr, gettext("hole in map\n"));
	done(1);
}

/*ARGSUSED*/
void
null(char *buf, size_t size)
{
}

/*
 * Do the tape i/o, dealing with volume changes
 * etc..
 */
static void
readtape(char *b)
{
	int i;
	int rd, newvol;
	int cnt;
	struct s_spcl *sp;
	int32_t	expected_magic;

	if (tbf == NULL) {
		(void) fprintf(stderr, gettext(
		    "Internal consistency failure in readtape: tbf is NULL\n"));
		done(1);
	}
	expected_magic = ((tp_bsize == TP_BSIZE_MIN) ? NFS_MAGIC : MTB_MAGIC);

top:
	if (bct < numtrec) {
		/*
		 * check for old-dump floppy EOM -- it may appear in
		 * the middle of a buffer.  The Dflag used to be used for
		 * this, but since it doesn't hurt to always do this we
		 * got rid of the Dflag.
		 */
		/*LINTED [tbf = malloc()]*/
		sp = &((union u_spcl *)&tbf[bct*tp_bsize])->s_spcl;
		if (sp->c_magic == expected_magic && sp->c_type == TS_EOM &&
		    (time_t)(sp->c_date) == dumpdate &&
		    (time_t)(sp->c_ddate) == dumptime) {
			for (i = 0; i < ntrec; i++)
				/*LINTED [tbf = malloc()]*/
				((struct s_spcl *)
				    &tbf[i*tp_bsize])->c_magic = 0;
			bct = 0;
			rd = 0;
			i = 0;
			goto nextvol;
		}
		bcopy(&tbf[(bct++*tp_bsize)], b, (size_t)tp_bsize);
		blksread++;
		tapea++;
		return;
	}
	/*LINTED [assertion always true]*/
	assert(sizeof (union u_spcl) == TP_BSIZE_MAX);
	for (i = 0; i < ntrec; i++)
		/*LINTED [tbf = malloc()]*/
		((struct s_spcl *)&tbf[i*sizeof (struct s_spcl)])->c_magic = 0;
	if (numtrec == 0) {
		/* LINTED unsigned/signed assignment ok */
		numtrec = ntrec;
	}
	/* LINTED unsigned/signed assignment ok */
	cnt = ntrec*tp_bsize;
	rd = 0;
getmore:
	if (host)
		i = rmtread(&tbf[rd], cnt);
	else
		i = read(mt, &tbf[rd], cnt);
	/*
	 * Check for mid-tape short read error.
	 * If found, return rest of buffer.
	 */
	if (numtrec < ntrec && i != 0) {
		/* LINTED unsigned/signed assignment ok */
		numtrec = ntrec;
		goto top;
	}
	/*
	 * Handle partial block read.
	 */
	if (i > 0 && i != ntrec*tp_bsize) {
		if (pipein) {
			rd += i;
			cnt -= i;
			if (cnt > 0)
				goto getmore;
			i = rd;
		} else {
			if (i % tp_bsize != 0)
				panic(gettext(
				    "partial block read: %d should be %d\n"),
				    i, ntrec * tp_bsize);
			numtrec = i / tp_bsize;
			if (numtrec == 0)
				/*
				 * it's possible to read only 512 bytes
				 * from a QIC device...
				 */
				i = 0;
		}
	}
	/*
	 * Handle read error.
	 */
	if (i < 0) {
		switch (curfile.action) {
		default:
			(void) fprintf(stderr, gettext(
			    "Read error while trying to set up volume\n"));
			break;
		case UNKNOWN:
			(void) fprintf(stderr, gettext(
			    "Read error while trying to resynchronize\n"));
			break;
		case USING:
			(void) fprintf(stderr, gettext(
			    "Read error while restoring %s\n"),
			    curfile.name);
			break;
		case SKIP:
			(void) fprintf(stderr, gettext(
			    "Read error while skipping over inode %d\n"),
			    curfile.ino);
			break;
		}
		if (!yflag && !reply(gettext("continue")))
			done(1);
		/* LINTED: unsigned->signed conversion ok */
		i = (int)(ntrec*tp_bsize);
		bzero(tbf, (size_t)i);
		if ((host != 0 && rmtseek(i, 1) < 0) ||
		    (host == 0 && (lseek64(mt, (offset_t)i, 1) ==
		    (off64_t)-1))) {
			perror(gettext("continuation failed"));
			done(1);
		}
	}
	/*
	 * Handle end of tape.  The Dflag used to be used, but since it doesn't
	 * hurt to always check we got rid if it.
	 */

	/*
	 * if the first record in the buffer just read is EOM,
	 * change volumes.
	 */
	/*LINTED [tbf = malloc()]*/
	sp = &((union u_spcl *)tbf)->s_spcl;
	if (i != 0 && sp->c_magic == expected_magic && sp->c_type == TS_EOM &&
	    (time_t)(sp->c_date) == dumpdate &&
	    (time_t)(sp->c_ddate) == dumptime) {
		i = 0;
	}
nextvol:
	if (i == 0) {
		if (!pipein) {
			newvol = volno + 1;
			volno = 0;
			numtrec = 0;
			getvol(newvol);
			readtape(b); /* XXX tail recursion, not goto top? */
			return;
		}
		/* XXX if panic returns, should we round rd up? */
		/* XXX if we do, then we should zero the intervening space */
		if (rd % tp_bsize != 0)
			panic(gettext("partial block read: %d should be %d\n"),
			    rd, ntrec * tp_bsize);
		bcopy((char *)&endoftapemark, &tbf[rd], (size_t)tp_bsize);
	}
	bct = 0;
	bcopy(&tbf[(bct++*tp_bsize)], b, (size_t)tp_bsize);
	blksread++;
	recsread++;
	tapea++;
	rec_position++;
}

void
findtapeblksize(int arfile)
{
	int	i;

	if (tbf == NULL) {
		(void) fprintf(stderr, gettext(
		    "Internal consistency failure in findtapeblksize: "
		    "tbf is NULL\n"));
		assert(tbf != NULL);
		done(1);
	}

	for (i = 0; i < ntrec; i++)
		/*LINTED [tbf = malloc()]*/
		((struct s_spcl *)&tbf[i * tp_bsize])->c_magic = 0;
	bct = 0;
	if (host && arfile == TAPE_FILE)
		tape_rec_size = rmtread(tbf, ntrec * tp_bsize);
	else
		tape_rec_size = read(mt, tbf, ntrec * tp_bsize);
	recsread++;
	rec_position++;
	if (tape_rec_size == (ssize_t)-1) {
		int saverr = errno;
		char *errmsg = gettext("Media read error");
		errno = saverr;
		perror(errmsg);
		done(1);
	}
	if (tape_rec_size % tp_bsize != 0) {
		(void) fprintf(stderr, gettext(
	    "Record size (%d) is not a multiple of dump block size (%d)\n"),
		    tape_rec_size, tp_bsize);
		done(1);
	}
	ntrec = (int)tape_rec_size / tp_bsize;
	/* LINTED unsigned/signed assignment ok */
	numtrec = ntrec;
	vprintf(stdout, gettext("Media block size is %d\n"), ntrec*2);
}

void
flsht(void)
{
	/* LINTED unsigned/signed assignment ok */
	bct = ntrec+1;
}

void
closemt(int mode)
{
	/*
	 * If mode == FORCE_OFFLINE then we're not done but
	 * we need to change tape. So, rewind and unload current
	 * tape before loading the new one.
	 */

	static struct mtop mtop = { MTOFFL, 0 };

	if (mt < 0)
		return;
	if (offline || mode == FORCE_OFFLINE)
		(void) fprintf(stderr, gettext("Rewinding tape\n"));
	if (host) {
		if (offline || mode == FORCE_OFFLINE)
			(void) rmtioctl(MTOFFL, 1);
		rmtclose();
	} else if (pipein) {
		char buffy[MAXBSIZE];

		while (read(mt, buffy, sizeof (buffy)) > 0) {
			continue;
			/*LINTED [assertion always true]*/
		}
		(void) close(mt);
	} else {
		/*
		 * Only way to tell if this is a floppy is to issue an ioctl
		 * but why waste one - if the eject fails, tough!
		 */
		if (offline || mode == FORCE_OFFLINE)
			(void) ioctl(mt, MTIOCTOP, &mtop);
		(void) ioctl(mt, FDEJECT, 0);
		(void) close(mt);
	}
	mt = -1;
}

static int
checkvol(struct s_spcl *b, int t)
{

	if (b->c_volume != t)
		return (FAIL);
	return (GOOD);
}

int
readhdr(struct s_spcl *b)
{

	if (gethead(b) == FAIL) {
		dprintf(stdout, gettext("readhdr fails at %ld blocks\n"),
		    blksread);
		return (FAIL);
	}
	return (GOOD);
}

/*
 * read the tape into buf, then return whether or
 * or not it is a header block.
 */
int
gethead(struct s_spcl *buf)
{
	int i;
	union u_ospcl {
		char dummy[TP_BSIZE_MIN];
		struct	s_ospcl {
			int32_t	c_type;
			int32_t	c_date;
			int32_t	c_ddate;
			int32_t	c_volume;
			int32_t	c_tapea;
			ushort_t c_inumber;
			int32_t	c_magic;
			int32_t	c_checksum;
			struct odinode {
				unsigned short odi_mode;
				ushort_t odi_nlink;
				ushort_t odi_uid;
				ushort_t odi_gid;
				int32_t	odi_size;
				int32_t	odi_rdev;
				char	odi_addr[36];
				int32_t	odi_atime;
				int32_t	odi_mtime;
				int32_t	odi_ctime;
			} c_dinode;
			int32_t	c_count;
			char	c_baddr[256];
		} s_ospcl;
	} u_ospcl;

	if (cvtflag) {
		readtape((char *)(&u_ospcl.s_ospcl));
		bzero((char *)buf, (size_t)TP_BSIZE_MIN);
		buf->c_type = u_ospcl.s_ospcl.c_type;
		buf->c_date = u_ospcl.s_ospcl.c_date;
		buf->c_ddate = u_ospcl.s_ospcl.c_ddate;
		buf->c_volume = u_ospcl.s_ospcl.c_volume;
		buf->c_tapea = u_ospcl.s_ospcl.c_tapea;
		buf->c_inumber = u_ospcl.s_ospcl.c_inumber;
		buf->c_checksum = u_ospcl.s_ospcl.c_checksum;
		buf->c_magic = u_ospcl.s_ospcl.c_magic;
		buf->c_dinode.di_mode = u_ospcl.s_ospcl.c_dinode.odi_mode;
		/* LINTED: unsigned/signed combination ok */
		buf->c_dinode.di_nlink = u_ospcl.s_ospcl.c_dinode.odi_nlink;
		buf->c_dinode.di_size =
		    (unsigned)(u_ospcl.s_ospcl.c_dinode.odi_size);
		buf->c_dinode.di_uid = u_ospcl.s_ospcl.c_dinode.odi_uid;
		buf->c_dinode.di_gid = u_ospcl.s_ospcl.c_dinode.odi_gid;
		buf->c_dinode.di_suid = UID_LONG;
		buf->c_dinode.di_sgid = GID_LONG;
		buf->c_dinode.di_ordev = u_ospcl.s_ospcl.c_dinode.odi_rdev;
		buf->c_dinode.di_atime = u_ospcl.s_ospcl.c_dinode.odi_atime;
		buf->c_dinode.di_mtime = u_ospcl.s_ospcl.c_dinode.odi_mtime;
		buf->c_dinode.di_ctime = u_ospcl.s_ospcl.c_dinode.odi_ctime;
		buf->c_count = u_ospcl.s_ospcl.c_count;
		bcopy(u_ospcl.s_ospcl.c_baddr, buf->c_addr,
		    sizeof (u_ospcl.s_ospcl.c_baddr));

		/*CONSTANTCONDITION*/
		assert(sizeof (u_ospcl.s_ospcl) < sizeof (union u_spcl));

		/* we byte-swap the new spclrec, but checksum the old	*/
		/* (see comments in normspcl())				*/
		if (normspcl(byteorder, buf,
		    (int *)(&u_ospcl.s_ospcl), sizeof (u_ospcl.s_ospcl),
		    OFS_MAGIC))
			return (FAIL);
		buf->c_magic =
		    ((tp_bsize == TP_BSIZE_MIN) ? NFS_MAGIC : MTB_MAGIC);
	} else {
		readtape((char *)buf);
		if (normspcl(byteorder, buf, (int *)buf, tp_bsize,
		    ((tp_bsize == TP_BSIZE_MIN) ? NFS_MAGIC : MTB_MAGIC)))
			return (FAIL);
	}

	switch (buf->c_type) {

	case TS_CLRI:
	case TS_BITS:
		/*
		 * Have to patch up missing information in bit map headers
		 */
		buf->c_inumber = 0;
		buf->c_dinode.di_size = (offset_t)buf->c_count * tp_bsize;
		for (i = 0; i < buf->c_count && i < TP_NINDIR; i++)
			buf->c_addr[i] = 1;
		break;

	case TS_TAPE:
	case TS_END:
		if (dumpinfo.c_date == 0) {
			dumpinfo.c_date = spcl.c_date;
			dumpinfo.c_ddate = spcl.c_ddate;
		}
		if (!hostinfo && spcl.c_host[0] != '\0') {
			bcopy(spcl.c_label, dumpinfo.c_label,
			    sizeof (spcl.c_label));
			bcopy(spcl.c_filesys, dumpinfo.c_filesys,
			    sizeof (spcl.c_filesys));
			bcopy(spcl.c_dev, dumpinfo.c_dev,
			    sizeof (spcl.c_dev));
			bcopy(spcl.c_host, dumpinfo.c_host,
			    sizeof (spcl.c_host));
			dumpinfo.c_level = spcl.c_level;
			hostinfo++;
			if (c_label != NULL &&
			    strncmp(c_label, spcl.c_label,
			    sizeof (spcl.c_label))
			    != 0) {
				(void) fprintf(stderr, gettext(
		    "Incorrect tape label.  Expected `%s', got `%.*s'\n"),
				    c_label,
				    sizeof (spcl.c_label), spcl.c_label);
				done(1);
			}
		}
		if (!inodeinfo && (spcl.c_flags & DR_INODEINFO)) {
			dumpinfo.c_volume = spcl.c_volume;
			bcopy(spcl.c_inos, dumpinfo.c_inos,
			    sizeof (spcl.c_inos));
			inodeinfo++;
		}
		buf->c_inumber = 0;
		break;

	case TS_INODE:
	case TS_ADDR:
		break;

	default:
		panic(gettext("%s: unknown inode type %d\n"),
		    "gethead", buf->c_type);
		return (FAIL);
	}
	if (dflag)
		accthdr(buf);
	return (GOOD);
}

/*
 * Check that a header is where it belongs and predict the next header
 */
static void
accthdr(struct s_spcl *header)
{
	static ino_t previno = (ino_t)(unsigned)-1;
	static int prevtype;
	static long predict;
	int blks, i;

	if (header->c_type == TS_TAPE) {
		if (header->c_firstrec)
			(void) fprintf(stderr,
			    gettext("Volume header begins with record %d"),
			    header->c_firstrec);
		else
			(void) fprintf(stderr, gettext("Volume header"));
		(void) fprintf(stderr, "\n");
		previno = (ino_t)(unsigned)-1;
		return;
	}
	if (previno == (ino_t)(unsigned)-1)
		goto newcalc;
	switch (prevtype) {
	case TS_BITS:
		(void) fprintf(stderr, gettext("Dump mask header"));
		break;
	case TS_CLRI:
		(void) fprintf(stderr, gettext("Remove mask header"));
		break;
	case TS_INODE:
		(void) fprintf(stderr,
		    gettext("File header, ino %d at record %d"),
		    previno, rec_position);
		break;
	case TS_ADDR:
		(void) fprintf(stderr,
		    gettext("File continuation header, ino %d"),
		    previno);
		break;
	case TS_END:
		(void) fprintf(stderr, gettext("End of media header"));
		break;
	}
	if (predict != blksread - 1)
		(void) fprintf(stderr,
		    gettext("; predicted %ld blocks, got %ld blocks"),
		    predict, blksread - 1);
	(void) fprintf(stderr, "\n");
newcalc:
	blks = 0;
	if (header->c_type != TS_END)
		for (i = 0; i < header->c_count; i++)
			if ((i >= TP_NINDIR) || (header->c_addr[i] != 0))
				blks++;
	predict = blks;
	blksread = 0;
	prevtype = header->c_type;
	previno = header->c_inumber;
}

/*
 * Try to determine which volume a file resides on.
 */
int
volnumber(ino_t inum)
{
	int i;

	if (inodeinfo == 0)
		return (0);
	for (i = 1; i <= dumpinfo.c_volume; i++)
		if (inum < (ino_t)(unsigned)(dumpinfo.c_inos[i]))
			break;
	return (i - 1);
}

/*
 * Find an inode header.
 * Note that *header must be stable storage, as curfile will end up with
 * pointers into it.
 */
void
findinode(struct s_spcl *header)
{
	long skipcnt = 0;
	int i;
	char buf[TP_BSIZE_MAX];

	curfile.name = gettext("<name unknown>");
	curfile.action = UNKNOWN;
	curfile.dip = (struct dinode *)NULL;
	curfile.ino = 0;
	curfile.ts = 0;
	if (ishead(header) == FAIL) {
		skipcnt++;
		while (gethead(header) == FAIL ||
		    (time_t)(header->c_date) != dumpdate)
			skipcnt++;
	}
	for (;;) {
		if (checktype(header, TS_ADDR) == GOOD) {
			/*
			 * Skip up to the beginning of the next record
			 */
			for (i = 0; i < header->c_count; i++)
				if ((i >= TP_NINDIR) || (header->c_addr[i]))
					readtape(buf);
			(void) gethead(header);
			continue;
		}
		if (checktype(header, TS_INODE) == GOOD) {
			curfile.dip = &header->c_dinode;
			if (curfile.dip->di_suid != UID_LONG)
				curfile.dip->di_uid = curfile.dip->di_suid;
			if (curfile.dip->di_sgid != GID_LONG)
				curfile.dip->di_gid = curfile.dip->di_sgid;
			curfile.ino = header->c_inumber;
			curfile.ts = TS_INODE;
			break;
		}
		if (checktype(header, TS_END) == GOOD) {
			curfile.ino = maxino;
			curfile.ts = TS_END;
			break;
		}
		if (checktype(header, TS_CLRI) == GOOD) {
			curfile.name = gettext("<file removal list>");
			curfile.ts = TS_CLRI;
			break;
		}
		if (checktype(header, TS_BITS) == GOOD) {
			curfile.name = gettext("<file dump list>");
			curfile.ts = TS_BITS;
			break;
		}
		while (gethead(header) == FAIL)
			skipcnt++;
	}
	if (skipcnt > 0)
		(void) fprintf(stderr,
		    gettext("resync restore, skipped %d blocks\n"),
		    skipcnt);
}

/*
 * return whether or not the buffer contains a header block
 */
static int
ishead(struct s_spcl *buf)
{
	if (buf->c_magic !=
	    ((tp_bsize == TP_BSIZE_MIN) ? NFS_MAGIC : MTB_MAGIC))
		return (FAIL);
	return (GOOD);
}

static int
checktype(struct s_spcl *b, int t)
{
	if (b->c_type != t)
		return (FAIL);
	return (GOOD);
}

/*
 * If autoloading is enabled, attempt to do it.  If we succeed,
 * return non-zero.
 */
static int
autoload_tape(void)
{
	int result = 0;		/* assume failure */
	int tries;
	int fd;

	if (autoload) {
		/*
		 * Wait for the tape to autoload.  Note that the delay
		 * period doesn't take into account however long it takes
		 * for the open to fail (measured at 21 seconds for an
		 * Exabyte 8200 under 2.7 on an Ultra 2).
		 */

		/* rewind tape and offline drive before loading new tape */
		closemt(FORCE_OFFLINE);
		(void) fprintf(stderr,
		    gettext("Attempting to autoload next volume\n"));
		for (tries = 0; tries < autoload_tries; tries++) {
			if (host) {
				if (rmtopen(magtape, O_RDONLY) >= 0) {
					rmtclose();
					result = 1;
					break;
				}
			} else {
				if ((fd = open(magtape, O_RDONLY|O_LARGEFILE,
				    0600)) >= 0) {
					(void) close(fd);
					result = 1;
					break;
				}
			}
			(void) sleep(autoload_period);
		}
		if (result == 0) {
			/* Assume caller will deal with manual change-over */
			(void) fprintf(stderr,
			    gettext("Autoload timed out\n"));
		} else {
			if ((host != NULL &&
			    (mt = rmtopen(magtape, O_RDONLY)) == -1) ||
			    (host == NULL &&
			    (mt = open(magtape, O_RDONLY|O_LARGEFILE)) == -1)) {
				(void) fprintf(stderr, gettext(
				    "Autoload could not re-open tape\n"));
				result = 0;
			} else {
				(void) fprintf(stderr, gettext(
				    "Tape loaded\n"));
			}
		}
	}

	return (result);
}
