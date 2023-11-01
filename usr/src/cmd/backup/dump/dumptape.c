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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#include "dump.h"
#include <rmt.h>
#include <setjmp.h>
#include <sys/fdio.h>
#include <sys/mkdev.h>
#include <assert.h>
#include <limits.h>

#define	SLEEPMS		50

int newtape;
static uint_t writesize;	/* size of malloc()ed buffer for tape */
static ino_t inos[TP_NINOS];	/* starting inodes on each tape */

/*
 * The req structure is used to pass commands from the parent
 * process through the pipes to the slave processes.  It comes
 * in two flavors, depending on which mode dump is operating under:
 * an inode request (on-line mode) and a disk block request ("old" mode).
 */
/*
 * The inode request structure is used during on-line mode.
 * The master passes inode numbers and starting offsets to
 * the slaves.  The tape writer passes out the current inode,
 * offset, and number of tape records written after completing a volume.
 */
struct ireq {
	ino_t	inumber;	/* inode number to open/dump */
	long	igen;		/* inode generation number */
	off_t	offset;		/* starting offset in inode */
	int	count;		/* count for 1st spclrec */
};
/*
 * The block request structure is used in off-line mode to pass
 * commands to dump disk blocks from the parent process through
 * the pipes to the slave processes.
 */
struct breq {
	diskaddr_t dblk;		/* disk address to read */
	size_t	size;		/* number of bytes to read from disk */
	ulong_t	spclrec[1];	/* actually longer */
};

struct req {
	short	aflag;		/* write data to archive process as well */
	short	tflag;		/* begin new tape */
	union	reqdata {
		struct ireq ino;	/* used for on-line mode */
		struct breq blks;	/* used for off-line mode */
	} data;
};

#define	ir_inumber	data.ino.inumber
#define	ir_igen		data.ino.igen
#define	ir_offset	data.ino.offset
#define	ir_count	data.ino.count

#define	br_dblk		data.blks.dblk
#define	br_size		data.blks.size
#define	br_spcl		data.blks.spclrec

static int reqsiz = 0;	/* alloctape will initialize */

#define	SLAVES 3
struct slaves {
	int	sl_slavefd;	/* pipe from master to slave */
	pid_t	sl_slavepid;	/* slave pid; used by killall() */
	ino_t	sl_inos;	/* inos, if this record starts tape */
	int	sl_offset;	/* logical blocks written for object */
	int	sl_count;	/* logical blocks left in spclrec */
	int	sl_tapea;	/* header number, if starting tape */
	int	sl_firstrec;	/* number of first block on tape */
	int	sl_state;	/* dump output state */
	struct	req *sl_req;	/* instruction packet to slave */
};
static struct slaves slaves[SLAVES];	/* one per slave */
static struct slaves *slp;	/* pointer to current slave */
static struct slaves chkpt;	/* checkpointed data */

struct bdesc {
	char	*b_data;	/* pointer to buffer data */
	int	b_flags;	/* flags (see below) */
};

/*
 * The following variables are in shared memory, and must be
 * explicitly checkpointed and/or reset.
 */
static caddr_t shared;		/* pointer to block of shared memory */
static struct bdesc *bufp;	/* buffer descriptors */
static struct bdesc **current;	/* output buffer to fill */
static int *tapea;		/* logical record count */

#ifdef INSTRUMENT
static int	*readmissp;	/* number of times writer was idle */
static int	*idle;		/* number of times slaves were idle */
#endif	/* INSTRUMENT */

/*
 * Buffer flags
 */
#define	BUF_EMPTY	0x0	/* nothing in buffer */
#define	BUF_FULL	0x1	/* data in buffer */
#define	BUF_SPCLREC	0x2	/* contains special record */
#define	BUF_ARCHIVE	0x4	/* dump to archive */

static int recsout;		/* number of req's sent to slaves */
static int totalrecsout;	/* total number of req's sent to slaves */
static int rotor;		/* next slave to be instructed */
static pid_t master;		/* pid of master, for sending error signals */
static int writer = -1;		/* fd of tape writer */
static pid_t writepid;		/* pid of tape writer */
static int arch;		/* fd of output archiver */
static pid_t archivepid;	/* pid of output archiver */
static int archivefd;		/* fd of archive file (proper) */
static offset_t lf_archoffset;	/* checkpointed offset into archive file */

int caught;			/* caught signal -- imported by mapfile() */

#ifdef DEBUG
extern	int xflag;
#endif

static void cmdwrterr(void);
static void cmdrderr(void);
static void freetape(void);
static void bufclear(void);
static pid_t setuparchive(void);
static pid_t setupwriter(void);
static void nextslave(void);
static void tperror(int);
static void rollforward(int);
static void nap(int);
static void alrm(int);
static void just_rewind(void);
static void killall(void);
static void proceed(int);
static void die(int);
static void enslave(void);
static void wait_our_turn(void);
static void dumpoffline(int, pid_t, int);
static void onxfsz(int);
static void dowrite(int);
static void checkpoint(struct bdesc *, int);
static ssize_t atomic(int (*)(), int, char *, int);

static size_t tapesize;

/*
 * Allocate buffers and shared memory variables.  Tape buffers are
 * allocated on page boundaries for tape write() efficiency.
 */
void
alloctape(void)
{
	struct slaves *slavep;
	ulong_t pgoff = (unsigned)(getpagesize() - 1); /* 2**n - 1 */
	int	mapfd;
	char	*obuf;
	int	saverr;
	int	i, j;

	writesize = ntrec * tp_bsize;
	if (!printsize)
		msg(gettext("Writing %d Kilobyte records\n"),
		    writesize / TP_BSIZE_MIN);

	/*
	 * set up shared memory seg for here and child
	 */
	mapfd = open("/dev/zero", O_RDWR);
	if (mapfd == -1) {
		saverr = errno;
		msg(gettext("Cannot open `%s': %s\n"),
		    "/dev/zero", strerror(saverr));
		dumpabort();
		/*NOTREACHED*/
	}
	/*
	 * Allocate space such that buffers are page-aligned and
	 * pointers are aligned on 4-byte boundaries (for SPARC).
	 * This code assumes that (NBUF * writesize) is a multiple
	 * of the page size and that pages are aligned on 4-byte
	 * boundaries.  Space is allocated as follows:
	 *
	 *    (NBUF * writesize) for the actual buffers
	 *    (pagesize - 1) for padding so the buffers are page-aligned
	 *    (NBUF * ntrec * sizeof (struct bdesc)) for each buffer
	 *    (n * sizeof (int)) for [n] debugging variables/pointers
	 *    (n * sizeof (int)) for [n] miscellaneous variables/pointers
	 */
	tapesize =
	    (NBUF * writesize)				/* output buffers */
		/* LINTED: pgoff fits into a size_t */
	    + (size_t)pgoff				/* page alignment */
							/* buffer descriptors */
	    + (((size_t)sizeof (struct bdesc)) * NBUF * ntrec)
#ifdef INSTRUMENT
	    + (2 * (size_t)sizeof (int *))		/* instrumentation */
#endif
							/* shared variables */
	    + (size_t)sizeof (struct bdesc **)
	    + (size_t)sizeof (int *)
	    + (3 * (size_t)sizeof (time_t));

	shared = mmap((char *)0, tapesize, PROT_READ|PROT_WRITE,
	    MAP_SHARED, mapfd, (off_t)0);
	if (shared == (caddr_t)-1) {
		saverr = errno;
		msg(gettext("Cannot memory map output buffers: %s\n"),
		    strerror(saverr));
		dumpabort();
		/*NOTREACHED*/
	}
	(void) close(mapfd);

	/*
	 * Buffers and buffer headers
	 */
	obuf = (char *)(((ulong_t)shared + pgoff) & ~pgoff);
	/* LINTED obuf and writesize are aligned */
	bufp = (struct bdesc *)(obuf + NBUF*writesize);
	/*
	 * Shared memory variables
	 */
	current = (struct bdesc **)&bufp[NBUF*ntrec];
	tapea = (int *)(current + 1);
	/* LINTED pointer alignment ok */
	telapsed = (time_t *)(tapea + 1);
	tstart_writing = telapsed + 1;
	tschedule = tstart_writing + 1;
#ifdef INSTRUMENT
	/*
	 * Debugging and instrumentation variables
	 */
	readmissp = (int *)(tschedule + 1);
	idle = readmissp + 1;
#endif
	for (i = 0, j = 0; i < NBUF * ntrec; i++, j += tp_bsize) {
		bufp[i].b_data = &obuf[j];
	}

	reqsiz = sizeof (struct req) + tp_bsize - sizeof (long);
	for (slavep = slaves; slavep < &slaves[SLAVES]; slavep++)
		slavep->sl_req = (struct req *)xmalloc(reqsiz);

	chkpt.sl_offset = 0;		/* start at offset 0 */
	chkpt.sl_count = 0;
	chkpt.sl_inos = UFSROOTINO;	/* in root inode */
	chkpt.sl_firstrec = 1;
	chkpt.sl_tapea = 0;
}

static void
freetape(void)
{
	if (shared == NULL)
		return;
	(void) timeclock((time_t)0);
	(void) munmap(shared, tapesize);
	shared = NULL;
}

/*
 * Reset tape state variables -- called
 * before a pass to dump active files.
 */
void
reset(void)
{
	bufclear();

#ifdef INSTRUMENT
	(*readmissp) = 0;
	(*idle) = 0;
#endif

	spcl.c_flags = 0;
	spcl.c_volume = 0;
	tapeno = 0;

	chkpt.sl_offset = 0;		/* start at offset 0 */
	chkpt.sl_count = 0;
	chkpt.sl_inos = UFSROOTINO;	/* in root inode */
	chkpt.sl_firstrec = 1;
	chkpt.sl_tapea = 0;
}

static void
bufclear(void)
{
	struct bdesc *bp;
	int i;

	for (i = 0, bp = bufp; i < NBUF * ntrec; i++, bp++)
		bp->b_flags = BUF_EMPTY;
	if ((caddr_t)current < shared ||
	    (caddr_t)current > (shared + tapesize)) {
		msg(gettext(
	    "bufclear: current pointer out of range of shared memory\n"));
		dumpabort();
		/*NOTREACHED*/
	}
	if ((*current != NULL) &&
	    (*current < &bufp[0] || *current > &bufp[NBUF*ntrec])) {
		/* ANSI string catenation, to shut cstyle up */
		msg(gettext("bufclear: current buffer pointer (0x%x) "
		    "out of range of buffer\naddresses (0x%x - 0x%x)\n"),
		    *current, &bufp[0], &bufp[NBUF*ntrec]);
		dumpabort();
		/*NOTREACHED*/
	}
	*current = bufp;
}

/*
 * Start a process to collect information describing the dump.
 * This data takes two forms:
 *    the bitmap and directory information being written to
 *	the front of the tape (the "archive" file)
 *    information describing each directory and inode (to
 *	be included in the database tmp file)
 * Write the data to the files as it is received so huge file
 * systems don't cause dump to consume large amounts of memory.
 */
static pid_t
setuparchive(void)
{
	struct slaves *slavep;
	int cmd[2];
	pid_t pid;
	ssize_t size;
	char *data;
	char *errmsg;
	int flags, saverr;
	int punt = 0;

	/*
	 * Both the archive and database tmp files are
	 * checkpointed by taking their current offsets
	 * (sizes) after completing each volume.  Restoring
	 * from a checkpoint involves truncating to the
	 * checkpointed size.
	 */
	if (archive && !doingactive) {
		/* It's allowed/expected to exist, so can't use O_EXCL */
		archivefd = safe_file_open(archivefile, O_WRONLY, 0600);
		if (archivefd < 0) {
			saverr = errno;
			msg(gettext("Cannot open archive file `%s': %s\n"),
			    archivefile, strerror(saverr));
			dumpabort();
			/*NOTREACHED*/
		}

		archive_opened = 1;

		if (lseek64(archivefd, lf_archoffset, 0) < 0) {
			saverr = errno;
			msg(gettext(
			    "Cannot position archive file `%s' : %s\n"),
			    archivefile, strerror(saverr));
			dumpabort();
			/*NOTREACHED*/
		}
		if (ftruncate64(archivefd, lf_archoffset) < 0) {
			saverr = errno;
			msg(gettext(
			    "Cannot truncate archive file `%s' : %s\n"),
			    archivefile, strerror(saverr));
			dumpabort();
			/*NOTREACHED*/
		}
	}

	if (pipe(cmd) < 0) {
		saverr = errno;
		msg(gettext("%s: %s error: %s\n"),
		    "setuparchive", "pipe", strerror(saverr));
		return (0);
	}
	sighold(SIGINT);
	if ((pid = fork()) < 0) {
		saverr = errno;
		msg(gettext("%s: %s error: %s\n"),
		    "setuparchive", "fork", strerror(saverr));
		return (0);
	}
	if (pid > 0) {
		sigrelse(SIGINT);
		/* parent process */
		(void) close(cmd[0]);
		arch = cmd[1];
		return (pid);
	}
	/*
	 * child process
	 */
	(void) signal(SIGINT, SIG_IGN);		/* master handles this */
#ifdef TDEBUG
	(void) sleep(4);	/* allow time for parent's message to get out */
	/* XGETTEXT:  #ifdef TDEBUG only */
	msg(gettext("Archiver has pid = %ld\n"), (long)getpid());
#endif
	freeino();	/* release unneeded resources */
	freetape();
	for (slavep = &slaves[0]; slavep < &slaves[SLAVES]; slavep++) {
		if (slavep->sl_slavefd != -1) {
			(void) close(slavep->sl_slavefd);
			slavep->sl_slavefd = -1;
		}
	}
	(void) close(to);
	(void) close(fi);
	to = fi = -1;
	(void) close(cmd[1]);
	data = xmalloc(tp_bsize);
	for (;;) {
		size = atomic((int(*)())read, cmd[0], (char *)&flags,
		    sizeof (flags));
		if ((unsigned)size != sizeof (flags))
			break;
		size = atomic((int(*)())read, cmd[0], data, tp_bsize);
		if (size == tp_bsize) {
			if (archive && flags & BUF_ARCHIVE && !punt &&
			    (size = write(archivefd, data, tp_bsize))
			    != tp_bsize) {
				struct stat64 stats;

				if (size != -1) {
					errmsg = strdup(gettext(
					    "Output truncated"));
					if (errmsg == NULL)
						errmsg = "";
				} else {
					errmsg = strerror(errno);
				}

				if (fstat64(archivefd, &stats) < 0)
					stats.st_size = -1;

				/* cast to keep lint&printf happy */
				msg(gettext(
		    "Cannot write archive file `%s' at offset %lld: %s\n"),
				    archivefile, (longlong_t)stats.st_size,
				    errmsg);
				msg(gettext(
		    "Archive file will be deleted, dump will continue\n"));
				punt++;
				if ((size != -1) && (*errmsg != '\0')) {
					free(errmsg);
				}
			}
		} else {
			break;
		}
	}
	(void) close(cmd[0]);
	if (archive) {
		(void) close(archivefd);
		archivefd = -1;
	}
	if (punt) {
		(void) unlink(archivefile);
		Exit(X_ABORT);
	}
	Exit(X_FINOK);
	/* NOTREACHED */
	return (0);
}

/*
 * Start a process to read the output buffers and write the data
 * to the output device.
 */
static pid_t
setupwriter(void)
{
	struct slaves *slavep;
	int cmd[2];
	pid_t pid;
	int saverr;

	caught = 0;
	if (pipe(cmd) < 0) {
		saverr = errno;
		msg(gettext("%s: %s error: %s\n"),
		    "setupwriter", "pipe", strerror(saverr));
		return (0);
	}
	sighold(SIGINT);
	if ((pid = fork()) < 0) {
		saverr = errno;
		msg(gettext("%s: %s error: %s\n"),
		    "setupwriter", "fork", strerror(saverr));
		return (0);
	}
	if (pid > 0) {
		/*
		 * Parent process
		 */
		sigrelse(SIGINT);
		(void) close(cmd[0]);
		writer = cmd[1];
		return (pid);
	}
	/*
	 * Child (writer) process
	 */
	(void) signal(SIGINT, SIG_IGN);		/* master handles this */
#ifdef TDEBUG
	(void) sleep(4);	/* allow time for parent's message to get out */
	/* XGETTEXT:  #ifdef TDEBUG only */
	msg(gettext("Writer has pid = %ld\n"), (long)getpid());
#endif
	child_chdir();
	freeino();	/* release unneeded resources */
	for (slavep = &slaves[0]; slavep < &slaves[SLAVES]; slavep++) {
		if (slavep->sl_slavefd != -1) {
			(void) close(slavep->sl_slavefd);
			slavep->sl_slavefd = -1;
		}
	}
	(void) close(fi);
	fi = -1;
	(void) close(cmd[1]);
	dowrite(cmd[0]);
	if (arch >= 0) {
		(void) close(arch);
		arch = -1;
	}
	(void) close(cmd[0]);
	Exit(X_FINOK);
	/* NOTREACHED */
	return (0);
}

void
spclrec(void)
{
	int s, i;
	int32_t *ip;
	int flags = BUF_SPCLREC;

	if ((BIT(ino, shamap)) && (spcl.c_type == TS_INODE)) {
		spcl.c_type = TS_ADDR;
		/* LINTED: result fits in a short */
		spcl.c_dinode.di_mode &= ~S_IFMT;
		/* LINTED: result fits in a short */
		spcl.c_dinode.di_mode |= IFSHAD;
	}

	/*
	 * Only TS_INODEs should have short metadata, if this
	 * isn't such a spclrec, clear the metadata flag and
	 * the c_shadow contents.
	 */
	if (!(spcl.c_type == TS_INODE && (spcl.c_flags & DR_HASMETA))) {
		spcl.c_flags &= ~DR_HASMETA;
		bcopy(c_shadow_save, &(spcl.c_shadow),
		    sizeof (spcl.c_shadow));
	}

	if (spcl.c_type == TS_END) {
		spcl.c_count = 1;
		spcl.c_flags |= DR_INODEINFO;
		bcopy((char *)inos, (char *)spcl.c_inos, sizeof (inos));
	} else if (spcl.c_type == TS_TAPE) {
		spcl.c_flags |= DR_NEWHEADER;
		if (doingactive)
			spcl.c_flags |= DR_REDUMP;
	} else if (spcl.c_type != TS_INODE)
		flags = BUF_SPCLREC;
	spcl.c_tapea = *tapea;
	/* LINTED for now, max inode # is 2**31 (ufs max size is 4TB) */
	spcl.c_inumber = (ino32_t)ino;
	spcl.c_magic = (tp_bsize == TP_BSIZE_MIN) ? NFS_MAGIC : MTB_MAGIC;
	spcl.c_checksum = 0;
	ip = (int32_t *)&spcl;
	s = CHECKSUM;
	assert((tp_bsize % sizeof (*ip)) == 0);
	i = tp_bsize / sizeof (*ip);
	assert((i%8) == 0);
	i /= 8;
	do {
		s -= *ip++; s -= *ip++; s -= *ip++; s -= *ip++;
		s -= *ip++; s -= *ip++; s -= *ip++; s -= *ip++;
	} while (--i > 0);
	spcl.c_checksum = s;
	taprec((uchar_t *)&spcl, flags, sizeof (spcl));
	if (spcl.c_type == TS_END)
		spcl.c_flags &= ~DR_INODEINFO;
	else if (spcl.c_type == TS_TAPE)
		spcl.c_flags &= ~(DR_NEWHEADER|DR_REDUMP|DR_TRUEINC);
}

/*
 * Fill appropriate buffer
 */
void
taprec(uchar_t *dp, int flags, int size)
{
	if (size > tp_bsize) {
		msg(gettext(
		    "taprec: Unexpected buffer size, expected %d, got %d.\n"),
		    tp_bsize, size);
		dumpabort();
		/*NOTREACHED*/
	}

	while ((*current)->b_flags & BUF_FULL)
		nap(10);

	bcopy(dp, (*current)->b_data, (size_t)size);
	if (size < tp_bsize) {
		bzero((*current)->b_data + size, tp_bsize - size);
	}

	if (dumptoarchive)
		flags |= BUF_ARCHIVE;

	/* no locking as we assume only one reader and one writer active */
	(*current)->b_flags = (flags | BUF_FULL);
	if (++*current >= &bufp[NBUF*ntrec])
		(*current) = &bufp[0];
	(*tapea)++;
}

void
dmpblk(daddr32_t blkno, size_t size, off_t offset)
{
	diskaddr_t dblkno;

	assert((offset >> DEV_BSHIFT) <= INT32_MAX);
	dblkno = fsbtodb(sblock, blkno) + (offset >> DEV_BSHIFT);
	size = (size + DEV_BSIZE-1) & ~(DEV_BSIZE-1);
	slp->sl_req->br_dblk = dblkno;
	slp->sl_req->br_size = size;
	if (dumptoarchive) {
		/* LINTED: result fits in a short */
		slp->sl_req->aflag |= BUF_ARCHIVE;
	}
	toslave((void(*)())0, ino);
}

/*ARGSUSED*/
static void
tperror(int sig)
{
	char buf[3000];

	if (pipeout) {
		msg(gettext("Write error on %s\n"), tape);
		msg(gettext("Cannot recover\n"));
		dumpabort();
		/* NOTREACHED */
	}
	if (!doingverify) {
		broadcast(gettext("WRITE ERROR!\n"));
		(void) snprintf(buf, sizeof (buf),
		    gettext("Do you want to restart?: (\"yes\" or \"no\") "));
		if (!query(buf)) {
			dumpabort();
			/*NOTREACHED*/
		}
		if (tapeout && (isrewind(to) || offline)) {
			/* ANSI string catenation, to shut cstyle up */
			msg(gettext("This tape will rewind.  After "
			    "it is rewound,\nreplace the faulty tape "
			    "with a new one;\nthis dump volume will "
			    "be rewritten.\n"));
		}
	} else {
		broadcast(gettext("TAPE VERIFICATION ERROR!\n"));
		(void) snprintf(buf, sizeof (buf), gettext(
		    "Do you want to rewrite?: (\"yes\" or \"no\") "));
		if (!query(buf)) {
			dumpabort();
			/*NOTREACHED*/
		}
		msg(gettext(
		    "This tape will be rewritten and then verified\n"));
	}
	killall();
	trewind();
	Exit(X_REWRITE);
}

/*
 * Called by master from pass() to send a request to dump files/blocks
 * to one of the slaves.  Slaves return whether the file was active
 * when it was being dumped.  The tape writer process sends checkpoint
 * info when it completes a volume.
 */
void
toslave(void (*fn)(), ino_t inumber)
{
	int	wasactive;

	if (recsout >= SLAVES) {
		if ((unsigned)atomic((int(*)())read, slp->sl_slavefd,
		    (char *)&wasactive, sizeof (wasactive)) !=
		    sizeof (wasactive)) {
			cmdrderr();
			dumpabort();
			/*NOTREACHED*/
		}
		if (wasactive) {
			active++;
			msg(gettext(
			    "The file at inode `%lu' was active and will "
			    "be recopied\n"),
			    slp->sl_req->ir_inumber);
			/* LINTED: 32-bit to 8-bit assignment ok */
			BIS(slp->sl_req->ir_inumber, activemap);
		}
	}
	slp->sl_req->aflag = 0;
	if (dumptoarchive) {
		/* LINTED: result fits in a short */
		slp->sl_req->aflag |= BUF_ARCHIVE;
	}
	if (fn)
		(*fn)(inumber);

	if (atomic((int(*)())write, slp->sl_slavefd, (char *)slp->sl_req,
	    reqsiz) != reqsiz) {
		cmdwrterr();
		dumpabort();
		/*NOTREACHED*/
	}
	++recsout;
	nextslave();
}

void
dospcl(ino_t inumber)
{
	/* LINTED for now, max inode # is 2**31 (ufs max size is 1TB) */
	spcl.c_inumber = (ino32_t)inumber;
	slp->sl_req->br_dblk = 0;
	bcopy((char *)&spcl, (char *)slp->sl_req->br_spcl, tp_bsize);
}

static void
nextslave(void)
{
	if (++rotor >= SLAVES) {
		rotor = 0;
	}
	slp = &slaves[rotor];
}

void
flushcmds(void)
{
	int i;
	int wasactive;

	/*
	 * Retrieve all slave status
	 */
	if (recsout < SLAVES) {
		slp = slaves;
		rotor = 0;
	}
	for (i = 0; i < (recsout < SLAVES ? recsout : SLAVES); i++) {
		if ((unsigned)atomic((int(*)())read, slp->sl_slavefd,
		    (char *)&wasactive, sizeof (wasactive)) !=
		    sizeof (wasactive)) {
			cmdrderr();
			dumpabort();
			/*NOTREACHED*/
		}
		if (wasactive) {
			active++;
			msg(gettext(
			    "inode %d was active and will be recopied\n"),
			    slp->sl_req->ir_inumber);
			/* LINTED: 32-bit to 8-bit assignment ok */
			BIS(slp->sl_req->ir_inumber, activemap);
		}
		nextslave();
	}
}

void
flusht(void)
{
	sigset_t block_set, oset;	/* hold SIGUSR1 and atomically sleep */

	(void) sigemptyset(&block_set);
	(void) sigaddset(&block_set, SIGUSR1);
	(void) sigprocmask(SIG_BLOCK, &block_set, &oset);
	(void) kill(writepid, SIGUSR1);	/* tell writer to flush */
	(void) sigpause(SIGUSR1);	/* wait for SIGUSR1 from writer */
	/*NOTREACHED*/
}

jmp_buf	checkpoint_buf;

/*
 * Roll forward to the next volume after receiving
 * an EOT signal from writer.  Get checkpoint data
 * from writer and return if done, otherwise fork
 * a new process and jump back to main state loop
 * to begin the next volume.  Installed as the master's
 * signal handler for SIGUSR1.
 */
/*ARGSUSED*/
static void
rollforward(int sig)
{
	int status;
	(void) sighold(SIGUSR1);

	/*
	 * Writer sends us checkpoint information after
	 * each volume.  A returned state of DS_DONE with no
	 * unwritten (left-over) records differentiates a
	 * clean flush from one in which EOT was encountered.
	 */
	if ((unsigned)atomic((int(*)())read, writer, (char *)&chkpt,
	    sizeof (struct slaves)) != sizeof (struct slaves)) {
		cmdrderr();
		dumpabort();
		/*NOTREACHED*/
	}
	if (atomic((int(*)())read, writer, (char *)&spcl,
	    TP_BSIZE_MIN) != TP_BSIZE_MIN) {
		cmdrderr();
		dumpabort();
		/*NOTREACHED*/
	}
	ino = chkpt.sl_inos - 1;
	pos = chkpt.sl_offset;
	leftover = chkpt.sl_count;
	dumpstate = chkpt.sl_state;
	blockswritten = ++chkpt.sl_tapea;

	if (dumpstate == DS_DONE) {
		if (archivepid) {
			/*
			 * If archiving (either archive or
			 * database), signal the archiver
			 * to finish up.  This must happen
			 * before the writer exits in order
			 * to avoid a race.
			 */
			(void) kill(archivepid, SIGUSR1);
		}
		(void) signal(SIGUSR1, SIG_IGN);
		(void) sigrelse(SIGUSR1);
		(void) kill(writepid, SIGUSR1);	/* tell writer to exit */

		lf_archoffset = 0LL;
		longjmp(checkpoint_buf, 1);
		/*NOTREACHED*/
	}

	if (leftover) {
		(void) memmove(spcl.c_addr,
		    &spcl.c_addr[spcl.c_count-leftover], leftover);
		bzero(&spcl.c_addr[leftover], TP_NINDIR-leftover);
	}
	if (writepid) {
		(void) kill(writepid, SIGUSR1);	/* tell writer to exit */
		(void) close(writer);
		writer = -1;
	}
	if (archivepid) {
		(void) waitpid(archivepid, &status, 0);	/* wait for archiver */
#ifdef TDEBUG

		/* XGETTEXT:  #ifdef TDEBUG only */
		msg(gettext("Archiver %ld returns with status %d\n"),
		    (long)archivepid, status);
#endif
		archivepid = 0;
	}
	/*
	 * Checkpoint archive file
	 */
	if (!doingverify && archive) {
		lf_archoffset = lseek64(archivefd, (off64_t)0, 2);
		if (lf_archoffset < 0) {
			int saverr = errno;
			msg(gettext("Cannot position archive file `%s': %s\n"),
			    archivefile, strerror(saverr));
			dumpabort();
			/*NOTREACHED*/
		}
		(void) close(archivefd);
		archivefd = -1;
	}
	resetino(ino);

	if (dumpstate == DS_START) {
		msg(gettext(
		    "Tape too short: changing volumes and restarting\n"));
		reset();
	}

	if (!pipeout) {
		if (verify && !doingverify)
			trewind();
		else {
			close_rewind();
			changevol();
		}
	}

	(void) sigrelse(SIGUSR1);
	otape(0);
	longjmp(checkpoint_buf, 1);
	/*NOTREACHED*/
}

static void
nap(int ms)
{
	struct timeval tv;

	tv.tv_sec = ms / 1000;
	tv.tv_usec = (ms - tv.tv_sec * 1000) * 1000;
	(void) select(0, (fd_set *)0, (fd_set *)0, (fd_set *)0, &tv);
}

static jmp_buf alrm_buf;

/*ARGSUSED*/
static void
alrm(int sig)
{
	longjmp(alrm_buf, 1);
	/*NOTREACHED*/
}

void
nextdevice(void)
{
	char	*cp;

	if (host != NULL)	/* we set the host only once in ufsdump */
		return;

	host = NULL;
	if (strchr(tape, ':')) {
		if (diskette) {
			msg(gettext("Cannot do remote dump to diskette\n"));
			Exit(X_ABORT);
		}
		host = tape;
		tape = strchr(host, ':');
		*tape++ = 0;
		cp = strchr(host, '@');	/* user@host? */
		if (cp != (char *)0)
			cp++;
		else
			cp = host;
	} else
		cp = spcl.c_host;
	/*
	 * dumpdev is provided for use in prompts and is of
	 * the form:
	 *	hostname:device
	 * sdumpdev is of the form:
	 *	hostname:device
	 * for remote devices, and simply:
	 *	device
	 * for local devices.
	 */
	if (dumpdev != (char *)NULL) {
		/* LINTED: dumpdev is not NULL */
		free(dumpdev);
	}
	/*LINTED [cast to smaller integer]*/
	dumpdev = xmalloc((size_t)((sizeof (spcl.c_host) + strlen(tape) + 2)));
	/* LINTED unsigned -> signed cast ok */
	(void) sprintf(dumpdev, "%.*s:%s", (int)sizeof (spcl.c_host), cp, tape);
	if (cp == spcl.c_host)
		sdumpdev = strchr(dumpdev, ':') + 1;
	else
		sdumpdev = dumpdev;
}

/*
 * Gross hack due to misfeature of mt tape driver that causes
 * the device to rewind if we generate any signals.  Guess
 * whether tape is rewind device or not -- for local devices
 * we can just look at the minor number.  For rmt devices,
 * make an educated guess.
 */
int
isrewind(int f)
{
	struct stat64 sbuf;
	char    *c;
	int	unit;
	int	rewind;

	if (host) {
		c = strrchr(tape, '/');
		if (c == NULL)
			c = tape;
		else
			c++;
		/*
		 * If the last component begins or ends with an 'n', it is
		 * assumed to be a non-rewind device.
		 */
		if (c[0] == 'n' || c[strlen(c)-1] == 'n')
			rewind = 0;
		else if ((strstr(tape, "mt") || strstr(tape, "st")) &&
		    sscanf(tape, "%*[a-zA-Z/]%d", &unit) == 1 &&
		    (unit & MT_NOREWIND))
			rewind = 0;
		else
			rewind = 1;
	} else {
		if (fstat64(f, &sbuf) < 0) {
			msg(gettext(
			    "Cannot obtain status of output device `%s'\n"),
			    tape);
			dumpabort();
			/*NOTREACHED*/
		}
		rewind = minor(sbuf.st_rdev) & MT_NOREWIND ? 0 : 1;
	}
	return (rewind);
}

static void
just_rewind(void)
{
	struct slaves *slavep;
	char *rewinding = gettext("Tape rewinding\n");

	for (slavep = &slaves[0]; slavep < &slaves[SLAVES]; slavep++) {
		if (slavep->sl_slavepid > 0)	/* signal normal exit */
			(void) kill(slavep->sl_slavepid, SIGTERM);
		if (slavep->sl_slavefd >= 0) {
			(void) close(slavep->sl_slavefd);
			slavep->sl_slavefd = -1;
		}
	}

	/* wait for any signals from slaves */
	while (waitpid(0, (int *)0, 0) >= 0)
		/*LINTED [empty body]*/
		continue;

	if (pipeout)
		return;

	if (doingverify) {
		/*
		 * Space to the end of the tape.
		 * Backup first in case we already read the EOF.
		 */
		if (host) {
			(void) rmtioctl(MTBSR, 1);
			if (rmtioctl(MTEOM, 1) < 0)
				(void) rmtioctl(MTFSF, 1);
		} else {
			static struct mtop bsr = { MTBSR, 1 };
			static struct mtop eom = { MTEOM, 1 };
			static struct mtop fsf = { MTFSF, 1 };

			(void) ioctl(to, MTIOCTOP, &bsr);
			if (ioctl(to, MTIOCTOP, &eom) < 0)
				(void) ioctl(to, MTIOCTOP, &fsf);
		}
	}

	/*
	 * Guess whether the tape is rewinding so we can tell
	 * the operator if it's going to take a long time.
	 */
	if (tapeout && isrewind(to)) {
		/* tape is probably rewinding */
		msg(rewinding);
	}
}

void
trewind(void)
{
	(void) timeclock((time_t)0);
	if (offline && (!verify || doingverify)) {
		close_rewind();
	} else {
		just_rewind();
		if (host)
			rmtclose();
		else {
			(void) close(to);
			to = -1;
		}
	}
}

void
close_rewind(void)
{
	char *rewinding = gettext("Tape rewinding\n");

	(void) timeclock((time_t)0);
	just_rewind();
	/*
	 * The check in just_rewind won't catch the case in
	 * which the current volume is being taken off-line
	 * and is not mounted on a no-rewind device (and is
	 * not the last volume, which is not taken off-line).
	 */
	if (tapeout && !isrewind(to) && offline) {
		/* tape is probably rewinding */
		msg(rewinding);
	}
	if (host) {
		if (offline || autoload)
			(void) rmtioctl(MTOFFL, 0);
		rmtclose();
	} else {
		if (offline || autoload) {
			static struct mtop offl = { MTOFFL, 0 };

			(void) ioctl(to, MTIOCTOP, &offl);
			if (diskette)
				(void) ioctl(to, FDEJECT, 0);
		}
		(void) close(to);
		to = -1;
	}
}

void
changevol(void)
{
	char buf1[3000], buf2[3000];
	char volname[LBLSIZE+1];

	/*CONSTANTCONDITION*/
	assert(sizeof (spcl.c_label) < sizeof (volname));

	filenum = 1;
	nextdevice();
	(void) strcpy(spcl.c_label, tlabel);
	if (host) {
		char	*rhost = host;
		char	*cp = strchr(host, '@');
		if (cp == (char *)0)
			cp = host;
		else
			cp++;

		if (rmthost(rhost, ntrec) == 0) {
			msg(gettext("Cannot connect to tape host `%s'\n"), cp);
			dumpabort();
			/*NOTREACHED*/
		}
		if (rhost != host)
			free(rhost);
	}

	/*
	 * Make volume switching as automatic as possible
	 * while avoiding overwriting volumes.  We will
	 * switch automatically under the following condition:
	 *    1) The user specified autoloading from the
	 *	command line.
	 * At one time, we (in the guise of hsmdump) had the
	 * concept of a sequence of devices to rotate through,
	 * but that's never been a ufsdump feature.
	 */
	if (autoload) {
		int tries;

		/*
		 * Stop the clock for throughput calculations.
		 */
		if ((telapsed != NULL) && (tstart_writing != NULL)) {
			*telapsed += time((time_t *)NULL) - *tstart_writing;
		}

		(void) snprintf(volname, sizeof (volname), "#%d", tapeno+1);
		(void) snprintf(buf1, sizeof (buf1), gettext(
		    "Mounting volume %s on %s\n"), volname, dumpdev);
		msg(buf1);
		broadcast(buf1);

		/*
		 * Wait for the tape to autoload.  Note that the delay
		 * period doesn't take into account however long it takes
		 * for the open to fail (measured at 21 seconds for an
		 * Exabyte 8200 under 2.7 on an Ultra 2).
		 */
		for (tries = 0; tries < autoload_tries; tries++) {
			if (host) {
				if (rmtopen(tape, O_RDONLY) >= 0) {
					rmtclose();
					return;
				}
			} else {
				int f, m;

				m = (access(tape, F_OK) == 0) ? 0 : O_CREAT;
				if ((f = doingverify ?
				    safe_device_open(tape, O_RDONLY, 0600) :
				    safe_device_open(tape, O_RDONLY|m, 0600))
				    >= 0) {
					(void) close(f);
					return;
				}
			}
			(void) sleep(autoload_period);
		}
		/*
		 * Autoload timed out, ask the operator to do it.
		 * Note that query() will update *telapsed, and we
		 * shouldn't charge for the autoload time.  So, since
		 * we updated *telapsed ourselves above, we just set
		 * tstart_writing to the current time, and query()
		 * will end up making a null-effect change.  This,
		 * of course, assumes that our caller will be resetting
		 * *tstart_writing.  This is currently the case.
		 * If tstart_writing is NULL (should never happen),
		 * we're ok, since time(2) will accept a NULL pointer.
		 */
		(void) time(tstart_writing);
	}

	if (strncmp(spcl.c_label, "none", 5)) {
		(void) strncpy(volname, spcl.c_label, sizeof (spcl.c_label));
		volname[sizeof (spcl.c_label)] = '\0';
	} else
		(void) snprintf(volname, sizeof (volname), "#%d", tapeno+1);

	timeest(1, spcl.c_tapea);
	(void) snprintf(buf1, sizeof (buf1), gettext(
	    "Change Volumes: Mount volume `%s' on `%s'\n"), volname, dumpdev);
	msg(buf1);
	broadcast(gettext("CHANGE VOLUMES!\7\7\n"));
	(void) snprintf(buf1, sizeof (buf1), gettext(
	    "Is the new volume (%s) mounted on `%s' and ready to go?: %s"),
	    volname, dumpdev, gettext("(\"yes\" or \"no\") "));
	while (!query(buf1)) {
		(void) snprintf(buf2, sizeof (buf2), gettext(
		    "Do you want to abort dump?: (\"yes\" or \"no\") "));
		if (query(buf2)) {
			dumpabort();
			/*NOTREACHED*/
		}
	}
}

/*
 *	We implement taking and restoring checkpoints on the tape level.
 *	When each tape is opened, a new process is created by forking; this
 *	saves all of the necessary context in the parent.  The child
 *	continues the dump; the parent waits around, saving the context.
 *	If the child returns X_REWRITE, then it had problems writing that tape;
 *	this causes the parent to fork again, duplicating the context, and
 *	everything continues as if nothing had happened.
 */

void
otape(int top)
{
	static struct mtget mt;
	char buf[3000];
	pid_t parentpid;
	pid_t childpid;
	pid_t waitproc;
	int status;
	struct sigvec sv, osv;

	sv.sv_flags = SA_RESTART;
	(void) sigemptyset(&sv.sa_mask);
	sv.sv_handler = SIG_IGN;
	(void) sigvec(SIGINT, &sv, (struct sigvec *)0);

	parentpid = getpid();

	if (verify) {
		if (doingverify)
			doingverify = 0;
		else
			Exit(X_VERIFY);
	}
restore_check_point:

	sv.sv_handler = interrupt;
	(void) sigvec(SIGINT, &sv, (struct sigvec *)0);
	(void) fflush(stderr);
	/*
	 *	All signals are inherited...
	 */
	sighold(SIGINT);
	childpid = fork();
	if (childpid < 0) {
		msg(gettext(
		    "Context-saving fork failed in parent %ld\n"),
		    (long)parentpid);
		Exit(X_ABORT);
	}
	if (childpid != 0) {
		/*
		 *	PARENT:
		 *	save the context by waiting
		 *	until the child doing all of the work returns.
		 *	let the child catch user interrupts
		 */
		sv.sv_handler = SIG_IGN;
		(void) sigvec(SIGINT, &sv, (struct sigvec *)0);
		sigrelse(SIGINT);
#ifdef TDEBUG

		/* XGETTEXT:  #ifdef TDEBUG only */
		msg(gettext(
		    "Volume: %d; parent process: %ld child process %ld\n"),
		    tapeno+1, (long)parentpid, (long)childpid);
#endif /* TDEBUG */
		for (;;) {
			waitproc = waitpid(0, &status, 0);
			if (waitproc == childpid)
				break;
			msg(gettext(
	"Parent %ld waiting for child %ld had another child %ld return\n"),
			    (long)parentpid, (long)childpid, (long)waitproc);
		}
		if (WIFSIGNALED(status)) {
			msg(gettext("Process %ld killed by signal %d: %s\n"),
			    (long)childpid, WTERMSIG(status),
			    strsignal(WTERMSIG(status)));
			status = X_ABORT;
		} else
			status = WEXITSTATUS(status);
#ifdef TDEBUG
		switch (status) {
		case X_FINOK:
			/* XGETTEXT:  #ifdef TDEBUG only */
			msg(gettext(
			    "Child %ld finishes X_FINOK\n"), (long)childpid);
			break;
		case X_ABORT:
			/* XGETTEXT:  #ifdef TDEBUG only */
			msg(gettext(
			    "Child %ld finishes X_ABORT\n"), (long)childpid);
			break;
		case X_REWRITE:
			/* XGETTEXT:  #ifdef TDEBUG only */
			msg(gettext(
			    "Child %ld finishes X_REWRITE\n"), (long)childpid);
			break;
		case X_RESTART:
			/* XGETTEXT:  #ifdef TDEBUG only */
			msg(gettext(
			    "Child %ld finishes X_RESTART\n"), (long)childpid);
			break;
		case X_VERIFY:
			/* XGETTEXT:  #ifdef TDEBUG only */
			msg(gettext(
			    "Child %ld finishes X_VERIFY\n"), (long)childpid);
			break;
		default:
			/* XGETTEXT:  #ifdef TDEBUG only */
			msg(gettext("Child %ld finishes unknown %d\n"),
			    (long)childpid, status);
			break;
		}
#endif /* TDEBUG */
		switch (status) {
		case X_FINOK:
			/* wait for children */
			while (waitpid(0, (int *)0, 0) >= 0)
				/*LINTED [empty body]*/
				continue;
			Exit(X_FINOK);
			/*NOTREACHED*/
		case X_ABORT:
			Exit(X_ABORT);
			/*NOTREACHED*/
		case X_VERIFY:
			doingverify++;
			goto restore_check_point;
			/*NOTREACHED*/
		case X_REWRITE:
			doingverify = 0;
			changevol();
			goto restore_check_point;
			/* NOTREACHED */
		case X_RESTART:
			doingverify = 0;
			if (!top) {
				Exit(X_RESTART);
			}
			if (!offline)
				autoload = 0;
			changevol();
			sv.sv_handler = interrupt;
			(void) sigvec(SIGINT, &sv, (struct sigvec *)0);
			return;
			/* NOTREACHED */
		default:
			msg(gettext("Bad return code from dump: %d\n"), status);
			Exit(X_ABORT);
			/*NOTREACHED*/
		}
		/*NOTREACHED*/
	} else {	/* we are the child; just continue */
		child_chdir();
		sigrelse(SIGINT);
#ifdef TDEBUG
		(void) sleep(4); /* time for parent's message to get out */
		/* XGETTEXT:  #ifdef TDEBUG only */
		msg(gettext(
		    "Child on Volume %d has parent %ld, my pid = %ld\n"),
		    tapeno+1, (long)parentpid, (long)getpid());
#endif
		(void) snprintf(buf, sizeof (buf), gettext(
"Cannot open `%s'.  Do you want to retry the open?: (\"yes\" or \"no\") "),
		    dumpdev);
		if (doingverify) {
			/* 1 for stdout */
			while ((to = host ? rmtopen(tape, O_RDONLY) :
			    pipeout ? 1 :
			    safe_device_open(tape, O_RDONLY, 0600)) < 0) {
				perror(tape);
				if (autoload) {
					if (!query_once(buf, 1)) {
						dumpabort();
						/*NOTREACHED*/
					}
				} else {
					if (!query(buf)) {
						dumpabort();
						/*NOTREACHED*/
					}
				}
			}

			/*
			 * If we're using the non-rewinding tape device,
			 * the tape will be left positioned after the
			 * EOF mark.  We need to back up to the beginning
			 * of this tape file (cross two tape marks in the
			 * reverse direction and one in the forward
			 * direction) before the verify pass.
			 */
			if (host) {
				if (rmtioctl(MTBSF, 2) >= 0)
					(void) rmtioctl(MTFSF, 1);
				else
					(void) rmtioctl(MTNBSF, 1);
			} else {
				static struct mtop bsf = { MTBSF, 2 };
				static struct mtop fsf = { MTFSF, 1 };
				static struct mtop nbsf = { MTNBSF, 1 };

				if (ioctl(to, MTIOCTOP, &bsf) >= 0)
					(void) ioctl(to, MTIOCTOP, &fsf);
				else
					(void) ioctl(to, MTIOCTOP, &nbsf);
			}
		} else {
			/*
			 * XXX Add logic to test for "tape" being a
			 * XXX device or a non-existent file.
			 * Current behaviour is that it must exist,
			 * and we over-write whatever's there.
			 * This can be bad if tape == "/etc/passwd".
			 */
			if (!pipeout && doposition && (tapeno == 0)) {
				positiontape(buf);
				if (setjmp(alrm_buf)) {
					/*
					 * The tape is rewinding;
					 * we're screwed.
					 */
					msg(gettext(
					    "Cannot position tape using "
					    "rewind device!\n"));
					dumpabort();
					/*NOTREACHED*/
				} else {
					sv.sv_handler = alrm;
					(void) sigvec(SIGALRM, &sv, &osv);
					(void) alarm(15);
				}
				while ((to = host ? rmtopen(tape, O_WRONLY) :
				    safe_device_open(tape, O_WRONLY, 0600)) < 0)
					(void) sleep(10);
				(void) alarm(0);
				(void) sigvec(SIGALRM, &osv,
				    (struct sigvec *)0);
			} else {
				int m;
				m = (access(tape, F_OK) == 0) ? 0 : O_CREAT;
				/*
				 * Only verify the tape label if label
				 * verification is on and we are at BOT
				 */
				if (pipeout)
					to = 1;
				else while ((to = host ?
				    rmtopen(tape, O_WRONLY) :
				    safe_device_open(tape, O_WRONLY|m, 0600))
				    < 0)
					if (!query_once(buf, 1)) {
						dumpabort();
						/*NOTREACHED*/
					}
			}
		}
		if (!pipeout) {
			tapeout = host ? rmtstatus(&mt) >= 0 :
			    ioctl(to, MTIOCGET, &mt) >= 0;	/* set state */
			/*
			 * Make sure the tape is positioned
			 * where it is supposed to be
			 */
			if (tapeout && (tapeno > 0) &&
			    (mt.mt_fileno != (filenum-1))) {
				(void) snprintf(buf, sizeof (buf), gettext(
				    "Warning - tape positioning error!\n\
\t%s current file %ld, should be %ld\n"),
				    tape, mt.mt_fileno+1, filenum);
				msg(buf);
				dumpailing();
			}
		}
		tapeno++;		/* current tape sequence */
		if (tapeno < TP_NINOS)
			inos[tapeno] = chkpt.sl_inos;
		spcl.c_firstrec = chkpt.sl_firstrec;
		spcl.c_tapea = (*tapea) = chkpt.sl_tapea;
		spcl.c_volume++;

		enslave();	/* Share tape buffers with slaves */

#ifdef DEBUG
		if (xflag) {
			/* XGETTEXT:  #ifdef DEBUG only */
			msg(gettext("Checkpoint state:\n"));
			msg("    blockswritten %u\n", blockswritten);
			msg("    ino %u\n", ino);
			msg("    pos %u\n", pos);
			msg("    left %u\n", leftover);
			msg("    tapea %u\n", (*tapea));
			msg("    state %d\n", dumpstate);
		}
#endif
		spcl.c_type = TS_TAPE;
		spcl.c_tpbsize = tp_bsize;
		if (leftover == 0) {
			spcl.c_count = 0;
			spclrec();
			newtape = 0;
		} else
			newtape++;	/* new volume indication */
		if (doingverify) {
			msg(gettext("Starting verify pass\n"));
		} else if (tapeno > 1) {
			msg(gettext(
			    "Volume %d begins with blocks from inode %lu\n"),
			    tapeno, chkpt.sl_inos);
		}
		(void) timeclock((time_t)1);
		(void) time(tstart_writing);
		timeest(0, spcl.c_tapea);
	}
}

void
dumpabort(void)
{

	if (master && master != getpid())
		/*
		 * signal master to call dumpabort
		 */
		(void) kill(master, SIGTERM);
	else {
		killall();

		if (archivefile && archive_opened)
			(void) unlink(archivefile);
		msg(gettext("The ENTIRE dump is aborted.\n"));
	}
	Exit(X_ABORT);
}

void
dumpailing(void)
{

	broadcast(gettext("DUMP IS AILING!\n"));
	if (!query(gettext(
	    "Do you want to attempt to continue? (\"yes\" or \"no\") "))) {
		dumpabort();
		/*NOTREACHED*/
	}
}

void
Exit(int status)
{
	/*
	 * Clean up message system
	 */
#ifdef TDEBUG

	/* XGETTEXT:  #ifdef TDEBUG only */
	msg(gettext("pid = %ld exits with status %d\n"),
	    (long)getpid(), status);
#endif /* TDEBUG */
	exit(status);
}

static void
killall(void)
{
	struct slaves *slavep;

	for (slavep = &slaves[0]; slavep < &slaves[SLAVES]; slavep++)
		if (slavep->sl_slavepid > 0) {
			(void) kill(slavep->sl_slavepid, SIGKILL);
#ifdef TDEBUG

			/* XGETTEXT:  #ifdef TDEBUG only */
			msg(gettext("Slave child %ld killed\n"),
			    (long)slavep->sl_slavepid);
#endif
		}
	if (writepid) {
		(void) kill(writepid, SIGKILL);
#ifdef TDEBUG

		/* XGETTEXT:  #ifdef TDEBUG only */
		msg(gettext("Writer child %ld killed\n"), (long)writepid);
#endif
	}
	if (archivepid) {
		(void) kill(archivepid, SIGKILL);
#ifdef TDEBUG

		/* XGETTEXT:  #ifdef TDEBUG only */
		msg(gettext("Archiver child %ld killed\n"), (long)archivepid);
#endif
	}
}

/*ARGSUSED*/
static void
proceed(int sig)
{
	caught++;
}

/*ARGSUSED*/
static void
die(int sig)
{
	Exit(X_FINOK);
}

static void
enslave(void)
{
	int cmd[2];			/* file descriptors */
	int i;
	struct sigvec sv;
	struct slaves *slavep;
	int saverr;

	sv.sv_flags = SA_RESTART;
	(void) sigemptyset(&sv.sa_mask);
	master = getpid();
	/*
	 * slave sends SIGTERM on dumpabort
	 */
	sv.sv_handler = (void(*)(int))dumpabort;
	(void) sigvec(SIGTERM, &sv, (struct sigvec *)0);
	sv.sv_handler = tperror;
	(void) sigvec(SIGUSR2, &sv, (struct sigvec *)0);
	sv.sv_handler = proceed;
	(void) sigvec(SIGUSR1, &sv, (struct sigvec *)0);
	totalrecsout += recsout;
	caught = 0;
	recsout = 0;
	rotor = 0;
	bufclear();
	for (slavep = &slaves[0]; slavep < &slaves[SLAVES]; slavep++)
		slavep->sl_slavefd = -1;
	archivefd = arch = writer = -1;
	for (i = 0; i < SLAVES; i++) {
		if (pipe(cmd) < 0) {
			saverr = errno;
			msg(gettext(
			    "Cannot create pipe for slave process: %s\n"),
			    strerror(saverr));
			dumpabort();
			/*NOTREACHED*/
		}
		sighold(SIGUSR2);
		sighold(SIGINT);
		sighold(SIGTERM);
		if ((slaves[i].sl_slavepid = fork()) < 0) {
			saverr = errno;
			msg(gettext("Cannot create slave process: %s\n"),
			    strerror(saverr));
			dumpabort();
			/*NOTREACHED*/
		}
		slaves[i].sl_slavefd = cmd[1];
		if (slaves[i].sl_slavepid == 0) {   /* Slave starts up here */
			pid_t next;		    /* pid of neighbor */

			sv.sv_handler = SIG_DFL;
			(void) sigvec(SIGUSR2, &sv, (struct sigvec *)0);
			sv.sv_handler = SIG_IGN;	/* master handler INT */
			(void) sigvec(SIGINT, &sv, (struct sigvec *)0);
			sv.sv_handler = die;		/* normal slave exit */
			(void) sigvec(SIGTERM, &sv, (struct sigvec *)0);

			child_chdir();
			sigrelse(SIGUSR2);
			sigrelse(SIGINT);
			sigrelse(SIGTERM);

			freeino();	/* release unneeded resources */
#ifdef TDEBUG
		(void) sleep(4); /* time for parent's message to get out */
		/* XGETTEXT:  #ifdef TDEBUG only */
		msg(gettext("Neighbor has pid = %ld\n"), (long)getpid());
#endif
			/* Closes cmd[1] as a side-effect */
			for (slavep = &slaves[0];
			    slavep < &slaves[SLAVES];
			    slavep++)
				if (slavep->sl_slavefd >= 0) {
					(void) close(slavep->sl_slavefd);
					slavep->sl_slavefd = -1;
				}
			(void) close(to);
			(void) close(fi);	    /* Need our own seek ptr */
			to = -1;

			fi = open(disk, O_RDONLY);

			if (fi < 0) {
				saverr = errno;
				msg(gettext(
				    "Cannot open dump device `%s': %s\n"),
				    disk, strerror(saverr));
				dumpabort();
				/*NOTREACHED*/
			}

			if ((unsigned)atomic((int(*)())read, cmd[0],
			    (char *)&next, sizeof (next)) != sizeof (next)) {
				cmdrderr();
				dumpabort();
				/*NOTREACHED*/
			}
			dumpoffline(cmd[0], next, i);
			Exit(X_FINOK);
		}
		/* Parent continues here */
		sigrelse(SIGUSR2);
		sigrelse(SIGINT);
		sigrelse(SIGTERM);
		(void) close(cmd[0]);
	}

	if (archive) {
		archivepid = setuparchive();
		if (!archivepid) {
			dumpabort();
			/*NOTREACHED*/
		}
	}

	writepid = setupwriter();
	if (!writepid) {
		dumpabort();
		/*NOTREACHED*/
	}

	if (arch >= 0) {
		(void) close(arch);		/* only writer has this open */
		arch = -1;
	}

	/* Tell each slave who follows it */
	for (i = 0; i < SLAVES; i++) {
		if ((unsigned)atomic((int(*)())write, slaves[i].sl_slavefd,
		    (char *)&(slaves[(i + 1) % SLAVES].sl_slavepid),
		    sizeof (int)) != sizeof (int)) {
			cmdwrterr();
			dumpabort();
			/*NOTREACHED*/
		}
	}
	sv.sv_handler = rollforward;		/* rcvd from writer on EOT */
	(void) sigvec(SIGUSR1, &sv, (struct sigvec *)0);
	slp = slaves;
	(void) kill(slp->sl_slavepid, SIGUSR1);
	master = 0;
}

static void
wait_our_turn(void)
{
	(void) sighold(SIGUSR1);

	if (!caught) {
#ifdef INSTRUMENT
		(*idle)++;
#endif
		(void) sigpause(SIGUSR1);
	}
	caught = 0;
	(void) sigrelse(SIGUSR1);
}

static void
dumpoffline(int cmd, pid_t next, int mynum)
{
	struct req *p = slaves[mynum].sl_req;
	ulong_t i;
	uchar_t *cp;
	uchar_t *blkbuf;
	int notactive = 0;

	blkbuf = xmalloc(sblock->fs_bsize);

	/*CONSTANTCONDITION*/
	assert(sizeof (spcl) == TP_BSIZE_MIN);

	while (atomic((int(*)())read, cmd, (char *)p, reqsiz) == reqsiz) {
		if (p->br_dblk) {
			bread(p->br_dblk, (uchar_t *)blkbuf, p->br_size);
		} else {
			bcopy((char *)p->br_spcl, (char *)&spcl,
			    sizeof (spcl));
			ino = spcl.c_inumber;
		}
		dumptoarchive = p->aflag & BUF_ARCHIVE;
		wait_our_turn();
		if (p->br_dblk) {
			for (i = p->br_size, cp = blkbuf;
			    i > 0;
			    /* LINTED character pointers aren't signed */
			    cp += i > tp_bsize ? tp_bsize : i,
			    i -= i > tp_bsize ? tp_bsize : i) {
				/* LINTED unsigned to signed conversion ok */
				taprec(cp, 0, i > tp_bsize ? tp_bsize : (int)i);
			}
		} else
			spclrec();
		(void) kill(next, SIGUSR1);	/* Next slave's turn */
		/*
		 * Note that we lie about file activity since we don't
		 * check for it.
		 */
		if ((unsigned)atomic((int(*)())write, cmd, (char *)&notactive,
		    sizeof (notactive)) != sizeof (notactive)) {
			cmdwrterr();
			dumpabort();
			/*NOTREACHED*/
		}
	}

	free(blkbuf);
}

static int count;		/* tape blocks written since last spclrec */

/*ARGSUSED*/
static void
onxfsz(int sig)
{
	msg(gettext("File size limit exceeded writing output volume %d\n"),
	    tapeno);
	(void) kill(master, SIGUSR2);
	Exit(X_REWRITE);
}

static long	lastnonaddr;		/* last DS_{INODE,CLRI,BITS} written */
static long	lastnonaddrm;		/* and the mode thereof */
/*
 * dowrite -- the main body of the output writer process
 */
static void
dowrite(int cmd)
{
	struct bdesc *last =
	    &bufp[(NBUF*ntrec)-1];		/* last buffer in pool */
	struct bdesc *bp = bufp;		/* current buf in tape block */
	struct bdesc *begin = bufp;		/* first buf of tape block */
	struct bdesc *end = bufp + (ntrec-1);	/* last buf of tape block */
	int siz;				/* bytes written (block) */
	int trecs;				/* records written (block)  */
	long asize = 0;				/* number of 0.1" units... */
						/* ...written on current tape */
	char *tp, *rbuf = NULL;
	char *recmap = spcl.c_addr;		/* current tape record map */
	char *endmp;				/* end of valid map data */
	char *mp;				/* current map entry */
	union u_spcl *sp;

	(void) signal(SIGXFSZ, onxfsz);

	bzero((char *)&spcl, sizeof (spcl));
	count = 0;

	if (doingverify) {
		rbuf = (char *)malloc((uint_t)writesize);
		if (rbuf == 0) {
			/* Restart from checkpoint */
			(void) kill(master, SIGUSR2);
			Exit(X_REWRITE);
		}
	}

	for (;;) {
		/* START: wait until all buffers in tape block are full */
		if ((bp->b_flags & BUF_FULL) == 0) {
			if (caught) {		/* master signalled flush */
				(void) sighold(SIGUSR1);
				caught = 0;
				/* signal ready */
				(void) kill(master, SIGUSR1);
				chkpt.sl_count = 0;	/* signal not at EOT */
				checkpoint(bp-1, cmd);	/* send data */
				(void) sigpause(SIGUSR1);
				break;
			}
#ifdef INSTRUMENT
			(*readmissp)++;
#endif
			nap(50);
			continue;
		}
		if (bp < end) {
			bp++;
			continue;
		}
		/* END: wait until all buffers in tape block are full */

		tp = begin->b_data;
		(void) sighold(SIGUSR1);
		if (host) {
			if (!doingverify)
				siz = rmtwrite(tp, writesize);
			else if ((siz = rmtread(rbuf, writesize)) ==
			    writesize && bcmp(rbuf, tp, writesize))
				siz = -1;
		} else {
			if (!doingverify)
				siz = write(to, tp, writesize);
			else if ((siz = read(to, rbuf, writesize)) ==
			    writesize && bcmp(rbuf, tp, writesize))
				siz = -1;
			if (siz < 0 && diskette && errno == ENOSPC)
				siz = 0;	/* really EOF */
		}
		(void) sigrelse(SIGUSR1);
		if (siz < 0 ||
		    (pipeout && siz != writesize)) {
			char buf[3000];

			/*
			 * Isn't i18n wonderful?
			 */
			if (doingverify) {
				if (diskette)
					(void) snprintf(buf, sizeof (buf),
					    gettext(
		    "Verification error %ld blocks into diskette %d\n"),
					    asize * 2, tapeno);
				else if (tapeout)
					(void) snprintf(buf, sizeof (buf),
					    gettext(
		    "Verification error %ld feet into tape %d\n"),
					    (cartridge ? asize/tracks :
					    asize)/120L,
					    tapeno);
				else
					(void) snprintf(buf, sizeof (buf),
					    gettext(
		    "Verification error %ld blocks into volume %d\n"),
					    asize * 2, tapeno);

			} else {
				if (diskette)
					(void) snprintf(buf, sizeof (buf),
					    gettext(
			"Write error %ld blocks into diskette %d\n"),
					    asize * 2, tapeno);
				else if (tapeout)
					(void) snprintf(buf, sizeof (buf),
					    gettext(
			"Write error %ld feet into tape %d\n"),
					    (cartridge ? asize/tracks :
					    asize)/120L, tapeno);
				else
					(void) snprintf(buf, sizeof (buf),
					    gettext(
			"Write error %ld blocks into volume %d\n"),
					    asize * 2, tapeno);
			}

			msg(buf);
			/* Restart from checkpoint */
#ifdef TDEBUG

			/* XGETTEXT:  #ifdef TDEBUG only */
			msg(gettext("sending SIGUSR2 to pid %ld\n"), master);
#endif
			(void) kill(master, SIGUSR2);
			Exit(X_REWRITE);
		}
		trecs = siz / tp_bsize;
		if (diskette)
			asize += trecs;	/* asize == blocks written */
		else
			asize += (siz/density + tenthsperirg);
		if (trecs)
			chkpt.sl_firstrec++;
		for (bp = begin; bp < begin + trecs; bp++) {
			if ((arch >= 0) && (bp->b_flags & BUF_ARCHIVE)) {
				if ((unsigned)atomic((int(*)())write, arch,
				    (char *)&bp->b_flags, sizeof (bp->b_flags))
				    != sizeof (bp->b_flags)) {
					cmdwrterr();
					dumpabort();
					/*NOTREACHED*/
				}
				if (atomic((int(*)())write, arch, bp->b_data,
				    tp_bsize) != tp_bsize) {
					cmdwrterr();
					dumpabort();
					/*NOTREACHED*/
				}
			}
			if (bp->b_flags & BUF_SPCLREC) {
				/*LINTED [bp->b_data is aligned]*/
				sp = (union u_spcl *)bp->b_data;
				if (sp->s_spcl.c_type != TS_ADDR) {
					lastnonaddr = sp->s_spcl.c_type;
					lastnonaddrm =
					    sp->s_spcl.c_dinode.di_mode;
					if (sp->s_spcl.c_type != TS_TAPE)
						chkpt.sl_offset = 0;
				}
				chkpt.sl_count = sp->s_spcl.c_count;
				bcopy((char *)sp, (char *)&spcl, sizeof (spcl));
				mp = recmap;
				endmp = &recmap[spcl.c_count];
				count = 0;
			} else {
				chkpt.sl_offset++;
				chkpt.sl_count--;
				count++;
				mp++;
			}
			/*
			 * Adjust for contiguous hole
			 */
			for (; mp < endmp; mp++) {
				if (*mp)
					break;
				chkpt.sl_offset++;
				chkpt.sl_count--;
			}
		}
		/*
		 * Check for end of tape
		 */
		if (trecs < ntrec ||
		    (!pipeout && tsize > 0 && asize > tsize)) {
			if (tapeout)
				msg(gettext("End-of-tape detected\n"));
			else
				msg(gettext("End-of-file detected\n"));
			(void) sighold(SIGUSR1);
			caught = 0;
			(void) kill(master, SIGUSR1);	/* signal EOT */
			checkpoint(--bp, cmd);	/* send checkpoint data */
			(void) sigpause(SIGUSR1);
			break;
		}
		for (bp = begin; bp <= end; bp++)
			bp->b_flags = BUF_EMPTY;
		if (end + ntrec > last) {
			bp = begin = bufp;
			timeest(0, spcl.c_tapea);
		} else
			bp = begin = end+1;
		end = begin + (ntrec-1);
	}

	if (rbuf != NULL)
		free(rbuf);
}

/*
 * Send checkpoint info back to master.  This information
 * consists of the current inode number, number of logical
 * blocks written for that inode (or bitmap), the last logical
 * block number written, the number of logical blocks written
 * to this volume, the current dump state, and the current
 * special record map.
 */
static void
checkpoint(struct bdesc *bp, int cmd)
{
	int	state, type;
	ino_t	ino;

	if (++bp >= &bufp[NBUF*ntrec])
		bp = bufp;

	/*
	 * If we are dumping files and the record following
	 * the last written to tape is a special record, use
	 * it to get an accurate indication of current state.
	 */
	if ((bp->b_flags & BUF_SPCLREC) && (bp->b_flags & BUF_FULL) &&
	    lastnonaddr == TS_INODE) {
		/*LINTED [bp->b_data is aligned]*/
		union u_spcl *nextspcl = (union u_spcl *)bp->b_data;

		if (nextspcl->s_spcl.c_type == TS_INODE) {
			chkpt.sl_offset = 0;
			chkpt.sl_count = 0;
		} else if (nextspcl->s_spcl.c_type == TS_END) {
			chkpt.sl_offset = 0;
			chkpt.sl_count = 1;	/* EOT indicator */
		}
		ino = nextspcl->s_spcl.c_inumber;
		type = nextspcl->s_spcl.c_type;
	} else {
		/*
		 * If not, use what we have.
		 */
		ino = spcl.c_inumber;
		type = spcl.c_type;
	}

	switch (type) {		/* set output state */
	case TS_ADDR:
		switch (lastnonaddr) {
		case TS_INODE:
		case TS_TAPE:
			if ((lastnonaddrm & IFMT) == IFDIR ||
			    (lastnonaddrm & IFMT) == IFATTRDIR)
				state = DS_DIRS;
			else
				state = DS_FILES;
			break;
		case TS_CLRI:
			state = DS_CLRI;
			break;
		case TS_BITS:
			state = DS_BITS;
			break;
		}
		break;
	case TS_INODE:
		if ((spcl.c_dinode.di_mode & IFMT) == IFDIR ||
		    (spcl.c_dinode.di_mode & IFMT) == IFATTRDIR)
			state = DS_DIRS;
		else
			state = DS_FILES;
		break;
	case 0:			/* EOT on 1st record */
	case TS_TAPE:
		state = DS_START;
		ino = UFSROOTINO;
		break;
	case TS_CLRI:
		state = DS_CLRI;
		break;
	case TS_BITS:
		state = DS_BITS;
		break;
	case TS_END:
		if (spcl.c_type == TS_END)
			state = DS_DONE;
		else
			state = DS_END;
		break;
	}

	/*
	 * Checkpoint info to be processed by rollforward():
	 *	The inode with which the next volume should begin
	 *	The last inode number on this volume
	 *	The last logical block number on this volume
	 *	The current output state
	 *	The offset within the current inode (already in sl_offset)
	 *	The number of records left from last spclrec (in sl_count)
	 *	The physical block the next vol begins with (in sl_firstrec)
	 */
	chkpt.sl_inos = ino;
	chkpt.sl_tapea = spcl.c_tapea + count;
	chkpt.sl_state = state;

	if ((unsigned)atomic((int(*)())write, cmd, (char *)&chkpt,
	    sizeof (chkpt)) != sizeof (chkpt)) {
		cmdwrterr();
		dumpabort();
		/*NOTREACHED*/
	}
	if ((unsigned)atomic((int(*)())write, cmd, (char *)&spcl,
	    sizeof (spcl)) != sizeof (spcl)) {
		cmdwrterr();
		dumpabort();
		/*NOTREACHED*/
	}
#ifdef DEBUG
	if (xflag) {
		/* XGETTEXT:  #ifdef DEBUG only */
		msg(gettext("sent chkpt to master:\n"));
		msg("    ino %u\n", chkpt.sl_inos);
		msg("    1strec %u\n", chkpt.sl_firstrec);
		msg("    lastrec %u\n", chkpt.sl_tapea);
		msg("    written %u\n", chkpt.sl_offset);
		msg("    left %u\n", chkpt.sl_count);
		msg("    state %d\n", chkpt.sl_state);
	}
#endif
}

/*
 * Since a read from a pipe may not return all we asked for,
 * or a write may not write all we ask if we get a signal,
 * loop until the count is satisfied (or error).
 */
static ssize_t
atomic(int (*func)(), int fd, char *buf, int count)
{
	ssize_t got = 0, need = count;

	/* don't inherit random value if immediately get zero back from func */
	errno = 0;
	while (need > 0) {
		got = (*func)(fd, buf, MIN(need, 4096));
		if (got < 0 && errno == EINTR)
			continue;
		if (got <= 0)
			break;
		buf += got;
		need -= got;
	}
	/* if we got what was asked for, return count, else failure (got) */
	return ((need != 0) ? got : count);
}

void
positiontape(char *msgbuf)
{
	/* Static as never change, no need to waste stack space */
	static struct mtget mt;
	static struct mtop rew = { MTREW, 1 };
	static struct mtop fsf = { MTFSF, 1 };
	char *info = strdup(gettext("Positioning `%s' to file %ld\n"));
	char *fail = strdup(gettext("Cannot position tape to file %d\n"));
	int m;

	/* gettext()'s return value is volatile, hence the strdup()s */

	m = (access(tape, F_OK) == 0) ? 0 : O_CREAT;

	/*
	 * To avoid writing tape marks at inappropriate places, we open the
	 * device read-only, position it, close it, and reopen it for writing.
	 */
	while ((to = host ? rmtopen(tape, O_RDONLY) :
	    safe_device_open(tape, O_RDONLY|m, 0600)) < 0) {
		if (autoload) {
			if (!query_once(msgbuf, 1)) {
				dumpabort();
				/*NOTREACHED*/
			}
		} else {
			if (!query(msgbuf)) {
				dumpabort();
				/*NOTREACHED*/
			}
		}
	}

	if (host) {
		if (rmtstatus(&mt) >= 0 &&
		    rmtioctl(MTREW, 1) >= 0 &&
		    filenum > 1) {
			msg(info, dumpdev, filenum);
			if (rmtioctl(MTFSF, filenum-1) < 0) {
				msg(fail, filenum);
				dumpabort();
				/*NOTREACHED*/
			}
		}
		rmtclose();
	} else {
		if (ioctl(to, MTIOCGET, &mt) >= 0 &&
		    ioctl(to, MTIOCTOP, &rew) >= 0 &&
		    filenum > 1) {
			msg(info, dumpdev, filenum);
			fsf.mt_count = filenum - 1;
			if (ioctl(to, MTIOCTOP, &fsf) < 0) {
				msg(fail, filenum);
				dumpabort();
				/*NOTREACHED*/
			}
		}
		(void) close(to);
		to = -1;
	}

	free(info);
	free(fail);
}

static void
cmdwrterr(void)
{
	int saverr = errno;
	msg(gettext("Error writing command pipe: %s\n"), strerror(saverr));
}

static void
cmdrderr(void)
{
	int saverr = errno;
	msg(gettext("Error reading command pipe: %s\n"), strerror(saverr));
}
