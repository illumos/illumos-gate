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

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef _DUMP_H
#define	_DUMP_H

#include <stdio.h>
#include <locale.h>
#include <sys/types.h>
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <fcntl.h>
#include <utmpx.h>
#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include <sys/param.h>	/* for MAXBSIZE */
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/vnode.h>	/* needed by inode.h */
#include <setjmp.h>
#include <sys/mman.h>
#include <assert.h>
#include <dumpusg.h>
#include <kstat.h>
#include <sys/fssnap_if.h>
#include <libgen.h>
#include <limits.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	SUPPORTS_MTB_TAPE_FORMAT
#include <protocols/dumprestore.h>
#include <memutils.h>
#include <note.h>

#define	NI		16
#define	MAXINOPB	(MAXBSIZE / sizeof (struct dinode))
#define	MAXNINDIR	(MAXBSIZE / sizeof (daddr32_t))

#ifndef roundup
#define	roundup(x, y)	((((x)+((y)-1))/(y))*(y))
#endif
#ifndef MIN
#define	MIN(a, b)	(((a) < (b)) ? (a) : (b))
#endif
#ifndef MAX
#define	MAX(a, b)	(((a) > (b)) ? (a) : (b))
#endif

/*
 * Define an overflow-free version of howmany so that we don't
 * run into trouble with large files.
 */
#define	d_howmany(x, y)	((x) / (y) + ((x) % (y) != 0))

#define	MWORD(m, i)	(m[(ino_t)(i-1)/NBBY])
#define	MBIT(i)		((1<<((ino_t)(i-1)%NBBY))&0xff)
#define	BIS(i, w)	(MWORD(w, i) |= MBIT(i))
#define	BIC(i, w)	(MWORD(w, i) &= ~MBIT(i))
#define	BIT(i, w)	(MWORD(w, i) & MBIT(i))

extern uint_t	msiz;
extern uchar_t	*clrmap;
extern uchar_t	*dirmap;
extern uchar_t	*filmap;
extern uchar_t	*nodmap;
extern uchar_t	*shamap;
extern uchar_t	*activemap;

/*
 *	All calculations done in 0.1" units!
 */

extern char	*disk;		/* name of the disk file */
extern char	*dname;		/* name to put in /etc/dumpdates */
extern int	disk_dynamic;	/* true if disk refers to dynamic storage */
extern char	*tape;		/* name of the tape file */
extern char	*host;	/* name of the remote tape host (may be "user@host") */
extern char	*dumpdev;	/* hostname:device for current volume */
extern char	*sdumpdev; /* short form of dumpdev (no user name if remote) */
extern char	*increm; /* name of file containing incremental information */
extern char	*filesystem;	/* name of the file system */
extern char	*myname;	/* argv[0] without leading path components */
extern char	lastincno;	/* increment number of previous dump */
extern char	incno;		/* increment number */
extern char	*tlabel;	/* what goes in tape header c_label field */
extern int	uflag;		/* update flag */
extern int	fi;		/* disk file descriptor */
extern int	to;		/* tape file descriptor */
extern int	mapfd;		/* block disk device descriptor for mmap */
extern int	pipeout;	/* true => output to standard output */
extern int	tapeout;	/* true => output to a tape drive */
extern ino_t	ino;		/* current inumber; used globally */
extern off_t	pos;		/* starting offset within ino; used globally */
extern int	leftover; /* number of tape recs left over from prev vol */
extern int	nsubdir;	/* counts subdirs, for deciding to dump a dir */
extern int	newtape;	/* new tape flag */
extern int	nadded;		/* number of added sub directories */
extern int	dadded;		/* directory added flag */
extern int	density;	/* density in 0.1" units */
extern ulong_t	tsize;		/* tape size in 0.1" units */
extern u_offset_t esize;	/* estimated tape size, blocks */
extern u_offset_t o_esize;	/* number of header blocks (overhead) */
extern u_offset_t f_esize;	/* number of TP_BSIZE blocks for files/maps */
extern uint_t	etapes;		/* estimated number of tapes */
extern uint_t	ntrec;		/* 1K records per tape block */
extern int	tenthsperirg;	/* 1/10" per tape inter-record gap */
extern dev_t	partial_dev;	/* id of BLOCK device used in partial mode */
extern pid_t	dumppid;	/* process-ID of top-level process */

extern int	verify;		/* verify each volume */
extern int	doingverify;	/* true => doing a verify pass */
extern int	active;		/* recopy active files */
extern int	doingactive;	/* true => redumping active files */
extern int	archive;	/* true => saving a archive in archivefile */
extern char	*archivefile;	/* name of archivefile */
extern int	archive_opened;	/* have opened/created the archivefile */
extern int	notify;		/* notify operator flag */
extern int	diskette;	/* true if dumping to a diskette */
extern int	cartridge;	/* true if dumping to a cartridge tape */
extern uint_t	tracks;		/* number of tracks on a cartridge tape */
extern int	printsize;	/* just print estimated size and exit */
extern int	offline;	/* take tape offline after rewinding */
extern int	autoload; /* wait for next tape to autoload; implies offline */
extern int	autoload_tries;	/* number of times to check on autoload */
extern int	autoload_period; /* seconds, tries*period = total wait time */
extern int	doposition;	/* move to specified... */
extern daddr32_t filenum;	/* position of dump on 1st volume */
extern int	dumpstate;	/* dump output state (see below) */
extern int	dumptoarchive;	/* mark records to be archived */

extern int	blockswritten;	/* number of blocks written on current tape */
extern uint_t	tapeno;		/* current tape number */

extern struct fs *sblock;	/* the file system super block */
extern int	shortmeta;	/* current file has small amount of metadata */
extern union u_shadow c_shadow_save[1];

extern time_t	*telapsed;	/* time spent writing previous tapes */
extern time_t	*tstart_writing; /* when we started writing the latest tape */
extern time_t	*tschedule; /* when next to give a remaining-time estimate */

extern char	*debug_chdir;	/* non-NULL means to mkdir this/pid, */
			/* and chdir there, once for each separate child */

/*
 * Defines for the msec part of
 * inode-based times, since we're
 * not part of the kernel.
 */
#define	di_atspare	di_ic.ic_atspare
#define	di_mtspare	di_ic.ic_mtspare
#define	di_ctspare	di_ic.ic_ctspare

#define	HOUR	(60L*60L)
#define	DAY	(24L*HOUR)
#define	YEAR	(365L*DAY)

/*
 *	Dump output states
 */
#define	DS_INIT		0
#define	DS_START	1
#define	DS_CLRI		2
#define	DS_BITS		3
#define	DS_DIRS		4
#define	DS_FILES	5
#define	DS_END		6
#define	DS_DONE		7

/*
 *	Exit status codes
 */
#define	X_FINOK		0	/* normal exit */
#define	X_REWRITE	2	/* restart writing from the check point */
#define	X_ABORT		3	/* abort all of dump; no checkpoint restart */
#define	X_VERIFY	4	/* verify the reel just written */
#define	X_RESTART	5	/* abort all progress so far; attempt restart */

#define	NINCREM	"/etc/dumpdates"	/* new format incremental info */

#define	TAPE	"/dev/rmt/0b"		/* default tape device */
#define	OPGRENT	"sys"			/* group entry to notify */
#define	DIALUP	"ttyd"			/* prefix for dialups */

#define	DISKETTE	"/dev/rfd0c"

#define	NBUF		64		/* number of output buffers */
#define	MAXNTREC	256		/* max tape blocking factor (in Kb) */

/*
 *	The contents of the file NINCREM are maintained both on
 *	a linked list and then (eventually) arrayified.
 */
struct	idates {
	char	id_name[MAXNAMLEN+3];
	char	id_incno;
	time32_t id_ddate;
};

extern size_t	nidates;		/* number of records (might be zero) */
extern struct	idates	**idatev;	/* the arrayfied version */
#define	ITITERATE(i, ip)	\
	for (i = 0; i < nidates && (ip = idatev[i]) != NULL; i++)

/*
 * Function declarations
 */
#ifdef __STDC__
/*
 * dumpfstab.c
 */
extern void mnttabread(void);
extern struct mntent *mnttabsearch(char *, int);
extern void setmnttab(void);
extern struct mntent *getmnttab(void);
/*
 * dumpitime.c
 */
extern char *prdate(time_t);
extern void inititimes(void);
extern void getitime(void);
extern void putitime(void);
extern void est(struct dinode *);
extern time32_t is_fssnap_dump(char *);
extern void bmapest(uchar_t *);
/*
 * dumplabel.c
 */
extern void getlabel(void);
/*
 * dumpmain.c
 */
extern void child_chdir(void);
extern char *unrawname(char *);
extern void sigAbort(int);
extern char *rawname(char *);
extern char *lf_rawname(char *);
extern time32_t timeclock(time32_t);
#ifdef signal
extern void (*nsignal(int, void (*)(int)))(int);
#endif
extern int safe_file_open(const char *file, int mode, int perms);
extern int safe_device_open(const char *file, int mode, int perms);
extern FILE *safe_fopen(const char *filename, const char *smode, int perms);
/*
 * dumponline.c
 */
extern void allocino(void);
extern void freeino(void);
extern void saveino(ino_t, struct dinode *);
extern void resetino(ino_t);
extern long getigen(ino_t);
extern int lf_ismounted(char *, char *);
extern int isoperator(uid_t, gid_t);
extern int lockfs(char *, char *);
extern int openi(ino_t, long, char *);
extern caddr_t mapfile(int, off_t, off_t, int);
extern void unmapfile(void);
extern void stattoi(struct stat *, struct dinode *);
extern void dumpfile(int, caddr_t, off_t, off_t, off_t, int, int);
extern void activepass(void);
/*
 * dumpoptr.c
 */
extern int query(char *);
extern int query_once(char *, int);
extern void interrupt(int);
extern void broadcast(char *);
extern void timeest(int, int);
/*PRINTFLIKE1*/
extern void msg(const char *, ...);
/*PRINTFLIKE1*/
extern void msgtail(const char *, ...);
extern void lastdump(int);
extern char *getresponse(char *, char *);
/*
 * dumptape.c
 */
extern void alloctape(void);
extern void reset(void);
extern void spclrec(void);
extern void taprec(uchar_t *, int, int);
extern void dmpblk(daddr32_t, size_t, off_t);
extern void toslave(void (*)(ino_t), ino_t);
extern void doinode(ino_t);
extern void dospcl(ino_t);
extern void flushcmds(void);
extern void flusht(void);
extern void nextdevice(void);
extern int isrewind(int);
extern void trewind(void);
extern void close_rewind(void);
extern void changevol(void);
extern void otape(int);
extern void dumpabort(void);
extern void dumpailing(void);
extern void Exit(int);
extern void positiontape(char *);
/*
 * dumptraverse.c
 */
extern void pass(void (*)(struct dinode *), uchar_t *);
extern void mark(struct dinode *);
extern void active_mark(struct dinode *);
extern void markshad(struct dinode *);
extern void estshad(struct dinode *);
extern void freeshad();
extern void add(struct dinode *);
extern void dirdump(struct dinode *);
extern void dump(struct dinode *);
extern void lf_dump(struct dinode *);
extern void dumpblocks(ino_t);
extern void bitmap(uchar_t *, int);
extern struct dinode *getino(ino_t);
extern void bread(diskaddr_t, uchar_t *, size_t);
extern int hasshortmeta(struct dinode **ip);
/*
 * lftw.c
 */
extern int lftw(const char *,
	int (*)(const char *, const struct stat *, int), int);
extern int lf_lftw(const char *,
	int (*)(const char *, const struct stat64 *, int), int);
/*
 * partial.c
 */
extern void partial_check(void);
extern void lf_partial_check(void);
extern int partial_mark(int, char **);
/*
 * unctime.c
 */
extern time_t unctime(char *);
#else	/* !STDC */
/*
 * dumpfstab.c
 */
extern void mnttabread();
extern struct mntent *mnttabsearch();
extern void setmnttab();
extern struct mntent *getmnttab();
/*
 * dumpitime.c
 */
extern char *prdate();
extern void inititimes();
extern void getitime();
extern void putitime();
extern void est();
extern time32_t is_fssnap_dump();
extern void bmapest();
/*
 * dumplabel.c
 */
extern void getlabel();
/*
 * dumpmain.c
 */
extern void child_chdir();
extern char *unrawname();
extern void sigAbort();
extern char *rawname();
extern char *lf_rawname();
extern time_t timeclock();
#ifdef signal
extern void nsignal();
#endif
extern int safe_file_open();
extern int safe_device_open();
extern FILE *safe_fopen();
/*
 * dumponline.c
 */
extern void allocino();
extern void freeino();
extern void saveino();
extern void resetino();
extern long getigen();
extern int lf_ismounted();
extern int isoperator();
extern ulong_t lockfs();
extern int openi();
extern caddr_t mapfile();
extern void unmapfile();
extern void stattoi();
extern void dumpfile();
extern void activepass();
/*
 * dumpoptr.c
 */
extern int query();
extern int query_once();
extern void interrupt();
extern void broadcast();
extern void timeest();
extern void msg();
extern void msgtail();
extern void lastdump();
extern char *getresponse();
/*
 * dumptape.c
 */
extern void alloctape();
extern void reset();
extern void spclrec();
extern void taprec();
extern void dmpblk();
extern void toslave();
extern void doinode();
extern void dospcl();
extern void flushcmds();
extern void flusht();
extern void nextdevice();
extern int isrewind();
extern void trewind();
extern void close_rewind();
extern void changevol();
extern void otape();
extern void dumpabort();
extern void dumpailing();
extern void Exit();
extern void positiontape();
/*
 * dumptraverse.c
 */
extern void pass();
extern void mark();
extern void active_mark();
extern void markshad();
extern void estshad();
extern void freeshad();
extern void add();
extern void dirdump();
extern void dump();
extern void lf_dump();
extern void dumpblocks();
extern void bitmap();
extern struct dinode *getino();
extern void bread();
extern int hasshortmeta();
/*
 * lftw.c
 */
extern int lftw();
extern int lf_lftw();
/*
 * partial.c
 */
extern void partial_check();
extern void lf_partial_check();
extern int partial_mark();
/*
 * unctime.c
 */
extern time_t unctime();
#endif /* __STDC__ */

/* Insufficiently-featureful system header files... */
NOTE(ALIGNMENT(mmap, 8))


#ifdef	__cplusplus
}
#endif

#endif /* _DUMP_H */
