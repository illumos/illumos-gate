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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/* Copyright (c) 1981 Regents of the University of California */

#include <stdio.h>	/* BUFSIZ: stdio = 1024, VMUNIX = 1024 */
#ifndef TRACE
#undef	NULL
#endif

#include "ex.h"
#include "ex_temp.h"
#include "ex_tty.h"
#include "ex_tune.h"
#include <pwd.h>
#include <locale.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>

#define DIRSIZ	MAXNAMLEN

short tfile = -1;	/* ditto */

/*
 *
 * This program searches through the specified directory and then
 * the directory usrpath(preserve) looking for an instance of the specified
 * file from a crashed editor or a crashed system.
 * If this file is found, it is unscrambled and written to
 * the standard output.
 *
 * If this program terminates without a "broken pipe" diagnostic
 * (i.e. the editor doesn't die right away) then the buffer we are
 * writing from is removed when we finish.  This is potentially a mistake
 * as there is not enough handshaking to guarantee that the file has actually
 * been recovered, but should suffice for most cases.
 */

/*
 * This directory definition also appears (obviously) in expreserve.c.
 * Change both if you change either.
 */
unsigned char	mydir[PATH_MAX+1];

/*
 * Limit on the number of printed entries
 * when an, e.g. ``ex -r'' command is given.
 */
#define	NENTRY	50

unsigned char	nb[BUFSIZE];
int	vercnt;			/* Count number of versions of file found */
void rputfile(void);
void rsyserror(void);
void searchdir(unsigned char *);
void scrapbad(void);
void findtmp(unsigned char *);
void listfiles(unsigned char *);

int
main(int argc, char *argv[])
{
	unsigned char string[50];
	unsigned char *cp;
	int c, b, i;
	int rflg = 0, errflg = 0;
	int label;
	line *tmpadr;
	extern unsigned char *mypass();
	struct passwd *pp = getpwuid(getuid());
	unsigned char rmcmd[PATH_MAX+1];

	(void)setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define TEXT_DOMAIN "SYS_TEST"
#endif
	(void)textdomain(TEXT_DOMAIN);
	cp = string;
	strcpy(mydir, USRPRESERVE);
	if (pp == NULL) {
		fprintf(stderr, gettext("Unable to get user's id\n"));
		exit(-1);
	}
	strcat(mydir, pp->pw_name);

	/*
	 * Initialize as though the editor had just started.
	 */
	fendcore = (line *) sbrk(0);
	dot = zero = dol = fendcore;
	one = zero + 1;
	endcore = fendcore - 2;
	iblock = oblock = -1;

	while ((c=getopt(argc, (char **)argv, "rx")) != EOF)
		switch (c) {
			case 'r':
				rflg++;
				break;

			case 'x':
				xflag++;
				break;

			case '?':
				errflg++;
				break;
		}
	argc -= optind;
	argv = &argv[optind];

	if (errflg)
		exit(2);

	/*
	 * If given only a -r argument, then list the saved files.
	 * (NOTE: single -r argument is scheduled to be replaced by -L).
	 */
	if (rflg && argc == 0) {
		fprintf(stderr,"%s:\n", mydir);
		listfiles(mydir);
		fprintf(stderr,"%s:\n", TMPDIR);
		listfiles((unsigned char *)TMPDIR);
		exit(0);
	}

	if (argc != 2)
		error(gettext(" Wrong number of arguments to exrecover"), 0);

	CP(file, argv[1]);

	/*
	 * Search for this file.
	 */
	findtmp((unsigned char *)argv[0]);

	/*
	 * Got (one of the versions of) it, write it back to the editor.
	 */
	(void)cftime((char *)cp, "%a %h %d %T", &H.Time);
	fprintf(stderr, vercnt > 1 ?
		gettext(" [Dated: %s, newest of %d saved]") :
		gettext(" [Dated: %s]"), cp, vercnt);
	fprintf(stderr, "\r\n");

	if(H.encrypted) {
		if(xflag) {
			kflag = run_setkey(perm, (unsigned char *)getenv("CrYpTkEy"));
		} else
			kflag = run_setkey(perm, mypass("Enter key:"));
		if(kflag == -1) {
			kflag = 0;
			xflag = 0;
			fprintf(stderr,gettext("Encryption facility not available\n"));
			exit(-1);
		}
                xtflag = 1;
                if (makekey(tperm) != 0) {
			xtflag = 0;
			fprintf(stderr,gettext("Warning--Cannot encrypt temporary buffer\n"));
			exit(-1);
        	}
	}
	fprintf(stderr,gettext("\r\n [Hit return to continue]"));
	fflush(stderr);
	setbuf(stdin, (char *)NULL);
	while((c = getchar()) != '\n' && c != '\r');
	H.Flines++;

	/*
	 * Allocate space for the line pointers from the temp file.
	 */
	if ((int) sbrk((int) (H.Flines * sizeof (line))) == -1)
		error(gettext(" Not enough core for lines"), 0);
#ifdef DEBUG
	fprintf(stderr, "%d lines\n", H.Flines);
#endif

	/*
	 * Now go get the blocks of seek pointers which are scattered
	 * throughout the temp file, reconstructing the incore
	 * line pointers at point of crash.
	 */
	b = 0;
	while (H.Flines > 0) {
		(void)lseek(tfile, (long) blocks[b] * BUFSIZE, 0);
		i = H.Flines < BUFSIZE / sizeof (line) ?
			H.Flines * sizeof (line) : BUFSIZE;
		if (read(tfile, (char *) dot, i) != i) {
			perror((char *)nb);
			exit(1);
		}
		dot += i / sizeof (line);
		H.Flines -= i / sizeof (line);
		b++;
	}
	dot--; dol = dot;

	/*
	 * Due to sandbagging some lines may really not be there.
	 * Find and discard such.  This shouldn't happen often.
	 */
	scrapbad();


	/*
	 * Now if there were any lines in the recovered file
	 * write them to the standard output.
	 */
	if (dol > zero) {
		addr1 = one; addr2 = dol; io = 1;
		rputfile();
	}
	/*
	 * Trash the saved buffer.
	 * Hopefully the system won't crash before the editor
	 * syncs the new recovered buffer; i.e. for an instant here
	 * you may lose if the system crashes because this file
	 * is gone, but the editor hasn't completed reading the recovered
	 * file from the pipe from us to it.
	 *
	 * This doesn't work if we are coming from an non-absolute path
	 * name since we may have chdir'ed but what the hay, noone really
	 * ever edits with temporaries in "." anyways.
	 */
	if (nb[0] == '/') {
		(void)unlink((const char *)nb);
		sprintf((char *)rmcmd, "rmdir %s 2> /dev/null", (char *)mydir);
		system((char *)rmcmd);
	}
	return (0);
}

/*
 * Print an error message (notably not in error
 * message file).  If terminal is in RAW mode, then
 * we should be writing output for "vi", so don't print
 * a newline which would mess up the screen.
 */
/*VARARGS2*/
void
error(str, inf)
	unsigned char *str;
	int inf;
{

	struct termio termio;
	if (inf)
		fprintf(stderr, (char *)str, inf);
	else
		fprintf(stderr, (char *)str);

	ioctl(2, TCGETA, &termio);
	if (termio.c_lflag & ICANON)
		fprintf(stderr, "\n");
	exit(1);
}

/*
 * Here we save the information about files, when
 * you ask us what files we have saved for you.
 * We buffer file name, number of lines, and the time
 * at which the file was saved.
 */
struct svfile {
	unsigned char	sf_name[FNSIZE + 1];
	int	sf_lines;
	unsigned char	sf_entry[DIRSIZ + 1];
	time_t	sf_time;
	short	sf_encrypted;
};
void enter(struct svfile *, unsigned char *, int);

void
listfiles(unsigned char *dirname)
{
	DIR *dir;
	struct dirent64 *direntry;
	int ecount, qucmp();
	int f;
	unsigned char cp[50];
	unsigned char cp2[50];
	unsigned char *filname;
	struct svfile *fp, svbuf[NENTRY];

	/*
	 * Open usrpath(preserve), and go there to make things quick.
	 */
	if ((dir = opendir((char *)dirname)) == NULL)
	{
		fprintf(stderr,gettext("No files saved.\n"));
		return;
	}
	if (chdir((const char *)dirname) < 0) {
		perror((char *)dirname);
		return;
	}

	/*
	 * Look at the candidate files in usrpath(preserve).
	 */
	fp = &svbuf[0];
	ecount = 0;
	while ((direntry = readdir64(dir)) != NULL)
	{
		filname = (unsigned char *)direntry->d_name;
		if (filname[0] != 'E')
			continue;
#ifdef DEBUG
		fprintf(stderr, "considering %s\n", filname);
#endif
		/*
		 * Name begins with E; open it and
		 * make sure the uid in the header is our uid.
		 * If not, then don't bother with this file, it can't
		 * be ours.
		 */
		f = open(filname, 0);
		if (f < 0) {
#ifdef DEBUG
			fprintf(stderr, "open failed\n");
#endif
			continue;
		}
		if (read(f, (char *) &H, sizeof H) != sizeof H) {
#ifdef DEBUG
			fprintf(stderr, "could not read header\n");
#endif
			(void)close(f);
			continue;
		}
		(void)close(f);
		if (getuid() != H.Uid) {
#ifdef DEBUG
			fprintf(stderr, "uid wrong\n");
#endif
			continue;
		}

		/*
		 * Saved the day!
		 */
		enter(fp++, filname, ecount);
		ecount++;
#ifdef DEBUG
		fprintf(stderr, "entered file %s\n", filname);
#endif
	}
	(void)closedir(dir);
	/*
	 * If any files were saved, then sort them and print
	 * them out.
	 */
	if (ecount == 0) {
		fprintf(stderr, gettext("No files saved.\n"));
		return;
	}
	qsort(&svbuf[0], ecount, sizeof svbuf[0], qucmp);
	for (fp = &svbuf[0]; fp < &svbuf[ecount]; fp++) {
		(void)cftime((char *)cp, "%a %b %d", &fp->sf_time);
		(void)cftime((char *)cp2, "%R", &fp->sf_time);
		fprintf(stderr,
		    gettext("On %s at %s, saved %d lines of file \"%s\" "),
		    cp, cp2, fp->sf_lines, fp->sf_name);
		fprintf(stderr, "%s\n",
		    (fp->sf_encrypted) ? gettext("[ENCRYPTED]") : "");
	}
}

/*
 * Enter a new file into the saved file information.
 */
void
enter(struct svfile *fp, unsigned char *fname, int count)
{
	unsigned char *cp, *cp2;
	struct svfile *f, *fl;
	time_t curtime;

	f = 0;
	if (count >= NENTRY) {
	        /*
		 * Trash the oldest as the most useless.
		 */
		fl = fp - count + NENTRY - 1;
		curtime = fl->sf_time;
		for (f = fl; --f > fp-count; )
			if (f->sf_time < curtime)
				curtime = f->sf_time;
		for (f = fl; --f > fp-count; )
			if (f->sf_time == curtime)
				break;
		fp = f;
	}

	/*
	 * Gotcha.
	 */
	fp->sf_time = H.Time;
	fp->sf_lines = H.Flines;
	fp->sf_encrypted = H.encrypted;
	for (cp2 = fp->sf_name, cp = savedfile; *cp;)
		*cp2++ = *cp++;
	*cp2++ = 0;
	for (cp2 = fp->sf_entry, cp = fname; *cp && cp-fname < 14;)
		*cp2++ = *cp++;
	*cp2++ = 0;
}

/*
 * Do the qsort compare to sort the entries first by file name,
 * then by modify time.
 */
int
qucmp(struct svfile *p1, struct svfile *p2)
{
	int t;

	if (t = strcmp(p1->sf_name, p2->sf_name))
		return(t);
	if (p1->sf_time > p2->sf_time)
		return(-1);
	return(p1->sf_time < p2->sf_time);
}

/*
 * Scratch for search.
 */
unsigned char	bestnb[BUFSIZE];		/* Name of the best one */
long	besttime = 0;		/* Time at which the best file was saved */
int	bestfd;			/* Keep best file open so it dont vanish */

/*
 * Look for a file, both in the users directory option value
 * (i.e. usually /tmp) and in usrpath(preserve).
 * Want to find the newest so we search on and on.
 */
void
findtmp(unsigned char *dir)
{

	/*
	 * No name or file so far.
	 */
	bestnb[0] = 0;
	bestfd = -1;

	/*
	 * Search usrpath(preserve) and, if we can get there, /tmp
	 * (actually the user's "directory" option).
	 */
	searchdir(dir);
	if (chdir((const char *)mydir) == 0)
		searchdir(mydir);
	if (bestfd != -1) {
		/*
		 * Gotcha.
		 * Put the file (which is already open) in the file
		 * used by the temp file routines, and save its
		 * name for later unlinking.
		 */
		tfile = bestfd;
		CP(nb, bestnb);
		(void)lseek(tfile, 0l, 0);

		/*
		 * Gotta be able to read the header or fall through
		 * to lossage.
		 */
		if (read(tfile, (char *) &H, sizeof H) == sizeof H)
			return;
	}

	/*
	 * Extreme lossage...
	 */
	error((unsigned char *)gettext(" File not found"), 0);
}

/*
 * Search for the file in directory dirname.
 *
 * Don't chdir here, because the users directory
 * may be ".", and we would move away before we searched it.
 * Note that we actually chdir elsewhere (because it is too slow
 * to look around in usrpath(preserve) without chdir'ing there) so we
 * can't win, because we don't know the name of '.' and if the path
 * name of the file we want to unlink is relative, rather than absolute
 * we won't be able to find it again.
 */
void
searchdir(unsigned char *dirname)
{
	struct dirent64 *direntry;
	DIR *dir;
	unsigned char dbuf[BUFSIZE];
	unsigned char *filname;
	if ((dir = opendir((char *)dirname)) == NULL)
		return;
	while ((direntry = readdir64(dir)) != NULL)
	{
		filname = (unsigned char *)direntry->d_name;
		if (filname[0] != 'E' || filname[1] != 'x')
			continue;
		/*
		 * Got a file in the directory starting with Ex...
		 * Save a consed up name for the file to unlink
		 * later, and check that this is really a file
		 * we are looking for.
		 */
		(void)strcat(strcat(strcpy(nb, dirname), "/"), filname);
		if (yeah(nb)) {
			/*
			 * Well, it is the file we are looking for.
			 * Is it more recent than any version we found before?
			 */
			if (H.Time > besttime) {
				/*
				 * A winner.
				 */
				(void)close(bestfd);
				bestfd = dup(tfile);
				besttime = H.Time;
				CP(bestnb, nb);
			}
			/*
			 * Count versions and tell user
			 */
			vercnt++;
		}
		(void)close(tfile);
	}
	(void)closedir(dir);
}

/*
 * Given a candidate file to be recovered, see
 * if it's really an editor temporary and of this
 * user and the file specified.
 */
int
yeah(unsigned char *name)
{

	tfile = open(name, 2);
	if (tfile < 0)
		return (0);
	if (read(tfile, (char *) &H, sizeof H) != sizeof H) {
nope:
		(void)close(tfile);
		return (0);
	}
	if (!eq(savedfile, file))
		goto nope;
	if (getuid() != H.Uid)
		goto nope;
	/*
	 * Old code: puts a word LOST in the header block, so that lost lines
	 * can be made to point at it.
	 */
	(void)lseek(tfile, (long)(BUFSIZE*HBLKS-8), 0);
	(void)write(tfile, "LOST", 5);
	return (1);
}

/*
 * Find the true end of the scratch file, and ``LOSE''
 * lines which point into thin air.  This lossage occurs
 * due to the sandbagging of i/o which can cause blocks to
 * be written in a non-obvious order, different from the order
 * in which the editor tried to write them.
 *
 * Lines which are lost are replaced with the text LOST so
 * they are easy to find.  We work hard at pretty formatting here
 * as lines tend to be lost in blocks.
 *
 * This only seems to happen on very heavily loaded systems, and
 * not very often.
 */
void
scrapbad(void)
{
	line *ip;
	struct stat64 stbuf;
	off_t size, maxt;
	int bno, cnt, bad, was;
	unsigned char bk[BUFSIZE];

	(void)fstat64(tfile, &stbuf);
	size = (off_t)stbuf.st_size;
	maxt = (size >> SHFT) | (BNDRY-1);
	bno = (maxt >> OFFBTS) & BLKMSK;
#ifdef DEBUG
	fprintf(stderr, "size %ld, maxt %o, bno %d\n", size, maxt, bno);
#endif

	/*
	 * Look for a null separating two lines in the temp file;
	 * if last line was split across blocks, then it is lost
	 * if the last block is.
	 */
	while (bno > 0) {
		(void)lseek(tfile, (long) BUFSIZE * bno, 0);
		cnt = read(tfile, (char *) bk, BUFSIZE);
	if(xtflag)
		if (run_crypt(0L, bk, CRSIZE, tperm) == -1)
		    rsyserror();
#ifdef DEBUG
	fprintf(stderr,"UNENCRYPTED: BLK %d\n",bno);
#endif
		while (cnt > 0)
			if (bk[--cnt] == 0)
				goto null;
		bno--;
	}
null:

	/*
	 * Magically calculate the largest valid pointer in the temp file,
	 * consing it up from the block number and the count.
	 */
	maxt = ((bno << OFFBTS) | (cnt >> SHFT)) & ~1;
#ifdef DEBUG
	fprintf(stderr, "bno %d, cnt %d, maxt %o\n", bno, cnt, maxt);
#endif

	/*
	 * Now cycle through the line pointers,
	 * trashing the Lusers.
	 */
	was = bad = 0;
	for (ip = one; ip <= dol; ip++)
		if (*ip > maxt) {
#ifdef DEBUG
			fprintf(stderr, "%d bad, %o > %o\n", ip - zero, *ip, maxt);
#endif
			if (was == 0)
				was = ip - zero;
			*ip = ((HBLKS*BUFSIZE)-8) >> SHFT;
		} else if (was) {
			if (bad == 0)
				fprintf(stderr, gettext(" [Lost line(s):"));
			fprintf(stderr, " %d", was);
			if ((ip - 1) - zero > was)
				fprintf(stderr, "-%d", (ip - 1) - zero);
			bad++;
			was = 0;
		}
	if (was != 0) {
		if (bad == 0)
			fprintf(stderr, " [Lost line(s):");
		fprintf(stderr, " %d", was);
		if (dol - zero != was)
			fprintf(stderr, "-%d", dol - zero);
		bad++;
	}
	if (bad)
		fprintf(stderr, "]");
}

int	cntch, cntln, cntodd, cntnull;
/*
 * Following routines stolen mercilessly from ex.
 */
void
rputfile(void)
{
	line *a1;
	unsigned char *fp, *lp;
	int nib;

	a1 = addr1;
	clrstats();
	cntln = addr2 - a1 + 1;
	if (cntln == 0)
		return;
	nib = BUFSIZE;
	fp = genbuf;
	do {
#ifdef DEBUG
		fprintf(stderr,"GETTING A LINE \n");
#endif
		getaline(*a1++);
		lp = linebuf;
#ifdef DEBUG
		fprintf(stderr,"LINE:%s\n",linebuf);
#endif
		for (;;) {
			if (--nib < 0) {
				nib = fp - genbuf;
				if (write(io, genbuf, nib) != nib)
					wrerror();
				cntch += nib;
				nib = BUFSIZE;
				fp = genbuf;
			}
			if ((*fp++ = *lp++) == 0) {
				fp[-1] = '\n';
				break;
			}
		}
	} while (a1 <= addr2);
	nib = fp - genbuf;
	if (write(io, genbuf, nib) != nib)
		wrerror();
	cntch += nib;
}

void
wrerror(void)
{

	rsyserror();
}

void
clrstats(void)
{

	ninbuf = 0;
	cntch = 0;
	cntln = 0;
	cntnull = 0;
	cntodd = 0;
}

#define	READ	0
#define	WRITE	1

void
getaline(line tl)
{
	unsigned char *bp, *lp;
	int nl;

	lp = linebuf;
	bp = getblock(tl);
	nl = nleft;
	tl &= ~OFFMSK;
	while (*lp++ = *bp++)
		if (--nl == 0) {
			bp = getblock(tl += INCRMT);
			nl = nleft;
		}
}

int	read();
int	write();

unsigned char *
getblock(atl)
	line atl;
{
	int bno, off;
        unsigned char *p1, *p2;
        int n;

	bno = (atl >> OFFBTS) & BLKMSK;
#ifdef DEBUG
	fprintf(stderr,"GETBLOCK: BLK %d\n",bno);
#endif
	off = (atl << SHFT) & LBTMSK;
	if (bno >= NMBLKS)
		error((unsigned char *)gettext(" Tmp file too large"));
	nleft = BUFSIZE - off;
	if (bno == iblock)
		return (ibuff + off);
	iblock = bno;
	blkio(bno, ibuff, read);
	if(xtflag)
		if (run_crypt(0L, ibuff, CRSIZE, tperm) == -1)
		    rsyserror();
#ifdef DEBUG
	fprintf(stderr,"UNENCRYPTED: BLK %d\n",bno);
#endif
	return (ibuff + off);
}

void
blkio(short b, unsigned char *buf, int (*iofcn)())
{

	int rc;
	lseek(tfile, (long) (unsigned) b * BUFSIZE, 0);
	if ((rc =(*iofcn)(tfile, buf, BUFSIZE)) != BUFSIZE) {
		(void)fprintf(stderr,gettext("Failed on BLK: %d with %d/%d\n"),b,rc,BUFSIZE);
		perror("");
		rsyserror();
	}
}

void
rsyserror(void)
{
	int save_err = errno;

	dirtcnt = 0;
	write(2, " ", 1);
	error(strerror(save_err));
	exit(1);
}

static int intrupt;

static void catch();

unsigned char *
mypass(prompt)
unsigned char	*prompt;
{
	struct termio ttyb;
	unsigned short flags;
	unsigned char *p;
	int c;
	static unsigned char pbuf[9];
	void	(*sig)();

	setbuf(stdin, (char*)NULL);
	sig = signal(SIGINT, catch);
	intrupt = 0;
	(void) ioctl(fileno(stdin), TCGETA, &ttyb);
	flags = ttyb.c_lflag;
	ttyb.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
	(void) ioctl(fileno(stdin), TCSETAF, &ttyb);
	(void) fputs((char *)prompt, stderr);
	for(p=pbuf; !intrupt && (c = getc(stdin)) != '\n' && c!= '\r' && c != EOF; ) {
		if(p < &pbuf[8])
			*p++ = c;
	}
	*p = '\0';
	(void) putc('\n', stderr);
	ttyb.c_lflag = flags;
	(void) ioctl(fileno(stdin), TCSETA, &ttyb);
	(void) signal(SIGINT, sig);
	if(intrupt)
		(void) kill(getpid(), SIGINT);
	return(pbuf);
}

static void
catch()
{
	++intrupt;
}
