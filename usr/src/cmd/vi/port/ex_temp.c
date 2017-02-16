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

#include "ex.h"
#include "ex_temp.h"
#include "ex_vis.h"
#include "ex_tty.h"
#include <unistd.h>

/*
 * Editor temporary file routines.
 * Very similar to those of ed, except uses 2 input buffers.
 */
#define	READ	0
#define	WRITE	1

unsigned char	tfname[PATH_MAX+1];
static unsigned char	rfname[PATH_MAX+1];
static unsigned char	tempname[PATH_MAX+1];
int	havetmp;
short	tfile = -1;
static short	rfile = -1;

extern int junk();

void
fileinit(void)
{
	unsigned char *p;
	pid_t j;
	int i;
	struct stat64 stbuf;

	if (tline == INCRMT * (HBLKS+2))
		return;
	cleanup(0);
	if (tfile != -1)
		close(tfile);
	tline = INCRMT * (HBLKS+2);
	blocks[0] = HBLKS;
	blocks[1] = HBLKS+1;
	blocks[2] = -1;
	dirtcnt = 0;
	iblock = -1;
	iblock2 = -1;
	oblock = -1;
	if (strlen(svalue(vi_DIRECTORY)) > (PATH_MAX -13))
		error(gettext("User set directory too long"));
	CP(tfname, svalue(vi_DIRECTORY));
	if (stat64((char *)tfname, &stbuf)) {
dumbness:
		if (setexit() == 0)
			filioerr(tfname);
		else
			putNFL();
		cleanup(1);
		exit(++errcnt);
	}
	if (!ISDIR(stbuf)) {
		errno = ENOTDIR;
		goto dumbness;
	}
	CP(tempname, tfname);
	ichanged = 0;
	ichang2 = 0;
	(void) strcat(tfname, "/ExXXXXXX");
	if ((tfile = mkstemp((char *)tfname)) < 0)
		goto dumbness;
#ifdef VMUNIX
	{
		extern int stilinc;		/* see below */
		stilinc = 0;
	}
#endif
	havetmp = 1;
/* 	brk((unsigned char *)fendcore); */
}

void
cleanup(bool all)
{
	pid_t pgrp;
	if (all) {
		if (kflag)
			crypt_close(perm);
		if (xtflag)
			crypt_close(tperm);
		putpad((unsigned char *)exit_ca_mode);
		flush();
		if (ioctl(2, TIOCGPGRP, &pgrp) == 0) {
			if (pgrp == getpgid(0)) {
#ifdef XPG4
				if (envlines != -1 || envcolumns != -1) {
					struct winsize jwin;
					jwin.ws_row = oldlines;
					jwin.ws_col = oldcolumns;
					ioctl(0, TIOCSWINSZ, &jwin);
				}
#endif /* XPG4 */
				resetterm();
				normtty--;
			}
		} else {
#ifdef XPG4
			if (envlines != -1 || envcolumns != -1) {
				struct winsize jwin;
				jwin.ws_row = oldlines;
				jwin.ws_col = oldcolumns;
				ioctl(0, TIOCSWINSZ, &jwin);
			}
#endif /* XPG4 */
			resetterm();
			normtty--;
		}
	}
	if (havetmp)
		unlink((char *)tfname);
	havetmp = 0;
	if (all && rfile >= 0) {
		unlink((char *)rfname);
		close(rfile);
		rfile = -1;
	}
	if (all == 1)
		exit(errcnt);
}

void
getaline(line tl)
{
	unsigned char *bp, *lp;
	int nl;

	lp = linebuf;
	bp = getblock(tl, READ);
	nl = nleft;
	tl &= ~OFFMSK;
	while (*lp++ = *bp++)
		if (--nl == 0) {
			bp = getblock(tl += INCRMT, READ);
			nl = nleft;
		}
}

int
putline(void)
{
	unsigned char *bp, *lp;
	unsigned char tmpbp;
	int nl;
	line tl;

	dirtcnt++;
	lp = linebuf;
	change();
	tl = tline;
	bp = getblock(tl, WRITE);
	nl = nleft;
	tl &= ~OFFMSK;
	while (*bp = *lp++) {
		tmpbp = *bp;
		if (tmpbp == '\n') {
			*bp = 0;
			linebp = lp;
			break;
		} else if (junk(*bp++)) {
			checkjunk(tmpbp);
			*--bp;
		}
		if (--nl == 0) {
			bp = getblock(tl += INCRMT, WRITE);
			nl = nleft;
		}
	}
	tl = tline;
	tline += (((lp - linebuf) + BNDRY - 1) >> SHFT) & 077776;
	return (tl);
}

int	read();
int	write();

unsigned char *
getblock(line atl, int iof)
{
	int bno, off;
	unsigned char *p1, *p2;
	int n;
	line *tmpptr;

	bno = (atl >> OFFBTS) & BLKMSK;
	off = (atl << SHFT) & LBTMSK;
	if (bno >= NMBLKS) {
		/*
		 * When we overflow tmpfile buffers,
		 * throw away line which could not be
		 * put into buffer.
		 */
		for (tmpptr = dot; tmpptr < unddol; tmpptr++)
			*tmpptr = *(tmpptr+1);
		if (dot == dol)
			dot--;
		dol--;
		unddol--;
		error(gettext(" Tmp file too large"));
	}
	nleft = BUFSIZE - off;
	if (bno == iblock) {
		ichanged |= iof;
		hitin2 = 0;
		return (ibuff + off);
	}
	if (bno == iblock2) {
		ichang2 |= iof;
		hitin2 = 1;
		return (ibuff2 + off);
	}
	if (bno == oblock)
		return (obuff + off);
	if (iof == READ) {
		if (hitin2 == 0) {
			if (ichang2) {
				if (xtflag) {
					if (run_crypt(0L, ibuff2,
					    CRSIZE, tperm) == -1) {
						filioerr(tfname);
					}
				}
				blkio(iblock2, ibuff2, write);
			}
			ichang2 = 0;
			iblock2 = bno;
			blkio(bno, ibuff2, read);
			if (xtflag)
				if (run_crypt(0L, ibuff2, CRSIZE, tperm) == -1)
					filioerr(tfname);
			hitin2 = 1;
			return (ibuff2 + off);
		}
		hitin2 = 0;
		if (ichanged) {
			if (xtflag)
				if (run_crypt(0L, ibuff, CRSIZE, tperm) == -1)
					filioerr(tfname);
			blkio(iblock, ibuff, write);
		}
		ichanged = 0;
		iblock = bno;
		blkio(bno, ibuff, read);
		if (xtflag)
			if (run_crypt(0L, ibuff, CRSIZE, tperm) == -1)
				filioerr(tfname);
		return (ibuff + off);
	}
	if (oblock >= 0) {
		if (xtflag) {
			/*
			 * Encrypt block before writing, so some devious
			 * person can't look at temp file while editing.
			 */
			p1 = obuff;
			p2 = crbuf;
			n = CRSIZE;
			while (n--)
				*p2++ = *p1++;
			if (run_crypt(0L, crbuf, CRSIZE, tperm) == -1)
				filioerr(tfname);
			blkio(oblock, crbuf, write);
		} else
			blkio(oblock, obuff, write);
	}
	oblock = bno;
	return (obuff + off);
}

#ifdef	VMUNIX
#define	INCORB	64
unsigned char	incorb[INCORB+1][BUFSIZE];
#define	pagrnd(a)	((unsigned char *)(((int)a)&~(BUFSIZE-1)))
int	stilinc;	/* up to here not written yet */
#endif

void
blkio(short b, unsigned char *buf, int (*iofcn)())
{

#ifdef VMUNIX
	if (b < INCORB) {
		if (iofcn == read) {
			bcopy(pagrnd(incorb[b+1]), buf, BUFSIZE);
			return;
		}
		bcopy(buf, pagrnd(incorb[b+1]), BUFSIZE);
		if (laste) {
			if (b >= stilinc)
				stilinc = b + 1;
			return;
		}
	} else if (stilinc)
		tflush();
#endif
	lseek(tfile, (long)(unsigned)b * BUFSIZE, 0);
	if ((*iofcn)(tfile, buf, BUFSIZE) != BUFSIZE)
		filioerr(tfname);
}

#ifdef VMUNIX
void
tlaste(void)
{

	if (stilinc)
		dirtcnt = 0;
}

void
tflush(void)
{
	int i = stilinc;

	stilinc = 0;
	lseek(tfile, (long)0, 0);
	if (write(tfile, pagrnd(incorb[1]), i * BUFSIZE) != (i * BUFSIZE))
		filioerr(tfname);
}
#endif

/*
 * Synchronize the state of the temporary file in case
 * a crash occurs.
 */
void
synctmp(void)
{
	int cnt;
	line *a;
	short *bp;
	unsigned char *p1, *p2;
	int n;

#ifdef VMUNIX
	if (stilinc)
		return;
#endif
	if (dol == zero)
		return;
	/*
	 * In theory, we need to encrypt iblock and iblock2 before writing
	 * them out, as well as oblock, but in practice ichanged and ichang2
	 * can never be set, so this isn't really needed.  Likewise, the
	 * code in getblock above for iblock+iblock2 isn't needed.
	 */
	if (ichanged)
		blkio(iblock, ibuff, write);
	ichanged = 0;
	if (ichang2)
		blkio(iblock2, ibuff2, write);
	ichang2 = 0;
	if (oblock != -1)
	if (xtflag) {
		/*
		 * Encrypt block before writing, so some devious
		 * person can't look at temp file while editing.
		 */
		p1 = obuff;
		p2 = crbuf;
		n = CRSIZE;
		while (n--)
			*p2++ = *p1++;
		if (run_crypt(0L, crbuf, CRSIZE, tperm) == -1)
			filioerr(tfname);
		blkio(oblock, crbuf, write);
	} else
		blkio(oblock, obuff, write);
	time(&H.Time);
	uid = getuid();
	if (xtflag)
		H.encrypted = 1;
	else
		H.encrypted = 0;
	*zero = (line) H.Time;
	for (a = zero, bp = blocks; a <= dol;
	    a += BUFSIZE / sizeof (*a), bp++) {
		if (bp >= &H.Blocks[LBLKS-1])
			error(gettext(
			    "file too large to recover with -r option"));
		if (*bp < 0) {
			tline = (tline + OFFMSK) &~ OFFMSK;
			*bp = ((tline >> OFFBTS) & BLKMSK);
			if (*bp > NMBLKS)
				error(gettext(" Tmp file too large"));
			tline += INCRMT;
			oblock = *bp + 1;
			bp[1] = -1;
		}
		lseek(tfile, (long)(unsigned)*bp * BUFSIZE, 0);
		cnt = ((dol - a) + 2) * sizeof (line);
		if (cnt > BUFSIZE)
			cnt = BUFSIZE;
		if (write(tfile, (char *)a, cnt) != cnt) {
oops:
			*zero = 0;
			filioerr(tfname);
		}
		*zero = 0;
	}
	flines = lineDOL();
	lseek(tfile, 0l, 0);
	if (write(tfile, (char *)&H, sizeof (H)) != sizeof (H))
		goto oops;
}

void
TSYNC(void)
{

	if (dirtcnt > MAXDIRT) {
#ifdef VMUNIX
		if (stilinc)
			tflush();
#endif
		dirtcnt = 0;
		synctmp();
	}
}

/*
 * Named buffer routines.
 * These are implemented differently than the main buffer.
 * Each named buffer has a chain of blocks in the register file.
 * Each block contains roughly 508 chars of text,
 * and a previous and next block number.  We also have information
 * about which blocks came from deletes of multiple partial lines,
 * e.g. deleting a sentence or a LISP object.
 *
 * We maintain a free map for the temp file.  To free the blocks
 * in a register we must read the blocks to find how they are chained
 * together.
 *
 * BUG:		The default savind of deleted lines in numbered
 *		buffers may be rather inefficient; it hasn't been profiled.
 */
struct	strreg {
	short	rg_flags;
	short	rg_nleft;
	short	rg_first;
	short	rg_last;
} strregs[('z'-'a'+1) + ('9'-'0'+1)], *strp;

struct	rbuf {
	short	rb_prev;
	short	rb_next;
	unsigned char	rb_text[BUFSIZE - 2 * sizeof (short)];
} *rbuf, KILLrbuf, putrbuf, YANKrbuf, regrbuf;
#ifdef VMUNIX
short	rused[256];
#else
short	rused[32];
#endif
short	rnleft;
short	rblock;
short	rnext;
unsigned char	*rbufcp;

void
regio(short b, int (*iofcn)())
{

	if (rfile == -1) {
		CP(rfname, tempname);
		(void) strcat(rfname, "/RxXXXXXX");
		if ((rfile = mkstemp((char *)rfname)) < 0)
			filioerr(rfname);
	}
	lseek(rfile, (long)b * BUFSIZE, 0);
	if ((*iofcn)(rfile, rbuf, BUFSIZE) != BUFSIZE)
		filioerr(rfname);
	rblock = b;
}

int
REGblk(void)
{
	int i, j, m;

	for (i = 0; i < sizeof (rused) / sizeof (rused[0]); i++) {
		m = (rused[i] ^ 0177777) & 0177777;
		if (i == 0)
			m &= ~1;
		if (m != 0) {
			j = 0;
			while ((m & 1) == 0)
				j++, m >>= 1;
			rused[i] |= (1 << j);
#ifdef RDEBUG
			viprintf("allocating block %d\n", i * 16 + j);
#endif
			return (i * 16 + j);
		}
	}
	error(gettext("Out of register space (ugh)"));
	/*NOTREACHED*/
	return (0);
}

struct strreg *
mapreg(int c)
{

	if (isupper(c))
		c = tolower(c);
	return (isdigit(c) ? &strregs[('z'-'a'+1)+(c-'0')] : &strregs[c-'a']);
}

int	shread();

void
KILLreg(int c)
{
	struct strreg *sp;

	rbuf = &KILLrbuf;
	sp = mapreg(c);
	rblock = sp->rg_first;
	sp->rg_first = sp->rg_last = 0;
	sp->rg_flags = sp->rg_nleft = 0;
	while (rblock != 0) {
#ifdef RDEBUG
		viprintf("freeing block %d\n", rblock);
#endif
		rused[rblock / 16] &= ~(1 << (rblock % 16));
		regio(rblock, shread);
		rblock = rbuf->rb_next;
	}
}

/*VARARGS*/
int
shread(void)
{
	struct front { short a; short b; };

	if (read(rfile, (char *)rbuf, sizeof (struct front)) ==
	    sizeof (struct front))
		return (sizeof (struct rbuf));
	return (0);
}

int	getREG();

int
putreg(unsigned char c)
{
	line *odot = dot;
	line *odol = dol;
	int cnt;

	deletenone();
	appendnone();
	rbuf = &putrbuf;
	rnleft = 0;
	rblock = 0;
	rnext = mapreg(c)->rg_first;
	if (rnext == 0) {
		if (inopen) {
			splitw++;
			vclean();
			vgoto(WECHO, 0);
		}
		vreg = -1;
		error(gettext("Nothing in register %c"), c);
	}
	if (inopen && partreg(c)) {
		if (!FIXUNDO) {
			splitw++; vclean(); vgoto(WECHO, 0); vreg = -1;
			error(gettext("Can't put partial line inside macro"));
		}
		squish();
		addr1 = addr2 = dol;
	}
	cnt = append(getREG, addr2);
	if (inopen && partreg(c)) {
		unddol = dol;
		dol = odol;
		dot = odot;
		pragged(0);
	}
	killcnt(cnt);
	notecnt = cnt;
	return (0);
}

short
partreg(unsigned char c)
{

	return (mapreg(c)->rg_flags);
}

void
notpart(int c)
{

	if (c)
		mapreg(c)->rg_flags = 0;
}

int
getREG(void)
{
	unsigned char *lp = linebuf;
	int c;

	for (;;) {
		if (rnleft == 0) {
			if (rnext == 0)
				return (EOF);
			regio(rnext, read);
			rnext = rbuf->rb_next;
			rbufcp = rbuf->rb_text;
			rnleft = sizeof (rbuf->rb_text);
		}
		c = *rbufcp;
		if (c == 0)
			return (EOF);
		rbufcp++, --rnleft;
		if (c == '\n') {
			*lp++ = 0;
			return (0);
		}
		*lp++ = c;
	}
}

int
YANKreg(int c)
{
	line *addr;
	struct strreg *sp;
	unsigned char savelb[LBSIZE];

	if (isdigit(c))
		kshift();
	if (islower(c))
		KILLreg(c);
	strp = sp = mapreg(c);
	sp->rg_flags = inopen && cursor && wcursor;
	rbuf = &YANKrbuf;
	if (sp->rg_last) {
		regio(sp->rg_last, read);
		rnleft = sp->rg_nleft;
		rbufcp = &rbuf->rb_text[sizeof (rbuf->rb_text) - rnleft];
	} else {
		rblock = 0;
		rnleft = 0;
	}
	CP(savelb, linebuf);
	for (addr = addr1; addr <= addr2; addr++) {
		getaline(*addr);
		if (sp->rg_flags) {
			if (addr == addr2)
				*wcursor = 0;
			if (addr == addr1)
				strcpy(linebuf, cursor);
		}
		YANKline();
	}
	rbflush();
	killed();
	CP(linebuf, savelb);
	return (0);
}

void
kshift(void)
{
	int i;

	KILLreg('9');
	for (i = '8'; i >= '0'; i--)
		copy(mapreg(i+1), mapreg(i), sizeof (struct strreg));
}

void
YANKline(void)
{
	unsigned char *lp = linebuf;
	struct rbuf *rp = rbuf;
	int c;

	do {
		c = *lp++;
		if (c == 0)
			c = '\n';
		if (rnleft == 0) {
			rp->rb_next = REGblk();
			rbflush();
			rblock = rp->rb_next;
			rp->rb_next = 0;
			rp->rb_prev = rblock;
			rnleft = sizeof (rp->rb_text);
			rbufcp = rp->rb_text;
		}
		*rbufcp++ = c;
		--rnleft;
	} while (c != '\n');
	if (rnleft)
		*rbufcp = 0;
}

void
rbflush(void)
{
	struct strreg *sp = strp;

	if (rblock == 0)
		return;
	regio(rblock, write);
	if (sp->rg_first == 0)
		sp->rg_first = rblock;
	sp->rg_last = rblock;
	sp->rg_nleft = rnleft;
}

/* Register c to char buffer buf of size buflen */
void
regbuf(unsigned char c, unsigned char *buf, int buflen)
{
	unsigned char *p, *lp;

	rbuf = &regrbuf;
	rnleft = 0;
	rblock = 0;
	rnext = mapreg(c)->rg_first;
	if (rnext == 0) {
		*buf = 0;
		error(gettext("Nothing in register %c"), c);
	}
	p = buf;
	while (getREG() == 0) {
		lp = linebuf;
		while (*lp) {
			if (p >= &buf[buflen])
				error(value(vi_TERSE) ?
gettext("Register too long") : gettext("Register too long to fit in memory"));
			*p++ = *lp++;
		}
		*p++ = '\n';
	}
	if (partreg(c)) p--;
	*p = '\0';
	getDOT();
}

#ifdef TRACE

/*
 * Test code for displaying named registers.
 */

shownam()
{
	int k;

	viprintf("\nRegister   Contents\n");
	viprintf("========   ========\n");
	for (k = 'a'; k <= 'z'; k++) {
		rbuf = &putrbuf;
		rnleft = 0;
		rblock = 0;
		rnext = mapreg(k)->rg_first;
		viprintf(" %c:", k);
		if (rnext == 0)
			viprintf("\t\tNothing in register.\n");
		while (getREG() == 0) {
			viprintf("\t\t%s\n", linebuf);
		}
	}
	return (0);
}

/*
 * Test code for displaying numbered registers.
 */

shownbr()
{
	int k;

	viprintf("\nRegister   Contents\n");
	viprintf("========   ========\n");
	for (k = '1'; k <= '9'; k++) {
		rbuf = &putrbuf;
		rnleft = 0;
		rblock = 0;
		rnext = mapreg(k)->rg_first;
		viprintf(" %c:", k);
		if (rnext == 0)
			viprintf("\t\tNothing in register.\n");
		while (getREG() == 0) {
			viprintf("\t\t%s\n", linebuf);
		}
	}
	return (0);
}
#endif
