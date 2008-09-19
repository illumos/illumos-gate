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
 * UNIX shell
 */

#include	"defs.h"
#include	"dup.h"
#include	<stdio.h>
#include	<fcntl.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<errno.h>

short topfd;

/* ========	input output and file copying ======== */

void
initf(int fd)
{
	struct fileblk *f = standin;

	f->fdes = fd;
	f->fsiz = ((flags & oneflg) == 0 ? BUFFERSIZE : 1);
	f->fnxt = f->fend = f->fbuf;
	f->nxtoff = f->endoff = 0;
	f->feval = 0;
	f->flin = 1;
	f->feof = FALSE;
}

int
estabf(unsigned char *s)
{
	struct fileblk *f;

	(f = standin)->fdes = -1;
	f->fend = length(s) + (f->fnxt = s);
	f->nxtoff = 0;
	f->endoff = length(s);
	f->flin = 1;
	return (f->feof = (s == 0));
}

void
push(struct fileblk *af)
{
	struct fileblk *f;

	(f = af)->fstak = standin;
	f->feof = 0;
	f->feval = 0;
	standin = f;
}

int
pop(void)
{
	struct fileblk *f;

	if ((f = standin)->fstak) {
		if (f->fdes >= 0)
			close(f->fdes);
		standin = f->fstak;
		return (TRUE);
	} else
		return (FALSE);
}

struct tempblk *tmpfptr;

void
pushtemp(int fd, struct tempblk *tb)
{
	tb->fdes = fd;
	tb->fstak = tmpfptr;
	tmpfptr = tb;
}

int
poptemp(void)
{
	if (tmpfptr) {
		close(tmpfptr->fdes);
		tmpfptr = tmpfptr->fstak;
		return (TRUE);
	} else
		return (FALSE);
}

void
chkpipe(int *pv)
{
	if (pipe(pv) < 0 || pv[INPIPE] < 0 || pv[OTPIPE] < 0)
		error(piperr);
}

int
chkopen(unsigned char *idf, int mode)
{
	int	rc;

	if ((rc = open((char *)idf, mode, 0666)) < 0)
		failed(idf, badopen);
	else
		return (rc);
}

/*
 * Make f2 be a synonym (including the close-on-exec flag) for f1, which is
 * then closed.  If f2 is descriptor 0, modify the global ioset variable
 * accordingly.
 */
void
renamef(int f1, int f2)
{
#ifdef RES
	if (f1 != f2) {
		dup(f1 | DUPFLG, f2);
		close(f1);
		if (f2 == 0)
			ioset |= 1;
	}
#else
	int	fs;

	if (f1 != f2) {
		fs = fcntl(f2, 1, 0);
		close(f2);
		fcntl(f1, 0, f2);
		close(f1);
		if (fs == 1)
			fcntl(f2, 2, 1);
		if (f2 == 0)
			ioset |= 1;
	}
#endif
}

int
create(unsigned char *s)
{
	int	rc;

	if ((rc = creat((char *)s, 0666)) < 0)
		failed(s, badcreate);
	else
		return (rc);
}


int
tmpfil(struct tempblk *tb)
{
	int fd;
	int len;
	size_t size_left = TMPOUTSZ - tmpout_offset;

	/* make sure tmp file does not already exist. */
	do {
		len = snprintf((char *)&tmpout[tmpout_offset], size_left,
		    "%u", serial);
		fd = open((char *)tmpout, O_RDWR|O_CREAT|O_EXCL, 0600);
		serial++;
		if ((serial >= UINT_MAX) || (len >= size_left)) {
			/*
			 * We've already cycled through all the possible
			 * numbers or the tmp file name is being
			 * truncated anyway (although TMPOUTSZ should be
			 * big enough), so start over.
			 */
			serial = 0;
			break;
		}
	} while ((fd == -1) && (errno == EEXIST));
	if (fd != -1) {
		pushtemp(fd, tb);
		return (fd);
	}
	else
		failed(tmpout, badcreate);
}

/*
 * set by trim
 */
extern BOOL		nosubst;
#define			CPYSIZ		512

void
copy(struct ionod	*ioparg)
{
	unsigned char	*cline;
	unsigned char	*clinep;
	struct ionod	*iop;
	unsigned int	c;
	unsigned char	*ends;
	unsigned char	*start;
	int		fd;
	int		i;
	int		stripflg;
	unsigned char	*pc;


	if (iop = ioparg) {
		struct tempblk tb;
		copy(iop->iolst);
		ends = mactrim(iop->ioname);
		stripflg = iop->iofile & IOSTRIP;
		if (nosubst)
			iop->iofile &= ~IODOC_SUBST;
		fd = tmpfil(&tb);

		if (fndef)
			iop->ioname = (char *)make(tmpout);
		else
			iop->ioname = (char *)cpystak(tmpout);

		iop->iolst = iotemp;
		iotemp = iop;

		cline = clinep = start = locstak();
		if (stripflg) {
			iop->iofile &= ~IOSTRIP;
			while (*ends == '\t')
				ends++;
		}
		for (;;) {
			chkpr();
			if (nosubst) {
				c = readwc();
				if (stripflg)
					while (c == '\t')
						c = readwc();

				while (!eolchar(c)) {
					pc = readw(c);
					while (*pc) {
						if (clinep >= brkend)
							growstak(clinep);
						*clinep++ = *pc++;
					}
					c = readwc();
				}
			} else {
				c = nextwc();
				if (stripflg)
					while (c == '\t')
						c = nextwc();

				while (!eolchar(c)) {
					pc = readw(c);
					while (*pc) {
						if (clinep >= brkend)
							growstak(clinep);
						*clinep++ = *pc++;
					}
					if (c == '\\') {
						pc = readw(readwc());
						/* *pc might be NULL */
						/* BEGIN CSTYLED */
						if (*pc) {
							while (*pc) {
								if (clinep >= brkend)
									growstak(clinep);
								*clinep++ = *pc++;
							}
						} else {
							if (clinep >= brkend)
								growstak(clinep);
							*clinep++ = *pc;
						}
						/* END CSTYLED */
					}
					c = nextwc();
				}
			}

			if (clinep >= brkend)
				growstak(clinep);
			*clinep = 0;
			if (eof || eq(cline, ends)) {
				if ((i = cline - start) > 0)
					write(fd, start, i);
				break;
			} else {
				if (clinep >= brkend)
					growstak(clinep);
				*clinep++ = NL;
			}

			if ((i = clinep - start) < CPYSIZ)
				cline = clinep;
			else
			{
				write(fd, start, i);
				cline = clinep = start;
			}
		}

		/*
		 * Pushed in tmpfil -- bug fix for problem
		 * deleting in-line script.
		 */
		poptemp();
	}
}

void
link_iodocs(struct ionod *i)
{
	int r;
	int len;
	size_t size_left = TMPOUTSZ - tmpout_offset;

	while (i) {
		free(i->iolink);

		/* make sure tmp file does not already exist. */
		do {
			len = snprintf((char *)&tmpout[tmpout_offset],
			    size_left, "%u", serial);
			serial++;
			r = link(i->ioname, (char *)tmpout);
			if ((serial >= UINT_MAX) || (len >= size_left)) {
			/*
			 * We've already cycled through all the possible
			 * numbers or the tmp file name is being
			 * truncated anyway, so start over.
			 */
				serial = 0;
				break;
			}
		} while (r == -1 && errno == EEXIST);

		if (r != -1) {
			i->iolink = (char *)make(tmpout);
			i = i->iolst;
		} else
			failed(tmpout, badcreate);

	}
}

void
swap_iodoc_nm(struct ionod *i)
{
	while (i) {
		free(i->ioname);
		i->ioname = i->iolink;
		i->iolink = 0;

		i = i->iolst;
	}
}

int
savefd(int fd)
{
	int	f;

	f = fcntl(fd, F_DUPFD, 10);
	/* this saved fd should not be found in an exec'ed cmd */
	(void) fcntl(f, F_SETFD, FD_CLOEXEC);
	return (f);
}

void
restore(int last)
{
	int 	i;
	int	dupfd;

	for (i = topfd - 1; i >= last; i--) {
		if ((dupfd = fdmap[i].dup_fd) > 0)
			renamef(dupfd, fdmap[i].org_fd);
		else
			close(fdmap[i].org_fd);
	}
	topfd = last;
}
