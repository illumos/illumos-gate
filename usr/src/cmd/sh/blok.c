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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 *	UNIX shell
 */

#include	"defs.h"


/*
 *	storage allocator
 *	(circular first fit strategy)
 */

#define	BUSY 01
#define	busy(x)	(Rcheat((x)->word) & BUSY)

unsigned	brkincr = BRKINCR;
struct blk *blokp;			/* current search pointer */
struct blk *bloktop;		/* top of arena (last blok) */

unsigned char		*brkbegin;
unsigned char		*setbrk();

void addblok(unsigned int);

#ifdef __STDC__
void *
#else
char *
#endif
alloc(nbytes)
	size_t nbytes;
{
	unsigned rbytes = round(nbytes + ALIGNSIZ, ALIGNSIZ);

	if (stakbot == 0) {
		addblok((unsigned)0);
	}

	for (;;)
	{
		int	c = 0;
		struct blk *p = blokp;
		struct blk *q;

		do
		{
			if (!busy(p))
			{
				while (!busy(q = p->word))
					p->word = q->word;
				if ((char *)q - (char *)p >= rbytes)
				{
					blokp = (struct blk *)
							((char *)p + rbytes);
					if (q > blokp)
						blokp->word = p->word;
					p->word = (struct blk *)
							(Rcheat(blokp) | BUSY);
					return ((char *)(p + 1));
				}
			}
			q = p;
			p = (struct blk *)(Rcheat(p->word) & ~BUSY);
		} while (p > q || (c++) == 0);
		addblok(rbytes);
	}
}

void
addblok(unsigned int reqd)
{
	if (stakbot == 0) {
		brkbegin = setbrk(3 * BRKINCR);
		/*
		 * setbrk() returns 8 byte aligned address
		 * but we could need larger align in future
		 */
		brkbegin = (unsigned char *)round(brkbegin, ALIGNSIZ);
		bloktop = (struct blk *)brkbegin;
	}

	if (stakbas != staktop) {
		unsigned char *rndstak;
		struct blk *blokstak;

		if (staktop >= brkend)
			growstak(staktop);
		pushstak(0);
		rndstak = (unsigned char *)round(staktop, ALIGNSIZ);
		blokstak = (struct blk *)(stakbas) - 1;
		blokstak->word = stakbsy;
		stakbsy = blokstak;
		bloktop->word = (struct blk *)(Rcheat(rndstak) | BUSY);
		bloktop = (struct blk *)(rndstak);
	}
	reqd += brkincr;
	reqd &= ~(brkincr - 1);
	blokp = bloktop;
	/*
	 * brkend points to the first invalid address.
	 * make sure bloktop is valid.
	 */
	if ((unsigned char *)&bloktop->word >= brkend) {
		if (setbrk((unsigned)((unsigned char *)
		    (&bloktop->word) - brkend + sizeof (struct blk))) ==
		    (unsigned char *)-1)
			error(nospace);
	}
	bloktop = bloktop->word = (struct blk *)(Rcheat(bloktop) + reqd);
	if ((unsigned char *)&bloktop->word >= brkend) {
		if (setbrk((unsigned)((unsigned char *)
		    (&bloktop->word) - brkend + sizeof (struct blk))) ==
		    (unsigned char *)-1)
			error(nospace);
	}
	bloktop->word = (struct blk *)(brkbegin + 1);
	{
		unsigned char *stakadr = (unsigned char *)
							(bloktop + 2);
		unsigned char *sp = stakadr;
		if (reqd = (staktop-stakbot)) {
			if (stakadr + reqd >= brkend)
				growstak(stakadr + reqd);
			while (reqd-- > 0)
				*sp++ = *stakbot++;
			sp--;
		}
		staktop = sp;
		if (staktop >= brkend)
			growstak(staktop);
		stakbas = stakbot = stakadr;
	}
}

void
free(ap)
	void *ap;
{
	struct blk *p;

	if ((p = (struct blk *)ap) && p < bloktop && p > (struct blk *)brkbegin)
	{
#ifdef DEBUG
		chkbptr(p);
#endif
		--p;
		p->word = (struct blk *)(Rcheat(p->word) & ~BUSY);
	}


}


#ifdef DEBUG

chkbptr(ptr)
	struct blk *ptr;
{
	int	exf = 0;
	struct blk *p = (struct blk *)brkbegin;
	struct blk *q;
	int	us = 0, un = 0;

	for (;;)
	{
		q = (struct blk *)(Rcheat(p->word) & ~BUSY);

		if (p+1 == ptr)
			exf++;

		if (q < (struct blk *)brkbegin || q > bloktop)
			abort(3);

		if (p == bloktop)
			break;

		if (busy(p))
			us += q - p;
		else
			un += q - p;

		if (p >= q)
			abort(4);

		p = q;
	}
	if (exf == 0)
		abort(1);
}


chkmem()
{
	struct blk *p = (struct blk *)brkbegin;
	struct blk *q;
	int	us = 0, un = 0;

	for (;;) {
		q = (struct blk *)(Rcheat(p->word) & ~BUSY);

		if (q < (struct blk *)brkbegin || q > bloktop)
			abort(3);

		if (p == bloktop)
			break;

		if (busy(p))
			us += q - p;
		else
			un += q - p;

		if (p >= q)
			abort(4);

		p = q;
	}

	prs("un/used/avail ");
	prn(un);
	blank();
	prn(us);
	blank();
	prn((char *)bloktop - brkbegin - (un + us));
	newline();

}

#endif

size_t
blklen(q)
char *q;
{
	struct blk *pp = (struct blk *)q;
	struct blk *p;

	--pp;
	p = (struct blk *)(Rcheat(pp->word) & ~BUSY);

	return ((size_t)((long)p - (long)q));
}

/*
 * This is a really hasty hack at putting realloc() in the shell, along
 * with alloc() and free(). I really hate having to do things like this,
 * hacking in something before I understand _why_ libcollate does any
 * memory (re)allocation, let alone feel comfortable with this particular
 * implementation of realloc, assuming it actually gets used by anything.
 *
 * I plan to revist this, for now this is just to get sh to compile so
 * that xcu4 builds may be done and we get xcu4 on our desktops.
 *
 * Eric Brunner, 10/21/94
 *
 * Implemented a variation on the suggested fix in Trusted Solaris 2.5,
 * then forward ported the fix into the mainline shell.
 *
 * 3/3/99
 */
#ifdef __STDC__
void *
realloc(pp, nbytes)
void *pp;
size_t nbytes;
#else
char *
realloc(pp, nbytes)
char *pp;
size_t nbytes;
#endif
{
	char *q;
	size_t blen;

	if (pp == NULL)
		return (alloc(nbytes));
	if ((nbytes == 0) && (pp != NULL))
		free(pp);

	blen = blklen(pp);

	if (blen < nbytes) {		/* need to grow */
		q = alloc(nbytes);
		memcpy(q, pp, blen);
		free(pp);
		return ((char *)q);
	} else if (blen == nbytes) {	/* do nothing */
		return (pp);
	} else {			/* free excess */
		q = alloc(nbytes);
		memcpy(q, pp, nbytes);
		free(pp);
		return ((char *)q);
	}

#ifdef undef
	/*
	 * all of what follows is the _idea_ of what is going to be done
	 * getting the size of the block is a problem -- what follows
	 * is _not_ "real", since "sizeof" isn't going to tell me any
	 * thing usefull, probably have to travers the list to the next
	 * blk, then subtract ptr addrs ... and be careful not to leave
	 * holes.
	 */
	p = (struct blk *)pp;
	if (sizeof (p) < nbytes) {			/* need to grow */
		q = alloc(nbytes);
		memcpy(q, pp, sizeof (p));
		free(pp);
		return ((char *)q);
	} else if (sizeof (p) == nbytes) {		/* do nothing */
		return (pp);
	} else {					/* free excess */
		q = alloc(nbytes);
		memcpy(q, pp, nbytes);
		free(pp);
		return ((char *)q);
	}
#endif
}
