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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.3	*/
#ifdef debug
#define ASSERT(p) if(!(p))botch("p");else
botch(s)
char *s;
{
	printf("assertion botched: %s\n",s);
	abort();
}
#else
#define ASSERT(p)
#endif

/*	C storage allocator
 *	circular first-fit strategy
 *	works with noncontiguous, but monotonically linked, arena
 *	each block is preceded by a ptr to the (pointer of) 
 *	the next following block
 *	blocks are exact number of words long 
 *	aligned to the data type requirements of ALIGN
 *	pointers to blocks must have BUSY bit 0
 *	bit in ptr is 1 for busy, 0 for idle
 *	gaps in arena are merely noted as busy blocks
 *	last block of arena is empty and
 *	has a pointer to first
 *	idle blocks are coalesced during space search
 *
 *	a different implementation may need to redefine
 *	ALIGN, NALIGN, BLOCK, BUSY, INT
 *	where INT is integer type to which a pointer can be cast
*/
#define INT int
#define ALIGN int
#define NALIGN 1
#define WORD sizeof(union store)
#define BLOCK 1024
#define BUSY 1
#define NULL 0
#define testbusy(p) ((INT)(p)&BUSY)
#define setbusy(p) (union store *)((INT)(p)|BUSY)
#define clearbusy(p) (union store *)((INT)(p)&~BUSY)

union store {
	      union store *ptr;
	      ALIGN dummy[NALIGN];
	      int calloc;	/*calloc clears an array of integers*/
};

static	union store alloca;	/* initial arena */
static	union store *allocb = &alloca;	/*arena base*/
static	union store *allocp = &alloca;	/*search ptr*/
static	union store *allocx;	/*for benefit of realloc*/
extern	char *sbrk();

char *
malloc(nbytes)
unsigned nbytes;
{
	register union store *p, *q;
	register nw;
	register temp;
	register union store *r = 0;

	nw = (nbytes+WORD+WORD-1)/WORD + 1;	/*need one more than asked for*/
	ASSERT(allock(allocp));
	for(; ; ) {	/* done at most twice */
		p = allocp;
		if(alloca.ptr!=0)		/*C can't initialize union*/
		for(temp=0; ; ) {
			if(!testbusy(p->ptr)) {
				while(!testbusy((q=p->ptr)->ptr)) {
					ASSERT(q>p);
					p->ptr = q->ptr;
					allocp = p;
				}
				if(q>=p+nw && p+nw>=p)
					goto found;
				r = p;
			}
			q = p;
			p = clearbusy(p->ptr);
			if(p <= q) {
				ASSERT(p==allocb);
				if(p != allocb)
					return(NULL);
				if(++temp>1)
					break;
			}
		}
		temp = nw;
		p = (union store *)sbrk(0);
		if (r && !testbusy(r->ptr) && r->ptr + 1 == p)
			temp -= p - r - 1;
		temp = ((temp+BLOCK/WORD)/(BLOCK/WORD))*(BLOCK/WORD);
		if(p+temp <= p)
			return(NULL);
		for(; ; ) {
			q = (union store *)sbrk(temp*WORD);
			if((INT)q != -1)
				break;
			temp -= (temp-nw+1)/2;
			if(temp <= nw)
				return(NULL);
		}
		ialloc((char *)q, (unsigned)temp*WORD);
	}
found:
	allocp = p + nw;
	if(q>allocp) {
		allocx = allocp->ptr;
		allocp->ptr = p->ptr;
	}
	p->ptr = setbusy(allocp);
	return((char *)(p+1));
}

/*	freeing strategy tuned for LIFO allocation
*/
free(ap)
char *ap;
{
	register union store *p = (union store *)ap;

	allocp = --p;
	ASSERT(allock(allocp));
	ASSERT(testbusy(p->ptr));
	p->ptr = clearbusy(p->ptr);
	ASSERT(p->ptr > allocp);
}

/* ialloc(q, nbytes) inserts a block that did not come
 * from malloc into the arena
 *
 * q points to new block
 * r points to last of new block
 * p points to last cell of arena before new block
 * s points to first cell of arena after new block
*/
ialloc(qq, nbytes)
char *qq;
unsigned nbytes;
{
	register union store *p, *q, *s;
	union store *r;

	q = (union store *)qq;
	r = q + (nbytes/WORD) - 1;
	q->ptr = r;
	if(alloca.ptr==0)		/*C can't initialize union*/
		alloca.ptr = &alloca;
	for(p=allocb; ; p=s) {
		s = clearbusy(p->ptr);
		if(s==allocb)
			break;
		ASSERT(s>p);
		if(s>r) {
			if(p<q)
				break;
			else
				ASSERT(p>r);
		}
	}
	p->ptr = q==p+1? q: setbusy(q);
	r->ptr = s==r+1? s: setbusy(s);
	if(allocb > q)
		allocb = q;
	allocp = allocb;
}

/*	realloc(p, nbytes) reallocates a block obtained from malloc()
 *	and freed since last call of malloc()
 *	to have new size nbytes, and old content
 *	returns new location, or 0 on failure
*/

char *
realloc(pp, nbytes)
char *pp;
unsigned nbytes;
{
	register union store *q;
	register union store *p = (union store *)pp;
	union store *s, *t;
	register unsigned nw;
	unsigned onw;

	ASSERT(allock(p-1));
	if(testbusy(p[-1].ptr))
		free((char *)p);
	onw = p[-1].ptr - p;
	q = (union store *)malloc(nbytes);
	if(q==NULL || q==p)
		return((char *)q);
	ASSERT(q<p||q>p[-1].ptr);
	s = p;
	t = q;
	nw = (nbytes+WORD-1)/WORD;
	if(nw<onw)
		onw = nw;
	while(onw--!=0)
		*t++ = *s++;
	ASSERT(clearbusy(q[-1].ptr)-q==nw);
	if(q<p && q+nw>=p)
		(q+(q+nw-p))->ptr = allocx;
	ASSERT(allock(q-1));
	return((char *)q);
}

#ifdef debug
allock(q)
union store *q;
{
#ifdef longdebug
	register union store *p, *r;
	int x;
	x = 0;
	p = allocb;
	if(alloca.ptr==0)
		return(1);
	for( ; (r=clearbusy(p->ptr)) > p; p=r) {
		if(p==q)
			x++;
	}
	return(r==allocb&(x==1|p==q));
#else
	return(q>=allocb);
#endif
}
#endif

