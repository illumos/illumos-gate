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
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#define	FATAL 0
#define	NFATAL 1
#define	BLK sizeof (struct blk)
#define	PTRSZ sizeof (int *)
#define	HEADSZ 1024
#define	STKSZ 100
#define	RDSKSZ 100
#define	TBLSZ 256
#define	ARRAYST 0241
#define	NL 1
#define	NG 2
#define	NE 3
#define	length(p) ((p)->wt-(p)->beg)
#define	rewind(p) ((p)->rd = (p)->beg)
#define	create(p)	((p)->rd = (p)->wt = (p)->beg)
#define	fsfile(p)	((p)->rd = (p)->wt)
#define	truncate(p)	((p)->wt = (p)->rd)
#define	sfeof(p)	(((p)->rd >= (p)->wt) ? 1 : 0)
#define	sfbeg(p)	(((p)->rd == (p)->beg) ? 1 : 0)
#define	sungetc(p, c)	(*(--(p)->rd) = c)
#define	sgetc(p)	(((p)->rd == (p)->wt) ? EOF: ctoint((int)*(p)->rd++))
#define	slookc(p)	(((p)->rd == (p)->wt) ? EOF: ctoint((int)*(p)->rd))
#define	sbackc(p)	(((p)->rd == (p)->beg) ? EOF: ctoint((int)*(--(p)->rd)))
#define	sputc(p, c)	{if ((p)->wt == (p)->last) more(p); *(p)->wt++ = c; }
#define	salterc(p, c)	{if ((p)->rd == (p)->last) more(p); *(p)->rd++ = c;\
			    if ((p)->rd > (p)->wt) (p)->wt = (p)->rd; }
#define	sunputc(p)	(*((p)->rd = --(p)->wt))
#define	zero(p)		for (pp = (p)->beg; pp < (p)->last; ) *pp++ = '\0'
#define	OUTC(x) {printf("%c", x); if (--count == 0)\
			    {printf("\\\n"); count = ll; } }
#define	TEST2	{if ((count -= 2) <= 0) {printf("\\\n"); count = ll; } }
#define	PRINT_MESSAGE	printf(gettext("stack empty\n"))
#define	EMPTY		if (stkerr != 0) {PRINT_MESSAGE; continue; }
#define	EMPTYR(x)	if (stkerr != 0) {pushp(x); PRINT_MESSAGE; continue; }
#define	EMPTYS		if (stkerr != 0) {PRINT_MESSAGE; return (1); }
#define	EMPTYSR(x)	if (stkerr != 0) {PRINT_MESSAGE; pushp(x); return (1); }
#define	CHECKEND	{ \
				if (count == 2) { \
					printf("\\\n"); \
					count = ll; \
				} \
			}
#define	error(p)	{printf(p); continue; }
#define	errorrt(p)	{printf(p); return (1); }
struct blk {
	char	*rd;
	char	*wt;
	char	*beg;
	char	*last;
};
struct	wblk {
	struct blk **rdw;
	struct blk **wtw;
	struct blk **begw;
	struct blk **lastw;
};
struct	blk *hfree;
struct	blk *getwd(struct blk *);
struct	blk *lookwd(struct blk *);
struct	blk *getdec(struct blk *, int);
struct	blk *morehd(void);

struct	blk *arg1, *arg2;
int	svargc;
char	savk;
char	**svargv;
int	dbg;
int	ifile;
FILE	*curfile;
struct	blk *scalptr, *basptr, *tenptr, *inbas;
struct	blk *sqtemp, *chptr, *strptr, *divxyz;
struct	blk *stack[STKSZ];
struct	blk **stkptr, **stkbeg;
struct	blk **stkend;
int	stkerr;
int	lastchar;
struct	blk *readstk[RDSKSZ];
struct	blk **readptr;
struct	blk *rem;
int	k;
struct	blk *irem;
int	skd, skr;
struct	blk *pop(void), *readin(void), *add0(struct blk *, int),
    *mult(struct blk *, struct blk *);
struct	blk *scalint(struct blk *);
struct	blk *removc(struct blk *, int);
struct	blk *add(struct blk *, struct blk *),
    *dcdiv(struct blk *, struct blk *), *removr(struct blk *, int);
struct	blk *exp(struct blk *, struct blk *);
struct	blk *sqrt(struct blk *);
struct	blk *salloc(int), *copy(struct blk *, int);
struct	blk *scale(struct blk *, int);
void	commnds(void);
void	init(int, char **);
void	pushp(struct blk *p);
void	chsign(struct blk *p);
char	readc(void);
void	unreadc(char);
void	binop(char);
void	print(struct blk *hptr);
void	tenot(struct blk *p, int sc);
void	oneot(struct blk *p, int sc, char ch);
void	seekc(struct blk *hptr, int n);
void	ospace(char *s);
void	garbage(char *s);
void	more(struct blk *hptr);
int	cond(char c);
void	load(void);
void	sdump(char *s1, struct blk *hptr);
void	salterwd(struct wblk *hptr, struct blk *n);
void	redef(struct blk *p);
void	release(struct blk *p);
void	putwd(struct blk *p, struct blk *c);

int	neg;
struct	sym {
	struct	sym *next;
	struct	blk *val;
} symlst[TBLSZ];
struct	sym *stable[TBLSZ];
struct	sym *sptr, *sfree;
FILE	*fsave;
long	rel;
long	nbytes;
long	all;
long	headmor;
long	obase;
int	fw, fw1, ll;
void	(*outdit)(struct blk *, int);
void	bigot(struct blk *, int), hexot(struct blk *, int);
int	logo;
int	log10;
int	count;
char	*pp;
void	onintr(int);
char	*nalloc(char *, unsigned int);
char	*dummy;
