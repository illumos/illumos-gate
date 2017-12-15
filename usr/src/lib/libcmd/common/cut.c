/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1992-2010 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                  Common Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*            http://www.opensource.org/licenses/cpl1.0.txt             *
*         (with md5 checksum 059e8cd6165cb4c31e351f2b69388fd9)         *
*                                                                      *
*              Information and Software Systems Research               *
*                            AT&T Research                             *
*                           Florham Park NJ                            *
*                                                                      *
*                 Glenn Fowler <gsf@research.att.com>                  *
*                  David Korn <dgk@research.att.com>                   *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * David Korn
 * AT&T Bell Laboratories
 *
 * cut fields or columns from fields from a file
 */

static const char usage[] =
"[-?\n@(#)$Id: cut (AT&T Research) 2009-12-04 $\n]"
USAGE_LICENSE
"[+NAME?cut - cut out selected columns or fields of each line of a file]"
"[+DESCRIPTION?\bcut\b bytes, characters, or character-delimited fields "
	"from one or more files, contatenating them on standard output.]"
"[+?The option argument \alist\a is a comma-separated or blank-separated "
	"list of positive numbers and ranges.  Ranges can be of three "
	"forms.  The first is two positive integers separated by a hyphen "
	"(\alow\a\b-\b\ahigh\a), which represents all fields from \alow\a to "
	"\ahigh\a.  The second is a positive number preceded by a hyphen "
	"(\b-\b\ahigh\a), which represents all fields from field \b1\b to "
	"\ahigh\a.  The last is a positive number followed by a hyphen "
	"(\alow\a\b-\b), which represents all fields from \alow\a to the "
	"last field, inclusive.  Elements in the \alist\a can be repeated, "
	"can overlap, and can appear in any order.  The order of the "
	"output is that of the input.]"
"[+?One and only one of \b-b\b, \b-c\b, or \b-f\b must be specified.]"
"[+?If no \afile\a is given, or if the \afile\a is \b-\b, \bcut\b "
        "cuts from standard input.   The start of the file is defined "
        "as the current offset.]"
"[b:bytes]:[list?\bcut\b based on a list of byte counts.]"
"[c:characters]:[list?\bcut\b based on a list of character counts.]"
"[d:delimiter]:[delim?The field character for the \b-f\b option is set "
	"to \adelim\a.  The default is the \btab\b character.]"
"[f:fields]:[list?\bcut\b based on fields separated by the delimiter "
	"character specified with the \b-d\b optiion.]"
"[n!:split?Split multibyte characters selected by the \b-b\b option.]"
"[R|r:reclen]#[reclen?If \areclen\a > 0, the input will be read as fixed length "
	"records of length \areclen\a when used with the \b-b\b or \b-c\b "
	"option.]"
"[s:suppress|only-delimited?Suppress lines with no delimiter characters, "
	"when used with the \b-f\b option.  By default, lines with no "
	"delimiters will be passsed in untouched.]"
"[D:line-delimeter|output-delimiter]:[ldelim?The line delimiter character for "
	"the \b-f\b option is set to \aldelim\a.  The default is the "
	"\bnewline\b character.]"
"[N!:newline?Output new-lines at end of each record when used "
	"with the \b-b\b or \b-c\b option.]"
"\n"
"\n[file ...]\n"
"\n"
"[+EXIT STATUS?]{"
	"[+0?All files processed successfully.]"
	"[+>0?One or more files failed to open or could not be read.]"
"}"
"[+SEE ALSO?\bpaste\b(1), \bgrep\b(1)]"
;

#include <cmd.h>
#include <ctype.h>

typedef struct Delim_s
{
	char*		str;
	int		len;
	int		chr;
} Delim_t;

typedef struct Cut_s
{
	int		mb;
	int		eob;
	int		cflag;
	int		nosplit;
	int		sflag;
	int		nlflag;
	int		reclen;
	Delim_t		wdelim;
	Delim_t		ldelim;
	unsigned char	space[UCHAR_MAX+1];
	int		list[2];	/* NOTE: must be last member */
} Cut_t;

#define HUGE		INT_MAX
#define BLOCK		8*1024
#define C_BYTES		1
#define C_CHARS		2
#define C_FIELDS	4
#define C_SUPRESS	8
#define C_NOSPLIT	16
#define C_NONEWLINE	32

#define SP_LINE		1
#define SP_WORD		2
#define SP_WIDE		3

#define mb2wc(w,p,n)	(*ast.mb_towc)(&w,(char*)p,n)

/*
 * compare the first of an array of integers
 */

static int
mycomp(register const void* a, register const void* b)
{
	if (*((int*)a) < *((int*)b))
		return -1;
	if (*((int*)a) > *((int*)b))
		return 1;
	return 0;
}

static Cut_t*
cutinit(int mode, char* str, Delim_t* wdelim, Delim_t* ldelim, size_t reclen)
{
	register int*	lp;
	register int	c;
	register int	n = 0;
	register int	range = 0;
	register char*	cp = str;
	Cut_t*		cut;

	if (!(cut = (Cut_t*)stakalloc(sizeof(Cut_t) + strlen(cp) * sizeof(int))))
		error(ERROR_exit(1), "out of space");
	if (cut->mb = mbwide())
	{
		memset(cut->space, 0, sizeof(cut->space) / 2);
		memset(cut->space + sizeof(cut->space) / 2, SP_WIDE, sizeof(cut->space) / 2);
	}
	else
		memset(cut->space, 0, sizeof(cut->space));
	cut->wdelim = *wdelim;
	if (wdelim->len == 1)
		cut->space[wdelim->chr] = SP_WORD;
	cut->ldelim = *ldelim;
	cut->eob = (ldelim->len == 1) ? ldelim->chr : 0;
	cut->space[cut->eob] = SP_LINE;
	cut->cflag = (mode&C_CHARS) && cut->mb;
	cut->nosplit = (mode&(C_BYTES|C_NOSPLIT)) == (C_BYTES|C_NOSPLIT) && cut->mb;
	cut->sflag = (mode&C_SUPRESS) != 0;
	cut->nlflag = (mode&C_NONEWLINE) != 0;
	cut->reclen = reclen;
	lp = cut->list;
	for (;;)
		switch(c = *cp++)
		{
		case ' ':
		case '\t':
			while(*cp==' ' || *cp=='\t')
				cp++;
			/*FALLTHROUGH*/
		case 0:
		case ',':
			if(range)
			{
				--range;
				if((n = (n ? (n-range) : (HUGE-1))) < 0)
					error(ERROR_exit(1),"invalid range for c/f option");
				*lp++ = range;
				*lp++ = n;
			}
			else
			{
				*lp++ = --n;
				*lp++ = 1;
			}
			if(c==0)
			{
				register int *dp;
				*lp = HUGE;
				n = 1 + (lp-cut->list)/2;
				qsort(lp=cut->list,n,2*sizeof(*lp),mycomp);
				/* eliminate overlapping regions */
				for(n=0,range= -2,dp=lp; *lp!=HUGE; lp+=2)
				{
					if(lp[0] <= range)
					{
						if(lp[1]==HUGE)
						{
							dp[-1] = HUGE;
							break;
						}
						if((c = lp[0]+lp[1]-range)>0)
						{
							range += c;
							dp[-1] += c;
						}
					}
					else
					{
						range = *dp++ = lp[0];
						if(lp[1]==HUGE)
						{
							*dp++ = HUGE;
							break;
						}
						range += (*dp++ = lp[1]);
					}
				}
				*dp = HUGE;
				lp = cut->list;
				/* convert ranges into gaps */
				for(n=0; *lp!=HUGE; lp+=2)
				{
					c = *lp;
					*lp -= n;
					n = c+lp[1];
				}
				return cut;
			}
			n = range = 0;
			break;

		case '-':
			if(range)
				error(ERROR_exit(1),"bad list for c/f option");
			range = n?n:1;
			n = 0;
			break;

		default:
			if(!isdigit(c))
				error(ERROR_exit(1),"bad list for c/f option");
			n = 10*n + (c-'0');
			break;
		}
	/* NOTREACHED */
}

/*
 * cut each line of file <fdin> and put results to <fdout> using list <list>
 */

static void
cutcols(Cut_t* cut, Sfio_t* fdin, Sfio_t* fdout)
{
	register int		c;
	register int		len;
	register int		ncol = 0;
	register const int*	lp = cut->list;
	register char*		bp;
	register int		skip; /* non-zero for don't copy */
	int			must;
	const char*		xx;

	for (;;)
	{
		if (len = cut->reclen)
			bp = sfreserve(fdin, len, -1);
		else
			bp = sfgetr(fdin, '\n', 0);
		if (!bp && !(bp = sfgetr(fdin, 0, SF_LASTR)))
			break;
		len = sfvalue(fdin);
		xx = 0;
		if (!(ncol = skip  = *(lp = cut->list)))
			ncol = *++lp;
		must = 1;
		do
		{
			if (cut->nosplit)
			{
				register const char*	s = bp;
				register int		w = len < ncol ? len : ncol;
				register int		z;

				while (w > 0)
				{
					if (!(*s & 0x80))
						z = 1;
					else if ((z = mblen(s, w)) <= 0)
					{
						if (s == bp && xx)
						{
							w += s - xx;
							bp = (char*)(s = xx);
							xx = 0;
							continue;
						}
						xx = s;
						if (skip)
							s += w;
						w = 0;
						break;
					}
					s += z;
					w -= z;
				}
				c = s - bp;
				ncol = !w && ncol >= len;
			}
			else if (cut->cflag)
			{
				register const char*	s = bp;
				register int		w = len;
				register int		z;

				while (w > 0 && ncol > 0)
				{
					ncol--;
					if (!(*s & 0x80) || (z = mblen(s, w)) <= 0)
						z = 1;
					s += z;
					w -= z;
					
				}
				c = s - bp;
				ncol = !w && (ncol || !skip);
			}
			else
			{
				if ((c = ncol) > len)
					c = len;
				else if (c == len && !skip)
					ncol++;
				ncol -= c;
			}
			if (!skip && c)
			{
				if (sfwrite(fdout, (char*)bp, c) < 0)
					return;
				must = 0;
			}
			bp += c;
			if (ncol)
				break;
			len -= c;
			ncol = *++lp;
			skip = !skip;
		} while (ncol != HUGE);
		if (!cut->nlflag && (skip || must || cut->reclen))
		{
			if (cut->ldelim.len > 1)
				sfwrite(fdout, cut->ldelim.str, cut->ldelim.len);
			else
				sfputc(fdout, cut->ldelim.chr);
		}
	}
}

/*
 * cut each line of file <fdin> and put results to <fdout> using list <list>
 * stream <fdin> must be line buffered
 */

static void
cutfields(Cut_t* cut, Sfio_t* fdin, Sfio_t* fdout)
{
	register unsigned char *sp = cut->space;
	register unsigned char *cp;
	register unsigned char *wp;
	register int c, nfields;
	register const int *lp = cut->list;
	register unsigned char *copy;
	register int nodelim, empty, inword=0;
	register unsigned char *ep;
	unsigned char *bp, *first;
	int lastchar;
	wchar_t w;
	Sfio_t *fdtmp = 0;
	long offset = 0;
	unsigned char mb[8];
	/* process each buffer */
	while ((bp = (unsigned char*)sfreserve(fdin, SF_UNBOUND, -1)) && (c = sfvalue(fdin)) > 0)
	{
		cp = bp;
		ep = cp + --c;
		if((lastchar = cp[c]) != cut->eob)
			*ep = cut->eob;
		/* process each line in the buffer */
		while (cp <= ep)
		{
			first = cp;
			if (!inword)
			{
				nodelim = empty = 1;
				copy = cp;
				if (nfields = *(lp = cut->list))
					copy = 0;
				else
					nfields = *++lp;
			}
			else if (copy)
				copy = cp;
			inword = 0;
			do
			{
				/* skip over non-delimiter characters */
				if (cut->mb)
					for (;;)
					{
						switch (c = sp[*(unsigned char*)cp++])
						{
						case 0:
							continue;
						case SP_WIDE:
							wp = --cp;
							while ((c = mb2wc(w, cp, ep - cp)) <= 0)
							{
								/* mb char possibly spanning buffer boundary -- fun stuff */
								if ((ep - cp) < mbmax())
								{
									int	i;
									int	j;
									int	k;

									if (lastchar != cut->eob)
									{
										*ep = lastchar;
										if ((c = mb2wc(w, cp, ep - cp)) > 0)
											break;
									}
									if (copy)
									{
										empty = 0;
										if ((c = cp - copy) > 0 && sfwrite(fdout, (char*)copy, c) < 0)
											goto failed;
									}
									for (i = 0; i <= (ep - cp); i++)
										mb[i] = cp[i];
									if (!(bp = (unsigned char*)sfreserve(fdin, SF_UNBOUND, -1)) || (c = sfvalue(fdin)) <= 0)
										goto failed;
									cp = bp;
									ep = cp + --c;
									if ((lastchar = cp[c]) != cut->eob)
										*ep = cut->eob;
									j = i;
									k = 0;
									while (j < mbmax())
										mb[j++] = cp[k++];
									if ((c = mb2wc(w, (char*)mb, j)) <= 0)
									{
										c = i;
										w = 0;
									}
									first = bp = cp += c - i;
									if (copy)
									{
										copy = bp;
										if (w == cut->ldelim.chr)
											lastchar = cut->ldelim.chr;
										else if (w != cut->wdelim.chr)
										{
											empty = 0;
											if (sfwrite(fdout, (char*)mb, c) < 0)
												goto failed;
										}
									}
									c = 0;
								}
								else
								{
									w = *cp;
									c = 1;
								}
								break;
							}
							cp += c;
							c = w;
							if (c == cut->wdelim.chr)
							{
								c = SP_WORD;
								break;
							}
							if (c == cut->ldelim.chr)
							{
								c = SP_LINE;
								break;
							}
							continue;
						default:
							wp = cp - 1;
							break;
						}
						break;
					}
				else
				{
					while (!(c = sp[*cp++]));
					wp = cp - 1;
				}
				/* check for end-of-line */
				if (c == SP_LINE)
				{
					if (cp <= ep)
						break;
					if (lastchar == cut->ldelim.chr)
						break;
					/* restore cut->last character */
					if (lastchar != cut->eob)
						*ep = lastchar;
					inword++;
					if (!sp[lastchar])
						break;
				}
				nodelim = 0;	
				if (--nfields > 0)
					continue;
				nfields = *++lp;
				if (copy)
				{
					empty = 0;
					if ((c = wp - copy) > 0 && sfwrite(fdout, (char*)copy, c) < 0)
						goto failed;
					copy = 0;
				}
				else
					/* set to delimiter unless the first field */
					copy = empty ? cp : wp;
			} while (!inword);
			if (!inword)
			{
				if (!copy)
				{
					if (nodelim)
					{
						if (!cut->sflag)
						{
							if (offset)
							{
								sfseek(fdtmp,(Sfoff_t)0,SEEK_SET);
								sfmove(fdtmp,fdout,offset,-1);
							}
							copy = first;
						}
					}
					else
						sfputc(fdout,'\n');
				}
				if (offset)
					sfseek(fdtmp,offset=0,SEEK_SET);
			}
			if (copy && (c=cp-copy)>0 && (!nodelim || !cut->sflag) && sfwrite(fdout,(char*)copy,c)< 0)
				goto failed;
		}
		/* see whether to save in tmp file */
		if(inword && nodelim && !cut->sflag && (c=cp-first)>0)
		{
			/* copy line to tmpfile in case no fields */
			if(!fdtmp)
				fdtmp = sftmp(BLOCK);
			sfwrite(fdtmp,(char*)first,c);
			offset +=c;
		}
	}
 failed:
	if(fdtmp)
		sfclose(fdtmp);
}

int
b_cut(int argc, char** argv, void* context)
{
	register char*		cp = 0;
	register Sfio_t*	fp;
	char*			s;
	int			n;
	Cut_t*			cut;
	int			mode = 0;
	Delim_t			wdelim;
	Delim_t			ldelim;
	size_t			reclen = 0;

	cmdinit(argc, argv, context, ERROR_CATALOG, 0);
	wdelim.chr = '\t';
	ldelim.chr = '\n';
	wdelim.len = ldelim.len = 1;
	for (;;)
	{
		switch (n = optget(argv, usage))
		{
		case 0:
			break;
		case 'b':
		case 'c':
			if(mode&C_FIELDS)
			{
				error(2, "f option already specified");
				continue;
			}
			cp = opt_info.arg;
			if(n=='b')
				mode |= C_BYTES;
			else
				mode |= C_CHARS;
			continue;
		case 'D':
			ldelim.str = opt_info.arg;
			if (mbwide())
			{
				s = opt_info.arg;
				ldelim.chr = mbchar(s);
				if ((n = s - opt_info.arg) > 1)
				{
					ldelim.len = n;
					continue;
				}
			}
			ldelim.chr = *(unsigned char*)opt_info.arg;
			ldelim.len = 1;
			continue;
		case 'd':
			wdelim.str = opt_info.arg;
			if (mbwide())
			{
				s = opt_info.arg;
				wdelim.chr = mbchar(s);
				if ((n = s - opt_info.arg) > 1)
				{
					wdelim.len = n;
					continue;
				}
			}
			wdelim.chr = *(unsigned char*)opt_info.arg;
			wdelim.len = 1;
			continue;
		case 'f':
			if(mode&(C_CHARS|C_BYTES))
			{
				error(2, "c option already specified");
				continue;
			}
			cp = opt_info.arg;
			mode |= C_FIELDS;
			continue;
		case 'n':
			mode |= C_NOSPLIT;
			continue;
		case 'N':
			mode |= C_NONEWLINE;
			continue;
		case 'R':
		case 'r':
			if(opt_info.num>0)
				reclen = opt_info.num;
			continue;
		case 's':
			mode |= C_SUPRESS;
			continue;
		case ':':
			error(2, "%s", opt_info.arg);
			break;
		case '?':
			error(ERROR_usage(2), "%s", opt_info.arg);
			break;
		}
		break;
	}
	argv += opt_info.index;
	if (error_info.errors)
		error(ERROR_usage(2), "%s",optusage(NiL));
	if(!cp)
	{
		error(2, "b, c or f option must be specified");
		error(ERROR_usage(2), "%s", optusage(NiL));
	}
	if(!*cp)
		error(3, "non-empty b, c or f option must be specified");
	if((mode & (C_FIELDS|C_SUPRESS)) == C_SUPRESS)
		error(3, "s option requires f option");
	cut = cutinit(mode, cp, &wdelim, &ldelim, reclen);
	if(cp = *argv)
		argv++;
	do
	{
		if(!cp || streq(cp,"-"))
			fp = sfstdin;
		else if(!(fp = sfopen(NiL,cp,"r")))
		{
			error(ERROR_system(0),"%s: cannot open",cp);
			continue;
		}
		if(mode&C_FIELDS)
			cutfields(cut,fp,sfstdout);
		else
			cutcols(cut,fp,sfstdout);
		if(fp!=sfstdin)
			sfclose(fp);
	} while(cp = *argv++);
	if (sfsync(sfstdout))
		error(ERROR_system(0), "write error");
	return error_info.errors != 0;
}
