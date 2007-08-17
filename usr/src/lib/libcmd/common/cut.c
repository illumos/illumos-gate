/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*           Copyright (c) 1992-2007 AT&T Knowledge Ventures            *
*                      and is licensed under the                       *
*                  Common Public License, Version 1.0                  *
*                      by AT&T Knowledge Ventures                      *
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
 * cut [-sN] [-f flist] [-c clist] [-d delim] [-D delim] [-r reclen] [file] ...
 *
 * cut fields or columns from fields from a file
 */

static const char usage[] =
"[-?\n@(#)$Id: cut (AT&T Research) 2007-01-23 $\n]"
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
"[b:bytes]:[list?\bcut\b based on a list of bytes.]"
"[c:characters]:[list?\bcut\b based on a list of characters.]"
"[d:delimiter]:[delim?The field character for the \b-f\b option is set "
	"to \adelim\a.  The default is the \btab\b character.]"
"[f:fields]:[list?\bcut\b based on fields separated by the delimiter "
	"character specified with the \b-d\b optiion.]"
"[n:nosplit?Do not split characters.  Currently ignored.]"
"[R|r:reclen]#[reclen?If \areclen\a > 0, the input will be read as fixed length "
	"records of length \areclen\a when used with the \b-b\b or \b-c\b "
	"option.]"
"[s:suppress|only-delimited?Suppress lines with no delimiter characters, "
	"when used with the \b-f\b option.  By default, lines with no "
	"delimiters will be passsed in untouched.]"
"[D:line-delimeter|output-delimiter]:[ldelim?The line delimiter character for "
	"the \b-f\b option is set to \aldelim\a.  The default is the "
	"\bnewline\b character.]"
"[N:nonewline?Do not output new-lines at end of each record when used "
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

typedef struct Last_s
{
	int		seqno;
	int		seq;
	int		wdelim;
	int		ldelim;
} Last_t;

typedef struct Cut_s
{
	int		cflag;
	int		sflag;
	int		nlflag;
	int		wdelim;
	int		ldelim;
	int		seqno;
	int		reclen;
	signed char	space[UCHAR_MAX];
	Last_t		last;
	int		list[2];	/* NOTE: must be last member */
} Cut_t;

#define HUGE		(1<<14)
#define BLOCK		8*1024
#define C_BYTES		1
#define C_CHARS		2
#define C_FIELDS	4
#define C_SUPRESS	8
#define C_NOCHOP	16
#define C_NONEWLINE	32

/*
 * compare the first of an array of integers
 */

static int mycomp(register const void *a,register const void *b)
{
	return(*((int*)a) - *((int*)b));
}

static Cut_t *cutinit(int mode,char *str,int wdelim,int ldelim,size_t reclen)
{
	register int *lp, c, n=0;
	register int range = 0;
	register char *cp = str;
	Cut_t *cuthdr;
	if (!(cuthdr = (Cut_t*)stakalloc(sizeof(Cut_t)+strlen(cp)*sizeof(int))))
		error(ERROR_exit(1), "out of space");
	memset(cuthdr->space, 0, sizeof(cuthdr->space));
	cuthdr->last.seqno = 0;
	cuthdr->last.seq = 0;
	cuthdr->last.wdelim = 0;
	cuthdr->last.ldelim = '\n';
	cuthdr->cflag = ((mode&C_CHARS)!=0 && mbwide());
	cuthdr->sflag = ((mode&C_SUPRESS)!=0);
	cuthdr->nlflag = ((mode&C_NONEWLINE)!=0);
	cuthdr->wdelim = wdelim;
	cuthdr->ldelim = ldelim;
	cuthdr->reclen = reclen;
	cuthdr->seqno = ++cuthdr->last.seqno;
	lp = cuthdr->list;
	while(1) switch(c= *cp++)
	{
		case ' ':
		case '\t':
			while(*cp==' ' || *cp=='\t')
				cp++;
		case 0:
		case ',':
			if(range)
			{
				--range;
				if((n = (n==0?HUGE:n-range)) < 0)
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
				n = 1 + (lp-cuthdr->list)/2;
				qsort(lp=cuthdr->list,n,2*sizeof(*lp),mycomp);
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
				lp = cuthdr->list;
				/* convert ranges into gaps */
				for(n=0; *lp!=HUGE; lp+=2)
				{
					c = *lp;
					*lp -= n;
					n = c+lp[1];
				}
				return(cuthdr);
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
	}
	/* NOTREACHED */
}

/*
 * advance <cp> by <n> multi-byte characters
 */
static int advance(const char *str, register int n, register int inlen)
{
	register int size, len=inlen;
	register const char *cp=str;
	while(len>0 && n-->0)
	{
		size = mblen(cp, len);
		if(size<0)
			size = 1;
		cp += size;
		len -= size;
		
	}
	if(n>0)
		return(inlen+1);
	return(cp-str);
}

/*
 * cut each line of file <fdin> and put results to <fdout> using list <list>
 */

static int cutcols(Cut_t *cuthdr,Sfio_t *fdin,Sfio_t *fdout)
{
	register int		c, ncol=0,len;
	register const int	*lp = cuthdr->list;
	register char		*inp;
	register int		skip; /* non-zero for don't copy */
	while(1)
	{
		if(len = cuthdr->reclen)
			inp = sfreserve(fdin, len, -1);
		else
			inp = sfgetr(fdin, '\n', 0);
		if(!inp && !(inp = sfgetr(fdin, 0, SF_LASTR)))
			break;
		len = sfvalue(fdin);
		if((ncol = skip  = *(lp = cuthdr->list)) == 0)
			ncol = *++lp;
		while(1)
		{
			if((c=(cuthdr->cflag?advance(inp,ncol,len):ncol)) > len)
				c = len;
			else if(c==len && !skip)
				ncol++;
			ncol -= c;
			if(!skip && sfwrite(fdout,(char*)inp,c)<0)
				return(-1);
			inp += c;
			if(ncol)
				break;
			len -= c;
			ncol = *++lp;
			skip = !skip;
		}
		if(!cuthdr->nlflag && (skip || cuthdr->reclen))
			sfputc(fdout,cuthdr->ldelim);
	}
	return(c);
}

/*
 * cut each line of file <fdin> and put results to <fdout> using list <list>
 * stream <fdin> must be line buffered
 */

#define endline(c)	(((signed char)-1)<0?(c)<0:(c)==((char)-1))

static int cutfields(Cut_t *cuthdr,Sfio_t *fdin,Sfio_t *fdout)
{
	register unsigned char *cp;
	register int c, nfields;
	register const int *lp = cuthdr->list;
	register unsigned char *copy;
	register int nodelim, empty, inword=0;
	register unsigned char *endbuff;
	unsigned char *inbuff, *first;
	int lastchar;
	Sfio_t *fdtmp = 0;
	long offset = 0;
	if(cuthdr->seqno != cuthdr->last.seq)
	{
		cuthdr->space[cuthdr->last.ldelim] = 0;
		cuthdr->space[cuthdr->last.wdelim] = 0;
		cuthdr->space[cuthdr->last.wdelim=cuthdr->wdelim] = 1;
		cuthdr->space[cuthdr->last.ldelim=cuthdr->ldelim] = -1;
		cuthdr->last.seq = cuthdr->seqno;
	}
	/* process each buffer */
	while ((inbuff = (unsigned char*)sfreserve(fdin, SF_UNBOUND, 0)) && (c = sfvalue(fdin)) > 0)
	{
		cp = inbuff;
		endbuff = cp + --c;
		if((lastchar = cp[c]) != cuthdr->ldelim)
			*endbuff = cuthdr->ldelim;
		/* process each line in the buffer */
		while(cp <= endbuff)
		{
			first = cp;
			if(!inword)
			{
				nodelim = empty = 1;
				copy = cp;
				if(nfields = *(lp = cuthdr->list))
					copy = 0;
				else
					nfields = *++lp;
			}
			else if(copy)
				copy = cp;
			inword = 0;
			while(!inword)
			{
				/* skip over non-delimiter characters */
				while(!(c=cuthdr->space[*cp++]));
				/* check for end-of-line */
				if(endline(c))
				{
					if(cp<=endbuff)
						break;
					if((c=cuthdr->space[lastchar]),endline(c))
						break;
					/* restore cuthdr->last. character */
					if(lastchar != cuthdr->ldelim)
						*endbuff = lastchar;
					inword++;
					if(!c)
						break;
				}
				nodelim = 0;	
				if(--nfields >0)
					continue;
				nfields = *++lp;
				if(copy)
				{
					empty = 0;
					if((c=(cp-1)-copy)>0 && sfwrite(fdout,(char*)copy,c)< 0)
						goto failed;
					copy = 0;
				}
				else
					/* set to delimiter unless the first field */
					copy = cp -!empty;
			}
			if(!inword)
			{
				if(!copy)
				{
					if(nodelim)
					{
						if(!cuthdr->sflag)
						{
							if(offset)
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
				if(offset)
					sfseek(fdtmp,offset=0,SEEK_SET);
			}
			if(copy && (c=cp-copy)>0 && (!nodelim || !cuthdr->sflag) && sfwrite(fdout,(char*)copy,c)< 0)
				goto failed;
		}
		/* see whether to save in tmp file */
		if(nodelim && inword && !cuthdr->sflag && (c=cp-first)>0)
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
	return(0);
}

int
b_cut(int argc,char *argv[], void* context)
{
	register char *cp = 0;
	register Sfio_t *fp;
	int	n;
	Cut_t	*cuthdr;
	int	mode = 0;
	int	wdelim = '\t';
	int	ldelim = '\n';
	size_t	reclen = 0;

	cmdinit(argc, argv, context, ERROR_CATALOG, 0);
	while (n = optget(argv, usage)) switch (n)
	{
	  case 'b':
	  case 'c':
		if(mode&C_FIELDS)
		{
			error(2, "f option already specified");
			break;
		}
		cp = opt_info.arg;
		if(n=='b')
			mode |= C_BYTES;
		else
			mode |= C_CHARS;
		break;
	  case 'D':
		ldelim = *(unsigned char*)opt_info.arg;
		break;
	  case 'd':
		wdelim = *(unsigned char*)opt_info.arg;
		break;
	  case 'f':
		if(mode&(C_CHARS|C_BYTES))
		{
			error(2, "c option already specified");
			break;
		}
		cp = opt_info.arg;
		mode |= C_FIELDS;
		break;
	  case 'n':
		mode |= C_NOCHOP;
		break;
	  case 'N':
		mode |= C_NONEWLINE;
		break;
	  case 'R':
	  case 'r':
		if(opt_info.num>0)
			reclen = opt_info.num;
		break;
	  case 's':
		mode |= C_SUPRESS;
		break;
	  case ':':
		error(2, "%s", opt_info.arg);
		break;
	  case '?':
		error(ERROR_usage(2), "%s", opt_info.arg);
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
	cuthdr = cutinit(mode,cp,wdelim,ldelim,reclen);
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
			cutfields(cuthdr,fp,sfstdout);
		else
			cutcols(cuthdr,fp,sfstdout);
		if(fp!=sfstdin)
			sfclose(fp);
	}
	while(cp= *argv++);
	return(error_info.errors?1:0);
}
