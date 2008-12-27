/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1992-2008 AT&T Intellectual Property          *
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
 * uniq
 *
 * Written by David Korn
 */

static const char usage[] =
"[-n?\n@(#)$Id: uniq (AT&T Research) 2008-04-24 $\n]"
USAGE_LICENSE
"[+NAME?uniq - Report or filter out repeated lines in a file]"
"[+DESCRIPTION?\buniq\b reads an input, comparing adjacent lines, and "
	"writing one copy of each input line on the output.  The second "
	"and succeeding copies of the repeated adjacent lines are not "
	"written.]"
"[+?If the output file, \aoutfile\a, is not specified, \buniq\b writes "
	"to standard output.  If no \ainfile\a is given, or if the \ainfile\a "
	"is \b-\b, \buniq\b reads from standard input with  the start of "
	"the file is defined as the current offset.]"
"[c:count?Output the number of times each line occurred  along with "
	"the line.]"
"[d:repeated|duplicates?Output the first of each duplicate line.]"
"[D:all-repeated?Output all duplicate lines as a group with an empty "
    "line delimiter specified by \adelimit\a:]:?[delimit:=none]"
    "{"
        "[n:none?Do not delimit duplicate groups.]"
        "[p:prepend?Prepend an empty line before each group.]"
        "[s:separate?Separate each group with an empty line.]"
    "}"
"[f:skip-fields]#[fields?\afields\a is the number of fields to skip over "
    "before checking for uniqueness. A field is the minimal string matching "
    "the BRE \b[[:blank:]]]]*[^[:blank:]]]]*\b.]"
"[i:ignore-case?Ignore case in comparisons.]"
"[s:skip-chars]#[chars?\achars\a is the number of characters to skip over "
	"before checking for uniqueness.  If specified along with \b-f\b, "
	"the first \achars\a after the first \afields\a are ignored.  If "
	"the \achars\a specifies more characters than are on the line, "
	"an empty string will be used for comparison.]"
"[u:unique?Output unique lines.]"
"[w:check-chars]#[chars?\achars\a is the number of characters to compare " 
	"after skipping any specified fields and characters.]"
"\n"
"\n[infile [outfile]]\n"
"\n"
"[+EXIT STATUS?]{"
	"[+0?The input file was successfully processed.]"
	"[+>0?An error occurred.]"
"}"
"[+SEE ALSO?\bsort\b(1), \bgrep\b(1)]"
;

#include <cmd.h>

#define C_FLAG	1
#define D_FLAG	2
#define U_FLAG	4

#define CWIDTH	4
#define MAXCNT	9999

typedef int (*Compare_f)(const char*, const char*, size_t);

static int uniq(Sfio_t *fdin, Sfio_t *fdout, int fields, int chars, int width, int mode, int* all, Compare_f compare)
{
	register int n, f, outsize=0;
	register char *cp, *ep, *bufp, *outp;
	char *orecp, *sbufp=0, *outbuff;
	int reclen,oreclen= -1,count=0,cwidth=0,sep,next;
	if(mode&C_FLAG)
		cwidth = CWIDTH+1;
	while(1)
	{
		if(bufp = sfgetr(fdin,'\n',0))
			n = sfvalue(fdin);
		else if(bufp = sfgetr(fdin,'\n',SF_LASTR))
		{
			n = sfvalue(fdin);
			bufp = memcpy(fmtbuf(n + 1), bufp, n);
			bufp[n++] = '\n';
		}
		else
			n = 0;
		if(n)
		{
			cp = bufp;
			ep = cp + n;
			if(f=fields)
				while(f-->0 && cp<ep) /* skip over fields */
				{
					while(cp<ep && *cp==' ' || *cp=='\t')
						cp++;
					while(cp<ep && *cp!=' ' && *cp!='\t')
						cp++;
				}
			if(chars)
				cp += chars;
			if((reclen = n - (cp-bufp)) <=0)
			{
				reclen = 1;
				cp = bufp + sfvalue(fdin)-1;
			}
			else if(width >= 0 && width < reclen)
				reclen = width;
		}
		else
			reclen=-2;
		if(reclen==oreclen && (!reclen || !(*compare)(cp,orecp,reclen)))
		{
			count++;
			if (!all)
				continue;
			next = count;
		}
		else
		{
			next = 0;
			if(outsize>0)
			{
				if(((mode&D_FLAG)&&count==0) || ((mode&U_FLAG)&&count))
				{
					if(outp!=sbufp)
						sfwrite(fdout,outp,0);
				}
				else
				{
					if(cwidth)
					{
						outp[CWIDTH] = ' ';
						if(count<MAXCNT)
						{
							sfsprintf(outp,cwidth,"%*d",CWIDTH,count+1);
							outp[CWIDTH] = ' ';
						}
						else
						{
							outsize -= (CWIDTH+1);
							if(outp!=sbufp)
							{
								if(!(sbufp=fmtbuf(outsize)))
									return(1);
								memcpy(sbufp,outp+CWIDTH+1,outsize);
								sfwrite(fdout,outp,0);
								outp = sbufp;
							}
							else
								outp += CWIDTH+1;
							sfprintf(fdout,"%4d ",count+1);
						}
					}
					if(sfwrite(fdout,outp,outsize) != outsize)
						return(1);
				}
			}
		}
		if(n==0)
			break;
		if(count = next)
		{
			if(sfwrite(fdout,outp,outsize) != outsize)
				return(1);
			if(*all >= 0)
				*all = 1;
			sep = 0;
		}
		else
			sep = all && *all > 0;
		/* save current record */
		if (!(outbuff = sfreserve(fdout, 0, 0)) || (outsize = sfvalue(fdout)) < 0)
			return(1);
		outp = outbuff;
		if(outsize < n+cwidth+sep)
		{
			/* no room in outp, clear lock and use side buffer */
			sfwrite(fdout,outp,0);
			if(!(sbufp = outp=fmtbuf(outsize=n+cwidth+sep)))
				return(1);
		}
		else
			outsize = n+cwidth+sep;
		memcpy(outp+cwidth+sep,bufp,n);
		if(sep)
			outp[cwidth] = '\n';
		oreclen = reclen;
		orecp = outp+cwidth+sep + (cp-bufp);
	}
	return(0);
}

int
b_uniq(int argc, char** argv, void* context)
{
	register int n, mode=0;
	register char *cp;
	int fields=0, chars=0, width=-1;
	Sfio_t *fpin, *fpout;
	int* all = 0;
	int sep;
	Compare_f compare = (Compare_f)memcmp;

	cmdinit(argc, argv, context, ERROR_CATALOG, 0);
	while (n = optget(argv, usage)) switch (n)
	{
	    case 'c':
		mode |= C_FLAG;
		break;
	    case 'd':
		mode |= D_FLAG;
		break;
	    case 'D':
		mode |= D_FLAG;
		switch ((int)opt_info.num)
		{
		case 'p':
			sep = 1;
			break;
		case 's':
			sep = 0;
			break;
		default:
			sep = -1;
			break;
		}
		all = &sep;
		break;
	    case 'i':
		compare = (Compare_f)strncasecmp;
		break;
	    case 'u':
		mode |= U_FLAG;
		break;
	    case 'f':
		if(*opt_info.option=='-')
			fields = opt_info.num;
		else
			chars = opt_info.num;
		break;
	    case 's':
		chars = opt_info.num;
		break;
	    case 'w':
		width = opt_info.num;
		break;
	    case ':':
		error(2, "%s", opt_info.arg);
		break;
	    case '?':
		error(ERROR_usage(2), "%s", opt_info.arg);
		break;
	}
	argv += opt_info.index;
	if(all && (mode&C_FLAG))
		error(2, "-c and -D are mutually exclusive");
	if(error_info.errors)
		error(ERROR_usage(2), "%s", optusage(NiL));
	if((cp = *argv) && (argv++,!streq(cp,"-")))
	{
		if(!(fpin = sfopen(NiL,cp,"r")))
			error(ERROR_system(1),"%s: cannot open",cp);
	}
	else
		fpin = sfstdin;
	if(cp = *argv)
	{
		argv++;
		if(!(fpout = sfopen(NiL,cp,"w")))
			error(ERROR_system(1),"%s: cannot create",cp);
	}
	else
		fpout = sfstdout;
	if(*argv)
	{
		error(2, "too many arguments");
		error(ERROR_usage(2), "%s", optusage(NiL));
	}
	error_info.errors = uniq(fpin,fpout,fields,chars,width,mode,all,compare);
	if(fpin!=sfstdin)
		sfclose(fpin);
	if(fpout!=sfstdout)
		sfclose(fpout);
	return(error_info.errors);
}

