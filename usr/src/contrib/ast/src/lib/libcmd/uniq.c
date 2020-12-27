/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1992-2012 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                 Eclipse Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*          http://www.eclipse.org/org/documents/epl-v10.html           *
*         (with md5 checksum b35adb5213ca9657e911e9befb180842)         *
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
"[-n?\n@(#)$Id: uniq (AT&T Research) 2009-11-28 $\n]"
USAGE_LICENSE
"[+NAME?uniq - Report or filter out repeated lines in a file]"
"[+DESCRIPTION?\buniq\b reads the input, compares adjacent lines, and "
	"writes one copy of each input line on the output.  The second "
	"and succeeding copies of the repeated adjacent lines are not "
	"written.]"
"[+?If the output file, \aoutfile\a, is not specified, \buniq\b writes "
	"to standard output.  If no \ainfile\a is given, or if the \ainfile\a "
	"is \b-\b, \buniq\b reads from standard input with the start of "
	"the file defined as the current offset.]"
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
    "the BRE \b[[:blank:]]]]*[^[:blank:]]]]*\b. -\anumber\a is equivalent to "
    "\b--skip-fields\b=\anumber\a.]"
"[i:ignore-case?Ignore case in comparisons.]"
"[s:skip-chars]#[chars?\achars\a is the number of characters to skip over "
	"before checking for uniqueness.  If specified along with \b-f\b, "
	"the first \achars\a after the first \afields\a are ignored.  If "
	"the \achars\a specifies more characters than are on the line, "
	"an empty string will be used for comparison. +\anumber\a is "
	"equivalent to \b--skip-chars\b=\anumber\a.]"
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
	register int n, f, outsize=0, mb = mbwide();
	register char *cp, *ep, *mp, *bufp, *outp;
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
		if (n)
		{
			cp = bufp;
			ep = cp + n;
			if (f = fields)
				while (f-->0 && cp<ep) /* skip over fields */
				{
					while (cp<ep && *cp==' ' || *cp=='\t')
						cp++;
					while (cp<ep && *cp!=' ' && *cp!='\t')
						cp++;
				}
			if (chars)
			{
				if (mb)
					for (f = chars; f; f--)
						mbchar(cp);
				else
					cp += chars;
			}
			if ((reclen = n - (cp - bufp)) <= 0)
			{
				reclen = 1;
				cp = bufp + n - 1;
			}
			else if (width >= 0 && width < reclen)
			{
				if (mb)
				{
					reclen = 0;
					mp = cp;
					while (reclen < width && mp < ep)
					{
						reclen++;
						mbchar(mp);
					}
					reclen = mp - cp;
				}
				else
					reclen = width;
			}
		}
		else
			reclen = -2;
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
						if(count<9)
						{
							f = 0;
							while(f < CWIDTH-1)
								outp[f++] = ' ';
							outp[f++] = '0' + count + 1;
							outp[f] = ' ';
						}
						else if(count<MAXCNT)
						{
							count++;
							f = CWIDTH;
							outp[f--] = ' ';
							do
							{
								outp[f--] = '0' + (count % 10);
							} while (count /= 10);
							while (f >= 0)
								outp[f--] = ' ';
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
b_uniq(int argc, char** argv, Shbltin_t* context)
{
	register int mode=0;
	register char *cp;
	int fields=0, chars=0, width=-1;
	Sfio_t *fpin, *fpout;
	int* all = 0;
	int sep;
	Compare_f compare = (Compare_f)memcmp;

	cmdinit(argc, argv, context, ERROR_CATALOG, 0);
	for (;;)
	{
		switch (optget(argv, usage))
		{
		case 'c':
			mode |= C_FLAG;
			continue;
		case 'd':
			mode |= D_FLAG;
			continue;
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
			continue;
		case 'i':
			compare = (Compare_f)strncasecmp;
			continue;
		case 'u':
			mode |= U_FLAG;
			continue;
		case 'f':
			if(*opt_info.option=='-')
				fields = opt_info.num;
			else
				chars = opt_info.num;
			continue;
		case 's':
			chars = opt_info.num;
			continue;
		case 'w':
			width = opt_info.num;
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

