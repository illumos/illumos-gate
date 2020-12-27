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
 * David Korn
 * AT&T Bell Laboratories
 *
 * paste [-s] [-d delim] [file] ...
 *
 * paste lines from files together
 */

static const char usage[] =
"[-?\n@(#)$Id: paste (AT&T Research) 2010-06-12 $\n]"
USAGE_LICENSE
"[+NAME?paste - merge lines of files]"
"[+DESCRIPTION?\bpaste\b concatenates the corresponding lines of a "
	"given input file and writes the resulting lines to standard "
	"output.  By default \bpaste\b replaces the newline character of "
	"every line other than the last input file with the TAB character.]"
"[+?Unless the \b-s\b option is specified, if an end-of-file is encountered "
	"on one or more input files, but not all input files, \bpaste\b "
	"behaves as if empty lines were read from the file(s) on which "
	"end-of-file was detected.]"
"[+?Unless the \b-s\b option is specified, \bpaste\b is limited by "
	"the underlying operating system on how many \afile\a operands "
	"can be specified.]"
"[+?If no \afile\a operands are given or if the \afile\a is \b-\b, \bpaste\b "
	"reads from standard input. The start of the file is defined as the "
	"current offset.]"

"[s:serial?Paste the lines of one file at a time rather than one line "
	"from each file.  In this case if the \b-d\b option is "
	"specified the delimiter will be reset to the first in the "
	"list at the beginning of each file.]"
"[d:delimiters]:[list?\alist\a specifies a list of delimiters.  These "
	"delimiters are used circularly instead of TAB to replace "
	"the newline character of the input lines. Unless the \b-s\b "
	"option is specified, the delimiter will be reset to the first "
	"element of \alist\a each time a line is processed from each file.  "
	"The delimiter characters corresponding to \alist\a will be found "
	"by treating \alist\a as an ANSI-C string, except that the \b\\0\b "
	"sequence will insert the empty string instead of the null character.]"
"\n"
"\n[file ...]\n"
"\n"
"[+EXIT STATUS?]{"
	"[+0?All files processed successfully.]"
	"[+>0?An error occurred.]"
"}"
"[+SEE ALSO?\bcut\b(1), \bcat\b(1), \bjoin\b(1)]"
;

#include <cmd.h>

typedef struct Delim_s
{
	const char*	chr;
	size_t		len;
} Delim_t;

/*
 * paste the lines of the <nstreams> defined in <streams> and put results
 * to <out>
 */

static int paste(int nstream,Sfio_t* streams[],Sfio_t *out, register const char *delim, int dsiz, int dlen, Delim_t* mp)
{
	register const char *cp;
	register int d, n, i, z, more=1;
	register Sfio_t *fp;
	do
	{
		d = (dlen>0?0:-1);
		for(n=more-1,more=0; n < nstream;)
		{
			if(fp=streams[n])
			{
				if(cp = sfgetr(fp,'\n',0))
				{
					if(n==0)
						more = 1;
					else if(!more) /* first stream with output */
					{
						if(dsiz == 1)
							sfnputc(out, *delim, n);
						else if(dlen>0)
						{
							for(d=n; d>dlen; d-=dlen)
								sfwrite(out,delim,dsiz);
							if(d)
							{
								if(mp)
									for (i = z = 0; i < d; i++)
										z += mp[i].len;
								else
									z = d;
								sfwrite(out,delim,z);
							}
						}
						more = n+1;
					}
					if(sfwrite(out,cp,sfvalue(fp)-((n+1)<nstream)) < 0)
						return(-1);
				}
				else
					streams[n] = 0;
			}
			if(++n<nstream && more && d>=0)
			{
				register int c;
				if(d >= dlen)
					d = 0;
				if(mp)
					sfwrite(out,mp[d].chr,mp[d].len);
				else if(c=delim[d])
					sfputc(out,c);
				d++;
			}
			else if(n==nstream && !streams[n-1] && more)
				sfputc(out,'\n');
		}
	} while(more);
	return(0);
}

/*
 * Handles paste -s, for file <in> to file <out> using delimiters <delim>
 */
static int spaste(Sfio_t *in,register Sfio_t* out,register const char *delim,int dsiz,int dlen,Delim_t* mp)
{
	register const char *cp;
	register int d=0;
	if((cp = sfgetr(in,'\n',0)) && sfwrite(out,cp,sfvalue(in)-1) < 0)
		return(-1);
	while(cp=sfgetr(in, '\n',0)) 
	{
		if(dlen)
		{
			register int c;
			if(d >= dlen)
				d = 0;
			if(mp)
				sfwrite(out,mp[d].chr,mp[d].len);
			else if(c=delim[d])
				sfputc(out,c);
			d++;
		}
		if(sfwrite(out,cp,sfvalue(in)-1) < 0)
			return(-1);
	}
	sfputc(out,'\n');
	return(0);
}

int
b_paste(int argc, char** argv, Shbltin_t* context)
{
	register int		n, sflag=0;
	register Sfio_t		*fp, **streams;
	register char 		*cp, *delim;
	char			*ep;
	Delim_t			*mp;
	int			dlen, dsiz;
	char			defdelim[2];

	cmdinit(argc, argv, context, ERROR_CATALOG, 0);
	delim = 0;
	for (;;)
	{
		switch (optget(argv, usage))
		{
		case 'd':
			delim = opt_info.arg;
			continue;
		case 's':
			sflag++;
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
	if(error_info.errors)
		error(ERROR_usage(2),"%s", optusage(NiL));
	if(!delim || !*delim)
	{
		delim = defdelim;
		delim[0] = '\t';
		delim[1] = 0;
	}
	if (!(delim = strdup(delim)))
		error(ERROR_system(1), "out of space");
	dlen = dsiz = stresc(delim);
	mp = 0;
	if (mbwide())
	{
		cp = delim;
		ep = delim + dlen;
		dlen = 0;
		while (cp < ep)
		{
			mbchar(cp);
			dlen++;
		}
		if(dlen < dsiz)
		{
			if (!(mp = newof(0, Delim_t, dlen, 0)))
			{
				free(delim);
				error(ERROR_system(1), "out of space");
			}
			cp = delim;
			dlen = 0;
			while (cp < ep)
			{
				mp[dlen].chr = cp;
				mbchar(cp);
				mp[dlen].len = cp - mp[dlen].chr;
				dlen++;
			}
		}
	}
	if(cp = *argv)
	{
		n = argc - opt_info.index;
		argv++;
	}
	else
		n = 1;
	if(!sflag)
	{
		if (!(streams = (Sfio_t**)stakalloc(n*sizeof(Sfio_t*))))
			error(ERROR_exit(1), "out of space");
		n = 0;
	}
	do
	{
		if(!cp || streq(cp,"-"))
			fp = sfstdin;
		else if(!(fp = sfopen(NiL,cp,"r")))
			error(ERROR_system(0),"%s: cannot open",cp);
		if(fp && sflag)
		{
			if(spaste(fp,sfstdout,delim,dsiz,dlen,mp) < 0)
				error(ERROR_system(0),"write failed");
			if(fp!=sfstdin)
				sfclose(fp);
		}
		else if(!sflag)
			streams[n++] = fp;
	} while(cp= *argv++);
	if(!sflag)
	{
		if(error_info.errors==0 && paste(n,streams,sfstdout,delim,dsiz,dlen,mp) < 0)
			error(ERROR_system(0),"write failed");
		while(--n>=0)
			if((fp=streams[n]) && fp!=sfstdin)
				sfclose(fp);
	}
	if (mp)
		free(mp);
	free(delim);
	return(error_info.errors);
}
