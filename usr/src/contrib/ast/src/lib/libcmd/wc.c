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
 * count the number of bytes, words, and lines in a file
 */

static const char usage[] =
"[-?\n@(#)$Id: wc (AT&T Research) 2009-11-28 $\n]"
USAGE_LICENSE
"[+NAME?wc - print the number of bytes, words, and lines in files]"
"[+DESCRIPTION?\bwc\b reads one or more input files and, by default, "
	"for each file writes a line containing the number of newlines, "
	"\aword\as, and bytes contained in each file followed by the "
	"file name to standard output in that order.  A \aword\a is "
	"defined to be a non-zero length string delimited by \bisspace\b(3) "
	"characters.]"
"[+?If more than one file is specified, \bwc\b writes a total count "
	"for all of the named files with \btotal\b written instead "
	"of the file name.]"
"[+?By default, \bwc\b writes all three counts.  Options can specified "
	"so that only certain counts are written.  The options \b-c\b "
	"and \b-m\b are mutually exclusive.]"
"[+?If no \afile\a is given, or if the \afile\a is \b-\b, \bwc\b "
        "reads from standard input and no filename is written to standard "
	"output.  The start of the file is defined as the current offset.]"
"[l:lines?List the line counts.]"
"[w:words?List the word counts.]"
"[c:bytes|chars:chars?List the byte counts.]"
"[m|C:multibyte-chars?List the character counts.]"
"[q:quiet?Suppress invalid multibyte character warnings.]"
"[L:longest-line|max-line-length?List the longest line length; the newline,"
    "if any, is not counted in the length.]"
"[N!:utf8?For \bUTF-8\b locales \b--noutf8\b disables \bUTF-8\b "
    "optimzations and relies on the native \bmbtowc\b(3).]"
"\n"
"\n[file ...]\n"
"\n"
"[+EXIT STATUS?]{"
        "[+0?All files processed successfully.]"
        "[+>0?One or more files failed to open or could not be read.]"
"}"
"[+SEE ALSO?\bcat\b(1), \bisspace\b(3)]"
;


#include <cmd.h>
#include <wc.h>
#include <ls.h>

#define ERRORMAX	125

static void printout(register Wc_t *wp, register char *name,register int mode)
{
	if (mode&WC_LINES)
		sfprintf(sfstdout," %7I*d",sizeof(wp->lines),wp->lines);
	if (mode&WC_WORDS)
		sfprintf(sfstdout," %7I*d",sizeof(wp->words),wp->words);
	if (mode&WC_CHARS)
		sfprintf(sfstdout," %7I*d",sizeof(wp->chars),wp->chars);
	if (mode&WC_LONGEST)
		sfprintf(sfstdout," %7I*d",sizeof(wp->chars),wp->longest);
	if (name)
		sfprintf(sfstdout," %s",name);
	sfputc(sfstdout,'\n');
}

int
b_wc(int argc,register char **argv, Shbltin_t* context)
{
	register char	*cp;
	register int	mode=0, n;
	register Wc_t	*wp;
	Sfio_t		*fp;
	Sfoff_t		tlines=0, twords=0, tchars=0;
	struct stat	statb;

	cmdinit(argc, argv, context, ERROR_CATALOG, 0);
	for (;;)
	{
		switch (optget(argv, usage))
		{
		case 'c':
			mode |= WC_CHARS;
			continue;
		case 'l':
			mode |= WC_LINES;
			continue;
		case 'L':
			mode |= WC_LONGEST;
			continue;
		case 'N':
			if (!opt_info.num)
				mode |= WC_NOUTF8;
			continue;
		case 'm':
		case 'C':
			mode |= WC_MBYTE;
			continue;
		case 'q':
			mode |= WC_QUIET;
			continue;
		case 'w':
			mode |= WC_WORDS;
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
		error(ERROR_usage(2), "%s", optusage(NiL));
	if (mode&WC_MBYTE)
	{
		if (mode&WC_CHARS)
			error(2, "-c and -C are mutually exclusive");
		if (!mbwide())
			mode &= ~WC_MBYTE;
		mode |= WC_CHARS;
	}
	if (!(mode&(WC_WORDS|WC_CHARS|WC_LINES|WC_MBYTE|WC_LONGEST)))
		mode |= (WC_WORDS|WC_CHARS|WC_LINES);
	if (!(wp = wc_init(mode)))
		error(3,"internal error");
	if (cp = *argv)
		argv++;
	n = 0;
	do
	{
		if (!cp || streq(cp,"-"))
			fp = sfstdin;
		else if (!(fp = sfopen(NiL,cp,"r")))
		{
			error(ERROR_system(0),"%s: cannot open",cp);
			continue;
		}
		if (cp)
			n++;
		if (!(mode&(WC_WORDS|WC_LINES|WC_MBYTE|WC_LONGEST)) && fstat(sffileno(fp),&statb)>=0
			 && S_ISREG(statb.st_mode))
		{
			wp->chars = statb.st_size - lseek(sffileno(fp),0L,1);
			lseek(sffileno(fp),0L,2);
		}
		else
			wc_count(wp, fp, cp);
		if (fp!=sfstdin)
			sfclose(fp);
		tchars += wp->chars;
		twords += wp->words;
		tlines += wp->lines;
		printout(wp,cp,mode);
	} while (cp= *argv++);
	if (n > 1)
	{
		wp->lines = tlines;
		wp->chars = tchars;
		wp->words = twords;
		printout(wp,"total",mode);
	}
	return error_info.errors<ERRORMAX?error_info.errors:ERRORMAX;
}
