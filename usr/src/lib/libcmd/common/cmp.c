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
 * Glenn Fowler
 * AT&T Bell Laboratories
 *
 * cmp
 */

static const char usage[] =
"[-?\n@(#)$Id: cmp (AT&T Research) 2009-01-05 $\n]"
USAGE_LICENSE
"[+NAME?cmp - compare two files]"
"[+DESCRIPTION?\bcmp\b compares two files \afile1\a and \afile2\a.  "
	"\bcmp\b writes no output if the files are the same.  By default, "
	"if the files differ, the byte and line number at which the "
	"first difference occurred are written to standard output.  Bytes "
	"and lines are numbered beginning with 1.]"
"[+?If \askip1\a or \askip2\a are specified, or the \b-i\b option is "
	"specified, initial bytes of the corresponding file are skipped "
	"before beginning the compare.  The skip values are in bytes or "
	"can have a suffix of \bk\b for kilobytes or \bm\b for megabytes.]"
"[+?If either \afile1\a or \afiles2\a is \b-\b, \bcmp\b "
        "uses standard input starting at the current location.]"
"[c:print-chars?Writes control characters as a \b^\b followed by a letter of "
	"the alphabet and precede characters that have the high bit set with "
	"\bM-\b as with \bcat\b(1).]"
"[i:ignore-initial]#[skip:=0?Sets default skip values for the operands "
	"\askip1\a and \askip2\a to \askip\a.]"
"[l:verbose?Write the decimal byte number and the differing bytes (in octal) "
	"for each difference.]"
"[s:quiet|silent?Write nothing for differing files; return non-zero "
	"exit status only.] ]"
"\n"
"\nfile1 file2 [skip1 [skip2]]\n"
"\n"
"[+EXIT STATUS?]{"
	"[+0?The files or portions compared are identical.]"
	"[+1?The files are different.]"
	"[+>1?An error occurred.]"
"}"
"[+SEE ALSO?\bcomm\b(1), \bdiff\b(1), \bcat\b(1)]"
;


#include <cmd.h>
#include <ls.h>
#include <ctype.h>

#define CMP_VERBOSE	1
#define CMP_SILENT	2
#define CMP_CHARS	4

#define cntl(x)		(x&037)
#define printchar(c)	((c) ^ ('A'-cntl('A')))

static void outchar(Sfio_t *out, register int c, int delim)
{
	if(c&0200)
	{
		sfputc(out,'M');
		sfputc(out,'-');
		c &= ~0200;
	}
	else if(!isprint(c))
	{
		sfputc(out,'^');
		c = printchar(c);
	}
	sfputc(out,c);
	sfputc(out,delim);
}

/*
 * compare two files
 */

static int
cmp(const char* file1, Sfio_t* f1, const char* file2, Sfio_t* f2, int flags)
{
	register int		c1;
	register int		c2;
	register unsigned char*	p1 = 0;
	register unsigned char*	p2 = 0;
	register Sfoff_t	lines = 1;
	register unsigned char*	e1 = 0;
	register unsigned char*	e2 = 0;
	Sfoff_t			pos = 0;
	int			ret = 0;
	unsigned char*		last;

	for (;;)
	{
		if ((c1 = e1 - p1) <= 0)
		{
			if (!(p1 = (unsigned char*)sfreserve(f1, SF_UNBOUND, 0)) || (c1 = sfvalue(f1)) <= 0)
			{
				if ((e2 - p2) > 0 || sfreserve(f2, SF_UNBOUND, 0) && sfvalue(f2) > 0)
				{
					ret = 1;
					if (!(flags & CMP_SILENT))
						error(ERROR_exit(1), "EOF on %s", file1);
				}
				return(ret);
			}
			e1 = p1 + c1;
		}
		if ((c2 = e2 - p2) <= 0)
		{
			if (!(p2 = (unsigned char*)sfreserve(f2, SF_UNBOUND, 0)) || (c2 = sfvalue(f2)) <= 0)
			{
				if (!(flags & CMP_SILENT))
					error(ERROR_exit(1), "EOF on %s", file2);
				return(1);
			}
			e2 = p2 + c2;
		}
		if (c1 > c2)
			c1 = c2;
		pos += c1;
		if (flags & CMP_SILENT)
		{
			if (memcmp(p1, p2, c1))
				return(1);
			p1 += c1;
			p2 += c1;
		}
		else
		{
			last = p1 + c1;
			while (p1 < last)
			{
				if ((c1 = *p1++) != *p2++)
				{
					if (flags)
					{
						ret = 1;
						if(flags&CMP_CHARS)
						{
							sfprintf(sfstdout, "%6I*d ", sizeof(pos), pos - (last - p1));
							outchar(sfstdout,c1,' ');
							outchar(sfstdout,*(p2-1),'\n');
						}
						else
							sfprintf(sfstdout, "%6I*d %3o %3o\n", sizeof(pos), pos - (last - p1), c1, *(p2 - 1));
					}
					else
					{
						sfprintf(sfstdout, "%s %s differ: char %I*d, line %I*u\n", file1, file2, sizeof(pos), pos - (last - p1), sizeof(lines), lines);
						return(1);
					}
				}
				if (c1 == '\n')
					lines++;
			}
		}
	}
}

int
b_cmp(int argc, register char** argv, void* context)
{
	char*		s;
	char*		e;
	Sfio_t*		f1 = 0;
	Sfio_t*		f2 = 0;
	char*		file1;
	char*		file2;
	int		n;
	off_t		o1 = 0;
	off_t		o2 = 0;
	struct stat	s1;
	struct stat	s2;

	int		flags = 0;

	NoP(argc);
	cmdinit(argc, argv, context, ERROR_CATALOG, 0);
	while (n = optget(argv, usage)) switch (n)
	{
	case 'l':
		flags |= CMP_VERBOSE;
		break;
	case 's':
		flags |= CMP_SILENT;
		break;
	case 'c':
		flags |= CMP_CHARS;
		break;
	case 'i':
		o1 = o2 = opt_info.num;
		break;
	case ':':
		error(2, "%s", opt_info.arg);
		break;
	case '?':
		error(ERROR_usage(2), "%s", opt_info.arg);
		break;
	}
	argv += opt_info.index;
	if (error_info.errors || !(file1 = *argv++) || !(file2 = *argv++))
		error(ERROR_usage(2), "%s", optusage(NiL));
	n = 2;
	if (streq(file1, "-"))
		f1 = sfstdin;
	else if (!(f1 = sfopen(NiL, file1, "r")))
	{
		if (!(flags & CMP_SILENT))
			error(ERROR_system(0), "%s: cannot open", file1);
		goto done;
	}
	if (streq(file2, "-"))
		f2 = sfstdin;
	else if (!(f2 = sfopen(NiL, file2, "r")))
	{
		if (!(flags & CMP_SILENT))
			error(ERROR_system(0), "%s: cannot open", file2);
		goto done;
	}
	if (s = *argv++)
	{
		o1 = strtol(s, &e, 0);
		if (*e)
		{
			error(ERROR_exit(0), "%s: %s: invalid skip", file1, s);
			goto done;
		}
		if (s = *argv++)
		{
			o2 = strtol(s, &e, 0);
			if (*e)
			{
				error(ERROR_exit(0), "%s: %s: invalid skip", file2, s);
				goto done;
			}
		}
		if (*argv)
		{
			error(ERROR_usage(0), "%s", optusage(NiL));
			goto done;
		}
	}
	if (o1 && sfseek(f1, o1, SEEK_SET) != o1)
	{
		if (!(flags & CMP_SILENT))
			error(ERROR_exit(0), "EOF on %s", file1);
		n = 1;
		goto done;
	}
	if (o2 && sfseek(f2, o2, SEEK_SET) != o2)
	{
		if (!(flags & CMP_SILENT))
			error(ERROR_exit(0), "EOF on %s", file2);
		n = 1;
		goto done;
	}
	if (fstat(sffileno(f1), &s1))
		error(ERROR_system(0), "%s: cannot stat", file1);
	else if (fstat(sffileno(f2), &s2))
		error(ERROR_system(0), "%s: cannot stat", file1);
	else if (s1.st_ino == s2.st_ino && s1.st_dev == s2.st_dev && o1 == o2)
		n = 0;
	else
		n = ((flags & CMP_SILENT) && S_ISREG(s1.st_mode) && S_ISREG(s2.st_mode) && (s1.st_size - o1) != (s2.st_size - o2)) ? 1 : cmp(file1, f1, file2, f2, flags);
 done:
	if (f1 && f1 != sfstdin) sfclose(f1);
	if (f2 && f2 != sfstdin) sfclose(f2);
	return(n);
}
