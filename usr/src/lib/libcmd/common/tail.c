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
 * print the tail of one or more files
 *
 *   David Korn
 *   Glenn Fowler
 */

static const char usage[] =
"+[-?\n@(#)$Id: tail (AT&T Research) 2006-10-18 $\n]"
USAGE_LICENSE
"[+NAME?tail - output trailing portion of one or more files ]"
"[+DESCRIPTION?\btail\b copies one or more input files to standard output "
	"starting at a designated point for each file.  Copying starts "
	"at the point indicated by the options and is unlimited in size.]"
"[+?By default a header of the form \b==> \b\afilename\a\b <==\b "
	"is output before all but the first file but this can be changed "
	"with the \b-q\b and \b-v\b options.]"
"[+?If no \afile\a is given, or if the \afile\a is \b-\b, \btail\b "
	"copies from standard input. The start of the file is defined "
	"as the current offset.]"
"[+?The option argument for \b-c\b can optionally be "
	"followed by one of the following characters to specify a different "
	"unit other than a single byte:]{"
		"[+b?512 bytes.]"
		"[+k?1-kilobyte.]"
		"[+m?1-megabyte.]"
	"}"
"[+?For backwards compatibility, \b-\b\anumber\a  is equivalent to "
	"\b-n\b \anumber\a and \b+\b\anumber\a is equivalent to "
	"\b-n -\b\anumber\a.]"

"[n:lines]:[lines:=10?Copy \alines\a lines from each file.  A negative value "
	"for \alines\a indicates an offset from the start of the file.]"
"[c:bytes]:?[chars?Copy \achars\a bytes from each file.  A negative value "
	"for \achars\a indicates an offset from the start of the file.]"
"[f:forever|follow?Loop forever trying to read more characters as the "
	"end of each file to copy new data. Ignored if reading from a pipe "
	"or fifo.]"
"[h!:headers?Output filename headers.]"
"[L:log?When a \b--forever\b file times out via \b--timeout\b, verify that "
	"the curent file has not been renamed and replaced by another file "
	"of the same name (a common log file practice) before giving up on "
	"the file.]"
"[q:quiet?Don't output filename headers. For GNU compatibility.]"
"[r:reverse?Output lines in reverse order.]"
"[s:silent?Don't warn about timeout expiration and log file changes.]"
"[t:timeout?Stop checking after \atimeout\a elapses with no additional "
	"\b--forever\b output. A separate elapsed time is maintained for "
	"each file operand. There is no timeout by default. The default "
	"\atimeout\a unit is seconds. \atimeout\a may be a catenation of 1 "
	"or more integers, each followed by a 1 character suffix. The suffix "
	"may be omitted from the last integer, in which case it is "
	"interpreted as seconds. The supported suffixes are:]:[timeout]{"
		"[+s?seconds]"
		"[+m?minutes]"
		"[+h?hours]"
		"[+d?days]"
		"[+w?weeks]"
		"[+M?months]"
		"[+y?years]"
		"[+S?scores]"
	"}"
"[v:verbose?Always ouput filename headers.]"
"\n"
"\n[file ...]\n"
"\n"
"[+EXIT STATUS?]{"
	"[+0?All files copied successfully.]"
	"[+>0?One or more files did not copy.]"
"}"
"[+SEE ALSO?\bcat\b(1), \bhead\b(1), \brev\b(1)]"
;

#include <cmd.h>
#include <ctype.h>
#include <ls.h>
#include <tm.h>
#include <rev.h>

#define COUNT		(1<<0)
#define ERROR		(1<<1)
#define FOLLOW		(1<<2)
#define HEADERS		(1<<3)
#define LOG		(1<<4)
#define NEGATIVE	(1<<5)
#define POSITIVE	(1<<6)
#define REVERSE		(1<<7)
#define SILENT		(1<<8)
#define TIMEOUT		(1<<9)
#define VERBOSE		(1<<10)

#define NOW		(unsigned long)time(NiL)

#define LINES		10

#ifdef S_ISSOCK
#define FIFO(m)		(S_ISFIFO(m)||S_ISSOCK(m))
#else
#define FIFO(m)		S_ISFIFO(m)
#endif

struct Tail_s; typedef struct Tail_s Tail_t;

struct Tail_s
{
	Tail_t*		next;
	char*		name;
	Sfio_t*		sp;
	Sfoff_t		last;
	unsigned long	expire;
	long		dev;
	long		ino;
};

/*
 * if file is seekable, position file to tail location and return offset
 * otherwise, return -1
 */

static Sfoff_t
tailpos(register Sfio_t* fp, register Sfoff_t number, int delim)
{
	register size_t		n;
	register Sfoff_t	offset;
	register Sfoff_t	first;
	register Sfoff_t	last;
	register char*		s;
	register char*		t;
	struct stat		st;

	last = sfsize(fp);
	if ((first = sfseek(fp, (Sfoff_t)0, SEEK_CUR)) < 0)
		return last || fstat(sffileno(fp), &st) || st.st_size || FIFO(st.st_mode) ? -1 : 0;
	if (delim < 0)
	{
		if ((offset = last - number) < first)
			return first;
		return offset;
	}
	if ((offset = last - SF_BUFSIZE) < first)
		offset = first;
	for (;;)
	{
		sfseek(fp, offset, SEEK_SET);
		n = last - offset;
		if (!(s = sfreserve(fp, n, SF_LOCKR)))
			return -1;
		t = s + n;
		while (t > s)
			if (*--t == delim && number-- <= 0)
			{
				sfread(fp, s, 0);
				return offset + (t - s) + 1;
			}
		sfread(fp, s, 0);
		if (offset == first)
			break;
		last = offset;
		if ((offset = last - SF_BUFSIZE) < first)
			offset = first;
	}
	return first;
}

/*
 * this code handles tail from a pipe without any size limits
 */

static void
pipetail(Sfio_t* infile, Sfio_t* outfile, Sfoff_t number, int delim)
{
	register Sfio_t*	out;
	register Sfoff_t	n;
	register Sfoff_t	nleft = number;
	register size_t		a = 2 * SF_BUFSIZE;
	register int		fno = 0;
	Sfoff_t			offset[2];
	Sfio_t*			tmp[2];

	if (delim < 0 && a > number)
		a = number;
	out = tmp[0] = sftmp(a);
	tmp[1] = sftmp(a);
	offset[0] = offset[1] = 0;
	while ((n = sfmove(infile, out, number, delim)) > 0)
	{
		offset[fno] = sftell(out);
		if ((nleft -= n) <= 0)
		{
			out = tmp[fno= !fno];
			sfseek(out, (Sfoff_t)0, SEEK_SET);
			nleft = number;
		}
	}
	if (nleft == number)
	{
		offset[fno] = 0;
		fno= !fno;
	}
	sfseek(tmp[0], (Sfoff_t)0, SEEK_SET);

	/*
	 * see whether both files are needed
	 */

	if (offset[fno])
	{
		sfseek(tmp[1], (Sfoff_t)0, SEEK_SET);
		if ((n = number - nleft) > 0) 
			sfmove(tmp[!fno], NiL, n, delim); 
		if ((n = offset[!fno] - sftell(tmp[!fno])) > 0)
			sfmove(tmp[!fno], outfile, n, -1); 
	}
	else
		fno = !fno;
	sfmove(tmp[fno], outfile, offset[fno], -1); 
	sfclose(tmp[0]);
	sfclose(tmp[1]);
}

/*
 * (re)initialize a tail stream
 */

static int
init(Tail_t* tp, Sfoff_t number, int delim, int flags)
{
	Sfoff_t		offset;
	struct stat	st;

	if (tp->sp)
	{
		offset = 0;
		if (tp->sp == sfstdin)
			tp->sp = 0;
	}
	else if (!number)
		offset = 0;
	else
		offset = 1;
	if (!tp->name || streq(tp->name, "-"))
	{
		tp->name = "/dev/stdin";
		tp->sp = sfstdin;
	}
	else if (!(tp->sp = sfopen(tp->sp, tp->name, "r")))
	{
		error(ERROR_system(0), "%s: cannot open", tp->name);
		return -1;
	}
	sfset(tp->sp, SF_SHARE, 0);
	if (offset)
	{
		if ((offset = tailpos(tp->sp, number, delim)) < 0)
		{
			error(ERROR_SYSTEM|2, "%s: cannot position file to tail", tp->name);
			goto bad;
		}
		sfseek(tp->sp, offset, SEEK_SET);
	}
	tp->last = offset;
	if (flags & LOG)
	{
		if (fstat(sffileno(tp->sp), &st))
		{
			error(ERROR_system(0), "%s: cannot stat", tp->name);
			goto bad;
		}
		tp->dev = st.st_dev;
		tp->ino = st.st_ino;
	}
	return 0;
 bad:
	if (tp->sp != sfstdin)
		sfclose(tp->sp);
	tp->sp = 0;
	return -1;
}

/*
 * convert number with validity diagnostics
 */

static intmax_t
num(register const char* s, char** e, int* f, int o)
{
	intmax_t	number;
	char*		t;
	int		c;

	*f &= ~(ERROR|NEGATIVE|POSITIVE);
	if ((c = *s) == '-')
	{
		*f |= NEGATIVE;
		s++;
	}
	else if (c == '+')
	{
		*f |= POSITIVE;
		s++;
	}
	while (*s == '0' && isdigit(*(s + 1)))
		s++;
	errno = 0;
	number = strtonll(s, &t, NiL, 0);
	if (!o && t > s && *(t - 1) == 'l')
		t--;
	if (t == s)
		number = LINES;
	if (o && *t)
	{
		number = 0;
		*f |= ERROR;
		error(2, "-%c: %s: invalid numeric argument -- unknown suffix", o, s);
	}
	else if (errno)
	{
		*f |= ERROR;
		if (o)
			error(2, "-%c: %s: invalid numeric argument -- out of range", o, s);
		else
			error(2, "%s: invalid numeric argument -- out of range", s);
	}
	else
	{
		*f |= COUNT;
		if (c == '-')
			number = -number;
	}
	if (e)
		*e = t;
	return number;
}

int
b_tail(int argc, char** argv, void* context)
{
	static const char	header_fmt[] = "\n==> %s <==\n";

	register Sfio_t*	ip;
	register int		n;
	register int		i;
	register int		delim = '\n';
	int			flags = HEADERS;
	char*			s;
	char*			t;
	char*			r;
	char*			e;
	char*			file;
	Sfoff_t			offset;
	Sfoff_t			number = LINES;
	unsigned long		timeout = 0;
	struct stat		st;
	const char*		format = header_fmt+1;
	size_t			z;
	Sfio_t*			op;
	register Tail_t*	fp;
	register Tail_t*	pp;
	register Tail_t*	hp;
	Tail_t*			files;

	cmdinit(argc, argv, context, ERROR_CATALOG, 0);
	for (;;)
	{
		switch (n = optget(argv, usage))
		{
		case 'c':
			delim = -1;
			if (opt_info.arg && *opt_info.arg=='f' && !*(opt_info.arg+1))
			{
				flags |= FOLLOW;
				continue;
			}
			/*FALLTHROUGH*/
		case 'n':
		case 'N':
			flags |= COUNT;
			if (s = opt_info.arg)
				number = num(s, &s, &flags, n);
			else
			{
				number = LINES;
				flags &= ~(ERROR|NEGATIVE|POSITIVE);
				s = "";
			}
			if (n=='c' && *s=='f')
			{
				s++;
				flags |= FOLLOW;
			}
			if (flags & ERROR)
				continue;
			if (flags & (NEGATIVE|POSITIVE))
				number = -number;
			if (opt_info.option[0]=='+')
				number = -number;
			continue;
		case 'f':
			flags |= FOLLOW;
			continue;
		case 'h':
			if (opt_info.num)
				flags |= HEADERS;
			else
				flags &= ~HEADERS;
			continue;
		case 'L':
			flags |= LOG;
			continue;
		case 'q':
			flags &= ~HEADERS;
			continue;
		case 'r':
			flags |= REVERSE;
			continue;
		case 's':
			flags |= SILENT;
			continue;
		case 't':
			flags |= TIMEOUT;
			timeout = strelapsed(opt_info.arg, &s, 1);
			if (*s)
				error(ERROR_exit(1), "%s: invalid elapsed time", opt_info.arg);
			continue;
		case 'v':
			flags |= VERBOSE;
			continue;
		case ':':
			/* handle old style arguments */
			r = s = argv[opt_info.index];
			number = num(s, &t, &flags, 0);
			for (;;)
			{
				switch (*t++)
				{
				case 0:
					opt_info.offset = t - r - 1;
					if (number)
						number = -number;
					break;
				case 'c':
					delim = -1;
					continue;
				case 'f':
					flags |= FOLLOW;
					continue;
				case 'l':
					delim = '\n';
					continue;
				case 'r':
					flags |= REVERSE;
					continue;
				default:
					error(2, "%s: invalid suffix", t - 1);
					opt_info.offset = strlen(r);
					break;
				}
				break;
			}
			continue;
		case '?':
			error(ERROR_usage(2), "%s", opt_info.arg);
			break;
		}
		break;
	}
	argv += opt_info.index;
	if (!*argv)
	{
		flags &= ~HEADERS;
		if (fstat(0, &st))
			error(ERROR_system(0), "/dev/stdin: cannot stat");
		else if (FIFO(st.st_mode))
			flags &= ~FOLLOW;
	}
	else if (!*(argv + 1))
		flags &= ~HEADERS;
	if (flags & REVERSE)
	{
		if (delim < 0)
			error(2, "--reverse requires line mode");
		else if (!(flags & COUNT))
			number = 0;
		flags &= ~FOLLOW;
	}
	if ((flags & (FOLLOW|TIMEOUT)) == TIMEOUT)
	{
		flags &= ~TIMEOUT;
		timeout = 0;
		error(ERROR_warn(0), "--timeout ignored for --noforever");
	}
	if ((flags & (LOG|TIMEOUT)) == LOG)
	{
		flags &= ~LOG;
		error(ERROR_warn(0), "--log ignored for --notimeout");
	}
	if (error_info.errors)
		error(ERROR_usage(2), "%s", optusage(NiL));
	if (flags & FOLLOW)
	{
		if (!(fp = (Tail_t*)stakalloc(argc * sizeof(Tail_t))))
			error(ERROR_system(1), "out of space");
		files = 0;
		s = *argv;
		do
		{
			fp->name = s;
			fp->sp = 0;
			if (!init(fp, number, delim, flags))
			{
				fp->expire = timeout ? (NOW + timeout + 1) : 0;
				if (files)
					pp->next = fp;
				else
					files = fp;
				pp = fp;
				fp++;
			}
		} while (s && (s = *++argv));
		if (!files)
			return error_info.errors != 0;
		pp->next = 0;
		hp = 0;
		for (;;)
		{
			if (sfsync(sfstdout))
				error(ERROR_system(1), "write error");
			sleep(1);
			n = 0;
			pp = 0;
			fp = files;
			while (fp)
			{
				if (fstat(sffileno(fp->sp), &st))
					error(ERROR_system(0), "%s: cannot stat", fp->name);
				else if (st.st_size > fp->last)
				{
					n = 1;
					if (timeout)
						fp->expire = NOW + timeout;
					z = st.st_size - fp->last;
					i = 0;
					if ((s = sfreserve(fp->sp, z, SF_LOCKR)) || (z = sfvalue(fp->sp)) && (s = sfreserve(fp->sp, z, SF_LOCKR)) && (i = 1))
					{
						r = 0;
						for (e = (t = s) + z; t < e; t++)
							if (*t == '\n')
								r = t;
						if (r || i && (r = e))
						{
							if ((flags & (HEADERS|VERBOSE)) && hp != fp)
							{
								hp = fp;
								sfprintf(sfstdout, format, fp->name);
								format = header_fmt;
							}
							z = r - s + 1;
							fp->last += z;
							sfwrite(sfstdout, s, z);
						}
						else
							z = 0;
						sfread(fp->sp, s, z);
					}
					goto next;
				}
				else if (!timeout || fp->expire > NOW)
					goto next;
				else
				{
					if (flags & LOG)
					{
						i = 3;
						while (--i && stat(fp->name, &st))
							sleep(1);
						if (i && (fp->dev != st.st_dev || fp->ino != st.st_ino) && !init(fp, 0, 0, flags))
						{
							if (!(flags & SILENT))
								error(ERROR_warn(0), "%s: log file change", fp->name);
							fp->expire = NOW + timeout;
							goto next;
						}
					}
					if (!(flags & SILENT))
						error(ERROR_warn(0), "%s: %s timeout", fp->name, fmtelapsed(timeout, 1));
				}
				if (fp->sp && fp->sp != sfstdin)
					sfclose(fp->sp);
				if (pp)
					pp = pp->next = fp->next;
				else if (!(files = files->next))
					return error_info.errors != 0;
				fp = fp->next;
				continue;
			next:
				pp = fp;
				fp = fp->next;
			}
		}
	}
	else
	{
		if (file = *argv)
			argv++;
		do
		{
			if (!file || streq(file, "-"))
			{
				file = "/dev/stdin";
				ip = sfstdin;
			}
			else if (!(ip = sfopen(NiL, file, "r")))
			{
				error(ERROR_system(0), "%s: cannot open", file);
				continue;
			}
			if (flags & (HEADERS|VERBOSE))
				sfprintf(sfstdout, format, file);
			format = header_fmt;
			if (number < 0 || !number && (flags & POSITIVE))
			{
				sfset(ip, SF_SHARE, !(flags & FOLLOW));
				if (number < -1)
					sfmove(ip, NiL, -number - 1, delim);
				if (flags & REVERSE)
					rev_line(ip, sfstdout, sfseek(ip, (Sfoff_t)0, SEEK_CUR));
				else
					sfmove(ip, sfstdout, SF_UNBOUND, -1);
			}
			else
			{
				sfset(ip, SF_SHARE, 0);
				if ((offset = tailpos(ip, number, delim)) >= 0)
				{
					if (flags & REVERSE)
						rev_line(ip, sfstdout, offset);
					else
					{
						sfseek(ip, offset, SEEK_SET);
						sfmove(ip, sfstdout, SF_UNBOUND, -1);
					}
				}
				else
				{
					op = (flags & REVERSE) ? sftmp(4*SF_BUFSIZE) : sfstdout;
					pipetail(ip, op, number, delim);
					if (flags & REVERSE)
					{
						sfseek(op, (Sfoff_t)0, SEEK_SET);
						rev_line(op, sfstdout, (Sfoff_t)0);
						sfclose(op);
					}
					flags = 0;
				}
			}
			if (ip != sfstdin)
				sfclose(ip);
		} while (file = *argv++);
	}
	return error_info.errors != 0;
}
