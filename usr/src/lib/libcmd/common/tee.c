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
 * tee
 */

static const char usage[] =
"[-?\n@(#)$Id: tee (AT&T Research) 2006-10-10 $\n]"
USAGE_LICENSE
"[+NAME?tee - duplicate standard input]"
"[+DESCRIPTION?\btee\b copies standard input to standard output "
	"and to zero or more files.  The options determine whether "
	"the specified files are overwritten or appended to.  The "
	"\btee\b utility does not buffer output.  If writes to any "
	"\afile\a fail, writes to other files continue although \btee\b "
	"will exit with a non-zero exit status.]"
"[+?The number of \afile\a operands that can be specified is limited "
	"by the underlying operating system.]"
"[a:append?Append the standard input to the given files rather "
	"than overwriting them.]"
"[i:ignore-interrupts?Ignore SIGINT signal.]"
"[l:linebuffer?Set the standard output to be line buffered.]"
"\n"
"\n[file ...]\n"
"\n"
"[+EXIT STATUS?]{"
        "[+0?All files copies successfully.]"
        "[+>0?An error occurred.]"
"}"
"[+SEE ALSO?\bcat\b(1), \bsignal\b(3)]"
;


#include <cmd.h>
#include <ls.h>
#include <sig.h>

typedef struct Tee_s
{
	Sfdisc_t	disc;
	int		fd[1];
} Tee_t;

/*
 * This discipline writes to each file in the list given in handle
 */

static ssize_t tee_write(Sfio_t* fp, const void* buf, size_t n, Sfdisc_t* handle)
{
	register const char*	bp;
	register const char*	ep;
	register int*		hp = ((Tee_t*)handle)->fd;
	register int		fd = sffileno(fp);
	register ssize_t	r;

	do
	{
		bp = (const char*)buf;
		ep = bp + n;
		while (bp < ep)
		{
			if ((r = write(fd, bp, ep - bp)) <= 0)
				return(-1);
			bp += r;
		}
	} while ((fd = *hp++) >= 0);
	return(n);
}

int
b_tee(int argc, register char** argv, void* context)
{
	register Tee_t*		tp = 0;
	register int		oflag = O_WRONLY|O_TRUNC|O_CREAT|O_BINARY;
	register int		n;
	register int*		hp;
	register char*		cp;
	int			line;
	Sfdisc_t		tee_disc;

	cmdinit(argc, argv, context, ERROR_CATALOG, 0);
	line = -1;
	while (n = optget(argv, usage)) switch (n)
	{
	case 'a':
		oflag &= ~O_TRUNC;
		oflag |= O_APPEND;
		break;
	case 'i':
		signal(SIGINT, SIG_IGN);
		break;
	case 'l':
		line = sfset(sfstdout, 0, 0) & SF_LINE;
		if ((line == 0) == (opt_info.num == 0))
			line = -1;
		else
			sfset(sfstdout, SF_LINE, !!opt_info.num);
		break;
	case ':':
		error(2, "%s", opt_info.arg);
		break;
	case '?':
		error(ERROR_usage(2), "%s", opt_info.arg);
		break;
	}
	if(error_info.errors)
		error(ERROR_usage(2), "%s", optusage(NiL));
	argv += opt_info.index;
	argc -= opt_info.index;

	/*
	 * for backward compatibility
	 */

	if (*argv && streq(*argv, "-"))
	{
		signal(SIGINT, SIG_IGN);
		argv++;
		argc--;
	}
	if (argc > 0)
	{
		if (!(tp = (Tee_t*)stakalloc(sizeof(Tee_t) + argc * sizeof(int))))
			error(ERROR_exit(1), "no space");
		memset(&tee_disc, 0, sizeof(tee_disc));
		tee_disc.writef = tee_write;
		tp->disc = tee_disc;
		hp = tp->fd;
		while (cp = *argv++)
		{
			if ((*hp = open(cp, oflag, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)) < 0)
				error(ERROR_system(0), "%s: cannot create", cp);
			else hp++;
		}
		if (hp == tp->fd)
			tp = 0;
		else
		{
			*hp = -1;
			sfdisc(sfstdout, &tp->disc);
		}
	}
	if (sfmove(sfstdin, sfstdout, SF_UNBOUND, -1) < 0 || !sfeof(sfstdin) || sfsync(sfstdout))
		error(ERROR_system(1), "cannot copy");

	/*
	 * close files and free resources
	 */

	if (tp)
	{
		sfdisc(sfstdout, NiL);
		if (line >= 0)
			sfset(sfstdout, SF_LINE, line);
		for(hp = tp->fd; (n = *hp) >= 0; hp++)
			close(n);
	}
	return(error_info.errors);
}
