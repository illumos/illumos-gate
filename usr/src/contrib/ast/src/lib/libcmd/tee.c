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
 * tee
 */

static const char usage[] =
"[-?\n@(#)$Id: tee (AT&T Research) 2012-05-31 $\n]"
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
	int		line;
	int		fd[1];
} Tee_t;

/*
 * This discipline writes to each file in the list given in handle
 */

static ssize_t
tee_write(Sfio_t* fp, const void* buf, size_t n, Sfdisc_t* handle)
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
				return -1;
			bp += r;
		}
	} while ((fd = *hp++) >= 0);
	return n;
}

static void
tee_cleanup(register Tee_t* tp)
{
	register int*	hp;
	register int	n;

	if (tp)
	{
		sfdisc(sfstdout, NiL);
		if (tp->line >= 0)
			sfset(sfstdout, SF_LINE, tp->line);
		for (hp = tp->fd; (n = *hp) >= 0; hp++)
			close(n);
	}
}

int
b_tee(int argc, register char** argv, Shbltin_t* context)
{
	register Tee_t*		tp = 0;
	register int		oflag = O_WRONLY|O_TRUNC|O_CREAT|O_BINARY|O_cloexec;
	register int*		hp;
	register char*		cp;
	int			line;

	if (argc <= 0)
	{
		if (context && (tp = (Tee_t*)sh_context(context)->data))
		{
			sh_context(context)->data = 0;
			tee_cleanup(tp);
		}
		return 0;
	}
	cmdinit(argc, argv, context, ERROR_CATALOG, ERROR_CALLBACK);
	line = -1;
	for (;;)
	{
		switch (optget(argv, usage))
		{
		case 'a':
			oflag &= ~O_TRUNC;
			oflag |= O_APPEND;
			continue;
		case 'i':
			signal(SIGINT, SIG_IGN);
			continue;
		case 'l':
			line = sfset(sfstdout, 0, 0) & SF_LINE;
			if ((line == 0) == (opt_info.num == 0))
				line = -1;
			else
				sfset(sfstdout, SF_LINE, !!opt_info.num);
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
	if (error_info.errors)
		error(ERROR_usage(2), "%s", optusage(NiL));
	argv += opt_info.index;
	argc -= opt_info.index;
#if _ANCIENT_BSD_COMPATIBILITY
	if (*argv && streq(*argv, "-"))
	{
		signal(SIGINT, SIG_IGN);
		argv++;
		argc--;
	}
#endif
	if (argc > 0)
	{
		if (tp = (Tee_t*)stakalloc(sizeof(Tee_t) + argc * sizeof(int)))
		{
			memset(&tp->disc, 0, sizeof(tp->disc));
			tp->disc.writef = tee_write;
			if (context)
				sh_context(context)->data = (void*)tp;
			tp->line = line;
			hp = tp->fd;
			while (cp = *argv++)
			{
				while ((*hp = open(cp, oflag, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)) < 0 && errno == EINTR)
					errno = 0;
				if (*hp < 0)
					error(ERROR_system(0), "%s: cannot create", cp);
				else
					hp++;
			}
			if (hp == tp->fd)
				tp = 0;
			else
			{
				*hp = -1;
				sfdisc(sfstdout, &tp->disc);
			}
		}
		else
			error(ERROR_exit(0), "out of space");
	}
	if ((sfmove(sfstdin, sfstdout, SF_UNBOUND, -1) < 0 || !sfeof(sfstdin)) && !ERROR_PIPE(errno) && errno != EINTR)
		error(ERROR_system(0), "read error");
	if (sfsync(sfstdout))
		error(ERROR_system(0), "write error");
	tee_cleanup(tp);
	return error_info.errors;
}
