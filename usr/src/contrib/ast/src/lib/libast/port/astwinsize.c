/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2012 AT&T Intellectual Property          *
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
*                   Phong Vo <kpv@research.att.com>                    *
*                                                                      *
***********************************************************************/
#pragma prototyped

/*
 * AT&T Research
 * return terminal rows and cols
 */

#include <ast.h>
#include <ast_tty.h>

#if defined(__STDPP__directive) && defined(__STDPP__hide)
__STDPP__directive pragma pp:hide ioctl sleep
#else
#define ioctl		______ioctl
#define sleep		______sleep
#endif

#if _sys_ioctl
#include <sys/ioctl.h>
#endif

#if defined(TIOCGWINSZ)
#if _sys_stream && _sys_ptem
#include <sys/stream.h>
#include <sys/ptem.h>
#endif
#else
#if !defined(TIOCGSIZE) && !defined(TIOCGWINSZ)
#if _hdr_jioctl
#define jwinsize	winsize
#include <jioctl.h>
#else
#if _sys_jioctl
#define jwinsize	winsize
#include <sys/jioctl.h>
#endif
#endif
#endif
#endif

#if defined(__STDPP__directive) && defined(__STDPP__hide)
__STDPP__directive pragma pp:nohide ioctl sleep
#else
#undef	ioctl
#undef	sleep
#endif

static int		ttctl(int, int, void*);

void
astwinsize(int fd, register int* rows, register int* cols)
{
#ifdef	TIOCGWINSZ
#define NEED_ttctl
	struct winsize	ws;

	if (!ttctl(fd, TIOCGWINSZ, &ws) && ws.ws_col > 0 && ws.ws_row > 0)
	{
		if (rows) *rows = ws.ws_row;
		if (cols) *cols = ws.ws_col;
	}
	else
#else
#ifdef	TIOCGSIZE
#define NEED_ttctl
	struct ttysize	ts;

	if (!ttctl(fd, TIOCGSIZE, &ts) && ts.ts_lines > 0 && ts.ts_cols > 0)
	{
		if (rows) *rows = ts.ts_lines;
		if (cols) *cols = ts.ts_cols;
	}
	else
#else
#ifdef	JWINSIZE
#define NEED_ttctl
	struct winsize	ws;

	if (!ttctl(fd, JWINSIZE, &ws) && ws.bytesx > 0 && ws.bytesy > 0)
	{
		if (rows) *rows = ws.bytesy;
		if (cols) *cols = ws.bytesx;
	}
	else
#endif
#endif
#endif
	{
		char*		s;

		if (rows) *rows = (s = getenv("LINES")) ? strtol(s, NiL, 0) : 0;
		if (cols) *cols = (s = getenv("COLUMNS")) ? strtol(s, NiL, 0) : 0;
	}
}

#ifdef	NEED_ttctl

/*
 * tty ioctl() -- no cache
 */

static int
ttctl(register int fd, int op, void* tt)
{
	register int	v;

	if (fd < 0)
	{
		for (fd = 0; fd <= 2; fd++)
			if (!ioctl(fd, op, tt)) return(0);
		if ((fd = open("/dev/tty", O_RDONLY|O_cloexec)) >= 0)
		{
			v = ioctl(fd, op, tt);
			close(fd);
			return(v);
		}
	}
	else if (!ioctl(fd, op, tt)) return(0);
	return(-1);
}

#endif
