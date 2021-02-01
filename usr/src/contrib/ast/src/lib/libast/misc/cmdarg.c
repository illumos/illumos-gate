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
 * Glenn Fowler
 * AT&T Research
 *
 * xargs/tw command arg list support
 */

#define _AST_API_H	1

#include <ast.h>
#include <cmdlib.h>
#include <proc.h>

static const char lib[] = "libast:cmdarg";

static int
cmdrun(int argc, char** argv, Cmddisc_t* disc)
{
	return procrun(argv[0], argv, PROC_ARGMOD|PROC_IGNOREPATH);
}

Cmdarg_t*
cmdopen(char** argv, int argmax, int size, const char* argpat, int flags)
{
	Cmddisc_t	disc;

	memset(&disc, 0, sizeof(disc));
	disc.version = CMD_VERSION;
	if (!(flags & CMD_SILENT))
	{
		flags |= CMD_EXIT;
		disc.errorf = errorf;
	}
	disc.flags = flags;
	return cmdopen_20120411(argv, argmax, size, argpat, &disc);
}

#undef	_AST_API_H

#include <ast_api.h>

#include <ctype.h>
#include <proc.h>

#ifndef ARG_MAX
#define ARG_MAX		(64*1024)
#endif
#ifndef EXIT_QUIT
#define EXIT_QUIT	255
#endif

static const char*	echo[] = { "echo", 0 };

Cmdarg_t*
cmdopen_20110505(char** argv, int argmax, int size, const char* argpat, int flags, Error_f errorf)
{
	Cmddisc_t	disc;

	memset(&disc, 0, sizeof(disc));
	disc.version = CMD_VERSION;
	disc.flags = flags;
	disc.errorf = errorf;
	return cmdopen_20120411(argv, argmax, size, argpat, &disc);
}

/*
 * open a cmdarg stream
 * initialize the command for execution
 * argv[-1] is reserved for procrun(PROC_ARGMOD)
 */

Cmdarg_t*
cmdopen_20120411(char** argv, int argmax, int size, const char* argpat, Cmddisc_t* disc)
{
	register Cmdarg_t*	cmd;
	register int		n;
	register char**		p;
	register char*		s;
	char*			sh;
	char*			exe;
	int			c;
	int			m;
	int			argc;
	long			x;

	char**			post = 0;

	n = sizeof(char**);
	if (*argv)
	{
		for (p = argv + 1; *p; p++)
		{
			if ((disc->flags & CMD_POST) && argpat && streq(*p, argpat))
			{
				*p = 0;
				post = p + 1;
				argpat = 0;
			}
			else
				n += strlen(*p) + 1;
		}
		argc = p - argv;
	}
	else
		argc = 0;
	for (p = environ; *p; p++)
		n += sizeof(char**) + strlen(*p) + 1;
	if ((x = strtol(astconf("ARG_MAX", NiL, NiL), NiL, 0)) <= 0)
		x = ARG_MAX;
	if (size <= 0 || size > x)
		size = x;
	sh = pathshell();
	m = n + (argc + 4) * sizeof(char**) + strlen(sh) + 1;
	m = roundof(m, sizeof(char**));
	if (size < m)
	{
		if (disc->errorf)
			(*disc->errorf)(NiL, sh, 2, "size must be at least %d", m);
		return 0;
	}
	if ((m = x / 10) > 2048)
		m = 2048;
	if (size > (x - m))
		size = x - m;
	n = size - n;
	m = ((disc->flags & CMD_INSERT) && argpat) ? (strlen(argpat) + 1) : 0;
	if (!(cmd = newof(0, Cmdarg_t, 1, n + m)))
	{
		if (disc->errorf)
			(*disc->errorf)(NiL, sh, ERROR_SYSTEM|2, "out of space");
		return 0;
	}
	cmd->id = lib;
	cmd->disc = disc;
	cmd->errorf = disc->errorf;
	if (!(cmd->runf = disc->runf))
		cmd->runf = cmdrun;
	c = n / sizeof(char**);
	if (argmax <= 0 || argmax > c)
		argmax = c;
	s = cmd->buf;
	if (!(exe = argv[0]))
	{
		exe = *(argv = (char**)echo);
		cmd->echo = 1;
	}
	else if (streq(exe, echo[0]))
	{
		cmd->echo = 1;
		disc->flags &= ~CMD_NEWLINE;
	}
	else if (!(disc->flags & CMD_CHECKED))
	{
		if (!pathpath(exe, NiL, PATH_REGULAR|PATH_EXECUTE, s, n + m))
		{
			n = EXIT_NOTFOUND;
			if (cmd->errorf)
				(*cmd->errorf)(NiL, cmd, ERROR_SYSTEM|2, "%s: command not found", exe);
			if (disc->flags & CMD_EXIT)
				(*error_info.exit)(n);
			free(cmd);
			return 0;
		}
		exe = s;
	}
	s += strlen(s) + 1;
	if (m)
	{
		cmd->insert = strcpy(s, argpat);
		cmd->insertlen = m - 1;
		s += m;
	}
	s += sizeof(char**) - (s - cmd->buf) % sizeof(char**);
	p = (char**)s;
	n -= strlen(*p++ = sh) + 1;
	cmd->argv = p;
	*p++ = exe;
	while (*p = *++argv)
		p++;
	if (m)
	{
		argmax = 1;
		*p++ = 0;
		cmd->insertarg = p;
		argv = cmd->argv;
		c = *cmd->insert;
		while (s = *argv)
		{
			while ((s = strchr(s, c)) && strncmp(cmd->insert, s, cmd->insertlen))
				s++;
			*p++ = s ? *argv : (char*)0;
			argv++;
		}
		*p++ = 0;
	}
	cmd->firstarg = cmd->nextarg = p;
	cmd->laststr = cmd->nextstr = cmd->buf + n;
	cmd->argmax = argmax;
	cmd->flags = disc->flags;
	cmd->offset = ((cmd->postarg = post) ? (argc - (post - argv)) : 0) + 3;
	return cmd;
}

/*
 * flush outstanding command file args
 */

int
cmdflush(register Cmdarg_t* cmd)
{
	register char*	s;
	register char**	p;
	register int	n;

	if (cmd->flags & CMD_EMPTY)
		cmd->flags &= ~CMD_EMPTY;
	else if (cmd->nextarg <= cmd->firstarg)
		return 0;
	if ((cmd->flags & CMD_MINIMUM) && cmd->argcount < cmd->argmax)
	{
		if (cmd->errorf)
			(*cmd->errorf)(NiL, cmd, 2, "%d arg command would be too long", cmd->argcount);
		return -1;
	}
	cmd->total.args += cmd->argcount;
	cmd->total.commands++;
	cmd->argcount = 0;
	if (p = cmd->postarg)
		while (*cmd->nextarg++ = *p++);
	else
		*cmd->nextarg = 0;
	if (s = cmd->insert)
	{
		char*	a;
		char*	b;
		char*	e;
		char*	t;
		char*	u;
		int	c;
		int	m;

		a = cmd->firstarg[0];
		b = (char*)&cmd->nextarg[1];
		e = cmd->nextstr;
		c = *s;
		m = cmd->insertlen;
		for (n = 1; cmd->argv[n]; n++)
			if (t = cmd->insertarg[n])
			{
				cmd->argv[n] = b;
				for (;;)
				{
					if (!(u = strchr(t, c)))
					{
						b += sfsprintf(b, e - b, "%s", t);
						break;
					}
					if (!strncmp(s, u, m))
					{
						b += sfsprintf(b, e - b, "%-.*s%s", u - t, t, a);
						t = u + m;
					}
					else if (b >= e)
						break;
					else
					{
						*b++ = *u++;
						t = u;
					}
				}
				if (b < e)
					*b++ = 0;
			}
		if (b >= e)
		{
			if (cmd->errorf)
				(*cmd->errorf)(NiL, cmd, 2, "%s: command too large after insert", a);
			return -1;
		}
	}
	n = (int)(cmd->nextarg - cmd->argv);
	cmd->nextarg = cmd->firstarg;
	cmd->nextstr = cmd->laststr;
	if (cmd->flags & (CMD_QUERY|CMD_TRACE))
	{
		p = cmd->argv;
		sfprintf(sfstderr, "+ %s", *p);
		while (s = *++p)
			sfprintf(sfstderr, " %s", s);
		if (!(cmd->flags & CMD_QUERY))
			sfprintf(sfstderr, "\n");
		else if (astquery(1, "? "))
		{
			return 0;
		}
	}
	if (cmd->echo)
	{
		n = (cmd->flags & CMD_NEWLINE) ? '\n' : ' ';
		for (p = cmd->argv + 1; s = *p++;)
			sfputr(sfstdout, s, *p ? n : '\n');
		n = 0;
	}
	else if ((n = (*cmd->runf)(n, cmd->argv, cmd->disc)) == -1)
	{
		n = EXIT_NOTFOUND - 1;
		if (cmd->errorf)
			(*cmd->errorf)(NiL, cmd, ERROR_SYSTEM|2, "%s: command exec error", *cmd->argv);
		if (cmd->flags & CMD_EXIT)
			(*error_info.exit)(n);
	}
	else if (n >= EXIT_NOTFOUND - 1)
	{
		if (cmd->flags & CMD_EXIT)
			(*error_info.exit)(n);
	}
	else if (!(cmd->flags & CMD_IGNORE))
	{
		if (n == EXIT_QUIT && (cmd->flags & CMD_EXIT))
			(*error_info.exit)(2);
		if (n)
			error_info.errors++;
	}
	return n;
}

/*
 * add file to the command arg list
 */

int
cmdarg(register Cmdarg_t* cmd, const char* file, register int len)
{
	int	i;
	int	r;

	r = 0;
	if (len > 0)
	{
		while ((cmd->nextstr -= len + 1) < (char*)(cmd->nextarg + cmd->offset))
		{
			if (cmd->nextarg == cmd->firstarg)
			{
				if (cmd->errorf)
					(*cmd->errorf)(NiL, cmd, 2, "%s: path too long for exec args", file);
				return -1;
			}
			if (i = cmdflush(cmd))
			{
				if (r < i)
					r = i;
				if (!(cmd->flags & CMD_IGNORE))
					return r;
			}
		}
		*cmd->nextarg++ = cmd->nextstr;
		memcpy(cmd->nextstr, file, len);
		cmd->nextstr[len] = 0;
		cmd->argcount++;
		if (cmd->argcount >= cmd->argmax && (i = cmdflush(cmd)) > r)
			r = i;
	}
	else
		cmd->argcount += len;
	return r;
}

/*
 * close a cmdarg stream
 */

int
cmdclose(Cmdarg_t* cmd)
{
	int	n;

	if ((cmd->flags & CMD_EXACT) && cmd->argcount < cmd->argmax)
	{
		if (cmd->errorf)
			(*cmd->errorf)(NiL, cmd, 2, "only %d arguments for last command", cmd->argcount);
		n = -1;
	}
	else
	{
		cmd->flags &= ~CMD_MINIMUM;
		n = cmdflush(cmd);
	}
	free(cmd);
	return n;
}
