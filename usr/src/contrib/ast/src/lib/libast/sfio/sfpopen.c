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
#include	"sfhdr.h"

/*	Create a coprocess.
**	Written by Kiem-Phong Vo.
*/

#if _PACKAGE_ast
#include	<proc.h>
#else

#define EXIT_NOTFOUND	127

#define READ		0
#define WRITE		1

#ifndef CHAR_BIT
#define CHAR_BIT	8
#endif
static char	Meta[1<<CHAR_BIT], **Path;

/* execute command directly if possible; else use the shell */
#if __STD_C
static void execute(const char* argcmd)
#else
static void execute(argcmd)
char*	argcmd;
#endif
{
	reg char	*s, *cmd, **argv, **p, *interp;
	reg int		n;

	/* define interpreter */
	if(!(interp = getenv("SHELL")) || !interp[0])
		interp = "/bin/sh";

	if(strcmp(interp,"/bin/sh") != 0 && strcmp(interp,"/bin/ksh") != 0 )
	{	if(access(interp,X_OK) == 0)
			goto do_interp;
		else	interp = "/bin/sh";
	}

	/* if there is a meta character, let the shell do it */
	for(s = (char*)argcmd; *s; ++s)
		if(Meta[(uchar)s[0]])
			goto do_interp;

	/* try to construct argv */
	if(!(cmd = (char*)malloc(strlen(argcmd)+1)) )
		goto do_interp;
	strcpy(cmd,argcmd);
	if(!(argv = (char**)malloc(16*sizeof(char*))) )
		goto do_interp;
	for(n = 0, s = cmd;; )
	{	while(isspace(s[0]))
			s += 1;
		if(s[0] == 0)
			break;

		/* new argument */
		argv[n++] = s;
		if((n%16) == 0 && !(argv = (char**)realloc(argv,(n+16)*sizeof(char*))) )
			goto do_interp;

		/* make this into a C string */
		while(s[0] && !isspace(s[0]))
			s += 1;
		if(!s[0])
			*s++ = 0;
	}
	if(n == 0)
		goto do_interp;
	argv[n] = NIL(char*);

	/* get the command name */
	cmd = argv[0];
	for(s = cmd+strlen(cmd)-1; s >= cmd; --s)
		if(*s == '/')
			break;
	argv[0] = s+1;

	/* Non-standard pathnames as in nDFS should be handled by the shell */
	for(s = cmd+strlen(cmd)-1; s >= cmd+2; --s)
		if(s[0] == '.' && s[-1] == '.' && s[-2] == '.')
			goto do_interp;

	if(cmd[0] == '/' ||
	   (cmd[0] == '.' && cmd[1] == '/') ||
	   (cmd[0] == '.' && cmd[1] == '.' && cmd[2] == '/') )
	{	if(access(cmd,X_OK) != 0)
			goto do_interp;
		else	execv(cmd,argv);
	}
	else
	{	for(p = Path; *p; ++p)
		{	s = sfprints("%s/%s", *p, cmd);
			if(access(s,X_OK) == 0)
				execv(s,argv);
		}
	}

	/* if get here, let the interpreter do it */
do_interp: 
	for(s = interp+strlen(interp)-1; s >= interp; --s)
		if(*s == '/')
			break;
	execl(interp, s+1, "-c", argcmd, NIL(char*));
	_exit(EXIT_NOTFOUND);
}

#endif /*_PACKAGE_ast*/

#if __STD_C
Sfio_t*	sfpopen(Sfio_t* f, const char* command, const char* mode)
#else
Sfio_t*	sfpopen(f,command,mode)
Sfio_t*	f;
char*	command;	/* command to execute */
char*	mode;		/* mode of the stream */
#endif
{
#if _PACKAGE_ast
	reg Proc_t*	proc;
	reg int		sflags;
	reg long	flags;
	reg int		pflags;
	char*		av[4];

	if (!command || !command[0] || !mode)
		return 0;
	sflags = _sftype(mode, NIL(int*), NIL(int*), NIL(int*));

	if(f == (Sfio_t*)(-1))
	{	/* stdio compatibility mode */
		f = NIL(Sfio_t*);
		pflags = 1;
	}
	else	pflags = 0;

	flags = 0;
	if (sflags & SF_READ)
		flags |= PROC_READ;
	if (sflags & SF_WRITE)
		flags |= PROC_WRITE;
	av[0] = "sh";
	av[1] = "-c";
	av[2] = (char*)command;
	av[3] = 0;
	if (!(proc = procopen(0, av, 0, 0, flags)))
		return 0;
	if (!(f = sfnew(f, NIL(Void_t*), (size_t)SF_UNBOUND,
	       		(sflags&SF_READ) ? proc->rfd : proc->wfd, sflags|((sflags&SF_RDWR)?0:SF_READ))) ||
	    _sfpopen(f, (sflags&SF_READ) ? proc->wfd : -1, proc->pid, pflags) < 0)
	{
		if (f) sfclose(f);
		procclose(proc);
		return 0;
	}
	procfree(proc);
	return f;
#else
	reg int		pid, fd, pkeep, ckeep, sflags;
	int		stdio, parent[2], child[2];
	Sfio_t		sf;

	/* set shell meta characters */
	if(Meta[0] == 0)
	{	reg char*	s;
		Meta[0] = 1;
		for(s = "!@#$%&*(){}[]:;<>~`'|\"\\"; *s; ++s)
			Meta[(uchar)s[0]] = 1;
	}
	if(!Path)
		Path = _sfgetpath("PATH");

	/* sanity check */
	if(!command || !command[0] || !mode)
		return NIL(Sfio_t*);
	sflags = _sftype(mode,NIL(int*),NIL(int*),NIL(int*));

	/* make pipes */
	parent[0] = parent[1] = child[0] = child[1] = -1;
	if(sflags&SF_RDWR)
	{	if(syspipef(parent) < 0)
			goto error;
		if((sflags&SF_RDWR) == SF_RDWR && syspipef(child) < 0)
			goto error;
	}

	switch((pid = fork()) )
	{
	default :	/* in parent process */
		if(sflags&SF_READ)
			{ pkeep = READ; ckeep = WRITE; }
		else	{ pkeep = WRITE; ckeep = READ; }

		if(f == (Sfio_t*)(-1))
		{	/* stdio compatibility mode */
			f = NIL(Sfio_t*);
			stdio = 1;
		}
		else	stdio = 0;

		/* make the streams */
		if(!(f = sfnew(f,NIL(Void_t*),(size_t)SF_UNBOUND,parent[pkeep],sflags|((sflags&SF_RDWR)?0:SF_READ))))
			goto error;
		if(sflags&SF_RDWR)
		{	CLOSE(parent[!pkeep]);
			SETCLOEXEC(parent[pkeep]);
			if((sflags&SF_RDWR) == SF_RDWR)
			{	CLOSE(child[!ckeep]);
				SETCLOEXEC(child[ckeep]);
			}
		}

		/* save process info */
		fd = (sflags&SF_RDWR) == SF_RDWR ? child[ckeep] : -1;
		if(_sfpopen(f,fd,pid,stdio) < 0)
		{	(void)sfclose(f);
			goto error;
		}

		return f;

	case 0 :	/* in child process */
		/* determine what to keep */
		if(sflags&SF_READ)
			{ pkeep = WRITE; ckeep = READ; }
		else	{ pkeep = READ; ckeep = WRITE; }

		/* zap fd that we don't need */
		if(sflags&SF_RDWR)
		{	CLOSE(parent[!pkeep]);
			if((sflags&SF_RDWR) == SF_RDWR)
				CLOSE(child[!ckeep]);
		}

		/* use sfsetfd to make these descriptors the std-ones */
		SFCLEAR(&sf,NIL(Vtmutex_t*));

		/* must be careful so not to close something useful */
		if((sflags&SF_RDWR) == SF_RDWR && pkeep == child[ckeep])
			if((child[ckeep] = sysdupf(pkeep)) < 0)
				_exit(EXIT_NOTFOUND);

		if(sflags&SF_RDWR)
		{	if (parent[pkeep] != pkeep)
			{	sf.file = parent[pkeep];
				CLOSE(pkeep);
				if(sfsetfd(&sf,pkeep) != pkeep)
					_exit(EXIT_NOTFOUND);
			}
			if((sflags&SF_RDWR) == SF_RDWR && child[ckeep] != ckeep)
			{	sf.file = child[ckeep];
				CLOSE(ckeep);
				if(sfsetfd(&sf,ckeep) != ckeep)
					_exit(EXIT_NOTFOUND);
			}
		}

		execute(command);
		return NIL(Sfio_t*);

	case -1 :	/* error */
	error:
		if(parent[0] >= 0)
			{ CLOSE(parent[0]); CLOSE(parent[1]); }
		if(child[0] >= 0)
			{ CLOSE(child[0]); CLOSE(child[1]); }
		return NIL(Sfio_t*);
	}
#endif /*_PACKAGE_ast*/
}
