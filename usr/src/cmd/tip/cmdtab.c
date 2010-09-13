/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "tip.h"

extern void	shell(int), getfl(int), tip_sendfile(int), chdirectory(int);
extern void	finish(int), help(int), pipefile(int), pipeout(int);
extern void	consh(int), variable(int), cu_take(int), cu_put(int);
extern void	genbrk(int), suspend(int);

esctable_t etable[] = {
	{ '!',	NORM,	"shell",			 shell },
	{ '<',	NORM,	"receive file from remote host", getfl },
	{ '>',	NORM,	"send file to remote host",	 tip_sendfile },
	{ 't',	NORM,	"take file from remote UNIX",	 cu_take },
	{ 'p',	NORM,	"put file to remote UNIX",	 cu_put },
	{ '|',	NORM,	"pipe remote file",		 pipefile },
	{ 'C',  NORM,	"connect program to remote host", consh },
	{ 'c',	NORM,	"change directory",		 chdirectory },
	{ '.',	NORM,	"exit from tip",		 finish },
	{_CTRL('d'), NORM, "exit from tip",		 finish },
	{ '$',	NORM,	"pipe local command to remote host", pipeout },
	{_CTRL('y'), NORM, "suspend tip (local only)",	 suspend },
	{_CTRL('z'), NORM, "suspend tip (local+remote)", suspend },
	{ 's',	NORM,	"set variable",			 variable },
	{ '?',	NORM,	"get this summary",		 help },
	{ '#',	NORM,	"send break",			 genbrk },
	{ 0, 0, 0 }
};
