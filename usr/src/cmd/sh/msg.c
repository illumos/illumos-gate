/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 *	UNIX shell
 */


#include	"defs.h"
#include	"sym.h"

/*
 * error messages
 */
#ifndef __STDC__
#define const 
#endif

const char	badopt[]	= "bad option(s)";
const char	mailmsg[]	= "you have mail\n";
const char	nospace[]	= "no space";
const char	nostack[]	= "no stack space";
const char	synmsg[]	= "syntax error";

const char	badnum[]	= "bad number";
const char	badsig[]	= "bad signal";
const char	badid[]		= "invalid id";
const char	badparam[]	= "parameter null or not set";
const char	unset[]		= "parameter not set";
const char	badsub[]	= "bad substitution";
const char	badcreate[]	= "cannot create";
const char	nofork[]	= "fork failed - too many processes";
const char	noswap[]	= "cannot fork: no swap space";
const char	restricted[]	= "restricted";
const char	piperr[]	= "cannot make pipe";
const char	badopen[]	= "cannot open";
const char	coredump[]	= " - core dumped";
const char	arglist[]	= "arg list too long";
const char	txtbsy[]	= "text busy";
const char	toobig[]	= "too big";
const char	badexec[]	= "cannot execute";
const char	notfound[]	= "not found";
const char	badfile[]	= "bad file number";
const char	badshift[]	= "cannot shift";
const char	baddir[]	= "bad directory";
const char	badtrap[]	= "bad trap";
const char	wtfailed[]	= "is read only";
const char	notid[]		= "is not an identifier";
const char 	badulimit[]	= "exceeds allowable limit";
const char	badreturn[] 	= "cannot return when not in function";
const char	badexport[] 	= "cannot export functions";
const char	badunset[] 	= "cannot unset";
const char	nohome[]	= "no home directory";
const char 	badperm[]	= "execute permission denied";
const char	longpwd[]	= "sh error: pwd too long";
const char	mssgargn[]	= "missing arguments";
const char	libacc[] 	= "can't access a needed shared library";
const char	libbad[]	= "accessing a corrupted shared library";
const char	libscn[]	= ".lib section in a.out corrupted";
const char	libmax[]	= "attempting to link in too many libs";
const char	emultihop[]	= "Multihop attempted";
const char	nulldir[]	= "null directory";
const char	enotdir[]	= "not a directory";
const char	enoent[]	= "does not exist";
const char	eacces[]	= "permission denied";
const char	enolink[]	= "remote link inactive";
const char	exited[]	= "Done";
const char	running[]	= "Running";
const char	ambiguous[]	= "ambiguous";
const char	usage[]		= "usage";
const char	nojc[]		= "no job control";
const char	stopuse[]	= "stop id ...";
const char	ulimuse[]	= "ulimit [ -HSacdfnstv ] [ limit ]";
const char	killuse[]	= "kill [ [ -sig ] id ... | -l ]";
const char	jobsuse[]	= "jobs [ [ -l | -p ] [ id ... ] | -x cmd ]";
const char	nosuchjob[]	= "no such job";
const char	nosuchpid[]	= "no such process";
const char	nosuchpgid[]	= "no such process group";
const char	nocurjob[]	= "no current job";
const char	jobsstopped[]	= "there are stopped jobs";
const char	jobsrunning[]	= "there are running jobs";
const char	loginsh[]	= "cannot stop login shell";
const char	nlorsemi[]	= "newline or ;";
const char	signalnum[]	= "Signal ";
const char	badpwd[]	= "cannot determine current directory";
const char	badlocale[]	= "couldn't set locale correctly\n";
const char	nobracket[]	= "] missing";
const char	noparen[]	= ") expected";
const char	noarg[]		= "argument expected";

/*
 * messages for 'builtin' functions
 */
const char	btest[]		= "test";
const char	badop[]		= "unknown operator ";
/*
 * built in names
 */
const char	pathname[]	= "PATH";
const char	cdpname[]	= "CDPATH";
const char	homename[]	= "HOME";
const char	mailname[]	= "MAIL";
const char	ifsname[]	= "IFS";
const char	ps1name[]	= "PS1";
const char	ps2name[]	= "PS2";
const char	mchkname[]	= "MAILCHECK";
const char	acctname[]  	= "SHACCT";
const char	mailpname[]	= "MAILPATH";

/*
 * string constants
 */
const char	nullstr[]	= "";
const char	sptbnl[]	= " \t\n";
const char	defpath[]	= "/usr/bin:";
const char	colon[]		= ": ";
const char	minus[]		= "-";
const char	endoffile[]	= "end of file";
const char	unexpected[] 	= " unexpected";
const char	atline[]	= " at line ";
const char	devnull[]	= "/dev/null";
const char	execpmsg[]	= "+ ";
const char	readmsg[]	= "> ";
const char	stdprompt[]	= "$ ";
const char	supprompt[]	= "# ";
const char	profile[]	= ".profile";
const char	sysprofile[]	= "/etc/profile";

/*
 * locale testing
 */
const char	localedir[]	= "/usr/lib/locale";
int		localedir_exists;

/*
 * tables
 */

const struct sysnod reserved[] =
{
	{ "case",	CASYM	},
	{ "do",		DOSYM	},
	{ "done",	ODSYM	},
	{ "elif",	EFSYM	},
	{ "else",	ELSYM	},
	{ "esac",	ESSYM	},
	{ "fi",		FISYM	},
	{ "for",	FORSYM	},
	{ "if",		IFSYM	},
	{ "in",		INSYM	},
	{ "then",	THSYM	},
	{ "until",	UNSYM	},
	{ "while",	WHSYM	},
	{ "{",		BRSYM	},
	{ "}",		KTSYM	}
};

const int no_reserved = sizeof(reserved)/sizeof(struct sysnod);

const char	export[] = "export";
const char	readonly[] = "readonly";


const struct sysnod commands[] =
{
	{ ".",		SYSDOT	},
	{ ":",		SYSNULL	},

#ifndef RES
	{ "[",		SYSTST },
#endif
	{ "bg",		SYSFGBG },
	{ "break",	SYSBREAK },
	{ "cd",		SYSCD	},
	{ "chdir",	SYSCD	},
	{ "continue",	SYSCONT	},
	{ "echo",	SYSECHO },
	{ "eval",	SYSEVAL	},
	{ "exec",	SYSEXEC	},
	{ "exit",	SYSEXIT	},
	{ "export",	SYSXPORT },
	{ "fg",		SYSFGBG },
	{ "getopts",	SYSGETOPT },
	{ "hash",	SYSHASH	},
	{ "jobs",	SYSJOBS },
	{ "kill",	SYSKILL },
#ifdef RES
	{ "login",	SYSLOGIN },
	{ "newgrp",	SYSLOGIN },
#else
	{ "newgrp",	SYSNEWGRP },
#endif

	{ "pwd",	SYSPWD },
	{ "read",	SYSREAD	},
	{ "readonly",	SYSRDONLY },
	{ "return",	SYSRETURN },
	{ "set",	SYSSET	},
	{ "shift",	SYSSHFT	},
	{ "stop",	SYSSTOP	},
	{ "suspend",	SYSSUSP},
	{ "test",	SYSTST },
	{ "times",	SYSTIMES },
	{ "trap",	SYSTRAP	},
	{ "type",	SYSTYPE },


#ifndef RES		
	{ "ulimit",	SYSULIMIT },
	{ "umask",	SYSUMASK },
#endif

	{ "unset", 	SYSUNS },
	{ "wait",	SYSWAIT	}
};

const int no_commands = sizeof(commands)/sizeof(struct sysnod);

