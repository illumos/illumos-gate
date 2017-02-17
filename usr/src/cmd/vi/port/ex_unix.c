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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/* Copyright (c) 1979 Regents of the University of California */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "ex.h"
#include "ex_temp.h"
#include "ex_tty.h"
#include "ex_vis.h"

extern int	getchar();
/*
 * Unix escapes, filtering
 */

/*
 * First part of a shell escape,
 * parse the line, expanding # and % and ! and printing if implied.
 */
void
unix0(bool warn, int contcmd)
{
	unsigned char *up, *fp;
	short c;
	char	multic[MB_LEN_MAX + 1];
	int	len;
	int	contread = 0;
	wchar_t	wc;
	unsigned char printub, puxb[UXBSIZE + sizeof (int)];
	const char	*specialchars = (contcmd ? "%#!\n" : "%#!");

	printub = 0;
	CP(puxb, uxb);
	c = peekchar();
	if (c == '\n' || c == EOF) {
		(void) getchar();
		error(value(vi_TERSE) ?
gettext("Incomplete shell escape command") :
gettext("Incomplete shell escape command - use 'shell' to get a shell"));
	}
	up = (unsigned char *)uxb;

	for (;;) {
		if (!isascii(c)) {
			if (c == EOF)
				break;
			if ((len = _mbftowc(multic, &wc, getchar, &peekc)) > 0) {
				if ((up + len) >= (unsigned char *)&uxb[UXBSIZE]) {
					uxb[0] = 0;
					error(gettext("Command too long"));
				}
				strncpy(up, multic, len);
				up += len;
				goto loop_check;
			}
		}

		(void) getchar();
		switch (c) {

		case '\\':
			if (any(peekchar(), specialchars)) {
				c = getchar();
				/*
				 * If we encountered a backslash-escaped
				 * newline, and we're processing a continuation
				 * command, then continue processing until
				 * non-backslash-escaped newline is reached.
				 */
				if (contcmd && (c == '\n')) {
					contread = 1;
				}
			}
		default:
			if (up >= (unsigned char *)&uxb[UXBSIZE]) {
tunix:
				uxb[0] = 0;
				error(gettext("Command too long"));
			}
			/*
			 * If this is a tag command (-t or :tag),
			 * then don't save any command that follows
			 * '!' in the invalid tags file, ie:
			 * '!!' should not repeat the invalid command
			 * later on when tagflg has been cleared.
			 */
			if (!tagflg)
				*up++ = c;
			break;

		case '!':
			if (up != (unsigned char *)uxb && *puxb != 0) {
				fp = puxb;
				if (*fp == 0) {
					uxb[0] = 0;
					error(value(vi_TERSE) ?
gettext("No previous command") :
gettext("No previous command to substitute for !"));
				}
				printub++;
				while (*fp) {
					if (up >= (unsigned char *)&uxb[UXBSIZE])
						goto tunix;
					*up++ = *fp++;
				}
			} else if (up == (unsigned char *)uxb) {
				/* If up = uxb it means we are on the first
				 * character inside the shell command.
				 * (i.e., after the ":!")
				 *
				 * The user has just entered ":!!" which
				 * means that though there is only technically
				 * one '!' we know they really meant ":!!!". So
				 * substitute the last command for them.
				 */
				fp = puxb;
				if (*fp == 0) {
					uxb[0] = 0;
					error(value(vi_TERSE) ?
gettext("No previous command") :
gettext("No previous command to substitute for !"));
				}
				printub++;
				while (*fp) {
					if (up >= (unsigned char *)&uxb[UXBSIZE])
						goto tunix;
					*up++ = *fp++;
				}
			} else {
				/*
				 * Treat a lone "!" as just a regular character
				 * so commands like "mail machine!login" will
				 * work as usual (i.e., the user doesn't need
				 * to dereference the "!" with "\!").
				 */
				if (up >= (unsigned char *)&uxb[UXBSIZE]) {
					uxb[0] = 0;
					error(gettext("Command too long"));
				}
				*up++ = c;
			}
			break;

		case '#':
			fp = (unsigned char *)altfile;
			if (*fp == 0) {
				uxb[0] = 0;
				error(value(vi_TERSE) ?
gettext("No alternate filename") :
gettext("No alternate filename to substitute for #"));
			}
			goto uexp;

		case '%':
			fp = savedfile;
			if (*fp == 0) {
				uxb[0] = 0;
				error(value(vi_TERSE) ?
gettext("No filename") :
gettext("No filename to substitute for %%"));
			}
uexp:
			printub++;
			while (*fp) {
				if (up >= (unsigned char *)&uxb[UXBSIZE])
					goto tunix;
				*up++ = *fp++;
			}
			break;
		}

loop_check:
		c = peekchar();
		if (c == '"' || c == '|' || (contread > 0) || !endcmd(c)) {
			/*
			 * If contread was set, then the newline just
			 * processed was preceeded by a backslash, and
			 * not considered the end of the command. Reset
			 * it here in case another backslash-escaped
			 * newline is processed.
			 */
			contread = 0;
			continue;
		} else {
			(void) getchar();
			break;
		}
	}
	if (c == EOF)
		ungetchar(c);
	*up = 0;
	if (!inopen)
		resetflav();
	if (warn)
		ckaw();
	if (warn && hush == 0 && chng && xchng != chng && value(vi_WARN) && dol > zero) {
		xchng = chng;
		vnfl();
		viprintf(mesg(value(vi_TERSE) ? gettext("[No write]") :
gettext("[No write since last change]")));
		noonl();
		flush();
	} else
		warn = 0;
	if (printub) {
		if (uxb[0] == 0)
			error(value(vi_TERSE) ? gettext("No previous command") :
gettext("No previous command to repeat"));
		if (inopen) {
			splitw++;
			vclean();
			vgoto(WECHO, 0);
		}
		if (warn)
			vnfl();
		if (hush == 0)
			lprintf("!%s", uxb);
		if (inopen && Outchar != termchar) {
			vclreol();
			vgoto(WECHO, 0);
		} else
			putnl();
		flush();
	}
}

/*
 * Do the real work for execution of a shell escape.
 * Mode is like the number passed to open system calls
 * and indicates filtering.  If input is implied, newstdin
 * must have been setup already.
 */
ttymode
unixex(opt, up, newstdin, mode)
	unsigned char *opt, *up;
	int newstdin, mode;
{
	int pvec[2];
	ttymode f;

	signal(SIGINT, SIG_IGN);
#ifdef SIGTSTP
	if (dosusp)
		signal(SIGTSTP, SIG_DFL);
#endif
	if (inopen)
		f = setty(normf);
	if ((mode & 1) && pipe(pvec) < 0) {
		/* Newstdin should be io so it will be closed */
		if (inopen)
			setty(f);
		error(gettext("Can't make pipe for filter"));
	}
#ifndef VFORK
	pid = fork();
#else
	pid = vfork();
#endif
	if (pid < 0) {
		if (mode & 1) {
			close(pvec[0]);
			close(pvec[1]);
		}
		setrupt();
		if (inopen)
			setty(f);
		error(gettext("No more processes"));
	}
	if (pid == 0) {
		if (mode & 2) {
			close(0);
			dup(newstdin);
			close(newstdin);
		}
		if (mode & 1) {
			close(pvec[0]);
			close(1);
			dup(pvec[1]);
			if (inopen) {
				close(2);
				dup(1);
			}
			close(pvec[1]);
		}
		if (io)
			close(io);
		if (tfile)
			close(tfile);
		signal(SIGHUP, oldhup);
		signal(SIGQUIT, oldquit);
		if (ruptible)
			signal(SIGINT, SIG_DFL);
		execlp((char *)svalue(vi_SHELL), (char *)svalue(vi_SHELL),
		    opt, up, (char *)0);
		viprintf(gettext("Invalid SHELL value: %s\n"),
		    svalue(vi_SHELL));
		flush();
		error(NOSTR);
	}
	if (mode & 1) {
		io = pvec[0];
		close(pvec[1]);
	}
	if (newstdin)
		close(newstdin);
	return (f);
}

/*
 * Wait for the command to complete.
 * F is for restoration of tty mode if from open/visual.
 * C flags suppression of printing.
 */
void
unixwt(c, f)
	bool c;
	ttymode f;
{

	waitfor();
#ifdef SIGTSTP
	if (dosusp)
		signal(SIGTSTP, onsusp);
#endif
	if (inopen)
		setty(f);
	setrupt();
	if (!inopen && c && hush == 0) {
		viprintf("!\n");
		flush();
		termreset();
		gettmode();
	}
}

/*
 * Setup a pipeline for the filtration implied by mode
 * which is like a open number.  If input is required to
 * the filter, then a child editor is created to write it.
 * If output is catch it from io which is created by unixex.
 */
int
vi_filter(int mode)
{
	static int pvec[2];
	ttymode f;	/* was register */
	int nlines = lineDOL();
	int status2;
	pid_t pid2 = 0;

	mode++;
	if (mode & 2) {
		signal(SIGINT, SIG_IGN);
		signal(SIGPIPE, SIG_IGN);
		if (pipe(pvec) < 0)
			error(gettext("Can't make pipe"));
		pid2 = fork();
		io = pvec[0];
		if (pid < 0) {
			setrupt();
			close(pvec[1]);
			error(gettext("No more processes"));
		}
		if (pid2 == 0) {
			extern unsigned char tfname[];
			setrupt();
			io = pvec[1];
			close(pvec[0]);

			/* To prevent seeking in this process and the
				 parent, we must reopen tfile here */
			close(tfile);
			tfile = open(tfname, 2);

			putfile(1);
			exit(errcnt);
		}
		close(pvec[1]);
		io = pvec[0];
		setrupt();
	}
	f = unixex("-c", uxb, (mode & 2) ? pvec[0] : 0, mode);
	if (mode == 3) {
		(void) delete(0);
		addr2 = addr1 - 1;
	}
	if (mode == 1)
		deletenone();
	if (mode & 1) {
		if(FIXUNDO)
			undap1 = undap2 = addr2+1;
		(void)append(getfile, addr2);
#ifdef UNDOTRACE
		if (trace)
			vudump(gettext("after append in filter"));
#endif
	}
	close(io);
	io = -1;
	unixwt(!inopen, f);
	if (pid2) {
		(void)kill(pid2, 9);
		do
			rpid = waitpid(pid2, &status2, 0);
		while (rpid == (pid_t)-1 && errno == EINTR);
	}
	netchHAD(nlines);
	return (0);
}

/*
 * Set up to do a recover, getting io to be a pipe from
 * the recover process.
 */
void
recover(void)
{
	static int pvec[2];

	if (pipe(pvec) < 0)
		error(gettext(" Can't make pipe for recovery"));
	pid = fork();
	io = pvec[0];
	if (pid < 0) {
		close(pvec[1]);
		error(gettext(" Can't fork to execute recovery"));
	}
	if (pid == 0) {
		unsigned char cryptkey[19];
		close(2);
		dup(1);
		close(1);
		dup(pvec[1]);
	        close(pvec[1]);
		if(xflag) {
			strcpy(cryptkey, "CrYpTkEy=XXXXXXXXX");
			strcpy(cryptkey + 9, key);
			if(putenv((char *)cryptkey) != 0)
				smerror(gettext(" Cannot copy key to environment"));
			execlp(EXRECOVER, "exrecover", "-x", svalue(vi_DIRECTORY), file, (char *) 0);
		} else
			execlp(EXRECOVER, "exrecover", svalue(vi_DIRECTORY), file, (char *) 0);
		close(1);
		dup(2);
		error(gettext(" No recovery routine"));
	}
	close(pvec[1]);
}

/*
 * Wait for the process (pid an external) to complete.
 */
void
waitfor(void)
{

	do
		rpid = waitpid(pid, &status, 0);
	while (rpid == (pid_t)-1 && errno != ECHILD);
	if ((status & 0377) == 0)
		status = (status >> 8) & 0377;
	else {
		/*
		 * TRANSLATION_NOTE
		 *	Reference order of arguments must not
		 *	be changed using '%digit$', since vi's
		 *	viprintf() does not support it.
		 */
		viprintf(gettext("%d: terminated with signal %d"), pid,
		    status & 0177);
		if (status & 0200)
			viprintf(gettext(" -- core dumped"));
		putchar('\n');
	}
}

/*
 * The end of a recover operation.  If the process
 * exits non-zero, force not edited; otherwise force
 * a write.
 */
void
revocer(void)
{

	waitfor();
	if (pid == rpid && status != 0)
		edited = 0;
	else
		change();
}
