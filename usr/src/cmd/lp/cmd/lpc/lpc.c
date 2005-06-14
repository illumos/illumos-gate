/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
 * lpc -- line printer control program
 */
#include <locale.h>
#include <stdio.h>
#include <signal.h>
#include <ctype.h>
#include <setjmp.h>
#include <pwd.h>
#include <assert.h>
#include <sys/systeminfo.h>

#include "lpc.h"

#include "lp.h"
#include "msgs.h"
#include "oam_def.h"


int		 fromatty;

char		 cmdline[200];
int		 margc;
char		*margv[20];
int		 top;
int		 isadmin;	/* set if root or lp */

jmp_buf		 toplevel;

extern struct cmd cmdtab[];
extern int NCMDS;

extern char	*Lhost;
extern char	*Printer;
extern char	*Name;

#if defined (__STDC__)
	void		  done(int);
static	struct cmd	* getcmd(char *);
static	void		  cmdscanner(int);
static	void		  intr(int);
static	void		  makeargv(void);
static	void 		  startup(void);
#else
	void		  done();
static	struct cmd	* getcmd();
static	void		  cmdscanner();
static	void		  intr();
static	void		  makeargv();
static	void 		  startup();
#endif

main(argc, argv)
char	*argv[];
{
	register struct cmd	*c;
	struct passwd		*p;
	char			my_name[MAXNAMELEN];

	(void) setlocale (LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	Name = argv[0];
	if (sysinfo(SI_HOSTNAME, my_name, sizeof (my_name)) < 0) {
		perror(Name);
		exit(1);
	}
	Lhost = my_name;

	isadmin = getuid() == 0 || 
		  (p = getpwnam(LPUSER)) && p->pw_uid == getuid();
	endpwent();
		
	if (--argc > 0) {
		c = getcmd(*++argv);
		if (c == (struct cmd *)-1) {
			printf(gettext("?Ambiguous command\n"));
			exit(1);
		}
		if (c == 0) {
			printf(gettext("?Invalid command\n"));
			exit(1);
		}
		if (c->c_priv && !isadmin) {
			printf(gettext("?Privileged command\n"));
			exit(1);
		}
		startup();
		(*c->c_handler)(argc, argv);
		done(0);
	}

	startup();

	fromatty = isatty(fileno(stdin));
	top = setjmp(toplevel) == 0;
	if (top)
		sigset(SIGINT, intr);
	for (;;) {
		cmdscanner(top);
		top = 1;
	}
}

/*ARGSUSED*/
static void
#if defined(__STDC__)
intr(int s)
#else
intr(s)
int	s;
#endif
{
	if (!fromatty)
		done(0);	
	longjmp(toplevel, 1);
}

/*
 * Command parser.
 */
static void
#if defined(__STDC__)
cmdscanner(int top)
#else
cmdscanner(top)
int	top;
#endif
{
	register struct cmd *c;

	if (!top)
		putchar('\n');
	for (;;) {
		if (fromatty) {
			printf("lpc> ");
			fflush(stdout);
		}
		if (fgets(cmdline, sizeof (cmdline), stdin) == 0)
			done(0);
		if (cmdline[0] == 0)
			break;
		makeargv();
		if (!margv[0])
			 break;
		c = getcmd(margv[0]);
		if (c == (struct cmd *)-1) {
			printf(gettext("?Ambiguous command\n"));
			continue;
		}
		if (c == 0) {
			printf(gettext("?Invalid command\n"));
			continue;
		}
		if (c->c_priv && !isadmin) {
			printf(gettext("?Privileged command\n"));
			continue;
		}
		(*c->c_handler)(margc, margv);
	}
	longjmp(toplevel, 0);
}

static struct cmd *
#if defined(__STDC__)
getcmd(register char *name)
#else
getcmd(name)
register char	*name;
#endif
{
	register char *p, *q;
	register struct cmd *c, *found;
	register int nmatches, longest;

	longest = 0;
	nmatches = 0;
	found = 0;
	if (!name) return(0);
	for (c = cmdtab; p = c->c_name; c++) {
		for (q = name; *q == *p++; q++)
			if (*q == 0)		/* exact match? */
				return(c);
		if (!*q) {			/* the name was a prefix */
			if (q - name > longest) {
				longest = q - name;
				nmatches = 1;
				found = c;
			} else if (q - name == longest)
				nmatches++;
		}
	}
	if (nmatches > 1)
		return((struct cmd *)-1);
	return(found);
}

/*
 * Slice a string up into argc/argv.
 */
static void
#if defined(__STDC__)
makeargv(void)
#else
makeargv()
#endif
{
	register char	 *cp;
	register char	**argp = margv;

	margc = 0;
	for (cp = cmdline; *cp;) {
		while (isspace(*cp))
			cp++;
		if (*cp == '\0')
			break;
		*argp++ = cp;
		margc += 1;
		while (*cp != '\0' && !isspace(*cp))
			cp++;
		if (*cp == '\0')
			break;
		*cp++ = '\0';
	}
	*argp++ = 0;
}

#define HELPINDENT (sizeof ("directory"))

/*
 * Help command.
 */
void
#if defined(__STDC__)
help(int argc, char **argv)
#else
help(argc, argv)
int	  argc;
char	**argv;
#endif
{
	register struct cmd *c;

	if (argc == 1) {
		register int i, j, w;
		int columns, width = 0, lines;

		printf(gettext("Commands may be abbreviated.  Commands are:\n\n"));
		for (c = cmdtab; c < &cmdtab[NCMDS]; c++) {
			int len = strlen(c->c_name);

			if (len > width)
				width = len;
		}
		width = (width + 8) &~ 7;
		columns = 80 / width;
		if (columns == 0)
			columns = 1;
		lines = (NCMDS + columns - 1) / columns;
		for (i = 0; i < lines; i++) {
			for (j = 0; j < columns; j++) {
				c = cmdtab + j * lines + i;
				printf("%s", c->c_name);
				if (c + lines >= &cmdtab[NCMDS]) {
					printf("\n");
					break;
				}
				w = strlen(c->c_name);
				while (w < width) {
					w = (w + 8) &~ 7;
					putchar('\t');
				}
			}
		}
		return;
	}
	while (--argc > 0) {
		register char *arg;
		arg = *++argv;
		c = getcmd(arg);
		if (c == (struct cmd *)-1)
			printf(gettext("?Ambiguous help command %s\n"), arg);
		else if (c == (struct cmd *)0)
			printf(gettext("?Invalid help command %s\n"), arg);
		else
			printf("%-*s\t%s\n", HELPINDENT,
				c->c_name, c->c_help);
	}
}

static void
#if defined(__STDC__)
catch(int s)
#else
catch(s)
int	s;
#endif
{
	done(2);
}

static void
#if defined(__STDC__)
startup(void)
#else
startup()
#endif
{
	register int	try = 0;

	if (sigset(SIGHUP, SIG_IGN) != SIG_IGN)
		(void)sigset(SIGHUP, catch);
	if (sigset(SIGINT, SIG_IGN) != SIG_IGN)
		(void)sigset(SIGINT, catch);
	if (sigset(SIGQUIT, SIG_IGN) != SIG_IGN)
		(void)sigset(SIGQUIT, catch);
	if (sigset(SIGTERM, SIG_IGN) != SIG_IGN)
		(void)sigset(SIGTERM, catch);

	(void)mopen();
}

void
#if defined(__STDC__)
done(int rc)
#else
done(rc)
int	rc;
#endif
{
	(void)mclose();
	exit(rc);
}
